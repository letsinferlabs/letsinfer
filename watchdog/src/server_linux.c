#include "watchdog/server.h"

#include "watchdog/controllers.h"
#include "watchdog/gateway.h"
#include "watchdog/metadata.h"
#include "watchdog/protobuf.h"
#include "watchdog/ring.h"
#include "watchdog/rollup.h"
#include "watchdog/sampler.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define WATCHDOG_RAW_CAPACITY 86400u
#define WATCHDOG_MINUTE_CAPACITY 43200u
#define WATCHDOG_QUARTER_CAPACITY 35040u
#define WATCHDOG_PENDING_MAX 256u
#define WATCHDOG_QUERY_SCAN_MAX 1024u
#define WATCHDOG_TLS_HANDSHAKE_TIMEOUT_MS 10000u
#define WATCHDOG_CLIENT_IDLE_TIMEOUT_MS 30000u
#define WATCHDOG_FRAME_STORAGE (WATCHDOG_MAX_FRAME_BYTES + 4u)
#define WATCHDOG_COLLECT_FATAL (-2)

typedef enum client_state {
    CLIENT_UNUSED = 0,
    CLIENT_HANDSHAKE,
    CLIENT_READY
} client_state;

typedef enum query_phase {
    QUERY_NONE = 0,
    QUERY_LATEST,
    QUERY_HISTORY,
    QUERY_COMPLETE
} query_phase;

typedef struct client_query {
    query_phase phase;
    bool subscribe;
    uint64_t request_id;
    uint64_t start_ms;
    uint64_t end_ms;
    uint64_t cursor_bucket;
    uint64_t final_bucket;
    uint64_t through_sequence;
    watchdog_resolution resolution;
} client_query;

typedef struct watchdog_client {
    int fd;
    SSL *ssl;
    client_state state;
    short handshake_want;
    short read_want;
    short write_want;
    uint64_t handshake_deadline_ms;
    uint64_t last_activity_ms;
    char controller_certificate_sha256[65u];
    uint8_t input[WATCHDOG_FRAME_STORAGE];
    size_t input_length;
    uint8_t output[WATCHDOG_FRAME_STORAGE];
    size_t output_length;
    size_t output_offset;
    bool subscribed;
    uint64_t subscription_request_id;
    uint64_t missed_sequence;
    client_query query;
} watchdog_client;

typedef struct watchdog_server {
    watchdog_config config;
    watchdog_public_state public_state;
    watchdog_controller_registry controllers;
    int listener;
    SSL_CTX *tls;
    watchdog_sampler sampler;
    watchdog_ring raw;
    watchdog_ring minute;
    watchdog_ring quarter;
    watchdog_metadata metadata;
    watchdog_safety_supervisor safety;
    watchdog_rollup minute_rollup;
    watchdog_rollup quarter_rollup;
    watchdog_sample pending[WATCHDOG_PENDING_MAX];
    size_t pending_count;
    watchdog_sample latest;
    bool has_latest;
    bool minute_dirty;
    bool quarter_dirty;
    bool started;
    uint64_t next_sequence;
    uint64_t next_sample_ms;
    uint64_t next_flush_ms;
    uint64_t last_sample_error_ms;
    watchdog_client clients[WATCHDOG_HARD_MAX_CONTROLLERS];
} watchdog_server;

static volatile sig_atomic_t stop_requested;
static volatile sig_atomic_t reload_requested;

static void request_stop(int signal_number) {
    (void)signal_number;
    stop_requested = 1;
}

static void request_reload(int signal_number) {
    (void)signal_number;
    reload_requested = 1;
}

static int peer_fingerprint(X509 *peer, char output[65u]) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int length = 0;
    if (peer == NULL || X509_digest(peer, EVP_sha256(), digest, &length) != 1
        || length != 32u) return -1;
    for (size_t index = 0; index < 32u; ++index) {
        snprintf(output + index * 2u, 3u, "%02x", digest[index]);
    }
    output[64] = '\0';
    return 0;
}

static uint64_t clock_ms(clockid_t clock_id) {
    struct timespec value;
    if (clock_gettime(clock_id, &value) != 0) return 0;
    return (uint64_t)value.tv_sec * 1000u + (uint64_t)value.tv_nsec / 1000000u;
}

static bool status_text_valid(const char *text, size_t maximum) {
    if (text == NULL || *text == '\0' || strlen(text) > maximum) return false;
    for (const unsigned char *cursor = (const unsigned char *)text; *cursor != '\0'; ++cursor) {
        if (!(isalnum(*cursor) || strchr("._:/@+-", *cursor) != NULL)) return false;
    }
    return true;
}

static bool lowercase_sha256_valid(const char *text) {
    if (text == NULL || strlen(text) != 64u) return false;
    for (const unsigned char *cursor = (const unsigned char *)text; *cursor != '\0'; ++cursor) {
        if (!((*cursor >= '0' && *cursor <= '9') || (*cursor >= 'a' && *cursor <= 'f'))) {
            return false;
        }
    }
    return true;
}

static int parse_status_u32(const char *text, uint32_t *output) {
    if (text == NULL || *text == '\0' || output == NULL) return -1;
    char *end = NULL;
    errno = 0;
    const unsigned long value = strtoul(text, &end, 10);
    if (errno != 0 || *end != '\0' || value == 0 || value > UINT32_MAX) return -1;
    *output = (uint32_t)value;
    return 0;
}

static int copy_status_text(char *output, size_t capacity, const char *value) {
    if (output == NULL || capacity == 0 || !status_text_valid(value, capacity - 1u)) return -1;
    memcpy(output, value, strlen(value) + 1u);
    return 0;
}

static int load_public_state(const char *path, watchdog_public_state *state) {
    if (path == NULL || state == NULL) return -1;
    struct stat details;
    if (lstat(path, &details) != 0 || !S_ISREG(details.st_mode)
        || details.st_uid != getuid() || (details.st_mode & 077u) != 0
        || details.st_size <= 0
        || (uintmax_t)details.st_size >= 2048u) return -1;
    const int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    char text[2048];
    size_t count = 0u;
    while (count < (size_t)details.st_size) {
        const ssize_t current = read(fd, text + count, (size_t)details.st_size - count);
        if (current <= 0) {
            count = 0u;
            break;
        }
        count += (size_t)current;
    }
    const int saved_errno = errno;
    close(fd);
    errno = saved_errno;
    if (count != (size_t)details.st_size || text[count - 1u] != '\n'
        || memchr(text, '\0', count) != NULL) return -1;
    text[count] = '\0';

    memset(state, 0, sizeof(*state));
    uint32_t seen = 0u;
    char *save = NULL;
    for (char *line = strtok_r(text, "\n", &save); line != NULL; line = strtok_r(NULL, "\n", &save)) {
        char *separator = strchr(line, '=');
        if (separator == NULL || separator == line) return -1;
        *separator = '\0';
        const char *value = separator + 1u;
        uint32_t bit = 0u;
        int result = 0;
        if (strcmp(line, "version") == 0) {
            bit = 1u << 0u;
            result = strcmp(value, "1") == 0 ? 0 : -1;
        } else if (strcmp(line, "installation_id") == 0) {
            bit = 1u << 13u;
            result = copy_status_text(
                state->installation_id, sizeof(state->installation_id), value);
            if (result == 0 && !lowercase_sha256_valid(value)) result = -1;
        } else if (strcmp(line, "release") == 0) {
            bit = 1u << 1u;
            result = copy_status_text(state->release, sizeof(state->release), value);
        } else if (strcmp(line, "model") == 0) {
            bit = 1u << 2u;
            result = copy_status_text(state->model, sizeof(state->model), value);
        } else if (strcmp(line, "engine") == 0) {
            bit = 1u << 3u;
            result = copy_status_text(state->engine, sizeof(state->engine), value);
        } else if (strcmp(line, "runtime_name") == 0) {
            bit = 1u << 4u;
            result = copy_status_text(state->runtime_name, sizeof(state->runtime_name), value);
        } else if (strcmp(line, "runtime_version") == 0) {
            bit = 1u << 5u;
            result = copy_status_text(state->runtime_version, sizeof(state->runtime_version), value);
        } else if (strcmp(line, "manifest_sha256") == 0) {
            bit = 1u << 6u;
            result = copy_status_text(state->manifest_sha256, sizeof(state->manifest_sha256), value);
            if (result == 0 && !lowercase_sha256_valid(value)) result = -1;
        } else if (strcmp(line, "cache_provider") == 0) {
            bit = 1u << 7u;
            result = copy_status_text(state->cache_provider, sizeof(state->cache_provider), value);
        } else if (strcmp(line, "cache_persistent") == 0) {
            bit = 1u << 8u;
            if (strcmp(value, "true") == 0) state->cache_persistent = true;
            else if (strcmp(value, "false") == 0) state->cache_persistent = false;
            else result = -1;
        } else if (strcmp(line, "inference_port") == 0) {
            bit = 1u << 9u;
            result = parse_status_u32(value, &state->inference_port);
            if (result == 0 && state->inference_port > UINT16_MAX) result = -1;
        } else if (strcmp(line, "max_connections") == 0) {
            bit = 1u << 10u;
            result = parse_status_u32(value, &state->max_connections);
        } else if (strcmp(line, "max_active_requests") == 0) {
            bit = 1u << 11u;
            result = parse_status_u32(value, &state->max_active_requests);
        } else if (strcmp(line, "max_context_tokens") == 0) {
            bit = 1u << 12u;
            result = parse_status_u32(value, &state->max_context_tokens);
        } else {
            return -1;
        }
        if (result != 0 || bit == 0u || (seen & bit) != 0u) return -1;
        seen |= bit;
    }
    return seen == ((1u << 14u) - 1u) ? 0 : -1;
}

static void log_openssl(const char *message) {
    const unsigned long code = ERR_get_error();
    char detail[256] = "unknown TLS error";
    if (code != 0) ERR_error_string_n(code, detail, sizeof(detail));
    fprintf(stderr, "watchdog: %s: %s\n", message, detail);
}

static void client_reset(watchdog_client *client) {
    if (client->ssl != NULL) SSL_free(client->ssl);
    if (client->fd >= 0) close(client->fd);
    memset(client, 0, sizeof(*client));
    client->fd = -1;
}

static void clients_init(watchdog_server *server) {
    for (size_t index = 0; index < WATCHDOG_HARD_MAX_CONTROLLERS; ++index) {
        server->clients[index].fd = -1;
    }
}

static void put_frame_length(uint8_t header[4], size_t length) {
    header[0] = (uint8_t)(length >> 24u);
    header[1] = (uint8_t)(length >> 16u);
    header[2] = (uint8_t)(length >> 8u);
    header[3] = (uint8_t)length;
}

static int finish_frame(watchdog_client *client, size_t payload_length) {
    if (payload_length == 0 || payload_length > WATCHDOG_MAX_FRAME_BYTES) return -1;
    put_frame_length(client->output, payload_length);
    client->output_length = payload_length + 4u;
    client->output_offset = 0;
    client->write_want = POLLOUT;
    return 0;
}

static int queue_error(watchdog_client *client, uint64_t request_id, uint32_t code, const char *message) {
    const size_t length = watchdog_pb_encode_error(
        request_id, code, message, client->output + 4u, WATCHDOG_MAX_FRAME_BYTES);
    return finish_frame(client, length);
}

static int queue_sample(
    watchdog_client *client,
    uint64_t request_id,
    watchdog_sample_message_kind kind,
    const watchdog_sample *sample
) {
    const size_t length = watchdog_pb_encode_sample(
        request_id, kind, sample, client->output + 4u, WATCHDOG_MAX_FRAME_BYTES);
    return finish_frame(client, length);
}

static int queue_capabilities(watchdog_server *server, watchdog_client *client, uint64_t request_id) {
    const size_t length = watchdog_pb_encode_capabilities(
        request_id,
        server->config.sample_interval_ms,
        server->config.flush_interval_ms,
        watchdog_nvml_device_count(&server->sampler.nvml),
        client->output + 4u,
        WATCHDOG_MAX_FRAME_BYTES);
    return finish_frame(client, length);
}

static int queue_pong(watchdog_client *client, uint64_t request_id, uint64_t nonce) {
    const size_t length = watchdog_pb_encode_pong(
        request_id, nonce, client->output + 4u, WATCHDOG_MAX_FRAME_BYTES);
    return finish_frame(client, length);
}

static const char *engine_state(
    const watchdog_safety_supervisor *safety,
    bool tripped
) {
    if (tripped) return "tripped";
    const size_t active = watchdog_safety_supervisor_active(safety);
    if (watchdog_safety_supervisor_armed(safety)) return "running";
    const watchdog_safety_runtime *primary = watchdog_safety_supervisor_primary(safety);
    if (primary == NULL) return "absent";
    if (active > 1u) return "degraded";
    switch (primary->target.phase) {
    case WATCHDOG_SAFETY_PHASE_PENDING: return "pending";
    case WATCHDOG_SAFETY_PHASE_STARTING: return "starting";
    case WATCHDOG_SAFETY_PHASE_ARMED: return primary->pid_fd >= 0 ? "running" : "degraded";
    case WATCHDOG_SAFETY_PHASE_DISARMED: return "stopped";
    case WATCHDOG_SAFETY_PHASE_NONE: return "absent";
    }
    return "unknown";
}

static int queue_site_status(
    watchdog_server *server,
    watchdog_client *client,
    uint64_t request_id
) {
    watchdog_public_state replacement;
    if (load_public_state(server->config.site_state_path, &replacement) != 0
        || strcmp(
            replacement.installation_id,
            server->public_state.installation_id) != 0) {
        return queue_error(
            client, request_id, 503u,
            "Let's Infer runtime identity is temporarily unavailable");
    }
    server->public_state = replacement;
    const bool tripped = watchdog_safety_supervisor_tripped(&server->safety);
    const bool armed = watchdog_safety_supervisor_armed(&server->safety);
    const watchdog_safety_runtime *primary =
        watchdog_safety_supervisor_primary(&server->safety);
    const size_t active = watchdog_safety_supervisor_active(&server->safety);
    const char *protection_phase = armed ? "armed"
        : active > 1u ? "mixed"
        : primary == NULL ? "none"
        : watchdog_safety_phase_name(primary->target.phase);
    const char *container_name = primary == NULL ? ""
        : active > 1u ? "multiple"
        : primary->target.container_name;
    const watchdog_site_status status = {
        .installation_id = server->public_state.installation_id,
        .release = server->public_state.release,
        .model = server->public_state.model,
        .engine = server->public_state.engine,
        .runtime_name = server->public_state.runtime_name,
        .runtime_version = server->public_state.runtime_version,
        .manifest_sha256 = server->public_state.manifest_sha256,
        .cache_provider = server->public_state.cache_provider,
        .cache_persistent = server->public_state.cache_persistent ? 1u : 0u,
        .inference_port = server->public_state.inference_port,
        .max_connections = server->public_state.max_connections,
        .max_active_requests = server->public_state.max_active_requests,
        .max_context_tokens = server->public_state.max_context_tokens,
        .service_state = "running",
        .engine_state = engine_state(&server->safety, tripped),
        .protection_phase = protection_phase,
        .protection_armed = armed ? 1u : 0u,
        .trip_latched = tripped ? 1u : 0u,
        .container_name = container_name
    };
    const size_t length = watchdog_pb_encode_site_status(
        request_id, &status, client->output + 4u, WATCHDOG_MAX_FRAME_BYTES);
    return finish_frame(client, length);
}

static int queue_gap(watchdog_server *server, watchdog_client *client) {
    const size_t length = watchdog_pb_encode_gap(
        client->subscription_request_id,
        client->missed_sequence,
        server->latest.sequence,
        client->output + 4u,
        WATCHDOG_MAX_FRAME_BYTES);
    if (finish_frame(client, length) != 0) return -1;
    client->missed_sequence = 0;
    return 0;
}

static watchdog_ring *query_ring(watchdog_server *server, watchdog_resolution resolution) {
    switch (resolution) {
    case WATCHDOG_RESOLUTION_RAW_1_SECOND: return &server->raw;
    case WATCHDOG_RESOLUTION_1_MINUTE: return &server->minute;
    case WATCHDOG_RESOLUTION_15_MINUTES: return &server->quarter;
    default: return NULL;
    }
}

static bool pending_read(const watchdog_server *server, uint64_t bucket, watchdog_sample *sample) {
    for (size_t index = 0; index < server->pending_count; ++index) {
        if (server->pending[index].unix_ms / 1000u == bucket) {
            *sample = server->pending[index];
            return true;
        }
    }
    return false;
}

static int begin_query(
    watchdog_server *server,
    watchdog_client *client,
    uint64_t request_id,
    uint64_t start_ms,
    uint64_t end_ms,
    watchdog_resolution resolution,
    bool subscribe,
    bool send_latest
) {
    watchdog_ring *ring = query_ring(server, resolution);
    if (ring == NULL || end_ms < start_ms) {
        return queue_error(client, request_id, 400u, "invalid telemetry range");
    }
    const uint64_t first = start_ms / ring->interval_ms;
    const uint64_t final = end_ms / ring->interval_ms;
    if (final - first >= ring->capacity) {
        return queue_error(client, request_id, 413u, "range exceeds retained history");
    }
    memset(&client->query, 0, sizeof(client->query));
    client->query.phase = send_latest ? QUERY_LATEST : QUERY_HISTORY;
    client->query.subscribe = subscribe;
    client->query.request_id = request_id;
    client->query.start_ms = start_ms;
    client->query.end_ms = end_ms;
    client->query.cursor_bucket = first;
    client->query.final_bucket = final;
    client->query.through_sequence = server->has_latest ? server->latest.sequence : 0;
    client->query.resolution = resolution;
    client->subscribed = false;
    client->missed_sequence = 0;
    return 0;
}

static int handle_request(
    watchdog_server *server,
    watchdog_client *client,
    const uint8_t *payload,
    size_t payload_length
) {
    watchdog_request request;
    if (watchdog_pb_decode_request(payload, payload_length, &request) != 0) {
        return queue_error(client, 0, 400u, "invalid protobuf request");
    }
    switch (request.kind) {
    case WATCHDOG_REQUEST_GET_LATEST:
        return server->has_latest
            ? queue_sample(client, request.request_id, WATCHDOG_MESSAGE_LATEST, &server->latest)
            : queue_error(client, request.request_id, 404u, "no sample available");
    case WATCHDOG_REQUEST_GET_CAPABILITIES:
        return queue_capabilities(server, client, request.request_id);
    case WATCHDOG_REQUEST_PING:
        return queue_pong(client, request.request_id, request.nonce);
    case WATCHDOG_REQUEST_GET_SITE_STATUS:
        return queue_site_status(server, client, request.request_id);
    case WATCHDOG_REQUEST_QUERY_RANGE:
        memset(&client->query, 0, sizeof(client->query));
        return begin_query(
            server, client, request.request_id, request.start_unix_ms,
            request.end_unix_ms, request.resolution, false, false);
    case WATCHDOG_REQUEST_SUBSCRIBE: {
        if (!server->has_latest) {
            return queue_error(client, request.request_id, 404u, "no sample available");
        }
        const uint64_t history_ms = (uint64_t)request.history_seconds * 1000u;
        const uint64_t end_ms = server->latest.unix_ms >= server->config.sample_interval_ms
            ? server->latest.unix_ms - server->config.sample_interval_ms
            : 0;
        const uint64_t start_ms = end_ms > history_ms ? end_ms - history_ms : 0;
        client->subscription_request_id = request.request_id;
        const int result = begin_query(
            server, client, request.request_id, start_ms, end_ms,
            WATCHDOG_RESOLUTION_RAW_1_SECOND, true, true);
        if (result == 0 && request.history_seconds == 0) {
            client->query.cursor_bucket = 1u;
            client->query.final_bucket = 0u;
        }
        return result;
    }
    default:
        return queue_error(client, request.request_id, 400u, "unsupported request");
    }
}

static int process_input(watchdog_server *server, watchdog_client *client) {
    while (client->output_length == 0 && client->input_length >= 4u) {
        uint32_t payload_length = 0;
        if (watchdog_frame_length(client->input, &payload_length) != 0) return -1;
        const size_t frame_length = (size_t)payload_length + 4u;
        if (client->input_length < frame_length) return 0;
        if (handle_request(server, client, client->input + 4u, payload_length) != 0) return -1;
        client->last_activity_ms = clock_ms(CLOCK_MONOTONIC);
        const size_t remaining = client->input_length - frame_length;
        memmove(client->input, client->input + frame_length, remaining);
        client->input_length = remaining;
        if (client->query.phase != QUERY_NONE) break;
    }
    return 0;
}

static int service_query(watchdog_server *server, watchdog_client *client) {
    if (client->output_length != 0 || client->query.phase == QUERY_NONE) return 0;
    if (client->query.phase == QUERY_LATEST) {
        client->query.phase = QUERY_HISTORY;
        return queue_sample(
            client, client->query.request_id, WATCHDOG_MESSAGE_LATEST, &server->latest);
    }
    if (client->query.phase == QUERY_HISTORY) {
        watchdog_ring *ring = query_ring(server, client->query.resolution);
        if (ring == NULL) return -1;
        watchdog_sample samples[WATCHDOG_MAX_BATCH_SAMPLES];
        size_t sample_count = 0;
        size_t scanned = 0;
        while (client->query.cursor_bucket <= client->query.final_bucket
            && sample_count < WATCHDOG_MAX_BATCH_SAMPLES
            && scanned < WATCHDOG_QUERY_SCAN_MAX) {
            watchdog_sample sample;
            int result;
            if (client->query.resolution == WATCHDOG_RESOLUTION_RAW_1_SECOND
                && pending_read(server, client->query.cursor_bucket, &sample)) {
                result = 0;
            } else {
                result = watchdog_ring_read_bucket(ring, client->query.cursor_bucket, &sample);
            }
            ++client->query.cursor_bucket;
            ++scanned;
            if (result < 0) return -1;
            if (result == 0 && sample.unix_ms >= client->query.start_ms
                && sample.unix_ms <= client->query.end_ms) {
                samples[sample_count++] = sample;
            }
        }
        if (client->query.cursor_bucket > client->query.final_bucket) {
            client->query.phase = QUERY_COMPLETE;
        }
        if (sample_count != 0) {
            const size_t length = watchdog_pb_encode_history_batch(
                client->query.request_id,
                samples,
                sample_count,
                client->output + 4u,
                WATCHDOG_MAX_FRAME_BYTES);
            return finish_frame(client, length);
        }
    }
    if (client->query.phase == QUERY_COMPLETE) {
        const bool subscribe = client->query.subscribe;
        const uint64_t request_id = client->query.request_id;
        const uint64_t through = client->query.through_sequence;
        memset(&client->query, 0, sizeof(client->query));
        client->subscribed = subscribe;
        const size_t length = watchdog_pb_encode_history_complete(
            request_id, through, client->output + 4u, WATCHDOG_MAX_FRAME_BYTES);
        return finish_frame(client, length);
    }
    return 0;
}

static void service_clients(watchdog_server *server) {
    for (size_t index = 0;
         index < WATCHDOG_HARD_MAX_CONTROLLERS
            && index < server->config.max_controllers;
         ++index) {
        watchdog_client *client = &server->clients[index];
        if (client->state != CLIENT_READY || client->output_length != 0) continue;
        if (process_input(server, client) != 0
            || service_query(server, client) != 0
            || (client->output_length == 0 && client->missed_sequence != 0
                && queue_gap(server, client) != 0)) {
            client_reset(client);
        }
    }
}

static int flush_storage(watchdog_server *server) {
    for (size_t index = 0; index < server->pending_count; ++index) {
        if (watchdog_ring_write(&server->raw, &server->pending[index]) != 0) return -1;
    }
    if (server->pending_count != 0 && watchdog_ring_sync(&server->raw) != 0) return -1;
    if (server->minute_dirty && watchdog_ring_sync(&server->minute) != 0) return -1;
    if (server->quarter_dirty && watchdog_ring_sync(&server->quarter) != 0) return -1;
    server->pending_count = 0;
    server->minute_dirty = false;
    server->quarter_dirty = false;
    watchdog_ring_drop_cache(&server->raw);
    watchdog_ring_drop_cache(&server->minute);
    watchdog_ring_drop_cache(&server->quarter);
    return 0;
}

static int flush_storage_callback(void *context) {
    return flush_storage((watchdog_server *)context);
}

static int collect_sample(watchdog_server *server) {
    if (server->pending_count == WATCHDOG_PENDING_MAX && flush_storage(server) != 0) return -1;
    watchdog_sample sample;
    if (watchdog_sampler_take(&server->sampler, server->next_sequence, &sample) != 0) {
        return -1;
    }
    watchdog_gateway_metrics gateway;
    if (watchdog_gateway_metrics_read(
            server->config.gateway_metrics_path, sample.unix_ms, &gateway) == 0) {
        sample.flags |= WATCHDOG_SAMPLE_GATEWAY_AVAILABLE;
        sample.active_requests = gateway.active_requests;
        sample.connected_clients = gateway.connected_clients;
        sample.queued_requests = gateway.queued_requests;
        sample.requests_received = gateway.requests_received;
        sample.requests_admitted = gateway.requests_admitted;
        sample.requests_completed = gateway.requests_completed;
        sample.requests_failed = gateway.requests_failed;
        sample.requests_cancelled = gateway.requests_cancelled;
        sample.requests_retried = gateway.requests_retried;
        sample.input_tokens = gateway.input_tokens;
        sample.output_tokens = gateway.output_tokens;
        sample.cached_tokens = gateway.cached_tokens;
        sample.queue_milliseconds = gateway.queue_milliseconds;
        sample.ttft_milliseconds = gateway.ttft_milliseconds;
        sample.decode_milliseconds = gateway.decode_milliseconds;
        sample.exact_token_requests = gateway.exact_token_requests;
        sample.prefix_cache_hits = gateway.prefix_cache_hits;
        sample.usage_records_dropped = gateway.usage_records_dropped;
        sample.usage_write_errors = gateway.usage_write_errors;
    }
    ++server->next_sequence;
    server->pending[server->pending_count++] = sample;
    server->latest = sample;
    server->has_latest = true;

    watchdog_safety_result safety_results[WATCHDOG_SAFETY_MAX_TARGETS];
    size_t safety_result_count = 0u;
    if (watchdog_safety_supervisor_tick(
            &server->safety,
            &sample,
            flush_storage_callback,
            server,
            safety_results,
            &safety_result_count) != 0) return WATCHDOG_COLLECT_FATAL;
    for (size_t safety_index = 0u;
         safety_index < safety_result_count;
         ++safety_index) {
        watchdog_safety_result *safety_result = &safety_results[safety_index];
        const watchdog_event event = {
            .unix_ms = sample.unix_ms,
            .kind = safety_result->kind,
            .severity = safety_result->severity,
            .workload_id = sample.workload_id,
            .payload_json = safety_result->payload_json
        };
        if (watchdog_metadata_add_event(&server->metadata, &event, NULL) != 0) {
            return WATCHDOG_COLLECT_FATAL;
        }
    }

    watchdog_sample completed;
    if (watchdog_rollup_push(&server->minute_rollup, &sample, &completed)) {
        if (watchdog_ring_write(&server->minute, &completed) != 0) return -1;
        server->minute_dirty = true;
    }
    if (watchdog_rollup_push(&server->quarter_rollup, &sample, &completed)) {
        if (watchdog_ring_write(&server->quarter, &completed) != 0) return -1;
        server->quarter_dirty = true;
    }

    for (size_t index = 0;
         index < WATCHDOG_HARD_MAX_CONTROLLERS
            && index < server->config.max_controllers;
         ++index) {
        watchdog_client *client = &server->clients[index];
        if (client->state != CLIENT_READY || !client->subscribed
            || client->query.phase != QUERY_NONE) continue;
        if (client->output_length == 0 && client->missed_sequence == 0) {
            if (queue_sample(
                    client,
                    client->subscription_request_id,
                    WATCHDOG_MESSAGE_LIVE,
                    &sample) != 0) {
                client_reset(client);
            }
        } else if (client->missed_sequence == 0) {
            client->missed_sequence = sample.sequence;
        }
    }
    return 0;
}

static int tls_error_events(SSL *ssl, int result, short *wanted) {
    switch (SSL_get_error(ssl, result)) {
    case SSL_ERROR_WANT_READ: *wanted = POLLIN; return 0;
    case SSL_ERROR_WANT_WRITE: *wanted = POLLOUT; return 0;
    case SSL_ERROR_ZERO_RETURN: return -1;
    default: return -1;
    }
}

static int advance_handshake(watchdog_server *server, watchdog_client *client) {
    const int result = SSL_accept(client->ssl);
    if (result == 1) {
        X509 *peer = SSL_get1_peer_certificate(client->ssl);
        if (peer == NULL || SSL_get_verify_result(client->ssl) != X509_V_OK
            || peer_fingerprint(peer, client->controller_certificate_sha256) != 0
            || !watchdog_controller_authorized(
                &server->controllers, client->controller_certificate_sha256)) {
            X509_free(peer);
            return -1;
        }
        X509_free(peer);
        client->state = CLIENT_READY;
        client->last_activity_ms = clock_ms(CLOCK_MONOTONIC);
        client->read_want = POLLIN;
        client->write_want = POLLOUT;
        return 0;
    }
    return tls_error_events(client->ssl, result, &client->handshake_want);
}

static int read_client(watchdog_server *server, watchdog_client *client) {
    if (client->input_length == sizeof(client->input)) return -1;
    size_t count = 0;
    const int result = SSL_read_ex(
        client->ssl,
        client->input + client->input_length,
        sizeof(client->input) - client->input_length,
        &count);
    if (result == 1) {
        if (count == 0) return -1;
        client->input_length += count;
        client->read_want = POLLIN;
        return process_input(server, client);
    }
    return tls_error_events(client->ssl, result, &client->read_want);
}

static int write_client(watchdog_client *client) {
    size_t count = 0;
    const int result = SSL_write_ex(
        client->ssl,
        client->output + client->output_offset,
        client->output_length - client->output_offset,
        &count);
    if (result == 1) {
        if (count == 0) return -1;
        client->last_activity_ms = clock_ms(CLOCK_MONOTONIC);
        client->output_offset += count;
        client->write_want = POLLOUT;
        if (client->output_offset == client->output_length) {
            client->output_length = 0;
            client->output_offset = 0;
        }
        return 0;
    }
    return tls_error_events(client->ssl, result, &client->write_want);
}

static int make_nonblocking_cloexec(int fd) {
    const int status_flags = fcntl(fd, F_GETFL, 0);
    const int descriptor_flags = fcntl(fd, F_GETFD, 0);
    if (status_flags < 0 || descriptor_flags < 0
        || fcntl(fd, F_SETFL, status_flags | O_NONBLOCK) != 0
        || fcntl(fd, F_SETFD, descriptor_flags | FD_CLOEXEC) != 0) return -1;
    return 0;
}

static void accept_clients(watchdog_server *server) {
    for (;;) {
        const int fd = accept(server->listener, NULL, NULL);
        if (fd < 0) {
            if (errno == EINTR) continue;
            if (errno != EAGAIN && errno != EWOULDBLOCK) perror("watchdog: accept");
            return;
        }
        if (make_nonblocking_cloexec(fd) != 0) {
            close(fd);
            continue;
        }
        watchdog_client *client = NULL;
        for (size_t index = 0;
             index < WATCHDOG_HARD_MAX_CONTROLLERS
                && index < server->config.max_controllers;
             ++index) {
            if (server->clients[index].state == CLIENT_UNUSED) {
                client = &server->clients[index];
                break;
            }
        }
        if (client == NULL) {
            close(fd);
            continue;
        }
        client->fd = fd;
        client->ssl = SSL_new(server->tls);
        if (client->ssl == NULL || SSL_set_fd(client->ssl, fd) != 1) {
            client_reset(client);
            continue;
        }
        SSL_set_accept_state(client->ssl);
        client->state = CLIENT_HANDSHAKE;
        client->handshake_want = POLLIN;
        client->handshake_deadline_ms = clock_ms(CLOCK_MONOTONIC)
            + WATCHDOG_TLS_HANDSHAKE_TIMEOUT_MS;
    }
}

static int open_listener(const watchdog_config *config) {
    char port[16];
    snprintf(port, sizeof(port), "%u", config->port);
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    struct addrinfo *addresses = NULL;
    const int status = getaddrinfo(config->listen_address, port, &hints, &addresses);
    if (status != 0) {
        fprintf(stderr, "watchdog: getaddrinfo: %s\n", gai_strerror(status));
        return -1;
    }
    int listener = -1;
    for (const struct addrinfo *address = addresses; address != NULL; address = address->ai_next) {
        listener = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
        if (listener < 0) continue;
        if (make_nonblocking_cloexec(listener) != 0) {
            close(listener);
            listener = -1;
            continue;
        }
        const int yes = 1;
        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        if (bind(listener, address->ai_addr, address->ai_addrlen) == 0
            && listen(listener, (int)config->max_controllers) == 0) break;
        close(listener);
        listener = -1;
    }
    freeaddrinfo(addresses);
    return listener;
}

static SSL_CTX *open_tls(const watchdog_config *config) {
    SSL_CTX *context = SSL_CTX_new(TLS_server_method());
    if (context == NULL) return NULL;
    if (SSL_CTX_set_min_proto_version(context, TLS1_3_VERSION) != 1
        || SSL_CTX_use_certificate_chain_file(context, config->certificate_path) != 1
        || SSL_CTX_use_PrivateKey_file(context, config->private_key_path, SSL_FILETYPE_PEM) != 1
        || SSL_CTX_check_private_key(context) != 1
        || SSL_CTX_load_verify_locations(context, config->controller_ca_path, NULL) != 1) {
        SSL_CTX_free(context);
        return NULL;
    }
    SSL_CTX_set_verify(context, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_verify_depth(context, 2);
    SSL_CTX_set_session_cache_mode(context, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_mode(context, SSL_MODE_ENABLE_PARTIAL_WRITE);
    return context;
}

static int make_path(char output[WATCHDOG_PATH_MAX], const char *directory, const char *name) {
    const int length = snprintf(output, WATCHDOG_PATH_MAX, "%s/%s", directory, name);
    return length > 0 && length < WATCHDOG_PATH_MAX ? 0 : -1;
}

static void add_server_event(watchdog_server *server, const char *kind) {
    const watchdog_event event = {
        .unix_ms = clock_ms(CLOCK_REALTIME),
        .kind = kind,
        .severity = 0,
        .workload_id = 0,
        .payload_json = ""
    };
    watchdog_metadata_add_event(&server->metadata, &event, NULL);
}

static int open_storage(watchdog_server *server) {
    if (mkdir(server->config.data_directory, 0750) != 0 && errno != EEXIST) return -1;
    char raw[WATCHDOG_PATH_MAX];
    char minute[WATCHDOG_PATH_MAX];
    char quarter[WATCHDOG_PATH_MAX];
    char metadata[WATCHDOG_PATH_MAX];
    if (make_path(raw, server->config.data_directory, "raw.ring") != 0
        || make_path(minute, server->config.data_directory, "minute.ring") != 0
        || make_path(quarter, server->config.data_directory, "quarter-hour.ring") != 0
        || make_path(metadata, server->config.data_directory, "metadata.sqlite3") != 0) return -1;
    if (watchdog_ring_open(&server->raw, raw, 1000u, WATCHDOG_RAW_CAPACITY) != 0
        || watchdog_ring_open(&server->minute, minute, 60000u, WATCHDOG_MINUTE_CAPACITY) != 0
        || watchdog_ring_open(&server->quarter, quarter, 900000u, WATCHDOG_QUARTER_CAPACITY) != 0
        || watchdog_metadata_open(&server->metadata, metadata) != 0) return -1;
    watchdog_sample recovered;
    const int latest = watchdog_ring_latest(&server->raw, &recovered);
    if (latest < 0) return -1;
    if (latest == 0) {
        server->latest = recovered;
        server->has_latest = true;
        server->next_sequence = recovered.sequence + 1u;
    } else {
        server->next_sequence = 1u;
    }
    watchdog_ring_drop_cache(&server->raw);
    return 0;
}

static void close_server(watchdog_server *server) {
    if (server == NULL) return;
    for (size_t index = 0; index < WATCHDOG_HARD_MAX_CONTROLLERS; ++index) {
        client_reset(&server->clients[index]);
    }
    if (server->listener >= 0) close(server->listener);
    if (server->started && server->metadata.database != NULL) {
        add_server_event(server, "server.stop");
    }
    watchdog_metadata_close(&server->metadata);
    watchdog_ring_close(&server->raw);
    watchdog_ring_close(&server->minute);
    watchdog_ring_close(&server->quarter);
    watchdog_sampler_close(&server->sampler);
    watchdog_safety_supervisor_close(&server->safety);
    if (server->tls != NULL) SSL_CTX_free(server->tls);
}

static int validate_config(const watchdog_config *config) {
    if (config == NULL || config->listen_address == NULL || config->data_directory == NULL
        || config->certificate_path == NULL || config->private_key_path == NULL
        || config->controller_ca_path == NULL || config->port == 0
        || config->controller_registry_path == NULL
        || config->site_state_path == NULL
        || config->gateway_metrics_path == NULL
        || config->max_controllers == 0
        || config->max_controllers > WATCHDOG_HARD_MAX_CONTROLLERS
        || config->sample_interval_ms != 1000u
        || config->flush_interval_ms < config->sample_interval_ms
        || config->flush_interval_ms > 60000u
        || config->flush_interval_ms / config->sample_interval_ms >= WATCHDOG_PENDING_MAX
        || config->safety.state_path == NULL
        || watchdog_safety_validate_thresholds(&config->safety.thresholds) != 0) {
        return -1;
    }
    return 0;
}

static int run_loop(watchdog_server *server) {
    while (!stop_requested) {
        if (reload_requested) {
            watchdog_controller_registry replacement;
            if (watchdog_controller_registry_load(
                    server->config.controller_registry_path, &replacement) != 0
                || strcmp(
                    replacement.installation_id,
                    server->public_state.installation_id) != 0) return -1;
            server->controllers = replacement;
            for (size_t index = 0; index < WATCHDOG_HARD_MAX_CONTROLLERS; ++index) {
                watchdog_client *client = &server->clients[index];
                if (client->state == CLIENT_READY
                    && !watchdog_controller_authorized(
                        &server->controllers, client->controller_certificate_sha256)) {
                    client_reset(client);
                }
            }
            reload_requested = 0;
        }
        service_clients(server);
        const uint64_t before_poll = clock_ms(CLOCK_MONOTONIC);
        struct pollfd descriptors[1u + WATCHDOG_HARD_MAX_CONTROLLERS];
        descriptors[0] = (struct pollfd){.fd = server->listener, .events = POLLIN};
        bool query_ready = false;
        for (size_t index = 0;
             index < WATCHDOG_HARD_MAX_CONTROLLERS
                && index < server->config.max_controllers;
             ++index) {
            watchdog_client *client = &server->clients[index];
            short events = 0;
            if (client->state == CLIENT_HANDSHAKE) {
                events = client->handshake_want;
                if (before_poll >= client->handshake_deadline_ms) client_reset(client);
            } else if (client->state == CLIENT_READY) {
                if (before_poll - client->last_activity_ms >= WATCHDOG_CLIENT_IDLE_TIMEOUT_MS) {
                    client_reset(client);
                    descriptors[index + 1u] = (struct pollfd){.fd = -1, .events = 0};
                    continue;
                }
                if (client->input_length < sizeof(client->input)) events |= client->read_want;
                if (client->output_length != 0) events |= client->write_want;
                if (client->query.phase != QUERY_NONE && client->output_length == 0) query_ready = true;
            }
            descriptors[index + 1u] = (struct pollfd){.fd = client->fd, .events = events};
        }
        uint64_t deadline = server->next_sample_ms < server->next_flush_ms
            ? server->next_sample_ms : server->next_flush_ms;
        int timeout = deadline <= before_poll ? 0 : (int)(deadline - before_poll);
        if (query_ready) timeout = 0;
        const int ready = poll(
            descriptors, 1u + server->config.max_controllers, timeout);
        if (ready < 0 && errno != EINTR) return -1;
        if (ready > 0 && (descriptors[0].revents & POLLIN) != 0) accept_clients(server);
        for (size_t index = 0;
             index < WATCHDOG_HARD_MAX_CONTROLLERS
                && index < server->config.max_controllers;
             ++index) {
            watchdog_client *client = &server->clients[index];
            const short events = descriptors[index + 1u].revents;
            if (client->state == CLIENT_UNUSED || events == 0) continue;
            if ((events & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
                client_reset(client);
                continue;
            }
            int status = 0;
            if (client->state == CLIENT_HANDSHAKE && (events & client->handshake_want) != 0) {
                status = advance_handshake(server, client);
            } else if (client->state == CLIENT_READY) {
                if (client->output_length != 0 && (events & client->write_want) != 0) {
                    status = write_client(client);
                }
                if (status == 0 && client->state == CLIENT_READY
                    && (events & client->read_want) != 0) {
                    status = read_client(server, client);
                }
            }
            if (status != 0) client_reset(client);
        }

        const uint64_t now = clock_ms(CLOCK_MONOTONIC);
        if (now >= server->next_sample_ms) {
            const int sample_result = collect_sample(server);
            if (sample_result == WATCHDOG_COLLECT_FATAL) return -1;
            if (sample_result != 0
                && (server->last_sample_error_ms == 0
                    || now - server->last_sample_error_ms >= 60000u)) {
                perror("watchdog: sample");
                server->last_sample_error_ms = now;
            }
            server->next_sample_ms += server->config.sample_interval_ms;
            if (server->next_sample_ms <= now) {
                server->next_sample_ms = now + server->config.sample_interval_ms;
            }
        }
        if (now >= server->next_flush_ms) {
            if (flush_storage(server) != 0) return -1;
            server->next_flush_ms = now + server->config.flush_interval_ms;
        }
    }
    return 0;
}

int watchdog_server_run(const watchdog_config *config) {
    if (validate_config(config) != 0) {
        fprintf(stderr, "watchdog: invalid configuration\n");
        return -1;
    }
    watchdog_server *server = calloc(1, sizeof(*server));
    if (server == NULL) return -1;
    server->config = *config;
    server->listener = -1;
    server->raw.fd = -1;
    server->minute.fd = -1;
    server->quarter.fd = -1;
    clients_init(server);
    watchdog_rollup_init(&server->minute_rollup, 60000u);
    watchdog_rollup_init(&server->quarter_rollup, 900000u);

    int result = -1;
    if (load_public_state(config->site_state_path, &server->public_state) != 0) {
        fprintf(stderr, "watchdog: Let's Infer state descriptor is invalid or inaccessible\n");
        goto done;
    }
    if (watchdog_controller_registry_load(
            config->controller_registry_path, &server->controllers) != 0
        || strcmp(
            server->controllers.installation_id,
            server->public_state.installation_id) != 0) {
        fprintf(stderr, "watchdog: controller registry is invalid or inaccessible\n");
        goto done;
    }
    server->tls = open_tls(config);
    if (server->tls == NULL) {
        log_openssl("TLS setup failed");
        goto done;
    }
    if (open_storage(server) != 0) {
        fprintf(stderr, "watchdog: storage setup failed: %s\n", strerror(errno));
        goto done;
    }
    if (watchdog_sampler_open(&server->sampler) != 0) {
        fprintf(stderr, "watchdog: sampler setup failed\n");
        goto done;
    }
    if (watchdog_safety_supervisor_open(&server->safety, &config->safety) != 0) {
        fprintf(stderr, "watchdog: protection setup failed: %s\n", strerror(errno));
        goto done;
    }
    server->listener = open_listener(config);
    if (server->listener < 0) {
        fprintf(stderr, "watchdog: listener setup failed: %s\n", strerror(errno));
        goto done;
    }
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, request_stop);
    signal(SIGTERM, request_stop);
    signal(SIGHUP, request_reload);
    stop_requested = 0;
    reload_requested = 0;
    const uint64_t now = clock_ms(CLOCK_MONOTONIC);
    server->next_sample_ms = now;
    server->next_flush_ms = now + config->flush_interval_ms;
    server->started = true;
    add_server_event(server, "server.start");
    fprintf(stderr, "watchdog: listening on %s:%u\n", config->listen_address, config->port);
    result = run_loop(server);
    if (flush_storage(server) != 0) result = -1;

done:
    close_server(server);
    free(server);
    return result;
}
