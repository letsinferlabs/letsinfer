#include "watchdog/gateway.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define GATEWAY_METRICS_MAX_BYTES 4096u
#define GATEWAY_METRICS_MAX_AGE_MS 5000u
#define GATEWAY_METRICS_FIELDS 19u

typedef struct metric_field {
    const char *name;
    size_t offset;
    bool value_is_u32;
} metric_field;

#define FIELD_U32(name) {#name, offsetof(watchdog_gateway_metrics, name), true}
#define FIELD_U64(name) {#name, offsetof(watchdog_gateway_metrics, name), false}

static const metric_field fields[GATEWAY_METRICS_FIELDS] = {
    FIELD_U32(active_requests),
    FIELD_U32(connected_clients),
    FIELD_U32(queued_requests),
    FIELD_U64(requests_received),
    FIELD_U64(requests_admitted),
    FIELD_U64(requests_completed),
    FIELD_U64(requests_failed),
    FIELD_U64(requests_cancelled),
    FIELD_U64(requests_retried),
    FIELD_U64(input_tokens),
    FIELD_U64(output_tokens),
    FIELD_U64(cached_tokens),
    FIELD_U64(queue_milliseconds),
    FIELD_U64(ttft_milliseconds),
    FIELD_U64(decode_milliseconds),
    FIELD_U64(exact_token_requests),
    FIELD_U64(prefix_cache_hits),
    FIELD_U64(usage_records_dropped),
    FIELD_U64(usage_write_errors)
};

static int read_private_file(
    const char *path,
    uint64_t now_unix_ms,
    char buffer[GATEWAY_METRICS_MAX_BYTES + 1u]
) {
    const int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) return errno == ENOENT ? 1 : -1;
    struct stat details;
    if (fstat(descriptor, &details) != 0
        || !S_ISREG(details.st_mode)
        || details.st_uid != geteuid()
        || (details.st_mode & 077u) != 0
        || details.st_size <= 0
        || details.st_size > (off_t)GATEWAY_METRICS_MAX_BYTES) {
        close(descriptor);
        return -1;
    }
    const uint64_t modified_ms = (uint64_t)details.st_mtime * 1000u;
    if (modified_ms > now_unix_ms + 1000u
        || now_unix_ms - modified_ms > GATEWAY_METRICS_MAX_AGE_MS) {
        close(descriptor);
        return 1;
    }
    size_t used = 0;
    while (used < (size_t)details.st_size) {
        const ssize_t count = read(descriptor, buffer + used, (size_t)details.st_size - used);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            close(descriptor);
            return -1;
        }
        used += (size_t)count;
    }
    close(descriptor);
    buffer[used] = '\0';
    return 0;
}

static int parse_value(const char *text, uint64_t *value) {
    if (text == NULL || *text == '\0' || *text == '+' || *text == '-') return -1;
    char *end = NULL;
    errno = 0;
    const unsigned long long parsed = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0') return -1;
    *value = (uint64_t)parsed;
    return 0;
}

int watchdog_gateway_metrics_read(
    const char *path,
    uint64_t now_unix_ms,
    watchdog_gateway_metrics *metrics
) {
    if (path == NULL || metrics == NULL || now_unix_ms == 0) return -1;
    memset(metrics, 0, sizeof(*metrics));
    char buffer[GATEWAY_METRICS_MAX_BYTES + 1u];
    const int status = read_private_file(path, now_unix_ms, buffer);
    if (status != 0) return status;
    bool version = false;
    bool seen[GATEWAY_METRICS_FIELDS] = {false};
    size_t count = 0;
    char *save = NULL;
    for (char *line = strtok_r(buffer, "\n", &save); line != NULL;
         line = strtok_r(NULL, "\n", &save)) {
        char *separator = strchr(line, '=');
        if (separator == NULL || separator == line || strchr(separator + 1, '=') != NULL) {
            return -1;
        }
        *separator = '\0';
        const char *value = separator + 1;
        if (strcmp(line, "version") == 0) {
            if (version || strcmp(value, "2") != 0) return -1;
            version = true;
            continue;
        }
        size_t index = 0;
        while (index < GATEWAY_METRICS_FIELDS && strcmp(line, fields[index].name) != 0) {
            ++index;
        }
        if (index == GATEWAY_METRICS_FIELDS || seen[index]) return -1;
        uint64_t parsed = 0;
        if (parse_value(value, &parsed) != 0
            || (fields[index].value_is_u32 && parsed > UINT32_MAX)) return -1;
        uint8_t *target = (uint8_t *)metrics + fields[index].offset;
        if (fields[index].value_is_u32) {
            const uint32_t narrowed = (uint32_t)parsed;
            memcpy(target, &narrowed, sizeof(narrowed));
        } else {
            memcpy(target, &parsed, sizeof(parsed));
        }
        seen[index] = true;
        ++count;
    }
    if (!version || count != GATEWAY_METRICS_FIELDS) return -1;
    return 0;
}
