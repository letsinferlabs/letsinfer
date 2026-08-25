#include "watchdog/protobuf.h"

#include <stdbool.h>
#include <string.h>

typedef struct pb_writer {
    uint8_t *data;
    size_t capacity;
    size_t length;
    bool failed;
} pb_writer;

typedef struct pb_reader {
    const uint8_t *data;
    size_t length;
    size_t offset;
} pb_reader;

static void write_byte(pb_writer *writer, uint8_t value) {
    if (writer->failed || writer->length >= writer->capacity) {
        writer->failed = true;
        return;
    }
    writer->data[writer->length++] = value;
}

static void write_raw(pb_writer *writer, const void *data, size_t length) {
    if (writer->failed || length > writer->capacity - writer->length) {
        writer->failed = true;
        return;
    }
    memcpy(writer->data + writer->length, data, length);
    writer->length += length;
}

static void write_varint(pb_writer *writer, uint64_t value) {
    while (value >= UINT64_C(0x80)) {
        write_byte(writer, (uint8_t)(value | UINT64_C(0x80)));
        value >>= 7u;
    }
    write_byte(writer, (uint8_t)value);
}

static void write_key(pb_writer *writer, uint32_t field, uint8_t wire_type) {
    write_varint(writer, ((uint64_t)field << 3u) | wire_type);
}

static void write_uint(pb_writer *writer, uint32_t field, uint64_t value) {
    write_key(writer, field, 0);
    write_varint(writer, value);
}

static uint64_t zigzag32(int32_t value) {
    return ((uint32_t)value << 1u) ^ (uint32_t)(value >> 31);
}

static void write_sint32(pb_writer *writer, uint32_t field, int32_t value) {
    write_uint(writer, field, zigzag32(value));
}

static void write_message(
    pb_writer *writer,
    uint32_t field,
    const uint8_t *message,
    size_t length
) {
    write_key(writer, field, 2);
    write_varint(writer, length);
    write_raw(writer, message, length);
}

static size_t encode_gpu(
    const watchdog_sample *sample,
    uint8_t *output,
    size_t capacity
) {
    pb_writer writer = {output, capacity, 0, false};
    write_uint(&writer, 1, sample->gpu_percent);
    write_uint(&writer, 2, sample->gpu_memory_percent);

    uint8_t packed[WATCHDOG_GPU_ENGINES * 2u];
    pb_writer packed_writer = {packed, sizeof(packed), 0, false};
    for (size_t index = 0; index < WATCHDOG_GPU_ENGINES; ++index) {
        write_varint(&packed_writer, sample->gpu_engine_percent[index]);
    }
    if (packed_writer.failed) {
        return 0;
    }
    write_message(&writer, 3, packed, packed_writer.length);
    write_sint32(&writer, 4, sample->gpu_temp_deci_c);
    write_uint(&writer, 5, sample->power_deci_w);
    write_uint(&writer, 6, sample->gpu_clock_mhz);
    write_uint(&writer, 7, sample->vram_clock_mhz);
    return writer.failed ? 0 : writer.length;
}

static size_t encode_telemetry(
    const watchdog_sample *sample,
    uint8_t *output,
    size_t capacity
) {
    pb_writer writer = {output, capacity, 0, false};
    write_uint(&writer, 1, sample->sequence);
    write_uint(&writer, 2, sample->unix_ms);
    write_uint(&writer, 3, sample->monotonic_ms);
    write_uint(&writer, 4, sample->flags);
    write_uint(&writer, 5, sample->cpu_percent);

    uint8_t packed[WATCHDOG_MAX_CPU_CORES * 2u];
    pb_writer packed_writer = {packed, sizeof(packed), 0, false};
    for (size_t index = 0; index < sample->cpu_core_count; ++index) {
        write_varint(&packed_writer, sample->cpu_core_percent[index]);
    }
    if (packed_writer.failed) {
        return 0;
    }
    write_message(&writer, 6, packed, packed_writer.length);
    write_uint(&writer, 7, sample->memory_percent);
    write_uint(&writer, 8, sample->disk_percent);

    uint8_t gpu[64];
    const size_t gpu_length = encode_gpu(sample, gpu, sizeof(gpu));
    if (gpu_length == 0) {
        return 0;
    }
    write_message(&writer, 9, gpu, gpu_length);
    write_sint32(&writer, 10, sample->system_temp_deci_c);
    write_sint32(&writer, 11, sample->nvme_temp_deci_c);
    write_uint(&writer, 12, sample->load1_centi);
    write_uint(&writer, 13, sample->memory_used_mib);
    write_uint(&writer, 14, sample->memory_total_mib);
    write_uint(&writer, 15, sample->disk_used_mib);
    write_uint(&writer, 16, sample->disk_total_mib);
    write_uint(&writer, 17, sample->network_rx_kib_s);
    write_uint(&writer, 18, sample->network_tx_kib_s);
    write_uint(&writer, 19, sample->disk_read_kib_s);
    write_uint(&writer, 20, sample->disk_write_kib_s);
    write_uint(&writer, 21, sample->workload_id);
    write_uint(&writer, 22, sample->workload_type);
    write_uint(&writer, 23, sample->cpu_clock_mhz);
    write_uint(&writer, 24, sample->system_ram_clock_mhz);
    write_uint(&writer, 25, sample->active_requests);
    write_uint(&writer, 26, sample->queued_requests);
    write_uint(&writer, 27, sample->requests_received);
    write_uint(&writer, 28, sample->requests_admitted);
    write_uint(&writer, 29, sample->requests_completed);
    write_uint(&writer, 30, sample->requests_failed);
    write_uint(&writer, 31, sample->requests_cancelled);
    write_uint(&writer, 32, sample->requests_retried);
    write_uint(&writer, 33, sample->input_tokens);
    write_uint(&writer, 34, sample->output_tokens);
    write_uint(&writer, 35, sample->cached_tokens);
    write_uint(&writer, 36, sample->queue_milliseconds);
    write_uint(&writer, 37, sample->ttft_milliseconds);
    write_uint(&writer, 38, sample->decode_milliseconds);
    write_uint(&writer, 39, sample->exact_token_requests);
    write_uint(&writer, 40, sample->prefix_cache_hits);
    write_uint(&writer, 41, sample->usage_records_dropped);
    write_uint(&writer, 42, sample->usage_write_errors);
    write_uint(&writer, 43, sample->connected_clients);
    return writer.failed ? 0 : writer.length;
}

static size_t encode_envelope(
    uint64_t request_id,
    uint32_t payload_field,
    const uint8_t *payload,
    size_t payload_length,
    uint8_t *output,
    size_t capacity
) {
    pb_writer writer = {output, capacity, 0, false};
    if (request_id != 0) {
        write_uint(&writer, 1, request_id);
    }
    write_message(&writer, payload_field, payload, payload_length);
    return writer.failed ? 0 : writer.length;
}

static bool read_varint(pb_reader *reader, uint64_t *value) {
    uint64_t result = 0;
    for (unsigned shift = 0; shift < 64; shift += 7) {
        if (reader->offset >= reader->length) {
            return false;
        }
        const uint8_t byte = reader->data[reader->offset++];
        result |= (uint64_t)(byte & 0x7fu) << shift;
        if ((byte & 0x80u) == 0) {
            *value = result;
            return true;
        }
    }
    return false;
}

static bool read_slice(pb_reader *reader, pb_reader *slice) {
    uint64_t length = 0;
    if (!read_varint(reader, &length)
        || length > SIZE_MAX
        || (size_t)length > reader->length - reader->offset) {
        return false;
    }
    slice->data = reader->data + reader->offset;
    slice->length = (size_t)length;
    slice->offset = 0;
    reader->offset += (size_t)length;
    return true;
}

static bool skip_field(pb_reader *reader, uint8_t wire_type) {
    uint64_t ignored = 0;
    pb_reader slice;
    switch (wire_type) {
    case 0:
        return read_varint(reader, &ignored);
    case 1:
        if (reader->length - reader->offset < 8) return false;
        reader->offset += 8;
        return true;
    case 2:
        return read_slice(reader, &slice);
    case 5:
        if (reader->length - reader->offset < 4) return false;
        reader->offset += 4;
        return true;
    default:
        return false;
    }
}

static bool decode_subscribe(pb_reader *reader, watchdog_request *request) {
    while (reader->offset < reader->length) {
        uint64_t key = 0;
        uint64_t value = 0;
        if (!read_varint(reader, &key)) return false;
        if ((key >> 3u) == 1 && (key & 7u) == 0) {
            if (!read_varint(reader, &value) || value > UINT32_MAX) return false;
            request->history_seconds = (uint32_t)value;
        } else if (!skip_field(reader, (uint8_t)(key & 7u))) {
            return false;
        }
    }
    return true;
}

static bool decode_query(pb_reader *reader, watchdog_request *request) {
    while (reader->offset < reader->length) {
        uint64_t key = 0;
        uint64_t value = 0;
        if (!read_varint(reader, &key)) return false;
        const uint32_t field = (uint32_t)(key >> 3u);
        if ((key & 7u) == 0 && field >= 1 && field <= 3) {
            if (!read_varint(reader, &value)) return false;
            if (field == 1) request->start_unix_ms = value;
            if (field == 2) request->end_unix_ms = value;
            if (field == 3 && value <= WATCHDOG_RESOLUTION_15_MINUTES) {
                request->resolution = (watchdog_resolution)value;
            }
        } else if (!skip_field(reader, (uint8_t)(key & 7u))) {
            return false;
        }
    }
    return request->end_unix_ms >= request->start_unix_ms
        && request->resolution != WATCHDOG_RESOLUTION_UNSPECIFIED;
}

static bool decode_ping(pb_reader *reader, watchdog_request *request) {
    while (reader->offset < reader->length) {
        uint64_t key = 0;
        if (!read_varint(reader, &key)) return false;
        if ((key >> 3u) == 1 && (key & 7u) == 0) {
            if (!read_varint(reader, &request->nonce)) return false;
        } else if (!skip_field(reader, (uint8_t)(key & 7u))) {
            return false;
        }
    }
    return true;
}

int watchdog_pb_decode_request(
    const uint8_t *payload,
    size_t payload_length,
    watchdog_request *request
) {
    if (payload == NULL || request == NULL || payload_length > WATCHDOG_MAX_FRAME_BYTES) {
        return -1;
    }
    memset(request, 0, sizeof(*request));
    pb_reader reader = {payload, payload_length, 0};
    while (reader.offset < reader.length) {
        uint64_t key = 0;
        if (!read_varint(&reader, &key)) return -1;
        const uint32_t field = (uint32_t)(key >> 3u);
        const uint8_t wire = (uint8_t)(key & 7u);
        if (field == 1 && wire == 0) {
            if (!read_varint(&reader, &request->request_id)) return -1;
            continue;
        }
        if (field >= 10 && field <= 15 && wire == 2) {
            pb_reader nested;
            if (!read_slice(&reader, &nested)) return -1;
            switch (field) {
            case 10:
                request->kind = WATCHDOG_REQUEST_GET_LATEST;
                break;
            case 11:
                request->kind = WATCHDOG_REQUEST_SUBSCRIBE;
                if (!decode_subscribe(&nested, request)) return -1;
                break;
            case 12:
                request->kind = WATCHDOG_REQUEST_QUERY_RANGE;
                if (!decode_query(&nested, request)) return -1;
                break;
            case 13:
                request->kind = WATCHDOG_REQUEST_GET_CAPABILITIES;
                break;
            case 14:
                request->kind = WATCHDOG_REQUEST_PING;
                if (!decode_ping(&nested, request)) return -1;
                break;
            case 15:
                request->kind = WATCHDOG_REQUEST_GET_SITE_STATUS;
                break;
            default:
                return -1;
            }
            continue;
        }
        if (!skip_field(&reader, wire)) return -1;
    }
    return request->kind == WATCHDOG_REQUEST_INVALID ? -1 : 0;
}

size_t watchdog_pb_encode_sample(
    uint64_t request_id,
    watchdog_sample_message_kind kind,
    const watchdog_sample *sample,
    uint8_t *output,
    size_t capacity
) {
    if (sample == NULL || output == NULL
        || (kind != WATCHDOG_MESSAGE_LATEST && kind != WATCHDOG_MESSAGE_LIVE)) {
        return 0;
    }
    uint8_t telemetry[384];
    const size_t length = encode_telemetry(sample, telemetry, sizeof(telemetry));
    if (length == 0) return 0;
    return encode_envelope(request_id, (uint32_t)kind, telemetry, length, output, capacity);
}

size_t watchdog_pb_encode_history_batch(
    uint64_t request_id,
    const watchdog_sample *samples,
    size_t sample_count,
    uint8_t *output,
    size_t capacity
) {
    if (samples == NULL || output == NULL || sample_count == 0
        || sample_count > WATCHDOG_MAX_BATCH_SAMPLES) {
        return 0;
    }
    uint8_t batch[WATCHDOG_MAX_FRAME_BYTES - 32u];
    pb_writer writer = {batch, sizeof(batch), 0, false};
    for (size_t index = 0; index < sample_count; ++index) {
        uint8_t telemetry[384];
        const size_t length = encode_telemetry(&samples[index], telemetry, sizeof(telemetry));
        if (length == 0) return 0;
        write_message(&writer, 1, telemetry, length);
    }
    if (writer.failed) return 0;
    return encode_envelope(request_id, 11, batch, writer.length, output, capacity);
}

size_t watchdog_pb_encode_history_complete(
    uint64_t request_id,
    uint64_t through_sequence,
    uint8_t *output,
    size_t capacity
) {
    uint8_t message[16];
    pb_writer writer = {message, sizeof(message), 0, false};
    write_uint(&writer, 1, through_sequence);
    return writer.failed ? 0
        : encode_envelope(request_id, 12, message, writer.length, output, capacity);
}

size_t watchdog_pb_encode_capabilities(
    uint64_t request_id,
    uint32_t sample_interval_ms,
    uint32_t flush_interval_ms,
    uint32_t physical_gpu_count,
    uint8_t *output,
    size_t capacity
) {
    uint8_t message[64];
    pb_writer writer = {message, sizeof(message), 0, false};
    write_uint(&writer, 1, WATCHDOG_PROTOCOL_VERSION);
    write_uint(&writer, 2, sample_interval_ms);
    write_uint(&writer, 3, flush_interval_ms);
    write_uint(&writer, 4, WATCHDOG_MAX_CPU_CORES);
    write_uint(&writer, 5, WATCHDOG_RESOLUTION_RAW_1_SECOND);
    write_uint(&writer, 5, WATCHDOG_RESOLUTION_1_MINUTE);
    write_uint(&writer, 5, WATCHDOG_RESOLUTION_15_MINUTES);
    write_uint(&writer, 6, 1);
    write_uint(&writer, 7, physical_gpu_count);
    return writer.failed ? 0
        : encode_envelope(request_id, 14, message, writer.length, output, capacity);
}

size_t watchdog_pb_encode_gap(
    uint64_t request_id,
    uint64_t first_missing_sequence,
    uint64_t latest_sequence,
    uint8_t *output,
    size_t capacity
) {
    uint8_t message[32];
    pb_writer writer = {message, sizeof(message), 0, false};
    write_uint(&writer, 1, first_missing_sequence);
    write_uint(&writer, 2, latest_sequence);
    return writer.failed ? 0
        : encode_envelope(request_id, 15, message, writer.length, output, capacity);
}

size_t watchdog_pb_encode_error(
    uint64_t request_id,
    uint32_t code,
    const char *message,
    uint8_t *output,
    size_t capacity
) {
    if (message == NULL) return 0;
    uint8_t body[512];
    pb_writer writer = {body, sizeof(body), 0, false};
    write_uint(&writer, 1, code);
    write_message(&writer, 2, (const uint8_t *)message, strlen(message));
    return writer.failed ? 0
        : encode_envelope(request_id, 16, body, writer.length, output, capacity);
}

size_t watchdog_pb_encode_pong(
    uint64_t request_id,
    uint64_t nonce,
    uint8_t *output,
    size_t capacity
) {
    uint8_t message[16];
    pb_writer writer = {message, sizeof(message), 0, false};
    write_uint(&writer, 1, nonce);
    return writer.failed ? 0
        : encode_envelope(request_id, 17, message, writer.length, output, capacity);
}

size_t watchdog_pb_encode_site_status(
    uint64_t request_id,
    const watchdog_site_status *status,
    uint8_t *output,
    size_t capacity
) {
    if (status == NULL || output == NULL || status->installation_id == NULL
        || status->release == NULL
        || status->model == NULL || status->engine == NULL
        || status->runtime_name == NULL || status->runtime_version == NULL
        || status->manifest_sha256 == NULL || status->cache_provider == NULL
        || status->service_state == NULL || status->engine_state == NULL
        || status->protection_phase == NULL || status->container_name == NULL) {
        return 0;
    }
    uint8_t message[2304];
    pb_writer writer = {message, sizeof(message), 0, false};
    write_message(&writer, 1, (const uint8_t *)status->release, strlen(status->release));
    write_message(&writer, 2, (const uint8_t *)status->model, strlen(status->model));
    write_message(&writer, 3, (const uint8_t *)status->engine, strlen(status->engine));
    write_message(&writer, 4, (const uint8_t *)status->runtime_name, strlen(status->runtime_name));
    write_message(&writer, 5, (const uint8_t *)status->runtime_version, strlen(status->runtime_version));
    write_message(&writer, 6, (const uint8_t *)status->manifest_sha256, strlen(status->manifest_sha256));
    write_message(&writer, 7, (const uint8_t *)status->cache_provider, strlen(status->cache_provider));
    write_uint(&writer, 8, status->cache_persistent);
    write_uint(&writer, 9, status->inference_port);
    write_uint(&writer, 10, status->max_connections);
    write_uint(&writer, 11, status->max_active_requests);
    write_uint(&writer, 12, status->max_context_tokens);
    write_message(&writer, 13, (const uint8_t *)status->service_state, strlen(status->service_state));
    write_message(&writer, 14, (const uint8_t *)status->engine_state, strlen(status->engine_state));
    write_message(&writer, 15, (const uint8_t *)status->protection_phase, strlen(status->protection_phase));
    write_uint(&writer, 16, status->protection_armed);
    write_uint(&writer, 17, status->trip_latched);
    write_message(&writer, 18, (const uint8_t *)status->container_name, strlen(status->container_name));
    write_message(&writer, 19, (const uint8_t *)status->installation_id,
                  strlen(status->installation_id));
    return writer.failed ? 0
        : encode_envelope(request_id, 18, message, writer.length, output, capacity);
}

size_t watchdog_frame_encode(
    const uint8_t *payload,
    size_t payload_length,
    uint8_t *output,
    size_t capacity
) {
    if (payload == NULL || output == NULL || payload_length > UINT32_MAX
        || payload_length > WATCHDOG_MAX_FRAME_BYTES || capacity < payload_length + 4u) {
        return 0;
    }
    const uint32_t length = (uint32_t)payload_length;
    output[0] = (uint8_t)(length >> 24u);
    output[1] = (uint8_t)(length >> 16u);
    output[2] = (uint8_t)(length >> 8u);
    output[3] = (uint8_t)length;
    memcpy(output + 4, payload, payload_length);
    return payload_length + 4u;
}

int watchdog_frame_length(const uint8_t header[4], uint32_t *payload_length) {
    if (header == NULL || payload_length == NULL) return -1;
    const uint32_t length = ((uint32_t)header[0] << 24u)
        | ((uint32_t)header[1] << 16u)
        | ((uint32_t)header[2] << 8u)
        | (uint32_t)header[3];
    if (length == 0 || length > WATCHDOG_MAX_FRAME_BYTES) return -1;
    *payload_length = length;
    return 0;
}
