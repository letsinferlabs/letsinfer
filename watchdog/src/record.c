#include "watchdog/record.h"

#include "watchdog/crc32.h"

#include <string.h>

#define WATCHDOG_RECORD_MAGIC UINT32_C(0x3152494c)
#define WATCHDOG_RECORD_VERSION UINT16_C(2)

static void put_u16(uint8_t *target, uint16_t value) {
    target[0] = (uint8_t)value;
    target[1] = (uint8_t)(value >> 8u);
}

static void put_u32(uint8_t *target, uint32_t value) {
    for (unsigned byte = 0; byte < 4; ++byte) {
        target[byte] = (uint8_t)(value >> (byte * 8u));
    }
}

static void put_u64(uint8_t *target, uint64_t value) {
    for (unsigned byte = 0; byte < 8; ++byte) {
        target[byte] = (uint8_t)(value >> (byte * 8u));
    }
}

static uint16_t get_u16(const uint8_t *source) {
    return (uint16_t)source[0] | ((uint16_t)source[1] << 8u);
}

static uint32_t get_u32(const uint8_t *source) {
    uint32_t value = 0;
    for (unsigned byte = 0; byte < 4; ++byte) {
        value |= (uint32_t)source[byte] << (byte * 8u);
    }
    return value;
}

static uint64_t get_u64(const uint8_t *source) {
    uint64_t value = 0;
    for (unsigned byte = 0; byte < 8; ++byte) {
        value |= (uint64_t)source[byte] << (byte * 8u);
    }
    return value;
}

void watchdog_sample_init(watchdog_sample *sample) {
    memset(sample, 0, sizeof(*sample));
    sample->cpu_percent = WATCHDOG_PERCENT_UNKNOWN;
    sample->gpu_percent = WATCHDOG_PERCENT_UNKNOWN;
    sample->memory_percent = WATCHDOG_PERCENT_UNKNOWN;
    sample->disk_percent = WATCHDOG_PERCENT_UNKNOWN;
    sample->gpu_memory_percent = WATCHDOG_PERCENT_UNKNOWN;
    memset(sample->cpu_core_percent, WATCHDOG_PERCENT_UNKNOWN, sizeof(sample->cpu_core_percent));
    memset(sample->gpu_engine_percent, WATCHDOG_PERCENT_UNKNOWN, sizeof(sample->gpu_engine_percent));
    sample->system_temp_deci_c = WATCHDOG_TEMP_UNKNOWN;
    sample->gpu_temp_deci_c = WATCHDOG_TEMP_UNKNOWN;
    sample->nvme_temp_deci_c = WATCHDOG_TEMP_UNKNOWN;
    sample->cpu_clock_mhz = WATCHDOG_CLOCK_UNKNOWN;
    sample->gpu_clock_mhz = WATCHDOG_CLOCK_UNKNOWN;
    sample->vram_clock_mhz = WATCHDOG_CLOCK_UNKNOWN;
    sample->system_ram_clock_mhz = WATCHDOG_CLOCK_UNKNOWN;
}

bool watchdog_record_encode(
    const watchdog_sample *sample,
    uint8_t output[WATCHDOG_RECORD_BYTES]
) {
    if (sample == NULL || output == NULL || sample->cpu_core_count > WATCHDOG_MAX_CPU_CORES) {
        return false;
    }

    memset(output, 0, WATCHDOG_RECORD_BYTES);
    put_u32(output + 0, WATCHDOG_RECORD_MAGIC);
    put_u16(output + 4, WATCHDOG_RECORD_VERSION);
    put_u16(output + 6, WATCHDOG_RECORD_BYTES);
    put_u64(output + 8, sample->sequence);
    put_u64(output + 16, sample->unix_ms);
    put_u64(output + 24, sample->monotonic_ms);
    output[32] = sample->cpu_core_count;
    output[33] = sample->flags;
    output[34] = sample->cpu_percent;
    output[35] = sample->gpu_percent;
    output[36] = sample->memory_percent;
    output[37] = sample->disk_percent;
    output[38] = sample->gpu_memory_percent;
    output[39] = sample->workload_type;
    memcpy(output + 40, sample->cpu_core_percent, WATCHDOG_MAX_CPU_CORES);
    memcpy(output + 72, sample->gpu_engine_percent, WATCHDOG_GPU_ENGINES);
    put_u16(output + 78, (uint16_t)sample->system_temp_deci_c);
    put_u16(output + 80, (uint16_t)sample->gpu_temp_deci_c);
    put_u16(output + 82, (uint16_t)sample->nvme_temp_deci_c);
    put_u16(output + 84, sample->power_deci_w);
    put_u16(output + 86, sample->load1_centi);
    put_u32(output + 88, sample->memory_used_mib);
    put_u32(output + 92, sample->memory_total_mib);
    put_u32(output + 96, sample->disk_used_mib);
    put_u32(output + 100, sample->disk_total_mib);
    put_u32(output + 104, sample->network_rx_kib_s);
    put_u32(output + 108, sample->network_tx_kib_s);
    put_u32(output + 112, sample->disk_read_kib_s);
    put_u32(output + 116, sample->disk_write_kib_s);
    put_u32(output + 120, sample->workload_id);
    put_u32(output + 124, sample->cpu_clock_mhz);
    put_u32(output + 128, sample->gpu_clock_mhz);
    put_u32(output + 132, sample->vram_clock_mhz);
    put_u32(output + 136, sample->system_ram_clock_mhz);
    put_u32(output + 140, sample->active_requests);
    put_u32(output + 144, sample->queued_requests);
    put_u64(output + 148, sample->requests_received);
    put_u64(output + 156, sample->requests_admitted);
    put_u64(output + 164, sample->requests_completed);
    put_u64(output + 172, sample->requests_failed);
    put_u64(output + 180, sample->requests_cancelled);
    put_u64(output + 188, sample->requests_retried);
    put_u64(output + 196, sample->input_tokens);
    put_u64(output + 204, sample->output_tokens);
    put_u64(output + 212, sample->cached_tokens);
    put_u64(output + 220, sample->queue_milliseconds);
    put_u64(output + 228, sample->ttft_milliseconds);
    put_u64(output + 236, sample->decode_milliseconds);
    put_u64(output + 244, sample->exact_token_requests);
    put_u64(output + 252, sample->prefix_cache_hits);
    put_u64(output + 260, sample->usage_records_dropped);
    put_u64(output + 268, sample->usage_write_errors);
    put_u32(output + 276, sample->connected_clients);
    put_u32(output + 280, watchdog_crc32(output, 280));
    return true;
}

bool watchdog_record_decode(
    const uint8_t input[WATCHDOG_RECORD_BYTES],
    watchdog_sample *sample
) {
    if (input == NULL || sample == NULL
        || get_u32(input + 0) != WATCHDOG_RECORD_MAGIC
        || get_u16(input + 4) != WATCHDOG_RECORD_VERSION
        || get_u16(input + 6) != WATCHDOG_RECORD_BYTES
        || get_u32(input + 280) != watchdog_crc32(input, 280)
        || input[32] > WATCHDOG_MAX_CPU_CORES) {
        return false;
    }

    watchdog_sample_init(sample);
    sample->sequence = get_u64(input + 8);
    sample->unix_ms = get_u64(input + 16);
    sample->monotonic_ms = get_u64(input + 24);
    sample->cpu_core_count = input[32];
    sample->flags = input[33];
    sample->cpu_percent = input[34];
    sample->gpu_percent = input[35];
    sample->memory_percent = input[36];
    sample->disk_percent = input[37];
    sample->gpu_memory_percent = input[38];
    sample->workload_type = input[39];
    memcpy(sample->cpu_core_percent, input + 40, WATCHDOG_MAX_CPU_CORES);
    memcpy(sample->gpu_engine_percent, input + 72, WATCHDOG_GPU_ENGINES);
    sample->system_temp_deci_c = (int16_t)get_u16(input + 78);
    sample->gpu_temp_deci_c = (int16_t)get_u16(input + 80);
    sample->nvme_temp_deci_c = (int16_t)get_u16(input + 82);
    sample->power_deci_w = get_u16(input + 84);
    sample->load1_centi = get_u16(input + 86);
    sample->memory_used_mib = get_u32(input + 88);
    sample->memory_total_mib = get_u32(input + 92);
    sample->disk_used_mib = get_u32(input + 96);
    sample->disk_total_mib = get_u32(input + 100);
    sample->network_rx_kib_s = get_u32(input + 104);
    sample->network_tx_kib_s = get_u32(input + 108);
    sample->disk_read_kib_s = get_u32(input + 112);
    sample->disk_write_kib_s = get_u32(input + 116);
    sample->workload_id = get_u32(input + 120);
    sample->cpu_clock_mhz = get_u32(input + 124);
    sample->gpu_clock_mhz = get_u32(input + 128);
    sample->vram_clock_mhz = get_u32(input + 132);
    sample->system_ram_clock_mhz = get_u32(input + 136);
    sample->active_requests = get_u32(input + 140);
    sample->queued_requests = get_u32(input + 144);
    sample->requests_received = get_u64(input + 148);
    sample->requests_admitted = get_u64(input + 156);
    sample->requests_completed = get_u64(input + 164);
    sample->requests_failed = get_u64(input + 172);
    sample->requests_cancelled = get_u64(input + 180);
    sample->requests_retried = get_u64(input + 188);
    sample->input_tokens = get_u64(input + 196);
    sample->output_tokens = get_u64(input + 204);
    sample->cached_tokens = get_u64(input + 212);
    sample->queue_milliseconds = get_u64(input + 220);
    sample->ttft_milliseconds = get_u64(input + 228);
    sample->decode_milliseconds = get_u64(input + 236);
    sample->exact_token_requests = get_u64(input + 244);
    sample->prefix_cache_hits = get_u64(input + 252);
    sample->usage_records_dropped = get_u64(input + 260);
    sample->usage_write_errors = get_u64(input + 268);
    sample->connected_clients = get_u32(input + 276);
    return true;
}
