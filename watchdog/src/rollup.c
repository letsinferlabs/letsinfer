#include "watchdog/rollup.h"

#include <string.h>

static void add_unsigned(watchdog_unsigned_accumulator *value, uint64_t sample) {
    value->total += sample;
    ++value->count;
}

static void add_percent(watchdog_unsigned_accumulator *value, uint8_t sample) {
    if (sample != WATCHDOG_PERCENT_UNKNOWN) add_unsigned(value, sample);
}

static void add_temperature(watchdog_signed_accumulator *value, int16_t sample) {
    if (sample != WATCHDOG_TEMP_UNKNOWN) {
        value->total += sample;
        ++value->count;
    }
}

static void add_clock(watchdog_unsigned_accumulator *value, uint32_t sample) {
    if (sample != WATCHDOG_CLOCK_UNKNOWN) add_unsigned(value, sample);
}

static uint8_t average_percent(const watchdog_unsigned_accumulator *value) {
    if (value->count == 0) return WATCHDOG_PERCENT_UNKNOWN;
    const uint64_t average = (value->total + value->count / 2u) / value->count;
    return average > 100u ? 100u : (uint8_t)average;
}

static uint32_t average_u32(const watchdog_unsigned_accumulator *value) {
    if (value->count == 0) return 0;
    const uint64_t average = (value->total + value->count / 2u) / value->count;
    return average > UINT32_MAX ? UINT32_MAX : (uint32_t)average;
}

static uint32_t average_clock(const watchdog_unsigned_accumulator *value) {
    return value->count == 0 ? WATCHDOG_CLOCK_UNKNOWN : average_u32(value);
}

static uint16_t average_u16(const watchdog_unsigned_accumulator *value) {
    const uint32_t average = average_u32(value);
    return average > UINT16_MAX ? UINT16_MAX : (uint16_t)average;
}

static int16_t average_temperature(const watchdog_signed_accumulator *value) {
    if (value->count == 0) return WATCHDOG_TEMP_UNKNOWN;
    const int64_t average = value->total / (int64_t)value->count;
    if (average < INT16_MIN || average > INT16_MAX) return WATCHDOG_TEMP_UNKNOWN;
    return (int16_t)average;
}

static void clear_accumulators(watchdog_rollup *rollup) {
    const uint64_t interval = rollup->interval_ms;
    memset(rollup, 0, sizeof(*rollup));
    rollup->interval_ms = interval;
}

static void accumulate(watchdog_rollup *rollup, const watchdog_sample *sample) {
    rollup->latest = *sample;
    ++rollup->samples;
    add_percent(&rollup->cpu, sample->cpu_percent);
    add_percent(&rollup->gpu, sample->gpu_percent);
    add_percent(&rollup->memory, sample->memory_percent);
    add_percent(&rollup->disk, sample->disk_percent);
    add_percent(&rollup->gpu_memory, sample->gpu_memory_percent);
    for (size_t index = 0; index < sample->cpu_core_count; ++index) {
        add_percent(&rollup->cores[index], sample->cpu_core_percent[index]);
    }
    for (size_t index = 0; index < WATCHDOG_GPU_ENGINES; ++index) {
        add_percent(&rollup->engines[index], sample->gpu_engine_percent[index]);
    }
    add_temperature(&rollup->system_temp, sample->system_temp_deci_c);
    add_temperature(&rollup->gpu_temp, sample->gpu_temp_deci_c);
    add_temperature(&rollup->nvme_temp, sample->nvme_temp_deci_c);
    add_unsigned(&rollup->power, sample->power_deci_w);
    add_unsigned(&rollup->load, sample->load1_centi);
    add_unsigned(&rollup->memory_used, sample->memory_used_mib);
    add_unsigned(&rollup->disk_used, sample->disk_used_mib);
    add_unsigned(&rollup->network_rx, sample->network_rx_kib_s);
    add_unsigned(&rollup->network_tx, sample->network_tx_kib_s);
    add_unsigned(&rollup->disk_read, sample->disk_read_kib_s);
    add_unsigned(&rollup->disk_write, sample->disk_write_kib_s);
    add_clock(&rollup->cpu_clock, sample->cpu_clock_mhz);
    add_clock(&rollup->gpu_clock, sample->gpu_clock_mhz);
    add_clock(&rollup->vram_clock, sample->vram_clock_mhz);
    add_clock(&rollup->system_ram_clock, sample->system_ram_clock_mhz);
    add_unsigned(&rollup->active_requests, sample->active_requests);
    add_unsigned(&rollup->connected_clients, sample->connected_clients);
    add_unsigned(&rollup->queued_requests, sample->queued_requests);
}

static bool complete(const watchdog_rollup *rollup, watchdog_sample *output) {
    if (rollup->samples == 0 || output == NULL) return false;
    watchdog_sample_init(output);
    output->sequence = rollup->latest.sequence;
    output->unix_ms = rollup->bucket * rollup->interval_ms;
    output->monotonic_ms = rollup->latest.monotonic_ms;
    output->flags = rollup->latest.flags | WATCHDOG_SAMPLE_ROLLUP;
    output->cpu_core_count = rollup->latest.cpu_core_count;
    output->workload_id = rollup->latest.workload_id;
    output->workload_type = rollup->latest.workload_type;
    output->cpu_percent = average_percent(&rollup->cpu);
    output->gpu_percent = average_percent(&rollup->gpu);
    output->memory_percent = average_percent(&rollup->memory);
    output->disk_percent = average_percent(&rollup->disk);
    output->gpu_memory_percent = average_percent(&rollup->gpu_memory);
    for (size_t index = 0; index < output->cpu_core_count; ++index) {
        output->cpu_core_percent[index] = average_percent(&rollup->cores[index]);
    }
    for (size_t index = 0; index < WATCHDOG_GPU_ENGINES; ++index) {
        output->gpu_engine_percent[index] = average_percent(&rollup->engines[index]);
    }
    output->system_temp_deci_c = average_temperature(&rollup->system_temp);
    output->gpu_temp_deci_c = average_temperature(&rollup->gpu_temp);
    output->nvme_temp_deci_c = average_temperature(&rollup->nvme_temp);
    output->power_deci_w = average_u16(&rollup->power);
    output->load1_centi = average_u16(&rollup->load);
    output->memory_used_mib = average_u32(&rollup->memory_used);
    output->memory_total_mib = rollup->latest.memory_total_mib;
    output->disk_used_mib = average_u32(&rollup->disk_used);
    output->disk_total_mib = rollup->latest.disk_total_mib;
    output->network_rx_kib_s = average_u32(&rollup->network_rx);
    output->network_tx_kib_s = average_u32(&rollup->network_tx);
    output->disk_read_kib_s = average_u32(&rollup->disk_read);
    output->disk_write_kib_s = average_u32(&rollup->disk_write);
    output->cpu_clock_mhz = average_clock(&rollup->cpu_clock);
    output->gpu_clock_mhz = average_clock(&rollup->gpu_clock);
    output->vram_clock_mhz = average_clock(&rollup->vram_clock);
    output->system_ram_clock_mhz = average_clock(&rollup->system_ram_clock);
    output->active_requests = average_u32(&rollup->active_requests);
    output->connected_clients = average_u32(&rollup->connected_clients);
    output->queued_requests = average_u32(&rollup->queued_requests);
    output->requests_received = rollup->latest.requests_received;
    output->requests_admitted = rollup->latest.requests_admitted;
    output->requests_completed = rollup->latest.requests_completed;
    output->requests_failed = rollup->latest.requests_failed;
    output->requests_cancelled = rollup->latest.requests_cancelled;
    output->requests_retried = rollup->latest.requests_retried;
    output->input_tokens = rollup->latest.input_tokens;
    output->output_tokens = rollup->latest.output_tokens;
    output->cached_tokens = rollup->latest.cached_tokens;
    output->queue_milliseconds = rollup->latest.queue_milliseconds;
    output->ttft_milliseconds = rollup->latest.ttft_milliseconds;
    output->decode_milliseconds = rollup->latest.decode_milliseconds;
    output->exact_token_requests = rollup->latest.exact_token_requests;
    output->prefix_cache_hits = rollup->latest.prefix_cache_hits;
    output->usage_records_dropped = rollup->latest.usage_records_dropped;
    output->usage_write_errors = rollup->latest.usage_write_errors;
    return true;
}

void watchdog_rollup_init(watchdog_rollup *rollup, uint64_t interval_ms) {
    if (rollup == NULL) return;
    memset(rollup, 0, sizeof(*rollup));
    rollup->interval_ms = interval_ms;
}

bool watchdog_rollup_push(
    watchdog_rollup *rollup,
    const watchdog_sample *sample,
    watchdog_sample *completed
) {
    if (rollup == NULL || sample == NULL || completed == NULL || rollup->interval_ms == 0) {
        return false;
    }
    const uint64_t bucket = sample->unix_ms / rollup->interval_ms;
    if (rollup->samples == 0) {
        rollup->bucket = bucket;
        accumulate(rollup, sample);
        return false;
    }
    if (bucket == rollup->bucket) {
        accumulate(rollup, sample);
        return false;
    }
    const bool result = complete(rollup, completed);
    clear_accumulators(rollup);
    rollup->bucket = bucket;
    accumulate(rollup, sample);
    return result;
}

bool watchdog_rollup_complete_partial(watchdog_rollup *rollup, watchdog_sample *completed) {
    if (rollup == NULL || completed == NULL) return false;
    const bool result = complete(rollup, completed);
    clear_accumulators(rollup);
    return result;
}
