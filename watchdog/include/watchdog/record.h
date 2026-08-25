#ifndef WATCHDOG_RECORD_H
#define WATCHDOG_RECORD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define WATCHDOG_RECORD_BYTES 284u
#define WATCHDOG_MAX_CPU_CORES 32u
#define WATCHDOG_GPU_ENGINES 6u
#define WATCHDOG_PERCENT_UNKNOWN 255u
#define WATCHDOG_TEMP_UNKNOWN INT16_MIN
#define WATCHDOG_CLOCK_UNKNOWN UINT32_MAX

enum watchdog_sample_flags {
    WATCHDOG_SAMPLE_ROLLUP = 1u << 0,
    WATCHDOG_SAMPLE_GPU_AVAILABLE = 1u << 1,
    WATCHDOG_SAMPLE_THROTTLED = 1u << 2,
    WATCHDOG_SAMPLE_GATEWAY_AVAILABLE = 1u << 3
};

enum watchdog_gpu_engine {
    WATCHDOG_GPU_SM = 0,
    WATCHDOG_GPU_MEMORY = 1,
    WATCHDOG_GPU_ENCODER = 2,
    WATCHDOG_GPU_DECODER = 3,
    WATCHDOG_GPU_JPEG = 4,
    WATCHDOG_GPU_OFA = 5
};

typedef struct watchdog_sample {
    uint64_t sequence;
    uint64_t unix_ms;
    uint64_t monotonic_ms;
    uint8_t cpu_core_count;
    uint8_t flags;
    uint8_t cpu_percent;
    uint8_t gpu_percent;
    uint8_t memory_percent;
    uint8_t disk_percent;
    uint8_t gpu_memory_percent;
    uint8_t workload_type;
    uint8_t cpu_core_percent[WATCHDOG_MAX_CPU_CORES];
    uint8_t gpu_engine_percent[WATCHDOG_GPU_ENGINES];
    int16_t system_temp_deci_c;
    int16_t gpu_temp_deci_c;
    int16_t nvme_temp_deci_c;
    uint16_t power_deci_w;
    uint16_t load1_centi;
    uint32_t memory_used_mib;
    uint32_t memory_total_mib;
    uint32_t disk_used_mib;
    uint32_t disk_total_mib;
    uint32_t network_rx_kib_s;
    uint32_t network_tx_kib_s;
    uint32_t disk_read_kib_s;
    uint32_t disk_write_kib_s;
    uint32_t workload_id;
    uint32_t cpu_clock_mhz;
    uint32_t gpu_clock_mhz;
    uint32_t vram_clock_mhz;
    uint32_t system_ram_clock_mhz;
    uint32_t active_requests;
    uint32_t queued_requests;
    uint32_t connected_clients;
    uint64_t requests_received;
    uint64_t requests_admitted;
    uint64_t requests_completed;
    uint64_t requests_failed;
    uint64_t requests_cancelled;
    uint64_t requests_retried;
    uint64_t input_tokens;
    uint64_t output_tokens;
    uint64_t cached_tokens;
    uint64_t queue_milliseconds;
    uint64_t ttft_milliseconds;
    uint64_t decode_milliseconds;
    uint64_t exact_token_requests;
    uint64_t prefix_cache_hits;
    uint64_t usage_records_dropped;
    uint64_t usage_write_errors;
} watchdog_sample;

void watchdog_sample_init(watchdog_sample *sample);
bool watchdog_record_encode(
    const watchdog_sample *sample,
    uint8_t output[WATCHDOG_RECORD_BYTES]
);
bool watchdog_record_decode(
    const uint8_t input[WATCHDOG_RECORD_BYTES],
    watchdog_sample *sample
);

#endif
