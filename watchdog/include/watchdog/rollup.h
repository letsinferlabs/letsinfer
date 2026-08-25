#ifndef WATCHDOG_ROLLUP_H
#define WATCHDOG_ROLLUP_H

#include "watchdog/record.h"

#include <stdbool.h>
#include <stdint.h>

typedef struct watchdog_unsigned_accumulator {
    uint64_t total;
    uint32_t count;
} watchdog_unsigned_accumulator;

typedef struct watchdog_signed_accumulator {
    int64_t total;
    uint32_t count;
} watchdog_signed_accumulator;

typedef struct watchdog_rollup {
    uint64_t interval_ms;
    uint64_t bucket;
    uint32_t samples;
    watchdog_sample latest;
    watchdog_unsigned_accumulator cpu;
    watchdog_unsigned_accumulator gpu;
    watchdog_unsigned_accumulator memory;
    watchdog_unsigned_accumulator disk;
    watchdog_unsigned_accumulator gpu_memory;
    watchdog_unsigned_accumulator cores[WATCHDOG_MAX_CPU_CORES];
    watchdog_unsigned_accumulator engines[WATCHDOG_GPU_ENGINES];
    watchdog_signed_accumulator system_temp;
    watchdog_signed_accumulator gpu_temp;
    watchdog_signed_accumulator nvme_temp;
    watchdog_unsigned_accumulator power;
    watchdog_unsigned_accumulator load;
    watchdog_unsigned_accumulator memory_used;
    watchdog_unsigned_accumulator disk_used;
    watchdog_unsigned_accumulator network_rx;
    watchdog_unsigned_accumulator network_tx;
    watchdog_unsigned_accumulator disk_read;
    watchdog_unsigned_accumulator disk_write;
    watchdog_unsigned_accumulator cpu_clock;
    watchdog_unsigned_accumulator gpu_clock;
    watchdog_unsigned_accumulator vram_clock;
    watchdog_unsigned_accumulator system_ram_clock;
    watchdog_unsigned_accumulator active_requests;
    watchdog_unsigned_accumulator connected_clients;
    watchdog_unsigned_accumulator queued_requests;
} watchdog_rollup;

void watchdog_rollup_init(watchdog_rollup *rollup, uint64_t interval_ms);
bool watchdog_rollup_push(
    watchdog_rollup *rollup,
    const watchdog_sample *sample,
    watchdog_sample *completed
);
bool watchdog_rollup_complete_partial(watchdog_rollup *rollup, watchdog_sample *completed);

#endif
