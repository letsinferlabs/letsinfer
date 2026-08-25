#include "test.h"

#include "watchdog/rollup.h"

void test_rollup_averages_and_rotates(void) {
    watchdog_rollup rollup;
    watchdog_rollup_init(&rollup, 60000u);

    watchdog_sample first;
    watchdog_sample_init(&first);
    first.sequence = 1u;
    first.unix_ms = 120000u;
    first.cpu_core_count = 2u;
    first.cpu_percent = 20u;
    first.gpu_percent = 40u;
    first.cpu_core_percent[0] = 10u;
    first.cpu_core_percent[1] = 30u;
    first.system_temp_deci_c = 500;
    first.memory_used_mib = 100u;
    first.memory_total_mib = 1000u;
    first.cpu_clock_mhz = 2000u;
    first.gpu_clock_mhz = 1000u;
    first.active_requests = 2u;
    first.connected_clients = 6u;
    first.queued_requests = 4u;
    first.requests_completed = 10u;
    first.output_tokens = 100u;

    watchdog_sample second = first;
    second.sequence = 2u;
    second.unix_ms = 150000u;
    second.cpu_percent = 40u;
    second.gpu_percent = 60u;
    second.cpu_core_percent[0] = 30u;
    second.cpu_core_percent[1] = 50u;
    second.system_temp_deci_c = 600;
    second.memory_used_mib = 300u;
    second.cpu_clock_mhz = 3000u;
    second.gpu_clock_mhz = 2000u;
    second.active_requests = 4u;
    second.connected_clients = 8u;
    second.queued_requests = 2u;
    second.requests_completed = 12u;
    second.output_tokens = 140u;

    watchdog_sample next = second;
    next.sequence = 3u;
    next.unix_ms = 180000u;

    watchdog_sample completed;
    TEST_ASSERT(!watchdog_rollup_push(&rollup, &first, &completed));
    TEST_ASSERT(!watchdog_rollup_push(&rollup, &second, &completed));
    TEST_ASSERT(watchdog_rollup_push(&rollup, &next, &completed));
    TEST_ASSERT(completed.sequence == 2u);
    TEST_ASSERT(completed.unix_ms == 120000u);
    TEST_ASSERT((completed.flags & WATCHDOG_SAMPLE_ROLLUP) != 0u);
    TEST_ASSERT(completed.cpu_percent == 30u);
    TEST_ASSERT(completed.gpu_percent == 50u);
    TEST_ASSERT(completed.cpu_core_percent[0] == 20u);
    TEST_ASSERT(completed.cpu_core_percent[1] == 40u);
    TEST_ASSERT(completed.system_temp_deci_c == 550);
    TEST_ASSERT(completed.memory_used_mib == 200u);
    TEST_ASSERT(completed.memory_total_mib == 1000u);
    TEST_ASSERT(completed.cpu_clock_mhz == 2500u);
    TEST_ASSERT(completed.gpu_clock_mhz == 1500u);
    TEST_ASSERT(completed.vram_clock_mhz == WATCHDOG_CLOCK_UNKNOWN);
    TEST_ASSERT(completed.active_requests == 3u);
    TEST_ASSERT(completed.connected_clients == 7u);
    TEST_ASSERT(completed.queued_requests == 3u);
    TEST_ASSERT(completed.requests_completed == 12u);
    TEST_ASSERT(completed.output_tokens == 140u);

    TEST_ASSERT(watchdog_rollup_complete_partial(&rollup, &completed));
    TEST_ASSERT(completed.sequence == 3u);
    TEST_ASSERT(!watchdog_rollup_complete_partial(&rollup, &completed));
}
