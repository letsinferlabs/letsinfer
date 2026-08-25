#include "test.h"

#include "watchdog/record.h"

#include <string.h>

static watchdog_sample fixture(void) {
    watchdog_sample sample;
    watchdog_sample_init(&sample);
    sample.sequence = 42;
    sample.unix_ms = UINT64_C(1700000000123);
    sample.monotonic_ms = 123456;
    sample.cpu_core_count = 20;
    sample.cpu_percent = 73;
    sample.cpu_core_percent[0] = 99;
    sample.gpu_percent = 96;
    sample.gpu_engine_percent[WATCHDOG_GPU_SM] = 96;
    sample.system_temp_deci_c = 439;
    sample.gpu_temp_deci_c = 680;
    sample.power_deci_w = 766;
    sample.memory_total_mib = 128000;
    sample.cpu_clock_mhz = 3800;
    sample.gpu_clock_mhz = 2400;
    sample.vram_clock_mhz = 9500;
    sample.system_ram_clock_mhz = 4266;
    sample.active_requests = 4;
    sample.connected_clients = 6;
    sample.queued_requests = 5;
    sample.requests_received = 100;
    sample.requests_completed = 90;
    sample.input_tokens = 1000;
    sample.output_tokens = 2000;
    sample.ttft_milliseconds = 3000;
    return sample;
}

void test_record_round_trip(void) {
    const watchdog_sample input = fixture();
    uint8_t bytes[WATCHDOG_RECORD_BYTES];
    watchdog_sample output;
    TEST_ASSERT(watchdog_record_encode(&input, bytes));
    TEST_ASSERT(watchdog_record_decode(bytes, &output));
    TEST_ASSERT(output.sequence == input.sequence);
    TEST_ASSERT(output.unix_ms == input.unix_ms);
    TEST_ASSERT(output.cpu_core_count == 20);
    TEST_ASSERT(output.cpu_core_percent[0] == 99);
    TEST_ASSERT(output.gpu_engine_percent[WATCHDOG_GPU_SM] == 96);
    TEST_ASSERT(output.gpu_temp_deci_c == 680);
    TEST_ASSERT(output.memory_total_mib == 128000);
    TEST_ASSERT(output.cpu_clock_mhz == 3800);
    TEST_ASSERT(output.gpu_clock_mhz == 2400);
    TEST_ASSERT(output.vram_clock_mhz == 9500);
    TEST_ASSERT(output.system_ram_clock_mhz == 4266);
    TEST_ASSERT(output.active_requests == 4);
    TEST_ASSERT(output.connected_clients == 6);
    TEST_ASSERT(output.queued_requests == 5);
    TEST_ASSERT(output.requests_received == 100);
    TEST_ASSERT(output.requests_completed == 90);
    TEST_ASSERT(output.input_tokens == 1000);
    TEST_ASSERT(output.output_tokens == 2000);
    TEST_ASSERT(output.ttft_milliseconds == 3000);
}

void test_record_rejects_corruption(void) {
    const watchdog_sample input = fixture();
    uint8_t bytes[WATCHDOG_RECORD_BYTES];
    watchdog_sample output;
    TEST_ASSERT(watchdog_record_encode(&input, bytes));
    bytes[42] ^= 1u;
    TEST_ASSERT(!watchdog_record_decode(bytes, &output));
}
