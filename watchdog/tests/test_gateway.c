#include "test.h"

#include "watchdog/gateway.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

void test_gateway_metrics_are_strict_and_complete(void) {
    char path[] = "/tmp/letsinfer-gateway-metrics-XXXXXX";
    const int descriptor = mkstemp(path);
    TEST_ASSERT(descriptor >= 0);
    const char *body =
        "version=2\n"
        "active_requests=2\n"
        "connected_clients=4\n"
        "queued_requests=3\n"
        "requests_received=11\n"
        "requests_admitted=10\n"
        "requests_completed=9\n"
        "requests_failed=1\n"
        "requests_cancelled=2\n"
        "requests_retried=3\n"
        "input_tokens=100\n"
        "output_tokens=200\n"
        "cached_tokens=50\n"
        "queue_milliseconds=400\n"
        "ttft_milliseconds=500\n"
        "decode_milliseconds=600\n"
        "exact_token_requests=7\n"
        "prefix_cache_hits=8\n"
        "usage_records_dropped=0\n"
        "usage_write_errors=0\n";
    TEST_ASSERT(write(descriptor, body, strlen(body)) == (ssize_t)strlen(body));
    TEST_ASSERT(close(descriptor) == 0);
    watchdog_gateway_metrics metrics;
    const uint64_t now_ms = (uint64_t)time(NULL) * 1000u;
    TEST_ASSERT(watchdog_gateway_metrics_read(path, now_ms, &metrics) == 0);
    TEST_ASSERT(metrics.active_requests == 2u);
    TEST_ASSERT(metrics.connected_clients == 4u);
    TEST_ASSERT(metrics.queued_requests == 3u);
    TEST_ASSERT(metrics.requests_received == 11u);
    TEST_ASSERT(metrics.output_tokens == 200u);
    TEST_ASSERT(metrics.ttft_milliseconds == 500u);
    TEST_ASSERT(metrics.prefix_cache_hits == 8u);
    TEST_ASSERT(unlink(path) == 0);

    TEST_ASSERT(watchdog_gateway_metrics_read(path, now_ms, &metrics) == 1);
}
