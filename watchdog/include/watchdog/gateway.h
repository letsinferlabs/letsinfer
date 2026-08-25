#ifndef WATCHDOG_GATEWAY_H
#define WATCHDOG_GATEWAY_H

#include <stdint.h>

typedef struct watchdog_gateway_metrics {
    uint32_t active_requests;
    uint32_t connected_clients;
    uint32_t queued_requests;
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
} watchdog_gateway_metrics;

/* Returns 0 for a complete fresh record, 1 when absent/stale, and -1 when unsafe. */
int watchdog_gateway_metrics_read(
    const char *path,
    uint64_t now_unix_ms,
    watchdog_gateway_metrics *metrics
);

#endif
