#ifndef WATCHDOG_TEST_H
#define WATCHDOG_TEST_H

#include <stdio.h>

extern int watchdog_test_failures;

#define TEST_ASSERT(expression) do { \
    if (!(expression)) { \
        fprintf(stderr, "%s:%d: assertion failed: %s\n", __FILE__, __LINE__, #expression); \
        ++watchdog_test_failures; \
        return; \
    } \
} while (0)

void test_record_round_trip(void);
void test_record_rejects_corruption(void);
void test_gateway_metrics_are_strict_and_complete(void);
void test_ring_wrap_and_query(void);
void test_rollup_averages_and_rotates(void);
void test_protobuf_request_and_response(void);
void test_controller_registry(void);
void test_metadata_workloads_and_events(void);
void test_safety_decision_precedence(void);
void test_safety_thresholds_and_descriptor(void);
void test_safety_supervisor_discovers_private_targets(void);
void test_safety_process_exit_latches_trip(void);
void test_safety_descriptor_loss_degrades_without_trip(void);

#endif
