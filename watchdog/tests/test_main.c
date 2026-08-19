#include "test.h"
#include "watchdog/server.h"

_Static_assert(WATCHDOG_DEFAULT_MAX_CONTROLLERS == 16u,
               "Watchdog must reserve the core telemetry stream floor");
_Static_assert(WATCHDOG_HARD_MAX_CONTROLLERS == 16u,
               "Watchdog telemetry stream storage must remain bounded");

int watchdog_test_failures = 0;

int main(void) {
    test_record_round_trip();
    test_record_rejects_corruption();
    test_gateway_metrics_are_strict_and_complete();
    test_ring_wrap_and_query();
    test_rollup_averages_and_rotates();
    test_protobuf_request_and_response();
    test_controller_registry();
    test_metadata_workloads_and_events();
    test_safety_decision_precedence();
    test_safety_thresholds_and_descriptor();
#ifdef __linux__
    test_safety_supervisor_discovers_private_targets();
    test_safety_process_exit_latches_trip();
#endif
    if (watchdog_test_failures == 0) {
        puts("watchdog tests passed");
    }
    return watchdog_test_failures == 0 ? 0 : 1;
}
