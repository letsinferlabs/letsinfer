#include "test.h"

#include "watchdog/safety.h"

#include <stdlib.h>
#include <string.h>
#ifdef __linux__
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

static watchdog_safety_thresholds thresholds(void) {
    return (watchdog_safety_thresholds){
        .warning_available_bytes = UINT64_C(16) << 30u,
        .graceful_available_bytes = UINT64_C(12) << 30u,
        .emergency_available_bytes = UINT64_C(8) << 30u,
        .swap_stop_bytes = UINT64_C(1) << 30u,
        .psi_some_us = 150000u,
        .psi_full_us = 50000u,
        .state_failures = 8u,
        .containment_grace_ms = 3000u
    };
}

void test_safety_decision_precedence(void) {
    const watchdog_safety_thresholds limits = thresholds();
    watchdog_safety_input input = {.available_bytes = UINT64_C(80) << 30u};
    watchdog_safety_decision result = watchdog_safety_decide(&limits, &input);
    TEST_ASSERT(result.action == WATCHDOG_SAFETY_ACTION_NONE);

    input.available_bytes = UINT64_C(7) << 30u;
    result = watchdog_safety_decide(&limits, &input);
    TEST_ASSERT(result.action == WATCHDOG_SAFETY_ACTION_KILL);
    TEST_ASSERT(strcmp(result.reason, "host_memory_emergency") == 0);

    input.available_bytes = UINT64_C(14) << 30u;
    input.cgroup_oom_group_kill_delta = 1u;
    result = watchdog_safety_decide(&limits, &input);
    TEST_ASSERT(result.action == WATCHDOG_SAFETY_ACTION_KILL);
    TEST_ASSERT(strcmp(result.reason, "cgroup_oom_kill") == 0);

    input.cgroup_oom_group_kill_delta = 0u;
    input.psi_some_delta_us = 150000u;
    result = watchdog_safety_decide(&limits, &input);
    TEST_ASSERT(result.action == WATCHDOG_SAFETY_ACTION_NONE);

    input.available_bytes = UINT64_C(11) << 30u;
    input.psi_some_delta_us = 0u;
    input.psi_full_delta_us = 50000u;
    result = watchdog_safety_decide(&limits, &input);
    TEST_ASSERT(result.action == WATCHDOG_SAFETY_ACTION_NONE);

    input.available_bytes = UINT64_C(80) << 30u;
    input.psi_full_delta_us = 0u;
    input.psi_some_delta_us = 0u;
    input.swap_used_bytes = UINT64_C(1) << 30u;
    result = watchdog_safety_decide(&limits, &input);
    TEST_ASSERT(result.action == WATCHDOG_SAFETY_ACTION_NONE);

    input.available_bytes = (UINT64_C(8) << 30u) + 1u;
    input.swap_used_bytes = UINT64_C(8) << 30u;
    input.psi_some_delta_us = 1000000u;
    input.psi_full_delta_us = 1000000u;
    result = watchdog_safety_decide(&limits, &input);
    TEST_ASSERT(result.action == WATCHDOG_SAFETY_ACTION_NONE);

    input.swap_used_bytes = 0u;
    input.psi_some_delta_us = 0u;
    input.psi_full_delta_us = 0u;
    input.available_bytes = UINT64_C(80) << 30u;
    input.cgroup_max_delta = 1u;
    result = watchdog_safety_decide(&limits, &input);
    TEST_ASSERT(result.action == WATCHDOG_SAFETY_ACTION_STOP);
    TEST_ASSERT(strcmp(result.reason, "cgroup_memory_limit") == 0);

    input.cgroup_max_delta = 0u;
    input.cgroup_oom_kill_delta = 1u;
    result = watchdog_safety_decide(&limits, &input);
    TEST_ASSERT(result.action == WATCHDOG_SAFETY_ACTION_KILL);
    TEST_ASSERT(strcmp(result.reason, "cgroup_oom_kill") == 0);
}

void test_safety_thresholds_and_descriptor(void) {
    watchdog_safety_thresholds limits = thresholds();
    TEST_ASSERT(watchdog_safety_validate_thresholds(&limits) == 0);
    limits.warning_available_bytes = limits.graceful_available_bytes;
    TEST_ASSERT(watchdog_safety_validate_thresholds(&limits) != 0);

    const char *identifier =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    char descriptor[512];
    snprintf(
        descriptor,
        sizeof(descriptor),
        "version=1\ngeneration=0123456789abcdef0123456789abcdef\n"
        "phase=armed\ncontainer_name=letsinfer-single-stream\ncontainer_id=%s\n"
        "pid=123\nstart_ticks=456\nboot_id=01234567-89ab-cdef-0123-456789abcdef\n"
        "cgroup=/sys/fs/cgroup/system.slice/docker-test.scope\n",
        identifier
    );
    watchdog_protected_engine target;
    TEST_ASSERT(watchdog_safety_parse_descriptor(descriptor, &target) == 0);
    TEST_ASSERT(target.phase == WATCHDOG_SAFETY_PHASE_ARMED);
    TEST_ASSERT(strcmp(target.container_id, identifier) == 0);

    TEST_ASSERT(watchdog_safety_parse_descriptor(
        "version=1\ngeneration=0123456789abcdef0123456789abcdef\n"
        "phase=pending\ncontainer_name=letsinfer-single-stream\ncontainer_id=-\n"
        "pid=-\nstart_ticks=-\nboot_id=-\ncgroup=-\n",
        &target
    ) == 0);
    TEST_ASSERT(target.phase == WATCHDOG_SAFETY_PHASE_PENDING);
    TEST_ASSERT(target.container_id[0] == '\0');

    TEST_ASSERT(watchdog_safety_parse_descriptor(
        "version=1\ngeneration=bad\nphase=armed\n"
        "container_name=x\ncontainer_id=-\npid=-\nstart_ticks=-\nboot_id=-\ncgroup=-\n",
        &target
    ) != 0);
}

#ifdef __linux__
void test_safety_supervisor_discovers_private_targets(void) {
    char root[] = "/tmp/letsinfer-safety-XXXXXX";
    TEST_ASSERT(mkdtemp(root) != NULL);
    TEST_ASSERT(chmod(root, 0700) == 0);
    char target[512];
    const int length = snprintf(
        target,
        sizeof(target),
        "%s/0123456789abcdef0123456789abcdef",
        root
    );
    TEST_ASSERT(length > 0 && (size_t)length < sizeof(target));
    TEST_ASSERT(mkdir(target, 0700) == 0);
    watchdog_safety_config config = {
        .state_path = root,
        .thresholds = thresholds()
    };
    watchdog_safety_supervisor supervisor;
    TEST_ASSERT(watchdog_safety_supervisor_open(&supervisor, &config) == 0);
    TEST_ASSERT(watchdog_safety_supervisor_primary(&supervisor) != NULL);
    TEST_ASSERT(watchdog_safety_supervisor_active(&supervisor) == 0u);
    TEST_ASSERT(!watchdog_safety_supervisor_armed(&supervisor));
    TEST_ASSERT(!watchdog_safety_supervisor_tripped(&supervisor));
    watchdog_safety_supervisor_close(&supervisor);
    char events[512];
    const int events_length = snprintf(
        events,
        sizeof(events),
        "%s/safety-events.ndjson",
        target
    );
    TEST_ASSERT(events_length > 0 && (size_t)events_length < sizeof(events));
    TEST_ASSERT(unlink(events) == 0);
    TEST_ASSERT(rmdir(target) == 0);
    TEST_ASSERT(rmdir(root) == 0);
}

static int flush_for_exit_test(void *context) {
    int *count = context;
    ++*count;
    return 0;
}

void test_safety_process_exit_latches_trip(void) {
    char root[] = "/tmp/letsinfer-safety-exit-XXXXXX";
    TEST_ASSERT(mkdtemp(root) != NULL);
    TEST_ASSERT(chmod(root, 0700) == 0);
    char state[512];
    char trip[512];
    char events[512];
    TEST_ASSERT(snprintf(state, sizeof(state), "%s/protected-engine.state", root) > 0);
    TEST_ASSERT(snprintf(trip, sizeof(trip), "%s/protection-trip.json", root) > 0);
    TEST_ASSERT(snprintf(events, sizeof(events), "%s/safety-events.ndjson", root) > 0);

    watchdog_safety_config config = {
        .state_path = state,
        .thresholds = thresholds()
    };
    watchdog_safety_runtime runtime;
    TEST_ASSERT(watchdog_safety_open(&runtime, &config) == 0);

    const pid_t child = fork();
    TEST_ASSERT(child >= 0);
    if (child == 0) _exit(0);
    const int pid_fd = (int)syscall(SYS_pidfd_open, child, 0u);
    TEST_ASSERT(pid_fd >= 0);
    TEST_ASSERT(waitpid(child, NULL, 0) == child);
    runtime.pid_fd = pid_fd;
    runtime.container_pid = child;
    runtime.target.phase = WATCHDOG_SAFETY_PHASE_ARMED;
    TEST_ASSERT(snprintf(
        runtime.target.generation,
        sizeof(runtime.target.generation),
        "0123456789abcdef0123456789abcdef"
    ) > 0);
    TEST_ASSERT(snprintf(
        runtime.target.container_id,
        sizeof(runtime.target.container_id),
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    ) > 0);

    int flush_count = 0;
    watchdog_safety_result result;
    const watchdog_sample sample = {0};
    TEST_ASSERT(watchdog_safety_tick(
        &runtime,
        &sample,
        flush_for_exit_test,
        &flush_count,
        &result
    ) == 0);
    TEST_ASSERT(flush_count == 1);
    TEST_ASSERT(result.has_event);
    TEST_ASSERT(strcmp(result.kind, "engine.exit") == 0);
    TEST_ASSERT(strcmp(result.reason, "protected_process_exited") == 0);
    TEST_ASSERT(runtime.tripped);

    const int trip_fd = open(trip, O_RDONLY | O_CLOEXEC);
    TEST_ASSERT(trip_fd >= 0);
    char payload[1024];
    const ssize_t length = read(trip_fd, payload, sizeof(payload) - 1u);
    close(trip_fd);
    TEST_ASSERT(length > 0);
    payload[length] = '\0';
    TEST_ASSERT(strstr(payload, "\"action\": \"stop\"") != NULL);
    TEST_ASSERT(strstr(payload, "\"reason\": \"protected_process_exited\"") != NULL);

    watchdog_safety_close(&runtime);
    TEST_ASSERT(unlink(trip) == 0);
    TEST_ASSERT(unlink(events) == 0);
    TEST_ASSERT(rmdir(root) == 0);
}
#endif
