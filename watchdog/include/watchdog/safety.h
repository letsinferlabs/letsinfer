#ifndef WATCHDOG_SAFETY_H
#define WATCHDOG_SAFETY_H

#include "watchdog/record.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define WATCHDOG_SAFETY_GENERATION_MAX 32u
#define WATCHDOG_SAFETY_CONTAINER_NAME_MAX 128u
#define WATCHDOG_SAFETY_CONTAINER_ID_MAX 64u
#define WATCHDOG_SAFETY_BOOT_ID_MAX 36u
#define WATCHDOG_SAFETY_PATH_MAX 4096u
#define WATCHDOG_SAFETY_EVENT_KIND_MAX 64u
#define WATCHDOG_SAFETY_REASON_MAX 96u
#define WATCHDOG_SAFETY_PAYLOAD_MAX 2048u
#define WATCHDOG_SAFETY_MAX_TARGETS 64u
#define WATCHDOG_SAFETY_TARGET_KEY_MAX 32u

typedef enum watchdog_safety_phase {
    WATCHDOG_SAFETY_PHASE_NONE = 0,
    WATCHDOG_SAFETY_PHASE_PENDING,
    WATCHDOG_SAFETY_PHASE_STARTING,
    WATCHDOG_SAFETY_PHASE_ARMED,
    WATCHDOG_SAFETY_PHASE_DISARMED
} watchdog_safety_phase;

typedef enum watchdog_safety_action {
    WATCHDOG_SAFETY_ACTION_NONE = 0,
    WATCHDOG_SAFETY_ACTION_STOP,
    WATCHDOG_SAFETY_ACTION_KILL
} watchdog_safety_action;

typedef struct watchdog_safety_thresholds {
    uint64_t warning_available_bytes;
    uint64_t graceful_available_bytes;
    uint64_t emergency_available_bytes;
    uint64_t swap_stop_bytes;
    uint64_t psi_some_us;
    uint64_t psi_full_us;
    uint32_t state_failures;
    uint32_t containment_grace_ms;
} watchdog_safety_thresholds;

typedef struct watchdog_safety_input {
    uint64_t available_bytes;
    uint64_t swap_used_bytes;
    uint64_t psi_some_delta_us;
    uint64_t psi_full_delta_us;
    uint64_t cgroup_oom_delta;
    uint64_t cgroup_oom_kill_delta;
    uint64_t cgroup_oom_group_kill_delta;
    uint64_t cgroup_max_delta;
} watchdog_safety_input;

typedef struct watchdog_safety_decision {
    watchdog_safety_action action;
    const char *reason;
} watchdog_safety_decision;

typedef struct watchdog_protected_engine {
    char generation[WATCHDOG_SAFETY_GENERATION_MAX + 1u];
    watchdog_safety_phase phase;
    char container_name[WATCHDOG_SAFETY_CONTAINER_NAME_MAX + 1u];
    char container_id[WATCHDOG_SAFETY_CONTAINER_ID_MAX + 1u];
    int pid;
    uint64_t start_ticks;
    char boot_id[WATCHDOG_SAFETY_BOOT_ID_MAX + 1u];
    char cgroup_path[WATCHDOG_SAFETY_PATH_MAX];
} watchdog_protected_engine;

typedef struct watchdog_safety_config {
    const char *state_path;
    watchdog_safety_thresholds thresholds;
} watchdog_safety_config;

typedef struct watchdog_safety_result {
    bool has_event;
    char kind[WATCHDOG_SAFETY_EVENT_KIND_MAX + 1u];
    char reason[WATCHDOG_SAFETY_REASON_MAX + 1u];
    char payload_json[WATCHDOG_SAFETY_PAYLOAD_MAX + 1u];
    uint32_t severity;
} watchdog_safety_result;

typedef struct watchdog_safety_runtime {
    watchdog_safety_config config;
    watchdog_protected_engine target;
    char state_path[WATCHDOG_SAFETY_PATH_MAX];
    char ack_path[WATCHDOG_SAFETY_PATH_MAX];
    char trip_path[WATCHDOG_SAFETY_PATH_MAX];
    char event_path[WATCHDOG_SAFETY_PATH_MAX];
    char cgroup_path[WATCHDOG_SAFETY_PATH_MAX];
    int event_fd;
    int pid_fd;
    int container_pid;
    uint64_t previous_psi_some;
    uint64_t previous_psi_full;
    uint64_t baseline_oom;
    uint64_t baseline_oom_kill;
    uint64_t baseline_oom_group_kill;
    uint64_t baseline_max;
    uint32_t state_failures;
    bool has_pressure_baseline;
    bool has_cgroup_baseline;
    bool state_warned;
    bool warned;
    bool tripped;
} watchdog_safety_runtime;

typedef struct watchdog_safety_slot {
    bool used;
    bool seen;
    char key[WATCHDOG_SAFETY_TARGET_KEY_MAX + 1u];
    watchdog_safety_runtime runtime;
} watchdog_safety_slot;

typedef struct watchdog_safety_supervisor {
    watchdog_safety_config config;
    char root_path[WATCHDOG_SAFETY_PATH_MAX];
    watchdog_safety_slot slots[WATCHDOG_SAFETY_MAX_TARGETS];
} watchdog_safety_supervisor;

int watchdog_safety_validate_thresholds(const watchdog_safety_thresholds *thresholds);
watchdog_safety_decision watchdog_safety_decide(
    const watchdog_safety_thresholds *thresholds,
    const watchdog_safety_input *input
);
int watchdog_safety_parse_descriptor(
    const char *text,
    watchdog_protected_engine *target
);
const char *watchdog_safety_phase_name(watchdog_safety_phase phase);

int watchdog_safety_open(
    watchdog_safety_runtime *runtime,
    const watchdog_safety_config *config
);
void watchdog_safety_close(watchdog_safety_runtime *runtime);
int watchdog_safety_tick(
    watchdog_safety_runtime *runtime,
    const watchdog_sample *sample,
    int (*flush_storage)(void *context),
    void *flush_context,
    watchdog_safety_result *result
);

int watchdog_safety_supervisor_open(
    watchdog_safety_supervisor *supervisor,
    const watchdog_safety_config *config
);
void watchdog_safety_supervisor_close(watchdog_safety_supervisor *supervisor);
int watchdog_safety_supervisor_tick(
    watchdog_safety_supervisor *supervisor,
    const watchdog_sample *sample,
    int (*flush_storage)(void *context),
    void *flush_context,
    watchdog_safety_result results[WATCHDOG_SAFETY_MAX_TARGETS],
    size_t *result_count
);
size_t watchdog_safety_supervisor_active(const watchdog_safety_supervisor *supervisor);
bool watchdog_safety_supervisor_tripped(const watchdog_safety_supervisor *supervisor);
bool watchdog_safety_supervisor_armed(const watchdog_safety_supervisor *supervisor);
const watchdog_safety_runtime *watchdog_safety_supervisor_primary(
    const watchdog_safety_supervisor *supervisor
);

#endif
