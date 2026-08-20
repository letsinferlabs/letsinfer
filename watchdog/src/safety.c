#include "watchdog/safety.h"

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

int watchdog_safety_validate_thresholds(const watchdog_safety_thresholds *thresholds) {
    if (thresholds == NULL
        || thresholds->warning_available_bytes <= thresholds->graceful_available_bytes
        || thresholds->graceful_available_bytes <= thresholds->emergency_available_bytes
        || thresholds->emergency_available_bytes == 0
        || thresholds->swap_stop_bytes == 0
        || thresholds->psi_some_us == 0
        || thresholds->psi_full_us == 0
        || thresholds->state_failures < 2u
        || thresholds->containment_grace_ms == 0u
        || thresholds->containment_grace_ms > 30000u) {
        return -1;
    }
    return 0;
}

watchdog_safety_decision watchdog_safety_decide(
    const watchdog_safety_thresholds *thresholds,
    const watchdog_safety_input *input
) {
    watchdog_safety_decision decision = {WATCHDOG_SAFETY_ACTION_NONE, NULL};
    if (watchdog_safety_validate_thresholds(thresholds) != 0 || input == NULL) {
        return decision;
    }
    if (input->available_bytes <= thresholds->emergency_available_bytes) {
        return (watchdog_safety_decision){WATCHDOG_SAFETY_ACTION_KILL, "host_memory_emergency"};
    }
    if (input->cgroup_oom_kill_delta != 0
        || input->cgroup_oom_group_kill_delta != 0) {
        return (watchdog_safety_decision){WATCHDOG_SAFETY_ACTION_KILL, "cgroup_oom_kill"};
    }
    /*
     * Available-memory, swap, and PSI thresholds are admission signals.  The
     * site agent publishes them and the gateway stops dispatching new work
     * until headroom returns.  They must not turn ordinary KV-cache pressure
     * into a destructive engine lifecycle event.  Containment is reserved for
     * the hard emergency floor and observed cgroup limit/OOM events below.
     */
    if (input->cgroup_oom_delta != 0 || input->cgroup_max_delta != 0) {
        return (watchdog_safety_decision){WATCHDOG_SAFETY_ACTION_STOP, "cgroup_memory_limit"};
    }
    return decision;
}

const char *watchdog_safety_phase_name(watchdog_safety_phase phase) {
    switch (phase) {
    case WATCHDOG_SAFETY_PHASE_PENDING: return "pending";
    case WATCHDOG_SAFETY_PHASE_STARTING: return "starting";
    case WATCHDOG_SAFETY_PHASE_ARMED: return "armed";
    case WATCHDOG_SAFETY_PHASE_DISARMED: return "disarmed";
    default: return "none";
    }
}

static bool safe_token(const char *value, size_t maximum, bool hex_only) {
    const size_t length = value == NULL ? 0u : strlen(value);
    if (length == 0u || length > maximum) return false;
    for (size_t index = 0; index < length; ++index) {
        const unsigned char byte = (unsigned char)value[index];
        if (hex_only ? !isxdigit(byte) : !(isalnum(byte) || byte == '.' || byte == '_' || byte == '-')) {
            return false;
        }
    }
    return true;
}

static bool safe_cgroup(const char *value) {
    if (value == NULL || strncmp(value, "/sys/fs/cgroup/", 15u) != 0
        || strlen(value) >= WATCHDOG_SAFETY_PATH_MAX || strstr(value, "..") != NULL) return false;
    for (const unsigned char *position = (const unsigned char *)value; *position != '\0'; ++position) {
        if (!(isalnum(*position) || strchr("/_.:-", *position) != NULL)) return false;
    }
    return true;
}

static int parse_positive(const char *value, uint64_t maximum, uint64_t *parsed) {
    if (value == NULL || *value == '\0' || !isdigit((unsigned char)*value)) return -1;
    char *end = NULL;
    errno = 0;
    const unsigned long long number = strtoull(value, &end, 10);
    if (errno != 0 || *end != '\0' || number == 0u || number > maximum) return -1;
    *parsed = (uint64_t)number;
    return 0;
}

static watchdog_safety_phase parse_phase(const char *value) {
    if (strcmp(value, "pending") == 0) return WATCHDOG_SAFETY_PHASE_PENDING;
    if (strcmp(value, "starting") == 0) return WATCHDOG_SAFETY_PHASE_STARTING;
    if (strcmp(value, "armed") == 0) return WATCHDOG_SAFETY_PHASE_ARMED;
    if (strcmp(value, "disarmed") == 0) return WATCHDOG_SAFETY_PHASE_DISARMED;
    return WATCHDOG_SAFETY_PHASE_NONE;
}

int watchdog_safety_parse_descriptor(
    const char *text,
    watchdog_protected_engine *target
) {
    if (text == NULL || target == NULL || strlen(text) > 2048u) return -1;
    char buffer[2049];
    memcpy(buffer, text, strlen(text) + 1u);
    memset(target, 0, sizeof(*target));
    unsigned fields = 0u;
    char *save = NULL;
    for (char *line = strtok_r(buffer, "\n", &save); line != NULL; line = strtok_r(NULL, "\n", &save)) {
        if (*line == '\0' || strchr(line, '\r') != NULL) return -1;
        char *separator = strchr(line, '=');
        if (separator == NULL || separator == line || strchr(separator + 1, '=') != NULL) return -1;
        *separator = '\0';
        const char *value = separator + 1;
        unsigned bit = 0u;
        if (strcmp(line, "version") == 0) {
            if (strcmp(value, "1") != 0) return -1;
            bit = 1u << 0;
        } else if (strcmp(line, "generation") == 0) {
            if (!safe_token(value, WATCHDOG_SAFETY_GENERATION_MAX, true)
                || strlen(value) != WATCHDOG_SAFETY_GENERATION_MAX) return -1;
            memcpy(target->generation, value, strlen(value) + 1u);
            bit = 1u << 1;
        } else if (strcmp(line, "phase") == 0) {
            target->phase = parse_phase(value);
            if (target->phase == WATCHDOG_SAFETY_PHASE_NONE) return -1;
            bit = 1u << 2;
        } else if (strcmp(line, "container_name") == 0) {
            if (!safe_token(value, WATCHDOG_SAFETY_CONTAINER_NAME_MAX, false)) return -1;
            memcpy(target->container_name, value, strlen(value) + 1u);
            bit = 1u << 3;
        } else if (strcmp(line, "container_id") == 0) {
            if (strcmp(value, "-") != 0) {
                if (!safe_token(value, WATCHDOG_SAFETY_CONTAINER_ID_MAX, true)
                    || strlen(value) != WATCHDOG_SAFETY_CONTAINER_ID_MAX) return -1;
                memcpy(target->container_id, value, strlen(value) + 1u);
            }
            bit = 1u << 4;
        } else if (strcmp(line, "pid") == 0) {
            if (strcmp(value, "-") != 0) {
                uint64_t parsed = 0u;
                if (parse_positive(value, INT32_MAX, &parsed) != 0 || parsed <= 1u) return -1;
                target->pid = (int)parsed;
            }
            bit = 1u << 5;
        } else if (strcmp(line, "start_ticks") == 0) {
            if (strcmp(value, "-") != 0
                && parse_positive(value, UINT64_MAX, &target->start_ticks) != 0) return -1;
            bit = 1u << 6;
        } else if (strcmp(line, "boot_id") == 0) {
            if (strcmp(value, "-") != 0) {
                if (!safe_token(value, WATCHDOG_SAFETY_BOOT_ID_MAX, false)
                    || strlen(value) != WATCHDOG_SAFETY_BOOT_ID_MAX) return -1;
                memcpy(target->boot_id, value, strlen(value) + 1u);
            }
            bit = 1u << 7;
        } else if (strcmp(line, "cgroup") == 0) {
            if (strcmp(value, "-") != 0) {
                if (!safe_cgroup(value)) return -1;
                memcpy(target->cgroup_path, value, strlen(value) + 1u);
            }
            bit = 1u << 8;
        } else {
            return -1;
        }
        if ((fields & bit) != 0u) return -1;
        fields |= bit;
    }
    if (fields != 0x1ffu) return -1;
    const bool needs_id = target->phase == WATCHDOG_SAFETY_PHASE_STARTING
        || target->phase == WATCHDOG_SAFETY_PHASE_ARMED;
    if (needs_id != (target->container_id[0] != '\0')
        || needs_id != (target->pid > 1)
        || needs_id != (target->start_ticks != 0u)
        || needs_id != (target->boot_id[0] != '\0')
        || needs_id != (target->cgroup_path[0] != '\0')) return -1;
    return 0;
}
