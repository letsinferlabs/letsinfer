#include "watchdog/safety.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define SAFETY_EVENT_ROTATE_BYTES (1024u * 1024u)

static uint64_t clock_ms(clockid_t clock_id) {
    struct timespec value;
    if (clock_gettime(clock_id, &value) != 0) return 0;
    return (uint64_t)value.tv_sec * 1000u + (uint64_t)value.tv_nsec / 1000000u;
}

static int copy_text(char *target, size_t capacity, const char *source) {
    if (target == NULL || source == NULL || capacity == 0u) return -1;
    const size_t length = strlen(source);
    if (length >= capacity) return -1;
    memcpy(target, source, length + 1u);
    return 0;
}

static int make_peer_path(char output[WATCHDOG_SAFETY_PATH_MAX], const char *state, const char *name) {
    const char *separator = strrchr(state, '/');
    if (separator == NULL || separator == state) return -1;
    const size_t directory = (size_t)(separator - state);
    const int length = snprintf(output, WATCHDOG_SAFETY_PATH_MAX, "%.*s/%s", (int)directory, state, name);
    return length > 0 && (size_t)length < WATCHDOG_SAFETY_PATH_MAX ? 0 : -1;
}

static int read_private_file(const char *path, char *buffer, size_t capacity) {
    if (capacity < 2u) return -1;
    const int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    struct stat details;
    if (fstat(fd, &details) != 0 || !S_ISREG(details.st_mode)
        || details.st_uid != getuid() || (details.st_mode & 0077) != 0) {
        close(fd);
        errno = EPERM;
        return -1;
    }
    size_t used = 0u;
    while (used + 1u < capacity) {
        const ssize_t count = read(fd, buffer + used, capacity - used - 1u);
        if (count == 0) break;
        if (count < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        used += (size_t)count;
    }
    close(fd);
    if (used + 1u == capacity) {
        errno = EFBIG;
        return -1;
    }
    buffer[used] = '\0';
    return 0;
}

static int write_atomic(const char *path, const char *payload) {
    char temporary[WATCHDOG_SAFETY_PATH_MAX];
    const int length = snprintf(temporary, sizeof(temporary), "%s.tmp-%ld", path, (long)getpid());
    if (length <= 0 || (size_t)length >= sizeof(temporary)) return -1;
    const int fd = open(
        temporary,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_DSYNC | O_NOFOLLOW,
        0600
    );
    if (fd < 0) return -1;
    const size_t size = strlen(payload);
    size_t offset = 0u;
    while (offset < size) {
        const ssize_t count = write(fd, payload + offset, size - offset);
        if (count < 0) {
            if (errno == EINTR) continue;
            close(fd);
            unlink(temporary);
            return -1;
        }
        offset += (size_t)count;
    }
    int result = fsync(fd);
    if (close(fd) != 0) result = -1;
    if (result == 0 && rename(temporary, path) != 0) result = -1;
    if (result != 0) unlink(temporary);
    return result;
}

static void close_target(watchdog_safety_runtime *runtime) {
    if (runtime->pid_fd >= 0) close(runtime->pid_fd);
    runtime->pid_fd = -1;
    runtime->container_pid = 0;
    runtime->cgroup_path[0] = '\0';
    runtime->has_cgroup_baseline = false;
    runtime->state_failures = 0u;
    runtime->warned = false;
    runtime->tripped = false;
}

static int rotate_event_log(watchdog_safety_runtime *runtime) {
    struct stat details;
    if (runtime->event_fd < 0 || fstat(runtime->event_fd, &details) != 0) return -1;
    if ((uint64_t)details.st_size < SAFETY_EVENT_ROTATE_BYTES) return 0;
    close(runtime->event_fd);
    runtime->event_fd = -1;
    char previous[WATCHDOG_SAFETY_PATH_MAX];
    const int length = snprintf(previous, sizeof(previous), "%s.1", runtime->event_path);
    if (length <= 0 || (size_t)length >= sizeof(previous)) return -1;
    unlink(previous);
    if (rename(runtime->event_path, previous) != 0 && errno != ENOENT) return -1;
    runtime->event_fd = open(
        runtime->event_path,
        O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_DSYNC | O_NOFOLLOW,
        0600
    );
    return runtime->event_fd >= 0 ? 0 : -1;
}

static int emit_event(
    watchdog_safety_runtime *runtime,
    watchdog_safety_result *result,
    const char *kind,
    uint32_t severity,
    const char *reason,
    const char *format,
    ...
) {
    memset(result, 0, sizeof(*result));
    result->has_event = true;
    result->severity = severity;
    if (copy_text(result->kind, sizeof(result->kind), kind) != 0
        || copy_text(result->reason, sizeof(result->reason), reason == NULL ? "" : reason) != 0) return -1;
    va_list arguments;
    va_start(arguments, format);
    const int payload_length = vsnprintf(result->payload_json, sizeof(result->payload_json), format, arguments);
    va_end(arguments);
    if (payload_length < 0 || (size_t)payload_length >= sizeof(result->payload_json)) return -1;
    char line[WATCHDOG_SAFETY_PAYLOAD_MAX + 512u];
    const int line_length = snprintf(
        line,
        sizeof(line),
        "{\"timestamp_unix_ms\":%llu,\"event\":\"%s\",\"severity\":%u,"
        "\"reason\":\"%s\",\"payload\":%s}\n",
        (unsigned long long)clock_ms(CLOCK_REALTIME),
        kind,
        severity,
        reason == NULL ? "" : reason,
        result->payload_json
    );
    if (line_length < 0 || (size_t)line_length >= sizeof(line) || rotate_event_log(runtime) != 0) return -1;
    size_t offset = 0u;
    while (offset < (size_t)line_length) {
        const ssize_t count = write(runtime->event_fd, line + offset, (size_t)line_length - offset);
        if (count < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        offset += (size_t)count;
    }
    return fdatasync(runtime->event_fd);
}

static int acknowledge(watchdog_safety_runtime *runtime, const watchdog_protected_engine *target) {
    char payload[512];
    const int length = snprintf(
        payload,
        sizeof(payload),
        "version=1\ngeneration=%s\nphase=%s\ncontainer_id=%s\n",
        target->generation,
        watchdog_safety_phase_name(target->phase),
        target->container_id[0] == '\0' ? "-" : target->container_id
    );
    return length > 0 && (size_t)length < sizeof(payload) ? write_atomic(runtime->ack_path, payload) : -1;
}

static int open_pidfd(int pid) {
#ifdef SYS_pidfd_open
    return (int)syscall(SYS_pidfd_open, pid, 0u);
#else
    (void)pid;
    errno = ENOSYS;
    return -1;
#endif
}

static int signal_pidfd(int pid_fd, int signal_number) {
#ifdef SYS_pidfd_send_signal
    const int result = (int)syscall(
        SYS_pidfd_send_signal, pid_fd, signal_number, NULL, 0u
    );
    return result == 0 || errno == ESRCH ? 0 : -1;
#else
    (void)pid_fd;
    (void)signal_number;
    errno = ENOSYS;
    return -1;
#endif
}

static int process_cgroup(int pid, char output[WATCHDOG_SAFETY_PATH_MAX]);

/* Last-resort containment for a container init process that does not exit
 * after SIGKILL. The cgroup path was bound to the exact PID/start/boot tuple;
 * revalidate each member before signaling so this cannot escape that target. */
static void signal_cgroup_members(const char *cgroup_path, int signal_number) {
    char path[WATCHDOG_SAFETY_PATH_MAX];
    const int length = snprintf(path, sizeof(path), "%s/cgroup.procs", cgroup_path);
    if (length <= 0 || (size_t)length >= sizeof(path)) return;
    FILE *stream = fopen(path, "re");
    if (stream == NULL) return;
    int pid = 0;
    while (fscanf(stream, "%d", &pid) == 1) {
        if (pid <= 1) continue;
        char actual[WATCHDOG_SAFETY_PATH_MAX];
        if (process_cgroup(pid, actual) != 0 || strcmp(actual, cgroup_path) != 0) continue;
        const int fd = open_pidfd(pid);
        if (fd >= 0) {
            (void)signal_pidfd(fd, signal_number);
            close(fd);
        }
    }
    fclose(stream);
}

static int cgroup_empty(const char *cgroup_path) {
    char path[WATCHDOG_SAFETY_PATH_MAX];
    const int length = snprintf(path, sizeof(path), "%s/cgroup.procs", cgroup_path);
    if (length <= 0 || (size_t)length >= sizeof(path)) return -1;
    FILE *stream = fopen(path, "re");
    if (stream == NULL) return errno == ENOENT ? 1 : -1;
    int pid = 0;
    const int scanned = fscanf(stream, "%d", &pid);
    const int result = scanned == EOF && !ferror(stream) ? 1 : scanned == 1 ? 0 : -1;
    fclose(stream);
    return result;
}

static int wait_cgroup_empty(const char *cgroup_path) {
    for (unsigned attempt = 0u; attempt < 20u; ++attempt) {
        const int state = cgroup_empty(cgroup_path);
        if (state != 0) return state;
        const struct timespec pause = {.tv_sec = 0, .tv_nsec = 100000000L};
        (void)nanosleep(&pause, NULL);
    }
    return cgroup_empty(cgroup_path);
}

static uint64_t process_start_ticks(int pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    const int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0u;
    char buffer[4096];
    const ssize_t count = read(fd, buffer, sizeof(buffer) - 1u);
    close(fd);
    if (count <= 0) return 0u;
    buffer[count] = '\0';
    char *position = strrchr(buffer, ')');
    if (position == NULL || position[1] != ' ') return 0u;
    position += 2;
    unsigned field = 3u;
    char *save = NULL;
    for (char *token = strtok_r(position, " ", &save); token != NULL; token = strtok_r(NULL, " ", &save), ++field) {
        if (field == 22u) return strtoull(token, NULL, 10);
    }
    return 0u;
}

static int current_boot_id(char output[WATCHDOG_SAFETY_BOOT_ID_MAX + 1u]) {
    const int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    const ssize_t count = read(fd, output, WATCHDOG_SAFETY_BOOT_ID_MAX);
    close(fd);
    if (count != (ssize_t)WATCHDOG_SAFETY_BOOT_ID_MAX) return -1;
    output[WATCHDOG_SAFETY_BOOT_ID_MAX] = '\0';
    return 0;
}

static int process_cgroup(int pid, char output[WATCHDOG_SAFETY_PATH_MAX]) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cgroup", pid);
    const int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    char buffer[8192];
    const ssize_t count = read(fd, buffer, sizeof(buffer) - 1u);
    close(fd);
    if (count <= 0) return -1;
    buffer[count] = '\0';
    char *unified = strstr(buffer, "0::/");
    if (unified == NULL) return -1;
    unified += 3;
    char *newline = strchr(unified, '\n');
    if (newline != NULL) *newline = '\0';
    const int length = snprintf(output, WATCHDOG_SAFETY_PATH_MAX, "/sys/fs/cgroup%s", unified);
    return length > 0 && (size_t)length < WATCHDOG_SAFETY_PATH_MAX ? 0 : -1;
}

static int bind_target(watchdog_safety_runtime *runtime, const watchdog_protected_engine *target) {
    char boot_id[WATCHDOG_SAFETY_BOOT_ID_MAX + 1u];
    char cgroup[WATCHDOG_SAFETY_PATH_MAX];
    if (current_boot_id(boot_id) != 0 || strcmp(boot_id, target->boot_id) != 0
        || process_start_ticks(target->pid) != target->start_ticks
        || process_cgroup(target->pid, cgroup) != 0
        || strcmp(cgroup, target->cgroup_path) != 0) return -1;
    const int pid_fd = open_pidfd(target->pid);
    if (pid_fd < 0) return -1;
    close_target(runtime);
    runtime->pid_fd = pid_fd;
    runtime->container_pid = target->pid;
    if (copy_text(runtime->cgroup_path, sizeof(runtime->cgroup_path), target->cgroup_path) != 0) {
        close_target(runtime);
        return -1;
    }
    return 0;
}

static uint64_t meminfo_kib(const char *buffer, const char *key) {
    const char *position = strstr(buffer, key);
    if (position == NULL || (position != buffer && position[-1] != '\n')) return 0u;
    position += strlen(key);
    while (*position == ':' || *position == ' ' || *position == '\t') ++position;
    return strtoull(position, NULL, 10);
}

static int read_memory(watchdog_safety_input *input) {
    const int fd = open("/proc/meminfo", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    char buffer[8192];
    const ssize_t count = read(fd, buffer, sizeof(buffer) - 1u);
    close(fd);
    if (count <= 0) return -1;
    buffer[count] = '\0';
    const uint64_t available = meminfo_kib(buffer, "MemAvailable");
    const uint64_t swap_total = meminfo_kib(buffer, "SwapTotal");
    const uint64_t swap_free = meminfo_kib(buffer, "SwapFree");
    if (available == 0u) return -1;
    input->available_bytes = available * 1024u;
    input->swap_used_bytes = swap_total > swap_free ? (swap_total - swap_free) * 1024u : 0u;
    return 0;
}

static uint64_t pressure_total(const char *buffer, const char *kind) {
    const char *line = strstr(buffer, kind);
    if (line == NULL || (line != buffer && line[-1] != '\n')) return 0u;
    const char *total = strstr(line, " total=");
    return total == NULL ? 0u : strtoull(total + 7, NULL, 10);
}

static void read_pressure(watchdog_safety_runtime *runtime, watchdog_safety_input *input) {
    const int fd = open("/proc/pressure/memory", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    char buffer[1024];
    const ssize_t count = read(fd, buffer, sizeof(buffer) - 1u);
    close(fd);
    if (count <= 0) return;
    buffer[count] = '\0';
    const uint64_t some = pressure_total(buffer, "some ");
    const uint64_t full = pressure_total(buffer, "full ");
    if (runtime->has_pressure_baseline) {
        input->psi_some_delta_us = some >= runtime->previous_psi_some ? some - runtime->previous_psi_some : 0u;
        input->psi_full_delta_us = full >= runtime->previous_psi_full ? full - runtime->previous_psi_full : 0u;
    }
    runtime->previous_psi_some = some;
    runtime->previous_psi_full = full;
    runtime->has_pressure_baseline = true;
}

static int read_cgroup_events(watchdog_safety_runtime *runtime, watchdog_safety_input *input) {
    char path[WATCHDOG_SAFETY_PATH_MAX];
    const int length = snprintf(path, sizeof(path), "%s/memory.events", runtime->cgroup_path);
    if (length <= 0 || (size_t)length >= sizeof(path)) return -1;
    const int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    char source[2048];
    const ssize_t count = read(fd, source, sizeof(source) - 1u);
    close(fd);
    if (count <= 0) return -1;
    source[count] = '\0';

    uint64_t oom = 0u;
    uint64_t oom_kill = 0u;
    uint64_t oom_group_kill = 0u;
    uint64_t maximum = 0u;
    bool saw_oom = false;
    bool saw_oom_kill = false;
    bool saw_max = false;
    char *save = NULL;
    for (char *line = strtok_r(source, "\n", &save); line != NULL; line = strtok_r(NULL, "\n", &save)) {
        char *separator = strchr(line, ' ');
        if (separator == NULL) continue;
        *separator = '\0';
        const uint64_t value = strtoull(separator + 1u, NULL, 10);
        if (strcmp(line, "oom") == 0) {
            oom = value;
            saw_oom = true;
        } else if (strcmp(line, "oom_kill") == 0) {
            oom_kill = value;
            saw_oom_kill = true;
        } else if (strcmp(line, "oom_group_kill") == 0) {
            oom_group_kill = value;
        } else if (strcmp(line, "max") == 0) {
            maximum = value;
            saw_max = true;
        }
    }
    if (!saw_oom || !saw_oom_kill || !saw_max) return -1;
    if (runtime->has_cgroup_baseline) {
        input->cgroup_oom_delta = oom >= runtime->baseline_oom ? oom - runtime->baseline_oom : 0u;
        input->cgroup_oom_kill_delta = oom_kill >= runtime->baseline_oom_kill ? oom_kill - runtime->baseline_oom_kill : 0u;
        input->cgroup_oom_group_kill_delta = oom_group_kill >= runtime->baseline_oom_group_kill
            ? oom_group_kill - runtime->baseline_oom_group_kill : 0u;
        input->cgroup_max_delta = maximum >= runtime->baseline_max ? maximum - runtime->baseline_max : 0u;
    }
    runtime->baseline_oom = oom;
    runtime->baseline_oom_kill = oom_kill;
    runtime->baseline_oom_group_kill = oom_group_kill;
    runtime->baseline_max = maximum;
    runtime->has_cgroup_baseline = true;
    return 0;
}

static int write_trip(
    watchdog_safety_runtime *runtime,
    watchdog_safety_action action,
    const char *reason,
    const watchdog_safety_input *input
) {
    char payload[1024];
    const int length = snprintf(
        payload,
        sizeof(payload),
        "{\n  \"schema_version\": 1,\n  \"timestamp_unix_ms\": %llu,\n"
        "  \"generation\": \"%s\",\n  \"container_id\": \"%s\",\n"
        "  \"action\": \"%s\",\n  \"reason\": \"%s\",\n"
        "  \"available_bytes\": %llu,\n  \"swap_used_bytes\": %llu\n}\n",
        (unsigned long long)clock_ms(CLOCK_REALTIME),
        runtime->target.generation,
        runtime->target.container_id,
        action == WATCHDOG_SAFETY_ACTION_KILL ? "kill" : "stop",
        reason,
        (unsigned long long)input->available_bytes,
        (unsigned long long)input->swap_used_bytes
    );
    return length > 0 && (size_t)length < sizeof(payload) ? write_atomic(runtime->trip_path, payload) : -1;
}

static int load_descriptor(watchdog_safety_runtime *runtime, watchdog_safety_result *result) {
    char text[2049];
    if (read_private_file(runtime->state_path, text, sizeof(text)) != 0) {
        if (errno == ENOENT && runtime->target.phase == WATCHDOG_SAFETY_PHASE_NONE) return 0;
        ++runtime->state_failures;
        return 0;
    }
    watchdog_protected_engine candidate;
    if (watchdog_safety_parse_descriptor(text, &candidate) != 0) {
        ++runtime->state_failures;
        return 0;
    }
    if (strcmp(candidate.generation, runtime->target.generation) == 0
        && candidate.phase == runtime->target.phase
        && strcmp(candidate.container_name, runtime->target.container_name) == 0
        && strcmp(candidate.container_id, runtime->target.container_id) == 0
        && candidate.pid == runtime->target.pid
        && candidate.start_ticks == runtime->target.start_ticks
        && strcmp(candidate.boot_id, runtime->target.boot_id) == 0
        && strcmp(candidate.cgroup_path, runtime->target.cgroup_path) == 0) {
        runtime->state_failures = 0u;
        runtime->state_warned = false;
        return 0;
    }
    if (candidate.phase == WATCHDOG_SAFETY_PHASE_PENDING
        || candidate.phase == WATCHDOG_SAFETY_PHASE_DISARMED) {
        close_target(runtime);
        runtime->target = candidate;
        runtime->state_failures = 0u;
        runtime->state_warned = false;
        if (acknowledge(runtime, &candidate) != 0) return -1;
        return emit_event(
            runtime,
            result,
            candidate.phase == WATCHDOG_SAFETY_PHASE_PENDING ? "protection.pending" : "protection.disarmed",
            0u,
            "",
            "{\"generation\":\"%s\",\"container_name\":\"%s\"}",
            candidate.generation,
            candidate.container_name
        );
    }
    if (bind_target(runtime, &candidate) != 0) {
        ++runtime->state_failures;
        return 0;
    }
    runtime->target = candidate;
    runtime->state_failures = 0u;
    runtime->state_warned = false;
    if (acknowledge(runtime, &candidate) != 0) return -1;
    return emit_event(
        runtime,
        result,
        candidate.phase == WATCHDOG_SAFETY_PHASE_ARMED ? "protection.armed" : "protection.starting",
        0u,
        "",
        "{\"generation\":\"%s\",\"container_name\":\"%s\","
        "\"container_id\":\"%s\",\"pid\":%d}",
        candidate.generation,
        candidate.container_name,
        candidate.container_id,
        candidate.pid
    );
}

int watchdog_safety_open(watchdog_safety_runtime *runtime, const watchdog_safety_config *config) {
    if (runtime == NULL || config == NULL || config->state_path == NULL
        || watchdog_safety_validate_thresholds(&config->thresholds) != 0) return -1;
    memset(runtime, 0, sizeof(*runtime));
    runtime->event_fd = -1;
    runtime->pid_fd = -1;
    runtime->config = *config;
    if (copy_text(runtime->state_path, sizeof(runtime->state_path), config->state_path) != 0
        || make_peer_path(runtime->ack_path, config->state_path, "protected-engine.ack") != 0
        || make_peer_path(runtime->trip_path, config->state_path, "protection-trip.json") != 0
        || make_peer_path(runtime->event_path, config->state_path, "safety-events.ndjson") != 0) return -1;
    runtime->config.state_path = runtime->state_path;
    runtime->event_fd = open(
        runtime->event_path,
        O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_DSYNC | O_NOFOLLOW,
        0600
    );
    return runtime->event_fd >= 0 ? 0 : -1;
}

void watchdog_safety_close(watchdog_safety_runtime *runtime) {
    if (runtime == NULL) return;
    close_target(runtime);
    if (runtime->event_fd >= 0) close(runtime->event_fd);
    runtime->event_fd = -1;
}

int watchdog_safety_tick(
    watchdog_safety_runtime *runtime,
    const watchdog_sample *sample,
    int (*flush_storage)(void *context),
    void *flush_context,
    watchdog_safety_result *result
) {
    (void)sample;
    if (runtime == NULL || result == NULL) return -1;
    memset(result, 0, sizeof(*result));
    if (load_descriptor(runtime, result) != 0 || result->has_event) return result->has_event ? 0 : -1;
    if (runtime->target.phase != WATCHDOG_SAFETY_PHASE_STARTING
        && runtime->target.phase != WATCHDOG_SAFETY_PHASE_ARMED) return 0;
    if (runtime->tripped) return 0;

    struct pollfd process = {.fd = runtime->pid_fd, .events = POLLIN};
    if (runtime->pid_fd < 0 || poll(&process, 1u, 0) > 0) {
        watchdog_safety_input input;
        memset(&input, 0, sizeof(input));
        (void)read_memory(&input);
        if (flush_storage != NULL && flush_storage(flush_context) != 0) return -1;
        if (write_trip(
                runtime,
                WATCHDOG_SAFETY_ACTION_STOP,
                "protected_process_exited",
                &input
            ) != 0) return -1;
        runtime->tripped = true;
        return emit_event(
            runtime,
            result,
            "engine.exit",
            2u,
            "protected_process_exited",
            "{\"generation\":\"%s\",\"container_id\":\"%s\",\"pid\":%d}",
            runtime->target.generation,
            runtime->target.container_id,
            runtime->container_pid
        );
    }

    if (runtime->state_failures >= runtime->config.thresholds.state_failures
        && !runtime->state_warned) {
        runtime->state_warned = true;
        return emit_event(
            runtime,
            result,
            "protection.degraded",
            2u,
            "protection_state_unavailable",
            "{\"generation\":\"%s\",\"container_id\":\"%s\","
            "\"state_failures\":%u}",
            runtime->target.generation,
            runtime->target.container_id,
            runtime->state_failures
        );
    }

    watchdog_safety_input input;
    memset(&input, 0, sizeof(input));
    if (read_memory(&input) != 0) return -1;
    read_pressure(runtime, &input);
    if (read_cgroup_events(runtime, &input) != 0) return -1;
    watchdog_safety_decision decision = watchdog_safety_decide(&runtime->config.thresholds, &input);
    if (input.available_bytes <= runtime->config.thresholds.warning_available_bytes
        && !runtime->warned && decision.action == WATCHDOG_SAFETY_ACTION_NONE) {
        runtime->warned = true;
        return emit_event(
            runtime,
            result,
            "protection.warning",
            1u,
            "host_memory_warning",
            "{\"container_id\":\"%s\",\"available_bytes\":%llu,"
            "\"swap_used_bytes\":%llu}",
            runtime->target.container_id,
            (unsigned long long)input.available_bytes,
            (unsigned long long)input.swap_used_bytes
        );
    }
    if (input.available_bytes > runtime->config.thresholds.warning_available_bytes) runtime->warned = false;
    if (decision.action == WATCHDOG_SAFETY_ACTION_NONE) return 0;

    if (flush_storage != NULL && flush_storage(flush_context) != 0) return -1;
    if (write_trip(runtime, decision.action, decision.reason, &input) != 0) return -1;
    int containment = signal_pidfd(
        runtime->pid_fd,
        decision.action == WATCHDOG_SAFETY_ACTION_KILL ? SIGKILL : SIGTERM
    );
    int ready = containment == 0
        ? poll(
            &process,
            1u,
            decision.action == WATCHDOG_SAFETY_ACTION_STOP
                ? (int)runtime->config.thresholds.containment_grace_ms
                : 1000
        )
        : 0;
    if (ready <= 0) {
        containment = signal_pidfd(runtime->pid_fd, SIGKILL);
        ready = containment == 0 ? poll(&process, 1u, 1000) : 0;
    }
    int empty = cgroup_empty(runtime->cgroup_path);
    if (empty != 1) {
        signal_cgroup_members(runtime->cgroup_path, SIGKILL);
        empty = wait_cgroup_empty(runtime->cgroup_path);
    }
    containment = empty == 1 ? 0 : -1;
    runtime->tripped = true;
    return emit_event(
        runtime,
        result,
        "protection.trip",
        decision.action == WATCHDOG_SAFETY_ACTION_KILL ? 3u : 2u,
        decision.reason,
        "{\"generation\":\"%s\",\"container_id\":\"%s\","
        "\"action\":\"%s\",\"available_bytes\":%llu,"
        "\"swap_used_bytes\":%llu,\"psi_some_delta_us\":%llu,"
        "\"psi_full_delta_us\":%llu,\"cgroup_oom_delta\":%llu,"
        "\"cgroup_oom_kill_delta\":%llu,\"cgroup_oom_group_kill_delta\":%llu,"
        "\"cgroup_max_delta\":%llu,"
        "\"containment_ok\":%s}",
        runtime->target.generation,
        runtime->target.container_id,
        decision.action == WATCHDOG_SAFETY_ACTION_KILL ? "kill" : "stop",
        (unsigned long long)input.available_bytes,
        (unsigned long long)input.swap_used_bytes,
        (unsigned long long)input.psi_some_delta_us,
        (unsigned long long)input.psi_full_delta_us,
        (unsigned long long)input.cgroup_oom_delta,
        (unsigned long long)input.cgroup_oom_kill_delta,
        (unsigned long long)input.cgroup_oom_group_kill_delta,
        (unsigned long long)input.cgroup_max_delta,
        containment == 0 ? "true" : "false"
    );
}

static bool valid_target_key(const char *value) {
    if (value == NULL || strlen(value) != WATCHDOG_SAFETY_TARGET_KEY_MAX) return false;
    for (size_t index = 0u; index < WATCHDOG_SAFETY_TARGET_KEY_MAX; ++index) {
        if (!isdigit((unsigned char)value[index])
            && !(value[index] >= 'a' && value[index] <= 'f')) return false;
    }
    return true;
}

static int private_directory(const char *path) {
    struct stat details;
    return path != NULL
        && lstat(path, &details) == 0
        && S_ISDIR(details.st_mode)
        && !S_ISLNK(details.st_mode)
        && details.st_uid == getuid()
        && (details.st_mode & 0077) == 0
        ? 0 : -1;
}

static watchdog_safety_slot *find_slot(
    watchdog_safety_supervisor *supervisor,
    const char *key
) {
    for (size_t index = 0u; index < WATCHDOG_SAFETY_MAX_TARGETS; ++index) {
        watchdog_safety_slot *slot = &supervisor->slots[index];
        if (slot->used && strcmp(slot->key, key) == 0) return slot;
    }
    return NULL;
}

static watchdog_safety_slot *empty_slot(watchdog_safety_supervisor *supervisor) {
    for (size_t index = 0u; index < WATCHDOG_SAFETY_MAX_TARGETS; ++index) {
        if (!supervisor->slots[index].used) return &supervisor->slots[index];
    }
    return NULL;
}

static void close_slot(watchdog_safety_slot *slot) {
    watchdog_safety_close(&slot->runtime);
    memset(slot, 0, sizeof(*slot));
    slot->runtime.event_fd = -1;
    slot->runtime.pid_fd = -1;
}

static int scan_targets(watchdog_safety_supervisor *supervisor) {
    for (size_t index = 0u; index < WATCHDOG_SAFETY_MAX_TARGETS; ++index) {
        supervisor->slots[index].seen = false;
    }
    DIR *directory = opendir(supervisor->root_path);
    if (directory == NULL) return -1;
    const int descriptor = dirfd(directory);
    struct dirent *entry = NULL;
    int result = 0;
    while (true) {
        errno = 0;
        entry = readdir(directory);
        if (entry == NULL) break;
        if (!valid_target_key(entry->d_name)) continue;
        struct stat details;
        if (fstatat(descriptor, entry->d_name, &details, AT_SYMLINK_NOFOLLOW) != 0
            || !S_ISDIR(details.st_mode)
            || details.st_uid != getuid()
            || (details.st_mode & 0077) != 0) {
            result = -1;
            break;
        }
        watchdog_safety_slot *slot = find_slot(supervisor, entry->d_name);
        if (slot == NULL) {
            slot = empty_slot(supervisor);
            if (slot == NULL) {
                errno = ENOSPC;
                result = -1;
                break;
            }
            char state_path[WATCHDOG_SAFETY_PATH_MAX];
            const int length = snprintf(
                state_path,
                sizeof(state_path),
                "%s/%s/protected-engine.state",
                supervisor->root_path,
                entry->d_name
            );
            if (length <= 0 || (size_t)length >= sizeof(state_path)) {
                result = -1;
                break;
            }
            watchdog_safety_config config = supervisor->config;
            config.state_path = state_path;
            if (watchdog_safety_open(&slot->runtime, &config) != 0
                || copy_text(slot->key, sizeof(slot->key), entry->d_name) != 0) {
                close_slot(slot);
                result = -1;
                break;
            }
            slot->used = true;
        }
        slot->seen = true;
    }
    if (errno != 0) result = -1;
    if (closedir(directory) != 0) result = -1;
    if (result != 0) return -1;
    for (size_t index = 0u; index < WATCHDOG_SAFETY_MAX_TARGETS; ++index) {
        watchdog_safety_slot *slot = &supervisor->slots[index];
        if (!slot->used || slot->seen) continue;
        const watchdog_safety_phase phase = slot->runtime.target.phase;
        if (phase == WATCHDOG_SAFETY_PHASE_NONE
            || phase == WATCHDOG_SAFETY_PHASE_PENDING
            || phase == WATCHDOG_SAFETY_PHASE_DISARMED) close_slot(slot);
    }
    return 0;
}

int watchdog_safety_supervisor_open(
    watchdog_safety_supervisor *supervisor,
    const watchdog_safety_config *config
) {
    if (supervisor == NULL || config == NULL || config->state_path == NULL
        || watchdog_safety_validate_thresholds(&config->thresholds) != 0
        || private_directory(config->state_path) != 0) return -1;
    memset(supervisor, 0, sizeof(*supervisor));
    supervisor->config = *config;
    if (copy_text(
            supervisor->root_path,
            sizeof(supervisor->root_path),
            config->state_path) != 0) return -1;
    supervisor->config.state_path = supervisor->root_path;
    for (size_t index = 0u; index < WATCHDOG_SAFETY_MAX_TARGETS; ++index) {
        supervisor->slots[index].runtime.event_fd = -1;
        supervisor->slots[index].runtime.pid_fd = -1;
    }
    return scan_targets(supervisor);
}

void watchdog_safety_supervisor_close(watchdog_safety_supervisor *supervisor) {
    if (supervisor == NULL) return;
    for (size_t index = 0u; index < WATCHDOG_SAFETY_MAX_TARGETS; ++index) {
        if (supervisor->slots[index].used) close_slot(&supervisor->slots[index]);
    }
}

int watchdog_safety_supervisor_tick(
    watchdog_safety_supervisor *supervisor,
    const watchdog_sample *sample,
    int (*flush_storage)(void *context),
    void *flush_context,
    watchdog_safety_result results[WATCHDOG_SAFETY_MAX_TARGETS],
    size_t *result_count
) {
    if (supervisor == NULL || results == NULL || result_count == NULL
        || scan_targets(supervisor) != 0) return -1;
    *result_count = 0u;
    for (size_t index = 0u; index < WATCHDOG_SAFETY_MAX_TARGETS; ++index) {
        watchdog_safety_slot *slot = &supervisor->slots[index];
        if (!slot->used) continue;
        watchdog_safety_result result;
        if (watchdog_safety_tick(
                &slot->runtime,
                sample,
                flush_storage,
                flush_context,
                &result) != 0) return -1;
        if (result.has_event) results[(*result_count)++] = result;
    }
    return 0;
}

size_t watchdog_safety_supervisor_active(const watchdog_safety_supervisor *supervisor) {
    if (supervisor == NULL) return 0u;
    size_t count = 0u;
    for (size_t index = 0u; index < WATCHDOG_SAFETY_MAX_TARGETS; ++index) {
        const watchdog_safety_runtime *runtime = &supervisor->slots[index].runtime;
        if (supervisor->slots[index].used
            && (runtime->target.phase == WATCHDOG_SAFETY_PHASE_PENDING
                || runtime->target.phase == WATCHDOG_SAFETY_PHASE_STARTING
                || runtime->target.phase == WATCHDOG_SAFETY_PHASE_ARMED)) ++count;
    }
    return count;
}

bool watchdog_safety_supervisor_tripped(const watchdog_safety_supervisor *supervisor) {
    if (supervisor == NULL) return false;
    for (size_t index = 0u; index < WATCHDOG_SAFETY_MAX_TARGETS; ++index) {
        const watchdog_safety_slot *slot = &supervisor->slots[index];
        struct stat details;
        if (slot->used && lstat(slot->runtime.trip_path, &details) == 0
            && S_ISREG(details.st_mode) && !S_ISLNK(details.st_mode)) return true;
    }
    return false;
}

bool watchdog_safety_supervisor_armed(const watchdog_safety_supervisor *supervisor) {
    const size_t active = watchdog_safety_supervisor_active(supervisor);
    if (active == 0u) return false;
    for (size_t index = 0u; index < WATCHDOG_SAFETY_MAX_TARGETS; ++index) {
        const watchdog_safety_slot *slot = &supervisor->slots[index];
        const watchdog_safety_runtime *runtime = &slot->runtime;
        if (!slot->used || runtime->target.phase == WATCHDOG_SAFETY_PHASE_DISARMED
            || runtime->target.phase == WATCHDOG_SAFETY_PHASE_NONE) continue;
        if (runtime->target.phase != WATCHDOG_SAFETY_PHASE_ARMED
            || runtime->pid_fd < 0 || runtime->tripped) return false;
    }
    return !watchdog_safety_supervisor_tripped(supervisor);
}

const watchdog_safety_runtime *watchdog_safety_supervisor_primary(
    const watchdog_safety_supervisor *supervisor
) {
    if (supervisor == NULL) return NULL;
    for (size_t index = 0u; index < WATCHDOG_SAFETY_MAX_TARGETS; ++index) {
        if (!supervisor->slots[index].used) continue;
        const watchdog_safety_phase phase = supervisor->slots[index].runtime.target.phase;
        if (phase == WATCHDOG_SAFETY_PHASE_PENDING
            || phase == WATCHDOG_SAFETY_PHASE_STARTING
            || phase == WATCHDOG_SAFETY_PHASE_ARMED) {
            return &supervisor->slots[index].runtime;
        }
    }
    for (size_t index = 0u; index < WATCHDOG_SAFETY_MAX_TARGETS; ++index) {
        if (supervisor->slots[index].used) return &supervisor->slots[index].runtime;
    }
    return NULL;
}
