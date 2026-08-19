#include "watchdog/server.h"

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WATCHDOG_VERSION "0.11.0-rc.5"

static void usage(FILE *stream, const char *program) {
    fprintf(stream,
        "Usage: %s [options]\n"
        "  --listen ADDRESS       Bind address (default 0.0.0.0)\n"
        "  --port PORT            TCP port (default 9768)\n"
        "  --data-dir PATH        Durable data directory\n"
        "  --cert PATH            TLS server certificate chain\n"
        "  --key PATH             TLS server private key\n"
        "  --controller-ca PATH   CA used to verify controller certificates\n"
        "  --controllers PATH     Private authorized-controller registry\n"
        "  --site-state PATH       Private typed Let's Infer service descriptor\n"
        "  --gateway-metrics PATH  Private gateway counter snapshot\n"
        "  --sample-ms N          Sampling interval (default 1000)\n"
        "  --flush-ms N           Durable flush interval (default 10000)\n"
        "  --max-controllers N    Concurrent controllers, maximum 4\n"
        "  --protect-root PATH    Private protected-engine directory root\n"
        "  --warning-bytes N      Required available-memory warning threshold\n"
        "  --stop-bytes N         Required available-memory graceful-stop threshold\n"
        "  --kill-bytes N         Required available-memory emergency-kill threshold\n"
        "  --swap-stop-bytes N    Required swap-use graceful-stop threshold\n"
        "  --psi-some-us N        Required one-second partial-stall stop threshold\n"
        "  --psi-full-us N        Required one-second full-stall stop threshold\n"
        "  --state-failures N     Required handshake failures before containment\n"
        "  --containment-grace-ms N  Required grace before escalating stop to kill\n"
        "  --version              Print version\n"
        "  --help                 Print this help\n",
        program);
}

static int parse_unsigned(const char *text, unsigned long maximum, unsigned long *value) {
    if (text == NULL || *text == '\0') return -1;
    char *end = NULL;
    errno = 0;
    const unsigned long parsed = strtoul(text, &end, 10);
    if (errno != 0 || *end != '\0' || parsed == 0 || parsed > maximum) return -1;
    *value = parsed;
    return 0;
}

int main(int argc, char **argv) {
    watchdog_config config = {
        .listen_address = "0.0.0.0",
        .port = WATCHDOG_DEFAULT_PORT,
        .data_directory = "/var/lib/letsinfer/watchdog",
        .certificate_path = "/etc/letsinfer/watchdog/server.crt",
        .private_key_path = "/etc/letsinfer/watchdog/server.key",
        .controller_ca_path = "/etc/letsinfer/watchdog/controller-ca.crt",
        .controller_registry_path = "/etc/letsinfer/watchdog/controllers.allow",
        .site_state_path = "/var/lib/letsinfer/watchdog/letsinfer.state",
        .gateway_metrics_path = "/var/lib/letsinfer/gateway/telemetry.state",
        .sample_interval_ms = WATCHDOG_DEFAULT_SAMPLE_INTERVAL_MS,
        .flush_interval_ms = WATCHDOG_DEFAULT_FLUSH_INTERVAL_MS,
        .max_controllers = WATCHDOG_DEFAULT_MAX_CONTROLLERS,
        .safety = {
            .state_path = "/var/lib/letsinfer/watchdog/protected-engines"
        }
    };
    static const struct option options[] = {
        {"listen", required_argument, NULL, 'l'},
        {"port", required_argument, NULL, 'p'},
        {"data-dir", required_argument, NULL, 'd'},
        {"cert", required_argument, NULL, 'c'},
        {"key", required_argument, NULL, 'k'},
        {"controller-ca", required_argument, NULL, 'a'},
        {"controllers", required_argument, NULL, 'A'},
        {"site-state", required_argument, NULL, 'b'},
        {"gateway-metrics", required_argument, NULL, 'M'},
        {"sample-ms", required_argument, NULL, 's'},
        {"flush-ms", required_argument, NULL, 'f'},
        {"max-controllers", required_argument, NULL, 'm'},
        {"protect-root", required_argument, NULL, 'P'},
        {"warning-bytes", required_argument, NULL, 'w'},
        {"stop-bytes", required_argument, NULL, 'S'},
        {"kill-bytes", required_argument, NULL, 'K'},
        {"swap-stop-bytes", required_argument, NULL, 'W'},
        {"psi-some-us", required_argument, NULL, 'q'},
        {"psi-full-us", required_argument, NULL, 'Q'},
        {"state-failures", required_argument, NULL, 'F'},
        {"containment-grace-ms", required_argument, NULL, 'G'},
        {"version", no_argument, NULL, 'v'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

    int option;
    while ((option = getopt_long(argc, argv, "", options, NULL)) != -1) {
        unsigned long parsed = 0;
        switch (option) {
        case 'l': config.listen_address = optarg; break;
        case 'd': config.data_directory = optarg; break;
        case 'c': config.certificate_path = optarg; break;
        case 'k': config.private_key_path = optarg; break;
        case 'a': config.controller_ca_path = optarg; break;
        case 'A': config.controller_registry_path = optarg; break;
        case 'b': config.site_state_path = optarg; break;
        case 'M': config.gateway_metrics_path = optarg; break;
        case 'P': config.safety.state_path = optarg; break;
        case 'p':
            if (parse_unsigned(optarg, UINT16_MAX, &parsed) != 0) goto invalid;
            config.port = (uint16_t)parsed;
            break;
        case 's':
            if (parse_unsigned(optarg, UINT32_MAX, &parsed) != 0) goto invalid;
            config.sample_interval_ms = (uint32_t)parsed;
            break;
        case 'f':
            if (parse_unsigned(optarg, UINT32_MAX, &parsed) != 0) goto invalid;
            config.flush_interval_ms = (uint32_t)parsed;
            break;
        case 'm':
            if (parse_unsigned(
                    optarg, WATCHDOG_HARD_MAX_CONTROLLERS, &parsed) != 0) goto invalid;
            config.max_controllers = (uint32_t)parsed;
            break;
        case 'w':
            if (parse_unsigned(optarg, ULONG_MAX, &parsed) != 0) goto invalid;
            config.safety.thresholds.warning_available_bytes = (uint64_t)parsed;
            break;
        case 'S':
            if (parse_unsigned(optarg, ULONG_MAX, &parsed) != 0) goto invalid;
            config.safety.thresholds.graceful_available_bytes = (uint64_t)parsed;
            break;
        case 'K':
            if (parse_unsigned(optarg, ULONG_MAX, &parsed) != 0) goto invalid;
            config.safety.thresholds.emergency_available_bytes = (uint64_t)parsed;
            break;
        case 'W':
            if (parse_unsigned(optarg, ULONG_MAX, &parsed) != 0) goto invalid;
            config.safety.thresholds.swap_stop_bytes = (uint64_t)parsed;
            break;
        case 'q':
            if (parse_unsigned(optarg, ULONG_MAX, &parsed) != 0) goto invalid;
            config.safety.thresholds.psi_some_us = (uint64_t)parsed;
            break;
        case 'Q':
            if (parse_unsigned(optarg, ULONG_MAX, &parsed) != 0) goto invalid;
            config.safety.thresholds.psi_full_us = (uint64_t)parsed;
            break;
        case 'F':
            if (parse_unsigned(optarg, UINT32_MAX, &parsed) != 0) goto invalid;
            config.safety.thresholds.state_failures = (uint32_t)parsed;
            break;
        case 'G':
            if (parse_unsigned(optarg, UINT32_MAX, &parsed) != 0) goto invalid;
            config.safety.thresholds.containment_grace_ms = (uint32_t)parsed;
            break;
        case 'v':
            puts("letsinfer-watchdog " WATCHDOG_VERSION);
            return 0;
        case 'h':
            usage(stdout, argv[0]);
            return 0;
        default:
            goto invalid;
        }
    }
    if (optind != argc) goto invalid;
    return watchdog_server_run(&config) == 0 ? 0 : 1;

invalid:
    usage(stderr, argv[0]);
    return 2;
}
