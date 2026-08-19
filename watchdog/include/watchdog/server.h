#ifndef WATCHDOG_SERVER_H
#define WATCHDOG_SERVER_H

#include "watchdog/safety.h"

#include <stdbool.h>
#include <stdint.h>

#define WATCHDOG_DEFAULT_PORT 9768u
#define WATCHDOG_DEFAULT_SAMPLE_INTERVAL_MS 1000u
#define WATCHDOG_DEFAULT_FLUSH_INTERVAL_MS 10000u
#define WATCHDOG_DEFAULT_MAX_CONTROLLERS 16u
#define WATCHDOG_HARD_MAX_CONTROLLERS 16u
#define WATCHDOG_STATUS_TEXT_MAX 127u

typedef struct watchdog_public_state {
    char installation_id[65u];
    char release[WATCHDOG_STATUS_TEXT_MAX + 1u];
    char model[WATCHDOG_STATUS_TEXT_MAX + 1u];
    char engine[WATCHDOG_STATUS_TEXT_MAX + 1u];
    char runtime_name[WATCHDOG_STATUS_TEXT_MAX + 1u];
    char runtime_version[WATCHDOG_STATUS_TEXT_MAX + 1u];
    char manifest_sha256[65u];
    char cache_provider[WATCHDOG_STATUS_TEXT_MAX + 1u];
    bool cache_persistent;
    uint32_t inference_port;
    uint32_t max_connections;
    uint32_t max_active_requests;
    uint32_t max_context_tokens;
} watchdog_public_state;

typedef struct watchdog_config {
    const char *listen_address;
    uint16_t port;
    const char *data_directory;
    const char *certificate_path;
    const char *private_key_path;
    const char *controller_ca_path;
    const char *controller_registry_path;
    const char *site_state_path;
    const char *gateway_metrics_path;
    uint32_t sample_interval_ms;
    uint32_t flush_interval_ms;
    uint32_t max_controllers;
    watchdog_safety_config safety;
} watchdog_config;

int watchdog_server_run(const watchdog_config *config);

#endif
