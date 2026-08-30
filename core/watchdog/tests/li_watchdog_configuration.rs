// SPDX-License-Identifier: AGPL-3.0-only

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use li_watchdog_manager::{
    WatchdogConfiguration, WatchdogConfigurationFile, WatchdogConfigurationFileProvider,
    WatchdogConfigurationLoader, WatchdogError, WatchdogGatewayCounterProviderKind,
    WatchdogGpuProviderKind, WATCHDOG_CONFIGURATION_MAX_BYTES,
};

// Returns one complete exact version-one resident configuration.
fn valid_configuration() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schema": {"name": "li_watchdog_configuration", "version": 2},
        "installation_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "node_id": "11111111111111111111111111111111",
        "core_release": "0.1.0",
        "core_source_identity": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "listener": {"address": "127.0.0.1", "port": 7443},
        "node_protection": {"socket_path": "/run/user/1000/letsinfer/node_protection.sock", "read_timeout_milliseconds": 1000, "write_timeout_milliseconds": 1000},
        "paths": {
            "data_directory": "/var/lib/letsinfer/watchdog",
            "server_certificate_path": "/etc/letsinfer/watchdog/server.crt",
            "server_private_key_path": "/etc/letsinfer/watchdog/server.key",
            "controller_ca_path": "/etc/letsinfer/watchdog/controller-ca.crt",
            "controller_allowlist_path": "/etc/letsinfer/watchdog/controllers.allow",
            "controller_snapshot_path": "/var/lib/letsinfer/watchdog/controllers.snapshot",
            "site_state_path": "/var/lib/letsinfer/watchdog/letsinfer.state",
            "gateway_metrics_path": "/var/lib/letsinfer/gateway/telemetry.state",
            "protection_root_path": "/var/lib/letsinfer/watchdog/protected-placements",
            "node_database_path": "/var/lib/letsinfer/core.sqlite3",
            "runtime_installation_root": "/var/lib/letsinfer/runtime-installations",
            "runtime_cache_root": "/var/cache/letsinfer/runtimes"
        },
        "cadence": {"sample_interval_milliseconds": 1000, "flush_interval_milliseconds": 10000},
        "maximum_controllers": 16,
        "providers": {"gpu": "nvml", "gateway_counters": "gateway_telemetry_v2"},
        "thresholds": {
            "warning_available_bytes": 17179869184_u64,
            "graceful_available_bytes": 8589934592_u64,
            "emergency_available_bytes": 4294967296_u64,
            "swap_stop_bytes": 1073741824_u64,
            "psi_some_microseconds": 100000,
            "psi_full_microseconds": 50000,
            "state_failures": 3,
            "containment_grace_milliseconds": 5000
        }
    }))
    .unwrap()
}

// Replaces one exact fixture line while preserving the closed field count.
fn replacing(source: &[u8], old: &str, new: &str) -> Vec<u8> {
    String::from_utf8(source.to_vec())
        .unwrap()
        .replace(old, new)
        .into_bytes()
}

// Returns whether an operation failed at either closed configuration boundary.
fn is_configuration_error(result: Result<WatchdogConfiguration, WatchdogError>) -> bool {
    matches!(result, Err(WatchdogError::InvalidContract { .. }))
}

#[test]
// Parses every required identity, provider, cadence, and threshold without defaults.
fn configuration_parses_complete_closed_document() {
    let configuration = WatchdogConfiguration::parse(&valid_configuration()).unwrap();
    assert_eq!(configuration.listen_address().to_string(), "127.0.0.1");
    assert_eq!(configuration.listen_port(), 7443);
    assert_eq!(configuration.node_id().as_str(), "1".repeat(32));
    assert_eq!(configuration.core_release(), "0.1.0");
    assert_eq!(
        configuration.core_source_identity().as_str(),
        "c".repeat(64)
    );
    assert_eq!(configuration.sample_interval_milliseconds(), 1_000);
    assert_eq!(configuration.flush_interval_milliseconds(), 10_000);
    assert_eq!(configuration.maximum_controllers(), 16);
    assert_eq!(configuration.gpu_provider(), WatchdogGpuProviderKind::Nvml);
    assert_eq!(
        configuration.gateway_counter_provider(),
        WatchdogGatewayCounterProviderKind::GatewayTelemetryVersionTwo
    );
    assert_eq!(configuration.thresholds().state_failures(), 3);
}

#[test]
// Rejects missing, duplicated, unknown, reordered, and trailing fields.
fn configuration_rejects_every_open_document_shape() {
    let valid = valid_configuration();
    let cases = [
        replacing(&valid, "\"maximum_controllers\":16,", ""),
        replacing(
            &valid,
            "\"core_source_identity\":\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\",",
            "",
        ),
        replacing(
            &valid,
            "\"maximum_controllers\":16",
            "\"maximum_controllers\":16,\"maximum_controllers\":16",
        ),
        replacing(&valid, "\"maximum_controllers\":16", "\"unknown\":16"),
        replacing(
            &valid,
            "\"maximum_controllers\":16",
            "\"maximum_controllers\":16,\"unknown\":1",
        ),
        replacing(&valid, "\"version\":2", "\"version\":1"),
    ];
    for source in cases {
        assert!(is_configuration_error(WatchdogConfiguration::parse(
            &source
        )));
    }
}

#[test]
// Rejects malformed framing, numeric aliases, and unsupported provider claims.
fn configuration_rejects_framing_numbers_and_provider_substitution() {
    let valid = valid_configuration();
    let mut truncated = valid.clone();
    truncated.pop();
    let cases = [
        truncated,
        replacing(&valid, "\"port\":7443", "\"port\":0"),
        replacing(
            &valid,
            "\"sample_interval_milliseconds\":1000",
            "\"sample_interval_milliseconds\":999",
        ),
        replacing(&valid, "\"gpu\":\"nvml\"", "\"gpu\":\"unsupported\""),
        replacing(&valid, &"c".repeat(64), &"C".repeat(64)),
        replacing(
            &valid,
            "\"gateway_counters\":\"gateway_telemetry_v2\"",
            "\"gateway_counters\":\"none\"",
        ),
    ];
    for source in cases {
        assert!(is_configuration_error(WatchdogConfiguration::parse(
            &source
        )));
    }
}

#[test]
// Rejects relative, aliased, duplicate, and oversized normalized path values.
fn configuration_rejects_unsafe_paths() {
    let valid = valid_configuration();
    let cases = [
        replacing(
            &valid,
            "/etc/letsinfer/watchdog/server.crt",
            "relative/server.crt",
        ),
        replacing(
            &valid,
            "/etc/letsinfer/watchdog/server.crt",
            "/etc/letsinfer/../server.crt",
        ),
        replacing(
            &valid,
            "/etc/letsinfer/watchdog/server.crt",
            "/etc/letsinfer/watchdog/server.key",
        ),
    ];
    for source in cases {
        assert!(is_configuration_error(WatchdogConfiguration::parse(
            &source
        )));
    }
}

// Returns one injected configuration file observation.
struct MockFileProvider {
    observation: Mutex<Option<WatchdogConfigurationFile>>,
}

impl WatchdogConfigurationFileProvider for MockFileProvider {
    // Returns the single injected observation and proves the loader's read bound.
    fn read(
        &self,
        _path: &Path,
        maximum_bytes: usize,
    ) -> Result<WatchdogConfigurationFile, WatchdogError> {
        assert_eq!(maximum_bytes, WATCHDOG_CONFIGURATION_MAX_BYTES);
        self.observation
            .lock()
            .unwrap()
            .take()
            .ok_or(WatchdogError::StateUnavailable)
    }
}

// Creates one loader around an exact injected descriptor observation.
fn loader_with(observation: WatchdogConfigurationFile) -> WatchdogConfigurationLoader {
    WatchdogConfigurationLoader::new(
        PathBuf::from("/etc/letsinfer/watchdog/li_watchdog.conf"),
        501,
        Box::new(MockFileProvider {
            observation: Mutex::new(Some(observation)),
        }),
    )
    .unwrap()
}

#[test]
// Accepts only a stable owner-matching mode-0600 single-link regular file.
fn configuration_loader_enforces_descriptor_identity() {
    let valid = valid_configuration();
    let accepted = WatchdogConfigurationFile::new(valid.clone(), 501, 0o600, 1, true, true);
    assert!(loader_with(accepted).load().is_ok());

    let unsafe_observations = [
        WatchdogConfigurationFile::new(valid.clone(), 502, 0o600, 1, true, true),
        WatchdogConfigurationFile::new(valid.clone(), 501, 0o640, 1, true, true),
        WatchdogConfigurationFile::new(valid.clone(), 501, 0o600, 2, true, true),
        WatchdogConfigurationFile::new(valid.clone(), 501, 0o600, 1, false, true),
        WatchdogConfigurationFile::new(valid, 501, 0o600, 1, true, false),
    ];
    for observation in unsafe_observations {
        assert!(loader_with(observation).load().is_err());
    }
}

#[test]
// Rejects a relative or lexically aliased configuration path before provider access.
fn configuration_loader_rejects_unsafe_source_path() {
    let provider = || {
        Box::new(MockFileProvider {
            observation: Mutex::new(None),
        })
    };
    assert!(WatchdogConfigurationLoader::new(PathBuf::from("relative"), 501, provider()).is_err());
    assert!(
        WatchdogConfigurationLoader::new(PathBuf::from("/etc/../config"), 501, provider()).is_err()
    );
}

#[test]
// Keeps the published JSON Schema identity and closed-object policy aligned with the parser.
fn configuration_schema_matches_the_runtime_identity() {
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/watchdog/li_watchdog_configuration_v2.schema.json"
    ))
    .unwrap();
    assert_eq!(
        schema["properties"]["schema"]["properties"]["name"]["const"],
        "li_watchdog_configuration"
    );
    assert_eq!(
        schema["properties"]["schema"]["properties"]["version"]["const"],
        2
    );
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(
        schema["properties"]["core_source_identity"]["pattern"],
        "^[0-9a-f]{64}$"
    );
    assert_eq!(
        schema["properties"]["providers"]["additionalProperties"],
        false
    );
}
