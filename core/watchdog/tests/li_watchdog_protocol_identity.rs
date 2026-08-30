// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::VecDeque;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use li_core_interface::{InstallationId, NodeId, Sha256Digest};
use li_watchdog_manager::{
    FilesystemWatchdogProtocolIdentityProvider, SystemWatchdogPublicStateFileProvider,
    WatchdogConfiguration, WatchdogError, WatchdogProtocolDataError,
    WatchdogProtocolIdentityProvider, WatchdogProtocolResidentStatus,
    WatchdogProtocolRuntimeStatus, WatchdogProtocolRuntimeStatusProvider,
    WatchdogProtocolSiteStatus, WatchdogPublicStateFile, WatchdogPublicStateFileProvider,
    WATCHDOG_PUBLIC_STATE_MAX_BYTES,
};

const INSTALLATION_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const MANIFEST_SHA256: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const PUBLIC_STATE: &[u8] = include_bytes!("fixtures/li_watchdog_public_state_v1.state");

// Returns one complete exact configuration with a caller-selected public-state path.
fn configuration(site_state_path: &Path) -> WatchdogConfiguration {
    let source = serde_json::to_vec(&serde_json::json!({
        "schema": {"name": "li_watchdog_configuration", "version": 2},
        "installation_id": INSTALLATION_ID,
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
            "site_state_path": site_state_path,
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
    .unwrap();
    WatchdogConfiguration::parse(&source).unwrap()
}

// Returns one exact coherent runtime projection supplied by the resident safety owner.
fn runtime_status() -> WatchdogProtocolRuntimeStatus {
    WatchdogProtocolRuntimeStatus::new(
        "running".to_string(),
        "running".to_string(),
        "armed".to_string(),
        true,
        false,
        "li_placement_fixture".to_string(),
    )
}

// Creates one owner-private stable injected descriptor observation.
fn public_state_file(bytes: Vec<u8>) -> WatchdogPublicStateFile {
    WatchdogPublicStateFile::new(bytes, 501, 0o600, 1, true, true)
}

// Supplies deterministic public-state observations and verifies the fixed read bound.
struct MockPublicStateFiles {
    reads: Mutex<VecDeque<Result<WatchdogPublicStateFile, WatchdogError>>>,
}

impl WatchdogPublicStateFileProvider for MockPublicStateFiles {
    // Returns the next exact observation for the configured public-state path.
    fn read(
        &self,
        path: &Path,
        maximum_bytes: usize,
    ) -> Result<WatchdogPublicStateFile, WatchdogError> {
        assert_eq!(
            path,
            Path::new("/var/lib/letsinfer/watchdog/letsinfer.state")
        );
        assert_eq!(maximum_bytes, WATCHDOG_PUBLIC_STATE_MAX_BYTES);
        self.reads.lock().unwrap().pop_front().unwrap()
    }
}

// Supplies one exact live status or one injected safety-owner failure.
struct MockRuntimeStatus {
    result: Result<WatchdogProtocolRuntimeStatus, WatchdogError>,
}

impl WatchdogProtocolRuntimeStatusProvider for MockRuntimeStatus {
    // Returns the complete injected runtime projection without deriving defaults.
    fn status(&self) -> Result<WatchdogProtocolRuntimeStatus, WatchdogError> {
        self.result.clone()
    }
}

// Creates one identity provider around deterministic public and runtime snapshots.
fn provider(
    reads: Vec<Result<WatchdogPublicStateFile, WatchdogError>>,
    runtime: Result<WatchdogProtocolRuntimeStatus, WatchdogError>,
) -> FilesystemWatchdogProtocolIdentityProvider {
    FilesystemWatchdogProtocolIdentityProvider::new(
        configuration(Path::new("/var/lib/letsinfer/watchdog/letsinfer.state")),
        501,
        2,
        Arc::new(MockPublicStateFiles {
            reads: Mutex::new(reads.into()),
        }),
        Arc::new(MockRuntimeStatus { result: runtime }),
    )
}

#[test]
// Preserves public status and idle resident identity from exact startup inputs.
fn protocol_identity_preserves_complete_public_and_live_state() {
    let provider = provider(
        vec![Ok(public_state_file(PUBLIC_STATE.to_vec()))],
        Ok(runtime_status()),
    );
    let capabilities = provider.capabilities().unwrap();
    assert_eq!(capabilities.sample_interval_milliseconds(), 1_000);
    assert_eq!(capabilities.flush_interval_milliseconds(), 10_000);
    assert_eq!(capabilities.physical_gpu_count(), 2);
    let expected = WatchdogProtocolSiteStatus::new(
        "v0.11.0-rc.99".to_string(),
        "fixture-model".to_string(),
        "dwarfstar".to_string(),
        "fixture-runtime".to_string(),
        "0.11.0-rc.2".to_string(),
        MANIFEST_SHA256.to_string(),
        "dwarfstar-native".to_string(),
        true,
        8_000,
        64,
        16,
        557_056,
        "running".to_string(),
        "running".to_string(),
        "armed".to_string(),
        true,
        false,
        "li_placement_fixture".to_string(),
        INSTALLATION_ID.to_string(),
    )
    .unwrap();
    assert_eq!(provider.site_status().unwrap(), expected);
    assert_eq!(
        provider.resident_status().unwrap(),
        WatchdogProtocolResidentStatus::ready(
            NodeId::parse(&"1".repeat(32)).unwrap(),
            "0.1.0".to_string(),
            Sha256Digest::parse(&"c".repeat(64)).unwrap(),
            InstallationId::parse(INSTALLATION_ID).unwrap(),
        )
        .unwrap()
    );
}

#[test]
// Rejects stale installation identity before consulting current protection state.
fn protocol_identity_rejects_stale_public_identity() {
    let stale = String::from_utf8(PUBLIC_STATE.to_vec())
        .unwrap()
        .replace(INSTALLATION_ID, &"c".repeat(64))
        .into_bytes();
    let provider = provider(vec![Ok(public_state_file(stale))], Ok(runtime_status()));
    assert_eq!(
        provider.site_status(),
        Err(WatchdogProtocolDataError::Unavailable)
    );
}

#[test]
// Rejects unknown, duplicated, missing, malformed, and out-of-range public-state fields.
fn protocol_identity_rejects_every_closed_schema_failure() {
    let source = String::from_utf8(PUBLIC_STATE.to_vec()).unwrap();
    let cases = [
        source.replace("version=1\n", "version=2\n"),
        source.replace("model=fixture-model\n", ""),
        source.replace(
            "model=fixture-model\n",
            "model=fixture-model\nmodel=duplicate\n",
        ),
        source.replace(
            "model=fixture-model\n",
            "model=fixture-model\nunknown=value\n",
        ),
        source.replace("cache_persistent=true", "cache_persistent=1"),
        source.replace("inference_port=8000", "inference_port=65536"),
        source.replace("max_connections=64", "max_connections=0"),
        source.replace("engine=dwarfstar", "engine=not allowed"),
        source.trim_end_matches('\n').to_string(),
    ];
    for source in cases {
        let provider = provider(
            vec![Ok(public_state_file(source.into_bytes()))],
            Ok(runtime_status()),
        );
        assert_eq!(
            provider.site_status(),
            Err(WatchdogProtocolDataError::Unavailable)
        );
    }
    let mut nul = PUBLIC_STATE.to_vec();
    nul.insert(8, 0);
    let provider = provider(vec![Ok(public_state_file(nul))], Ok(runtime_status()));
    assert_eq!(
        provider.site_status(),
        Err(WatchdogProtocolDataError::Unavailable)
    );
}

#[test]
// Rejects foreign ownership, public mode, hardlinks, non-files, replacement, and oversize.
fn protocol_identity_rejects_every_unsafe_file_identity() {
    let unsafe_files = [
        WatchdogPublicStateFile::new(PUBLIC_STATE.to_vec(), 502, 0o600, 1, true, true),
        WatchdogPublicStateFile::new(PUBLIC_STATE.to_vec(), 501, 0o604, 1, true, true),
        WatchdogPublicStateFile::new(PUBLIC_STATE.to_vec(), 501, 0o600, 2, true, true),
        WatchdogPublicStateFile::new(PUBLIC_STATE.to_vec(), 501, 0o600, 1, false, true),
        WatchdogPublicStateFile::new(PUBLIC_STATE.to_vec(), 501, 0o600, 1, true, false),
        WatchdogPublicStateFile::new(Vec::new(), 501, 0o600, 1, true, true),
        WatchdogPublicStateFile::new(
            vec![b'x'; WATCHDOG_PUBLIC_STATE_MAX_BYTES + 1],
            501,
            0o600,
            1,
            true,
            true,
        ),
    ];
    for file in unsafe_files {
        let provider = provider(vec![Ok(file)], Ok(runtime_status()));
        assert_eq!(
            provider.site_status(),
            Err(WatchdogProtocolDataError::Unavailable)
        );
    }
}

#[test]
// Closes native read, safety snapshot, and invalid live-field failures as unavailable.
fn protocol_identity_redacts_provider_and_live_status_failures() {
    let read_failure = provider(
        vec![Err(WatchdogError::provider(
            "public state",
            "injected read failure",
        ))],
        Ok(runtime_status()),
    );
    assert_eq!(
        read_failure.site_status(),
        Err(WatchdogProtocolDataError::Unavailable)
    );

    let runtime_failure = provider(
        vec![Ok(public_state_file(PUBLIC_STATE.to_vec()))],
        Err(WatchdogError::StateUnavailable),
    );
    assert_eq!(
        runtime_failure.site_status(),
        Err(WatchdogProtocolDataError::Unavailable)
    );

    let invalid = WatchdogProtocolRuntimeStatus::new(
        "running".to_string(),
        "invented state".to_string(),
        "armed".to_string(),
        true,
        false,
        String::new(),
    );
    let invalid_runtime = provider(
        vec![Ok(public_state_file(PUBLIC_STATE.to_vec()))],
        Ok(invalid),
    );
    assert_eq!(
        invalid_runtime.site_status(),
        Err(WatchdogProtocolDataError::Unavailable)
    );
}

#[test]
// Enforces no-follow, single-link, private-mode, and byte bounds through the real filesystem.
fn system_public_state_reader_rejects_unsafe_native_files() {
    let directory = tempfile::tempdir().unwrap();
    let safe_path = directory.path().join("site.state");
    std::fs::write(&safe_path, PUBLIC_STATE).unwrap();
    std::fs::set_permissions(&safe_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let owner_user_id = unsafe { libc::geteuid() };
    let identity = |path: PathBuf| {
        FilesystemWatchdogProtocolIdentityProvider::new(
            configuration(&path),
            owner_user_id,
            2,
            Arc::new(SystemWatchdogPublicStateFileProvider),
            Arc::new(MockRuntimeStatus {
                result: Ok(runtime_status()),
            }),
        )
    };
    assert!(identity(safe_path.clone()).site_status().is_ok());

    let symlink_path = directory.path().join("site-symlink.state");
    symlink(&safe_path, &symlink_path).unwrap();
    assert_eq!(
        identity(symlink_path).site_status(),
        Err(WatchdogProtocolDataError::Unavailable)
    );

    let hardlink_path = directory.path().join("site-hardlink.state");
    std::fs::hard_link(&safe_path, &hardlink_path).unwrap();
    assert_eq!(
        identity(safe_path).site_status(),
        Err(WatchdogProtocolDataError::Unavailable)
    );

    let oversized_path = directory.path().join("site-oversized.state");
    std::fs::write(
        &oversized_path,
        vec![b'x'; WATCHDOG_PUBLIC_STATE_MAX_BYTES + 1],
    )
    .unwrap();
    std::fs::set_permissions(&oversized_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(SystemWatchdogPublicStateFileProvider
        .read(&oversized_path, WATCHDOG_PUBLIC_STATE_MAX_BYTES)
        .is_err());
}
