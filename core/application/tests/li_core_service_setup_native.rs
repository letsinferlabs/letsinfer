// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::VecDeque;
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use li_core_application::{
    CoreNativeServiceCommandOutput, CoreNativeServiceCommandRunner, CoreProcessLayout,
    CoreProcessPlatform, CoreResidentProcess, CoreServiceDefinitionProvider, CoreServiceSetupError,
    CoreServiceSetupHealthProvider, CoreServiceSetupObservation, CoreServiceSetupPreflight,
    CoreServiceSetupResidentHealth, SystemCoreServiceSetupComposition,
    SystemCoreServiceSetupHealthProvider, SystemCoreServiceSetupPreflight,
};
use li_core_interface::Sha256Digest;
use li_core_update_manager::{
    CoreInstallation, CoreUpdateError, CoreUpdateNodeRole, CoreUpdateServiceContext,
    CoreUpdateServicePlatform, CoreVersion,
};
use serde_json::json;
use sha2::{Digest, Sha256};

// Returns queued native capability observations and records exact bounded calls.
#[derive(Default)]
struct RunnerMock {
    outputs: Mutex<VecDeque<Result<CoreNativeServiceCommandOutput, CoreUpdateError>>>,
    calls: Mutex<Vec<(PathBuf, Vec<String>, Duration)>>,
}

impl RunnerMock {
    // Appends one exact successful or unsuccessful native command result.
    fn output(&self, status: i32, output: &str) {
        self.output_bytes(status, output.as_bytes(), &[]);
    }

    // Appends one exact binary native result including optional diagnostics.
    fn output_bytes(&self, status: i32, output: &[u8], diagnostic: &[u8]) {
        self.outputs.lock().expect("outputs").push_back(Ok(
            CoreNativeServiceCommandOutput::new_with_stderr(
                status,
                output.to_vec(),
                diagnostic.to_vec(),
            ),
        ));
    }
}

impl CoreNativeServiceCommandRunner for RunnerMock {
    // Records exact argv and returns one preloaded result without host mutation.
    fn run(
        &self,
        executable: &Path,
        arguments: &[String],
        timeout: Duration,
        _maximum_stdout_bytes: usize,
    ) -> Result<CoreNativeServiceCommandOutput, CoreUpdateError> {
        self.calls.lock().expect("calls").push((
            executable.to_path_buf(),
            arguments.to_vec(),
            timeout,
        ));
        self.outputs
            .lock()
            .expect("outputs")
            .pop_front()
            .expect("queued output")
    }
}

// Supplies one explicit resident health state while recording the deadline passed through.
struct ResidentHealthMock {
    result: CoreServiceSetupObservation,
    calls: Mutex<Vec<(CoreResidentProcess, Duration)>>,
}

impl CoreServiceSetupResidentHealth for ResidentHealthMock {
    // Returns one configured concrete or unsupported role-health observation.
    fn observe(
        &self,
        _context: CoreUpdateServiceContext,
        process: CoreResidentProcess,
        timeout: Duration,
    ) -> Result<CoreServiceSetupObservation, CoreServiceSetupError> {
        self.calls.lock().expect("calls").push((process, timeout));
        Ok(self.result)
    }
}

// Owns one complete immutable Linux resident-set fixture.
struct PreflightFixture {
    _temporary: tempfile::TempDir,
    owner_user_id: u32,
    home: PathBuf,
    letsinfer_home: PathBuf,
    configuration_root: PathBuf,
    service_root: PathBuf,
    installation: CoreInstallation,
    commands: Vec<li_core_application::CoreResidentProcessCommand>,
}

impl PreflightFixture {
    // Creates immutable binaries, exact source identity, and all closed resident configurations.
    fn new(role: CoreUpdateNodeRole) -> Self {
        Self::new_for(CoreProcessPlatform::Linux, role)
    }

    // Creates one macOS fixture containing only its supported Node and Gateway residents.
    fn new_macos(role: CoreUpdateNodeRole) -> Self {
        Self::new_for(CoreProcessPlatform::Macos, role)
    }

    // Creates the exact platform resident set beneath one canonical temporary home.
    fn new_for(platform: CoreProcessPlatform, role: CoreUpdateNodeRole) -> Self {
        let temporary = tempfile::tempdir().expect("temporary");
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
            .expect("temporary mode");
        let temporary_root = temporary
            .path()
            .canonicalize()
            .expect("canonical temporary");
        let owner_user_id = fs::metadata(&temporary_root).expect("metadata").uid();
        let home = temporary_root.join("home");
        let letsinfer_home = temporary_root.join("letsinfer");
        let configuration_root = temporary_root.join("configuration");
        let service_root = match platform {
            CoreProcessPlatform::Linux => home.join(".config/systemd/user"),
            CoreProcessPlatform::Macos => home.join("Library/LaunchAgents"),
        };
        let mut directories = vec![
            home.clone(),
            letsinfer_home.clone(),
            configuration_root.clone(),
        ];
        match platform {
            CoreProcessPlatform::Linux => {
                directories.push(home.join(".config"));
                directories.push(home.join(".config/systemd"));
            }
            CoreProcessPlatform::Macos => directories.push(home.join("Library")),
        }
        directories.push(service_root.clone());
        for path in directories {
            fs::create_dir_all(&path).expect("directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("directory mode");
        }
        write_private_json(
            &configuration_root.join("li_node.json"),
            &node_configuration(platform, &configuration_root),
        );
        write_private_json(
            &configuration_root.join("li_gateway.json"),
            &gateway_configuration(platform, role),
        );
        write_private_json(
            &configuration_root.join("li_watchdog.json"),
            &watchdog_configuration(),
        );
        let mut binaries = vec![
            (CoreResidentProcess::Node, b"node-binary".as_slice()),
            (CoreResidentProcess::Gateway, b"gateway-binary".as_slice()),
        ];
        if platform == CoreProcessPlatform::Linux {
            binaries.insert(
                1,
                (CoreResidentProcess::Watchdog, b"watchdog-binary".as_slice()),
            );
        }
        let files = binaries
            .iter()
            .map(|(process, bytes)| {
                json!({
                    "path": format!("bin/{}", process.executable_name()),
                    "bytes": bytes.len(),
                    "mode": 0o755,
                    "sha256": digest_text(bytes),
                })
            })
            .collect::<Vec<_>>();
        let manifest = serde_json::to_vec(&json!({
            "schema": {"name": "li_core_release_manifest", "version": 1},
            "release": {"version": "1.2.3"},
            "platform": {
                "os": if platform == CoreProcessPlatform::Linux { "linux" } else { "macos" },
                "architecture": "arm64"
            },
            "files": files,
        }))
        .expect("manifest");
        let identity = Sha256Digest::parse(&digest_text(&manifest)).expect("identity");
        let installation = CoreInstallation::new(
            CoreVersion::parse("1.2.3").expect("version"),
            identity.clone(),
        );
        let root = letsinfer_home
            .join("core/versions/1.2.3")
            .join(identity.as_str());
        fs::create_dir_all(root.join("bin")).expect("binary root");
        for (process, bytes) in binaries {
            write_mode(
                &root.join("bin").join(process.executable_name()),
                bytes,
                0o555,
            );
        }
        write_mode(
            &root.join("li_core_release_manifest_v1.json"),
            &manifest,
            0o444,
        );
        fs::set_permissions(root.join("bin"), fs::Permissions::from_mode(0o555)).expect("bin mode");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o555)).expect("root mode");
        let commands = CoreProcessLayout::new(
            platform,
            root,
            configuration_root.clone(),
            letsinfer_home.join("logs"),
        )
        .expect("layout")
        .commands()
        .expect("commands");
        Self {
            _temporary: temporary,
            owner_user_id,
            home,
            letsinfer_home,
            configuration_root,
            service_root,
            installation,
            commands,
        }
    }

    // Returns the exact main or child setup context used by this fixture.
    fn context(&self, role: CoreUpdateNodeRole) -> CoreUpdateServiceContext {
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, role)
    }
}

// Writes one private JSON document through an exact mode.
fn write_private_json(path: &Path, value: &serde_json::Value) {
    write_mode(path, &serde_json::to_vec(value).expect("JSON"), 0o600);
}

// Writes one fixture file before applying its exact final mode.
fn write_mode(path: &Path, bytes: &[u8], mode: u32) {
    fs::write(path, bytes).expect("write");
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("mode");
}

// Returns one canonical lower-hex SHA-256 fixture identity.
fn digest_text(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

// Returns one complete exact Node configuration.
fn node_configuration(
    platform: CoreProcessPlatform,
    configuration_root: &Path,
) -> serde_json::Value {
    let macos = platform == CoreProcessPlatform::Macos;
    let pairing = if macos {
        json!({
            "setup_secret_file": "/var/lib/letsinfer/secrets/pairing_setup.key", "operating_system": "macos",
            "discovery_command": "/usr/bin/dns-sd", "openssl_command": "/usr/bin/openssl",
            "trust_workspace": "/var/lib/letsinfer/trust/pairing_trust_staging",
            "site_private_key_file": "/var/lib/letsinfer/trust/site.key", "site_public_key_file": "/var/lib/letsinfer/trust/site.pub",
            "site_ca_certificate_file": "/var/lib/letsinfer/trust/site-ca.crt", "local_control_certificate_file": "/var/lib/letsinfer/trust/node.crt",
            "public_key_sha256": "11".repeat(32), "certificate_sha256": "22".repeat(32)
        })
    } else {
        json!({
            "setup_secret_file": "/var/lib/letsinfer/secrets/pairing_setup.key", "operating_system": "linux",
            "discovery_command": "/usr/bin/avahi-publish-service", "openssl_command": "/usr/bin/openssl",
            "trust_workspace": "/var/lib/letsinfer/trust/pairing_trust_staging",
            "site_private_key_file": "/var/lib/letsinfer/trust/site.key", "site_public_key_file": "/var/lib/letsinfer/trust/site.pub",
            "site_ca_certificate_file": "/var/lib/letsinfer/trust/site-ca.crt", "local_control_certificate_file": "/var/lib/letsinfer/trust/node.crt",
            "public_key_sha256": "11".repeat(32), "certificate_sha256": "22".repeat(32),
            "direct_link_sys_class": "/sys/class", "direct_link_ip_command": "/usr/sbin/ip"
        })
    };
    let hardware = if macos {
        json!({
            "operating_system": "macos", "architecture": "arm64",
            "sysctl_command": "/usr/sbin/sysctl", "metal_probe_command": "/usr/local/libexec/li_hardware_macos_probe"
        })
    } else {
        json!({
            "operating_system": "linux", "architecture": "arm64",
            "boot_id_file": "/proc/sys/kernel/random/boot_id", "cpu_information_file": "/proc/cpuinfo",
            "memory_information_file": "/proc/meminfo", "nvidia_smi_command": "/usr/bin/nvidia-smi",
            "rdma_command": "/usr/bin/rdma"
        })
    };
    let placement_safety = if macos {
        json!({"operating_system": "macos"})
    } else {
        json!({
            "operating_system": "linux", "socket_path": "/var/lib/letsinfer/node_protection.sock",
            "maximum_workers": 8, "read_timeout_milliseconds": 1000,
            "write_timeout_milliseconds": 1000, "accept_poll_interval_milliseconds": 50,
            "protection_root": "/var/lib/letsinfer/protection",
            "watchdog_source_identity": "33".repeat(32),
            "gateway": {
                "path": "/opt/letsinfer/bin/li_gateway", "executable_sha256": "44".repeat(32),
                "principal_id": "55".repeat(16)
            },
            "watchdog": {
                "path": "/opt/letsinfer/bin/li_watchdog", "executable_sha256": "66".repeat(32),
                "principal_id": "77".repeat(16)
            },
            "lease_milliseconds": 3000
        })
    };
    let benchmark = (!macos).then(|| json!({
        "worker_executable": "/var/lib/letsinfer/core/current/bin/li_benchmark_worker",
        "github_cli_command": "/usr/bin/gh",
        "task_root": "/var/lib/letsinfer/benchmark_tasks",
        "telemetry_root": "/var/lib/letsinfer/benchmark_telemetry",
        "evidence_root": "/var/lib/letsinfer/benchmark_evidence",
        "signing_workspace_root": "/var/lib/letsinfer/benchmark_signing",
        "signing_private_key_file": "/var/lib/letsinfer/trust/benchmark-signing.key",
        "signing_public_key_file": "/var/lib/letsinfer/trust/benchmark-signing.pub",
        "maximum_runtime_milliseconds": 86_400_000,
        "stop_grace_milliseconds": 30_000,
        "watchdog": {
            "host": "127.0.0.1", "port": 7443, "server_name": "127.0.0.1",
            "ca_file": "/var/lib/letsinfer/trust/watchdog-ca.crt",
            "controller_authority_private_key_file": "/var/lib/letsinfer/trust/watchdog-ca.key",
            "controller_allowlist_file": "/var/lib/letsinfer/trust/watchdog-controllers.allow",
            "controller_reload_receipt_file": "/var/lib/letsinfer/watchdog/controller-snapshot.json",
            "enrollment_server_certificate_file": "/var/lib/letsinfer/trust/watchdog-server.crt",
            "enrollment_server_private_key_file": "/var/lib/letsinfer/trust/watchdog-server.key",
            "controller_certificate_file": "/var/lib/letsinfer/trust/watchdog-controller.crt",
            "controller_private_key_file": "/var/lib/letsinfer/trust/watchdog-controller.key",
            "timeout_milliseconds": 5_000
        }
    }));
    json!({
        "schema": {"name": "li_node_configuration", "version": 4},
        "runtime": {"database_file": "/var/lib/letsinfer/core.sqlite3"},
        "core_update": {
            "release_platform": if macos { "macos_arm64" } else { "linux_arm64" },
            "letsinfer_home": "/var/lib/letsinfer", "home_directory": if macos { "/Users/test" } else { "/home/test" },
            "setup_state_directory": "/var/lib/letsinfer/setup",
            "configuration_root": configuration_root.display().to_string(),
            "curl_command": "/usr/bin/curl", "ssh_keygen_command": "/usr/bin/ssh-keygen",
            "allowed_signers_file": "/var/lib/letsinfer/trust/release-allowed-signers",
            "supervisor_command": if macos { "/bin/launchctl" } else { "/usr/bin/systemctl" },
            "readiness_timeout_milliseconds": 30000, "readiness_poll_milliseconds": 100,
            "stable_readiness_observations": 2
        },
        "model": {
            "catalog_source": "https://github.com/letsinferlabs/runtimes/releases/latest/download/catalog.json",
            "catalog_cache_root": "/var/lib/letsinfer/catalog_cache",
            "catalog_hydration_root": "/var/lib/letsinfer/catalog_hydration",
            "http_workspace_root": "/var/lib/letsinfer/http_workspace",
            "installation_root": "/var/lib/letsinfer/runtime_installations",
            "runtime_cache_root": "/var/lib/letsinfer/runtime_cache",
            "curl_command": "/usr/bin/curl", "docker_command": "/usr/bin/docker",
            "command_working_directory": "/var/lib/letsinfer/command_workspace",
            "placement_material_root": "/var/lib/letsinfer/placement_material",
            "placement_secret_root": "/var/lib/letsinfer/placement_secrets",
            "placement_tls_workspace_root": "/var/lib/letsinfer/placement_tls_staging",
            "first_port": 18000, "port_count": 32, "endpoint_timeout_milliseconds": 1000,
            "maximum_hardware_age_milliseconds": 60000, "group_id": 20,
            "launch_agents_root": macos.then_some("/Users/test/Library/LaunchAgents"),
            "launchctl_command": macos.then_some("/bin/launchctl")
        },
        "benchmark": benchmark,
        "pairing": pairing,
        "hardware": hardware,
        "placement_safety": placement_safety,
        "daemon": {"cadence_milliseconds": 1000},
        "private_api": {
            "local": {
                "socket_path": "/var/lib/letsinfer/node.sock",
                "maximum_workers": 8,
                "read_timeout_milliseconds": 5000,
                "write_timeout_milliseconds": 5000,
                "accept_poll_interval_milliseconds": 50
            },
            "remote": {
                "bind_address": "127.0.0.1:9770",
                "maximum_workers": 8,
                "accept_poll_interval_milliseconds": 50,
                "handshake_timeout_milliseconds": 5000,
                "read_timeout_milliseconds": 5000,
                "write_timeout_milliseconds": 5000,
                "server_certificate_file": "/var/lib/letsinfer/node.crt",
                "server_private_key_file": "/var/lib/letsinfer/node.key",
                "client_ca_file": "/var/lib/letsinfer/main-ca.crt"
            }
        }
    })
}

// Returns one role-exact Gateway configuration.
fn gateway_configuration(
    platform: CoreProcessPlatform,
    role: CoreUpdateNodeRole,
) -> serde_json::Value {
    let mode = match role {
        CoreUpdateNodeRole::Main => "main",
        CoreUpdateNodeRole::Child => "child",
    };
    let mut document = json!({
        "schema": {"name": "li_gateway_configuration", "version": 5},
        "node_id": "11111111111111111111111111111111",
        "core_release": "1.2.3",
        "core_source_identity": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "mode": mode,
        "health": {
            "socket_path": "/var/lib/letsinfer/gateway_health.sock",
            "maximum_workers": 8,
            "read_timeout_milliseconds": 1000,
            "write_timeout_milliseconds": 1000,
            "accept_poll_interval_milliseconds": 10
        },
        "node_protection": {
            "socket_path": "/var/lib/letsinfer/node_protection.sock",
            "read_timeout_milliseconds": 1000,
            "write_timeout_milliseconds": 1000,
            "maximum_cache_milliseconds": 2000,
            "poll_interval_milliseconds": 500
        },
        "runtime": {
            "node_socket_path": "/var/lib/letsinfer/node.sock",
            "telemetry_file": "/var/lib/letsinfer/gateway_telemetry_v2",
            "telemetry_cadence_milliseconds": 1000,
            "maximum_queue_milliseconds": 30000
        },
        "private_listener": {
            "address": "127.0.0.1:9771",
            "maximum_connections": 32,
            "tls": {
                "server_certificate_file": "/var/lib/letsinfer/gateway.crt",
                "server_private_key_file": "/var/lib/letsinfer/gateway.key",
                "client_ca_file": "/var/lib/letsinfer/main-ca.crt",
                "client_certificate_file": "/var/lib/letsinfer/main.crt"
            }
        }
    });
    if role == CoreUpdateNodeRole::Main {
        document.as_object_mut().expect("object").insert(
            "public_listener".to_string(),
            json!({"address": "127.0.0.1:9772", "maximum_connections": 64}),
        );
    }
    if platform == CoreProcessPlatform::Macos {
        document
            .as_object_mut()
            .expect("object")
            .remove("node_protection");
        document.as_object_mut().expect("object").insert(
            "macos_placement_safety".to_string(),
            json!({
                "placement_material_root": "/var/lib/letsinfer/placement_material",
                "launch_agents_root": "/Users/test/Library/LaunchAgents",
                "launchctl_command": "/bin/launchctl",
                "command_working_directory": "/var/lib/letsinfer/command_workspace",
                "lease_milliseconds": 2000
            }),
        );
    }
    document
}

// Returns one complete exact Watchdog configuration.
fn watchdog_configuration() -> serde_json::Value {
    json!({
        "schema": {"name": "li_watchdog_configuration", "version": 2},
        "installation_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "node_id": "11111111111111111111111111111111",
        "core_release": "1.2.3",
        "core_source_identity": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "listener": {"address": "127.0.0.1", "port": 9773},
        "node_protection": {"socket_path": "/tmp/li_node_protection.sock", "read_timeout_milliseconds": 1000, "write_timeout_milliseconds": 1000},
        "paths": {
            "data_directory": "/var/lib/letsinfer/watchdog",
            "server_certificate_path": "/var/lib/letsinfer/watchdog.crt",
            "server_private_key_path": "/var/lib/letsinfer/watchdog.key",
            "controller_ca_path": "/var/lib/letsinfer/controller-ca.crt",
            "controller_allowlist_path": "/var/lib/letsinfer/controllers.allow",
            "controller_snapshot_path": "/var/lib/letsinfer/controllers.snapshot",
            "site_state_path": "/var/lib/letsinfer/letsinfer.state",
            "gateway_metrics_path": "/var/lib/letsinfer/gateway.metrics",
            "protection_root_path": "/var/lib/letsinfer/protection",
            "node_database_path": "/var/lib/letsinfer/core.sqlite3",
            "runtime_installation_root": "/var/lib/letsinfer/runtime-installations",
            "runtime_cache_root": "/var/lib/letsinfer/runtime-cache"
        },
        "cadence": {"sample_interval_milliseconds": 1000, "flush_interval_milliseconds": 10000},
        "maximum_controllers": 8,
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
    })
}

// Proves every exact immutable/config/native preflight input before cutover begin.
#[test]
fn production_preflight_verifies_complete_linux_resident_inputs() {
    let fixture = PreflightFixture::new(CoreUpdateNodeRole::Main);
    let runner = Arc::new(RunnerMock::default());
    runner.output(0, "");
    runner.output(0, "yes\n");
    let preflight = SystemCoreServiceSetupPreflight::new(
        CoreProcessPlatform::Linux,
        fixture.service_root.clone(),
        fixture.owner_user_id,
        runner.clone(),
    )
    .expect("preflight");
    preflight
        .verify(
            fixture.context(CoreUpdateNodeRole::Main),
            &fixture.installation,
            &fixture.commands,
        )
        .expect("verify");
    let calls = runner.calls.lock().expect("calls");
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].0, Path::new("/usr/bin/systemctl"));
    assert_eq!(calls[0].1, ["--user", "show-environment"]);
    assert_eq!(calls[1].0, Path::new("/usr/bin/loginctl"));
    assert_eq!(calls[1].1[0], "show-user");
    assert_eq!(calls[1].1[1], fixture.owner_user_id.to_string());
}

// Fails before native commands for binary tampering, unsafe mode, and configuration role drift.
#[test]
fn production_preflight_rejects_input_identity_drift_before_native_capability() {
    for mutation in 0..6 {
        let fixture = PreflightFixture::new(CoreUpdateNodeRole::Main);
        match mutation {
            0 => {
                fs::set_permissions(
                    fixture.commands[0].executable(),
                    fs::Permissions::from_mode(0o755),
                )
                .expect("mode");
                fs::write(fixture.commands[0].executable(), b"tampered").expect("tamper");
                fs::set_permissions(
                    fixture.commands[0].executable(),
                    fs::Permissions::from_mode(0o555),
                )
                .expect("mode");
            }
            1 => fs::set_permissions(
                fixture.commands[0].executable(),
                fs::Permissions::from_mode(0o755),
            )
            .expect("unsafe mode"),
            2 => write_private_json(
                &fixture.configuration_root.join("li_gateway.json"),
                &gateway_configuration(CoreProcessPlatform::Linux, CoreUpdateNodeRole::Child),
            ),
            3 => fs::set_permissions(
                fixture.configuration_root.join("li_node.json"),
                fs::Permissions::from_mode(0o644),
            )
            .expect("unsafe configuration mode"),
            4 => {
                let binary_directory = fixture.commands[0]
                    .executable()
                    .parent()
                    .expect("binary directory");
                fs::set_permissions(binary_directory, fs::Permissions::from_mode(0o755))
                    .expect("mutable binary directory");
            }
            5 => {
                let installation_root = fixture.commands[0]
                    .executable()
                    .parent()
                    .and_then(Path::parent)
                    .expect("installation root");
                let binary_directory = installation_root.join("bin");
                let redirected_directory = installation_root.join("redirected-bin");
                fs::set_permissions(installation_root, fs::Permissions::from_mode(0o700))
                    .expect("mutable installation root");
                fs::set_permissions(&binary_directory, fs::Permissions::from_mode(0o700))
                    .expect("mutable binary directory");
                fs::rename(&binary_directory, &redirected_directory)
                    .expect("redirect binary directory");
                fs::set_permissions(&redirected_directory, fs::Permissions::from_mode(0o555))
                    .expect("immutable redirected directory");
                symlink(&redirected_directory, &binary_directory)
                    .expect("symlink binary directory");
                fs::set_permissions(installation_root, fs::Permissions::from_mode(0o555))
                    .expect("immutable installation root");
            }
            _ => unreachable!(),
        }
        let runner = Arc::new(RunnerMock::default());
        let preflight = SystemCoreServiceSetupPreflight::new(
            CoreProcessPlatform::Linux,
            fixture.service_root.clone(),
            fixture.owner_user_id,
            runner.clone(),
        )
        .expect("preflight");
        assert!(preflight
            .verify(
                fixture.context(CoreUpdateNodeRole::Main),
                &fixture.installation,
                &fixture.commands,
            )
            .is_err());
        assert!(runner.calls.lock().expect("calls").is_empty());
    }
}

// Rejects absent user bus, disabled lingering, and ambiguous output without mutation.
#[test]
fn production_preflight_fails_closed_on_native_user_domain_boundaries() {
    for outputs in [
        vec![(1, "")],
        vec![(0, ""), (0, "no\n")],
        vec![(0, ""), (0, "yes\nextra\n")],
    ] {
        let fixture = PreflightFixture::new(CoreUpdateNodeRole::Main);
        let runner = Arc::new(RunnerMock::default());
        for (status, output) in outputs {
            runner.output(status, output);
        }
        let preflight = SystemCoreServiceSetupPreflight::new(
            CoreProcessPlatform::Linux,
            fixture.service_root.clone(),
            fixture.owner_user_id,
            runner,
        )
        .expect("preflight");
        assert!(preflight
            .verify(
                fixture.context(CoreUpdateNodeRole::Main),
                &fixture.installation,
                &fixture.commands,
            )
            .is_err());
    }
}

// Requires the exact launchd Aqua manager identity after verifying both macOS residents.
#[test]
fn production_preflight_verifies_and_rejects_launchd_gui_domain_exactly() {
    for (manager_user_id_status, manager_user_id_matches, manager_name, accepted) in [
        (0, true, (0, "Aqua\n"), true),
        (113, true, (0, "Aqua\n"), false),
        (0, false, (0, "Aqua\n"), false),
        (0, true, (113, ""), false),
        (0, true, (0, "Background\n"), false),
    ] {
        let fixture = PreflightFixture::new_macos(CoreUpdateNodeRole::Main);
        let runner = Arc::new(RunnerMock::default());
        let represented_user_id = if manager_user_id_matches {
            fixture.owner_user_id
        } else {
            fixture
                .owner_user_id
                .checked_add(1)
                .expect("different owner")
        };
        runner.output(manager_user_id_status, &format!("{represented_user_id}\n"));
        if manager_user_id_status == 0 && manager_user_id_matches {
            runner.output(manager_name.0, manager_name.1);
        }
        let preflight = SystemCoreServiceSetupPreflight::new(
            CoreProcessPlatform::Macos,
            fixture.service_root.clone(),
            fixture.owner_user_id,
            runner.clone(),
        )
        .expect("preflight");
        let result = preflight.verify(
            CoreUpdateServiceContext::new(
                CoreUpdateServicePlatform::Macos,
                CoreUpdateNodeRole::Main,
            ),
            &fixture.installation,
            &fixture.commands,
        );
        assert_eq!(result.is_ok(), accepted);
        let calls = runner.calls.lock().expect("calls");
        assert_eq!(
            calls.len(),
            if manager_user_id_status == 0 && manager_user_id_matches {
                2
            } else {
                1
            }
        );
        assert_eq!(calls[0].0, Path::new("/bin/launchctl"));
        assert_eq!(calls[0].1, ["manageruid".to_string()]);
        if calls.len() == 2 {
            assert_eq!(calls[1].0, Path::new("/bin/launchctl"));
            assert_eq!(calls[1].1, ["managername".to_string()]);
        }
    }
}

// Rejects every multiline, non-UTF-8, or diagnostic-bearing launchd identity response.
#[test]
fn production_preflight_rejects_malformed_launchd_manager_identity() {
    for case in 0..6 {
        let fixture = PreflightFixture::new_macos(CoreUpdateNodeRole::Main);
        let runner = Arc::new(RunnerMock::default());
        let owner = format!("{}\n", fixture.owner_user_id);
        match case {
            0 => runner.output_bytes(0, format!("{owner}extra\n").as_bytes(), &[]),
            1 => runner.output_bytes(0, &[0xff], &[]),
            2 => runner.output_bytes(0, owner.as_bytes(), b"diagnostic"),
            3 => {
                runner.output_bytes(0, owner.as_bytes(), &[]);
                runner.output_bytes(0, b"Aqua\nextra\n", &[]);
            }
            4 => {
                runner.output_bytes(0, owner.as_bytes(), &[]);
                runner.output_bytes(0, &[0xff], &[]);
            }
            5 => {
                runner.output_bytes(0, owner.as_bytes(), &[]);
                runner.output_bytes(0, b"Aqua\n", b"diagnostic");
            }
            _ => unreachable!(),
        }
        let preflight = SystemCoreServiceSetupPreflight::new(
            CoreProcessPlatform::Macos,
            fixture.service_root.clone(),
            fixture.owner_user_id,
            runner,
        )
        .expect("preflight");
        assert!(preflight
            .verify(
                CoreUpdateServiceContext::new(
                    CoreUpdateServicePlatform::Macos,
                    CoreUpdateNodeRole::Main,
                ),
                &fixture.installation,
                &fixture.commands,
            )
            .is_err());
    }
}

// Uses the definition's single memory ceiling and keeps equality outside readiness.
#[test]
fn system_health_uses_strict_shared_memory_envelope_boundary() {
    let layout = CoreProcessLayout::new(
        CoreProcessPlatform::Linux,
        PathBuf::from("/var/lib/letsinfer/core/versions/1.2.3/identity"),
        PathBuf::from("/var/lib/letsinfer/configuration"),
        PathBuf::from("/var/lib/letsinfer/logs"),
    )
    .expect("layout");
    let definition = CoreServiceDefinitionProvider
        .definition(
            CoreProcessPlatform::Linux,
            &layout
                .command(CoreResidentProcess::Gateway)
                .expect("command"),
        )
        .expect("definition");
    let maximum = definition.memory_max_bytes().expect("memory maximum");
    for (current, expected) in [
        (maximum - 1, CoreServiceSetupObservation::Ready),
        (maximum, CoreServiceSetupObservation::NotReady),
        (maximum + 1, CoreServiceSetupObservation::NotReady),
    ] {
        let runner = Arc::new(RunnerMock::default());
        runner.output(0, &format!("{current}\n"));
        let resident = Arc::new(ResidentHealthMock {
            result: CoreServiceSetupObservation::Ready,
            calls: Mutex::new(Vec::new()),
        });
        let health = SystemCoreServiceSetupHealthProvider::new(
            CoreProcessPlatform::Linux,
            runner.clone(),
            resident,
        );
        assert_eq!(
            health
                .memory_envelope(
                    CoreUpdateServiceContext::new(
                        CoreUpdateServicePlatform::Linux,
                        CoreUpdateNodeRole::Main,
                    ),
                    &definition,
                    Duration::from_secs(90),
                )
                .expect("memory"),
            expected
        );
        let calls = runner.calls.lock().expect("calls");
        assert_eq!(calls[0].1[2], definition.service_identity());
        assert_eq!(calls[0].2, Duration::from_secs(5));
    }
}

// Rejects a foreign owner before command execution or service-directory creation.
#[test]
fn production_composition_rejects_foreign_owner_before_mutation() {
    let fixture = PreflightFixture::new(CoreUpdateNodeRole::Main);
    let foreign = fixture.owner_user_id.wrapping_add(1);
    let resident = Arc::new(ResidentHealthMock {
        result: CoreServiceSetupObservation::Ready,
        calls: Mutex::new(Vec::new()),
    });
    assert!(SystemCoreServiceSetupComposition::compose(
        fixture.context(CoreUpdateNodeRole::Main),
        fixture.letsinfer_home,
        fixture.configuration_root,
        fixture.home,
        &[],
        foreign,
        resident,
    )
    .is_err());
}

// Creates only the canonical private service/store directory chains before composing providers.
#[test]
fn production_composition_safely_creates_missing_native_roots() {
    let fixture = PreflightFixture::new(CoreUpdateNodeRole::Main);
    fs::remove_dir(&fixture.service_root).expect("remove service root");
    fs::remove_dir(fixture.home.join(".config/systemd")).expect("remove systemd root");
    let resident = Arc::new(ResidentHealthMock {
        result: CoreServiceSetupObservation::Ready,
        calls: Mutex::new(Vec::new()),
    });
    let private_roots = vec![
        fixture.letsinfer_home.join("material/gateway"),
        fixture.letsinfer_home.join("benchmark_tasks"),
        fixture.letsinfer_home.join("benchmark_telemetry"),
        fixture.letsinfer_home.join("benchmark_evidence"),
        fixture.letsinfer_home.join("benchmark_signing"),
    ];
    SystemCoreServiceSetupComposition::compose(
        fixture.context(CoreUpdateNodeRole::Main),
        fixture.letsinfer_home.clone(),
        fixture.configuration_root,
        fixture.home,
        &private_roots,
        fixture.owner_user_id,
        resident,
    )
    .expect("composition");
    let mut expected_roots = vec![
        fixture.service_root,
        fixture.letsinfer_home.join("state"),
        fixture.letsinfer_home.join("state/service_cutover"),
    ];
    expected_roots.extend(private_roots);
    for path in expected_roots {
        let metadata = fs::symlink_metadata(path).expect("metadata");
        assert!(metadata.file_type().is_dir());
        assert_eq!(metadata.uid(), fixture.owner_user_id);
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
    }
}

// Creates the private macOS resident log root before returning the production composition.
#[test]
fn production_composition_creates_macos_log_root_for_fresh_home() {
    let fixture = PreflightFixture::new_macos(CoreUpdateNodeRole::Main);
    let log_root = fixture.letsinfer_home.join("logs");
    assert!(!log_root.exists());
    let resident = Arc::new(ResidentHealthMock {
        result: CoreServiceSetupObservation::Ready,
        calls: Mutex::new(Vec::new()),
    });

    SystemCoreServiceSetupComposition::compose(
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Macos, CoreUpdateNodeRole::Main),
        fixture.letsinfer_home,
        fixture.configuration_root,
        fixture.home,
        &[],
        fixture.owner_user_id,
        resident,
    )
    .expect("macOS composition");

    let metadata = fs::symlink_metadata(log_root).expect("macOS log root");
    assert!(metadata.file_type().is_dir());
    assert_eq!(metadata.uid(), fixture.owner_user_id);
    assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
}

// Preserves existing private macOS resident logs when setup composition is replayed.
#[test]
fn production_composition_replays_macos_log_root_without_replacing_contents() {
    let fixture = PreflightFixture::new_macos(CoreUpdateNodeRole::Main);
    let log_root = fixture.letsinfer_home.join("logs");
    let resident = || {
        Arc::new(ResidentHealthMock {
            result: CoreServiceSetupObservation::Ready,
            calls: Mutex::new(Vec::new()),
        })
    };
    SystemCoreServiceSetupComposition::compose(
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Macos, CoreUpdateNodeRole::Main),
        fixture.letsinfer_home.clone(),
        fixture.configuration_root.clone(),
        fixture.home.clone(),
        &[],
        fixture.owner_user_id,
        resident(),
    )
    .expect("initial macOS composition");
    let node_log = log_root.join("li_node.log");
    fs::write(&node_log, b"resident-ready\n").expect("node log");
    fs::set_permissions(&node_log, fs::Permissions::from_mode(0o600)).expect("node log mode");

    SystemCoreServiceSetupComposition::compose(
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Macos, CoreUpdateNodeRole::Main),
        fixture.letsinfer_home,
        fixture.configuration_root,
        fixture.home,
        &[],
        fixture.owner_user_id,
        resident(),
    )
    .expect("replayed macOS composition");

    assert_eq!(
        fs::read(&node_log).expect("retained node log"),
        b"resident-ready\n"
    );
    let metadata = fs::symlink_metadata(log_root).expect("macOS log root");
    assert!(metadata.file_type().is_dir());
    assert_eq!(metadata.uid(), fixture.owner_user_id);
    assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
}

// Rejects an unsafe macOS log root before creating service or cutover state.
#[test]
fn production_composition_rejects_symlinked_macos_log_root_before_mutation() {
    let fixture = PreflightFixture::new_macos(CoreUpdateNodeRole::Main);
    fs::remove_dir(&fixture.service_root).expect("remove service root");
    let redirected = fixture.home.join("redirected-logs");
    fs::create_dir(&redirected).expect("redirected logs");
    fs::set_permissions(&redirected, fs::Permissions::from_mode(0o700))
        .expect("redirected logs mode");
    let log_root = fixture.letsinfer_home.join("logs");
    symlink(&redirected, &log_root).expect("macOS log root symlink");
    let resident = Arc::new(ResidentHealthMock {
        result: CoreServiceSetupObservation::Ready,
        calls: Mutex::new(Vec::new()),
    });

    assert!(SystemCoreServiceSetupComposition::compose(
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Macos, CoreUpdateNodeRole::Main,),
        fixture.letsinfer_home.clone(),
        fixture.configuration_root,
        fixture.home,
        &[],
        fixture.owner_user_id,
        resident,
    )
    .is_err());
    assert!(!fixture.service_root.exists());
    assert!(!fixture.letsinfer_home.join("state").exists());
}

// Preserves a safe runtime-created telemetry file when a failed setup retries composition.
#[test]
fn production_composition_replays_gateway_root_after_service_rollback() {
    let fixture = PreflightFixture::new(CoreUpdateNodeRole::Main);
    let gateway_root = fixture.letsinfer_home.join("material/gateway");
    let resident = || {
        Arc::new(ResidentHealthMock {
            result: CoreServiceSetupObservation::Ready,
            calls: Mutex::new(Vec::new()),
        })
    };
    SystemCoreServiceSetupComposition::compose(
        fixture.context(CoreUpdateNodeRole::Main),
        fixture.letsinfer_home.clone(),
        fixture.configuration_root.clone(),
        fixture.home.clone(),
        std::slice::from_ref(&gateway_root),
        fixture.owner_user_id,
        resident(),
    )
    .expect("initial composition");
    let telemetry = gateway_root.join("telemetry.json");
    fs::write(&telemetry, b"version=2\n").expect("telemetry");
    fs::set_permissions(&telemetry, fs::Permissions::from_mode(0o600)).expect("telemetry mode");

    SystemCoreServiceSetupComposition::compose(
        fixture.context(CoreUpdateNodeRole::Main),
        fixture.letsinfer_home,
        fixture.configuration_root,
        fixture.home,
        std::slice::from_ref(&gateway_root),
        fixture.owner_user_id,
        resident(),
    )
    .expect("replayed composition");
    assert_eq!(
        fs::read(&telemetry).expect("retained telemetry"),
        b"version=2\n"
    );
    let metadata = fs::symlink_metadata(gateway_root).expect("Gateway root");
    assert!(metadata.file_type().is_dir());
    assert_eq!(metadata.uid(), fixture.owner_user_id);
    assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
}

// Rejects a private root outside the explicit Let's Infer home before native setup mutates state.
#[test]
fn production_composition_rejects_private_root_outside_letsinfer_home() {
    let fixture = PreflightFixture::new(CoreUpdateNodeRole::Main);
    fs::remove_dir(&fixture.service_root).expect("remove service root");
    let outside_root = fixture.home.join("benchmark_tasks");
    let resident = Arc::new(ResidentHealthMock {
        result: CoreServiceSetupObservation::Ready,
        calls: Mutex::new(Vec::new()),
    });
    assert!(SystemCoreServiceSetupComposition::compose(
        fixture.context(CoreUpdateNodeRole::Main),
        fixture.letsinfer_home.clone(),
        fixture.configuration_root,
        fixture.home,
        &[outside_root],
        fixture.owner_user_id,
        resident,
    )
    .is_err());
    assert!(!fixture.service_root.exists());
    assert!(!fixture.letsinfer_home.join("state").exists());
}

// Rejects an existing symlink in a private-root plan before creating service or cutover state.
#[test]
fn production_composition_rejects_symlinked_private_root_before_mutation() {
    let fixture = PreflightFixture::new(CoreUpdateNodeRole::Main);
    fs::remove_dir(&fixture.service_root).expect("remove service root");
    let redirected = fixture.home.join("redirected-benchmark");
    fs::create_dir(&redirected).expect("redirected benchmark");
    fs::set_permissions(&redirected, fs::Permissions::from_mode(0o700))
        .expect("redirected benchmark mode");
    let private_root = fixture.letsinfer_home.join("benchmark_tasks");
    symlink(&redirected, &private_root).expect("private root symlink");
    let resident = Arc::new(ResidentHealthMock {
        result: CoreServiceSetupObservation::Ready,
        calls: Mutex::new(Vec::new()),
    });
    assert!(SystemCoreServiceSetupComposition::compose(
        fixture.context(CoreUpdateNodeRole::Main),
        fixture.letsinfer_home.clone(),
        fixture.configuration_root,
        fixture.home,
        &[private_root],
        fixture.owner_user_id,
        resident,
    )
    .is_err());
    assert!(!fixture.service_root.exists());
    assert!(!fixture.letsinfer_home.join("state").exists());
}

// Rejects group-readable and special-bit private ancestors before creating any setup state.
#[test]
fn production_composition_rejects_non_private_existing_ancestor_before_mutation() {
    for mode in [0o750, 0o1700] {
        let fixture = PreflightFixture::new(CoreUpdateNodeRole::Main);
        fs::remove_dir(&fixture.service_root).expect("remove service root");
        let material_root = fixture.letsinfer_home.join("material");
        let watchdog_root = material_root.join("watchdog");
        let protection_root = watchdog_root.join("protected-placements");
        fs::create_dir(&material_root).expect("material root");
        fs::set_permissions(&material_root, fs::Permissions::from_mode(0o700))
            .expect("material root mode");
        fs::create_dir(&watchdog_root).expect("Watchdog root");
        fs::set_permissions(&watchdog_root, fs::Permissions::from_mode(mode))
            .expect("Watchdog root mode");
        let resident = Arc::new(ResidentHealthMock {
            result: CoreServiceSetupObservation::Ready,
            calls: Mutex::new(Vec::new()),
        });

        let error = SystemCoreServiceSetupComposition::compose(
            fixture.context(CoreUpdateNodeRole::Main),
            fixture.letsinfer_home.clone(),
            fixture.configuration_root.clone(),
            fixture.home.clone(),
            &[protection_root.clone()],
            fixture.owner_user_id,
            resident,
        )
        .err()
        .expect("non-private ancestor");

        assert_eq!(
            error,
            CoreServiceSetupError::provider(
                "service preflight",
                "service directory identity is unsafe",
            )
        );
        assert!(!fixture.service_root.exists());
        assert!(!fixture.letsinfer_home.join("state").exists());
        assert!(!protection_root.exists());
    }
}

// Rejects an existing symlink at the service-root boundary without creating cutover state.
#[test]
fn production_composition_rejects_symlinked_service_root_without_partial_creation() {
    let fixture = PreflightFixture::new(CoreUpdateNodeRole::Main);
    fs::remove_dir(&fixture.service_root).expect("remove service root");
    let redirected = fixture.home.join("redirected");
    fs::create_dir(&redirected).expect("redirected");
    fs::set_permissions(&redirected, fs::Permissions::from_mode(0o700)).expect("redirected mode");
    symlink(&redirected, &fixture.service_root).expect("symlink");
    let resident = Arc::new(ResidentHealthMock {
        result: CoreServiceSetupObservation::Ready,
        calls: Mutex::new(Vec::new()),
    });
    assert!(SystemCoreServiceSetupComposition::compose(
        fixture.context(CoreUpdateNodeRole::Main),
        fixture.letsinfer_home.clone(),
        fixture.configuration_root,
        fixture.home,
        &[],
        fixture.owner_user_id,
        resident,
    )
    .is_err());
    assert!(!fixture.letsinfer_home.join("state").exists());
}
