// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use li_node_manager::{
    NodeConfiguration, NodeConfigurationError, NodeConfigurationFile,
    NodeConfigurationFileProvider, NodeConfigurationFileReference, NodePairingPlatform,
    SystemNodeConfigurationFileProvider, NODE_CONFIGURATION_MAX_DOCUMENT_BYTES,
};

// Returns one ordinary closed Node configuration document.
fn configuration_document() -> serde_json::Value {
    serde_json::json!({
        "schema": {"name": "li_node_configuration", "version": 4},
        "runtime": {"database_file": "/var/lib/letsinfer/core.sqlite3"},
        "core_update": {
            "release_platform": "macos_arm64",
            "letsinfer_home": "/var/lib/letsinfer",
            "home_directory": "/Users/test",
            "setup_state_directory": "/var/lib/letsinfer/setup",
            "configuration_root": "/etc/letsinfer",
            "curl_command": "/usr/bin/curl",
            "ssh_keygen_command": "/usr/bin/ssh-keygen",
            "allowed_signers_file": "/var/lib/letsinfer/trust/release-allowed-signers",
            "supervisor_command": "/bin/launchctl",
            "readiness_timeout_milliseconds": 30000,
            "readiness_poll_milliseconds": 100,
            "stable_readiness_observations": 2
        },
        "model": {
            "catalog_source": "https://github.com/letsinferlabs/runtimes/releases/latest/download/catalog.json",
            "catalog_cache_root": "/var/lib/letsinfer/catalog_cache",
            "catalog_hydration_root": "/var/lib/letsinfer/catalog_hydration",
            "http_workspace_root": "/var/lib/letsinfer/http_workspace",
            "installation_root": "/var/lib/letsinfer/runtime_installations",
            "runtime_cache_root": "/var/lib/letsinfer/runtime_cache",
            "curl_command": "/usr/bin/curl",
            "docker_command": "/usr/bin/docker",
            "command_working_directory": "/var/lib/letsinfer/command_workspace",
            "placement_material_root": "/var/lib/letsinfer/placement_material",
            "placement_secret_root": "/var/lib/letsinfer/placement_secrets",
            "placement_tls_workspace_root": "/var/lib/letsinfer/placement_tls_staging",
            "first_port": 18000,
            "port_count": 32,
            "endpoint_timeout_milliseconds": 1000,
            "maximum_hardware_age_milliseconds": 60000,
            "group_id": 20,
            "launch_agents_root": "/Users/test/Library/LaunchAgents",
            "launchctl_command": "/bin/launchctl"
        },
        "benchmark": null,
        "pairing": pairing_configuration("macos"),
        "hardware": {
            "operating_system": "macos",
            "architecture": "arm64",
            "sysctl_command": "/usr/sbin/sysctl",
            "metal_probe_command": "/usr/local/libexec/li_metal_probe"
        },
        "placement_safety": {"operating_system": "macos"},
        "daemon": {"cadence_milliseconds": 1000},
        "private_api": {
            "local": {
                "socket_path": "/var/run/user/501/letsinfer/node.sock",
                "maximum_workers": 8,
                "read_timeout_milliseconds": 5000,
                "write_timeout_milliseconds": 6000,
                "accept_poll_interval_milliseconds": 50
            },
            "remote": {
                "bind_address": "127.0.0.1:9770",
                "maximum_workers": 16,
                "accept_poll_interval_milliseconds": 75,
                "handshake_timeout_milliseconds": 7000,
                "read_timeout_milliseconds": 8000,
                "write_timeout_milliseconds": 9000,
                "server_certificate_file": "/var/lib/letsinfer/secrets/node.crt",
                "server_private_key_file": "/var/lib/letsinfer/secrets/node.key",
                "client_ca_file": "/var/lib/letsinfer/secrets/main-ca.crt"
            }
        }
    })
}

// Returns one complete Linux document with a production benchmark and Watchdog boundary.
fn linux_configuration_document() -> serde_json::Value {
    let mut value = configuration_document();
    value["core_update"]["release_platform"] = serde_json::json!("linux_x86_64");
    value["core_update"]["supervisor_command"] = serde_json::json!("/usr/bin/systemctl");
    value["model"]["launch_agents_root"] = serde_json::Value::Null;
    value["model"]["launchctl_command"] = serde_json::Value::Null;
    value["pairing"] = pairing_configuration("linux");
    value["hardware"] = serde_json::json!({
        "operating_system": "linux",
        "architecture": "x86_64",
        "boot_id_file": "/proc/sys/kernel/random/boot_id",
        "cpu_information_file": "/proc/cpuinfo",
        "memory_information_file": "/proc/meminfo",
        "nvidia_smi_command": "/usr/bin/nvidia-smi",
        "rdma_command": "/usr/bin/rdma"
    });
    value["placement_safety"] = serde_json::json!({
        "operating_system": "linux",
        "socket_path": "/var/run/user/501/letsinfer/protection.sock",
        "maximum_workers": 4,
        "read_timeout_milliseconds": 1000,
        "write_timeout_milliseconds": 1000,
        "accept_poll_interval_milliseconds": 50,
        "protection_root": "/var/lib/letsinfer/protection",
        "watchdog_source_identity": "33".repeat(32),
        "gateway": {
            "path": "/var/lib/letsinfer/core/current/bin/li_gateway",
            "executable_sha256": "44".repeat(32),
            "principal_id": "55".repeat(16)
        },
        "watchdog": {
            "path": "/var/lib/letsinfer/core/current/bin/li_watchdog",
            "executable_sha256": "66".repeat(32),
            "principal_id": "77".repeat(16)
        },
        "lease_milliseconds": 5000
    });
    value["benchmark"] = benchmark_configuration();
    value
}

// Returns the complete closed Linux benchmark execution and telemetry contract.
fn benchmark_configuration() -> serde_json::Value {
    serde_json::json!({
        "worker_executable": "/var/lib/letsinfer/core/current/bin/li_benchmark_worker",
        "github_cli_command": "/usr/bin/gh",
        "task_root": "/var/lib/letsinfer/benchmark_tasks",
        "telemetry_root": "/var/lib/letsinfer/benchmark_telemetry",
        "evidence_root": "/var/lib/letsinfer/benchmark_evidence",
        "signing_workspace_root": "/var/lib/letsinfer/benchmark_signing",
        "signing_private_key_file": "/var/lib/letsinfer/trust/benchmark-signing.key",
        "signing_public_key_file": "/var/lib/letsinfer/trust/benchmark-signing.pub",
        "maximum_runtime_milliseconds": 86400000,
        "stop_grace_milliseconds": 30000,
        "watchdog": {
            "host": "127.0.0.1",
            "port": 7443,
            "server_name": "127.0.0.1",
            "ca_file": "/var/lib/letsinfer/trust/watchdog-ca.crt",
            "controller_authority_private_key_file": "/var/lib/letsinfer/trust/watchdog-ca.key",
            "controller_allowlist_file": "/var/lib/letsinfer/trust/watchdog-controllers.allow",
            "controller_reload_receipt_file": "/var/lib/letsinfer/watchdog/controller-snapshot.json",
            "enrollment_server_certificate_file": "/var/lib/letsinfer/trust/watchdog-server.crt",
            "enrollment_server_private_key_file": "/var/lib/letsinfer/trust/watchdog-server.key",
            "controller_certificate_file": "/var/lib/letsinfer/trust/watchdog-controller.crt",
            "controller_private_key_file": "/var/lib/letsinfer/trust/watchdog-controller.key",
            "timeout_milliseconds": 5000
        }
    })
}

// Returns one complete explicit platform-closed pairing configuration fixture.
fn pairing_configuration(operating_system: &str) -> serde_json::Value {
    let mut value = serde_json::json!({
        "setup_secret_file": "/var/lib/letsinfer/secrets/pairing_setup.key",
        "operating_system": operating_system,
        "discovery_command": "/usr/bin/dns-sd",
        "openssl_command": "/usr/bin/openssl",
        "trust_workspace": "/var/lib/letsinfer/trust/pairing_trust_staging",
        "site_private_key_file": "/var/lib/letsinfer/trust/site.key",
        "site_public_key_file": "/var/lib/letsinfer/trust/site.pub",
        "site_ca_certificate_file": "/var/lib/letsinfer/trust/site-ca.crt",
        "local_control_certificate_file": "/var/lib/letsinfer/trust/node.crt",
        "public_key_sha256": "11".repeat(32),
        "certificate_sha256": "22".repeat(32)
    });
    if operating_system == "linux" {
        value["direct_link_sys_class"] = serde_json::json!("/sys/class");
        value["direct_link_ip_command"] = serde_json::json!("/usr/sbin/ip");
    }
    value
}

// Encodes one test document through ordinary serde JSON bytes.
fn document_bytes(value: &serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("configuration JSON")
}

// Returns one exact absolute test reference.
fn reference(owner_uid: u32) -> NodeConfigurationFileReference {
    NodeConfigurationFileReference::new("/etc/letsinfer/node.json".into(), owner_uid)
        .expect("reference")
}

// Supplies one retained descriptor-shaped file and records exact read bounds.
struct MockFileProvider {
    file: NodeConfigurationFile,
    calls: Mutex<Vec<(String, usize)>>,
}

impl MockFileProvider {
    // Creates one provider around the supplied file observation.
    fn new(file: NodeConfigurationFile) -> Self {
        Self {
            file,
            calls: Mutex::new(Vec::new()),
        }
    }
}

impl NodeConfigurationFileProvider for MockFileProvider {
    // Returns one cloned observation without performing hidden filesystem work.
    fn read_no_follow(
        &self,
        path: &Path,
        maximum_bytes: usize,
    ) -> Result<NodeConfigurationFile, NodeConfigurationError> {
        self.calls
            .lock()
            .expect("calls")
            .push((path.display().to_string(), maximum_bytes));
        Ok(self.file.clone())
    }
}

// Loads every resident and listener value from one owner-only closed document.
#[test]
fn configuration_loads_exact_native_bounds() {
    let owner_uid = 501;
    let provider = MockFileProvider::new(NodeConfigurationFile::new(
        owner_uid,
        0o600,
        1,
        true,
        document_bytes(&configuration_document()),
    ));
    let configuration =
        NodeConfiguration::load(&reference(owner_uid), &provider).expect("configuration");
    assert_eq!(
        configuration.database_file(),
        Path::new("/var/lib/letsinfer/core.sqlite3")
    );
    assert_eq!(
        configuration.core_update().allowed_signers_file(),
        Path::new("/var/lib/letsinfer/trust/release-allowed-signers")
    );
    assert_eq!(
        configuration.pairing_setup_secret_file(),
        Path::new("/var/lib/letsinfer/secrets/pairing_setup.key")
    );
    assert_eq!(
        configuration.pairing().openssl_command(),
        Path::new("/usr/bin/openssl")
    );
    assert_eq!(
        configuration.pairing().public_key_sha256().as_str(),
        "11".repeat(32)
    );
    assert_eq!(
        configuration.pairing().certificate_sha256().as_str(),
        "22".repeat(32)
    );
    assert_eq!(
        configuration.pairing().platform(),
        &NodePairingPlatform::Macos
    );
    assert_eq!(configuration.benchmark(), None);
    assert_eq!(configuration.daemon_cadence(), Duration::from_secs(1));
    assert_eq!(
        configuration.local_server().socket_path(),
        Path::new("/var/run/user/501/letsinfer/node.sock")
    );
    assert_eq!(configuration.local_server().owner_uid(), owner_uid);
    assert_eq!(configuration.local_server().maximum_workers(), 8);
    assert_eq!(configuration.remote_server().bind_address().port(), 9770);
    assert_eq!(configuration.remote_server().maximum_workers(), 16);
    assert_eq!(
        configuration.remote_handshake_timeout(),
        Duration::from_secs(7)
    );
    assert_eq!(configuration.remote_read_timeout(), Duration::from_secs(8));
    assert_eq!(configuration.remote_write_timeout(), Duration::from_secs(9));
    assert_eq!(
        provider.calls.into_inner().expect("calls"),
        [(
            "/etc/letsinfer/node.json".to_string(),
            NODE_CONFIGURATION_MAX_DOCUMENT_BYTES
        )]
    );
}

// Loads the exact Linux benchmark execution, signing, and loopback telemetry contract.
#[test]
fn linux_configuration_loads_benchmark_contract() {
    let owner_uid = 501;
    let provider = MockFileProvider::new(NodeConfigurationFile::new(
        owner_uid,
        0o600,
        1,
        true,
        document_bytes(&linux_configuration_document()),
    ));
    let configuration =
        NodeConfiguration::load(&reference(owner_uid), &provider).expect("configuration");
    let benchmark = configuration.benchmark().expect("Linux benchmark");
    assert_eq!(
        benchmark.worker_executable(),
        Path::new("/var/lib/letsinfer/core/current/bin/li_benchmark_worker")
    );
    assert_eq!(benchmark.maximum_runtime(), Duration::from_secs(86_400));
    assert_eq!(benchmark.stop_grace(), Duration::from_secs(30));
    assert_eq!(benchmark.watchdog().host(), "127.0.0.1");
    assert_eq!(benchmark.watchdog().port(), 7443);
    assert_eq!(benchmark.watchdog().server_name(), "127.0.0.1");
    assert_eq!(benchmark.watchdog().timeout(), Duration::from_secs(5));
    assert_eq!(
        benchmark.watchdog().controller_private_key_file(),
        Path::new("/var/lib/letsinfer/trust/watchdog-controller.key")
    );
}

// Rejects every unsafe descriptor observation before parsing otherwise valid JSON.
#[test]
fn configuration_rejects_unsafe_file_matrix() {
    let owner_uid = 501;
    let bytes = document_bytes(&configuration_document());
    let observations = [
        NodeConfigurationFile::new(owner_uid + 1, 0o600, 1, true, bytes.clone()),
        NodeConfigurationFile::new(owner_uid, 0o640, 1, true, bytes.clone()),
        NodeConfigurationFile::new(owner_uid, 0o600, 2, true, bytes.clone()),
        NodeConfigurationFile::new(owner_uid, 0o600, 1, false, bytes.clone()),
    ];
    for file in observations {
        let error = NodeConfiguration::load(&reference(owner_uid), &MockFileProvider::new(file))
            .expect_err("unsafe file");
        assert_eq!(error, NodeConfigurationError::UnsafeFile);
    }
    let oversized = NodeConfigurationFile::new(
        owner_uid,
        0o600,
        1,
        true,
        vec![b' '; NODE_CONFIGURATION_MAX_DOCUMENT_BYTES + 1],
    );
    assert_eq!(
        NodeConfiguration::load(&reference(owner_uid), &MockFileProvider::new(oversized)),
        Err(NodeConfigurationError::DocumentTooLarge)
    );
}

// Rejects unknown JSON, schema, path, timeout, bind, worker, and TLS identity mutations.
#[test]
fn configuration_rejects_closed_document_and_semantic_mutations() {
    let owner_uid = 501;
    let mut mutations = Vec::new();
    let mut value = configuration_document();
    value["unexpected"] = serde_json::json!(true);
    mutations.push((value, NodeConfigurationError::InvalidDocument));
    let mut value = configuration_document();
    value["schema"]["name"] = serde_json::json!("other");
    mutations.push((value, NodeConfigurationError::UnsupportedSchema));
    let mut value = configuration_document();
    value["schema"]["version"] = serde_json::json!(1);
    mutations.push((value, NodeConfigurationError::UnsupportedSchema));
    let mut value = configuration_document();
    value["runtime"]["database_file"] = serde_json::json!("relative.sqlite3");
    mutations.push((value, NodeConfigurationError::InvalidConfiguration));
    let mut value = configuration_document();
    value["core_update"]["release_platform"] = serde_json::json!("linux_arm64");
    mutations.push((value, NodeConfigurationError::InvalidConfiguration));
    let mut value = configuration_document();
    value["core_update"]["allowed_signers_file"] = serde_json::json!("/tmp/foreign-signers");
    mutations.push((value, NodeConfigurationError::InvalidConfiguration));
    let mut value = configuration_document();
    value["core_update"]["configuration_root"] = serde_json::json!("/tmp/other");
    mutations.push((value, NodeConfigurationError::InvalidConfiguration));
    let mut value = configuration_document();
    value["model"]["catalog_source"] =
        serde_json::json!("https://catalog.letsinfer.ai/release.json");
    mutations.push((value, NodeConfigurationError::InvalidConfiguration));
    let mut value = configuration_document();
    value["pairing"]["setup_secret_file"] = serde_json::json!("relative.key");
    mutations.push((value, NodeConfigurationError::InvalidConfiguration));
    let mut value = configuration_document();
    value["pairing"]["setup_secret_file"] = value["runtime"]["database_file"].clone();
    mutations.push((value, NodeConfigurationError::InvalidConfiguration));
    let mut value = configuration_document();
    value["pairing"]["openssl_command"] = serde_json::json!("relative/openssl");
    mutations.push((value, NodeConfigurationError::InvalidConfiguration));
    let mut value = configuration_document();
    value["pairing"]["public_key_sha256"] = serde_json::json!("secret-value");
    mutations.push((value, NodeConfigurationError::InvalidConfiguration));
    let mut value = configuration_document();
    value["pairing"]["unexpected"] = serde_json::json!(true);
    mutations.push((value, NodeConfigurationError::InvalidDocument));
    let mut value = configuration_document();
    value["pairing"]["direct_link_sys_class"] = serde_json::json!("/sys/class");
    mutations.push((value, NodeConfigurationError::InvalidConfiguration));
    let mut value = configuration_document();
    value["pairing"] = pairing_configuration("linux");
    value["pairing"]
        .as_object_mut()
        .expect("pairing")
        .remove("direct_link_ip_command");
    mutations.push((value, NodeConfigurationError::InvalidConfiguration));
    let mut value = configuration_document();
    value["pairing"] = pairing_configuration("linux");
    mutations.push((value, NodeConfigurationError::InvalidConfiguration));
    let mut value = configuration_document();
    value["benchmark"] = benchmark_configuration();
    mutations.push((value, NodeConfigurationError::InvalidConfiguration));
    let mut value = linux_configuration_document();
    value["benchmark"] = serde_json::Value::Null;
    mutations.push((value, NodeConfigurationError::InvalidConfiguration));
    let mut value = linux_configuration_document();
    value["benchmark"]["watchdog"]["host"] = serde_json::json!("0.0.0.0");
    mutations.push((value, NodeConfigurationError::InvalidConfiguration));
    let mut value = linux_configuration_document();
    value["benchmark"]["watchdog"]["port"] = serde_json::json!(0);
    mutations.push((value, NodeConfigurationError::InvalidConfiguration));
    let mut value = linux_configuration_document();
    value["benchmark"]["maximum_runtime_milliseconds"] = serde_json::json!(0);
    mutations.push((value, NodeConfigurationError::InvalidConfiguration));
    let mut value = linux_configuration_document();
    value["benchmark"]["stop_grace_milliseconds"] = serde_json::json!(86_400_001_u64);
    mutations.push((value, NodeConfigurationError::InvalidConfiguration));
    let mut value = linux_configuration_document();
    value["benchmark"]["task_root"] = value["benchmark"]["telemetry_root"].clone();
    mutations.push((value, NodeConfigurationError::InvalidConfiguration));
    let mut value = linux_configuration_document();
    value["benchmark"]["signing_public_key_file"] =
        value["benchmark"]["signing_private_key_file"].clone();
    mutations.push((value, NodeConfigurationError::InvalidConfiguration));
    let mut value = linux_configuration_document();
    value["benchmark"]["watchdog"]["unexpected"] = serde_json::json!(true);
    mutations.push((value, NodeConfigurationError::InvalidDocument));
    let mut value = configuration_document();
    value["hardware"]["architecture"] = serde_json::json!("x86_64");
    mutations.push((value, NodeConfigurationError::InvalidConfiguration));
    let mut value = configuration_document();
    value["hardware"]["sysctl_command"] = serde_json::json!("relative/sysctl");
    mutations.push((value, NodeConfigurationError::InvalidConfiguration));
    let mut value = configuration_document();
    value["daemon"]["cadence_milliseconds"] = serde_json::json!(99);
    mutations.push((value, NodeConfigurationError::InvalidConfiguration));
    let mut value = configuration_document();
    value["private_api"]["local"]["socket_path"] = serde_json::json!("relative.sock");
    mutations.push((value, NodeConfigurationError::InvalidConfiguration));
    let mut value = configuration_document();
    value["private_api"]["remote"]["bind_address"] = serde_json::json!("127.0.0.1:0");
    mutations.push((value, NodeConfigurationError::InvalidConfiguration));
    let mut value = configuration_document();
    value["private_api"]["remote"]["maximum_workers"] = serde_json::json!(65);
    mutations.push((value, NodeConfigurationError::InvalidConfiguration));
    let mut value = configuration_document();
    value["private_api"]["remote"]["handshake_timeout_milliseconds"] = serde_json::json!(60001);
    mutations.push((value, NodeConfigurationError::InvalidConfiguration));
    let mut value = configuration_document();
    value["private_api"]["remote"]["server_private_key_file"] =
        value["private_api"]["remote"]["server_certificate_file"].clone();
    mutations.push((value, NodeConfigurationError::InvalidConfiguration));

    for (value, expected) in mutations {
        let provider = MockFileProvider::new(NodeConfigurationFile::new(
            owner_uid,
            0o600,
            1,
            true,
            document_bytes(&value),
        ));
        assert_eq!(
            NodeConfiguration::load(&reference(owner_uid), &provider),
            Err(expected)
        );
    }
}

// Exercises the production no-follow reader against an ordinary file, hard link, and symlink.
#[test]
fn system_configuration_reader_enforces_owner_only_no_follow_single_link_files() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("node.json");
    let mut document = configuration_document();
    document["core_update"]["configuration_root"] =
        serde_json::json!(directory.path().display().to_string());
    fs::write(&path, document_bytes(&document)).expect("write configuration");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("permissions");
    let owner_uid = fs::metadata(&path).expect("metadata").uid();
    let reference =
        NodeConfigurationFileReference::new(path.clone(), owner_uid).expect("reference");
    NodeConfiguration::load(&reference, &SystemNodeConfigurationFileProvider)
        .expect("system configuration");

    let hard_link = directory.path().join("node-hard-link.json");
    fs::hard_link(&path, &hard_link).expect("hard link");
    assert_eq!(
        NodeConfiguration::load(&reference, &SystemNodeConfigurationFileProvider),
        Err(NodeConfigurationError::UnsafeFile)
    );

    let symlink_path = directory.path().join("node-symlink.json");
    symlink(&path, &symlink_path).expect("symlink");
    let symlink_reference =
        NodeConfigurationFileReference::new(symlink_path, owner_uid).expect("reference");
    assert_eq!(
        NodeConfiguration::load(&symlink_reference, &SystemNodeConfigurationFileProvider),
        Err(NodeConfigurationError::FileUnavailable)
    );
}

// Requires the checked-in schema to carry the exact identity and hard cadence bounds.
#[test]
fn checked_in_configuration_schema_matches_the_loader_contract() {
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/node/li_node_configuration_v4.schema.json"
    ))
    .expect("schema");
    assert_eq!(
        schema["properties"]["schema"]["properties"]["name"]["const"],
        "li_node_configuration"
    );
    assert_eq!(
        schema["properties"]["schema"]["properties"]["version"]["const"],
        4
    );
    assert_eq!(
        schema["properties"]["daemon"]["properties"]["cadence_milliseconds"]["minimum"],
        100
    );
    assert_eq!(
        schema["properties"]["daemon"]["properties"]["cadence_milliseconds"]["maximum"],
        300000
    );
    assert!(schema["required"]
        .as_array()
        .expect("required fields")
        .iter()
        .any(|value| value == "pairing"));
    assert!(schema["required"]
        .as_array()
        .expect("required fields")
        .iter()
        .any(|value| value == "benchmark"));
    assert_eq!(
        schema["$defs"]["benchmark"]["properties"]["watchdog"]["$ref"],
        "#/$defs/benchmark_watchdog"
    );
    assert_eq!(
        schema["$defs"]["linux_pairing"]["allOf"][1]["properties"]["operating_system"]["const"],
        "linux"
    );
    assert_eq!(
        schema["$defs"]["macos_pairing"]["allOf"][1]["properties"]["operating_system"]["const"],
        "macos"
    );
    assert_eq!(
        schema["$defs"]["model"]["properties"]["catalog_source"]["pattern"],
        "^https://[^\\s@#/]+(?:/[^\\s@#]*)*/catalog\\.json$"
    );
    assert!(schema["$defs"]["macos_pairing"]["allOf"][1]["properties"]
        .get("direct_link_sys_class")
        .is_none());
}
