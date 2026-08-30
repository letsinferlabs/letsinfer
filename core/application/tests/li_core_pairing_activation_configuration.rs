// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use li_core_application::{
    CorePairingActivationConfigurationPort, CorePairingActivationError, CoreServiceCutoverFile,
    CoreServiceCutoverFileIo, CoreServiceSetupError, SystemCorePairingActivationConfiguration,
};
use li_core_interface::{
    DisplayName, EntityTimestamps, InstallationId, MachineId, Node, NodeAddress, NodeId,
    NodeIdentity, NodeRole, NodeState, Sha256Digest, UnixMilliseconds,
};
use li_node_manager::{NodePairingCredentials, LETSINFER_PRIVATE_GATEWAY_PORT};
use serde_json::{json, Value};

// Stores exact file bytes and modes behind the production adapter's injected native boundary.
#[derive(Default)]
struct TestFileIo {
    files: Mutex<BTreeMap<PathBuf, CoreServiceCutoverFile>>,
    replacements: AtomicUsize,
    fail_after_replace: AtomicUsize,
}

impl TestFileIo {
    // Seeds one owner-only file before activation begins.
    fn seed(&self, path: PathBuf, bytes: Vec<u8>) {
        self.files.lock().expect("files").insert(
            path,
            CoreServiceCutoverFile::new(bytes, 0o600).expect("file"),
        );
    }

    // Returns exact current bytes for assertions.
    fn bytes(&self, path: &Path) -> Option<Vec<u8>> {
        self.files
            .lock()
            .expect("files")
            .get(path)
            .map(|file| file.bytes().to_vec())
    }

    // Fails once after the selected replacement has durably changed the map.
    fn fail_after(&self, replacement: usize) {
        self.fail_after_replace.store(replacement, Ordering::SeqCst);
    }
}

impl CoreServiceCutoverFileIo for TestFileIo {
    // Accepts the already-explicit deterministic test root.
    fn validate_root(
        &self,
        _root: &Path,
        _owner_user_id: u32,
    ) -> Result<(), CoreServiceSetupError> {
        Ok(())
    }

    // Returns one cloned exact-mode file or absence.
    fn read(
        &self,
        path: &Path,
        _owner_user_id: u32,
    ) -> Result<Option<CoreServiceCutoverFile>, CoreServiceSetupError> {
        Ok(self.files.lock().expect("files").get(path).map(|file| {
            CoreServiceCutoverFile::new(file.bytes().to_vec(), file.mode()).expect("clone")
        }))
    }

    // Applies one atomic replacement before the selected injected interruption.
    fn replace(
        &self,
        path: &Path,
        file: &CoreServiceCutoverFile,
        _owner_user_id: u32,
    ) -> Result<(), CoreServiceSetupError> {
        self.files.lock().expect("files").insert(
            path.to_path_buf(),
            CoreServiceCutoverFile::new(file.bytes().to_vec(), file.mode()).expect("replace"),
        );
        let call = self.replacements.fetch_add(1, Ordering::SeqCst) + 1;
        if self.fail_after_replace.load(Ordering::SeqCst) == call {
            self.fail_after_replace.store(0, Ordering::SeqCst);
            return Err(CoreServiceSetupError::provider(
                "test file",
                "injected post-write interruption",
            ));
        }
        Ok(())
    }

    // Removes one exact current file.
    fn remove(&self, path: &Path, _owner_user_id: u32) -> Result<bool, CoreServiceSetupError> {
        Ok(self.files.lock().expect("files").remove(path).is_some())
    }
}

// Reconciles an interrupted three-document cutover and refuses divergent rollback state.
#[test]
fn production_configuration_cutover_replays_and_rolls_back_exactly() {
    let root = PathBuf::from("/private/letsinfer-test/configuration");
    let cli_path = root.join("li_core_cli_configuration.json");
    let node_path = root.join("li_node.json");
    let gateway_path = root.join("li_gateway.json");
    let cli = encoded(cli_configuration(&root));
    let node = encoded(node_configuration(&root));
    let gateway = encoded(gateway_configuration());
    let io = Arc::new(TestFileIo::default());
    io.seed(cli_path.clone(), cli.clone());
    io.seed(node_path.clone(), node.clone());
    io.seed(gateway_path.clone(), gateway.clone());
    let configuration =
        SystemCorePairingActivationConfiguration::with_io(root.clone(), 501, io.clone())
            .expect("configuration");
    let receipt = configuration
        .prepare(
            &digest('8'),
            &main_node(),
            9_443,
            &digest('c'),
            &credentials(),
        )
        .expect("prepare");
    let prepared_path = root.join(".li_pairing_activation_configuration.json");
    let prepared_bytes = io.bytes(&prepared_path).expect("prepared configuration");
    let schema: Value = serde_json::from_str(include_str!(
        "../../../schemas/core/li_pairing_activation_configuration_v1.schema.json"
    ))
    .expect("prepared configuration schema");
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(
        schema["properties"]["schema"]["properties"]["name"]["const"],
        "li_pairing_activation_configuration"
    );
    assert_eq!(
        schema["properties"]["schema"]["properties"]["version"]["const"],
        1
    );
    let mut unknown: Value =
        serde_json::from_slice(&prepared_bytes).expect("prepared configuration JSON");
    unknown["unknown"] = json!(true);
    io.seed(prepared_path.clone(), encoded(unknown));
    assert_eq!(
        configuration.prepared(&receipt),
        Err(CorePairingActivationError::RecoveryRequired)
    );
    io.seed(prepared_path, prepared_bytes);
    assert_eq!(
        configuration.prepared(&receipt).expect("prepared").main(),
        &main_node()
    );

    io.fail_after(7);
    assert_eq!(
        configuration.commit(&receipt),
        Err(CorePairingActivationError::ConfigurationUnavailable)
    );
    configuration.commit(&receipt).expect("replayed commit");
    configuration.verify(&receipt).expect("verify child");
    let child_cli: Value =
        serde_json::from_slice(&io.bytes(&cli_path).expect("child CLI")).expect("child CLI JSON");
    assert_eq!(child_cli["remote_main"]["address"], "main.local");
    assert_eq!(child_cli["remote_main"]["port"], 9_443);
    io.remove(&root.join("li_main_ca.crt"), 501)
        .expect("remove trust material");
    assert_eq!(
        configuration.verify(&receipt),
        Err(CorePairingActivationError::ConfigurationUnavailable)
    );
    io.seed(
        root.join("li_main_ca.crt"),
        credentials().main_ca_certificate().to_vec(),
    );
    let child_gateway: Value =
        serde_json::from_slice(&io.bytes(&gateway_path).expect("child gateway"))
            .expect("child gateway JSON");
    assert_eq!(child_gateway["mode"], "child");
    assert!(child_gateway.get("public_listener").is_none());
    let child_gateway_address = child_gateway["private_listener"]["address"]
        .as_str()
        .expect("child Gateway private address")
        .parse::<SocketAddr>()
        .expect("child Gateway private socket");
    assert_eq!(child_gateway_address.port(), LETSINFER_PRIVATE_GATEWAY_PORT);

    io.seed(gateway_path.clone(), b"{}\n".to_vec());
    assert_eq!(
        configuration.restore(&receipt),
        Err(CorePairingActivationError::RecoveryRequired)
    );
    io.seed(gateway_path.clone(), encoded(child_gateway));
    configuration.restore(&receipt).expect("restore main");
    assert_eq!(io.bytes(&cli_path), Some(cli));
    assert_eq!(io.bytes(&node_path), Some(node));
    assert_eq!(io.bytes(&gateway_path), Some(gateway));
    configuration
        .finish_rollback(&receipt)
        .expect("finish rollback");
    assert!(io
        .bytes(&root.join(".li_pairing_activation_configuration.json"))
        .is_none());
    assert!(io.bytes(&root.join("li_main_ca.crt")).is_none());
}

// Returns one complete schema-4 owner-local CLI configuration without a paired main.
fn cli_configuration(root: &Path) -> Value {
    json!({
        "schema": {"name": "li_core_cli_configuration", "version": 4},
        "local_node_socket": root.join("node.sock"),
        "entropy_source": "/dev/urandom",
        "client": {"timeout_milliseconds": 5000, "maximum_response_bytes": 1_048_576},
        "pairing": {
            "node_configuration_file": root.join("li_node_configuration.json"),
            "installation": {
                "version": "0.11.0-rc.114",
                "source_identity": "aa".repeat(32)
            },
            "watchdog_health": null
        },
        "uninstall": {
            "launcher_file": "/usr/local/bin/letsinfer",
            "privilege_command": null
        },
        "remote_main": null
    })
}

// Returns one complete schema-4 macOS Node configuration.
fn node_configuration(root: &Path) -> Value {
    json!({
        "schema": {"name": "li_node_configuration", "version": 4},
        "runtime": {"database_file": "/var/lib/letsinfer/core.sqlite3"},
        "core_update": {
            "release_platform": "macos_arm64", "letsinfer_home": "/var/lib/letsinfer",
            "home_directory": "/Users/test", "setup_state_directory": "/var/lib/letsinfer/setup",
            "configuration_root": root, "curl_command": "/usr/bin/curl",
            "ssh_keygen_command": "/usr/bin/ssh-keygen",
            "allowed_signers_file": "/var/lib/letsinfer/trust/release-allowed-signers",
            "supervisor_command": "/bin/launchctl", "readiness_timeout_milliseconds": 30000,
            "readiness_poll_milliseconds": 100, "stable_readiness_observations": 2
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
            "launch_agents_root": "/Users/test/Library/LaunchAgents",
            "launchctl_command": "/bin/launchctl"
        },
        "benchmark": null,
        "pairing": {
            "setup_secret_file": "/var/lib/letsinfer/secrets/pairing_setup.key",
            "operating_system": "macos", "discovery_command": "/usr/bin/dns-sd",
            "openssl_command": "/usr/bin/openssl",
            "trust_workspace": "/var/lib/letsinfer/trust/pairing_trust_staging",
            "site_private_key_file": "/var/lib/letsinfer/trust/site.key",
            "site_public_key_file": "/var/lib/letsinfer/trust/site.pub",
            "site_ca_certificate_file": "/var/lib/letsinfer/trust/site-ca.crt",
            "local_control_certificate_file": "/var/lib/letsinfer/trust/node.crt",
            "public_key_sha256": "11".repeat(32), "certificate_sha256": "22".repeat(32)
        },
        "hardware": {
            "operating_system": "macos", "architecture": "arm64",
            "sysctl_command": "/usr/sbin/sysctl",
            "metal_probe_command": "/usr/local/libexec/li_hardware_macos_probe"
        },
        "placement_safety": {"operating_system": "macos"},
        "daemon": {"cadence_milliseconds": 1000},
        "private_api": {
            "local": {
                "socket_path": "/var/lib/letsinfer/node.sock", "maximum_workers": 8,
                "read_timeout_milliseconds": 5000, "write_timeout_milliseconds": 5000,
                "accept_poll_interval_milliseconds": 50
            },
            "remote": {
                "bind_address": "127.0.0.1:9443", "maximum_workers": 8,
                "accept_poll_interval_milliseconds": 50, "handshake_timeout_milliseconds": 5000,
                "read_timeout_milliseconds": 5000, "write_timeout_milliseconds": 5000,
                "server_certificate_file": "/var/lib/letsinfer/node.crt",
                "server_private_key_file": "/var/lib/letsinfer/node.key",
                "client_ca_file": "/var/lib/letsinfer/main-ca.crt"
            }
        }
    })
}

// Returns one complete schema-4 main Gateway configuration.
fn gateway_configuration() -> Value {
    json!({
        "schema": {"name": "li_gateway_configuration", "version": 5},
        "node_id": "11".repeat(16), "core_release": "1.2.3",
        "core_source_identity": "cc".repeat(32), "mode": "main",
        "health": {
            "socket_path": "/var/lib/letsinfer/gateway_health.sock", "maximum_workers": 8,
            "read_timeout_milliseconds": 1000, "write_timeout_milliseconds": 1000,
            "accept_poll_interval_milliseconds": 10
        },
        "macos_placement_safety": {
            "placement_material_root": "/var/lib/letsinfer/placement_material",
            "launch_agents_root": "/Users/test/Library/LaunchAgents",
            "launchctl_command": "/bin/launchctl",
            "command_working_directory": "/var/lib/letsinfer/command_workspace",
            "lease_milliseconds": 2000
        },
        "runtime": {
            "node_socket_path": "/var/lib/letsinfer/node.sock",
            "telemetry_file": "/var/lib/letsinfer/gateway_telemetry_v2",
            "telemetry_cadence_milliseconds": 1000, "maximum_queue_milliseconds": 30000
        },
        "public_listener": {"address": "127.0.0.1:8000", "maximum_connections": 64},
        "private_listener": {
            "address": "127.0.0.1:9444", "maximum_connections": 32,
            "tls": {
                "server_certificate_file": "/var/lib/letsinfer/gateway.crt",
                "server_private_key_file": "/var/lib/letsinfer/gateway.key",
                "client_ca_file": "/var/lib/letsinfer/main-ca.crt",
                "client_certificate_file": "/var/lib/letsinfer/main.crt"
            }
        }
    })
}

// Returns one complete active public membership package.
fn credentials() -> NodePairingCredentials {
    NodePairingCredentials::new(
        b"main-public-key".to_vec(),
        b"main-ca".to_vec(),
        b"child-certificate".to_vec(),
        b"membership-signature".to_vec(),
        digest('b'),
        UnixMilliseconds::new(500),
        UnixMilliseconds::new(500_000),
    )
    .expect("credentials")
}

// Returns one exact active destination main Node.
fn main_node() -> Node {
    Node::new(
        NodeIdentity::new(
            NodeId::parse(&"4".repeat(32)).expect("node"),
            MachineId::parse(&"5".repeat(32)).expect("machine"),
            InstallationId::parse(&"6".repeat(64)).expect("installation"),
        ),
        DisplayName::parse("Main").expect("name"),
        NodeRole::Main,
        NodeState::Active,
        NodeAddress::parse("main.local").expect("address"),
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(1_000))
            .expect("timestamps"),
    )
}

// Encodes one deterministic pretty JSON document.
fn encoded(value: Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(&value).expect("JSON");
    bytes.push(b'\n');
    bytes
}

// Returns one canonical SHA-256 fixture.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
}
