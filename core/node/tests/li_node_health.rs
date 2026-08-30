// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use li_core_interface::{
    DisplayName, EntityTimestamps, InstallationId, MachineId, Node, NodeAddress, NodeId,
    NodeIdentity, NodeRole, NodeState, Sha256Digest, TechnicalName, UnixMilliseconds,
};
use li_node_manager::{
    NodeConfiguration, NodeConfigurationError, NodeConfigurationFile,
    NodeConfigurationFileProvider, NodeConfigurationFileReference, NodeHealthError,
    NodeHealthExchange, NodeHealthProbe, NodePrivateRemoteError, NodePrivateResponse,
    NodePrivateTransport, NodePrivateTransportOutcome, NodePrivateTransportResponse,
    SystemNodeHealthExchange,
};

// Supplies one owner-only in-memory Node configuration document.
struct ConfigurationProvider;

impl NodeConfigurationFileProvider for ConfigurationProvider {
    // Returns one safe bounded file observation without native I/O.
    fn read_no_follow(
        &self,
        _path: &Path,
        _maximum_bytes: usize,
    ) -> Result<NodeConfigurationFile, NodeConfigurationError> {
        Ok(NodeConfigurationFile::new(
            501,
            0o600,
            1,
            true,
            serde_json::to_vec(&serde_json::json!({
                "schema": {"name": "li_node_configuration", "version": 4},
                "runtime": {"database_file": "/var/lib/letsinfer/core.sqlite3"},
                "core_update": {
                    "release_platform": "linux_arm64", "letsinfer_home": "/var/lib/letsinfer",
                    "home_directory": "/home/test", "setup_state_directory": "/var/lib/letsinfer/setup",
                    "configuration_root": "/etc/letsinfer", "curl_command": "/usr/bin/curl",
                    "ssh_keygen_command": "/usr/bin/ssh-keygen",
                    "allowed_signers_file": "/var/lib/letsinfer/trust/release-allowed-signers",
                    "supervisor_command": "/usr/bin/systemctl", "readiness_timeout_milliseconds": 30000,
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
                    "first_port": 18000, "port_count": 32,
                    "endpoint_timeout_milliseconds": 1000,
                    "maximum_hardware_age_milliseconds": 60000, "group_id": 20,
                    "launch_agents_root": null,
                    "launchctl_command": null
                },
                "benchmark": {
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
                },
                "pairing": {
                    "setup_secret_file": "/var/lib/letsinfer/secrets/pairing_setup.key",
                    "operating_system": "linux", "discovery_command": "/usr/bin/avahi-publish-service",
                    "openssl_command": "/usr/bin/openssl", "trust_workspace": "/var/lib/letsinfer/trust/pairing_trust_staging",
                    "site_private_key_file": "/var/lib/letsinfer/trust/site.key", "site_public_key_file": "/var/lib/letsinfer/trust/site.pub",
                    "site_ca_certificate_file": "/var/lib/letsinfer/trust/site-ca.crt", "local_control_certificate_file": "/var/lib/letsinfer/trust/node.crt",
                    "public_key_sha256": "11".repeat(32), "certificate_sha256": "22".repeat(32),
                    "direct_link_sys_class": "/sys/class", "direct_link_ip_command": "/usr/sbin/ip"
                },
                "hardware": {
                    "operating_system": "linux",
                    "architecture": "arm64",
                    "boot_id_file": "/proc/sys/kernel/random/boot_id",
                    "cpu_information_file": "/proc/cpuinfo",
                    "memory_information_file": "/proc/meminfo",
                    "nvidia_smi_command": null,
                    "rdma_command": null
                },
                "placement_safety": {
                    "operating_system": "linux",
                    "socket_path": "/var/lib/letsinfer/node_protection.sock",
                    "maximum_workers": 4,
                    "read_timeout_milliseconds": 1000,
                    "write_timeout_milliseconds": 1000,
                    "accept_poll_interval_milliseconds": 10,
                    "protection_root": "/var/lib/letsinfer/protection",
                    "watchdog_source_identity": "33".repeat(32),
                    "gateway": {
                        "path": "/opt/letsinfer/bin/li_gateway",
                        "executable_sha256": "44".repeat(32),
                        "principal_id": "55".repeat(16)
                    },
                    "watchdog": {
                        "path": "/opt/letsinfer/bin/li_watchdog",
                        "executable_sha256": "66".repeat(32),
                        "principal_id": "77".repeat(16)
                    },
                    "lease_milliseconds": 3000
                },
                "daemon": {"cadence_milliseconds": 1000},
                "private_api": {
                    "local": {
                        "socket_path": "/run/user/501/letsinfer/node.sock",
                        "maximum_workers": 4,
                        "read_timeout_milliseconds": 1000,
                        "write_timeout_milliseconds": 1000,
                        "accept_poll_interval_milliseconds": 10
                    },
                    "remote": {
                        "bind_address": "127.0.0.1:9770",
                        "maximum_workers": 4,
                        "accept_poll_interval_milliseconds": 10,
                        "handshake_timeout_milliseconds": 1000,
                        "read_timeout_milliseconds": 1000,
                        "write_timeout_milliseconds": 1000,
                        "server_certificate_file": "/var/lib/letsinfer/node.crt",
                        "server_private_key_file": "/var/lib/letsinfer/node.key",
                        "client_ca_file": "/var/lib/letsinfer/main-ca.crt"
                    }
                }
            }))
            .expect("document"),
        ))
    }
}

// Selects one deterministic health exchange result.
#[derive(Clone, Copy)]
enum ResponseMode {
    Healthy,
    Inactive,
    WrongIdentity,
    WrongRole,
    Failure,
    MismatchedRequest,
    Malformed,
    Unavailable,
}

// Produces exact wire responses and records owner, path, and timeout inputs.
struct ExchangeMock {
    mode: ResponseMode,
    calls: Mutex<Vec<(String, u32, Duration)>>,
}

impl NodeHealthExchange for ExchangeMock {
    // Returns the selected response through the same production codec contract.
    fn exchange(
        &self,
        socket_path: &Path,
        owner_uid: u32,
        request: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, NodeHealthError> {
        self.calls.lock().expect("calls").push((
            socket_path.display().to_string(),
            owner_uid,
            timeout,
        ));
        if matches!(self.mode, ResponseMode::Unavailable) {
            return Err(NodeHealthError::EndpointUnavailable);
        }
        if matches!(self.mode, ResponseMode::Malformed) {
            return Ok(b"not-json".to_vec());
        }
        let request = NodePrivateTransport::decode_request(request).expect("request");
        let request_id = if matches!(self.mode, ResponseMode::MismatchedRequest) {
            Sha256Digest::parse(&"f".repeat(64)).expect("request identity")
        } else {
            request.request_id().clone()
        };
        let outcome = if matches!(self.mode, ResponseMode::Failure) {
            NodePrivateTransportOutcome::Failure(
                NodePrivateRemoteError::new(
                    TechnicalName::parse("unavailable").expect("code"),
                    "Node is unavailable",
                )
                .expect("failure"),
            )
        } else {
            let state = if matches!(self.mode, ResponseMode::Inactive) {
                NodeState::Offline
            } else {
                NodeState::Active
            };
            let character = if matches!(self.mode, ResponseMode::WrongIdentity) {
                '9'
            } else {
                '1'
            };
            let role = if matches!(self.mode, ResponseMode::WrongRole) {
                NodeRole::Child
            } else {
                NodeRole::Main
            };
            NodePrivateTransportOutcome::Success(NodePrivateResponse::LocalNode(local_node(
                character, role, state,
            )))
        };
        NodePrivateTransport::encode_response(&NodePrivateTransportResponse::new(
            request_id, outcome,
        ))
        .map_err(|_| NodeHealthError::InvalidResponse)
    }
}

// Returns one validated configuration through the ordinary strict loader.
fn configuration() -> NodeConfiguration {
    NodeConfiguration::load(
        &NodeConfigurationFileReference::new("/etc/letsinfer/li_node.json".into(), 501)
            .expect("reference"),
        &ConfigurationProvider,
    )
    .expect("configuration")
}

// Returns one coherent local Node with a selectable identity and lifecycle state.
fn local_node(character: char, role: NodeRole, state: NodeState) -> Node {
    Node::new(
        NodeIdentity::new(
            NodeId::parse(&character.to_string().repeat(32)).expect("node"),
            MachineId::parse(&"2".repeat(32)).expect("machine"),
            InstallationId::parse(&"3".repeat(64)).expect("installation"),
        ),
        DisplayName::parse("Home AI").expect("name"),
        role,
        state,
        NodeAddress::parse("homeai.local").expect("address"),
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1), UnixMilliseconds::new(1))
            .expect("timestamps"),
    )
}

// Proves setup health accepts only the exact active Node identity and role from ReadLocalNode.
#[test]
fn health_binds_the_setup_identity_without_database_access() {
    let node_id = NodeId::parse(&"1".repeat(32)).expect("node");
    for (mode, expected) in [
        (ResponseMode::Healthy, Ok(())),
        (
            ResponseMode::Unavailable,
            Err(NodeHealthError::EndpointUnavailable),
        ),
        (ResponseMode::WrongIdentity, Err(NodeHealthError::NotReady)),
        (ResponseMode::WrongRole, Err(NodeHealthError::NotReady)),
    ] {
        let probe = NodeHealthProbe::new(Box::new(ExchangeMock {
            mode,
            calls: Mutex::new(Vec::new()),
        }));
        assert_eq!(
            probe.observe_expected(
                &configuration(),
                Some(&node_id),
                NodeRole::Main,
                Duration::from_secs(2),
            ),
            expected
        );
    }
}

// Proves role-only service activation still uses the same local API and rejects role drift.
#[test]
fn health_role_projection_never_requires_a_database_identity_read() {
    for (mode, expected) in [
        (ResponseMode::Healthy, Ok(())),
        (ResponseMode::WrongRole, Err(NodeHealthError::NotReady)),
    ] {
        let probe = NodeHealthProbe::new(Box::new(ExchangeMock {
            mode,
            calls: Mutex::new(Vec::new()),
        }));
        assert_eq!(
            probe.observe_expected(
                &configuration(),
                None,
                NodeRole::Main,
                Duration::from_secs(2),
            ),
            expected
        );
    }
}

// Proves health requires an owner-authenticated round trip to the exact active durable identity.
#[test]
fn health_observes_exact_active_node_through_private_api() {
    let exchange = ExchangeMock {
        mode: ResponseMode::Healthy,
        calls: Mutex::new(Vec::new()),
    };
    let probe = NodeHealthProbe::new(Box::new(exchange));
    probe
        .observe(
            &configuration(),
            &NodeId::parse(&"1".repeat(32)).expect("node"),
            Duration::from_secs(2),
        )
        .expect("healthy");
}

// Rejects every unavailable, corrupt, mismatched, or inactive process observation.
#[test]
fn health_failure_matrix_never_treats_process_presence_as_readiness() {
    for (mode, expected) in [
        (ResponseMode::Inactive, NodeHealthError::NotReady),
        (ResponseMode::WrongIdentity, NodeHealthError::NotReady),
        (ResponseMode::Failure, NodeHealthError::InvalidResponse),
        (
            ResponseMode::MismatchedRequest,
            NodeHealthError::InvalidResponse,
        ),
        (ResponseMode::Malformed, NodeHealthError::InvalidResponse),
        (
            ResponseMode::Unavailable,
            NodeHealthError::EndpointUnavailable,
        ),
    ] {
        let probe = NodeHealthProbe::new(Box::new(ExchangeMock {
            mode,
            calls: Mutex::new(Vec::new()),
        }));
        assert_eq!(
            probe.observe(
                &configuration(),
                &NodeId::parse(&"1".repeat(32)).expect("node"),
                Duration::from_secs(2),
            ),
            Err(expected)
        );
    }
    let probe = NodeHealthProbe::new(Box::new(ExchangeMock {
        mode: ResponseMode::Healthy,
        calls: Mutex::new(Vec::new()),
    }));
    assert_eq!(
        probe.observe(
            &configuration(),
            &NodeId::parse(&"1".repeat(32)).expect("node"),
            Duration::ZERO,
        ),
        Err(NodeHealthError::InvalidContract)
    );
}

// Rejects one valid-looking health socket reached through an intermediate symbolic link.
#[test]
fn system_health_exchange_rejects_an_intermediate_parent_symlink() {
    let directory = tempfile::tempdir().expect("temporary directory");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("root permissions");
    let directory_path = fs::canonicalize(directory.path()).expect("canonical socket parent");
    let target = directory_path.join("target");
    let protected = target.join("protected");
    fs::create_dir_all(&protected).expect("protected hierarchy");
    fs::set_permissions(&protected, fs::Permissions::from_mode(0o700))
        .expect("protected permissions");
    let real_socket = protected.join("node.sock");
    let _listener = UnixListener::bind(&real_socket).expect("real socket");
    fs::set_permissions(&real_socket, fs::Permissions::from_mode(0o600))
        .expect("socket permissions");
    let alias = directory_path.join("alias");
    symlink(&target, &alias).expect("intermediate symlink");
    let owner_user_id = fs::metadata(&protected).expect("owner").uid();

    assert_eq!(
        SystemNodeHealthExchange.exchange(
            &alias.join("protected/node.sock"),
            owner_user_id,
            b"{}",
            Duration::from_secs(1),
        ),
        Err(NodeHealthError::EndpointUnavailable)
    );
}
