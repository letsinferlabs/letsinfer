// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use li_core_interface::{CpuArchitecture, InstallationId, NodeId, Sha256Digest};
use li_core_update_manager::{
    CoreUpdateNodeRole, CoreUpdateServiceContext, CoreUpdateServicePlatform, CoreVersion,
};
use li_gateway_manager::{
    GatewayConfiguration, GatewayConfigurationFile, GatewayNativeFile, GatewayNativeFileIo,
    GatewayNativeIoError,
};
use li_node_manager::{
    NodeConfiguration, NodeConfigurationError, NodeConfigurationFile,
    NodeConfigurationFileProvider, NodeConfigurationFileReference,
};
use li_watchdog_manager::{WatchdogConfiguration, WatchdogSafetyThresholds};

use crate::li_core_cli_process::{
    CoreCliConfiguration, CoreCliConfigurationFile, CoreCliConfigurationFileProvider,
    CoreCliProcessError, CORE_CLI_CONFIGURATION_FILENAME, CORE_CLI_CONFIGURATION_SCHEMA_NAME,
    CORE_CLI_CONFIGURATION_SCHEMA_VERSION, MAXIMUM_CORE_CLI_CONFIGURATION_BYTES,
};
use crate::li_core_setup::CoreSetupPreparedMaterial;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const CONFIGURATION_DIRECTORY_MODE: u32 = 0o700;
const CONFIGURATION_FILE_MODE: u32 = 0o600;
const MAXIMUM_CONFIGURATION_BYTES: usize = 64 * 1024;
const MAXIMUM_TRANSACTION_BYTES: usize = 128 * 1024;
const SETUP_LOCK_FILENAME: &str = ".li_core_setup_configuration.lock";
const SETUP_INTENT_FILENAME: &str = ".li_core_setup_configuration.intent.json";
const SETUP_INTENT_PENDING_FILENAME: &str = ".li_core_setup_configuration.intent.pending";
const SETUP_RECEIPT_FILENAME: &str = ".li_core_setup_configuration.receipt.json";
const SETUP_RECEIPT_PENDING_FILENAME: &str = ".li_core_setup_configuration.receipt.pending";
const SETUP_ROLLBACK_FILENAME: &str = ".li_core_setup_configuration.rollback.json";
const SETUP_ROLLBACK_PENDING_FILENAME: &str = ".li_core_setup_configuration.rollback.pending";

pub const NODE_CONFIGURATION_FILENAME: &str = "li_node.json";
pub const GATEWAY_CONFIGURATION_FILENAME: &str = "li_gateway.json";
pub const WATCHDOG_CONFIGURATION_FILENAME: &str = "li_watchdog.json";

// Describes one stable redacted configuration-generation or installation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupConfigurationError {
    reason: &'static str,
    recovery_required: bool,
}

impl CoreSetupConfigurationError {
    // Creates one stable provider-facing error without accepting native or document values.
    pub const fn provider(reason: &'static str) -> Self {
        Self {
            reason,
            recovery_required: false,
        }
    }

    // Creates one stable failure after a durable configuration intent may own native state.
    pub const fn recovery_required(reason: &'static str) -> Self {
        Self {
            reason,
            recovery_required: true,
        }
    }

    // Returns the stable redacted failure reason.
    pub const fn reason(&self) -> &'static str {
        self.reason
    }

    // Returns whether setup must preserve native state for deterministic recovery.
    pub const fn requires_recovery(&self) -> bool {
        self.recovery_required
    }
}

impl fmt::Display for CoreSetupConfigurationError {
    // Presents one stable failure without paths, native errors, or configuration values.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason)
    }
}

impl Error for CoreSetupConfigurationError {}

// Carries one exact Linux or Apple Silicon hardware-provider input set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoreSetupNodeHardwareInput {
    Linux {
        architecture: CpuArchitecture,
        boot_id_file: PathBuf,
        cpu_information_file: PathBuf,
        memory_information_file: PathBuf,
        nvidia_smi_command: Option<PathBuf>,
        rdma_command: Option<PathBuf>,
    },
    MacosArm64 {
        sysctl_command: PathBuf,
        metal_probe_command: PathBuf,
    },
}

// Selects one platform-closed native pairing discovery and direct-link contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoreSetupNodePairingPlatformInput {
    Linux {
        discovery_command: PathBuf,
        direct_link_sys_class: PathBuf,
        direct_link_ip_command: PathBuf,
    },
    Macos {
        discovery_command: PathBuf,
    },
}

// Carries every explicit native and trust input required by PairingManager composition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupNodePairingInput {
    platform: CoreSetupNodePairingPlatformInput,
    openssl_command: PathBuf,
    trust_workspace: PathBuf,
    site_private_key_file: PathBuf,
    site_public_key_file: PathBuf,
    site_ca_certificate_file: PathBuf,
    local_control_certificate_file: PathBuf,
    public_key_sha256: Sha256Digest,
    certificate_sha256: Sha256Digest,
}

impl CoreSetupNodePairingInput {
    // Creates one complete injected pairing input without inspecting native state.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        platform: CoreSetupNodePairingPlatformInput,
        openssl_command: PathBuf,
        trust_workspace: PathBuf,
        site_private_key_file: PathBuf,
        site_public_key_file: PathBuf,
        site_ca_certificate_file: PathBuf,
        local_control_certificate_file: PathBuf,
        public_key_sha256: Sha256Digest,
        certificate_sha256: Sha256Digest,
    ) -> Self {
        Self {
            platform,
            openssl_command,
            trust_workspace,
            site_private_key_file,
            site_public_key_file,
            site_ca_certificate_file,
            local_control_certificate_file,
            public_key_sha256,
            certificate_sha256,
        }
    }
}

// Carries the complete owner-local Node private API configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupNodeLocalApiInput {
    socket_path: PathBuf,
    maximum_workers: usize,
    read_timeout_milliseconds: u64,
    write_timeout_milliseconds: u64,
    accept_poll_interval_milliseconds: u64,
}

impl CoreSetupNodeLocalApiInput {
    // Creates one explicit local listener input without discovering paths or timing defaults.
    pub const fn new(
        socket_path: PathBuf,
        maximum_workers: usize,
        read_timeout_milliseconds: u64,
        write_timeout_milliseconds: u64,
        accept_poll_interval_milliseconds: u64,
    ) -> Self {
        Self {
            socket_path,
            maximum_workers,
            read_timeout_milliseconds,
            write_timeout_milliseconds,
            accept_poll_interval_milliseconds,
        }
    }

    // Returns the exact owner-local socket shared with the native CLI client.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

// Carries the complete nonresident native CLI configuration input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupCliInput {
    local_node_socket: PathBuf,
    entropy_source: PathBuf,
    launcher_file: PathBuf,
    privilege_command: Option<PathBuf>,
    timeout_milliseconds: u64,
    maximum_response_bytes: usize,
}

impl CoreSetupCliInput {
    // Creates one explicit client configuration without discovering a socket or entropy source.
    pub const fn new(
        local_node_socket: PathBuf,
        entropy_source: PathBuf,
        launcher_file: PathBuf,
        privilege_command: Option<PathBuf>,
        timeout_milliseconds: u64,
        maximum_response_bytes: usize,
    ) -> Self {
        Self {
            local_node_socket,
            entropy_source,
            launcher_file,
            privilege_command,
            timeout_milliseconds,
            maximum_response_bytes,
        }
    }
}

// Carries the complete mutually authenticated Node remote API configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupNodeRemoteApiInput {
    bind_address: SocketAddr,
    maximum_workers: usize,
    accept_poll_interval_milliseconds: u64,
    handshake_timeout_milliseconds: u64,
    read_timeout_milliseconds: u64,
    write_timeout_milliseconds: u64,
    server_certificate_file: PathBuf,
    server_private_key_file: PathBuf,
    client_ca_file: PathBuf,
}

impl CoreSetupNodeRemoteApiInput {
    // Creates one explicit remote listener whose credential material remains in referenced files.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        bind_address: SocketAddr,
        maximum_workers: usize,
        accept_poll_interval_milliseconds: u64,
        handshake_timeout_milliseconds: u64,
        read_timeout_milliseconds: u64,
        write_timeout_milliseconds: u64,
        server_certificate_file: PathBuf,
        server_private_key_file: PathBuf,
        client_ca_file: PathBuf,
    ) -> Self {
        Self {
            bind_address,
            maximum_workers,
            accept_poll_interval_milliseconds,
            handshake_timeout_milliseconds,
            read_timeout_milliseconds,
            write_timeout_milliseconds,
            server_certificate_file,
            server_private_key_file,
            client_ca_file,
        }
    }
}

// Carries every explicit Node document value supplied by setup orchestration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupNodeInput {
    database_file: PathBuf,
    core_update: CoreSetupNodeUpdateInput,
    model: CoreSetupNodeModelInput,
    benchmark: Option<CoreSetupNodeBenchmarkInput>,
    pairing_setup_secret_file: PathBuf,
    pairing: CoreSetupNodePairingInput,
    hardware: CoreSetupNodeHardwareInput,
    placement_safety: CoreSetupNodePlacementSafetyInput,
    daemon_cadence_milliseconds: u64,
    local_api: CoreSetupNodeLocalApiInput,
    remote_api: CoreSetupNodeRemoteApiInput,
}

impl CoreSetupNodeInput {
    // Creates one Node input without consulting host hardware, networking, or filesystem state.
    pub const fn new(
        database_file: PathBuf,
        core_update: CoreSetupNodeUpdateInput,
        model: CoreSetupNodeModelInput,
        benchmark: Option<CoreSetupNodeBenchmarkInput>,
        pairing_setup_secret_file: PathBuf,
        pairing: CoreSetupNodePairingInput,
        hardware: CoreSetupNodeHardwareInput,
        placement_safety: CoreSetupNodePlacementSafetyInput,
        daemon_cadence_milliseconds: u64,
        local_api: CoreSetupNodeLocalApiInput,
        remote_api: CoreSetupNodeRemoteApiInput,
    ) -> Self {
        Self {
            database_file,
            core_update,
            model,
            benchmark,
            pairing_setup_secret_file,
            pairing,
            hardware,
            placement_safety,
            daemon_cadence_milliseconds,
            local_api,
            remote_api,
        }
    }
}

// Carries every explicit production Core-update authority written to Node configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupNodeUpdateInput {
    pub release_platform: String,
    pub letsinfer_home: PathBuf,
    pub home_directory: PathBuf,
    pub setup_state_directory: PathBuf,
    pub configuration_root: PathBuf,
    pub curl_command: PathBuf,
    pub ssh_keygen_command: PathBuf,
    pub allowed_signers_file: PathBuf,
    pub supervisor_command: PathBuf,
    pub readiness_timeout_milliseconds: u64,
    pub readiness_poll_milliseconds: u64,
    pub stable_readiness_observations: u32,
}

// Carries every explicit signed-runtime and native-placement value written to Node configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupNodeModelInput {
    pub catalog_source: String,
    pub catalog_cache_root: PathBuf,
    pub catalog_hydration_root: PathBuf,
    pub http_workspace_root: PathBuf,
    pub installation_root: PathBuf,
    pub runtime_cache_root: PathBuf,
    pub curl_command: PathBuf,
    pub docker_command: PathBuf,
    pub command_working_directory: PathBuf,
    pub placement_material_root: PathBuf,
    pub placement_secret_root: PathBuf,
    pub placement_tls_workspace_root: PathBuf,
    pub first_port: u16,
    pub port_count: u16,
    pub endpoint_timeout_milliseconds: u64,
    pub maximum_hardware_age_milliseconds: u64,
    pub group_id: u32,
    pub launch_agents_root: Option<PathBuf>,
    pub launchctl_command: Option<PathBuf>,
}

// Carries one explicit Linux benchmark execution, signing, and Watchdog history contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupNodeBenchmarkInput {
    worker_executable: PathBuf,
    github_cli_command: PathBuf,
    task_root: PathBuf,
    telemetry_root: PathBuf,
    evidence_root: PathBuf,
    signing_workspace_root: PathBuf,
    signing_private_key_file: PathBuf,
    signing_public_key_file: PathBuf,
    maximum_runtime_milliseconds: u64,
    stop_grace_milliseconds: u64,
    watchdog_host: String,
    watchdog_port: u16,
    watchdog_server_name: String,
    watchdog_ca_file: PathBuf,
    watchdog_controller_authority_private_key_file: PathBuf,
    watchdog_controller_allowlist_file: PathBuf,
    watchdog_controller_reload_receipt_file: PathBuf,
    watchdog_enrollment_server_certificate_file: PathBuf,
    watchdog_enrollment_server_private_key_file: PathBuf,
    watchdog_controller_certificate_file: PathBuf,
    watchdog_controller_private_key_file: PathBuf,
    watchdog_timeout_milliseconds: u64,
}

impl CoreSetupNodeBenchmarkInput {
    // Creates one complete benchmark contract without native discovery or credential bytes.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        worker_executable: PathBuf,
        github_cli_command: PathBuf,
        task_root: PathBuf,
        telemetry_root: PathBuf,
        evidence_root: PathBuf,
        signing_workspace_root: PathBuf,
        signing_private_key_file: PathBuf,
        signing_public_key_file: PathBuf,
        maximum_runtime_milliseconds: u64,
        stop_grace_milliseconds: u64,
        watchdog_host: String,
        watchdog_port: u16,
        watchdog_server_name: String,
        watchdog_ca_file: PathBuf,
        watchdog_controller_authority_private_key_file: PathBuf,
        watchdog_controller_allowlist_file: PathBuf,
        watchdog_controller_reload_receipt_file: PathBuf,
        watchdog_enrollment_server_certificate_file: PathBuf,
        watchdog_enrollment_server_private_key_file: PathBuf,
        watchdog_controller_certificate_file: PathBuf,
        watchdog_controller_private_key_file: PathBuf,
        watchdog_timeout_milliseconds: u64,
    ) -> Self {
        Self {
            worker_executable,
            github_cli_command,
            task_root,
            telemetry_root,
            evidence_root,
            signing_workspace_root,
            signing_private_key_file,
            signing_public_key_file,
            maximum_runtime_milliseconds,
            stop_grace_milliseconds,
            watchdog_host,
            watchdog_port,
            watchdog_server_name,
            watchdog_ca_file,
            watchdog_controller_authority_private_key_file,
            watchdog_controller_allowlist_file,
            watchdog_controller_reload_receipt_file,
            watchdog_enrollment_server_certificate_file,
            watchdog_enrollment_server_private_key_file,
            watchdog_controller_certificate_file,
            watchdog_controller_private_key_file,
            watchdog_timeout_milliseconds,
        }
    }
}

// Carries one immutable service executable expected on the Linux protection socket.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupNodeProtectionExecutableInput {
    path: PathBuf,
    executable_sha256: Sha256Digest,
    principal_id: li_core_interface::CredentialId,
}

impl CoreSetupNodeProtectionExecutableInput {
    // Creates one exact installed executable and role-specific API principal.
    pub const fn new(
        path: PathBuf,
        executable_sha256: Sha256Digest,
        principal_id: li_core_interface::CredentialId,
    ) -> Self {
        Self {
            path,
            executable_sha256,
            principal_id,
        }
    }
}

// Selects Linux Watchdog protection or the distinct macOS launchd safety contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoreSetupNodePlacementSafetyInput {
    Linux {
        socket_path: PathBuf,
        maximum_workers: usize,
        read_timeout_milliseconds: u64,
        write_timeout_milliseconds: u64,
        accept_poll_interval_milliseconds: u64,
        protection_root: PathBuf,
        watchdog_source_identity: Sha256Digest,
        gateway: CoreSetupNodeProtectionExecutableInput,
        watchdog: CoreSetupNodeProtectionExecutableInput,
        lease_milliseconds: u64,
    },
    MacosLaunchd,
}

// Carries every explicit owner-local Gateway health endpoint bound.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupGatewayHealthInput {
    socket_path: PathBuf,
    maximum_workers: usize,
    read_timeout_milliseconds: u64,
    write_timeout_milliseconds: u64,
    accept_poll_interval_milliseconds: u64,
}

impl CoreSetupGatewayHealthInput {
    // Creates one local health input without discovering paths or timing defaults.
    pub const fn new(
        socket_path: PathBuf,
        maximum_workers: usize,
        read_timeout_milliseconds: u64,
        write_timeout_milliseconds: u64,
        accept_poll_interval_milliseconds: u64,
    ) -> Self {
        Self {
            socket_path,
            maximum_workers,
            read_timeout_milliseconds,
            write_timeout_milliseconds,
            accept_poll_interval_milliseconds,
        }
    }
}

// Carries every explicit Gateway-to-Node protection channel and cache bound.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupGatewayProtectionInput {
    socket_path: PathBuf,
    read_timeout_milliseconds: u64,
    write_timeout_milliseconds: u64,
    maximum_cache_milliseconds: u64,
    poll_interval_milliseconds: u64,
}

impl CoreSetupGatewayProtectionInput {
    // Creates one dedicated protection input without discovering socket or timing defaults.
    pub const fn new(
        socket_path: PathBuf,
        read_timeout_milliseconds: u64,
        write_timeout_milliseconds: u64,
        maximum_cache_milliseconds: u64,
        poll_interval_milliseconds: u64,
    ) -> Self {
        Self {
            socket_path,
            read_timeout_milliseconds,
            write_timeout_milliseconds,
            maximum_cache_milliseconds,
            poll_interval_milliseconds,
        }
    }

    // Returns the exact dedicated Node-owned protection socket.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    // Returns the complete-frame client read timeout.
    pub const fn read_timeout_milliseconds(&self) -> u64 {
        self.read_timeout_milliseconds
    }

    // Returns the complete-frame client write timeout.
    pub const fn write_timeout_milliseconds(&self) -> u64 {
        self.write_timeout_milliseconds
    }
}

// Carries one bounded Gateway listener selected by setup orchestration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoreSetupGatewayListenerInput {
    address: SocketAddr,
    maximum_connections: usize,
}

impl CoreSetupGatewayListenerInput {
    // Creates one literal socket listener without native address discovery.
    pub const fn new(address: SocketAddr, maximum_connections: usize) -> Self {
        Self {
            address,
            maximum_connections,
        }
    }
}

// Carries the Gateway private listener and four referenced TLS file roles.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupGatewayPrivateListenerInput {
    listener: CoreSetupGatewayListenerInput,
    server_certificate_file: PathBuf,
    server_private_key_file: PathBuf,
    client_ca_file: PathBuf,
    client_certificate_file: PathBuf,
}

impl CoreSetupGatewayPrivateListenerInput {
    // Creates one private listener whose certificates and key remain external file references.
    pub const fn new(
        listener: CoreSetupGatewayListenerInput,
        server_certificate_file: PathBuf,
        server_private_key_file: PathBuf,
        client_ca_file: PathBuf,
        client_certificate_file: PathBuf,
    ) -> Self {
        Self {
            listener,
            server_certificate_file,
            server_private_key_file,
            client_ca_file,
            client_certificate_file,
        }
    }
}

// Carries every explicit Gateway document value supplied by setup orchestration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupGatewayInput {
    node_id: NodeId,
    core_version: CoreVersion,
    core_source_identity: Sha256Digest,
    health: CoreSetupGatewayHealthInput,
    node_protection: CoreSetupGatewayProtectionInput,
    node_socket_path: PathBuf,
    telemetry_file: PathBuf,
    telemetry_cadence_milliseconds: u64,
    maximum_queue_milliseconds: u64,
    public_listener: Option<CoreSetupGatewayListenerInput>,
    private_listener: CoreSetupGatewayPrivateListenerInput,
}

impl CoreSetupGatewayInput {
    // Creates one role-bound Gateway input without inferring public exposure or native paths.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        node_id: NodeId,
        core_version: CoreVersion,
        core_source_identity: Sha256Digest,
        health: CoreSetupGatewayHealthInput,
        node_protection: CoreSetupGatewayProtectionInput,
        node_socket_path: PathBuf,
        telemetry_file: PathBuf,
        telemetry_cadence_milliseconds: u64,
        maximum_queue_milliseconds: u64,
        public_listener: Option<CoreSetupGatewayListenerInput>,
        private_listener: CoreSetupGatewayPrivateListenerInput,
    ) -> Self {
        Self {
            node_id,
            core_version,
            core_source_identity,
            health,
            node_protection,
            node_socket_path,
            telemetry_file,
            telemetry_cadence_milliseconds,
            maximum_queue_milliseconds,
            public_listener,
            private_listener,
        }
    }
}

// Carries every referenced Watchdog path without carrying any credential bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupWatchdogPathsInput {
    data_directory: PathBuf,
    server_certificate_path: PathBuf,
    server_private_key_path: PathBuf,
    controller_ca_path: PathBuf,
    controller_allowlist_path: PathBuf,
    controller_snapshot_path: PathBuf,
    site_state_path: PathBuf,
    gateway_metrics_path: PathBuf,
    protection_root_path: PathBuf,
    node_database_path: PathBuf,
    runtime_installation_root: PathBuf,
    runtime_cache_root: PathBuf,
}

impl CoreSetupWatchdogPathsInput {
    // Creates one complete Watchdog path set without filesystem probing or implicit aliases.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        data_directory: PathBuf,
        server_certificate_path: PathBuf,
        server_private_key_path: PathBuf,
        controller_ca_path: PathBuf,
        controller_allowlist_path: PathBuf,
        controller_snapshot_path: PathBuf,
        site_state_path: PathBuf,
        gateway_metrics_path: PathBuf,
        protection_root_path: PathBuf,
        node_database_path: PathBuf,
        runtime_installation_root: PathBuf,
        runtime_cache_root: PathBuf,
    ) -> Self {
        Self {
            data_directory,
            server_certificate_path,
            server_private_key_path,
            controller_ca_path,
            controller_allowlist_path,
            controller_snapshot_path,
            site_state_path,
            gateway_metrics_path,
            protection_root_path,
            node_database_path,
            runtime_installation_root,
            runtime_cache_root,
        }
    }
}

// Carries Linux-only Watchdog identity, listener, storage, cadence, and safety inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupWatchdogInput {
    installation_id: InstallationId,
    node_id: NodeId,
    core_version: CoreVersion,
    core_source_identity: Sha256Digest,
    listen_address: IpAddr,
    listen_port: u16,
    paths: CoreSetupWatchdogPathsInput,
    node_protection: CoreSetupWatchdogProtectionInput,
    flush_interval_milliseconds: u32,
    maximum_controllers: usize,
    thresholds: WatchdogSafetyThresholds,
}

impl CoreSetupWatchdogInput {
    // Creates one Linux Watchdog input while retaining the existing typed safety contract.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        installation_id: InstallationId,
        node_id: NodeId,
        core_version: CoreVersion,
        core_source_identity: Sha256Digest,
        listen_address: IpAddr,
        listen_port: u16,
        paths: CoreSetupWatchdogPathsInput,
        node_protection: CoreSetupWatchdogProtectionInput,
        flush_interval_milliseconds: u32,
        maximum_controllers: usize,
        thresholds: WatchdogSafetyThresholds,
    ) -> Self {
        Self {
            installation_id,
            node_id,
            core_version,
            core_source_identity,
            listen_address,
            listen_port,
            paths,
            node_protection,
            flush_interval_milliseconds,
            maximum_controllers,
            thresholds,
        }
    }
}

// Carries the dedicated Watchdog-to-Node client channel without server-only fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupWatchdogProtectionInput {
    socket_path: PathBuf,
    read_timeout_milliseconds: u64,
    write_timeout_milliseconds: u64,
}

impl CoreSetupWatchdogProtectionInput {
    // Creates one explicit bounded client channel.
    pub const fn new(
        socket_path: PathBuf,
        read_timeout_milliseconds: u64,
        write_timeout_milliseconds: u64,
    ) -> Self {
        Self {
            socket_path,
            read_timeout_milliseconds,
            write_timeout_milliseconds,
        }
    }
}

// Binds one setup transaction to an explicit platform, role, owner, and complete document inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupConfigurationInput {
    context: CoreUpdateServiceContext,
    configuration_directory: PathBuf,
    owner_user_id: u32,
    cli: CoreSetupCliInput,
    node: CoreSetupNodeInput,
    gateway: CoreSetupGatewayInput,
    watchdog: Option<CoreSetupWatchdogInput>,
}

impl CoreSetupConfigurationInput {
    // Creates the sole typed input accepted by configuration generation and installation.
    pub const fn new(
        context: CoreUpdateServiceContext,
        configuration_directory: PathBuf,
        owner_user_id: u32,
        cli: CoreSetupCliInput,
        node: CoreSetupNodeInput,
        gateway: CoreSetupGatewayInput,
        watchdog: Option<CoreSetupWatchdogInput>,
    ) -> Self {
        Self {
            context,
            configuration_directory,
            owner_user_id,
            cli,
            node,
            gateway,
            watchdog,
        }
    }

    // Returns the exact role and platform bound to this complete document set.
    pub const fn context(&self) -> CoreUpdateServiceContext {
        self.context
    }

    // Returns the canonical private directory that owns the complete transaction.
    pub fn configuration_directory(&self) -> &Path {
        &self.configuration_directory
    }

    // Returns the native owner required for every transaction and configuration file.
    pub const fn owner_user_id(&self) -> u32 {
        self.owner_user_id
    }
}

// Binds configuration bytes to the exact setup request, preceding receipts, and provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupConfigurationBinding {
    request_identity: Sha256Digest,
    identity_receipt_identity: Sha256Digest,
    material_receipt_identity: Sha256Digest,
    material_identity: Sha256Digest,
    provider_identity: Sha256Digest,
    provisioned_files: BTreeSet<PathBuf>,
}

impl CoreSetupConfigurationBinding {
    // Creates one secret-free binding after the composition root resolves prepared material.
    pub fn new(
        request_identity: Sha256Digest,
        identity_receipt_identity: Sha256Digest,
        material_receipt_identity: Sha256Digest,
        material_identity: Sha256Digest,
        provider_identity: Sha256Digest,
        provisioned_files: impl IntoIterator<Item = PathBuf>,
    ) -> Result<Self, CoreSetupConfigurationError> {
        let provisioned_files = provisioned_files.into_iter().collect::<BTreeSet<_>>();
        if provisioned_files.is_empty()
            || provisioned_files
                .iter()
                .any(|path| !is_normal_absolute_path(path) || path == Path::new("/"))
        {
            return Err(configuration_error(
                "prepared material path closure is invalid",
            ));
        }
        Ok(Self {
            request_identity,
            identity_receipt_identity,
            material_receipt_identity,
            material_identity,
            provider_identity,
            provisioned_files,
        })
    }

    // Returns the exact provider implementation identity persisted in durable intent.
    pub const fn provider_identity(&self) -> &Sha256Digest {
        &self.provider_identity
    }
}

// Identifies whether setup created at least one file or exactly replayed durable state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreSetupConfigurationInstallStatus {
    Installed,
    Replayed,
}

// Returns the exact installed file set and whether this transaction mutated it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupConfigurationInstallation {
    status: CoreSetupConfigurationInstallStatus,
    files: Vec<PathBuf>,
    receipt_identity: Sha256Digest,
}

impl CoreSetupConfigurationInstallation {
    // Returns whether at least one absent configuration was installed.
    pub const fn status(&self) -> CoreSetupConfigurationInstallStatus {
        self.status
    }

    // Returns the complete authoritative configuration paths in deterministic generation order.
    pub fn files(&self) -> &[PathBuf] {
        &self.files
    }

    // Returns the opaque durable transaction identity required for exact rollback.
    pub const fn receipt_identity(&self) -> &Sha256Digest {
        &self.receipt_identity
    }
}

// Carries one bounded no-follow observation used for exact replay and divergence judgment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupConfigurationFile {
    owner_user_id: u32,
    mode: u32,
    link_count: u64,
    is_regular_file: bool,
    is_stable: bool,
    bytes: Vec<u8>,
}

impl CoreSetupConfigurationFile {
    // Creates one descriptor-shaped observation for production or deterministic tests.
    pub fn new(
        owner_user_id: u32,
        mode: u32,
        link_count: u64,
        is_regular_file: bool,
        is_stable: bool,
        bytes: Vec<u8>,
    ) -> Self {
        Self {
            owner_user_id,
            mode,
            link_count,
            is_regular_file,
            is_stable,
            bytes,
        }
    }
}

// Holds one process-wide setup lock until the transaction completes or unwinds.
pub trait CoreSetupConfigurationLock: Send {}

// Isolates owner-bound no-follow reads and the two ambiguous publication boundaries.
pub trait CoreSetupConfigurationIo: Send + Sync {
    // Acquires the fixed owner-only process lock for one configuration directory.
    fn acquire_lock(
        &self,
        directory: &Path,
        owner_user_id: u32,
    ) -> Result<Box<dyn CoreSetupConfigurationLock>, CoreSetupConfigurationError>;

    // Reads one optional bounded path without following its final component.
    fn read_no_follow(
        &self,
        path: &Path,
        maximum_bytes: usize,
    ) -> Result<Option<CoreSetupConfigurationFile>, CoreSetupConfigurationError>;

    // Creates and file-synchronizes one absent same-directory temporary configuration.
    fn stage(
        &self,
        path: &Path,
        bytes: &[u8],
        owner_user_id: u32,
    ) -> Result<(), CoreSetupConfigurationError>;

    // Atomically renames one synchronized temporary file to its authoritative path.
    fn activate(
        &self,
        source: &Path,
        destination: &Path,
    ) -> Result<(), CoreSetupConfigurationError>;

    // Removes one exact safe file while refusing missing metadata or byte drift.
    fn remove_exact(
        &self,
        path: &Path,
        expected: &[u8],
        owner_user_id: u32,
    ) -> Result<(), CoreSetupConfigurationError>;

    // Synchronizes the containing directory after activation or exact replay.
    fn sync_directory(&self, path: &Path) -> Result<(), CoreSetupConfigurationError>;
}

// Performs production owner-bound atomic configuration I/O through the retained lock directory.
#[derive(Clone, Default)]
pub struct SystemCoreSetupConfigurationIo {
    locked_directories: Arc<Mutex<BTreeMap<PathBuf, Arc<LockedConfigurationDirectory>>>>,
}

// Retains one owner-bound directory descriptor for every operation under the fixed lock.
struct LockedConfigurationDirectory {
    file: File,
    owner_user_id: u32,
}

// Holds the production advisory lock descriptor and releases it on drop.
struct SystemCoreSetupConfigurationLock {
    file: File,
    directory_path: PathBuf,
    directory: Arc<LockedConfigurationDirectory>,
    locked_directories: Arc<Mutex<BTreeMap<PathBuf, Arc<LockedConfigurationDirectory>>>>,
}

impl CoreSetupConfigurationLock for SystemCoreSetupConfigurationLock {}

impl Drop for SystemCoreSetupConfigurationLock {
    // Releases the advisory lock before closing its descriptor.
    fn drop(&mut self) {
        if let Ok(mut directories) = self.locked_directories.lock() {
            if directories
                .get(&self.directory_path)
                .is_some_and(|directory| Arc::ptr_eq(directory, &self.directory))
            {
                directories.remove(&self.directory_path);
            }
        }
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

impl CoreSetupConfigurationIo for SystemCoreSetupConfigurationIo {
    // Validates the private directory and acquires its fixed no-follow owner-only lock.
    fn acquire_lock(
        &self,
        directory: &Path,
        owner_user_id: u32,
    ) -> Result<Box<dyn CoreSetupConfigurationLock>, CoreSetupConfigurationError> {
        validate_configuration_directory(directory, owner_user_id)?;
        let directory_path = directory.to_path_buf();
        let directory_file = open_directory_descriptor(directory)?;
        validate_opened_configuration_directory(&directory_file, directory, owner_user_id)?;
        let directory = Arc::new(LockedConfigurationDirectory {
            file: directory_file,
            owner_user_id,
        });
        let file = open_file_at(
            &directory.file,
            SETUP_LOCK_FILENAME,
            libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            CONFIGURATION_FILE_MODE,
        )
        .map_err(|_| configuration_error("configuration setup lock is unavailable"))?;
        validate_file_descriptor(&file, owner_user_id, false, MAXIMUM_TRANSACTION_BYTES)?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(configuration_error(
                "configuration setup lock could not be acquired",
            ));
        }
        let mut directories = self
            .locked_directories
            .lock()
            .map_err(|_| configuration_error("configuration setup lock state is unavailable"))?;
        if directories.contains_key(&directory_path) {
            return Err(configuration_error(
                "configuration setup lock state is divergent",
            ));
        }
        directories.insert(directory_path.clone(), Arc::clone(&directory));
        drop(directories);
        Ok(Box::new(SystemCoreSetupConfigurationLock {
            file,
            directory_path,
            directory,
            locked_directories: Arc::clone(&self.locked_directories),
        }))
    }

    // Reads and revalidates one bounded descriptor without following symbolic links.
    fn read_no_follow(
        &self,
        path: &Path,
        maximum_bytes: usize,
    ) -> Result<Option<CoreSetupConfigurationFile>, CoreSetupConfigurationError> {
        let (directory, filename) = self.locked_parent_and_filename(path)?;
        let mut file = match open_file_at(
            &directory.file,
            &filename,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0,
        ) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => {
                return Err(configuration_error(
                    "configuration path could not be opened safely",
                ))
            }
        };
        let before = file
            .metadata()
            .map_err(|_| configuration_error("configuration metadata is unavailable"))?;
        if !before.file_type().is_file() {
            return Ok(Some(configuration_file(&before, false, Vec::new())));
        }
        if before.len() > maximum_bytes as u64 {
            return Err(configuration_error("configuration file is oversized"));
        }
        let mut bytes = Vec::with_capacity(before.len() as usize);
        Read::by_ref(&mut file)
            .take(maximum_bytes as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| configuration_error("configuration file could not be read"))?;
        if bytes.len() > maximum_bytes {
            return Err(configuration_error("configuration file is oversized"));
        }
        let after = file
            .metadata()
            .map_err(|_| configuration_error("configuration metadata is unavailable"))?;
        let stable = same_file(&before, &after) && after.len() == bytes.len() as u64;
        Ok(Some(configuration_file(&after, stable, bytes)))
    }

    // Creates, writes, synchronizes, and revalidates one owner-only temporary file.
    fn stage(
        &self,
        path: &Path,
        bytes: &[u8],
        owner_user_id: u32,
    ) -> Result<(), CoreSetupConfigurationError> {
        let (directory, filename) = self.locked_parent_and_filename(path)?;
        let mut file = open_file_at(
            &directory.file,
            &filename,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            CONFIGURATION_FILE_MODE,
        )
        .map_err(|_| configuration_error("configuration could not be staged"))?;
        let result = file
            .write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| configuration_error("configuration staging could not be persisted"))
            .and_then(|_| {
                validate_file_descriptor(&file, owner_user_id, true, MAXIMUM_TRANSACTION_BYTES)
            });
        if result.is_err() {
            let _ = self.remove_file_at_locked_parent(path);
        }
        result
    }

    // Renames one synchronized same-directory temporary file into authoritative state.
    fn activate(
        &self,
        source: &Path,
        destination: &Path,
    ) -> Result<(), CoreSetupConfigurationError> {
        let (source_directory, source_name) = self.locked_parent_and_filename(source)?;
        let (destination_directory, destination_name) =
            self.locked_parent_and_filename(destination)?;
        if !Arc::ptr_eq(&source_directory, &destination_directory) {
            return Err(configuration_error(
                "configuration activation directory is invalid",
            ));
        }
        activate_no_replace_at(&source_directory.file, &source_name, &destination_name)
    }

    // Reopens and verifies one descriptor immediately before descriptor-anchored unlink.
    fn remove_exact(
        &self,
        path: &Path,
        expected: &[u8],
        owner_user_id: u32,
    ) -> Result<(), CoreSetupConfigurationError> {
        let file = self
            .read_no_follow(path, expected.len().max(1))?
            .ok_or_else(|| configuration_recovery("configuration rollback state is incomplete"))?;
        require_exact_file(&file, owner_user_id, expected)?;
        self.remove_file_at_locked_parent(path)
    }

    // Persists one already-validated private configuration directory.
    fn sync_directory(&self, path: &Path) -> Result<(), CoreSetupConfigurationError> {
        self.locked_directory(path)?
            .file
            .sync_all()
            .map_err(|_| configuration_error("configuration directory could not be persisted"))
    }
}

impl SystemCoreSetupConfigurationIo {
    // Returns the exact retained directory descriptor for one active fixed lock.
    fn locked_directory(
        &self,
        directory: &Path,
    ) -> Result<Arc<LockedConfigurationDirectory>, CoreSetupConfigurationError> {
        let directory = self
            .locked_directories
            .lock()
            .map_err(|_| configuration_error("configuration setup lock state is unavailable"))?
            .get(directory)
            .cloned()
            .ok_or_else(|| configuration_error("configuration setup lock is not retained"))?;
        validate_retained_configuration_directory(&directory.file, directory.owner_user_id)?;
        Ok(directory)
    }

    // Resolves one contained filename against the exact retained transaction directory.
    fn locked_parent_and_filename(
        &self,
        path: &Path,
    ) -> Result<(Arc<LockedConfigurationDirectory>, String), CoreSetupConfigurationError> {
        if !is_normal_absolute_path(path) || path == Path::new("/") {
            return Err(configuration_error("configuration path is invalid"));
        }
        let parent = path
            .parent()
            .ok_or_else(|| configuration_error("configuration path is invalid"))?;
        let filename = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| configuration_error("configuration filename is invalid"))?;
        contained_name(filename)?;
        Ok((self.locked_directory(parent)?, filename.to_owned()))
    }

    // Removes one contained filename relative to the exact retained transaction directory.
    fn remove_file_at_locked_parent(&self, path: &Path) -> Result<(), CoreSetupConfigurationError> {
        let (directory, filename) = self.locked_parent_and_filename(path)?;
        let filename = contained_name(&filename)?;
        if unsafe { libc::unlinkat(directory.file.as_raw_fd(), filename.as_ptr(), 0) } != 0 {
            return Err(configuration_recovery(
                "configuration file could not be removed exactly",
            ));
        }
        Ok(())
    }
}

// Owns deterministic generation, exact replay judgment, and crash-safe file activation.
pub struct CoreSetupConfigurationInstaller {
    io: Arc<dyn CoreSetupConfigurationIo>,
}

impl Default for CoreSetupConfigurationInstaller {
    // Creates one production installer using native owner-bound filesystem operations.
    fn default() -> Self {
        Self::new()
    }
}

impl CoreSetupConfigurationInstaller {
    // Creates one production configuration installer.
    pub fn new() -> Self {
        Self {
            io: Arc::new(SystemCoreSetupConfigurationIo::default()),
        }
    }

    // Creates one installer with explicit deterministic filesystem boundaries.
    pub fn with_io(io: Arc<dyn CoreSetupConfigurationIo>) -> Self {
        Self { io }
    }

    // Generates, validates, and installs one complete set behind a durable ownership intent.
    pub fn install(
        &self,
        input: &CoreSetupConfigurationInput,
        binding: &CoreSetupConfigurationBinding,
    ) -> Result<CoreSetupConfigurationInstallation, CoreSetupConfigurationError> {
        validate_configuration_input(input)?;
        let documents = generated_configurations(input)?;
        validate_generated_configurations(input, &documents)?;
        validate_provisioned_material(input, binding)?;
        let _lock = self
            .io
            .acquire_lock(&input.configuration_directory, input.owner_user_id)?;

        if self
            .io
            .read_no_follow(
                &input.configuration_directory.join(SETUP_ROLLBACK_FILENAME),
                MAXIMUM_TRANSACTION_BYTES,
            )?
            .is_some()
            || self
                .io
                .read_no_follow(
                    &input
                        .configuration_directory
                        .join(SETUP_ROLLBACK_PENDING_FILENAME),
                    MAXIMUM_TRANSACTION_BYTES,
                )?
                .is_some()
        {
            return Err(configuration_recovery(
                "configuration rollback is incomplete",
            ));
        }

        let intent = self.load_or_create_intent(input, binding, &documents)?;
        let receipt = receipt_document(&intent)?;
        let receipt_bytes = encode_document(&receipt)?;
        let receipt_path = input.configuration_directory.join(SETUP_RECEIPT_FILENAME);
        let receipt_observation = self
            .io
            .read_no_follow(&receipt_path, MAXIMUM_TRANSACTION_BYTES)?;
        if let Some(file) = &receipt_observation {
            require_exact_file(file, input.owner_user_id, &receipt_bytes)
                .map_err(|_| configuration_recovery("configuration receipt is divergent"))?;
        }
        let receipt_was_present = receipt_observation.is_some();
        self.preflight_intent_state(input, &intent, &documents, receipt_was_present)?;

        for document in &intent.documents {
            self.reconcile_document(input, document, &documents)
                .map_err(configuration_after_intent)?;
        }
        self.reconcile_publication(
            input,
            SETUP_RECEIPT_PENDING_FILENAME,
            SETUP_RECEIPT_FILENAME,
            &receipt_bytes,
            MAXIMUM_TRANSACTION_BYTES,
        )
        .map_err(configuration_after_intent)?;
        self.io
            .sync_directory(&input.configuration_directory)
            .map_err(configuration_after_intent)?;
        Ok(CoreSetupConfigurationInstallation {
            status: if receipt_was_present {
                CoreSetupConfigurationInstallStatus::Replayed
            } else {
                CoreSetupConfigurationInstallStatus::Installed
            },
            files: documents
                .iter()
                .map(|document| input.configuration_directory.join(document.filename))
                .collect(),
            receipt_identity: Sha256Digest::parse(&intent.transaction_identity).map_err(|_| {
                configuration_recovery("configuration transaction identity is corrupt")
            })?,
        })
    }

    // Removes only the exact files marked setup-owned by the durable transaction intent.
    pub fn rollback(
        &self,
        configuration_directory: &Path,
        owner_user_id: u32,
        provider_identity: &Sha256Digest,
        receipt_identity: &Sha256Digest,
    ) -> Result<(), CoreSetupConfigurationError> {
        let _lock = self
            .io
            .acquire_lock(configuration_directory, owner_user_id)?;
        let intent_path = configuration_directory.join(SETUP_INTENT_FILENAME);
        let rollback_path = configuration_directory.join(SETUP_ROLLBACK_FILENAME);
        let (intent, rollback_was_present) = match self
            .io
            .read_no_follow(&rollback_path, MAXIMUM_TRANSACTION_BYTES)?
        {
            Some(file) => {
                let rollback: ConfigurationRollbackDocument =
                    decode_exact_file(&file, owner_user_id, MAXIMUM_TRANSACTION_BYTES)?;
                (rollback.intent, true)
            }
            None => match self
                .io
                .read_no_follow(&intent_path, MAXIMUM_TRANSACTION_BYTES)?
            {
                Some(file) => (
                    decode_exact_file(&file, owner_user_id, MAXIMUM_TRANSACTION_BYTES)?,
                    false,
                ),
                None => {
                    self.remove_pending_intent_if_present(
                        configuration_directory,
                        owner_user_id,
                        provider_identity,
                        receipt_identity,
                    )?;
                    return Ok(());
                }
            },
        };
        validate_rollback_identity(&intent, provider_identity, receipt_identity)?;
        let rollback = ConfigurationRollbackDocument {
            schema: ConfigurationSchemaDocument::rollback(),
            intent: intent.clone(),
        };
        let rollback_bytes = encode_document(&rollback)?;
        self.reconcile_publication_at(
            configuration_directory,
            owner_user_id,
            SETUP_ROLLBACK_PENDING_FILENAME,
            SETUP_ROLLBACK_FILENAME,
            &rollback_bytes,
            MAXIMUM_TRANSACTION_BYTES,
        )?;
        self.preflight_rollback(
            configuration_directory,
            owner_user_id,
            &intent,
            rollback_was_present,
        )?;

        self.remove_transaction_file_if_present(
            configuration_directory,
            owner_user_id,
            SETUP_RECEIPT_FILENAME,
            &encode_document(&receipt_document(&intent)?)?,
        )?;
        self.remove_transaction_file_if_present(
            configuration_directory,
            owner_user_id,
            SETUP_RECEIPT_PENDING_FILENAME,
            &encode_document(&receipt_document(&intent)?)?,
        )?;
        for document in intent.documents.iter().rev() {
            if document.owned {
                self.remove_owned_document_if_present(
                    configuration_directory,
                    owner_user_id,
                    document,
                )?;
            }
        }
        let intent_bytes = encode_document(&intent)?;
        self.remove_transaction_file_if_present(
            configuration_directory,
            owner_user_id,
            SETUP_INTENT_PENDING_FILENAME,
            &intent_bytes,
        )?;
        self.remove_transaction_file_if_present(
            configuration_directory,
            owner_user_id,
            SETUP_INTENT_FILENAME,
            &intent_bytes,
        )?;
        self.io.sync_directory(configuration_directory)?;
        self.remove_transaction_file_if_present(
            configuration_directory,
            owner_user_id,
            SETUP_ROLLBACK_FILENAME,
            &rollback_bytes,
        )?;
        self.io.sync_directory(configuration_directory)
    }

    // Loads exact durable intent or creates it after complete no-mutation preflight.
    fn load_or_create_intent(
        &self,
        input: &CoreSetupConfigurationInput,
        binding: &CoreSetupConfigurationBinding,
        documents: &[GeneratedConfiguration],
    ) -> Result<ConfigurationIntentDocument, CoreSetupConfigurationError> {
        let intent_path = input.configuration_directory.join(SETUP_INTENT_FILENAME);
        if let Some(file) = self
            .io
            .read_no_follow(&intent_path, MAXIMUM_TRANSACTION_BYTES)?
        {
            let intent = decode_exact_file(&file, input.owner_user_id, MAXIMUM_TRANSACTION_BYTES)?;
            validate_intent(input, binding, documents, &intent)?;
            self.reconcile_stale_pending(
                input,
                SETUP_INTENT_PENDING_FILENAME,
                &encode_document(&intent)?,
                MAXIMUM_TRANSACTION_BYTES,
            )
            .map_err(configuration_after_intent)?;
            return Ok(intent);
        }

        let pending_path = input
            .configuration_directory
            .join(SETUP_INTENT_PENDING_FILENAME);
        if let Some(file) = self
            .io
            .read_no_follow(&pending_path, MAXIMUM_TRANSACTION_BYTES)?
        {
            let intent = decode_exact_file(&file, input.owner_user_id, MAXIMUM_TRANSACTION_BYTES)?;
            validate_intent(input, binding, documents, &intent)?;
            self.publish_pending(
                input,
                SETUP_INTENT_PENDING_FILENAME,
                SETUP_INTENT_FILENAME,
                &encode_document(&intent)?,
                MAXIMUM_TRANSACTION_BYTES,
            )
            .map_err(configuration_after_intent)?;
            return Ok(intent);
        }

        let intent = create_intent(input, binding, documents, self.io.as_ref())?;
        let bytes = encode_document(&intent)?;
        self.io.stage(&pending_path, &bytes, input.owner_user_id)?;
        self.io
            .sync_directory(&input.configuration_directory)
            .map_err(configuration_after_intent)?;
        self.publish_pending(
            input,
            SETUP_INTENT_PENDING_FILENAME,
            SETUP_INTENT_FILENAME,
            &bytes,
            MAXIMUM_TRANSACTION_BYTES,
        )
        .map_err(configuration_after_intent)?;
        Ok(intent)
    }

    // Preflights every persisted document before resuming any incomplete transaction mutation.
    fn preflight_intent_state(
        &self,
        input: &CoreSetupConfigurationInput,
        intent: &ConfigurationIntentDocument,
        generated: &[GeneratedConfiguration],
        receipt_is_durable: bool,
    ) -> Result<(), CoreSetupConfigurationError> {
        for persisted in &intent.documents {
            let desired = generated
                .iter()
                .find(|document| document.filename == persisted.filename)
                .ok_or_else(|| configuration_recovery("configuration intent is divergent"))?;
            let destination = input.configuration_directory.join(&persisted.filename);
            let pending = input
                .configuration_directory
                .join(pending_configuration_filename(&persisted.filename)?);
            let authoritative = self
                .io
                .read_no_follow(&destination, MAXIMUM_CONFIGURATION_BYTES)?;
            let pending = self
                .io
                .read_no_follow(&pending, MAXIMUM_CONFIGURATION_BYTES)?;
            if let Some(file) = &authoritative {
                require_exact_file(file, input.owner_user_id, &desired.bytes).map_err(|_| {
                    configuration_recovery("configuration replay state is divergent")
                })?;
            }
            if let Some(file) = &pending {
                require_exact_file(file, input.owner_user_id, &desired.bytes).map_err(|_| {
                    configuration_recovery("configuration pending replay state is divergent")
                })?;
            }
            if (!persisted.owned && authoritative.is_none())
                || (!persisted.owned && pending.is_some())
                || (receipt_is_durable && authoritative.is_none())
                || (receipt_is_durable && pending.is_some())
            {
                return Err(configuration_recovery(
                    "configuration replay state is incomplete",
                ));
            }
        }
        Ok(())
    }

    // Reconciles one owned or pre-existing document against the durable ownership decision.
    fn reconcile_document(
        &self,
        input: &CoreSetupConfigurationInput,
        intent: &ConfigurationIntentFileDocument,
        generated: &[GeneratedConfiguration],
    ) -> Result<(), CoreSetupConfigurationError> {
        let document = generated
            .iter()
            .find(|document| document.filename == intent.filename)
            .ok_or_else(|| configuration_recovery("configuration intent is divergent"))?;
        let destination = input.configuration_directory.join(&intent.filename);
        let pending_name = pending_configuration_filename(&intent.filename)?;
        let pending = input.configuration_directory.join(&pending_name);
        let observed = self
            .io
            .read_no_follow(&destination, MAXIMUM_CONFIGURATION_BYTES)?;
        if !intent.owned {
            let file = observed.ok_or_else(|| {
                configuration_recovery("pre-existing configuration state is missing")
            })?;
            require_exact_file(&file, input.owner_user_id, &document.bytes)
                .map_err(|_| configuration_recovery("pre-existing configuration state drifted"))?;
            if self
                .io
                .read_no_follow(&pending, MAXIMUM_CONFIGURATION_BYTES)?
                .is_some()
            {
                return Err(configuration_recovery(
                    "pre-existing configuration has ambiguous pending state",
                ));
            }
            return Ok(());
        }

        if let Some(file) = observed {
            require_exact_file(&file, input.owner_user_id, &document.bytes)
                .map_err(|_| configuration_recovery("setup-owned configuration state drifted"))?;
            self.reconcile_stale_pending(
                input,
                &pending_name,
                &document.bytes,
                MAXIMUM_CONFIGURATION_BYTES,
            )?;
            return Ok(());
        }
        self.reconcile_publication(
            input,
            &pending_name,
            &intent.filename,
            &document.bytes,
            MAXIMUM_CONFIGURATION_BYTES,
        )
    }

    // Stages or reuses exact bytes and reconciles an ambiguous no-replace activation.
    fn reconcile_publication(
        &self,
        input: &CoreSetupConfigurationInput,
        pending_name: &str,
        destination_name: &str,
        bytes: &[u8],
        maximum_bytes: usize,
    ) -> Result<(), CoreSetupConfigurationError> {
        self.reconcile_publication_at(
            &input.configuration_directory,
            input.owner_user_id,
            pending_name,
            destination_name,
            bytes,
            maximum_bytes,
        )
    }

    // Performs one same-directory publication using an explicit fixed transaction location.
    fn reconcile_publication_at(
        &self,
        directory: &Path,
        owner_user_id: u32,
        pending_name: &str,
        destination_name: &str,
        bytes: &[u8],
        maximum_bytes: usize,
    ) -> Result<(), CoreSetupConfigurationError> {
        let pending = directory.join(pending_name);
        let destination = directory.join(destination_name);
        if let Some(file) = self.io.read_no_follow(&destination, maximum_bytes)? {
            require_exact_file(&file, owner_user_id, bytes)
                .map_err(|_| configuration_recovery("configuration publication is divergent"))?;
            if let Some(file) = self.io.read_no_follow(&pending, maximum_bytes)? {
                require_exact_file(&file, owner_user_id, bytes).map_err(|_| {
                    configuration_recovery("configuration pending publication is divergent")
                })?;
                self.io.remove_exact(&pending, bytes, owner_user_id)?;
                self.io.sync_directory(directory)?;
            }
            return Ok(());
        }
        if let Some(file) = self.io.read_no_follow(&pending, maximum_bytes)? {
            require_exact_file(&file, owner_user_id, bytes).map_err(|_| {
                configuration_recovery("configuration pending publication is divergent")
            })?;
        } else {
            self.io.stage(&pending, bytes, owner_user_id)?;
            self.io.sync_directory(directory)?;
        }
        self.publish_pending_at(
            directory,
            owner_user_id,
            pending_name,
            destination_name,
            bytes,
            maximum_bytes,
        )
    }

    // Publishes one already-staged file and judges an activation error from visible exact state.
    fn publish_pending(
        &self,
        input: &CoreSetupConfigurationInput,
        pending_name: &str,
        destination_name: &str,
        bytes: &[u8],
        maximum_bytes: usize,
    ) -> Result<(), CoreSetupConfigurationError> {
        self.publish_pending_at(
            &input.configuration_directory,
            input.owner_user_id,
            pending_name,
            destination_name,
            bytes,
            maximum_bytes,
        )
    }

    // Reconciles one ambiguous activation against exact authoritative and pending observations.
    fn publish_pending_at(
        &self,
        directory: &Path,
        owner_user_id: u32,
        pending_name: &str,
        destination_name: &str,
        bytes: &[u8],
        maximum_bytes: usize,
    ) -> Result<(), CoreSetupConfigurationError> {
        let pending = directory.join(pending_name);
        let destination = directory.join(destination_name);
        let activation = self.io.activate(&pending, &destination);
        match self.io.read_no_follow(&destination, maximum_bytes)? {
            Some(file) => {
                require_exact_file(&file, owner_user_id, bytes).map_err(|_| {
                    configuration_recovery("configuration activation published divergent state")
                })?;
                if let Some(file) = self.io.read_no_follow(&pending, maximum_bytes)? {
                    require_exact_file(&file, owner_user_id, bytes).map_err(|_| {
                        configuration_recovery("configuration activation is ambiguous")
                    })?;
                    self.io.remove_exact(&pending, bytes, owner_user_id)?;
                }
                self.io.sync_directory(directory)
            }
            None => Err(match activation {
                Ok(()) => configuration_recovery("configuration activation did not become visible"),
                Err(_) => configuration_recovery("configuration activation is incomplete"),
            }),
        }
    }

    // Removes one exact stale pending file after its authoritative counterpart is proven.
    fn reconcile_stale_pending(
        &self,
        input: &CoreSetupConfigurationInput,
        pending_name: &str,
        expected: &[u8],
        maximum_bytes: usize,
    ) -> Result<(), CoreSetupConfigurationError> {
        let pending = input.configuration_directory.join(pending_name);
        if let Some(file) = self.io.read_no_follow(&pending, maximum_bytes)? {
            require_exact_file(&file, input.owner_user_id, expected)
                .map_err(|_| configuration_recovery("configuration pending state is divergent"))?;
            self.io
                .remove_exact(&pending, expected, input.owner_user_id)?;
            self.io.sync_directory(&input.configuration_directory)?;
        }
        Ok(())
    }

    // Removes one exact setup-owned authoritative and pending document when each is present.
    fn remove_owned_document_if_present(
        &self,
        directory: &Path,
        owner_user_id: u32,
        document: &ConfigurationIntentFileDocument,
    ) -> Result<(), CoreSetupConfigurationError> {
        let bytes = document_bytes_from_intent(document)?;
        self.remove_transaction_file_if_present(
            directory,
            owner_user_id,
            document.filename.as_str(),
            &bytes,
        )?;
        self.remove_transaction_file_if_present(
            directory,
            owner_user_id,
            &pending_configuration_filename(&document.filename)?,
            &bytes,
        )
    }

    // Removes one exact transaction file and treats prior removal as idempotent recovery.
    fn remove_transaction_file_if_present(
        &self,
        directory: &Path,
        owner_user_id: u32,
        filename: &str,
        expected: &[u8],
    ) -> Result<(), CoreSetupConfigurationError> {
        let path = directory.join(filename);
        if let Some(file) = self.io.read_no_follow(&path, expected.len().max(1))? {
            require_exact_file(&file, owner_user_id, expected).map_err(|_| {
                configuration_recovery("configuration rollback encountered drifted state")
            })?;
            self.io.remove_exact(&path, expected, owner_user_id)?;
            self.io.sync_directory(directory)?;
        }
        Ok(())
    }

    // Retires only an exact unpublished intent when rollback follows intent staging failure.
    fn remove_pending_intent_if_present(
        &self,
        directory: &Path,
        owner_user_id: u32,
        provider_identity: &Sha256Digest,
        receipt_identity: &Sha256Digest,
    ) -> Result<(), CoreSetupConfigurationError> {
        let path = directory.join(SETUP_INTENT_PENDING_FILENAME);
        let Some(file) = self.io.read_no_follow(&path, MAXIMUM_TRANSACTION_BYTES)? else {
            return Ok(());
        };
        let intent: ConfigurationIntentDocument =
            decode_exact_file(&file, owner_user_id, MAXIMUM_TRANSACTION_BYTES)?;
        validate_rollback_identity(&intent, provider_identity, receipt_identity)?;
        self.io.remove_exact(&path, &file.bytes, owner_user_id)?;
        self.io.sync_directory(directory)
    }

    // Proves every setup-owned file and receipt exact before the first destructive rollback step.
    fn preflight_rollback(
        &self,
        directory: &Path,
        owner_user_id: u32,
        intent: &ConfigurationIntentDocument,
        allow_prior_removal: bool,
    ) -> Result<(), CoreSetupConfigurationError> {
        let intent_bytes = encode_document(intent)?;
        let intent_file = self.io.read_no_follow(
            &directory.join(SETUP_INTENT_FILENAME),
            MAXIMUM_TRANSACTION_BYTES,
        )?;
        match intent_file {
            Some(file) => {
                require_exact_file(&file, owner_user_id, &intent_bytes).map_err(|_| {
                    configuration_recovery("configuration rollback intent is divergent")
                })?
            }
            None if allow_prior_removal => {}
            None => {
                return Err(configuration_recovery(
                    "configuration rollback intent is missing",
                ))
            }
        }
        let receipt = encode_document(&receipt_document(intent)?)?;
        let receipt_file = self.io.read_no_follow(
            &directory.join(SETUP_RECEIPT_FILENAME),
            MAXIMUM_TRANSACTION_BYTES,
        )?;
        match receipt_file {
            Some(file) => require_exact_file(&file, owner_user_id, &receipt).map_err(|_| {
                configuration_recovery("configuration rollback receipt is divergent")
            })?,
            None if allow_prior_removal => {}
            None => {
                return Err(configuration_recovery(
                    "configuration rollback receipt is missing",
                ))
            }
        }
        for document in &intent.documents {
            if !document.owned {
                continue;
            }
            let expected = document_bytes_from_intent(document)?;
            let file = self.io.read_no_follow(
                &directory.join(&document.filename),
                MAXIMUM_CONFIGURATION_BYTES,
            )?;
            match file {
                Some(file) => {
                    require_exact_file(&file, owner_user_id, &expected).map_err(|_| {
                        configuration_recovery("setup-owned configuration state drifted")
                    })?
                }
                None if allow_prior_removal => {}
                None => {
                    return Err(configuration_recovery(
                        "setup-owned configuration state is missing",
                    ))
                }
            }
        }
        Ok(())
    }
}

// Carries one deterministic document and its fixed authoritative filename.
struct GeneratedConfiguration {
    filename: &'static str,
    bytes: Vec<u8>,
}

// Stores the stable schema identity of the owner-local CLI document.
#[derive(Serialize)]
struct CoreCliConfigurationSchemaDocument {
    name: String,
    version: u32,
}

// Stores the complete bounded private Node client contract.
#[derive(Serialize)]
struct CoreCliClientConfigurationDocument {
    timeout_milliseconds: u64,
    maximum_response_bytes: usize,
}

// Stores the minimal stable configuration consumed by the public native CLI process.
#[derive(Serialize)]
struct CoreCliConfigurationDocument {
    schema: CoreCliConfigurationSchemaDocument,
    local_node_socket: String,
    entropy_source: String,
    client: CoreCliClientConfigurationDocument,
    pairing: CoreCliPairingConfigurationDocument,
    uninstall: CoreCliUninstallConfigurationDocument,
    remote_main: Option<CoreCliRemoteMainConfigurationDocument>,
}

// Stores the exact installed launcher and optional shell-free privilege executable.
#[derive(Serialize)]
struct CoreCliUninstallConfigurationDocument {
    launcher_file: String,
    privilege_command: Option<String>,
}

// Stores the exact Node configuration, installation, and optional Watchdog pairing authorities.
#[derive(Serialize)]
struct CoreCliPairingConfigurationDocument {
    node_configuration_file: String,
    installation: CoreCliInstallationDocument,
    watchdog_health: Option<CoreCliWatchdogHealthDocument>,
}

// Stores the immutable Core installation used during pairing service-role cutover.
#[derive(Serialize)]
struct CoreCliInstallationDocument {
    version: String,
    source_identity: String,
}

// Stores Linux Watchdog health trust references without credential bytes.
#[derive(Serialize)]
struct CoreCliWatchdogHealthDocument {
    authority_certificate_file: String,
    controller_certificate_file: String,
    controller_private_key_file: String,
}

// Stores one role-dependent paired-main endpoint without retaining private key bytes.
#[derive(Serialize)]
struct CoreCliRemoteMainConfigurationDocument {
    address: String,
    port: u16,
    server_certificate_sha256: String,
    client_certificate_file: String,
    client_private_key_file: String,
}

// Identifies one closed durable configuration transaction document.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ConfigurationSchemaDocument {
    name: String,
    version: u32,
}

impl ConfigurationSchemaDocument {
    // Returns the schema identity for the ownership intent written before configuration files.
    fn intent() -> Self {
        Self {
            name: "li_core_setup_configuration_intent".to_owned(),
            version: 1,
        }
    }

    // Returns the schema identity for the complete-set durable receipt.
    fn receipt() -> Self {
        Self {
            name: "li_core_setup_configuration_receipt".to_owned(),
            version: 1,
        }
    }

    // Returns the schema identity for a durable reverse-order rollback marker.
    fn rollback() -> Self {
        Self {
            name: "li_core_setup_configuration_rollback".to_owned(),
            version: 1,
        }
    }
}

// Records one exact authoritative document and whether setup owns its lifecycle.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ConfigurationIntentFileDocument {
    filename: String,
    sha256: String,
    contents_base64: String,
    owned: bool,
}

// Persists the complete content, platform, role, provider, and rollback ownership decision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ConfigurationIntentDocument {
    schema: ConfigurationSchemaDocument,
    transaction_identity: String,
    provider_identity: String,
    request_identity: String,
    identity_receipt_identity: String,
    material_receipt_identity: String,
    material_identity: String,
    platform: String,
    role: String,
    configuration_directory: String,
    owner_user_id: u32,
    documents: Vec<ConfigurationIntentFileDocument>,
}

// Proves that the complete intent-owned document set became durable.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ConfigurationReceiptDocument {
    schema: ConfigurationSchemaDocument,
    transaction_identity: String,
    intent_sha256: String,
}

// Retains the complete ownership closure until reverse rollback finishes durably.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ConfigurationRollbackDocument {
    schema: ConfigurationSchemaDocument,
    intent: ConfigurationIntentDocument,
}

// Creates one intent only after preflighting every final and pending file without mutation.
fn create_intent(
    input: &CoreSetupConfigurationInput,
    binding: &CoreSetupConfigurationBinding,
    generated: &[GeneratedConfiguration],
    io: &dyn CoreSetupConfigurationIo,
) -> Result<ConfigurationIntentDocument, CoreSetupConfigurationError> {
    for filename in [
        SETUP_RECEIPT_FILENAME,
        SETUP_RECEIPT_PENDING_FILENAME,
        SETUP_ROLLBACK_FILENAME,
        SETUP_ROLLBACK_PENDING_FILENAME,
    ] {
        if io
            .read_no_follow(
                &input.configuration_directory.join(filename),
                MAXIMUM_TRANSACTION_BYTES,
            )?
            .is_some()
        {
            return Err(configuration_recovery(
                "configuration transaction state exists without its intent",
            ));
        }
    }
    let mut documents = Vec::with_capacity(generated.len());
    for document in generated {
        let destination = input.configuration_directory.join(document.filename);
        let pending = input
            .configuration_directory
            .join(pending_configuration_filename(document.filename)?);
        if io
            .read_no_follow(&pending, MAXIMUM_CONFIGURATION_BYTES)?
            .is_some()
        {
            return Err(configuration_recovery(
                "configuration pending state exists without its intent",
            ));
        }
        let owned = match io.read_no_follow(&destination, MAXIMUM_CONFIGURATION_BYTES)? {
            Some(file) => {
                require_exact_file(&file, input.owner_user_id, &document.bytes)?;
                false
            }
            None => true,
        };
        documents.push(ConfigurationIntentFileDocument {
            filename: document.filename.to_owned(),
            sha256: sha256(&document.bytes),
            contents_base64: BASE64.encode(&document.bytes),
            owned,
        });
    }
    let mut intent = ConfigurationIntentDocument {
        schema: ConfigurationSchemaDocument::intent(),
        transaction_identity: String::new(),
        provider_identity: binding.provider_identity.as_str().to_owned(),
        request_identity: binding.request_identity.as_str().to_owned(),
        identity_receipt_identity: binding.identity_receipt_identity.as_str().to_owned(),
        material_receipt_identity: binding.material_receipt_identity.as_str().to_owned(),
        material_identity: binding.material_identity.as_str().to_owned(),
        platform: platform_name(input.context.platform()).to_owned(),
        role: role_name(input.context.role()).to_owned(),
        configuration_directory: path_text(&input.configuration_directory)?,
        owner_user_id: input.owner_user_id,
        documents,
    };
    intent.transaction_identity = transaction_identity(&intent)?;
    Ok(intent)
}

// Requires one persisted intent to match every exact input, binding, byte, and ownership invariant.
fn validate_intent(
    input: &CoreSetupConfigurationInput,
    binding: &CoreSetupConfigurationBinding,
    generated: &[GeneratedConfiguration],
    intent: &ConfigurationIntentDocument,
) -> Result<(), CoreSetupConfigurationError> {
    if intent.schema != ConfigurationSchemaDocument::intent()
        || intent.provider_identity != binding.provider_identity.as_str()
        || intent.request_identity != binding.request_identity.as_str()
        || intent.identity_receipt_identity != binding.identity_receipt_identity.as_str()
        || intent.material_receipt_identity != binding.material_receipt_identity.as_str()
        || intent.material_identity != binding.material_identity.as_str()
        || intent.platform != platform_name(input.context.platform())
        || intent.role != role_name(input.context.role())
        || intent.configuration_directory != path_text(&input.configuration_directory)?
        || intent.owner_user_id != input.owner_user_id
        || intent.documents.len() != generated.len()
        || intent.transaction_identity != transaction_identity(intent)?
    {
        return Err(configuration_recovery(
            "configuration intent identity is divergent",
        ));
    }
    for (persisted, desired) in intent.documents.iter().zip(generated) {
        if persisted.filename != desired.filename
            || persisted.contents_base64 != BASE64.encode(&desired.bytes)
            || persisted.sha256 != sha256(&desired.bytes)
        {
            return Err(configuration_recovery(
                "configuration intent content is divergent",
            ));
        }
    }
    Ok(())
}

// Computes the transaction identity over the complete intent except its self-referential field.
fn transaction_identity(
    intent: &ConfigurationIntentDocument,
) -> Result<String, CoreSetupConfigurationError> {
    let mut projection = intent.clone();
    projection.transaction_identity.clear();
    Ok(sha256(&encode_document(&projection)?))
}

// Creates the complete-set receipt bound to the exact intent bytes.
fn receipt_document(
    intent: &ConfigurationIntentDocument,
) -> Result<ConfigurationReceiptDocument, CoreSetupConfigurationError> {
    Ok(ConfigurationReceiptDocument {
        schema: ConfigurationSchemaDocument::receipt(),
        transaction_identity: intent.transaction_identity.clone(),
        intent_sha256: sha256(&encode_document(intent)?),
    })
}

// Validates rollback authorization against both provider and opaque transaction identity.
fn validate_rollback_identity(
    intent: &ConfigurationIntentDocument,
    provider_identity: &Sha256Digest,
    receipt_identity: &Sha256Digest,
) -> Result<(), CoreSetupConfigurationError> {
    if intent.schema != ConfigurationSchemaDocument::intent()
        || intent.provider_identity != provider_identity.as_str()
        || intent.transaction_identity != receipt_identity.as_str()
        || intent.transaction_identity != transaction_identity(intent)?
    {
        return Err(configuration_recovery(
            "configuration rollback receipt is divergent",
        ));
    }
    Ok(())
}

// Decodes one safe bounded transaction document through its closed serde shape.
fn decode_exact_file<Value>(
    file: &CoreSetupConfigurationFile,
    owner_user_id: u32,
    maximum_bytes: usize,
) -> Result<Value, CoreSetupConfigurationError>
where
    Value: for<'de> Deserialize<'de> + Serialize,
{
    require_safe_file(file, owner_user_id, maximum_bytes)?;
    let value: Value = serde_json::from_slice(&file.bytes)
        .map_err(|_| configuration_recovery("configuration transaction document is corrupt"))?;
    if encode_document(&value)? != file.bytes {
        return Err(configuration_recovery(
            "configuration transaction document is noncanonical",
        ));
    }
    Ok(value)
}

// Returns and verifies the exact persisted document bytes required for owned rollback.
fn document_bytes_from_intent(
    document: &ConfigurationIntentFileDocument,
) -> Result<Vec<u8>, CoreSetupConfigurationError> {
    let bytes = BASE64.decode(&document.contents_base64).map_err(|_| {
        configuration_recovery("configuration rollback document identity is corrupt")
    })?;
    if bytes.is_empty()
        || bytes.len() > MAXIMUM_CONFIGURATION_BYTES
        || document.sha256 != sha256(&bytes)
    {
        return Err(configuration_recovery(
            "configuration rollback document identity is corrupt",
        ));
    }
    Ok(bytes)
}

// Returns the fixed pending filename for one closed resident configuration filename.
fn pending_configuration_filename(filename: &str) -> Result<String, CoreSetupConfigurationError> {
    if !matches!(
        filename,
        CORE_CLI_CONFIGURATION_FILENAME
            | NODE_CONFIGURATION_FILENAME
            | GATEWAY_CONFIGURATION_FILENAME
            | WATCHDOG_CONFIGURATION_FILENAME
    ) {
        return Err(configuration_recovery(
            "configuration intent filename is invalid",
        ));
    }
    Ok(format!(".{filename}.pending"))
}

// Generates the complete fixed-order document set only from the typed setup input.
fn generated_configurations(
    input: &CoreSetupConfigurationInput,
) -> Result<Vec<GeneratedConfiguration>, CoreSetupConfigurationError> {
    let mut documents = vec![
        GeneratedConfiguration {
            filename: CORE_CLI_CONFIGURATION_FILENAME,
            bytes: encode_document(&cli_document(input)?)?,
        },
        GeneratedConfiguration {
            filename: NODE_CONFIGURATION_FILENAME,
            bytes: encode_document(&node_document(input)?)?,
        },
        GeneratedConfiguration {
            filename: GATEWAY_CONFIGURATION_FILENAME,
            bytes: encode_document(&gateway_document(input)?)?,
        },
    ];
    if let Some(watchdog) = input.watchdog.as_ref() {
        documents.push(GeneratedConfiguration {
            filename: WATCHDOG_CONFIGURATION_FILENAME,
            bytes: encode_document(&watchdog_document(watchdog)?)?,
        });
    }
    Ok(documents)
}

// Validates platform, role, directory, and Linux-only Watchdog shape before generation.
fn validate_configuration_input(
    input: &CoreSetupConfigurationInput,
) -> Result<(), CoreSetupConfigurationError> {
    if !is_normal_absolute_path(&input.configuration_directory)
        || input.configuration_directory == Path::new("/")
    {
        return Err(configuration_error("configuration directory is invalid"));
    }
    let is_linux_hardware = matches!(
        input.node.hardware,
        CoreSetupNodeHardwareInput::Linux { .. }
    );
    match input.context.platform() {
        CoreUpdateServicePlatform::Linux
            if is_linux_hardware && input.watchdog.is_some() && input.node.benchmark.is_some() =>
        {
            let watchdog = input
                .watchdog
                .as_ref()
                .expect("validated Watchdog presence");
            let benchmark = input
                .node
                .benchmark
                .as_ref()
                .expect("validated benchmark presence");
            if input.gateway.node_id != watchdog.node_id
                || input.gateway.core_version != watchdog.core_version
                || input.gateway.core_source_identity != watchdog.core_source_identity
                || watchdog.listen_address.to_string() != benchmark.watchdog_host
                || watchdog.listen_port != benchmark.watchdog_port
                || watchdog.paths.controller_ca_path != benchmark.watchdog_ca_file
                || !matches!(
                    input.node.placement_safety,
                    CoreSetupNodePlacementSafetyInput::Linux { .. }
                )
            {
                return Err(configuration_error(
                    "resident identities do not match the Core installation",
                ));
            }
        }
        CoreUpdateServicePlatform::Macos
            if !is_linux_hardware
                && input.watchdog.is_none()
                && input.node.benchmark.is_none()
                && matches!(
                    input.node.placement_safety,
                    CoreSetupNodePlacementSafetyInput::MacosLaunchd
                ) => {}
        _ => {
            return Err(configuration_error(
                "configuration platform inputs do not match",
            ))
        }
    }
    match input.context.role() {
        CoreUpdateNodeRole::Main if input.gateway.public_listener.is_some() => {}
        CoreUpdateNodeRole::Child if input.gateway.public_listener.is_none() => {}
        _ => {
            return Err(configuration_error(
                "Gateway exposure does not match the node role",
            ))
        }
    }
    if input.gateway.health.socket_path == input.node.local_api.socket_path {
        return Err(configuration_error(
            "resident local socket identities are ambiguous",
        ));
    }
    if input.cli.local_node_socket != input.node.local_api.socket_path
        || input.gateway.node_socket_path != input.node.local_api.socket_path
    {
        return Err(configuration_error(
            "resident Node local socket identities are divergent",
        ));
    }
    if let CoreSetupNodePlacementSafetyInput::Linux {
        socket_path,
        protection_root,
        watchdog_source_identity,
        ..
    } = &input.node.placement_safety
    {
        let watchdog = input
            .watchdog
            .as_ref()
            .ok_or_else(|| configuration_error("Linux placement safety requires Watchdog"))?;
        if socket_path != &input.gateway.node_protection.socket_path
            || protection_root != &watchdog.paths.protection_root_path
            || watchdog_source_identity != &input.gateway.core_source_identity
            || [
                input.node.local_api.socket_path.as_path(),
                input.gateway.health.socket_path.as_path(),
            ]
            .contains(&socket_path.as_path())
        {
            return Err(configuration_error(
                "placement safety identities are divergent",
            ));
        }
    }
    Ok(())
}

// Requires every resident credential, secret, and database reference to be provisioned exactly.
fn validate_provisioned_material(
    input: &CoreSetupConfigurationInput,
    binding: &CoreSetupConfigurationBinding,
) -> Result<(), CoreSetupConfigurationError> {
    let mut referenced = BTreeSet::from([
        input.node.database_file.clone(),
        input.node.pairing_setup_secret_file.clone(),
        input.node.pairing.site_private_key_file.clone(),
        input.node.pairing.site_public_key_file.clone(),
        input.node.pairing.site_ca_certificate_file.clone(),
        input.node.pairing.local_control_certificate_file.clone(),
        input.node.remote_api.server_certificate_file.clone(),
        input.node.remote_api.server_private_key_file.clone(),
        input.node.remote_api.client_ca_file.clone(),
        input
            .gateway
            .private_listener
            .server_certificate_file
            .clone(),
        input
            .gateway
            .private_listener
            .server_private_key_file
            .clone(),
        input.gateway.private_listener.client_ca_file.clone(),
        input
            .gateway
            .private_listener
            .client_certificate_file
            .clone(),
    ]);
    if let Some(watchdog) = &input.watchdog {
        referenced.extend([
            watchdog.paths.node_database_path.clone(),
            watchdog.paths.server_certificate_path.clone(),
            watchdog.paths.server_private_key_path.clone(),
            watchdog.paths.controller_ca_path.clone(),
            watchdog.paths.controller_allowlist_path.clone(),
        ]);
    }
    if let Some(benchmark) = &input.node.benchmark {
        referenced.extend([
            benchmark.signing_private_key_file.clone(),
            benchmark.signing_public_key_file.clone(),
            benchmark.watchdog_ca_file.clone(),
            benchmark
                .watchdog_controller_authority_private_key_file
                .clone(),
            benchmark.watchdog_controller_allowlist_file.clone(),
            benchmark
                .watchdog_enrollment_server_certificate_file
                .clone(),
            benchmark
                .watchdog_enrollment_server_private_key_file
                .clone(),
            benchmark.watchdog_controller_certificate_file.clone(),
            benchmark.watchdog_controller_private_key_file.clone(),
        ]);
    }
    if referenced.iter().any(|path| {
        !is_normal_absolute_path(path)
            || path == Path::new("/")
            || !binding.provisioned_files.contains(path)
    }) {
        return Err(configuration_error(
            "configuration references unprovisioned private material",
        ));
    }
    Ok(())
}

// Requires every typed resident role to reference its matching prepared-material role.
pub(crate) fn validate_configuration_material_projection(
    input: &CoreSetupConfigurationInput,
    material: &CoreSetupPreparedMaterial,
) -> Result<(), CoreSetupConfigurationError> {
    let pairing = material.pairing_trust();
    let node = material.node_trust();
    let gateway = material.gateway_trust();
    let common_matches = input.node.database_file == material.database_file()
        && input.node.pairing_setup_secret_file == material.pairing_setup_secret_file()
        && input.node.pairing.site_private_key_file == pairing.site_private_key_file()
        && input.node.pairing.site_public_key_file == pairing.site_public_key_file()
        && input.node.pairing.site_ca_certificate_file == pairing.site_ca_certificate_file()
        && input.node.pairing.local_control_certificate_file
            == pairing.local_control_certificate_file()
        && input.node.pairing.public_key_sha256 == *pairing.public_key_sha256()
        && input.node.pairing.certificate_sha256 == *pairing.certificate_sha256()
        && input.node.remote_api.server_certificate_file == node.server_certificate_file()
        && input.node.remote_api.server_private_key_file == node.server_private_key_file()
        && input.node.remote_api.client_ca_file == node.authority_certificate_file()
        && input.gateway.private_listener.server_certificate_file
            == gateway.server_certificate_file()
        && input.gateway.private_listener.server_private_key_file
            == gateway.server_private_key_file()
        && input.gateway.private_listener.client_ca_file == gateway.authority_certificate_file()
        && input.gateway.private_listener.client_certificate_file
            == gateway.relay_client_certificate_file();
    let database_file = material.database_file();
    let watchdog_matches = match (&input.watchdog, material.watchdog_trust()) {
        (None, None) => true,
        (Some(input), Some(trust)) => {
            input.paths.node_database_path == database_file
                && input.paths.server_certificate_path == trust.server_certificate_file()
                && input.paths.server_private_key_path == trust.server_private_key_file()
                && input.paths.controller_ca_path == trust.authority_certificate_file()
                && input.paths.controller_allowlist_path == trust.controller_allowlist_file()
        }
        _ => false,
    };
    let benchmark_matches = match (&input.node.benchmark, material.benchmark_signing()) {
        (None, Some(_)) if material.watchdog_trust().is_none() => true,
        (Some(benchmark), Some(signing)) => {
            let Some(watchdog) = material.watchdog_trust() else {
                return Err(configuration_error(
                    "configuration private material roles are divergent",
                ));
            };
            let Some(watchdog_input) = input.watchdog.as_ref() else {
                return Err(configuration_error(
                    "configuration private material roles are divergent",
                ));
            };
            benchmark.signing_private_key_file == signing.private_key_file()
                && benchmark.signing_public_key_file == signing.public_key_file()
                && benchmark.watchdog_ca_file == watchdog.authority_certificate_file()
                && benchmark.watchdog_controller_authority_private_key_file
                    == watchdog.authority_private_key_file()
                && benchmark.watchdog_controller_allowlist_file
                    == watchdog.controller_allowlist_file()
                && benchmark.watchdog_controller_reload_receipt_file
                    == watchdog_input.paths.controller_snapshot_path
                && benchmark.watchdog_enrollment_server_certificate_file
                    == watchdog.server_certificate_file()
                && benchmark.watchdog_enrollment_server_private_key_file
                    == watchdog.server_private_key_file()
                && benchmark.watchdog_controller_certificate_file
                    == watchdog.controller_certificate_file()
                && benchmark.watchdog_controller_private_key_file
                    == watchdog.controller_private_key_file()
        }
        _ => false,
    };
    if !common_matches || !watchdog_matches || !benchmark_matches {
        return Err(configuration_error(
            "configuration private material roles are divergent",
        ));
    }
    Ok(())
}

// Validates generated bytes through each resident's existing strict parser before mutation.
fn validate_generated_configurations(
    input: &CoreSetupConfigurationInput,
    documents: &[GeneratedConfiguration],
) -> Result<(), CoreSetupConfigurationError> {
    let cli = document_bytes(documents, CORE_CLI_CONFIGURATION_FILENAME)?;
    let cli_path = input
        .configuration_directory
        .join(CORE_CLI_CONFIGURATION_FILENAME);
    CoreCliConfiguration::load(
        &cli_path,
        input.owner_user_id,
        &GeneratedCoreCliFileProvider {
            owner_user_id: input.owner_user_id,
            bytes: cli.to_vec(),
        },
    )
    .map_err(|_| configuration_error("generated CLI configuration is invalid"))?;

    let node = document_bytes(documents, NODE_CONFIGURATION_FILENAME)?;
    let node_reference = NodeConfigurationFileReference::new(
        input
            .configuration_directory
            .join(NODE_CONFIGURATION_FILENAME),
        input.owner_user_id,
    )
    .map_err(|_| configuration_error("generated Node configuration is invalid"))?;
    NodeConfiguration::load(
        &node_reference,
        &GeneratedNodeFileProvider {
            owner_user_id: input.owner_user_id,
            bytes: node.to_vec(),
        },
    )
    .map_err(|_| configuration_error("generated Node configuration is invalid"))?;

    let gateway = document_bytes(documents, GATEWAY_CONFIGURATION_FILENAME)?;
    let gateway_reference = GatewayConfigurationFile::new(
        input.owner_user_id,
        input
            .configuration_directory
            .join(GATEWAY_CONFIGURATION_FILENAME),
    )
    .map_err(|_| configuration_error("generated Gateway configuration is invalid"))?;
    GatewayConfiguration::load(
        &gateway_reference,
        &GeneratedGatewayFileIo {
            owner_user_id: input.owner_user_id,
            bytes: gateway.to_vec(),
        },
    )
    .map_err(|_| configuration_error("generated Gateway configuration is invalid"))?;

    match input.context.platform() {
        CoreUpdateServicePlatform::Linux => {
            WatchdogConfiguration::parse(document_bytes(
                documents,
                WATCHDOG_CONFIGURATION_FILENAME,
            )?)
            .map_err(|_| configuration_error("generated Watchdog configuration is invalid"))?;
        }
        CoreUpdateServicePlatform::Macos => {}
    }
    Ok(())
}

// Supplies one generated CLI document to its production parser without native mutation.
struct GeneratedCoreCliFileProvider {
    owner_user_id: u32,
    bytes: Vec<u8>,
}

impl CoreCliConfigurationFileProvider for GeneratedCoreCliFileProvider {
    // Returns the exact safe descriptor projection created by the setup transaction.
    fn read_no_follow(
        &self,
        _path: &Path,
        maximum_bytes: usize,
    ) -> Result<CoreCliConfigurationFile, CoreCliProcessError> {
        if maximum_bytes != MAXIMUM_CORE_CLI_CONFIGURATION_BYTES {
            return Err(CoreCliProcessError::ConfigurationUnavailable);
        }
        Ok(CoreCliConfigurationFile::new(
            self.owner_user_id,
            CONFIGURATION_FILE_MODE,
            1,
            true,
            self.bytes.clone(),
        ))
    }
}

// Converts the explicit CLI input into its minimal owner-local client document.
fn cli_document(
    input: &CoreSetupConfigurationInput,
) -> Result<CoreCliConfigurationDocument, CoreSetupConfigurationError> {
    let watchdog_health = input
        .node
        .benchmark
        .as_ref()
        .map(|benchmark| {
            Ok(CoreCliWatchdogHealthDocument {
                authority_certificate_file: path_text(&benchmark.watchdog_ca_file)?,
                controller_certificate_file: path_text(
                    &benchmark.watchdog_controller_certificate_file,
                )?,
                controller_private_key_file: path_text(
                    &benchmark.watchdog_controller_private_key_file,
                )?,
            })
        })
        .transpose()?;
    Ok(CoreCliConfigurationDocument {
        schema: CoreCliConfigurationSchemaDocument {
            name: CORE_CLI_CONFIGURATION_SCHEMA_NAME.to_owned(),
            version: CORE_CLI_CONFIGURATION_SCHEMA_VERSION,
        },
        local_node_socket: path_text(&input.cli.local_node_socket)?,
        entropy_source: path_text(&input.cli.entropy_source)?,
        client: CoreCliClientConfigurationDocument {
            timeout_milliseconds: input.cli.timeout_milliseconds,
            maximum_response_bytes: input.cli.maximum_response_bytes,
        },
        pairing: CoreCliPairingConfigurationDocument {
            node_configuration_file: path_text(
                &input
                    .configuration_directory
                    .join(NODE_CONFIGURATION_FILENAME),
            )?,
            installation: CoreCliInstallationDocument {
                version: input.gateway.core_version.to_string(),
                source_identity: input.gateway.core_source_identity.as_str().to_owned(),
            },
            watchdog_health,
        },
        uninstall: CoreCliUninstallConfigurationDocument {
            launcher_file: path_text(&input.cli.launcher_file)?,
            privilege_command: input
                .cli
                .privilege_command
                .as_ref()
                .map(|path| path_text(path))
                .transpose()?,
        },
        remote_main: None,
    })
}

// Returns one generated document by its fixed identity.
fn document_bytes<'a>(
    documents: &'a [GeneratedConfiguration],
    filename: &str,
) -> Result<&'a [u8], CoreSetupConfigurationError> {
    documents
        .iter()
        .find(|document| document.filename == filename)
        .map(|document| document.bytes.as_slice())
        .ok_or_else(|| configuration_error("generated configuration set is incomplete"))
}

// Encodes one schema document with stable field order, indentation, and trailing newline.
fn encode_document(document: &impl Serialize) -> Result<Vec<u8>, CoreSetupConfigurationError> {
    let mut bytes = serde_json::to_vec_pretty(document)
        .map_err(|_| configuration_error("configuration could not be encoded"))?;
    bytes.push(b'\n');
    if bytes.len() > MAXIMUM_CONFIGURATION_BYTES {
        return Err(configuration_error("generated configuration is oversized"));
    }
    Ok(bytes)
}

// Converts the explicit Node input into the closed schema-four field set.
fn node_document(
    input: &CoreSetupConfigurationInput,
) -> Result<NodeDocument, CoreSetupConfigurationError> {
    let hardware = match &input.node.hardware {
        CoreSetupNodeHardwareInput::Linux {
            architecture,
            boot_id_file,
            cpu_information_file,
            memory_information_file,
            nvidia_smi_command,
            rdma_command,
        } => NodeHardwareDocument::Linux {
            architecture: architecture_name(*architecture),
            boot_id_file: path_text(boot_id_file)?,
            cpu_information_file: path_text(cpu_information_file)?,
            memory_information_file: path_text(memory_information_file)?,
            nvidia_smi_command: optional_path_text(nvidia_smi_command.as_ref())?,
            rdma_command: optional_path_text(rdma_command.as_ref())?,
        },
        CoreSetupNodeHardwareInput::MacosArm64 {
            sysctl_command,
            metal_probe_command,
        } => NodeHardwareDocument::Macos {
            architecture: "arm64",
            sysctl_command: path_text(sysctl_command)?,
            metal_probe_command: path_text(metal_probe_command)?,
        },
    };
    Ok(NodeDocument {
        schema: SchemaDocument {
            name: "li_node_configuration",
            version: 4,
        },
        runtime: NodeRuntimeDocument {
            database_file: path_text(&input.node.database_file)?,
        },
        core_update: NodeCoreUpdateDocument {
            release_platform: input.node.core_update.release_platform.clone(),
            letsinfer_home: path_text(&input.node.core_update.letsinfer_home)?,
            home_directory: path_text(&input.node.core_update.home_directory)?,
            setup_state_directory: path_text(&input.node.core_update.setup_state_directory)?,
            configuration_root: path_text(&input.node.core_update.configuration_root)?,
            curl_command: path_text(&input.node.core_update.curl_command)?,
            ssh_keygen_command: path_text(&input.node.core_update.ssh_keygen_command)?,
            allowed_signers_file: path_text(&input.node.core_update.allowed_signers_file)?,
            supervisor_command: path_text(&input.node.core_update.supervisor_command)?,
            readiness_timeout_milliseconds: input.node.core_update.readiness_timeout_milliseconds,
            readiness_poll_milliseconds: input.node.core_update.readiness_poll_milliseconds,
            stable_readiness_observations: input.node.core_update.stable_readiness_observations,
        },
        model: NodeModelDocument {
            catalog_source: input.node.model.catalog_source.clone(),
            catalog_cache_root: path_text(&input.node.model.catalog_cache_root)?,
            catalog_hydration_root: path_text(&input.node.model.catalog_hydration_root)?,
            http_workspace_root: path_text(&input.node.model.http_workspace_root)?,
            installation_root: path_text(&input.node.model.installation_root)?,
            runtime_cache_root: path_text(&input.node.model.runtime_cache_root)?,
            curl_command: path_text(&input.node.model.curl_command)?,
            docker_command: path_text(&input.node.model.docker_command)?,
            command_working_directory: path_text(&input.node.model.command_working_directory)?,
            placement_material_root: path_text(&input.node.model.placement_material_root)?,
            placement_secret_root: path_text(&input.node.model.placement_secret_root)?,
            placement_tls_workspace_root: path_text(
                &input.node.model.placement_tls_workspace_root,
            )?,
            first_port: input.node.model.first_port,
            port_count: input.node.model.port_count,
            endpoint_timeout_milliseconds: input.node.model.endpoint_timeout_milliseconds,
            maximum_hardware_age_milliseconds: input.node.model.maximum_hardware_age_milliseconds,
            group_id: input.node.model.group_id,
            launch_agents_root: optional_path_text(input.node.model.launch_agents_root.as_ref())?,
            launchctl_command: optional_path_text(input.node.model.launchctl_command.as_ref())?,
        },
        benchmark: input
            .node
            .benchmark
            .as_ref()
            .map(node_benchmark_document)
            .transpose()?,
        pairing: node_pairing_document(&input.node)?,
        hardware,
        placement_safety: node_placement_safety_document(&input.node.placement_safety)?,
        daemon: NodeDaemonDocument {
            cadence_milliseconds: input.node.daemon_cadence_milliseconds,
        },
        private_api: NodePrivateApiDocument {
            local: NodeLocalApiDocument {
                socket_path: path_text(&input.node.local_api.socket_path)?,
                maximum_workers: input.node.local_api.maximum_workers,
                read_timeout_milliseconds: input.node.local_api.read_timeout_milliseconds,
                write_timeout_milliseconds: input.node.local_api.write_timeout_milliseconds,
                accept_poll_interval_milliseconds: input
                    .node
                    .local_api
                    .accept_poll_interval_milliseconds,
            },
            remote: NodeRemoteApiDocument {
                bind_address: input.node.remote_api.bind_address.to_string(),
                maximum_workers: input.node.remote_api.maximum_workers,
                accept_poll_interval_milliseconds: input
                    .node
                    .remote_api
                    .accept_poll_interval_milliseconds,
                handshake_timeout_milliseconds: input
                    .node
                    .remote_api
                    .handshake_timeout_milliseconds,
                read_timeout_milliseconds: input.node.remote_api.read_timeout_milliseconds,
                write_timeout_milliseconds: input.node.remote_api.write_timeout_milliseconds,
                server_certificate_file: path_text(&input.node.remote_api.server_certificate_file)?,
                server_private_key_file: path_text(&input.node.remote_api.server_private_key_file)?,
                client_ca_file: path_text(&input.node.remote_api.client_ca_file)?,
            },
        },
    })
}

// Projects one explicit Linux benchmark contract without inspecting files or native services.
fn node_benchmark_document(
    input: &CoreSetupNodeBenchmarkInput,
) -> Result<NodeBenchmarkDocument, CoreSetupConfigurationError> {
    Ok(NodeBenchmarkDocument {
        worker_executable: path_text(&input.worker_executable)?,
        github_cli_command: path_text(&input.github_cli_command)?,
        task_root: path_text(&input.task_root)?,
        telemetry_root: path_text(&input.telemetry_root)?,
        evidence_root: path_text(&input.evidence_root)?,
        signing_workspace_root: path_text(&input.signing_workspace_root)?,
        signing_private_key_file: path_text(&input.signing_private_key_file)?,
        signing_public_key_file: path_text(&input.signing_public_key_file)?,
        maximum_runtime_milliseconds: input.maximum_runtime_milliseconds,
        stop_grace_milliseconds: input.stop_grace_milliseconds,
        watchdog: NodeBenchmarkWatchdogDocument {
            host: input.watchdog_host.clone(),
            port: input.watchdog_port,
            server_name: input.watchdog_server_name.clone(),
            ca_file: path_text(&input.watchdog_ca_file)?,
            controller_authority_private_key_file: path_text(
                &input.watchdog_controller_authority_private_key_file,
            )?,
            controller_allowlist_file: path_text(&input.watchdog_controller_allowlist_file)?,
            controller_reload_receipt_file: path_text(
                &input.watchdog_controller_reload_receipt_file,
            )?,
            enrollment_server_certificate_file: path_text(
                &input.watchdog_enrollment_server_certificate_file,
            )?,
            enrollment_server_private_key_file: path_text(
                &input.watchdog_enrollment_server_private_key_file,
            )?,
            controller_certificate_file: path_text(&input.watchdog_controller_certificate_file)?,
            controller_private_key_file: path_text(&input.watchdog_controller_private_key_file)?,
            timeout_milliseconds: input.watchdog_timeout_milliseconds,
        },
    })
}

// Projects one platform-native placement-safety contract without a synthetic Watchdog on macOS.
fn node_placement_safety_document(
    input: &CoreSetupNodePlacementSafetyInput,
) -> Result<NodePlacementSafetyDocument, CoreSetupConfigurationError> {
    match input {
        CoreSetupNodePlacementSafetyInput::Linux {
            socket_path,
            maximum_workers,
            read_timeout_milliseconds,
            write_timeout_milliseconds,
            accept_poll_interval_milliseconds,
            protection_root,
            watchdog_source_identity,
            gateway,
            watchdog,
            lease_milliseconds,
        } => Ok(NodePlacementSafetyDocument::Linux {
            socket_path: path_text(socket_path)?,
            maximum_workers: *maximum_workers,
            read_timeout_milliseconds: *read_timeout_milliseconds,
            write_timeout_milliseconds: *write_timeout_milliseconds,
            accept_poll_interval_milliseconds: *accept_poll_interval_milliseconds,
            protection_root: path_text(protection_root)?,
            watchdog_source_identity: watchdog_source_identity.as_str().to_string(),
            gateway: node_protection_executable_document(gateway)?,
            watchdog: node_protection_executable_document(watchdog)?,
            lease_milliseconds: *lease_milliseconds,
        }),
        CoreSetupNodePlacementSafetyInput::MacosLaunchd => Ok(NodePlacementSafetyDocument::Macos),
    }
}

// Projects one immutable executable identity without exposing executable bytes.
fn node_protection_executable_document(
    input: &CoreSetupNodeProtectionExecutableInput,
) -> Result<NodeProtectionExecutableDocument, CoreSetupConfigurationError> {
    Ok(NodeProtectionExecutableDocument {
        path: path_text(&input.path)?,
        executable_sha256: input.executable_sha256.as_str().to_string(),
        principal_id: input.principal_id.as_str().to_string(),
    })
}

// Converts one required injected pairing input into its exact platform-closed document.
fn node_pairing_document(
    input: &CoreSetupNodeInput,
) -> Result<NodePairingDocument, CoreSetupConfigurationError> {
    let pairing = &input.pairing;
    let (operating_system, discovery_command, direct_link_sys_class, direct_link_ip_command) =
        match &pairing.platform {
            CoreSetupNodePairingPlatformInput::Linux {
                discovery_command,
                direct_link_sys_class,
                direct_link_ip_command,
            } => (
                "linux",
                path_text(discovery_command)?,
                Some(path_text(direct_link_sys_class)?),
                Some(path_text(direct_link_ip_command)?),
            ),
            CoreSetupNodePairingPlatformInput::Macos { discovery_command } => {
                ("macos", path_text(discovery_command)?, None, None)
            }
        };
    Ok(NodePairingDocument {
        setup_secret_file: path_text(&input.pairing_setup_secret_file)?,
        operating_system,
        discovery_command,
        openssl_command: path_text(&pairing.openssl_command)?,
        trust_workspace: path_text(&pairing.trust_workspace)?,
        site_private_key_file: path_text(&pairing.site_private_key_file)?,
        site_public_key_file: path_text(&pairing.site_public_key_file)?,
        site_ca_certificate_file: path_text(&pairing.site_ca_certificate_file)?,
        local_control_certificate_file: path_text(&pairing.local_control_certificate_file)?,
        public_key_sha256: pairing.public_key_sha256.as_str().to_string(),
        certificate_sha256: pairing.certificate_sha256.as_str().to_string(),
        direct_link_sys_class,
        direct_link_ip_command,
    })
}

// Converts the explicit role-bound Gateway input into the closed schema-four field set.
fn gateway_document(
    input: &CoreSetupConfigurationInput,
) -> Result<GatewayDocument<'_>, CoreSetupConfigurationError> {
    let listener = &input.gateway.private_listener.listener;
    let (node_protection, macos_placement_safety) = match &input.node.placement_safety {
        CoreSetupNodePlacementSafetyInput::Linux { .. } => (
            Some(GatewayNodeProtectionDocument {
                socket_path: path_text(&input.gateway.node_protection.socket_path)?,
                read_timeout_milliseconds: input.gateway.node_protection.read_timeout_milliseconds,
                write_timeout_milliseconds: input
                    .gateway
                    .node_protection
                    .write_timeout_milliseconds,
                maximum_cache_milliseconds: input
                    .gateway
                    .node_protection
                    .maximum_cache_milliseconds,
                poll_interval_milliseconds: input
                    .gateway
                    .node_protection
                    .poll_interval_milliseconds,
            }),
            None,
        ),
        CoreSetupNodePlacementSafetyInput::MacosLaunchd => (
            None,
            Some(GatewayMacOsPlacementSafetyDocument {
                placement_material_root: path_text(&input.node.model.placement_material_root)?,
                launch_agents_root: path_text(
                    input.node.model.launch_agents_root.as_ref().ok_or(
                        CoreSetupConfigurationError::provider(
                            "macOS Gateway safety launch-agent root is unavailable",
                        ),
                    )?,
                )?,
                launchctl_command: path_text(input.node.model.launchctl_command.as_ref().ok_or(
                    CoreSetupConfigurationError::provider(
                        "macOS Gateway safety launchctl command is unavailable",
                    ),
                )?)?,
                command_working_directory: path_text(&input.node.model.command_working_directory)?,
                lease_milliseconds: input.gateway.node_protection.maximum_cache_milliseconds,
            }),
        ),
    };
    Ok(GatewayDocument {
        schema: SchemaDocument {
            name: "li_gateway_configuration",
            version: 5,
        },
        node_id: input.gateway.node_id.as_str(),
        core_release: input.gateway.core_version.as_str(),
        core_source_identity: input.gateway.core_source_identity.as_str(),
        mode: match input.context.role() {
            CoreUpdateNodeRole::Main => "main",
            CoreUpdateNodeRole::Child => "child",
        },
        health: GatewayHealthDocument {
            socket_path: path_text(&input.gateway.health.socket_path)?,
            maximum_workers: input.gateway.health.maximum_workers,
            read_timeout_milliseconds: input.gateway.health.read_timeout_milliseconds,
            write_timeout_milliseconds: input.gateway.health.write_timeout_milliseconds,
            accept_poll_interval_milliseconds: input
                .gateway
                .health
                .accept_poll_interval_milliseconds,
        },
        node_protection,
        macos_placement_safety,
        runtime: GatewayRuntimeDocument {
            node_socket_path: path_text(&input.gateway.node_socket_path)?,
            telemetry_file: path_text(&input.gateway.telemetry_file)?,
            telemetry_cadence_milliseconds: input.gateway.telemetry_cadence_milliseconds,
            maximum_queue_milliseconds: input.gateway.maximum_queue_milliseconds,
        },
        public_listener: input.gateway.public_listener.map(listener_document),
        private_listener: GatewayPrivateListenerDocument {
            address: listener.address.to_string(),
            maximum_connections: listener.maximum_connections,
            tls: GatewayTlsDocument {
                server_certificate_file: path_text(
                    &input.gateway.private_listener.server_certificate_file,
                )?,
                server_private_key_file: path_text(
                    &input.gateway.private_listener.server_private_key_file,
                )?,
                client_ca_file: path_text(&input.gateway.private_listener.client_ca_file)?,
                client_certificate_file: path_text(
                    &input.gateway.private_listener.client_certificate_file,
                )?,
            },
        },
    })
}

// Converts one typed listener into its exact Gateway schema projection.
fn listener_document(input: CoreSetupGatewayListenerInput) -> GatewayListenerDocument {
    GatewayListenerDocument {
        address: input.address.to_string(),
        maximum_connections: input.maximum_connections,
    }
}

// Converts the explicit Linux Watchdog input into the closed schema-two field set.
fn watchdog_document(
    input: &CoreSetupWatchdogInput,
) -> Result<WatchdogDocument<'_>, CoreSetupConfigurationError> {
    let paths = &input.paths;
    let thresholds = input.thresholds;
    Ok(WatchdogDocument {
        schema: SchemaDocument {
            name: "li_watchdog_configuration",
            version: 2,
        },
        installation_id: input.installation_id.as_str(),
        node_id: input.node_id.as_str(),
        core_release: input.core_version.as_str(),
        core_source_identity: input.core_source_identity.as_str(),
        listener: WatchdogListenerDocument {
            address: input.listen_address,
            port: input.listen_port,
        },
        node_protection: WatchdogNodeProtectionDocument {
            socket_path: path_text(&input.node_protection.socket_path)?,
            read_timeout_milliseconds: input.node_protection.read_timeout_milliseconds,
            write_timeout_milliseconds: input.node_protection.write_timeout_milliseconds,
        },
        paths: WatchdogPathsDocument {
            data_directory: path_text(&paths.data_directory)?,
            server_certificate_path: path_text(&paths.server_certificate_path)?,
            server_private_key_path: path_text(&paths.server_private_key_path)?,
            controller_ca_path: path_text(&paths.controller_ca_path)?,
            controller_allowlist_path: path_text(&paths.controller_allowlist_path)?,
            controller_snapshot_path: path_text(&paths.controller_snapshot_path)?,
            site_state_path: path_text(&paths.site_state_path)?,
            gateway_metrics_path: path_text(&paths.gateway_metrics_path)?,
            protection_root_path: path_text(&paths.protection_root_path)?,
            node_database_path: path_text(&paths.node_database_path)?,
            runtime_installation_root: path_text(&paths.runtime_installation_root)?,
            runtime_cache_root: path_text(&paths.runtime_cache_root)?,
        },
        cadence: WatchdogCadenceDocument {
            sample_interval_milliseconds: 1_000,
            flush_interval_milliseconds: input.flush_interval_milliseconds,
        },
        maximum_controllers: input.maximum_controllers,
        providers: WatchdogProvidersDocument {
            gpu: "nvml",
            gateway_counters: "gateway_telemetry_v2",
        },
        thresholds: WatchdogThresholdsDocument {
            warning_available_bytes: thresholds.warning_available_bytes(),
            graceful_available_bytes: thresholds.graceful_available_bytes(),
            emergency_available_bytes: thresholds.emergency_available_bytes(),
            swap_stop_bytes: thresholds.swap_stop_bytes(),
            psi_some_microseconds: thresholds.psi_some_microseconds(),
            psi_full_microseconds: thresholds.psi_full_microseconds(),
            state_failures: thresholds.state_failures(),
            containment_grace_milliseconds: thresholds.containment_grace_milliseconds(),
        },
    })
}

// Converts one path into JSON text without accepting non-Unicode values.
fn path_text(path: &Path) -> Result<String, CoreSetupConfigurationError> {
    path.to_str()
        .map(str::to_string)
        .ok_or_else(|| configuration_error("configuration path text is invalid"))
}

// Converts one optional path without discovering a native substitute.
fn optional_path_text(
    path: Option<&PathBuf>,
) -> Result<Option<String>, CoreSetupConfigurationError> {
    path.map(|value| path_text(value)).transpose()
}

// Returns the schema spelling for one supported Linux CPU architecture.
const fn architecture_name(architecture: CpuArchitecture) -> &'static str {
    match architecture {
        CpuArchitecture::Arm64 => "arm64",
        CpuArchitecture::X86_64 => "x86_64",
    }
}

// Requires one exact safe file and distinguishes unsafe metadata from byte divergence.
fn require_exact_file(
    file: &CoreSetupConfigurationFile,
    owner_user_id: u32,
    expected: &[u8],
) -> Result<(), CoreSetupConfigurationError> {
    require_safe_file(file, owner_user_id, expected.len().max(1))?;
    if file.bytes != expected {
        return Err(configuration_error(
            "existing configuration differs from the requested configuration",
        ));
    }
    Ok(())
}

// Requires one bounded stable owner-private descriptor observation without judging bytes.
fn require_safe_file(
    file: &CoreSetupConfigurationFile,
    owner_user_id: u32,
    maximum_bytes: usize,
) -> Result<(), CoreSetupConfigurationError> {
    if file.owner_user_id != owner_user_id
        || file.mode != CONFIGURATION_FILE_MODE
        || file.link_count != 1
        || !file.is_regular_file
        || !file.is_stable
        || file.bytes.is_empty()
        || file.bytes.len() > maximum_bytes
    {
        return Err(configuration_error("configuration file metadata is unsafe"));
    }
    Ok(())
}

// Validates one canonical owner-private production configuration directory.
fn validate_configuration_directory(
    directory: &Path,
    owner_user_id: u32,
) -> Result<(), CoreSetupConfigurationError> {
    if !is_normal_absolute_path(directory) || directory == Path::new("/") {
        return Err(configuration_error("configuration directory is invalid"));
    }
    let canonical = fs::canonicalize(directory)
        .map_err(|_| configuration_error("configuration directory is unavailable"))?;
    let metadata = fs::symlink_metadata(directory)
        .map_err(|_| configuration_error("configuration directory is unavailable"))?;
    if canonical != directory
        || !metadata.file_type().is_dir()
        || metadata.uid() != owner_user_id
        || metadata.permissions().mode() & 0o777 != CONFIGURATION_DIRECTORY_MODE
    {
        return Err(configuration_error(
            "configuration directory metadata is unsafe",
        ));
    }
    Ok(())
}

// Binds the newly opened descriptor to the exact directory observed at the requested path.
fn validate_opened_configuration_directory(
    directory: &File,
    path: &Path,
    owner_user_id: u32,
) -> Result<(), CoreSetupConfigurationError> {
    validate_retained_configuration_directory(directory, owner_user_id)?;
    let retained = directory
        .metadata()
        .map_err(|_| configuration_error("configuration directory metadata is unavailable"))?;
    let current = fs::symlink_metadata(path)
        .map_err(|_| configuration_error("configuration directory is unavailable"))?;
    if retained.dev() != current.dev() || retained.ino() != current.ino() {
        return Err(configuration_error(
            "configuration directory identity is unstable",
        ));
    }
    Ok(())
}

// Revalidates owner-private directory metadata on the exact retained descriptor before use.
fn validate_retained_configuration_directory(
    directory: &File,
    owner_user_id: u32,
) -> Result<(), CoreSetupConfigurationError> {
    let metadata = directory
        .metadata()
        .map_err(|_| configuration_error("configuration directory metadata is unavailable"))?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != owner_user_id
        || metadata.permissions().mode() & 0o777 != CONFIGURATION_DIRECTORY_MODE
    {
        return Err(configuration_error(
            "configuration directory metadata is unsafe",
        ));
    }
    Ok(())
}

// Validates one staged or lock descriptor against its exact owner and metadata contract.
fn validate_file_descriptor(
    file: &File,
    owner_user_id: u32,
    require_nonempty: bool,
    maximum_bytes: usize,
) -> Result<(), CoreSetupConfigurationError> {
    let metadata = file
        .metadata()
        .map_err(|_| configuration_error("configuration metadata is unavailable"))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != owner_user_id
        || metadata.permissions().mode() & 0o777 != CONFIGURATION_FILE_MODE
        || metadata.nlink() != 1
        || metadata.len() > maximum_bytes as u64
        || (require_nonempty && metadata.len() == 0)
    {
        return Err(configuration_error("configuration file metadata is unsafe"));
    }
    Ok(())
}

// Converts descriptor metadata into the shared exact-observation shape.
fn configuration_file(
    metadata: &fs::Metadata,
    stable: bool,
    bytes: Vec<u8>,
) -> CoreSetupConfigurationFile {
    CoreSetupConfigurationFile::new(
        metadata.uid(),
        metadata.permissions().mode() & 0o777,
        metadata.nlink(),
        metadata.file_type().is_file(),
        stable,
        bytes,
    )
}

// Returns whether one file descriptor retained the same native identity during its read.
fn same_file(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.uid() == after.uid()
        && before.mode() == after.mode()
        && before.nlink() == after.nlink()
        && before.len() == after.len()
}

// Atomically publishes one configuration without replacing a concurrently created destination.
#[cfg(target_os = "linux")]
fn activate_no_replace_at(
    directory: &File,
    source: &str,
    destination: &str,
) -> Result<(), CoreSetupConfigurationError> {
    let source = contained_name(source)?;
    let destination = contained_name(destination)?;
    let status = unsafe {
        libc::renameat2(
            directory.as_raw_fd(),
            source.as_ptr(),
            directory.as_raw_fd(),
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if status != 0 {
        return Err(configuration_error("configuration could not be activated"));
    }
    Ok(())
}

// Atomically publishes one configuration without replacing a concurrently created destination.
#[cfg(target_os = "macos")]
fn activate_no_replace_at(
    directory: &File,
    source: &str,
    destination: &str,
) -> Result<(), CoreSetupConfigurationError> {
    let source = contained_name(source)?;
    let destination = contained_name(destination)?;
    let status = unsafe {
        libc::renameatx_np(
            directory.as_raw_fd(),
            source.as_ptr(),
            directory.as_raw_fd(),
            destination.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if status != 0 {
        return Err(configuration_error("configuration could not be activated"));
    }
    Ok(())
}

// Opens one directory without following its final component and retains its native identity.
fn open_directory_descriptor(path: &Path) -> Result<File, CoreSetupConfigurationError> {
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| configuration_error("configuration directory path is invalid"))?;
    let descriptor = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(configuration_error(
            "configuration directory could not be opened safely",
        ));
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

// Opens one contained filename relative to an already-open directory descriptor.
fn open_file_at(directory: &File, filename: &str, flags: i32, mode: u32) -> io::Result<File> {
    let filename =
        contained_name(filename).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            filename.as_ptr(),
            flags,
            mode as libc::mode_t as libc::c_uint,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

// Converts one nonempty ordinary filename into a native contained-name value.
fn contained_name(filename: &str) -> Result<std::ffi::CString, CoreSetupConfigurationError> {
    if filename.is_empty()
        || filename == "."
        || filename == ".."
        || filename.as_bytes().contains(&b'/')
    {
        return Err(configuration_error("configuration filename is invalid"));
    }
    std::ffi::CString::new(filename)
        .map_err(|_| configuration_error("configuration filename is invalid"))
}

// Returns whether one path is absolute and free of traversal or prefix components.
fn is_normal_absolute_path(path: &Path) -> bool {
    let Some(text) = path.to_str() else {
        return false;
    };
    path.is_absolute()
        && text.starts_with('/')
        && text.len() > 1
        && !text.ends_with('/')
        && !text.contains("//")
        && !text
            .split('/')
            .any(|component| matches!(component, "." | ".."))
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

// Creates one stable redacted setup-configuration failure.
const fn configuration_error(reason: &'static str) -> CoreSetupConfigurationError {
    CoreSetupConfigurationError::provider(reason)
}

// Creates one stable failure after durable intent makes automatic compensation unsafe.
const fn configuration_recovery(reason: &'static str) -> CoreSetupConfigurationError {
    CoreSetupConfigurationError::recovery_required(reason)
}

// Converts any failure after durable intent into an explicit manual-recovery boundary.
fn configuration_after_intent(error: CoreSetupConfigurationError) -> CoreSetupConfigurationError {
    configuration_recovery(error.reason())
}

// Returns the stable persisted platform spelling for one service context.
const fn platform_name(platform: CoreUpdateServicePlatform) -> &'static str {
    match platform {
        CoreUpdateServicePlatform::Linux => "linux",
        CoreUpdateServicePlatform::Macos => "macos",
    }
}

// Returns the stable persisted role spelling for one service context.
const fn role_name(role: CoreUpdateNodeRole) -> &'static str {
    match role {
        CoreUpdateNodeRole::Main => "main",
        CoreUpdateNodeRole::Child => "child",
    }
}

// Returns the lowercase SHA-256 identity for one exact byte sequence.
fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

// Supplies generated Node bytes through the existing strict loader contract.
struct GeneratedNodeFileProvider {
    owner_user_id: u32,
    bytes: Vec<u8>,
}

impl NodeConfigurationFileProvider for GeneratedNodeFileProvider {
    // Returns one exact safe in-memory Node configuration observation.
    fn read_no_follow(
        &self,
        _path: &Path,
        _maximum_bytes: usize,
    ) -> Result<NodeConfigurationFile, NodeConfigurationError> {
        Ok(NodeConfigurationFile::new(
            self.owner_user_id,
            CONFIGURATION_FILE_MODE,
            1,
            true,
            self.bytes.clone(),
        ))
    }
}

// Supplies generated Gateway bytes through the existing strict loader contract.
struct GeneratedGatewayFileIo {
    owner_user_id: u32,
    bytes: Vec<u8>,
}

impl GatewayNativeFileIo for GeneratedGatewayFileIo {
    // Returns one exact safe in-memory Gateway configuration observation.
    fn read_no_follow(
        &self,
        _path: &Path,
        _maximum_bytes: usize,
    ) -> Result<GatewayNativeFile, GatewayNativeIoError> {
        GatewayNativeFile::new(
            self.owner_user_id,
            CONFIGURATION_FILE_MODE,
            1,
            self.bytes.clone(),
        )
    }
}

// Projects one nested schema identity using the repository-wide name/version convention.
#[derive(Serialize)]
struct SchemaDocument<'a> {
    name: &'a str,
    version: u32,
}

// Projects the closed Node configuration schema.
#[derive(Serialize)]
struct NodeDocument {
    schema: SchemaDocument<'static>,
    runtime: NodeRuntimeDocument,
    core_update: NodeCoreUpdateDocument,
    model: NodeModelDocument,
    benchmark: Option<NodeBenchmarkDocument>,
    pairing: NodePairingDocument,
    hardware: NodeHardwareDocument,
    placement_safety: NodePlacementSafetyDocument,
    daemon: NodeDaemonDocument,
    private_api: NodePrivateApiDocument,
}

// Projects the complete signed Core-update production composition contract.
#[derive(Serialize)]
struct NodeCoreUpdateDocument {
    release_platform: String,
    letsinfer_home: String,
    home_directory: String,
    setup_state_directory: String,
    configuration_root: String,
    curl_command: String,
    ssh_keygen_command: String,
    allowed_signers_file: String,
    supervisor_command: String,
    readiness_timeout_milliseconds: u64,
    readiness_poll_milliseconds: u64,
    stable_readiness_observations: u32,
}

// Projects one closed Linux or macOS placement-safety configuration.
#[derive(Serialize)]
#[serde(tag = "operating_system", rename_all = "snake_case")]
enum NodePlacementSafetyDocument {
    Linux {
        socket_path: String,
        maximum_workers: usize,
        read_timeout_milliseconds: u64,
        write_timeout_milliseconds: u64,
        accept_poll_interval_milliseconds: u64,
        protection_root: String,
        watchdog_source_identity: String,
        gateway: NodeProtectionExecutableDocument,
        watchdog: NodeProtectionExecutableDocument,
        lease_milliseconds: u64,
    },
    Macos,
}

// Projects one exact immutable service executable and API principal.
#[derive(Serialize)]
struct NodeProtectionExecutableDocument {
    path: String,
    executable_sha256: String,
    principal_id: String,
}

// Projects the external installation-bound PairingManager derivation secret reference.
#[derive(Serialize)]
struct NodePairingDocument {
    setup_secret_file: String,
    operating_system: &'static str,
    discovery_command: String,
    openssl_command: String,
    trust_workspace: String,
    site_private_key_file: String,
    site_public_key_file: String,
    site_ca_certificate_file: String,
    local_control_certificate_file: String,
    public_key_sha256: String,
    certificate_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    direct_link_sys_class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    direct_link_ip_command: Option<String>,
}

// Projects the Node database reference.
#[derive(Serialize)]
struct NodeRuntimeDocument {
    database_file: String,
}

// Projects the closed production ModelCoordinator composition contract.
#[derive(Serialize)]
struct NodeModelDocument {
    catalog_source: String,
    catalog_cache_root: String,
    catalog_hydration_root: String,
    http_workspace_root: String,
    installation_root: String,
    runtime_cache_root: String,
    curl_command: String,
    docker_command: String,
    command_working_directory: String,
    placement_material_root: String,
    placement_secret_root: String,
    placement_tls_workspace_root: String,
    first_port: u16,
    port_count: u16,
    endpoint_timeout_milliseconds: u64,
    maximum_hardware_age_milliseconds: u64,
    group_id: u32,
    launch_agents_root: Option<String>,
    launchctl_command: Option<String>,
}

// Projects the Linux benchmark worker, persistence, signing, and telemetry inputs.
#[derive(Serialize)]
struct NodeBenchmarkDocument {
    worker_executable: String,
    github_cli_command: String,
    task_root: String,
    telemetry_root: String,
    evidence_root: String,
    signing_workspace_root: String,
    signing_private_key_file: String,
    signing_public_key_file: String,
    maximum_runtime_milliseconds: u64,
    stop_grace_milliseconds: u64,
    watchdog: NodeBenchmarkWatchdogDocument,
}

// Projects the exact loopback mTLS Watchdog history endpoint.
#[derive(Serialize)]
struct NodeBenchmarkWatchdogDocument {
    host: String,
    port: u16,
    server_name: String,
    ca_file: String,
    controller_authority_private_key_file: String,
    controller_allowlist_file: String,
    controller_reload_receipt_file: String,
    enrollment_server_certificate_file: String,
    enrollment_server_private_key_file: String,
    controller_certificate_file: String,
    controller_private_key_file: String,
    timeout_milliseconds: u64,
}

// Projects exactly one platform-native Node hardware input set.
#[derive(Serialize)]
#[serde(tag = "operating_system", rename_all = "snake_case")]
enum NodeHardwareDocument {
    Linux {
        architecture: &'static str,
        boot_id_file: String,
        cpu_information_file: String,
        memory_information_file: String,
        nvidia_smi_command: Option<String>,
        rdma_command: Option<String>,
    },
    Macos {
        architecture: &'static str,
        sysctl_command: String,
        metal_probe_command: String,
    },
}

// Projects the Node resident cadence.
#[derive(Serialize)]
struct NodeDaemonDocument {
    cadence_milliseconds: u64,
}

// Projects the two Node private listener surfaces.
#[derive(Serialize)]
struct NodePrivateApiDocument {
    local: NodeLocalApiDocument,
    remote: NodeRemoteApiDocument,
}

// Projects the owner-local Node listener contract.
#[derive(Serialize)]
struct NodeLocalApiDocument {
    socket_path: String,
    maximum_workers: usize,
    read_timeout_milliseconds: u64,
    write_timeout_milliseconds: u64,
    accept_poll_interval_milliseconds: u64,
}

// Projects the mutually authenticated Node listener contract using only file references.
#[derive(Serialize)]
struct NodeRemoteApiDocument {
    bind_address: String,
    maximum_workers: usize,
    accept_poll_interval_milliseconds: u64,
    handshake_timeout_milliseconds: u64,
    read_timeout_milliseconds: u64,
    write_timeout_milliseconds: u64,
    server_certificate_file: String,
    server_private_key_file: String,
    client_ca_file: String,
}

// Projects the closed role-aware Gateway configuration schema.
#[derive(Serialize)]
struct GatewayDocument<'a> {
    schema: SchemaDocument<'static>,
    node_id: &'a str,
    core_release: &'a str,
    core_source_identity: &'a str,
    mode: &'static str,
    health: GatewayHealthDocument,
    #[serde(skip_serializing_if = "Option::is_none")]
    node_protection: Option<GatewayNodeProtectionDocument>,
    #[serde(skip_serializing_if = "Option::is_none")]
    macos_placement_safety: Option<GatewayMacOsPlacementSafetyDocument>,
    runtime: GatewayRuntimeDocument,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_listener: Option<GatewayListenerDocument>,
    private_listener: GatewayPrivateListenerDocument,
}

// Projects the dedicated Gateway-to-Node protection socket and freshness bounds.
#[derive(Serialize)]
struct GatewayNodeProtectionDocument {
    socket_path: String,
    read_timeout_milliseconds: u64,
    write_timeout_milliseconds: u64,
    maximum_cache_milliseconds: u64,
    poll_interval_milliseconds: u64,
}

// Projects native macOS launchd observation without a synthetic Watchdog channel.
#[derive(Serialize)]
struct GatewayMacOsPlacementSafetyDocument {
    placement_material_root: String,
    launch_agents_root: String,
    launchctl_command: String,
    command_working_directory: String,
    lease_milliseconds: u64,
}

// Projects one dedicated owner-local Gateway health endpoint.
#[derive(Serialize)]
struct GatewayHealthDocument {
    socket_path: String,
    maximum_workers: usize,
    read_timeout_milliseconds: u64,
    write_timeout_milliseconds: u64,
    accept_poll_interval_milliseconds: u64,
}

// Projects the Gateway process dependencies and timing bounds.
#[derive(Serialize)]
struct GatewayRuntimeDocument {
    node_socket_path: String,
    telemetry_file: String,
    telemetry_cadence_milliseconds: u64,
    maximum_queue_milliseconds: u64,
}

// Projects one Gateway listener.
#[derive(Serialize)]
struct GatewayListenerDocument {
    address: String,
    maximum_connections: usize,
}

// Projects the private Gateway listener and referenced TLS roles.
#[derive(Serialize)]
struct GatewayPrivateListenerDocument {
    address: String,
    maximum_connections: usize,
    tls: GatewayTlsDocument,
}

// Projects four distinct Gateway TLS file references without credential bytes.
#[derive(Serialize)]
struct GatewayTlsDocument {
    server_certificate_file: String,
    server_private_key_file: String,
    client_ca_file: String,
    client_certificate_file: String,
}

// Projects the closed Linux Watchdog configuration schema.
#[derive(Serialize)]
struct WatchdogDocument<'a> {
    schema: SchemaDocument<'static>,
    installation_id: &'a str,
    node_id: &'a str,
    core_release: &'a str,
    core_source_identity: &'a str,
    listener: WatchdogListenerDocument,
    node_protection: WatchdogNodeProtectionDocument,
    paths: WatchdogPathsDocument,
    cadence: WatchdogCadenceDocument,
    maximum_controllers: usize,
    providers: WatchdogProvidersDocument<'static>,
    thresholds: WatchdogThresholdsDocument,
}

// Projects the dedicated Watchdog-to-Node protection client channel.
#[derive(Serialize)]
struct WatchdogNodeProtectionDocument {
    socket_path: String,
    read_timeout_milliseconds: u64,
    write_timeout_milliseconds: u64,
}

// Projects the literal Watchdog listener.
#[derive(Serialize)]
struct WatchdogListenerDocument {
    address: IpAddr,
    port: u16,
}

// Projects every distinct Watchdog filesystem dependency.
#[derive(Serialize)]
struct WatchdogPathsDocument {
    data_directory: String,
    server_certificate_path: String,
    server_private_key_path: String,
    controller_ca_path: String,
    controller_allowlist_path: String,
    controller_snapshot_path: String,
    site_state_path: String,
    gateway_metrics_path: String,
    protection_root_path: String,
    node_database_path: String,
    runtime_installation_root: String,
    runtime_cache_root: String,
}

// Projects the fixed sample cadence and caller-supplied durable flush cadence.
#[derive(Serialize)]
struct WatchdogCadenceDocument {
    sample_interval_milliseconds: u32,
    flush_interval_milliseconds: u32,
}

// Projects the only concrete providers accepted by the current Watchdog parser.
#[derive(Serialize)]
struct WatchdogProvidersDocument<'a> {
    gpu: &'a str,
    gateway_counters: &'a str,
}

// Projects the already-validated Watchdog safety threshold contract.
#[derive(Serialize)]
struct WatchdogThresholdsDocument {
    warning_available_bytes: u64,
    graceful_available_bytes: u64,
    emergency_available_bytes: u64,
    swap_stop_bytes: u64,
    psi_some_microseconds: u64,
    psi_full_microseconds: u64,
    state_failures: u32,
    containment_grace_milliseconds: u32,
}
