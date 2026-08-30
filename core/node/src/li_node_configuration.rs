// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::fs::OpenOptions;
use std::io::Read;
use std::net::SocketAddr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use li_core_interface::{CpuArchitecture, CredentialId, PortRange, Sha256Digest};
use li_core_update_manager::{
    CoreUpdateReadinessPolicy, CoreUpdateReleasePlatform, CoreUpdateServicePlatform,
};

use crate::{
    ExpectedNodeProtectionExecutable, NodePrivateLocalServerConfiguration,
    NodePrivateRemoteServerConfiguration, NodePrivateRemoteTlsFileSet,
    NodeProtectionConnectionRole, NodeProtectionLocalConfiguration,
};

const SCHEMA_NAME: &str = "li_node_configuration";
const SCHEMA_VERSION: u32 = 4;
pub const NODE_CONFIGURATION_MAX_DOCUMENT_BYTES: usize = 64 * 1024;
const MIN_DAEMON_CADENCE: Duration = Duration::from_millis(100);
const MAX_DAEMON_CADENCE: Duration = Duration::from_secs(300);
const MAXIMUM_BENCHMARK_RUNTIME: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const MAXIMUM_BENCHMARK_STOP_GRACE: Duration = Duration::from_secs(10 * 60);
const MAXIMUM_BENCHMARK_WATCHDOG_TIMEOUT: Duration = Duration::from_secs(60);

// Names one stable configuration-file or semantic validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeConfigurationError {
    RelativePath,
    FileUnavailable,
    UnsafeFile,
    DocumentTooLarge,
    InvalidDocument,
    UnsupportedSchema,
    InvalidConfiguration,
}

impl fmt::Display for NodeConfigurationError {
    // Presents fixed configuration language without copying paths or document values.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RelativePath => formatter.write_str("Node configuration path must be absolute"),
            Self::FileUnavailable => formatter.write_str("Node configuration is unavailable"),
            Self::UnsafeFile => formatter.write_str("Node configuration file metadata is unsafe"),
            Self::DocumentTooLarge => formatter.write_str("Node configuration is oversized"),
            Self::InvalidDocument => formatter.write_str("Node configuration JSON is invalid"),
            Self::UnsupportedSchema => {
                formatter.write_str("Node configuration schema is unsupported")
            }
            Self::InvalidConfiguration => {
                formatter.write_str("Node configuration values are invalid")
            }
        }
    }
}

impl Error for NodeConfigurationError {}

// Identifies one exact owner-bound configuration file before native I/O begins.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeConfigurationFileReference {
    path: PathBuf,
    owner_uid: u32,
}

impl NodeConfigurationFileReference {
    // Creates one file reference only from an absolute path and explicit owner identity.
    pub fn new(path: PathBuf, owner_uid: u32) -> Result<Self, NodeConfigurationError> {
        if !path.is_absolute() {
            return Err(NodeConfigurationError::RelativePath);
        }
        Ok(Self { path, owner_uid })
    }

    // Returns the exact absolute file path supplied by process composition.
    pub fn path(&self) -> &Path {
        &self.path
    }

    // Returns the effective user required to own the configuration file.
    pub const fn owner_uid(&self) -> u32 {
        self.owner_uid
    }
}

// Carries one no-follow configuration observation for strict loader validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeConfigurationFile {
    owner_uid: u32,
    mode: u32,
    link_count: u64,
    regular_file: bool,
    bytes: Vec<u8>,
}

impl NodeConfigurationFile {
    // Creates one descriptor-shaped file observation for production or deterministic mocks.
    pub fn new(
        owner_uid: u32,
        mode: u32,
        link_count: u64,
        regular_file: bool,
        bytes: Vec<u8>,
    ) -> Self {
        Self {
            owner_uid,
            mode,
            link_count,
            regular_file,
            bytes,
        }
    }
}

// Reads one exact bounded file without following its final path component.
pub trait NodeConfigurationFileProvider: Send + Sync {
    // Returns one descriptor-shaped observation after a no-follow bounded read.
    fn read_no_follow(
        &self,
        path: &Path,
        maximum_bytes: usize,
    ) -> Result<NodeConfigurationFile, NodeConfigurationError>;
}

// Supplies production no-follow, close-on-exec configuration file reads.
#[derive(Default)]
pub struct SystemNodeConfigurationFileProvider;

impl NodeConfigurationFileProvider for SystemNodeConfigurationFileProvider {
    // Opens, bounds, and revalidates one descriptor without exposing native errors.
    fn read_no_follow(
        &self,
        path: &Path,
        maximum_bytes: usize,
    ) -> Result<NodeConfigurationFile, NodeConfigurationError> {
        read_system_configuration_file(path, maximum_bytes)
    }
}

// Selects one complete platform-native hardware observation input set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodeHardwareConfiguration {
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

// Selects one platform-native placement-safety authority without fabricating Watchdog on macOS.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodePlacementSafetyConfiguration {
    Linux(NodeLinuxProtectionConfiguration),
    MacosLaunchd,
}

// Holds every explicit production Core-update path, trust, command, and readiness authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeCoreUpdateConfiguration {
    release_platform: CoreUpdateReleasePlatform,
    letsinfer_home: PathBuf,
    home_directory: PathBuf,
    setup_state_directory: PathBuf,
    configuration_root: PathBuf,
    curl_command: PathBuf,
    ssh_keygen_command: PathBuf,
    allowed_signers_file: PathBuf,
    supervisor_command: PathBuf,
    readiness: CoreUpdateReadinessPolicy,
}

impl NodeCoreUpdateConfiguration {
    // Returns the exact signed release archive family selected by setup.
    pub const fn release_platform(&self) -> CoreUpdateReleasePlatform {
        self.release_platform
    }

    // Returns the owner-private Let's Infer installation root.
    pub fn letsinfer_home(&self) -> &Path {
        &self.letsinfer_home
    }

    // Returns the exact native user home used for service definitions.
    pub fn home_directory(&self) -> &Path {
        &self.home_directory
    }

    // Returns the owner-private setup/update lock root.
    pub fn setup_state_directory(&self) -> &Path {
        &self.setup_state_directory
    }

    // Returns the exact resident configuration directory used during service handoff.
    pub fn configuration_root(&self) -> &Path {
        &self.configuration_root
    }

    // Returns the exact shell-free HTTPS transport executable.
    pub fn curl_command(&self) -> &Path {
        &self.curl_command
    }

    // Returns the exact shell-free SSHSIG verification executable.
    pub fn ssh_keygen_command(&self) -> &Path {
        &self.ssh_keygen_command
    }

    // Returns the persistent release trust document installed by the signed bootstrap.
    pub fn allowed_signers_file(&self) -> &Path {
        &self.allowed_signers_file
    }

    // Returns the exact platform-native resident service supervisor executable.
    pub fn supervisor_command(&self) -> &Path {
        &self.supervisor_command
    }

    // Returns the bounded stable-readiness policy for atomic service handoff.
    pub const fn readiness(&self) -> CoreUpdateReadinessPolicy {
        self.readiness
    }
}

// Holds every explicit signed-runtime and native-placement input owned by ModelCoordinator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeModelConfiguration {
    catalog_source: String,
    catalog_cache_root: PathBuf,
    catalog_hydration_root: PathBuf,
    http_workspace_root: PathBuf,
    installation_root: PathBuf,
    runtime_cache_root: PathBuf,
    curl_command: PathBuf,
    docker_command: PathBuf,
    command_working_directory: PathBuf,
    placement_material_root: PathBuf,
    placement_secret_root: PathBuf,
    placement_tls_workspace_root: PathBuf,
    first_port: u16,
    port_count: u16,
    endpoint_timeout: Duration,
    maximum_hardware_age: Duration,
    group_id: u32,
    launch_agents_root: Option<PathBuf>,
    launchctl_command: Option<PathBuf>,
}

impl NodeModelConfiguration {
    // Returns the exact signed catalog source selected by setup.
    pub fn catalog_source(&self) -> &str {
        &self.catalog_source
    }
    // Returns the verified catalog cache root.
    pub fn catalog_cache_root(&self) -> &Path {
        &self.catalog_cache_root
    }
    // Returns the private catalog hydration root.
    pub fn catalog_hydration_root(&self) -> &Path {
        &self.catalog_hydration_root
    }
    // Returns the private native HTTP workspace root.
    pub fn http_workspace_root(&self) -> &Path {
        &self.http_workspace_root
    }
    // Returns the immutable runtime installation root.
    pub fn installation_root(&self) -> &Path {
        &self.installation_root
    }
    // Returns the mutable runtime cache root.
    pub fn runtime_cache_root(&self) -> &Path {
        &self.runtime_cache_root
    }
    // Returns the exact curl executable.
    pub fn curl_command(&self) -> &Path {
        &self.curl_command
    }
    // Returns the exact Docker executable.
    pub fn docker_command(&self) -> &Path {
        &self.docker_command
    }
    // Returns the shell-free command working directory.
    pub fn command_working_directory(&self) -> &Path {
        &self.command_working_directory
    }
    // Returns the private sealed placement material root.
    pub fn placement_material_root(&self) -> &Path {
        &self.placement_material_root
    }
    // Returns the private placement secret root.
    pub fn placement_secret_root(&self) -> &Path {
        &self.placement_secret_root
    }
    // Returns the private placement TLS workspace root.
    pub fn placement_tls_workspace_root(&self) -> &Path {
        &self.placement_tls_workspace_root
    }
    // Returns the first managed local Engine port.
    pub const fn first_port(&self) -> u16 {
        self.first_port
    }
    // Returns the complete managed contiguous port envelope.
    pub const fn port_count(&self) -> u16 {
        self.port_count
    }
    // Returns the bounded native endpoint readiness deadline.
    pub const fn endpoint_timeout(&self) -> Duration {
        self.endpoint_timeout
    }
    // Returns the maximum admitted HardwareManager observation age.
    pub const fn maximum_hardware_age(&self) -> Duration {
        self.maximum_hardware_age
    }
    // Returns the service group identity used by native execution.
    pub const fn group_id(&self) -> u32 {
        self.group_id
    }
    // Returns the macOS user LaunchAgents root when configured.
    pub fn launch_agents_root(&self) -> Option<&Path> {
        self.launch_agents_root.as_deref()
    }
    // Returns the exact launchctl executable when configured.
    pub fn launchctl_command(&self) -> Option<&Path> {
        self.launchctl_command.as_deref()
    }
}

// Holds the exact loopback mTLS boundary used to read Watchdog benchmark history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeBenchmarkWatchdogConfiguration {
    host: String,
    port: u16,
    server_name: String,
    ca_file: PathBuf,
    controller_authority_private_key_file: PathBuf,
    controller_allowlist_file: PathBuf,
    controller_reload_receipt_file: PathBuf,
    enrollment_server_certificate_file: PathBuf,
    enrollment_server_private_key_file: PathBuf,
    controller_certificate_file: PathBuf,
    controller_private_key_file: PathBuf,
    timeout: Duration,
}

impl NodeBenchmarkWatchdogConfiguration {
    // Returns the fixed loopback transport host without performing name resolution.
    pub fn host(&self) -> &str {
        &self.host
    }

    // Returns the exact installed Watchdog listener port.
    pub const fn port(&self) -> u16 {
        self.port
    }

    // Returns the certificate server identity issued during setup.
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    // Returns the exact Watchdog server trust anchor.
    pub fn ca_file(&self) -> &Path {
        &self.ca_file
    }

    // Returns the owner-private controller authority key used only for confirmed enrollment.
    pub fn controller_authority_private_key_file(&self) -> &Path {
        &self.controller_authority_private_key_file
    }

    // Returns the owner-only allowlist atomically projected into the resident Watchdog.
    pub fn controller_allowlist_file(&self) -> &Path {
        &self.controller_allowlist_file
    }

    // Returns the Watchdog registry snapshot that acknowledges an exact live allowlist identity.
    pub fn controller_reload_receipt_file(&self) -> &Path {
        &self.controller_reload_receipt_file
    }

    // Returns the Watchdog-authority server certificate used by the transient pairing listener.
    pub fn enrollment_server_certificate_file(&self) -> &Path {
        &self.enrollment_server_certificate_file
    }

    // Returns the owner-private server key used only by the transient pairing listener.
    pub fn enrollment_server_private_key_file(&self) -> &Path {
        &self.enrollment_server_private_key_file
    }

    // Returns the exact allowlisted Core controller certificate.
    pub fn controller_certificate_file(&self) -> &Path {
        &self.controller_certificate_file
    }

    // Returns the owner-private Core controller key.
    pub fn controller_private_key_file(&self) -> &Path {
        &self.controller_private_key_file
    }

    // Returns the complete bounded Watchdog query deadline.
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }
}

// Holds every explicit production benchmark path, deadline, and telemetry authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeBenchmarkConfiguration {
    worker_executable: PathBuf,
    github_cli_command: PathBuf,
    task_root: PathBuf,
    telemetry_root: PathBuf,
    evidence_root: PathBuf,
    signing_workspace_root: PathBuf,
    signing_private_key_file: PathBuf,
    signing_public_key_file: PathBuf,
    maximum_runtime: Duration,
    stop_grace: Duration,
    watchdog: NodeBenchmarkWatchdogConfiguration,
}

impl NodeBenchmarkConfiguration {
    // Returns the immutable native benchmark worker installed with this Core release.
    pub fn worker_executable(&self) -> &Path {
        &self.worker_executable
    }

    // Returns the authenticated GitHub CLI executable used only by proposal verification.
    pub fn github_cli_command(&self) -> &Path {
        &self.github_cli_command
    }

    // Returns the owner-private worker task root.
    pub fn task_root(&self) -> &Path {
        &self.task_root
    }

    // Returns the owner-private manager telemetry journal root.
    pub fn telemetry_root(&self) -> &Path {
        &self.telemetry_root
    }

    // Returns the immutable completed benchmark evidence root.
    pub fn evidence_root(&self) -> &Path {
        &self.evidence_root
    }

    // Returns the owner-private signing transaction workspace.
    pub fn signing_workspace_root(&self) -> &Path {
        &self.signing_workspace_root
    }

    // Returns the dedicated owner-private Ed25519 signing key.
    pub fn signing_private_key_file(&self) -> &Path {
        &self.signing_private_key_file
    }

    // Returns the dedicated Ed25519 verification key.
    pub fn signing_public_key_file(&self) -> &Path {
        &self.signing_public_key_file
    }

    // Returns the complete benchmark execution deadline.
    pub const fn maximum_runtime(&self) -> Duration {
        self.maximum_runtime
    }

    // Returns the bounded graceful worker-stop deadline.
    pub const fn stop_grace(&self) -> Duration {
        self.stop_grace
    }

    // Returns the exact Watchdog history authority for this Node.
    pub const fn watchdog(&self) -> &NodeBenchmarkWatchdogConfiguration {
        &self.watchdog
    }
}

// Holds every explicit Linux Node-owned protection channel and identity binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeLinuxProtectionConfiguration {
    local_server: NodeProtectionLocalConfiguration,
    protection_root: PathBuf,
    watchdog_source_identity: Sha256Digest,
    gateway: ExpectedNodeProtectionExecutable,
    watchdog: ExpectedNodeProtectionExecutable,
    lease_milliseconds: u64,
}

impl NodeLinuxProtectionConfiguration {
    // Returns the dedicated owner-only protection listener configuration.
    pub const fn local_server(&self) -> &NodeProtectionLocalConfiguration {
        &self.local_server
    }

    // Returns the exact placement protection descriptor root shared with Watchdog.
    pub fn protection_root(&self) -> &Path {
        &self.protection_root
    }

    // Returns the immutable Watchdog executable source identity.
    pub const fn watchdog_source_identity(&self) -> &Sha256Digest {
        &self.watchdog_source_identity
    }

    // Returns the expected immutable Gateway executable identity and principal.
    pub const fn gateway(&self) -> &ExpectedNodeProtectionExecutable {
        &self.gateway
    }

    // Returns the expected immutable Watchdog executable identity and principal.
    pub const fn watchdog(&self) -> &ExpectedNodeProtectionExecutable {
        &self.watchdog
    }

    // Returns the short lease duration granted by each complete successful cycle.
    pub const fn lease_milliseconds(&self) -> u64 {
        self.lease_milliseconds
    }
}

// Holds one fully validated database, hardware, resident, listener, and TLS configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeConfiguration {
    database_file: PathBuf,
    core_update: NodeCoreUpdateConfiguration,
    model: NodeModelConfiguration,
    benchmark: Option<NodeBenchmarkConfiguration>,
    pairing: NodePairingConfiguration,
    hardware: NodeHardwareConfiguration,
    placement_safety: NodePlacementSafetyConfiguration,
    daemon_cadence: Duration,
    local_server: NodePrivateLocalServerConfiguration,
    remote_server: NodePrivateRemoteServerConfiguration,
    remote_tls_files: NodePrivateRemoteTlsFileSet,
    remote_handshake_timeout: Duration,
    remote_read_timeout: Duration,
    remote_write_timeout: Duration,
}

impl NodeConfiguration {
    // Loads one strict closed JSON document from an owner-only bounded file observation.
    pub fn load(
        reference: &NodeConfigurationFileReference,
        provider: &dyn NodeConfigurationFileProvider,
    ) -> Result<Self, NodeConfigurationError> {
        let file =
            provider.read_no_follow(reference.path(), NODE_CONFIGURATION_MAX_DOCUMENT_BYTES)?;
        if file.owner_uid != reference.owner_uid()
            || file.mode != 0o600
            || file.link_count != 1
            || !file.regular_file
        {
            return Err(NodeConfigurationError::UnsafeFile);
        }
        if file.bytes.len() > NODE_CONFIGURATION_MAX_DOCUMENT_BYTES {
            return Err(NodeConfigurationError::DocumentTooLarge);
        }
        let wire: WireNodeConfiguration = serde_json::from_slice(&file.bytes)
            .map_err(|_| NodeConfigurationError::InvalidDocument)?;
        let configuration_root = reference
            .path()
            .parent()
            .ok_or(NodeConfigurationError::InvalidConfiguration)?;
        wire.into_configuration(reference.owner_uid(), configuration_root)
    }

    // Returns the exact shared Core database selected by process composition.
    pub fn database_file(&self) -> &Path {
        &self.database_file
    }

    // Returns every explicit production Core-update composition authority.
    pub const fn core_update(&self) -> &NodeCoreUpdateConfiguration {
        &self.core_update
    }

    // Returns every explicit production ModelCoordinator composition input.
    pub const fn model(&self) -> &NodeModelConfiguration {
        &self.model
    }

    // Returns production benchmark composition only on a platform with truthful telemetry.
    pub const fn benchmark(&self) -> Option<&NodeBenchmarkConfiguration> {
        self.benchmark.as_ref()
    }

    // Returns the exact installation-bound secret file used only for pairing code derivation.
    pub fn pairing_setup_secret_file(&self) -> &Path {
        self.pairing.setup_secret_file()
    }

    // Returns every explicit native and trust input required by PairingManager composition.
    pub const fn pairing(&self) -> &NodePairingConfiguration {
        &self.pairing
    }

    // Returns every explicit native input required by the selected hardware provider.
    pub const fn hardware(&self) -> &NodeHardwareConfiguration {
        &self.hardware
    }

    // Returns the exact platform-native placement-safety configuration.
    pub const fn placement_safety(&self) -> &NodePlacementSafetyConfiguration {
        &self.placement_safety
    }

    // Returns the bounded interval between resident NodeDaemon cycles.
    pub const fn daemon_cadence(&self) -> Duration {
        self.daemon_cadence
    }

    // Returns the exact validated local private-listener configuration.
    pub const fn local_server(&self) -> &NodePrivateLocalServerConfiguration {
        &self.local_server
    }

    // Returns the exact validated remote private-listener configuration.
    pub const fn remote_server(&self) -> &NodePrivateRemoteServerConfiguration {
        &self.remote_server
    }

    // Returns the three exact owner-only TLS file references.
    pub const fn remote_tls_files(&self) -> &NodePrivateRemoteTlsFileSet {
        &self.remote_tls_files
    }

    // Returns the complete TLS handshake deadline.
    pub const fn remote_handshake_timeout(&self) -> Duration {
        self.remote_handshake_timeout
    }

    // Returns the complete authenticated request-frame deadline.
    pub const fn remote_read_timeout(&self) -> Duration {
        self.remote_read_timeout
    }

    // Returns the complete authenticated response-frame deadline.
    pub const fn remote_write_timeout(&self) -> Duration {
        self.remote_write_timeout
    }
}

// Stores the required nested Let's Infer schema identity.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireSchema {
    name: String,
    version: u32,
}

// Stores one closed Node configuration document.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireNodeConfiguration {
    schema: WireSchema,
    runtime: WireRuntimeConfiguration,
    core_update: WireCoreUpdateConfiguration,
    model: WireModelConfiguration,
    benchmark: Option<WireBenchmarkConfiguration>,
    pairing: WirePairingConfiguration,
    hardware: WireHardwareConfiguration,
    placement_safety: WirePlacementSafetyConfiguration,
    daemon: WireDaemonConfiguration,
    private_api: WirePrivateApiConfiguration,
}

impl WireNodeConfiguration {
    // Validates schema and converts every native input into one canonical typed configuration.
    fn into_configuration(
        self,
        owner_uid: u32,
        configuration_file_root: &Path,
    ) -> Result<NodeConfiguration, NodeConfigurationError> {
        if self.schema.name != SCHEMA_NAME || self.schema.version != SCHEMA_VERSION {
            return Err(NodeConfigurationError::UnsupportedSchema);
        }
        let database_file = absolute_path(&self.runtime.database_file)?;
        let pairing = self.pairing.into_configuration()?;
        let hardware = self.hardware.into_configuration()?;
        let model = self.model.into_configuration(&hardware)?;
        let benchmark = self
            .benchmark
            .map(WireBenchmarkConfiguration::into_configuration)
            .transpose()?;
        if benchmark.is_some() != matches!(hardware, NodeHardwareConfiguration::Linux { .. }) {
            return Err(NodeConfigurationError::InvalidConfiguration);
        }
        let core_update =
            self.core_update
                .into_configuration(&hardware, &model, configuration_file_root)?;
        let placement_safety = self
            .placement_safety
            .into_configuration(owner_uid, &hardware)?;
        if !matches!(
            (pairing.platform(), &hardware),
            (
                NodePairingPlatform::Linux { .. },
                NodeHardwareConfiguration::Linux { .. }
            ) | (
                NodePairingPlatform::Macos,
                NodeHardwareConfiguration::MacosArm64 { .. }
            )
        ) {
            return Err(NodeConfigurationError::InvalidConfiguration);
        }
        let daemon_cadence = duration(self.daemon.cadence_milliseconds)?;
        if !(MIN_DAEMON_CADENCE..=MAX_DAEMON_CADENCE).contains(&daemon_cadence) {
            return Err(NodeConfigurationError::InvalidConfiguration);
        }
        let local = self.private_api.local;
        let local_socket_path = absolute_path(&local.socket_path)?;
        let local_server = NodePrivateLocalServerConfiguration::new(
            local_socket_path,
            owner_uid,
            local.maximum_workers,
            duration(local.read_timeout_milliseconds)?,
            duration(local.write_timeout_milliseconds)?,
            duration(local.accept_poll_interval_milliseconds)?,
        )
        .map_err(|_| NodeConfigurationError::InvalidConfiguration)?;
        let remote = self.private_api.remote;
        if remote.bind_address.len() > 64 {
            return Err(NodeConfigurationError::InvalidConfiguration);
        }
        let bind_address = remote
            .bind_address
            .parse::<SocketAddr>()
            .map_err(|_| NodeConfigurationError::InvalidConfiguration)?;
        if bind_address.port() == 0 {
            return Err(NodeConfigurationError::InvalidConfiguration);
        }
        let remote_server = NodePrivateRemoteServerConfiguration::new(
            bind_address,
            remote.maximum_workers,
            duration(remote.accept_poll_interval_milliseconds)?,
        )
        .map_err(|_| NodeConfigurationError::InvalidConfiguration)?;
        let mut remote_tls_files = NodePrivateRemoteTlsFileSet::new(
            owner_uid,
            absolute_path(&remote.server_certificate_file)?,
            absolute_path(&remote.server_private_key_file)?,
            absolute_path(&remote.client_ca_file)?,
        )
        .map_err(|_| NodeConfigurationError::InvalidConfiguration)?;
        if let Some(benchmark) = &benchmark {
            remote_tls_files = remote_tls_files
                .with_additional_client_ca_file(benchmark.watchdog().ca_file().to_path_buf())
                .map_err(|_| NodeConfigurationError::InvalidConfiguration)?;
        }
        let mut native_paths = vec![
            database_file.as_path(),
            pairing.setup_secret_file(),
            pairing.discovery_command(),
            pairing.openssl_command(),
            pairing.trust_workspace(),
            pairing.site_private_key_file(),
            pairing.site_public_key_file(),
            pairing.site_ca_certificate_file(),
            pairing.local_control_certificate_file(),
            local_server.socket_path(),
            Path::new(&remote.server_certificate_file),
            Path::new(&remote.server_private_key_file),
            Path::new(&remote.client_ca_file),
        ];
        if let Some(benchmark) = &benchmark {
            native_paths.extend([
                benchmark.worker_executable(),
                benchmark.task_root(),
                benchmark.telemetry_root(),
                benchmark.evidence_root(),
                benchmark.signing_workspace_root(),
                benchmark.signing_private_key_file(),
                benchmark.signing_public_key_file(),
                benchmark.watchdog().ca_file(),
                benchmark.watchdog().controller_authority_private_key_file(),
                benchmark.watchdog().controller_allowlist_file(),
                benchmark.watchdog().controller_reload_receipt_file(),
                benchmark.watchdog().enrollment_server_certificate_file(),
                benchmark.watchdog().enrollment_server_private_key_file(),
                benchmark.watchdog().controller_certificate_file(),
                benchmark.watchdog().controller_private_key_file(),
            ]);
        }
        if native_paths
            .iter()
            .enumerate()
            .any(|(index, path)| native_paths[..index].contains(path))
        {
            return Err(NodeConfigurationError::InvalidConfiguration);
        }
        if let NodePlacementSafetyConfiguration::Linux(protection) = &placement_safety {
            let protection_paths = [
                protection.local_server().socket_path(),
                protection.protection_root(),
                protection.gateway().canonical_path(),
                protection.watchdog().canonical_path(),
            ];
            if protection_paths
                .iter()
                .any(|path| native_paths.contains(path))
                || protection_paths
                    .iter()
                    .enumerate()
                    .any(|(index, path)| protection_paths[..index].contains(path))
            {
                return Err(NodeConfigurationError::InvalidConfiguration);
            }
        }
        let remote_handshake_timeout = duration(remote.handshake_timeout_milliseconds)?;
        let remote_read_timeout = duration(remote.read_timeout_milliseconds)?;
        let remote_write_timeout = duration(remote.write_timeout_milliseconds)?;
        if [
            remote_handshake_timeout,
            remote_read_timeout,
            remote_write_timeout,
        ]
        .iter()
        .any(|value| value.is_zero() || *value > Duration::from_secs(60))
        {
            return Err(NodeConfigurationError::InvalidConfiguration);
        }
        Ok(NodeConfiguration {
            database_file,
            core_update,
            model,
            benchmark,
            pairing,
            hardware,
            placement_safety,
            daemon_cadence,
            local_server,
            remote_server,
            remote_tls_files,
            remote_handshake_timeout,
            remote_read_timeout,
            remote_write_timeout,
        })
    }
}

// Stores every required production Core-update authority without native path discovery.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireCoreUpdateConfiguration {
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

impl WireCoreUpdateConfiguration {
    // Validates platform identity, exact product paths, native commands, trust, and timing bounds.
    fn into_configuration(
        self,
        hardware: &NodeHardwareConfiguration,
        model: &NodeModelConfiguration,
        configuration_file_root: &Path,
    ) -> Result<NodeCoreUpdateConfiguration, NodeConfigurationError> {
        let release_platform = release_platform(&self.release_platform)?;
        if !release_platform_matches_hardware(release_platform, hardware) {
            return Err(NodeConfigurationError::InvalidConfiguration);
        }
        let letsinfer_home = absolute_path(&self.letsinfer_home)?;
        let home_directory = absolute_path(&self.home_directory)?;
        let setup_state_directory = absolute_path(&self.setup_state_directory)?;
        let configuration_root = absolute_path(&self.configuration_root)?;
        let curl_command = absolute_path(&self.curl_command)?;
        let ssh_keygen_command = absolute_path(&self.ssh_keygen_command)?;
        let allowed_signers_file = absolute_path(&self.allowed_signers_file)?;
        let supervisor_command = absolute_path(&self.supervisor_command)?;
        let expected_supervisor = match release_service_platform(release_platform) {
            CoreUpdateServicePlatform::Linux => Path::new("/usr/bin/systemctl"),
            CoreUpdateServicePlatform::Macos => Path::new("/bin/launchctl"),
        };
        if configuration_root != configuration_file_root
            || allowed_signers_file != letsinfer_home.join("trust/release-allowed-signers")
            || curl_command != model.curl_command()
            || supervisor_command != expected_supervisor
        {
            return Err(NodeConfigurationError::InvalidConfiguration);
        }
        let readiness = CoreUpdateReadinessPolicy::new(
            self.readiness_timeout_milliseconds,
            self.readiness_poll_milliseconds,
            self.stable_readiness_observations,
        )
        .map_err(|_| NodeConfigurationError::InvalidConfiguration)?;
        Ok(NodeCoreUpdateConfiguration {
            release_platform,
            letsinfer_home,
            home_directory,
            setup_state_directory,
            configuration_root,
            curl_command,
            ssh_keygen_command,
            allowed_signers_file,
            supervisor_command,
            readiness,
        })
    }
}

// Parses one closed release archive family from its canonical configuration identity.
fn release_platform(value: &str) -> Result<CoreUpdateReleasePlatform, NodeConfigurationError> {
    match value {
        "linux_arm64" => Ok(CoreUpdateReleasePlatform::LinuxArm64),
        "linux_x86_64" => Ok(CoreUpdateReleasePlatform::LinuxX86_64),
        "macos_arm64" => Ok(CoreUpdateReleasePlatform::MacosArm64),
        _ => Err(NodeConfigurationError::InvalidConfiguration),
    }
}

// Requires one signed release family to match the exact configured hardware platform.
const fn release_platform_matches_hardware(
    release: CoreUpdateReleasePlatform,
    hardware: &NodeHardwareConfiguration,
) -> bool {
    matches!(
        (release, hardware),
        (
            CoreUpdateReleasePlatform::LinuxArm64,
            NodeHardwareConfiguration::Linux {
                architecture: CpuArchitecture::Arm64,
                ..
            }
        ) | (
            CoreUpdateReleasePlatform::LinuxX86_64,
            NodeHardwareConfiguration::Linux {
                architecture: CpuArchitecture::X86_64,
                ..
            }
        ) | (
            CoreUpdateReleasePlatform::MacosArm64,
            NodeHardwareConfiguration::MacosArm64 { .. }
        )
    )
}

// Maps one release archive family to its resident service platform.
const fn release_service_platform(
    platform: CoreUpdateReleasePlatform,
) -> CoreUpdateServicePlatform {
    match platform {
        CoreUpdateReleasePlatform::LinuxArm64 | CoreUpdateReleasePlatform::LinuxX86_64 => {
            CoreUpdateServicePlatform::Linux
        }
        CoreUpdateReleasePlatform::MacosArm64 => CoreUpdateServicePlatform::Macos,
    }
}

// Stores the exact shared durable database selected by this process.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRuntimeConfiguration {
    database_file: String,
}

// Stores every closed signed-runtime and native placement composition value.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireModelConfiguration {
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

impl WireModelConfiguration {
    // Converts a complete platform-exact model composition document without host discovery.
    fn into_configuration(
        self,
        hardware: &NodeHardwareConfiguration,
    ) -> Result<NodeModelConfiguration, NodeConfigurationError> {
        let macos = matches!(hardware, NodeHardwareConfiguration::MacosArm64 { .. });
        let launch_agents_root = optional_absolute_path(self.launch_agents_root)?;
        let launchctl_command = optional_absolute_path(self.launchctl_command)?;
        if !runtime_catalog_source(&self.catalog_source)
            || self.first_port == 0
            || self.port_count == 0
            || self.group_id == 0
            || macos != launch_agents_root.is_some()
            || macos != launchctl_command.is_some()
        {
            return Err(NodeConfigurationError::InvalidConfiguration);
        }
        PortRange::new(self.first_port, self.port_count)
            .map_err(|_| NodeConfigurationError::InvalidConfiguration)?;
        let endpoint_timeout = duration(self.endpoint_timeout_milliseconds)?;
        let maximum_hardware_age = duration(self.maximum_hardware_age_milliseconds)?;
        if endpoint_timeout.is_zero()
            || endpoint_timeout > Duration::from_secs(30)
            || maximum_hardware_age.is_zero()
            || maximum_hardware_age > Duration::from_secs(86_400)
        {
            return Err(NodeConfigurationError::InvalidConfiguration);
        }
        Ok(NodeModelConfiguration {
            catalog_source: self.catalog_source,
            catalog_cache_root: absolute_path(&self.catalog_cache_root)?,
            catalog_hydration_root: absolute_path(&self.catalog_hydration_root)?,
            http_workspace_root: absolute_path(&self.http_workspace_root)?,
            installation_root: absolute_path(&self.installation_root)?,
            runtime_cache_root: absolute_path(&self.runtime_cache_root)?,
            curl_command: absolute_path(&self.curl_command)?,
            docker_command: absolute_path(&self.docker_command)?,
            command_working_directory: absolute_path(&self.command_working_directory)?,
            placement_material_root: absolute_path(&self.placement_material_root)?,
            placement_secret_root: absolute_path(&self.placement_secret_root)?,
            placement_tls_workspace_root: absolute_path(&self.placement_tls_workspace_root)?,
            first_port: self.first_port,
            port_count: self.port_count,
            endpoint_timeout,
            maximum_hardware_age,
            group_id: self.group_id,
            launch_agents_root,
            launchctl_command,
        })
    }
}

// Returns whether one credential-free HTTPS source names the signed runtime catalog document.
fn runtime_catalog_source(value: &str) -> bool {
    if value.len() > 2_048
        || value.chars().any(char::is_whitespace)
        || value.chars().any(char::is_control)
        || value.contains('@')
        || value.contains('#')
        || !value.ends_with("/catalog.json")
    {
        return false;
    }
    value.strip_prefix("https://").is_some_and(|remainder| {
        let authority = remainder.split('/').next().unwrap_or_default();
        !authority.is_empty()
            && authority != "."
            && authority != ".."
            && !authority.starts_with(':')
    })
}

// Stores the closed Linux benchmark execution, signing, and Watchdog history contract.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireBenchmarkConfiguration {
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
    watchdog: WireBenchmarkWatchdogConfiguration,
}

// Stores one exact loopback mTLS Watchdog history endpoint without discovery inputs.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireBenchmarkWatchdogConfiguration {
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

impl WireBenchmarkConfiguration {
    // Converts one complete benchmark document after rejecting aliases and unsafe lifetimes.
    fn into_configuration(self) -> Result<NodeBenchmarkConfiguration, NodeConfigurationError> {
        let worker_executable = normal_absolute_path(&self.worker_executable)?;
        let github_cli_command = normal_absolute_path(&self.github_cli_command)?;
        let task_root = normal_absolute_path(&self.task_root)?;
        let telemetry_root = normal_absolute_path(&self.telemetry_root)?;
        let evidence_root = normal_absolute_path(&self.evidence_root)?;
        let signing_workspace_root = normal_absolute_path(&self.signing_workspace_root)?;
        let signing_private_key_file = normal_absolute_path(&self.signing_private_key_file)?;
        let signing_public_key_file = normal_absolute_path(&self.signing_public_key_file)?;
        let ca_file = normal_absolute_path(&self.watchdog.ca_file)?;
        let controller_authority_private_key_file =
            normal_absolute_path(&self.watchdog.controller_authority_private_key_file)?;
        let controller_allowlist_file =
            normal_absolute_path(&self.watchdog.controller_allowlist_file)?;
        let controller_reload_receipt_file =
            normal_absolute_path(&self.watchdog.controller_reload_receipt_file)?;
        let enrollment_server_certificate_file =
            normal_absolute_path(&self.watchdog.enrollment_server_certificate_file)?;
        let enrollment_server_private_key_file =
            normal_absolute_path(&self.watchdog.enrollment_server_private_key_file)?;
        let controller_certificate_file =
            normal_absolute_path(&self.watchdog.controller_certificate_file)?;
        let controller_private_key_file =
            normal_absolute_path(&self.watchdog.controller_private_key_file)?;
        let roots = [
            task_root.as_path(),
            telemetry_root.as_path(),
            evidence_root.as_path(),
            signing_workspace_root.as_path(),
        ];
        let immutable_files = [
            worker_executable.as_path(),
            github_cli_command.as_path(),
            signing_private_key_file.as_path(),
            signing_public_key_file.as_path(),
            ca_file.as_path(),
            controller_authority_private_key_file.as_path(),
            controller_allowlist_file.as_path(),
            controller_reload_receipt_file.as_path(),
            enrollment_server_certificate_file.as_path(),
            enrollment_server_private_key_file.as_path(),
            controller_certificate_file.as_path(),
            controller_private_key_file.as_path(),
        ];
        if !paths_are_disjoint(&roots)
            || immutable_files
                .iter()
                .enumerate()
                .any(|(index, path)| immutable_files[..index].contains(path))
            || roots.iter().any(|root| {
                immutable_files
                    .iter()
                    .any(|immutable| immutable.starts_with(root))
            })
        {
            return Err(NodeConfigurationError::InvalidConfiguration);
        }
        let maximum_runtime = duration(self.maximum_runtime_milliseconds)?;
        let stop_grace = duration(self.stop_grace_milliseconds)?;
        let timeout = duration(self.watchdog.timeout_milliseconds)?;
        if maximum_runtime > MAXIMUM_BENCHMARK_RUNTIME
            || stop_grace > MAXIMUM_BENCHMARK_STOP_GRACE
            || stop_grace > maximum_runtime
            || timeout > MAXIMUM_BENCHMARK_WATCHDOG_TIMEOUT
            || self.watchdog.host != "127.0.0.1"
            || self.watchdog.port == 0
            || !valid_server_name(&self.watchdog.server_name)
        {
            return Err(NodeConfigurationError::InvalidConfiguration);
        }
        Ok(NodeBenchmarkConfiguration {
            worker_executable,
            github_cli_command,
            task_root,
            telemetry_root,
            evidence_root,
            signing_workspace_root,
            signing_private_key_file,
            signing_public_key_file,
            maximum_runtime,
            stop_grace,
            watchdog: NodeBenchmarkWatchdogConfiguration {
                host: self.watchdog.host,
                port: self.watchdog.port,
                server_name: self.watchdog.server_name,
                ca_file,
                controller_authority_private_key_file,
                controller_allowlist_file,
                controller_reload_receipt_file,
                enrollment_server_certificate_file,
                enrollment_server_private_key_file,
                controller_certificate_file,
                controller_private_key_file,
                timeout,
            },
        })
    }
}

// Stores the explicit installation-bound pairing setup secret reference.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WirePairingConfiguration {
    setup_secret_file: String,
    operating_system: String,
    discovery_command: String,
    openssl_command: String,
    trust_workspace: String,
    site_private_key_file: String,
    site_public_key_file: String,
    site_ca_certificate_file: String,
    local_control_certificate_file: String,
    public_key_sha256: String,
    certificate_sha256: String,
    direct_link_sys_class: Option<String>,
    direct_link_ip_command: Option<String>,
}

// Holds the complete platform-closed PairingManager native and trust configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodePairingConfiguration {
    platform: NodePairingPlatform,
    setup_secret_file: PathBuf,
    discovery_command: PathBuf,
    openssl_command: PathBuf,
    trust_workspace: PathBuf,
    site_private_key_file: PathBuf,
    site_public_key_file: PathBuf,
    site_ca_certificate_file: PathBuf,
    local_control_certificate_file: PathBuf,
    public_key_sha256: Sha256Digest,
    certificate_sha256: Sha256Digest,
}

impl NodePairingConfiguration {
    // Returns the exact platform-native discovery and optional direct-link contract.
    pub const fn platform(&self) -> &NodePairingPlatform {
        &self.platform
    }

    // Returns the installation-bound HMAC setup-secret file.
    pub fn setup_secret_file(&self) -> &Path {
        &self.setup_secret_file
    }

    // Returns the exact native discovery executable.
    pub fn discovery_command(&self) -> &Path {
        &self.discovery_command
    }

    // Returns the exact OpenSSL executable.
    pub fn openssl_command(&self) -> &Path {
        &self.openssl_command
    }

    // Returns the owner-private pairing trust workspace root.
    pub fn trust_workspace(&self) -> &Path {
        &self.trust_workspace
    }

    // Returns the exact site private-key file.
    pub fn site_private_key_file(&self) -> &Path {
        &self.site_private_key_file
    }

    // Returns the exact site public-key file.
    pub fn site_public_key_file(&self) -> &Path {
        &self.site_public_key_file
    }

    // Returns the exact site CA certificate file.
    pub fn site_ca_certificate_file(&self) -> &Path {
        &self.site_ca_certificate_file
    }

    // Returns the exact local control certificate file.
    pub fn local_control_certificate_file(&self) -> &Path {
        &self.local_control_certificate_file
    }

    // Returns the configured local public-key identity.
    pub const fn public_key_sha256(&self) -> &Sha256Digest {
        &self.public_key_sha256
    }

    // Returns the configured local control-certificate identity.
    pub const fn certificate_sha256(&self) -> &Sha256Digest {
        &self.certificate_sha256
    }
}

// Selects one closed native pairing platform and its Linux-only direct-link inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodePairingPlatform {
    Linux {
        sys_class: PathBuf,
        ip_command: PathBuf,
    },
    Macos,
}

impl WirePairingConfiguration {
    // Converts one closed wire contract without inventing platform-native defaults.
    fn into_configuration(self) -> Result<NodePairingConfiguration, NodeConfigurationError> {
        let platform = match self.operating_system.as_str() {
            "linux" => NodePairingPlatform::Linux {
                sys_class: absolute_path(
                    self.direct_link_sys_class
                        .as_deref()
                        .ok_or(NodeConfigurationError::InvalidConfiguration)?,
                )?,
                ip_command: absolute_path(
                    self.direct_link_ip_command
                        .as_deref()
                        .ok_or(NodeConfigurationError::InvalidConfiguration)?,
                )?,
            },
            "macos"
                if self.direct_link_sys_class.is_none()
                    && self.direct_link_ip_command.is_none() =>
            {
                NodePairingPlatform::Macos
            }
            _ => return Err(NodeConfigurationError::InvalidConfiguration),
        };
        let configuration = NodePairingConfiguration {
            platform,
            setup_secret_file: absolute_path(&self.setup_secret_file)?,
            discovery_command: absolute_path(&self.discovery_command)?,
            openssl_command: absolute_path(&self.openssl_command)?,
            trust_workspace: absolute_path(&self.trust_workspace)?,
            site_private_key_file: absolute_path(&self.site_private_key_file)?,
            site_public_key_file: absolute_path(&self.site_public_key_file)?,
            site_ca_certificate_file: absolute_path(&self.site_ca_certificate_file)?,
            local_control_certificate_file: absolute_path(&self.local_control_certificate_file)?,
            public_key_sha256: Sha256Digest::parse(&self.public_key_sha256)
                .map_err(|_| NodeConfigurationError::InvalidConfiguration)?,
            certificate_sha256: Sha256Digest::parse(&self.certificate_sha256)
                .map_err(|_| NodeConfigurationError::InvalidConfiguration)?,
        };
        let paths = [
            configuration.setup_secret_file(),
            configuration.discovery_command(),
            configuration.openssl_command(),
            configuration.trust_workspace(),
            configuration.site_private_key_file(),
            configuration.site_public_key_file(),
            configuration.site_ca_certificate_file(),
            configuration.local_control_certificate_file(),
        ];
        if paths
            .iter()
            .enumerate()
            .any(|(index, path)| paths[..index].contains(path))
        {
            return Err(NodeConfigurationError::InvalidConfiguration);
        }
        Ok(configuration)
    }
}

// Stores one closed Linux or Apple Silicon native hardware input set.
#[derive(Deserialize)]
#[serde(
    tag = "operating_system",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum WireHardwareConfiguration {
    Linux {
        architecture: String,
        boot_id_file: String,
        cpu_information_file: String,
        memory_information_file: String,
        nvidia_smi_command: Option<String>,
        rdma_command: Option<String>,
    },
    Macos {
        architecture: String,
        sysctl_command: String,
        metal_probe_command: String,
    },
}

impl WireHardwareConfiguration {
    // Converts one platform-tagged document into exact typed native dependencies.
    fn into_configuration(self) -> Result<NodeHardwareConfiguration, NodeConfigurationError> {
        match self {
            Self::Linux {
                architecture,
                boot_id_file,
                cpu_information_file,
                memory_information_file,
                nvidia_smi_command,
                rdma_command,
            } => Ok(NodeHardwareConfiguration::Linux {
                architecture: cpu_architecture(&architecture)?,
                boot_id_file: absolute_path(&boot_id_file)?,
                cpu_information_file: absolute_path(&cpu_information_file)?,
                memory_information_file: absolute_path(&memory_information_file)?,
                nvidia_smi_command: optional_absolute_path(nvidia_smi_command)?,
                rdma_command: optional_absolute_path(rdma_command)?,
            }),
            Self::Macos {
                architecture,
                sysctl_command,
                metal_probe_command,
            } => {
                if architecture != "arm64" {
                    return Err(NodeConfigurationError::InvalidConfiguration);
                }
                Ok(NodeHardwareConfiguration::MacosArm64 {
                    sysctl_command: absolute_path(&sysctl_command)?,
                    metal_probe_command: absolute_path(&metal_probe_command)?,
                })
            }
        }
    }
}

// Selects Linux Watchdog protection or the distinct macOS launchd safety authority.
#[derive(Deserialize)]
#[serde(
    tag = "operating_system",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum WirePlacementSafetyConfiguration {
    Linux {
        socket_path: String,
        maximum_workers: usize,
        read_timeout_milliseconds: u64,
        write_timeout_milliseconds: u64,
        accept_poll_interval_milliseconds: u64,
        protection_root: String,
        watchdog_source_identity: String,
        gateway: WireProtectionExecutable,
        watchdog: WireProtectionExecutable,
        lease_milliseconds: u64,
    },
    Macos,
}

// Stores one exact immutable service executable and its distinct API principal.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireProtectionExecutable {
    path: String,
    executable_sha256: String,
    principal_id: String,
}

impl WirePlacementSafetyConfiguration {
    // Converts one platform-matched closed document into its native safety configuration.
    fn into_configuration(
        self,
        owner_uid: u32,
        hardware: &NodeHardwareConfiguration,
    ) -> Result<NodePlacementSafetyConfiguration, NodeConfigurationError> {
        match (self, hardware) {
            (
                Self::Linux {
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
                },
                NodeHardwareConfiguration::Linux { .. },
            ) => {
                if lease_milliseconds == 0 || lease_milliseconds > 60_000 {
                    return Err(NodeConfigurationError::InvalidConfiguration);
                }
                let local_server = NodeProtectionLocalConfiguration::new(
                    absolute_path(&socket_path)?,
                    owner_uid,
                    maximum_workers,
                    duration(read_timeout_milliseconds)?,
                    duration(write_timeout_milliseconds)?,
                    duration(accept_poll_interval_milliseconds)?,
                )
                .map_err(|_| NodeConfigurationError::InvalidConfiguration)?;
                let gateway =
                    protection_executable(gateway, NodeProtectionConnectionRole::Gateway)?;
                let watchdog =
                    protection_executable(watchdog, NodeProtectionConnectionRole::Watchdog)?;
                if local_server.socket_path() == Path::new(&protection_root)
                    || gateway.canonical_path() == watchdog.canonical_path()
                {
                    return Err(NodeConfigurationError::InvalidConfiguration);
                }
                Ok(NodePlacementSafetyConfiguration::Linux(
                    NodeLinuxProtectionConfiguration {
                        local_server,
                        protection_root: absolute_path(&protection_root)?,
                        watchdog_source_identity: Sha256Digest::parse(&watchdog_source_identity)
                            .map_err(|_| NodeConfigurationError::InvalidConfiguration)?,
                        gateway,
                        watchdog,
                        lease_milliseconds,
                    },
                ))
            }
            (Self::Macos, NodeHardwareConfiguration::MacosArm64 { .. }) => {
                Ok(NodePlacementSafetyConfiguration::MacosLaunchd)
            }
            _ => Err(NodeConfigurationError::InvalidConfiguration),
        }
    }
}

// Converts one immutable executable document into the role-fixed peer-verifier contract.
fn protection_executable(
    executable: WireProtectionExecutable,
    role: NodeProtectionConnectionRole,
) -> Result<ExpectedNodeProtectionExecutable, NodeConfigurationError> {
    ExpectedNodeProtectionExecutable::new(
        absolute_path(&executable.path)?,
        Sha256Digest::parse(&executable.executable_sha256)
            .map_err(|_| NodeConfigurationError::InvalidConfiguration)?,
        CredentialId::parse(&executable.principal_id)
            .map_err(|_| NodeConfigurationError::InvalidConfiguration)?,
        role,
    )
    .map_err(|_| NodeConfigurationError::InvalidConfiguration)
}

// Stores one closed resident cadence configuration.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireDaemonConfiguration {
    cadence_milliseconds: u64,
}

// Stores the two private API listener configurations.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WirePrivateApiConfiguration {
    local: WireLocalPrivateApiConfiguration,
    remote: WireRemotePrivateApiConfiguration,
}

// Stores local Unix listener paths, concurrency, and frame deadlines.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireLocalPrivateApiConfiguration {
    socket_path: String,
    maximum_workers: usize,
    read_timeout_milliseconds: u64,
    write_timeout_milliseconds: u64,
    accept_poll_interval_milliseconds: u64,
}

// Stores remote bind, TLS input, concurrency, and absolute operation deadlines.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRemotePrivateApiConfiguration {
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

// Converts one positive millisecond value without unit ambiguity.
fn duration(milliseconds: u64) -> Result<Duration, NodeConfigurationError> {
    if milliseconds == 0 {
        return Err(NodeConfigurationError::InvalidConfiguration);
    }
    Ok(Duration::from_millis(milliseconds))
}

// Parses one bounded absolute native path without accepting control characters.
fn absolute_path(value: &str) -> Result<PathBuf, NodeConfigurationError> {
    if value.is_empty()
        || value.len() > 4096
        || value.chars().any(char::is_control)
        || !Path::new(value).is_absolute()
    {
        return Err(NodeConfigurationError::InvalidConfiguration);
    }
    Ok(PathBuf::from(value))
}

// Parses one absolute path whose lexical identity cannot hide traversal or platform prefixes.
fn normal_absolute_path(value: &str) -> Result<PathBuf, NodeConfigurationError> {
    let path = absolute_path(value)?;
    if path
        .components()
        .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(NodeConfigurationError::InvalidConfiguration);
    }
    Ok(path)
}

// Requires one bounded certificate identity without whitespace, control bytes, or separators.
fn valid_server_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .chars()
            .all(|character| !character.is_control() && !character.is_whitespace())
}

// Requires every mutable benchmark root to own one disjoint subtree.
fn paths_are_disjoint(paths: &[&Path]) -> bool {
    paths.iter().enumerate().all(|(index, path)| {
        paths
            .iter()
            .skip(index + 1)
            .all(|other| !path.starts_with(other) && !other.starts_with(path))
    })
}

// Parses one optional native dependency without discovering a substitute.
fn optional_absolute_path(
    value: Option<String>,
) -> Result<Option<PathBuf>, NodeConfigurationError> {
    value.as_deref().map(absolute_path).transpose()
}

// Parses the two Linux CPU architectures distributed by Let's Infer.
fn cpu_architecture(value: &str) -> Result<CpuArchitecture, NodeConfigurationError> {
    match value {
        "arm64" => Ok(CpuArchitecture::Arm64),
        "x86_64" => Ok(CpuArchitecture::X86_64),
        _ => Err(NodeConfigurationError::InvalidConfiguration),
    }
}

// Opens, reads, and revalidates one exact no-follow configuration descriptor.
fn read_system_configuration_file(
    path: &Path,
    maximum_bytes: usize,
) -> Result<NodeConfigurationFile, NodeConfigurationError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| NodeConfigurationError::FileUnavailable)?;
    let before = file
        .metadata()
        .map_err(|_| NodeConfigurationError::FileUnavailable)?;
    if before.len() > maximum_bytes as u64 {
        return Err(NodeConfigurationError::DocumentTooLarge);
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take((maximum_bytes as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| NodeConfigurationError::FileUnavailable)?;
    if bytes.len() > maximum_bytes {
        return Err(NodeConfigurationError::DocumentTooLarge);
    }
    let after = file
        .metadata()
        .map_err(|_| NodeConfigurationError::FileUnavailable)?;
    if !same_file_observation(&before, &after) || after.len() != bytes.len() as u64 {
        return Err(NodeConfigurationError::UnsafeFile);
    }
    Ok(NodeConfigurationFile::new(
        after.uid(),
        after.mode() & 0o777,
        after.nlink(),
        after.file_type().is_file(),
        bytes,
    ))
}

// Returns whether one descriptor retained the exact native identity throughout its read.
fn same_file_observation(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.uid() == after.uid()
        && before.mode() == after.mode()
        && before.nlink() == after.nlink()
        && before.len() == after.len()
}
