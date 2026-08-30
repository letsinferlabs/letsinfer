// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use li_authentication_manager::ControllerRole;
use li_core_cli::{
    compose_system_native_node_cli, CliExitCode, CommandFailure, CommandProgressPort,
    NativeControllerEnrollmentCommitPort, NativeControllerEnrollmentPort,
    NativeNodeCliCompositionError, NativeNodePairingEndpoint, NativeNodePairingJoinRequest,
    NativeNodePairingPort, NodePrivateClient, NodePrivateClientConfiguration,
    PairedMainChildLifecycle, SystemNativeNodeCliProcess, SystemNodePrivateDocumentExchange,
    SystemNodeRequestIdentitySource,
};
use li_core_interface::{Node, NodeAddress, NodeRole, Sha256Digest};
use li_core_update_manager::{
    CoreInstallation, CoreUpdateNodeRole, CoreUpdateReleasePlatform, CoreUpdateServiceContext,
    CoreUpdateServicePlatform, CoreVersion,
};
use li_node_manager::{
    NodeConfiguration, NodeConfigurationFileReference, NodePairedChildActivationRequest,
    NodePairedMainRestorationRequest, NodePairingCancellation, NodePairingPlatform,
    NodePrivateRemoteClientFileSet, NodePrivateRequest, NodePrivateResponse,
    SystemNodeConfigurationFileProvider, SystemNodePairingClient, SystemNodePrivateRemoteClient,
};
use li_pairing_manager::{
    NativePairingDiscoveryBrowser, OpenSslPairingCandidateTrustProvider,
    PairingCandidateIdentityFiles, PairingCandidateTrustProvider, PairingDiscoveryPlatform,
    PairingNativeCommandRunner, PairingTrustWorkspaceIo, SystemPairingClock,
    SystemPairingMaterialProvider, SystemPairingNativeCommandRunner, SystemPairingTrustWorkspaceIo,
    PAIRING_DISCOVERY_PORT,
};
use serde::Deserialize;

use crate::{
    compose_system_core_controller_enrollment, ApplicationCoreCliPairing,
    CoreControllerEnrollmentConfiguration, CoreGatewayServiceHealth, CoreNodeServiceHealth,
    CorePairedNodeDocumentExchange, CorePairingActivationAuthorityPort,
    CorePairingActivationCoordinator, CorePairingActivationError, CorePairingActivationService,
    CoreResidentProcess, CoreServiceSetupError, CoreServiceSetupObservation,
    CoreServiceSetupResidentHealth, CoreWatchdogHealthTlsFiles, CoreWatchdogServiceHealth,
    LazySystemCoreCliUninstall, SystemCoreCliPairingEntropy, SystemCoreCliPairingSetupCode,
    SystemCorePairingActivationConfiguration, SystemCorePairingActivationConfirmation,
    SystemCorePairingActivationStore, SystemCorePairingActivationWaiter,
    SystemCoreServiceSetupComposition, SystemCoreUninstallNativeRemoval,
    GATEWAY_CONFIGURATION_FILENAME, NODE_CONFIGURATION_FILENAME, WATCHDOG_CONFIGURATION_FILENAME,
};

pub const CORE_CLI_CONFIGURATION_SCHEMA_NAME: &str = "li_core_cli_configuration";
pub const CORE_CLI_CONFIGURATION_SCHEMA_VERSION: u32 = 4;
pub const CORE_CLI_CONFIGURATION_FILENAME: &str = "li_core_cli_configuration.json";
pub const MAXIMUM_CORE_CLI_CONFIGURATION_BYTES: usize = 16 * 1024;

const CONFIGURATION_FLAG: &str = "--configuration";
const COMMAND_SEPARATOR: &str = "--";

// Carries one retained descriptor observation from the configuration I/O boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreCliConfigurationFile {
    owner_user_id: u32,
    mode: u32,
    link_count: u64,
    regular_file: bool,
    bytes: Vec<u8>,
}

impl CoreCliConfigurationFile {
    // Creates one descriptor-shaped observation for production or deterministic tests.
    pub fn new(
        owner_user_id: u32,
        mode: u32,
        link_count: u64,
        regular_file: bool,
        bytes: Vec<u8>,
    ) -> Self {
        Self {
            owner_user_id,
            mode,
            link_count,
            regular_file,
            bytes,
        }
    }
}

// Supplies one exact no-follow configuration read without granting process policy to I/O.
pub trait CoreCliConfigurationFileProvider {
    // Reads one bounded file while preserving its descriptor identity through the complete read.
    fn read_no_follow(
        &self,
        path: &Path,
        maximum_bytes: usize,
    ) -> Result<CoreCliConfigurationFile, CoreCliProcessError>;
}

// Reads the ordinary owner-only configuration through one no-follow close-on-exec descriptor.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemCoreCliConfigurationFileProvider;

impl CoreCliConfigurationFileProvider for SystemCoreCliConfigurationFileProvider {
    // Opens and revalidates one exact file without copying native diagnostics into errors.
    fn read_no_follow(
        &self,
        path: &Path,
        maximum_bytes: usize,
    ) -> Result<CoreCliConfigurationFile, CoreCliProcessError> {
        read_system_configuration_file(path, maximum_bytes)
    }
}

// Holds the complete minimal client configuration consumed by the public native process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreCliConfiguration {
    local_node_socket: PathBuf,
    entropy_source: PathBuf,
    client: NodePrivateClientConfiguration,
    pairing: CoreCliPairingConfiguration,
    uninstall: CoreCliUninstallConfiguration,
    remote_main: Option<CoreCliRemoteMainConfiguration>,
}

// Holds the exact installed launcher and optional shell-free privilege authority for teardown.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreCliUninstallConfiguration {
    launcher_file: PathBuf,
    privilege_command: Option<PathBuf>,
}

impl CoreCliUninstallConfiguration {
    // Returns the exact launcher file installed by the signed bootstrap.
    pub fn launcher_file(&self) -> &Path {
        &self.launcher_file
    }

    // Returns the exact privilege executable required to retire a system-owned launcher.
    pub fn privilege_command(&self) -> Option<&Path> {
        self.privilege_command.as_deref()
    }
}

// Holds every explicit owner-only input required to compose native pairing and role cutover.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreCliPairingConfiguration {
    node_configuration_file: PathBuf,
    installation: CoreInstallation,
    watchdog_health: Option<CoreCliWatchdogHealthConfiguration>,
}

// Holds Linux-only Watchdog health identities needed during atomic service-role cutover.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreCliWatchdogHealthConfiguration {
    authority_certificate_file: PathBuf,
    controller_certificate_file: PathBuf,
    controller_private_key_file: PathBuf,
}

impl CoreCliPairingConfiguration {
    // Returns the exact owner-only Node configuration consumed by production composition.
    pub fn node_configuration_file(&self) -> &Path {
        &self.node_configuration_file
    }

    // Returns the immutable signed Core installation used for atomic service activation.
    pub const fn installation(&self) -> &CoreInstallation {
        &self.installation
    }

    // Returns Linux Watchdog health material or absence on macOS.
    pub const fn watchdog_health(&self) -> Option<&CoreCliWatchdogHealthConfiguration> {
        self.watchdog_health.as_ref()
    }
}

impl CoreCliWatchdogHealthConfiguration {
    // Returns the exact Watchdog server authority certificate path.
    pub fn authority_certificate_file(&self) -> &Path {
        &self.authority_certificate_file
    }

    // Returns the exact Watchdog health-controller certificate path.
    pub fn controller_certificate_file(&self) -> &Path {
        &self.controller_certificate_file
    }

    // Returns the exact owner-only Watchdog health-controller private-key path.
    pub fn controller_private_key_file(&self) -> &Path {
        &self.controller_private_key_file
    }
}

// Holds one exact paired-main endpoint and child identity reference for lifecycle commands.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreCliRemoteMainConfiguration {
    address: NodeAddress,
    port: u16,
    server_certificate_sha256: Sha256Digest,
    client_certificate_file: PathBuf,
    client_private_key_file: PathBuf,
}

impl CoreCliRemoteMainConfiguration {
    // Returns the exact paired main address without DNS discovery.
    pub const fn address(&self) -> &NodeAddress {
        &self.address
    }

    // Returns the exact paired main private Node listener port.
    pub const fn port(&self) -> u16 {
        self.port
    }

    // Returns the exact pairing-bound main server leaf identity.
    pub const fn server_certificate_sha256(&self) -> &Sha256Digest {
        &self.server_certificate_sha256
    }

    // Returns the exact owner-only child certificate path.
    pub fn client_certificate_file(&self) -> &Path {
        &self.client_certificate_file
    }

    // Returns the exact existing local identity private-key path.
    pub fn client_private_key_file(&self) -> &Path {
        &self.client_private_key_file
    }
}

impl CoreCliConfiguration {
    // Loads one closed owner-only document without consulting Node persistence or resident state.
    pub fn load(
        path: &Path,
        owner_user_id: u32,
        provider: &dyn CoreCliConfigurationFileProvider,
    ) -> Result<Self, CoreCliProcessError> {
        if !path.is_absolute() {
            return Err(CoreCliProcessError::InvalidArguments);
        }
        let file = provider.read_no_follow(path, MAXIMUM_CORE_CLI_CONFIGURATION_BYTES)?;
        if file.owner_user_id != owner_user_id
            || file.mode != 0o600
            || file.link_count != 1
            || !file.regular_file
        {
            return Err(CoreCliProcessError::ConfigurationUnavailable);
        }
        if file.bytes.len() > MAXIMUM_CORE_CLI_CONFIGURATION_BYTES {
            return Err(CoreCliProcessError::ConfigurationUnavailable);
        }
        let wire: WireCoreCliConfiguration = serde_json::from_slice(&file.bytes)
            .map_err(|_| CoreCliProcessError::ConfigurationUnavailable)?;
        wire.into_configuration()
    }

    // Returns the exact local Node socket without discovering a per-platform default.
    pub fn local_node_socket(&self) -> &Path {
        &self.local_node_socket
    }

    // Returns the explicit request-identity entropy source without selecting a fallback.
    pub fn entropy_source(&self) -> &Path {
        &self.entropy_source
    }

    // Returns the complete bounded private client contract.
    pub const fn client(&self) -> NodePrivateClientConfiguration {
        self.client
    }

    // Returns the complete owner-only native pairing composition contract.
    pub const fn pairing(&self) -> &CoreCliPairingConfiguration {
        &self.pairing
    }

    // Returns every exact immutable-retirement authority supplied by the signed installer.
    pub const fn uninstall(&self) -> &CoreCliUninstallConfiguration {
        &self.uninstall
    }

    // Returns paired-main lifecycle configuration only for an activated child.
    pub const fn remote_main(&self) -> Option<&CoreCliRemoteMainConfiguration> {
        self.remote_main.as_ref()
    }
}

// Stores the nested stable schema identity of one CLI configuration document.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireSchema {
    name: String,
    version: u32,
}

// Stores explicit local transport and client bounds without resident-only configuration fields.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireCoreCliConfiguration {
    schema: WireSchema,
    local_node_socket: String,
    entropy_source: String,
    client: WireCoreCliClientConfiguration,
    pairing: WireCoreCliPairingConfiguration,
    uninstall: WireCoreCliUninstallConfiguration,
    remote_main: Option<WireCoreCliRemoteMainConfiguration>,
}

// Stores the exact launcher file and optional native privilege command without arguments.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireCoreCliUninstallConfiguration {
    launcher_file: String,
    privilege_command: Option<String>,
}

// Stores explicit native pairing and immutable installation inputs without credential bytes.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireCoreCliPairingConfiguration {
    node_configuration_file: String,
    installation: WireCoreCliInstallation,
    watchdog_health: Option<WireCoreCliWatchdogHealthConfiguration>,
}

// Stores one exact immutable Core installation selected by the signed installer.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireCoreCliInstallation {
    version: String,
    source_identity: String,
}

// Stores exact Linux Watchdog health file references without certificate or key bytes.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireCoreCliWatchdogHealthConfiguration {
    authority_certificate_file: String,
    controller_certificate_file: String,
    controller_private_key_file: String,
}

// Stores one exact paired-main mTLS endpoint without secret bytes.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireCoreCliRemoteMainConfiguration {
    address: String,
    port: u16,
    server_certificate_sha256: String,
    client_certificate_file: String,
    client_private_key_file: String,
}

impl WireCoreCliConfiguration {
    // Converts one closed document into the canonical internal client configuration.
    fn into_configuration(self) -> Result<CoreCliConfiguration, CoreCliProcessError> {
        if self.schema.name != CORE_CLI_CONFIGURATION_SCHEMA_NAME
            || self.schema.version != CORE_CLI_CONFIGURATION_SCHEMA_VERSION
        {
            return Err(CoreCliProcessError::ConfigurationUnavailable);
        }
        let local_node_socket = absolute_path(&self.local_node_socket)?;
        let entropy_source = absolute_path(&self.entropy_source)?;
        if local_node_socket == entropy_source {
            return Err(CoreCliProcessError::ConfigurationUnavailable);
        }
        let client = NodePrivateClientConfiguration::new(
            Duration::from_millis(self.client.timeout_milliseconds),
            self.client.maximum_response_bytes,
        )
        .map_err(|_| CoreCliProcessError::ConfigurationUnavailable)?;
        let pairing = self.pairing.into_configuration()?;
        if [local_node_socket.as_path(), entropy_source.as_path()]
            .contains(&pairing.node_configuration_file.as_path())
        {
            return Err(CoreCliProcessError::ConfigurationUnavailable);
        }
        let launcher_file = absolute_path(&self.uninstall.launcher_file)?;
        let privilege_command = self
            .uninstall
            .privilege_command
            .map(|value| absolute_path(&value))
            .transpose()?;
        if launcher_file == local_node_socket
            || launcher_file == entropy_source
            || launcher_file == pairing.node_configuration_file
            || privilege_command.as_ref().is_some_and(|command| {
                command == &launcher_file
                    || command == &local_node_socket
                    || command == &entropy_source
                    || command == &pairing.node_configuration_file
            })
        {
            return Err(CoreCliProcessError::ConfigurationUnavailable);
        }
        let uninstall = CoreCliUninstallConfiguration {
            launcher_file,
            privilege_command,
        };
        let remote_main = self
            .remote_main
            .map(|remote| {
                let client_certificate_file = absolute_path(&remote.client_certificate_file)?;
                let client_private_key_file = absolute_path(&remote.client_private_key_file)?;
                if remote.port == 0
                    || client_certificate_file == client_private_key_file
                    || [local_node_socket.as_path(), entropy_source.as_path()]
                        .contains(&client_certificate_file.as_path())
                    || [local_node_socket.as_path(), entropy_source.as_path()]
                        .contains(&client_private_key_file.as_path())
                {
                    return Err(CoreCliProcessError::ConfigurationUnavailable);
                }
                Ok(CoreCliRemoteMainConfiguration {
                    address: NodeAddress::parse(&remote.address)
                        .map_err(|_| CoreCliProcessError::ConfigurationUnavailable)?,
                    port: remote.port,
                    server_certificate_sha256: Sha256Digest::parse(
                        &remote.server_certificate_sha256,
                    )
                    .map_err(|_| CoreCliProcessError::ConfigurationUnavailable)?,
                    client_certificate_file,
                    client_private_key_file,
                })
            })
            .transpose()?;
        Ok(CoreCliConfiguration {
            local_node_socket,
            entropy_source,
            client,
            pairing,
            uninstall,
            remote_main,
        })
    }
}

impl WireCoreCliPairingConfiguration {
    // Converts one closed pairing document into exact native paths and release identity.
    fn into_configuration(self) -> Result<CoreCliPairingConfiguration, CoreCliProcessError> {
        let node_configuration_file = absolute_path(&self.node_configuration_file)?;
        let installation = CoreInstallation::new(
            CoreVersion::parse(&self.installation.version)
                .map_err(|_| CoreCliProcessError::ConfigurationUnavailable)?,
            Sha256Digest::parse(&self.installation.source_identity)
                .map_err(|_| CoreCliProcessError::ConfigurationUnavailable)?,
        );
        let watchdog_health = self
            .watchdog_health
            .map(|value| {
                let authority_certificate_file = absolute_path(&value.authority_certificate_file)?;
                let controller_certificate_file =
                    absolute_path(&value.controller_certificate_file)?;
                let controller_private_key_file =
                    absolute_path(&value.controller_private_key_file)?;
                let paths = [
                    authority_certificate_file.as_path(),
                    controller_certificate_file.as_path(),
                    controller_private_key_file.as_path(),
                ];
                if paths
                    .iter()
                    .enumerate()
                    .any(|(index, path)| paths[..index].contains(path))
                {
                    return Err(CoreCliProcessError::ConfigurationUnavailable);
                }
                Ok(CoreCliWatchdogHealthConfiguration {
                    authority_certificate_file,
                    controller_certificate_file,
                    controller_private_key_file,
                })
            })
            .transpose()?;
        Ok(CoreCliPairingConfiguration {
            node_configuration_file,
            installation,
            watchdog_health,
        })
    }
}

// Stores the complete-request deadline and response allocation bound.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireCoreCliClientConfiguration {
    timeout_milliseconds: u64,
    maximum_response_bytes: usize,
}

// Holds the private configuration path and untouched public command argument vector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreCliProcessArguments {
    configuration_file: PathBuf,
    command_arguments: Vec<String>,
}

impl CoreCliProcessArguments {
    // Parses exactly `--configuration ABSOLUTE_PATH -- COMMAND...` without aliases or extras.
    pub fn parse(
        arguments: impl IntoIterator<Item = OsString>,
    ) -> Result<Self, CoreCliProcessError> {
        let arguments = arguments.into_iter().collect::<Vec<_>>();
        if arguments.len() < 4
            || arguments[0] != OsStr::new(CONFIGURATION_FLAG)
            || arguments[2] != OsStr::new(COMMAND_SEPARATOR)
        {
            return Err(CoreCliProcessError::InvalidArguments);
        }
        let configuration_file = PathBuf::from(&arguments[1]);
        if !configuration_file.is_absolute() {
            return Err(CoreCliProcessError::InvalidArguments);
        }
        let command_arguments = arguments[3..]
            .iter()
            .map(|argument| {
                argument
                    .to_str()
                    .map(str::to_owned)
                    .ok_or(CoreCliProcessError::InvalidArguments)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if command_arguments.is_empty() {
            return Err(CoreCliProcessError::InvalidArguments);
        }
        Ok(Self {
            configuration_file,
            command_arguments,
        })
    }

    // Returns the owner-only minimal CLI configuration selected by the installed launcher.
    pub fn configuration_file(&self) -> &Path {
        &self.configuration_file
    }

    // Returns the ordinary public or internal command arguments after the private separator.
    pub fn command_arguments(&self) -> &[String] {
        &self.command_arguments
    }
}

// Supplies the hidden bootstrap prefix from one immutable installed Core executable layout.
pub fn installed_core_cli_arguments(
    executable_file: &Path,
    command_arguments: impl IntoIterator<Item = OsString>,
) -> Result<Vec<OsString>, CoreCliProcessError> {
    let bin = executable_file
        .parent()
        .filter(|path| path.file_name() == Some(OsStr::new("bin")))
        .ok_or(CoreCliProcessError::InvalidArguments)?;
    if executable_file.file_name() != Some(OsStr::new("li_letsinfer")) {
        return Err(CoreCliProcessError::InvalidArguments);
    }
    let _source_identity = bin
        .parent()
        .and_then(Path::file_name)
        .and_then(OsStr::to_str)
        .filter(|value| valid_sha256(value))
        .ok_or(CoreCliProcessError::InvalidArguments)?;
    let version_root = bin
        .parent()
        .and_then(Path::parent)
        .ok_or(CoreCliProcessError::InvalidArguments)?;
    let version = version_root
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or(CoreCliProcessError::InvalidArguments)?;
    CoreVersion::parse(version).map_err(|_| CoreCliProcessError::InvalidArguments)?;
    let versions = version_root
        .parent()
        .filter(|path| path.file_name() == Some(OsStr::new("versions")))
        .ok_or(CoreCliProcessError::InvalidArguments)?;
    let core = versions
        .parent()
        .filter(|path| path.file_name() == Some(OsStr::new("core")))
        .ok_or(CoreCliProcessError::InvalidArguments)?;
    let letsinfer_home = core
        .parent()
        .filter(|path| path.is_absolute() && *path != Path::new("/"))
        .ok_or(CoreCliProcessError::InvalidArguments)?;
    let configuration_file = letsinfer_home
        .join("configuration")
        .join(CORE_CLI_CONFIGURATION_FILENAME);
    let mut arguments = vec![
        OsString::from(CONFIGURATION_FLAG),
        configuration_file.into_os_string(),
        OsString::from(COMMAND_SEPARATOR),
    ];
    arguments.extend(command_arguments);
    Ok(arguments)
}

// Describes one stable process composition failure without retaining native paths or documents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreCliProcessError {
    InvalidArguments,
    ConfigurationUnavailable,
    CompositionUnavailable,
}

impl fmt::Display for CoreCliProcessError {
    // Presents fixed process language suitable for the external launcher boundary.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArguments => {
                formatter.write_str("li_letsinfer bootstrap arguments are invalid")
            }
            Self::ConfigurationUnavailable => {
                formatter.write_str("li_letsinfer configuration is unavailable")
            }
            Self::CompositionUnavailable => {
                formatter.write_str("li_letsinfer native process composition is unavailable")
            }
        }
    }
}

impl Error for CoreCliProcessError {}

// Lazily owns production pairing so unrelated CLI leaves never open pairing state or service ports.
struct SystemCoreCliPairing {
    configuration: CoreCliPairingConfiguration,
    local_node_socket: PathBuf,
    entropy_source: PathBuf,
    client: NodePrivateClientConfiguration,
    owner_user_id: u32,
    composed: OnceLock<Result<Arc<ApplicationCoreCliPairing>, CoreCliProcessError>>,
}

impl SystemCoreCliPairing {
    // Retains only validated owner configuration until a Node pairing leaf is invoked.
    const fn new(
        configuration: CoreCliPairingConfiguration,
        local_node_socket: PathBuf,
        entropy_source: PathBuf,
        client: NodePrivateClientConfiguration,
        owner_user_id: u32,
    ) -> Self {
        Self {
            configuration,
            local_node_socket,
            entropy_source,
            client,
            owner_user_id,
            composed: OnceLock::new(),
        }
    }

    // Returns one shared exact production composition or its stable cached failure.
    fn pairing(&self) -> Result<&Arc<ApplicationCoreCliPairing>, CommandFailure> {
        self.composed
            .get_or_init(|| {
                compose_system_core_cli_pairing(
                    &self.configuration,
                    &self.local_node_socket,
                    &self.entropy_source,
                    self.client,
                    self.owner_user_id,
                )
            })
            .as_ref()
            .map_err(|_| pairing_composition_failure())
    }
}

impl NativeNodePairingPort for SystemCoreCliPairing {
    // Returns the endpoint from the same lazy production composition used by every mutation.
    fn local_endpoint(&self) -> Result<NativeNodePairingEndpoint, CommandFailure> {
        self.pairing()?.local_endpoint()
    }

    // Runs candidate-offer preflight through the exact configured production provider.
    fn connectx_mode(
        &self,
        direct_interface: &li_core_interface::NetworkInterfaceName,
        timeout: Duration,
    ) -> Result<li_node_manager::NodePairingMode, CommandFailure> {
        self.pairing()?.connectx_mode(direct_interface, timeout)
    }

    // Runs discovery, proof, enrollment, and atomic child activation through one composition.
    fn join(
        &self,
        request: &NativeNodePairingJoinRequest,
        progress: &mut dyn CommandProgressPort,
    ) -> Result<Node, CommandFailure> {
        self.pairing()?.join(request, progress)
    }
}

// Owns one serialized owner-authenticated Node connection for pairing authority and snapshots.
struct CoreCliPairingAuthorityClient {
    client: Mutex<
        NodePrivateClient<SystemNodePrivateDocumentExchange, SystemNodeRequestIdentitySource>,
    >,
}

impl CoreCliPairingAuthorityClient {
    // Opens only the configured local Node endpoint and explicit entropy source.
    fn open(
        local_node_socket: &Path,
        entropy_source: &Path,
        configuration: NodePrivateClientConfiguration,
    ) -> Result<Self, CoreCliProcessError> {
        let exchange = SystemNodePrivateDocumentExchange::open(local_node_socket.to_path_buf())
            .map_err(|_| CoreCliProcessError::CompositionUnavailable)?;
        let identity = SystemNodeRequestIdentitySource::open(entropy_source)
            .map_err(|_| CoreCliProcessError::CompositionUnavailable)?;
        Ok(Self {
            client: Mutex::new(NodePrivateClient::new(exchange, identity, configuration)),
        })
    }

    // Executes one typed owner-local request without opening persistence or another transport.
    fn execute(
        &self,
        request: NodePrivateRequest,
    ) -> Result<NodePrivateResponse, CorePairingActivationError> {
        self.client
            .lock()
            .map_err(|_| CorePairingActivationError::RoleUnavailable)?
            .execute(request)
            .map_err(|_| CorePairingActivationError::RoleUnavailable)
    }
}

impl CorePairingActivationAuthorityPort for CoreCliPairingAuthorityClient {
    // Reads the exact local Node from the resident owner.
    fn local_node(&self) -> Result<Node, CorePairingActivationError> {
        match self.execute(NodePrivateRequest::ReadLocalNode)? {
            NodePrivateResponse::LocalNode(local) => Ok(local),
            _ => Err(CorePairingActivationError::RoleUnavailable),
        }
    }

    // Reads the complete bounded Node snapshot from the same resident owner.
    fn nodes(&self) -> Result<Vec<Node>, CorePairingActivationError> {
        match self.execute(NodePrivateRequest::ReadNodes)? {
            NodePrivateResponse::Nodes(nodes) => Ok(nodes),
            _ => Err(CorePairingActivationError::RoleUnavailable),
        }
    }

    // Delegates one atomic child-authority transition to Node and validates the response shape.
    fn activate_paired_child(
        &self,
        request: NodePairedChildActivationRequest,
    ) -> Result<(), CorePairingActivationError> {
        match self.execute(NodePrivateRequest::ActivatePairedChild(request))? {
            NodePrivateResponse::PairingAuthorityChanged(receipt)
                if receipt.local().role() == NodeRole::Child
                    && receipt.local().state() == li_core_interface::NodeState::Active =>
            {
                Ok(())
            }
            _ => Err(CorePairingActivationError::RoleUnavailable),
        }
    }

    // Delegates one exact restoration to Node and validates the restored local role.
    fn restore_paired_main(
        &self,
        request: NodePairedMainRestorationRequest,
    ) -> Result<(), CorePairingActivationError> {
        match self.execute(NodePrivateRequest::RestorePairedMain(request))? {
            NodePrivateResponse::PairingAuthorityChanged(receipt)
                if receipt.local().role() == NodeRole::Main
                    && receipt.local().state() == li_core_interface::NodeState::Active =>
            {
                Ok(())
            }
            _ => Err(CorePairingActivationError::RecoveryRequired),
        }
    }
}

// Routes service health through the exact resident configuration selected by role cutover.
struct CoreCliPairingResidentHealth {
    platform: CoreUpdateServicePlatform,
    configuration_root: PathBuf,
    owner_user_id: u32,
    watchdog_health: Option<CoreWatchdogHealthTlsFiles>,
}

impl CoreServiceSetupResidentHealth for CoreCliPairingResidentHealth {
    // Loads the process-owned closed configuration only when its resident is observed.
    fn observe(
        &self,
        context: CoreUpdateServiceContext,
        process: CoreResidentProcess,
        timeout: Duration,
    ) -> Result<CoreServiceSetupObservation, CoreServiceSetupError> {
        if context.platform() != self.platform || timeout.is_zero() {
            return Err(CoreServiceSetupError::InvalidContract {
                reason: "pairing resident health context is invalid",
            });
        }
        match process {
            CoreResidentProcess::Node => CoreNodeServiceHealth::load(
                self.configuration_root.join(NODE_CONFIGURATION_FILENAME),
                self.owner_user_id,
            )?
            .observe(context, process, timeout),
            CoreResidentProcess::Gateway => CoreGatewayServiceHealth::load(
                self.configuration_root.join(GATEWAY_CONFIGURATION_FILENAME),
                self.owner_user_id,
            )?
            .observe(context, process, timeout),
            CoreResidentProcess::Watchdog => {
                let files =
                    self.watchdog_health
                        .clone()
                        .ok_or(CoreServiceSetupError::InvalidContract {
                            reason: "pairing Watchdog health material is unavailable",
                        })?;
                CoreWatchdogServiceHealth::load(
                    self.configuration_root
                        .join(WATCHDOG_CONFIGURATION_FILENAME),
                    self.owner_user_id,
                    files,
                )?
                .observe(context, process, timeout)
            }
        }
    }
}

// Composes controller enrollment only for a configured main with Linux controller authority.
fn compose_system_core_cli_controller_enrollment(
    input: &CoreCliPairingConfiguration,
    owner_user_id: u32,
    local_node_socket: &Path,
    entropy_source: &Path,
    client_configuration: NodePrivateClientConfiguration,
) -> Result<Option<Arc<dyn NativeControllerEnrollmentPort>>, CoreCliProcessError> {
    let reference =
        NodeConfigurationFileReference::new(input.node_configuration_file.clone(), owner_user_id)
            .map_err(|_| CoreCliProcessError::ConfigurationUnavailable)?;
    let configuration = NodeConfiguration::load(&reference, &SystemNodeConfigurationFileProvider)
        .map_err(|_| CoreCliProcessError::ConfigurationUnavailable)?;
    let Some(benchmark) = configuration.benchmark() else {
        return Ok(None);
    };
    let exchange = SystemNodePrivateDocumentExchange::open(local_node_socket.to_path_buf())
        .map_err(|_| CoreCliProcessError::CompositionUnavailable)?;
    let identity = SystemNodeRequestIdentitySource::open(entropy_source)
        .map_err(|_| CoreCliProcessError::CompositionUnavailable)?;
    let mut client = NodePrivateClient::new(exchange, identity, client_configuration);
    let local = match client
        .execute(NodePrivateRequest::ReadLocalNode)
        .map_err(|_| CoreCliProcessError::CompositionUnavailable)?
    {
        NodePrivateResponse::LocalNode(local) => local,
        _ => return Err(CoreCliProcessError::CompositionUnavailable),
    };
    if local.role() != NodeRole::Main {
        return Ok(None);
    }
    let remote_address = configuration.remote_server().bind_address();
    let controller_address =
        std::net::SocketAddr::new(remote_address.ip(), crate::CORE_CONTROLLER_ENROLLMENT_PORT);
    let controller = CoreControllerEnrollmentConfiguration::new(
        local.identity().installation_id().clone(),
        controller_address,
        benchmark.watchdog().port(),
        remote_address.port(),
        benchmark
            .watchdog()
            .enrollment_server_certificate_file()
            .to_path_buf(),
        benchmark
            .watchdog()
            .enrollment_server_private_key_file()
            .to_path_buf(),
        benchmark.watchdog().ca_file().to_path_buf(),
    )
    .map_err(|_| CoreCliProcessError::ConfigurationUnavailable)?;
    Ok(Some(compose_system_core_controller_enrollment(controller)))
}

// Composes the existing pairing provider from one validated owner-only CLI contract.
fn compose_system_core_cli_pairing(
    input: &CoreCliPairingConfiguration,
    local_node_socket: &Path,
    entropy_source: &Path,
    client_configuration: NodePrivateClientConfiguration,
    owner_user_id: u32,
) -> Result<Arc<ApplicationCoreCliPairing>, CoreCliProcessError> {
    let reference =
        NodeConfigurationFileReference::new(input.node_configuration_file.clone(), owner_user_id)
            .map_err(|_| CoreCliProcessError::ConfigurationUnavailable)?;
    let configuration = NodeConfiguration::load(&reference, &SystemNodeConfigurationFileProvider)
        .map_err(|_| CoreCliProcessError::ConfigurationUnavailable)?;
    let authority = Arc::new(CoreCliPairingAuthorityClient::open(
        local_node_socket,
        entropy_source,
        client_configuration,
    )?);
    let local = authority
        .local_node()
        .map_err(|_| CoreCliProcessError::CompositionUnavailable)?;
    let pairing = configuration.pairing();
    let runner: Arc<dyn PairingNativeCommandRunner> = Arc::new(SystemPairingNativeCommandRunner);
    let workspace: Arc<dyn PairingTrustWorkspaceIo> = Arc::new(SystemPairingTrustWorkspaceIo);
    let material = Arc::new(SystemPairingMaterialProvider);
    let trust: Arc<dyn PairingCandidateTrustProvider> = Arc::new(
        OpenSslPairingCandidateTrustProvider::new(
            pairing.openssl_command().to_path_buf(),
            PairingCandidateIdentityFiles::new(
                pairing.site_private_key_file().to_path_buf(),
                pairing.site_public_key_file().to_path_buf(),
            )
            .map_err(|_| CoreCliProcessError::ConfigurationUnavailable)?,
            pairing
                .trust_workspace()
                .parent()
                .ok_or(CoreCliProcessError::ConfigurationUnavailable)?
                .join("pairing_candidate_staging"),
            owner_user_id,
            runner.clone(),
            workspace,
            material,
        )
        .map_err(|_| CoreCliProcessError::CompositionUnavailable)?,
    );
    let discovery_platform = match pairing.platform() {
        NodePairingPlatform::Linux { .. } => PairingDiscoveryPlatform::LinuxAvahi,
        NodePairingPlatform::Macos => PairingDiscoveryPlatform::MacosBonjour,
    };
    let discovery = Arc::new(
        NativePairingDiscoveryBrowser::new(
            discovery_platform,
            pairing.discovery_command().to_path_buf(),
            runner,
        )
        .map_err(|_| CoreCliProcessError::CompositionUnavailable)?,
    );
    let clock = Arc::new(SystemPairingClock);
    let cancellation = Arc::new(NodePairingCancellation::default());
    let platform = service_platform(configuration.core_update().release_platform());
    let watchdog_health = watchdog_health(input, platform, owner_user_id)?;
    let health = Arc::new(CoreCliPairingResidentHealth {
        platform,
        configuration_root: configuration
            .core_update()
            .configuration_root()
            .to_path_buf(),
        owner_user_id,
        watchdog_health,
    });
    let main_services = Arc::new(
        SystemCoreServiceSetupComposition::compose(
            CoreUpdateServiceContext::new(platform, CoreUpdateNodeRole::Main),
            configuration.core_update().letsinfer_home().to_path_buf(),
            configuration
                .core_update()
                .configuration_root()
                .to_path_buf(),
            configuration.core_update().home_directory().to_path_buf(),
            &[],
            owner_user_id,
            health.clone(),
        )
        .map_err(|_| CoreCliProcessError::CompositionUnavailable)?,
    );
    let child_services = Arc::new(
        SystemCoreServiceSetupComposition::compose(
            CoreUpdateServiceContext::new(platform, CoreUpdateNodeRole::Child),
            configuration.core_update().letsinfer_home().to_path_buf(),
            configuration
                .core_update()
                .configuration_root()
                .to_path_buf(),
            configuration.core_update().home_directory().to_path_buf(),
            &[],
            owner_user_id,
            health,
        )
        .map_err(|_| CoreCliProcessError::CompositionUnavailable)?,
    );
    let services = Arc::new(
        CorePairingActivationService::new(
            child_services,
            main_services,
            input.installation.clone(),
        )
        .map_err(|_| CoreCliProcessError::CompositionUnavailable)?,
    );
    let activation = Arc::new(CorePairingActivationCoordinator::new(
        authority,
        Arc::new(SystemNodePairingClient),
        trust.clone(),
        cancellation.clone(),
        Arc::new(
            SystemCorePairingActivationConfiguration::new(
                configuration
                    .core_update()
                    .configuration_root()
                    .to_path_buf(),
                owner_user_id,
            )
            .map_err(|_| CoreCliProcessError::CompositionUnavailable)?,
        ),
        services,
        Arc::new(
            SystemCorePairingActivationStore::new(
                configuration
                    .core_update()
                    .letsinfer_home()
                    .join("state")
                    .join("pairing_activation"),
                owner_user_id,
            )
            .map_err(|_| CoreCliProcessError::CompositionUnavailable)?,
        ),
        Arc::new(SystemCorePairingActivationWaiter),
    ));
    Ok(Arc::new(ApplicationCoreCliPairing::new(
        NativeNodePairingEndpoint::new(
            local.control_address().clone(),
            PAIRING_DISCOVERY_PORT,
            pairing.certificate_sha256().clone(),
        )
        .map_err(|_| CoreCliProcessError::ConfigurationUnavailable)?,
        discovery,
        Arc::new(SystemNodePairingClient),
        trust,
        clock,
        cancellation,
        Arc::new(SystemCoreCliPairingSetupCode),
        Arc::new(SystemCoreCliPairingEntropy),
        Arc::new(SystemCorePairingActivationConfirmation),
        activation,
    )))
}

// Validates Linux-only Watchdog health material against the configured service platform.
fn watchdog_health(
    input: &CoreCliPairingConfiguration,
    platform: CoreUpdateServicePlatform,
    owner_user_id: u32,
) -> Result<Option<CoreWatchdogHealthTlsFiles>, CoreCliProcessError> {
    match (platform, input.watchdog_health.as_ref()) {
        (CoreUpdateServicePlatform::Linux, Some(files)) => CoreWatchdogHealthTlsFiles::new(
            owner_user_id,
            files.authority_certificate_file.clone(),
            files.controller_certificate_file.clone(),
            files.controller_private_key_file.clone(),
        )
        .map(Some)
        .map_err(|_| CoreCliProcessError::ConfigurationUnavailable),
        (CoreUpdateServicePlatform::Macos, None) => Ok(None),
        _ => Err(CoreCliProcessError::ConfigurationUnavailable),
    }
}

// Maps one signed native archive platform to its exact resident service family.
const fn service_platform(platform: CoreUpdateReleasePlatform) -> CoreUpdateServicePlatform {
    match platform {
        CoreUpdateReleasePlatform::LinuxArm64 | CoreUpdateReleasePlatform::LinuxX86_64 => {
            CoreUpdateServicePlatform::Linux
        }
        CoreUpdateReleasePlatform::MacosArm64 => CoreUpdateServicePlatform::Macos,
    }
}

// Returns one redacted failure when production pairing cannot be composed.
fn pairing_composition_failure() -> CommandFailure {
    CommandFailure::new(
        li_core_cli::CommandFailureKind::Failed,
        "node.pairing_unavailable",
        "node pairing is unavailable",
    )
    .expect("static pairing composition failure")
}

// Returns one redacted failure when complete native uninstall composition is unavailable.
fn uninstall_composition_failure() -> CommandFailure {
    CommandFailure::new(
        li_core_cli::CommandFailureKind::Failed,
        "uninstall.composition_unavailable",
        "native uninstall is unavailable",
    )
    .expect("static uninstall composition failure")
}

// Defers controller authority and identity loading until the interactive add command owns it.
struct LazySystemCoreControllerEnrollment {
    compose: Box<ControllerEnrollmentComposition>,
}

// Names the one deferred composition closure without exposing Node configuration to the CLI crate.
type ControllerEnrollmentComposition = dyn Fn() -> Result<Option<Arc<dyn NativeControllerEnrollmentPort>>, CommandFailure>
    + Send
    + Sync;

impl LazySystemCoreControllerEnrollment {
    // Creates one lazy boundary without probing Node state for unrelated CLI commands.
    fn new(
        compose: impl Fn() -> Result<Option<Arc<dyn NativeControllerEnrollmentPort>>, CommandFailure>
            + Send
            + Sync
            + 'static,
    ) -> Self {
        Self {
            compose: Box::new(compose),
        }
    }
}

impl NativeControllerEnrollmentPort for LazySystemCoreControllerEnrollment {
    // Composes the exact platform authority once the command has passed CLI validation.
    fn enroll(
        &self,
        timeout: Duration,
        role: ControllerRole,
        progress: &mut dyn CommandProgressPort,
        commit: &mut dyn NativeControllerEnrollmentCommitPort,
    ) -> Result<li_node_manager::NodeControllerSummary, CommandFailure> {
        let provider = (self.compose)()?.ok_or_else(controller_enrollment_unavailable_failure)?;
        provider.enroll(timeout, role, progress, commit)
    }
}

// Returns one fixed failure when this platform or role has no controller authority.
fn controller_enrollment_unavailable_failure() -> CommandFailure {
    CommandFailure::new(
        li_core_cli::CommandFailureKind::Failed,
        "auth.controller.enrollment_unavailable",
        "Controller enrollment is unavailable on this node.",
    )
    .expect("static controller enrollment failure")
}

// Returns one fixed failure when the installed controller composition cannot be reconstructed.
fn controller_enrollment_composition_failure() -> CommandFailure {
    CommandFailure::new(
        li_core_cli::CommandFailureKind::Failed,
        "auth.controller.composition_unavailable",
        "Controller enrollment configuration is unavailable.",
    )
    .expect("static controller composition failure")
}

// Owns one already-validated system Node client and its untouched product command arguments.
pub struct CoreCliProcess {
    command_arguments: Vec<String>,
    native: SystemNativeNodeCliProcess,
}

impl CoreCliProcess {
    // Composes one CLI without opening manager persistence or discovering a transport fallback.
    pub fn compose(
        arguments: CoreCliProcessArguments,
        owner_user_id: u32,
        configuration_provider: &dyn CoreCliConfigurationFileProvider,
    ) -> Result<Self, CoreCliProcessError> {
        let configuration = CoreCliConfiguration::load(
            arguments.configuration_file(),
            owner_user_id,
            configuration_provider,
        )?;
        let mut native = compose_system_native_node_cli(
            configuration.local_node_socket().to_path_buf(),
            configuration.entropy_source(),
            configuration.client(),
        )
        .map_err(composition_error)?;
        let controller_configuration = configuration.pairing().clone();
        let controller_socket = configuration.local_node_socket().to_path_buf();
        let controller_entropy = configuration.entropy_source().to_path_buf();
        let controller_client = configuration.client();
        native = native.with_controller_enrollment(Arc::new(
            LazySystemCoreControllerEnrollment::new(move || {
                compose_system_core_cli_controller_enrollment(
                    &controller_configuration,
                    owner_user_id,
                    &controller_socket,
                    &controller_entropy,
                    controller_client,
                )
                .map_err(|_| controller_enrollment_composition_failure())
            }),
        ));
        native = native.with_node_pairing(Arc::new(SystemCoreCliPairing::new(
            configuration.pairing().clone(),
            configuration.local_node_socket().to_path_buf(),
            configuration.entropy_source().to_path_buf(),
            configuration.client(),
            owner_user_id,
        )));
        let uninstall_node_configuration = configuration
            .pairing()
            .node_configuration_file()
            .to_path_buf();
        let uninstall_installation = configuration.pairing().installation().clone();
        let uninstall_launcher = configuration.uninstall().launcher_file().to_path_buf();
        let uninstall_privilege = configuration
            .uninstall()
            .privilege_command()
            .map(Path::to_path_buf);
        let uninstall_socket = configuration.local_node_socket().to_path_buf();
        let uninstall_entropy = configuration.entropy_source().to_path_buf();
        let uninstall_client = configuration.client();
        native = native.with_uninstall(Arc::new(LazySystemCoreCliUninstall::new(move || {
            let node_configuration = NodeConfiguration::load(
                &NodeConfigurationFileReference::new(
                    uninstall_node_configuration.clone(),
                    owner_user_id,
                )
                .map_err(|_| uninstall_composition_failure())?,
                &SystemNodeConfigurationFileProvider,
            )
            .map_err(|_| uninstall_composition_failure())?;
            let exchange = SystemNodePrivateDocumentExchange::open(uninstall_socket.clone())
                .map_err(|_| uninstall_composition_failure())?;
            let identity = SystemNodeRequestIdentitySource::open(&uninstall_entropy)
                .map_err(|_| uninstall_composition_failure())?;
            let uninstall = crate::compose_system_core_cli_uninstall(
                owner_user_id,
                node_configuration,
                uninstall_installation.clone(),
                uninstall_launcher.clone(),
                uninstall_privilege.clone(),
                NodePrivateClient::new(exchange, identity, uninstall_client),
                Arc::new(SystemCoreUninstallNativeRemoval),
            )
            .map_err(|_| uninstall_composition_failure())?;
            Ok(Arc::new(uninstall) as Arc<dyn li_core_cli::NativeUninstallPort>)
        })));
        if let Some(remote) = configuration.remote_main() {
            let remote_client = Arc::new(
                SystemNodePrivateRemoteClient::open(
                    &NodePrivateRemoteClientFileSet::new(
                        owner_user_id,
                        remote.client_certificate_file().to_path_buf(),
                        remote.client_private_key_file().to_path_buf(),
                    )
                    .map_err(|_| CoreCliProcessError::ConfigurationUnavailable)?,
                )
                .map_err(|_| CoreCliProcessError::ConfigurationUnavailable)?,
            );
            let exchange = CorePairedNodeDocumentExchange::new(
                remote_client,
                remote.address().clone(),
                remote.port(),
                remote.server_certificate_sha256().clone(),
                Arc::new(NodePairingCancellation::default()),
            );
            let identity = SystemNodeRequestIdentitySource::open(configuration.entropy_source())
                .map_err(|_| CoreCliProcessError::CompositionUnavailable)?;
            native = native.with_child_lifecycle(Arc::new(PairedMainChildLifecycle::new(
                NodePrivateClient::new(exchange, identity, configuration.client()),
            )));
        }
        Ok(Self {
            command_arguments: arguments.command_arguments,
            native,
        })
    }

    // Runs one ordinary CLI lifecycle with a mandatory fail-closed audit projection boundary.
    pub fn run<StandardOutput, StandardError>(
        &mut self,
        standard_output: &mut StandardOutput,
        standard_error: &mut StandardError,
    ) -> CliExitCode
    where
        StandardOutput: Write,
        StandardError: Write,
    {
        self.native.run_with_node_audit(
            self.command_arguments.iter().map(String::as_str),
            standard_output,
            standard_error,
        )
    }
}

// Parses, composes, and runs the internal binary while preserving stable early-failure output.
pub fn run_system_core_cli_process<StandardOutput, StandardError>(
    arguments: impl IntoIterator<Item = OsString>,
    owner_user_id: u32,
    standard_output: &mut StandardOutput,
    standard_error: &mut StandardError,
) -> CliExitCode
where
    StandardOutput: Write,
    StandardError: Write,
{
    let result = CoreCliProcessArguments::parse(arguments).and_then(|arguments| {
        CoreCliProcess::compose(
            arguments,
            owner_user_id,
            &SystemCoreCliConfigurationFileProvider,
        )
    });
    match result {
        Ok(mut process) => process.run(standard_output, standard_error),
        Err(error) => {
            let _ = writeln!(standard_error, "li_letsinfer: {error}");
            CliExitCode::Failure
        }
    }
}

// Opens and bounds one exact configuration file while retaining its native identity.
fn read_system_configuration_file(
    path: &Path,
    maximum_bytes: usize,
) -> Result<CoreCliConfigurationFile, CoreCliProcessError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| CoreCliProcessError::ConfigurationUnavailable)?;
    let before = file
        .metadata()
        .map_err(|_| CoreCliProcessError::ConfigurationUnavailable)?;
    if before.len() > maximum_bytes as u64 {
        return Err(CoreCliProcessError::ConfigurationUnavailable);
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take((maximum_bytes as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| CoreCliProcessError::ConfigurationUnavailable)?;
    if bytes.len() > maximum_bytes {
        return Err(CoreCliProcessError::ConfigurationUnavailable);
    }
    let after = file
        .metadata()
        .map_err(|_| CoreCliProcessError::ConfigurationUnavailable)?;
    if !same_file_observation(&before, &after) || after.len() != bytes.len() as u64 {
        return Err(CoreCliProcessError::ConfigurationUnavailable);
    }
    Ok(CoreCliConfigurationFile::new(
        after.uid(),
        after.mode() & 0o777,
        after.nlink(),
        after.file_type().is_file(),
        bytes,
    ))
}

// Returns whether one descriptor retained the same exact native file throughout its read.
fn same_file_observation(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.uid() == after.uid()
        && before.mode() == after.mode()
        && before.nlink() == after.nlink()
        && before.len() == after.len()
}

// Parses one bounded normal absolute path without resolving or following its native target.
fn absolute_path(value: &str) -> Result<PathBuf, CoreCliProcessError> {
    let path = PathBuf::from(value);
    if value.is_empty()
        || value.len() > 4096
        || value.chars().any(char::is_control)
        || value == "/"
        || value
            .split('/')
            .skip(1)
            .any(|component| component.is_empty() || component == "." || component == "..")
        || !path.is_absolute()
        || path.components().next() != Some(Component::RootDir)
        || path
            .components()
            .skip(1)
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(CoreCliProcessError::ConfigurationUnavailable);
    }
    Ok(path)
}

// Collapses native socket and entropy setup failures without preserving which path failed.
const fn composition_error(_error: NativeNodeCliCompositionError) -> CoreCliProcessError {
    CoreCliProcessError::CompositionUnavailable
}

// Returns whether one value is exactly one lowercase SHA-256 identity.
fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
