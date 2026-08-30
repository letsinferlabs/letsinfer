// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread::JoinHandle;

#[cfg(target_os = "linux")]
use std::net::SocketAddr;
#[cfg(target_os = "linux")]
use std::num::NonZeroU64;
#[cfg(any(target_os = "linux", test))]
use std::sync::Mutex;
#[cfg(any(target_os = "linux", test))]
use std::time::Duration;

#[cfg(target_os = "linux")]
use li_core_interface::{InstallationId, Sha256Digest};
#[cfg(target_os = "linux")]
use li_node_manager::{
    NodeProtectionBeginRequest, NodeProtectionCommitRequest, NodeProtectionEndRequest,
    NodeProtectionLocalClient, NodeProtectionLocalClientConfiguration, NodeProtectionLocalError,
    NodeProtectionReadSiteStatusRequest, NodeProtectionRequest,
    NodeProtectionResolveControllerBindingRequest, NodeProtectionResponse,
};
use li_watchdog_manager::{
    SystemWatchdogResidentSignalAdapter, WatchdogResident, WatchdogResidentOutcome,
    WatchdogRustlsTcpServer,
};

#[cfg(target_os = "linux")]
use li_watchdog_manager::{
    DynamicWatchdogNvmlPort, FilesystemWatchdogControllerSnapshotProvider,
    FilesystemWatchdogProtocolDataProvider, FilesystemWatchdogStorage,
    LinuxWatchdogProtectionProvider, LinuxWatchdogSampleProvider, NvmlWatchdogLinuxGpuProvider,
    SystemWatchdogConfigurationFileProvider, SystemWatchdogControllerAllowlistSource,
    SystemWatchdogControllerSnapshotIo, SystemWatchdogGatewayTelemetryFileProvider,
    SystemWatchdogLinuxClock, SystemWatchdogLinuxHostFileProvider,
    SystemWatchdogLinuxPidFdProvider, SystemWatchdogLinuxProcessProvider,
    SystemWatchdogLinuxProtectionFileProvider, SystemWatchdogTlsFileProvider,
    WatchdogConfiguration, WatchdogConfigurationLoader, WatchdogControllerAllowlistSource,
    WatchdogControllerBinding, WatchdogControllerRegistry, WatchdogControllerRegistryReloader,
    WatchdogControllerSessionProvider, WatchdogError, WatchdogGatewayTelemetryProvider,
    WatchdogLinuxCapability, WatchdogLinuxProcessLayout, WatchdogLinuxProcessProvider,
    WatchdogLinuxProtectionLayout, WatchdogLinuxSampleLayout, WatchdogLiveFanout,
    WatchdogLiveFanoutLimits, WatchdogManager, WatchdogProtectionCycle,
    WatchdogProtocolCapabilities, WatchdogProtocolDataError, WatchdogProtocolDispatcher,
    WatchdogProtocolIdentityProvider, WatchdogProtocolListener, WatchdogProtocolListenerLimits,
    WatchdogProtocolResidentStatus, WatchdogProtocolService, WatchdogProtocolSiteStatus,
    WatchdogResidentConfigurationSource, WatchdogResidentService,
    WatchdogRustlsServerConfiguration, WatchdogRustlsTcpLimits, WatchdogTlsFileSet,
};

#[cfg(any(target_os = "linux", test))]
const NODE_PROTECTION_CONNECTION_ATTEMPTS: usize = 20;
#[cfg(any(target_os = "linux", test))]
const NODE_PROTECTION_CONNECTION_INTERVAL: Duration = Duration::from_millis(250);

// Classifies only endpoint unavailability as safe to retry before Watchdog composition begins.
#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NodeProtectionConnectionAttemptFailure {
    Unavailable,
    Permanent,
}

// Retries one local Node connection under an exact attempt and wait bound.
#[cfg(any(target_os = "linux", test))]
fn retry_node_protection_connection<Connection>(
    mut connect: impl FnMut() -> Result<Connection, NodeProtectionConnectionAttemptFailure>,
    mut wait: impl FnMut(Duration),
) -> Result<Connection, CoreWatchdogProcessError> {
    for attempt in 0..NODE_PROTECTION_CONNECTION_ATTEMPTS {
        match connect() {
            Ok(connection) => return Ok(connection),
            Err(NodeProtectionConnectionAttemptFailure::Permanent) => {
                return Err(CoreWatchdogProcessError::CompositionUnavailable)
            }
            Err(NodeProtectionConnectionAttemptFailure::Unavailable)
                if attempt + 1 < NODE_PROTECTION_CONNECTION_ATTEMPTS =>
            {
                wait(NODE_PROTECTION_CONNECTION_INTERVAL);
            }
            Err(NodeProtectionConnectionAttemptFailure::Unavailable) => {
                return Err(CoreWatchdogProcessError::CompositionUnavailable)
            }
        }
    }
    Err(CoreWatchdogProcessError::CompositionUnavailable)
}

// Names stable executable, composition, and resident failure classes without path disclosure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreWatchdogProcessError {
    InvalidArguments,
    UnsupportedPlatform,
    ConfigurationUnavailable,
    CompositionUnavailable,
    ListenerUnavailable,
    ResidentUnavailable,
    ThreadUnavailable,
}

impl fmt::Display for CoreWatchdogProcessError {
    // Presents fixed user-safe process failure language.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArguments => formatter.write_str("li_watchdog arguments are invalid"),
            Self::UnsupportedPlatform => {
                formatter.write_str("li_watchdog is available only on Linux")
            }
            Self::ConfigurationUnavailable => {
                formatter.write_str("li_watchdog configuration is unavailable")
            }
            Self::CompositionUnavailable => {
                formatter.write_str("li_watchdog native composition is unavailable")
            }
            Self::ListenerUnavailable => {
                formatter.write_str("li_watchdog listener terminated unexpectedly")
            }
            Self::ResidentUnavailable => {
                formatter.write_str("li_watchdog resident lifecycle failed")
            }
            Self::ThreadUnavailable => formatter.write_str("li_watchdog worker lifecycle failed"),
        }
    }
}

impl Error for CoreWatchdogProcessError {}

// Stores the one exact process argument owned by CoreProcessLayout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreWatchdogProcessArguments {
    configuration_path: PathBuf,
}

impl CoreWatchdogProcessArguments {
    // Parses exactly `--configuration <absolute-path>` without aliases or defaults.
    pub fn parse(
        arguments: impl IntoIterator<Item = OsString>,
    ) -> Result<Self, CoreWatchdogProcessError> {
        let arguments = arguments.into_iter().collect::<Vec<_>>();
        if arguments.len() != 2 || arguments[0] != OsStr::new("--configuration") {
            return Err(CoreWatchdogProcessError::InvalidArguments);
        }
        let configuration_path = PathBuf::from(&arguments[1]);
        if !configuration_path.is_absolute() {
            return Err(CoreWatchdogProcessError::InvalidArguments);
        }
        Ok(Self { configuration_path })
    }

    // Returns the exact configuration path selected by CoreProcessLayout.
    pub fn configuration_path(&self) -> &Path {
        &self.configuration_path
    }
}

// Owns the blocking native TLS listener lifecycle.
pub trait CoreWatchdogNetworkServer: Send + Sync {
    // Serves accepted connections until explicit shutdown or a terminal listener failure.
    fn serve(&self) -> Result<(), CoreWatchdogProcessError>;

    // Requests listener shutdown and interrupts every active connection worker.
    fn shutdown(&self) -> Result<(), CoreWatchdogProcessError>;
}

// Owns the blocking resident sampling lifecycle.
pub trait CoreWatchdogResidentRunner: Send + Sync {
    // Samples until native or process-local run control requests a clean stop.
    fn run(&self) -> Result<WatchdogResidentOutcome, CoreWatchdogProcessError>;
}

// Interrupts resident cadence when another process component terminates.
pub trait CoreWatchdogRunControl: Send + Sync {
    // Requests one clean final-flush stop without fabricating process success.
    fn request_stop(&self) -> Result<(), CoreWatchdogProcessError>;
}

// Closes one already-begun Node protection session exactly once.
trait CoreWatchdogProtectionSession: Send + Sync {
    // Ends the exact durable session while its authenticated connection remains open.
    fn finish(&self) -> Result<(), CoreWatchdogProcessError>;
}

// Owns rollback for every path after Node accepted BeginWatchdogSession.
#[cfg(any(target_os = "linux", test))]
struct CoreWatchdogProtectionSessionGuard {
    session: Arc<dyn CoreWatchdogProtectionSession>,
    finished: Mutex<bool>,
}

#[cfg(any(target_os = "linux", test))]
impl CoreWatchdogProtectionSessionGuard {
    // Arms rollback immediately around one already-begun session.
    fn new(session: Arc<dyn CoreWatchdogProtectionSession>) -> Self {
        Self {
            session,
            finished: Mutex::new(false),
        }
    }
}

#[cfg(any(target_os = "linux", test))]
impl CoreWatchdogProtectionSession for CoreWatchdogProtectionSessionGuard {
    // Ends once after success and leaves a failed close eligible for Drop retry.
    fn finish(&self) -> Result<(), CoreWatchdogProcessError> {
        let mut finished = self
            .finished
            .lock()
            .map_err(|_| CoreWatchdogProcessError::ResidentUnavailable)?;
        if *finished {
            return Ok(());
        }
        self.session.finish()?;
        *finished = true;
        Ok(())
    }
}

#[cfg(any(target_os = "linux", test))]
impl Drop for CoreWatchdogProtectionSessionGuard {
    // Performs best-effort rollback when later composition or startup abandons the session.
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

// Rejects a mismatched Begin receipt only after its armed rollback owner exists.
#[cfg(any(target_os = "linux", test))]
fn require_matching_watchdog_authority<Connection>(
    connection: Connection,
    matches: bool,
) -> Result<Connection, CoreWatchdogProcessError> {
    if matches {
        Ok(connection)
    } else {
        Err(CoreWatchdogProcessError::CompositionUnavailable)
    }
}

impl CoreWatchdogNetworkServer for WatchdogRustlsTcpServer {
    // Delegates to the concrete bounded Rustls listener.
    fn serve(&self) -> Result<(), CoreWatchdogProcessError> {
        WatchdogRustlsTcpServer::serve(self)
            .map_err(|_| CoreWatchdogProcessError::ListenerUnavailable)
    }

    // Delegates to the concrete listener shutdown boundary.
    fn shutdown(&self) -> Result<(), CoreWatchdogProcessError> {
        WatchdogRustlsTcpServer::shutdown(self)
            .map_err(|_| CoreWatchdogProcessError::ListenerUnavailable)
    }
}

impl CoreWatchdogResidentRunner for WatchdogResident {
    // Delegates to the concrete cadence, reload, signal, and final-flush owner.
    fn run(&self) -> Result<WatchdogResidentOutcome, CoreWatchdogProcessError> {
        WatchdogResident::run(self).map_err(|_| CoreWatchdogProcessError::ResidentUnavailable)
    }
}

impl CoreWatchdogRunControl for SystemWatchdogResidentSignalAdapter {
    // Wakes the concrete resident through its clean stop path.
    fn request_stop(&self) -> Result<(), CoreWatchdogProcessError> {
        SystemWatchdogResidentSignalAdapter::request_stop(self)
            .map_err(|_| CoreWatchdogProcessError::ResidentUnavailable)
    }
}

// Owns process-wide ordering between the independent listener and resident lifecycles.
pub struct CoreWatchdogProcess {
    server: Arc<dyn CoreWatchdogNetworkServer>,
    resident: Arc<dyn CoreWatchdogResidentRunner>,
    run_control: Arc<dyn CoreWatchdogRunControl>,
    protection: Option<Arc<dyn CoreWatchdogProtectionSession>>,
}

impl CoreWatchdogProcess {
    // Creates one process after all native resources are fully composed and bound.
    pub const fn new(
        server: Arc<dyn CoreWatchdogNetworkServer>,
        resident: Arc<dyn CoreWatchdogResidentRunner>,
        run_control: Arc<dyn CoreWatchdogRunControl>,
    ) -> Self {
        Self {
            server,
            resident,
            run_control,
            protection: None,
        }
    }

    // Binds the Linux Watchdog session whose lifecycle must end with this process.
    #[cfg(target_os = "linux")]
    fn with_protection(mut self, protection: Arc<dyn CoreWatchdogProtectionSession>) -> Self {
        self.protection = Some(protection);
        self
    }

    // Runs both owners, propagates either failure, and always stops and joins the listener.
    pub fn run(&self) -> Result<WatchdogResidentOutcome, CoreWatchdogProcessError> {
        let listener = require_started_listener(
            start_listener_worker(self.server.clone(), self.run_control.clone()),
            self.protection.as_deref(),
        )?;
        let resident_result = self.resident.run();
        let shutdown_result = self.server.shutdown();
        let listener_result = join_listener_worker(listener);
        let protection_result = self
            .protection
            .as_ref()
            .map_or(Ok(()), |protection| protection.finish());
        resident_result
            .and(shutdown_result.map(|_| WatchdogResidentOutcome::Stopped))
            .and(listener_result.map(|_| WatchdogResidentOutcome::Stopped))
            .and(protection_result.map(|_| WatchdogResidentOutcome::Stopped))
    }
}

// Retains one initial immutable configuration and re-reads only for explicit reload.
#[cfg(target_os = "linux")]
struct CoreWatchdogConfigurationSource {
    initial: Mutex<Option<WatchdogConfiguration>>,
    loader: WatchdogConfigurationLoader,
}

#[cfg(target_os = "linux")]
impl CoreWatchdogConfigurationSource {
    // Creates one source whose first read is byte-equivalent to already-composed resources.
    fn new(initial: WatchdogConfiguration, loader: WatchdogConfigurationLoader) -> Self {
        Self {
            initial: Mutex::new(Some(initial)),
            loader,
        }
    }
}

#[cfg(target_os = "linux")]
impl WatchdogResidentConfigurationSource for CoreWatchdogConfigurationSource {
    // Returns the retained initial value once, then the strict owner-only live document.
    fn load(&self) -> Result<WatchdogConfiguration, WatchdogError> {
        let initial = self
            .initial
            .lock()
            .map_err(|_| WatchdogError::StateUnavailable)?
            .take();
        initial.map_or_else(|| self.loader.load(), Ok)
    }
}

// Owns one role-confined persistent Watchdog session on the dedicated Node protection channel.
#[cfg(target_os = "linux")]
struct CoreWatchdogNodeProtectionClient {
    client: Mutex<NodeProtectionLocalClient>,
    node_id: li_core_interface::NodeId,
    authority: li_gateway_manager::GatewayProtectionAuthority,
}

// Returns an armed local client together with its exact-once rollback owner.
#[cfg(target_os = "linux")]
struct CoreWatchdogNodeProtectionConnection {
    client: Arc<CoreWatchdogNodeProtectionClient>,
    session: Arc<CoreWatchdogProtectionSessionGuard>,
}

#[cfg(target_os = "linux")]
impl CoreWatchdogNodeProtectionClient {
    // Opens a fresh authenticated connection and durably begins one monotonic session.
    fn connect(
        configuration: &WatchdogConfiguration,
        owner_user_id: u32,
    ) -> Result<CoreWatchdogNodeProtectionConnection, CoreWatchdogProcessError> {
        let channel = configuration.node_protection();
        let client_configuration = NodeProtectionLocalClientConfiguration::new(
            channel.socket_path().to_path_buf(),
            owner_user_id,
            channel.read_timeout(),
            channel.write_timeout(),
        )
        .map_err(|_| CoreWatchdogProcessError::CompositionUnavailable)?;
        let client = retry_node_protection_connection(
            || {
                let connection_id = random_digest()
                    .map_err(|_| NodeProtectionConnectionAttemptFailure::Permanent)?;
                NodeProtectionLocalClient::connect(&client_configuration, connection_id).map_err(
                    |error| match error {
                        NodeProtectionLocalError::EndpointUnavailable => {
                            NodeProtectionConnectionAttemptFailure::Unavailable
                        }
                        _ => NodeProtectionConnectionAttemptFailure::Permanent,
                    },
                )
            },
            std::thread::sleep,
        )?;
        let session_nonce = random_digest()?;
        let begin = NodeProtectionBeginRequest::new(
            &format!("li_watchdog_begin_{}", session_nonce.as_str()),
            configuration.node_id().clone(),
            InstallationId::parse(configuration.installation_id())
                .map_err(|_| CoreWatchdogProcessError::CompositionUnavailable)?,
            configuration.core_source_identity().clone(),
            session_nonce,
            NonZeroU64::MIN,
        )
        .map_err(|_| CoreWatchdogProcessError::CompositionUnavailable)?;
        let authority = match client
            .exchange(NodeProtectionRequest::BeginWatchdogSession(begin))
            .map_err(|_| CoreWatchdogProcessError::CompositionUnavailable)?
        {
            NodeProtectionResponse::WatchdogSessionBegan(authority) => authority,
            _ => return Err(CoreWatchdogProcessError::CompositionUnavailable),
        };
        let client = Arc::new(Self {
            client: Mutex::new(client),
            node_id: authority.node_id().clone(),
            authority,
        });
        let connection = CoreWatchdogNodeProtectionConnection {
            session: Arc::new(CoreWatchdogProtectionSessionGuard::new(client.clone())),
            client,
        };
        let authority_matches = connection.client.authority.node_id() == configuration.node_id()
            && connection.client.authority.core_installation_id().as_str()
                == configuration.installation_id()
            && connection.client.authority.watchdog_source_identity()
                == configuration.core_source_identity();
        require_matching_watchdog_authority(connection, authority_matches)
    }

    // Commits only the receipt returned after one complete successful Watchdog tick.
    fn commit(&self, cycle: &WatchdogProtectionCycle) -> Result<(), WatchdogError> {
        let response = self
            .client
            .lock()
            .map_err(|_| WatchdogError::StateUnavailable)?
            .exchange(NodeProtectionRequest::CommitWatchdogCycle(
                NodeProtectionCommitRequest::new(
                    self.node_id.clone(),
                    self.authority.watchdog_session_id().clone(),
                    self.authority.watchdog_session_generation(),
                    cycle.clone(),
                ),
            ))
            .map_err(|_| WatchdogError::StateUnavailable)?;
        if matches!(
            response,
            NodeProtectionResponse::WatchdogCycleCommitted { .. }
        ) {
            Ok(())
        } else {
            Err(WatchdogError::StateUnavailable)
        }
    }

    // Resolves one TLS-authenticated controller only through the Node-owned session authority.
    fn resolve_controller_binding(
        &self,
        certificate_sha256: &str,
    ) -> Result<WatchdogControllerBinding, WatchdogError> {
        let certificate_sha256 =
            Sha256Digest::parse(certificate_sha256).map_err(|_| WatchdogError::StateUnavailable)?;
        let response = self
            .client
            .lock()
            .map_err(|_| WatchdogError::StateUnavailable)?
            .exchange(NodeProtectionRequest::ResolveControllerBinding(
                NodeProtectionResolveControllerBindingRequest::new(certificate_sha256),
            ))
            .map_err(|_| WatchdogError::StateUnavailable)?;
        match response {
            NodeProtectionResponse::ControllerBinding(binding) => Ok(binding),
            _ => Err(WatchdogError::StateUnavailable),
        }
    }

    // Reads one binding-scoped status projection only through the Node-owned manager graph.
    fn read_site_status(
        &self,
        binding: &WatchdogControllerBinding,
    ) -> Result<WatchdogProtocolSiteStatus, WatchdogProtocolDataError> {
        let response = self
            .client
            .lock()
            .map_err(|_| WatchdogProtocolDataError::Unavailable)?
            .exchange(NodeProtectionRequest::ReadSiteStatus(
                NodeProtectionReadSiteStatusRequest::new(binding.clone()),
            ))
            .map_err(|_| WatchdogProtocolDataError::Unavailable)?;
        match response {
            NodeProtectionResponse::SiteStatus(status) => Ok(status),
            _ => Err(WatchdogProtocolDataError::Unavailable),
        }
    }

    // Ends the exact session before the persistent connection is released.
    fn finish(&self) -> Result<(), CoreWatchdogProcessError> {
        let response = self
            .client
            .lock()
            .map_err(|_| CoreWatchdogProcessError::ResidentUnavailable)?
            .exchange(NodeProtectionRequest::EndWatchdogSession(
                NodeProtectionEndRequest::new(
                    self.node_id.clone(),
                    self.authority.watchdog_session_id().clone(),
                    self.authority.watchdog_session_generation(),
                ),
            ))
            .map_err(|_| CoreWatchdogProcessError::ResidentUnavailable)?;
        if response == NodeProtectionResponse::WatchdogSessionEnded {
            Ok(())
        } else {
            Err(CoreWatchdogProcessError::ResidentUnavailable)
        }
    }
}

#[cfg(target_os = "linux")]
impl WatchdogControllerSessionProvider for CoreWatchdogNodeProtectionClient {
    // Resolves controller authority without giving Watchdog direct persistence access.
    fn binding_for_certificate(
        &self,
        certificate_sha256: &str,
    ) -> Result<WatchdogControllerBinding, WatchdogError> {
        self.resolve_controller_binding(certificate_sha256)
    }
}

#[cfg(target_os = "linux")]
impl CoreWatchdogProtectionSession for CoreWatchdogNodeProtectionClient {
    // Ends the exact authenticated Node session without exposing its authority document.
    fn finish(&self) -> Result<(), CoreWatchdogProcessError> {
        CoreWatchdogNodeProtectionClient::finish(self)
    }
}

// Supplies immutable local capabilities and delegates Node-owned status over private IPC.
#[cfg(target_os = "linux")]
struct CoreWatchdogProtocolIdentityProvider {
    node_id: li_core_interface::NodeId,
    core_release: String,
    core_source_identity: Sha256Digest,
    installation_id: InstallationId,
    capabilities: WatchdogProtocolCapabilities,
    protection: Arc<CoreWatchdogNodeProtectionClient>,
}

#[cfg(target_os = "linux")]
impl CoreWatchdogProtocolIdentityProvider {
    // Creates one protocol identity after validating every immutable resident field.
    #[allow(clippy::too_many_arguments)]
    fn new(
        node_id: li_core_interface::NodeId,
        core_release: String,
        core_source_identity: Sha256Digest,
        installation_id: String,
        sample_interval_milliseconds: u32,
        flush_interval_milliseconds: u32,
        physical_gpu_count: u32,
        protection: Arc<CoreWatchdogNodeProtectionClient>,
    ) -> Result<Self, WatchdogError> {
        if core_release.is_empty() {
            return Err(WatchdogError::StateUnavailable);
        }
        Ok(Self {
            node_id,
            core_release,
            core_source_identity,
            installation_id: InstallationId::parse(&installation_id)
                .map_err(|_| WatchdogError::StateUnavailable)?,
            capabilities: WatchdogProtocolCapabilities::new(
                sample_interval_milliseconds,
                flush_interval_milliseconds,
                physical_gpu_count,
            )?,
            protection,
        })
    }
}

#[cfg(target_os = "linux")]
impl WatchdogProtocolIdentityProvider for CoreWatchdogProtocolIdentityProvider {
    // Returns immutable cadence and initialized physical-GPU capabilities.
    fn capabilities(&self) -> Result<WatchdogProtocolCapabilities, WatchdogProtocolDataError> {
        Ok(self.capabilities.clone())
    }

    // Delegates target-specific status to the Node-owned authenticated protection channel.
    fn site_status(
        &self,
        binding: &WatchdogControllerBinding,
    ) -> Result<WatchdogProtocolSiteStatus, WatchdogProtocolDataError> {
        self.protection.read_site_status(binding)
    }

    // Returns immutable Watchdog readiness without reading Node persistence.
    fn resident_status(&self) -> Result<WatchdogProtocolResidentStatus, WatchdogProtocolDataError> {
        WatchdogProtocolResidentStatus::ready(
            self.node_id.clone(),
            self.core_release.clone(),
            self.core_source_identity.clone(),
            self.installation_id.clone(),
        )
        .map_err(|_| WatchdogProtocolDataError::Unavailable)
    }
}

// Commits Node protection immediately after the same complete tick published to controllers.
#[cfg(target_os = "linux")]
struct CoreWatchdogProtectedResidentService {
    service: Arc<WatchdogProtocolService>,
    reloader: Arc<WatchdogControllerRegistryReloader>,
    protection: Arc<CoreWatchdogNodeProtectionClient>,
}

#[cfg(target_os = "linux")]
impl WatchdogResidentService for CoreWatchdogProtectedResidentService {
    // Publishes one complete tick and then commits its exact protection-cycle receipt.
    fn tick(&self) -> Result<(), WatchdogError> {
        let tick = self.service.tick()?;
        self.protection.commit(tick.protection_cycle())
    }

    // Flushes the exact existing durable Watchdog storage boundary.
    fn flush(&self) -> Result<(), WatchdogError> {
        self.service.flush()
    }

    // Applies only the existing same-installation controller trust reload.
    fn reload_controller_registry(
        &self,
        configuration: &WatchdogConfiguration,
    ) -> Result<(), WatchdogError> {
        self.reloader.reload(configuration)
    }
}

// Returns one fresh SHA-256-shaped identity from operating-system entropy.
#[cfg(target_os = "linux")]
fn random_digest() -> Result<Sha256Digest, CoreWatchdogProcessError> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| CoreWatchdogProcessError::CompositionUnavailable)?;
    let value = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Sha256Digest::parse(&value).map_err(|_| CoreWatchdogProcessError::CompositionUnavailable)
}

// Parses process arguments, composes Linux providers, and runs the complete Rust Watchdog.
pub fn run_core_watchdog_process(
    arguments: impl IntoIterator<Item = OsString>,
) -> Result<WatchdogResidentOutcome, CoreWatchdogProcessError> {
    let arguments = CoreWatchdogProcessArguments::parse(arguments)?;
    #[cfg(not(target_os = "linux"))]
    {
        let _ = arguments;
        Err(CoreWatchdogProcessError::UnsupportedPlatform)
    }
    #[cfg(target_os = "linux")]
    {
        compose_linux_watchdog_process(arguments.configuration_path())?.run()
    }
}

// Composes every concrete Linux provider without a Python, C, or shell fallback.
#[cfg(target_os = "linux")]
fn compose_linux_watchdog_process(
    configuration_path: &Path,
) -> Result<CoreWatchdogProcess, CoreWatchdogProcessError> {
    let owner_user_id = unsafe { libc::geteuid() };
    let loader = WatchdogConfigurationLoader::new(
        configuration_path.to_path_buf(),
        owner_user_id,
        Box::new(SystemWatchdogConfigurationFileProvider),
    )
    .map_err(configuration_error)?;
    let configuration = loader.load().map_err(configuration_error)?;
    let node_protection_connection =
        CoreWatchdogNodeProtectionClient::connect(&configuration, owner_user_id)?;
    let node_protection = node_protection_connection.client;
    let protection_session = node_protection_connection.session;
    let reload_loader = WatchdogConfigurationLoader::new(
        configuration_path.to_path_buf(),
        owner_user_id,
        Box::new(SystemWatchdogConfigurationFileProvider),
    )
    .map_err(configuration_error)?;

    let host = Arc::new(SystemWatchdogLinuxHostFileProvider);
    let processes: Arc<dyn WatchdogLinuxProcessProvider> =
        Arc::new(SystemWatchdogLinuxProcessProvider::new(
            WatchdogLinuxProcessLayout::system(),
            host.clone(),
            Arc::new(SystemWatchdogLinuxPidFdProvider),
        ));
    let nvml = match DynamicWatchdogNvmlPort::open().map_err(composition_error)? {
        WatchdogLinuxCapability::Available(nvml) => Arc::new(nvml),
        WatchdogLinuxCapability::Unsupported => {
            return Err(CoreWatchdogProcessError::CompositionUnavailable)
        }
    };
    let physical_gpu_count = nvml.physical_device_count();
    let gpu = Arc::new(NvmlWatchdogLinuxGpuProvider::new(nvml));
    let gateway = Arc::new(
        WatchdogGatewayTelemetryProvider::new(
            configuration.gateway_metrics_path().to_path_buf(),
            owner_user_id,
            Box::new(SystemWatchdogGatewayTelemetryFileProvider),
        )
        .map_err(composition_error)?,
    );
    let samples = Arc::new(LinuxWatchdogSampleProvider::new_with_gateway(
        WatchdogLinuxSampleLayout::system(),
        Arc::new(SystemWatchdogLinuxClock),
        host.clone(),
        gpu,
        gateway,
    ));
    let protection = Arc::new(LinuxWatchdogProtectionProvider::new(
        WatchdogLinuxProtectionLayout::new(
            configuration.protection_root_path().to_path_buf(),
            PathBuf::from("/proc/meminfo"),
            PathBuf::from("/proc/pressure/memory"),
        )
        .map_err(composition_error)?,
        Arc::new(SystemWatchdogLinuxProtectionFileProvider::new(
            owner_user_id,
        )),
        host,
        processes,
        Arc::new(SystemWatchdogLinuxClock),
    ));
    let storage = Arc::new(
        FilesystemWatchdogStorage::open(configuration.data_directory())
            .map_err(composition_error)?,
    );
    let manager = Arc::new(
        WatchdogManager::new(
            configuration.thresholds(),
            samples,
            protection,
            storage.clone(),
        )
        .map_err(composition_error)?,
    );
    let identity = Arc::new(
        CoreWatchdogProtocolIdentityProvider::new(
            configuration.node_id().clone(),
            configuration.core_release().to_string(),
            configuration.core_source_identity().clone(),
            configuration.installation_id().to_string(),
            configuration.sample_interval_milliseconds(),
            configuration.flush_interval_milliseconds(),
            physical_gpu_count,
            node_protection.clone(),
        )
        .map_err(|_| CoreWatchdogProcessError::CompositionUnavailable)?,
    );
    let data = Arc::new(FilesystemWatchdogProtocolDataProvider::new(
        storage, identity,
    ));
    let dispatcher = Arc::new(WatchdogProtocolDispatcher::new(data));

    let allowlists = Arc::new(SystemWatchdogControllerAllowlistSource);
    let allowlist = allowlists
        .load(configuration.controller_allowlist_path(), owner_user_id)
        .map_err(composition_error)?;
    if allowlist.installation_id() != configuration.installation_id() {
        return Err(CoreWatchdogProcessError::CompositionUnavailable);
    }
    let snapshots = Arc::new(
        FilesystemWatchdogControllerSnapshotProvider::new(
            configuration.controller_snapshot_path().to_path_buf(),
            owner_user_id,
            Arc::new(SystemWatchdogControllerSnapshotIo),
        )
        .map_err(composition_error)?,
    );
    let registry = Arc::new(
        WatchdogControllerRegistry::open_persistent(
            allowlist,
            configuration.maximum_controllers(),
            snapshots,
        )
        .map_err(composition_error)?,
    );
    let listener = Arc::new(WatchdogProtocolListener::new(
        dispatcher,
        registry,
        node_protection.clone(),
        configuration.node_id().clone(),
        WatchdogProtocolListenerLimits::production(),
    ));
    let registries = listener.controller_registry_store();
    let fanout = Arc::new(WatchdogLiveFanout::new(
        WatchdogLiveFanoutLimits::production(),
    ));
    let service = Arc::new(WatchdogProtocolService::new_with_fanout(
        manager,
        listener.clone(),
        fanout.clone(),
    ));
    let reloader = Arc::new(WatchdogControllerRegistryReloader::new(
        registries,
        allowlists,
        owner_user_id,
    ));
    let resident_service = CoreWatchdogProtectedResidentService {
        service,
        reloader,
        protection: node_protection.clone(),
    };

    let tls_files = WatchdogTlsFileSet::new(
        owner_user_id,
        configuration.server_certificate_path().to_path_buf(),
        configuration.server_private_key_path().to_path_buf(),
        configuration.controller_ca_path().to_path_buf(),
    )
    .map_err(composition_error)?;
    let tls = WatchdogRustlsServerConfiguration::load(&tls_files, &SystemWatchdogTlsFileProvider)
        .map_err(composition_error)?;
    let server = Arc::new(
        WatchdogRustlsTcpServer::bind(
            SocketAddr::new(configuration.listen_address(), configuration.listen_port()),
            listener,
            fanout,
            tls,
            WatchdogRustlsTcpLimits::production(),
        )
        .map_err(composition_error)?,
    );
    let signals =
        Arc::new(SystemWatchdogResidentSignalAdapter::install().map_err(composition_error)?);
    let resident = Arc::new(
        WatchdogResident::new(
            Box::new(CoreWatchdogConfigurationSource::new(
                configuration,
                reload_loader,
            )),
            Box::new(resident_service),
            Box::new(signals.as_ref().clone()),
            Box::new(signals.as_ref().clone()),
            Box::new(signals.as_ref().clone()),
        )
        .map_err(composition_error)?,
    );
    Ok(CoreWatchdogProcess::new(server, resident, signals).with_protection(protection_session))
}

// Starts the listener worker and requests resident stop on every listener terminal path.
fn start_listener_worker(
    server: Arc<dyn CoreWatchdogNetworkServer>,
    run_control: Arc<dyn CoreWatchdogRunControl>,
) -> Result<JoinHandle<Result<(), CoreWatchdogProcessError>>, CoreWatchdogProcessError> {
    std::thread::Builder::new()
        .name("li_watchdog_listener".to_string())
        .spawn(move || {
            let listener_result = server.serve();
            let stop_result = run_control.request_stop();
            listener_result.and(stop_result)
        })
        .map_err(|_| CoreWatchdogProcessError::ThreadUnavailable)
}

// Ends an armed Node session immediately when the listener worker could not be created.
fn require_started_listener<Listener>(
    result: Result<Listener, CoreWatchdogProcessError>,
    protection: Option<&dyn CoreWatchdogProtectionSession>,
) -> Result<Listener, CoreWatchdogProcessError> {
    match result {
        Ok(listener) => Ok(listener),
        Err(error) => {
            if let Some(protection) = protection {
                let _ = protection.finish();
            }
            Err(error)
        }
    }
}

// Joins the exact listener worker and preserves its redacted terminal result.
fn join_listener_worker(
    worker: JoinHandle<Result<(), CoreWatchdogProcessError>>,
) -> Result<(), CoreWatchdogProcessError> {
    worker
        .join()
        .map_err(|_| CoreWatchdogProcessError::ThreadUnavailable)?
}

// Maps strict configuration failures without exposing selected paths or document bytes.
#[cfg(target_os = "linux")]
fn configuration_error(_error: WatchdogError) -> CoreWatchdogProcessError {
    CoreWatchdogProcessError::ConfigurationUnavailable
}

// Maps native provider failures without exposing certificate, process, or path identities.
#[cfg(target_os = "linux")]
fn composition_error(_error: WatchdogError) -> CoreWatchdogProcessError {
    CoreWatchdogProcessError::CompositionUnavailable
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Records exact session-end attempts without requiring a native protection socket.
    struct ProtectionSessionMock {
        finishes: AtomicUsize,
    }

    impl CoreWatchdogProtectionSession for ProtectionSessionMock {
        // Records one successful redacted session close.
        fn finish(&self) -> Result<(), CoreWatchdogProcessError> {
            self.finishes.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }
    }

    // Rolls back drops and receipt mismatches without repeating a successful normal End.
    #[test]
    fn protection_session_guard_ends_exactly_once_on_drop_or_finish() {
        for disposition in ["drop", "finish", "authority-mismatch"] {
            let session = Arc::new(ProtectionSessionMock {
                finishes: AtomicUsize::new(0),
            });
            let guard = CoreWatchdogProtectionSessionGuard::new(session.clone());
            match disposition {
                "drop" => drop(guard),
                "finish" => {
                    guard.finish().expect("normal finish");
                    drop(guard);
                }
                "authority-mismatch" => {
                    assert!(matches!(
                        require_matching_watchdog_authority(guard, false),
                        Err(CoreWatchdogProcessError::CompositionUnavailable)
                    ));
                }
                _ => unreachable!(),
            }
            assert_eq!(session.finishes.load(Ordering::Acquire), 1);
        }
    }

    // Closes the armed session before preserving an exact listener-start failure.
    #[test]
    fn listener_start_failure_ends_protection_before_return() {
        let session = Arc::new(ProtectionSessionMock {
            finishes: AtomicUsize::new(0),
        });
        let guard = CoreWatchdogProtectionSessionGuard::new(session.clone());
        assert_eq!(
            require_started_listener::<u8>(
                Err(CoreWatchdogProcessError::ThreadUnavailable),
                Some(&guard),
            ),
            Err(CoreWatchdogProcessError::ThreadUnavailable)
        );
        assert_eq!(session.finishes.load(Ordering::Acquire), 1);
        drop(guard);
        assert_eq!(session.finishes.load(Ordering::Acquire), 1);
    }

    // Retries only unavailable attempts and returns the first complete connection.
    #[test]
    fn node_protection_connection_retry_recovers_with_exact_waits() {
        let mut results = VecDeque::from([
            Err(NodeProtectionConnectionAttemptFailure::Unavailable),
            Err(NodeProtectionConnectionAttemptFailure::Unavailable),
            Ok(7_u8),
        ]);
        let mut attempts = 0_usize;
        let mut waits = Vec::new();

        let connection = retry_node_protection_connection(
            || {
                attempts += 1;
                results.pop_front().expect("connection result")
            },
            |duration| waits.push(duration),
        )
        .expect("connection");

        assert_eq!(connection, 7);
        assert_eq!(attempts, 3);
        assert_eq!(
            waits,
            vec![
                NODE_PROTECTION_CONNECTION_INTERVAL,
                NODE_PROTECTION_CONNECTION_INTERVAL
            ]
        );
    }

    // Exhausts the exact retry bound without waiting after the final attempt.
    #[test]
    fn node_protection_connection_retry_exhausts_exact_bound() {
        let mut attempts = 0_usize;
        let mut waits = Vec::new();

        let error = retry_node_protection_connection::<u8>(
            || {
                attempts += 1;
                Err(NodeProtectionConnectionAttemptFailure::Unavailable)
            },
            |duration| waits.push(duration),
        )
        .expect_err("exhausted connection");

        assert_eq!(error, CoreWatchdogProcessError::CompositionUnavailable);
        assert_eq!(attempts, NODE_PROTECTION_CONNECTION_ATTEMPTS);
        assert_eq!(waits.len(), NODE_PROTECTION_CONNECTION_ATTEMPTS - 1);
        assert!(waits
            .iter()
            .all(|duration| *duration == NODE_PROTECTION_CONNECTION_INTERVAL));
    }

    // Fails a permanent connection error immediately without another attempt or wait.
    #[test]
    fn node_protection_connection_retry_rejects_permanent_failure() {
        let mut attempts = 0_usize;
        let mut waits = Vec::new();

        let error = retry_node_protection_connection::<u8>(
            || {
                attempts += 1;
                Err(NodeProtectionConnectionAttemptFailure::Permanent)
            },
            |duration| waits.push(duration),
        )
        .expect_err("permanent failure");

        assert_eq!(error, CoreWatchdogProcessError::CompositionUnavailable);
        assert_eq!(attempts, 1);
        assert!(waits.is_empty());
    }
}
