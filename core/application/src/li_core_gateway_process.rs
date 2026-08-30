// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::num::NonZeroU64;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use li_core_interface::{LogicalModelName, NodeRole, NodeState};
use li_gateway_manager::{
    GatewayConfiguration, GatewayConfigurationFile, GatewayConfigurationMode, GatewayError,
    GatewayExecution, GatewayExecutionFailureKind, GatewayHealthServer, GatewayHttpError,
    GatewayHttpHandler, GatewayHttpRelayTokenProvider, GatewayHttpTokenProvider, GatewayMode,
    GatewayNativeExecutionProvider, GatewayNativeFileIo, GatewayProcess, GatewayProcessHandlers,
    GatewayProcessRunControl, GatewayProcessRuntimeCounterProvider, GatewayResidentIdentity,
    GatewayTelemetryFailureHandler, GatewayTelemetryResident, GatewayTokenCountClient,
    SystemGatewayClock, SystemGatewayHttpRequestIdProvider, SystemGatewayNativeFileIo,
    SystemGatewayNativeHttpIo, SystemGatewayProcessRunControl, SystemGatewayQueueWaiter,
    SystemGatewayTelemetryPublisher,
};
use li_node_manager::SystemNodeGatewayInventoryClock;

#[cfg(target_os = "macos")]
use li_placement_manager::{
    FilesystemPlacementMaterialReader, ShellFreeCommand, SystemPlacementMaterialIo,
    SystemShellFreeCommandRunner,
};

#[cfg(target_os = "linux")]
use li_gateway_manager::{GatewayProtectionCachePolicy, GatewayProtectionLeaseProvider};
#[cfg(target_os = "linux")]
use li_node_manager::NodeProtectionLocalClientConfiguration;

// Names stable process-boundary failures without exposing paths, credentials, or provider detail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreGatewayProcessError {
    InvalidArguments,
    ConfigurationUnavailable,
    CompositionUnavailable,
    RuntimeUnavailable,
}

impl fmt::Display for CoreGatewayProcessError {
    // Presents one fixed resident-process failure suitable for native service logs.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArguments => formatter.write_str("li_gateway arguments are invalid"),
            Self::ConfigurationUnavailable => {
                formatter.write_str("li_gateway configuration is unavailable")
            }
            Self::CompositionUnavailable => {
                formatter.write_str("li_gateway composition is unavailable")
            }
            Self::RuntimeUnavailable => formatter.write_str("li_gateway runtime failed"),
        }
    }
}

impl Error for CoreGatewayProcessError {}

// Holds the one strict command-line input emitted by CoreProcessLayout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreGatewayProcessArguments {
    configuration: PathBuf,
}

// Interrupts queued request waits during resident shutdown.
trait CoreGatewayQueueControl {
    // Makes current and future queue waits terminal.
    fn interrupt(&self) -> Result<(), CoreGatewayProcessError>;
}

impl CoreGatewayQueueControl for SystemGatewayQueueWaiter {
    // Delegates the concrete queue interruption with stable process failure mapping.
    fn interrupt(&self) -> Result<(), CoreGatewayProcessError> {
        SystemGatewayQueueWaiter::interrupt(self)
            .map_err(|_| CoreGatewayProcessError::RuntimeUnavailable)
    }
}

// Joins every retained public/private listener and connection worker.
trait CoreGatewayListenerControl {
    // Stops and joins the complete listener set.
    fn join(&self) -> Result<(), CoreGatewayProcessError>;
}

impl CoreGatewayListenerControl for GatewayProcess {
    // Delegates complete listener shutdown with stable process failure mapping.
    fn join(&self) -> Result<(), CoreGatewayProcessError> {
        GatewayProcess::join(self).map_err(|_| CoreGatewayProcessError::RuntimeUnavailable)
    }
}

// Stops and joins the periodic telemetry publication worker.
trait CoreGatewayTelemetryControl {
    // Interrupts the active cadence wait.
    fn stop(&self) -> Result<(), CoreGatewayProcessError>;

    // Joins the exact cadence worker and returns its terminal publication state.
    fn join(&self) -> Result<(), CoreGatewayProcessError>;
}

impl CoreGatewayTelemetryControl for GatewayTelemetryResident {
    // Delegates cadence interruption with stable process failure mapping.
    fn stop(&self) -> Result<(), CoreGatewayProcessError> {
        GatewayTelemetryResident::stop(self)
            .map_err(|_| CoreGatewayProcessError::RuntimeUnavailable)
    }

    // Delegates worker join with stable process failure mapping.
    fn join(&self) -> Result<(), CoreGatewayProcessError> {
        GatewayTelemetryResident::join(self)
            .map_err(|_| CoreGatewayProcessError::RuntimeUnavailable)
    }
}

// Stops and joins the platform-selected placement-safety resident.
trait CoreGatewayProtectionControl: Send + Sync {
    // Interrupts resident polling without coupling Node supervision.
    fn stop(&self) -> Result<(), CoreGatewayProcessError>;

    // Joins the exact worker after any bounded in-flight exchange completes.
    fn join(&self) -> Result<(), CoreGatewayProcessError>;
}

// Owns the optional Linux protection resident behind one idempotent lifecycle.
struct CoreGatewayProtectionLifecycle {
    resident: Mutex<Option<crate::CoreGatewayProtectionResident>>,
}

impl CoreGatewayProtectionLifecycle {
    // Creates one active lifecycle around an already-started resident.
    #[cfg(any(target_os = "linux", test))]
    const fn active(resident: crate::CoreGatewayProtectionResident) -> Self {
        Self {
            resident: Mutex::new(Some(resident)),
        }
    }

    // Creates one explicit fail-closed lifecycle for a platform without a native provider.
    #[cfg(target_os = "macos")]
    const fn unavailable() -> Self {
        Self {
            resident: Mutex::new(None),
        }
    }
}

impl Drop for CoreGatewayProtectionLifecycle {
    // Stops and joins an active worker when later composition exits before explicit ownership.
    fn drop(&mut self) {
        let resident = match self.resident.get_mut() {
            Ok(resident) => resident,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(mut resident) = resident.take() {
            resident.stop();
            let _ = resident.join();
        }
    }
}

impl CoreGatewayProtectionControl for CoreGatewayProtectionLifecycle {
    // Stops an active resident and leaves an unavailable platform inert.
    fn stop(&self) -> Result<(), CoreGatewayProcessError> {
        let resident = self
            .resident
            .lock()
            .map_err(|_| CoreGatewayProcessError::RuntimeUnavailable)?;
        if let Some(resident) = resident.as_ref() {
            resident.stop();
        }
        Ok(())
    }

    // Takes and joins the worker exactly once.
    fn join(&self) -> Result<(), CoreGatewayProcessError> {
        let mut resident = self
            .resident
            .lock()
            .map_err(|_| CoreGatewayProcessError::RuntimeUnavailable)?;
        if let Some(mut resident) = resident.take() {
            resident
                .join()
                .map_err(|_| CoreGatewayProcessError::RuntimeUnavailable)?;
        }
        Ok(())
    }
}

// Stops and joins the dedicated owner-local Gateway health endpoint.
trait CoreGatewayHealthControl {
    // Interrupts the listener and every stalled accepted connection.
    fn stop(&self) -> Result<(), CoreGatewayProcessError>;

    // Joins the listener and every worker before removing its exact socket.
    fn join(&self) -> Result<(), CoreGatewayProcessError>;
}

impl CoreGatewayHealthControl for GatewayHealthServer {
    // Delegates health-listener interruption with stable process failure mapping.
    fn stop(&self) -> Result<(), CoreGatewayProcessError> {
        GatewayHealthServer::stop(self).map_err(|_| CoreGatewayProcessError::RuntimeUnavailable)
    }

    // Delegates complete health-listener shutdown with stable process failure mapping.
    fn join(&self) -> Result<(), CoreGatewayProcessError> {
        GatewayHealthServer::join(self).map_err(|_| CoreGatewayProcessError::RuntimeUnavailable)
    }
}

impl CoreGatewayProcessArguments {
    // Parses exactly `--configuration ABSOLUTE_PATH` without accepting aliases or extra fields.
    pub fn parse(
        arguments: impl IntoIterator<Item = OsString>,
    ) -> Result<Self, CoreGatewayProcessError> {
        let arguments = arguments.into_iter().collect::<Vec<_>>();
        if arguments.len() != 2 || arguments[0] != OsStr::new("--configuration") {
            return Err(CoreGatewayProcessError::InvalidArguments);
        }
        let configuration = PathBuf::from(&arguments[1]);
        if !configuration.is_absolute() {
            return Err(CoreGatewayProcessError::InvalidArguments);
        }
        Ok(Self { configuration })
    }

    // Returns the exact absolute configuration selected by CoreProcessLayout.
    pub fn configuration(&self) -> &std::path::Path {
        &self.configuration
    }
}

// Authenticates and dispatches exact token counting across deterministic Gateway-owned routes.
struct PublicGatewayTokenProvider {
    manager: Arc<li_gateway_manager::GatewayManager>,
    client: Arc<GatewayTokenCountClient>,
}

impl PublicGatewayTokenProvider {
    // Creates one public token provider without duplicating route or authentication policy.
    const fn new(
        manager: Arc<li_gateway_manager::GatewayManager>,
        client: Arc<GatewayTokenCountClient>,
    ) -> Self {
        Self { manager, client }
    }
}

impl GatewayHttpTokenProvider for PublicGatewayTokenProvider {
    // Authenticates before native work and returns one exact positive Engine count.
    fn count(
        &self,
        bearer_token: &str,
        model: &LogicalModelName,
        normalized_body: &[u8],
    ) -> Result<NonZeroU64, GatewayHttpError> {
        self.manager
            .authorize_public_token_count(bearer_token, model)
            .map_err(token_authorization_error)?;
        count_tokens(
            self.manager.as_ref(),
            self.client.as_ref(),
            model,
            normalized_body,
        )
    }
}

// Authenticates private main-to-child token counting through the same Gateway authority.
struct RelayGatewayTokenProvider {
    manager: Arc<li_gateway_manager::GatewayManager>,
    client: Arc<GatewayTokenCountClient>,
}

impl RelayGatewayTokenProvider {
    // Creates one private token provider without copying relay authorization policy.
    const fn new(
        manager: Arc<li_gateway_manager::GatewayManager>,
        client: Arc<GatewayTokenCountClient>,
    ) -> Self {
        Self { manager, client }
    }

    // Authorizes one relay and returns one exact positive local Engine count.
    fn count_authorized(
        &self,
        relay_credential: &str,
        model: &LogicalModelName,
        normalized_body: &[u8],
    ) -> Result<NonZeroU64, GatewayHttpError> {
        self.manager
            .authorize_relay_token_count(relay_credential)
            .map_err(token_authorization_error)?;
        count_tokens(
            self.manager.as_ref(),
            self.client.as_ref(),
            model,
            normalized_body,
        )
    }
}

impl GatewayHttpTokenProvider for RelayGatewayTokenProvider {
    // Authenticates private inference preparation before contacting a local Engine.
    fn count(
        &self,
        relay_credential: &str,
        model: &LogicalModelName,
        normalized_body: &[u8],
    ) -> Result<NonZeroU64, GatewayHttpError> {
        self.count_authorized(relay_credential, model, normalized_body)
    }
}

impl GatewayHttpRelayTokenProvider for RelayGatewayTokenProvider {
    // Authenticates the dedicated private token-count endpoint before native work.
    fn count(
        &self,
        relay_credential: &str,
        model: &LogicalModelName,
        normalized_body: &[u8],
    ) -> Result<NonZeroU64, GatewayHttpError> {
        self.count_authorized(relay_credential, model, normalized_body)
    }
}

// Loads exact process state, composes concrete providers, and owns clean shutdown.
pub fn run_core_gateway_process(
    arguments: CoreGatewayProcessArguments,
) -> Result<(), CoreGatewayProcessError> {
    let owner_user_id = effective_user_id();
    let files: Arc<dyn GatewayNativeFileIo> = Arc::new(SystemGatewayNativeFileIo);
    let configuration_file =
        GatewayConfigurationFile::new(owner_user_id, arguments.configuration().to_path_buf())
            .map_err(|_| CoreGatewayProcessError::ConfigurationUnavailable)?;
    let configuration = GatewayConfiguration::load(&configuration_file, files.as_ref())
        .map_err(|_| CoreGatewayProcessError::ConfigurationUnavailable)?;
    let run_control = Arc::new(
        SystemGatewayProcessRunControl::install()
            .map_err(|_| CoreGatewayProcessError::CompositionUnavailable)?,
    );
    let result = run_composed_gateway(
        &configuration,
        owner_user_id,
        files,
        run_control.as_ref(),
        run_control.clone(),
    );
    let control_result = run_control
        .join()
        .map_err(|_| CoreGatewayProcessError::RuntimeUnavailable);
    result.and(control_result)
}

// Composes every concrete cross-manager port before binding either listener.
fn run_composed_gateway(
    configuration: &GatewayConfiguration,
    owner_user_id: u32,
    files: Arc<dyn GatewayNativeFileIo>,
    run_control: &dyn GatewayProcessRunControl,
    telemetry_failure: Arc<dyn GatewayTelemetryFailureHandler>,
) -> Result<(), CoreGatewayProcessError> {
    let node = Arc::new(
        crate::li_core_gateway_node_client::CoreGatewayNodeClient::open(
            configuration.node_socket_path().to_path_buf(),
        )
        .map_err(|_| CoreGatewayProcessError::CompositionUnavailable)?,
    );
    let local = node.local_node();
    if local.state() != NodeState::Active {
        return Err(CoreGatewayProcessError::CompositionUnavailable);
    }
    if local.identity().node_id() != configuration.node_id() {
        return Err(CoreGatewayProcessError::CompositionUnavailable);
    }
    let mode = gateway_mode(configuration, node.as_ref(), local.role())?;
    let gateway_authentication = node.clone();
    let routes = node.clone();
    let targets = node.clone();
    let native_http = Arc::new(SystemGatewayNativeHttpIo);
    let native_execution = Arc::new(GatewayNativeExecutionProvider::new(
        targets.clone(),
        files.clone(),
        native_http.clone(),
    ));
    let token_client = Arc::new(GatewayTokenCountClient::new(
        targets,
        files.clone(),
        native_http,
    ));
    let usage = node.clone();
    let counters = Arc::new(GatewayProcessRuntimeCounterProvider::new(node.clone()));
    let telemetry = Arc::new(
        SystemGatewayTelemetryPublisher::new(
            configuration.telemetry_file().to_path_buf(),
            owner_user_id,
            counters.clone(),
        )
        .map_err(|_| CoreGatewayProcessError::CompositionUnavailable)?,
    );
    let relay_authorization = node.clone();
    #[cfg(target_os = "linux")]
    let (protection, protection_lifecycle) = compose_gateway_protection(
        configuration,
        owner_user_id,
        node.local_node().identity().node_id().clone(),
    )?;
    #[cfg(target_os = "linux")]
    let manager = Arc::new(
        li_gateway_manager::GatewayManager::new_with_telemetry(
            mode,
            gateway_authentication,
            relay_authorization,
            routes,
            protection,
            Arc::new(SystemGatewayClock::new()),
            usage,
            telemetry,
        )
        .map_err(|_| CoreGatewayProcessError::CompositionUnavailable)?,
    );
    #[cfg(target_os = "macos")]
    let protection_lifecycle: Arc<dyn CoreGatewayProtectionControl> =
        Arc::new(CoreGatewayProtectionLifecycle::unavailable());
    #[cfg(target_os = "macos")]
    let manager = {
        let safety = configuration
            .macos_placement_safety()
            .ok_or(CoreGatewayProcessError::CompositionUnavailable)?;
        let material = FilesystemPlacementMaterialReader::new(
            safety.placement_material_root().to_path_buf(),
            owner_user_id,
            Arc::new(SystemPlacementMaterialIo),
            node.clone(),
        )
        .map_err(|_| CoreGatewayProcessError::CompositionUnavailable)?;
        let launchctl = ShellFreeCommand::new(
            safety.launchctl_command().to_path_buf(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            safety.command_working_directory().to_path_buf(),
        )
        .map_err(|_| CoreGatewayProcessError::CompositionUnavailable)?;
        let safety = Arc::new(
            crate::li_core_gateway_macos_safety::SystemCoreGatewayMacOsSafetyProvider::new(
                node.local_node().identity().node_id().clone(),
                node.local_node().identity().installation_id().clone(),
                owner_user_id,
                safety.launch_agents_root().to_path_buf(),
                safety.lease_milliseconds(),
                node.clone(),
                material,
                launchctl,
                Arc::new(SystemShellFreeCommandRunner),
                Arc::new(SystemGatewayClock::new()),
            )
            .map_err(|_| CoreGatewayProcessError::CompositionUnavailable)?,
        );
        Arc::new(
            li_gateway_manager::GatewayManager::new_with_macos_safety_and_telemetry(
                mode,
                gateway_authentication,
                relay_authorization,
                routes,
                safety,
                Arc::new(SystemGatewayClock::new()),
                usage,
                telemetry,
            )
            .map_err(|_| CoreGatewayProcessError::CompositionUnavailable)?,
        )
    };
    let queue_waiter = Arc::new(SystemGatewayQueueWaiter::default());
    let execution = Arc::new(GatewayExecution::new(
        manager.clone(),
        native_execution,
        queue_waiter.clone(),
    ));
    let handlers = gateway_handlers(
        configuration,
        node,
        manager.clone(),
        token_client,
        execution,
    )?;
    let process = Arc::new(
        GatewayProcess::start(configuration, handlers, files.as_ref())
            .map_err(|_| CoreGatewayProcessError::RuntimeUnavailable)?,
    );
    if counters.bind(&process).is_err() {
        let _ = process.join();
        return Err(CoreGatewayProcessError::RuntimeUnavailable);
    }
    let telemetry_resident = match GatewayTelemetryResident::start(
        manager.clone(),
        configuration.telemetry_cadence(),
        telemetry_failure,
    ) {
        Ok(resident) => resident,
        Err(_) => {
            let _ = process.join();
            return Err(CoreGatewayProcessError::RuntimeUnavailable);
        }
    };
    let health = GatewayHealthServer::start(
        configuration.health().clone(),
        GatewayResidentIdentity::from_configuration(configuration),
        manager,
    );
    start_gateway_health_lifecycle(
        health.map_err(|_| CoreGatewayProcessError::RuntimeUnavailable),
        run_control,
        queue_waiter.as_ref(),
        process.as_ref(),
        &telemetry_resident,
        protection_lifecycle.as_ref(),
    )
}

// Selects Linux Watchdog protection from the dedicated Node-owned channel.
#[cfg(target_os = "linux")]
fn compose_gateway_protection(
    configuration: &GatewayConfiguration,
    owner_user_id: u32,
    node_id: li_core_interface::NodeId,
) -> Result<
    (
        Arc<dyn GatewayProtectionLeaseProvider>,
        Arc<dyn CoreGatewayProtectionControl>,
    ),
    CoreGatewayProcessError,
> {
    let channel = configuration
        .node_protection()
        .ok_or(CoreGatewayProcessError::CompositionUnavailable)?;
    let client = NodeProtectionLocalClientConfiguration::new(
        channel.socket_path().to_path_buf(),
        owner_user_id,
        channel.read_timeout(),
        channel.write_timeout(),
    )
    .map_err(|_| CoreGatewayProcessError::CompositionUnavailable)?;
    let cache = GatewayProtectionCachePolicy::new(channel.maximum_cache_milliseconds())
        .map_err(|_| CoreGatewayProcessError::CompositionUnavailable)?;
    let provider = Arc::new(
        crate::CoreGatewayNodeProtectionProvider::new(node_id, client, cache)
            .map_err(|_| CoreGatewayProcessError::CompositionUnavailable)?,
    );
    let resident =
        crate::CoreGatewayProtectionResident::start(provider.clone(), channel.poll_interval())
            .map_err(|_| CoreGatewayProcessError::RuntimeUnavailable)?;
    Ok((
        provider,
        Arc::new(CoreGatewayProtectionLifecycle::active(resident)),
    ))
}

// Rolls back every earlier resident when health startup fails, otherwise enters the run loop.
fn start_gateway_health_lifecycle<Health: CoreGatewayHealthControl>(
    health: Result<Health, CoreGatewayProcessError>,
    run_control: &dyn GatewayProcessRunControl,
    queue: &dyn CoreGatewayQueueControl,
    listeners: &dyn CoreGatewayListenerControl,
    telemetry: &dyn CoreGatewayTelemetryControl,
    protection: &dyn CoreGatewayProtectionControl,
) -> Result<(), CoreGatewayProcessError> {
    match health {
        Ok(health) => finish_gateway_lifecycle(
            run_control,
            queue,
            listeners,
            telemetry,
            protection,
            &health,
        ),
        Err(error) => {
            let rollback = rollback_gateway_startup(queue, listeners, telemetry, protection);
            match rollback {
                Ok(()) => Err(error),
                Err(rollback_error) => Err(rollback_error),
            }
        }
    }
}

// Interrupts queues and joins every already-started owner after a later startup failure.
fn rollback_gateway_startup(
    queue: &dyn CoreGatewayQueueControl,
    listeners: &dyn CoreGatewayListenerControl,
    telemetry: &dyn CoreGatewayTelemetryControl,
    protection: &dyn CoreGatewayProtectionControl,
) -> Result<(), CoreGatewayProcessError> {
    let queue = queue.interrupt();
    let protection_stop = protection.stop();
    let telemetry_stop = telemetry.stop();
    let listeners = listeners.join();
    let protection_join = protection.join();
    let telemetry_join = telemetry.join();
    queue
        .and(protection_stop)
        .and(telemetry_stop)
        .and(listeners)
        .and(protection_join)
        .and(telemetry_join)
}

// Waits once, interrupts queues, and joins every resident owner without short-circuiting cleanup.
fn finish_gateway_lifecycle(
    run_control: &dyn GatewayProcessRunControl,
    queue: &dyn CoreGatewayQueueControl,
    listeners: &dyn CoreGatewayListenerControl,
    telemetry: &dyn CoreGatewayTelemetryControl,
    protection: &dyn CoreGatewayProtectionControl,
    health: &dyn CoreGatewayHealthControl,
) -> Result<(), CoreGatewayProcessError> {
    let wait = run_control
        .wait_for_stop()
        .map_err(|_| CoreGatewayProcessError::RuntimeUnavailable);
    let queue = queue.interrupt();
    let health_stop = health.stop();
    let protection_stop = protection.stop();
    let telemetry_stop = telemetry.stop();
    let listeners = listeners.join();
    let health_join = health.join();
    let protection_join = protection.join();
    let telemetry_join = telemetry.join();
    wait.and(queue)
        .and(health_stop)
        .and(protection_stop)
        .and(telemetry_stop)
        .and(listeners)
        .and(health_join)
        .and(protection_join)
        .and(telemetry_join)
}

// Derives the exact Gateway role from active persisted Node state and strict configuration.
fn gateway_mode(
    configuration: &GatewayConfiguration,
    node: &crate::li_core_gateway_node_client::CoreGatewayNodeClient,
    role: NodeRole,
) -> Result<GatewayMode, CoreGatewayProcessError> {
    match (configuration.mode(), role) {
        (GatewayConfigurationMode::Main, NodeRole::Main) => Ok(GatewayMode::Main {
            local_node_id: node.local_node().identity().node_id().clone(),
        }),
        (GatewayConfigurationMode::Child, NodeRole::Child) => {
            let main = node
                .main_node()
                .map_err(|_| CoreGatewayProcessError::CompositionUnavailable)?;
            Ok(GatewayMode::Child {
                local_node_id: node.local_node().identity().node_id().clone(),
                main_node_id: main.identity().node_id().clone(),
            })
        }
        _ => Err(CoreGatewayProcessError::CompositionUnavailable),
    }
}

// Builds the exact main public-plus-private or child private-only handler set.
fn gateway_handlers(
    configuration: &GatewayConfiguration,
    node: Arc<crate::li_core_gateway_node_client::CoreGatewayNodeClient>,
    manager: Arc<li_gateway_manager::GatewayManager>,
    token_client: Arc<GatewayTokenCountClient>,
    execution: Arc<GatewayExecution>,
) -> Result<GatewayProcessHandlers, CoreGatewayProcessError> {
    let models = node.clone();
    let request_ids = Arc::new(SystemGatewayHttpRequestIdProvider::new());
    let relay_tokens = Arc::new(RelayGatewayTokenProvider::new(
        manager.clone(),
        token_client.clone(),
    ));
    let private = Arc::new(
        GatewayHttpHandler::new_with_relay_tokens(
            li_gateway_manager::GatewayHttpSurface::PrivateRelay,
            configuration.maximum_queue_milliseconds(),
            models.clone(),
            relay_tokens.clone(),
            (configuration.mode() == GatewayConfigurationMode::Child)
                .then_some(relay_tokens as Arc<dyn GatewayHttpRelayTokenProvider>),
            request_ids.clone(),
            execution.clone(),
        )
        .map_err(|_| CoreGatewayProcessError::CompositionUnavailable)?,
    );
    if configuration.mode() == GatewayConfigurationMode::Child {
        return GatewayProcessHandlers::child(private)
            .map_err(|_| CoreGatewayProcessError::CompositionUnavailable);
    }
    let public_tokens = Arc::new(PublicGatewayTokenProvider::new(
        manager.clone(),
        token_client,
    ));
    let model_list = Arc::new(
        crate::li_core_gateway_node_client::CoreGatewayNodeModelListProvider::new(
            node,
            manager.clone(),
            Arc::new(SystemNodeGatewayInventoryClock),
        ),
    );
    let public = Arc::new(
        GatewayHttpHandler::new_with_public_reads(
            configuration.maximum_queue_milliseconds(),
            models,
            manager,
            model_list,
            public_tokens,
            request_ids,
            execution,
        )
        .map_err(|_| CoreGatewayProcessError::CompositionUnavailable)?,
    );
    GatewayProcessHandlers::main(public, private)
        .map_err(|_| CoreGatewayProcessError::CompositionUnavailable)
}

// Tries deterministic healthy routes while preserving terminal contract failures.
fn count_tokens(
    manager: &li_gateway_manager::GatewayManager,
    client: &GatewayTokenCountClient,
    model: &LogicalModelName,
    normalized_body: &[u8],
) -> Result<NonZeroU64, GatewayHttpError> {
    let routes = manager
        .token_count_routes(model)
        .map_err(|_| token_provider_error())?;
    for route in routes {
        match client.count(&route, model, normalized_body) {
            Ok(count) => return NonZeroU64::new(count).ok_or_else(token_provider_error),
            Err(error) if error.kind() == GatewayExecutionFailureKind::RetryableBackend => {}
            Err(_) => return Err(token_provider_error()),
        }
    }
    Err(token_provider_error())
}

// Maps authentication failures without exposing credentials or provider state.
fn token_authorization_error(error: GatewayError) -> GatewayHttpError {
    match error {
        GatewayError::AuthenticationDenied | GatewayError::RelayDenied => {
            GatewayHttpError::new(401, "unauthorized", "credential is invalid or expired")
        }
        _ => token_provider_error(),
    }
}

// Returns one stable token-count provider failure.
fn token_provider_error() -> GatewayHttpError {
    GatewayHttpError::new(
        503,
        "token_count_unavailable",
        "exact token counting is temporarily unavailable",
    )
}

// Returns the effective account identity trusted by owner-only native file contracts.
fn effective_user_id() -> u32 {
    // SAFETY: geteuid has no preconditions and returns the current process credential identity.
    unsafe { libc::geteuid() }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;

    use li_core_interface::{
        CredentialId, DisplayName, EntityTimestamps, InstallationId, MachineId, Node, NodeAddress,
        NodeId, NodeIdentity, PairingInviteId, UnixMilliseconds,
    };
    use li_database::{DatabaseConfiguration, DatabaseManager};
    use li_gateway_manager::{
        GatewayNativeFile, GatewayNativeIoError, GatewayProcessRunControlError,
    };
    use li_node_manager::{
        ExactNodePrivateLocalPeerIdentity, LocalNodeRoleReadinessProvider, LocalNodeRoleTransition,
        LocalNodeRoleTransitionProof, NodeManager, NodeManagerError, NodePairingApiError,
        NodePairingApiPort, NodePairingApproveRequest, NodePairingEnrollRequest,
        NodePairingEnrollment, NodePairingInvitation, NodePairingOpenRequest, NodePairingStatus,
        NodePrivateApi, NodePrivateApiError, NodePrivateAuthorizationProvider,
        NodePrivateLocalEndpoint, NodePrivateLocalServer, NodePrivateLocalServerConfiguration,
        NodePrivateLocalServerHandle, SystemNodePrivateLocalSocketProvider,
    };
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
        IsCa, KeyPair, KeyUsagePurpose,
    };

    use super::*;

    // Returns immediately so complete resident startup and shutdown remain deterministic.
    struct ImmediateRunControl;

    impl GatewayProcessRunControl for ImmediateRunControl {
        // Requests shutdown as soon as every production provider and listener is live.
        fn wait_for_stop(&self) -> Result<(), GatewayProcessRunControlError> {
            Ok(())
        }
    }

    // Returns one deterministic run-control failure after complete startup.
    struct FailingRunControl;

    impl GatewayProcessRunControl for FailingRunControl {
        // Fails the wait boundary so cleanup must still interrupt and join every owner.
        fn wait_for_stop(&self) -> Result<(), GatewayProcessRunControlError> {
            Err(GatewayProcessRunControlError::unavailable())
        }
    }

    impl GatewayTelemetryFailureHandler for FailingRunControl {
        // Accepts an unreachable telemetry notification in the run-control failure fixture.
        fn telemetry_did_fail(
            &self,
        ) -> Result<(), li_gateway_manager::GatewayTelemetryResidentError> {
            Ok(())
        }
    }

    // Supplies the exact role-transition proof needed to construct one persisted child fixture.
    struct ExactRoleReadiness;

    impl LocalNodeRoleReadinessProvider for ExactRoleReadiness {
        // Binds one deterministic proof to the requested local and destination authority.
        fn proof(
            &self,
            local: &Node,
            transition: &LocalNodeRoleTransition,
            now: UnixMilliseconds,
        ) -> Result<LocalNodeRoleTransitionProof, NodeManagerError> {
            let LocalNodeRoleTransition::BecomeChild { main } = transition else {
                return Err(NodeManagerError::InvalidLocalRoleTransition {
                    reason: "the child fixture requires a destination main",
                });
            };
            LocalNodeRoleTransitionProof::new(
                local.identity().node_id().clone(),
                local.role(),
                transition.target_role(),
                main.identity().node_id().clone(),
                now,
                UnixMilliseconds::new(now.value() + 60_000),
            )
        }
    }

    // Records exact lifecycle ordering and optionally fails its owned boundary.
    struct LifecycleControl {
        calls: Arc<std::sync::Mutex<Vec<&'static str>>>,
        fail: bool,
    }

    impl CoreGatewayQueueControl for LifecycleControl {
        // Records queue interruption before returning the configured result.
        fn interrupt(&self) -> Result<(), CoreGatewayProcessError> {
            self.calls.lock().unwrap().push("queue_interrupt");
            lifecycle_result(self.fail)
        }
    }

    impl CoreGatewayListenerControl for LifecycleControl {
        // Records complete listener join before returning the configured result.
        fn join(&self) -> Result<(), CoreGatewayProcessError> {
            self.calls.lock().unwrap().push("listener_join");
            lifecycle_result(self.fail)
        }
    }

    impl CoreGatewayTelemetryControl for LifecycleControl {
        // Records cadence interruption before returning the configured result.
        fn stop(&self) -> Result<(), CoreGatewayProcessError> {
            self.calls.lock().unwrap().push("telemetry_stop");
            lifecycle_result(self.fail)
        }

        // Records cadence join before returning the configured result.
        fn join(&self) -> Result<(), CoreGatewayProcessError> {
            self.calls.lock().unwrap().push("telemetry_join");
            lifecycle_result(self.fail)
        }
    }

    impl CoreGatewayProtectionControl for LifecycleControl {
        // Records protection-resident interruption before returning the configured result.
        fn stop(&self) -> Result<(), CoreGatewayProcessError> {
            self.calls.lock().unwrap().push("protection_stop");
            lifecycle_result(self.fail)
        }

        // Records protection-resident join before returning the configured result.
        fn join(&self) -> Result<(), CoreGatewayProcessError> {
            self.calls.lock().unwrap().push("protection_join");
            lifecycle_result(self.fail)
        }
    }

    impl CoreGatewayHealthControl for LifecycleControl {
        // Records health interruption before returning the configured result.
        fn stop(&self) -> Result<(), CoreGatewayProcessError> {
            self.calls.lock().unwrap().push("health_stop");
            lifecycle_result(self.fail)
        }

        // Records health join before returning the configured result.
        fn join(&self) -> Result<(), CoreGatewayProcessError> {
            self.calls.lock().unwrap().push("health_join");
            lifecycle_result(self.fail)
        }
    }

    // Records one run-control wait and applies its configured deterministic result.
    struct LifecycleRunControl {
        calls: Arc<std::sync::Mutex<Vec<&'static str>>>,
        fail: bool,
    }

    impl GatewayProcessRunControl for LifecycleRunControl {
        // Records the one wait boundary before returning success or failure.
        fn wait_for_stop(&self) -> Result<(), GatewayProcessRunControlError> {
            self.calls.lock().unwrap().push("wait");
            if self.fail {
                Err(GatewayProcessRunControlError::unavailable())
            } else {
                Ok(())
            }
        }
    }

    // Converts one fixture switch to the stable process runtime result.
    fn lifecycle_result(fail: bool) -> Result<(), CoreGatewayProcessError> {
        if fail {
            Err(CoreGatewayProcessError::RuntimeUnavailable)
        } else {
            Ok(())
        }
    }

    impl GatewayTelemetryFailureHandler for ImmediateRunControl {
        // Accepts an unreachable test publication failure through the production capability.
        fn telemetry_did_fail(
            &self,
        ) -> Result<(), li_gateway_manager::GatewayTelemetryResidentError> {
            Ok(())
        }
    }

    // Supplies descriptor-shaped configuration and TLS files without secret filesystem fixtures.
    struct FileIo {
        files: BTreeMap<PathBuf, GatewayNativeFile>,
    }

    // Allows the owner-authenticated local process actions used by this composition fixture.
    struct AllowLocalAuthorization;

    impl NodePrivateAuthorizationProvider for AllowLocalAuthorization {
        // Accepts every action after the real local socket has authenticated the owner UID.
        fn authorize(
            &self,
            _principal_id: &CredentialId,
            _action: li_node_manager::NodePrivateAction,
        ) -> Result<(), NodePrivateApiError> {
            Ok(())
        }
    }

    // Rejects every pairing operation that Gateway startup cannot invoke.
    struct UnavailablePairing;

    impl NodePairingApiPort for UnavailablePairing {
        // Rejects an unexpected invitation request.
        fn open(
            &self,
            _request: &NodePairingOpenRequest,
        ) -> Result<NodePairingInvitation, NodePairingApiError> {
            Err(NodePairingApiError::Unavailable)
        }

        // Rejects an unexpected enrollment request.
        fn enroll(
            &self,
            _request: &NodePairingEnrollRequest,
        ) -> Result<NodePairingEnrollment, NodePairingApiError> {
            Err(NodePairingApiError::Unavailable)
        }

        // Rejects an unexpected approval request.
        fn approve(
            &self,
            _request: &NodePairingApproveRequest,
        ) -> Result<NodePairingStatus, NodePairingApiError> {
            Err(NodePairingApiError::Unavailable)
        }

        // Rejects an unexpected status request.
        fn status(
            &self,
            _invite_id: &PairingInviteId,
        ) -> Result<NodePairingStatus, NodePairingApiError> {
            Err(NodePairingApiError::Unavailable)
        }
    }

    impl GatewayNativeFileIo for FileIo {
        // Returns one exact bounded private-file observation.
        fn read_no_follow(
            &self,
            path: &Path,
            maximum_bytes: usize,
        ) -> Result<GatewayNativeFile, GatewayNativeIoError> {
            let file = self
                .files
                .get(path)
                .cloned()
                .ok_or_else(|| GatewayNativeIoError::terminal_before_head("missing"))?;
            if file.bytes().len() > maximum_bytes {
                return Err(GatewayNativeIoError::terminal_before_head("oversized"));
            }
            Ok(file)
        }
    }

    // Creates one active persisted main Node required by real Gateway composition.
    fn initialize_node(database_file: &Path) {
        let database =
            Arc::new(DatabaseManager::open(DatabaseConfiguration::new(database_file)).unwrap());
        let node = Node::new(
            NodeIdentity::new(
                NodeId::parse(&"1".repeat(32)).unwrap(),
                MachineId::parse(&"2".repeat(32)).unwrap(),
                InstallationId::parse(&"3".repeat(64)).unwrap(),
            ),
            DisplayName::parse("Home AI").unwrap(),
            NodeRole::Main,
            NodeState::Active,
            NodeAddress::parse("homeai.local").unwrap(),
            None,
            EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(1_000))
                .unwrap(),
        );
        let (manager, _) = NodeManager::open(database, node, "initialize-node").unwrap();
        manager.close().unwrap();
    }

    // Creates one active local child and its distinct active main authority atomically.
    fn initialize_child_node(database_file: &Path) {
        let database =
            Arc::new(DatabaseManager::open(DatabaseConfiguration::new(database_file)).unwrap());
        let local = Node::new(
            NodeIdentity::new(
                NodeId::parse(&"1".repeat(32)).unwrap(),
                MachineId::parse(&"2".repeat(32)).unwrap(),
                InstallationId::parse(&"3".repeat(64)).unwrap(),
            ),
            DisplayName::parse("Home AI").unwrap(),
            NodeRole::Main,
            NodeState::Active,
            NodeAddress::parse("homeai.local").unwrap(),
            None,
            EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(1_000))
                .unwrap(),
        );
        let main = Node::new(
            NodeIdentity::new(
                NodeId::parse(&"4".repeat(32)).unwrap(),
                MachineId::parse(&"5".repeat(32)).unwrap(),
                InstallationId::parse(&"6".repeat(64)).unwrap(),
            ),
            DisplayName::parse("Main AI").unwrap(),
            NodeRole::Main,
            NodeState::Active,
            NodeAddress::parse("main.local").unwrap(),
            None,
            EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(1_500))
                .unwrap(),
        );
        let (manager, _) = NodeManager::open(database, local, "initialize-child-node").unwrap();
        manager
            .transition_local_role(
                "become-child",
                1,
                LocalNodeRoleTransition::BecomeChild { main },
                UnixMilliseconds::new(2_000),
                &ExactRoleReadiness,
            )
            .unwrap();
        manager.close().unwrap();
    }

    // Starts the real owner-UID local Node transport over the persisted fixture identity.
    fn start_node_server(database_file: &Path, socket_path: &Path) -> NodePrivateLocalServerHandle {
        let database = Arc::new(
            DatabaseManager::open(DatabaseConfiguration::new(database_file)).expect("database"),
        );
        let manager = Arc::new(NodeManager::load(database).expect("Node manager"));
        let api = Arc::new(NodePrivateApi::new(
            manager.clone(),
            Arc::new(AllowLocalAuthorization),
            Arc::new(UnavailablePairing),
        ));
        let endpoint = Arc::new(NodePrivateLocalEndpoint::new(api));
        let configuration = NodePrivateLocalServerConfiguration::new(
            socket_path.to_path_buf(),
            effective_user_id(),
            4,
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(1),
            std::time::Duration::from_millis(2),
        )
        .expect("Node local configuration");
        NodePrivateLocalServer::new(
            configuration,
            endpoint,
            Arc::new(ExactNodePrivateLocalPeerIdentity::new(
                effective_user_id(),
                manager.local_node_id().clone(),
            )),
            Arc::new(SystemNodePrivateLocalSocketProvider),
        )
        .start()
        .expect("Node local server")
    }

    // Generates one CA plus server and client certificates entirely in memory.
    fn tls_identity() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut ca_parameters = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_parameters.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        ca_parameters.distinguished_name = distinguished_name("li-test-ca");
        let ca_key = KeyPair::generate().unwrap();
        let ca_certificate = ca_parameters.self_signed(&ca_key).unwrap();
        let mut server_parameters =
            CertificateParams::new(vec!["child.local".to_string()]).unwrap();
        server_parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        server_parameters.distinguished_name = distinguished_name("child.local");
        let server_key = KeyPair::generate().unwrap();
        let server_certificate = server_parameters
            .signed_by(&server_key, &ca_certificate, &ca_key)
            .unwrap();
        let mut client_parameters = CertificateParams::new(Vec::<String>::new()).unwrap();
        client_parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        client_parameters.distinguished_name = distinguished_name("li-test-main");
        let client_key = KeyPair::generate().unwrap();
        let client_certificate = client_parameters
            .signed_by(&client_key, &ca_certificate, &ca_key)
            .unwrap();
        (
            ca_certificate.pem().into_bytes(),
            server_certificate.pem().into_bytes(),
            server_key.serialize_pem().into_bytes(),
            client_certificate.pem().into_bytes(),
        )
    }

    // Returns one deterministic certificate subject.
    fn distinguished_name(common_name: &str) -> DistinguishedName {
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, common_name);
        name
    }

    // Creates one canonical owner-private directory accepted by local resident path guards.
    fn private_directory() -> tempfile::TempDir {
        let root = if cfg!(target_os = "macos") {
            "/private/tmp"
        } else {
            "/tmp"
        };
        let directory = tempfile::tempdir_in(root).unwrap();
        std::fs::set_permissions(
            directory.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        directory
    }

    // Builds one strict main configuration and its exact no-follow file provider.
    fn configuration(
        directory: &tempfile::TempDir,
        mode: &str,
    ) -> (GatewayConfiguration, Arc<dyn GatewayNativeFileIo>) {
        let owner_user_id = effective_user_id();
        let root = directory.path();
        std::fs::set_permissions(root, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .unwrap();
        let configuration_path = root.join("li_gateway.json");
        let node_socket = root.join("node.sock");
        let telemetry_directory = root.join("telemetry");
        std::fs::create_dir(&telemetry_directory).unwrap();
        std::fs::set_permissions(
            &telemetry_directory,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let telemetry_file = telemetry_directory.join("gateway_telemetry_v2");
        let health_socket = root.join("gateway_health.sock");
        let certificate_file = root.join("gateway.crt");
        let private_key_file = root.join("gateway.key");
        let client_ca_file = root.join("main-ca.crt");
        let client_certificate_file = root.join("main.crt");
        let (ca, certificate, private_key, client_certificate) = tls_identity();
        let mut document = serde_json::json!({
            "schema":{"name":"li_gateway_configuration","version":5},
            "node_id":"11111111111111111111111111111111",
            "core_release":"1.2.3",
            "core_source_identity":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "mode":mode,
            "health":{
                "socket_path":health_socket,
                "maximum_workers":4,
                "read_timeout_milliseconds":1000,
                "write_timeout_milliseconds":1000,
                "accept_poll_interval_milliseconds":5
            },
            "node_protection":{
                "socket_path":root.join("node_protection.sock"),
                "read_timeout_milliseconds":1000,
                "write_timeout_milliseconds":1000,
                "maximum_cache_milliseconds":2000,
                "poll_interval_milliseconds":500
            },
            "runtime":{
                "node_socket_path":node_socket,
                "telemetry_file":telemetry_file,
                "telemetry_cadence_milliseconds":100,
                "maximum_queue_milliseconds":0
            },
            "private_listener":{
                "address":"127.0.0.1:0",
                "maximum_connections":2,
                "tls":{
                    "server_certificate_file":certificate_file,
                    "server_private_key_file":private_key_file,
                    "client_ca_file":client_ca_file,
                    "client_certificate_file":client_certificate_file
                }
            }
        });
        if cfg!(target_os = "macos") {
            let placement_material = root.join("placement_material");
            let launch_agents = root.join("LaunchAgents");
            let command_workspace = root.join("command-workspace");
            for path in [&placement_material, &launch_agents, &command_workspace] {
                std::fs::create_dir(path).unwrap();
                std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o700))
                    .unwrap();
            }
            document.as_object_mut().unwrap().remove("node_protection");
            document.as_object_mut().unwrap().insert(
                "macos_placement_safety".to_string(),
                serde_json::json!({
                    "placement_material_root":placement_material,
                    "launch_agents_root":launch_agents,
                    "launchctl_command":"/bin/launchctl",
                    "command_working_directory":command_workspace,
                    "lease_milliseconds":2000
                }),
            );
        }
        if mode == "main" {
            let public_address = std::net::TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .to_string();
            document.as_object_mut().unwrap().insert(
                "public_listener".to_string(),
                serde_json::json!({"address":public_address,"maximum_connections":2}),
            );
        }
        let payload = serde_json::to_vec(&document).unwrap();
        let files = Arc::new(FileIo {
            files: [
                (configuration_path.clone(), payload),
                (certificate_file, certificate),
                (private_key_file, private_key),
                (client_ca_file, ca),
                (client_certificate_file, client_certificate),
            ]
            .into_iter()
            .map(|(path, bytes)| {
                (
                    path,
                    GatewayNativeFile::new(owner_user_id, 0o600, 1, bytes).unwrap(),
                )
            })
            .collect(),
        });
        let reference = GatewayConfigurationFile::new(owner_user_id, configuration_path).unwrap();
        let configuration = GatewayConfiguration::load(&reference, files.as_ref()).unwrap();
        (configuration, files)
    }

    // Starts the complete concrete main composition then joins both listeners and telemetry.
    #[test]
    fn concrete_main_composition_starts_and_stops_without_placeholders() {
        let directory = private_directory();
        let database = directory.path().join("core.sqlite3");
        initialize_node(&database);
        let _node_server = start_node_server(&database, &directory.path().join("node.sock"));
        let (configuration, files) = configuration(&directory, "main");
        run_composed_gateway(
            &configuration,
            effective_user_id(),
            files,
            &ImmediateRunControl,
            Arc::new(ImmediateRunControl),
        )
        .unwrap();
        assert!(directory
            .path()
            .join("telemetry")
            .join("gateway_telemetry_v2")
            .is_file());
    }

    // Starts one real child composition with only its authenticated private listener.
    #[test]
    fn concrete_child_composition_starts_private_only_and_stops_cleanly() {
        let directory = private_directory();
        let database = directory.path().join("core.sqlite3");
        initialize_child_node(&database);
        let _node_server = start_node_server(&database, &directory.path().join("node.sock"));
        let (configuration, files) = configuration(&directory, "child");
        assert!(configuration.public_listener().is_none());
        run_composed_gateway(
            &configuration,
            effective_user_id(),
            files,
            &ImmediateRunControl,
            Arc::new(ImmediateRunControl),
        )
        .unwrap();
        assert!(directory
            .path()
            .join("telemetry")
            .join("gateway_telemetry_v2")
            .is_file());
    }

    // Rejects role/configuration drift before any listener or telemetry publication is visible.
    #[test]
    fn concrete_composition_rejects_role_drift_before_startup() {
        let directory = private_directory();
        let database = directory.path().join("core.sqlite3");
        initialize_node(&database);
        let _node_server = start_node_server(&database, &directory.path().join("node.sock"));
        let (configuration, files) = configuration(&directory, "child");
        assert_eq!(
            run_composed_gateway(
                &configuration,
                effective_user_id(),
                files,
                &ImmediateRunControl,
                Arc::new(ImmediateRunControl),
            ),
            Err(CoreGatewayProcessError::CompositionUnavailable)
        );
        assert!(!directory
            .path()
            .join("telemetry")
            .join("gateway_telemetry_v2")
            .exists());
    }

    // Fails before listener or telemetry mutation when the owner-local Node endpoint is absent.
    #[test]
    fn concrete_composition_requires_the_local_node_endpoint() {
        let directory = private_directory();
        let (configuration, files) = configuration(&directory, "main");
        assert_eq!(
            run_composed_gateway(
                &configuration,
                effective_user_id(),
                files,
                &ImmediateRunControl,
                Arc::new(ImmediateRunControl),
            ),
            Err(CoreGatewayProcessError::CompositionUnavailable)
        );
        assert!(!directory
            .path()
            .join("telemetry")
            .join("gateway_telemetry_v2")
            .exists());
    }

    // Rolls back and releases the already-bound public listener when telemetry startup fails.
    #[test]
    fn telemetry_startup_failure_joins_started_listeners() {
        let directory = private_directory();
        let database = directory.path().join("core.sqlite3");
        initialize_node(&database);
        let _node_server = start_node_server(&database, &directory.path().join("node.sock"));
        let (configuration, files) = configuration(&directory, "main");
        let public_address = configuration.public_listener().unwrap().address();
        std::fs::set_permissions(
            directory.path().join("telemetry"),
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .unwrap();
        assert_eq!(
            run_composed_gateway(
                &configuration,
                effective_user_id(),
                files,
                &ImmediateRunControl,
                Arc::new(ImmediateRunControl),
            ),
            Err(CoreGatewayProcessError::RuntimeUnavailable)
        );
        let rebound = std::net::TcpListener::bind(public_address).unwrap();
        drop(rebound);
    }

    // Cleans every resident owner even when the run-control boundary fails after startup.
    #[test]
    fn run_control_failure_still_joins_concrete_process() {
        let directory = private_directory();
        let database = directory.path().join("core.sqlite3");
        initialize_node(&database);
        let _node_server = start_node_server(&database, &directory.path().join("node.sock"));
        let (configuration, files) = configuration(&directory, "main");
        let public_address = configuration.public_listener().unwrap().address();
        assert_eq!(
            run_composed_gateway(
                &configuration,
                effective_user_id(),
                files,
                &FailingRunControl,
                Arc::new(FailingRunControl),
            ),
            Err(CoreGatewayProcessError::RuntimeUnavailable)
        );
        let rebound = std::net::TcpListener::bind(public_address).unwrap();
        drop(rebound);
    }

    // Calls queue interruption and every join boundary even when all of them fail.
    #[test]
    fn lifecycle_failure_matrix_never_short_circuits_cleanup() {
        let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let run_control = LifecycleRunControl {
            calls: calls.clone(),
            fail: true,
        };
        let owner = LifecycleControl {
            calls: calls.clone(),
            fail: true,
        };
        assert_eq!(
            finish_gateway_lifecycle(&run_control, &owner, &owner, &owner, &owner, &owner),
            Err(CoreGatewayProcessError::RuntimeUnavailable)
        );
        assert_eq!(
            *calls.lock().unwrap(),
            vec![
                "wait",
                "queue_interrupt",
                "health_stop",
                "protection_stop",
                "telemetry_stop",
                "listener_join",
                "health_join",
                "protection_join",
                "telemetry_join"
            ]
        );
    }

    // Rolls back queues, telemetry, and listeners when the later health startup boundary fails.
    #[test]
    fn health_startup_failure_never_leaves_an_earlier_resident_detached() {
        let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let run_control = LifecycleRunControl {
            calls: calls.clone(),
            fail: false,
        };
        let owner = LifecycleControl {
            calls: calls.clone(),
            fail: false,
        };
        assert_eq!(
            start_gateway_health_lifecycle::<LifecycleControl>(
                Err(CoreGatewayProcessError::RuntimeUnavailable),
                &run_control,
                &owner,
                &owner,
                &owner,
                &owner,
            ),
            Err(CoreGatewayProcessError::RuntimeUnavailable)
        );
        assert_eq!(
            *calls.lock().unwrap(),
            vec![
                "queue_interrupt",
                "protection_stop",
                "telemetry_stop",
                "listener_join",
                "protection_join",
                "telemetry_join"
            ]
        );
    }

    // Joins an already-started protection worker when later composition returns an error.
    #[test]
    fn post_start_composition_failure_joins_protection_resident() {
        let directory = private_directory();
        let provider = Arc::new(
            crate::CoreGatewayNodeProtectionProvider::new(
                NodeId::parse(&"1".repeat(32)).unwrap(),
                li_node_manager::NodeProtectionLocalClientConfiguration::new(
                    directory.path().join("node_protection.sock"),
                    effective_user_id(),
                    std::time::Duration::from_secs(1),
                    std::time::Duration::from_secs(1),
                )
                .unwrap(),
                li_gateway_manager::GatewayProtectionCachePolicy::new(2_000).unwrap(),
            )
            .unwrap(),
        );
        let result = (|| -> Result<(), CoreGatewayProcessError> {
            let resident = crate::CoreGatewayProtectionResident::start(
                provider.clone(),
                std::time::Duration::from_secs(60),
            )
            .unwrap();
            let _lifecycle = CoreGatewayProtectionLifecycle::active(resident);
            Err(CoreGatewayProcessError::CompositionUnavailable)
        })();
        assert_eq!(result, Err(CoreGatewayProcessError::CompositionUnavailable));
        assert_eq!(Arc::strong_count(&provider), 1);
    }
}
