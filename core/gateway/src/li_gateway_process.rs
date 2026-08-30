// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::{
    GatewayConfiguration, GatewayConfigurationMode, GatewayHttpHandler, GatewayHttpSurface,
    GatewayListenerConfiguration, GatewayNativeFileIo, GatewayNativeServerHandle,
    GatewayNativeTlsServerConfiguration, GatewayPrivateListenerConfiguration,
    SystemGatewayHttpServer, SystemGatewayTlsServer,
};

// Describes one stable redacted Gateway process-boundary failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayProcessError {
    reason: &'static str,
}

impl GatewayProcessError {
    // Creates one internal stable failure without accepting provider detail.
    const fn new(reason: &'static str) -> Self {
        Self { reason }
    }

    // Returns the stable redacted process failure.
    pub const fn reason(&self) -> &'static str {
        self.reason
    }
}

impl fmt::Display for GatewayProcessError {
    // Presents one stable process failure without addresses or native detail.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason)
    }
}

impl Error for GatewayProcessError {}

// Prevents injected run control from carrying signal or platform detail into failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GatewayProcessRunControlError;

impl GatewayProcessRunControlError {
    // Creates the only closed run-control failure value.
    pub const fn unavailable() -> Self {
        Self
    }
}

// Blocks one resident process until its external signal owner requests shutdown.
pub trait GatewayProcessRunControl: Send + Sync {
    // Waits once for a stop request without owning listener or provider state.
    fn wait_for_stop(&self) -> Result<(), GatewayProcessRunControlError>;
}

// Binds already-composed route, target, authentication, and execution providers to surfaces.
pub struct GatewayProcessHandlers {
    mode: GatewayConfigurationMode,
    public: Option<Arc<GatewayHttpHandler>>,
    private: Arc<GatewayHttpHandler>,
}

impl GatewayProcessHandlers {
    // Creates the mandatory public plus private handler set for a main Gateway.
    pub fn main(
        public: Arc<GatewayHttpHandler>,
        private: Arc<GatewayHttpHandler>,
    ) -> Result<Self, GatewayProcessError> {
        if public.surface() != GatewayHttpSurface::Public
            || !public.has_public_reads()
            || private.surface() != GatewayHttpSurface::PrivateRelay
        {
            return Err(GatewayProcessError::new(
                "Gateway process handler set is invalid",
            ));
        }
        Ok(Self {
            mode: GatewayConfigurationMode::Main,
            public: Some(public),
            private,
        })
    }

    // Creates the mandatory private-only handler set for a child Gateway.
    pub fn child(private: Arc<GatewayHttpHandler>) -> Result<Self, GatewayProcessError> {
        if private.surface() != GatewayHttpSurface::PrivateRelay {
            return Err(GatewayProcessError::new(
                "Gateway process handler set is invalid",
            ));
        }
        Ok(Self {
            mode: GatewayConfigurationMode::Child,
            public: None,
            private,
        })
    }
}

// Identifies one retained listener without exposing protocol implementation detail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GatewayProcessListenerSurface {
    Public,
    Private,
}

// Defines the exact lifecycle required from either system or deterministic test listeners.
trait GatewayProcessListenerLifecycle: Send + Sync {
    // Requests idempotent active-socket interruption.
    fn stop(&self) -> Result<(), GatewayProcessError>;

    // Joins the supervisor and every worker idempotently.
    fn join(&self) -> Result<(), GatewayProcessError>;

    // Returns current registered worker count.
    fn active_connections(&self) -> usize;

    // Returns the saturated rejected-connection count.
    fn rejected_connections(&self) -> u64;
}

impl GatewayProcessListenerLifecycle for GatewayNativeServerHandle {
    // Delegates stop while redacting native listener detail.
    fn stop(&self) -> Result<(), GatewayProcessError> {
        GatewayNativeServerHandle::stop(self)
            .map_err(|_| GatewayProcessError::new("Gateway listener shutdown failed"))
    }

    // Delegates join while redacting native worker detail.
    fn join(&self) -> Result<(), GatewayProcessError> {
        GatewayNativeServerHandle::join(self)
            .map_err(|_| GatewayProcessError::new("Gateway listener shutdown failed"))
    }

    // Returns exact registered worker ownership from the resident handle.
    fn active_connections(&self) -> usize {
        GatewayNativeServerHandle::active_connections(self)
    }

    // Returns exact saturated rejection accounting from the resident handle.
    fn rejected_connections(&self) -> u64 {
        GatewayNativeServerHandle::rejected_connections(self)
    }
}

// Retains one exact listener address and its complete lifecycle owner.
struct GatewayProcessListener {
    surface: GatewayProcessListenerSurface,
    address: SocketAddr,
    lifecycle: Box<dyn GatewayProcessListenerLifecycle>,
}

// Separates system listener construction from process ordering and rollback policy.
trait GatewayProcessListenerFactory {
    type PrivateConfiguration;

    // Loads every private identity input before any listener becomes visible.
    fn prepare_private(
        &self,
        configuration: &GatewayPrivateListenerConfiguration,
        io: &dyn GatewayNativeFileIo,
    ) -> Result<Self::PrivateConfiguration, GatewayProcessError>;

    // Starts one fully configured public resident listener.
    fn start_public(
        &self,
        configuration: &GatewayListenerConfiguration,
        handler: Arc<GatewayHttpHandler>,
    ) -> Result<GatewayProcessListener, GatewayProcessError>;

    // Starts one fully authenticated private resident listener.
    fn start_private(
        &self,
        configuration: &GatewayPrivateListenerConfiguration,
        handler: Arc<GatewayHttpHandler>,
        private: Self::PrivateConfiguration,
    ) -> Result<GatewayProcessListener, GatewayProcessError>;
}

// Builds production public and private native listener implementations.
#[derive(Clone, Copy, Debug, Default)]
struct SystemGatewayProcessListenerFactory;

impl GatewayProcessListenerFactory for SystemGatewayProcessListenerFactory {
    type PrivateConfiguration = GatewayNativeTlsServerConfiguration;

    // Loads owner-bound TLS files before either main listener is started.
    fn prepare_private(
        &self,
        configuration: &GatewayPrivateListenerConfiguration,
        io: &dyn GatewayNativeFileIo,
    ) -> Result<Self::PrivateConfiguration, GatewayProcessError> {
        GatewayNativeTlsServerConfiguration::load(configuration.tls_files(), io).map_err(|_| {
            GatewayProcessError::new("Gateway private listener identity is unavailable")
        })
    }

    // Binds and starts one public native server under resident ownership.
    fn start_public(
        &self,
        configuration: &GatewayListenerConfiguration,
        handler: Arc<GatewayHttpHandler>,
    ) -> Result<GatewayProcessListener, GatewayProcessError> {
        let server = SystemGatewayHttpServer::bind(
            configuration.address(),
            configuration.maximum_connections(),
            handler,
        )
        .map_err(|_| GatewayProcessError::new("Gateway public listener cannot be started"))?;
        let address = server
            .local_address()
            .map_err(|_| GatewayProcessError::new("Gateway public listener cannot be started"))?;
        let handle = server
            .start()
            .map_err(|_| GatewayProcessError::new("Gateway public listener cannot be started"))?;
        Ok(GatewayProcessListener {
            surface: GatewayProcessListenerSurface::Public,
            address,
            lifecycle: Box::new(handle),
        })
    }

    // Binds and starts one private native server under resident ownership.
    fn start_private(
        &self,
        configuration: &GatewayPrivateListenerConfiguration,
        handler: Arc<GatewayHttpHandler>,
        private: Self::PrivateConfiguration,
    ) -> Result<GatewayProcessListener, GatewayProcessError> {
        let server = SystemGatewayTlsServer::bind(
            configuration.listener().address(),
            configuration.listener().maximum_connections(),
            handler,
            private,
        )
        .map_err(|_| GatewayProcessError::new("Gateway private listener cannot be started"))?;
        let address = server
            .local_address()
            .map_err(|_| GatewayProcessError::new("Gateway private listener cannot be started"))?;
        let handle = server
            .start()
            .map_err(|_| GatewayProcessError::new("Gateway private listener cannot be started"))?;
        Ok(GatewayProcessListener {
            surface: GatewayProcessListenerSurface::Private,
            address,
            lifecycle: Box::new(handle),
        })
    }
}

// Owns every listener of one exact main or child Gateway process.
pub struct GatewayProcess {
    mode: GatewayConfigurationMode,
    listeners: Vec<GatewayProcessListener>,
}

impl GatewayProcess {
    // Prepares private identity and starts the exact configured system listener set.
    pub fn start(
        configuration: &GatewayConfiguration,
        handlers: GatewayProcessHandlers,
        io: &dyn GatewayNativeFileIo,
    ) -> Result<Self, GatewayProcessError> {
        Self::start_with_factory(
            configuration,
            handlers,
            io,
            &SystemGatewayProcessListenerFactory,
        )
    }

    // Prepares all private state, starts listeners in order, and rolls back partial startup.
    fn start_with_factory<Factory: GatewayProcessListenerFactory>(
        configuration: &GatewayConfiguration,
        handlers: GatewayProcessHandlers,
        io: &dyn GatewayNativeFileIo,
        factory: &Factory,
    ) -> Result<Self, GatewayProcessError> {
        if configuration.mode() != handlers.mode {
            return Err(GatewayProcessError::new(
                "Gateway configuration and handler modes do not match",
            ));
        }
        let private = factory.prepare_private(configuration.private_listener(), io)?;
        let mut listeners =
            Vec::with_capacity(if configuration.mode() == GatewayConfigurationMode::Main {
                2
            } else {
                1
            });
        if let Some(public_configuration) = configuration.public_listener() {
            let public_handler = handlers.public.ok_or_else(|| {
                GatewayProcessError::new("Gateway process handler set is invalid")
            })?;
            let public = factory.start_public(public_configuration, public_handler)?;
            listeners.push(public);
        }
        let private = match factory.start_private(
            configuration.private_listener(),
            handlers.private,
            private,
        ) {
            Ok(private) => private,
            Err(error) => {
                if shutdown_listeners(&listeners).is_err() {
                    return Err(GatewayProcessError::new("Gateway startup rollback failed"));
                }
                return Err(error);
            }
        };
        listeners.push(private);
        Ok(Self {
            mode: configuration.mode(),
            listeners,
        })
    }

    // Returns whether this process owns a main or child listener set.
    pub const fn mode(&self) -> GatewayConfigurationMode {
        self.mode
    }

    // Returns the bound public address only for a main process.
    pub fn public_address(&self) -> Option<SocketAddr> {
        self.listener(GatewayProcessListenerSurface::Public)
            .map(|listener| listener.address)
    }

    // Returns the mandatory bound private address.
    pub fn private_address(&self) -> Option<SocketAddr> {
        self.listener(GatewayProcessListenerSurface::Private)
            .map(|listener| listener.address)
    }

    // Returns the exact active worker count for one listener surface.
    pub fn active_connections(&self, surface: GatewayHttpSurface) -> usize {
        self.listener(process_surface(surface))
            .map(|listener| listener.lifecycle.active_connections())
            .unwrap_or(0)
    }

    // Returns the saturated rejection count for one listener surface.
    pub fn rejected_connections(&self, surface: GatewayHttpSurface) -> u64 {
        self.listener(process_surface(surface))
            .map(|listener| listener.lifecycle.rejected_connections())
            .unwrap_or(0)
    }

    // Requests idempotent active-socket interruption on every retained listener.
    pub fn stop(&self) -> Result<(), GatewayProcessError> {
        stop_listeners(&self.listeners)
    }

    // Stops and joins every retained listener without detaching after one failure.
    pub fn join(&self) -> Result<(), GatewayProcessError> {
        shutdown_listeners(&self.listeners)
    }

    // Waits for external run control and always shuts down every listener afterward.
    pub fn run(&self, control: &dyn GatewayProcessRunControl) -> Result<(), GatewayProcessError> {
        let wait = control
            .wait_for_stop()
            .map_err(|_| GatewayProcessError::new("Gateway run control is unavailable"));
        let shutdown = self.join();
        wait.and(shutdown)
    }

    // Finds one retained listener by its exact protocol surface.
    fn listener(&self, surface: GatewayProcessListenerSurface) -> Option<&GatewayProcessListener> {
        self.listeners
            .iter()
            .find(|listener| listener.surface == surface)
    }
}

impl Drop for GatewayProcess {
    // Prevents process-owner loss from detaching any listener or worker.
    fn drop(&mut self) {
        let _ = self.join();
    }
}

// Converts the public HTTP surface vocabulary to resident listener identity.
const fn process_surface(surface: GatewayHttpSurface) -> GatewayProcessListenerSurface {
    match surface {
        GatewayHttpSurface::Public => GatewayProcessListenerSurface::Public,
        GatewayHttpSurface::PrivateRelay => GatewayProcessListenerSurface::Private,
    }
}

// Stops every retained listener even when one stop operation fails.
fn stop_listeners(listeners: &[GatewayProcessListener]) -> Result<(), GatewayProcessError> {
    let mut result = Ok(());
    for listener in listeners {
        if let Err(error) = listener.lifecycle.stop() {
            result = Err(error);
        }
    }
    result
}

// Stops and joins every retained listener without short-circuiting cleanup.
fn shutdown_listeners(listeners: &[GatewayProcessListener]) -> Result<(), GatewayProcessError> {
    let mut result = stop_listeners(listeners);
    for listener in listeners {
        if let Err(error) = listener.lifecycle.join() {
            if result.is_ok() {
                result = Err(error);
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::Mutex;

    use li_core_interface::{LogicalModelName, Sha256Digest};
    use serde_json::json;

    use super::*;
    use crate::{
        GatewayChatCompletionRequest, GatewayError, GatewayHttpError, GatewayHttpExecutionProvider,
        GatewayHttpHealthProvider, GatewayHttpModelList, GatewayHttpModelListProvider,
        GatewayHttpModelProvider, GatewayHttpRequestIdProvider, GatewayHttpTokenProvider,
        GatewayNativeFile, GatewayNativeIoError, GatewayResponseWriter,
    };

    const CONFIGURATION_PATH: &str = "/private/li_gateway.json";
    const REQUEST_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    // Supplies one exact configuration document to process-composition tests.
    struct ConfigurationFileIo {
        bytes: Vec<u8>,
    }

    impl GatewayNativeFileIo for ConfigurationFileIo {
        // Returns one safe owner-only configuration observation.
        fn read_no_follow(
            &self,
            path: &Path,
            maximum_bytes: usize,
        ) -> Result<GatewayNativeFile, GatewayNativeIoError> {
            if path != Path::new(CONFIGURATION_PATH) || self.bytes.len() > maximum_bytes {
                return Err(GatewayNativeIoError::terminal_before_head("missing"));
            }
            GatewayNativeFile::new(501, 0o600, 1, self.bytes.clone())
        }
    }

    // Resolves every test request to one canonical model.
    struct ModelProvider;

    impl GatewayHttpModelProvider for ModelProvider {
        // Returns one fixed logical model without external state.
        fn resolve(&self, _requested_model: &str) -> Result<LogicalModelName, GatewayHttpError> {
            Ok(LogicalModelName::parse("model-a").unwrap())
        }
    }

    // Counts one exact prompt token for handler-shape validation.
    struct TokenProvider;

    impl GatewayHttpTokenProvider for TokenProvider {
        // Returns one positive fixed token count.
        fn count(
            &self,
            _bearer_token: &str,
            _model: &LogicalModelName,
            _normalized_body: &[u8],
        ) -> Result<NonZeroU64, GatewayHttpError> {
            Ok(NonZeroU64::new(1).unwrap())
        }
    }

    // Supplies one deterministic immutable request identity.
    struct RequestIdProvider;

    impl GatewayHttpRequestIdProvider for RequestIdProvider {
        // Returns one fixed SHA-256 request identity.
        fn next(&self) -> Result<Sha256Digest, GatewayHttpError> {
            Ok(Sha256Digest::parse(REQUEST_ID).unwrap())
        }
    }

    // Rejects every unreachable execution path in listener-composition tests.
    struct ExecutionProvider;

    impl GatewayHttpExecutionProvider for ExecutionProvider {
        // Rejects public forwarding without inventing a route.
        fn forward_public(
            &self,
            _bearer_token: &str,
            _request: GatewayChatCompletionRequest,
            _response: &mut dyn GatewayResponseWriter,
        ) -> Result<(), GatewayError> {
            Err(GatewayError::NoRoute)
        }

        // Rejects private forwarding without inventing a route.
        fn forward_relay(
            &self,
            _relay_credential: &str,
            _request: GatewayChatCompletionRequest,
            _response: &mut dyn GatewayResponseWriter,
        ) -> Result<(), GatewayError> {
            Err(GatewayError::NoRoute)
        }
    }

    // Reports deterministic healthy public readiness for handler composition.
    struct HealthProvider;

    impl GatewayHttpHealthProvider for HealthProvider {
        // Returns healthy without consulting a live manager.
        fn health(&self) -> Result<bool, GatewayHttpError> {
            Ok(true)
        }
    }

    // Returns one deterministic empty authenticated model list.
    struct ModelListProvider;

    impl GatewayHttpModelListProvider for ModelListProvider {
        // Returns one empty stable list without retaining its bearer.
        fn models(&self, _bearer_token: &str) -> Result<GatewayHttpModelList, GatewayHttpError> {
            GatewayHttpModelList::new(1, Vec::new())
        }
    }

    // Records listener lifecycle calls and supports deterministic injected failures.
    struct ListenerState {
        name: &'static str,
        events: Arc<Mutex<Vec<&'static str>>>,
        stop_calls: AtomicUsize,
        join_calls: AtomicUsize,
        rejected_connections: AtomicU64,
        fail_stop: bool,
        fail_join: bool,
    }

    impl ListenerState {
        // Creates one empty deterministic listener lifecycle record.
        fn new(
            name: &'static str,
            events: Arc<Mutex<Vec<&'static str>>>,
            fail_stop: bool,
            fail_join: bool,
        ) -> Self {
            Self {
                name,
                events,
                stop_calls: AtomicUsize::new(0),
                join_calls: AtomicUsize::new(0),
                rejected_connections: AtomicU64::new(0),
                fail_stop,
                fail_join,
            }
        }
    }

    // Owns one shared mock state through the process lifecycle trait.
    struct ListenerLifecycle {
        state: Arc<ListenerState>,
    }

    impl GatewayProcessListenerLifecycle for ListenerLifecycle {
        // Records one idempotent stop request and applies its injected outcome.
        fn stop(&self) -> Result<(), GatewayProcessError> {
            self.state.stop_calls.fetch_add(1, Ordering::AcqRel);
            self.state
                .events
                .lock()
                .unwrap()
                .push(if self.state.name == "public" {
                    "stop_public"
                } else {
                    "stop_private"
                });
            if self.state.fail_stop {
                return Err(GatewayProcessError::new("injected stop failure"));
            }
            Ok(())
        }

        // Records one idempotent join request and applies its injected outcome.
        fn join(&self) -> Result<(), GatewayProcessError> {
            self.state.join_calls.fetch_add(1, Ordering::AcqRel);
            self.state
                .events
                .lock()
                .unwrap()
                .push(if self.state.name == "public" {
                    "join_public"
                } else {
                    "join_private"
                });
            if self.state.fail_join {
                return Err(GatewayProcessError::new("injected join failure"));
            }
            Ok(())
        }

        // Returns no active workers for synthetic listener ownership.
        fn active_connections(&self) -> usize {
            0
        }

        // Returns the injected saturated rejection count.
        fn rejected_connections(&self) -> u64 {
            self.state.rejected_connections.load(Ordering::Acquire)
        }
    }

    // Starts deterministic synthetic listeners and records exact startup order.
    struct ListenerFactory {
        events: Arc<Mutex<Vec<&'static str>>>,
        listeners: Arc<Mutex<Vec<Arc<ListenerState>>>>,
        fail_prepare: bool,
        fail_public: bool,
        fail_private: bool,
        fail_public_stop: bool,
        fail_public_join: bool,
    }

    impl ListenerFactory {
        // Creates one ordinary deterministic listener factory.
        fn new() -> Self {
            Self {
                events: Arc::new(Mutex::new(Vec::new())),
                listeners: Arc::new(Mutex::new(Vec::new())),
                fail_prepare: false,
                fail_public: false,
                fail_private: false,
                fail_public_stop: false,
                fail_public_join: false,
            }
        }

        // Creates and retains one shared listener state for later assertions.
        fn listener(
            &self,
            name: &'static str,
            fail_stop: bool,
            fail_join: bool,
        ) -> Box<dyn GatewayProcessListenerLifecycle> {
            let state = Arc::new(ListenerState::new(
                name,
                self.events.clone(),
                fail_stop,
                fail_join,
            ));
            self.listeners.lock().unwrap().push(state.clone());
            Box::new(ListenerLifecycle { state })
        }
    }

    impl GatewayProcessListenerFactory for ListenerFactory {
        type PrivateConfiguration = ();

        // Records private preflight and returns its deterministic outcome.
        fn prepare_private(
            &self,
            _configuration: &GatewayPrivateListenerConfiguration,
            _io: &dyn GatewayNativeFileIo,
        ) -> Result<Self::PrivateConfiguration, GatewayProcessError> {
            self.events.lock().unwrap().push("prepare_private");
            if self.fail_prepare {
                return Err(GatewayProcessError::new("injected prepare failure"));
            }
            Ok(())
        }

        // Records and starts one synthetic public listener.
        fn start_public(
            &self,
            configuration: &GatewayListenerConfiguration,
            _handler: Arc<GatewayHttpHandler>,
        ) -> Result<GatewayProcessListener, GatewayProcessError> {
            self.events.lock().unwrap().push("start_public");
            if self.fail_public {
                return Err(GatewayProcessError::new("injected public failure"));
            }
            Ok(GatewayProcessListener {
                surface: GatewayProcessListenerSurface::Public,
                address: configuration.address(),
                lifecycle: self.listener("public", self.fail_public_stop, self.fail_public_join),
            })
        }

        // Records and starts one synthetic private listener.
        fn start_private(
            &self,
            configuration: &GatewayPrivateListenerConfiguration,
            _handler: Arc<GatewayHttpHandler>,
            _private: Self::PrivateConfiguration,
        ) -> Result<GatewayProcessListener, GatewayProcessError> {
            self.events.lock().unwrap().push("start_private");
            if self.fail_private {
                return Err(GatewayProcessError::new("injected private failure"));
            }
            Ok(GatewayProcessListener {
                surface: GatewayProcessListenerSurface::Private,
                address: configuration.listener().address(),
                lifecycle: self.listener("private", false, false),
            })
        }
    }

    // Returns immediately with one configured deterministic run-control outcome.
    struct RunControl {
        result: Result<(), GatewayProcessRunControlError>,
    }

    impl GatewayProcessRunControl for RunControl {
        // Returns the configured signal-wait outcome exactly once per call.
        fn wait_for_stop(&self) -> Result<(), GatewayProcessRunControlError> {
            self.result
        }
    }

    // Loads one exact main or child process configuration through the real loader.
    fn configuration(mode: GatewayConfigurationMode) -> GatewayConfiguration {
        let mut document = json!({
            "schema":{"name":"li_gateway_configuration","version":5},
            "node_id":"11111111111111111111111111111111",
            "core_release":"1.2.3",
            "core_source_identity":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "mode": if mode == GatewayConfigurationMode::Main {"main"} else {"child"},
            "health":{
                "socket_path":"/private/gateway_health.sock",
                "maximum_workers":4,
                "read_timeout_milliseconds":1000,
                "write_timeout_milliseconds":1000,
                "accept_poll_interval_milliseconds":10
            },
            "node_protection":{
                "socket_path":"/private/node_protection.sock",
                "read_timeout_milliseconds":1000,
                "write_timeout_milliseconds":1000,
                "maximum_cache_milliseconds":2000,
                "poll_interval_milliseconds":500
            },
            "runtime":{
                "node_socket_path":"/private/node.sock",
                "telemetry_file":"/private/gateway_telemetry_v2",
                "telemetry_cadence_milliseconds":1000,
                "maximum_queue_milliseconds":30000
            },
            "private_listener":{
                "address":"127.0.0.1:9101",
                "maximum_connections":2,
                "tls":{
                    "server_certificate_file":"/private/server.crt",
                    "server_private_key_file":"/private/server.key",
                    "client_ca_file":"/private/client-ca.crt",
                    "client_certificate_file":"/private/client.crt"
                }
            }
        });
        if mode == GatewayConfigurationMode::Main {
            document.as_object_mut().unwrap().insert(
                "public_listener".to_string(),
                json!({"address":"127.0.0.1:9100","maximum_connections":2}),
            );
        }
        let io = ConfigurationFileIo {
            bytes: serde_json::to_vec(&document).unwrap(),
        };
        let file =
            crate::GatewayConfigurationFile::new(501, PathBuf::from(CONFIGURATION_PATH)).unwrap();
        GatewayConfiguration::load(&file, &io).unwrap()
    }

    // Creates one complete public handler from explicit injected capabilities.
    fn public_handler() -> Arc<GatewayHttpHandler> {
        Arc::new(
            GatewayHttpHandler::new_with_public_reads(
                0,
                Arc::new(ModelProvider),
                Arc::new(HealthProvider),
                Arc::new(ModelListProvider),
                Arc::new(TokenProvider),
                Arc::new(RequestIdProvider),
                Arc::new(ExecutionProvider),
            )
            .unwrap(),
        )
    }

    // Creates one complete private handler from explicit injected capabilities.
    fn private_handler() -> Arc<GatewayHttpHandler> {
        Arc::new(
            GatewayHttpHandler::new(
                GatewayHttpSurface::PrivateRelay,
                0,
                Arc::new(ModelProvider),
                Arc::new(TokenProvider),
                Arc::new(RequestIdProvider),
                Arc::new(ExecutionProvider),
            )
            .unwrap(),
        )
    }

    // Proves main and child modes start only their exact listener sets and can restart.
    #[test]
    fn process_mode_composition_is_exact_and_restartable() {
        let main_configuration = configuration(GatewayConfigurationMode::Main);
        let main_factory = ListenerFactory::new();
        let main = GatewayProcess::start_with_factory(
            &main_configuration,
            GatewayProcessHandlers::main(public_handler(), private_handler()).unwrap(),
            &ConfigurationFileIo { bytes: Vec::new() },
            &main_factory,
        )
        .unwrap();
        assert_eq!(main.mode(), GatewayConfigurationMode::Main);
        assert_eq!(main.public_address().unwrap().port(), 9100);
        assert_eq!(main.private_address().unwrap().port(), 9101);
        {
            let listeners = main_factory.listeners.lock().unwrap();
            listeners[0]
                .rejected_connections
                .store(3, Ordering::Release);
            listeners[1]
                .rejected_connections
                .store(4, Ordering::Release);
        }
        assert_eq!(main.rejected_connections(GatewayHttpSurface::Public), 3);
        assert_eq!(
            main.rejected_connections(GatewayHttpSurface::PrivateRelay),
            4
        );
        assert_eq!(
            main_factory.events.lock().unwrap().as_slice(),
            ["prepare_private", "start_public", "start_private"]
        );
        main.join().unwrap();

        let restarted = GatewayProcess::start_with_factory(
            &main_configuration,
            GatewayProcessHandlers::main(public_handler(), private_handler()).unwrap(),
            &ConfigurationFileIo { bytes: Vec::new() },
            &ListenerFactory::new(),
        )
        .unwrap();
        restarted.join().unwrap();

        let child_factory = ListenerFactory::new();
        let child = GatewayProcess::start_with_factory(
            &configuration(GatewayConfigurationMode::Child),
            GatewayProcessHandlers::child(private_handler()).unwrap(),
            &ConfigurationFileIo { bytes: Vec::new() },
            &child_factory,
        )
        .unwrap();
        assert_eq!(child.mode(), GatewayConfigurationMode::Child);
        assert!(child.public_address().is_none());
        assert_eq!(child.private_address().unwrap().port(), 9101);
        child.join().unwrap();
        assert_eq!(
            child_factory.events.lock().unwrap().as_slice(),
            [
                "prepare_private",
                "start_private",
                "stop_private",
                "join_private"
            ]
        );
    }

    // Proves private startup failure rolls back and joins an already started public listener.
    #[test]
    fn process_startup_failure_rolls_back_every_started_listener() {
        let mut factory = ListenerFactory::new();
        factory.fail_private = true;
        let error = GatewayProcess::start_with_factory(
            &configuration(GatewayConfigurationMode::Main),
            GatewayProcessHandlers::main(public_handler(), private_handler()).unwrap(),
            &ConfigurationFileIo { bytes: Vec::new() },
            &factory,
        )
        .err()
        .unwrap();

        assert_eq!(error.reason(), "injected private failure");
        assert_eq!(
            factory.events.lock().unwrap().as_slice(),
            [
                "prepare_private",
                "start_public",
                "start_private",
                "stop_public",
                "join_public"
            ]
        );
        let listeners = factory.listeners.lock().unwrap();
        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].stop_calls.load(Ordering::Acquire), 1);
        assert_eq!(listeners[0].join_calls.load(Ordering::Acquire), 1);
        drop(listeners);

        let mut preflight = ListenerFactory::new();
        preflight.fail_prepare = true;
        assert!(GatewayProcess::start_with_factory(
            &configuration(GatewayConfigurationMode::Main),
            GatewayProcessHandlers::main(public_handler(), private_handler()).unwrap(),
            &ConfigurationFileIo { bytes: Vec::new() },
            &preflight,
        )
        .is_err());
        assert_eq!(
            preflight.events.lock().unwrap().as_slice(),
            ["prepare_private"]
        );
        assert!(preflight.listeners.lock().unwrap().is_empty());

        let mismatch = ListenerFactory::new();
        assert!(GatewayProcess::start_with_factory(
            &configuration(GatewayConfigurationMode::Main),
            GatewayProcessHandlers::child(private_handler()).unwrap(),
            &ConfigurationFileIo { bytes: Vec::new() },
            &mismatch,
        )
        .is_err());
        assert!(mismatch.events.lock().unwrap().is_empty());
    }

    // Proves run-control failure still stops and joins every listener idempotently.
    #[test]
    fn process_run_control_failure_still_shuts_down_every_listener() {
        let factory = ListenerFactory::new();
        let process = GatewayProcess::start_with_factory(
            &configuration(GatewayConfigurationMode::Main),
            GatewayProcessHandlers::main(public_handler(), private_handler()).unwrap(),
            &ConfigurationFileIo { bytes: Vec::new() },
            &factory,
        )
        .unwrap();

        let error = process
            .run(&RunControl {
                result: Err(GatewayProcessRunControlError::unavailable()),
            })
            .unwrap_err();
        assert_eq!(error.reason(), "Gateway run control is unavailable");
        assert!(process.stop().is_ok());
        assert!(process.join().is_ok());
        let listeners = factory.listeners.lock().unwrap();
        assert_eq!(listeners.len(), 2);
        assert!(listeners
            .iter()
            .all(|listener| listener.stop_calls.load(Ordering::Acquire) >= 2));
        assert!(listeners
            .iter()
            .all(|listener| listener.join_calls.load(Ordering::Acquire) >= 2));
    }

    // Proves one listener failure cannot short-circuit another retained listener's join.
    #[test]
    fn process_shutdown_failure_never_detaches_another_listener() {
        let mut factory = ListenerFactory::new();
        factory.fail_public_stop = true;
        factory.fail_public_join = true;
        let process = GatewayProcess::start_with_factory(
            &configuration(GatewayConfigurationMode::Main),
            GatewayProcessHandlers::main(public_handler(), private_handler()).unwrap(),
            &ConfigurationFileIo { bytes: Vec::new() },
            &factory,
        )
        .unwrap();
        let error = process.join().unwrap_err();

        assert_eq!(error.reason(), "injected stop failure");
        let listeners = factory.listeners.lock().unwrap();
        assert_eq!(listeners.len(), 2);
        assert!(listeners
            .iter()
            .all(|listener| listener.stop_calls.load(Ordering::Acquire) == 1));
        assert!(listeners
            .iter()
            .all(|listener| listener.join_calls.load(Ordering::Acquire) == 1));
    }
}
