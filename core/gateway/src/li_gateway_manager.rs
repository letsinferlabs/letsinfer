// SPDX-License-Identifier: AGPL-3.0-only

mod li_gateway_authentication;
mod li_gateway_configuration;
mod li_gateway_contract;
mod li_gateway_execution;
mod li_gateway_exposure;
mod li_gateway_health;
mod li_gateway_http;
mod li_gateway_macos_placement_safety;
mod li_gateway_native_client;
mod li_gateway_native_io;
mod li_gateway_native_resident;
mod li_gateway_native_server;
mod li_gateway_native_tls_server;
mod li_gateway_node_protection_poller;
mod li_gateway_process;
mod li_gateway_protection_lease;
mod li_gateway_public_read;
mod li_gateway_signal;
mod li_gateway_system;
mod li_gateway_telemetry;
mod li_gateway_telemetry_resident;
mod li_gateway_usage;

pub use li_gateway_authentication::AuthenticationManagerGatewayProvider;
pub use li_gateway_configuration::{
    GatewayConfiguration, GatewayConfigurationError, GatewayConfigurationFile,
    GatewayConfigurationMode, GatewayHealthConfiguration, GatewayListenerConfiguration,
    GatewayMacOsPlacementSafetyConfiguration, GatewayNodeProtectionConfiguration,
    GatewayPrivateListenerConfiguration, LI_GATEWAY_CONFIGURATION_SCHEMA_NAME,
    LI_GATEWAY_CONFIGURATION_SCHEMA_VERSION,
};
pub use li_gateway_contract::{
    GatewayAdmission, GatewayAuthenticationProvider, GatewayClock, GatewayMode, GatewayPrincipal,
    GatewayQueueStatus, GatewayQueueTicket, GatewayRelayAuthorizationProvider, GatewayRequest,
    GatewayReservation, GatewayRoute, GatewayRouteProvider, GatewayRouteTarget, GatewayUsageRecord,
    GatewayUsageStore,
};
pub use li_gateway_execution::{
    GatewayChatCompletionRequest, GatewayExactUsage, GatewayExecution, GatewayExecutionFailure,
    GatewayExecutionFailureKind, GatewayExecutionProvider, GatewayExecutionReceipt,
    GatewayQueueWaiter, GatewayResponseHead, GatewayResponseHeader, GatewayResponseWriter,
};
pub use li_gateway_exposure::{
    GatewayExposure, GatewayExposureCommand, GatewayExposureCommandOutput,
    GatewayExposureCommandRunner, GatewayExposureCoordinator, GatewayExposureError,
    GatewayExposureProvider, GatewayExposureReadinessProvider, GatewayExposureStatus,
    GatewayExposureStore, SystemGatewayExposureCommandRunner, SystemGatewayExposureProvider,
    TailscaleGatewayExposureProvider, LETSINFER_PUBLIC_HTTPS_PORT,
    LETSINFER_PUBLIC_INFERENCE_TARGET,
};
pub use li_gateway_health::{
    GatewayHealthError, GatewayHealthExchange, GatewayHealthObservation, GatewayHealthProbe,
    GatewayHealthReadinessProvider, GatewayHealthServer, GatewayResidentIdentity,
    SystemGatewayHealthExchange, LI_GATEWAY_HEALTH_SCHEMA_NAME, LI_GATEWAY_HEALTH_SCHEMA_VERSION,
};
pub use li_gateway_http::{
    GatewayHttpError, GatewayHttpExecutionProvider, GatewayHttpHandler, GatewayHttpHealthProvider,
    GatewayHttpMethod, GatewayHttpModelList, GatewayHttpModelListProvider,
    GatewayHttpModelProvider, GatewayHttpOutcome, GatewayHttpRelayTokenProvider,
    GatewayHttpRequest, GatewayHttpRequestIdProvider, GatewayHttpSurface, GatewayHttpTokenProvider,
    LETSINFER_RELAY_TOKEN_COUNT_PATH,
};
pub use li_gateway_macos_placement_safety::{
    GatewayMacOsPlacementSafetyLease, GatewayMacOsPlacementSafetyProvider,
    GatewayMacOsPlacementSafetySnapshot,
};
pub use li_gateway_native_client::{
    GatewayNativeExecutionProvider, GatewayNativeTarget, GatewayNativeTargetProvider,
    GatewayTokenCountClient, LETSINFER_TOKEN_COUNT_PROTOCOL,
};
pub use li_gateway_native_io::{
    GatewayNativeClientIdentity, GatewayNativeFile, GatewayNativeFileIo, GatewayNativeHttpFailure,
    GatewayNativeHttpIo, GatewayNativeHttpRequest, GatewayNativeHttpResponseObserver,
    GatewayNativeIoError, GatewayNativeIoFailurePhase, GatewayNativeResponseHead,
    GatewayNativeTlsConfiguration, SystemGatewayNativeFileIo, SystemGatewayNativeHttpIo,
};
pub use li_gateway_native_resident::GatewayNativeServerHandle;
pub use li_gateway_native_server::{
    GatewayNativeConnectionServer, GatewayNativeRequestParser, GatewayNativeResponseWriter,
    GatewayNativeServerError, SystemGatewayHttpServer,
};
pub use li_gateway_native_tls_server::{
    GatewayNativeTlsFileSet, GatewayNativeTlsServerConfiguration, SystemGatewayTlsServer,
};
pub use li_gateway_node_protection_poller::{
    GatewayNodeProtectionPoller, GatewayProtectionCachePolicy, GatewayProtectionMonotonicClock,
    GatewayProtectionPollResponse, GatewayProtectionSnapshotClient,
    SystemGatewayProtectionMonotonicClock,
};
pub use li_gateway_process::{
    GatewayProcess, GatewayProcessError, GatewayProcessHandlers, GatewayProcessRunControl,
    GatewayProcessRunControlError,
};
pub use li_gateway_protection_lease::{
    GatewayPlacementProtectionLease, GatewayPlacementProtectionSnapshot,
    GatewayProtectionAuthority, GatewayProtectionLeaseProvider,
    UnavailableGatewayProtectionLeaseProvider,
};
pub use li_gateway_public_read::{
    AuthenticationManagerGatewayModelListProvider, GatewayHttpModelAvailabilityProvider,
    GatewayHttpModelInventory, GatewayHttpModelInventoryEntry, GatewayHttpModelInventoryProvider,
};
pub use li_gateway_signal::{GatewayProcessStopReason, SystemGatewayProcessRunControl};
pub use li_gateway_system::{
    SystemGatewayClock, SystemGatewayHttpRequestIdProvider, SystemGatewayQueueWaiter,
};
pub use li_gateway_telemetry::{
    GatewayModelActivity, GatewayPlacementGroupActivity, GatewayPlacementGroupCounters,
    GatewayPlacementGroupRates, GatewayTelemetryCounters, GatewayTelemetryHealth,
    GatewayTelemetryPublisher, GatewayTelemetryRuntimeCounterProvider,
    GatewayTelemetryRuntimeCounters, GatewayTelemetrySnapshot, SystemGatewayTelemetryPublisher,
};
pub use li_gateway_telemetry_resident::{
    GatewayProcessRuntimeCounterProvider, GatewayTelemetryCadenceWaiter,
    GatewayTelemetryFailureHandler, GatewayTelemetryResident, GatewayTelemetryResidentError,
    GatewayUsageRuntimeCounterProvider, SystemGatewayTelemetryCadenceWaiter,
};

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex};

use li_core_interface::{ApiKeyId, LogicalModelName, PlacementGroupId, Sha256Digest};

use li_gateway_macos_placement_safety::GatewayMacOsPlacementSafetyState;
use li_gateway_protection_lease::GatewayProtectionLeaseState;
use li_gateway_telemetry::{
    DiscardingGatewayTelemetryPublisher, GatewayTelemetryState, GatewayTelemetryTiming,
};

const ROLLING_WINDOW_MILLISECONDS: u64 = 60_000;
const MAX_QUEUED_REQUESTS: usize = 1024;
const MAX_BACKEND_FAILURES: u8 = 16;
const MAX_BACKEND_COOLDOWN_MILLISECONDS: u64 = 60_000;
const PREFIX_AFFINITY_MILLISECONDS: u64 = 60 * 60 * 1_000;
const MAX_PREFIX_AFFINITY_ENTRIES: usize = 4096;

// Describes one stable GatewayManager admission or lifecycle failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GatewayError {
    InvalidContract {
        reason: &'static str,
    },
    AuthenticationDenied,
    RelayDenied,
    PublicUnavailableOnChild,
    PrivateRelayUnavailableOnMain,
    DuplicateRequest,
    RequestRateLimit,
    TokenRateLimit,
    ConcurrencyLimit,
    ContextTooLarge,
    NoRoute,
    CapacityUnavailable,
    QueueFull,
    QueueExpired,
    RequestNotFound,
    Provider {
        capability: &'static str,
        reason: &'static str,
    },
    StateUnavailable,
}

impl GatewayError {
    // Creates one redacted provider failure at an exact injected boundary.
    pub const fn provider(capability: &'static str, reason: &'static str) -> Self {
        Self::Provider { capability, reason }
    }
}

impl fmt::Display for GatewayError {
    // Presents stable Gateway language without bearer tokens or request bodies.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidContract { reason } => {
                write!(formatter, "gateway contract is invalid: {reason}")
            }
            Self::AuthenticationDenied => formatter.write_str("gateway authentication is denied"),
            Self::RelayDenied => formatter.write_str("private gateway relay is denied"),
            Self::PublicUnavailableOnChild => {
                formatter.write_str("public inference is unavailable on a child gateway")
            }
            Self::PrivateRelayUnavailableOnMain => {
                formatter.write_str("private child relay is unavailable on a main gateway")
            }
            Self::DuplicateRequest => {
                formatter.write_str("gateway request identity is already active")
            }
            Self::RequestRateLimit => formatter.write_str("API key request-rate limit reached"),
            Self::TokenRateLimit => formatter.write_str("API key token-rate limit reached"),
            Self::ConcurrencyLimit => formatter.write_str("API key concurrency limit reached"),
            Self::ContextTooLarge => {
                formatter.write_str("request context exceeds every available placement")
            }
            Self::NoRoute => {
                formatter.write_str("no healthy placement is available for the requested model")
            }
            Self::CapacityUnavailable => {
                formatter.write_str("no placement capacity is currently available")
            }
            Self::QueueFull => formatter.write_str("gateway queue reached its bound"),
            Self::QueueExpired => formatter.write_str("gateway queue wait expired"),
            Self::RequestNotFound => {
                formatter.write_str("gateway request reservation was not found")
            }
            Self::Provider { capability, reason } => {
                write!(formatter, "gateway {capability} failed: {reason}")
            }
            Self::StateUnavailable => formatter.write_str("gateway state is unavailable"),
        }
    }
}

impl Error for GatewayError {}

// Owns live authentication limits, FIFO queues, route selection, and reservations.
pub struct GatewayManager {
    mode: GatewayMode,
    authentication: Arc<dyn GatewayAuthenticationProvider>,
    relay_authorization: Arc<dyn GatewayRelayAuthorizationProvider>,
    routes: Arc<dyn GatewayRouteProvider>,
    placement_safety: GatewayPlacementSafetyProvider,
    clock: Arc<dyn GatewayClock>,
    usage: Arc<dyn GatewayUsageStore>,
    telemetry_publisher: Arc<dyn GatewayTelemetryPublisher>,
    state: Mutex<GatewayState>,
    protection_state: Mutex<GatewayProtectionLeaseState>,
    macos_safety_state: Mutex<GatewayMacOsPlacementSafetyState>,
}

// Selects one platform-native placement-safety authority without translating identities.
enum GatewayPlacementSafetyProvider {
    Linux(Arc<dyn GatewayProtectionLeaseProvider>),
    Macos(Arc<dyn GatewayMacOsPlacementSafetyProvider>),
}

impl GatewayManager {
    // Creates one Gateway owner from explicit policy, topology, time, and usage capabilities.
    pub fn new(
        mode: GatewayMode,
        authentication: Arc<dyn GatewayAuthenticationProvider>,
        relay_authorization: Arc<dyn GatewayRelayAuthorizationProvider>,
        routes: Arc<dyn GatewayRouteProvider>,
        protection: Arc<dyn GatewayProtectionLeaseProvider>,
        clock: Arc<dyn GatewayClock>,
        usage: Arc<dyn GatewayUsageStore>,
    ) -> Result<Self, GatewayError> {
        Self::new_with_telemetry(
            mode,
            authentication,
            relay_authorization,
            routes,
            protection,
            clock,
            usage,
            Arc::new(DiscardingGatewayTelemetryPublisher),
        )
    }

    // Creates one Gateway owner with an explicit atomic native telemetry boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_telemetry(
        mode: GatewayMode,
        authentication: Arc<dyn GatewayAuthenticationProvider>,
        relay_authorization: Arc<dyn GatewayRelayAuthorizationProvider>,
        routes: Arc<dyn GatewayRouteProvider>,
        protection: Arc<dyn GatewayProtectionLeaseProvider>,
        clock: Arc<dyn GatewayClock>,
        usage: Arc<dyn GatewayUsageStore>,
        telemetry_publisher: Arc<dyn GatewayTelemetryPublisher>,
    ) -> Result<Self, GatewayError> {
        Self::new_configured(
            mode,
            authentication,
            relay_authorization,
            routes,
            GatewayPlacementSafetyProvider::Linux(protection),
            clock,
            usage,
            telemetry_publisher,
        )
    }

    // Creates one macOS Gateway using only native Node/launchd safety observations.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_macos_safety_and_telemetry(
        mode: GatewayMode,
        authentication: Arc<dyn GatewayAuthenticationProvider>,
        relay_authorization: Arc<dyn GatewayRelayAuthorizationProvider>,
        routes: Arc<dyn GatewayRouteProvider>,
        placement_safety: Arc<dyn GatewayMacOsPlacementSafetyProvider>,
        clock: Arc<dyn GatewayClock>,
        usage: Arc<dyn GatewayUsageStore>,
        telemetry_publisher: Arc<dyn GatewayTelemetryPublisher>,
    ) -> Result<Self, GatewayError> {
        Self::new_configured(
            mode,
            authentication,
            relay_authorization,
            routes,
            GatewayPlacementSafetyProvider::Macos(placement_safety),
            clock,
            usage,
            telemetry_publisher,
        )
    }

    // Creates one Gateway after the platform-specific safety authority is fixed.
    #[allow(clippy::too_many_arguments)]
    fn new_configured(
        mode: GatewayMode,
        authentication: Arc<dyn GatewayAuthenticationProvider>,
        relay_authorization: Arc<dyn GatewayRelayAuthorizationProvider>,
        routes: Arc<dyn GatewayRouteProvider>,
        placement_safety: GatewayPlacementSafetyProvider,
        clock: Arc<dyn GatewayClock>,
        usage: Arc<dyn GatewayUsageStore>,
        telemetry_publisher: Arc<dyn GatewayTelemetryPublisher>,
    ) -> Result<Self, GatewayError> {
        if mode
            .main_node_id()
            .is_some_and(|main| main == mode.local_node_id())
        {
            return Err(GatewayError::InvalidContract {
                reason: "child gateway local and main identities must differ",
            });
        }
        Ok(Self {
            mode,
            authentication,
            relay_authorization,
            routes,
            placement_safety,
            clock,
            usage,
            telemetry_publisher,
            state: Mutex::new(GatewayState::default()),
            protection_state: Mutex::new(GatewayProtectionLeaseState::default()),
            macos_safety_state: Mutex::new(GatewayMacOsPlacementSafetyState::default()),
        })
    }

    // Authenticates and admits one public request only on a main gateway.
    pub fn admit_public(
        &self,
        bearer_token: &str,
        request: GatewayRequest,
    ) -> Result<GatewayAdmission, GatewayError> {
        self.record_received()?;
        let result = (|| {
            if !matches!(self.mode, GatewayMode::Main { .. }) {
                return Err(GatewayError::PublicUnavailableOnChild);
            }
            let principal = self
                .authentication
                .authenticate(bearer_token, request.model())?;
            self.admit(request, Some(principal))
        })();
        self.record_initial_failure(result)
    }

    // Authenticates and admits one private main relay only on a child gateway.
    pub fn admit_relay(
        &self,
        relay_credential: &str,
        request: GatewayRequest,
    ) -> Result<GatewayAdmission, GatewayError> {
        self.record_received()?;
        let result = (|| {
            let expected_main = self
                .mode
                .main_node_id()
                .ok_or(GatewayError::PrivateRelayUnavailableOnMain)?;
            let authorized_main = self.relay_authorization.authorize(relay_credential)?;
            if &authorized_main != expected_main {
                return Err(GatewayError::RelayDenied);
            }
            self.admit(request, None)
        })();
        self.record_initial_failure(result)
    }

    // Polls one FIFO queue ticket and converts it to a reservation when capacity exists.
    pub fn poll_queue(
        &self,
        ticket: &GatewayQueueTicket,
    ) -> Result<GatewayQueueStatus, GatewayError> {
        let now = self.clock.now()?;
        let request = {
            let state = self
                .state
                .lock()
                .map_err(|_| GatewayError::StateUnavailable)?;
            state
                .queued
                .get(ticket.request_id())
                .map(|queued| queued.request.clone())
                .ok_or(GatewayError::RequestNotFound)?
        };
        let routes = self.current_routes(request.model())?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| GatewayError::StateUnavailable)?;
        let queued = state
            .queued
            .get(ticket.request_id())
            .ok_or(GatewayError::RequestNotFound)?;
        if queued
            .queued_milliseconds
            .saturating_add(now.value().saturating_sub(queued.enqueued_at))
            > request.maximum_queue_milliseconds()
        {
            let queued = remove_queued_request(&mut state, ticket.request_id())?;
            let queue_milliseconds = queued
                .queued_milliseconds
                .saturating_add(now.value().saturating_sub(queued.enqueued_at));
            release_principal(
                &mut state,
                queued.principal.as_ref(),
                queued.reserved_tokens,
            );
            state.telemetry.record_unrouted_failure_with_timing(
                GatewayTelemetryTiming::from_observations(queue_milliseconds, None, None, None),
            );
            return Err(GatewayError::QueueExpired);
        }
        if state.queue_order.iter().any(|request_id| {
            request_id != ticket.request_id()
                && state
                    .queued
                    .get(request_id)
                    .is_some_and(|candidate| candidate.request.model() == request.model())
        }) {
            let first_for_model = state.queue_order.iter().find(|request_id| {
                state
                    .queued
                    .get(*request_id)
                    .is_some_and(|candidate| candidate.request.model() == request.model())
            });
            if first_for_model != Some(ticket.request_id()) {
                return Ok(GatewayQueueStatus::Waiting);
            }
        }
        match select_route(&state, &request, routes, now.value())? {
            RouteSelection::Selected(route) => {
                let queued = remove_queued_request(&mut state, ticket.request_id())?;
                let reservation = reserve_route(&mut state, queued, route, now)?;
                Ok(GatewayQueueStatus::Admitted(reservation))
            }
            RouteSelection::Busy => Ok(GatewayQueueStatus::Waiting),
        }
    }

    // Cancels one queued request and releases only its live quota reservations.
    pub fn cancel_queue(&self, ticket: GatewayQueueTicket) -> Result<(), GatewayError> {
        let now = self.clock.now()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| GatewayError::StateUnavailable)?;
        let queued = remove_queued_request(&mut state, ticket.request_id())?;
        release_principal(
            &mut state,
            queued.principal.as_ref(),
            queued.reserved_tokens,
        );
        state.telemetry.record_cancelled(
            None,
            GatewayTelemetryTiming::from_observations(
                queued
                    .queued_milliseconds
                    .saturating_add(now.value().saturating_sub(queued.enqueued_at)),
                None,
                None,
                None,
            ),
        );
        Ok(())
    }

    // Completes one active request, releases capacity, and records exact token usage.
    pub fn complete(
        &self,
        reservation: GatewayReservation,
        input_tokens: u64,
        output_tokens: u64,
    ) -> Result<Option<GatewayUsageRecord>, GatewayError> {
        let timing = GatewayTelemetryTiming::from_observations(
            reservation.queued_milliseconds,
            None,
            None,
            None,
        );
        self.complete_request(reservation, input_tokens, output_tokens, 0, true, timing)
    }

    // Completes one forwarded request with exact cache and execution-duration telemetry.
    pub(crate) fn complete_execution(
        &self,
        reservation: GatewayReservation,
        usage: GatewayExactUsage,
        timing: GatewayTelemetryTiming,
    ) -> Result<Option<GatewayUsageRecord>, GatewayError> {
        self.complete_request(
            reservation,
            usage.input_tokens(),
            usage.output_tokens(),
            usage.cached_tokens(),
            true,
            timing,
        )
    }

    // Releases one completion and commits its exact secret-free counters.
    #[allow(clippy::too_many_arguments)]
    fn complete_request(
        &self,
        reservation: GatewayReservation,
        input_tokens: u64,
        output_tokens: u64,
        cached_tokens: u64,
        exact_tokens: bool,
        timing: GatewayTelemetryTiming,
    ) -> Result<Option<GatewayUsageRecord>, GatewayError> {
        let completed_at = self.clock.now();
        let total_tokens =
            input_tokens
                .checked_add(output_tokens)
                .ok_or(GatewayError::InvalidContract {
                    reason: "completed gateway usage overflows its token bound",
                });
        let usage = match (completed_at.as_ref(), total_tokens.as_ref()) {
            (Ok(completed_at), Ok(total_tokens)) => reservation
                .principal
                .as_ref()
                .map(|principal| {
                    GatewayUsageRecord::new(
                        reservation.request.request_id().clone(),
                        principal.key_id().clone(),
                        reservation.received_at,
                        *completed_at,
                        *total_tokens,
                    )
                })
                .transpose(),
            (Err(error), _) => Err(error.clone()),
            (_, Err(error)) => Err(error.clone()),
        };
        {
            let mut state = self
                .state
                .lock()
                .map_err(|_| GatewayError::StateUnavailable)?;
            release_reservation(&mut state, &reservation)?;
            if let Ok(completed_at) = completed_at.as_ref() {
                mark_route_success(&mut state, reservation.route.placement_group_id());
                if let Some(prefix_key) = reservation.request.prefix_key() {
                    record_prefix_affinity(
                        &mut state,
                        (reservation.request.model().clone(), prefix_key.clone()),
                        reservation.route.placement_group_id().clone(),
                        completed_at.value(),
                    );
                }
            }
            if let Some(principal) = reservation.principal.as_ref() {
                release_principal(&mut state, Some(principal), reservation.reserved_tokens);
                if let (Ok(completed_at), Ok(total_tokens)) = (&completed_at, &total_tokens) {
                    state
                        .token_windows
                        .entry(principal.key_id().clone())
                        .or_default()
                        .push_back((completed_at.value(), *total_tokens));
                }
            }
            match (&completed_at, &total_tokens, &usage) {
                (Ok(completed_at), Ok(_), Ok(_)) => state.telemetry.record_completed(
                    &reservation.route,
                    completed_at.value(),
                    timing,
                    input_tokens,
                    output_tokens,
                    cached_tokens,
                    exact_tokens,
                ),
                _ => state.telemetry.record_failed(&reservation.route, timing),
            }
        }
        match usage? {
            Some(usage) => {
                self.usage.record(&usage)?;
                Ok(Some(usage))
            }
            None => Ok(None),
        }
    }

    // Cancels one active request without charging completed token usage.
    pub fn cancel(&self, reservation: GatewayReservation) -> Result<(), GatewayError> {
        let timing = GatewayTelemetryTiming::from_observations(
            reservation.queued_milliseconds,
            None,
            None,
            None,
        );
        self.cancel_with_timing(reservation, timing)
    }

    // Cancels one forwarded request with its already-observed terminal durations.
    pub(crate) fn cancel_execution(
        &self,
        reservation: GatewayReservation,
        timing: GatewayTelemetryTiming,
    ) -> Result<(), GatewayError> {
        self.cancel_with_timing(reservation, timing)
    }

    // Releases one active cancellation and preserves monotonic telemetry gauges.
    fn cancel_with_timing(
        &self,
        reservation: GatewayReservation,
        timing: GatewayTelemetryTiming,
    ) -> Result<(), GatewayError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| GatewayError::StateUnavailable)?;
        release_reservation(&mut state, &reservation)?;
        release_principal(
            &mut state,
            reservation.principal.as_ref(),
            reservation.reserved_tokens,
        );
        state
            .telemetry
            .record_cancelled(Some(&reservation.route), timing);
        Ok(())
    }

    // Retries one failed request only before output begins without double-charging policy.
    pub fn retry_before_output(
        &self,
        reservation: GatewayReservation,
    ) -> Result<GatewayAdmission, GatewayError> {
        let now = self.clock.now();
        let routes = self.current_routes(reservation.request.model());
        let mut state = self
            .state
            .lock()
            .map_err(|_| GatewayError::StateUnavailable)?;
        release_reservation(&mut state, &reservation)?;
        let terminal_timing = GatewayTelemetryTiming::from_observations(
            reservation.queued_milliseconds,
            None,
            None,
            None,
        );
        let now = match now {
            Ok(now) => now,
            Err(error) => {
                release_principal(
                    &mut state,
                    reservation.principal.as_ref(),
                    reservation.reserved_tokens,
                );
                state
                    .telemetry
                    .record_failed(&reservation.route, terminal_timing);
                return Err(error);
            }
        };
        mark_route_failure(
            &mut state,
            reservation.route.placement_group_id(),
            now.value(),
        );
        let routes = match routes {
            Ok(routes) => routes,
            Err(error) => {
                release_principal(
                    &mut state,
                    reservation.principal.as_ref(),
                    reservation.reserved_tokens,
                );
                state
                    .telemetry
                    .record_failed(&reservation.route, terminal_timing);
                return Err(error);
            }
        };
        let queued = QueuedRequest {
            request: reservation.request.clone(),
            principal: reservation.principal,
            received_at: reservation.received_at,
            enqueued_at: now.value(),
            queued_milliseconds: reservation.queued_milliseconds,
            reserved_tokens: reservation.reserved_tokens,
            was_admitted: true,
        };
        let result = match select_route(&state, &queued.request, routes, now.value()) {
            Ok(RouteSelection::Selected(route)) => Ok(GatewayAdmission::Admitted(reserve_route(
                &mut state, queued, route, now,
            )?)),
            Ok(RouteSelection::Busy)
                if queued.request.maximum_queue_milliseconds() > 0
                    && queued
                        .queued_milliseconds
                        .saturating_add(now.value().saturating_sub(queued.enqueued_at))
                        <= queued.request.maximum_queue_milliseconds() =>
            {
                if state.queued.len() >= MAX_QUEUED_REQUESTS {
                    release_principal(
                        &mut state,
                        queued.principal.as_ref(),
                        queued.reserved_tokens,
                    );
                    state
                        .telemetry
                        .record_failed(&reservation.route, terminal_timing);
                    return Err(GatewayError::QueueFull);
                }
                let request_id = queued.request.request_id().clone();
                state.queue_order.push_back(request_id.clone());
                state.queued.insert(request_id.clone(), queued);
                Ok(GatewayAdmission::Queued(GatewayQueueTicket::new(
                    request_id,
                )))
            }
            Ok(RouteSelection::Busy) => {
                release_principal(
                    &mut state,
                    queued.principal.as_ref(),
                    queued.reserved_tokens,
                );
                state
                    .telemetry
                    .record_failed(&reservation.route, terminal_timing);
                Err(GatewayError::CapacityUnavailable)
            }
            Err(error) => {
                release_principal(
                    &mut state,
                    queued.principal.as_ref(),
                    queued.reserved_tokens,
                );
                state
                    .telemetry
                    .record_failed(&reservation.route, terminal_timing);
                Err(error)
            }
        };
        if result.is_ok() {
            state.telemetry.record_retried(&reservation.route);
        }
        result
    }

    // Ends one post-output failure without any silent retry and cools its route down.
    pub fn fail_after_output(&self, reservation: GatewayReservation) -> Result<(), GatewayError> {
        let timing = GatewayTelemetryTiming::from_observations(
            reservation.queued_milliseconds,
            None,
            None,
            None,
        );
        self.fail_reservation(reservation, timing)
    }

    // Ends one forwarded failure with its observed queue and response durations.
    pub(crate) fn fail_execution(
        &self,
        reservation: GatewayReservation,
        timing: GatewayTelemetryTiming,
    ) -> Result<(), GatewayError> {
        self.fail_reservation(reservation, timing)
    }

    // Releases one failed reservation and applies bounded route cooldown.
    fn fail_reservation(
        &self,
        reservation: GatewayReservation,
        timing: GatewayTelemetryTiming,
    ) -> Result<(), GatewayError> {
        let now = self.clock.now();
        let mut state = self
            .state
            .lock()
            .map_err(|_| GatewayError::StateUnavailable)?;
        release_reservation(&mut state, &reservation)?;
        release_principal(
            &mut state,
            reservation.principal.as_ref(),
            reservation.reserved_tokens,
        );
        let now = match now {
            Ok(now) => now,
            Err(error) => {
                state.telemetry.record_failed(&reservation.route, timing);
                return Err(error);
            }
        };
        mark_route_failure(
            &mut state,
            reservation.route.placement_group_id(),
            now.value(),
        );
        state.telemetry.record_failed(&reservation.route, timing);
        Ok(())
    }

    // Releases one queued request after a terminal native wait or polling failure.
    pub(crate) fn fail_queue(&self, ticket: GatewayQueueTicket) -> Result<(), GatewayError> {
        let now = self.clock.now()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| GatewayError::StateUnavailable)?;
        let queued = remove_queued_request(&mut state, ticket.request_id())?;
        release_principal(
            &mut state,
            queued.principal.as_ref(),
            queued.reserved_tokens,
        );
        state.telemetry.record_unrouted_failure_with_timing(
            GatewayTelemetryTiming::from_observations(
                queued
                    .queued_milliseconds
                    .saturating_add(now.value().saturating_sub(queued.enqueued_at)),
                None,
                None,
                None,
            ),
        );
        Ok(())
    }

    // Returns one immutable secret-free schema-2 telemetry snapshot.
    pub fn telemetry_snapshot(&self) -> Result<GatewayTelemetrySnapshot, GatewayError> {
        let observed_at = self.clock.now()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| GatewayError::StateUnavailable)?;
        let active_requests = state.active_requests.len();
        let queued_models = state
            .queued
            .values()
            .map(|queued| queued.request.model().clone())
            .collect::<Vec<_>>();
        let route_active = state.route_active.clone();
        Ok(state.telemetry.snapshot(
            observed_at,
            active_requests,
            queued_models.into_iter(),
            &route_active,
        ))
    }

    // Publishes one immutable snapshot and records redacted publisher readiness.
    pub fn publish_telemetry(&self) -> Result<GatewayTelemetrySnapshot, GatewayError> {
        let snapshot = self.telemetry_snapshot()?;
        let observed_at = snapshot.observed_at().value();
        let result = self.telemetry_publisher.publish_atomically(&snapshot);
        let mut state = self
            .state
            .lock()
            .map_err(|_| GatewayError::StateUnavailable)?;
        match result {
            Ok(()) => {
                state.telemetry.publisher_did_succeed(observed_at);
                Ok(snapshot)
            }
            Err(_) => {
                state.telemetry.publisher_did_fail(observed_at);
                Err(GatewayError::provider(
                    "telemetry_publish",
                    "atomic publisher rejected snapshot",
                ))
            }
        }
    }

    // Returns whether the latest atomic telemetry publication remains fresh.
    pub fn telemetry_health(&self) -> Result<GatewayTelemetryHealth, GatewayError> {
        let observed_at = self.clock.now()?;
        let state = self
            .state
            .lock()
            .map_err(|_| GatewayError::StateUnavailable)?;
        Ok(state.telemetry.health(observed_at.value()))
    }

    // Returns optional execution timing without making observability a forwarding gate.
    pub(crate) fn telemetry_observed_at(&self) -> Option<u64> {
        self.clock.now().ok().map(|observed_at| observed_at.value())
    }

    // Records one inbound request before authentication or route policy runs.
    fn record_received(&self) -> Result<(), GatewayError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| GatewayError::StateUnavailable)?;
        state.telemetry.record_received();
        Ok(())
    }

    // Converts one initial admission error into exactly one terminal failure counter.
    fn record_initial_failure<T>(
        &self,
        result: Result<T, GatewayError>,
    ) -> Result<T, GatewayError> {
        match result {
            Ok(value) => Ok(value),
            Err(error) => {
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| GatewayError::StateUnavailable)?;
                state.telemetry.record_unrouted_failure();
                Err(error)
            }
        }
    }

    // Returns current active and queued counts without exposing request payloads.
    pub fn counts(&self) -> Result<(usize, usize), GatewayError> {
        let state = self
            .state
            .lock()
            .map_err(|_| GatewayError::StateUnavailable)?;
        Ok((state.active_requests.len(), state.queued.len()))
    }

    // Returns whether one public model has a safe route with immediate live capacity.
    pub fn public_model_is_available(
        &self,
        model: &LogicalModelName,
    ) -> Result<bool, GatewayError> {
        if !matches!(self.mode, GatewayMode::Main { .. }) {
            return Ok(false);
        }
        let now = self.clock.now()?;
        let routes = self.current_routes(model)?;
        let state = self
            .state
            .lock()
            .map_err(|_| GatewayError::StateUnavailable)?;
        Ok(routes
            .iter()
            .any(|route| route_has_admission_capacity(&state, route, now.value())))
    }

    // Authenticates one public credential before any native token-count work begins.
    pub fn authorize_public_token_count(
        &self,
        bearer_token: &str,
        model: &LogicalModelName,
    ) -> Result<(), GatewayError> {
        if !matches!(self.mode, GatewayMode::Main { .. }) {
            return Err(GatewayError::PublicUnavailableOnChild);
        }
        self.authentication.authenticate(bearer_token, model)?;
        Ok(())
    }

    // Authenticates one child relay credential before any local token-count work begins.
    pub fn authorize_relay_token_count(&self, relay_credential: &str) -> Result<(), GatewayError> {
        let expected_main = self
            .mode
            .main_node_id()
            .ok_or(GatewayError::PrivateRelayUnavailableOnMain)?;
        if &self.relay_authorization.authorize(relay_credential)? != expected_main {
            return Err(GatewayError::RelayDenied);
        }
        Ok(())
    }

    // Returns deterministic healthy token-count routes without reserving inference capacity.
    pub fn token_count_routes(
        &self,
        model: &LogicalModelName,
    ) -> Result<Vec<GatewayRoute>, GatewayError> {
        let now = self.clock.now()?;
        let mut routes = self.current_routes(model)?;
        let state = self
            .state
            .lock()
            .map_err(|_| GatewayError::StateUnavailable)?;
        routes.retain(|route| {
            route.is_healthy()
                && !route.has_memory_pressure()
                && state
                    .unavailable_until
                    .get(route.placement_group_id())
                    .is_none_or(|deadline| *deadline <= now.value())
        });
        routes.sort_by(|left, right| {
            right
                .max_context_tokens()
                .cmp(&left.max_context_tokens())
                .then_with(|| left.endpoint_node_id().cmp(right.endpoint_node_id()))
                .then_with(|| left.placement_group_id().cmp(right.placement_group_id()))
        });
        Ok(routes)
    }

    // Applies policy, selects current capacity, or owns one bounded FIFO queue entry.
    fn admit(
        &self,
        request: GatewayRequest,
        principal: Option<GatewayPrincipal>,
    ) -> Result<GatewayAdmission, GatewayError> {
        let now = self.clock.now()?;
        let routes = self.current_routes(request.model())?;
        let since = li_core_interface::UnixMilliseconds::new(
            now.value().saturating_sub(ROLLING_WINDOW_MILLISECONDS),
        );
        let should_load_usage = match principal.as_ref() {
            Some(principal) => !self
                .state
                .lock()
                .map_err(|_| GatewayError::StateUnavailable)?
                .loaded_keys
                .contains(principal.key_id()),
            None => false,
        };
        let recent = match principal.as_ref() {
            Some(principal) if should_load_usage => self.usage.recent(principal.key_id(), since)?,
            None => Vec::new(),
            Some(_) => Vec::new(),
        };
        let mut state = self
            .state
            .lock()
            .map_err(|_| GatewayError::StateUnavailable)?;
        require_new_request(&state, request.request_id())?;
        if let Some(principal) = principal.as_ref() {
            load_recent_usage(
                &mut state,
                principal.key_id(),
                recent,
                since.value(),
                now.value(),
            )?;
            admit_principal(&mut state, principal, &request, now.value())?;
        }
        let reserved_tokens = principal
            .as_ref()
            .and_then(|principal| principal.limits().tokens_per_minute())
            .map_or(0, |_| request.token_demand());
        let queued = QueuedRequest {
            request: request.clone(),
            principal,
            received_at: now,
            enqueued_at: now.value(),
            queued_milliseconds: 0,
            reserved_tokens,
            was_admitted: false,
        };
        match select_route(&state, &request, routes, now.value()) {
            Ok(RouteSelection::Selected(route)) => Ok(GatewayAdmission::Admitted(reserve_route(
                &mut state, queued, route, now,
            )?)),
            Ok(RouteSelection::Busy) if request.maximum_queue_milliseconds() > 0 => {
                if state.queued.len() >= MAX_QUEUED_REQUESTS {
                    release_principal(&mut state, queued.principal.as_ref(), reserved_tokens);
                    return Err(GatewayError::QueueFull);
                }
                let request_id = request.request_id().clone();
                state.queue_order.push_back(request_id.clone());
                state.queued.insert(request_id.clone(), queued);
                Ok(GatewayAdmission::Queued(GatewayQueueTicket::new(
                    request_id,
                )))
            }
            Ok(RouteSelection::Busy) => {
                release_principal(&mut state, queued.principal.as_ref(), reserved_tokens);
                Err(GatewayError::CapacityUnavailable)
            }
            Err(error) => {
                release_principal(&mut state, queued.principal.as_ref(), reserved_tokens);
                Err(error)
            }
        }
    }

    // Reads and validates one current route snapshot outside live state mutation.
    fn current_routes(&self, model: &LogicalModelName) -> Result<Vec<GatewayRoute>, GatewayError> {
        let routes = self.routes.routes(model)?;
        let mut identities = HashSet::new();
        let mut protected = Vec::new();
        for route in routes {
            if route.model() != model || !identities.insert(route.placement_group_id().clone()) {
                return Err(GatewayError::InvalidContract {
                    reason: "gateway route snapshot has a foreign model or duplicate group",
                });
            }
            match (&self.mode, route.target()) {
                (
                    GatewayMode::Child { local_node_id, .. },
                    GatewayRouteTarget::LocalEngine { .. },
                ) if route.endpoint_node_id() == local_node_id => {}
                (GatewayMode::Child { .. }, _) => {
                    return Err(GatewayError::InvalidContract {
                        reason: "child gateway may route only its local Engine endpoint",
                    })
                }
                (GatewayMode::Main { .. }, _) => {}
            }
            if matches!(
                (&self.mode, route.target()),
                (
                    GatewayMode::Main { .. },
                    GatewayRouteTarget::ChildRelay { .. }
                )
            ) {
                // The authenticated child relay performs its own local placement-safety admission.
                protected.push(route);
                continue;
            }
            let accepted = match &self.placement_safety {
                GatewayPlacementSafetyProvider::Linux(protection) => {
                    let Some(snapshot) = protection.snapshot(&route)? else {
                        continue;
                    };
                    let now = self.clock.now()?;
                    self.protection_state
                        .lock()
                        .map_err(|_| GatewayError::StateUnavailable)?
                        .accepts(&route, &snapshot, now)
                }
                GatewayPlacementSafetyProvider::Macos(protection) => {
                    let Some(snapshot) = protection.snapshot(&route)? else {
                        continue;
                    };
                    let now = self.clock.now()?;
                    self.macos_safety_state
                        .lock()
                        .map_err(|_| GatewayError::StateUnavailable)?
                        .accepts(&route, &snapshot, now)
                }
            };
            if accepted {
                protected.push(route);
            }
        }
        Ok(protected)
    }
}

// Stores one authenticated queued request without bearer material.
struct QueuedRequest {
    request: GatewayRequest,
    principal: Option<GatewayPrincipal>,
    received_at: li_core_interface::UnixMilliseconds,
    enqueued_at: u64,
    queued_milliseconds: u64,
    reserved_tokens: u64,
    was_admitted: bool,
}

// Stores live Gateway-owned counters and reservations under one lock.
#[derive(Default)]
struct GatewayState {
    loaded_keys: HashSet<ApiKeyId>,
    request_windows: HashMap<ApiKeyId, VecDeque<u64>>,
    token_windows: HashMap<ApiKeyId, VecDeque<(u64, u64)>>,
    principal_active: HashMap<ApiKeyId, u32>,
    principal_reserved_tokens: HashMap<ApiKeyId, u64>,
    route_active: HashMap<PlacementGroupId, u32>,
    failure_counts: HashMap<PlacementGroupId, u8>,
    unavailable_until: HashMap<PlacementGroupId, u64>,
    prefix_affinity: BTreeMap<(LogicalModelName, Sha256Digest), (PlacementGroupId, u64)>,
    active_requests: HashMap<Sha256Digest, PlacementGroupId>,
    queue_order: VecDeque<Sha256Digest>,
    queued: HashMap<Sha256Digest, QueuedRequest>,
    telemetry: GatewayTelemetryState,
}

// Describes whether compatible route capacity is selected or currently busy.
enum RouteSelection {
    Selected(GatewayRoute),
    Busy,
}

// Rejects reuse of one active or queued request identity.
fn require_new_request(
    state: &GatewayState,
    request_id: &Sha256Digest,
) -> Result<(), GatewayError> {
    if state.active_requests.contains_key(request_id) || state.queued.contains_key(request_id) {
        return Err(GatewayError::DuplicateRequest);
    }
    Ok(())
}

// Loads one key's persisted rolling window exactly once per gateway process.
fn load_recent_usage(
    state: &mut GatewayState,
    key_id: &ApiKeyId,
    recent: Vec<GatewayUsageRecord>,
    since: u64,
    now: u64,
) -> Result<(), GatewayError> {
    if recent.iter().any(|usage| {
        usage.key_id() != key_id
            || usage.received_at().value() < since
            || usage.completed_at().value() > now
    }) {
        return Err(GatewayError::InvalidContract {
            reason: "gateway usage store returned a foreign or out-of-window record",
        });
    }
    if !state.loaded_keys.insert(key_id.clone()) {
        return Ok(());
    }
    for usage in recent {
        state
            .request_windows
            .entry(key_id.clone())
            .or_default()
            .push_back(usage.received_at().value());
        state
            .token_windows
            .entry(key_id.clone())
            .or_default()
            .push_back((usage.completed_at().value(), usage.tokens()));
    }
    Ok(())
}

// Applies request, token, concurrency, and context limits before routing.
fn admit_principal(
    state: &mut GatewayState,
    principal: &GatewayPrincipal,
    request: &GatewayRequest,
    now: u64,
) -> Result<(), GatewayError> {
    let key_id = principal.key_id();
    let cutoff = now.saturating_sub(ROLLING_WINDOW_MILLISECONDS);
    let requests = state.request_windows.entry(key_id.clone()).or_default();
    while requests.front().is_some_and(|value| *value <= cutoff) {
        requests.pop_front();
    }
    let tokens = state.token_windows.entry(key_id.clone()).or_default();
    while tokens
        .front()
        .is_some_and(|(observed, _)| *observed <= cutoff)
    {
        tokens.pop_front();
    }
    let limits = principal.limits();
    if limits
        .context_tokens()
        .is_some_and(|limit| request.context_tokens().get() > limit.get())
    {
        return Err(GatewayError::ContextTooLarge);
    }
    if limits
        .requests_per_minute()
        .is_some_and(|limit| requests.len() >= limit.get() as usize)
    {
        return Err(GatewayError::RequestRateLimit);
    }
    let active = state.principal_active.get(key_id).copied().unwrap_or(0);
    if limits
        .concurrency()
        .is_some_and(|limit| active >= limit.get())
    {
        return Err(GatewayError::ConcurrencyLimit);
    }
    if let Some(limit) = limits.tokens_per_minute() {
        let used = tokens.iter().map(|(_, value)| *value).sum::<u64>();
        let reserved = state
            .principal_reserved_tokens
            .get(key_id)
            .copied()
            .unwrap_or(0);
        if used
            .checked_add(reserved)
            .and_then(|value| value.checked_add(request.token_demand()))
            .is_none_or(|value| value > limit.get())
        {
            return Err(GatewayError::TokenRateLimit);
        }
        state
            .principal_reserved_tokens
            .insert(key_id.clone(), reserved + request.token_demand());
    }
    requests.push_back(now);
    state.principal_active.insert(key_id.clone(), active + 1);
    Ok(())
}

// Selects one deterministic healthy compatible route or reports current capacity pressure.
fn select_route(
    state: &GatewayState,
    request: &GatewayRequest,
    routes: Vec<GatewayRoute>,
    now: u64,
) -> Result<RouteSelection, GatewayError> {
    let healthy = routes
        .into_iter()
        .filter(|route| route.is_healthy() && !route.has_memory_pressure())
        .collect::<Vec<_>>();
    if healthy.is_empty() {
        return Err(GatewayError::NoRoute);
    }
    let compatible = healthy
        .into_iter()
        .filter(|route| route.max_context_tokens().get() >= request.token_demand())
        .collect::<Vec<_>>();
    if compatible.is_empty() {
        return Err(GatewayError::ContextTooLarge);
    }
    let routable = compatible
        .into_iter()
        .filter(|route| {
            state
                .unavailable_until
                .get(route.placement_group_id())
                .is_none_or(|deadline| *deadline <= now)
        })
        .collect::<Vec<_>>();
    if routable.is_empty() {
        return Err(GatewayError::NoRoute);
    }
    let mut available = routable
        .into_iter()
        .filter(|route| {
            state
                .route_active
                .get(route.placement_group_id())
                .copied()
                .unwrap_or(0)
                < route.max_active_requests().get()
        })
        .collect::<Vec<_>>();
    if available.is_empty() {
        return Ok(RouteSelection::Busy);
    }
    let affinity = request.prefix_key().and_then(|prefix_key| {
        state
            .prefix_affinity
            .get(&(request.model().clone(), prefix_key.clone()))
            .filter(|(_, deadline)| *deadline > now)
            .map(|(placement_group_id, _)| placement_group_id)
    });
    available.sort_by(|left, right| {
        let left_prefix = request.prefix_key().is_some_and(|prefix| {
            left.prefix_keys().contains(prefix) || affinity == Some(left.placement_group_id())
        });
        let right_prefix = request.prefix_key().is_some_and(|prefix| {
            right.prefix_keys().contains(prefix) || affinity == Some(right.placement_group_id())
        });
        let left_active = state
            .route_active
            .get(left.placement_group_id())
            .copied()
            .unwrap_or(0);
        let right_active = state
            .route_active
            .get(right.placement_group_id())
            .copied()
            .unwrap_or(0);
        (!left_prefix)
            .cmp(&(!right_prefix))
            .then_with(|| {
                (u64::from(left_active) * u64::from(right.max_active_requests().get()))
                    .cmp(&(u64::from(right_active) * u64::from(left.max_active_requests().get())))
            })
            .then_with(|| {
                left.temperature_millicelsius()
                    .unwrap_or(u32::MAX)
                    .cmp(&right.temperature_millicelsius().unwrap_or(u32::MAX))
            })
            .then_with(|| left.endpoint_node_id().cmp(right.endpoint_node_id()))
    });
    Ok(RouteSelection::Selected(available.remove(0)))
}

// Returns whether one route passes health, pressure, cooldown, and capacity gates.
fn route_has_admission_capacity(state: &GatewayState, route: &GatewayRoute, now: u64) -> bool {
    route.is_healthy()
        && !route.has_memory_pressure()
        && state
            .unavailable_until
            .get(route.placement_group_id())
            .is_none_or(|deadline| *deadline <= now)
        && state
            .route_active
            .get(route.placement_group_id())
            .copied()
            .unwrap_or(0)
            < route.max_active_requests().get()
}

// Applies one bounded exponential cooldown after a backend failure.
fn mark_route_failure(state: &mut GatewayState, placement_group_id: &PlacementGroupId, now: u64) {
    let failures = state
        .failure_counts
        .get(placement_group_id)
        .copied()
        .unwrap_or(0)
        .saturating_add(1)
        .min(MAX_BACKEND_FAILURES);
    state
        .failure_counts
        .insert(placement_group_id.clone(), failures);
    let exponent = u32::from(failures.saturating_sub(1)).min(16);
    let cooldown = (1_u64 << exponent)
        .saturating_mul(1_000)
        .min(MAX_BACKEND_COOLDOWN_MILLISECONDS);
    state
        .unavailable_until
        .insert(placement_group_id.clone(), now.saturating_add(cooldown));
}

// Clears one route's failure history after a completed successful request.
fn mark_route_success(state: &mut GatewayState, placement_group_id: &PlacementGroupId) {
    state.failure_counts.remove(placement_group_id);
    state.unavailable_until.remove(placement_group_id);
}

// Records one learned prefix route while expiring and bounding prior entries.
fn record_prefix_affinity(
    state: &mut GatewayState,
    key: (LogicalModelName, Sha256Digest),
    placement_group_id: PlacementGroupId,
    now: u64,
) {
    state
        .prefix_affinity
        .retain(|_, (_, deadline)| *deadline > now);
    state.prefix_affinity.insert(
        key,
        (
            placement_group_id,
            now.saturating_add(PREFIX_AFFINITY_MILLISECONDS),
        ),
    );
    while state.prefix_affinity.len() > MAX_PREFIX_AFFINITY_ENTRIES {
        let oldest = state
            .prefix_affinity
            .iter()
            .min_by(|left, right| left.1 .1.cmp(&right.1 .1).then_with(|| left.0.cmp(right.0)))
            .map(|(key, _)| key.clone());
        if let Some(oldest) = oldest {
            state.prefix_affinity.remove(&oldest);
        }
    }
}

// Converts one queued request into exact route and active-request ownership.
fn reserve_route(
    state: &mut GatewayState,
    queued: QueuedRequest,
    route: GatewayRoute,
    now: li_core_interface::UnixMilliseconds,
) -> Result<GatewayReservation, GatewayError> {
    let queued_milliseconds = queued
        .queued_milliseconds
        .saturating_add(now.value().saturating_sub(queued.enqueued_at));
    if state
        .active_requests
        .insert(
            queued.request.request_id().clone(),
            route.placement_group_id().clone(),
        )
        .is_some()
    {
        return Err(GatewayError::DuplicateRequest);
    }
    *state
        .route_active
        .entry(route.placement_group_id().clone())
        .or_default() += 1;
    if !queued.was_admitted {
        state.telemetry.record_admitted(&route);
    }
    Ok(GatewayReservation {
        request: queued.request,
        route,
        principal: queued.principal,
        received_at: queued.received_at,
        queued_milliseconds,
        reserved_tokens: queued.reserved_tokens,
    })
}

// Removes one exact queue entry and its FIFO index.
fn remove_queued_request(
    state: &mut GatewayState,
    request_id: &Sha256Digest,
) -> Result<QueuedRequest, GatewayError> {
    let queued = state
        .queued
        .remove(request_id)
        .ok_or(GatewayError::RequestNotFound)?;
    state
        .queue_order
        .retain(|candidate| candidate != request_id);
    Ok(queued)
}

// Releases one exact active route reservation and rejects foreign completion.
fn release_reservation(
    state: &mut GatewayState,
    reservation: &GatewayReservation,
) -> Result<(), GatewayError> {
    let observed = state
        .active_requests
        .remove(reservation.request.request_id())
        .ok_or(GatewayError::RequestNotFound)?;
    if &observed != reservation.route.placement_group_id() {
        return Err(GatewayError::StateUnavailable);
    }
    let active = state
        .route_active
        .get(reservation.route.placement_group_id())
        .copied()
        .ok_or(GatewayError::StateUnavailable)?;
    if active <= 1 {
        state
            .route_active
            .remove(reservation.route.placement_group_id());
    } else {
        state
            .route_active
            .insert(reservation.route.placement_group_id().clone(), active - 1);
    }
    Ok(())
}

// Releases only live concurrency and token reservations for one authenticated principal.
fn release_principal(
    state: &mut GatewayState,
    principal: Option<&GatewayPrincipal>,
    reserved_tokens: u64,
) {
    let Some(principal) = principal else {
        return;
    };
    let key_id = principal.key_id();
    let active = state.principal_active.get(key_id).copied().unwrap_or(0);
    if active <= 1 {
        state.principal_active.remove(key_id);
    } else {
        state.principal_active.insert(key_id.clone(), active - 1);
    }
    if reserved_tokens > 0 {
        let reserved = state
            .principal_reserved_tokens
            .get(key_id)
            .copied()
            .unwrap_or(0)
            .saturating_sub(reserved_tokens);
        if reserved == 0 {
            state.principal_reserved_tokens.remove(key_id);
        } else {
            state
                .principal_reserved_tokens
                .insert(key_id.clone(), reserved);
        }
    }
}
