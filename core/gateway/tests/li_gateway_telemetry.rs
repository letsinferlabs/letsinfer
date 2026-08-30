// SPDX-License-Identifier: AGPL-3.0-only

use std::num::{NonZeroU32, NonZeroU64};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use li_authentication_manager::ApiKeyLimits;
use li_core_interface::{
    ApiKeyId, BootId, EndpointAddress, EndpointScheme, InstallationId, LogicalModelName,
    NodeAddress, NodeId, PlacementGroupId, PlacementId, Sha256Digest, TechnicalName,
    UnixMilliseconds,
};
use li_gateway_manager::{
    GatewayAdmission, GatewayAuthenticationProvider, GatewayChatCompletionRequest, GatewayClock,
    GatewayError, GatewayExactUsage, GatewayExecution, GatewayExecutionFailure,
    GatewayExecutionProvider, GatewayManager, GatewayMode, GatewayPlacementProtectionLease,
    GatewayPlacementProtectionSnapshot, GatewayPrincipal, GatewayProtectionAuthority,
    GatewayProtectionLeaseProvider, GatewayQueueTicket, GatewayQueueWaiter,
    GatewayRelayAuthorizationProvider, GatewayRequest, GatewayResponseHead, GatewayResponseHeader,
    GatewayResponseWriter, GatewayRoute, GatewayRouteProvider, GatewayRouteTarget,
    GatewayTelemetryPublisher, GatewayTelemetrySnapshot, GatewayUsageRecord, GatewayUsageStore,
};

// Supplies deterministic time to request lifecycles and publisher freshness checks.
struct ClockMock {
    now: AtomicU64,
}

impl ClockMock {
    // Advances fixture time without sleeping or consulting the host clock.
    fn advance(&self, milliseconds: u64) {
        self.now.fetch_add(milliseconds, Ordering::SeqCst);
    }
}

impl GatewayClock for ClockMock {
    // Returns the exact test-controlled Unix observation.
    fn now(&self) -> Result<UnixMilliseconds, GatewayError> {
        Ok(UnixMilliseconds::new(self.now.load(Ordering::SeqCst)))
    }
}

// Projects one unrestricted principal without retaining bearer material.
struct AuthenticationMock;

impl GatewayAuthenticationProvider for AuthenticationMock {
    // Returns the fixed API-key identity for every fixture model.
    fn authenticate(
        &self,
        _bearer_token: &str,
        _model: &LogicalModelName,
    ) -> Result<GatewayPrincipal, GatewayError> {
        Ok(GatewayPrincipal::new(
            api_key_id('a'),
            ApiKeyLimits::new(None, None, None, None),
        ))
    }
}

// Authorizes the fixed main identity for an otherwise unused relay boundary.
struct RelayAuthorizationMock;

impl GatewayRelayAuthorizationProvider for RelayAuthorizationMock {
    // Returns the main node bound by the fixture child relationship.
    fn authorize(&self, _relay_credential: &str) -> Result<NodeId, GatewayError> {
        Ok(node_id('1'))
    }
}

// Supplies one mutable route snapshot for lifecycle and identity-bound tests.
struct RouteMock {
    routes: Mutex<Vec<GatewayRoute>>,
}

impl GatewayRouteProvider for RouteMock {
    // Returns a cloned deterministic route snapshot for the exact model.
    fn routes(&self, _model: &LogicalModelName) -> Result<Vec<GatewayRoute>, GatewayError> {
        Ok(self.routes.lock().expect("routes").clone())
    }
}

// Supplies current protection snapshots to telemetry request-lifecycle fixtures.
struct ProtectionMock {
    clock: Arc<ClockMock>,
    sequence: AtomicU64,
}

impl GatewayProtectionLeaseProvider for ProtectionMock {
    // Returns one fresh single-placement lease for an exact route.
    fn snapshot(
        &self,
        route: &GatewayRoute,
    ) -> Result<Option<GatewayPlacementProtectionSnapshot>, GatewayError> {
        let now = self.clock.now.load(Ordering::SeqCst);
        let sequence = self.sequence.fetch_add(1, Ordering::SeqCst) + 1;
        let placement_id =
            PlacementId::parse(route.placement_group_id().as_str()).expect("placement identity");
        let core = InstallationId::parse(&identity('a', 64)).expect("Core");
        let watchdog = digest('b');
        let session = digest('c');
        let session_generation = NonZeroU64::new(1).expect("session generation");
        let lease = GatewayPlacementProtectionLease::new(
            route.endpoint_node_id().clone(),
            route.placement_group_id().clone(),
            placement_id.clone(),
            core.clone(),
            watchdog.clone(),
            session.clone(),
            session_generation,
            &identity('e', 32),
            TechnicalName::parse("li_placement_fixture").expect("container"),
            digest('f'),
            42,
            84,
            BootId::parse("12345678-1234-1234-1234-123456789abc").expect("boot"),
            "/sys/fs/cgroup/li_fixture",
            NonZeroU64::new(sequence).expect("sequence"),
            UnixMilliseconds::new(now),
            now.max(1),
            UnixMilliseconds::new(now + 1_000),
            true,
            false,
        )?;
        Ok(Some(GatewayPlacementProtectionSnapshot::new(
            route.placement_group_id().clone(),
            vec![(placement_id, route.endpoint_node_id().clone())],
            vec![GatewayProtectionAuthority::new(
                route.endpoint_node_id().clone(),
                core,
                watchdog,
                session,
                session_generation,
            )],
            vec![lease],
        )?))
    }
}

// Accepts completed rolling-window usage without retaining request history.
struct UsageMock;

impl GatewayUsageStore for UsageMock {
    // Returns no prior usage for a fresh deterministic Gateway process.
    fn recent(
        &self,
        _key_id: &ApiKeyId,
        _since: UnixMilliseconds,
    ) -> Result<Vec<GatewayUsageRecord>, GatewayError> {
        Ok(Vec::new())
    }

    // Accepts one exact usage record without external I/O.
    fn record(&self, _usage: &GatewayUsageRecord) -> Result<(), GatewayError> {
        Ok(())
    }
}

// Captures only the latest immutable snapshot and injects atomic publication failure.
struct TelemetryPublisherMock {
    fail: AtomicBool,
    calls: AtomicUsize,
    latest: Mutex<Option<GatewayTelemetrySnapshot>>,
}

impl GatewayTelemetryPublisher for TelemetryPublisherMock {
    // Publishes the whole snapshot or fails before changing its visible fixture state.
    fn publish_atomically(&self, snapshot: &GatewayTelemetrySnapshot) -> Result<(), GatewayError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst) {
            return Err(GatewayError::provider("native_io", "mock failure"));
        }
        *self.latest.lock().expect("latest snapshot") = Some(snapshot.clone());
        Ok(())
    }
}

// Advances deterministic time around one complete streamed Engine response.
struct TimedExecutionProvider {
    clock: Arc<ClockMock>,
}

impl GatewayExecutionProvider for TimedExecutionProvider {
    // Emits one head and body before returning exact cumulative usage.
    fn forward(
        &self,
        _route: &GatewayRoute,
        _request: &GatewayChatCompletionRequest,
        response: &mut dyn GatewayResponseWriter,
    ) -> Result<GatewayExactUsage, GatewayExecutionFailure> {
        self.clock.advance(25);
        response.write_head(&response_head())?;
        self.clock.advance(75);
        response.write_body(b"{\"id\":\"completion\"}")?;
        self.clock.advance(40);
        Ok(GatewayExactUsage::new(10, 4, 2).expect("usage"))
    }
}

// Rejects any unexpected queue wait in immediate execution fixtures.
struct ImmediateQueueWaiter;

impl GatewayQueueWaiter for ImmediateQueueWaiter {
    // Fails if a test unexpectedly enters the manager-owned FIFO queue.
    fn wait(&self, _ticket: &GatewayQueueTicket) -> Result<(), GatewayError> {
        Err(GatewayError::provider("queue_wait", "unexpected mock wait"))
    }
}

// Accepts bounded response output without retaining body or credential data.
struct ResponseWriterMock;

impl GatewayResponseWriter for ResponseWriterMock {
    // Accepts one already-validated response head.
    fn write_head(&mut self, _head: &GatewayResponseHead) -> Result<(), GatewayExecutionFailure> {
        Ok(())
    }

    // Accepts one already-bounded body fragment.
    fn write_body(&mut self, _body: &[u8]) -> Result<(), GatewayExecutionFailure> {
        Ok(())
    }
}

// Groups the manager with the deterministic boundaries observed by telemetry tests.
struct TestEnvironment {
    manager: Arc<GatewayManager>,
    clock: Arc<ClockMock>,
    routes: Arc<RouteMock>,
    publisher: Arc<TelemetryPublisherMock>,
}

// Creates one main Gateway with explicit time, route, usage, and publisher boundaries.
fn environment(routes: Vec<GatewayRoute>) -> TestEnvironment {
    let clock = Arc::new(ClockMock {
        now: AtomicU64::new(1_000),
    });
    let routes = Arc::new(RouteMock {
        routes: Mutex::new(routes),
    });
    let publisher = Arc::new(TelemetryPublisherMock {
        fail: AtomicBool::new(false),
        calls: AtomicUsize::new(0),
        latest: Mutex::new(None),
    });
    let protection = Arc::new(ProtectionMock {
        clock: clock.clone(),
        sequence: AtomicU64::new(0),
    });
    let manager = Arc::new(
        GatewayManager::new_with_telemetry(
            GatewayMode::Main {
                local_node_id: node_id('1'),
            },
            Arc::new(AuthenticationMock),
            Arc::new(RelayAuthorizationMock),
            routes.clone(),
            protection,
            clock.clone(),
            Arc::new(UsageMock),
            publisher.clone(),
        )
        .expect("gateway"),
    );
    TestEnvironment {
        manager,
        clock,
        routes,
        publisher,
    }
}

// Returns one repeated canonical identity.
fn identity(character: char, length: usize) -> String {
    character.to_string().repeat(length)
}

// Returns one canonical SHA-256 fixture identity.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&identity(character, 64)).expect("digest")
}

// Returns one canonical node identity.
fn node_id(character: char) -> NodeId {
    NodeId::parse(&identity(character, 32)).expect("node")
}

// Returns one canonical API-key identity.
fn api_key_id(character: char) -> ApiKeyId {
    ApiKeyId::parse(&identity(character, 32)).expect("API key")
}

// Returns the ordinary logical-model fixture.
fn model() -> LogicalModelName {
    LogicalModelName::parse("qwen3_8").expect("model")
}

// Returns one canonical SHA-256 request identity from a bounded integer.
fn request_digest(value: usize) -> Sha256Digest {
    Sha256Digest::parse(&format!("{value:064x}")).expect("request digest")
}

// Returns one canonical placement-group identity from a bounded integer.
fn indexed_placement_group_id(value: usize) -> PlacementGroupId {
    PlacementGroupId::parse(&format!("{value:032x}")).expect("placement group")
}

// Returns one exact token-counted request.
fn request(value: usize, queue_milliseconds: u64) -> GatewayRequest {
    GatewayRequest::new(
        request_digest(value),
        model(),
        NonZeroU64::new(10).expect("context"),
        NonZeroU64::new(10).expect("output"),
        None,
        queue_milliseconds,
    )
    .expect("request")
}

// Returns one bounded normalized chat-completions request.
fn chat_request(value: usize) -> GatewayChatCompletionRequest {
    GatewayChatCompletionRequest::new(
        request(value, 0),
        b"{\"model\":\"qwen3_8\",\"messages\":[]}".to_vec(),
    )
    .expect("chat request")
}

// Returns one valid local Engine route with deterministic capacity.
fn route(placement_group_id: PlacementGroupId, capacity: u32) -> GatewayRoute {
    GatewayRoute::new(
        placement_group_id,
        node_id('1'),
        model(),
        GatewayRouteTarget::LocalEngine {
            endpoint: EndpointAddress::new(
                EndpointScheme::Https,
                NodeAddress::parse("127.0.0.1").expect("address"),
                18_000,
            )
            .expect("endpoint"),
        },
        NonZeroU32::new(capacity).expect("capacity"),
        NonZeroU64::new(1_024).expect("context"),
        true,
        false,
        Some(40_000),
        Vec::new(),
    )
    .expect("route")
}

// Returns one validated ordinary OpenAI response head.
fn response_head() -> GatewayResponseHead {
    GatewayResponseHead::new(
        200,
        vec![GatewayResponseHeader::new("Content-Type", "application/json").expect("content type")],
    )
    .expect("response head")
}

// Records exact tokens and latency while expiring only the bounded rate window.
#[test]
fn ordinary_success_produces_exact_aggregate_and_group_activity() {
    let group = indexed_placement_group_id(1);
    let environment = environment(vec![route(group.clone(), 2)]);
    let execution = GatewayExecution::new(
        environment.manager.clone(),
        Arc::new(TimedExecutionProvider {
            clock: environment.clock.clone(),
        }),
        Arc::new(ImmediateQueueWaiter),
    );
    let mut response = ResponseWriterMock;

    execution
        .forward_public("secret", chat_request(1), &mut response)
        .expect("execution");
    let snapshot = environment
        .manager
        .telemetry_snapshot()
        .expect("telemetry snapshot");
    let counters = snapshot.counters();
    assert_eq!(snapshot.schema_version(), 2);
    assert_eq!(counters.requests_received(), 1);
    assert_eq!(counters.requests_admitted(), 1);
    assert_eq!(counters.requests_completed(), 1);
    assert_eq!(
        (counters.active_requests(), counters.queued_requests()),
        (0, 0)
    );
    assert_eq!(
        (
            counters.input_tokens(),
            counters.output_tokens(),
            counters.cached_tokens(),
        ),
        (10, 4, 2)
    );
    assert_eq!(counters.ttft_milliseconds(), 100);
    assert_eq!(counters.decode_milliseconds(), 40);
    assert_eq!(counters.exact_token_requests(), 1);
    assert_eq!(counters.prefix_cache_hits(), 1);
    let activity = &snapshot.placement_groups()[0];
    assert_eq!(activity.placement_group_id(), &group);
    assert_eq!(activity.counters().requests_completed(), 1);
    assert_eq!(activity.rates().output_tokens_per_second(), 4.0);

    environment.clock.advance(5_001);
    let expired = environment
        .manager
        .telemetry_snapshot()
        .expect("expired rate snapshot");
    assert_eq!(expired.counters().output_tokens(), 4);
    assert_eq!(
        expired.placement_groups()[0]
            .rates()
            .output_tokens_per_second(),
        0.0
    );
}

// Counts retry, terminal failure, and explicit cancellation exactly once per request.
#[test]
fn retry_failure_and_cancellation_preserve_terminal_counter_identity() {
    let first_group = indexed_placement_group_id(1);
    let second_group = indexed_placement_group_id(2);
    let environment = environment(vec![
        route(first_group.clone(), 1),
        route(second_group.clone(), 1),
    ]);
    let GatewayAdmission::Admitted(first) = environment
        .manager
        .admit_public("secret", request(1, 0))
        .expect("first admission")
    else {
        panic!("first reservation");
    };
    let GatewayAdmission::Admitted(retried) = environment
        .manager
        .retry_before_output(first)
        .expect("retry")
    else {
        panic!("retry reservation");
    };
    environment
        .manager
        .fail_after_output(retried)
        .expect("terminal failure");

    environment.clock.advance(1_001);
    let GatewayAdmission::Admitted(cancelled) = environment
        .manager
        .admit_public("secret", request(2, 0))
        .expect("cancellation admission")
    else {
        panic!("cancellation reservation");
    };
    environment.manager.cancel(cancelled).expect("cancel");

    let snapshot = environment
        .manager
        .telemetry_snapshot()
        .expect("telemetry snapshot");
    let counters = snapshot.counters();
    assert_eq!(counters.requests_received(), 2);
    assert_eq!(counters.requests_admitted(), 2);
    assert_eq!(counters.requests_retried(), 1);
    assert_eq!(counters.requests_failed(), 1);
    assert_eq!(counters.requests_cancelled(), 1);
    assert_eq!(counters.requests_completed(), 0);
    assert_eq!(
        (counters.active_requests(), counters.queued_requests()),
        (0, 0)
    );
    let first = snapshot
        .placement_groups()
        .iter()
        .find(|activity| activity.placement_group_id() == &first_group)
        .expect("first group");
    let second = snapshot
        .placement_groups()
        .iter()
        .find(|activity| activity.placement_group_id() == &second_group)
        .expect("second group");
    assert_eq!(first.counters().requests_retried(), 1);
    assert_eq!(first.counters().requests_cancelled(), 1);
    assert_eq!(second.counters().requests_failed(), 1);
}

// Keeps active and queued gauges at zero after duplicate terminal calls are rejected.
#[test]
fn cancellation_gauges_never_underflow() {
    let environment = environment(vec![route(indexed_placement_group_id(1), 1)]);
    let GatewayAdmission::Admitted(blocker) = environment
        .manager
        .admit_public("secret", request(1, 0))
        .expect("blocker")
    else {
        panic!("blocker reservation");
    };
    let GatewayAdmission::Queued(ticket) = environment
        .manager
        .admit_public("secret", request(2, 1_000))
        .expect("queued request")
    else {
        panic!("queue ticket");
    };
    let queued = environment
        .manager
        .telemetry_snapshot()
        .expect("queued snapshot");
    assert_eq!(
        (
            queued.counters().active_requests(),
            queued.counters().queued_requests()
        ),
        (1, 1)
    );
    assert_eq!(queued.models()[0].queued_requests(), 1);

    environment
        .manager
        .cancel_queue(ticket.clone())
        .expect("cancel queue");
    assert_eq!(
        environment.manager.cancel_queue(ticket),
        Err(GatewayError::RequestNotFound)
    );
    environment.manager.cancel(blocker).expect("cancel blocker");
    let terminal = environment
        .manager
        .telemetry_snapshot()
        .expect("terminal snapshot");
    assert_eq!(
        (
            terminal.counters().active_requests(),
            terminal.counters().queued_requests(),
            terminal.counters().requests_cancelled(),
        ),
        (0, 0, 2)
    );
    assert!(terminal.models().is_empty());
}

// Makes readiness depend on one fresh successful atomic publication.
#[test]
fn publisher_failure_and_freshness_drive_redacted_health() {
    let environment = environment(vec![route(indexed_placement_group_id(1), 1)]);
    assert!(!environment
        .manager
        .telemetry_health()
        .expect("initial health")
        .is_healthy());

    let published = environment.manager.publish_telemetry().expect("publish");
    assert_eq!(
        environment
            .publisher
            .latest
            .lock()
            .expect("latest")
            .as_ref(),
        Some(&published)
    );
    assert!(environment
        .manager
        .telemetry_health()
        .expect("published health")
        .is_healthy());

    environment.clock.advance(3_501);
    assert!(!environment
        .manager
        .telemetry_health()
        .expect("stale health")
        .is_healthy());
    environment.publisher.fail.store(true, Ordering::SeqCst);
    assert_eq!(
        environment.manager.publish_telemetry(),
        Err(GatewayError::provider(
            "telemetry_publish",
            "atomic publisher rejected snapshot",
        ))
    );
    let failed = environment
        .manager
        .telemetry_health()
        .expect("failed health");
    assert!(!failed.is_healthy());
    assert_eq!(failed.last_failure_at(), Some(UnixMilliseconds::new(4_501)));

    environment.publisher.fail.store(false, Ordering::SeqCst);
    environment
        .manager
        .publish_telemetry()
        .expect("recovered publish");
    let recovered = environment
        .manager
        .telemetry_health()
        .expect("recovered health");
    assert!(recovered.is_healthy());
    assert_eq!(recovered.last_failure_at(), None);
    assert_eq!(environment.publisher.calls.load(Ordering::SeqCst), 3);
}

// Retains a fixed placement-group identity set while aggregate counters remain exact.
#[test]
fn placement_group_activity_has_a_hard_identity_bound() {
    let environment = environment(vec![route(indexed_placement_group_id(1), 1)]);
    let bound = GatewayTelemetrySnapshot::maximum_placement_group_activity();
    for value in 1..=bound + 1 {
        *environment.routes.routes.lock().expect("routes") =
            vec![route(indexed_placement_group_id(value), 1)];
        let GatewayAdmission::Admitted(reservation) = environment
            .manager
            .admit_public("secret", request(value, 0))
            .expect("admission")
        else {
            panic!("reservation");
        };
        environment.manager.cancel(reservation).expect("cancel");
    }

    let snapshot = environment
        .manager
        .telemetry_snapshot()
        .expect("bounded snapshot");
    assert_eq!(snapshot.placement_groups().len(), bound);
    assert_eq!(snapshot.counters().requests_received(), (bound + 1) as u64);
    assert_eq!(snapshot.counters().requests_admitted(), (bound + 1) as u64);
    assert_eq!(snapshot.counters().requests_cancelled(), (bound + 1) as u64);
}
