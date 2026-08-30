// SPDX-License-Identifier: AGPL-3.0-only

use std::num::{NonZeroU32, NonZeroU64};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use li_authentication_manager::ApiKeyLimits;
use li_core_interface::{
    ApiKeyId, BootId, EndpointAddress, EndpointScheme, InstallationId, LogicalModelName,
    NodeAddress, NodeId, PlacementGroupId, PlacementId, Sha256Digest, TechnicalName,
    UnixMilliseconds,
};
use li_gateway_manager::{
    GatewayAdmission, GatewayAuthenticationProvider, GatewayClock, GatewayError, GatewayManager,
    GatewayMode, GatewayPlacementProtectionLease, GatewayPlacementProtectionSnapshot,
    GatewayPrincipal, GatewayProtectionAuthority, GatewayProtectionLeaseProvider,
    GatewayQueueStatus, GatewayRelayAuthorizationProvider, GatewayRequest, GatewayRoute,
    GatewayRouteProvider, GatewayRouteTarget, GatewayUsageRecord, GatewayUsageStore,
};

// Supplies explicit mutable time and one deterministic failure switch.
struct TestClock {
    now: AtomicU64,
    fail: AtomicBool,
}

impl TestClock {
    // Advances test time without sleeping.
    fn advance(&self, milliseconds: u64) {
        self.now.fetch_add(milliseconds, Ordering::SeqCst);
    }
}

impl GatewayClock for TestClock {
    // Returns deterministic time or one injected failure.
    fn now(&self) -> Result<UnixMilliseconds, GatewayError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(GatewayError::provider("clock", "mock failure"));
        }
        Ok(UnixMilliseconds::new(self.now.load(Ordering::SeqCst)))
    }
}

// Returns one fixed verified API-key principal.
struct AuthenticationMock {
    principal: GatewayPrincipal,
    calls: AtomicUsize,
    fail: AtomicBool,
}

impl GatewayAuthenticationProvider for AuthenticationMock {
    // Authenticates without retaining or recording bearer material.
    fn authenticate(
        &self,
        _bearer_token: &str,
        _model: &LogicalModelName,
    ) -> Result<GatewayPrincipal, GatewayError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst) {
            return Err(GatewayError::AuthenticationDenied);
        }
        Ok(self.principal.clone())
    }
}

// Returns one fixed main-node identity for a private relay credential.
struct RelayAuthorizationMock {
    node_id: Mutex<NodeId>,
    calls: AtomicUsize,
    fail: AtomicBool,
}

impl GatewayRelayAuthorizationProvider for RelayAuthorizationMock {
    // Resolves one private relay credential to its bound main node.
    fn authorize(&self, _relay_credential: &str) -> Result<NodeId, GatewayError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst) {
            return Err(GatewayError::RelayDenied);
        }
        Ok(self.node_id.lock().expect("relay node").clone())
    }
}

// Supplies one mutable deterministic route snapshot.
struct RouteMock {
    routes: Mutex<Vec<GatewayRoute>>,
    calls: AtomicUsize,
    fail: AtomicBool,
}

impl GatewayRouteProvider for RouteMock {
    // Returns the current cloned route snapshot or one injected failure.
    fn routes(&self, _model: &LogicalModelName) -> Result<Vec<GatewayRoute>, GatewayError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst) {
            return Err(GatewayError::provider("routes", "mock failure"));
        }
        Ok(self.routes.lock().expect("routes").clone())
    }
}

// Supplies fresh exact single-placement protection to manager behavior fixtures.
struct ProtectionMock {
    clock: Arc<TestClock>,
    session_generation: AtomicU64,
    last_clock: AtomicU64,
}

impl GatewayProtectionLeaseProvider for ProtectionMock {
    // Constructs one current complete group snapshot without retaining route state.
    fn snapshot(
        &self,
        route: &GatewayRoute,
    ) -> Result<Option<GatewayPlacementProtectionSnapshot>, GatewayError> {
        let now = self.clock.now.load(Ordering::SeqCst);
        let sequence = now.max(1);
        let previous_clock = self.last_clock.swap(now, Ordering::SeqCst);
        if now < previous_clock {
            self.session_generation.fetch_add(1, Ordering::SeqCst);
        }
        let generation = self.session_generation.load(Ordering::SeqCst);
        let session_character = if generation % 2 == 0 { 'd' } else { 'e' };
        let placement_id =
            PlacementId::parse(route.placement_group_id().as_str()).expect("placement identity");
        let core_installation_id = InstallationId::parse(&identity('a', 64)).expect("Core");
        let watchdog_source_identity = digest('b');
        let session_id = digest(session_character);
        let session_generation = NonZeroU64::new(generation).expect("session generation");
        let lease = GatewayPlacementProtectionLease::new(
            route.endpoint_node_id().clone(),
            route.placement_group_id().clone(),
            placement_id.clone(),
            core_installation_id.clone(),
            watchdog_source_identity.clone(),
            session_id.clone(),
            session_generation,
            &identity('c', 32),
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
                core_installation_id,
                watchdog_source_identity,
                session_id,
                session_generation,
            )],
            vec![lease],
        )?))
    }
}

// Stores completed usage and supplies restart-window fixtures.
#[derive(Default)]
struct UsageMock {
    records: Mutex<Vec<GatewayUsageRecord>>,
    recent_calls: AtomicUsize,
    record_calls: AtomicUsize,
    fail_recent: AtomicBool,
    fail_record: AtomicBool,
    return_foreign: AtomicBool,
}

impl GatewayUsageStore for UsageMock {
    // Returns one key's recent completed records unless corruption is injected.
    fn recent(
        &self,
        key_id: &ApiKeyId,
        since: UnixMilliseconds,
    ) -> Result<Vec<GatewayUsageRecord>, GatewayError> {
        self.recent_calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_recent.load(Ordering::SeqCst) {
            return Err(GatewayError::provider("usage_read", "mock failure"));
        }
        let records = self.records.lock().expect("usage records");
        if self.return_foreign.load(Ordering::SeqCst) {
            return Ok(records.clone());
        }
        Ok(records
            .iter()
            .filter(|record| {
                record.key_id() == key_id && record.completed_at().value() >= since.value()
            })
            .cloned()
            .collect())
    }

    // Appends one exact completed usage record.
    fn record(&self, usage: &GatewayUsageRecord) -> Result<(), GatewayError> {
        self.record_calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_record.load(Ordering::SeqCst) {
            return Err(GatewayError::provider("usage_write", "mock failure"));
        }
        self.records
            .lock()
            .expect("usage records")
            .push(usage.clone());
        Ok(())
    }
}

// Groups one manager with observable deterministic providers.
struct TestEnvironment {
    manager: Arc<GatewayManager>,
    authentication: Arc<AuthenticationMock>,
    relay: Arc<RelayAuthorizationMock>,
    routes: Arc<RouteMock>,
    clock: Arc<TestClock>,
    usage: Arc<UsageMock>,
}

// Creates one complete deterministic Gateway composition.
fn environment(
    mode: GatewayMode,
    limits: ApiKeyLimits,
    routes: Vec<GatewayRoute>,
) -> TestEnvironment {
    let authentication = Arc::new(AuthenticationMock {
        principal: GatewayPrincipal::new(api_key_id('a'), limits),
        calls: AtomicUsize::new(0),
        fail: AtomicBool::new(false),
    });
    let relay = Arc::new(RelayAuthorizationMock {
        node_id: Mutex::new(node_id('1')),
        calls: AtomicUsize::new(0),
        fail: AtomicBool::new(false),
    });
    let routes = Arc::new(RouteMock {
        routes: Mutex::new(routes),
        calls: AtomicUsize::new(0),
        fail: AtomicBool::new(false),
    });
    let clock = Arc::new(TestClock {
        now: AtomicU64::new(100_000),
        fail: AtomicBool::new(false),
    });
    let usage = Arc::new(UsageMock::default());
    let protection = Arc::new(ProtectionMock {
        clock: clock.clone(),
        session_generation: AtomicU64::new(1),
        last_clock: AtomicU64::new(100_000),
    });
    let manager = Arc::new(
        GatewayManager::new(
            mode,
            authentication.clone(),
            relay.clone(),
            routes.clone(),
            protection,
            clock.clone(),
            usage.clone(),
        )
        .expect("gateway"),
    );
    TestEnvironment {
        manager,
        authentication,
        relay,
        routes,
        clock,
        usage,
    }
}

// Returns one repeated canonical identity.
fn identity(character: char, length: usize) -> String {
    character.to_string().repeat(length)
}

// Returns one canonical node identity.
fn node_id(character: char) -> NodeId {
    NodeId::parse(&identity(character, 32)).expect("node")
}

// Returns one canonical placement-group identity.
fn placement_group_id(character: char) -> PlacementGroupId {
    PlacementGroupId::parse(&identity(character, 32)).expect("placement group")
}

// Returns one canonical API-key identity.
fn api_key_id(character: char) -> ApiKeyId {
    ApiKeyId::parse(&identity(character, 32)).expect("API key")
}

// Returns one canonical SHA-256 identity.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&identity(character, 64)).expect("digest")
}

// Returns the ordinary logical model fixture.
fn model() -> LogicalModelName {
    LogicalModelName::parse("qwen3_8").expect("model")
}

// Returns one explicit set of optional API-key limits.
fn limits(
    requests_per_minute: Option<u32>,
    tokens_per_minute: Option<u64>,
    concurrency: Option<u32>,
    context_tokens: Option<u64>,
) -> ApiKeyLimits {
    ApiKeyLimits::new(
        requests_per_minute.and_then(NonZeroU32::new),
        tokens_per_minute.and_then(NonZeroU64::new),
        concurrency.and_then(NonZeroU32::new),
        context_tokens.and_then(NonZeroU64::new),
    )
}

// Returns one valid route with explicit capacity and load-balancing facts.
#[allow(clippy::too_many_arguments)]
fn route(
    group_character: char,
    node_character: char,
    max_active_requests: u32,
    max_context_tokens: u64,
    temperature_millicelsius: Option<u32>,
    prefix_keys: Vec<Sha256Digest>,
    healthy: bool,
    memory_pressure: bool,
    target: GatewayRouteTarget,
) -> GatewayRoute {
    GatewayRoute::new(
        placement_group_id(group_character),
        node_id(node_character),
        model(),
        target,
        NonZeroU32::new(max_active_requests).expect("active capacity"),
        NonZeroU64::new(max_context_tokens).expect("context capacity"),
        healthy,
        memory_pressure,
        temperature_millicelsius,
        prefix_keys,
    )
    .expect("route")
}

// Returns one local Engine route.
fn local_route(group_character: char, node_character: char, capacity: u32) -> GatewayRoute {
    route(
        group_character,
        node_character,
        capacity,
        1_024,
        Some(50_000),
        Vec::new(),
        true,
        false,
        GatewayRouteTarget::LocalEngine {
            endpoint: EndpointAddress::new(
                EndpointScheme::Https,
                NodeAddress::parse("127.0.0.1").expect("address"),
                18_000,
            )
            .expect("endpoint"),
        },
    )
}

// Returns one exact token-counted request.
fn request(
    character: char,
    context_tokens: u64,
    maximum_output_tokens: u64,
    prefix_key: Option<Sha256Digest>,
    queue_milliseconds: u64,
) -> GatewayRequest {
    GatewayRequest::new(
        digest(character),
        model(),
        NonZeroU64::new(context_tokens).expect("context"),
        NonZeroU64::new(maximum_output_tokens).expect("output"),
        prefix_key,
        queue_milliseconds,
    )
    .expect("request")
}

// Returns one main-gateway mode fixture.
fn main_mode() -> GatewayMode {
    GatewayMode::Main {
        local_node_id: node_id('1'),
    }
}

// Returns one child-gateway mode fixture.
fn child_mode() -> GatewayMode {
    GatewayMode::Child {
        local_node_id: node_id('2'),
        main_node_id: node_id('1'),
    }
}

// Admits, completes, and persists one ordinary public request.
#[test]
fn main_admits_completes_and_persists_public_usage() {
    let environment = environment(
        main_mode(),
        limits(None, None, None, None),
        vec![local_route('3', '1', 2)],
    );
    let admission = environment
        .manager
        .admit_public("secret", request('1', 30, 20, None, 0))
        .expect("admission");
    let GatewayAdmission::Admitted(reservation) = admission else {
        panic!("immediate reservation");
    };
    assert_eq!(
        reservation.route().placement_group_id(),
        &placement_group_id('3')
    );
    assert_eq!(environment.manager.counts().expect("counts"), (1, 0));
    environment.clock.advance(25);
    let usage = environment
        .manager
        .complete(reservation, 30, 15)
        .expect("complete")
        .expect("public usage");
    assert_eq!(usage.tokens(), 45);
    assert_eq!(environment.manager.counts().expect("counts"), (0, 0));
    assert_eq!(environment.usage.record_calls.load(Ordering::SeqCst), 1);
    assert_eq!(environment.usage.records.lock().expect("records").len(), 1);
}

// Enforces public-main and private-child surfaces before unrelated providers run.
#[test]
fn gateway_modes_expose_only_their_authorized_surface() {
    let child = environment(
        child_mode(),
        limits(None, None, None, None),
        vec![local_route('3', '2', 1)],
    );
    assert_eq!(
        child
            .manager
            .admit_public("secret", request('1', 10, 10, None, 0)),
        Err(GatewayError::PublicUnavailableOnChild)
    );
    assert_eq!(child.authentication.calls.load(Ordering::SeqCst), 0);
    *child.relay.node_id.lock().expect("relay node") = node_id('4');
    assert_eq!(
        child
            .manager
            .admit_relay("relay", request('2', 10, 10, None, 0)),
        Err(GatewayError::RelayDenied)
    );
    *child.relay.node_id.lock().expect("relay node") = node_id('1');
    let GatewayAdmission::Admitted(reservation) = child
        .manager
        .admit_relay("relay", request('3', 10, 10, None, 0))
        .expect("relay admission")
    else {
        panic!("relay reservation");
    };
    assert!(child
        .manager
        .complete(reservation, 10, 5)
        .expect("complete relay")
        .is_none());
    assert_eq!(child.usage.record_calls.load(Ordering::SeqCst), 0);

    let main = environment(
        main_mode(),
        limits(None, None, None, None),
        vec![local_route('3', '1', 1)],
    );
    assert_eq!(
        main.manager
            .admit_relay("relay", request('4', 10, 10, None, 0)),
        Err(GatewayError::PrivateRelayUnavailableOnMain)
    );
    assert_eq!(main.relay.calls.load(Ordering::SeqCst), 0);
}

// Prefers prefix locality, normalized free capacity, temperature, then node identity.
#[test]
fn route_selection_is_deterministic_and_capacity_aware() {
    let prefix = digest('e');
    let prefix_route = route(
        '3',
        '1',
        2,
        1_024,
        Some(90_000),
        vec![prefix.clone()],
        true,
        false,
        GatewayRouteTarget::LocalEngine {
            endpoint: EndpointAddress::new(
                EndpointScheme::Https,
                NodeAddress::parse("127.0.0.1").expect("address"),
                18_001,
            )
            .expect("endpoint"),
        },
    );
    let cool_route = route(
        '4',
        '2',
        2,
        1_024,
        Some(40_000),
        Vec::new(),
        true,
        false,
        GatewayRouteTarget::ChildRelay {
            address: NodeAddress::parse("child.local").expect("address"),
        },
    );
    let environment = environment(
        main_mode(),
        limits(None, None, None, None),
        vec![prefix_route, cool_route],
    );
    let GatewayAdmission::Admitted(first) = environment
        .manager
        .admit_public("secret", request('1', 10, 10, Some(prefix), 0))
        .expect("prefix admission")
    else {
        panic!("prefix reservation");
    };
    assert_eq!(first.route().placement_group_id(), &placement_group_id('3'));
    let GatewayAdmission::Admitted(second) = environment
        .manager
        .admit_public("secret", request('2', 10, 10, None, 0))
        .expect("cool admission")
    else {
        panic!("cool reservation");
    };
    assert_eq!(
        second.route().placement_group_id(),
        &placement_group_id('4')
    );
    let GatewayAdmission::Admitted(third) = environment
        .manager
        .admit_public("secret", request('3', 10, 10, None, 0))
        .expect("normalized admission")
    else {
        panic!("normalized reservation");
    };
    assert_eq!(third.route().placement_group_id(), &placement_group_id('4'));
    environment.manager.cancel(first).expect("cancel first");
    environment.manager.cancel(second).expect("cancel second");
    environment.manager.cancel(third).expect("cancel third");
}

// Rejects incompatible context, unhealthy snapshots, and active memory pressure.
#[test]
fn route_and_context_failure_matrix_fails_closed() {
    let constrained = environment(
        main_mode(),
        limits(None, None, None, None),
        vec![route(
            '3',
            '1',
            1,
            100,
            None,
            Vec::new(),
            true,
            false,
            GatewayRouteTarget::LocalEngine {
                endpoint: EndpointAddress::new(
                    EndpointScheme::Https,
                    NodeAddress::parse("127.0.0.1").expect("address"),
                    18_000,
                )
                .expect("endpoint"),
            },
        )],
    );
    assert_eq!(
        constrained
            .manager
            .admit_public("secret", request('1', 80, 21, None, 0)),
        Err(GatewayError::ContextTooLarge)
    );
    let unhealthy = environment(
        main_mode(),
        limits(None, None, None, None),
        vec![route(
            '3',
            '1',
            1,
            1_024,
            None,
            Vec::new(),
            false,
            false,
            GatewayRouteTarget::LocalEngine {
                endpoint: EndpointAddress::new(
                    EndpointScheme::Https,
                    NodeAddress::parse("127.0.0.1").expect("address"),
                    18_000,
                )
                .expect("endpoint"),
            },
        )],
    );
    assert_eq!(
        unhealthy
            .manager
            .admit_public("secret", request('2', 10, 10, None, 0)),
        Err(GatewayError::NoRoute)
    );
    let pressure = environment(
        main_mode(),
        limits(None, None, None, None),
        vec![route(
            '3',
            '1',
            1,
            1_024,
            None,
            Vec::new(),
            true,
            true,
            GatewayRouteTarget::LocalEngine {
                endpoint: EndpointAddress::new(
                    EndpointScheme::Https,
                    NodeAddress::parse("127.0.0.1").expect("address"),
                    18_000,
                )
                .expect("endpoint"),
            },
        )],
    );
    assert_eq!(
        pressure
            .manager
            .admit_public("secret", request('3', 10, 10, None, 0)),
        Err(GatewayError::NoRoute)
    );

    let duplicate = local_route('3', '1', 1);
    let environment = environment(
        main_mode(),
        limits(None, None, None, None),
        vec![duplicate.clone(), duplicate],
    );
    assert!(matches!(
        environment
            .manager
            .admit_public("secret", request('4', 10, 10, None, 0)),
        Err(GatewayError::InvalidContract { .. })
    ));
}

// Reports public discovery availability from the same live safety and capacity gates.
#[test]
fn public_model_availability_tracks_mode_safety_capacity_and_cooldown() {
    let main_environment = environment(
        main_mode(),
        limits(None, None, None, None),
        vec![local_route('3', '1', 1)],
    );
    assert!(main_environment
        .manager
        .public_model_is_available(&model())
        .expect("available"));
    let GatewayAdmission::Admitted(reservation) = main_environment
        .manager
        .admit_public("secret", request('1', 10, 10, None, 0))
        .expect("admission")
    else {
        panic!("reservation");
    };
    assert!(!main_environment
        .manager
        .public_model_is_available(&model())
        .expect("full"));
    main_environment
        .manager
        .fail_after_output(reservation)
        .expect("failure");
    assert!(!main_environment
        .manager
        .public_model_is_available(&model())
        .expect("cooldown"));
    main_environment.clock.advance(60_001);
    assert!(main_environment
        .manager
        .public_model_is_available(&model())
        .expect("recovered"));

    *main_environment.routes.routes.lock().expect("routes") = vec![route(
        '3',
        '1',
        1,
        1_024,
        None,
        Vec::new(),
        true,
        true,
        GatewayRouteTarget::LocalEngine {
            endpoint: EndpointAddress::new(
                EndpointScheme::Https,
                NodeAddress::parse("127.0.0.1").expect("address"),
                18_000,
            )
            .expect("endpoint"),
        },
    )];
    assert!(!main_environment
        .manager
        .public_model_is_available(&model())
        .expect("pressure"));

    let child = environment(
        child_mode(),
        limits(None, None, None, None),
        vec![local_route('3', '2', 1)],
    );
    assert!(!child
        .manager
        .public_model_is_available(&model())
        .expect("private child"));
    assert_eq!(child.routes.calls.load(Ordering::SeqCst), 0);
}

// Enforces API-key context, request-rate, and concurrency limits independently.
#[test]
fn durable_policy_limit_matrix_is_gateway_owned() {
    let context = environment(
        main_mode(),
        limits(None, None, None, Some(50)),
        vec![local_route('3', '1', 2)],
    );
    assert_eq!(
        context
            .manager
            .admit_public("secret", request('1', 51, 1, None, 0)),
        Err(GatewayError::ContextTooLarge)
    );

    let rate = environment(
        main_mode(),
        limits(Some(1), None, None, None),
        vec![local_route('3', '1', 2)],
    );
    let GatewayAdmission::Admitted(first) = rate
        .manager
        .admit_public("secret", request('2', 10, 10, None, 0))
        .expect("first")
    else {
        panic!("first reservation");
    };
    rate.manager.cancel(first).expect("cancel");
    assert_eq!(
        rate.manager
            .admit_public("secret", request('3', 10, 10, None, 0)),
        Err(GatewayError::RequestRateLimit)
    );
    rate.clock.advance(60_001);
    assert!(matches!(
        rate.manager
            .admit_public("secret", request('4', 10, 10, None, 0)),
        Ok(GatewayAdmission::Admitted(_))
    ));

    let concurrency = environment(
        main_mode(),
        limits(None, None, Some(1), None),
        vec![local_route('3', '1', 2)],
    );
    let GatewayAdmission::Admitted(first) = concurrency
        .manager
        .admit_public("secret", request('5', 10, 10, None, 0))
        .expect("first")
    else {
        panic!("first reservation");
    };
    assert_eq!(
        concurrency
            .manager
            .admit_public("secret", request('6', 10, 10, None, 0)),
        Err(GatewayError::ConcurrencyLimit)
    );
    concurrency.manager.cancel(first).expect("cancel");
}

// Reserves worst-case token demand and replaces it with exact completion usage.
#[test]
fn token_limit_counts_active_reservations_and_completed_usage() {
    let environment = environment(
        main_mode(),
        limits(None, Some(100), None, None),
        vec![local_route('3', '1', 2)],
    );
    let GatewayAdmission::Admitted(first) = environment
        .manager
        .admit_public("secret", request('1', 30, 40, None, 0))
        .expect("first")
    else {
        panic!("first reservation");
    };
    assert_eq!(
        environment
            .manager
            .admit_public("secret", request('2', 20, 20, None, 0)),
        Err(GatewayError::TokenRateLimit)
    );
    environment
        .manager
        .complete(first, 30, 20)
        .expect("complete");
    let GatewayAdmission::Admitted(second) = environment
        .manager
        .admit_public("secret", request('3', 20, 20, None, 0))
        .expect("second")
    else {
        panic!("second reservation");
    };
    environment.manager.cancel(second).expect("cancel");
    environment.clock.advance(60_001);
    assert!(matches!(
        environment
            .manager
            .admit_public("secret", request('4', 50, 50, None, 0)),
        Ok(GatewayAdmission::Admitted(_))
    ));
}

// Owns a per-model FIFO queue and admits only its head when capacity returns.
#[test]
fn fifo_queue_orders_waiters_and_releases_capacity() {
    let environment = environment(
        main_mode(),
        limits(None, None, None, None),
        vec![local_route('3', '1', 1)],
    );
    let GatewayAdmission::Admitted(first) = environment
        .manager
        .admit_public("secret", request('1', 10, 10, None, 0))
        .expect("first")
    else {
        panic!("first reservation");
    };
    let GatewayAdmission::Queued(second) = environment
        .manager
        .admit_public("secret", request('2', 10, 10, None, 1_000))
        .expect("second")
    else {
        panic!("second queue");
    };
    let GatewayAdmission::Queued(third) = environment
        .manager
        .admit_public("secret", request('3', 10, 10, None, 1_000))
        .expect("third")
    else {
        panic!("third queue");
    };
    assert_eq!(
        environment.manager.poll_queue(&third).expect("third poll"),
        GatewayQueueStatus::Waiting
    );
    environment.manager.cancel(first).expect("cancel first");
    let GatewayQueueStatus::Admitted(second_reservation) = environment
        .manager
        .poll_queue(&second)
        .expect("second poll")
    else {
        panic!("second reservation");
    };
    assert_eq!(
        environment.manager.poll_queue(&third).expect("third waits"),
        GatewayQueueStatus::Waiting
    );
    environment
        .manager
        .cancel(second_reservation)
        .expect("cancel second");
    let GatewayQueueStatus::Admitted(third_reservation) =
        environment.manager.poll_queue(&third).expect("third poll")
    else {
        panic!("third reservation");
    };
    environment
        .manager
        .cancel(third_reservation)
        .expect("cancel third");
    assert_eq!(environment.manager.counts().expect("counts"), (0, 0));
}

// Expires one queue entry and releases its concurrency/token reservations exactly once.
#[test]
fn queue_expiry_releases_live_policy_reservations() {
    let environment = environment(
        main_mode(),
        limits(None, Some(100), Some(2), None),
        vec![local_route('3', '1', 1)],
    );
    let GatewayAdmission::Admitted(first) = environment
        .manager
        .admit_public("secret", request('1', 10, 10, None, 0))
        .expect("first")
    else {
        panic!("first reservation");
    };
    let GatewayAdmission::Queued(second) = environment
        .manager
        .admit_public("secret", request('2', 10, 10, None, 100))
        .expect("second")
    else {
        panic!("second queue");
    };
    environment.clock.advance(101);
    assert_eq!(
        environment.manager.poll_queue(&second),
        Err(GatewayError::QueueExpired)
    );
    environment.manager.cancel(first).expect("cancel first");
    assert!(matches!(
        environment
            .manager
            .admit_public("secret", request('3', 10, 10, None, 0)),
        Ok(GatewayAdmission::Admitted(_))
    ));
}

// Rejects duplicate request identities in both active and queued state.
#[test]
fn duplicate_request_identity_never_acquires_second_capacity() {
    let environment = environment(
        main_mode(),
        limits(None, None, None, None),
        vec![local_route('3', '1', 1)],
    );
    let first_request = request('1', 10, 10, None, 0);
    let GatewayAdmission::Admitted(first) = environment
        .manager
        .admit_public("secret", first_request.clone())
        .expect("first")
    else {
        panic!("first reservation");
    };
    assert_eq!(
        environment.manager.admit_public("secret", first_request),
        Err(GatewayError::DuplicateRequest)
    );
    let queued_request = request('2', 10, 10, None, 1_000);
    let GatewayAdmission::Queued(queued) = environment
        .manager
        .admit_public("secret", queued_request.clone())
        .expect("queued")
    else {
        panic!("queue ticket");
    };
    assert_eq!(
        environment.manager.admit_public("secret", queued_request),
        Err(GatewayError::DuplicateRequest)
    );
    environment
        .manager
        .cancel_queue(queued)
        .expect("cancel queue");
    environment.manager.cancel(first).expect("cancel active");
}

// Reconstructs the one-minute rate window once and expires it with injected time.
#[test]
fn durable_usage_reconstructs_once_after_gateway_restart() {
    let environment = environment(
        main_mode(),
        limits(Some(1), None, None, None),
        vec![local_route('3', '1', 2)],
    );
    environment.usage.records.lock().expect("records").push(
        GatewayUsageRecord::new(
            digest('1'),
            api_key_id('a'),
            UnixMilliseconds::new(99_000),
            UnixMilliseconds::new(99_500),
            20,
        )
        .expect("usage"),
    );
    assert_eq!(
        environment
            .manager
            .admit_public("secret", request('1', 10, 10, None, 0)),
        Err(GatewayError::RequestRateLimit)
    );
    assert_eq!(environment.usage.recent_calls.load(Ordering::SeqCst), 1);
    environment.clock.advance(60_001);
    assert!(matches!(
        environment
            .manager
            .admit_public("secret", request('2', 10, 10, None, 0)),
        Ok(GatewayAdmission::Admitted(_))
    ));
    assert_eq!(environment.usage.recent_calls.load(Ordering::SeqCst), 1);
}

// Rejects foreign or future usage-store records without partially loading policy state.
#[test]
fn corrupt_usage_snapshot_fails_closed_without_live_reservations() {
    let environment = environment(
        main_mode(),
        limits(None, None, None, None),
        vec![local_route('3', '1', 1)],
    );
    environment.usage.records.lock().expect("records").push(
        GatewayUsageRecord::new(
            digest('2'),
            api_key_id('b'),
            UnixMilliseconds::new(99_000),
            UnixMilliseconds::new(99_500),
            20,
        )
        .expect("usage"),
    );
    environment
        .usage
        .return_foreign
        .store(true, Ordering::SeqCst);
    assert!(matches!(
        environment
            .manager
            .admit_public("secret", request('1', 10, 10, None, 0)),
        Err(GatewayError::InvalidContract { .. })
    ));
    assert_eq!(environment.manager.counts().expect("counts"), (0, 0));
}

// Propagates every external provider failure without leaking active reservations.
#[test]
fn provider_failure_matrix_is_deterministic_and_cleanup_safe() {
    let authentication = environment(
        main_mode(),
        limits(None, None, None, None),
        vec![local_route('3', '1', 1)],
    );
    authentication
        .authentication
        .fail
        .store(true, Ordering::SeqCst);
    assert_eq!(
        authentication
            .manager
            .admit_public("secret", request('1', 10, 10, None, 0)),
        Err(GatewayError::AuthenticationDenied)
    );

    let routes = environment(
        main_mode(),
        limits(None, None, None, None),
        vec![local_route('3', '1', 1)],
    );
    routes.routes.fail.store(true, Ordering::SeqCst);
    assert!(matches!(
        routes
            .manager
            .admit_public("secret", request('2', 10, 10, None, 0)),
        Err(GatewayError::Provider {
            capability: "routes",
            ..
        })
    ));

    let clock = environment(
        main_mode(),
        limits(None, None, None, None),
        vec![local_route('3', '1', 1)],
    );
    clock.clock.fail.store(true, Ordering::SeqCst);
    assert!(matches!(
        clock
            .manager
            .admit_public("secret", request('3', 10, 10, None, 0)),
        Err(GatewayError::Provider {
            capability: "clock",
            ..
        })
    ));

    let usage_read = environment(
        main_mode(),
        limits(None, None, None, None),
        vec![local_route('3', '1', 1)],
    );
    usage_read.usage.fail_recent.store(true, Ordering::SeqCst);
    assert!(matches!(
        usage_read
            .manager
            .admit_public("secret", request('4', 10, 10, None, 0)),
        Err(GatewayError::Provider {
            capability: "usage_read",
            ..
        })
    ));

    let usage_write = environment(
        main_mode(),
        limits(None, None, None, None),
        vec![local_route('3', '1', 1)],
    );
    let GatewayAdmission::Admitted(reservation) = usage_write
        .manager
        .admit_public("secret", request('5', 10, 10, None, 0))
        .expect("admit")
    else {
        panic!("reservation");
    };
    usage_write.usage.fail_record.store(true, Ordering::SeqCst);
    assert!(matches!(
        usage_write.manager.complete(reservation, 10, 5),
        Err(GatewayError::Provider {
            capability: "usage_write",
            ..
        })
    ));
    assert_eq!(usage_write.manager.counts().expect("counts"), (0, 0));
}

// Releases live capacity even when terminal clock or token accounting is invalid.
#[test]
fn completion_validation_failure_never_leaks_reservations() {
    let environment = environment(
        main_mode(),
        limits(None, None, None, None),
        vec![local_route('3', '1', 1)],
    );
    let GatewayAdmission::Admitted(first) = environment
        .manager
        .admit_public("secret", request('1', 10, 10, None, 0))
        .expect("first")
    else {
        panic!("first reservation");
    };
    environment.clock.now.store(99_999, Ordering::SeqCst);
    assert!(matches!(
        environment.manager.complete(first, 10, 5),
        Err(GatewayError::InvalidContract { .. })
    ));
    assert_eq!(environment.manager.counts().expect("counts"), (0, 0));

    environment.clock.now.store(100_000, Ordering::SeqCst);
    let GatewayAdmission::Admitted(second) = environment
        .manager
        .admit_public("secret", request('2', 10, 10, None, 0))
        .expect("second")
    else {
        panic!("second reservation");
    };
    assert!(matches!(
        environment.manager.complete(second, u64::MAX, 1),
        Err(GatewayError::InvalidContract { .. })
    ));
    assert_eq!(environment.manager.counts().expect("counts"), (0, 0));
}

// Retries a pre-output failure on one sibling without repeating auth or quota admission.
#[test]
fn pre_output_retry_moves_to_sibling_without_double_charging() {
    let first_route = route(
        '3',
        '1',
        1,
        1_024,
        Some(40_000),
        Vec::new(),
        true,
        false,
        GatewayRouteTarget::LocalEngine {
            endpoint: EndpointAddress::new(
                EndpointScheme::Https,
                NodeAddress::parse("127.0.0.1").expect("address"),
                18_001,
            )
            .expect("endpoint"),
        },
    );
    let second_route = route(
        '4',
        '2',
        1,
        1_024,
        Some(50_000),
        Vec::new(),
        true,
        false,
        GatewayRouteTarget::ChildRelay {
            address: NodeAddress::parse("child.local").expect("address"),
        },
    );
    let environment = environment(
        main_mode(),
        limits(Some(1), Some(100), Some(1), None),
        vec![first_route, second_route],
    );
    let GatewayAdmission::Admitted(first) = environment
        .manager
        .admit_public("secret", request('1', 20, 20, None, 0))
        .expect("first")
    else {
        panic!("first reservation");
    };
    assert_eq!(first.route().placement_group_id(), &placement_group_id('3'));
    let GatewayAdmission::Admitted(retry) = environment
        .manager
        .retry_before_output(first)
        .expect("retry")
    else {
        panic!("retry reservation");
    };
    assert_eq!(retry.route().placement_group_id(), &placement_group_id('4'));
    assert_eq!(environment.authentication.calls.load(Ordering::SeqCst), 1);
    assert_eq!(environment.usage.recent_calls.load(Ordering::SeqCst), 1);
    environment
        .manager
        .complete(retry, 20, 10)
        .expect("complete retry");
    assert_eq!(environment.manager.counts().expect("counts"), (0, 0));
}

// Releases policy ownership when no sibling can accept a pre-output retry.
#[test]
fn exhausted_pre_output_retry_releases_capacity_and_recovers_after_cooldown() {
    let environment = environment(
        main_mode(),
        limits(None, None, Some(1), None),
        vec![local_route('3', '1', 1)],
    );
    let GatewayAdmission::Admitted(first) = environment
        .manager
        .admit_public("secret", request('1', 10, 10, None, 0))
        .expect("first")
    else {
        panic!("first reservation");
    };
    assert_eq!(
        environment.manager.retry_before_output(first),
        Err(GatewayError::NoRoute)
    );
    assert_eq!(environment.manager.counts().expect("counts"), (0, 0));
    environment.clock.advance(1_001);
    assert!(matches!(
        environment
            .manager
            .admit_public("secret", request('2', 10, 10, None, 0)),
        Ok(GatewayAdmission::Admitted(_))
    ));
}

// Learns successful prefix locality without overriding an exact static prefix claim.
#[test]
fn successful_completion_learns_bounded_prefix_affinity() {
    let prefix = digest('e');
    let first_routes = vec![
        route(
            '3',
            '1',
            2,
            1_024,
            Some(40_000),
            Vec::new(),
            true,
            false,
            GatewayRouteTarget::LocalEngine {
                endpoint: EndpointAddress::new(
                    EndpointScheme::Https,
                    NodeAddress::parse("127.0.0.1").expect("address"),
                    18_001,
                )
                .expect("endpoint"),
            },
        ),
        route(
            '4',
            '2',
            2,
            1_024,
            Some(50_000),
            Vec::new(),
            true,
            false,
            GatewayRouteTarget::ChildRelay {
                address: NodeAddress::parse("child.local").expect("address"),
            },
        ),
    ];
    let environment = environment(main_mode(), limits(None, None, None, None), first_routes);
    let GatewayAdmission::Admitted(first) = environment
        .manager
        .admit_public("secret", request('1', 10, 10, Some(prefix.clone()), 0))
        .expect("first")
    else {
        panic!("first reservation");
    };
    assert_eq!(first.route().placement_group_id(), &placement_group_id('3'));
    environment
        .manager
        .complete(first, 10, 5)
        .expect("complete");
    *environment.routes.routes.lock().expect("routes") = vec![
        route(
            '3',
            '1',
            2,
            1_024,
            Some(90_000),
            Vec::new(),
            true,
            false,
            GatewayRouteTarget::LocalEngine {
                endpoint: EndpointAddress::new(
                    EndpointScheme::Https,
                    NodeAddress::parse("127.0.0.1").expect("address"),
                    18_001,
                )
                .expect("endpoint"),
            },
        ),
        route(
            '4',
            '2',
            2,
            1_024,
            Some(30_000),
            Vec::new(),
            true,
            false,
            GatewayRouteTarget::ChildRelay {
                address: NodeAddress::parse("child.local").expect("address"),
            },
        ),
    ];
    let GatewayAdmission::Admitted(affinity) = environment
        .manager
        .admit_public("secret", request('2', 10, 10, Some(prefix), 0))
        .expect("affinity")
    else {
        panic!("affinity reservation");
    };
    assert_eq!(
        affinity.route().placement_group_id(),
        &placement_group_id('3')
    );
    let GatewayAdmission::Admitted(cooler) = environment
        .manager
        .admit_public("secret", request('3', 10, 10, Some(digest('f')), 0))
        .expect("cooler")
    else {
        panic!("cooler reservation");
    };
    assert_eq!(
        cooler.route().placement_group_id(),
        &placement_group_id('4')
    );
    environment
        .manager
        .cancel(affinity)
        .expect("cancel affinity");
    environment.manager.cancel(cooler).expect("cancel cooler");
}

// Ends a post-output failure without retrying and cools only its failed route.
#[test]
fn post_output_failure_never_replays_and_cools_failed_route() {
    let routes = vec![
        route(
            '3',
            '1',
            1,
            1_024,
            Some(40_000),
            Vec::new(),
            true,
            false,
            GatewayRouteTarget::LocalEngine {
                endpoint: EndpointAddress::new(
                    EndpointScheme::Https,
                    NodeAddress::parse("127.0.0.1").expect("address"),
                    18_001,
                )
                .expect("endpoint"),
            },
        ),
        route(
            '4',
            '2',
            1,
            1_024,
            Some(50_000),
            Vec::new(),
            true,
            false,
            GatewayRouteTarget::ChildRelay {
                address: NodeAddress::parse("child.local").expect("address"),
            },
        ),
    ];
    let environment = environment(main_mode(), limits(None, None, None, None), routes);
    let GatewayAdmission::Admitted(first) = environment
        .manager
        .admit_public("secret", request('1', 10, 10, None, 0))
        .expect("first")
    else {
        panic!("first reservation");
    };
    assert_eq!(first.route().placement_group_id(), &placement_group_id('3'));
    environment
        .manager
        .fail_after_output(first)
        .expect("failed output");
    assert_eq!(environment.manager.counts().expect("counts"), (0, 0));
    let GatewayAdmission::Admitted(second) = environment
        .manager
        .admit_public("secret", request('2', 10, 10, None, 0))
        .expect("second")
    else {
        panic!("second reservation");
    };
    assert_eq!(
        second.route().placement_group_id(),
        &placement_group_id('4')
    );
    environment.manager.cancel(second).expect("cancel");
}

// Serializes concurrent capacity admission so exactly one request owns the route.
#[test]
fn concurrent_admission_has_one_capacity_winner() {
    let environment = environment(
        main_mode(),
        limits(None, None, None, None),
        vec![local_route('3', '1', 1)],
    );
    let mut workers = Vec::new();
    for character in ['1', '2'] {
        let manager = Arc::clone(&environment.manager);
        workers.push(thread::spawn(move || {
            manager.admit_public("secret", request(character, 10, 10, None, 0))
        }));
    }
    let results = workers
        .into_iter()
        .map(|worker| worker.join().expect("worker"))
        .collect::<Vec<_>>();
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Ok(GatewayAdmission::Admitted(_))))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| result == &&Err(GatewayError::CapacityUnavailable))
            .count(),
        1
    );
    assert_eq!(environment.manager.counts().expect("counts"), (1, 0));
}

// Rejects unsafe mode, request, prefix, and temperature construction boundaries.
#[test]
fn constructor_validation_matrix_rejects_unsafe_contracts() {
    let authentication = Arc::new(AuthenticationMock {
        principal: GatewayPrincipal::new(api_key_id('a'), limits(None, None, None, None)),
        calls: AtomicUsize::new(0),
        fail: AtomicBool::new(false),
    });
    let relay = Arc::new(RelayAuthorizationMock {
        node_id: Mutex::new(node_id('1')),
        calls: AtomicUsize::new(0),
        fail: AtomicBool::new(false),
    });
    let routes = Arc::new(RouteMock {
        routes: Mutex::new(Vec::new()),
        calls: AtomicUsize::new(0),
        fail: AtomicBool::new(false),
    });
    let clock = Arc::new(TestClock {
        now: AtomicU64::new(0),
        fail: AtomicBool::new(false),
    });
    assert!(GatewayManager::new(
        GatewayMode::Child {
            local_node_id: node_id('1'),
            main_node_id: node_id('1'),
        },
        authentication,
        relay,
        routes,
        Arc::new(li_gateway_manager::UnavailableGatewayProtectionLeaseProvider),
        clock,
        Arc::new(UsageMock::default()),
    )
    .is_err());
    assert!(GatewayRequest::new(
        digest('1'),
        model(),
        NonZeroU64::new(1).expect("one"),
        NonZeroU64::new(1).expect("one"),
        None,
        300_001,
    )
    .is_err());
    assert!(GatewayRoute::new(
        placement_group_id('3'),
        node_id('1'),
        model(),
        GatewayRouteTarget::ChildRelay {
            address: NodeAddress::parse("child.local").expect("address"),
        },
        NonZeroU32::new(1).expect("one"),
        NonZeroU64::new(100).expect("context"),
        true,
        false,
        Some(250_001),
        vec![digest('e'), digest('e')],
    )
    .is_err());
}
