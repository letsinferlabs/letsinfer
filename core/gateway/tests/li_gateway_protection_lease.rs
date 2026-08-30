// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::num::{NonZeroU32, NonZeroU64};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

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
    GatewayRelayAuthorizationProvider, GatewayRequest, GatewayRoute, GatewayRouteProvider,
    GatewayRouteTarget, GatewayUsageRecord, GatewayUsageStore,
};

// Supplies deterministic mutable time to freshness and delayed-read tests.
struct ClockMock(AtomicU64);

impl GatewayClock for ClockMock {
    // Returns the exact test-controlled Unix time.
    fn now(&self) -> Result<UnixMilliseconds, GatewayError> {
        Ok(UnixMilliseconds::new(self.0.load(Ordering::SeqCst)))
    }
}

// Returns one unrestricted public principal without retaining bearer material.
struct AuthenticationMock;

impl GatewayAuthenticationProvider for AuthenticationMock {
    // Authenticates every fixture bearer to the same bounded principal.
    fn authenticate(
        &self,
        _bearer_token: &str,
        _model: &LogicalModelName,
    ) -> Result<GatewayPrincipal, GatewayError> {
        Ok(GatewayPrincipal::new(
            ApiKeyId::parse(&identity('a', 32)).expect("key"),
            ApiKeyLimits::new(None, None, None, None),
        ))
    }
}

// Authorizes the exact main identity used by child-relay fixtures.
struct RelayMock;

impl GatewayRelayAuthorizationProvider for RelayMock {
    // Returns the fixed main Node identity.
    fn authorize(&self, _relay_credential: &str) -> Result<NodeId, GatewayError> {
        Ok(node_id('1'))
    }
}

// Supplies one immutable route set to each test manager.
struct RoutesMock(Vec<GatewayRoute>);

impl GatewayRouteProvider for RoutesMock {
    // Returns every fixture route for the one fixture model.
    fn routes(&self, _model: &LogicalModelName) -> Result<Vec<GatewayRoute>, GatewayError> {
        Ok(self.0.clone())
    }
}

// Stores mutable snapshots and can advance time during the provider call.
struct ProtectionMock {
    snapshots: Mutex<BTreeMap<PlacementGroupId, Option<GatewayPlacementProtectionSnapshot>>>,
    clock: Arc<ClockMock>,
    advance_during_read: AtomicU64,
}

impl ProtectionMock {
    // Replaces one route snapshot without changing any other replica.
    fn set(
        &self,
        placement_group_id: PlacementGroupId,
        snapshot: Option<GatewayPlacementProtectionSnapshot>,
    ) {
        self.snapshots
            .lock()
            .expect("snapshots")
            .insert(placement_group_id, snapshot);
    }
}

impl GatewayProtectionLeaseProvider for ProtectionMock {
    // Returns the selected Node-owned snapshot after one injected read delay.
    fn snapshot(
        &self,
        route: &GatewayRoute,
    ) -> Result<Option<GatewayPlacementProtectionSnapshot>, GatewayError> {
        self.clock.0.fetch_add(
            self.advance_during_read.load(Ordering::SeqCst),
            Ordering::SeqCst,
        );
        Ok(self
            .snapshots
            .lock()
            .expect("snapshots")
            .get(route.placement_group_id())
            .cloned()
            .flatten())
    }
}

// Accepts unreachable usage writes without durable side effects.
struct UsageMock;

impl GatewayUsageStore for UsageMock {
    // Returns no prior usage for a fresh fixture principal.
    fn recent(
        &self,
        _key_id: &ApiKeyId,
        _since: UnixMilliseconds,
    ) -> Result<Vec<GatewayUsageRecord>, GatewayError> {
        Ok(Vec::new())
    }

    // Accepts one completed record without retaining it.
    fn record(&self, _usage: &GatewayUsageRecord) -> Result<(), GatewayError> {
        Ok(())
    }
}

// Returns one repeated canonical identity.
fn identity(character: char, length: usize) -> String {
    character.to_string().repeat(length)
}

// Returns one canonical Node identity.
fn node_id(character: char) -> NodeId {
    NodeId::parse(&identity(character, 32)).expect("node")
}

// Returns one canonical placement-group identity.
fn group_id(character: char) -> PlacementGroupId {
    PlacementGroupId::parse(&identity(character, 32)).expect("group")
}

// Returns one canonical placement identity.
fn placement_id(character: char) -> PlacementId {
    PlacementId::parse(&identity(character, 32)).expect("placement")
}

// Returns one canonical SHA-256 identity.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&identity(character, 64)).expect("digest")
}

// Returns the one logical model selected by all protection fixtures.
fn model() -> LogicalModelName {
    LogicalModelName::parse("model-a").expect("model")
}

// Creates one healthy local route with exact capacity.
fn route(group: char, node: char, capacity: u32) -> GatewayRoute {
    GatewayRoute::new(
        group_id(group),
        node_id(node),
        model(),
        GatewayRouteTarget::LocalEngine {
            endpoint: EndpointAddress::new(
                EndpointScheme::Http,
                NodeAddress::parse("127.0.0.1").expect("address"),
                8_000 + u16::from(group as u8),
            )
            .expect("endpoint"),
        },
        NonZeroU32::new(capacity).expect("capacity"),
        NonZeroU64::new(8_192).expect("context"),
        true,
        false,
        None,
        Vec::new(),
    )
    .expect("route")
}

// Creates one complete candidate lease with explicit safety and clock fields.
#[allow(clippy::too_many_arguments)]
fn lease(
    group: char,
    placement: char,
    node: char,
    session: char,
    session_generation: u64,
    sample_sequence: u64,
    observed_at: u64,
    expires_at: u64,
    armed: bool,
    trip_latched: bool,
    cgroup: &str,
) -> Result<GatewayPlacementProtectionLease, GatewayError> {
    GatewayPlacementProtectionLease::new(
        node_id(node),
        group_id(group),
        placement_id(placement),
        InstallationId::parse(&identity(node, 64)).expect("Core installation"),
        digest('f'),
        digest(session),
        NonZeroU64::new(session_generation).expect("session generation"),
        &identity('e', 32),
        TechnicalName::parse(&format!("li_placement_{placement}")).expect("container"),
        digest('d'),
        42,
        84,
        BootId::parse("12345678-1234-1234-1234-123456789abc").expect("boot"),
        cgroup,
        NonZeroU64::new(sample_sequence).expect("sample sequence"),
        UnixMilliseconds::new(observed_at),
        observed_at.max(1),
        UnixMilliseconds::new(expires_at),
        armed,
        trip_latched,
    )
}

// Creates one authority for an exact Node and monotonic resident session.
fn authority(node: char, session: char, generation: u64) -> GatewayProtectionAuthority {
    GatewayProtectionAuthority::new(
        node_id(node),
        InstallationId::parse(&identity(node, 64)).expect("Core installation"),
        digest('f'),
        digest(session),
        NonZeroU64::new(generation).expect("session generation"),
    )
}

// Creates one snapshot from explicit placement ownership and candidate leases.
fn snapshot(
    group: char,
    expected: &[(char, char)],
    authorities: &[(char, char, u64)],
    leases: Vec<GatewayPlacementProtectionLease>,
) -> GatewayPlacementProtectionSnapshot {
    GatewayPlacementProtectionSnapshot::new(
        group_id(group),
        expected
            .iter()
            .map(|(placement, node)| (placement_id(*placement), node_id(*node)))
            .collect(),
        authorities
            .iter()
            .map(|(node, session, generation)| authority(*node, *session, *generation))
            .collect(),
        leases,
    )
    .expect("snapshot")
}

// Creates one Gateway and mutable protection provider at an exact time.
fn manager(
    mode: GatewayMode,
    routes: Vec<GatewayRoute>,
    now: u64,
) -> (Arc<GatewayManager>, Arc<ProtectionMock>, Arc<ClockMock>) {
    let clock = Arc::new(ClockMock(AtomicU64::new(now)));
    let protection = Arc::new(ProtectionMock {
        snapshots: Mutex::new(BTreeMap::new()),
        clock: clock.clone(),
        advance_during_read: AtomicU64::new(0),
    });
    let manager = Arc::new(
        GatewayManager::new(
            mode,
            Arc::new(AuthenticationMock),
            Arc::new(RelayMock),
            Arc::new(RoutesMock(routes)),
            protection.clone(),
            clock.clone(),
            Arc::new(UsageMock),
        )
        .expect("manager"),
    );
    (manager, protection, clock)
}

// Creates one bounded request with a selected queue policy.
fn request(character: char, queue_milliseconds: u64) -> GatewayRequest {
    GatewayRequest::new(
        digest(character),
        model(),
        NonZeroU64::new(128).expect("context"),
        NonZeroU64::new(32).expect("output"),
        None,
        queue_milliseconds,
    )
    .expect("request")
}

// Proves malformed clocks, generations, process facts, and cgroups fail construction.
#[test]
fn lease_contract_rejects_noncanonical_process_and_time_matrix() {
    for cgroup in [
        "/sys/fs/cgroup//li",
        "/sys/fs/cgroup/./li",
        "/sys/fs/cgroup/a/../li",
        "/sys/fs/cgroup/li/",
    ] {
        assert!(lease('1', 'a', '1', 'a', 1, 1, 100, 200, true, false, cgroup).is_err());
    }
    assert!(lease(
        '1',
        'a',
        '1',
        'a',
        1,
        1,
        100,
        100,
        true,
        false,
        "/sys/fs/cgroup/li"
    )
    .is_err());
    assert!(lease(
        '1',
        'a',
        '1',
        'a',
        1,
        1,
        100,
        60_101,
        true,
        false,
        "/sys/fs/cgroup/li"
    )
    .is_err());
}

// Proves every admission/read/selection path closes when no current lease exists.
#[test]
fn missing_lease_closes_public_relay_read_token_count_and_queued_polling() {
    let local_route = route('1', '1', 1);
    let (main, protection, _) = manager(
        GatewayMode::Main {
            local_node_id: node_id('1'),
        },
        vec![local_route.clone()],
        1_000,
    );
    assert_eq!(
        main.admit_public("bearer", request('1', 0)),
        Err(GatewayError::NoRoute)
    );
    assert!(!main
        .public_model_is_available(&model())
        .expect("availability"));
    assert!(main
        .token_count_routes(&model())
        .expect("token routes")
        .is_empty());

    protection.set(
        group_id('1'),
        Some(snapshot(
            '1',
            &[('a', '1')],
            &[('1', 'a', 1)],
            vec![lease(
                '1',
                'a',
                '1',
                'a',
                1,
                1,
                1_000,
                2_000,
                true,
                false,
                "/sys/fs/cgroup/li",
            )
            .expect("lease")],
        )),
    );
    let active = match main
        .admit_public("bearer", request('2', 0))
        .expect("first admission")
    {
        GatewayAdmission::Admitted(reservation) => reservation,
        GatewayAdmission::Queued(_) => panic!("first request queued"),
    };
    let ticket = match main
        .admit_public("bearer", request('3', 1_000))
        .expect("queued admission")
    {
        GatewayAdmission::Queued(ticket) => ticket,
        GatewayAdmission::Admitted(_) => panic!("second request admitted"),
    };
    protection.set(group_id('1'), None);
    assert_eq!(main.poll_queue(&ticket), Err(GatewayError::NoRoute));
    main.cancel_queue(ticket).expect("cancel queue");
    main.complete(active, 1, 1).expect("complete active");

    let child_route = route('2', '2', 1);
    let (child, _, _) = manager(
        GatewayMode::Child {
            local_node_id: node_id('2'),
            main_node_id: node_id('1'),
        },
        vec![child_route],
        1_000,
    );
    assert_eq!(
        child.admit_relay("relay", request('4', 0)),
        Err(GatewayError::NoRoute)
    );
    assert!(child
        .token_count_routes(&model())
        .expect("token routes")
        .is_empty());
}

// Proves stale, future, tripped, disarmed, missing, and identity-mismatched leases never route.
#[test]
fn lease_judgment_matrix_fails_closed() {
    let (manager, protection, _) = manager(
        GatewayMode::Main {
            local_node_id: node_id('1'),
        },
        vec![route('1', '1', 1)],
        1_000,
    );
    let candidates = [
        lease(
            '1',
            'a',
            '1',
            'a',
            1,
            1,
            800,
            1_000,
            true,
            false,
            "/sys/fs/cgroup/li",
        )
        .expect("stale"),
        lease(
            '1',
            'a',
            '1',
            'a',
            1,
            1,
            1_001,
            1_100,
            true,
            false,
            "/sys/fs/cgroup/li",
        )
        .expect("future"),
        lease(
            '1',
            'a',
            '1',
            'a',
            1,
            1,
            900,
            1_100,
            true,
            true,
            "/sys/fs/cgroup/li",
        )
        .expect("tripped"),
        lease(
            '1',
            'a',
            '1',
            'a',
            1,
            1,
            900,
            1_100,
            false,
            false,
            "/sys/fs/cgroup/li",
        )
        .expect("disarmed"),
        lease(
            '2',
            'a',
            '1',
            'a',
            1,
            1,
            900,
            1_100,
            true,
            false,
            "/sys/fs/cgroup/li",
        )
        .expect("foreign group"),
    ];
    for candidate in candidates {
        protection.set(
            group_id('1'),
            Some(snapshot(
                '1',
                &[('a', '1')],
                &[('1', 'a', 1)],
                vec![candidate],
            )),
        );
        assert!(manager
            .token_count_routes(&model())
            .expect("routes")
            .is_empty());
    }
    protection.set(
        group_id('1'),
        Some(snapshot('1', &[('a', '1')], &[('1', 'a', 1)], Vec::new())),
    );
    assert!(manager
        .token_count_routes(&model())
        .expect("routes")
        .is_empty());
}

// Proves provider delay cannot use a lease that expires during snapshot acquisition.
#[test]
fn freshness_clock_is_sampled_after_snapshot_read() {
    let (manager, protection, clock) = manager(
        GatewayMode::Main {
            local_node_id: node_id('1'),
        },
        vec![route('1', '1', 1)],
        1_000,
    );
    protection.set(
        group_id('1'),
        Some(snapshot(
            '1',
            &[('a', '1')],
            &[('1', 'a', 1)],
            vec![lease(
                '1',
                'a',
                '1',
                'a',
                1,
                1,
                1_000,
                1_005,
                true,
                false,
                "/sys/fs/cgroup/li",
            )
            .expect("lease")],
        )),
    );
    protection.advance_during_read.store(10, Ordering::SeqCst);
    assert!(manager
        .token_count_routes(&model())
        .expect("routes")
        .is_empty());
    assert_eq!(clock.0.load(Ordering::SeqCst), 1_010);
}

// Proves session generations prevent same-generation substitution and A-B-A replay.
#[test]
fn monotonic_session_generation_rejects_substitution_and_replay() {
    let (manager, protection, _) = manager(
        GatewayMode::Main {
            local_node_id: node_id('1'),
        },
        vec![route('1', '1', 1)],
        1_000,
    );
    let set = |session: char, generation: u64, sequence: u64| {
        protection.set(
            group_id('1'),
            Some(snapshot(
                '1',
                &[('a', '1')],
                &[('1', session, generation)],
                vec![lease(
                    '1',
                    'a',
                    '1',
                    session,
                    generation,
                    sequence,
                    900,
                    1_100,
                    true,
                    false,
                    "/sys/fs/cgroup/li",
                )
                .expect("lease")],
            )),
        );
    };
    set('a', 1, 10);
    assert_eq!(
        manager.token_count_routes(&model()).expect("routes").len(),
        1
    );
    set('b', 1, 11);
    assert!(manager
        .token_count_routes(&model())
        .expect("routes")
        .is_empty());
    set('a', 2, 1);
    assert!(manager
        .token_count_routes(&model())
        .expect("routes")
        .is_empty());
    set('b', 2, 1);
    assert_eq!(
        manager.token_count_routes(&model()).expect("routes").len(),
        1
    );
    set('a', 1, 12);
    assert!(manager
        .token_count_routes(&model())
        .expect("routes")
        .is_empty());
}

// Proves sample sequence, observation time, and same-sequence content cannot regress.
#[test]
fn lease_sample_high_water_rejects_sequence_time_and_content_regression() {
    let (manager, protection, _) = manager(
        GatewayMode::Main {
            local_node_id: node_id('1'),
        },
        vec![route('1', '1', 1)],
        1_000,
    );
    let set = |sequence: u64, observed_at: u64, expires_at: u64| {
        protection.set(
            group_id('1'),
            Some(snapshot(
                '1',
                &[('a', '1')],
                &[('1', 'a', 1)],
                vec![lease(
                    '1',
                    'a',
                    '1',
                    'a',
                    1,
                    sequence,
                    observed_at,
                    expires_at,
                    true,
                    false,
                    "/sys/fs/cgroup/li",
                )
                .expect("lease")],
            )),
        );
    };
    set(10, 900, 1_100);
    assert_eq!(
        manager.token_count_routes(&model()).expect("routes").len(),
        1
    );
    set(9, 901, 1_100);
    assert!(manager
        .token_count_routes(&model())
        .expect("routes")
        .is_empty());
    set(11, 899, 1_100);
    assert!(manager
        .token_count_routes(&model())
        .expect("routes")
        .is_empty());
    set(10, 900, 1_101);
    assert!(manager
        .token_count_routes(&model())
        .expect("routes")
        .is_empty());
    set(10, 900, 1_100);
    assert_eq!(
        manager.token_count_routes(&model()).expect("routes").len(),
        1
    );
}

// Proves authority and expected-placement substitutions fail independently.
#[test]
fn snapshot_identity_mutation_matrix_fails_closed() {
    let (manager, protection, _) = manager(
        GatewayMode::Main {
            local_node_id: node_id('1'),
        },
        vec![route('1', '1', 1)],
        1_000,
    );
    let valid_lease = lease(
        '1',
        'a',
        '1',
        'a',
        1,
        1,
        900,
        1_100,
        true,
        false,
        "/sys/fs/cgroup/li",
    )
    .expect("lease");
    let mutations = [
        snapshot(
            '1',
            &[('b', '1')],
            &[('1', 'a', 1)],
            vec![valid_lease.clone()],
        ),
        snapshot(
            '1',
            &[('a', '2')],
            &[('2', 'a', 1)],
            vec![valid_lease.clone()],
        ),
        snapshot(
            '1',
            &[('a', '1')],
            &[('1', 'b', 1)],
            vec![valid_lease.clone()],
        ),
        snapshot(
            '1',
            &[('a', '1')],
            &[('1', 'a', 2)],
            vec![valid_lease.clone()],
        ),
        GatewayPlacementProtectionSnapshot::new(
            group_id('1'),
            vec![(placement_id('a'), node_id('1'))],
            vec![GatewayProtectionAuthority::new(
                node_id('1'),
                InstallationId::parse(&identity('2', 64)).expect("foreign Core"),
                digest('f'),
                digest('a'),
                NonZeroU64::new(1).expect("generation"),
            )],
            vec![valid_lease.clone()],
        )
        .expect("snapshot"),
        GatewayPlacementProtectionSnapshot::new(
            group_id('1'),
            vec![(placement_id('a'), node_id('1'))],
            vec![GatewayProtectionAuthority::new(
                node_id('1'),
                InstallationId::parse(&identity('1', 64)).expect("Core"),
                digest('e'),
                digest('a'),
                NonZeroU64::new(1).expect("generation"),
            )],
            vec![valid_lease],
        )
        .expect("snapshot"),
    ];
    for mutation in mutations {
        protection.set(group_id('1'), Some(mutation));
        assert!(manager
            .token_count_routes(&model())
            .expect("routes")
            .is_empty());
    }
}

// Proves one unsafe multi-placement group is removed while a sibling replica remains eligible.
#[test]
fn complete_group_gate_preserves_safe_sibling_replica_across_nodes() {
    let (manager, protection, _) = manager(
        GatewayMode::Main {
            local_node_id: node_id('1'),
        },
        vec![route('1', '1', 1), route('2', '2', 1)],
        1_000,
    );
    protection.set(
        group_id('1'),
        Some(snapshot(
            '1',
            &[('a', '1'), ('b', '2')],
            &[('1', 'a', 1), ('2', 'b', 1)],
            vec![lease(
                '1',
                'a',
                '1',
                'a',
                1,
                1,
                900,
                1_100,
                true,
                false,
                "/sys/fs/cgroup/li_a",
            )
            .expect("lease")],
        )),
    );
    protection.set(
        group_id('2'),
        Some(snapshot(
            '2',
            &[('c', '2')],
            &[('2', 'b', 1)],
            vec![lease(
                '2',
                'c',
                '2',
                'b',
                1,
                1,
                900,
                1_100,
                true,
                false,
                "/sys/fs/cgroup/li_c",
            )
            .expect("lease")],
        )),
    );
    let routes = manager.token_count_routes(&model()).expect("routes");
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].placement_group_id(), &group_id('2'));
    let admission = manager
        .admit_public("bearer", request('9', 0))
        .expect("safe sibling admission");
    let GatewayAdmission::Admitted(reservation) = admission else {
        panic!("safe sibling queued");
    };
    assert_eq!(reservation.route().placement_group_id(), &group_id('2'));
}
