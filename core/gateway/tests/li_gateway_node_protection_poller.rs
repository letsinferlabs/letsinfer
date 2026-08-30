// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::VecDeque;
use std::num::{NonZeroU32, NonZeroU64};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use li_core_interface::{
    BootId, EndpointAddress, EndpointScheme, InstallationId, LogicalModelName, NodeAddress, NodeId,
    PlacementGroupId, PlacementId, Sha256Digest, TechnicalName, UnixMilliseconds,
};
use li_gateway_manager::{
    GatewayError, GatewayNodeProtectionPoller, GatewayPlacementProtectionLease,
    GatewayPlacementProtectionSnapshot, GatewayProtectionAuthority, GatewayProtectionCachePolicy,
    GatewayProtectionLeaseProvider, GatewayProtectionMonotonicClock, GatewayProtectionPollResponse,
    GatewayProtectionSnapshotClient, GatewayRoute, GatewayRouteTarget,
};

// Supplies mutable deterministic process-local monotonic time.
struct ClockMock(AtomicU64);

impl ClockMock {
    // Replaces the next observed monotonic timestamp.
    fn set(&self, value: u64) {
        self.0.store(value, Ordering::Release);
    }
}

impl GatewayProtectionMonotonicClock for ClockMock {
    // Returns the configured boot-scoped timestamp.
    fn now_milliseconds(&self) -> Result<u64, GatewayError> {
        Ok(self.0.load(Ordering::Acquire))
    }
}

// Supplies queued authenticated Node responses and failures.
struct ClientMock(Mutex<VecDeque<Result<GatewayProtectionPollResponse, GatewayError>>>);

impl ClientMock {
    // Creates one client from exact response order.
    fn new(responses: Vec<Result<GatewayProtectionPollResponse, GatewayError>>) -> Self {
        Self(Mutex::new(responses.into()))
    }
}

impl GatewayProtectionSnapshotClient for ClientMock {
    // Returns the next exact response or rejects an unexpected poll.
    fn poll(
        &self,
        _connection_id: &Sha256Digest,
        _route: &GatewayRoute,
    ) -> Result<GatewayProtectionPollResponse, GatewayError> {
        self.0
            .lock()
            .expect("responses")
            .pop_front()
            .expect("expected poll")
    }
}

// Returns one repeated lowercase hexadecimal identity.
fn identity(character: char, length: usize) -> String {
    character.to_string().repeat(length)
}

// Returns one canonical SHA-256 identity.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&identity(character, 64)).expect("digest")
}

// Returns one canonical Node identity.
fn node_id() -> NodeId {
    NodeId::parse(&identity('1', 32)).expect("node")
}

// Returns one canonical placement-group identity.
fn group_id() -> PlacementGroupId {
    PlacementGroupId::parse(&identity('2', 32)).expect("group")
}

// Returns one canonical placement identity.
fn placement_id() -> PlacementId {
    PlacementId::parse(&identity('3', 32)).expect("placement")
}

// Returns the exact route selected by every poller fixture.
fn route() -> GatewayRoute {
    GatewayRoute::new(
        group_id(),
        node_id(),
        LogicalModelName::parse("example_model").expect("model"),
        GatewayRouteTarget::LocalEngine {
            endpoint: EndpointAddress::new(
                EndpointScheme::Http,
                NodeAddress::parse("127.0.0.1").expect("address"),
                9_000,
            )
            .expect("endpoint"),
        },
        NonZeroU32::new(2).expect("capacity"),
        NonZeroU64::new(4_096).expect("context"),
        true,
        false,
        Some(50_000),
        Vec::new(),
    )
    .expect("route")
}

// Returns one complete identity-bound Node snapshot.
fn snapshot(sample_sequence: u64) -> GatewayPlacementProtectionSnapshot {
    let authority = GatewayProtectionAuthority::new(
        node_id(),
        InstallationId::parse(&identity('4', 64)).expect("installation"),
        digest('5'),
        digest('6'),
        NonZeroU64::new(1).expect("generation"),
    );
    let lease = GatewayPlacementProtectionLease::new(
        node_id(),
        group_id(),
        placement_id(),
        authority.core_installation_id().clone(),
        authority.watchdog_source_identity().clone(),
        authority.watchdog_session_id().clone(),
        authority.watchdog_session_generation(),
        &identity('7', 32),
        TechnicalName::parse("li_engine").expect("container"),
        digest('8'),
        1234,
        5678,
        BootId::parse("12345678-1234-1234-1234-123456789abc").expect("boot"),
        "/sys/fs/cgroup/user.slice/li_engine",
        NonZeroU64::new(sample_sequence).expect("sample"),
        UnixMilliseconds::new(1_000),
        sample_sequence,
        UnixMilliseconds::new(60_000),
        true,
        false,
    )
    .expect("lease");
    GatewayPlacementProtectionSnapshot::new(
        group_id(),
        vec![(placement_id(), node_id())],
        vec![authority],
        vec![lease],
    )
    .expect("snapshot")
}

// Returns one authenticated response for the ordinary connection.
fn response(sequence: u64, sample_sequence: u64) -> GatewayProtectionPollResponse {
    GatewayProtectionPollResponse::new(
        digest('9'),
        NonZeroU64::new(sequence).expect("sequence"),
        Some(snapshot(sample_sequence)),
    )
}

// Proves disconnect invalidates a previously admissible snapshot immediately.
#[test]
fn disconnect_invalidates_every_cached_snapshot_immediately() {
    let clock = Arc::new(ClockMock(AtomicU64::new(100)));
    let poller = GatewayNodeProtectionPoller::new(
        Arc::new(ClientMock::new(vec![Ok(response(1, 1))])),
        clock,
        GatewayProtectionCachePolicy::new(1_000).expect("cache policy"),
    )
    .expect("poller");
    assert!(poller.snapshot(&route()).expect("closed").is_none());

    poller.connection_did_open(digest('9')).expect("connection");
    poller.poll(&route()).expect("poll");
    assert!(poller.snapshot(&route()).expect("snapshot").is_some());
    poller
        .connection_did_close(&digest('9'))
        .expect("disconnect");
    assert!(poller.snapshot(&route()).expect("closed").is_none());
}

// Proves repeated static Node data cannot refresh local age during a wall-clock rollback.
#[test]
fn unchanged_snapshot_expires_by_local_monotonic_age() {
    let clock = Arc::new(ClockMock(AtomicU64::new(100)));
    let poller = GatewayNodeProtectionPoller::new(
        Arc::new(ClientMock::new(vec![
            Ok(response(1, 1)),
            Ok(response(2, 1)),
        ])),
        clock.clone(),
        GatewayProtectionCachePolicy::new(100).expect("cache policy"),
    )
    .expect("poller");
    poller.connection_did_open(digest('9')).expect("connection");
    poller.poll(&route()).expect("first poll");
    clock.set(150);
    poller.poll(&route()).expect("static replay");
    clock.set(200);

    assert!(poller.snapshot(&route()).expect("expired").is_none());
}

// Proves one new completed cycle refreshes the local monotonic receipt boundary.
#[test]
fn advanced_snapshot_refreshes_local_monotonic_age() {
    let clock = Arc::new(ClockMock(AtomicU64::new(100)));
    let poller = GatewayNodeProtectionPoller::new(
        Arc::new(ClientMock::new(vec![
            Ok(response(1, 1)),
            Ok(response(2, 2)),
        ])),
        clock.clone(),
        GatewayProtectionCachePolicy::new(100).expect("cache policy"),
    )
    .expect("poller");
    poller.connection_did_open(digest('9')).expect("connection");
    poller.poll(&route()).expect("first poll");
    clock.set(150);
    poller.poll(&route()).expect("advanced poll");
    clock.set(225);

    assert_eq!(
        poller
            .snapshot(&route())
            .expect("fresh")
            .expect("snapshot")
            .leases()[0]
            .sample_sequence()
            .get(),
        2
    );
}

// Proves sequence regression, monotonic rollback, and read failure each clear cached state.
#[test]
fn transport_failure_matrix_fails_closed() {
    let failures = [
        Ok(response(1, 2)),
        Err(GatewayError::provider("Node poll", "read failed")),
    ];
    for failure in failures {
        let clock = Arc::new(ClockMock(AtomicU64::new(100)));
        let poller = GatewayNodeProtectionPoller::new(
            Arc::new(ClientMock::new(vec![Ok(response(2, 1)), failure])),
            clock.clone(),
            GatewayProtectionCachePolicy::new(1_000).expect("cache policy"),
        )
        .expect("poller");
        poller.connection_did_open(digest('9')).expect("connection");
        poller.poll(&route()).expect("first poll");
        assert!(poller.poll(&route()).is_err());
        assert!(poller.snapshot(&route()).expect("closed").is_none());
    }

    let clock = Arc::new(ClockMock(AtomicU64::new(100)));
    let poller = GatewayNodeProtectionPoller::new(
        Arc::new(ClientMock::new(vec![
            Ok(response(1, 1)),
            Ok(response(2, 2)),
        ])),
        clock.clone(),
        GatewayProtectionCachePolicy::new(1_000).expect("cache policy"),
    )
    .expect("poller");
    poller.connection_did_open(digest('9')).expect("connection");
    poller.poll(&route()).expect("first poll");
    clock.set(99);
    assert!(poller.poll(&route()).is_err());
    assert!(poller.snapshot(&route()).expect("closed").is_none());
}
