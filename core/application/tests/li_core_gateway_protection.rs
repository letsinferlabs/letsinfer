// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::VecDeque;
use std::num::{NonZeroU32, NonZeroU64};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use li_core_application::{
    CoreGatewayNodeProtectionProvider, CoreGatewayProtectionConnection,
    CoreGatewayProtectionConnectionIdentityProvider, CoreGatewayProtectionConnectionProvider,
    CoreGatewayProtectionResident,
};
use li_core_interface::{
    BootId, EndpointAddress, EndpointScheme, InstallationId, LogicalModelName, NodeAddress, NodeId,
    PlacementGroupId, PlacementId, Sha256Digest, TechnicalName, UnixMilliseconds,
};
use li_gateway_manager::{
    GatewayError, GatewayPlacementProtectionLease, GatewayPlacementProtectionSnapshot,
    GatewayProtectionAuthority, GatewayProtectionCachePolicy, GatewayProtectionLeaseProvider,
    GatewayProtectionMonotonicClock, GatewayProtectionPollResponse, GatewayRoute,
    GatewayRouteTarget,
};

// Supplies mutable deterministic local monotonic time.
struct ClockMock(AtomicU64);

impl ClockMock {
    // Replaces the next observed local monotonic timestamp.
    fn set(&self, value: u64) {
        self.0.store(value, Ordering::Release);
    }
}

impl GatewayProtectionMonotonicClock for ClockMock {
    // Returns the exact configured process-local time.
    fn now_milliseconds(&self) -> Result<u64, GatewayError> {
        Ok(self.0.load(Ordering::Acquire))
    }
}

// Supplies exact connection identities in deterministic order.
struct IdentityProviderMock(Mutex<VecDeque<Sha256Digest>>);

impl CoreGatewayProtectionConnectionIdentityProvider for IdentityProviderMock {
    // Returns the next expected identity.
    fn next(&self) -> Result<Sha256Digest, GatewayError> {
        self.0
            .lock()
            .expect("identities")
            .pop_front()
            .ok_or_else(test_error)
    }
}

// Describes one deterministic Node connection response.
enum ConnectionResult {
    Snapshot(u64),
    Failure,
    Panic(mpsc::Sender<()>),
}

// Coordinates an optional intentionally slow Node read.
#[derive(Default)]
struct ConnectionGate {
    started: AtomicBool,
    released: Mutex<bool>,
    signal: Condvar,
}

impl ConnectionGate {
    // Waits until the connection enters its simulated Node read.
    fn wait_until_started(&self) {
        while !self.started.load(Ordering::Acquire) {
            thread::yield_now();
        }
    }

    // Releases the simulated Node read.
    fn release(&self) {
        *self.released.lock().expect("released") = true;
        self.signal.notify_all();
    }

    // Blocks until the test explicitly releases this read.
    fn wait(&self) {
        self.started.store(true, Ordering::Release);
        let mut released = self.released.lock().expect("released");
        while !*released {
            released = self.signal.wait(released).expect("gate");
        }
    }
}

// Returns queued snapshots or failures on one exact connection.
struct ConnectionMock {
    connection_id: Sha256Digest,
    results: Mutex<VecDeque<ConnectionResult>>,
    response_sequence: AtomicU64,
    gate: Option<Arc<ConnectionGate>>,
}

impl CoreGatewayProtectionConnection for ConnectionMock {
    // Returns the immutable injected connection identity.
    fn connection_id(&self) -> &Sha256Digest {
        &self.connection_id
    }

    // Returns the next deterministic response after any configured delay.
    fn poll(
        &self,
        _node_id: &NodeId,
        _route: &GatewayRoute,
    ) -> Result<GatewayProtectionPollResponse, GatewayError> {
        if let Some(gate) = self.gate.as_ref() {
            gate.wait();
        }
        let result = self
            .results
            .lock()
            .expect("results")
            .pop_front()
            .ok_or_else(test_error)?;
        match result {
            ConnectionResult::Snapshot(sample_sequence) => Ok(GatewayProtectionPollResponse::new(
                self.connection_id.clone(),
                NonZeroU64::new(self.response_sequence.fetch_add(1, Ordering::AcqRel) + 1)
                    .expect("sequence"),
                Some(snapshot(sample_sequence)),
            )),
            ConnectionResult::Failure => Err(test_error()),
            ConnectionResult::Panic(observed) => {
                observed.send(()).expect("panic observation");
                panic!("simulated protection resident panic");
            }
        }
    }
}

// Opens one mock connection for every queued response plan.
struct ConnectionProviderMock {
    plans: Mutex<VecDeque<(Vec<ConnectionResult>, Option<Arc<ConnectionGate>>)>>,
    identities: Mutex<Vec<Sha256Digest>>,
}

impl CoreGatewayProtectionConnectionProvider for ConnectionProviderMock {
    // Opens one exact connection and records its fresh identity.
    fn connect(
        &self,
        connection_id: Sha256Digest,
    ) -> Result<Arc<dyn CoreGatewayProtectionConnection>, GatewayError> {
        self.identities
            .lock()
            .expect("opened identities")
            .push(connection_id.clone());
        let (results, gate) = self
            .plans
            .lock()
            .expect("plans")
            .pop_front()
            .ok_or_else(test_error)?;
        Ok(Arc::new(ConnectionMock {
            connection_id,
            results: Mutex::new(results.into()),
            response_sequence: AtomicU64::new(0),
            gate,
        }))
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

// Returns the exact route selected by every composition fixture.
fn route() -> GatewayRoute {
    route_for(group_id())
}

// Returns one route for an exact registry-capacity fixture group.
fn route_for(placement_group_id: PlacementGroupId) -> GatewayRoute {
    GatewayRoute::new(
        placement_group_id,
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

// Returns one complete identity-bound protection snapshot.
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

// Creates one provider and returns the inspectable connection provider.
fn provider(
    clock: Arc<ClockMock>,
    plans: Vec<(Vec<ConnectionResult>, Option<Arc<ConnectionGate>>)>,
) -> (
    Arc<CoreGatewayNodeProtectionProvider>,
    Arc<ConnectionProviderMock>,
) {
    let connections = Arc::new(ConnectionProviderMock {
        plans: Mutex::new(plans.into()),
        identities: Mutex::new(Vec::new()),
    });
    let provider = Arc::new(
        CoreGatewayNodeProtectionProvider::new_with_providers(
            node_id(),
            GatewayProtectionCachePolicy::new(100).expect("cache policy"),
            clock,
            Arc::new(IdentityProviderMock(Mutex::new(
                vec![digest('9'), digest('a'), digest('b')].into(),
            ))),
            connections.clone(),
        )
        .expect("provider"),
    );
    (provider, connections)
}

// Returns one stable test-only provider failure.
const fn test_error() -> GatewayError {
    GatewayError::provider("protection test", "mock failure")
}

// Proves slow Node IPC never enters the inference request critical path.
#[test]
fn slow_node_poll_does_not_block_snapshot_reads() {
    let clock = Arc::new(ClockMock(AtomicU64::new(10)));
    let gate = Arc::new(ConnectionGate::default());
    let (provider, _) = provider(
        clock,
        vec![(vec![ConnectionResult::Snapshot(1)], Some(gate.clone()))],
    );
    assert!(provider.snapshot(&route()).expect("register").is_none());
    let polling = {
        let provider = provider.clone();
        thread::spawn(move || provider.poll_once())
    };
    gate.wait_until_started();
    let (sender, receiver) = mpsc::channel();
    let reading = {
        let provider = provider.clone();
        thread::spawn(move || sender.send(provider.snapshot(&route())).expect("send"))
    };
    assert!(receiver
        .recv_timeout(Duration::from_millis(100))
        .expect("nonblocking read")
        .expect("snapshot")
        .is_none());
    gate.release();
    polling.join().expect("poll thread").expect("poll");
    reading.join().expect("read thread");
    assert!(provider.snapshot(&route()).expect("published").is_some());
}

// Proves cache age is local-monotonic and not extended without an advanced protection cycle.
#[test]
fn local_monotonic_expiry_closes_cached_snapshot() {
    let clock = Arc::new(ClockMock(AtomicU64::new(10)));
    let (provider, _) = provider(
        clock.clone(),
        vec![(vec![ConnectionResult::Snapshot(1)], None)],
    );
    assert!(provider.snapshot(&route()).expect("register").is_none());
    provider.poll_once().expect("poll");
    assert!(provider.snapshot(&route()).expect("fresh").is_some());
    clock.set(110);
    assert!(provider.snapshot(&route()).expect("expired").is_none());
}

// Proves a failed read clears all cache and only a new fresh connection can reopen it.
#[test]
fn disconnect_invalidates_cache_and_reconnect_uses_fresh_identity() {
    let clock = Arc::new(ClockMock(AtomicU64::new(10)));
    let (provider, connections) = provider(
        clock.clone(),
        vec![
            (
                vec![ConnectionResult::Snapshot(1), ConnectionResult::Failure],
                None,
            ),
            (vec![ConnectionResult::Snapshot(2)], None),
        ],
    );
    assert!(provider.snapshot(&route()).expect("register").is_none());
    provider.poll_once().expect("first poll");
    assert!(provider.snapshot(&route()).expect("first cache").is_some());
    assert!(provider.poll_once().is_err());
    assert!(provider.snapshot(&route()).expect("disconnected").is_none());
    clock.set(20);
    provider.poll_once().expect("reconnect");
    assert_eq!(
        provider
            .snapshot(&route())
            .expect("fresh")
            .expect("cache")
            .leases()[0]
            .sample_sequence()
            .get(),
        2
    );
    assert_eq!(
        *connections.identities.lock().expect("identities"),
        vec![digest('9'), digest('a')]
    );
}

// Proves the background owner can stop and join without coupling Gateway or Node lifecycles.
#[test]
fn resident_shutdown_is_independent_and_bounded() {
    let clock = Arc::new(ClockMock(AtomicU64::new(10)));
    let (provider, _) = provider(clock, Vec::new());
    let mut resident =
        CoreGatewayProtectionResident::start(provider, Duration::from_secs(60)).expect("resident");
    resident.stop();
    resident.join().expect("join");
}

// Proves concurrent registration remains bounded and a new group fails closed at capacity.
#[test]
fn route_registry_is_bounded_under_concurrent_registration() {
    let clock = Arc::new(ClockMock(AtomicU64::new(10)));
    let (provider, _) = provider(clock, Vec::new());
    let mut workers = Vec::new();
    for worker_index in 0..8_u64 {
        let provider = provider.clone();
        workers.push(thread::spawn(move || {
            for offset in 0..128_u64 {
                let index = worker_index * 128 + offset + 1;
                let group =
                    PlacementGroupId::parse(&format!("{index:032x}")).expect("placement group");
                assert!(provider
                    .snapshot(&route_for(group))
                    .expect("registered")
                    .is_none());
            }
        }));
    }
    for worker in workers {
        worker.join().expect("registration worker");
    }
    let overflow = PlacementGroupId::parse(&format!("{:032x}", 1_025_u64)).expect("overflow");
    assert!(provider.snapshot(&route_for(overflow)).is_err());
    assert!(provider.snapshot(&route()).is_err());
}

// Proves a resident panic is observable and closes an already-published snapshot immediately.
#[test]
fn resident_panic_invalidates_request_cache_and_join_reports_failure() {
    let clock = Arc::new(ClockMock(AtomicU64::new(10)));
    let (panic_observed, panic_observation) = mpsc::channel();
    let (provider, _) = provider(
        clock,
        vec![(
            vec![
                ConnectionResult::Snapshot(1),
                ConnectionResult::Panic(panic_observed),
            ],
            None,
        )],
    );
    assert!(provider.snapshot(&route()).expect("register").is_none());
    provider.poll_once().expect("initial poll");
    assert!(provider.snapshot(&route()).expect("published").is_some());
    let mut resident =
        CoreGatewayProtectionResident::start(provider.clone(), Duration::from_millis(1))
            .expect("resident");
    panic_observation
        .recv_timeout(Duration::from_secs(1))
        .expect("resident panic observation");
    assert!(resident.join().is_err());
    assert!(provider.snapshot(&route()).expect("closed").is_none());
}
