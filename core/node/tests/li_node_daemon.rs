// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use li_benchmark_manager::BenchmarkError;
use li_core_interface::{
    BootId, ByteCount, CpuArchitecture, DisplayName, EntityTimestamps, HardwareObservation,
    HardwareObservationId, InstallationId, MachineId, Node, NodeAddress, NodeId, NodeIdentity,
    NodeRole, NodeState, OperatingSystem, PlatformIdentity, ProcessorObservation, UnixMilliseconds,
};
use li_database::{DatabaseClock, DatabaseConfiguration, DatabaseError, DatabaseManager};
use li_node_manager::{
    NodeBenchmarkPollingPort, NodeBenchmarkSnapshot, NodeDaemon, NodeDaemonClock, NodeDaemonError,
    NodeHardwareObservationProvider, NodeManager, NodeManagerError, NodeOutboxDeliveryProvider,
    NodeOutboxEvent,
};

// Supplies deterministic increasing database commit timestamps.
struct TestDatabaseClock(AtomicI64);

impl DatabaseClock for TestDatabaseClock {
    // Returns one unique commit timestamp.
    fn now_unix_milliseconds(&self) -> Result<i64, DatabaseError> {
        Ok(self.0.fetch_add(1, Ordering::SeqCst))
    }
}

// Supplies queued deterministic hardware observations or failures.
struct HardwareMock(Mutex<VecDeque<Result<HardwareObservation, NodeManagerError>>>);

impl NodeHardwareObservationProvider for HardwareMock {
    // Returns the next configured hardware result.
    fn observe(&self) -> Result<HardwareObservation, NodeManagerError> {
        self.0
            .lock()
            .map_err(|_| NodeManagerError::InvalidHardwareObservation {
                reason: "hardware mock is unavailable",
            })?
            .pop_front()
            .unwrap_or(Err(NodeManagerError::InvalidHardwareObservation {
                reason: "hardware mock has no observation",
            }))
    }
}

// Delivers event identities while one explicit failure switch is active.
struct DeliveryMock {
    fail: AtomicBool,
    delivered: Mutex<Vec<String>>,
}

impl NodeOutboxDeliveryProvider for DeliveryMock {
    // Records one deterministic event delivery or injected failure.
    fn deliver(&self, event: &NodeOutboxEvent) -> Result<(), NodeDaemonError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(NodeDaemonError::provider("delivery", "mock failure"));
        }
        self.delivered
            .lock()
            .expect("delivered")
            .push(event.event_id().as_str().to_string());
        Ok(())
    }
}

// Supplies one fixed acknowledgement time or explicit failure.
struct DaemonClockMock {
    fail: AtomicBool,
    now: u64,
}

impl NodeDaemonClock for DaemonClockMock {
    // Returns deterministic acknowledgement time.
    fn now(&self) -> Result<UnixMilliseconds, NodeDaemonError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(NodeDaemonError::provider("clock", "mock failure"));
        }
        Ok(UnixMilliseconds::new(self.now))
    }
}

// Records resident benchmark polls and injects one stable scheduler failure.
struct BenchmarkPollingMock(AtomicI64);

impl NodeBenchmarkPollingPort for BenchmarkPollingMock {
    // Records and rejects one deterministic benchmark poll.
    fn poll_active(&self) -> Result<Option<NodeBenchmarkSnapshot>, BenchmarkError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(BenchmarkError::provider(
            "execution observation",
            "mock failure",
        ))
    }
}

// Opens one isolated shared NodeManager.
fn manager(directory: &tempfile::TempDir) -> Arc<NodeManager> {
    let database = Arc::new(
        DatabaseManager::open(
            DatabaseConfiguration::new(directory.path().join("core.sqlite3"))
                .with_busy_timeout(Duration::from_secs(1))
                .with_clock(Arc::new(TestDatabaseClock(AtomicI64::new(10_000)))),
        )
        .expect("database"),
    );
    Arc::new(
        NodeManager::open(database, local_node(), "initialize-node")
            .expect("manager")
            .0,
    )
}

// Returns one ordinary active local node.
fn local_node() -> Node {
    Node::new(
        NodeIdentity::new(
            NodeId::parse(&"1".repeat(32)).expect("node"),
            MachineId::parse(&"2".repeat(32)).expect("machine"),
            InstallationId::parse(&"3".repeat(64)).expect("installation"),
        ),
        DisplayName::parse("Home AI").expect("name"),
        NodeRole::Main,
        NodeState::Active,
        NodeAddress::parse("homeai.local").expect("address"),
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(1_000))
            .expect("timestamps"),
    )
}

// Returns one minimal complete local hardware observation.
fn observation(character: char, observed_at: u64) -> HardwareObservation {
    HardwareObservation::new(
        HardwareObservationId::parse(&character.to_string().repeat(32)).expect("observation"),
        NodeId::parse(&"1".repeat(32)).expect("node"),
        BootId::parse("boot-1").expect("boot"),
        PlatformIdentity::new(OperatingSystem::Linux, CpuArchitecture::Arm64),
        ProcessorObservation::new(DisplayName::parse("NVIDIA GB10").expect("CPU"), 20)
            .expect("processor"),
        ByteCount::new(128 * 1024 * 1024 * 1024).expect("memory"),
        Vec::new(),
        Vec::new(),
        UnixMilliseconds::new(observed_at),
    )
    .expect("observation")
}

// Creates one daemon and retains its observable delivery provider.
fn daemon(
    manager: Arc<NodeManager>,
    hardware: Vec<Result<HardwareObservation, NodeManagerError>>,
    delivery_fails: bool,
    clock_fails: bool,
) -> (NodeDaemon, Arc<DeliveryMock>, Arc<DaemonClockMock>) {
    let delivery = Arc::new(DeliveryMock {
        fail: AtomicBool::new(delivery_fails),
        delivered: Mutex::new(Vec::new()),
    });
    let clock = Arc::new(DaemonClockMock {
        fail: AtomicBool::new(clock_fails),
        now: 4_000,
    });
    (
        NodeDaemon::new(
            manager,
            Arc::new(HardwareMock(Mutex::new(hardware.into()))),
            delivery.clone(),
            clock.clone(),
        ),
        delivery,
        clock,
    )
}

// Refreshes hardware then delivers and acknowledges every resulting durable event.
#[test]
fn tick_commits_hardware_and_acknowledges_outbox_after_delivery() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let manager = manager(&directory);
    let (daemon, delivery, _) = daemon(
        manager.clone(),
        vec![Ok(observation('4', 2_000))],
        false,
        false,
    );
    let tick = daemon.tick("hardware-1").expect("tick");
    assert!(tick.hardware().is_some());
    assert!(!tick.hardware_failed());
    assert_eq!(tick.delivered_event_ids().len(), 2);
    assert!(tick.pending_event_ids().is_empty());
    assert_eq!(delivery.delivered.lock().expect("delivered").len(), 2);
    assert!(manager.pending_outbox_events().expect("pending").is_empty());
}

// Continues durable delivery when hardware observation fails independently.
#[test]
fn hardware_failure_does_not_terminate_existing_outbox_delivery() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let manager = manager(&directory);
    let (daemon, _, _) = daemon(
        manager.clone(),
        vec![Err(NodeManagerError::InvalidHardwareObservation {
            reason: "mock failure",
        })],
        false,
        false,
    );
    let tick = daemon.tick("hardware-failed").expect("tick");
    assert!(tick.hardware().is_none());
    assert!(tick.hardware_failed());
    assert_eq!(tick.delivered_event_ids().len(), 1);
    assert!(tick.pending_event_ids().is_empty());
}

// Continues hardware and outbox work when restart-safe benchmark polling fails independently.
#[test]
fn benchmark_poll_failure_is_reported_without_terminating_resident_node_work() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let manager = manager(&directory);
    let (daemon, delivery, _) = daemon(
        manager.clone(),
        vec![Ok(observation('4', 2_000))],
        false,
        false,
    );
    let benchmark = Arc::new(BenchmarkPollingMock(AtomicI64::new(0)));
    let tick = daemon
        .with_benchmark(benchmark.clone())
        .tick("hardware-benchmark-failure")
        .expect("tick");

    assert!(tick.hardware().is_some());
    assert!(!tick.hardware_failed());
    assert!(tick.benchmark().is_none());
    assert!(tick.benchmark_failed());
    assert_eq!(benchmark.0.load(Ordering::SeqCst), 1);
    assert_eq!(tick.delivered_event_ids().len(), 2);
    assert!(tick.pending_event_ids().is_empty());
    assert_eq!(delivery.delivered.lock().expect("delivered").len(), 2);
    assert!(manager.pending_outbox_events().expect("pending").is_empty());
}

// Leaves failed delivery pending and redelivers it idempotently on the next cycle.
#[test]
fn failed_delivery_remains_pending_until_a_later_tick() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let manager = manager(&directory);
    let (daemon, delivery, clock) = daemon(
        manager.clone(),
        vec![
            Ok(observation('4', 2_000)),
            Err(NodeManagerError::InvalidHardwareObservation {
                reason: "no refresh",
            }),
        ],
        true,
        false,
    );
    let first = daemon.tick("hardware-1").expect("first tick");
    assert_eq!(first.pending_event_ids().len(), 2);
    assert!(first.delivered_event_ids().is_empty());

    delivery.fail.store(false, Ordering::SeqCst);
    clock.fail.store(false, Ordering::SeqCst);
    let second = daemon.tick("hardware-2").expect("second tick");
    assert_eq!(second.delivered_event_ids().len(), 2);
    assert!(second.pending_event_ids().is_empty());
    assert!(manager.pending_outbox_events().expect("pending").is_empty());
}

// Keeps every event pending for authenticated private-API consumption when no pusher is owned.
#[test]
fn private_outbox_mode_never_fabricates_delivery_or_acknowledgment() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let manager = manager(&directory);
    let daemon = NodeDaemon::new_with_private_outbox(
        manager.clone(),
        Arc::new(HardwareMock(Mutex::new(
            vec![Ok(observation('4', 2_000))].into(),
        ))),
        Arc::new(DaemonClockMock {
            fail: AtomicBool::new(false),
            now: 4_000,
        }),
    );

    let tick = daemon.tick("hardware-1").expect("tick");

    assert!(tick.delivered_event_ids().is_empty());
    assert_eq!(tick.pending_event_ids().len(), 2);
    assert_eq!(manager.pending_outbox_events().expect("pending").len(), 2);
}
