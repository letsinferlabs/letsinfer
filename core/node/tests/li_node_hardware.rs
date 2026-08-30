// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use li_core_interface::{
    Accelerator, AcceleratorDriver, AcceleratorMemory, AcceleratorTelemetry, AcceleratorVendor,
    BootId, ByteCount, ComputeCapability, CpuArchitecture, DeviceId, DisplayName, EntityTimestamps,
    HardwareObservation, HardwareObservationId, InstallationId, InterconnectObservation,
    InterconnectObservationKind, MachineId, MemoryTopology, NetworkInterfaceName, Node,
    NodeAddress, NodeId, NodeIdentity, NodeRole, NodeState, OperatingSystem, PlatformIdentity,
    ProcessorObservation, TechnicalName, UnixMilliseconds,
};
use li_database::{DatabaseClock, DatabaseConfiguration, DatabaseError, DatabaseManager};
use li_node_manager::{
    NodeHardwareObservationProvider, NodeManager, NodeManagerError, NodeManagerEvent,
};
use rusqlite::{params, Connection};

// Supplies deterministic increasing database commit timestamps.
struct TestClock(AtomicI64);

impl DatabaseClock for TestClock {
    // Returns one unique commit timestamp.
    fn now_unix_milliseconds(&self) -> Result<i64, DatabaseError> {
        Ok(self.0.fetch_add(1, Ordering::SeqCst))
    }
}

// Supplies one deterministic HardwareManager observation or failure.
struct HardwareProviderMock {
    observation: Option<HardwareObservation>,
    calls: AtomicUsize,
}

impl NodeHardwareObservationProvider for HardwareProviderMock {
    // Returns the configured observation without performing native I/O.
    fn observe(&self) -> Result<HardwareObservation, NodeManagerError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.observation
            .clone()
            .ok_or(NodeManagerError::InvalidHardwareObservation {
                reason: "mock hardware observation failed",
            })
    }
}

// Opens one isolated database manager with deterministic native time.
fn database(path: &std::path::Path) -> Arc<DatabaseManager> {
    Arc::new(
        DatabaseManager::open(
            DatabaseConfiguration::new(path)
                .with_busy_timeout(Duration::from_secs(1))
                .with_clock(Arc::new(TestClock(AtomicI64::new(10_000)))),
        )
        .expect("database"),
    )
}

// Returns one repeated canonical identity.
fn identity(character: char, length: usize) -> String {
    character.to_string().repeat(length)
}

// Returns the ordinary active local main fixture.
fn main_node() -> Node {
    Node::new(
        NodeIdentity::new(
            NodeId::parse(&identity('1', 32)).expect("node"),
            MachineId::parse(&identity('2', 32)).expect("machine"),
            InstallationId::parse(&identity('3', 64)).expect("installation"),
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

// Opens one NodeManager over the supplied database path.
fn open_manager(path: &std::path::Path) -> NodeManager {
    NodeManager::open(database(path), main_node(), "initialize-node")
        .expect("manager")
        .0
}

// Returns one complete NVIDIA observation with mutable telemetry and RDMA topology.
fn observation(
    observation_character: char,
    node_character: char,
    observed_at: u64,
    temperature_millicelsius: i32,
) -> HardwareObservation {
    let device_id = DeviceId::parse("GPU-00000000-0000-0000-0000-000000000001").expect("device");
    let accelerator = Accelerator::new(
        device_id.clone(),
        AcceleratorVendor::Nvidia,
        DisplayName::parse("NVIDIA GB10").expect("name"),
        AcceleratorMemory::new(
            MemoryTopology::Discrete,
            Some(ByteCount::new(24 * 1024 * 1024 * 1024).expect("framebuffer")),
            Some(TechnicalName::parse("ats").expect("addressing")),
        )
        .expect("memory"),
        ComputeCapability::Cuda {
            architecture: TechnicalName::parse("sm121").expect("architecture"),
            maximum_version: Some(TechnicalName::parse("cuda13").expect("CUDA")),
        },
    )
    .with_driver(AcceleratorDriver::new(
        TechnicalName::parse("nvidia").expect("driver source"),
        TechnicalName::parse("580.95.05").expect("driver version"),
    ))
    .with_telemetry(
        AcceleratorTelemetry::new(
            Some(temperature_millicelsius),
            Some(1_800),
            Some(7_000),
            Some(750),
            Some(90_000),
            Some(8 * 1024 * 1024 * 1024),
        )
        .expect("telemetry"),
    );
    HardwareObservation::new(
        HardwareObservationId::parse(&identity(observation_character, 32)).expect("observation"),
        NodeId::parse(&identity(node_character, 32)).expect("node"),
        BootId::parse("boot-1").expect("boot"),
        PlatformIdentity::new(OperatingSystem::Linux, CpuArchitecture::Arm64),
        ProcessorObservation::new(DisplayName::parse("NVIDIA GB10").expect("CPU"), 20)
            .expect("processor"),
        ByteCount::new(128 * 1024 * 1024 * 1024).expect("memory"),
        vec![accelerator],
        vec![InterconnectObservation::new(
            InterconnectObservationKind::Rdma,
            Some(NetworkInterfaceName::parse("enp1s0f0").expect("interface")),
            vec![device_id],
            true,
            Some(200_000),
            Some(1_500),
        )
        .expect("interconnect")],
        UnixMilliseconds::new(observed_at),
    )
    .expect("hardware observation")
}

// Persists complete latest hardware, replaces it, and reconstructs after restart.
#[test]
fn manager_records_replaces_and_reopens_complete_hardware() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("core.sqlite3");
    let manager = open_manager(&path);
    let first = observation('4', '1', 2_000, 60_000);
    let recorded = manager
        .record_local_hardware_observation("hardware-first", 1, first.clone())
        .expect("record first");
    assert_eq!(recorded.observation(), &first);
    assert_eq!(recorded.node_revision(), 2);
    assert_eq!(
        recorded.event(),
        Some(&NodeManagerEvent::HardwareRecorded {
            observation_id: first.observation_id().clone(),
        })
    );
    assert_eq!(
        manager
            .hardware_observation(manager.local_node_id())
            .expect("read"),
        Some(first)
    );
    assert_eq!(
        manager
            .local_node()
            .expect("local")
            .latest_hardware_observation_id(),
        Some(recorded.observation().observation_id())
    );

    let second = observation('5', '1', 3_000, 65_000);
    let replaced = manager
        .record_local_hardware_observation("hardware-second", 2, second.clone())
        .expect("replace");
    assert_eq!(replaced.node_revision(), 3);
    assert_eq!(
        manager
            .hardware_observation(manager.local_node_id())
            .expect("latest"),
        Some(second.clone())
    );
    assert_eq!(
        manager
            .outbox_events()
            .expect("outbox")
            .iter()
            .filter(|event| event.event().kind().as_str() == "hardware_recorded")
            .count(),
        2
    );
    manager.close().expect("close");

    let reopened = open_manager(&path);
    assert_eq!(
        reopened
            .hardware_observation(reopened.local_node_id())
            .expect("reopened"),
        Some(second)
    );
    assert_eq!(
        reopened
            .local_node()
            .expect("local")
            .latest_hardware_observation_id(),
        Some(replaced.observation().observation_id())
    );
}

// Replays one committed observation without another outbox event or revision.
#[test]
fn identical_hardware_replay_is_observed_without_mutation() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let manager = open_manager(&directory.path().join("core.sqlite3"));
    let observation = observation('4', '1', 2_000, 60_000);
    let first = manager
        .record_local_hardware_observation("hardware", 1, observation.clone())
        .expect("first");
    let replay = manager
        .record_local_hardware_observation("different-key", 1, observation)
        .expect("replay");
    assert_eq!(replay.node_revision(), first.node_revision());
    assert!(replay.event().is_none());
    assert_eq!(
        manager
            .outbox_events()
            .expect("outbox")
            .iter()
            .filter(|event| event.event().kind().as_str() == "hardware_recorded")
            .count(),
        1
    );
}

// Rejects foreign identity, backward time, and stale revision without partial writes.
#[test]
fn invalid_hardware_matrix_fails_before_atomic_commit() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let manager = open_manager(&directory.path().join("core.sqlite3"));
    assert!(matches!(
        manager.record_local_hardware_observation(
            "foreign",
            1,
            observation('4', '7', 2_000, 60_000),
        ),
        Err(NodeManagerError::InvalidHardwareObservation { .. })
    ));
    assert!(matches!(
        manager.record_local_hardware_observation("old", 1, observation('4', '1', 999, 60_000),),
        Err(NodeManagerError::InvalidHardwareObservation { .. })
    ));
    let first = observation('4', '1', 2_000, 60_000);
    manager
        .record_local_hardware_observation("first", 1, first.clone())
        .expect("first");
    assert!(matches!(
        manager.record_local_hardware_observation(
            "backwards",
            2,
            observation('5', '1', 1_999, 61_000),
        ),
        Err(NodeManagerError::InvalidHardwareObservation { .. })
    ));
    assert!(matches!(
        manager
            .record_local_hardware_observation("stale", 1, observation('6', '1', 3_000, 62_000),),
        Err(NodeManagerError::Database(DatabaseError::Conflict { .. }))
    ));
    assert_eq!(
        manager
            .hardware_observation(manager.local_node_id())
            .expect("latest"),
        Some(first)
    );
    assert_eq!(
        manager
            .outbox_events()
            .expect("outbox")
            .iter()
            .filter(|event| event.event().kind().as_str() == "hardware_recorded")
            .count(),
        1
    );
}

// Orchestrates the injected HardwareManager capability once and preserves provider failure.
#[test]
fn hardware_refresh_uses_one_narrow_provider_boundary() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let manager = open_manager(&directory.path().join("core.sqlite3"));
    let expected = observation('4', '1', 2_000, 60_000);
    let provider = HardwareProviderMock {
        observation: Some(expected.clone()),
        calls: AtomicUsize::new(0),
    };
    let change = manager
        .refresh_local_hardware("refresh", 1, &provider)
        .expect("refresh");
    assert_eq!(change.observation(), &expected);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);

    let failed = HardwareProviderMock {
        observation: None,
        calls: AtomicUsize::new(0),
    };
    assert!(matches!(
        manager.refresh_local_hardware("failed-refresh", change.node_revision(), &failed),
        Err(NodeManagerError::InvalidHardwareObservation { .. })
    ));
    assert_eq!(failed.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        manager
            .hardware_observation(manager.local_node_id())
            .expect("latest"),
        Some(expected)
    );
}

// Round-trips each closed accelerator vendor, memory, and compute union once.
#[test]
fn hardware_persistence_preserves_accelerator_unions() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let manager = open_manager(&directory.path().join("core.sqlite3"));
    let nvidia = observation('4', '1', 2_000, 60_000).accelerators()[0].clone();
    let apple = Accelerator::new(
        DeviceId::parse("apple-gpu-0").expect("device"),
        AcceleratorVendor::Apple,
        DisplayName::parse("Apple M4 Max").expect("name"),
        AcceleratorMemory::new(
            MemoryTopology::Unified,
            None,
            Some(TechnicalName::parse("unified").expect("addressing")),
        )
        .expect("memory"),
        ComputeCapability::Metal {
            family: TechnicalName::parse("apple9").expect("family"),
            version: TechnicalName::parse("metal4").expect("version"),
        },
    );
    let other = Accelerator::new(
        DeviceId::parse("accelerator-0").expect("device"),
        AcceleratorVendor::Other(TechnicalName::parse("example").expect("vendor")),
        DisplayName::parse("Example Accelerator").expect("name"),
        AcceleratorMemory::new(MemoryTopology::Unknown, None, None).expect("memory"),
        ComputeCapability::Other {
            api: TechnicalName::parse("example_api").expect("API"),
            capability: Some(TechnicalName::parse("v1").expect("capability")),
        },
    );
    let expected = HardwareObservation::new(
        HardwareObservationId::parse(&identity('7', 32)).expect("observation"),
        manager.local_node_id().clone(),
        BootId::parse("boot-1").expect("boot"),
        PlatformIdentity::new(OperatingSystem::Macos, CpuArchitecture::Arm64),
        ProcessorObservation::new(DisplayName::parse("Apple M4 Max").expect("CPU"), 16)
            .expect("processor"),
        ByteCount::new(128 * 1024 * 1024 * 1024).expect("memory"),
        vec![nvidia, apple, other],
        Vec::new(),
        UnixMilliseconds::new(2_000),
    )
    .expect("observation");
    manager
        .record_local_hardware_observation("unions", 1, expected.clone())
        .expect("record");
    assert_eq!(
        manager
            .hardware_observation(manager.local_node_id())
            .expect("read"),
        Some(expected)
    );
}

// Serializes concurrent observations so one exact local revision wins.
#[test]
fn concurrent_hardware_refresh_has_one_durable_winner() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let manager = Arc::new(open_manager(&directory.path().join("core.sqlite3")));
    let mut workers = Vec::new();
    for (key, character, temperature) in [("first", '4', 60_000), ("second", '5', 65_000)] {
        let manager = Arc::clone(&manager);
        workers.push(thread::spawn(move || {
            manager.record_local_hardware_observation(
                key,
                1,
                observation(character, '1', 2_000, temperature),
            )
        }));
    }
    let results = workers
        .into_iter()
        .map(|worker| worker.join().expect("worker"))
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(
                result,
                Err(NodeManagerError::Database(DatabaseError::Conflict { .. }))
            ))
            .count(),
        1
    );
    assert_eq!(
        manager
            .local_node()
            .expect("local")
            .timestamps()
            .updated_at(),
        UnixMilliseconds::new(2_000)
    );
}

// Rejects semantically corrupt hardware persistence instead of fabricating facts.
#[test]
fn corrupt_hardware_record_fails_closed_after_restart() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("core.sqlite3");
    let manager = open_manager(&path);
    manager
        .record_local_hardware_observation("hardware", 1, observation('4', '1', 2_000, 60_000))
        .expect("record");
    manager.close().expect("close");

    let connection = Connection::open(&path).expect("SQLite");
    let payload: Vec<u8> = connection
        .query_row(
            "SELECT payload FROM li_database_records WHERE collection = ?1 AND identifier = ?2",
            params!["hardware_observations", identity('1', 32)],
            |row| row.get(0),
        )
        .expect("payload");
    let mut value: serde_json::Value = serde_json::from_slice(&payload).expect("JSON");
    value["observation"]["memory_bytes"] = serde_json::json!(0);
    connection
        .execute(
            "UPDATE li_database_records SET payload = ?1 WHERE collection = ?2 AND identifier = ?3",
            params![
                serde_json::to_vec(&value).expect("encoded"),
                "hardware_observations",
                identity('1', 32)
            ],
        )
        .expect("corrupt payload");
    drop(connection);

    let reopened = open_manager(&path);
    assert!(reopened
        .hardware_observation(reopened.local_node_id())
        .is_err());
}

// Rejects unsupported schema, unknown nested fields, and duplicate nested keys after restart.
#[test]
fn strict_hardware_document_corruption_fails_closed_after_restart() {
    for corruption in ["future-schema", "unknown-field", "duplicate-key"] {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("core.sqlite3");
        let manager = open_manager(&path);
        manager
            .record_local_hardware_observation("hardware", 1, observation('4', '1', 2_000, 60_000))
            .expect("record");
        manager.close().expect("close");
        let connection = Connection::open(&path).expect("SQLite");
        let payload: Vec<u8> = connection
            .query_row(
                "SELECT payload FROM li_database_records WHERE collection = ?1 AND identifier = ?2",
                params!["hardware_observations", identity('1', 32)],
                |row| row.get(0),
            )
            .expect("payload");
        let replacement = match corruption {
            "future-schema" => {
                let mut value: serde_json::Value = serde_json::from_slice(&payload).expect("JSON");
                value["observation"]["schema"]["version"] = serde_json::json!(2);
                serde_json::to_vec(&value).expect("future schema")
            }
            "unknown-field" => {
                let mut value: serde_json::Value = serde_json::from_slice(&payload).expect("JSON");
                value["observation"]["accelerators"][0]["driver"]["secret"] =
                    serde_json::json!(true);
                serde_json::to_vec(&value).expect("unknown field")
            }
            "duplicate-key" => String::from_utf8(payload)
                .expect("UTF-8")
                .replacen("\"source\":", "\"source\":\"duplicate\",\"source\":", 1)
                .into_bytes(),
            _ => unreachable!("fixed corruption matrix"),
        };
        connection
            .execute(
                "UPDATE li_database_records SET payload = ?1 WHERE collection = ?2 AND identifier = ?3",
                params![replacement, "hardware_observations", identity('1', 32)],
            )
            .expect("corrupt payload");
        drop(connection);
        let reopened = open_manager(&path);
        assert!(
            reopened
                .hardware_observation(reopened.local_node_id())
                .is_err(),
            "corruption {corruption}"
        );
    }
}
