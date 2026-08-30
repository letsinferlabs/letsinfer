// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use li_core_interface::{
    CredentialId, DeviceId, EndpointAddress, EndpointHealth, EndpointOwnership, EndpointScheme,
    EngineDistribution, EntityTimestamps, InterconnectKind, InterconnectRequirement,
    ModelServiceDesiredState, ModelServiceId, NetworkInterfaceName, NetworkPort, NodeAddress,
    NodeId, Placement, PlacementAssignment, PlacementEndpoint, PlacementGroup,
    PlacementGroupCapacity, PlacementGroupId, PlacementGroupState, PlacementId, PlacementResources,
    PlacementState, PortRange, ResourceIdentity, ResourceLease, ResourceLeaseId,
    ResourceLeaseState, RuntimeCandidateId, RuntimeIdentity, RuntimeInstallationId, RuntimeSource,
    RuntimeVersion, Sha256Digest, TargetId, TaskId, UnixMilliseconds,
};
use li_database::{DatabaseConfiguration, DatabaseManager};
use li_node_manager::DatabasePlacementStore;
use li_placement_manager::{PlacementError, PlacementRecord, PlacementStore};

// Returns one exact runtime identity for placement persistence.
fn runtime_identity() -> RuntimeIdentity {
    RuntimeIdentity::new(
        RuntimeCandidateId::parse("sglang--radixark--qwen3.8--dgx-spark").expect("candidate"),
        RuntimeVersion::parse("1.0.0").expect("version"),
        TargetId::parse("dgx-spark").expect("target"),
        RuntimeSource::parse(&format!("ghcr.io/runtime/qwen@sha256:{}", "a".repeat(64)))
            .expect("runtime source"),
        EngineDistribution::oci(
            RuntimeSource::parse(&format!("ghcr.io/engine/qwen@sha256:{}", "b".repeat(64)))
                .expect("Engine source"),
            Sha256Digest::parse(&"c".repeat(64)).expect("Engine identity"),
            None,
            Some(Sha256Digest::parse(&"d".repeat(64)).expect("payload")),
        ),
        Sha256Digest::parse(&"a".repeat(64)).expect("runtime digest"),
        Sha256Digest::parse(&"e".repeat(64)).expect("manifest"),
        Sha256Digest::parse(&"f".repeat(64)).expect("execution"),
    )
    .expect("runtime")
}

// Returns one complete aggregate at a supported terminal lifecycle state.
fn record(identity_value: u64, state: PlacementGroupState) -> PlacementRecord {
    let placement_group_id =
        PlacementGroupId::parse(&format!("{identity_value:032x}")).expect("placement group");
    let placement_id =
        PlacementId::parse(&format!("{:032x}", identity_value + 1)).expect("placement");
    let node_id = NodeId::parse(&"1".repeat(32)).expect("node");
    let resources = PlacementResources::new(
        PortRange::new(18_000, 2).expect("ports"),
        vec![DeviceId::parse("GPU-A").expect("GPU")],
        Some(NetworkInterfaceName::parse("enp1s0f0np0").expect("RDMA")),
    )
    .expect("resources");
    let placement_state = match state {
        PlacementGroupState::Staged => PlacementState::Staged,
        PlacementGroupState::Running => PlacementState::Running,
        PlacementGroupState::Stopped => PlacementState::Stopped,
        PlacementGroupState::Removed => PlacementState::Removed,
        _ => panic!("unsupported fixture state"),
    };
    let lease_state = match state {
        PlacementGroupState::Running => ResourceLeaseState::Active,
        PlacementGroupState::Removed => ResourceLeaseState::Released,
        PlacementGroupState::Staged | PlacementGroupState::Stopped => ResourceLeaseState::Reserved,
        _ => panic!("unsupported fixture state"),
    };
    let placement = Placement::new(
        placement_id.clone(),
        placement_group_id.clone(),
        PlacementAssignment::new(
            node_id.clone(),
            RuntimeInstallationId::parse(&"2".repeat(32)).expect("installation"),
            li_core_interface::HardwareObservationId::parse(&"6".repeat(32))
                .expect("hardware observation"),
            li_core_interface::BootId::parse("11111111-2222-3333-4444-555555555555").expect("boot"),
            UnixMilliseconds::new(900),
            TaskId::parse("task-0").expect("task"),
            NodeAddress::parse("spark.local").expect("address"),
            resources.clone(),
            EndpointOwnership::Owner,
        ),
        placement_state,
        None,
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(2_000))
            .expect("timestamps"),
    )
    .expect("placement");
    let endpoint = (state == PlacementGroupState::Running).then(|| {
        PlacementEndpoint::new(
            placement_id.clone(),
            node_id.clone(),
            EndpointAddress::new(
                EndpointScheme::Https,
                NodeAddress::parse("spark.local").expect("address"),
                18_000,
            )
            .expect("endpoint address"),
            CredentialId::parse(&"3".repeat(32)).expect("credential"),
            Some(CredentialId::parse(&"4".repeat(32)).expect("CA")),
            None,
            4,
            262_144,
            EndpointHealth::new(true, false, Some(52_000), Vec::new()).expect("health"),
        )
        .expect("endpoint")
    });
    let desired_state = match state {
        PlacementGroupState::Stopped => ModelServiceDesiredState::Stopped,
        PlacementGroupState::Removed => ModelServiceDesiredState::Removed,
        _ => ModelServiceDesiredState::Running,
    };
    let group = PlacementGroup::new(
        placement_group_id,
        ModelServiceId::parse(&"5".repeat(32)).expect("service"),
        runtime_identity(),
        vec![placement_id.clone()],
        placement_id.clone(),
        endpoint,
        PlacementGroupCapacity::new(
            8,
            4,
            262_144,
            InterconnectRequirement::new(InterconnectKind::Connectx, true, 200_000, 1_500),
        )
        .expect("capacity"),
        desired_state,
        state,
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(2_000))
            .expect("timestamps"),
    )
    .expect("group");
    let resources = [
        ResourceIdentity::Accelerator(DeviceId::parse("GPU-A").expect("GPU")),
        ResourceIdentity::Port(NetworkPort::new(18_000).expect("port")),
        ResourceIdentity::Port(NetworkPort::new(18_001).expect("port")),
        ResourceIdentity::RdmaInterface(NetworkInterfaceName::parse("enp1s0f0np0").expect("RDMA")),
    ];
    let leases = resources
        .into_iter()
        .enumerate()
        .map(|(index, resource)| {
            ResourceLease::new(
                ResourceLeaseId::parse(&format!("{:032x}", identity_value + 2 + index as u64))
                    .expect("lease"),
                placement_id.clone(),
                node_id.clone(),
                resource,
                lease_state,
                EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(2_000))
                    .expect("timestamps"),
            )
        })
        .collect();
    PlacementRecord::new(
        group,
        vec![placement],
        leases,
        vec![vec![placement_id.clone()]],
        vec![(
            placement_id,
            Sha256Digest::parse(&"9".repeat(64)).expect("launch plan"),
        )],
    )
    .expect("placement record")
}

// Opens one isolated real DatabaseManager.
fn database(directory: &tempfile::TempDir) -> Arc<DatabaseManager> {
    Arc::new(
        DatabaseManager::open(DatabaseConfiguration::new(
            directory.path().join("core.sqlite3"),
        ))
        .expect("database"),
    )
}

// Replaces one exact fragment inside an isolated private database payload.
fn corrupt_payload(
    database_path: &std::path::Path,
    collection: &str,
    identifier: &str,
    expected: &str,
    replacement: &str,
) {
    let connection = rusqlite::Connection::open(database_path).expect("raw database");
    let payload: Vec<u8> = connection
        .query_row(
            "SELECT payload FROM li_database_records WHERE collection = ?1 AND identifier = ?2",
            rusqlite::params![collection, identifier],
            |row| row.get(0),
        )
        .expect("stored payload");
    let payload = String::from_utf8(payload).expect("UTF-8 payload");
    let corrupted = payload.replacen(expected, replacement, 1);
    assert_ne!(corrupted, payload);
    connection
        .execute(
            "UPDATE li_database_records SET payload = ?1 WHERE collection = ?2 AND identifier = ?3",
            rusqlite::params![corrupted.as_bytes(), collection, identifier],
        )
        .expect("corrupt payload");
}

// Persists and reconstructs every aggregate field across a real database restart.
#[test]
fn placement_store_round_trips_complete_aggregate_after_restart() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let staged = record(10, PlacementGroupState::Staged);
    let placement_group_id = staged.group().placement_group_id().clone();
    {
        let store = DatabasePlacementStore::new(database(&directory));
        let created = store.create(staged.clone()).expect("create");
        assert_eq!(created.revision(), 1);
        assert_eq!(
            store
                .occupied_resources(staged.placements()[0].assignment().node_id())
                .expect("occupied")
                .len(),
            4
        );
    }
    let store = DatabasePlacementStore::new(database(&directory));
    let observed = store
        .read(&placement_group_id)
        .expect("read")
        .expect("record");
    assert_eq!(observed.record(), &staged);
    assert_eq!(observed.revision(), 1);
}

// Replaces one aggregate and reconstructs its endpoint and active leases exactly.
#[test]
fn placement_store_replaces_complete_running_state() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let store = DatabasePlacementStore::new(database(&directory));
    let staged = record(20, PlacementGroupState::Staged);
    let identity = staged.group().placement_group_id().clone();
    let created = store.create(staged).expect("create");
    let running = record(20, PlacementGroupState::Running);
    let replaced = store
        .replace(running.clone(), created.revision())
        .expect("replace");
    assert_eq!(replaced.revision(), 2);
    assert_eq!(
        store
            .read(&identity)
            .expect("read")
            .expect("record")
            .record(),
        &running
    );
}

// Releases the global resource index atomically before another group acquires it.
#[test]
fn placement_store_rejects_overlap_then_allows_post_release_reuse() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let store = DatabasePlacementStore::new(database(&directory));
    let first = record(30, PlacementGroupState::Staged);
    let first_identity = first.group().placement_group_id().clone();
    let first = store.create(first).expect("first create");
    let second = record(40, PlacementGroupState::Staged);
    assert_eq!(
        store.create(second.clone()).expect_err("overlap"),
        PlacementError::ResourceConflict
    );
    store
        .replace(record(30, PlacementGroupState::Removed), first.revision())
        .expect("release");
    assert!(store
        .occupied_resources(&NodeId::parse(&"1".repeat(32)).expect("node"))
        .expect("occupied after release")
        .is_empty());
    store.create(second).expect("resource reuse");
    assert_eq!(
        store
            .read(&first_identity)
            .expect("first read")
            .expect("first record")
            .record()
            .group()
            .state(),
        PlacementGroupState::Removed
    );
}

// Allows exactly one winner when concurrent stores race for the same resources.
#[test]
fn placement_store_serializes_concurrent_resource_conflict() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let store = Arc::new(DatabasePlacementStore::new(database(&directory)));
    let (first, second) = std::thread::scope(|scope| {
        let first_store = store.clone();
        let second_store = store.clone();
        let first =
            scope.spawn(move || first_store.create(record(50, PlacementGroupState::Staged)));
        let second =
            scope.spawn(move || second_store.create(record(60, PlacementGroupState::Staged)));
        (
            first.join().expect("first thread"),
            second.join().expect("second thread"),
        )
    });
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    assert!(matches!(
        first.err().or_else(|| second.err()).expect("conflict"),
        PlacementError::ResourceConflict | PlacementError::StoreConflict
    ));
    assert_eq!(
        store
            .occupied_resources(&NodeId::parse(&"1".repeat(32)).expect("node"))
            .expect("occupied")
            .len(),
        4
    );
}

// Rejects replay and stale aggregate revisions without changing durable state.
#[test]
fn placement_store_enforces_replay_and_optimistic_revision() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let store = DatabasePlacementStore::new(database(&directory));
    let staged = record(70, PlacementGroupState::Staged);
    let created = store.create(staged.clone()).expect("create");
    assert_eq!(
        store.create(staged).expect_err("create replay"),
        PlacementError::StoreConflict
    );
    let running = record(70, PlacementGroupState::Running);
    store
        .replace(running.clone(), created.revision())
        .expect("replace");
    assert_eq!(
        store
            .replace(running, created.revision())
            .expect_err("stale replace"),
        PlacementError::StoreConflict
    );
}

// Rejects semantically corrupt aggregate and resource-index records after restart.
#[test]
fn placement_store_fails_closed_on_semantic_corruption() {
    let aggregate_directory = tempfile::tempdir().expect("aggregate directory");
    let aggregate = record(80, PlacementGroupState::Staged);
    let aggregate_id = aggregate.group().placement_group_id().clone();
    {
        let store = DatabasePlacementStore::new(database(&aggregate_directory));
        store.create(aggregate).expect("create aggregate");
    }
    corrupt_payload(
        &aggregate_directory.path().join("core.sqlite3"),
        "placements",
        aggregate_id.as_str(),
        "\"state\":\"staged\"",
        "\"state\":\"invalid\"",
    );
    let aggregate_store = DatabasePlacementStore::new(database(&aggregate_directory));
    assert_eq!(
        aggregate_store
            .read(&aggregate_id)
            .expect_err("corrupt aggregate"),
        PlacementError::StoreUnavailable
    );

    let index_directory = tempfile::tempdir().expect("index directory");
    {
        let store = DatabasePlacementStore::new(database(&index_directory));
        store
            .create(record(90, PlacementGroupState::Staged))
            .expect("create index");
    }
    corrupt_payload(
        &index_directory.path().join("core.sqlite3"),
        "configuration",
        "li_placement_resource_index_v1",
        &format!("\"node_id\":\"{}\"", "1".repeat(32)),
        "\"node_id\":\"invalid\"",
    );
    let index_store = DatabasePlacementStore::new(database(&index_directory));
    assert_eq!(
        index_store
            .occupied_resources(&NodeId::parse(&"1".repeat(32)).expect("node"))
            .expect_err("corrupt index"),
        PlacementError::StoreUnavailable
    );
}
