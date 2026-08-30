// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use li_core_interface::{
    DisplayName, EntityTimestamps, InstallationId, LogicalModelName, MachineId, ModelService,
    ModelServiceDesiredState, ModelServiceId, Node, NodeAddress, NodeId, NodeIdentity, NodeRole,
    NodeState, PlacementGroupId, UnixMilliseconds,
};
use li_database::{DatabaseClock, DatabaseConfiguration, DatabaseError, DatabaseManager};
use li_node_manager::{NodeManager, NodeManagerError, NodeManagerEvent};
use rusqlite::{params, Connection};

// Supplies deterministic increasing database commit timestamps.
struct TestClock(AtomicI64);

impl DatabaseClock for TestClock {
    // Returns one unique commit timestamp.
    fn now_unix_milliseconds(&self) -> Result<i64, DatabaseError> {
        Ok(self.0.fetch_add(1, Ordering::SeqCst))
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
fn identity(character: char) -> String {
    character.to_string().repeat(32)
}

// Returns one coherent local node fixture.
fn node(role: NodeRole) -> Node {
    Node::new(
        NodeIdentity::new(
            NodeId::parse(&identity('1')).expect("node"),
            MachineId::parse(&identity('2')).expect("machine"),
            InstallationId::parse(&"3".repeat(64)).expect("installation"),
        ),
        DisplayName::parse("Home AI").expect("name"),
        role,
        NodeState::Active,
        NodeAddress::parse("homeai.local").expect("address"),
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(1_000))
            .expect("timestamps"),
    )
}

// Opens one NodeManager from the supplied local role.
fn open_manager(path: &std::path::Path, role: NodeRole) -> NodeManager {
    NodeManager::open(database(path), node(role), "initialize-node")
        .expect("manager")
        .0
}

// Returns one empty stopped model-service fixture.
fn service(character: char, model: &str) -> ModelService {
    ModelService::new(
        ModelServiceId::parse(&identity(character)).expect("service"),
        LogicalModelName::parse(model).expect("model"),
        ModelServiceDesiredState::Stopped,
        Vec::new(),
        EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(1_000))
            .expect("timestamps"),
    )
    .expect("service")
}

// Returns one canonical placement-group identity.
fn group(character: char) -> PlacementGroupId {
    PlacementGroupId::parse(&identity(character)).expect("placement group")
}

// Creates, replays, lists, and reconstructs one model service after restart.
#[test]
fn main_creates_replays_and_reopens_model_service() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("core.sqlite3");
    let manager = open_manager(&path, NodeRole::Main);
    let expected = service('4', "qwen3_8");
    let created = manager
        .create_model_service("create-service", expected.clone())
        .expect("create");
    assert_eq!(created.revision(), 1);
    assert_eq!(
        created.event(),
        Some(&NodeManagerEvent::ModelServiceCreated {
            service_id: expected.service_id().clone(),
        })
    );
    let replay = manager
        .create_model_service("different-key", expected.clone())
        .expect("replay");
    assert_eq!(replay.revision(), 1);
    assert!(replay.event().is_none());
    assert_eq!(
        manager.model_services().expect("services"),
        vec![expected.clone()]
    );
    manager.close().expect("close");

    let reopened = open_manager(&path, NodeRole::Main);
    assert_eq!(
        reopened
            .model_service(expected.service_id())
            .expect("service")
            .value(),
        &expected
    );
}

// Keeps service creation main-owned and logical models globally unambiguous.
#[test]
fn service_creation_requires_main_and_unique_active_model() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let child = open_manager(&directory.path().join("child.sqlite3"), NodeRole::Child);
    assert_eq!(
        child.create_model_service("child-create", service('4', "qwen3_8")),
        Err(NodeManagerError::NotMain)
    );

    let main = open_manager(&directory.path().join("main.sqlite3"), NodeRole::Main);
    let first = service('4', "qwen3_8");
    main.create_model_service("first", first.clone())
        .expect("first");
    assert!(matches!(
        main.create_model_service("duplicate", service('5', "qwen3_8")),
        Err(NodeManagerError::InvalidModelService { .. })
    ));
    main.transition_model_service(
        "remove-first",
        first.service_id(),
        ModelServiceDesiredState::Removed,
        1,
        UnixMilliseconds::new(2_000),
    )
    .expect("remove");
    main.create_model_service("replacement", service('5', "qwen3_8"))
        .expect("replacement");
}

// Owns explicit attach, run, stop, detach, and remove lifecycle ordering.
#[test]
fn service_lifecycle_coordinates_placement_group_ownership() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let manager = open_manager(&directory.path().join("core.sqlite3"), NodeRole::Main);
    let service = service('4', "qwen3_8");
    manager
        .create_model_service("create", service.clone())
        .expect("create");
    let attached = manager
        .attach_placement_group(
            "attach",
            service.service_id(),
            group('5'),
            1,
            UnixMilliseconds::new(2_000),
        )
        .expect("attach");
    assert_eq!(attached.value().placement_group_ids(), [group('5')]);
    let attach_replay = manager
        .attach_placement_group(
            "attach-replay",
            service.service_id(),
            group('5'),
            1,
            UnixMilliseconds::new(9_000),
        )
        .expect("attach replay");
    assert_eq!(attach_replay.revision(), attached.revision());
    assert!(attach_replay.event().is_none());
    let running = manager
        .transition_model_service(
            "run",
            service.service_id(),
            ModelServiceDesiredState::Running,
            attached.revision(),
            UnixMilliseconds::new(3_000),
        )
        .expect("run");
    let stopped = manager
        .transition_model_service(
            "stop",
            service.service_id(),
            ModelServiceDesiredState::Stopped,
            running.revision(),
            UnixMilliseconds::new(4_000),
        )
        .expect("stop");
    let detached = manager
        .detach_placement_group(
            "detach",
            service.service_id(),
            &group('5'),
            stopped.revision(),
            UnixMilliseconds::new(5_000),
        )
        .expect("detach");
    assert!(detached.value().placement_group_ids().is_empty());
    let removed = manager
        .transition_model_service(
            "remove",
            service.service_id(),
            ModelServiceDesiredState::Removed,
            detached.revision(),
            UnixMilliseconds::new(6_000),
        )
        .expect("remove");
    assert_eq!(
        removed.value().desired_state(),
        ModelServiceDesiredState::Removed
    );
    assert!(matches!(
        removed.event(),
        Some(NodeManagerEvent::ModelServiceRemoved { .. })
    ));
}

// Rejects invalid desired-state order, stale revision, and backwards time.
#[test]
fn invalid_service_transition_matrix_fails_closed() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let manager = open_manager(&directory.path().join("core.sqlite3"), NodeRole::Main);
    let service = service('4', "qwen3_8");
    manager
        .create_model_service("create", service.clone())
        .expect("create");
    assert!(matches!(
        manager.transition_model_service(
            "empty-run",
            service.service_id(),
            ModelServiceDesiredState::Running,
            1,
            UnixMilliseconds::new(2_000),
        ),
        Err(NodeManagerError::InvalidModelService { .. })
    ));
    let attached = manager
        .attach_placement_group(
            "attach",
            service.service_id(),
            group('5'),
            1,
            UnixMilliseconds::new(2_000),
        )
        .expect("attach");
    assert!(matches!(
        manager.transition_model_service(
            "remove-owned",
            service.service_id(),
            ModelServiceDesiredState::Removed,
            attached.revision(),
            UnixMilliseconds::new(3_000),
        ),
        Err(NodeManagerError::InvalidModelService { .. })
    ));
    assert!(matches!(
        manager.detach_placement_group(
            "stale",
            service.service_id(),
            &group('5'),
            1,
            UnixMilliseconds::new(3_000),
        ),
        Err(NodeManagerError::Database(DatabaseError::Conflict { .. }))
    ));
    assert!(matches!(
        manager.detach_placement_group(
            "backwards",
            service.service_id(),
            &group('5'),
            attached.revision(),
            UnixMilliseconds::new(1_999),
        ),
        Err(NodeManagerError::InvalidModelService { .. })
    ));
}

// Serializes concurrent placement-group attachment through one service revision.
#[test]
fn concurrent_service_attachment_has_one_durable_winner() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let manager = Arc::new(open_manager(
        &directory.path().join("core.sqlite3"),
        NodeRole::Main,
    ));
    let service = service('4', "qwen3_8");
    manager
        .create_model_service("create", service.clone())
        .expect("create");
    let mut workers = Vec::new();
    for (key, group_id) in [("first", group('5')), ("second", group('6'))] {
        let manager = Arc::clone(&manager);
        let service_id = service.service_id().clone();
        workers.push(thread::spawn(move || {
            manager.attach_placement_group(
                key,
                &service_id,
                group_id,
                1,
                UnixMilliseconds::new(2_000),
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
            .model_service(service.service_id())
            .expect("service")
            .value()
            .placement_group_ids()
            .len(),
        1
    );
}

// Rejects semantically corrupt service persistence after restart.
#[test]
fn corrupt_model_service_record_fails_closed() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("core.sqlite3");
    let manager = open_manager(&path, NodeRole::Main);
    let service = service('4', "qwen3_8");
    manager
        .create_model_service("create", service.clone())
        .expect("create");
    manager.close().expect("close");

    let connection = Connection::open(&path).expect("SQLite");
    let payload: Vec<u8> = connection
        .query_row(
            "SELECT payload FROM li_database_records WHERE collection = ?1 AND identifier = ?2",
            params!["services", service.service_id().as_str()],
            |row| row.get(0),
        )
        .expect("payload");
    let mut value: serde_json::Value = serde_json::from_slice(&payload).expect("JSON");
    value["desired_state"] = serde_json::json!("unknown");
    connection
        .execute(
            "UPDATE li_database_records SET payload = ?1 WHERE collection = ?2 AND identifier = ?3",
            params![
                serde_json::to_vec(&value).expect("encoded"),
                "services",
                service.service_id().as_str()
            ],
        )
        .expect("corrupt payload");
    drop(connection);

    let reopened = open_manager(&path, NodeRole::Main);
    assert!(reopened.model_service(service.service_id()).is_err());
}
