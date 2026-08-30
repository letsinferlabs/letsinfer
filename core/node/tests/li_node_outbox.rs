// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use li_core_interface::{
    DisplayName, EntityTimestamps, InstallationId, MachineId, ModelServiceId, Node, NodeAddress,
    NodeId, NodeIdentity, NodeRole, NodeState, OperationId, OperationKind, OperationTarget,
    UnixMilliseconds,
};
use li_database::{DatabaseClock, DatabaseConfiguration, DatabaseError, DatabaseManager};
use li_node_manager::{NodeManager, NodeOutboxState, NodeTransition};

// Supplies deterministic increasing database commit timestamps.
struct TestClock(AtomicI64);

impl DatabaseClock for TestClock {
    // Returns one unique database commit timestamp.
    fn now_unix_milliseconds(&self) -> Result<i64, DatabaseError> {
        Ok(self.0.fetch_add(1, Ordering::SeqCst))
    }
}

// Returns one canonical repeated identity.
fn identity(character: char) -> String {
    character.to_string().repeat(32)
}

// Returns one coherent main or child node fixture.
fn node(
    node_character: char,
    machine_character: char,
    installation_character: char,
    role: NodeRole,
    state: NodeState,
    address: &str,
) -> Node {
    Node::new(
        NodeIdentity::new(
            NodeId::parse(&identity(node_character)).expect("node"),
            MachineId::parse(&identity(machine_character)).expect("machine"),
            InstallationId::parse(&installation_character.to_string().repeat(64))
                .expect("installation"),
        ),
        DisplayName::parse(if role == NodeRole::Main {
            "Home AI"
        } else {
            "Node 2"
        })
        .expect("name"),
        role,
        state,
        NodeAddress::parse(address).expect("address"),
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(1_000))
            .expect("timestamps"),
    )
}

// Opens one isolated NodeManager with deterministic database time.
fn open_manager(directory: &tempfile::TempDir) -> NodeManager {
    let database = Arc::new(
        DatabaseManager::open(
            DatabaseConfiguration::new(directory.path().join("core.sqlite3"))
                .with_busy_timeout(Duration::from_secs(1))
                .with_clock(Arc::new(TestClock(AtomicI64::new(10_000)))),
        )
        .expect("database"),
    );
    NodeManager::open(
        database,
        node(
            '1',
            '2',
            '3',
            NodeRole::Main,
            NodeState::Active,
            "homeai.local",
        ),
        "initialize-node",
    )
    .expect("manager")
    .0
}

// Persists initialization as one pending deterministic outbox event.
#[test]
fn initialization_event_is_durable_and_restart_stable() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let manager = open_manager(&directory);
    let events = manager.outbox_events().expect("events");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event().kind().as_str(), "node_initialized");
    assert_eq!(events[0].event().entity_id(), identity('1'));
    assert_eq!(events[0].event().state(), NodeOutboxState::Pending);
    assert_eq!(
        events[0].event().occurred_at(),
        UnixMilliseconds::new(1_000)
    );
    assert_eq!(events[0].revision(), 1);
    let event_id = events[0].event().event_id().clone();
    manager.close().expect("close");

    let manager = open_manager(&directory);
    let reopened = manager.outbox_events().expect("reopened events");
    assert_eq!(reopened.len(), 1);
    assert_eq!(reopened[0].event().event_id(), &event_id);
}

// Commits node and operation events atomically while replay creates no duplicate outbox rows.
#[test]
fn entity_mutations_create_one_replay_safe_outbox_event_each() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let manager = open_manager(&directory);
    let child = node(
        '4',
        '5',
        '6',
        NodeRole::Child,
        NodeState::Pending,
        "homeai-node-2.local",
    );
    let enrolled = manager
        .enroll_child("enroll-child", child.clone())
        .expect("enroll");
    manager
        .enroll_child("enroll-child", child.clone())
        .expect("replay enroll");
    manager
        .transition_child(
            "activate-child",
            child.identity().node_id(),
            enrolled.revision(),
            NodeTransition::Activate,
            UnixMilliseconds::new(2_000),
        )
        .expect("activate");
    let operation_id = OperationId::parse(&identity('7')).expect("operation");
    let began = manager
        .begin_operation(
            "begin-operation",
            operation_id.clone(),
            OperationKind::Start,
            OperationTarget::ModelService(ModelServiceId::parse(&identity('8')).expect("service")),
            UnixMilliseconds::new(3_000),
        )
        .expect("begin");
    manager
        .begin_operation(
            "begin-operation",
            operation_id.clone(),
            OperationKind::Start,
            began.value().target().clone(),
            UnixMilliseconds::new(3_000),
        )
        .expect("replay begin");
    let events = manager.outbox_events().expect("events");
    assert_eq!(events.len(), 4);
    let kinds = events
        .iter()
        .map(|event| event.event().kind().as_str())
        .collect::<Vec<_>>();
    for expected in [
        "node_initialized",
        "node_enrolled",
        "node_activated",
        "operation_began",
    ] {
        assert!(kinds.contains(&expected), "{expected}");
    }
}

// Acknowledges one event idempotently and removes it from pending delivery only.
#[test]
fn acknowledgment_is_durable_idempotent_and_not_self_emitting() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let manager = open_manager(&directory);
    let pending = manager.pending_outbox_events().expect("pending");
    let event = pending[0].clone();
    let acknowledged = manager
        .acknowledge_outbox_event(
            "acknowledge-initialization",
            event.event().event_id(),
            event.revision(),
            UnixMilliseconds::new(2_000),
        )
        .expect("acknowledge");
    assert_eq!(acknowledged.event().state(), NodeOutboxState::Acknowledged);
    assert_eq!(acknowledged.revision(), 2);
    let replay = manager
        .acknowledge_outbox_event(
            "acknowledge-initialization",
            event.event().event_id(),
            event.revision(),
            UnixMilliseconds::new(2_000),
        )
        .expect("replay");
    assert_eq!(replay.revision(), acknowledged.revision());
    assert!(manager.pending_outbox_events().expect("pending").is_empty());
    assert_eq!(manager.outbox_events().expect("all").len(), 1);
}

// Rejects acknowledgment before occurrence without mutating durable delivery state.
#[test]
fn acknowledgment_time_cannot_precede_event() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let manager = open_manager(&directory);
    let event = manager.outbox_events().expect("events")[0].clone();
    assert!(manager
        .acknowledge_outbox_event(
            "acknowledge-too-early",
            event.event().event_id(),
            event.revision(),
            UnixMilliseconds::new(999),
        )
        .is_err());
    assert_eq!(
        manager
            .outbox_event(event.event().event_id())
            .expect("current")
            .event()
            .state(),
        NodeOutboxState::Pending
    );
}

// Rolls back the outbox row when its paired entity mutation loses an optimistic conflict.
#[test]
fn stale_entity_transition_never_leaks_an_outbox_event() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let manager = open_manager(&directory);
    let child = node(
        '4',
        '5',
        '6',
        NodeRole::Child,
        NodeState::Pending,
        "homeai-node-2.local",
    );
    let enrolled = manager
        .enroll_child("enroll", child.clone())
        .expect("enroll");
    let activated = manager
        .transition_child(
            "activate",
            child.identity().node_id(),
            enrolled.revision(),
            NodeTransition::Activate,
            UnixMilliseconds::new(2_000),
        )
        .expect("activate");
    let count = manager.outbox_events().expect("before").len();
    assert!(matches!(
        manager.transition_child(
            "pause-stale",
            child.identity().node_id(),
            enrolled.revision(),
            NodeTransition::Pause,
            UnixMilliseconds::new(2_100),
        ),
        Err(li_node_manager::NodeManagerError::Database(
            DatabaseError::Conflict { .. }
        ))
    ));
    assert_eq!(manager.outbox_events().expect("after").len(), count);
    assert_eq!(
        manager
            .node(child.identity().node_id())
            .expect("child")
            .revision(),
        activated.revision()
    );
}

// Produces distinct deterministic IDs for distinct event intent and entity identity.
#[test]
fn outbox_event_identities_are_unique_and_canonical() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let manager = open_manager(&directory);
    let child = node(
        '4',
        '5',
        '6',
        NodeRole::Child,
        NodeState::Pending,
        "homeai-node-2.local",
    );
    manager.enroll_child("enroll", child).expect("enroll");
    let events = manager.outbox_events().expect("events");
    let identities = events
        .iter()
        .map(|event| event.event().event_id().as_str())
        .collect::<Vec<_>>();
    assert_eq!(identities.len(), 2);
    assert_ne!(identities[0], identities[1]);
    assert!(identities.iter().all(|identity| {
        identity.len() == 64
            && identity
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }));
}
