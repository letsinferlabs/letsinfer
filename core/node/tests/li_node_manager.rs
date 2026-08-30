// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use li_core_interface::{
    DisplayName, EntityTimestamps, FailureDescription, InstallationId, MachineId, ModelServiceId,
    Node, NodeAddress, NodeId, NodeIdentity, NodeRole, NodeState, OperationId, OperationKind,
    OperationState, OperationTarget, TechnicalName, UnixMilliseconds,
};
use li_database::{DatabaseClock, DatabaseConfiguration, DatabaseError, DatabaseManager};
use li_node_manager::{NodeManager, NodeManagerError, NodeManagerEvent, OperationCompletion};

// Supplies deterministic increasing database commit timestamps.
struct TestClock {
    next_value: AtomicI64,
}

impl TestClock {
    // Creates one deterministic clock beginning at the supplied value.
    fn new(first_value: i64) -> Self {
        Self {
            next_value: AtomicI64::new(first_value),
        }
    }
}

impl DatabaseClock for TestClock {
    // Returns one unique timestamp for every new database commit.
    fn now_unix_milliseconds(&self) -> Result<i64, DatabaseError> {
        Ok(self.next_value.fetch_add(1, Ordering::SeqCst))
    }
}

// Returns one canonical identity fixture.
fn identity(character: char) -> String {
    character.to_string().repeat(32)
}

// Returns one coherent timestamp fixture.
fn timestamps(created_at: u64, updated_at: u64) -> EntityTimestamps {
    EntityTimestamps::new(
        UnixMilliseconds::new(created_at),
        UnixMilliseconds::new(updated_at),
    )
    .expect("timestamps")
}

// Returns one local-node fixture with distinct logical and physical identities.
fn node(node_character: char, display_name: &str) -> Node {
    Node::new(
        NodeIdentity::new(
            NodeId::parse(&identity(node_character)).expect("node"),
            MachineId::parse(&identity('2')).expect("machine"),
            InstallationId::parse(&"3".repeat(64)).expect("installation"),
        ),
        DisplayName::parse(display_name).expect("display name"),
        NodeRole::Main,
        NodeState::Active,
        NodeAddress::parse("homeai.local").expect("address"),
        None,
        timestamps(1_000, 1_000),
    )
}

// Opens one isolated database manager using deterministic native dependencies.
fn database(directory: &tempfile::TempDir) -> Arc<DatabaseManager> {
    Arc::new(
        DatabaseManager::open(
            DatabaseConfiguration::new(directory.path().join("core.sqlite3"))
                .with_busy_timeout(Duration::from_secs(1))
                .with_clock(Arc::new(TestClock::new(10_000))),
        )
        .expect("database manager"),
    )
}

// Returns one bounded failure fixture.
fn failure() -> FailureDescription {
    FailureDescription::new(
        TechnicalName::parse("runtime_failed").expect("failure code"),
        "Runtime failed",
    )
    .expect("failure")
}

// Initializes the local node once and returns stored state on later opens.
#[test]
fn manager_initializes_and_reopens_local_identity() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (manager, initialized) = NodeManager::open(
        database(&directory),
        node('1', "Home AI"),
        "initialize-node",
    )
    .expect("node manager");
    assert_eq!(initialized.revision(), 1);
    assert_eq!(
        initialized.event(),
        Some(&NodeManagerEvent::NodeInitialized {
            node_id: NodeId::parse(&identity('1')).expect("node"),
        })
    );
    manager.close().expect("close node manager");

    let (manager, reopened) = NodeManager::open(
        database(&directory),
        node('1', "Changed Display Name"),
        "initialize-node",
    )
    .expect("reopened node manager");
    assert!(reopened.event().is_none());
    assert_eq!(reopened.value().display_name().as_str(), "Home AI");
    assert_eq!(manager.local_node().expect("local node"), *reopened.value());
}

// Loads the exact persisted local identity without inventing bootstrap state.
#[test]
fn manager_loads_an_initialized_process_database() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let expected = node('1', "Home AI");
    let (manager, _) = NodeManager::open(database(&directory), expected.clone(), "initialize-node")
        .expect("node manager");
    manager.close().expect("close initial manager");
    let loaded = NodeManager::load(database(&directory)).expect("load node manager");
    assert_eq!(loaded.local_node().expect("local node"), expected);
}

// Rejects a different local node identity instead of adopting it silently.
#[test]
fn manager_rejects_a_changed_local_identity() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (manager, _) = NodeManager::open(
        database(&directory),
        node('1', "Home AI"),
        "initialize-node",
    )
    .expect("node manager");
    manager.close().expect("close node manager");
    let error = match NodeManager::open(
        database(&directory),
        node('4', "Other Node"),
        "initialize-other-node",
    ) {
        Ok(_) => panic!("changed identity must fail"),
        Err(error) => error,
    };
    assert_eq!(error, NodeManagerError::IdentityMismatch);
}

// Applies one complete operation lifecycle and suppresses replayed domain events.
#[test]
fn manager_applies_idempotent_operation_lifecycle() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (manager, _) = NodeManager::open(
        database(&directory),
        node('1', "Home AI"),
        "initialize-node",
    )
    .expect("node manager");
    let operation_id = OperationId::parse(&identity('5')).expect("operation");
    let target = OperationTarget::ModelService(
        ModelServiceId::parse(&identity('6')).expect("model service"),
    );
    let began = manager
        .begin_operation(
            "begin-operation",
            operation_id.clone(),
            OperationKind::Start,
            target,
            UnixMilliseconds::new(2_000),
        )
        .expect("begin operation");
    assert_eq!(began.value().state(), OperationState::Pending);
    assert!(matches!(
        began.event(),
        Some(NodeManagerEvent::OperationBegan { .. })
    ));
    let replay = manager
        .begin_operation(
            "begin-operation",
            operation_id.clone(),
            OperationKind::Start,
            began.value().target().clone(),
            UnixMilliseconds::new(2_000),
        )
        .expect("replay begin");
    assert_eq!(replay.revision(), began.revision());
    assert!(replay.event().is_none());

    let started = manager
        .start_operation(
            "start-operation",
            &operation_id,
            began.revision(),
            UnixMilliseconds::new(2_100),
        )
        .expect("start operation");
    assert_eq!(started.value().state(), OperationState::Running);
    assert!(matches!(
        started.event(),
        Some(NodeManagerEvent::OperationStarted { .. })
    ));
    let start_replay = manager
        .start_operation(
            "start-operation",
            &operation_id,
            began.revision(),
            UnixMilliseconds::new(2_100),
        )
        .expect("replay start");
    assert!(start_replay.event().is_none());

    let completed = manager
        .complete_operation(
            "complete-operation",
            &operation_id,
            started.revision(),
            OperationCompletion::Succeeded,
            UnixMilliseconds::new(2_200),
        )
        .expect("complete operation");
    assert_eq!(completed.value().state(), OperationState::Succeeded);
    assert!(matches!(
        completed.event(),
        Some(NodeManagerEvent::OperationSucceeded { .. })
    ));
    let completion_replay = manager
        .complete_operation(
            "complete-operation",
            &operation_id,
            started.revision(),
            OperationCompletion::Succeeded,
            UnixMilliseconds::new(2_200),
        )
        .expect("replay completion");
    assert!(completion_replay.event().is_none());
}

// Rejects completion success before an operation has started.
#[test]
fn manager_rejects_invalid_operation_transition() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (manager, _) = NodeManager::open(
        database(&directory),
        node('1', "Home AI"),
        "initialize-node",
    )
    .expect("node manager");
    let operation_id = OperationId::parse(&identity('5')).expect("operation");
    let began = manager
        .begin_operation(
            "begin-operation",
            operation_id.clone(),
            OperationKind::Start,
            OperationTarget::Node(NodeId::parse(&identity('1')).expect("node")),
            UnixMilliseconds::new(2_000),
        )
        .expect("begin operation");
    let error = manager
        .complete_operation(
            "complete-operation",
            &operation_id,
            began.revision(),
            OperationCompletion::Succeeded,
            UnixMilliseconds::new(2_100),
        )
        .expect_err("pending success must fail");
    assert!(matches!(
        error,
        NodeManagerError::InvalidOperationTransition {
            current: "pending",
            action: "complete",
            ..
        }
    ));
    assert_eq!(
        manager.operation(&operation_id).expect("operation").state(),
        OperationState::Pending
    );
}

// Records failed and cancelled outcomes with their exact terminal contracts.
#[test]
fn manager_records_failure_and_cancellation() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (manager, _) = NodeManager::open(
        database(&directory),
        node('1', "Home AI"),
        "initialize-node",
    )
    .expect("node manager");
    let failed_id = OperationId::parse(&identity('5')).expect("failed operation");
    let failed = manager
        .begin_operation(
            "begin-failed",
            failed_id.clone(),
            OperationKind::Install,
            OperationTarget::Node(NodeId::parse(&identity('1')).expect("node")),
            UnixMilliseconds::new(2_000),
        )
        .expect("begin failed operation");
    let failed = manager
        .complete_operation(
            "fail-operation",
            &failed_id,
            failed.revision(),
            OperationCompletion::Failed(failure()),
            UnixMilliseconds::new(2_100),
        )
        .expect("fail operation");
    assert_eq!(failed.value().state(), OperationState::Failed);
    assert_eq!(
        failed.value().failure().expect("failure").code().as_str(),
        "runtime_failed"
    );

    let cancelled_id = OperationId::parse(&identity('7')).expect("cancelled operation");
    let cancelled = manager
        .begin_operation(
            "begin-cancelled",
            cancelled_id.clone(),
            OperationKind::Update,
            OperationTarget::Node(NodeId::parse(&identity('1')).expect("node")),
            UnixMilliseconds::new(3_000),
        )
        .expect("begin cancelled operation");
    let cancelled = manager
        .complete_operation(
            "cancel-operation",
            &cancelled_id,
            cancelled.revision(),
            OperationCompletion::Cancelled,
            UnixMilliseconds::new(3_100),
        )
        .expect("cancel operation");
    assert_eq!(cancelled.value().state(), OperationState::Cancelled);
    assert!(cancelled.value().failure().is_none());
}

// Lets exactly one concurrent transition commit for an expected revision.
#[test]
fn manager_serializes_concurrent_operation_transitions() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (manager, _) = NodeManager::open(
        database(&directory),
        node('1', "Home AI"),
        "initialize-node",
    )
    .expect("node manager");
    let manager = Arc::new(manager);
    let operation_id = OperationId::parse(&identity('5')).expect("operation");
    let began = manager
        .begin_operation(
            "begin-operation",
            operation_id.clone(),
            OperationKind::Start,
            OperationTarget::Node(NodeId::parse(&identity('1')).expect("node")),
            UnixMilliseconds::new(2_000),
        )
        .expect("begin operation");
    let expected_revision = began.revision();
    let mut workers = Vec::new();
    for index in 0..2 {
        let manager = Arc::clone(&manager);
        let operation_id = operation_id.clone();
        workers.push(thread::spawn(move || {
            manager.start_operation(
                &format!("start-operation-{index}"),
                &operation_id,
                expected_revision,
                UnixMilliseconds::new(2_100 + index),
            )
        }));
    }
    let results: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().expect("transition worker"))
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
    assert_eq!(
        manager.operation(&operation_id).expect("operation").state(),
        OperationState::Running
    );
}

// Persists operation snapshots across a clean node-manager restart.
#[test]
fn manager_reopens_committed_operations() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (manager, _) = NodeManager::open(
        database(&directory),
        node('1', "Home AI"),
        "initialize-node",
    )
    .expect("node manager");
    let operation_id = OperationId::parse(&identity('5')).expect("operation");
    manager
        .begin_operation(
            "begin-operation",
            operation_id.clone(),
            OperationKind::Start,
            OperationTarget::Node(NodeId::parse(&identity('1')).expect("node")),
            UnixMilliseconds::new(2_000),
        )
        .expect("begin operation");
    manager.close().expect("close node manager");

    let (manager, _) = NodeManager::open(
        database(&directory),
        node('1', "Home AI"),
        "initialize-node",
    )
    .expect("reopen node manager");
    assert_eq!(manager.operations().expect("operations").len(), 1);
    assert_eq!(
        manager.operation(&operation_id).expect("operation").state(),
        OperationState::Pending
    );
}
