// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use li_core_interface::{
    DisplayName, EntityTimestamps, InstallationId, MachineId, Node, NodeAddress, NodeId,
    NodeIdentity, NodeRole, NodeState, UnixMilliseconds,
};
use li_database::{
    DatabaseClock, DatabaseConfiguration, DatabaseError, DatabaseManager, DatabaseTransaction,
};
use li_node_manager::{
    LocalNodeRoleReadinessProvider, LocalNodeRoleTransition, LocalNodeRoleTransitionProof,
    NodeManager, NodeManagerError, NodeManagerEvent,
};

// Supplies deterministic increasing database commit timestamps.
struct TestClock(AtomicI64);

impl DatabaseClock for TestClock {
    // Returns one unique commit timestamp.
    fn now_unix_milliseconds(&self) -> Result<i64, DatabaseError> {
        Ok(self.0.fetch_add(1, Ordering::SeqCst))
    }
}

// Selects one deterministic readiness-provider outcome.
#[derive(Clone, Copy)]
enum ReadinessMode {
    Exact,
    WrongLocalIdentity,
    WrongRoles,
    WrongAuthority,
    Expired,
    Future,
    Failure,
}

// Supplies exact or deliberately malformed readiness proof without native state.
struct ReadinessMock {
    authority_node_id: NodeId,
    mode: ReadinessMode,
    calls: AtomicUsize,
}

impl ReadinessMock {
    // Creates one provider bound to an exact current or destination authority.
    fn new(authority_node_id: NodeId, mode: ReadinessMode) -> Self {
        Self {
            authority_node_id,
            mode,
            calls: AtomicUsize::new(0),
        }
    }

    // Returns how many readiness decisions reached this external boundary.
    fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl LocalNodeRoleReadinessProvider for ReadinessMock {
    // Returns one deterministic proof variant for the requested transition.
    fn proof(
        &self,
        local: &Node,
        transition: &LocalNodeRoleTransition,
        now: UnixMilliseconds,
    ) -> Result<LocalNodeRoleTransitionProof, NodeManagerError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if matches!(self.mode, ReadinessMode::Failure) {
            return Err(NodeManagerError::InvalidLocalRoleTransition {
                reason: "readiness provider rejected external state",
            });
        }
        let wrong_node_id = NodeId::parse(&identity('e')).expect("wrong node");
        let wrong_authority_id = NodeId::parse(&identity('f')).expect("wrong authority");
        let local_node_id = if matches!(self.mode, ReadinessMode::WrongLocalIdentity) {
            wrong_node_id
        } else {
            local.identity().node_id().clone()
        };
        let (mut from_role, mut to_role) = (local.role(), transition.target_role());
        if matches!(self.mode, ReadinessMode::WrongRoles) {
            std::mem::swap(&mut from_role, &mut to_role);
        }
        let authority_node_id = if matches!(self.mode, ReadinessMode::WrongAuthority) {
            wrong_authority_id
        } else {
            self.authority_node_id.clone()
        };
        let (issued_at, expires_at) = match self.mode {
            ReadinessMode::Expired => (
                UnixMilliseconds::new(now.value() - 2_000),
                UnixMilliseconds::new(now.value() - 1_000),
            ),
            ReadinessMode::Future => (
                UnixMilliseconds::new(now.value() + 1_000),
                UnixMilliseconds::new(now.value() + 2_000),
            ),
            ReadinessMode::Exact
            | ReadinessMode::WrongLocalIdentity
            | ReadinessMode::WrongRoles
            | ReadinessMode::WrongAuthority
            | ReadinessMode::Failure => (now, UnixMilliseconds::new(now.value() + 60_000)),
        };
        LocalNodeRoleTransitionProof::new(
            local_node_id,
            from_role,
            to_role,
            authority_node_id,
            issued_at,
            expires_at,
        )
    }
}

// Synchronizes concurrent role writers after they have read identical state.
struct BarrierReadiness {
    authority_node_id: NodeId,
    barrier: Arc<Barrier>,
}

impl LocalNodeRoleReadinessProvider for BarrierReadiness {
    // Releases both writers together with independently bound valid proof.
    fn proof(
        &self,
        local: &Node,
        transition: &LocalNodeRoleTransition,
        now: UnixMilliseconds,
    ) -> Result<LocalNodeRoleTransitionProof, NodeManagerError> {
        self.barrier.wait();
        LocalNodeRoleTransitionProof::new(
            local.identity().node_id().clone(),
            local.role(),
            transition.target_role(),
            self.authority_node_id.clone(),
            now,
            UnixMilliseconds::new(now.value() + 60_000),
        )
    }
}

// Fails if an already-completed transition consults external readiness again.
struct PanicReadiness;

impl LocalNodeRoleReadinessProvider for PanicReadiness {
    // Rejects any unexpected external call made by an idempotent role request.
    fn proof(
        &self,
        _local: &Node,
        _transition: &LocalNodeRoleTransition,
        _now: UnixMilliseconds,
    ) -> Result<LocalNodeRoleTransitionProof, NodeManagerError> {
        panic!("completed role transition consulted readiness")
    }
}

// Opens one isolated database manager with deterministic native time.
fn database(directory: &tempfile::TempDir) -> Arc<DatabaseManager> {
    Arc::new(
        DatabaseManager::open(
            DatabaseConfiguration::new(directory.path().join("core.sqlite3"))
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

// Returns one coherent node fixture with explicit identity, role, state, and address.
#[allow(clippy::too_many_arguments)]
fn node(
    node_character: char,
    machine_character: char,
    installation_character: char,
    name: &str,
    role: NodeRole,
    state: NodeState,
    address: &str,
    updated_at: u64,
) -> Node {
    Node::new(
        NodeIdentity::new(
            NodeId::parse(&identity(node_character)).expect("node"),
            MachineId::parse(&identity(machine_character)).expect("machine"),
            InstallationId::parse(&installation_character.to_string().repeat(64))
                .expect("installation"),
        ),
        DisplayName::parse(name).expect("name"),
        role,
        state,
        NodeAddress::parse(address).expect("address"),
        None,
        EntityTimestamps::new(
            UnixMilliseconds::new(1_000),
            UnixMilliseconds::new(updated_at),
        )
        .expect("timestamps"),
    )
}

// Returns the ordinary active local main fixture.
fn local_main() -> Node {
    node(
        '1',
        '2',
        '3',
        "Home AI",
        NodeRole::Main,
        NodeState::Active,
        "homeai.local",
        1_000,
    )
}

// Returns one independent active destination-main fixture.
fn destination_main(
    node_character: char,
    machine_character: char,
    installation_character: char,
    address: &str,
) -> Node {
    node(
        node_character,
        machine_character,
        installation_character,
        "Destination",
        NodeRole::Main,
        NodeState::Active,
        address,
        1_500,
    )
}

// Opens one NodeManager from the supplied local snapshot.
fn open_manager(directory: &tempfile::TempDir, local: Node) -> NodeManager {
    NodeManager::open(database(directory), local, "initialize-node")
        .expect("node manager")
        .0
}

// Moves one local main to child and returns the manager, authority, and local revision.
fn configured_child(directory: &tempfile::TempDir) -> (NodeManager, Node, u64) {
    let manager = open_manager(directory, local_main());
    let authority = destination_main('4', '5', '6', "destination.local");
    let readiness =
        ReadinessMock::new(authority.identity().node_id().clone(), ReadinessMode::Exact);
    let changed = manager
        .transition_local_role(
            "become-child",
            1,
            LocalNodeRoleTransition::BecomeChild {
                main: authority.clone(),
            },
            UnixMilliseconds::new(2_000),
            &readiness,
        )
        .expect("become child");
    (manager, authority, changed.revision())
}

// Atomically replaces local main authority and reconstructs it after restart.
#[test]
fn main_becomes_child_with_one_durable_authority_and_outbox_event() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let manager = open_manager(&directory, local_main());
    let authority = destination_main('4', '5', '6', "destination.local");
    let readiness =
        ReadinessMock::new(authority.identity().node_id().clone(), ReadinessMode::Exact);
    let changed = manager
        .transition_local_role(
            "move-home",
            1,
            LocalNodeRoleTransition::BecomeChild {
                main: authority.clone(),
            },
            UnixMilliseconds::new(2_000),
            &readiness,
        )
        .expect("role transition");
    assert_eq!(readiness.call_count(), 1);
    assert_eq!(changed.value().role(), NodeRole::Child);
    assert_eq!(changed.value().state(), NodeState::Active);
    assert_eq!(changed.revision(), 2);
    assert_eq!(
        changed.event(),
        Some(&NodeManagerEvent::LocalRoleChanged {
            node_id: manager.local_node_id().clone(),
            role: NodeRole::Child,
        })
    );
    let committed_main = manager.main_node().expect("active main");
    assert_eq!(committed_main.value(), &authority);
    assert_eq!(committed_main.revision(), 1);
    let role_events = manager
        .outbox_events()
        .expect("outbox")
        .into_iter()
        .filter(|event| event.event().kind().as_str() == "local_became_child")
        .collect::<Vec<_>>();
    assert_eq!(role_events.len(), 1);
    assert_eq!(
        role_events[0].event().entity_id(),
        manager.local_node_id().as_str()
    );
    manager.close().expect("close");

    let reopened = open_manager(&directory, local_main());
    assert_eq!(
        reopened.local_node().expect("local").role(),
        NodeRole::Child
    );
    assert_eq!(reopened.main_node().expect("main").value(), &authority);
    assert_eq!(
        reopened
            .pending_outbox_events()
            .expect("pending outbox")
            .iter()
            .filter(|event| event.event().kind().as_str() == "local_became_child")
            .count(),
        1
    );
}

// Promotes one child and retires its previous main in the same transaction.
#[test]
fn child_becomes_main_and_retires_previous_authority() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (manager, authority, local_revision) = configured_child(&directory);
    let readiness =
        ReadinessMock::new(authority.identity().node_id().clone(), ReadinessMode::Exact);
    let changed = manager
        .transition_local_role(
            "detach-home",
            local_revision,
            LocalNodeRoleTransition::BecomeMain,
            UnixMilliseconds::new(3_000),
            &readiness,
        )
        .expect("become main");
    assert_eq!(readiness.call_count(), 1);
    assert_eq!(changed.value().role(), NodeRole::Main);
    assert_eq!(changed.revision(), 3);
    assert_eq!(manager.main_node().expect("main").value(), changed.value());
    let retired = manager
        .node(authority.identity().node_id())
        .expect("retired authority");
    assert_eq!(retired.value().role(), NodeRole::Main);
    assert_eq!(retired.value().state(), NodeState::Removed);
    assert_eq!(retired.revision(), 2);
    let mut role_kinds = manager
        .outbox_events()
        .expect("outbox")
        .into_iter()
        .map(|event| event.event().kind().as_str().to_string())
        .filter(|kind| kind.starts_with("local_became_"))
        .collect::<Vec<_>>();
    role_kinds.sort();
    assert_eq!(
        role_kinds,
        vec![
            "local_became_child".to_string(),
            "local_became_main".to_string()
        ]
    );
    manager.close().expect("close");

    let reopened = open_manager(&directory, local_main());
    assert_eq!(reopened.local_node().expect("local").role(), NodeRole::Main);
    assert_eq!(
        reopened
            .node(authority.identity().node_id())
            .expect("old main")
            .value()
            .state(),
        NodeState::Removed
    );
}

// Rejects every mismatched proof dimension and provider failure before persistence.
#[test]
fn readiness_proof_failure_matrix_leaves_authority_unchanged() {
    for (index, mode) in [
        ReadinessMode::WrongLocalIdentity,
        ReadinessMode::WrongRoles,
        ReadinessMode::WrongAuthority,
        ReadinessMode::Expired,
        ReadinessMode::Future,
        ReadinessMode::Failure,
    ]
    .into_iter()
    .enumerate()
    {
        let directory = tempfile::tempdir().expect("temporary directory");
        let manager = open_manager(&directory, local_main());
        let authority = destination_main('4', '5', '6', "destination.local");
        let readiness = ReadinessMock::new(authority.identity().node_id().clone(), mode);
        assert!(matches!(
            manager.transition_local_role(
                &format!("proof-failure-{index}"),
                1,
                LocalNodeRoleTransition::BecomeChild {
                    main: authority.clone(),
                },
                UnixMilliseconds::new(5_000),
                &readiness,
            ),
            Err(NodeManagerError::InvalidLocalRoleTransition { .. })
        ));
        assert_eq!(readiness.call_count(), 1);
        assert_eq!(manager.local_node().expect("local").role(), NodeRole::Main);
        assert!(matches!(
            manager.node(authority.identity().node_id()),
            Err(NodeManagerError::Database(DatabaseError::NotFound { .. }))
        ));
        assert_eq!(
            manager
                .outbox_events()
                .expect("outbox")
                .iter()
                .filter(|event| event.event().kind().as_str().starts_with("local_became_"))
                .count(),
            0
        );
    }
}

// Rejects invalid destination state, identity, and uniqueness before readiness.
#[test]
fn destination_main_validation_matrix_fails_closed() {
    let invalid_authorities = [
        node(
            '4',
            '5',
            '6',
            "Child",
            NodeRole::Child,
            NodeState::Active,
            "child.local",
            1_500,
        ),
        node(
            '4',
            '5',
            '6',
            "Pending main",
            NodeRole::Main,
            NodeState::Pending,
            "pending.local",
            1_500,
        ),
        local_main(),
        node(
            '4',
            '2',
            '6',
            "Duplicate machine",
            NodeRole::Main,
            NodeState::Active,
            "duplicate.local",
            1_500,
        ),
    ];
    for (index, authority) in invalid_authorities.into_iter().enumerate() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let manager = open_manager(&directory, local_main());
        let readiness =
            ReadinessMock::new(authority.identity().node_id().clone(), ReadinessMode::Exact);
        assert!(manager
            .transition_local_role(
                &format!("invalid-authority-{index}"),
                1,
                LocalNodeRoleTransition::BecomeChild { main: authority },
                UnixMilliseconds::new(2_000),
                &readiness,
            )
            .is_err());
        assert_eq!(readiness.call_count(), 0);
        assert_eq!(manager.local_node().expect("local").role(), NodeRole::Main);
    }

    let directory = tempfile::tempdir().expect("temporary directory");
    let inactive = node(
        '1',
        '2',
        '3',
        "Inactive",
        NodeRole::Main,
        NodeState::Draining,
        "homeai.local",
        1_000,
    );
    let manager = open_manager(&directory, inactive);
    let authority = destination_main('4', '5', '6', "destination.local");
    let readiness =
        ReadinessMock::new(authority.identity().node_id().clone(), ReadinessMode::Exact);
    assert!(matches!(
        manager.transition_local_role(
            "inactive-local",
            1,
            LocalNodeRoleTransition::BecomeChild { main: authority },
            UnixMilliseconds::new(2_000),
            &readiness,
        ),
        Err(NodeManagerError::InvalidLocalRoleTransition { .. })
    ));
    assert_eq!(readiness.call_count(), 0);
}

// Rolls back both authority records and the outbox when optimistic revision fails.
#[test]
fn stale_local_revision_rolls_back_complete_role_transaction() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let manager = open_manager(&directory, local_main());
    let authority = destination_main('4', '5', '6', "destination.local");
    let readiness =
        ReadinessMock::new(authority.identity().node_id().clone(), ReadinessMode::Exact);
    assert!(matches!(
        manager.transition_local_role(
            "stale-role",
            77,
            LocalNodeRoleTransition::BecomeChild {
                main: authority.clone(),
            },
            UnixMilliseconds::new(2_000),
            &readiness,
        ),
        Err(NodeManagerError::Database(DatabaseError::Conflict { .. }))
    ));
    assert_eq!(manager.local_node().expect("local").role(), NodeRole::Main);
    assert!(matches!(
        manager.node(authority.identity().node_id()),
        Err(NodeManagerError::Database(DatabaseError::NotFound { .. }))
    ));
    assert_eq!(
        manager
            .outbox_events()
            .expect("outbox")
            .iter()
            .filter(|event| event.event().kind().as_str() == "local_became_child")
            .count(),
        0
    );

    assert!(matches!(
        manager.transition_local_role(
            "backwards-role-time",
            1,
            LocalNodeRoleTransition::BecomeChild {
                main: authority.clone(),
            },
            UnixMilliseconds::new(999),
            &readiness,
        ),
        Err(NodeManagerError::InvalidLocalRoleTransition { .. })
    ));
    assert_eq!(manager.local_node().expect("local").role(), NodeRole::Main);
    assert!(matches!(
        manager.node(authority.identity().node_id()),
        Err(NodeManagerError::Database(DatabaseError::NotFound { .. }))
    ));
}

// Allows exactly one concurrent destination to acquire main authority.
#[test]
fn concurrent_role_changes_have_one_atomic_winner() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let manager = Arc::new(open_manager(&directory, local_main()));
    let destinations = [
        destination_main('4', '5', '6', "first.local"),
        destination_main('7', '8', '9', "second.local"),
    ];
    let barrier = Arc::new(Barrier::new(2));
    let mut workers = Vec::new();
    for (index, authority) in destinations.iter().cloned().enumerate() {
        let manager = Arc::clone(&manager);
        let readiness = BarrierReadiness {
            authority_node_id: authority.identity().node_id().clone(),
            barrier: Arc::clone(&barrier),
        };
        workers.push(thread::spawn(move || {
            manager.transition_local_role(
                &format!("concurrent-role-{index}"),
                1,
                LocalNodeRoleTransition::BecomeChild { main: authority },
                UnixMilliseconds::new(2_000),
                &readiness,
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
    let main = manager.main_node().expect("winning main");
    assert!(destinations
        .iter()
        .any(|authority| authority.identity() == main.value().identity()));
    assert_eq!(manager.local_node().expect("local").role(), NodeRole::Child);
    assert_eq!(
        manager
            .outbox_events()
            .expect("outbox")
            .iter()
            .filter(|event| event.event().kind().as_str() == "local_became_child")
            .count(),
        1
    );
}

// Observes completed target roles without repeating readiness or outbox writes.
#[test]
fn completed_role_requests_are_idempotent_without_external_work() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let manager = open_manager(&directory, local_main());
    let already_main = manager
        .transition_local_role(
            "already-main",
            1,
            LocalNodeRoleTransition::BecomeMain,
            UnixMilliseconds::new(1_500),
            &PanicReadiness,
        )
        .expect("already main");
    assert_eq!(already_main.revision(), 1);
    assert!(already_main.event().is_none());

    let authority = destination_main('4', '5', '6', "destination.local");
    let readiness =
        ReadinessMock::new(authority.identity().node_id().clone(), ReadinessMode::Exact);
    let first = manager
        .transition_local_role(
            "move",
            1,
            LocalNodeRoleTransition::BecomeChild {
                main: authority.clone(),
            },
            UnixMilliseconds::new(2_000),
            &readiness,
        )
        .expect("first move");
    let replay = manager
        .transition_local_role(
            "different-replay-key",
            1,
            LocalNodeRoleTransition::BecomeChild { main: authority },
            UnixMilliseconds::new(9_000),
            &PanicReadiness,
        )
        .expect("observed move");
    assert_eq!(replay.value(), first.value());
    assert_eq!(replay.revision(), first.revision());
    assert!(replay.event().is_none());
    let other_authority = destination_main('7', '8', '9', "other.local");
    assert!(matches!(
        manager.transition_local_role(
            "different-authority",
            replay.revision(),
            LocalNodeRoleTransition::BecomeChild {
                main: other_authority,
            },
            UnixMilliseconds::new(10_000),
            &PanicReadiness,
        ),
        Err(NodeManagerError::InvalidLocalRoleTransition { .. })
    ));
    assert_eq!(
        manager
            .outbox_events()
            .expect("outbox")
            .iter()
            .filter(|event| event.event().kind().as_str() == "local_became_child")
            .count(),
        1
    );
}

// Commits pairing-owned state with local child authority and exactly replays the completed role.
#[test]
fn paired_child_transaction_is_atomic_and_restart_safe() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = database(&directory);
    let manager = NodeManager::open(database, local_main(), "initialize-node")
        .expect("node manager")
        .0;
    let authority = destination_main('4', '5', '6', "destination.local");
    let readiness =
        ReadinessMock::new(authority.identity().node_id().clone(), ReadinessMode::Exact);
    let transaction = DatabaseTransaction::new("pairing:activate").expect("transaction");
    let first = manager
        .activate_paired_child_with_transaction(
            "pairing:activate",
            1,
            &authority,
            UnixMilliseconds::new(2_000),
            &readiness,
            transaction,
        )
        .expect("activate paired child");
    assert_eq!(first.value().role(), NodeRole::Child);
    assert!(first.event().is_some());
    assert_eq!(manager.main_node().expect("main").value(), &authority);
    assert_eq!(readiness.call_count(), 1);

    let replay = manager
        .activate_paired_child_with_transaction(
            "pairing:activate",
            first.revision(),
            &authority,
            UnixMilliseconds::new(3_000),
            &PanicReadiness,
            DatabaseTransaction::new("pairing:activate").expect("replay transaction"),
        )
        .expect("replay paired child");
    assert_eq!(replay.value(), first.value());
    assert!(replay.event().is_none());
    assert_eq!(
        manager
            .outbox_events()
            .expect("outbox")
            .iter()
            .filter(|event| event.event().kind().as_str() == "local_became_child")
            .count(),
        1
    );
}

// Rejects mismatched transaction identity before readiness or Node persistence.
#[test]
fn paired_child_transaction_rejects_identity_drift_without_mutation() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let manager = open_manager(&directory, local_main());
    let authority = destination_main('4', '5', '6', "destination.local");
    let readiness =
        ReadinessMock::new(authority.identity().node_id().clone(), ReadinessMode::Exact);
    let result = manager.activate_paired_child_with_transaction(
        "pairing:activate",
        1,
        &authority,
        UnixMilliseconds::new(2_000),
        &readiness,
        DatabaseTransaction::new("pairing:drift").expect("transaction"),
    );
    assert!(matches!(
        result,
        Err(NodeManagerError::InvalidLocalRoleTransition { .. })
    ));
    assert_eq!(readiness.call_count(), 0);
    assert_eq!(manager.local_node().expect("local").role(), NodeRole::Main);
    assert!(manager.node(authority.identity().node_id()).is_err());
}

// Enforces proof identity separation and the exact five-minute validity bound.
#[test]
fn readiness_proof_constructor_rejects_invalid_contracts() {
    let local_node_id = NodeId::parse(&identity('1')).expect("local");
    let authority_node_id = NodeId::parse(&identity('4')).expect("authority");
    let issued_at = UnixMilliseconds::new(1_000);
    assert!(LocalNodeRoleTransitionProof::new(
        local_node_id.clone(),
        NodeRole::Main,
        NodeRole::Main,
        authority_node_id.clone(),
        issued_at,
        UnixMilliseconds::new(2_000),
    )
    .is_err());
    assert!(LocalNodeRoleTransitionProof::new(
        local_node_id.clone(),
        NodeRole::Main,
        NodeRole::Child,
        local_node_id.clone(),
        issued_at,
        UnixMilliseconds::new(2_000),
    )
    .is_err());
    assert!(LocalNodeRoleTransitionProof::new(
        local_node_id.clone(),
        NodeRole::Main,
        NodeRole::Child,
        authority_node_id.clone(),
        issued_at,
        UnixMilliseconds::new(999),
    )
    .is_err());
    assert!(LocalNodeRoleTransitionProof::new(
        local_node_id.clone(),
        NodeRole::Main,
        NodeRole::Child,
        authority_node_id.clone(),
        issued_at,
        UnixMilliseconds::new(301_001),
    )
    .is_err());
    assert!(LocalNodeRoleTransitionProof::new(
        local_node_id,
        NodeRole::Main,
        NodeRole::Child,
        authority_node_id,
        issued_at,
        UnixMilliseconds::new(301_000),
    )
    .is_ok());
}
