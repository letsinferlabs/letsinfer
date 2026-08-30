// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use li_core_interface::{
    DisplayName, EntityTimestamps, InstallationId, MachineId, Node, NodeAddress, NodeId,
    NodeIdentity, NodeRole, NodeState, UnixMilliseconds,
};
use li_database::{DatabaseClock, DatabaseConfiguration, DatabaseError, DatabaseManager};
use li_node_manager::{NodeManager, NodeManagerError, NodeManagerEvent, NodeTransition};

// Supplies deterministic increasing database commit timestamps.
struct TestClock(AtomicI64);

impl DatabaseClock for TestClock {
    // Returns one unique commit timestamp.
    fn now_unix_milliseconds(&self) -> Result<i64, DatabaseError> {
        Ok(self.0.fetch_add(1, Ordering::SeqCst))
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
fn main_node() -> Node {
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

// Returns one ordinary pending child fixture.
fn child_node() -> Node {
    node(
        '4',
        '5',
        '6',
        "Node 2",
        NodeRole::Child,
        NodeState::Pending,
        "homeai-node-2.local",
        1_000,
    )
}

// Opens one NodeManager from the supplied local node.
fn open_manager(directory: &tempfile::TempDir, local: Node) -> NodeManager {
    NodeManager::open(database(directory), local, "initialize-node")
        .expect("node manager")
        .0
}

// Enrolls one child idempotently and reconstructs it after manager restart.
#[test]
fn main_enrolls_replays_and_reopens_pending_child() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let manager = open_manager(&directory, main_node());
    let child = child_node();
    let enrolled = manager
        .enroll_child("enroll-child", child.clone())
        .expect("enroll");
    assert_eq!(enrolled.revision(), 1);
    assert_eq!(
        enrolled.event(),
        Some(&NodeManagerEvent::NodeEnrolled {
            node_id: child.identity().node_id().clone()
        })
    );
    let replay = manager
        .enroll_child("enroll-child", child.clone())
        .expect("replay");
    assert_eq!(replay.revision(), enrolled.revision());
    assert!(replay.event().is_none());
    assert_eq!(manager.nodes().expect("nodes").len(), 2);
    manager.close().expect("close");

    let manager = open_manager(&directory, main_node());
    let reopened = manager
        .node(child.identity().node_id())
        .expect("reopened child");
    assert_eq!(reopened.value(), &child);
    assert_eq!(reopened.revision(), 1);
}

// Rejects topology mutation from a child local node.
#[test]
fn child_cannot_enroll_or_transition_nodes() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let local_child = node(
        '1',
        '2',
        '3',
        "Child",
        NodeRole::Child,
        NodeState::Active,
        "child.local",
        1_000,
    );
    let manager = open_manager(&directory, local_child);
    assert_eq!(
        manager
            .enroll_child("enroll", child_node())
            .expect_err("authority"),
        NodeManagerError::NotMain
    );
    assert_eq!(
        manager
            .transition_child(
                "transition",
                &NodeId::parse(&identity('4')).expect("node"),
                1,
                NodeTransition::Activate,
                UnixMilliseconds::new(2_000),
            )
            .expect_err("authority"),
        NodeManagerError::NotMain
    );
}

// Rejects wrong role, state, and local-main identity at enrollment.
#[test]
fn enrollment_requires_one_distinct_pending_child() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let manager = open_manager(&directory, main_node());
    let invalid = [
        node(
            '4',
            '5',
            '6',
            "Main",
            NodeRole::Main,
            NodeState::Pending,
            "other-main.local",
            1_000,
        ),
        node(
            '4',
            '5',
            '6',
            "Active",
            NodeRole::Child,
            NodeState::Active,
            "active.local",
            1_000,
        ),
        node(
            '1',
            '5',
            '6',
            "Local",
            NodeRole::Child,
            NodeState::Pending,
            "local-copy.local",
            1_000,
        ),
    ];
    for child in invalid {
        assert!(matches!(
            manager.enroll_child("invalid", child),
            Err(NodeManagerError::InvalidNodeEnrollment { .. })
        ));
    }
}

// Rejects duplicate node, machine, installation, address, and divergent replay identities.
#[test]
fn enrollment_identity_matrix_is_globally_unique() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let manager = open_manager(&directory, main_node());
    let first = child_node();
    manager
        .enroll_child("enroll-first", first.clone())
        .expect("first");
    let conflicts = [
        node(
            '4',
            '7',
            '8',
            "Same node",
            NodeRole::Child,
            NodeState::Pending,
            "same-node.local",
            1_000,
        ),
        node(
            '7',
            '5',
            '8',
            "Same machine",
            NodeRole::Child,
            NodeState::Pending,
            "same-machine.local",
            1_000,
        ),
        node(
            '7',
            '8',
            '6',
            "Same install",
            NodeRole::Child,
            NodeState::Pending,
            "same-install.local",
            1_000,
        ),
        node(
            '7',
            '8',
            '9',
            "Same address",
            NodeRole::Child,
            NodeState::Pending,
            "homeai-node-2.local",
            1_000,
        ),
    ];
    for (index, child) in conflicts.into_iter().enumerate() {
        assert!(matches!(
            manager.enroll_child(&format!("conflict-{index}"), child),
            Err(NodeManagerError::NodeIdentityConflict { .. })
        ));
    }
}

// Applies every supported child lifecycle transition with stable event vocabulary.
#[test]
fn child_lifecycle_covers_activate_pause_resume_offline_and_remove() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let manager = open_manager(&directory, main_node());
    let child = child_node();
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
    assert_eq!(activated.value().state(), NodeState::Active);
    assert!(matches!(
        activated.event(),
        Some(NodeManagerEvent::NodeActivated { .. })
    ));
    let replay = manager
        .transition_child(
            "activate",
            child.identity().node_id(),
            enrolled.revision(),
            NodeTransition::Activate,
            UnixMilliseconds::new(2_000),
        )
        .expect("replay");
    assert_eq!(replay.revision(), activated.revision());
    assert!(replay.event().is_none());

    let paused = manager
        .transition_child(
            "pause",
            child.identity().node_id(),
            activated.revision(),
            NodeTransition::Pause,
            UnixMilliseconds::new(2_100),
        )
        .expect("pause");
    assert_eq!(paused.value().state(), NodeState::Draining);
    let resumed = manager
        .transition_child(
            "resume",
            child.identity().node_id(),
            paused.revision(),
            NodeTransition::Resume,
            UnixMilliseconds::new(2_200),
        )
        .expect("resume");
    assert_eq!(resumed.value().state(), NodeState::Active);
    let offline = manager
        .transition_child(
            "offline",
            child.identity().node_id(),
            resumed.revision(),
            NodeTransition::MarkOffline,
            UnixMilliseconds::new(2_300),
        )
        .expect("offline");
    assert_eq!(offline.value().state(), NodeState::Offline);
    let active = manager
        .transition_child(
            "resume-offline",
            child.identity().node_id(),
            offline.revision(),
            NodeTransition::Resume,
            UnixMilliseconds::new(2_400),
        )
        .expect("resume offline");
    let draining = manager
        .transition_child(
            "drain-remove",
            child.identity().node_id(),
            active.revision(),
            NodeTransition::Pause,
            UnixMilliseconds::new(2_500),
        )
        .expect("drain");
    let removed = manager
        .transition_child(
            "remove",
            child.identity().node_id(),
            draining.revision(),
            NodeTransition::Remove,
            UnixMilliseconds::new(2_600),
        )
        .expect("remove");
    assert_eq!(removed.value().state(), NodeState::Removed);
    assert!(matches!(
        removed.event(),
        Some(NodeManagerEvent::NodeRemoved { .. })
    ));
}

// Rejects every unsupported state/action pair without advancing its revision.
#[test]
fn invalid_child_transition_matrix_fails_closed() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let manager = open_manager(&directory, main_node());
    let child = child_node();
    let enrolled = manager
        .enroll_child("enroll", child.clone())
        .expect("enroll");
    for transition in [
        NodeTransition::Pause,
        NodeTransition::Resume,
        NodeTransition::MarkOffline,
    ] {
        assert!(matches!(
            manager.transition_child(
                "invalid-pending",
                child.identity().node_id(),
                enrolled.revision(),
                transition,
                UnixMilliseconds::new(2_000),
            ),
            Err(NodeManagerError::InvalidNodeTransition { .. })
        ));
    }
    let active = manager
        .transition_child(
            "activate",
            child.identity().node_id(),
            enrolled.revision(),
            NodeTransition::Activate,
            UnixMilliseconds::new(2_000),
        )
        .expect("activate");
    assert!(matches!(
        manager.transition_child(
            "remove-active",
            child.identity().node_id(),
            active.revision(),
            NodeTransition::Remove,
            UnixMilliseconds::new(2_100),
        ),
        Err(NodeManagerError::InvalidNodeTransition { .. })
    ));
    assert_eq!(
        manager
            .node(child.identity().node_id())
            .expect("current")
            .revision(),
        active.revision()
    );
}

// Allows exactly one of two concurrent transitions from the same optimistic revision.
#[test]
fn concurrent_child_transitions_have_one_durable_winner() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let manager = Arc::new(open_manager(&directory, main_node()));
    let child = child_node();
    let enrolled = manager
        .enroll_child("enroll", child.clone())
        .expect("enroll");
    let mut workers = Vec::new();
    for (key, transition) in [
        ("activate", NodeTransition::Activate),
        ("remove", NodeTransition::Remove),
    ] {
        let manager = Arc::clone(&manager);
        let node_id = child.identity().node_id().clone();
        let revision = enrolled.revision();
        workers.push(thread::spawn(move || {
            manager.transition_child(
                key,
                &node_id,
                revision,
                transition,
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
    let current = manager
        .node(child.identity().node_id())
        .expect("current child");
    assert_eq!(current.revision(), 2);
    assert!(matches!(
        current.value().state(),
        NodeState::Active | NodeState::Removed
    ));
}

// Rejects a child transition that targets the local main identity.
#[test]
fn child_transition_never_mutates_local_main() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let manager = open_manager(&directory, main_node());
    assert!(matches!(
        manager.transition_child(
            "pause-main",
            manager.local_node_id(),
            1,
            NodeTransition::Pause,
            UnixMilliseconds::new(2_000),
        ),
        Err(NodeManagerError::InvalidNodeEnrollment { .. })
    ));
    assert_eq!(
        manager.local_node().expect("main").state(),
        NodeState::Active
    );
}
