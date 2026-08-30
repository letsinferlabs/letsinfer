// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use li_authentication_manager::PeerCredentialStore;
use li_core_interface::{
    DisplayName, EntityTimestamps, InstallationId, MachineId, Node, NodeAddress, NodeId,
    NodeIdentity, NodeRole, NodeState, Sha256Digest, UnixMilliseconds,
};
use li_database::{DatabaseConfiguration, DatabaseError, DatabaseManager};
use li_node_manager::{
    DatabasePeerCredentialStore, LocalNodeRoleReadinessProvider, LocalNodeRoleTransition,
    LocalNodeRoleTransitionProof, NodeManager, NodeManagerError, NodePairedChildActivationRequest,
    NodePairedMainRestorationRequest, NodePairingActivationAuthority,
    NodePairingActivationAuthorityError, NodePairingActivationAuthorityPort,
    NodePairingAuthorityDisposition, NodePairingCredentials,
};
use li_pairing_manager::{PairingClock, PairingError};

// Supplies one deterministic role-transition time.
struct TestClock;

impl PairingClock for TestClock {
    // Returns one fixed current timestamp for every exact replay.
    fn now(&self) -> Result<UnixMilliseconds, PairingError> {
        Ok(UnixMilliseconds::new(2_000))
    }
}

// Selects one deterministic readiness decision for transaction atomicity tests.
struct TestReadiness {
    authority_node_id: NodeId,
    available: bool,
}

impl LocalNodeRoleReadinessProvider for TestReadiness {
    // Returns one exact role proof or rejects before the shared transaction is written.
    fn proof(
        &self,
        local: &Node,
        transition: &LocalNodeRoleTransition,
        now: UnixMilliseconds,
    ) -> Result<LocalNodeRoleTransitionProof, NodeManagerError> {
        if !self.available {
            return Err(NodeManagerError::InvalidLocalRoleTransition {
                reason: "fixture readiness rejected the transition",
            });
        }
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

// Returns one repeated canonical identity.
fn identity(character: char) -> String {
    character.to_string().repeat(32)
}

// Returns one repeated canonical digest.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
}

// Returns one coherent active Node with explicit role and authority identity.
#[allow(clippy::too_many_arguments)]
fn node(
    node_character: char,
    machine_character: char,
    installation_character: char,
    display_name: &str,
    address: &str,
    role: NodeRole,
) -> Node {
    Node::new(
        NodeIdentity::new(
            NodeId::parse(&identity(node_character)).expect("node id"),
            MachineId::parse(&identity(machine_character)).expect("machine id"),
            InstallationId::parse(&installation_character.to_string().repeat(64))
                .expect("installation id"),
        ),
        DisplayName::parse(display_name).expect("display name"),
        role,
        NodeState::Active,
        NodeAddress::parse(address).expect("address"),
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(1_000))
            .expect("timestamps"),
    )
}

// Opens one isolated database manager.
fn database(directory: &tempfile::TempDir, name: &str) -> Arc<DatabaseManager> {
    Arc::new(
        DatabaseManager::open(DatabaseConfiguration::new(directory.path().join(name)))
            .expect("database"),
    )
}

// Returns one complete active public pairing credential package.
fn credentials(expires_at: u64) -> NodePairingCredentials {
    NodePairingCredentials::new(
        b"main-public-key".to_vec(),
        b"main-ca".to_vec(),
        b"child-certificate".to_vec(),
        b"membership-signature".to_vec(),
        digest('b'),
        UnixMilliseconds::new(500),
        UnixMilliseconds::new(expires_at),
    )
    .expect("credentials")
}

// Composes one authority over the exact shared manager database and readiness decision.
fn authority(
    database: Arc<DatabaseManager>,
    manager: Arc<NodeManager>,
    main: &Node,
    available: bool,
) -> NodePairingActivationAuthority {
    NodePairingActivationAuthority::new(
        manager,
        database,
        Arc::new(TestClock),
        Arc::new(TestReadiness {
            authority_node_id: main.identity().node_id().clone(),
            available,
        }),
    )
    .expect("authority")
}

// Proves credential and role activation/restoration are atomic, exact, and replay safe.
#[test]
fn paired_authority_commits_and_restores_credential_and_role_atomically() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = database(&directory, "core.sqlite3");
    let local = node(
        '1',
        '2',
        '3',
        "Candidate",
        "candidate.local",
        NodeRole::Main,
    );
    let main = node('4', '5', '6', "Main", "main.local", NodeRole::Main);
    let manager = Arc::new(
        NodeManager::open(database.clone(), local, "initialize-node")
            .expect("manager")
            .0,
    );
    let authority = authority(database.clone(), manager.clone(), &main, true);
    let activation = NodePairedChildActivationRequest::new(
        "pairing:activate".to_string(),
        main.clone(),
        digest('c'),
        credentials(500_000),
    )
    .expect("activation");
    let applied = authority
        .activate_paired_child(&activation)
        .expect("activate");
    assert_eq!(
        applied.disposition(),
        NodePairingAuthorityDisposition::Applied
    );
    assert_eq!(applied.local().role(), NodeRole::Child);
    let replayed = authority
        .activate_paired_child(&activation)
        .expect("replay activation");
    assert_eq!(
        replayed.disposition(),
        NodePairingAuthorityDisposition::Replayed
    );
    assert_eq!(manager.main_node().expect("main").value(), &main);
    assert_eq!(
        DatabasePeerCredentialStore::new(database.clone())
            .matching_peer_credentials(&digest('c'), 2)
            .expect("credentials")
            .len(),
        1
    );

    let conflicting = NodePairedChildActivationRequest::new(
        "pairing:activate-conflict".to_string(),
        main.clone(),
        digest('c'),
        credentials(600_000),
    )
    .expect("conflicting activation");
    assert_eq!(
        authority.activate_paired_child(&conflicting),
        Err(NodePairingActivationAuthorityError::AuthorityConflict)
    );

    let restoration = NodePairedMainRestorationRequest::new(
        "pairing:restore".to_string(),
        main.clone(),
        digest('c'),
        credentials(500_000),
    )
    .expect("restoration");
    let restored = authority
        .restore_paired_main(&restoration)
        .expect("restore");
    assert_eq!(
        restored.disposition(),
        NodePairingAuthorityDisposition::Applied
    );
    assert_eq!(restored.local().role(), NodeRole::Main);
    assert_eq!(
        authority
            .restore_paired_main(&restoration)
            .expect("replay restoration")
            .disposition(),
        NodePairingAuthorityDisposition::Replayed
    );
    assert!(DatabasePeerCredentialStore::new(database)
        .matching_peer_credentials(&digest('c'), 2)
        .expect("restored credentials")
        .is_empty());
    assert!(matches!(
        manager.node(main.identity().node_id()),
        Err(NodeManagerError::Database(DatabaseError::NotFound { .. }))
    ));
}

// Rejects a different credential database before any role or peer state can diverge.
#[test]
fn pairing_authority_requires_the_manager_database_identity() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let other = database(&directory, "other.sqlite3");
    let database = database(&directory, "core.sqlite3");
    let local = node(
        '1',
        '2',
        '3',
        "Candidate",
        "candidate.local",
        NodeRole::Main,
    );
    let main = node('4', '5', '6', "Main", "main.local", NodeRole::Main);
    let manager = Arc::new(
        NodeManager::open(database, local, "initialize-node")
            .expect("manager")
            .0,
    );
    assert!(matches!(
        NodePairingActivationAuthority::new(
            manager,
            other,
            Arc::new(TestClock),
            Arc::new(TestReadiness {
                authority_node_id: main.identity().node_id().clone(),
                available: true,
            }),
        ),
        Err(NodePairingActivationAuthorityError::InvalidRequest)
    ));
}

// Proves readiness failure leaves credential, remote authority, and local role unchanged.
#[test]
fn pairing_authority_failure_rolls_back_without_partial_database_state() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = database(&directory, "core.sqlite3");
    let local = node(
        '1',
        '2',
        '3',
        "Candidate",
        "candidate.local",
        NodeRole::Main,
    );
    let main = node('4', '5', '6', "Main", "main.local", NodeRole::Main);
    let manager = Arc::new(
        NodeManager::open(database.clone(), local, "initialize-node")
            .expect("manager")
            .0,
    );
    let authority = authority(database.clone(), manager.clone(), &main, false);
    let request = NodePairedChildActivationRequest::new(
        "pairing:rejected".to_string(),
        main.clone(),
        digest('c'),
        credentials(500_000),
    )
    .expect("activation");
    assert_eq!(
        authority.activate_paired_child(&request),
        Err(NodePairingActivationAuthorityError::AuthorityConflict)
    );
    assert_eq!(manager.local_node().expect("local").role(), NodeRole::Main);
    assert!(manager.node(main.identity().node_id()).is_err());
    assert!(DatabasePeerCredentialStore::new(database)
        .matching_peer_credentials(&digest('c'), 2)
        .expect("credentials")
        .is_empty());
}
