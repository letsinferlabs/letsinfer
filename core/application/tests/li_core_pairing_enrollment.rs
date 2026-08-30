// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use li_authentication_manager::{
    ApiKeyMaterialProvider, AuthenticationClock, AuthenticationError, AuthenticationManager,
    AuthenticationRecord, AuthenticationRotation, AuthenticationStore, AuthenticationStoreError,
    PeerCredential, PeerCredentialDirection, PeerCredentialError, PeerCredentialState,
    PeerCredentialStore, VersionedAuthenticationRecord,
};
use li_core_application::{
    CorePairingEnrollmentCoordinator, CorePairingEnrollmentError, DatabasePairingStore,
    DatabasePeerCredentialStore,
};
use li_core_interface::{
    ApiKeyId, CredentialId, DisplayName, EntityTimestamps, InstallationId, MachineId, Node,
    NodeAddress, NodeId, NodeIdentity, NodeRole, NodeState, PairingInviteId, Sha256Digest,
    UnixMilliseconds,
};
use li_database::{
    DatabaseClock, DatabaseCollection, DatabaseCommand, DatabaseCommitDisposition,
    DatabaseConfiguration, DatabaseError, DatabaseManager, DatabaseQuery, DatabaseRecord,
    DatabaseResult, DatabaseRevision,
};
use li_node_manager::NodeManager;
use li_pairing_manager::{
    PairingAdvertisement, PairingCandidate, PairingClock, PairingContext, PairingCredentials,
    PairingDirectLinkProvider, PairingDiscoveryProvider, PairingError, PairingManager,
    PairingMaterialProvider, PairingMembershipState, PairingMode, PairingResult,
    PairingSetupCodeProvider, PairingStore, PairingTrustProvider, PairingWindowRequest,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// Mirrors the closed outbox shape only to inject one final-mutation conflict.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct OutboxConflictRecord {
    event_id: String,
    kind: String,
    entity_id: String,
    occurred_at_unix_milliseconds: u64,
    state: String,
    acknowledged_at_unix_milliseconds: Option<u64>,
}

impl DatabaseRecord for OutboxConflictRecord {
    const COLLECTION: DatabaseCollection = DatabaseCollection::Outbox;

    // Returns the exact final outbox target selected by NodeManager.
    fn identifier(&self) -> &str {
        &self.event_id
    }
}

// Supplies deterministic database commit time.
struct TestDatabaseClock(AtomicU64);

impl DatabaseClock for TestDatabaseClock {
    // Returns one increasing database timestamp.
    fn now_unix_milliseconds(&self) -> Result<i64, DatabaseError> {
        i64::try_from(self.0.fetch_add(1, Ordering::SeqCst)).map_err(|_| DatabaseError::Closed)
    }
}

// Supplies deterministic pairing approval time with explicit test mutation.
struct TestPairingClock(AtomicU64);

impl TestPairingClock {
    // Changes time observed by subsequent pairing operations.
    fn set(&self, value: u64) {
        self.0.store(value, Ordering::SeqCst);
    }
}

impl PairingClock for TestPairingClock {
    // Returns the exact configured pairing time.
    fn now(&self) -> Result<UnixMilliseconds, PairingError> {
        Ok(UnixMilliseconds::new(self.0.load(Ordering::SeqCst)))
    }
}

// Supplies deterministic bounded invitation bytes.
struct TestPairingMaterial(AtomicU8);

impl PairingMaterialProvider for TestPairingMaterial {
    // Fills one destination with a unique deterministic byte.
    fn fill(&self, destination: &mut [u8]) -> Result<(), PairingError> {
        destination.fill(self.0.fetch_add(1, Ordering::SeqCst));
        Ok(())
    }
}

// Derives one deterministic installation-bound setup code for application composition tests.
struct TestSetupCode;

impl PairingSetupCodeProvider for TestSetupCode {
    // Returns the exact eight-digit fixture without storing it in persistence.
    fn derive(
        &self,
        _installation_id: &InstallationId,
        _invite_id: &PairingInviteId,
        _nonce: &Sha256Digest,
        _salt: &[u8; 16],
    ) -> Result<[u8; 8], PairingError> {
        Ok(*b"12345678")
    }
}

// Keeps discovery observable only through PairingManager state in composition tests.
struct TestDiscovery;

impl PairingDiscoveryProvider for TestDiscovery {
    // Accepts one validated advertisement without native publication.
    fn publish(&self, _advertisement: &PairingAdvertisement) -> Result<(), PairingError> {
        Ok(())
    }

    // Completes deterministic cleanup without native state.
    fn unpublish(&self, _invite_id: &PairingInviteId) {}
}

// Refuses an unused direct-link path.
struct TestDirectLink;

impl PairingDirectLinkProvider for TestDirectLink {
    // Rejects accidental direct-link use in LAN and remote tests.
    fn verify(
        &self,
        _interface: &li_core_interface::NetworkInterfaceName,
        _peer_address: &NodeAddress,
    ) -> Result<(), PairingError> {
        Err(PairingError::DirectLinkUnavailable)
    }
}

// Issues exact deterministic certificate identity and validity facts.
struct TestTrust;

impl PairingTrustProvider for TestTrust {
    // Returns the canonical fixture public-key fingerprint after proof shape validation.
    fn verify_candidate(
        &self,
        public_key: &[u8],
        transcript: &[u8],
        signature: &[u8],
    ) -> Result<Sha256Digest, PairingError> {
        if public_key.len() != 128 || transcript.is_empty() || signature != b"proof" {
            return Err(PairingError::Unauthorized);
        }
        Ok(digest('9'))
    }

    // Returns one complete exact public credential package.
    fn issue_membership(
        &self,
        _context: &PairingContext,
        _candidate: &PairingCandidate,
        _public_key_fingerprint: &Sha256Digest,
        _state: PairingMembershipState,
        _approval_expires_at: Option<UnixMilliseconds>,
    ) -> Result<PairingCredentials, PairingError> {
        PairingCredentials::new(
            b"site-public-key".to_vec(),
            b"site-ca-certificate".to_vec(),
            b"member-certificate".to_vec(),
            b"membership-signature".to_vec(),
            digest('a'),
            UnixMilliseconds::new(500),
            UnixMilliseconds::new(500_000),
        )
    }
}

// Keeps API-key persistence outside peer-certificate composition tests.
struct UnusedAuthenticationStore;

impl AuthenticationStore for UnusedAuthenticationStore {
    // Rejects accidental API-key reads.
    fn read(
        &self,
        _api_key_id: &ApiKeyId,
    ) -> Result<Option<VersionedAuthenticationRecord>, AuthenticationStoreError> {
        Err(AuthenticationStoreError::Unavailable)
    }

    // Rejects accidental API-key collection reads.
    fn all(&self) -> Result<Vec<VersionedAuthenticationRecord>, AuthenticationStoreError> {
        Err(AuthenticationStoreError::Unavailable)
    }

    // Rejects accidental API-key creation.
    fn create(
        &self,
        _record: AuthenticationRecord,
    ) -> Result<VersionedAuthenticationRecord, AuthenticationStoreError> {
        Err(AuthenticationStoreError::Unavailable)
    }

    // Rejects accidental API-key replacement.
    fn replace(
        &self,
        _record: AuthenticationRecord,
        _expected_revision: u64,
    ) -> Result<VersionedAuthenticationRecord, AuthenticationStoreError> {
        Err(AuthenticationStoreError::Unavailable)
    }

    // Rejects accidental API-key rotation.
    fn rotate(
        &self,
        _revoked: AuthenticationRecord,
        _expected_revision: u64,
        _replacement: AuthenticationRecord,
    ) -> Result<AuthenticationRotation, AuthenticationStoreError> {
        Err(AuthenticationStoreError::Unavailable)
    }
}

// Refuses unused API-key entropy.
struct UnusedAuthenticationMaterial;

impl ApiKeyMaterialProvider for UnusedAuthenticationMaterial {
    // Rejects accidental API-key material creation.
    fn fill(&self, _destination: &mut [u8]) -> Result<(), AuthenticationError> {
        Err(AuthenticationError::EntropyUnavailable)
    }
}

// Supplies exact authentication resolution time.
struct TestAuthenticationClock(u64);

impl AuthenticationClock for TestAuthenticationClock {
    // Returns the exact configured authentication time.
    fn now(&self) -> Result<UnixMilliseconds, AuthenticationError> {
        Ok(UnixMilliseconds::new(self.0))
    }
}

// Holds one complete real-database pairing and Node composition fixture.
struct Fixture {
    _directory: tempfile::TempDir,
    database: Arc<DatabaseManager>,
    nodes: Arc<NodeManager>,
    pairings: Arc<PairingManager>,
    pairing_clock: Arc<TestPairingClock>,
}

impl Fixture {
    // Creates one active-main fixture over exactly one shared DatabaseManager.
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database = Arc::new(
            DatabaseManager::open(
                DatabaseConfiguration::new(directory.path().join("core.sqlite3"))
                    .with_busy_timeout(Duration::from_secs(1))
                    .with_clock(Arc::new(TestDatabaseClock(AtomicU64::new(10_000)))),
            )
            .expect("database"),
        );
        let (nodes, _) = NodeManager::open(database.clone(), main_node(), "initialize-main")
            .expect("node manager");
        let nodes = Arc::new(nodes);
        let pairing_clock = Arc::new(TestPairingClock(AtomicU64::new(1_000)));
        let pairings = pairing_manager(database.clone(), pairing_clock.clone());
        Self {
            _directory: directory,
            database,
            nodes,
            pairings,
            pairing_clock,
        }
    }

    // Produces one verified pairing result without committing application state.
    fn pair(&self, mode: PairingMode) -> li_pairing_manager::PairingChange<PairingResult> {
        static NEXT_PAIRING_KEY: AtomicU64 = AtomicU64::new(1);
        let identity = NEXT_PAIRING_KEY.fetch_add(1, Ordering::SeqCst);
        let open_key = format!("pairing:open:{identity}");
        let enroll_key = format!("pairing:enroll:{identity}");
        let mut opened = self
            .pairings
            .open(
                &open_key,
                PairingWindowRequest::new(mode, 180).expect("window"),
            )
            .expect("open pairing");
        let invite_id = opened.value().invite_id().clone();
        let code = opened
            .value_mut()
            .setup_code_mut()
            .expect("setup code")
            .take()
            .expect("present setup code");
        self.pairings
            .enroll(&enroll_key, &invite_id, &child_candidate(code))
            .expect("pair child")
    }

    // Creates the production atomic composition owner over this fixture's exact database.
    fn composition(&self) -> CorePairingEnrollmentCoordinator {
        CorePairingEnrollmentCoordinator::new(self.database.clone(), self.nodes.clone())
            .expect("shared database composition")
    }

    // Creates AuthenticationManager over the persisted peer-credential adapter.
    fn authentication(&self, now: u64) -> AuthenticationManager {
        AuthenticationManager::new_with_peer_credential_store(
            Arc::new(UnusedAuthenticationStore),
            Arc::new(DatabasePeerCredentialStore::new(self.database.clone())),
            Arc::new(UnusedAuthenticationMaterial),
            Arc::new(TestAuthenticationClock(now)),
        )
    }
}

// Reconstructs PairingManager over the same durable store to model process restart.
fn pairing_manager(
    database: Arc<DatabaseManager>,
    pairing_clock: Arc<TestPairingClock>,
) -> Arc<PairingManager> {
    let store: Arc<dyn PairingStore> = Arc::new(DatabasePairingStore::new(database));
    Arc::new(PairingManager::new(
        pairing_context(),
        Arc::new(TestDiscovery),
        Arc::new(TestDirectLink),
        Arc::new(TestTrust),
        Arc::new(TestPairingMaterial(AtomicU8::new(20))),
        Arc::new(TestSetupCode),
        pairing_clock,
        store,
    ))
}

// Returns one canonical active local main Node.
fn main_node() -> Node {
    Node::new(
        pairing_context().identity().clone(),
        DisplayName::parse("Home AI").expect("main name"),
        NodeRole::Main,
        NodeState::Active,
        NodeAddress::parse("homeai.local").expect("main address"),
        None,
        EntityTimestamps::new(UnixMilliseconds::new(100), UnixMilliseconds::new(100))
            .expect("main timestamps"),
    )
}

// Returns the exact main identity supplied independently to PairingManager.
fn pairing_context() -> PairingContext {
    PairingContext::new(
        NodeIdentity::new(
            NodeId::parse(&"1".repeat(32)).expect("main node"),
            MachineId::parse(&"2".repeat(32)).expect("main machine"),
            InstallationId::parse(&"3".repeat(64)).expect("main installation"),
        ),
        NodeRole::Main,
        DisplayName::parse("Home AI").expect("main name"),
        NodeAddress::parse("homeai.local").expect("main address"),
        9_770,
        digest('4'),
        digest('5'),
    )
}

// Returns one exact child candidate carrying the presented setup code.
fn child_candidate(code: String) -> PairingCandidate {
    PairingCandidate::new(
        NodeIdentity::new(
            NodeId::parse(&"6".repeat(32)).expect("child node"),
            MachineId::parse(&"7".repeat(32)).expect("child machine"),
            InstallationId::parse(&"8".repeat(64)).expect("child installation"),
        ),
        DisplayName::parse("Child AI").expect("child name"),
        NodeAddress::parse("child.local").expect("child address"),
        vec![9; 128],
        UnixMilliseconds::new(900),
        b"proof".to_vec(),
        Some(code),
        NodeAddress::parse("192.168.1.20").expect("peer address"),
    )
    .expect("candidate")
}

// Returns one repeated lowercase digest fixture.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
}

// Reproduces NodeManager's deterministic outbox target for final-conflict injection.
fn outbox_event_id(idempotency_key: &str, kind: &str, entity_id: &str) -> String {
    let mut digest = Sha256::new();
    for value in ["li_node_outbox_v1", idempotency_key, kind, entity_id] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    format!("{:x}", digest.finalize())
}

// Proves direct pairing applies and replays one exact four-record atomic enrollment.
#[test]
fn active_pairing_atomically_enrolls_and_replays() {
    let fixture = Fixture::new();
    let paired = fixture.pair(PairingMode::Lan);
    let composition = fixture.composition();
    let applied = composition
        .commit_pairing(
            "pairing:active",
            paired.value(),
            UnixMilliseconds::new(1_100),
        )
        .expect("active commit");
    assert_eq!(applied.disposition(), DatabaseCommitDisposition::Applied);
    assert_eq!(
        applied.node().expect("enrolled node").value().identity(),
        paired.value().child_identity()
    );
    let principal = fixture
        .authentication(1_100)
        .resolve_peer_credential(paired.value().credentials().member_leaf_sha256())
        .expect("active peer");
    assert_eq!(
        principal.credential_id(),
        &CredentialId::parse(&"a".repeat(32)).expect("credential")
    );
    assert_eq!(
        principal.local_node_id(),
        paired.value().pairing_record().main_node_id()
    );
    assert_eq!(
        principal.peer_node_id(),
        paired.value().child_identity().node_id()
    );
    assert_eq!(principal.direction(), PeerCredentialDirection::ChildToMain);
    let replayed = composition
        .commit_pairing(
            "pairing:active",
            paired.value(),
            UnixMilliseconds::new(1_100),
        )
        .expect("active replay");
    assert_eq!(replayed.disposition(), DatabaseCommitDisposition::Replayed);
    assert_eq!(fixture.nodes.nodes().expect("nodes").len(), 2);

    let conflicting = fixture.pair(PairingMode::Lan);
    assert!(composition
        .commit_pairing(
            "pairing:conflict",
            conflicting.value(),
            UnixMilliseconds::new(1_100),
        )
        .is_err());
    let stored = DatabasePairingStore::new(fixture.database.clone())
        .pairing(conflicting.value().invite_id())
        .expect("pairing lookup")
        .expect("open pairing");
    assert_eq!(
        stored.record().state(),
        li_pairing_manager::PairingRecordState::Open
    );
    assert_eq!(
        fixture.nodes.nodes().expect("nodes after conflict").len(),
        2
    );
}

// Proves remote pending reconstructs after restart and concurrent approval applies exactly once.
#[test]
fn remote_pairing_restarts_pending_and_concurrently_approves_once() {
    let fixture = Fixture::new();
    let paired = fixture.pair(PairingMode::Remote);
    let composition = fixture.composition();
    let pending = composition
        .commit_pairing(
            "pairing:pending",
            paired.value(),
            UnixMilliseconds::new(1_100),
        )
        .expect("pending commit");
    assert!(pending.node().is_none());
    assert_eq!(fixture.nodes.nodes().expect("nodes").len(), 1);
    assert_eq!(
        fixture
            .authentication(1_100)
            .resolve_peer_credential(paired.value().credentials().member_leaf_sha256()),
        Err(PeerCredentialError::Pending)
    );

    let restarted_pairings =
        pairing_manager(fixture.database.clone(), fixture.pairing_clock.clone());
    let approved = restarted_pairings
        .approve("pairing:approve", paired.value().invite_id())
        .expect("approval proposal");
    let outcomes = thread::scope(|scope| {
        let first = scope.spawn(|| {
            composition.approve_pairing(
                "pairing:approve",
                approved.value(),
                UnixMilliseconds::new(1_200),
            )
        });
        let second = scope.spawn(|| {
            composition.approve_pairing(
                "pairing:approve",
                approved.value(),
                UnixMilliseconds::new(1_200),
            )
        });
        [
            first.join().expect("first approval worker"),
            second.join().expect("second approval worker"),
        ]
    });
    let outcomes = outcomes.map(|result| result.expect("approval commit"));
    assert_eq!(
        outcomes
            .iter()
            .filter(|change| change.disposition() == DatabaseCommitDisposition::Applied)
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|change| change.disposition() == DatabaseCommitDisposition::Replayed)
            .count(),
        1
    );
    assert!(outcomes.iter().all(|change| change.node().is_some()));
    assert_eq!(
        fixture.nodes.pending_outbox_events().expect("outbox").len(),
        2
    );
    assert!(fixture
        .authentication(1_200)
        .resolve_peer_credential(paired.value().credentials().member_leaf_sha256())
        .is_ok());
}

// Proves a conflict on the final outbox target rolls back every staged prior mutation.
#[test]
fn late_outbox_conflict_rolls_back_pairing_credential_and_child() {
    let fixture = Fixture::new();
    let paired = fixture.pair(PairingMode::Lan);
    let idempotency_key = "pairing:late-conflict";
    let event_id = outbox_event_id(
        idempotency_key,
        "node_enrolled",
        paired.value().child_identity().node_id().as_str(),
    );
    fixture
        .database
        .write(DatabaseCommand::save(
            "inject:late-outbox-conflict",
            OutboxConflictRecord {
                event_id: event_id.clone(),
                kind: "foreign_event".to_string(),
                entity_id: "foreign".to_string(),
                occurred_at_unix_milliseconds: 1,
                state: "pending".to_string(),
                acknowledged_at_unix_milliseconds: None,
            },
            DatabaseRevision::Missing,
        ))
        .expect("inject outbox target");

    assert!(fixture
        .composition()
        .commit_pairing(
            idempotency_key,
            paired.value(),
            UnixMilliseconds::new(1_100),
        )
        .is_err());
    let pairing = DatabasePairingStore::new(fixture.database.clone())
        .pairing(paired.value().invite_id())
        .expect("pairing lookup")
        .expect("open pairing");
    assert_eq!(
        pairing.record().state(),
        li_pairing_manager::PairingRecordState::Open
    );
    assert!(DatabasePeerCredentialStore::new(fixture.database.clone())
        .matching_peer_credentials(paired.value().credentials().member_leaf_sha256(), 2)
        .expect("peer lookup")
        .is_empty());
    assert!(fixture
        .nodes
        .node(paired.value().child_identity().node_id())
        .is_err());
    let retained = fixture
        .database
        .read(DatabaseQuery::<OutboxConflictRecord>::record(event_id))
        .expect("conflicting outbox record");
    assert!(matches!(
        retained,
        DatabaseResult::Record(record) if record.value.kind == "foreign_event"
    ));
}

// Proves approval cannot rewrite a pending credential whose exact Node relationship drifted.
#[test]
fn approval_rejects_local_or_peer_relationship_drift() {
    for drift_local_node in [true, false] {
        let fixture = Fixture::new();
        let paired = fixture.pair(PairingMode::Remote);
        let composition = fixture.composition();
        composition
            .commit_pairing(
                "pairing:pending-relationship",
                paired.value(),
                UnixMilliseconds::new(1_100),
            )
            .expect("pending commit");
        let store = DatabasePeerCredentialStore::new(fixture.database.clone());
        let leaf = paired.value().credentials().member_leaf_sha256();
        let current = store
            .matching_peer_credentials(leaf, 2)
            .expect("peer lookup")
            .remove(0);
        let wrong_node_id = NodeId::parse(&"9".repeat(32)).expect("wrong Node");
        let drifted = PeerCredential::new_with_state(
            current.credential().credential_id().clone(),
            leaf.clone(),
            if drift_local_node {
                wrong_node_id.clone()
            } else {
                current.credential().local_node_id().clone()
            },
            if drift_local_node {
                current.credential().peer_node_id().clone()
            } else {
                wrong_node_id
            },
            PeerCredentialDirection::ChildToMain,
            PeerCredentialState::Pending,
            current.credential().issued_at(),
            current.credential().expires_at(),
            None,
            None,
        )
        .expect("drifted credential");
        store
            .replace(
                drifted,
                current.revision(),
                format!("peer:relationship-drift:{drift_local_node}"),
            )
            .expect("relationship drift fixture");
        let approval_key = format!("pairing:relationship-approve:{drift_local_node}");
        let approval = fixture
            .pairings
            .approve(&approval_key, paired.value().invite_id())
            .expect("approval proposal");
        assert_eq!(
            composition.approve_pairing(
                "pairing:relationship-commit",
                approval.value(),
                UnixMilliseconds::new(1_200),
            ),
            Err(CorePairingEnrollmentError::InvalidMaterial)
        );
        assert_eq!(fixture.nodes.nodes().expect("nodes").len(), 1);
    }
}

// Proves revoked or rotated pending material and expired approval leave Node unenrolled.
#[test]
fn approval_rejects_terminal_or_expired_material_without_partial_enrollment() {
    for rotated in [false, true] {
        let fixture = Fixture::new();
        let paired = fixture.pair(PairingMode::Remote);
        let composition = fixture.composition();
        composition
            .commit_pairing(
                "pairing:pending",
                paired.value(),
                UnixMilliseconds::new(1_100),
            )
            .expect("pending commit");
        let store = DatabasePeerCredentialStore::new(fixture.database.clone());
        let leaf = paired.value().credentials().member_leaf_sha256();
        let current = store
            .matching_peer_credentials(leaf, 2)
            .expect("peer lookup")
            .remove(0);
        let revoked = PeerCredential::new_with_state(
            current.credential().credential_id().clone(),
            leaf.clone(),
            current.credential().local_node_id().clone(),
            current.credential().peer_node_id().clone(),
            current.credential().direction(),
            PeerCredentialState::Pending,
            current.credential().issued_at(),
            current.credential().expires_at(),
            Some(UnixMilliseconds::new(1_150)),
            rotated.then(|| CredentialId::parse(&"b".repeat(32)).expect("replacement")),
        )
        .expect("terminal pending credential");
        store
            .replace(revoked, current.revision(), "peer:terminal")
            .expect("terminal mutation");
        let approval = fixture
            .pairings
            .approve("pairing:terminal-approve", paired.value().invite_id())
            .expect("approval proposal");
        assert_eq!(
            composition.approve_pairing(
                "pairing:approve",
                approval.value(),
                UnixMilliseconds::new(1_200),
            ),
            Err(CorePairingEnrollmentError::InvalidMaterial)
        );
        assert_eq!(fixture.nodes.nodes().expect("nodes").len(), 1);
    }

    let fixture = Fixture::new();
    let paired = fixture.pair(PairingMode::Remote);
    fixture
        .composition()
        .commit_pairing(
            "pairing:pending",
            paired.value(),
            UnixMilliseconds::new(1_100),
        )
        .expect("pending commit");
    fixture.pairing_clock.set(181_000);
    assert_eq!(
        fixture
            .pairings
            .approve("pairing:expired-approve", paired.value().invite_id())
            .expect_err("expired approval"),
        PairingError::Expired
    );
    assert_eq!(fixture.nodes.nodes().expect("nodes").len(), 1);
}
