// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use li_core_application::{
    CoreNodePairingApi, CoreNodePairingEnrollmentPort, CorePairingEnrollmentCoordinator,
    CorePairingEnrollmentError, DatabasePairingStore,
};
use li_core_interface::{
    DisplayName, EntityTimestamps, InstallationId, MachineId, Node, NodeAddress, NodeId,
    NodeIdentity, NodeRole, NodeState, PairingInviteId, Sha256Digest, UnixMilliseconds,
};
use li_database::{
    DatabaseClock, DatabaseCommitDisposition, DatabaseConfiguration, DatabaseError, DatabaseManager,
};
use li_node_manager::{
    NodeManager, NodePairingApiError, NodePairingApiPort, NodePairingApproveRequest,
    NodePairingEnrollRequest, NodePairingMode, NodePairingOpenRequest, NodePairingState,
};
use li_pairing_manager::{
    PairingAdvertisement, PairingApproval, PairingCandidate, PairingClock, PairingContext,
    PairingCredentials, PairingDirectLinkProvider, PairingDiscoveryProvider, PairingError,
    PairingManager, PairingMaterialProvider, PairingMembershipState, PairingResult,
    PairingSetupCodeProvider, PairingTrustProvider,
};

// Supplies deterministic increasing database commit timestamps.
struct TestDatabaseClock(AtomicI64);

impl DatabaseClock for TestDatabaseClock {
    // Returns one unique commit timestamp.
    fn now_unix_milliseconds(&self) -> Result<i64, DatabaseError> {
        Ok(self.0.fetch_add(1, Ordering::SeqCst))
    }
}

// Supplies one deterministic pairing time shared by manager and adapter.
struct TestPairingClock(AtomicU64);

impl PairingClock for TestPairingClock {
    // Returns the exact configured pairing timestamp.
    fn now(&self) -> Result<UnixMilliseconds, PairingError> {
        Ok(UnixMilliseconds::new(self.0.load(Ordering::SeqCst)))
    }
}

// Fills each pairing material request with one distinct deterministic byte.
struct TestPairingMaterial(AtomicU8);

impl PairingMaterialProvider for TestPairingMaterial {
    // Produces bounded deterministic invitation material.
    fn fill(&self, destination: &mut [u8]) -> Result<(), PairingError> {
        destination.fill(self.0.fetch_add(1, Ordering::SeqCst));
        Ok(())
    }
}

// Derives one deterministic installation-bound setup code for API lifecycle tests.
struct TestSetupCode;

impl PairingSetupCodeProvider for TestSetupCode {
    // Returns the exact eight-digit fixture without durable plaintext storage.
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

// Records native advertisement publication and post-commit cleanup identities.
#[derive(Default)]
struct TestDiscovery {
    published: Mutex<Vec<PairingInviteId>>,
    unpublished: Mutex<Vec<PairingInviteId>>,
}

impl PairingDiscoveryProvider for TestDiscovery {
    // Records one successfully published invitation identity.
    fn publish(&self, advertisement: &PairingAdvertisement) -> Result<(), PairingError> {
        self.published
            .lock()
            .expect("published")
            .push(advertisement.invite_id().clone());
        Ok(())
    }

    // Records one cleanup only after its lifecycle owner requests it.
    fn unpublish(&self, invite_id: &PairingInviteId) {
        self.unpublished
            .lock()
            .expect("unpublished")
            .push(invite_id.clone());
    }
}

// Rejects the unused ConnectX verification path.
struct TestDirectLink;

impl PairingDirectLinkProvider for TestDirectLink {
    // Fails any accidental direct-link request.
    fn verify(
        &self,
        _interface: &li_core_interface::NetworkInterfaceName,
        _peer_address: &NodeAddress,
    ) -> Result<(), PairingError> {
        Err(PairingError::DirectLinkUnavailable)
    }
}

// Issues deterministic public trust material or one injected verification failure.
struct TestTrust {
    fail_verification: AtomicBool,
}

impl PairingTrustProvider for TestTrust {
    // Verifies the exact fixture proof without exposing it in any error.
    fn verify_candidate(
        &self,
        public_key: &[u8],
        transcript: &[u8],
        signature: &[u8],
    ) -> Result<Sha256Digest, PairingError> {
        if self.fail_verification.load(Ordering::SeqCst)
            || public_key.len() != 128
            || transcript.is_empty()
            || signature != b"private-proof"
        {
            return Err(PairingError::Unauthorized);
        }
        Ok(digest('9'))
    }

    // Returns one exact public credential response package.
    fn issue_membership(
        &self,
        _context: &PairingContext,
        _candidate: &PairingCandidate,
        _public_key_fingerprint: &Sha256Digest,
        _state: PairingMembershipState,
        _approval_expires_at: Option<UnixMilliseconds>,
    ) -> Result<PairingCredentials, PairingError> {
        PairingCredentials::new(
            b"main-public-key".to_vec(),
            b"main-ca-certificate".to_vec(),
            b"child-certificate".to_vec(),
            b"membership-signature".to_vec(),
            digest('a'),
            UnixMilliseconds::new(500),
            UnixMilliseconds::new(500_000),
        )
    }
}

// Rejects every application commit to prove native discovery is not closed early.
struct FailingEnrollment;

impl CoreNodePairingEnrollmentPort for FailingEnrollment {
    // Injects one atomic initial-enrollment failure.
    fn commit_pairing(
        &self,
        _idempotency_key: &str,
        _result: &PairingResult,
        _committed_at: UnixMilliseconds,
    ) -> Result<DatabaseCommitDisposition, CorePairingEnrollmentError> {
        Err(CorePairingEnrollmentError::Database(
            DatabaseError::Unavailable {
                reason: "injected commit failure",
            },
        ))
    }

    // Injects one atomic approval failure.
    fn approve_pairing(
        &self,
        _idempotency_key: &str,
        _approval: &PairingApproval,
        _committed_at: UnixMilliseconds,
    ) -> Result<DatabaseCommitDisposition, CorePairingEnrollmentError> {
        Err(CorePairingEnrollmentError::Database(
            DatabaseError::Unavailable {
                reason: "injected approval failure",
            },
        ))
    }
}

// Applies the initial pending commit but rejects its later atomic approval.
struct FailingApprovalEnrollment {
    delegate: Arc<CorePairingEnrollmentCoordinator>,
}

impl CoreNodePairingEnrollmentPort for FailingApprovalEnrollment {
    // Delegates the initial pending commit to the real atomic composition owner.
    fn commit_pairing(
        &self,
        idempotency_key: &str,
        result: &PairingResult,
        committed_at: UnixMilliseconds,
    ) -> Result<DatabaseCommitDisposition, CorePairingEnrollmentError> {
        CoreNodePairingEnrollmentPort::commit_pairing(
            self.delegate.as_ref(),
            idempotency_key,
            result,
            committed_at,
        )
    }

    // Injects one approval failure before any pending state can advance.
    fn approve_pairing(
        &self,
        _idempotency_key: &str,
        _approval: &PairingApproval,
        _committed_at: UnixMilliseconds,
    ) -> Result<DatabaseCommitDisposition, CorePairingEnrollmentError> {
        Err(CorePairingEnrollmentError::Database(
            DatabaseError::Unavailable {
                reason: "injected approval failure",
            },
        ))
    }
}

// Owns one real database, PairingManager, NodeManager, and observable discovery lifecycle.
struct Fixture {
    _directory: tempfile::TempDir,
    database: Arc<DatabaseManager>,
    nodes: Arc<NodeManager>,
    store: Arc<DatabasePairingStore>,
    pairings: Arc<PairingManager>,
    clock: Arc<TestPairingClock>,
    discovery: Arc<TestDiscovery>,
    trust: Arc<TestTrust>,
}

impl Fixture {
    // Creates one active main with a single shared durable authority.
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database = Arc::new(
            DatabaseManager::open(
                DatabaseConfiguration::new(directory.path().join("core.sqlite3"))
                    .with_busy_timeout(Duration::from_secs(1))
                    .with_clock(Arc::new(TestDatabaseClock(AtomicI64::new(10_000)))),
            )
            .expect("database"),
        );
        let (nodes, _) = NodeManager::open(database.clone(), main_node(), "initialize-main")
            .expect("node manager");
        let nodes = Arc::new(nodes);
        let store = Arc::new(DatabasePairingStore::new(database.clone()));
        let clock = Arc::new(TestPairingClock(AtomicU64::new(1_000)));
        let discovery = Arc::new(TestDiscovery::default());
        let trust = Arc::new(TestTrust {
            fail_verification: AtomicBool::new(false),
        });
        let pairings = Arc::new(PairingManager::new(
            pairing_context(),
            discovery.clone(),
            Arc::new(TestDirectLink),
            trust.clone(),
            Arc::new(TestPairingMaterial(AtomicU8::new(20))),
            Arc::new(TestSetupCode),
            clock.clone(),
            store.clone(),
        ));
        Self {
            _directory: directory,
            database,
            nodes,
            store,
            pairings,
            clock,
            discovery,
            trust,
        }
    }

    // Composes the production atomic enrollment owner.
    fn enrollment(&self) -> Arc<CorePairingEnrollmentCoordinator> {
        Arc::new(
            CorePairingEnrollmentCoordinator::new(self.database.clone(), self.nodes.clone())
                .expect("enrollment composition"),
        )
    }

    // Composes the Node pairing adapter over real managers and one selectable commit boundary.
    fn api(&self, enrollment: Arc<dyn CoreNodePairingEnrollmentPort>) -> CoreNodePairingApi {
        CoreNodePairingApi::new(
            self.pairings.clone(),
            enrollment,
            self.store.clone(),
            self.clock.clone(),
        )
    }

    // Reconstructs one fresh PairingManager over the same durable store and atomic owner.
    fn restarted_api(
        &self,
        enrollment: Arc<dyn CoreNodePairingEnrollmentPort>,
    ) -> CoreNodePairingApi {
        CoreNodePairingApi::new(
            Arc::new(PairingManager::new(
                pairing_context(),
                self.discovery.clone(),
                Arc::new(TestDirectLink),
                self.trust.clone(),
                Arc::new(TestPairingMaterial(AtomicU8::new(90))),
                Arc::new(TestSetupCode),
                self.clock.clone(),
                self.store.clone(),
            )),
            enrollment,
            self.store.clone(),
            self.clock.clone(),
        )
    }
}

// Returns one canonical active local main Node.
fn main_node() -> Node {
    Node::new(
        pairing_context().identity().clone(),
        DisplayName::parse("Home AI").expect("name"),
        NodeRole::Main,
        NodeState::Active,
        NodeAddress::parse("homeai.local").expect("address"),
        None,
        EntityTimestamps::new(UnixMilliseconds::new(100), UnixMilliseconds::new(100))
            .expect("timestamps"),
    )
}

// Returns the exact main identity supplied independently to PairingManager.
fn pairing_context() -> PairingContext {
    PairingContext::new(
        NodeIdentity::new(
            NodeId::parse(&"1".repeat(32)).expect("node"),
            MachineId::parse(&"2".repeat(32)).expect("machine"),
            InstallationId::parse(&"3".repeat(64)).expect("installation"),
        ),
        NodeRole::Main,
        DisplayName::parse("Home AI").expect("name"),
        NodeAddress::parse("homeai.local").expect("address"),
        9_770,
        digest('4'),
        digest('5'),
    )
}

// Returns the exact child identity used by enrollment requests.
fn child_identity() -> NodeIdentity {
    NodeIdentity::new(
        NodeId::parse(&"6".repeat(32)).expect("node"),
        MachineId::parse(&"7".repeat(32)).expect("machine"),
        InstallationId::parse(&"8".repeat(64)).expect("installation"),
    )
}

// Returns one repeated lowercase SHA-256 fixture.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
}

// Opens one exact mode and returns the invitation response with its one-time code.
fn open(api: &CoreNodePairingApi, mode: NodePairingMode) -> li_node_manager::NodePairingInvitation {
    api.open(
        &NodePairingOpenRequest::new("open-pairing".to_string(), mode, 180).expect("open request"),
    )
    .expect("open pairing")
}

// Creates one bounded candidate request carrying the presented setup code.
fn enroll_request(invite_id: PairingInviteId, setup_code: String) -> NodePairingEnrollRequest {
    NodePairingEnrollRequest::new(
        "enroll-pairing".to_string(),
        invite_id,
        child_identity(),
        DisplayName::parse("Child AI").expect("name"),
        NodeAddress::parse("child.local").expect("address"),
        vec![9; 128],
        UnixMilliseconds::new(900),
        b"private-proof".to_vec(),
        Some(setup_code),
        NodeAddress::parse("192.168.1.20").expect("peer address"),
    )
    .expect("enroll request")
}

// Projects open, active, and exact replay behavior through the real atomic composition.
#[test]
fn lan_lifecycle_commits_before_credentials_and_replays_the_public_package() {
    let fixture = Fixture::new();
    let api = fixture.api(fixture.enrollment());
    let invitation = open(&api, NodePairingMode::Lan);
    assert_eq!(
        api.status(invitation.invite_id())
            .expect("open status")
            .state(),
        NodePairingState::Open
    );
    let request = enroll_request(
        invitation.invite_id().clone(),
        invitation.setup_code().expect("setup code").to_string(),
    );

    let enrollment = api.enroll(&request).expect("enrollment");

    assert_eq!(enrollment.status().state(), NodePairingState::Active);
    assert_eq!(
        enrollment.credentials().main_public_key(),
        b"main-public-key"
    );
    assert_eq!(
        api.status(invitation.invite_id())
            .expect("active status")
            .state(),
        NodePairingState::Active
    );
    assert!(fixture.nodes.node(child_identity().node_id()).is_ok());
    assert_eq!(
        fixture.discovery.unpublished.lock().expect("cleanup").len(),
        1
    );
    let restarted = fixture.restarted_api(fixture.enrollment());
    assert_eq!(restarted.enroll(&request), Ok(enrollment));
    assert_eq!(
        fixture.discovery.unpublished.lock().expect("cleanup").len(),
        1
    );
}

// Replays an open response exactly while rejecting one changed request under the same identity.
#[test]
fn open_replay_is_exact_after_manager_restart_and_conflicts_fail_closed() {
    let fixture = Fixture::new();
    let first_api = fixture.api(fixture.enrollment());
    let first = open(&first_api, NodePairingMode::Lan);
    let restarted = fixture.restarted_api(fixture.enrollment());
    let replayed = open(&restarted, NodePairingMode::Lan);

    assert_eq!(replayed, first);
    assert_eq!(
        fixture.discovery.published.lock().expect("published").len(),
        1
    );
    let conflict =
        NodePairingOpenRequest::new("open-pairing".to_string(), NodePairingMode::Remote, 180)
            .expect("conflict request");
    assert_eq!(
        restarted.open(&conflict),
        Err(NodePairingApiError::Conflict)
    );
}

// Projects pending approval and active approval while cleaning discovery only after each commit.
#[test]
fn remote_lifecycle_preserves_pending_status_until_atomic_approval() {
    let fixture = Fixture::new();
    let api = fixture.api(fixture.enrollment());
    let invitation = open(&api, NodePairingMode::Remote);
    let enrollment = api
        .enroll(&enroll_request(
            invitation.invite_id().clone(),
            invitation.setup_code().expect("setup code").to_string(),
        ))
        .expect("pending enrollment");
    assert_eq!(
        enrollment.status().state(),
        NodePairingState::PendingApproval
    );
    assert!(enrollment.status().comparison_code().is_some());
    assert!(fixture.nodes.node(child_identity().node_id()).is_err());

    let request = NodePairingApproveRequest::new(
        "approve-pairing".to_string(),
        invitation.invite_id().clone(),
    )
    .expect("approval request");
    let approved = api.approve(&request).expect("approval");

    assert_eq!(approved.state(), NodePairingState::Active);
    assert!(approved.comparison_code().is_none());
    assert!(fixture.nodes.node(child_identity().node_id()).is_ok());
    assert_eq!(
        fixture.discovery.unpublished.lock().expect("cleanup").len(),
        2
    );
    assert_eq!(api.approve(&request), Ok(approved));
    assert_eq!(
        fixture.discovery.unpublished.lock().expect("cleanup").len(),
        2
    );
}

// Leaves pairing open and native discovery live when the atomic application commit fails.
#[test]
fn atomic_commit_failure_never_calls_pairing_did_commit() {
    let fixture = Fixture::new();
    let api = fixture.api(Arc::new(FailingEnrollment));
    let invitation = open(&api, NodePairingMode::Lan);
    let request = enroll_request(
        invitation.invite_id().clone(),
        invitation.setup_code().expect("setup code").to_string(),
    );

    assert_eq!(api.enroll(&request), Err(NodePairingApiError::Unavailable));
    assert!(fixture
        .discovery
        .unpublished
        .lock()
        .expect("cleanup")
        .is_empty());
    assert_eq!(
        api.status(invitation.invite_id())
            .expect("retained status")
            .state(),
        NodePairingState::Open
    );
    assert!(fixture.nodes.node(child_identity().node_id()).is_err());
}

// Retains pending pairing and discovery state when the exact approval commit fails.
#[test]
fn atomic_approval_failure_never_calls_pairing_did_commit() {
    let fixture = Fixture::new();
    let api = fixture.api(Arc::new(FailingApprovalEnrollment {
        delegate: fixture.enrollment(),
    }));
    let invitation = open(&api, NodePairingMode::Remote);
    api.enroll(&enroll_request(
        invitation.invite_id().clone(),
        invitation.setup_code().expect("setup code").to_string(),
    ))
    .expect("pending enrollment");
    assert_eq!(
        fixture.discovery.unpublished.lock().expect("cleanup").len(),
        1
    );
    let request = NodePairingApproveRequest::new(
        "approve-pairing".to_string(),
        invitation.invite_id().clone(),
    )
    .expect("approval request");

    assert_eq!(api.approve(&request), Err(NodePairingApiError::Unavailable));
    assert_eq!(
        fixture.discovery.unpublished.lock().expect("cleanup").len(),
        1
    );
    assert_eq!(
        api.status(invitation.invite_id())
            .expect("pending status")
            .state(),
        NodePairingState::PendingApproval
    );
    assert!(fixture.nodes.node(child_identity().node_id()).is_err());
}

// Maps manager proof failure and missing status while keeping every sensitive request value redacted.
#[test]
fn manager_failures_are_closed_and_diagnostics_are_redacted() {
    let fixture = Fixture::new();
    let api = fixture.api(fixture.enrollment());
    let invitation = open(&api, NodePairingMode::Lan);
    fixture
        .trust
        .fail_verification
        .store(true, Ordering::SeqCst);
    let request = enroll_request(
        invitation.invite_id().clone(),
        invitation.setup_code().expect("setup code").to_string(),
    );
    let missing = PairingInviteId::parse(&"f".repeat(32)).expect("missing invitation");

    let error = api.enroll(&request).expect_err("proof failure");

    assert_eq!(error, NodePairingApiError::InvalidRequest);
    assert_eq!(api.status(&missing), Err(NodePairingApiError::NotFound));
    let presented = format!("{request:?} {error:?} {error}");
    assert!(!presented.contains("private-proof"));
    assert!(!presented.contains(invitation.setup_code().expect("setup code")));
    assert!(!presented.contains(&"9".repeat(128)));
}
