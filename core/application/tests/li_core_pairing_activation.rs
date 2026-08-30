// SPDX-License-Identifier: AGPL-3.0-only

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use li_authentication_manager::{PeerCredentialDirection, PeerCredentialStore};
use li_core_application::{
    CorePairingActivationAuthorityPort, CorePairingActivationConfigurationPort,
    CorePairingActivationConfirmationPort, CorePairingActivationCoordinator,
    CorePairingActivationError, CorePairingActivationPhase, CorePairingActivationRecord,
    CorePairingActivationServicePort, CorePairingActivationStore, CorePairingActivationWaiter,
    CorePairingJoinRequest, CorePairingPreparedActivation, DatabasePeerCredentialStore,
};
use li_core_interface::{
    DisplayName, EntityTimestamps, InstallationId, MachineId, Node, NodeAddress, NodeId,
    NodeIdentity, NodeRole, NodeState, PairingInviteId, Sha256Digest, UnixMilliseconds,
};
use li_database::{DatabaseConfiguration, DatabaseManager};
use li_node_manager::{
    LocalNodeRoleReadinessProvider, LocalNodeRoleTransition, LocalNodeRoleTransitionProof,
    NodeManager, NodeManagerError, NodePairedChildActivationRequest,
    NodePairedMainRestorationRequest, NodePairingActivationAuthority,
    NodePairingActivationAuthorityError, NodePairingActivationAuthorityPort,
    NodePairingCancellationPort, NodePairingClientPort, NodePairingCredentials,
    NodePairingEnrollment, NodePairingMode, NodePairingState, NodePairingStatus,
    NodePairingTransportError, NodePairingTransportRequest, NodePairingTransportResponse,
};
use li_pairing_manager::{PairingCandidateTrustProvider, PairingClock, PairingError};

// Supplies one deterministic pairing and role-transition time.
struct TestClock(AtomicU64);

impl PairingClock for TestClock {
    // Returns the exact configured millisecond value.
    fn now(&self) -> Result<UnixMilliseconds, PairingError> {
        Ok(UnixMilliseconds::new(self.0.load(Ordering::SeqCst)))
    }
}

// Keeps cancellation false for ordinary restart tests.
struct ActiveCancellation;

impl NodePairingCancellationPort for ActiveCancellation {
    // Reports one still-active operation.
    fn is_cancelled(&self) -> bool {
        false
    }
}

// Accepts the remote comparison boundary while remaining unused by active LAN fixtures.
struct AcceptConfirmation;

impl CorePairingActivationConfirmationPort for AcceptConfirmation {
    // Accepts only one canonical six-digit code from a remote fixture.
    fn confirm(&self, comparison_code: &str) -> Result<bool, CorePairingActivationError> {
        assert_eq!(comparison_code, "654321");
        Ok(true)
    }
}

// Returns exact child-transition readiness without external mutation.
struct ExactReadiness {
    authority_node_id: NodeId,
}

impl LocalNodeRoleReadinessProvider for ExactReadiness {
    // Binds one short-lived proof to the requested local and main identities.
    fn proof(
        &self,
        local: &Node,
        transition: &LocalNodeRoleTransition,
        now: UnixMilliseconds,
    ) -> Result<LocalNodeRoleTransitionProof, NodeManagerError> {
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

// Adapts the real Node-owned authority to the application saga's narrow local client port.
struct TestAuthority {
    nodes: Arc<NodeManager>,
    authority: NodePairingActivationAuthority,
}

impl TestAuthority {
    // Composes one real atomic authority over the exact shared fixture database.
    fn new(
        database: Arc<DatabaseManager>,
        nodes: Arc<NodeManager>,
        authority_node_id: NodeId,
    ) -> Self {
        let authority = NodePairingActivationAuthority::new(
            nodes.clone(),
            database,
            Arc::new(TestClock(AtomicU64::new(2_000))),
            Arc::new(ExactReadiness { authority_node_id }),
        )
        .expect("pairing authority");
        Self { nodes, authority }
    }
}

impl CorePairingActivationAuthorityPort for TestAuthority {
    // Returns the current local Node from the authority's exact manager.
    fn local_node(&self) -> Result<Node, CorePairingActivationError> {
        self.nodes
            .local_node()
            .map_err(|_| CorePairingActivationError::RoleUnavailable)
    }

    // Returns the complete bounded Node snapshot from the same manager.
    fn nodes(&self) -> Result<Vec<Node>, CorePairingActivationError> {
        self.nodes
            .nodes()
            .map_err(|_| CorePairingActivationError::RoleUnavailable)
    }

    // Delegates the exact atomic child authority request.
    fn activate_paired_child(
        &self,
        request: NodePairedChildActivationRequest,
    ) -> Result<(), CorePairingActivationError> {
        self.authority
            .activate_paired_child(&request)
            .map(|_| ())
            .map_err(authority_error)
    }

    // Delegates the exact atomic main restoration request.
    fn restore_paired_main(
        &self,
        request: NodePairedMainRestorationRequest,
    ) -> Result<(), CorePairingActivationError> {
        self.authority
            .restore_paired_main(&request)
            .map(|_| ())
            .map_err(authority_error)
    }
}

// Maps the Node-owned closed authority surface into the saga's stable role boundary.
fn authority_error(error: NodePairingActivationAuthorityError) -> CorePairingActivationError {
    match error {
        NodePairingActivationAuthorityError::RecoveryRequired => {
            CorePairingActivationError::RecoveryRequired
        }
        NodePairingActivationAuthorityError::InvalidRequest
        | NodePairingActivationAuthorityError::AuthorityConflict
        | NodePairingActivationAuthorityError::Unavailable => {
            CorePairingActivationError::RoleUnavailable
        }
    }
}

// Verifies deterministic public material without native cryptographic processes.
struct TestTrust;

impl PairingCandidateTrustProvider for TestTrust {
    // Returns the exact candidate key and its canonical fixture fingerprint.
    fn public_key(&self) -> Result<(Vec<u8>, Sha256Digest), PairingError> {
        Ok((vec![b'k'; 128], digest('9')))
    }

    // Returns one bounded deterministic possession proof.
    fn sign(&self, transcript: &[u8]) -> Result<Vec<u8>, PairingError> {
        if transcript.is_empty() {
            return Err(PairingError::Unauthorized);
        }
        Ok(b"candidate-proof".to_vec())
    }

    // Accepts the fixture main membership signature and returns its public-key identity.
    fn verify(
        &self,
        public_key: &[u8],
        transcript: &[u8],
        signature: &[u8],
    ) -> Result<Sha256Digest, PairingError> {
        if public_key != b"main-public-key"
            || transcript.is_empty()
            || signature != b"membership-signature"
        {
            return Err(PairingError::Unauthorized);
        }
        Ok(digest('a'))
    }

    // Accepts only the exact fixture child certificate package.
    fn verify_membership_certificate(
        &self,
        candidate_public_key: &[u8],
        main_ca_certificate: &[u8],
        child_certificate: &[u8],
        expected_child_leaf_sha256: &Sha256Digest,
    ) -> Result<(), PairingError> {
        if candidate_public_key != vec![b'k'; 128]
            || main_ca_certificate != b"main-ca"
            || child_certificate != b"child-certificate"
            || expected_child_leaf_sha256 != &digest('b')
        {
            return Err(PairingError::Unauthorized);
        }
        Ok(())
    }
}

// Returns one exact LAN challenge and active enrollment while counting remote exchanges.
struct TestClient {
    main: Node,
    local_node_id: NodeId,
    invite_id: PairingInviteId,
    exchanges: AtomicUsize,
}

impl NodePairingClientPort for TestClient {
    // Projects the request-specific deterministic response without retaining setup material.
    fn exchange(
        &self,
        _address: &NodeAddress,
        _port: u16,
        expected_certificate_sha256: &Sha256Digest,
        request: &NodePairingTransportRequest,
        _timeout: Duration,
        _cancellation: &dyn NodePairingCancellationPort,
    ) -> Result<NodePairingTransportResponse, NodePairingTransportError> {
        if expected_certificate_sha256 != &digest('c') {
            return Err(NodePairingTransportError::UntrustedPeer);
        }
        self.exchanges.fetch_add(1, Ordering::SeqCst);
        match request {
            NodePairingTransportRequest::Challenge { invite_id }
                if invite_id == &self.invite_id =>
            {
                Ok(NodePairingTransportResponse::Challenge {
                    challenge: li_node_manager::NodePairingChallenge::new(
                        self.invite_id.clone(),
                        NodePairingMode::Lan,
                        digest('d'),
                        UnixMilliseconds::new(1_000),
                        UnixMilliseconds::new(100_000),
                        self.main.identity().node_id().clone(),
                        self.main.control_address().clone(),
                        9_770,
                        digest('a'),
                        digest('c'),
                    )
                    .expect("challenge"),
                    main: self.main.clone(),
                })
            }
            NodePairingTransportRequest::Enroll(request)
                if request.invite_id() == &self.invite_id =>
            {
                Ok(NodePairingTransportResponse::Enrollment(
                    NodePairingEnrollment::new(
                        NodePairingStatus::new(
                            self.invite_id.clone(),
                            NodePairingMode::Lan,
                            NodePairingState::Active,
                            UnixMilliseconds::new(100_000),
                            0,
                            Some(self.local_node_id.clone()),
                            None,
                        )
                        .expect("status"),
                        credentials(),
                    )
                    .expect("enrollment"),
                ))
            }
            _ => Err(NodePairingTransportError::RequestRejected),
        }
    }
}

// Durably retains prepared public material and idempotent configuration state in memory.
#[derive(Default)]
struct TestConfiguration {
    prepared: Mutex<Option<CorePairingPreparedActivation>>,
    commits: AtomicUsize,
    restores: AtomicUsize,
    rollback_finishes: AtomicUsize,
}

impl CorePairingActivationConfigurationPort for TestConfiguration {
    // Stages or exactly replays one verified public configuration package.
    fn prepare(
        &self,
        _request_identity: &Sha256Digest,
        main: &Node,
        main_private_port: u16,
        main_certificate_sha256: &Sha256Digest,
        credentials: &NodePairingCredentials,
    ) -> Result<Sha256Digest, CorePairingActivationError> {
        let desired = CorePairingPreparedActivation::new(
            main.clone(),
            main_private_port,
            main_certificate_sha256.clone(),
            credentials.clone(),
        )?;
        let mut current = self
            .prepared
            .lock()
            .map_err(|_| CorePairingActivationError::ConfigurationUnavailable)?;
        if current.as_ref().is_some_and(|value| value != &desired) {
            return Err(CorePairingActivationError::ConfigurationUnavailable);
        }
        *current = Some(desired);
        Ok(digest('e'))
    }

    // Recovers only the exact prepared fixture receipt.
    fn prepared(
        &self,
        receipt: &Sha256Digest,
    ) -> Result<CorePairingPreparedActivation, CorePairingActivationError> {
        if receipt != &digest('e') {
            return Err(CorePairingActivationError::ConfigurationUnavailable);
        }
        self.prepared
            .lock()
            .map_err(|_| CorePairingActivationError::ConfigurationUnavailable)?
            .clone()
            .ok_or(CorePairingActivationError::ConfigurationUnavailable)
    }

    // Records one idempotent staged configuration activation.
    fn commit(&self, receipt: &Sha256Digest) -> Result<(), CorePairingActivationError> {
        self.prepared(receipt)?;
        self.commits.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    // Verifies the prepared configuration remains recoverable.
    fn verify(&self, receipt: &Sha256Digest) -> Result<(), CorePairingActivationError> {
        self.prepared(receipt).map(|_| ())
    }

    // Keeps rollback idempotent for the test composition.
    fn restore(&self, _receipt: &Sha256Digest) -> Result<(), CorePairingActivationError> {
        self.restores.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    // Keeps terminal rollback cleanup idempotent for the test composition.
    fn finish_rollback(&self, _receipt: &Sha256Digest) -> Result<(), CorePairingActivationError> {
        self.rollback_finishes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

// Records idempotent child service activation and readiness.
#[derive(Default)]
struct TestServices {
    activations: AtomicUsize,
    restorations: AtomicUsize,
    fail_activation: AtomicBool,
}

impl CorePairingActivationServicePort for TestServices {
    // Records one child activation attempt.
    fn activate_child(&self) -> Result<(), CorePairingActivationError> {
        self.activations.fetch_add(1, Ordering::SeqCst);
        if self.fail_activation.load(Ordering::SeqCst) {
            Err(CorePairingActivationError::ServiceUnavailable)
        } else {
            Ok(())
        }
    }

    // Accepts the test service state as ready.
    fn verify_child(&self) -> Result<(), CorePairingActivationError> {
        Ok(())
    }

    // Keeps rollback idempotent for the test composition.
    fn restore_main(&self) -> Result<(), CorePairingActivationError> {
        self.restorations.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

// Rejects accidental waiting because ordinary fixtures activate immediately.
struct PanicWaiter;

impl CorePairingActivationWaiter for PanicWaiter {
    // Fails if an active enrollment enters remote approval polling.
    fn wait(&self, _interval: Duration) -> Result<(), CorePairingActivationError> {
        panic!("active pairing entered approval polling")
    }
}

// Returns a pending remote enrollment, then one pending and one approved status in order.
struct RemoteApprovalClient {
    main: Node,
    local_node_id: NodeId,
    invite_id: PairingInviteId,
    enrollment_state: NodePairingState,
    events: Arc<Mutex<Vec<&'static str>>>,
}

impl NodePairingClientPort for RemoteApprovalClient {
    // Records fixed-port requests and returns the exact remote approval state machine.
    fn exchange(
        &self,
        _address: &NodeAddress,
        port: u16,
        expected_certificate_sha256: &Sha256Digest,
        request: &NodePairingTransportRequest,
        _timeout: Duration,
        _cancellation: &dyn NodePairingCancellationPort,
    ) -> Result<NodePairingTransportResponse, NodePairingTransportError> {
        assert_eq!(port, 9_769);
        assert_eq!(expected_certificate_sha256, &digest('c'));
        let mut events = self.events.lock().expect("remote events");
        match request {
            NodePairingTransportRequest::Challenge { invite_id }
                if invite_id == &self.invite_id =>
            {
                events.push("challenge");
                Ok(NodePairingTransportResponse::Challenge {
                    challenge: li_node_manager::NodePairingChallenge::new(
                        self.invite_id.clone(),
                        NodePairingMode::Remote,
                        digest('d'),
                        UnixMilliseconds::new(1_000),
                        UnixMilliseconds::new(100_000),
                        self.main.identity().node_id().clone(),
                        self.main.control_address().clone(),
                        9_770,
                        digest('a'),
                        digest('c'),
                    )
                    .expect("remote challenge"),
                    main: self.main.clone(),
                })
            }
            NodePairingTransportRequest::Enroll(request)
                if request.invite_id() == &self.invite_id =>
            {
                events.push("enroll");
                Ok(NodePairingTransportResponse::Enrollment(remote_enrollment(
                    &self.invite_id,
                    &self.local_node_id,
                    self.enrollment_state,
                    (self.enrollment_state == NodePairingState::PendingApproval)
                        .then_some("654321"),
                )))
            }
            NodePairingTransportRequest::Status { invite_id } if invite_id == &self.invite_id => {
                let pending = !events.contains(&"wait");
                events.push("status");
                Ok(NodePairingTransportResponse::Status(remote_status(
                    &self.invite_id,
                    &self.local_node_id,
                    if pending {
                        NodePairingState::PendingApproval
                    } else {
                        NodePairingState::Active
                    },
                    pending.then_some("654321"),
                )))
            }
            _ => Err(NodePairingTransportError::RequestRejected),
        }
    }
}

// Records one child-local comparison presentation and returns its configured decision.
struct RecordingConfirmation {
    events: Arc<Mutex<Vec<&'static str>>>,
    approved: bool,
    presentations: AtomicUsize,
}

impl CorePairingActivationConfirmationPort for RecordingConfirmation {
    // Verifies the six-digit code without retaining it and records one presentation boundary.
    fn confirm(&self, comparison_code: &str) -> Result<bool, CorePairingActivationError> {
        assert_eq!(comparison_code, "654321");
        self.presentations.fetch_add(1, Ordering::SeqCst);
        self.events.lock().expect("remote events").push("confirm");
        Ok(self.approved)
    }
}

// Records bounded polling only after the child-local comparison decision completes.
struct RecordingWaiter {
    events: Arc<Mutex<Vec<&'static str>>>,
}

impl CorePairingActivationWaiter for RecordingWaiter {
    // Records the coordinator-selected positive interval without sleeping.
    fn wait(&self, interval: Duration) -> Result<(), CorePairingActivationError> {
        assert!(!interval.is_zero());
        assert!(interval <= Duration::from_secs(1));
        self.events.lock().expect("remote events").push("wait");
        Ok(())
    }
}

// Persists each phase before simulating one process crash at a selected transition.
struct CrashStore {
    record: Mutex<Option<CorePairingActivationRecord>>,
    replace_calls: AtomicUsize,
    crash_after_replace: usize,
    crashed: AtomicBool,
}

impl CrashStore {
    // Creates one empty journal with one deterministic crash point.
    fn new(crash_after_replace: usize) -> Self {
        Self {
            record: Mutex::new(None),
            replace_calls: AtomicUsize::new(0),
            crash_after_replace,
            crashed: AtomicBool::new(false),
        }
    }
}

impl CorePairingActivationStore for CrashStore {
    // Returns the exact last durably persisted phase.
    fn load(&self) -> Result<Option<CorePairingActivationRecord>, CorePairingActivationError> {
        self.record
            .lock()
            .map(|value| value.clone())
            .map_err(|_| CorePairingActivationError::StateConflict)
    }

    // Creates one initial request record only once.
    fn create(
        &self,
        record: &CorePairingActivationRecord,
    ) -> Result<(), CorePairingActivationError> {
        let mut current = self
            .record
            .lock()
            .map_err(|_| CorePairingActivationError::StateConflict)?;
        if current.is_some() {
            return Err(CorePairingActivationError::StateConflict);
        }
        *current = Some(record.clone());
        Ok(())
    }

    // Persists the legal successor before one selected crash boundary.
    fn replace(
        &self,
        expected: CorePairingActivationPhase,
        replacement: &CorePairingActivationRecord,
    ) -> Result<(), CorePairingActivationError> {
        let mut current = self
            .record
            .lock()
            .map_err(|_| CorePairingActivationError::StateConflict)?;
        if current.as_ref().map(CorePairingActivationRecord::phase) != Some(expected) {
            return Err(CorePairingActivationError::StateConflict);
        }
        *current = Some(replacement.clone());
        drop(current);
        let call = self.replace_calls.fetch_add(1, Ordering::SeqCst) + 1;
        if call == self.crash_after_replace && !self.crashed.swap(true, Ordering::SeqCst) {
            panic!("simulated process crash after durable phase")
        }
        Ok(())
    }
}

// Replays every durable phase without recontacting a consumed invitation.
#[test]
fn every_durable_activation_phase_recovers_without_reenrollment() {
    for crash_after_replace in 1..=6 {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database = Arc::new(
            DatabaseManager::open(DatabaseConfiguration::new(
                directory.path().join("core.sqlite3"),
            ))
            .expect("database"),
        );
        let local = node('1', '2', '3', "Candidate", "candidate.local");
        let main = node('4', '5', '6', "Main", "main.local");
        let nodes = Arc::new(
            NodeManager::open(database.clone(), local.clone(), "initialize-node")
                .expect("node manager")
                .0,
        );
        let client = Arc::new(TestClient {
            main: main.clone(),
            local_node_id: local.identity().node_id().clone(),
            invite_id: invite_id(),
            exchanges: AtomicUsize::new(0),
        });
        let configurations = Arc::new(TestConfiguration::default());
        let services = Arc::new(TestServices::default());
        let store = Arc::new(CrashStore::new(crash_after_replace));
        let first = coordinator(
            database.clone(),
            nodes.clone(),
            client.clone(),
            configurations.clone(),
            services.clone(),
            store.clone(),
        );
        assert!(catch_unwind(AssertUnwindSafe(|| {
            first.activate(&request(), &AcceptConfirmation)
        }))
        .is_err());

        let restarted = coordinator(
            database.clone(),
            nodes.clone(),
            client.clone(),
            configurations,
            services,
            store,
        );
        let result = restarted
            .activate(&request(), &AcceptConfirmation)
            .expect("restart activation");
        assert_eq!(result.main(), &main);
        assert_eq!(result.local().role(), NodeRole::Child);
        assert_eq!(client.exchanges.load(Ordering::SeqCst), 2);
        let credentials = DatabasePeerCredentialStore::new(database)
            .matching_peer_credentials(&digest('c'), 2)
            .expect("main credential");
        assert_eq!(credentials.len(), 1);
        assert_eq!(
            credentials[0].credential().direction(),
            PeerCredentialDirection::MainToChild
        );
    }
}

// Confirms the child-visible code before any approval poll and preserves both fixed ports.
#[test]
fn remote_activation_confirms_comparison_before_waiting_for_main_approval() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = Arc::new(
        DatabaseManager::open(DatabaseConfiguration::new(
            directory.path().join("core.sqlite3"),
        ))
        .expect("database"),
    );
    let local = node('1', '2', '3', "Candidate", "candidate.local");
    let main = node('4', '5', '6', "Main", "main.local");
    let nodes = Arc::new(
        NodeManager::open(database.clone(), local.clone(), "initialize-node")
            .expect("node manager")
            .0,
    );
    let events = Arc::new(Mutex::new(Vec::new()));
    let client = Arc::new(RemoteApprovalClient {
        main: main.clone(),
        local_node_id: local.identity().node_id().clone(),
        invite_id: invite_id(),
        enrollment_state: NodePairingState::PendingApproval,
        events: events.clone(),
    });
    let configurations = Arc::new(TestConfiguration::default());
    let services = Arc::new(TestServices::default());
    let store = Arc::new(CrashStore::new(usize::MAX));
    let coordinator = CorePairingActivationCoordinator::new(
        Arc::new(TestAuthority::new(
            database,
            nodes,
            main.identity().node_id().clone(),
        )),
        client,
        Arc::new(TestTrust),
        Arc::new(ActiveCancellation),
        configurations.clone(),
        services,
        store,
        Arc::new(RecordingWaiter {
            events: events.clone(),
        }),
    );
    let confirmation = RecordingConfirmation {
        events: events.clone(),
        approved: true,
        presentations: AtomicUsize::new(0),
    };

    let result = coordinator
        .activate(&request(), &confirmation)
        .expect("remote activation");

    assert_eq!(result.main(), &main);
    assert_eq!(result.local().role(), NodeRole::Child);
    assert_eq!(confirmation.presentations.load(Ordering::SeqCst), 1);
    assert_eq!(
        *events.lock().expect("remote events"),
        vec!["challenge", "enroll", "confirm", "status", "wait", "status"]
    );
    assert_eq!(
        configurations
            .prepared
            .lock()
            .expect("prepared activation")
            .as_ref()
            .expect("prepared activation")
            .main_private_port(),
        9_770
    );
    let status = remote_status(
        &invite_id(),
        local.identity().node_id(),
        NodePairingState::PendingApproval,
        Some("654321"),
    );
    assert!(!format!("{status:?}").contains("654321"));
}

// Stops before the first approval poll when the child does not explicitly accept the code.
#[test]
fn remote_activation_denial_never_waits_or_accepts_main_approval() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = Arc::new(
        DatabaseManager::open(DatabaseConfiguration::new(
            directory.path().join("core.sqlite3"),
        ))
        .expect("database"),
    );
    let local = node('1', '2', '3', "Candidate", "candidate.local");
    let main = node('4', '5', '6', "Main", "main.local");
    let nodes = Arc::new(
        NodeManager::open(database.clone(), local.clone(), "initialize-node")
            .expect("node manager")
            .0,
    );
    let events = Arc::new(Mutex::new(Vec::new()));
    let configurations = Arc::new(TestConfiguration::default());
    let services = Arc::new(TestServices::default());
    let store = Arc::new(CrashStore::new(usize::MAX));
    let coordinator = CorePairingActivationCoordinator::new(
        Arc::new(TestAuthority::new(
            database,
            nodes.clone(),
            main.identity().node_id().clone(),
        )),
        Arc::new(RemoteApprovalClient {
            main: main.clone(),
            local_node_id: local.identity().node_id().clone(),
            invite_id: invite_id(),
            enrollment_state: NodePairingState::PendingApproval,
            events: events.clone(),
        }),
        Arc::new(TestTrust),
        Arc::new(ActiveCancellation),
        configurations.clone(),
        services.clone(),
        store.clone(),
        Arc::new(RecordingWaiter {
            events: events.clone(),
        }),
    );
    let confirmation = RecordingConfirmation {
        events: events.clone(),
        approved: false,
        presentations: AtomicUsize::new(0),
    };

    assert_eq!(
        coordinator.activate(&request(), &confirmation),
        Err(CorePairingActivationError::ConfirmationDenied)
    );
    assert_eq!(confirmation.presentations.load(Ordering::SeqCst), 1);
    assert_eq!(
        *events.lock().expect("remote events"),
        vec!["challenge", "enroll", "confirm"]
    );
    assert_eq!(nodes.local_node().expect("local").role(), NodeRole::Main);
    assert!(configurations
        .prepared
        .lock()
        .expect("prepared activation")
        .is_none());
    assert_eq!(services.activations.load(Ordering::SeqCst), 0);
    assert_eq!(
        store
            .load()
            .expect("activation record")
            .expect("stored activation")
            .phase(),
        CorePairingActivationPhase::Requested
    );
    assert!(!CorePairingActivationError::ConfirmationDenied
        .to_string()
        .contains("654321"));
}

// Rolls back one failed child service activation without leaving trust or remote authority.
#[test]
fn failed_activation_atomically_restores_main_and_deletes_pairing_authority() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = Arc::new(
        DatabaseManager::open(DatabaseConfiguration::new(
            directory.path().join("core.sqlite3"),
        ))
        .expect("database"),
    );
    let local = node('1', '2', '3', "Candidate", "candidate.local");
    let main = node('4', '5', '6', "Main", "main.local");
    let nodes = Arc::new(
        NodeManager::open(database.clone(), local.clone(), "initialize-node")
            .expect("node manager")
            .0,
    );
    let client = Arc::new(TestClient {
        main: main.clone(),
        local_node_id: local.identity().node_id().clone(),
        invite_id: invite_id(),
        exchanges: AtomicUsize::new(0),
    });
    let configurations = Arc::new(TestConfiguration::default());
    let services = Arc::new(TestServices {
        fail_activation: AtomicBool::new(true),
        ..TestServices::default()
    });
    let store = Arc::new(CrashStore::new(usize::MAX));
    let coordinator = coordinator(
        database.clone(),
        nodes.clone(),
        client,
        configurations.clone(),
        services.clone(),
        store.clone(),
    );

    assert_eq!(
        coordinator.activate(&request(), &AcceptConfirmation),
        Err(CorePairingActivationError::RolledBack)
    );
    let restored = nodes.local_node().expect("local");
    assert_eq!(restored.identity(), local.identity());
    assert_eq!(restored.display_name(), local.display_name());
    assert_eq!(restored.control_address(), local.control_address());
    assert_eq!(restored.role(), NodeRole::Main);
    assert_eq!(restored.state(), NodeState::Active);
    assert_eq!(
        restored.timestamps().updated_at(),
        UnixMilliseconds::new(2_000)
    );
    assert!(matches!(
        nodes.node(main.identity().node_id()),
        Err(NodeManagerError::Database(
            li_database::DatabaseError::NotFound { .. }
        ))
    ));
    assert!(DatabasePeerCredentialStore::new(database)
        .matching_peer_credentials(&digest('c'), 2)
        .expect("credential lookup")
        .is_empty());
    assert_eq!(services.restorations.load(Ordering::SeqCst), 1);
    assert_eq!(configurations.restores.load(Ordering::SeqCst), 1);
    assert_eq!(configurations.rollback_finishes.load(Ordering::SeqCst), 1);
    assert_eq!(
        store
            .load()
            .expect("activation record")
            .expect("stored activation")
            .phase(),
        CorePairingActivationPhase::RolledBack
    );
}

// Composes one coordinator over shared durable authorities and deterministic adapters.
fn coordinator(
    database: Arc<DatabaseManager>,
    nodes: Arc<NodeManager>,
    client: Arc<TestClient>,
    configurations: Arc<TestConfiguration>,
    services: Arc<TestServices>,
    store: Arc<CrashStore>,
) -> CorePairingActivationCoordinator {
    let authority_node_id = client.main.identity().node_id().clone();
    CorePairingActivationCoordinator::new(
        Arc::new(TestAuthority::new(database, nodes, authority_node_id)),
        client,
        Arc::new(TestTrust),
        Arc::new(ActiveCancellation),
        configurations,
        services,
        store,
        Arc::new(PanicWaiter),
    )
}

// Returns one complete active certificate package.
fn credentials() -> NodePairingCredentials {
    NodePairingCredentials::new(
        b"main-public-key".to_vec(),
        b"main-ca".to_vec(),
        b"child-certificate".to_vec(),
        b"membership-signature".to_vec(),
        digest('b'),
        UnixMilliseconds::new(500),
        UnixMilliseconds::new(500_000),
    )
    .expect("credentials")
}

// Returns one coherent remote enrollment for the selected approval state.
fn remote_enrollment(
    invite_id: &PairingInviteId,
    local_node_id: &NodeId,
    state: NodePairingState,
    comparison_code: Option<&str>,
) -> NodePairingEnrollment {
    NodePairingEnrollment::new(
        remote_status(invite_id, local_node_id, state, comparison_code),
        credentials(),
    )
    .expect("remote enrollment")
}

// Returns one exact remote status with comparison material only while approval is pending.
fn remote_status(
    invite_id: &PairingInviteId,
    local_node_id: &NodeId,
    state: NodePairingState,
    comparison_code: Option<&str>,
) -> NodePairingStatus {
    NodePairingStatus::new(
        invite_id.clone(),
        NodePairingMode::Remote,
        state,
        UnixMilliseconds::new(100_000),
        0,
        Some(local_node_id.clone()),
        comparison_code.map(str::to_string),
    )
    .expect("remote status")
}

// Returns one exact LAN join request with no caller-supplied machine proof fields.
fn request() -> CorePairingJoinRequest {
    CorePairingJoinRequest::new(
        invite_id(),
        NodeAddress::parse("main.local").expect("address"),
        9_769,
        digest('c'),
        Some("12345678".to_string()),
        Duration::from_secs(10),
    )
    .expect("request")
}

// Returns one coherent active main-shaped Node fixture.
fn node(
    node_character: char,
    machine_character: char,
    installation_character: char,
    name: &str,
    address: &str,
) -> Node {
    Node::new(
        NodeIdentity::new(
            NodeId::parse(&node_character.to_string().repeat(32)).expect("node"),
            MachineId::parse(&machine_character.to_string().repeat(32)).expect("machine"),
            InstallationId::parse(&installation_character.to_string().repeat(64))
                .expect("installation"),
        ),
        DisplayName::parse(name).expect("name"),
        NodeRole::Main,
        NodeState::Active,
        NodeAddress::parse(address).expect("address"),
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(1_000))
            .expect("timestamps"),
    )
}

// Returns one canonical fixed-length invitation identity.
fn invite_id() -> PairingInviteId {
    PairingInviteId::parse(&"7".repeat(32)).expect("invite")
}

// Returns one canonical SHA-256 fixture.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
}
