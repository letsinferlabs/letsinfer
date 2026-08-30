// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use li_core_interface::{
    CredentialId, DisplayName, EntityTimestamps, InstallationId, MachineId, Node, NodeAddress,
    NodeId, NodeIdentity, NodeRole, NodeState, PairingInviteId, Sha256Digest, UnixMilliseconds,
};
use li_database::{DatabaseClock, DatabaseConfiguration, DatabaseError, DatabaseManager};
use li_node_manager::{
    NodeManager, NodePairingApiError, NodePairingApiPort, NodePairingApproveRequest,
    NodePairingCredentials, NodePairingEnrollRequest, NodePairingEnrollment, NodePairingInvitation,
    NodePairingMode, NodePairingOpenRequest, NodePairingState, NodePairingStatus,
    NodePrivateAction, NodePrivateApi, NodePrivateApiError, NodePrivateAuthorizationProvider,
    NodePrivateRequest, NodePrivateResponse,
};

// Supplies deterministic increasing database commit timestamps.
struct TestClock(AtomicI64);

impl DatabaseClock for TestClock {
    // Returns one unique commit timestamp.
    fn now_unix_milliseconds(&self) -> Result<i64, DatabaseError> {
        Ok(self.0.fetch_add(1, Ordering::SeqCst))
    }
}

// Returns one repeated canonical identity.
fn identity(character: char, length: usize) -> String {
    character.to_string().repeat(length)
}

// Returns one coherent local Node fixture for an exact topology role.
fn local_node(role: NodeRole) -> Node {
    Node::new(
        NodeIdentity::new(
            NodeId::parse(&identity('1', 32)).expect("node"),
            MachineId::parse(&identity('2', 32)).expect("machine"),
            InstallationId::parse(&identity('3', 64)).expect("installation"),
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

// Opens one isolated manager for the supplied local topology role.
fn manager(directory: &tempfile::TempDir, role: NodeRole) -> Arc<NodeManager> {
    let database = Arc::new(
        DatabaseManager::open(
            DatabaseConfiguration::new(directory.path().join("core.sqlite3"))
                .with_busy_timeout(Duration::from_secs(1))
                .with_clock(Arc::new(TestClock(AtomicI64::new(10_000)))),
        )
        .expect("database"),
    );
    Arc::new(
        NodeManager::open(database, local_node(role), "initialize-node")
            .expect("manager")
            .0,
    )
}

// Allows every action while retaining the exact authorization order.
#[derive(Default)]
struct AllowAuthorization {
    calls: Mutex<Vec<NodePrivateAction>>,
}

impl NodePrivateAuthorizationProvider for AllowAuthorization {
    // Records and allows one exact private action.
    fn authorize(
        &self,
        _principal_id: &CredentialId,
        action: NodePrivateAction,
    ) -> Result<(), NodePrivateApiError> {
        self.calls.lock().expect("calls").push(action);
        Ok(())
    }
}

// Denies every action before role checks or pairing-port calls.
struct DenyAuthorization;

impl NodePrivateAuthorizationProvider for DenyAuthorization {
    // Returns one generic authorization denial.
    fn authorize(
        &self,
        _principal_id: &CredentialId,
        _action: NodePrivateAction,
    ) -> Result<(), NodePrivateApiError> {
        Err(NodePrivateApiError::AuthorizationDenied)
    }
}

// Names the exact pairing-port method reached by private API dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PairingCall {
    Open,
    Enroll,
    Approve,
    Status,
}

// Returns deterministic pairing values and records every call without manager coupling.
struct MockPairing {
    calls: Mutex<Vec<PairingCall>>,
    failure: Mutex<Option<NodePairingApiError>>,
}

impl MockPairing {
    // Creates one successful deterministic pairing port.
    fn new() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            failure: Mutex::new(None),
        }
    }

    // Returns the injected failure when one is configured.
    fn require_available(&self) -> Result<(), NodePairingApiError> {
        self.failure.lock().expect("failure").map_or(Ok(()), Err)
    }
}

impl NodePairingApiPort for MockPairing {
    // Records and returns the exact opened invitation fixture.
    fn open(
        &self,
        _request: &NodePairingOpenRequest,
    ) -> Result<NodePairingInvitation, NodePairingApiError> {
        self.calls.lock().expect("calls").push(PairingCall::Open);
        self.require_available()?;
        invitation()
    }

    // Records and returns the exact pending enrollment fixture.
    fn enroll(
        &self,
        _request: &NodePairingEnrollRequest,
    ) -> Result<NodePairingEnrollment, NodePairingApiError> {
        self.calls.lock().expect("calls").push(PairingCall::Enroll);
        self.require_available()?;
        enrollment()
    }

    // Records and returns the exact active approval status fixture.
    fn approve(
        &self,
        _request: &NodePairingApproveRequest,
    ) -> Result<NodePairingStatus, NodePairingApiError> {
        self.calls.lock().expect("calls").push(PairingCall::Approve);
        self.require_available()?;
        active_status()
    }

    // Records and returns the exact pending status fixture.
    fn status(
        &self,
        _invite_id: &PairingInviteId,
    ) -> Result<NodePairingStatus, NodePairingApiError> {
        self.calls.lock().expect("calls").push(PairingCall::Status);
        self.require_available()?;
        pending_status()
    }
}

// Returns the exact invitation identity shared across pairing fixtures.
fn invite_id() -> PairingInviteId {
    PairingInviteId::parse(&identity('4', 32)).expect("invite")
}

// Returns one exact remote pairing invitation.
fn invitation() -> Result<NodePairingInvitation, NodePairingApiError> {
    NodePairingInvitation::new(
        invite_id(),
        NodePairingMode::Remote,
        Sha256Digest::parse(&identity('5', 64)).expect("nonce"),
        UnixMilliseconds::new(10_000),
        Some("12345678".to_string()),
    )
}

// Returns one exact verified child identity.
fn child_identity() -> NodeIdentity {
    NodeIdentity::new(
        NodeId::parse(&identity('6', 32)).expect("node"),
        MachineId::parse(&identity('7', 32)).expect("machine"),
        InstallationId::parse(&identity('8', 64)).expect("installation"),
    )
}

// Returns one pending remote status containing its human comparison code.
fn pending_status() -> Result<NodePairingStatus, NodePairingApiError> {
    NodePairingStatus::new(
        invite_id(),
        NodePairingMode::Remote,
        NodePairingState::PendingApproval,
        UnixMilliseconds::new(10_000),
        0,
        Some(child_identity().node_id().clone()),
        Some("654321".to_string()),
    )
}

// Returns the same pairing identity after explicit approval.
fn active_status() -> Result<NodePairingStatus, NodePairingApiError> {
    NodePairingStatus::new(
        invite_id(),
        NodePairingMode::Remote,
        NodePairingState::Active,
        UnixMilliseconds::new(10_000),
        0,
        Some(child_identity().node_id().clone()),
        None,
    )
}

// Returns one exact bounded public trust package.
fn credentials() -> Result<NodePairingCredentials, NodePairingApiError> {
    NodePairingCredentials::new(
        vec![b'a'; 128],
        vec![b'b'; 128],
        vec![b'c'; 128],
        vec![b'd'; 64],
        Sha256Digest::parse(&identity('9', 64)).expect("leaf"),
        UnixMilliseconds::new(900),
        UnixMilliseconds::new(20_000),
    )
}

// Returns one pending enrollment containing its exact public trust package.
fn enrollment() -> Result<NodePairingEnrollment, NodePairingApiError> {
    NodePairingEnrollment::new(pending_status()?, credentials()?)
}

// Returns one exact candidate request for the main-owned pairing port.
fn enroll_request() -> NodePairingEnrollRequest {
    NodePairingEnrollRequest::new(
        "enroll-pairing".to_string(),
        invite_id(),
        child_identity(),
        DisplayName::parse("Node 2").expect("name"),
        NodeAddress::parse("homeai-node-2.local").expect("address"),
        vec![b'p'; 128],
        UnixMilliseconds::new(800),
        vec![b's'; 64],
        Some("12345678".to_string()),
        NodeAddress::parse("192.168.1.20").expect("peer"),
    )
    .expect("enroll request")
}

// Returns one exact authenticated remote principal.
fn principal() -> CredentialId {
    CredentialId::parse(&identity('a', 32)).expect("principal")
}

// Dispatches open, enroll, approval, and status through one injected pairing capability.
#[test]
fn private_api_routes_complete_pairing_surface_after_authorization() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let pairing = Arc::new(MockPairing::new());
    let authorization = Arc::new(AllowAuthorization::default());
    let api = NodePrivateApi::new(
        manager(&directory, NodeRole::Main),
        authorization.clone(),
        pairing.clone(),
    );
    let requests = [
        NodePrivateRequest::OpenPairing(
            NodePairingOpenRequest::new("open-pairing".to_string(), NodePairingMode::Remote, 180)
                .expect("open request"),
        ),
        NodePrivateRequest::EnrollPairing(enroll_request()),
        NodePrivateRequest::ApprovePairing(
            NodePairingApproveRequest::new("approve-pairing".to_string(), invite_id())
                .expect("approve request"),
        ),
        NodePrivateRequest::ReadPairingStatus {
            invite_id: invite_id(),
        },
    ];
    let responses = requests
        .into_iter()
        .map(|request| api.dispatch(&principal(), request).expect("dispatch"))
        .collect::<Vec<_>>();
    assert!(matches!(
        responses[0],
        NodePrivateResponse::PairingInvitation(_)
    ));
    assert!(matches!(
        responses[1],
        NodePrivateResponse::PairingEnrollment(_)
    ));
    assert!(matches!(
        responses[2],
        NodePrivateResponse::PairingStatus(_)
    ));
    assert!(matches!(
        responses[3],
        NodePrivateResponse::PairingStatus(_)
    ));
    assert_eq!(
        *pairing.calls.lock().expect("calls"),
        [
            PairingCall::Open,
            PairingCall::Enroll,
            PairingCall::Approve,
            PairingCall::Status
        ]
    );
    assert_eq!(
        *authorization.calls.lock().expect("authorization calls"),
        [
            NodePrivateAction::OpenPairing,
            NodePrivateAction::EnrollPairing,
            NodePrivateAction::ApprovePairing,
            NodePrivateAction::ReadPairingStatus
        ]
    );
}

// Rejects pairing on a child Node after authorization but before the injected port is reached.
#[test]
fn private_api_enforces_active_main_role_for_every_pairing_action() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let pairing = Arc::new(MockPairing::new());
    let api = NodePrivateApi::new(
        manager(&directory, NodeRole::Child),
        Arc::new(AllowAuthorization::default()),
        pairing.clone(),
    );
    let requests = [
        NodePrivateRequest::OpenPairing(
            NodePairingOpenRequest::new("open-pairing".to_string(), NodePairingMode::Remote, 180)
                .expect("open request"),
        ),
        NodePrivateRequest::EnrollPairing(enroll_request()),
        NodePrivateRequest::ApprovePairing(
            NodePairingApproveRequest::new("approve-pairing".to_string(), invite_id())
                .expect("approve request"),
        ),
        NodePrivateRequest::ReadPairingStatus {
            invite_id: invite_id(),
        },
    ];
    for request in requests {
        assert_eq!(
            api.dispatch(&principal(), request).expect_err("main only"),
            NodePrivateApiError::ActiveMainRequired
        );
    }
    assert!(pairing.calls.lock().expect("calls").is_empty());
}

// Proves remote authorization denial precedes role checks and all pairing mechanisms.
#[test]
fn private_api_authorization_denial_precedes_pairing_port_dispatch() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let pairing = Arc::new(MockPairing::new());
    let api = NodePrivateApi::new(
        manager(&directory, NodeRole::Main),
        Arc::new(DenyAuthorization),
        pairing.clone(),
    );
    assert_eq!(
        api.dispatch(
            &principal(),
            NodePrivateRequest::ReadPairingStatus {
                invite_id: invite_id(),
            },
        )
        .expect_err("denied"),
        NodePrivateApiError::AuthorizationDenied
    );
    assert!(pairing.calls.lock().expect("calls").is_empty());
}

// Preserves one closed pairing failure and keeps proof and code material out of diagnostics.
#[test]
fn private_api_preserves_redacted_pairing_failures() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let pairing = Arc::new(MockPairing::new());
    *pairing.failure.lock().expect("failure") = Some(NodePairingApiError::Conflict);
    let api = NodePrivateApi::new(
        manager(&directory, NodeRole::Main),
        Arc::new(AllowAuthorization::default()),
        pairing,
    );
    let error = api
        .dispatch(
            &principal(),
            NodePrivateRequest::EnrollPairing(enroll_request()),
        )
        .expect_err("conflict");
    assert_eq!(
        error,
        NodePrivateApiError::Pairing(NodePairingApiError::Conflict)
    );
    let presented = format!("{error:?} {error}");
    assert!(!presented.contains("12345678"));
    assert!(!presented.contains(&"s".repeat(64)));
}
