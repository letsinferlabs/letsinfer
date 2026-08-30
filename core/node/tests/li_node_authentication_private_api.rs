// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::{Arc, Mutex};

use li_authentication_manager::{
    ApiKey, ApiKeyLimits, ApiKeyModelScope, ApiKeyPolicy, AuthenticationError, ControllerError,
    ControllerPublicKey, ControllerRole, ControllerState,
};
use li_core_interface::{
    ApiKeyId, ControllerId, CredentialId, DisplayName, EntityTimestamps, InstallationId, MachineId,
    Node, NodeAddress, NodeId, NodeIdentity, NodeRole, NodeState, PairingInviteId, Sha256Digest,
    UnixMilliseconds,
};
use li_database::{DatabaseConfiguration, DatabaseManager};
use li_node_manager::{
    NodeApiKeyPolicyUpdate, NodeAuthenticationApiPort, NodeControllerEnrollmentCandidate,
    NodeControllerEnrollmentReceipt, NodeControllerSummary, NodeIssuedApiKey, NodeManager,
    NodePairingApiError, NodePairingApiPort, NodePairingApproveRequest, NodePairingEnrollRequest,
    NodePairingEnrollment, NodePairingInvitation, NodePairingOpenRequest, NodePairingStatus,
    NodePrivateAction, NodePrivateApi, NodePrivateApiError, NodePrivateAuthorizationProvider,
    NodePrivateRequest,
};
use sha2::Digest;

// Authorizes or denies every private action without consulting state.
struct AuthorizationMock(bool);

impl NodePrivateAuthorizationProvider for AuthorizationMock {
    // Applies the configured decision before any manager projection runs.
    fn authorize(
        &self,
        _principal_id: &CredentialId,
        _action: NodePrivateAction,
    ) -> Result<(), NodePrivateApiError> {
        if self.0 {
            Ok(())
        } else {
            Err(NodePrivateApiError::AuthorizationDenied)
        }
    }

    // Applies the same deterministic decision to the distinct controller principal path.
    fn authorize_controller(
        &self,
        _controller_id: &ControllerId,
        _certificate_sha256: &Sha256Digest,
        _action: NodePrivateAction,
    ) -> Result<(), NodePrivateApiError> {
        if self.0 {
            Ok(())
        } else {
            Err(NodePrivateApiError::AuthorizationDenied)
        }
    }
}

// Rejects every unused pairing action.
struct PairingUnavailable;

impl NodePairingApiPort for PairingUnavailable {
    // Rejects invitation opening.
    fn open(
        &self,
        _request: &NodePairingOpenRequest,
    ) -> Result<NodePairingInvitation, NodePairingApiError> {
        Err(NodePairingApiError::Unavailable)
    }

    // Rejects pairing enrollment.
    fn enroll(
        &self,
        _request: &NodePairingEnrollRequest,
    ) -> Result<NodePairingEnrollment, NodePairingApiError> {
        Err(NodePairingApiError::Unavailable)
    }

    // Rejects pairing approval.
    fn approve(
        &self,
        _request: &NodePairingApproveRequest,
    ) -> Result<NodePairingStatus, NodePairingApiError> {
        Err(NodePairingApiError::Unavailable)
    }

    // Rejects pairing status.
    fn status(
        &self,
        _invite_id: &PairingInviteId,
    ) -> Result<NodePairingStatus, NodePairingApiError> {
        Err(NodePairingApiError::Unavailable)
    }
}

// Records every authentication call after authorization and active-main gating.
#[derive(Default)]
struct AuthenticationMock {
    calls: Mutex<Vec<&'static str>>,
}

impl NodeAuthenticationApiPort for AuthenticationMock {
    // Records one controller enrollment call.
    fn add_controller(
        &self,
        _candidate: NodeControllerEnrollmentCandidate,
        _role: ControllerRole,
    ) -> Result<NodeControllerEnrollmentReceipt, ControllerError> {
        self.calls.lock().expect("calls").push("controller_add");
        controller_receipt()
    }

    // Records one controller listing call.
    fn controllers(&self) -> Result<Vec<NodeControllerSummary>, ControllerError> {
        self.calls.lock().expect("calls").push("controller_list");
        Ok(vec![controller()])
    }

    // Records one controller revocation call.
    fn revoke_controller(&self, _selector: &str) -> Result<NodeControllerSummary, ControllerError> {
        self.calls.lock().expect("calls").push("controller_revoke");
        Ok(controller())
    }

    // Records one create call and returns the fixed one-time token.
    fn create(
        &self,
        name: DisplayName,
        policy: ApiKeyPolicy,
    ) -> Result<NodeIssuedApiKey, AuthenticationError> {
        self.calls.lock().expect("calls").push("create");
        Ok(NodeIssuedApiKey::new(api_key(name, policy), token()))
    }

    // Records one list call.
    fn keys(&self) -> Result<Vec<ApiKey>, AuthenticationError> {
        self.calls.lock().expect("calls").push("list");
        Ok(vec![api_key(
            DisplayName::parse("Application").expect("name"),
            policy(),
        )])
    }

    // Records one detail call.
    fn key(&self, _selector: &str) -> Result<ApiKey, AuthenticationError> {
        self.calls.lock().expect("calls").push("show");
        Ok(api_key(
            DisplayName::parse("Application").expect("name"),
            policy(),
        ))
    }

    // Records one policy update call.
    fn update(
        &self,
        _selector: &str,
        _update: NodeApiKeyPolicyUpdate,
    ) -> Result<ApiKey, AuthenticationError> {
        self.calls.lock().expect("calls").push("update");
        Ok(api_key(
            DisplayName::parse("Application").expect("name"),
            policy(),
        ))
    }

    // Records one rotation call and returns the fixed one-time token.
    fn rotate(&self, _selector: &str) -> Result<NodeIssuedApiKey, AuthenticationError> {
        self.calls.lock().expect("calls").push("rotate");
        Ok(NodeIssuedApiKey::new(
            api_key(DisplayName::parse("Application").expect("name"), policy()),
            token(),
        ))
    }

    // Records one revocation call.
    fn revoke(&self, _selector: &str) -> Result<ApiKey, AuthenticationError> {
        self.calls.lock().expect("calls").push("revoke");
        Ok(api_key(
            DisplayName::parse("Application").expect("name"),
            policy(),
        ))
    }
}

// Returns one fixed complete policy.
fn policy() -> ApiKeyPolicy {
    ApiKeyPolicy::new(
        ApiKeyModelScope::all(),
        None,
        ApiKeyLimits::default(),
        None,
        None,
    )
}

// Returns one fixed non-secret API-key snapshot.
fn api_key(name: DisplayName, policy: ApiKeyPolicy) -> ApiKey {
    ApiKey::new(
        ApiKeyId::parse(&"a".repeat(32)).expect("key"),
        name,
        policy,
        UnixMilliseconds::new(1_000),
        None,
        None,
    )
    .expect("API key")
}

// Returns one fixed identity-bound bearer token.
fn token() -> String {
    format!("li_{}_{}", "a".repeat(32), "b".repeat(64))
}

// Returns one fixed secret-free active controller snapshot.
fn controller() -> NodeControllerSummary {
    NodeControllerSummary::restore(
        ControllerId::parse(&"d".repeat(32)).expect("controller"),
        DisplayName::parse("Desk Mac").expect("controller name"),
        ControllerRole::Administrator,
        ControllerState::Active,
        Sha256Digest::parse(&"e".repeat(64)).expect("certificate"),
        Sha256Digest::parse(&"f".repeat(64)).expect("public key"),
        UnixMilliseconds::new(0),
        UnixMilliseconds::new(10_000),
        UnixMilliseconds::new(1_000),
        Some(UnixMilliseconds::new(1_000)),
        None,
    )
    .expect("controller summary")
}

// Opens one initialized Node manager under the requested local role and state.
fn manager(directory: &tempfile::TempDir, role: NodeRole, state: NodeState) -> Arc<NodeManager> {
    let database = Arc::new(
        DatabaseManager::open(DatabaseConfiguration::new(
            directory.path().join("core.sqlite3"),
        ))
        .expect("database"),
    );
    Arc::new(
        NodeManager::open(
            database,
            Node::new(
                NodeIdentity::new(
                    NodeId::parse(&"1".repeat(32)).expect("node"),
                    MachineId::parse(&"2".repeat(32)).expect("machine"),
                    InstallationId::parse(&"3".repeat(64)).expect("installation"),
                ),
                DisplayName::parse("Home AI").expect("name"),
                role,
                state,
                NodeAddress::parse("homeai.local").expect("address"),
                None,
                EntityTimestamps::new(UnixMilliseconds::new(1), UnixMilliseconds::new(1))
                    .expect("timestamps"),
            ),
            "initialize-node",
        )
        .expect("manager")
        .0,
    )
}

// Composes one private API with deterministic authorization and authentication ports.
fn api(
    directory: &tempfile::TempDir,
    role: NodeRole,
    state: NodeState,
    authorized: bool,
    authentication: Arc<AuthenticationMock>,
) -> NodePrivateApi {
    NodePrivateApi::new(
        manager(directory, role, state),
        Arc::new(AuthorizationMock(authorized)),
        Arc::new(PairingUnavailable),
    )
    .with_authentication(authentication)
}

// Returns one fixed remote principal identity.
fn principal() -> CredentialId {
    CredentialId::parse(&"c".repeat(32)).expect("credential")
}

// Returns one fixed proof-validated public controller candidate.
fn controller_candidate() -> NodeControllerEnrollmentCandidate {
    NodeControllerEnrollmentCandidate::new(
        ControllerId::parse(&"c".repeat(32)).expect("controller"),
        DisplayName::parse("Desk Mac").expect("controller name"),
        ControllerPublicKey::new(vec![7; 96]).expect("public key"),
    )
}

// Returns one active controller commit receipt with only public certificate bytes.
fn controller_receipt() -> Result<NodeControllerEnrollmentReceipt, ControllerError> {
    let certificate = b"public-controller-certificate".to_vec();
    let mut summary = controller();
    let fingerprint = Sha256Digest::parse(&format!("{:x}", sha2::Sha256::digest(&certificate)))
        .expect("certificate digest");
    summary = NodeControllerSummary::restore(
        summary.controller_id().clone(),
        summary.name().clone(),
        summary.role(),
        summary.state(),
        fingerprint,
        summary.public_key_sha256().clone(),
        summary.certificate_valid_from(),
        summary.certificate_expires_at(),
        summary.issued_at(),
        summary.activated_at(),
        summary.revoked_at(),
    )?;
    NodeControllerEnrollmentReceipt::restore(summary, certificate)
}

// Dispatches every authentication leaf only after authorization and active-main readiness.
#[test]
fn private_api_routes_every_authentication_leaf_through_the_injected_port() {
    let directory = tempfile::tempdir().expect("directory");
    let authentication = Arc::new(AuthenticationMock::default());
    let api = api(
        &directory,
        NodeRole::Main,
        NodeState::Active,
        true,
        authentication.clone(),
    );
    let controller_requests = [
        NodePrivateRequest::AddController {
            candidate: controller_candidate(),
            role: ControllerRole::Administrator,
        },
        NodePrivateRequest::ReadControllers,
        NodePrivateRequest::RevokeController {
            selector: "Desk Mac".to_string(),
        },
    ];
    for request in controller_requests {
        api.dispatch_local(api.manager().local_node_id(), request)
            .expect("local controller dispatch");
    }
    let key_requests = [
        NodePrivateRequest::CreateApiKey {
            name: DisplayName::parse("Application").expect("name"),
            policy: policy(),
        },
        NodePrivateRequest::ReadApiKeys,
        NodePrivateRequest::ReadApiKey {
            selector: "Application".to_string(),
        },
        NodePrivateRequest::UpdateApiKeyPolicy {
            selector: "Application".to_string(),
            update: NodeApiKeyPolicyUpdate::default(),
        },
        NodePrivateRequest::RotateApiKey {
            selector: "Application".to_string(),
        },
        NodePrivateRequest::RevokeApiKey {
            selector: "Application".to_string(),
        },
    ];
    for request in key_requests {
        api.dispatch(&principal(), request).expect("dispatch");
    }
    assert_eq!(
        authentication.calls.lock().expect("calls").as_slice(),
        &[
            "controller_add",
            "controller_list",
            "controller_revoke",
            "create",
            "list",
            "show",
            "update",
            "rotate",
            "revoke"
        ]
    );
}

// Routes an active controller only through the non-local remote surface.
#[test]
fn private_api_keeps_controller_and_peer_authorization_paths_distinct() {
    let directory = tempfile::tempdir().expect("directory");
    let controller_api = api(
        &directory,
        NodeRole::Main,
        NodeState::Active,
        true,
        Arc::new(AuthenticationMock::default()),
    );
    let controller_id = ControllerId::parse(&"c".repeat(32)).expect("controller");
    let certificate = Sha256Digest::parse(&"d".repeat(64)).expect("certificate");
    assert!(controller_api
        .dispatch_controller(
            &controller_id,
            &certificate,
            NodePrivateRequest::ReadLocalNode,
        )
        .is_ok());
    assert_eq!(
        controller_api.dispatch_controller(
            &controller_id,
            &certificate,
            NodePrivateRequest::ReadControllers,
        ),
        Err(NodePrivateApiError::AuthorizationDenied)
    );

    let denied_directory = tempfile::tempdir().expect("directory");
    let denied = api(
        &denied_directory,
        NodeRole::Main,
        NodeState::Active,
        false,
        Arc::new(AuthenticationMock::default()),
    );
    assert_eq!(
        denied.dispatch_controller(
            &controller_id,
            &certificate,
            NodePrivateRequest::ReadLocalNode,
        ),
        Err(NodePrivateApiError::AuthorizationDenied)
    );
}

// Denies before the authentication port for remote authorization and local role readiness.
#[test]
fn private_api_denies_before_authentication_storage_or_entropy() {
    let denied_directory = tempfile::tempdir().expect("directory");
    let denied_authentication = Arc::new(AuthenticationMock::default());
    let denied = api(
        &denied_directory,
        NodeRole::Main,
        NodeState::Active,
        false,
        denied_authentication.clone(),
    );
    assert_eq!(
        denied
            .dispatch(&principal(), NodePrivateRequest::ReadApiKeys)
            .expect_err("authorization denial"),
        NodePrivateApiError::AuthorizationDenied
    );
    assert!(denied_authentication
        .calls
        .lock()
        .expect("calls")
        .is_empty());

    assert_eq!(
        denied
            .dispatch(&principal(), NodePrivateRequest::ReadControllers)
            .expect_err("controller remote denial"),
        NodePrivateApiError::AuthorizationDenied
    );

    let child_directory = tempfile::tempdir().expect("directory");
    let child_authentication = Arc::new(AuthenticationMock::default());
    let child = api(
        &child_directory,
        NodeRole::Child,
        NodeState::Active,
        true,
        child_authentication.clone(),
    );
    assert_eq!(
        child
            .dispatch(&principal(), NodePrivateRequest::ReadApiKeys)
            .expect_err("active-main denial"),
        NodePrivateApiError::ActiveMainRequired
    );
    assert!(child_authentication.calls.lock().expect("calls").is_empty());
}
