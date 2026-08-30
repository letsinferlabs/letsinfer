// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::{Arc, Mutex};

use li_authentication_manager::AuthenticationStoreError;
use li_core_interface::{NodeAddress, PairingInviteId, UnixMilliseconds};
use li_database::{DatabaseCommitDisposition, DatabaseError};
use li_node_manager::{
    NodePairingApiError, NodePairingApiPort, NodePairingApproveRequest, NodePairingChallenge,
    NodePairingCredentials, NodePairingEnrollRequest, NodePairingEnrollment, NodePairingInvitation,
    NodePairingMode, NodePairingOpenRequest, NodePairingState, NodePairingStatus,
};
use li_pairing_manager::{
    IssuedPairingWindow, PairingApproval, PairingCandidate, PairingChallenge, PairingChange,
    PairingClock, PairingError, PairingManager, PairingMode, PairingRecord, PairingRecordState,
    PairingResult, PairingStore, PairingWindowRequest,
};

use crate::{CorePairingEnrollmentCoordinator, CorePairingEnrollmentError};

// Isolates PairingManager lifecycle operations for deterministic application composition tests.
pub trait CoreNodePairingManagerPort: Send + Sync {
    // Opens one validated pairing window.
    fn open_window(
        &self,
        idempotency_key: &str,
        request: PairingWindowRequest,
    ) -> Result<PairingChange<IssuedPairingWindow>, PairingError>;

    // Returns one exact challenge after PairingManager enforces expiry and direct-link proof.
    fn challenge(
        &self,
        invite_id: &PairingInviteId,
        observed_peer_address: &NodeAddress,
    ) -> Result<PairingChallenge, PairingError> {
        let _ = (invite_id, observed_peer_address);
        Err(PairingError::StateUnavailable)
    }

    // Verifies one exact candidate against one live invitation.
    fn enroll_candidate(
        &self,
        idempotency_key: &str,
        invite_id: &PairingInviteId,
        candidate: &PairingCandidate,
    ) -> Result<PairingChange<PairingResult>, PairingError>;

    // Proposes one exact pending-to-active transition.
    fn approve_invitation(
        &self,
        idempotency_key: &str,
        invite_id: &PairingInviteId,
    ) -> Result<PairingChange<PairingApproval>, PairingError>;

    // Ends native advertisement only after the application confirms durable state.
    fn pairing_did_commit(&self, invite_id: &PairingInviteId);
}

impl CoreNodePairingManagerPort for PairingManager {
    // Delegates one open operation to the bounded PairingManager lifecycle.
    fn open_window(
        &self,
        idempotency_key: &str,
        request: PairingWindowRequest,
    ) -> Result<PairingChange<IssuedPairingWindow>, PairingError> {
        PairingManager::open(self, idempotency_key, request)
    }

    // Delegates one public challenge to PairingManager without bypassing mode authorization.
    fn challenge(
        &self,
        invite_id: &PairingInviteId,
        observed_peer_address: &NodeAddress,
    ) -> Result<PairingChallenge, PairingError> {
        PairingManager::challenge(self, invite_id, observed_peer_address)
    }

    // Delegates one candidate proof to PairingManager.
    fn enroll_candidate(
        &self,
        idempotency_key: &str,
        invite_id: &PairingInviteId,
        candidate: &PairingCandidate,
    ) -> Result<PairingChange<PairingResult>, PairingError> {
        PairingManager::enroll(self, idempotency_key, invite_id, candidate)
    }

    // Delegates one explicit remote approval proposal to PairingManager.
    fn approve_invitation(
        &self,
        idempotency_key: &str,
        invite_id: &PairingInviteId,
    ) -> Result<PairingChange<PairingApproval>, PairingError> {
        PairingManager::approve(self, idempotency_key, invite_id)
    }

    // Removes native discovery state only after an atomic application commit.
    fn pairing_did_commit(&self, invite_id: &PairingInviteId) {
        PairingManager::pairing_did_commit(self, invite_id);
    }
}

// Isolates the atomic Pairing-to-Authentication-and-Node commit boundary.
pub trait CoreNodePairingEnrollmentPort: Send + Sync {
    // Commits one verified initial enrollment under its exact replay identity.
    fn commit_pairing(
        &self,
        idempotency_key: &str,
        result: &PairingResult,
        committed_at: UnixMilliseconds,
    ) -> Result<DatabaseCommitDisposition, CorePairingEnrollmentError>;

    // Commits one explicit pending approval under its exact replay identity.
    fn approve_pairing(
        &self,
        idempotency_key: &str,
        approval: &PairingApproval,
        committed_at: UnixMilliseconds,
    ) -> Result<DatabaseCommitDisposition, CorePairingEnrollmentError>;
}

impl CoreNodePairingEnrollmentPort for CorePairingEnrollmentCoordinator {
    // Delegates one initial atomic commit and returns its applied-or-replayed disposition.
    fn commit_pairing(
        &self,
        idempotency_key: &str,
        result: &PairingResult,
        committed_at: UnixMilliseconds,
    ) -> Result<DatabaseCommitDisposition, CorePairingEnrollmentError> {
        CorePairingEnrollmentCoordinator::commit_pairing(
            self,
            idempotency_key,
            result,
            committed_at,
        )
        .map(|change| change.disposition())
    }

    // Delegates one approval atomic commit and returns its applied-or-replayed disposition.
    fn approve_pairing(
        &self,
        idempotency_key: &str,
        approval: &PairingApproval,
        committed_at: UnixMilliseconds,
    ) -> Result<DatabaseCommitDisposition, CorePairingEnrollmentError> {
        CorePairingEnrollmentCoordinator::approve_pairing(
            self,
            idempotency_key,
            approval,
            committed_at,
        )
        .map(|change| change.disposition())
    }
}

// Adapts PairingManager and its atomic application commit into the Node private API contract.
pub struct CoreNodePairingApi {
    manager: Arc<dyn CoreNodePairingManagerPort>,
    enrollment: Arc<dyn CoreNodePairingEnrollmentPort>,
    store: Arc<dyn PairingStore>,
    clock: Arc<dyn PairingClock>,
    operation_lock: Mutex<()>,
}

impl CoreNodePairingApi {
    // Creates one adapter from an explicitly shared pairing lifecycle, store, commit owner, and clock.
    pub const fn new(
        manager: Arc<dyn CoreNodePairingManagerPort>,
        enrollment: Arc<dyn CoreNodePairingEnrollmentPort>,
        store: Arc<dyn PairingStore>,
        clock: Arc<dyn PairingClock>,
    ) -> Self {
        Self {
            manager,
            enrollment,
            store,
            clock,
            operation_lock: Mutex::new(()),
        }
    }

    // Projects one durable pairing record into the closed Node status vocabulary.
    fn status_from_record(
        &self,
        record: &PairingRecord,
    ) -> Result<NodePairingStatus, NodePairingApiError> {
        status_from_record(record)
    }
}

impl NodePairingApiPort for CoreNodePairingApi {
    // Opens one pairing window and presents its setup code exactly once.
    fn open(
        &self,
        request: &NodePairingOpenRequest,
    ) -> Result<NodePairingInvitation, NodePairingApiError> {
        let _operation = self
            .operation_lock
            .lock()
            .map_err(|_| NodePairingApiError::Unavailable)?;
        let window =
            PairingWindowRequest::new(pairing_mode(request.mode()), request.lifetime_seconds())
                .map_err(pairing_error)?;
        let mut change = self
            .manager
            .open_window(request.idempotency_key(), window)
            .map_err(pairing_error)?;
        let setup_code = change
            .value_mut()
            .setup_code_mut()
            .and_then(|value| value.take());
        NodePairingInvitation::new(
            change.value().invite_id().clone(),
            node_pairing_mode(change.value().mode()),
            change.value().nonce().clone(),
            change.value().expires_at(),
            setup_code,
        )
    }

    // Returns one public challenge only after PairingManager validates the observed peer route.
    fn challenge(
        &self,
        invite_id: &PairingInviteId,
        observed_peer_address: &NodeAddress,
    ) -> Result<NodePairingChallenge, NodePairingApiError> {
        let challenge = self
            .manager
            .challenge(invite_id, observed_peer_address)
            .map_err(pairing_error)?;
        NodePairingChallenge::new(
            challenge.invite_id().clone(),
            node_pairing_mode(challenge.mode()),
            challenge.nonce().clone(),
            challenge.created_at(),
            challenge.expires_at(),
            challenge.main_node_id().clone(),
            challenge.main_address().clone(),
            challenge.main_private_port(),
            challenge.public_key_fingerprint().clone(),
            challenge.certificate_fingerprint().clone(),
        )
    }

    // Verifies one candidate and exposes credentials only after the atomic application commit.
    fn enroll(
        &self,
        request: &NodePairingEnrollRequest,
    ) -> Result<NodePairingEnrollment, NodePairingApiError> {
        let _operation = self
            .operation_lock
            .lock()
            .map_err(|_| NodePairingApiError::Unavailable)?;
        let candidate = PairingCandidate::new(
            request.candidate_identity().clone(),
            request.candidate_name().clone(),
            request.candidate_address().clone(),
            request.candidate_public_key().to_vec(),
            request.installation_created_at(),
            request.proof_signature().to_vec(),
            request.setup_code().map(str::to_string),
            request.observed_peer_address().clone(),
        )
        .map_err(pairing_error)?;
        let change = self
            .manager
            .enroll_candidate(request.idempotency_key(), request.invite_id(), &candidate)
            .map_err(pairing_error)?;
        let committed_at = self.clock.now().map_err(pairing_error)?;
        let disposition = self
            .enrollment
            .commit_pairing(request.idempotency_key(), change.value(), committed_at)
            .map_err(enrollment_error)?;
        if disposition == DatabaseCommitDisposition::Applied {
            self.manager.pairing_did_commit(request.invite_id());
        }
        enrollment_from_result(change.value())
    }

    // Activates one pending remote child only after the exact atomic approval commit.
    fn approve(
        &self,
        request: &NodePairingApproveRequest,
    ) -> Result<NodePairingStatus, NodePairingApiError> {
        let _operation = self
            .operation_lock
            .lock()
            .map_err(|_| NodePairingApiError::Unavailable)?;
        let change = self
            .manager
            .approve_invitation(request.idempotency_key(), request.invite_id())
            .map_err(pairing_error)?;
        let committed_at = self.clock.now().map_err(pairing_error)?;
        let disposition = self
            .enrollment
            .approve_pairing(request.idempotency_key(), change.value(), committed_at)
            .map_err(enrollment_error)?;
        if disposition == DatabaseCommitDisposition::Applied {
            self.manager.pairing_did_commit(request.invite_id());
        }
        self.status_from_record(change.value().pairing_record())
    }

    // Reads one exact durable invitation without alternate identity lookup.
    fn status(
        &self,
        invite_id: &PairingInviteId,
    ) -> Result<NodePairingStatus, NodePairingApiError> {
        let pairing = self
            .store
            .pairing(invite_id)
            .map_err(pairing_error)?
            .ok_or(NodePairingApiError::NotFound)?;
        self.status_from_record(pairing.record())
    }
}

// Converts one Node API mode into the PairingManager vocabulary without defaults.
fn pairing_mode(mode: &NodePairingMode) -> PairingMode {
    match mode {
        NodePairingMode::Lan => PairingMode::Lan,
        NodePairingMode::Remote => PairingMode::Remote,
        NodePairingMode::ConnectX {
            candidate_public_key_sha256,
            direct_interface,
        } => PairingMode::ConnectX {
            candidate_public_key: candidate_public_key_sha256.clone(),
            direct_interface: direct_interface.clone(),
        },
    }
}

// Converts one PairingManager mode into the Node API vocabulary without defaults.
fn node_pairing_mode(mode: &PairingMode) -> NodePairingMode {
    match mode {
        PairingMode::Lan => NodePairingMode::Lan,
        PairingMode::Remote => NodePairingMode::Remote,
        PairingMode::ConnectX {
            candidate_public_key,
            direct_interface,
        } => NodePairingMode::ConnectX {
            candidate_public_key_sha256: candidate_public_key.clone(),
            direct_interface: direct_interface.clone(),
        },
    }
}

// Projects one verified PairingManager result into public Node response material.
fn enrollment_from_result(
    result: &PairingResult,
) -> Result<NodePairingEnrollment, NodePairingApiError> {
    let credentials = result.credentials();
    NodePairingEnrollment::new(
        status_from_record(result.pairing_record())?,
        NodePairingCredentials::new(
            credentials.site_public_key().to_vec(),
            credentials.site_ca_certificate().to_vec(),
            credentials.member_certificate().to_vec(),
            credentials.membership_signature().to_vec(),
            credentials.member_leaf_sha256().clone(),
            credentials.member_valid_from(),
            credentials.member_expires_at(),
        )?,
    )
}

// Projects one validated durable record into an open, pending, or active status.
fn status_from_record(record: &PairingRecord) -> Result<NodePairingStatus, NodePairingApiError> {
    let (state, child_node_id, comparison_code) = match record.state() {
        PairingRecordState::Open => (NodePairingState::Open, None, None),
        PairingRecordState::PendingApproval => {
            let enrollment = record
                .enrollment()
                .ok_or(NodePairingApiError::InvalidResponse)?;
            let code = record
                .comparison_code_bytes()
                .map(|value| String::from_utf8(value.to_vec()))
                .transpose()
                .map_err(|_| NodePairingApiError::InvalidResponse)?;
            (
                NodePairingState::PendingApproval,
                Some(enrollment.child_identity().node_id().clone()),
                code,
            )
        }
        PairingRecordState::Active => {
            let enrollment = record
                .enrollment()
                .ok_or(NodePairingApiError::InvalidResponse)?;
            (
                NodePairingState::Active,
                Some(enrollment.child_identity().node_id().clone()),
                None,
            )
        }
    };
    NodePairingStatus::new(
        record.invite_id().clone(),
        node_pairing_mode(record.mode()),
        state,
        record.expires_at(),
        record.attempts(),
        child_node_id,
        comparison_code,
    )
}

// Maps PairingManager failures into one closed Node API error without proof detail.
fn pairing_error(error: PairingError) -> NodePairingApiError {
    match error {
        PairingError::MainOnly => NodePairingApiError::MainOnly,
        PairingError::NotFound => NodePairingApiError::NotFound,
        PairingError::Expired => NodePairingApiError::Expired,
        PairingError::Consumed
        | PairingError::AttemptLimit
        | PairingError::InvalidApproval
        | PairingError::StoreConflict => NodePairingApiError::Conflict,
        PairingError::InvalidRequest { .. }
        | PairingError::Unauthorized
        | PairingError::Interface(_) => NodePairingApiError::InvalidRequest,
        PairingError::StoreCorrupt => NodePairingApiError::InvalidResponse,
        PairingError::EntropyUnavailable
        | PairingError::DiscoveryUnavailable
        | PairingError::DirectLinkUnavailable
        | PairingError::TrustUnavailable
        | PairingError::StoreUnavailable
        | PairingError::StateUnavailable => NodePairingApiError::Unavailable,
    }
}

// Maps atomic application failures without exposing stored certificate or identity material.
fn enrollment_error(error: CorePairingEnrollmentError) -> NodePairingApiError {
    match error {
        CorePairingEnrollmentError::Pairing(error) => pairing_error(error),
        CorePairingEnrollmentError::Authentication(AuthenticationStoreError::Conflict) => {
            NodePairingApiError::Conflict
        }
        CorePairingEnrollmentError::Authentication(AuthenticationStoreError::Corrupt) => {
            NodePairingApiError::InvalidResponse
        }
        CorePairingEnrollmentError::Authentication(AuthenticationStoreError::Unavailable) => {
            NodePairingApiError::Unavailable
        }
        CorePairingEnrollmentError::Node(error) => match error {
            li_node_manager::NodeManagerError::Database(database) => database_error(database),
            li_node_manager::NodeManagerError::NodeIdentityConflict { .. }
            | li_node_manager::NodeManagerError::InvalidNodeTransition { .. } => {
                NodePairingApiError::Conflict
            }
            li_node_manager::NodeManagerError::DatabaseInUse => NodePairingApiError::Unavailable,
            li_node_manager::NodeManagerError::Interface(_)
            | li_node_manager::NodeManagerError::IdentityMismatch
            | li_node_manager::NodeManagerError::NotMain
            | li_node_manager::NodeManagerError::InvalidNodeEnrollment { .. }
            | li_node_manager::NodeManagerError::InvalidLocalRoleTransition { .. }
            | li_node_manager::NodeManagerError::InvalidHardwareObservation { .. }
            | li_node_manager::NodeManagerError::InvalidModelService { .. }
            | li_node_manager::NodeManagerError::CorruptState { .. }
            | li_node_manager::NodeManagerError::InvalidOperationTransition { .. } => {
                NodePairingApiError::InvalidResponse
            }
        },
        CorePairingEnrollmentError::Database(error) => database_error(error),
        CorePairingEnrollmentError::DatabaseMismatch
        | CorePairingEnrollmentError::IdentityMismatch
        | CorePairingEnrollmentError::InvalidMaterial
        | CorePairingEnrollmentError::CorruptCommit => NodePairingApiError::InvalidResponse,
    }
}

// Maps atomic database outcomes without copying record identities into diagnostics.
fn database_error(error: DatabaseError) -> NodePairingApiError {
    match error {
        DatabaseError::Conflict { .. } | DatabaseError::IdempotencyConflict { .. } => {
            NodePairingApiError::Conflict
        }
        DatabaseError::NotFound { .. }
        | DatabaseError::InvalidInput { .. }
        | DatabaseError::Corrupt { .. } => NodePairingApiError::InvalidResponse,
        DatabaseError::Unavailable { .. } | DatabaseError::Closed => {
            NodePairingApiError::Unavailable
        }
    }
}
