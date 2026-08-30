// SPDX-License-Identifier: AGPL-3.0-only

mod li_pairing_candidate_trust;
mod li_pairing_error;
mod li_pairing_native_command;
mod li_pairing_native_direct_link;
mod li_pairing_native_discovery;
mod li_pairing_native_trust;
mod li_pairing_provider;
mod li_pairing_setup_code;
mod li_pairing_store;
mod li_pairing_types;

pub use li_pairing_candidate_trust::{
    OpenSslPairingCandidateTrustProvider, PairingCandidateIdentityFiles,
    PairingCandidateTrustProvider,
};
pub use li_pairing_error::PairingError;
pub use li_pairing_native_command::{
    PairingNativeCommand, PairingNativeCommandOutput, PairingNativeCommandRunner,
    PairingNativeProcess, SystemPairingNativeCommandRunner,
};
pub use li_pairing_native_direct_link::{
    LinuxPairingDirectLinkProvider, PairingDirectLinkIo, SystemPairingDirectLinkIo,
};
pub use li_pairing_native_discovery::{
    NativePairingCandidateDiscoveryProvider, NativePairingDiscoveryBrowser,
    NativePairingDiscoveryProvider, PairingCandidateAdvertisement, PairingDiscoveredAdvertisement,
    PairingDiscoveredCandidate, PairingDiscoveryMode, PairingDiscoveryPlatform,
    PAIRING_CANDIDATE_DISCOVERY_SERVICE_TYPE, PAIRING_DISCOVERY_PORT,
    PAIRING_DISCOVERY_SERVICE_TYPE,
};
pub use li_pairing_native_trust::{
    pairing_membership_transcript, OpenSslPairingTrustProvider, PairingTrustIdentityFiles,
    PairingTrustWorkspaceIo, SystemPairingTrustWorkspaceIo,
};
pub use li_pairing_provider::{
    PairingClock, PairingDirectLinkProvider, PairingDiscoveryProvider, PairingMaterialProvider,
    PairingTrustProvider, SystemPairingClock, SystemPairingMaterialProvider,
};
pub use li_pairing_setup_code::{
    HmacPairingSetupCodeProvider, PairingSetupCodeProvider, PairingSetupSecretFile,
    PairingSetupSecretFileProvider, PairingSetupSecretFileReference,
    SystemPairingSetupSecretFileProvider,
};
pub use li_pairing_store::{
    PairingApproval, PairingEnrollmentMaterial, PairingOpenReplayMaterial,
    PairingPeerCredentialMaterial, PairingRecord, PairingRecordState, PairingReplayIdentity,
    PairingReplayOperation, PairingReplayRecord, PairingStore, VersionedPairingRecord,
};
pub use li_pairing_types::{
    IssuedPairingWindow, PairingAdvertisement, PairingCandidate, PairingChallenge,
    PairingComparisonCode, PairingContext, PairingCredentials, PairingMembershipState, PairingMode,
    PairingResult, PairingSetupCode, PairingWindowRequest,
};

use std::sync::{Arc, Mutex};

use li_core_interface::{PairingInviteId, Sha256Digest, UnixMilliseconds};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const MAX_INVITATIONS: usize = 16;
const MAX_ATTEMPTS: u8 = 5;
const PROOF_FUTURE_TOLERANCE_MILLISECONDS: u64 = 300_000;
const IDEMPOTENCY_DOMAIN: &[u8] = b"letsinfer-pairing-idempotency-v1\0";
const OPEN_REQUEST_DOMAIN: &[u8] = b"letsinfer-pairing-open-request-v1\0";
const ENROLL_REQUEST_DOMAIN: &[u8] = b"letsinfer-pairing-enroll-request-v1\0";
const APPROVE_REQUEST_DOMAIN: &[u8] = b"letsinfer-pairing-approve-request-v1\0";
const TRANSCRIPT_DOMAIN: &[u8] = b"letsinfer-child-enrollment-v1\0";
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 255;

// Describes one completed PairingManager lifecycle change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PairingEvent {
    WindowOpened {
        invite_id: PairingInviteId,
    },
    WindowClosed {
        invite_id: PairingInviteId,
    },
    ChildPaired {
        invite_id: PairingInviteId,
        child_node_id: li_core_interface::NodeId,
    },
}

// Returns one pairing value and its completed domain event.
#[derive(Debug)]
pub struct PairingChange<Value> {
    value: Value,
    event: PairingEvent,
}

impl<Value> PairingChange<Value> {
    // Creates one successful pairing lifecycle result.
    const fn new(value: Value, event: PairingEvent) -> Self {
        Self { value, event }
    }

    // Returns the pairing lifecycle value.
    pub const fn value(&self) -> &Value {
        &self.value
    }

    // Returns mutable ownership for one-time setup-code presentation.
    pub fn value_mut(&mut self) -> &mut Value {
        &mut self.value
    }

    // Returns the completed pairing domain event.
    pub const fn event(&self) -> &PairingEvent {
        &self.event
    }
}

// Owns bounded invitation state and the complete proof-to-trust lifecycle.
pub struct PairingManager {
    context: PairingContext,
    discovery: Arc<dyn PairingDiscoveryProvider>,
    direct_link: Arc<dyn PairingDirectLinkProvider>,
    trust: Arc<dyn PairingTrustProvider>,
    material: Arc<dyn PairingMaterialProvider>,
    setup_code: Arc<dyn PairingSetupCodeProvider>,
    clock: Arc<dyn PairingClock>,
    store: Arc<dyn PairingStore>,
    operation_lock: Mutex<()>,
}

impl PairingManager {
    // Creates one pairing owner from explicit identity and native capabilities.
    pub fn new(
        context: PairingContext,
        discovery: Arc<dyn PairingDiscoveryProvider>,
        direct_link: Arc<dyn PairingDirectLinkProvider>,
        trust: Arc<dyn PairingTrustProvider>,
        material: Arc<dyn PairingMaterialProvider>,
        setup_code: Arc<dyn PairingSetupCodeProvider>,
        clock: Arc<dyn PairingClock>,
        store: Arc<dyn PairingStore>,
    ) -> Self {
        Self {
            context,
            discovery,
            direct_link,
            trust,
            material,
            setup_code,
            clock,
            store,
            operation_lock: Mutex::new(()),
        }
    }

    // Opens, stores, and advertises one bounded pairing invitation.
    pub fn open(
        &self,
        idempotency_key: &str,
        request: PairingWindowRequest,
    ) -> Result<PairingChange<IssuedPairingWindow>, PairingError> {
        if self.context.role() != li_core_interface::NodeRole::Main {
            return Err(PairingError::MainOnly);
        }
        let _operation = self
            .operation_lock
            .lock()
            .map_err(|_| PairingError::StateUnavailable)?;
        let now = self.clock.now()?;
        let replay = open_replay_identity(idempotency_key, &request)?;
        if let Some(stored) = self.store.replay(replay.idempotency_sha256())? {
            if stored.operation_kind() != PairingReplayOperation::Open
                || stored.identity() != &replay
            {
                return Err(PairingError::StoreConflict);
            }
            let material = stored.open_material().ok_or(PairingError::StoreCorrupt)?;
            if now >= material.expires_at() {
                return Err(PairingError::Expired);
            }
            if let Some(current) = self.store.pairing(stored.invite_id())? {
                if current.record().main_node_id() != self.context.identity().node_id()
                    || current.record().open_replay() != &replay
                    || current.record().mode() != material.mode()
                    || current.record().nonce() != material.nonce()
                    || current.record().setup_salt() != material.salt()
                    || current.record().expires_at() != material.expires_at()
                {
                    return Err(PairingError::StoreCorrupt);
                }
            }
            return self.open_change(
                stored.invite_id().clone(),
                material.mode().clone(),
                material.nonce().clone(),
                *material.salt(),
                material.expires_at(),
            );
        }
        self.prune_inactive_at(now)?;
        let expires_at = now
            .value()
            .checked_add(u64::from(request.lifetime_seconds()) * 1_000)
            .map(UnixMilliseconds::new)
            .ok_or(PairingError::StateUnavailable)?;
        let invite_id = self.generate_invite_id()?;
        let nonce = self.generate_nonce()?;
        let mut salt = [0_u8; 16];
        self.material.fill(&mut salt)?;
        let advertisement = PairingAdvertisement::new(
            invite_id.clone(),
            self.context.display_name().clone(),
            self.context.control_address().clone(),
            self.context.certificate_fingerprint().clone(),
            expires_at,
            request.mode().clone(),
        );
        let active_count = self
            .store
            .pairings(MAX_INVITATIONS + 1)?
            .into_iter()
            .filter(|value| value.record().state() != PairingRecordState::Active)
            .count();
        if active_count >= MAX_INVITATIONS {
            self.discovery.unpublish(&invite_id);
            return Err(PairingError::StateUnavailable);
        }
        let invitation = PairingRecord::open(
            self.context.identity().node_id().clone(),
            invite_id.clone(),
            request.mode().clone(),
            nonce.clone(),
            replay,
            salt,
            now,
            expires_at,
        )?;
        let stored = self.store.create(invitation)?;
        if let Err(error) = self.discovery.publish(&advertisement) {
            self.store
                .rollback_create(stored.record(), stored.revision())?;
            return Err(error);
        }
        self.open_change(invite_id, request.mode().clone(), nonce, salt, expires_at)
    }

    // Returns one public challenge for an active invitation.
    pub fn challenge(
        &self,
        invite_id: &PairingInviteId,
        peer_address: &li_core_interface::NodeAddress,
    ) -> Result<PairingChallenge, PairingError> {
        let now = self.clock.now()?;
        let invitation = self
            .store
            .pairing(invite_id)?
            .ok_or(PairingError::NotFound)?;
        require_available(invitation.record(), now)?;
        if let PairingMode::ConnectX {
            direct_interface, ..
        } = invitation.record().mode()
        {
            self.direct_link.verify(direct_interface, peer_address)?;
        }
        Ok(PairingChallenge::new(
            invite_id.clone(),
            invitation.record().nonce().clone(),
            invitation.record().mode().clone(),
            invitation.record().created_at(),
            invitation.record().expires_at(),
            &self.context,
        ))
    }

    // Verifies one candidate, consumes its invitation, and returns trust material.
    pub fn enroll(
        &self,
        idempotency_key: &str,
        invite_id: &PairingInviteId,
        candidate: &PairingCandidate,
    ) -> Result<PairingChange<PairingResult>, PairingError> {
        let now = self.clock.now()?;
        let _operation = self
            .operation_lock
            .lock()
            .map_err(|_| PairingError::StateUnavailable)?;
        let replay = enroll_replay_identity(idempotency_key, invite_id, candidate)?;
        if let Some(stored) = self.store.replay(replay.idempotency_sha256())? {
            if stored.operation_kind() != PairingReplayOperation::Enroll
                || stored.identity() != &replay
                || stored.invite_id() != invite_id
            {
                return Err(PairingError::StoreConflict);
            }
            return self.replay_enrollment(invite_id, candidate, now, &replay);
        }
        let invitation = self
            .store
            .pairing(invite_id)?
            .ok_or(PairingError::NotFound)?;
        if invitation.record().main_node_id() != self.context.identity().node_id() {
            return Err(PairingError::StoreCorrupt);
        }
        require_available(invitation.record(), now)?;
        if candidate.installation_created_at().value() == 0
            || candidate.installation_created_at().value()
                > now
                    .value()
                    .saturating_add(PROOF_FUTURE_TOLERANCE_MILLISECONDS)
        {
            return Err(PairingError::InvalidRequest {
                reason: "candidate installation timestamp is invalid",
            });
        }
        if let Err(error) = self.authorize_mode(invitation.record(), candidate) {
            self.record_failed_attempt(&invitation)?;
            return Err(error);
        }
        let transcript =
            enrollment_transcript(&self.context, invite_id, invitation.record(), candidate);
        let fingerprint = match self.trust.verify_candidate(
            candidate.public_key(),
            &transcript,
            candidate.proof_signature(),
        ) {
            Ok(fingerprint) => fingerprint,
            Err(_) => {
                self.record_failed_attempt(&invitation)?;
                return Err(PairingError::Unauthorized);
            }
        };
        if let PairingMode::ConnectX {
            candidate_public_key,
            ..
        } = invitation.record().mode()
        {
            if &fingerprint != candidate_public_key {
                self.record_failed_attempt(&invitation)?;
                return Err(PairingError::Unauthorized);
            }
        }
        let state = match invitation.record().mode() {
            PairingMode::Remote => PairingMembershipState::PendingApproval,
            PairingMode::Lan | PairingMode::ConnectX { .. } => PairingMembershipState::Active,
        };
        let approval_expires_at = (state == PairingMembershipState::PendingApproval)
            .then_some(invitation.record().expires_at());
        let credentials = self.trust.issue_membership(
            &self.context,
            candidate,
            &fingerprint,
            state,
            approval_expires_at,
        )?;
        let comparison_code = (state == PairingMembershipState::PendingApproval)
            .then(|| comparison_code(&transcript));
        let peer_credential = credentials.peer_credential_material(state)?;
        let enrollment = PairingEnrollmentMaterial::new(
            candidate.identity().clone(),
            candidate.display_name().clone(),
            candidate.control_address().clone(),
            fingerprint.clone(),
            peer_credential,
        );
        let pairing_record = invitation.record().completing(
            replay,
            enrollment,
            comparison_code.as_ref().map(PairingComparisonCode::bytes),
            credentials.clone(),
        )?;
        let result = PairingResult::new(
            invite_id.clone(),
            candidate.identity().clone(),
            candidate.display_name().clone(),
            candidate.control_address().clone(),
            fingerprint,
            state,
            approval_expires_at,
            comparison_code,
            credentials,
            pairing_record,
            invitation.revision(),
        );
        Ok(PairingChange::new(
            result,
            PairingEvent::ChildPaired {
                invite_id: invite_id.clone(),
                child_node_id: candidate.identity().node_id().clone(),
            },
        ))
    }

    // Proposes one exact pending-to-active transition for atomic application approval.
    pub fn approve(
        &self,
        idempotency_key: &str,
        invite_id: &PairingInviteId,
    ) -> Result<PairingChange<PairingApproval>, PairingError> {
        let _operation = self
            .operation_lock
            .lock()
            .map_err(|_| PairingError::StateUnavailable)?;
        let now = self.clock.now()?;
        let replay = approve_replay_identity(idempotency_key, invite_id)?;
        if let Some(stored) = self.store.replay(replay.idempotency_sha256())? {
            if stored.operation_kind() != PairingReplayOperation::Approve
                || stored.identity() != &replay
                || stored.invite_id() != invite_id
            {
                return Err(PairingError::StoreConflict);
            }
            let current = self
                .store
                .pairing(invite_id)?
                .ok_or(PairingError::StoreCorrupt)?;
            if current.record().main_node_id() != self.context.identity().node_id()
                || current.record().approval_replay() != Some(&replay)
                || current.record().state() != PairingRecordState::Active
            {
                return Err(PairingError::StoreCorrupt);
            }
            return Ok(PairingChange::new(
                PairingApproval::new(current.record().clone(), current.revision())?,
                PairingEvent::ChildPaired {
                    invite_id: invite_id.clone(),
                    child_node_id: current
                        .record()
                        .enrollment()
                        .ok_or(PairingError::StoreCorrupt)?
                        .child_identity()
                        .node_id()
                        .clone(),
                },
            ));
        }
        let pending = self
            .store
            .pairing(invite_id)?
            .ok_or(PairingError::NotFound)?;
        if pending.record().main_node_id() != self.context.identity().node_id()
            || pending.record().state() != PairingRecordState::PendingApproval
        {
            return Err(PairingError::InvalidApproval);
        }
        if now >= pending.record().expires_at()
            || pending
                .record()
                .enrollment()
                .is_none_or(|value| now >= value.peer_credential().expires_at())
        {
            return Err(PairingError::Expired);
        }
        let pairing_record = pending.record().approving(replay)?;
        let child_node_id = pairing_record
            .enrollment()
            .ok_or(PairingError::StoreCorrupt)?
            .child_identity()
            .node_id()
            .clone();
        Ok(PairingChange::new(
            PairingApproval::new(pairing_record, pending.revision())?,
            PairingEvent::ChildPaired {
                invite_id: invite_id.clone(),
                child_node_id,
            },
        ))
    }

    // Removes the advertisement only after the application confirms an atomic durable commit.
    pub fn pairing_did_commit(&self, invite_id: &PairingInviteId) {
        self.discovery.unpublish(invite_id);
    }

    // Closes one unconsumed invitation and removes its advertisement.
    pub fn close(&self, invite_id: &PairingInviteId) -> Result<PairingChange<()>, PairingError> {
        let invitation = self
            .store
            .pairing(invite_id)?
            .ok_or(PairingError::NotFound)?;
        self.store.delete(invite_id, invitation.revision())?;
        self.discovery.unpublish(invite_id);
        Ok(PairingChange::new(
            (),
            PairingEvent::WindowClosed {
                invite_id: invite_id.clone(),
            },
        ))
    }

    // Removes consumed and expired invitations and their discovery records.
    pub fn prune_inactive(&self) -> Result<Vec<PairingInviteId>, PairingError> {
        let now = self.clock.now()?;
        self.prune_inactive_at(now)
    }

    // Removes consumed and expired invitations at one already-observed time.
    fn prune_inactive_at(
        &self,
        now: UnixMilliseconds,
    ) -> Result<Vec<PairingInviteId>, PairingError> {
        let invitations = self.store.pairings(MAX_INVITATIONS + 1)?;
        let mut removed = Vec::with_capacity(invitations.len());
        for invitation in invitations {
            if invitation.record().state() == PairingRecordState::Active
                || invitation.record().expires_at() > now
            {
                continue;
            }
            let invite_id = invitation.record().invite_id().clone();
            self.store.delete(&invite_id, invitation.revision())?;
            self.discovery.unpublish(&invite_id);
            removed.push(invite_id);
        }
        Ok(removed)
    }

    // Applies code-based or direct-link authorization for one invitation mode.
    fn authorize_mode(
        &self,
        invitation: &PairingRecord,
        candidate: &PairingCandidate,
    ) -> Result<(), PairingError> {
        match invitation.mode() {
            PairingMode::Lan | PairingMode::Remote => {
                let code = candidate.setup_code().ok_or(PairingError::Unauthorized)?;
                let expected = self.setup_code.derive(
                    self.context.identity().installation_id(),
                    invitation.invite_id(),
                    invitation.nonce(),
                    invitation.setup_salt(),
                )?;
                if code.len() != expected.len()
                    || !bool::from(expected.as_slice().ct_eq(code.as_bytes()))
                {
                    return Err(PairingError::Unauthorized);
                }
                Ok(())
            }
            PairingMode::ConnectX {
                direct_interface, ..
            } => {
                if candidate.setup_code().is_some() {
                    return Err(PairingError::Unauthorized);
                }
                self.direct_link
                    .verify(direct_interface, candidate.peer_address())
                    .map_err(|_| PairingError::Unauthorized)
            }
        }
    }

    // Persists one bounded failed authorization attempt at the exact observed revision.
    fn record_failed_attempt(
        &self,
        invitation: &VersionedPairingRecord,
    ) -> Result<(), PairingError> {
        let updated = invitation.record().recording_failed_attempt()?;
        self.store.replace(updated, invitation.revision())?;
        if invitation.record().attempts() + 1 >= MAX_ATTEMPTS {
            return Err(PairingError::AttemptLimit);
        }
        Ok(())
    }

    // Generates one random canonical invitation identity.
    fn generate_invite_id(&self) -> Result<PairingInviteId, PairingError> {
        let mut bytes = [0_u8; 16];
        self.material.fill(&mut bytes)?;
        PairingInviteId::parse(&hexadecimal(&bytes)).map_err(Into::into)
    }

    // Generates one random 256-bit challenge nonce.
    fn generate_nonce(&self) -> Result<Sha256Digest, PairingError> {
        let mut bytes = [0_u8; 32];
        self.material.fill(&mut bytes)?;
        Sha256Digest::parse(&hexadecimal(&bytes)).map_err(Into::into)
    }

    // Builds one opened response by deriving its one-time code from durable non-secret inputs.
    fn open_change(
        &self,
        invite_id: PairingInviteId,
        mode: PairingMode,
        nonce: Sha256Digest,
        salt: [u8; 16],
        expires_at: UnixMilliseconds,
    ) -> Result<PairingChange<IssuedPairingWindow>, PairingError> {
        let setup_code = match mode {
            PairingMode::Lan | PairingMode::Remote => {
                Some(PairingSetupCode::new(self.setup_code.derive(
                    self.context.identity().installation_id(),
                    &invite_id,
                    &nonce,
                    &salt,
                )?))
            }
            PairingMode::ConnectX { .. } => None,
        };
        Ok(PairingChange::new(
            IssuedPairingWindow::new(invite_id.clone(), mode, nonce, expires_at, setup_code),
            PairingEvent::WindowOpened { invite_id },
        ))
    }

    // Reconstructs one exact enrollment response only from committed matching durable state.
    fn replay_enrollment(
        &self,
        invite_id: &PairingInviteId,
        candidate: &PairingCandidate,
        now: UnixMilliseconds,
        replay: &PairingReplayIdentity,
    ) -> Result<PairingChange<PairingResult>, PairingError> {
        let current = self
            .store
            .pairing(invite_id)?
            .ok_or(PairingError::StoreCorrupt)?;
        let record = current.record();
        if record.main_node_id() != self.context.identity().node_id()
            || record.enrollment_replay() != Some(replay)
            || record.state() == PairingRecordState::Open
        {
            return Err(PairingError::StoreCorrupt);
        }
        self.authorize_mode(record, candidate)?;
        let transcript = enrollment_transcript(&self.context, invite_id, record, candidate);
        let fingerprint = self
            .trust
            .verify_candidate(
                candidate.public_key(),
                &transcript,
                candidate.proof_signature(),
            )
            .map_err(|_| PairingError::Unauthorized)?;
        let enrollment = record.enrollment().ok_or(PairingError::StoreCorrupt)?;
        let credentials = record.credentials().ok_or(PairingError::StoreCorrupt)?;
        if &fingerprint != enrollment.child_public_key_fingerprint()
            || candidate.identity() != enrollment.child_identity()
            || candidate.display_name() != enrollment.child_name()
            || candidate.control_address() != enrollment.child_address()
            || now >= credentials.member_expires_at()
        {
            return Err(PairingError::StoreConflict);
        }
        let comparison_code = record
            .comparison_code_bytes()
            .copied()
            .map(PairingComparisonCode::new);
        let result = PairingResult::new(
            invite_id.clone(),
            candidate.identity().clone(),
            candidate.display_name().clone(),
            candidate.control_address().clone(),
            fingerprint,
            enrollment.peer_credential().state(),
            (record.state() == PairingRecordState::PendingApproval).then_some(record.expires_at()),
            comparison_code,
            credentials.clone(),
            record.clone(),
            current.revision(),
        );
        Ok(PairingChange::new(
            result,
            PairingEvent::ChildPaired {
                invite_id: invite_id.clone(),
                child_node_id: candidate.identity().node_id().clone(),
            },
        ))
    }
}

impl Drop for PairingManager {
    // Removes every remaining advertisement when its lifecycle owner stops.
    fn drop(&mut self) {
        if let Ok(invitations) = self.store.pairings(MAX_INVITATIONS + 1) {
            for invitation in invitations {
                if invitation.record().state() != PairingRecordState::Active {
                    self.discovery.unpublish(invitation.record().invite_id());
                }
            }
        }
    }
}

// Requires one invitation to remain active, fresh, and below its attempt bound.
fn require_available(
    invitation: &PairingRecord,
    now: UnixMilliseconds,
) -> Result<(), PairingError> {
    if invitation.state() != PairingRecordState::Open {
        return Err(PairingError::Consumed);
    }
    if now >= invitation.expires_at() {
        return Err(PairingError::Expired);
    }
    if invitation.attempts() >= MAX_ATTEMPTS {
        return Err(PairingError::AttemptLimit);
    }
    Ok(())
}

// Binds one open idempotency identity to its complete semantic request.
fn open_replay_identity(
    idempotency_key: &str,
    request: &PairingWindowRequest,
) -> Result<PairingReplayIdentity, PairingError> {
    let lifetime = request.lifetime_seconds().to_be_bytes();
    let mut fields = vec![
        pairing_mode_name(request.mode()).as_bytes(),
        lifetime.as_slice(),
    ];
    if let PairingMode::ConnectX {
        candidate_public_key,
        direct_interface: interface,
    } = request.mode()
    {
        fields.push(candidate_public_key.as_str().as_bytes());
        fields.push(interface.as_str().as_bytes());
    }
    replay_identity(idempotency_key, OPEN_REQUEST_DOMAIN, &fields)
}

// Binds one enrollment idempotency identity to every non-setup candidate request field.
fn enroll_replay_identity(
    idempotency_key: &str,
    invite_id: &PairingInviteId,
    candidate: &PairingCandidate,
) -> Result<PairingReplayIdentity, PairingError> {
    let installation_created_at = candidate.installation_created_at().value().to_be_bytes();
    replay_identity(
        idempotency_key,
        ENROLL_REQUEST_DOMAIN,
        &[
            invite_id.as_str().as_bytes(),
            candidate.identity().node_id().as_str().as_bytes(),
            candidate.identity().machine_id().as_str().as_bytes(),
            candidate.identity().installation_id().as_str().as_bytes(),
            candidate.display_name().as_str().as_bytes(),
            candidate.control_address().as_str().as_bytes(),
            candidate.public_key(),
            installation_created_at.as_slice(),
            candidate.proof_signature(),
            candidate.peer_address().as_str().as_bytes(),
        ],
    )
}

// Binds one approval idempotency identity to one exact invitation.
fn approve_replay_identity(
    idempotency_key: &str,
    invite_id: &PairingInviteId,
) -> Result<PairingReplayIdentity, PairingError> {
    replay_identity(
        idempotency_key,
        APPROVE_REQUEST_DOMAIN,
        &[invite_id.as_str().as_bytes()],
    )
}

// Produces one domain-separated idempotency digest and one semantic request digest.
fn replay_identity(
    idempotency_key: &str,
    request_domain: &[u8],
    request_fields: &[&[u8]],
) -> Result<PairingReplayIdentity, PairingError> {
    if idempotency_key.is_empty()
        || idempotency_key.len() > MAX_IDEMPOTENCY_KEY_BYTES
        || idempotency_key.chars().any(char::is_control)
    {
        return Err(PairingError::InvalidRequest {
            reason: "pairing idempotency key is invalid",
        });
    }
    Ok(PairingReplayIdentity::new(
        digest_fields(IDEMPOTENCY_DOMAIN, &[idempotency_key.as_bytes()])?,
        digest_fields(request_domain, request_fields)?,
    ))
}

// Hashes one unambiguous domain-separated field sequence into a canonical digest identity.
fn digest_fields(domain: &[u8], fields: &[&[u8]]) -> Result<Sha256Digest, PairingError> {
    let mut digest = Sha256::new();
    digest.update((domain.len() as u64).to_be_bytes());
    digest.update(domain);
    for field in fields {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    Sha256Digest::parse(&hexadecimal(&digest.finalize())).map_err(Into::into)
}

// Returns deterministic proof bytes binding every enrollment identity.
fn enrollment_transcript(
    context: &PairingContext,
    invite_id: &PairingInviteId,
    invitation: &PairingRecord,
    candidate: &PairingCandidate,
) -> Vec<u8> {
    pairing_enrollment_transcript(
        context.identity().node_id(),
        context.private_control_port(),
        invite_id,
        invitation.nonce(),
        invitation.created_at(),
        invitation.mode(),
        invitation.expires_at(),
        candidate.identity(),
        candidate.display_name(),
        candidate.control_address(),
        candidate.installation_created_at(),
    )
}

// Returns the canonical proof transcript shared by the main verifier and candidate signer.
#[allow(clippy::too_many_arguments)]
pub fn pairing_enrollment_transcript(
    main_node_id: &li_core_interface::NodeId,
    main_private_port: u16,
    invite_id: &PairingInviteId,
    nonce: &Sha256Digest,
    created_at: UnixMilliseconds,
    mode: &PairingMode,
    expires_at: UnixMilliseconds,
    candidate_identity: &li_core_interface::NodeIdentity,
    candidate_name: &li_core_interface::DisplayName,
    candidate_address: &li_core_interface::NodeAddress,
    installation_created_at: UnixMilliseconds,
) -> Vec<u8> {
    let mut transcript = Vec::new();
    append_transcript_field(&mut transcript, TRANSCRIPT_DOMAIN);
    append_transcript_field(&mut transcript, main_node_id.as_str().as_bytes());
    append_transcript_field(&mut transcript, &main_private_port.to_be_bytes());
    append_transcript_field(&mut transcript, invite_id.as_str().as_bytes());
    append_transcript_field(&mut transcript, nonce.as_str().as_bytes());
    append_transcript_field(&mut transcript, &created_at.value().to_be_bytes());
    append_transcript_field(&mut transcript, pairing_mode_name(mode).as_bytes());
    append_transcript_field(&mut transcript, &expires_at.value().to_be_bytes());
    append_transcript_field(
        &mut transcript,
        candidate_identity.node_id().as_str().as_bytes(),
    );
    append_transcript_field(
        &mut transcript,
        candidate_identity.machine_id().as_str().as_bytes(),
    );
    append_transcript_field(
        &mut transcript,
        candidate_identity.installation_id().as_str().as_bytes(),
    );
    append_transcript_field(&mut transcript, candidate_name.as_str().as_bytes());
    append_transcript_field(&mut transcript, candidate_address.as_str().as_bytes());
    append_transcript_field(
        &mut transcript,
        &installation_created_at.value().to_be_bytes(),
    );
    transcript
}

// Adds one length-delimited value to the canonical enrollment transcript.
fn append_transcript_field(transcript: &mut Vec<u8>, value: &[u8]) {
    transcript.extend_from_slice(&(value.len() as u64).to_be_bytes());
    transcript.extend_from_slice(value);
}

// Returns the stable transcript name for one pairing mode.
fn pairing_mode_name(mode: &PairingMode) -> &'static str {
    match mode {
        PairingMode::Lan => "lan",
        PairingMode::Remote => "remote",
        PairingMode::ConnectX { .. } => "connectx",
    }
}

// Derives one six-digit human comparison code from the signed transcript.
fn comparison_code(transcript: &[u8]) -> PairingComparisonCode {
    let digest = Sha256::digest(transcript);
    let mut tail = [0_u8; 8];
    tail.copy_from_slice(&digest[digest.len() - 8..]);
    let value = u64::from_be_bytes(tail) % 1_000_000;
    let text = format!("{value:06}");
    let mut digits = [0_u8; 6];
    digits.copy_from_slice(text.as_bytes());
    PairingComparisonCode::new(digits)
}

// Converts fixed random bytes to lowercase hexadecimal identity text.
fn hexadecimal(value: &[u8]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(ALPHABET[(byte >> 4) as usize] as char);
        output.push(ALPHABET[(byte & 0x0f) as usize] as char);
    }
    output
}
