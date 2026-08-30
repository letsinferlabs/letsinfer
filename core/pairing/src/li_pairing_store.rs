// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;

use li_core_interface::{
    CredentialId, DisplayName, NodeAddress, NodeId, NodeIdentity, PairingInviteId, Sha256Digest,
    UnixMilliseconds,
};

use crate::{PairingError, PairingMembershipState, PairingMode};

// Binds one caller idempotency identity to the exact semantic request digest it first owned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingReplayIdentity {
    idempotency_sha256: Sha256Digest,
    request_sha256: Sha256Digest,
}

impl PairingReplayIdentity {
    // Creates one replay identity from already-domain-separated cryptographic digests.
    pub const fn new(idempotency_sha256: Sha256Digest, request_sha256: Sha256Digest) -> Self {
        Self {
            idempotency_sha256,
            request_sha256,
        }
    }

    // Returns the digest used for bounded durable replay lookup.
    pub const fn idempotency_sha256(&self) -> &Sha256Digest {
        &self.idempotency_sha256
    }

    // Returns the exact semantic request digest bound to the idempotency identity.
    pub const fn request_sha256(&self) -> &Sha256Digest {
        &self.request_sha256
    }
}

// Names one durable idempotent pairing operation without sharing request payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingReplayOperation {
    Open,
    Enroll,
    Approve,
}

// Retains the non-secret invitation facts required to replay an open response after pruning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingOpenReplayMaterial {
    mode: PairingMode,
    nonce: Sha256Digest,
    salt: [u8; 16],
    expires_at: UnixMilliseconds,
}

impl PairingOpenReplayMaterial {
    // Captures one exact open response source without retaining its derived setup code.
    pub const fn new(
        mode: PairingMode,
        nonce: Sha256Digest,
        salt: [u8; 16],
        expires_at: UnixMilliseconds,
    ) -> Self {
        Self {
            mode,
            nonce,
            salt,
            expires_at,
        }
    }

    // Returns the invitation authorization mode.
    pub const fn mode(&self) -> &PairingMode {
        &self.mode
    }

    // Returns the exact challenge nonce.
    pub const fn nonce(&self) -> &Sha256Digest {
        &self.nonce
    }

    // Returns the derivation salt only to the setup-code capability.
    pub const fn salt(&self) -> &[u8; 16] {
        &self.salt
    }

    // Returns the exclusive invitation expiration boundary.
    pub const fn expires_at(&self) -> UnixMilliseconds {
        self.expires_at
    }
}

impl Drop for PairingOpenReplayMaterial {
    // Clears retained derivation salt when the replay snapshot leaves memory.
    fn drop(&mut self) {
        self.salt.fill(0);
    }
}

// Maps one durable request identity to its invitation and optional open-response source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingReplayRecord {
    identity: PairingReplayIdentity,
    operation: PairingReplayOperation,
    invite_id: PairingInviteId,
    open: Option<PairingOpenReplayMaterial>,
}

impl PairingReplayRecord {
    // Creates one open replay record with every non-secret response input.
    pub fn open(record: &PairingRecord) -> Result<Self, PairingError> {
        if record.state() != PairingRecordState::Open {
            return Err(PairingError::StoreCorrupt);
        }
        Ok(Self {
            identity: record.open_replay().clone(),
            operation: PairingReplayOperation::Open,
            invite_id: record.invite_id().clone(),
            open: Some(PairingOpenReplayMaterial::new(
                record.mode().clone(),
                record.nonce().clone(),
                *record.setup_salt(),
                record.expires_at(),
            )),
        })
    }

    // Reconstructs one validated open mapping from strict persistence fields.
    pub fn restore_open(
        identity: PairingReplayIdentity,
        invite_id: PairingInviteId,
        open: PairingOpenReplayMaterial,
    ) -> Result<Self, PairingError> {
        if open.expires_at().value() == 0 {
            return Err(PairingError::StoreCorrupt);
        }
        Ok(Self {
            identity,
            operation: PairingReplayOperation::Open,
            invite_id,
            open: Some(open),
        })
    }

    // Creates one enroll or approve replay pointer without duplicating response material.
    pub fn operation(
        identity: PairingReplayIdentity,
        operation: PairingReplayOperation,
        invite_id: PairingInviteId,
    ) -> Result<Self, PairingError> {
        if operation == PairingReplayOperation::Open {
            return Err(PairingError::StoreCorrupt);
        }
        Ok(Self {
            identity,
            operation,
            invite_id,
            open: None,
        })
    }

    // Returns the exact replay identity used as the durable lookup key.
    pub const fn identity(&self) -> &PairingReplayIdentity {
        &self.identity
    }

    // Returns the closed operation kind bound to this identity.
    pub const fn operation_kind(&self) -> PairingReplayOperation {
        self.operation
    }

    // Returns the invitation owning the replay response.
    pub const fn invite_id(&self) -> &PairingInviteId {
        &self.invite_id
    }

    // Returns open-response derivation facts only for an open operation.
    pub const fn open_material(&self) -> Option<&PairingOpenReplayMaterial> {
        self.open.as_ref()
    }
}

// Stores one exact certificate identity and validity interval produced by pairing trust.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingPeerCredentialMaterial {
    credential_id: CredentialId,
    peer_leaf_sha256: Sha256Digest,
    valid_from: UnixMilliseconds,
    expires_at: UnixMilliseconds,
    state: PairingMembershipState,
}

impl PairingPeerCredentialMaterial {
    // Creates one coherent exact peer-certificate lifecycle without fabricating trust facts.
    pub fn new(
        credential_id: CredentialId,
        peer_leaf_sha256: Sha256Digest,
        valid_from: UnixMilliseconds,
        expires_at: UnixMilliseconds,
        state: PairingMembershipState,
    ) -> Result<Self, PairingError> {
        if expires_at <= valid_from {
            return Err(PairingError::InvalidRequest {
                reason: "member certificate expiration must follow its validity start",
            });
        }
        Ok(Self {
            credential_id,
            peer_leaf_sha256,
            valid_from,
            expires_at,
            state,
        })
    }

    // Returns the stable credential identity derived from the exact certificate leaf.
    pub const fn credential_id(&self) -> &CredentialId {
        &self.credential_id
    }

    // Returns the SHA-256 digest of the exact certificate leaf DER bytes.
    pub const fn peer_leaf_sha256(&self) -> &Sha256Digest {
        &self.peer_leaf_sha256
    }

    // Returns the inclusive certificate validity start.
    pub const fn valid_from(&self) -> UnixMilliseconds {
        self.valid_from
    }

    // Returns the exclusive certificate expiration boundary.
    pub const fn expires_at(&self) -> UnixMilliseconds {
        self.expires_at
    }

    // Returns whether this credential awaits human approval or is active.
    pub const fn state(&self) -> PairingMembershipState {
        self.state
    }

    // Returns the same exact certificate material after explicit approval.
    pub fn activated(&self) -> Self {
        Self {
            state: PairingMembershipState::Active,
            ..self.clone()
        }
    }
}

// Stores the bounded child identity needed to complete or reconstruct enrollment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingEnrollmentMaterial {
    child_identity: NodeIdentity,
    child_name: DisplayName,
    child_address: NodeAddress,
    child_public_key_fingerprint: Sha256Digest,
    peer_credential: PairingPeerCredentialMaterial,
}

impl PairingEnrollmentMaterial {
    // Creates one exact child enrollment projection from verified pairing facts.
    pub const fn new(
        child_identity: NodeIdentity,
        child_name: DisplayName,
        child_address: NodeAddress,
        child_public_key_fingerprint: Sha256Digest,
        peer_credential: PairingPeerCredentialMaterial,
    ) -> Self {
        Self {
            child_identity,
            child_name,
            child_address,
            child_public_key_fingerprint,
            peer_credential,
        }
    }

    // Returns the exact authenticated child identity.
    pub const fn child_identity(&self) -> &NodeIdentity {
        &self.child_identity
    }

    // Returns the child display name.
    pub const fn child_name(&self) -> &DisplayName {
        &self.child_name
    }

    // Returns the child private control address.
    pub const fn child_address(&self) -> &NodeAddress {
        &self.child_address
    }

    // Returns the verified child public-key fingerprint.
    pub const fn child_public_key_fingerprint(&self) -> &Sha256Digest {
        &self.child_public_key_fingerprint
    }

    // Returns the exact peer certificate lifecycle material.
    pub const fn peer_credential(&self) -> &PairingPeerCredentialMaterial {
        &self.peer_credential
    }

    // Returns this same enrollment after explicit human approval.
    pub fn activated(&self) -> Self {
        Self {
            peer_credential: self.peer_credential.activated(),
            ..self.clone()
        }
    }
}

// Names the durable invitation and approval states without boolean combinations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingRecordState {
    Open,
    PendingApproval,
    Active,
}

// Stores one complete durable pairing invitation and any verified enrollment material.
#[derive(Clone, Eq, PartialEq)]
pub struct PairingRecord {
    main_node_id: NodeId,
    invite_id: PairingInviteId,
    mode: PairingMode,
    nonce: Sha256Digest,
    open_replay: PairingReplayIdentity,
    enrollment_replay: Option<PairingReplayIdentity>,
    approval_replay: Option<PairingReplayIdentity>,
    salt: [u8; 16],
    created_at: UnixMilliseconds,
    expires_at: UnixMilliseconds,
    attempts: u8,
    state: PairingRecordState,
    comparison_code: Option<[u8; 6]>,
    enrollment: Option<PairingEnrollmentMaterial>,
    credentials: Option<crate::PairingCredentials>,
}

impl PairingRecord {
    // Creates one durable open invitation without retaining its plaintext setup code.
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        main_node_id: NodeId,
        invite_id: PairingInviteId,
        mode: PairingMode,
        nonce: Sha256Digest,
        open_replay: PairingReplayIdentity,
        salt: [u8; 16],
        created_at: UnixMilliseconds,
        expires_at: UnixMilliseconds,
    ) -> Result<Self, PairingError> {
        if expires_at <= created_at {
            return Err(PairingError::StoreCorrupt);
        }
        Ok(Self {
            main_node_id,
            invite_id,
            mode,
            nonce,
            open_replay,
            enrollment_replay: None,
            approval_replay: None,
            salt,
            created_at,
            expires_at,
            attempts: 0,
            state: PairingRecordState::Open,
            comparison_code: None,
            enrollment: None,
            credentials: None,
        })
    }

    // Reconstructs one validated durable pairing snapshot from persistence.
    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        main_node_id: NodeId,
        invite_id: PairingInviteId,
        mode: PairingMode,
        nonce: Sha256Digest,
        open_replay: PairingReplayIdentity,
        enrollment_replay: Option<PairingReplayIdentity>,
        approval_replay: Option<PairingReplayIdentity>,
        salt: [u8; 16],
        created_at: UnixMilliseconds,
        expires_at: UnixMilliseconds,
        attempts: u8,
        state: PairingRecordState,
        comparison_code: Option<[u8; 6]>,
        enrollment: Option<PairingEnrollmentMaterial>,
        credentials: Option<crate::PairingCredentials>,
    ) -> Result<Self, PairingError> {
        if expires_at <= created_at
            || attempts > 5
            || (state == PairingRecordState::Open
                && (comparison_code.is_some()
                    || enrollment.is_some()
                    || credentials.is_some()
                    || enrollment_replay.is_some()
                    || approval_replay.is_some()))
            || (state == PairingRecordState::PendingApproval
                && (!matches!(mode, PairingMode::Remote)
                    || comparison_code.is_none()
                    || approval_replay.is_some()
                    || credentials.is_none()
                    || enrollment_replay.is_none()
                    || enrollment.as_ref().is_none_or(|value| {
                        value.peer_credential().state() != PairingMembershipState::PendingApproval
                    })))
            || (state == PairingRecordState::Active
                && (comparison_code.is_some()
                    || credentials.is_none()
                    || enrollment_replay.is_none()
                    || enrollment.as_ref().is_none_or(|value| {
                        value.peer_credential().state() != PairingMembershipState::Active
                    })))
        {
            return Err(PairingError::StoreCorrupt);
        }
        Ok(Self {
            main_node_id,
            invite_id,
            mode,
            nonce,
            open_replay,
            enrollment_replay,
            approval_replay,
            salt,
            created_at,
            expires_at,
            attempts,
            state,
            comparison_code,
            enrollment,
            credentials,
        })
    }

    // Returns the main node authority that opened this invitation.
    pub const fn main_node_id(&self) -> &NodeId {
        &self.main_node_id
    }

    // Returns the invitation identity.
    pub const fn invite_id(&self) -> &PairingInviteId {
        &self.invite_id
    }

    // Returns the invitation authorization mode.
    pub const fn mode(&self) -> &PairingMode {
        &self.mode
    }

    // Returns the exact challenge nonce.
    pub const fn nonce(&self) -> &Sha256Digest {
        &self.nonce
    }

    // Returns the exact durable replay identity for opening this invitation.
    pub const fn open_replay(&self) -> &PairingReplayIdentity {
        &self.open_replay
    }

    // Returns the exact durable replay identity for completed candidate enrollment.
    pub const fn enrollment_replay(&self) -> Option<&PairingReplayIdentity> {
        self.enrollment_replay.as_ref()
    }

    // Returns the exact durable replay identity for explicit remote approval.
    pub const fn approval_replay(&self) -> Option<&PairingReplayIdentity> {
        self.approval_replay.as_ref()
    }

    // Returns the setup-code salt only to the persistence adapter and manager boundary.
    pub const fn setup_salt(&self) -> &[u8; 16] {
        &self.salt
    }

    // Returns when this invitation was created.
    pub const fn created_at(&self) -> UnixMilliseconds {
        self.created_at
    }

    // Returns the invitation and approval expiration boundary.
    pub const fn expires_at(&self) -> UnixMilliseconds {
        self.expires_at
    }

    // Returns the number of failed authorization attempts.
    pub const fn attempts(&self) -> u8 {
        self.attempts
    }

    // Returns the durable invitation or approval state.
    pub const fn state(&self) -> PairingRecordState {
        self.state
    }

    // Returns the redacted-at-debug comparison digits for the approval UI.
    pub const fn comparison_code_bytes(&self) -> Option<&[u8; 6]> {
        self.comparison_code.as_ref()
    }

    // Returns verified enrollment material after proof completion.
    pub const fn enrollment(&self) -> Option<&PairingEnrollmentMaterial> {
        self.enrollment.as_ref()
    }

    // Returns the exact public credential response retained for restart-safe enrollment replay.
    pub const fn credentials(&self) -> Option<&crate::PairingCredentials> {
        self.credentials.as_ref()
    }

    // Returns one optimistic failed-attempt update.
    pub(crate) fn recording_failed_attempt(&self) -> Result<Self, PairingError> {
        let attempts = self
            .attempts
            .checked_add(1)
            .ok_or(PairingError::StoreCorrupt)?;
        Self::restore(
            self.main_node_id.clone(),
            self.invite_id.clone(),
            self.mode.clone(),
            self.nonce.clone(),
            self.open_replay.clone(),
            self.enrollment_replay.clone(),
            self.approval_replay.clone(),
            self.salt,
            self.created_at,
            self.expires_at,
            attempts,
            self.state,
            self.comparison_code,
            self.enrollment.clone(),
            self.credentials.clone(),
        )
    }

    // Returns the exact durable result proposed after successful proof and issuance.
    pub(crate) fn completing(
        &self,
        replay: PairingReplayIdentity,
        enrollment: PairingEnrollmentMaterial,
        comparison_code: Option<[u8; 6]>,
        credentials: crate::PairingCredentials,
    ) -> Result<Self, PairingError> {
        let state = match enrollment.peer_credential().state() {
            PairingMembershipState::Active => PairingRecordState::Active,
            PairingMembershipState::PendingApproval => PairingRecordState::PendingApproval,
        };
        Self::restore(
            self.main_node_id.clone(),
            self.invite_id.clone(),
            self.mode.clone(),
            self.nonce.clone(),
            self.open_replay.clone(),
            Some(replay),
            None,
            self.salt,
            self.created_at,
            self.expires_at,
            self.attempts,
            state,
            comparison_code,
            Some(enrollment),
            Some(credentials),
        )
    }

    // Returns the exact active result proposed by explicit remote approval.
    pub(crate) fn approving(&self, replay: PairingReplayIdentity) -> Result<Self, PairingError> {
        if self.state != PairingRecordState::PendingApproval {
            return Err(PairingError::InvalidApproval);
        }
        let enrollment = self
            .enrollment
            .as_ref()
            .ok_or(PairingError::StoreCorrupt)?
            .activated();
        Self::restore(
            self.main_node_id.clone(),
            self.invite_id.clone(),
            self.mode.clone(),
            self.nonce.clone(),
            self.open_replay.clone(),
            self.enrollment_replay.clone(),
            Some(replay),
            self.salt,
            self.created_at,
            self.expires_at,
            self.attempts,
            PairingRecordState::Active,
            None,
            Some(enrollment),
            self.credentials.clone(),
        )
    }
}

impl fmt::Debug for PairingRecord {
    // Presents pairing state without setup verification or comparison-code bytes.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingRecord")
            .field("main_node_id", &self.main_node_id)
            .field("invite_id", &self.invite_id)
            .field("mode", &self.mode)
            .field("nonce", &self.nonce)
            .field("open_replay", &self.open_replay)
            .field("enrollment_replay", &self.enrollment_replay)
            .field("approval_replay", &self.approval_replay)
            .field("setup_material", &"<redacted>")
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("attempts", &self.attempts)
            .field("state", &self.state)
            .field("comparison_code", &"<redacted>")
            .field("enrollment", &self.enrollment)
            .field(
                "credentials",
                &self.credentials.as_ref().map(|_| "<public-package>"),
            )
            .finish()
    }
}

impl Drop for PairingRecord {
    // Clears setup verification and comparison bytes when a snapshot leaves memory.
    fn drop(&mut self) {
        self.salt.fill(0);
        if let Some(code) = &mut self.comparison_code {
            code.fill(0);
        }
    }
}

// Carries one durable pairing snapshot with its exact optimistic revision.
#[derive(Debug)]
pub struct VersionedPairingRecord {
    record: PairingRecord,
    revision: u64,
}

// Returns one exact remote-approval transition for atomic application composition.
#[derive(Debug)]
pub struct PairingApproval {
    pairing_record: PairingRecord,
    expected_pairing_revision: u64,
    enrollment: PairingEnrollmentMaterial,
}

impl PairingApproval {
    // Creates one active proposal from one exact pending record revision.
    pub(crate) fn new(
        pairing_record: PairingRecord,
        expected_pairing_revision: u64,
    ) -> Result<Self, PairingError> {
        let enrollment = pairing_record
            .enrollment()
            .ok_or(PairingError::StoreCorrupt)?
            .clone();
        Ok(Self {
            pairing_record,
            expected_pairing_revision,
            enrollment,
        })
    }

    // Returns the exact approved pairing state for atomic persistence.
    pub const fn pairing_record(&self) -> &PairingRecord {
        &self.pairing_record
    }

    // Returns the exact pending revision that approval must replace.
    pub const fn expected_pairing_revision(&self) -> u64 {
        self.expected_pairing_revision
    }

    // Returns the exact approved child and peer-credential material.
    pub const fn enrollment(&self) -> &PairingEnrollmentMaterial {
        &self.enrollment
    }
}

impl VersionedPairingRecord {
    // Creates one versioned record only when persistence supplied a real revision.
    pub fn new(record: PairingRecord, revision: u64) -> Result<Self, PairingError> {
        if revision == 0 {
            return Err(PairingError::StoreCorrupt);
        }
        Ok(Self { record, revision })
    }

    // Returns the validated pairing record.
    pub const fn record(&self) -> &PairingRecord {
        &self.record
    }

    // Returns the exact optimistic persistence revision.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    // Transfers the validated pairing record to an atomic composition owner.
    pub fn into_record(self) -> PairingRecord {
        self.record
    }
}

// Persists PairingManager-owned invitation and approval state through one injected authority.
pub trait PairingStore: Send + Sync {
    // Creates one absent invitation and returns its exact database revision.
    fn create(&self, record: PairingRecord) -> Result<VersionedPairingRecord, PairingError>;

    // Reads one exact invitation without scanning or alternate identity lookup.
    fn pairing(
        &self,
        invite_id: &PairingInviteId,
    ) -> Result<Option<VersionedPairingRecord>, PairingError>;

    // Resolves at most one operation replay by its bounded idempotency digest.
    fn replay(
        &self,
        idempotency_sha256: &Sha256Digest,
    ) -> Result<Option<PairingReplayRecord>, PairingError>;

    // Lists the bounded records required for expiry pruning and discovery cleanup.
    fn pairings(&self, maximum_results: usize)
        -> Result<Vec<VersionedPairingRecord>, PairingError>;

    // Replaces one exact invitation only at its observed revision.
    fn replace(
        &self,
        record: PairingRecord,
        expected_revision: u64,
    ) -> Result<VersionedPairingRecord, PairingError>;

    // Rolls back one newly created invitation and its replay identity after native publication fails.
    fn rollback_create(
        &self,
        record: &PairingRecord,
        expected_revision: u64,
    ) -> Result<(), PairingError>;

    // Deletes one exact invitation only at its observed revision.
    fn delete(
        &self,
        invite_id: &PairingInviteId,
        expected_revision: u64,
    ) -> Result<(), PairingError>;
}
