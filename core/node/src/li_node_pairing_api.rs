// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;

use li_core_interface::{
    DisplayName, NetworkInterfaceName, NodeAddress, NodeId, NodeIdentity, PairingInviteId,
    Sha256Digest, UnixMilliseconds,
};

const MAX_IDEMPOTENCY_KEY_BYTES: usize = 255;
const MAX_PUBLIC_KEY_BYTES: usize = 8 * 1024;
const MIN_PUBLIC_KEY_BYTES: usize = 128;
const MAX_PROOF_BYTES: usize = 1024;
const MAX_CREDENTIAL_BYTES: usize = 64 * 1024;

// Selects one exact authorization mode without importing PairingManager implementation types.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodePairingMode {
    Lan,
    Remote,
    ConnectX {
        candidate_public_key_sha256: Sha256Digest,
        direct_interface: NetworkInterfaceName,
    },
}

// Names the durable pairing state projected through the Node private API.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodePairingState {
    Open,
    PendingApproval,
    Active,
}

// Carries one bounded main-owned request to open a pairing invitation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodePairingOpenRequest {
    idempotency_key: String,
    mode: NodePairingMode,
    lifetime_seconds: u16,
}

impl NodePairingOpenRequest {
    // Creates one open request only from a bounded replay identity and invitation lifetime.
    pub fn new(
        idempotency_key: String,
        mode: NodePairingMode,
        lifetime_seconds: u16,
    ) -> Result<Self, NodePairingApiError> {
        require_idempotency_key(&idempotency_key)?;
        if !(30..=600).contains(&lifetime_seconds) {
            return Err(NodePairingApiError::InvalidRequest);
        }
        Ok(Self {
            idempotency_key,
            mode,
            lifetime_seconds,
        })
    }

    // Returns the exact replay identity supplied by the caller.
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    // Returns the requested pairing authorization mode.
    pub const fn mode(&self) -> &NodePairingMode {
        &self.mode
    }

    // Returns the bounded invitation lifetime in seconds.
    pub const fn lifetime_seconds(&self) -> u16 {
        self.lifetime_seconds
    }
}

// Returns one opened invitation while keeping its one-time setup code out of diagnostics.
#[derive(Clone, Eq, PartialEq)]
pub struct NodePairingInvitation {
    invite_id: PairingInviteId,
    mode: NodePairingMode,
    nonce: Sha256Digest,
    expires_at: UnixMilliseconds,
    setup_code: Option<String>,
}

// Returns one public invitation challenge used to derive candidate possession proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodePairingChallenge {
    invite_id: PairingInviteId,
    mode: NodePairingMode,
    nonce: Sha256Digest,
    created_at: UnixMilliseconds,
    expires_at: UnixMilliseconds,
    main_node_id: NodeId,
    main_address: NodeAddress,
    main_private_port: u16,
    main_public_key_sha256: Sha256Digest,
    main_certificate_sha256: Sha256Digest,
}

impl NodePairingChallenge {
    // Creates one complete challenge whose timestamps and trust identities are nonempty.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        invite_id: PairingInviteId,
        mode: NodePairingMode,
        nonce: Sha256Digest,
        created_at: UnixMilliseconds,
        expires_at: UnixMilliseconds,
        main_node_id: NodeId,
        main_address: NodeAddress,
        main_private_port: u16,
        main_public_key_sha256: Sha256Digest,
        main_certificate_sha256: Sha256Digest,
    ) -> Result<Self, NodePairingApiError> {
        if created_at.value() == 0 || expires_at <= created_at || main_private_port == 0 {
            return Err(NodePairingApiError::InvalidResponse);
        }
        Ok(Self {
            invite_id,
            mode,
            nonce,
            created_at,
            expires_at,
            main_node_id,
            main_address,
            main_private_port,
            main_public_key_sha256,
            main_certificate_sha256,
        })
    }

    // Returns the exact invitation identity.
    pub const fn invite_id(&self) -> &PairingInviteId {
        &self.invite_id
    }

    // Returns the exact invitation authorization mode.
    pub const fn mode(&self) -> &NodePairingMode {
        &self.mode
    }

    // Returns the challenge nonce bound into candidate proof.
    pub const fn nonce(&self) -> &Sha256Digest {
        &self.nonce
    }

    // Returns the exact invitation creation time bound into candidate proof.
    pub const fn created_at(&self) -> UnixMilliseconds {
        self.created_at
    }

    // Returns the exclusive invitation expiration time.
    pub const fn expires_at(&self) -> UnixMilliseconds {
        self.expires_at
    }

    // Returns the exact main Node identity bound into candidate proof.
    pub const fn main_node_id(&self) -> &NodeId {
        &self.main_node_id
    }

    // Returns the main private control address.
    pub const fn main_address(&self) -> &NodeAddress {
        &self.main_address
    }

    // Returns the exact authenticated private Node listener port.
    pub const fn main_private_port(&self) -> u16 {
        self.main_private_port
    }

    // Returns the main public-key fingerprint asserted by PairingManager.
    pub const fn main_public_key_sha256(&self) -> &Sha256Digest {
        &self.main_public_key_sha256
    }

    // Returns the main pairing certificate fingerprint asserted by PairingManager.
    pub const fn main_certificate_sha256(&self) -> &Sha256Digest {
        &self.main_certificate_sha256
    }
}

impl NodePairingInvitation {
    // Creates one coherent invitation response with the exact code requirement for its mode.
    pub fn new(
        invite_id: PairingInviteId,
        mode: NodePairingMode,
        nonce: Sha256Digest,
        expires_at: UnixMilliseconds,
        setup_code: Option<String>,
    ) -> Result<Self, NodePairingApiError> {
        let requires_code = !matches!(mode, NodePairingMode::ConnectX { .. });
        if expires_at.value() == 0
            || requires_code != setup_code.is_some()
            || setup_code
                .as_deref()
                .is_some_and(|value| !is_digit_code(value, 8))
        {
            return Err(NodePairingApiError::InvalidResponse);
        }
        Ok(Self {
            invite_id,
            mode,
            nonce,
            expires_at,
            setup_code,
        })
    }

    // Returns the durable invitation identity.
    pub const fn invite_id(&self) -> &PairingInviteId {
        &self.invite_id
    }

    // Returns the exact pairing mode recorded for this invitation.
    pub const fn mode(&self) -> &NodePairingMode {
        &self.mode
    }

    // Returns the challenge nonce bound to candidate proof.
    pub const fn nonce(&self) -> &Sha256Digest {
        &self.nonce
    }

    // Returns the exclusive invitation expiration boundary.
    pub const fn expires_at(&self) -> UnixMilliseconds {
        self.expires_at
    }

    // Returns the one-time setup code only to the authenticated caller.
    pub fn setup_code(&self) -> Option<&str> {
        self.setup_code.as_deref()
    }
}

impl fmt::Debug for NodePairingInvitation {
    // Presents invitation identity and lifetime while redacting its one-time setup code.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NodePairingInvitation")
            .field("invite_id", &self.invite_id)
            .field("mode", &self.mode)
            .field("nonce", &self.nonce)
            .field("expires_at", &self.expires_at)
            .field("setup_code", &"<redacted>")
            .finish()
    }
}

// Carries one verified-candidate input without exposing proof or setup material in diagnostics.
#[derive(Clone, Eq, PartialEq)]
pub struct NodePairingEnrollRequest {
    idempotency_key: String,
    invite_id: PairingInviteId,
    candidate_identity: NodeIdentity,
    candidate_name: DisplayName,
    candidate_address: NodeAddress,
    candidate_public_key: Vec<u8>,
    installation_created_at: UnixMilliseconds,
    proof_signature: Vec<u8>,
    setup_code: Option<String>,
    observed_peer_address: NodeAddress,
}

impl NodePairingEnrollRequest {
    // Creates one bounded candidate request while leaving cryptographic judgment to pairing.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        idempotency_key: String,
        invite_id: PairingInviteId,
        candidate_identity: NodeIdentity,
        candidate_name: DisplayName,
        candidate_address: NodeAddress,
        candidate_public_key: Vec<u8>,
        installation_created_at: UnixMilliseconds,
        proof_signature: Vec<u8>,
        setup_code: Option<String>,
        observed_peer_address: NodeAddress,
    ) -> Result<Self, NodePairingApiError> {
        require_idempotency_key(&idempotency_key)?;
        if !(MIN_PUBLIC_KEY_BYTES..=MAX_PUBLIC_KEY_BYTES).contains(&candidate_public_key.len())
            || proof_signature.is_empty()
            || proof_signature.len() > MAX_PROOF_BYTES
            || installation_created_at.value() == 0
            || setup_code
                .as_deref()
                .is_some_and(|value| !is_digit_code(value, 8))
        {
            return Err(NodePairingApiError::InvalidRequest);
        }
        Ok(Self {
            idempotency_key,
            invite_id,
            candidate_identity,
            candidate_name,
            candidate_address,
            candidate_public_key,
            installation_created_at,
            proof_signature,
            setup_code,
            observed_peer_address,
        })
    }

    // Returns the exact replay identity for the pairing and enrollment commit.
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    // Returns the invitation consumed by this candidate proof.
    pub const fn invite_id(&self) -> &PairingInviteId {
        &self.invite_id
    }

    // Returns the exact candidate node identity bound into proof.
    pub const fn candidate_identity(&self) -> &NodeIdentity {
        &self.candidate_identity
    }

    // Returns the candidate display name bound into proof.
    pub const fn candidate_name(&self) -> &DisplayName {
        &self.candidate_name
    }

    // Returns the candidate private control address bound into proof.
    pub const fn candidate_address(&self) -> &NodeAddress {
        &self.candidate_address
    }

    // Returns the exact candidate public-key bytes.
    pub fn candidate_public_key(&self) -> &[u8] {
        &self.candidate_public_key
    }

    // Returns the candidate installation creation time bound into proof.
    pub const fn installation_created_at(&self) -> UnixMilliseconds {
        self.installation_created_at
    }

    // Returns the exact candidate proof signature bytes.
    pub fn proof_signature(&self) -> &[u8] {
        &self.proof_signature
    }

    // Returns the optional code required by LAN and remote invitations.
    pub fn setup_code(&self) -> Option<&str> {
        self.setup_code.as_deref()
    }

    // Returns the peer address observed by the trusted local pairing protocol adapter.
    pub const fn observed_peer_address(&self) -> &NodeAddress {
        &self.observed_peer_address
    }
}

impl fmt::Debug for NodePairingEnrollRequest {
    // Presents candidate identity while redacting public-key, proof, and setup-code bytes.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NodePairingEnrollRequest")
            .field("idempotency_key", &self.idempotency_key)
            .field("invite_id", &self.invite_id)
            .field("candidate_identity", &self.candidate_identity)
            .field("candidate_name", &self.candidate_name)
            .field("candidate_address", &self.candidate_address)
            .field("candidate_public_key", &"<redacted>")
            .field("installation_created_at", &self.installation_created_at)
            .field("proof_signature", &"<redacted>")
            .field("setup_code", &"<redacted>")
            .field("observed_peer_address", &self.observed_peer_address)
            .finish()
    }
}

// Carries one replay-safe explicit approval of an already pending remote pairing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodePairingApproveRequest {
    idempotency_key: String,
    invite_id: PairingInviteId,
}

impl NodePairingApproveRequest {
    // Creates one approval request from an exact invitation and bounded replay identity.
    pub fn new(
        idempotency_key: String,
        invite_id: PairingInviteId,
    ) -> Result<Self, NodePairingApiError> {
        require_idempotency_key(&idempotency_key)?;
        Ok(Self {
            idempotency_key,
            invite_id,
        })
    }

    // Returns the replay identity for the complete atomic approval transaction.
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    // Returns the exact pending invitation to approve.
    pub const fn invite_id(&self) -> &PairingInviteId {
        &self.invite_id
    }
}

// Projects one durable pairing state without exposing persistence record shapes.
#[derive(Clone, Eq, PartialEq)]
pub struct NodePairingStatus {
    invite_id: PairingInviteId,
    mode: NodePairingMode,
    state: NodePairingState,
    expires_at: UnixMilliseconds,
    attempts: u8,
    child_node_id: Option<NodeId>,
    comparison_code: Option<String>,
}

impl NodePairingStatus {
    // Creates one coherent open, pending, or active status projection.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        invite_id: PairingInviteId,
        mode: NodePairingMode,
        state: NodePairingState,
        expires_at: UnixMilliseconds,
        attempts: u8,
        child_node_id: Option<NodeId>,
        comparison_code: Option<String>,
    ) -> Result<Self, NodePairingApiError> {
        let shape_is_valid = match state {
            NodePairingState::Open => child_node_id.is_none() && comparison_code.is_none(),
            NodePairingState::PendingApproval => {
                matches!(mode, NodePairingMode::Remote)
                    && child_node_id.is_some()
                    && comparison_code
                        .as_deref()
                        .is_some_and(|value| is_digit_code(value, 6))
            }
            NodePairingState::Active => child_node_id.is_some() && comparison_code.is_none(),
        };
        if expires_at.value() == 0 || attempts > 5 || !shape_is_valid {
            return Err(NodePairingApiError::InvalidResponse);
        }
        Ok(Self {
            invite_id,
            mode,
            state,
            expires_at,
            attempts,
            child_node_id,
            comparison_code,
        })
    }

    // Returns the exact invitation represented by this status.
    pub const fn invite_id(&self) -> &PairingInviteId {
        &self.invite_id
    }

    // Returns the invitation authorization mode.
    pub const fn mode(&self) -> &NodePairingMode {
        &self.mode
    }

    // Returns the durable pairing lifecycle state.
    pub const fn state(&self) -> NodePairingState {
        self.state
    }

    // Returns the exclusive pairing expiration boundary.
    pub const fn expires_at(&self) -> UnixMilliseconds {
        self.expires_at
    }

    // Returns the number of rejected candidate attempts.
    pub const fn attempts(&self) -> u8 {
        self.attempts
    }

    // Returns the exact verified child identity after candidate proof.
    pub const fn child_node_id(&self) -> Option<&NodeId> {
        self.child_node_id.as_ref()
    }

    // Returns the remote comparison code only to an authenticated presentation owner.
    pub fn comparison_code(&self) -> Option<&str> {
        self.comparison_code.as_deref()
    }
}

impl fmt::Debug for NodePairingStatus {
    // Presents durable state while redacting the human comparison code.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NodePairingStatus")
            .field("invite_id", &self.invite_id)
            .field("mode", &self.mode)
            .field("state", &self.state)
            .field("expires_at", &self.expires_at)
            .field("attempts", &self.attempts)
            .field("child_node_id", &self.child_node_id)
            .field("comparison_code", &"<redacted>")
            .finish()
    }
}

// Carries the bounded public trust package issued for one verified child.
#[derive(Clone, Eq, PartialEq)]
pub struct NodePairingCredentials {
    main_public_key: Vec<u8>,
    main_ca_certificate: Vec<u8>,
    child_certificate: Vec<u8>,
    membership_signature: Vec<u8>,
    child_leaf_sha256: Sha256Digest,
    valid_from: UnixMilliseconds,
    expires_at: UnixMilliseconds,
}

impl NodePairingCredentials {
    // Creates one exact nonempty bounded public credential package.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        main_public_key: Vec<u8>,
        main_ca_certificate: Vec<u8>,
        child_certificate: Vec<u8>,
        membership_signature: Vec<u8>,
        child_leaf_sha256: Sha256Digest,
        valid_from: UnixMilliseconds,
        expires_at: UnixMilliseconds,
    ) -> Result<Self, NodePairingApiError> {
        let values = [
            main_public_key.as_slice(),
            main_ca_certificate.as_slice(),
            child_certificate.as_slice(),
            membership_signature.as_slice(),
        ];
        if values
            .iter()
            .any(|value| value.is_empty() || value.len() > MAX_CREDENTIAL_BYTES)
            || expires_at <= valid_from
        {
            return Err(NodePairingApiError::InvalidResponse);
        }
        Ok(Self {
            main_public_key,
            main_ca_certificate,
            child_certificate,
            membership_signature,
            child_leaf_sha256,
            valid_from,
            expires_at,
        })
    }

    // Returns the main public key distributed to the child.
    pub fn main_public_key(&self) -> &[u8] {
        &self.main_public_key
    }

    // Returns the exact main CA certificate distributed to the child.
    pub fn main_ca_certificate(&self) -> &[u8] {
        &self.main_ca_certificate
    }

    // Returns the issued child certificate.
    pub fn child_certificate(&self) -> &[u8] {
        &self.child_certificate
    }

    // Returns the main signature over membership state.
    pub fn membership_signature(&self) -> &[u8] {
        &self.membership_signature
    }

    // Returns the SHA-256 digest of the exact issued child certificate leaf.
    pub const fn child_leaf_sha256(&self) -> &Sha256Digest {
        &self.child_leaf_sha256
    }

    // Returns the inclusive child-certificate validity start.
    pub const fn valid_from(&self) -> UnixMilliseconds {
        self.valid_from
    }

    // Returns the exclusive child-certificate expiration boundary.
    pub const fn expires_at(&self) -> UnixMilliseconds {
        self.expires_at
    }
}

impl fmt::Debug for NodePairingCredentials {
    // Presents credential identities and bounds without dumping certificate or signature bytes.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NodePairingCredentials")
            .field("main_public_key_bytes", &self.main_public_key.len())
            .field("main_ca_certificate_bytes", &self.main_ca_certificate.len())
            .field("child_certificate_bytes", &self.child_certificate.len())
            .field(
                "membership_signature_bytes",
                &self.membership_signature.len(),
            )
            .field("child_leaf_sha256", &self.child_leaf_sha256)
            .field("valid_from", &self.valid_from)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

// Returns one completed enrollment and the exact public trust package for its child.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodePairingEnrollment {
    status: NodePairingStatus,
    credentials: NodePairingCredentials,
}

impl NodePairingEnrollment {
    // Creates one enrollment only from a verified pending or active pairing status.
    pub fn new(
        status: NodePairingStatus,
        credentials: NodePairingCredentials,
    ) -> Result<Self, NodePairingApiError> {
        if status.state() == NodePairingState::Open
            || status.expires_at() > credentials.expires_at()
        {
            return Err(NodePairingApiError::InvalidResponse);
        }
        Ok(Self {
            status,
            credentials,
        })
    }

    // Returns the durable state resulting from enrollment.
    pub const fn status(&self) -> &NodePairingStatus {
        &self.status
    }

    // Returns the exact public trust package issued to the child.
    pub const fn credentials(&self) -> &NodePairingCredentials {
        &self.credentials
    }
}

// Names stable pairing-port failures without importing manager or persistence errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodePairingApiError {
    MainOnly,
    InvalidRequest,
    NotFound,
    Expired,
    Conflict,
    Unavailable,
    InvalidResponse,
}

impl fmt::Display for NodePairingApiError {
    // Presents fixed pairing boundary language without candidate or credential values.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MainOnly => formatter.write_str("pairing action requires an active main node"),
            Self::InvalidRequest => formatter.write_str("pairing request is invalid"),
            Self::NotFound => formatter.write_str("pairing invitation is unavailable"),
            Self::Expired => formatter.write_str("pairing invitation has expired"),
            Self::Conflict => formatter.write_str("pairing state changed concurrently"),
            Self::Unavailable => formatter.write_str("pairing service is unavailable"),
            Self::InvalidResponse => formatter.write_str("pairing service returned invalid state"),
        }
    }
}

impl Error for NodePairingApiError {}

// Isolates PairingManager and atomic application composition behind one Node-owned capability.
pub trait NodePairingApiPort: Send + Sync {
    // Opens one durable pairing invitation and returns its one-time presentation material.
    fn open(
        &self,
        request: &NodePairingOpenRequest,
    ) -> Result<NodePairingInvitation, NodePairingApiError>;

    // Returns one public challenge after transport has supplied its observed peer address.
    fn challenge(
        &self,
        invite_id: &PairingInviteId,
        observed_peer_address: &NodeAddress,
    ) -> Result<NodePairingChallenge, NodePairingApiError> {
        let _ = (invite_id, observed_peer_address);
        Err(NodePairingApiError::Unavailable)
    }

    // Verifies one candidate and atomically materializes its pending or active enrollment.
    fn enroll(
        &self,
        request: &NodePairingEnrollRequest,
    ) -> Result<NodePairingEnrollment, NodePairingApiError>;

    // Atomically approves one exact pending remote pairing.
    fn approve(
        &self,
        request: &NodePairingApproveRequest,
    ) -> Result<NodePairingStatus, NodePairingApiError>;

    // Returns one exact durable pairing status without alternate identity lookup.
    fn status(&self, invite_id: &PairingInviteId)
        -> Result<NodePairingStatus, NodePairingApiError>;
}

// Requires one replay identity to be nonempty, bounded, and free of terminal controls.
fn require_idempotency_key(value: &str) -> Result<(), NodePairingApiError> {
    if value.is_empty()
        || value.len() > MAX_IDEMPOTENCY_KEY_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(NodePairingApiError::InvalidRequest);
    }
    Ok(())
}

// Returns whether one human code contains the exact number of ASCII digits.
fn is_digit_code(value: &str, digits: usize) -> bool {
    value.len() == digits && value.bytes().all(|byte| byte.is_ascii_digit())
}
