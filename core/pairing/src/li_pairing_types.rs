// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;

use li_core_interface::{
    CredentialId, DisplayName, NetworkInterfaceName, NodeAddress, NodeIdentity, NodeRole,
    PairingInviteId, Sha256Digest, UnixMilliseconds,
};

use crate::{PairingError, PairingPeerCredentialMaterial, PairingRecord};

// Selects the authorization mechanism for one pairing invitation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PairingMode {
    Lan,
    Remote,
    ConnectX {
        candidate_public_key: Sha256Digest,
        direct_interface: NetworkInterfaceName,
    },
}

// Supplies immutable local identity and public trust facts from NodeManager.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingContext {
    identity: NodeIdentity,
    role: NodeRole,
    display_name: DisplayName,
    control_address: NodeAddress,
    private_control_port: u16,
    public_key_fingerprint: Sha256Digest,
    certificate_fingerprint: Sha256Digest,
}

impl PairingContext {
    // Creates one explicit pairing context without reading NodeManager.
    pub const fn new(
        identity: NodeIdentity,
        role: NodeRole,
        display_name: DisplayName,
        control_address: NodeAddress,
        private_control_port: u16,
        public_key_fingerprint: Sha256Digest,
        certificate_fingerprint: Sha256Digest,
    ) -> Self {
        Self {
            identity,
            role,
            display_name,
            control_address,
            private_control_port,
            public_key_fingerprint,
            certificate_fingerprint,
        }
    }

    // Returns the local node identity supplied by NodeManager.
    pub const fn identity(&self) -> &NodeIdentity {
        &self.identity
    }

    // Returns the local node topology role.
    pub const fn role(&self) -> NodeRole {
        self.role
    }

    // Returns the local node display name.
    pub const fn display_name(&self) -> &DisplayName {
        &self.display_name
    }

    // Returns the private control-plane address.
    pub const fn control_address(&self) -> &NodeAddress {
        &self.control_address
    }

    // Returns the explicit authenticated private Node listener port.
    pub const fn private_control_port(&self) -> u16 {
        self.private_control_port
    }

    // Returns the local node public-key fingerprint.
    pub const fn public_key_fingerprint(&self) -> &Sha256Digest {
        &self.public_key_fingerprint
    }

    // Returns the pinned control certificate fingerprint.
    pub const fn certificate_fingerprint(&self) -> &Sha256Digest {
        &self.certificate_fingerprint
    }
}

// Configures one bounded pairing window.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingWindowRequest {
    mode: PairingMode,
    lifetime_seconds: u16,
}

impl PairingWindowRequest {
    // Creates one invitation lasting between thirty seconds and ten minutes.
    pub fn new(mode: PairingMode, lifetime_seconds: u16) -> Result<Self, PairingError> {
        if !(30..=600).contains(&lifetime_seconds) {
            return Err(PairingError::InvalidRequest {
                reason: "invitation lifetime must be between 30 and 600 seconds",
            });
        }
        Ok(Self {
            mode,
            lifetime_seconds,
        })
    }

    // Returns the pairing authorization mode.
    pub const fn mode(&self) -> &PairingMode {
        &self.mode
    }

    // Returns the invitation lifetime in seconds.
    pub const fn lifetime_seconds(&self) -> u16 {
        self.lifetime_seconds
    }
}

// Owns one eight-digit setup code until it is presented once.
pub struct PairingSetupCode {
    digits: Option<[u8; 8]>,
}

impl PairingSetupCode {
    // Creates one setup-code owner from generated ASCII digits.
    pub(crate) const fn new(digits: [u8; 8]) -> Self {
        Self {
            digits: Some(digits),
        }
    }

    // Takes the setup code once and clears the retained byte buffer.
    pub fn take(&mut self) -> Option<String> {
        let mut digits = self.digits.take()?;
        let value = String::from_utf8(digits.to_vec()).ok();
        digits.fill(0);
        value
    }
}

impl fmt::Debug for PairingSetupCode {
    // Redacts the setup code from debug presentation.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairingSetupCode(<redacted>)")
    }
}

impl Drop for PairingSetupCode {
    // Clears unpresented setup-code bytes when their owner is released.
    fn drop(&mut self) {
        if let Some(digits) = &mut self.digits {
            digits.fill(0);
        }
    }
}

// Returns one opened invitation and its optional one-time setup code.
#[derive(Debug)]
pub struct IssuedPairingWindow {
    invite_id: PairingInviteId,
    mode: PairingMode,
    nonce: Sha256Digest,
    expires_at: UnixMilliseconds,
    setup_code: Option<PairingSetupCode>,
}

impl IssuedPairingWindow {
    // Creates one opened invitation result.
    pub(crate) const fn new(
        invite_id: PairingInviteId,
        mode: PairingMode,
        nonce: Sha256Digest,
        expires_at: UnixMilliseconds,
        setup_code: Option<PairingSetupCode>,
    ) -> Self {
        Self {
            invite_id,
            mode,
            nonce,
            expires_at,
            setup_code,
        }
    }

    // Returns the invitation identity.
    pub const fn invite_id(&self) -> &PairingInviteId {
        &self.invite_id
    }

    // Returns the invitation mode.
    pub const fn mode(&self) -> &PairingMode {
        &self.mode
    }

    // Returns the invitation challenge nonce.
    pub const fn nonce(&self) -> &Sha256Digest {
        &self.nonce
    }

    // Returns the invitation expiry.
    pub const fn expires_at(&self) -> UnixMilliseconds {
        self.expires_at
    }

    // Returns mutable ownership for one-time setup-code presentation.
    pub fn setup_code_mut(&mut self) -> Option<&mut PairingSetupCode> {
        self.setup_code.as_mut()
    }
}

// Publishes only bounded identity and pairing connection hints.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingAdvertisement {
    invite_id: PairingInviteId,
    display_name: DisplayName,
    control_address: NodeAddress,
    certificate_fingerprint: Sha256Digest,
    expires_at: UnixMilliseconds,
    mode: PairingMode,
}

impl PairingAdvertisement {
    // Creates one credential-free pairing advertisement.
    pub(crate) const fn new(
        invite_id: PairingInviteId,
        display_name: DisplayName,
        control_address: NodeAddress,
        certificate_fingerprint: Sha256Digest,
        expires_at: UnixMilliseconds,
        mode: PairingMode,
    ) -> Self {
        Self {
            invite_id,
            display_name,
            control_address,
            certificate_fingerprint,
            expires_at,
            mode,
        }
    }

    // Returns the invitation identity.
    pub const fn invite_id(&self) -> &PairingInviteId {
        &self.invite_id
    }

    // Returns the advertised main-node name.
    pub const fn display_name(&self) -> &DisplayName {
        &self.display_name
    }

    // Returns the advertised private control address.
    pub const fn control_address(&self) -> &NodeAddress {
        &self.control_address
    }

    // Returns the pinned control certificate fingerprint.
    pub const fn certificate_fingerprint(&self) -> &Sha256Digest {
        &self.certificate_fingerprint
    }

    // Returns when this advertisement becomes unusable.
    pub const fn expires_at(&self) -> UnixMilliseconds {
        self.expires_at
    }

    // Returns the invitation authorization mode.
    pub const fn mode(&self) -> &PairingMode {
        &self.mode
    }
}

// Describes the public challenge returned before candidate proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingChallenge {
    invite_id: PairingInviteId,
    nonce: Sha256Digest,
    mode: PairingMode,
    created_at: UnixMilliseconds,
    expires_at: UnixMilliseconds,
    main_node_id: li_core_interface::NodeId,
    main_address: NodeAddress,
    main_private_port: u16,
    public_key_fingerprint: Sha256Digest,
    certificate_fingerprint: Sha256Digest,
}

impl PairingChallenge {
    // Creates one bounded challenge from an active invitation and local context.
    pub(crate) fn new(
        invite_id: PairingInviteId,
        nonce: Sha256Digest,
        mode: PairingMode,
        created_at: UnixMilliseconds,
        expires_at: UnixMilliseconds,
        context: &PairingContext,
    ) -> Self {
        Self {
            invite_id,
            nonce,
            mode,
            created_at,
            expires_at,
            main_node_id: context.identity().node_id().clone(),
            main_address: context.control_address().clone(),
            main_private_port: context.private_control_port(),
            public_key_fingerprint: context.public_key_fingerprint().clone(),
            certificate_fingerprint: context.certificate_fingerprint().clone(),
        }
    }

    // Returns the invitation identity.
    pub const fn invite_id(&self) -> &PairingInviteId {
        &self.invite_id
    }

    // Returns the invitation challenge nonce.
    pub const fn nonce(&self) -> &Sha256Digest {
        &self.nonce
    }

    // Returns the invitation mode.
    pub const fn mode(&self) -> &PairingMode {
        &self.mode
    }

    // Returns the exact invitation creation time bound into candidate proof.
    pub const fn created_at(&self) -> UnixMilliseconds {
        self.created_at
    }

    // Returns the invitation expiry.
    pub const fn expires_at(&self) -> UnixMilliseconds {
        self.expires_at
    }

    // Returns the main node identity.
    pub const fn main_node_id(&self) -> &li_core_interface::NodeId {
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

    // Returns the main node public-key fingerprint.
    pub const fn public_key_fingerprint(&self) -> &Sha256Digest {
        &self.public_key_fingerprint
    }

    // Returns the pinned main control certificate fingerprint.
    pub const fn certificate_fingerprint(&self) -> &Sha256Digest {
        &self.certificate_fingerprint
    }
}

// Carries one candidate identity and proof into PairingManager.
#[derive(Clone, Eq, PartialEq)]
pub struct PairingCandidate {
    identity: NodeIdentity,
    display_name: DisplayName,
    control_address: NodeAddress,
    public_key: Vec<u8>,
    installation_created_at: UnixMilliseconds,
    proof_signature: Vec<u8>,
    setup_code: Option<String>,
    peer_address: NodeAddress,
}

impl fmt::Debug for PairingCandidate {
    // Redacts setup code, proof signature, and public-key bytes from debug output.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingCandidate")
            .field("identity", &self.identity)
            .field("display_name", &self.display_name)
            .field("control_address", &self.control_address)
            .field("public_key", &"<redacted>")
            .field("installation_created_at", &self.installation_created_at)
            .field("proof_signature", &"<redacted>")
            .field("setup_code", &"<redacted>")
            .field("peer_address", &self.peer_address)
            .finish()
    }
}

impl PairingCandidate {
    // Creates one bounded candidate request without verifying its proof.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        identity: NodeIdentity,
        display_name: DisplayName,
        control_address: NodeAddress,
        public_key: Vec<u8>,
        installation_created_at: UnixMilliseconds,
        proof_signature: Vec<u8>,
        setup_code: Option<String>,
        peer_address: NodeAddress,
    ) -> Result<Self, PairingError> {
        if !(128..=8 * 1024).contains(&public_key.len()) {
            return Err(PairingError::InvalidRequest {
                reason: "candidate public key size is invalid",
            });
        }
        if proof_signature.is_empty() || proof_signature.len() > 1024 {
            return Err(PairingError::InvalidRequest {
                reason: "candidate proof size is invalid",
            });
        }
        Ok(Self {
            identity,
            display_name,
            control_address,
            public_key,
            installation_created_at,
            proof_signature,
            setup_code,
            peer_address,
        })
    }

    // Returns the candidate node identity.
    pub const fn identity(&self) -> &NodeIdentity {
        &self.identity
    }

    // Returns the candidate display name.
    pub const fn display_name(&self) -> &DisplayName {
        &self.display_name
    }

    // Returns the candidate private control address.
    pub const fn control_address(&self) -> &NodeAddress {
        &self.control_address
    }

    // Returns the candidate public key bytes.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    // Returns when the candidate installation identity was created.
    pub const fn installation_created_at(&self) -> UnixMilliseconds {
        self.installation_created_at
    }

    // Returns the candidate proof signature.
    pub fn proof_signature(&self) -> &[u8] {
        &self.proof_signature
    }

    // Returns the optional code presented by a code-based invitation.
    pub fn setup_code(&self) -> Option<&str> {
        self.setup_code.as_deref()
    }

    // Returns the network peer address observed by the private API.
    pub const fn peer_address(&self) -> &NodeAddress {
        &self.peer_address
    }
}

// Describes the initial membership state produced by pairing mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingMembershipState {
    Active,
    PendingApproval,
}

// Carries public certificates and signatures produced by the trust provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingCredentials {
    site_public_key: Vec<u8>,
    site_ca_certificate: Vec<u8>,
    member_certificate: Vec<u8>,
    membership_signature: Vec<u8>,
    member_leaf_sha256: Sha256Digest,
    member_valid_from: UnixMilliseconds,
    member_expires_at: UnixMilliseconds,
}

impl PairingCredentials {
    // Creates one non-empty bounded public credential package.
    pub fn new(
        site_public_key: Vec<u8>,
        site_ca_certificate: Vec<u8>,
        member_certificate: Vec<u8>,
        membership_signature: Vec<u8>,
        member_leaf_sha256: Sha256Digest,
        member_valid_from: UnixMilliseconds,
        member_expires_at: UnixMilliseconds,
    ) -> Result<Self, PairingError> {
        let values = [
            site_public_key.as_slice(),
            site_ca_certificate.as_slice(),
            member_certificate.as_slice(),
            membership_signature.as_slice(),
        ];
        if values
            .iter()
            .any(|value| value.is_empty() || value.len() > 64 * 1024)
        {
            return Err(PairingError::InvalidRequest {
                reason: "pairing credential package is empty or oversized",
            });
        }
        if member_expires_at <= member_valid_from {
            return Err(PairingError::InvalidRequest {
                reason: "member certificate expiration must follow its validity start",
            });
        }
        Ok(Self {
            site_public_key,
            site_ca_certificate,
            member_certificate,
            membership_signature,
            member_leaf_sha256,
            member_valid_from,
            member_expires_at,
        })
    }

    // Returns the main site public key.
    pub fn site_public_key(&self) -> &[u8] {
        &self.site_public_key
    }

    // Returns the main site CA certificate.
    pub fn site_ca_certificate(&self) -> &[u8] {
        &self.site_ca_certificate
    }

    // Returns the issued child certificate.
    pub fn member_certificate(&self) -> &[u8] {
        &self.member_certificate
    }

    // Returns the main signature over membership state.
    pub fn membership_signature(&self) -> &[u8] {
        &self.membership_signature
    }

    // Returns the SHA-256 digest of the exact issued certificate leaf DER bytes.
    pub const fn member_leaf_sha256(&self) -> &Sha256Digest {
        &self.member_leaf_sha256
    }

    // Returns the exact inclusive certificate validity start supplied by the trust provider.
    pub const fn member_valid_from(&self) -> UnixMilliseconds {
        self.member_valid_from
    }

    // Returns the exact exclusive certificate expiration supplied by the trust provider.
    pub const fn member_expires_at(&self) -> UnixMilliseconds {
        self.member_expires_at
    }

    // Projects exact trust facts into AuthenticationManager-owned lifecycle material.
    pub(crate) fn peer_credential_material(
        &self,
        state: PairingMembershipState,
    ) -> Result<PairingPeerCredentialMaterial, PairingError> {
        let credential_id = CredentialId::parse(&self.member_leaf_sha256.as_str()[..32])?;
        PairingPeerCredentialMaterial::new(
            credential_id,
            self.member_leaf_sha256.clone(),
            self.member_valid_from,
            self.member_expires_at,
            state,
        )
    }
}

// Owns one six-digit remote comparison code without debug disclosure.
pub struct PairingComparisonCode([u8; 6]);

impl PairingComparisonCode {
    // Creates one comparison code from deterministic ASCII digits.
    pub(crate) const fn new(digits: [u8; 6]) -> Self {
        Self(digits)
    }

    // Returns the human comparison code for explicit approval.
    pub fn expose(&self) -> String {
        String::from_utf8_lossy(&self.0).into_owned()
    }

    // Returns comparison digits only to the durable pairing transition owner.
    pub(crate) const fn bytes(&self) -> [u8; 6] {
        self.0
    }
}

impl fmt::Debug for PairingComparisonCode {
    // Redacts the comparison code from debug presentation.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairingComparisonCode(<redacted>)")
    }
}

impl Drop for PairingComparisonCode {
    // Clears comparison digits when their approval owner is released.
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

// Returns the validated trust result that NodeManager may commit.
#[derive(Debug)]
pub struct PairingResult {
    invite_id: PairingInviteId,
    child_identity: NodeIdentity,
    child_name: DisplayName,
    child_address: NodeAddress,
    child_public_key_fingerprint: Sha256Digest,
    state: PairingMembershipState,
    approval_expires_at: Option<UnixMilliseconds>,
    comparison_code: Option<PairingComparisonCode>,
    credentials: PairingCredentials,
    pairing_record: PairingRecord,
    expected_pairing_revision: u64,
}

impl PairingResult {
    // Creates one complete pairing result after every proof and mode check passes.
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        invite_id: PairingInviteId,
        child_identity: NodeIdentity,
        child_name: DisplayName,
        child_address: NodeAddress,
        child_public_key_fingerprint: Sha256Digest,
        state: PairingMembershipState,
        approval_expires_at: Option<UnixMilliseconds>,
        comparison_code: Option<PairingComparisonCode>,
        credentials: PairingCredentials,
        pairing_record: PairingRecord,
        expected_pairing_revision: u64,
    ) -> Self {
        Self {
            invite_id,
            child_identity,
            child_name,
            child_address,
            child_public_key_fingerprint,
            state,
            approval_expires_at,
            comparison_code,
            credentials,
            pairing_record,
            expected_pairing_revision,
        }
    }

    // Returns the consumed invitation identity.
    pub const fn invite_id(&self) -> &PairingInviteId {
        &self.invite_id
    }

    // Returns the authenticated child identity.
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

    // Returns the initial child membership state.
    pub const fn state(&self) -> PairingMembershipState {
        self.state
    }

    // Returns the remote-approval expiry when one exists.
    pub const fn approval_expires_at(&self) -> Option<UnixMilliseconds> {
        self.approval_expires_at
    }

    // Returns the human comparison code for remote approval.
    pub const fn comparison_code(&self) -> Option<&PairingComparisonCode> {
        self.comparison_code.as_ref()
    }

    // Returns the public trust credential package.
    pub const fn credentials(&self) -> &PairingCredentials {
        &self.credentials
    }

    // Returns the exact durable pairing state that must join the enrollment transaction.
    pub const fn pairing_record(&self) -> &PairingRecord {
        &self.pairing_record
    }

    // Returns the exact pairing revision observed before proof and certificate issuance.
    pub const fn expected_pairing_revision(&self) -> u64 {
        self.expected_pairing_revision
    }
}
