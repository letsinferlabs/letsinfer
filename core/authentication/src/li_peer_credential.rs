// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;

use li_core_interface::{CredentialId, NodeId, Sha256Digest, UnixMilliseconds};

use crate::{AuthenticationError, AuthenticationStoreError};

// Allows one exact result plus one duplicate sentinel without an unbounded store read.
pub const MAX_PEER_CREDENTIAL_LOOKUP_RESULTS: usize = 2;

// Names whether exact peer certificate material still awaits approval or may authorize.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerCredentialState {
    Pending,
    Active,
}

// Names one exact peer-certificate direction without implying reciprocal authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerCredentialDirection {
    ChildToMain,
    MainToChild,
}

// Carries one live peer identity together with its exact directional Node relationship.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerCredentialPrincipal {
    credential_id: CredentialId,
    local_node_id: NodeId,
    peer_node_id: NodeId,
    direction: PeerCredentialDirection,
}

impl PeerCredentialPrincipal {
    // Creates one principal only from a previously validated durable credential.
    const fn new(
        credential_id: CredentialId,
        local_node_id: NodeId,
        peer_node_id: NodeId,
        direction: PeerCredentialDirection,
    ) -> Self {
        Self {
            credential_id,
            local_node_id,
            peer_node_id,
            direction,
        }
    }

    // Returns the exact certificate-derived credential identity.
    pub const fn credential_id(&self) -> &CredentialId {
        &self.credential_id
    }

    // Returns the resident Node accepting this directional credential.
    pub const fn local_node_id(&self) -> &NodeId {
        &self.local_node_id
    }

    // Returns the exact remote Node represented by the peer certificate.
    pub const fn peer_node_id(&self) -> &NodeId {
        &self.peer_node_id
    }

    // Returns the closed direction authorized by the issued certificate relationship.
    pub const fn direction(&self) -> PeerCredentialDirection {
        self.direction
    }
}

// Stores one exact peer certificate identity and its durable authorization lifecycle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerCredential {
    credential_id: CredentialId,
    peer_leaf_sha256: Sha256Digest,
    local_node_id: NodeId,
    peer_node_id: NodeId,
    direction: PeerCredentialDirection,
    state: PeerCredentialState,
    issued_at: UnixMilliseconds,
    expires_at: UnixMilliseconds,
    revoked_at: Option<UnixMilliseconds>,
    rotated_to: Option<CredentialId>,
}

impl PeerCredential {
    // Creates one coherent persisted peer-certificate credential snapshot.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        credential_id: CredentialId,
        peer_leaf_sha256: Sha256Digest,
        local_node_id: NodeId,
        peer_node_id: NodeId,
        direction: PeerCredentialDirection,
        issued_at: UnixMilliseconds,
        expires_at: UnixMilliseconds,
        revoked_at: Option<UnixMilliseconds>,
        rotated_to: Option<CredentialId>,
    ) -> Result<Self, PeerCredentialError> {
        Self::new_with_state(
            credential_id,
            peer_leaf_sha256,
            local_node_id,
            peer_node_id,
            direction,
            PeerCredentialState::Active,
            issued_at,
            expires_at,
            revoked_at,
            rotated_to,
        )
    }

    // Creates one coherent persisted peer credential with an explicit approval state.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_state(
        credential_id: CredentialId,
        peer_leaf_sha256: Sha256Digest,
        local_node_id: NodeId,
        peer_node_id: NodeId,
        direction: PeerCredentialDirection,
        state: PeerCredentialState,
        issued_at: UnixMilliseconds,
        expires_at: UnixMilliseconds,
        revoked_at: Option<UnixMilliseconds>,
        rotated_to: Option<CredentialId>,
    ) -> Result<Self, PeerCredentialError> {
        if local_node_id == peer_node_id {
            return Err(PeerCredentialError::InvalidRecord {
                reason: "local and peer Nodes must differ",
            });
        }
        if expires_at <= issued_at {
            return Err(PeerCredentialError::InvalidRecord {
                reason: "expiration must follow issuance",
            });
        }
        if revoked_at.is_some_and(|revoked_at| revoked_at < issued_at) {
            return Err(PeerCredentialError::InvalidRecord {
                reason: "revocation cannot precede issuance",
            });
        }
        if rotated_to.is_some() && revoked_at.is_none() {
            return Err(PeerCredentialError::InvalidRecord {
                reason: "rotation requires revocation",
            });
        }
        if rotated_to.as_ref() == Some(&credential_id) {
            return Err(PeerCredentialError::InvalidRecord {
                reason: "rotation must identify a different credential",
            });
        }
        Ok(Self {
            credential_id,
            peer_leaf_sha256,
            local_node_id,
            peer_node_id,
            direction,
            state,
            issued_at,
            expires_at,
            revoked_at,
            rotated_to,
        })
    }

    // Returns the exact credential identity represented by this certificate leaf.
    pub const fn credential_id(&self) -> &CredentialId {
        &self.credential_id
    }

    // Returns the canonical SHA-256 digest of the exact peer leaf DER bytes.
    pub const fn peer_leaf_sha256(&self) -> &Sha256Digest {
        &self.peer_leaf_sha256
    }

    // Returns the resident Node accepting this directional credential.
    pub const fn local_node_id(&self) -> &NodeId {
        &self.local_node_id
    }

    // Returns the exact remote Node represented by this peer certificate.
    pub const fn peer_node_id(&self) -> &NodeId {
        &self.peer_node_id
    }

    // Returns the only direction authorized by this persisted relationship.
    pub const fn direction(&self) -> PeerCredentialDirection {
        self.direction
    }

    // Returns whether this exact certificate awaits approval or may authorize.
    pub const fn state(&self) -> PeerCredentialState {
        self.state
    }

    // Returns the same exact certificate lifecycle after explicit pairing approval.
    pub fn activated(&self) -> Self {
        Self {
            state: PeerCredentialState::Active,
            ..self.clone()
        }
    }

    // Returns when this credential first becomes valid.
    pub const fn issued_at(&self) -> UnixMilliseconds {
        self.issued_at
    }

    // Returns the exclusive credential expiration boundary.
    pub const fn expires_at(&self) -> UnixMilliseconds {
        self.expires_at
    }

    // Returns when this credential was terminally revoked.
    pub const fn revoked_at(&self) -> Option<UnixMilliseconds> {
        self.revoked_at
    }

    // Returns the replacement identity only as lifecycle metadata, never as a fallback.
    pub const fn rotated_to(&self) -> Option<&CredentialId> {
        self.rotated_to.as_ref()
    }

    // Returns this exact identity only while every durable lifetime gate remains active.
    pub(crate) fn resolve_at(
        &self,
        now: UnixMilliseconds,
    ) -> Result<PeerCredentialPrincipal, PeerCredentialError> {
        if self.rotated_to.is_some() {
            return Err(PeerCredentialError::Rotated);
        }
        if self.revoked_at.is_some() {
            return Err(PeerCredentialError::Revoked);
        }
        if self.state == PeerCredentialState::Pending {
            return Err(PeerCredentialError::Pending);
        }
        if now < self.issued_at {
            return Err(PeerCredentialError::NotYetValid);
        }
        if now >= self.expires_at {
            return Err(PeerCredentialError::Expired);
        }
        Ok(PeerCredentialPrincipal::new(
            self.credential_id.clone(),
            self.local_node_id.clone(),
            self.peer_node_id.clone(),
            self.direction,
        ))
    }
}

// Carries one peer credential with its exact persistence revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionedPeerCredential {
    credential: PeerCredential,
    revision: u64,
}

impl VersionedPeerCredential {
    // Creates one versioned result returned by a persisted peer-credential adapter.
    pub const fn new(credential: PeerCredential, revision: u64) -> Self {
        Self {
            credential,
            revision,
        }
    }

    // Returns the validated persisted credential snapshot.
    pub const fn credential(&self) -> &PeerCredential {
        &self.credential
    }

    // Returns the exact persistence revision observed by this lookup.
    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

// Reads exact peer-certificate identities from AuthenticationManager-owned persistence.
pub trait PeerCredentialStore: Send + Sync {
    // Returns at most the requested exact-digest matches without scanning another identity.
    fn matching_peer_credentials(
        &self,
        peer_leaf_sha256: &Sha256Digest,
        maximum_results: usize,
    ) -> Result<Vec<VersionedPeerCredential>, AuthenticationStoreError>;

    // Returns at most the requested exact-identity matches for live action authorization.
    fn matching_peer_credential_ids(
        &self,
        credential_id: &CredentialId,
        maximum_results: usize,
    ) -> Result<Vec<VersionedPeerCredential>, AuthenticationStoreError>;
}

// Names every closed peer-credential resolution decision without exposing an identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PeerCredentialError {
    InvalidRecord { reason: &'static str },
    Unrecognized,
    NotYetValid,
    Pending,
    Expired,
    Revoked,
    Rotated,
    Ambiguous,
    ClockUnavailable,
    Store(AuthenticationStoreError),
}

impl fmt::Display for PeerCredentialError {
    // Presents fixed language without leaf digests, credential identities, or store details.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRecord { reason } => {
                write!(formatter, "peer credential record is invalid: {reason}")
            }
            Self::Unrecognized
            | Self::NotYetValid
            | Self::Pending
            | Self::Expired
            | Self::Revoked
            | Self::Rotated
            | Self::Ambiguous => formatter.write_str("peer credential is unauthorized"),
            Self::ClockUnavailable => formatter.write_str("peer credential time is unavailable"),
            Self::Store(AuthenticationStoreError::Conflict) => {
                formatter.write_str("peer credential state changed concurrently")
            }
            Self::Store(AuthenticationStoreError::Corrupt) => {
                formatter.write_str("peer credential state is corrupt")
            }
            Self::Store(AuthenticationStoreError::Unavailable) => {
                formatter.write_str("peer credential storage is unavailable")
            }
        }
    }
}

impl Error for PeerCredentialError {}

impl From<AuthenticationStoreError> for PeerCredentialError {
    // Preserves one closed persistence failure at the peer-resolution boundary.
    fn from(error: AuthenticationStoreError) -> Self {
        Self::Store(error)
    }
}

impl From<AuthenticationError> for PeerCredentialError {
    // Redacts clock/provider failures without treating them as an unknown credential.
    fn from(_error: AuthenticationError) -> Self {
        Self::ClockUnavailable
    }
}
