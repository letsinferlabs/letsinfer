// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::sync::Arc;

use li_authentication_manager::{
    AuthenticationStoreError, PeerCredential, PeerCredentialDirection, PeerCredentialState,
};
use li_core_interface::{EntityTimestamps, Node, NodeId, NodeRole, NodeState, UnixMilliseconds};
use li_database::{DatabaseCollection, DatabaseCommitDisposition, DatabaseError, DatabaseManager};
use li_node_manager::{NodeManager, NodeManagerChange, NodeManagerError};
use li_pairing_manager::{
    PairingApproval, PairingEnrollmentMaterial, PairingError, PairingMembershipState,
    PairingResult, PairingStore,
};

use crate::{DatabasePairingStore, DatabasePeerCredentialStore};

// Returns one exact pairing composition outcome without claiming a Node before remote approval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorePairingEnrollmentChange {
    node: Option<NodeManagerChange<Node>>,
    disposition: DatabaseCommitDisposition,
}

impl CorePairingEnrollmentChange {
    // Creates one committed initial or approved enrollment result.
    const fn new(
        node: Option<NodeManagerChange<Node>>,
        disposition: DatabaseCommitDisposition,
    ) -> Self {
        Self { node, disposition }
    }

    // Returns the enrolled Node only for active or explicitly approved pairing.
    pub const fn node(&self) -> Option<&NodeManagerChange<Node>> {
        self.node.as_ref()
    }

    // Returns whether the exact atomic transaction applied or replayed.
    pub const fn disposition(&self) -> DatabaseCommitDisposition {
        self.disposition
    }
}

// Names fixed redacted failures at the pairing-to-enrollment composition boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CorePairingEnrollmentError {
    Pairing(PairingError),
    Authentication(AuthenticationStoreError),
    Node(NodeManagerError),
    Database(DatabaseError),
    DatabaseMismatch,
    IdentityMismatch,
    InvalidMaterial,
    CorruptCommit,
}

impl fmt::Display for CorePairingEnrollmentError {
    // Presents fixed language without certificate, identity, or persistence record contents.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pairing(error) => write!(formatter, "{error}"),
            Self::Authentication(AuthenticationStoreError::Conflict) => {
                formatter.write_str("peer credential state changed concurrently")
            }
            Self::Authentication(AuthenticationStoreError::Corrupt) => {
                formatter.write_str("peer credential state is corrupt")
            }
            Self::Authentication(AuthenticationStoreError::Unavailable) => {
                formatter.write_str("peer credential storage is unavailable")
            }
            Self::Node(error) => write!(formatter, "{error}"),
            Self::Database(error) => write!(formatter, "{error}"),
            Self::DatabaseMismatch => {
                formatter.write_str("pairing composition requires one shared database authority")
            }
            Self::IdentityMismatch => {
                formatter.write_str("pairing authority or child identity does not match")
            }
            Self::InvalidMaterial => formatter.write_str("pairing credential material is invalid"),
            Self::CorruptCommit => formatter.write_str("pairing enrollment commit is corrupt"),
        }
    }
}

impl Error for CorePairingEnrollmentError {}

// Owns the one atomic handoff from PairingManager into authentication and Node persistence.
pub struct CorePairingEnrollmentCoordinator {
    database: Arc<DatabaseManager>,
    pairings: DatabasePairingStore,
    peer_credentials: DatabasePeerCredentialStore,
    nodes: Arc<NodeManager>,
}

impl CorePairingEnrollmentCoordinator {
    // Creates one composition owner over one shared DatabaseManager and NodeManager authority.
    pub fn new(
        database: Arc<DatabaseManager>,
        nodes: Arc<NodeManager>,
    ) -> Result<Self, CorePairingEnrollmentError> {
        if !nodes.uses_database(&database) {
            return Err(CorePairingEnrollmentError::DatabaseMismatch);
        }
        Ok(Self {
            pairings: DatabasePairingStore::new(database.clone()),
            peer_credentials: DatabasePeerCredentialStore::new(database.clone()),
            database,
            nodes,
        })
    }

    // Atomically persists active pairing, credential, child Node, and outbox or remote pending state.
    pub fn commit_pairing(
        &self,
        idempotency_key: &str,
        result: &PairingResult,
        committed_at: UnixMilliseconds,
    ) -> Result<CorePairingEnrollmentChange, CorePairingEnrollmentError> {
        self.require_authority_and_child(
            result.pairing_record().main_node_id(),
            result.child_identity(),
            result
                .pairing_record()
                .enrollment()
                .ok_or(CorePairingEnrollmentError::InvalidMaterial)?,
        )?;
        let credential = peer_credential(
            result
                .pairing_record()
                .enrollment()
                .ok_or(CorePairingEnrollmentError::InvalidMaterial)?,
            result.pairing_record().main_node_id(),
        )?;
        if let Some(replayed) = self.replayed_pairing(result.pairing_record(), &credential)? {
            return Ok(replayed);
        }
        if committed_at >= result.pairing_record().expires_at() {
            return Err(CorePairingEnrollmentError::InvalidMaterial);
        }
        require_commit_time(&credential, committed_at)?;
        let transaction = self.pairings.replacing_transaction(
            result.pairing_record(),
            result.expected_pairing_revision(),
            idempotency_key,
        )?;
        let transaction = self
            .peer_credentials
            .creating_transaction(transaction, &credential)?;
        match result.state() {
            PairingMembershipState::PendingApproval => {
                let write = self.database.write_transaction(transaction)?;
                require_pending_commits(write.commit().commits())?;
                Ok(CorePairingEnrollmentChange::new(None, write.disposition()))
            }
            PairingMembershipState::Active => {
                let node = child_node(
                    result
                        .pairing_record()
                        .enrollment()
                        .ok_or(CorePairingEnrollmentError::InvalidMaterial)?,
                    committed_at,
                )?;
                let change =
                    self.nodes
                        .enroll_child_with_transaction(idempotency_key, node, transaction)?;
                let disposition = if change.event().is_some() {
                    DatabaseCommitDisposition::Applied
                } else {
                    DatabaseCommitDisposition::Replayed
                };
                Ok(CorePairingEnrollmentChange::new(Some(change), disposition))
            }
        }
    }

    // Atomically activates pending pairing and credential while enrolling its child and outbox.
    pub fn approve_pairing(
        &self,
        idempotency_key: &str,
        approval: &PairingApproval,
        approved_at: UnixMilliseconds,
    ) -> Result<CorePairingEnrollmentChange, CorePairingEnrollmentError> {
        self.require_authority_and_child(
            approval.pairing_record().main_node_id(),
            approval.enrollment().child_identity(),
            approval.enrollment(),
        )?;
        let desired = peer_credential(
            approval.enrollment(),
            approval.pairing_record().main_node_id(),
        )?;
        if desired.state() != PeerCredentialState::Active {
            return Err(CorePairingEnrollmentError::InvalidMaterial);
        }
        let current = self
            .peer_credentials
            .exact_credential(desired.peer_leaf_sha256())?
            .ok_or(CorePairingEnrollmentError::InvalidMaterial)?;
        if current.credential() == &desired
            && self
                .pairings
                .pairing(approval.pairing_record().invite_id())?
                .is_some_and(|value| value.record() == approval.pairing_record())
        {
            let observed = self
                .nodes
                .node(approval.enrollment().child_identity().node_id())
                .map_err(CorePairingEnrollmentError::from)?;
            if !node_matches_enrollment(observed.value(), approval.enrollment()) {
                return Err(CorePairingEnrollmentError::IdentityMismatch);
            }
            return Ok(CorePairingEnrollmentChange::new(
                Some(observed),
                DatabaseCommitDisposition::Replayed,
            ));
        }
        if approved_at >= approval.pairing_record().expires_at() {
            return Err(CorePairingEnrollmentError::InvalidMaterial);
        }
        require_commit_time(&desired, approved_at)?;
        if current.credential().credential_id() != desired.credential_id()
            || current.credential().peer_leaf_sha256() != desired.peer_leaf_sha256()
            || current.credential().local_node_id() != desired.local_node_id()
            || current.credential().peer_node_id() != desired.peer_node_id()
            || current.credential().direction() != desired.direction()
            || current.credential().state() != PeerCredentialState::Pending
            || current.credential().issued_at() != desired.issued_at()
            || current.credential().expires_at() != desired.expires_at()
            || current.credential().revoked_at().is_some()
            || current.credential().rotated_to().is_some()
        {
            return Err(CorePairingEnrollmentError::InvalidMaterial);
        }
        let transaction = self.pairings.replacing_transaction(
            approval.pairing_record(),
            approval.expected_pairing_revision(),
            idempotency_key,
        )?;
        let transaction = self.peer_credentials.replacing_transaction(
            transaction,
            &desired,
            current.revision(),
        )?;
        let node = child_node(approval.enrollment(), approved_at)?;
        let change =
            self.nodes
                .enroll_child_with_transaction(idempotency_key, node, transaction)?;
        let disposition = if change.event().is_some() {
            DatabaseCommitDisposition::Applied
        } else {
            DatabaseCommitDisposition::Replayed
        };
        Ok(CorePairingEnrollmentChange::new(Some(change), disposition))
    }

    // Requires one result to bind this exact main authority and one exact child identity.
    fn require_authority_and_child(
        &self,
        main_node_id: &li_core_interface::NodeId,
        child_identity: &li_core_interface::NodeIdentity,
        enrollment: &PairingEnrollmentMaterial,
    ) -> Result<(), CorePairingEnrollmentError> {
        if main_node_id != self.nodes.local_node_id()
            || child_identity != enrollment.child_identity()
            || child_identity.node_id() == self.nodes.local_node_id()
        {
            return Err(CorePairingEnrollmentError::IdentityMismatch);
        }
        Ok(())
    }

    // Recognizes one exact already-committed enrollment before proposing another transaction.
    fn replayed_pairing(
        &self,
        record: &li_pairing_manager::PairingRecord,
        credential: &PeerCredential,
    ) -> Result<Option<CorePairingEnrollmentChange>, CorePairingEnrollmentError> {
        let Some(current_pairing) = self.pairings.pairing(record.invite_id())? else {
            return Ok(None);
        };
        if current_pairing.record() != record {
            return Ok(None);
        }
        let current_credential = self
            .peer_credentials
            .exact_credential(credential.peer_leaf_sha256())?
            .ok_or(CorePairingEnrollmentError::InvalidMaterial)?;
        if current_credential.credential() != credential {
            return Err(CorePairingEnrollmentError::InvalidMaterial);
        }
        let enrollment = record
            .enrollment()
            .ok_or(CorePairingEnrollmentError::InvalidMaterial)?;
        match record.state() {
            li_pairing_manager::PairingRecordState::PendingApproval => Ok(Some(
                CorePairingEnrollmentChange::new(None, DatabaseCommitDisposition::Replayed),
            )),
            li_pairing_manager::PairingRecordState::Active => {
                let observed = self
                    .nodes
                    .node(enrollment.child_identity().node_id())
                    .map_err(CorePairingEnrollmentError::from)?;
                if !node_matches_enrollment(observed.value(), enrollment) {
                    return Err(CorePairingEnrollmentError::IdentityMismatch);
                }
                Ok(Some(CorePairingEnrollmentChange::new(
                    Some(observed),
                    DatabaseCommitDisposition::Replayed,
                )))
            }
            li_pairing_manager::PairingRecordState::Open => {
                Err(CorePairingEnrollmentError::InvalidMaterial)
            }
        }
    }
}

// Converts exact PairingManager certificate material into AuthenticationManager state.
fn peer_credential(
    enrollment: &PairingEnrollmentMaterial,
    main_node_id: &NodeId,
) -> Result<PeerCredential, CorePairingEnrollmentError> {
    let material = enrollment.peer_credential();
    let state = match material.state() {
        PairingMembershipState::PendingApproval => PeerCredentialState::Pending,
        PairingMembershipState::Active => PeerCredentialState::Active,
    };
    PeerCredential::new_with_state(
        material.credential_id().clone(),
        material.peer_leaf_sha256().clone(),
        main_node_id.clone(),
        enrollment.child_identity().node_id().clone(),
        PeerCredentialDirection::ChildToMain,
        state,
        material.valid_from(),
        material.expires_at(),
        None,
        None,
    )
    .map_err(|_| CorePairingEnrollmentError::InvalidMaterial)
}

// Creates one pending child Node only from the exact approved pairing enrollment material.
fn child_node(
    enrollment: &PairingEnrollmentMaterial,
    changed_at: UnixMilliseconds,
) -> Result<Node, CorePairingEnrollmentError> {
    Ok(Node::new(
        enrollment.child_identity().clone(),
        enrollment.child_name().clone(),
        NodeRole::Child,
        NodeState::Pending,
        enrollment.child_address().clone(),
        None,
        EntityTimestamps::new(changed_at, changed_at)
            .map_err(|_| CorePairingEnrollmentError::InvalidMaterial)?,
    ))
}

// Requires one durable child to preserve every pairing-owned identity and address field.
fn node_matches_enrollment(node: &Node, enrollment: &PairingEnrollmentMaterial) -> bool {
    node.identity() == enrollment.child_identity()
        && node.display_name() == enrollment.child_name()
        && node.role() == NodeRole::Child
        && node.control_address() == enrollment.child_address()
}

// Requires persistence and approval to occur inside the exact certificate lifetime.
fn require_commit_time(
    credential: &PeerCredential,
    committed_at: UnixMilliseconds,
) -> Result<(), CorePairingEnrollmentError> {
    if committed_at < credential.issued_at() || committed_at >= credential.expires_at() {
        return Err(CorePairingEnrollmentError::InvalidMaterial);
    }
    Ok(())
}

// Requires the initial remote transaction to contain only pairing and pending credential records.
fn require_pending_commits(
    commits: &[li_database::DatabaseCommit],
) -> Result<(), CorePairingEnrollmentError> {
    if commits.len() != 3
        || commits[0].collection != DatabaseCollection::Pairings
        || commits[1].collection != DatabaseCollection::PairingReplays
        || commits[2].collection != DatabaseCollection::PeerCredentials
    {
        return Err(CorePairingEnrollmentError::CorruptCommit);
    }
    Ok(())
}

impl From<PairingError> for CorePairingEnrollmentError {
    // Preserves one redacted pairing lifecycle failure.
    fn from(error: PairingError) -> Self {
        Self::Pairing(error)
    }
}

impl From<AuthenticationStoreError> for CorePairingEnrollmentError {
    // Preserves one closed authentication persistence failure.
    fn from(error: AuthenticationStoreError) -> Self {
        Self::Authentication(error)
    }
}

impl From<NodeManagerError> for CorePairingEnrollmentError {
    // Preserves one closed Node orchestration failure.
    fn from(error: NodeManagerError) -> Self {
        Self::Node(error)
    }
}

impl From<DatabaseError> for CorePairingEnrollmentError {
    // Preserves one shared database failure without exposing record contents.
    fn from(error: DatabaseError) -> Self {
        Self::Database(error)
    }
}
