// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::sync::Arc;

use li_authentication_manager::{PeerCredential, PeerCredentialDirection, PeerCredentialState};
use li_core_interface::{CredentialId, Node, NodeRole, NodeState, Sha256Digest};
use li_database::{DatabaseError, DatabaseManager, DatabaseTransaction};
use li_pairing_manager::PairingClock;

use crate::{
    DatabasePeerCredentialStore, LocalNodeRoleReadinessProvider, NodeManager, NodeManagerError,
    NodePairingCredentials,
};

const MAXIMUM_IDEMPOTENCY_KEY_BYTES: usize = 255;

// Carries one exact verified authority package into the atomic paired-child transition.
#[derive(Clone, Eq, PartialEq)]
pub struct NodePairedChildActivationRequest {
    idempotency_key: String,
    main: Node,
    main_certificate_sha256: Sha256Digest,
    credentials: NodePairingCredentials,
}

impl NodePairedChildActivationRequest {
    // Creates one bounded activation request without accepting a caller-owned database revision.
    pub fn new(
        idempotency_key: String,
        main: Node,
        main_certificate_sha256: Sha256Digest,
        credentials: NodePairingCredentials,
    ) -> Result<Self, NodePairingActivationAuthorityError> {
        validate_request(&idempotency_key, &main, &main_certificate_sha256)?;
        Ok(Self {
            idempotency_key,
            main,
            main_certificate_sha256,
            credentials,
        })
    }

    // Returns the exact database replay identity owned by the pairing saga.
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    // Returns the verified destination main authority.
    pub const fn main(&self) -> &Node {
        &self.main
    }

    // Returns the verified main TLS leaf identity committed with child authority.
    pub const fn main_certificate_sha256(&self) -> &Sha256Digest {
        &self.main_certificate_sha256
    }

    // Returns the public credential package whose validity bounds the trust record.
    pub const fn credentials(&self) -> &NodePairingCredentials {
        &self.credentials
    }
}

impl fmt::Debug for NodePairedChildActivationRequest {
    // Presents only non-secret replay and authority identities.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NodePairedChildActivationRequest")
            .field("idempotency_key", &self.idempotency_key)
            .field("main", &self.main)
            .field("main_certificate_sha256", &self.main_certificate_sha256)
            .field("credentials", &"<public-credential-package>")
            .finish()
    }
}

// Carries the exact activation identity required to atomically restore standalone main authority.
#[derive(Clone, Eq, PartialEq)]
pub struct NodePairedMainRestorationRequest {
    idempotency_key: String,
    main: Node,
    main_certificate_sha256: Sha256Digest,
    credentials: NodePairingCredentials,
}

impl NodePairedMainRestorationRequest {
    // Creates one bounded restoration request bound to the activation-owned main and credential.
    pub fn new(
        idempotency_key: String,
        main: Node,
        main_certificate_sha256: Sha256Digest,
        credentials: NodePairingCredentials,
    ) -> Result<Self, NodePairingActivationAuthorityError> {
        validate_request(&idempotency_key, &main, &main_certificate_sha256)?;
        Ok(Self {
            idempotency_key,
            main,
            main_certificate_sha256,
            credentials,
        })
    }

    // Returns the exact database replay identity owned by compensation.
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    // Returns the exact paired main authority that must be retired.
    pub const fn main(&self) -> &Node {
        &self.main
    }

    // Returns the exact activation-owned credential leaf that must be deleted.
    pub const fn main_certificate_sha256(&self) -> &Sha256Digest {
        &self.main_certificate_sha256
    }

    // Returns the public package used to reconstruct the exact expected credential.
    pub const fn credentials(&self) -> &NodePairingCredentials {
        &self.credentials
    }
}

impl fmt::Debug for NodePairedMainRestorationRequest {
    // Presents only non-secret replay and authority identities.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NodePairedMainRestorationRequest")
            .field("idempotency_key", &self.idempotency_key)
            .field("main", &self.main)
            .field("main_certificate_sha256", &self.main_certificate_sha256)
            .field("credentials", &"<public-credential-package>")
            .finish()
    }
}

// Distinguishes a new atomic authority commit from an exact observed replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodePairingAuthorityDisposition {
    Applied,
    Replayed,
}

// Returns the local Node snapshot committed by one paired authority transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodePairingAuthorityReceipt {
    local: Node,
    disposition: NodePairingAuthorityDisposition,
}

impl NodePairingAuthorityReceipt {
    // Creates one receipt only inside the authority after post-commit verification.
    const fn new(local: Node, disposition: NodePairingAuthorityDisposition) -> Self {
        Self { local, disposition }
    }

    // Restores one receipt after a transport or deterministic mock validates its closed fields.
    pub const fn restore(local: Node, disposition: NodePairingAuthorityDisposition) -> Self {
        Self::new(local, disposition)
    }

    // Returns the exact local Node snapshot after activation or restoration.
    pub const fn local(&self) -> &Node {
        &self.local
    }

    // Returns whether the authority transaction applied or exactly replayed.
    pub const fn disposition(&self) -> NodePairingAuthorityDisposition {
        self.disposition
    }
}

// Describes one stable atomic pairing authority failure without database detail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodePairingActivationAuthorityError {
    InvalidRequest,
    AuthorityConflict,
    Unavailable,
    RecoveryRequired,
}

impl fmt::Display for NodePairingActivationAuthorityError {
    // Presents fixed language safe for the local private API boundary.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest => formatter.write_str("pairing authority request is invalid"),
            Self::AuthorityConflict => formatter.write_str("pairing authority state conflicts"),
            Self::Unavailable => formatter.write_str("pairing authority is unavailable"),
            Self::RecoveryRequired => formatter.write_str("pairing authority requires recovery"),
        }
    }
}

impl Error for NodePairingActivationAuthorityError {}

// Defines the Node-owned atomic role and peer-credential authority consumed by local clients.
pub trait NodePairingActivationAuthorityPort: Send + Sync {
    // Atomically commits the verified main credential, main Node, and local child role.
    fn activate_paired_child(
        &self,
        request: &NodePairedChildActivationRequest,
    ) -> Result<NodePairingAuthorityReceipt, NodePairingActivationAuthorityError>;

    // Atomically deletes activation-owned trust and restores standalone local main authority.
    fn restore_paired_main(
        &self,
        request: &NodePairedMainRestorationRequest,
    ) -> Result<NodePairingAuthorityReceipt, NodePairingActivationAuthorityError>;
}

// Owns one shared database authority for paired role and credential transitions inside Node.
pub struct NodePairingActivationAuthority {
    nodes: Arc<NodeManager>,
    peer_credentials: DatabasePeerCredentialStore,
    clock: Arc<dyn PairingClock>,
    readiness: Arc<dyn LocalNodeRoleReadinessProvider>,
}

impl NodePairingActivationAuthority {
    // Creates one authority only when NodeManager and credential persistence share a database.
    pub fn new(
        nodes: Arc<NodeManager>,
        database: Arc<DatabaseManager>,
        clock: Arc<dyn PairingClock>,
        readiness: Arc<dyn LocalNodeRoleReadinessProvider>,
    ) -> Result<Self, NodePairingActivationAuthorityError> {
        if !nodes.uses_database(&database) {
            return Err(NodePairingActivationAuthorityError::InvalidRequest);
        }
        Ok(Self {
            nodes,
            peer_credentials: DatabasePeerCredentialStore::new(database),
            clock,
            readiness,
        })
    }

    // Returns the exact expected non-secret credential for one local/main authority pair.
    fn credential(
        &self,
        local: &Node,
        main: &Node,
        main_certificate_sha256: &Sha256Digest,
        credentials: &NodePairingCredentials,
    ) -> Result<PeerCredential, NodePairingActivationAuthorityError> {
        PeerCredential::new_with_state(
            CredentialId::parse(&main_certificate_sha256.as_str()[..32])
                .map_err(|_| NodePairingActivationAuthorityError::InvalidRequest)?,
            main_certificate_sha256.clone(),
            local.identity().node_id().clone(),
            main.identity().node_id().clone(),
            PeerCredentialDirection::MainToChild,
            PeerCredentialState::Active,
            credentials.valid_from(),
            credentials.expires_at(),
            None,
            None,
        )
        .map_err(|_| NodePairingActivationAuthorityError::InvalidRequest)
    }

    // Requires post-transaction credential and role state to match one paired child exactly.
    fn verify_child(
        &self,
        local: Node,
        main: &Node,
        credential: &PeerCredential,
    ) -> Result<Node, NodePairingActivationAuthorityError> {
        let observed = self
            .peer_credentials
            .exact_credential(credential.peer_leaf_sha256())
            .map_err(|_| NodePairingActivationAuthorityError::RecoveryRequired)?
            .ok_or(NodePairingActivationAuthorityError::RecoveryRequired)?;
        let authority = self
            .nodes
            .node(main.identity().node_id())
            .map_err(|_| NodePairingActivationAuthorityError::RecoveryRequired)?;
        if local.role() != NodeRole::Child
            || local.state() != NodeState::Active
            || observed.credential() != credential
            || authority.value() != main
        {
            return Err(NodePairingActivationAuthorityError::RecoveryRequired);
        }
        Ok(local)
    }

    // Requires restored main state and exact activation-owned authority absence.
    fn verify_main(
        &self,
        local: Node,
        main: &Node,
        main_certificate_sha256: &Sha256Digest,
    ) -> Result<Node, NodePairingActivationAuthorityError> {
        let credential_absent = self
            .peer_credentials
            .exact_credential(main_certificate_sha256)
            .map_err(|_| NodePairingActivationAuthorityError::RecoveryRequired)?
            .is_none();
        let authority_absent = matches!(
            self.nodes.node(main.identity().node_id()),
            Err(NodeManagerError::Database(DatabaseError::NotFound { .. }))
        );
        if local.role() != NodeRole::Main
            || local.state() != NodeState::Active
            || !credential_absent
            || !authority_absent
        {
            return Err(NodePairingActivationAuthorityError::RecoveryRequired);
        }
        Ok(local)
    }
}

impl NodePairingActivationAuthorityPort for NodePairingActivationAuthority {
    // Atomically commits one exact verified main credential and local child transition.
    fn activate_paired_child(
        &self,
        request: &NodePairedChildActivationRequest,
    ) -> Result<NodePairingAuthorityReceipt, NodePairingActivationAuthorityError> {
        let local = self
            .nodes
            .node(self.nodes.local_node_id())
            .map_err(authority_manager_error)?;
        let credential = self.credential(
            local.value(),
            request.main(),
            request.main_certificate_sha256(),
            request.credentials(),
        )?;
        let transaction = DatabaseTransaction::new(request.idempotency_key())
            .map_err(|_| NodePairingActivationAuthorityError::InvalidRequest)?;
        let transaction = match self
            .peer_credentials
            .exact_credential(credential.peer_leaf_sha256())
            .map_err(|_| NodePairingActivationAuthorityError::Unavailable)?
        {
            Some(existing) if existing.credential() == &credential => transaction,
            Some(_) => return Err(NodePairingActivationAuthorityError::AuthorityConflict),
            None => self
                .peer_credentials
                .creating_transaction(transaction, &credential)
                .map_err(|_| NodePairingActivationAuthorityError::Unavailable)?,
        };
        let change = self
            .nodes
            .activate_paired_child_with_transaction(
                request.idempotency_key(),
                local.revision(),
                request.main(),
                self.clock
                    .now()
                    .map_err(|_| NodePairingActivationAuthorityError::Unavailable)?,
                self.readiness.as_ref(),
                transaction,
            )
            .map_err(authority_manager_error)?;
        let disposition = if change.event().is_some() {
            NodePairingAuthorityDisposition::Applied
        } else {
            NodePairingAuthorityDisposition::Replayed
        };
        let verified = self.verify_child(change.value().clone(), request.main(), &credential)?;
        Ok(NodePairingAuthorityReceipt::new(verified, disposition))
    }

    // Atomically removes one paired authority and restores the exact local main role.
    fn restore_paired_main(
        &self,
        request: &NodePairedMainRestorationRequest,
    ) -> Result<NodePairingAuthorityReceipt, NodePairingActivationAuthorityError> {
        let local = self
            .nodes
            .node(self.nodes.local_node_id())
            .map_err(authority_manager_error)?;
        let expected = self.credential(
            local.value(),
            request.main(),
            request.main_certificate_sha256(),
            request.credentials(),
        )?;
        let stored = self
            .peer_credentials
            .exact_credential(request.main_certificate_sha256())
            .map_err(|_| NodePairingActivationAuthorityError::Unavailable)?;
        if local.value().role() == NodeRole::Main {
            let verified = self.verify_main(
                local.value().clone(),
                request.main(),
                request.main_certificate_sha256(),
            )?;
            return Ok(NodePairingAuthorityReceipt::new(
                verified,
                NodePairingAuthorityDisposition::Replayed,
            ));
        }
        let stored = stored.ok_or(NodePairingActivationAuthorityError::RecoveryRequired)?;
        if stored.credential() != &expected || stored.revision() == 0 {
            return Err(NodePairingActivationAuthorityError::AuthorityConflict);
        }
        let transaction = DatabaseTransaction::new(request.idempotency_key())
            .map_err(|_| NodePairingActivationAuthorityError::InvalidRequest)?;
        let transaction = self
            .peer_credentials
            .deleting_transaction(
                transaction,
                request.main_certificate_sha256(),
                stored.revision(),
            )
            .map_err(|_| NodePairingActivationAuthorityError::Unavailable)?;
        let change = self
            .nodes
            .restore_paired_main_with_transaction(
                request.idempotency_key(),
                local.revision(),
                request.main(),
                self.clock
                    .now()
                    .map_err(|_| NodePairingActivationAuthorityError::Unavailable)?,
                self.readiness.as_ref(),
                transaction,
            )
            .map_err(authority_manager_error)?;
        let disposition = if change.event().is_some() {
            NodePairingAuthorityDisposition::Applied
        } else {
            NodePairingAuthorityDisposition::Replayed
        };
        let verified = self.verify_main(
            change.value().clone(),
            request.main(),
            request.main_certificate_sha256(),
        )?;
        Ok(NodePairingAuthorityReceipt::new(verified, disposition))
    }
}

// Rejects malformed replay or authority identities before any state observation or mutation.
fn validate_request(
    idempotency_key: &str,
    main: &Node,
    main_certificate_sha256: &Sha256Digest,
) -> Result<(), NodePairingActivationAuthorityError> {
    if idempotency_key.is_empty()
        || idempotency_key.len() > MAXIMUM_IDEMPOTENCY_KEY_BYTES
        || main.role() != NodeRole::Main
        || main.state() != NodeState::Active
        || main_certificate_sha256.as_str().len() != 64
    {
        return Err(NodePairingActivationAuthorityError::InvalidRequest);
    }
    Ok(())
}

// Maps NodeManager failures into one closed local authority error surface.
fn authority_manager_error(error: NodeManagerError) -> NodePairingActivationAuthorityError {
    match error {
        NodeManagerError::Database(DatabaseError::Conflict { .. })
        | NodeManagerError::Database(DatabaseError::IdempotencyConflict { .. })
        | NodeManagerError::InvalidLocalRoleTransition { .. }
        | NodeManagerError::NodeIdentityConflict { .. } => {
            NodePairingActivationAuthorityError::AuthorityConflict
        }
        NodeManagerError::CorruptState { .. } => {
            NodePairingActivationAuthorityError::RecoveryRequired
        }
        _ => NodePairingActivationAuthorityError::Unavailable,
    }
}
