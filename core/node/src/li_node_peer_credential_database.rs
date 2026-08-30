// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use crate::{NodePrivatePrincipalResolver, NodePrivateRemotePrincipal, NodePrivateRemoteTlsError};
use li_authentication_manager::{
    AuthenticationManager, AuthenticationStoreError, ControllerRole, PeerCredential,
    PeerCredentialDirection, PeerCredentialError, PeerCredentialState, PeerCredentialStore,
    VersionedPeerCredential, MAX_PEER_CREDENTIAL_LOOKUP_RESULTS,
};
use li_core_interface::{CredentialId, NodeId, Sha256Digest, UnixMilliseconds};
use li_database::{
    DatabaseCollection, DatabaseCommand, DatabaseCommitDisposition, DatabaseError, DatabaseManager,
    DatabaseQuery, DatabaseRecord, DatabaseResult, DatabaseRevision, DatabaseTransaction,
};
use serde::{Deserialize, Serialize};

const MAXIMUM_PERSISTED_PEER_CREDENTIALS: usize = 4096;

// Stores one exact leaf bucket in the dedicated peer-credential collection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PeerCredentialDatabaseBucket {
    peer_leaf_sha256: String,
    credentials: Vec<PeerCredentialDatabaseRecord>,
}

impl DatabaseRecord for PeerCredentialDatabaseBucket {
    const COLLECTION: DatabaseCollection = DatabaseCollection::PeerCredentials;

    // Returns the exact leaf digest used as the indexed database identity.
    fn identifier(&self) -> &str {
        &self.peer_leaf_sha256
    }
}

// Stores one closed non-secret peer-credential lifecycle inside its leaf bucket.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PeerCredentialDatabaseRecord {
    credential_id: String,
    local_node_id: String,
    peer_node_id: String,
    direction: String,
    state: String,
    issued_at_unix_milliseconds: u64,
    expires_at_unix_milliseconds: u64,
    revoked_at_unix_milliseconds: Option<u64>,
    rotated_to: Option<String>,
}

// Returns one applied or replayed exact peer-credential persistence result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DatabasePeerCredentialChange {
    credential: VersionedPeerCredential,
    disposition: DatabaseCommitDisposition,
}

impl DatabasePeerCredentialChange {
    // Creates one result only after database state matches the requested credential exactly.
    const fn new(
        credential: VersionedPeerCredential,
        disposition: DatabaseCommitDisposition,
    ) -> Self {
        Self {
            credential,
            disposition,
        }
    }

    // Returns the exact persisted credential and current revision.
    pub const fn credential(&self) -> &VersionedPeerCredential {
        &self.credential
    }

    // Returns whether this call applied or replayed the exact mutation.
    pub const fn disposition(&self) -> DatabaseCommitDisposition {
        self.disposition
    }
}

// Adapts AuthenticationManager's peer store to the one shared DatabaseManager authority.
pub struct DatabasePeerCredentialStore {
    database: Arc<DatabaseManager>,
}

impl DatabasePeerCredentialStore {
    // Creates one adapter without opening another database or owning its lifecycle.
    pub const fn new(database: Arc<DatabaseManager>) -> Self {
        Self { database }
    }

    // Appends one absent exact credential to a caller-owned atomic transaction.
    pub fn creating_transaction(
        &self,
        transaction: DatabaseTransaction,
        credential: &PeerCredential,
    ) -> Result<DatabaseTransaction, AuthenticationStoreError> {
        transaction
            .save(database_bucket(credential), DatabaseRevision::Missing)
            .map_err(authentication_store_error)
    }

    // Appends one exact optimistic credential replacement to an atomic transaction.
    pub fn replacing_transaction(
        &self,
        transaction: DatabaseTransaction,
        credential: &PeerCredential,
        expected_revision: u64,
    ) -> Result<DatabaseTransaction, AuthenticationStoreError> {
        if expected_revision == 0 {
            return Err(AuthenticationStoreError::Corrupt);
        }
        transaction
            .save(
                database_bucket(credential),
                DatabaseRevision::Exact(expected_revision),
            )
            .map_err(authentication_store_error)
    }

    // Appends one exact optimistic credential deletion to an atomic authority transaction.
    pub fn deleting_transaction(
        &self,
        transaction: DatabaseTransaction,
        peer_leaf_sha256: &Sha256Digest,
        expected_revision: u64,
    ) -> Result<DatabaseTransaction, AuthenticationStoreError> {
        if expected_revision == 0 {
            return Err(AuthenticationStoreError::Corrupt);
        }
        transaction
            .delete::<PeerCredentialDatabaseBucket>(
                peer_leaf_sha256.as_str(),
                DatabaseRevision::Exact(expected_revision),
            )
            .map_err(authentication_store_error)
    }

    // Returns the one exact digest record required by approval composition.
    pub fn exact_credential(
        &self,
        peer_leaf_sha256: &Sha256Digest,
    ) -> Result<Option<VersionedPeerCredential>, AuthenticationStoreError> {
        let records = self.read_bucket(peer_leaf_sha256)?;
        if records.len() > 1 {
            return Err(AuthenticationStoreError::Corrupt);
        }
        Ok(records.into_iter().next())
    }

    // Creates one exact leaf credential only when its dedicated bucket is absent.
    pub fn create(
        &self,
        credential: PeerCredential,
        idempotency_key: impl Into<String>,
    ) -> Result<DatabasePeerCredentialChange, AuthenticationStoreError> {
        self.save(credential, idempotency_key, DatabaseRevision::Missing)
    }

    // Replaces one exact leaf credential only at the expected persisted revision.
    pub fn replace(
        &self,
        credential: PeerCredential,
        expected_revision: u64,
        idempotency_key: impl Into<String>,
    ) -> Result<DatabasePeerCredentialChange, AuthenticationStoreError> {
        if expected_revision == 0 {
            return Err(AuthenticationStoreError::Corrupt);
        }
        self.save(
            credential,
            idempotency_key,
            DatabaseRevision::Exact(expected_revision),
        )
    }

    // Commits one closed leaf bucket and verifies the current state before returning it.
    fn save(
        &self,
        credential: PeerCredential,
        idempotency_key: impl Into<String>,
        expected_revision: DatabaseRevision,
    ) -> Result<DatabasePeerCredentialChange, AuthenticationStoreError> {
        let peer_leaf_sha256 = credential.peer_leaf_sha256().clone();
        let bucket = database_bucket(&credential);
        let result = self
            .database
            .write(DatabaseCommand::save(
                idempotency_key,
                bucket,
                expected_revision,
            ))
            .map_err(authentication_store_error)?;
        let current = self.read_bucket(&peer_leaf_sha256)?;
        if current.len() != 1
            || current[0].credential() != &credential
            || current[0].revision() != result.commit().revision
        {
            return Err(AuthenticationStoreError::Conflict);
        }
        Ok(DatabasePeerCredentialChange::new(
            current[0].clone(),
            result.disposition(),
        ))
    }

    // Reads and reconstructs one exact digest bucket without scanning the collection.
    fn read_bucket(
        &self,
        peer_leaf_sha256: &Sha256Digest,
    ) -> Result<Vec<VersionedPeerCredential>, AuthenticationStoreError> {
        match self
            .database
            .read(DatabaseQuery::record(peer_leaf_sha256.as_str()))
        {
            Ok(DatabaseResult::Record(stored)) => {
                peer_credentials(stored.value, stored.revision, peer_leaf_sha256)
            }
            Ok(DatabaseResult::Records(_)) => Err(AuthenticationStoreError::Corrupt),
            Err(DatabaseError::NotFound { .. }) => Ok(Vec::new()),
            Err(error) => Err(authentication_store_error(error)),
        }
    }
}

impl PeerCredentialStore for DatabasePeerCredentialStore {
    // Returns zero, one, or the duplicate sentinel from one exact bounded digest bucket.
    fn matching_peer_credentials(
        &self,
        peer_leaf_sha256: &Sha256Digest,
        maximum_results: usize,
    ) -> Result<Vec<VersionedPeerCredential>, AuthenticationStoreError> {
        if maximum_results == 0 || maximum_results > MAX_PEER_CREDENTIAL_LOOKUP_RESULTS {
            return Err(AuthenticationStoreError::Corrupt);
        }
        let credentials = self.read_bucket(peer_leaf_sha256)?;
        if credentials.len() > maximum_results {
            return Err(AuthenticationStoreError::Corrupt);
        }
        Ok(credentials)
    }

    // Finds one exact credential identity while rejecting duplicate or oversized persisted state.
    fn matching_peer_credential_ids(
        &self,
        credential_id: &CredentialId,
        maximum_results: usize,
    ) -> Result<Vec<VersionedPeerCredential>, AuthenticationStoreError> {
        if maximum_results == 0 || maximum_results > MAX_PEER_CREDENTIAL_LOOKUP_RESULTS {
            return Err(AuthenticationStoreError::Corrupt);
        }
        let result = self
            .database
            .read(DatabaseQuery::<PeerCredentialDatabaseBucket>::all())
            .map_err(authentication_store_error)?;
        let DatabaseResult::Records(records) = result else {
            return Err(AuthenticationStoreError::Corrupt);
        };
        if records.len() > MAXIMUM_PERSISTED_PEER_CREDENTIALS {
            return Err(AuthenticationStoreError::Corrupt);
        }
        let mut matches = Vec::new();
        for stored in records {
            let expected = Sha256Digest::parse(&stored.value.peer_leaf_sha256)
                .map_err(|_| AuthenticationStoreError::Corrupt)?;
            for versioned in peer_credentials(stored.value, stored.revision, &expected)? {
                if versioned.credential().credential_id() == credential_id {
                    matches.push(versioned);
                    if matches.len() > maximum_results {
                        return Err(AuthenticationStoreError::Corrupt);
                    }
                }
            }
        }
        Ok(matches)
    }
}

// Bridges AuthenticationManager's exact decision to Node's transport-local resolver contract.
pub struct CoreNodePrincipalResolver {
    authentication: Arc<AuthenticationManager>,
    local_node_id: NodeId,
    direction: PeerCredentialDirection,
}

impl CoreNodePrincipalResolver {
    // Creates one narrow bridge without granting Node access to authentication persistence.
    pub const fn new(authentication: Arc<AuthenticationManager>, local_node_id: NodeId) -> Self {
        Self::new_for_direction(
            authentication,
            local_node_id,
            PeerCredentialDirection::ChildToMain,
        )
    }

    // Creates one bridge for the exact peer-certificate direction accepted by the local role.
    pub const fn new_for_direction(
        authentication: Arc<AuthenticationManager>,
        local_node_id: NodeId,
        direction: PeerCredentialDirection,
    ) -> Self {
        Self {
            authentication,
            local_node_id,
            direction,
        }
    }
}

impl NodePrivatePrincipalResolver for CoreNodePrincipalResolver {
    // Resolves a paired peer first, then only an exact active controller leaf when no peer exists.
    fn principal_for_certificate(
        &self,
        peer_leaf_sha256: &Sha256Digest,
    ) -> Result<NodePrivateRemotePrincipal, NodePrivateRemoteTlsError> {
        match self
            .authentication
            .resolve_peer_credential(peer_leaf_sha256)
        {
            Ok(principal)
                if principal.local_node_id() == &self.local_node_id
                    && principal.direction() == self.direction =>
            {
                return Ok(NodePrivateRemotePrincipal::Peer(
                    principal.credential_id().clone(),
                ));
            }
            Ok(_) => return Err(NodePrivateRemoteTlsError::PrincipalRejected),
            Err(PeerCredentialError::Unrecognized) => {}
            Err(_) => return Err(NodePrivateRemoteTlsError::PrincipalRejected),
        }
        let matches = self
            .authentication
            .controllers()
            .map_err(|_| NodePrivateRemoteTlsError::PrincipalRejected)?
            .into_iter()
            .filter(|controller| controller.certificate().certificate_sha256() == peer_leaf_sha256)
            .collect::<Vec<_>>();
        let [controller] = matches.as_slice() else {
            return Err(NodePrivateRemoteTlsError::PrincipalRejected);
        };
        self.authentication
            .authorize_controller(
                controller.controller_id(),
                peer_leaf_sha256,
                ControllerRole::Viewer,
            )
            .map_err(|_| NodePrivateRemoteTlsError::PrincipalRejected)?;
        Ok(NodePrivateRemotePrincipal::Controller {
            controller_id: controller.controller_id().clone(),
            certificate_sha256: peer_leaf_sha256.clone(),
        })
    }
}

// Projects one validated peer credential into the closed persistence schema.
fn database_bucket(credential: &PeerCredential) -> PeerCredentialDatabaseBucket {
    PeerCredentialDatabaseBucket {
        peer_leaf_sha256: credential.peer_leaf_sha256().as_str().to_string(),
        credentials: vec![PeerCredentialDatabaseRecord {
            credential_id: credential.credential_id().as_str().to_string(),
            local_node_id: credential.local_node_id().as_str().to_string(),
            peer_node_id: credential.peer_node_id().as_str().to_string(),
            direction: peer_credential_direction_name(credential.direction()).to_string(),
            state: peer_credential_state_name(credential.state()).to_string(),
            issued_at_unix_milliseconds: credential.issued_at().value(),
            expires_at_unix_milliseconds: credential.expires_at().value(),
            revoked_at_unix_milliseconds: credential.revoked_at().map(UnixMilliseconds::value),
            rotated_to: credential
                .rotated_to()
                .map(|identity| identity.as_str().to_string()),
        }],
    }
}

// Reconstructs one bounded closed bucket and rejects mismatched or incoherent persistence.
fn peer_credentials(
    bucket: PeerCredentialDatabaseBucket,
    revision: u64,
    expected_peer_leaf_sha256: &Sha256Digest,
) -> Result<Vec<VersionedPeerCredential>, AuthenticationStoreError> {
    let peer_leaf_sha256 = Sha256Digest::parse(&bucket.peer_leaf_sha256)
        .map_err(|_| AuthenticationStoreError::Corrupt)?;
    if revision == 0
        || &peer_leaf_sha256 != expected_peer_leaf_sha256
        || bucket.credentials.is_empty()
        || bucket.credentials.len() > MAX_PEER_CREDENTIAL_LOOKUP_RESULTS
    {
        return Err(AuthenticationStoreError::Corrupt);
    }
    bucket
        .credentials
        .into_iter()
        .map(|record| {
            let credential = PeerCredential::new_with_state(
                CredentialId::parse(&record.credential_id)
                    .map_err(|_| AuthenticationStoreError::Corrupt)?,
                peer_leaf_sha256.clone(),
                NodeId::parse(&record.local_node_id)
                    .map_err(|_| AuthenticationStoreError::Corrupt)?,
                NodeId::parse(&record.peer_node_id)
                    .map_err(|_| AuthenticationStoreError::Corrupt)?,
                peer_credential_direction(&record.direction)?,
                peer_credential_state(&record.state)?,
                UnixMilliseconds::new(record.issued_at_unix_milliseconds),
                UnixMilliseconds::new(record.expires_at_unix_milliseconds),
                record
                    .revoked_at_unix_milliseconds
                    .map(UnixMilliseconds::new),
                record
                    .rotated_to
                    .map(|identity| CredentialId::parse(&identity))
                    .transpose()
                    .map_err(|_| AuthenticationStoreError::Corrupt)?,
            )
            .map_err(|_| AuthenticationStoreError::Corrupt)?;
            Ok(VersionedPeerCredential::new(credential, revision))
        })
        .collect()
}

// Returns the closed persistence name for one peer-credential direction.
const fn peer_credential_direction_name(direction: PeerCredentialDirection) -> &'static str {
    match direction {
        PeerCredentialDirection::ChildToMain => "child_to_main",
        PeerCredentialDirection::MainToChild => "main_to_child",
    }
}

// Reconstructs only a direction implemented by the current pairing trust contract.
fn peer_credential_direction(
    value: &str,
) -> Result<PeerCredentialDirection, AuthenticationStoreError> {
    match value {
        "child_to_main" => Ok(PeerCredentialDirection::ChildToMain),
        "main_to_child" => Ok(PeerCredentialDirection::MainToChild),
        _ => Err(AuthenticationStoreError::Corrupt),
    }
}

// Returns the closed persistence name for one peer-credential approval state.
fn peer_credential_state_name(state: PeerCredentialState) -> &'static str {
    match state {
        PeerCredentialState::Pending => "pending",
        PeerCredentialState::Active => "active",
    }
}

// Reconstructs one closed peer-credential approval state without a default.
fn peer_credential_state(value: &str) -> Result<PeerCredentialState, AuthenticationStoreError> {
    match value {
        "pending" => Ok(PeerCredentialState::Pending),
        "active" => Ok(PeerCredentialState::Active),
        _ => Err(AuthenticationStoreError::Corrupt),
    }
}

// Converts database outcomes to AuthenticationManager's fixed redacted persistence surface.
fn authentication_store_error(error: DatabaseError) -> AuthenticationStoreError {
    match error {
        DatabaseError::Conflict { .. } | DatabaseError::IdempotencyConflict { .. } => {
            AuthenticationStoreError::Conflict
        }
        DatabaseError::Corrupt { .. } => AuthenticationStoreError::Corrupt,
        DatabaseError::NotFound { .. }
        | DatabaseError::InvalidInput { .. }
        | DatabaseError::Unavailable { .. }
        | DatabaseError::Closed => AuthenticationStoreError::Unavailable,
    }
}
