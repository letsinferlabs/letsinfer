// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::num::NonZeroU64;
use std::sync::Arc;

use li_core_interface::{InstallationId, NodeId, Sha256Digest};
use li_database::{
    DatabaseCollection, DatabaseCommand, DatabaseCommitDisposition, DatabaseError, DatabaseManager,
    DatabaseQuery, DatabaseRecord, DatabaseResult, DatabaseRevision,
};
use li_gateway_manager::GatewayProtectionAuthority;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const RECORD_PREFIX: &str = "li_node_protection_session_generation_";
pub const NODE_PROTECTION_SESSION_GENERATION_SCHEMA_NAME: &str =
    "li_node_protection_session_generation";
pub const NODE_PROTECTION_SESSION_GENERATION_SCHEMA_VERSION: u32 = 1;

// Names stable durable-generation failures without exposing session material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeProtectionSessionGenerationError {
    Conflict,
    Corrupt,
    StoreUnavailable,
}

impl fmt::Display for NodeProtectionSessionGenerationError {
    // Presents one fixed durable-session failure class.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conflict => formatter.write_str("protection session changed concurrently"),
            Self::Corrupt => formatter.write_str("protection session generation is corrupt"),
            Self::StoreUnavailable => {
                formatter.write_str("protection session generation store is unavailable")
            }
        }
    }
}

impl Error for NodeProtectionSessionGenerationError {}

// Stores the required nested schema identity for one private database record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct NodeProtectionSessionGenerationSchema {
    name: String,
    version: u32,
}

// Stores one restart-safe high-water mark through a closed private shape.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct NodeProtectionSessionGenerationRecord {
    record_id: String,
    schema: NodeProtectionSessionGenerationSchema,
    node_id: String,
    core_installation_id: String,
    watchdog_source_identity: String,
    begin_idempotency_key: String,
    watchdog_session_nonce: String,
    watchdog_session_id: String,
    session_generation: u64,
    state: String,
}

impl DatabaseRecord for NodeProtectionSessionGenerationRecord {
    const COLLECTION: DatabaseCollection = DatabaseCollection::Configuration;

    // Returns the Node-scoped durable record identity.
    fn identifier(&self) -> &str {
        &self.record_id
    }
}

// Owns durable optimistic allocation of one monotonic Watchdog generation per Node.
pub struct DatabaseNodeProtectionSessionGenerationStore {
    database: Arc<DatabaseManager>,
}

impl DatabaseNodeProtectionSessionGenerationStore {
    // Creates one adapter over the Node-owned shared DatabaseManager.
    pub const fn new(database: Arc<DatabaseManager>) -> Self {
        Self { database }
    }

    // Returns whether composition supplied this exact shared DatabaseManager authority.
    pub fn uses_database(&self, database: &Arc<DatabaseManager>) -> bool {
        Arc::ptr_eq(&self.database, database)
    }

    // Allocates exactly one new generation or replays the same authenticated session begin.
    pub fn allocate(
        &self,
        idempotency_key: &str,
        node_id: &NodeId,
        core_installation_id: &InstallationId,
        watchdog_source_identity: &Sha256Digest,
        watchdog_session_nonce: &Sha256Digest,
    ) -> Result<GatewayProtectionAuthority, NodeProtectionSessionGenerationError> {
        let current = self.read(node_id)?;
        if let Some((record, _)) = &current {
            let authority = authority_from_record(record, node_id)?;
            if record.state == "active"
                && authority.core_installation_id() == core_installation_id
                && authority.watchdog_source_identity() == watchdog_source_identity
                && record.begin_idempotency_key == idempotency_key
                && record.watchdog_session_nonce == watchdog_session_nonce.as_str()
            {
                return Ok(authority);
            }
            if record.state == "active"
                || record.watchdog_session_nonce == watchdog_session_nonce.as_str()
            {
                return Err(NodeProtectionSessionGenerationError::Conflict);
            }
        }
        let generation = current
            .as_ref()
            .map(|(record, _)| record.session_generation)
            .unwrap_or(0)
            .checked_add(1)
            .and_then(NonZeroU64::new)
            .ok_or(NodeProtectionSessionGenerationError::Corrupt)?;
        let session_id = derived_session_id(
            node_id,
            core_installation_id,
            watchdog_source_identity,
            watchdog_session_nonce,
            generation,
        )?;
        let record = generation_record(
            node_id,
            core_installation_id,
            watchdog_source_identity,
            idempotency_key,
            watchdog_session_nonce,
            &session_id,
            generation,
        );
        let expected_revision = current
            .as_ref()
            .map(|(_, revision)| DatabaseRevision::Exact(*revision))
            .unwrap_or(DatabaseRevision::Missing);
        let result = self
            .database
            .write(DatabaseCommand::save(
                idempotency_key,
                record,
                expected_revision,
            ))
            .map_err(database_error)?;
        let expected_commit_revision = current
            .as_ref()
            .map(|(_, revision)| revision.saturating_add(1))
            .unwrap_or(1);
        if !matches!(
            result.disposition(),
            DatabaseCommitDisposition::Applied | DatabaseCommitDisposition::Replayed
        ) || result.commit().collection != DatabaseCollection::Configuration
            || result.commit().identifier != record_id(node_id)
            || result.commit().revision != expected_commit_revision
        {
            return Err(NodeProtectionSessionGenerationError::Corrupt);
        }
        Ok(GatewayProtectionAuthority::new(
            node_id.clone(),
            core_installation_id.clone(),
            watchdog_source_identity.clone(),
            session_id,
            generation,
        ))
    }

    // Retires one exact disconnected session so its begin document can never reopen it.
    pub fn retire(
        &self,
        idempotency_key: &str,
        authority: &GatewayProtectionAuthority,
    ) -> Result<(), NodeProtectionSessionGenerationError> {
        let Some((mut record, revision)) = self.read(authority.node_id())? else {
            return Err(NodeProtectionSessionGenerationError::Conflict);
        };
        if authority_from_record(&record, authority.node_id())? != *authority {
            return Err(NodeProtectionSessionGenerationError::Conflict);
        }
        if record.state == "ended" {
            return Ok(());
        }
        record.state = "ended".to_string();
        self.write_record(idempotency_key, record, revision)
    }

    // Retires a stale active record before a restarted Node accepts any protection connection.
    pub fn recover(&self, node_id: &NodeId) -> Result<(), NodeProtectionSessionGenerationError> {
        let Some((mut record, revision)) = self.read(node_id)? else {
            return Ok(());
        };
        if record.state == "ended" {
            return Ok(());
        }
        record.state = "ended".to_string();
        self.write_record(
            &format!(
                "li_node_protection_recover_{}_{}",
                node_id.as_str(),
                revision
            ),
            record,
            revision,
        )
    }

    // Reads and validates one durable high-water mark with its optimistic revision.
    fn read(
        &self,
        node_id: &NodeId,
    ) -> Result<
        Option<(NodeProtectionSessionGenerationRecord, u64)>,
        NodeProtectionSessionGenerationError,
    > {
        match self
            .database
            .read(DatabaseQuery::record(record_id(node_id)))
        {
            Ok(DatabaseResult::Record(stored)) => {
                authority_from_record(&stored.value, node_id)?;
                Ok(Some((stored.value, stored.revision)))
            }
            Ok(DatabaseResult::Records(_)) => Err(NodeProtectionSessionGenerationError::Corrupt),
            Err(DatabaseError::NotFound { .. }) => Ok(None),
            Err(error) => Err(database_error(error)),
        }
    }

    // Writes one exact record replacement and validates its optimistic commit identity.
    fn write_record(
        &self,
        idempotency_key: &str,
        record: NodeProtectionSessionGenerationRecord,
        revision: u64,
    ) -> Result<(), NodeProtectionSessionGenerationError> {
        let identifier = record.record_id.clone();
        let result = self
            .database
            .write(DatabaseCommand::save(
                idempotency_key,
                record,
                DatabaseRevision::Exact(revision),
            ))
            .map_err(database_error)?;
        if !matches!(
            result.disposition(),
            DatabaseCommitDisposition::Applied | DatabaseCommitDisposition::Replayed
        ) || result.commit().collection != DatabaseCollection::Configuration
            || result.commit().identifier != identifier
            || result.commit().revision != revision.saturating_add(1)
        {
            return Err(NodeProtectionSessionGenerationError::Corrupt);
        }
        Ok(())
    }
}

// Creates one closed record from validated identities.
fn generation_record(
    node_id: &NodeId,
    core_installation_id: &InstallationId,
    watchdog_source_identity: &Sha256Digest,
    begin_idempotency_key: &str,
    watchdog_session_nonce: &Sha256Digest,
    watchdog_session_id: &Sha256Digest,
    session_generation: NonZeroU64,
) -> NodeProtectionSessionGenerationRecord {
    NodeProtectionSessionGenerationRecord {
        record_id: record_id(node_id),
        schema: NodeProtectionSessionGenerationSchema {
            name: NODE_PROTECTION_SESSION_GENERATION_SCHEMA_NAME.to_string(),
            version: NODE_PROTECTION_SESSION_GENERATION_SCHEMA_VERSION,
        },
        node_id: node_id.as_str().to_string(),
        core_installation_id: core_installation_id.as_str().to_string(),
        watchdog_source_identity: watchdog_source_identity.as_str().to_string(),
        begin_idempotency_key: begin_idempotency_key.to_string(),
        watchdog_session_nonce: watchdog_session_nonce.as_str().to_string(),
        watchdog_session_id: watchdog_session_id.as_str().to_string(),
        session_generation: session_generation.get(),
        state: "active".to_string(),
    }
}

// Reconstructs one authority only when every persisted identity is canonical and self-consistent.
fn authority_from_record(
    record: &NodeProtectionSessionGenerationRecord,
    expected_node_id: &NodeId,
) -> Result<GatewayProtectionAuthority, NodeProtectionSessionGenerationError> {
    if record.record_id != record_id(expected_node_id)
        || record.schema.name != NODE_PROTECTION_SESSION_GENERATION_SCHEMA_NAME
        || record.schema.version != NODE_PROTECTION_SESSION_GENERATION_SCHEMA_VERSION
        || record.node_id != expected_node_id.as_str()
        || !valid_idempotency_key(&record.begin_idempotency_key)
        || !matches!(record.state.as_str(), "active" | "ended")
    {
        return Err(NodeProtectionSessionGenerationError::Corrupt);
    }
    let core_installation_id = InstallationId::parse(&record.core_installation_id)
        .map_err(|_| NodeProtectionSessionGenerationError::Corrupt)?;
    let watchdog_source_identity = Sha256Digest::parse(&record.watchdog_source_identity)
        .map_err(|_| NodeProtectionSessionGenerationError::Corrupt)?;
    let watchdog_session_nonce = Sha256Digest::parse(&record.watchdog_session_nonce)
        .map_err(|_| NodeProtectionSessionGenerationError::Corrupt)?;
    let watchdog_session_id = Sha256Digest::parse(&record.watchdog_session_id)
        .map_err(|_| NodeProtectionSessionGenerationError::Corrupt)?;
    let session_generation = NonZeroU64::new(record.session_generation)
        .ok_or(NodeProtectionSessionGenerationError::Corrupt)?;
    if derived_session_id(
        expected_node_id,
        &core_installation_id,
        &watchdog_source_identity,
        &watchdog_session_nonce,
        session_generation,
    )? != watchdog_session_id
    {
        return Err(NodeProtectionSessionGenerationError::Corrupt);
    }
    Ok(GatewayProtectionAuthority::new(
        expected_node_id.clone(),
        core_installation_id,
        watchdog_source_identity,
        watchdog_session_id,
        session_generation,
    ))
}

// Rejects empty, oversized, or control-bearing durable replay identities.
fn valid_idempotency_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && !value.chars().any(|character| character.is_control())
}

// Derives a generation-bound session identity so a retired nonce cannot replay as A to B to A.
fn derived_session_id(
    node_id: &NodeId,
    core_installation_id: &InstallationId,
    watchdog_source_identity: &Sha256Digest,
    watchdog_session_nonce: &Sha256Digest,
    session_generation: NonZeroU64,
) -> Result<Sha256Digest, NodeProtectionSessionGenerationError> {
    let mut digest = Sha256::new();
    update_digest_field(&mut digest, b"li_node_protection_session_v1");
    update_digest_field(&mut digest, node_id.as_str().as_bytes());
    update_digest_field(&mut digest, core_installation_id.as_str().as_bytes());
    update_digest_field(&mut digest, watchdog_source_identity.as_str().as_bytes());
    update_digest_field(&mut digest, watchdog_session_nonce.as_str().as_bytes());
    update_digest_field(&mut digest, &session_generation.get().to_be_bytes());
    Sha256Digest::parse(&format!("{:x}", digest.finalize()))
        .map_err(|_| NodeProtectionSessionGenerationError::Corrupt)
}

// Commits one length-prefixed field to the session-identity derivation.
fn update_digest_field(digest: &mut Sha256, field: &[u8]) {
    digest.update((field.len() as u64).to_be_bytes());
    digest.update(field);
}

// Returns one Node-scoped private record identity.
fn record_id(node_id: &NodeId) -> String {
    format!("{RECORD_PREFIX}{}", node_id.as_str())
}

// Maps optimistic conflicts distinctly while redacting every database detail.
fn database_error(error: DatabaseError) -> NodeProtectionSessionGenerationError {
    match error {
        DatabaseError::Conflict { .. } | DatabaseError::IdempotencyConflict { .. } => {
            NodeProtectionSessionGenerationError::Conflict
        }
        DatabaseError::Corrupt { .. } => NodeProtectionSessionGenerationError::Corrupt,
        _ => NodeProtectionSessionGenerationError::StoreUnavailable,
    }
}
