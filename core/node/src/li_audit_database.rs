// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use li_audit_manager::{
    AuditAction, AuditActor, AuditActorId, AuditActorType, AuditAppendDisposition,
    AuditAppendReceipt, AuditCheckpoint, AuditCorrelationId, AuditEvent, AuditEventId, AuditLedger,
    AuditLedgerEntry, AuditOrigin, AuditOriginInterface, AuditOutcome, AuditReason, AuditReplayId,
    AuditReplayReceipt, AuditStore, AuditStoreError, AuditTarget, AuditUnixNanoseconds,
};
use li_core_interface::{NodeId, Sha256Digest};
use li_database::{
    DatabaseCollection, DatabaseCommitDisposition, DatabaseError, DatabaseManager, DatabaseQuery,
    DatabaseRecord, DatabaseResult, DatabaseRevision, DatabaseStoredRecord, DatabaseTransaction,
};
use serde::{Deserialize, Serialize};

const AUDIT_STATE_RECORD_ID: &str = "chain";

// Stores the optimistic head required to serialize the complete chain.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct AuditStateDatabaseRecord {
    record_id: String,
    revision: u64,
    head_sha256: String,
}

impl DatabaseRecord for AuditStateDatabaseRecord {
    const COLLECTION: DatabaseCollection = DatabaseCollection::AuditState;

    // Returns the singleton chain-head identity.
    fn identifier(&self) -> &str {
        &self.record_id
    }
}

// Stores one append-only event independently of its lexical event identity order.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct AuditEventDatabaseRecord {
    event_id: String,
    sequence: u64,
    correlation_id: String,
    timestamp_unix_ns: u64,
    node_id: String,
    actor_type: String,
    actor_id: String,
    origin_node_id: String,
    origin_interface: String,
    action: String,
    target: String,
    before_sha256: Option<String>,
    after_sha256: Option<String>,
    outcome: String,
    reason: Option<String>,
    previous_hash: String,
    event_hash: String,
}

impl DatabaseRecord for AuditEventDatabaseRecord {
    const COLLECTION: DatabaseCollection = DatabaseCollection::AuditEvents;

    // Returns the stable event identity rather than its mutable storage position.
    fn identifier(&self) -> &str {
        &self.event_id
    }
}

// Stores one optional checkpoint under its sortable event sequence.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct AuditCheckpointDatabaseRecord {
    record_id: String,
    sequence: u64,
    event_hash: String,
    signature: Vec<u8>,
    created_at_unix_ns: u64,
}

impl DatabaseRecord for AuditCheckpointDatabaseRecord {
    const COLLECTION: DatabaseCollection = DatabaseCollection::AuditCheckpoints;

    // Returns the zero-padded chronological checkpoint identity.
    fn identifier(&self) -> &str {
        &self.record_id
    }
}

// Binds one caller replay identity to its first committed semantic request.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct AuditReplayDatabaseRecord {
    replay_id: String,
    request_sha256: String,
    event_id: String,
    sequence: u64,
}

impl DatabaseRecord for AuditReplayDatabaseRecord {
    const COLLECTION: DatabaseCollection = DatabaseCollection::AuditReplays;

    // Returns the caller-owned replay identity.
    fn identifier(&self) -> &str {
        &self.replay_id
    }
}

// Adapts DatabaseManager's atomic records to AuditManager's append-only store.
pub struct DatabaseAuditStore {
    database: Arc<DatabaseManager>,
}

impl DatabaseAuditStore {
    // Creates one ordinary native audit store with an independent genesis.
    pub const fn new(database: Arc<DatabaseManager>) -> Self {
        Self { database }
    }

    // Reconstructs one entry for a persisted replay or event lookup.
    fn entry(
        &self,
        event_id: &AuditEventId,
    ) -> Result<Option<(AuditLedgerEntry, u64)>, AuditStoreError> {
        let ledger = self.ledger()?;
        let revision = ledger.revision();
        Ok(ledger
            .entries()
            .iter()
            .find(|entry| entry.event().event_id() == event_id)
            .cloned()
            .map(|entry| (entry, revision)))
    }

    // Builds the one atomic database transaction for an event, checkpoint, replay, and head.
    fn append_transaction(
        &self,
        expected_revision: u64,
        replay_id: &AuditReplayId,
        request_sha256: &Sha256Digest,
        entry: &AuditLedgerEntry,
    ) -> Result<DatabaseTransaction, AuditStoreError> {
        let event = entry.event();
        let state_revision = if expected_revision == 0 {
            DatabaseRevision::Missing
        } else {
            DatabaseRevision::Exact(expected_revision)
        };
        let transaction_id = database_replay_id(replay_id)?;
        let mut transaction = DatabaseTransaction::new(transaction_id)
            .map_err(database_store_error)?
            .save(
                AuditStateDatabaseRecord {
                    record_id: AUDIT_STATE_RECORD_ID.to_string(),
                    revision: event.sequence(),
                    head_sha256: event.event_hash().as_str().to_string(),
                },
                state_revision,
            )
            .map_err(database_store_error)?
            .save(event_record(event), DatabaseRevision::Missing)
            .map_err(database_store_error)?;
        if let Some(checkpoint) = entry.checkpoint() {
            transaction = transaction
                .save(checkpoint_record(checkpoint), DatabaseRevision::Missing)
                .map_err(database_store_error)?;
        }
        let transaction = transaction
            .save(
                AuditReplayDatabaseRecord {
                    replay_id: replay_id.as_str().to_string(),
                    request_sha256: request_sha256.as_str().to_string(),
                    event_id: event.event_id().as_str().to_string(),
                    sequence: event.sequence(),
                },
                DatabaseRevision::Missing,
            )
            .map_err(database_store_error)?;
        Ok(transaction)
    }

    // Resolves a concurrent database idempotency collision through the durable replay index.
    fn replay_after_collision(
        &self,
        replay_id: &AuditReplayId,
        request_sha256: &Sha256Digest,
    ) -> Result<AuditAppendReceipt, AuditStoreError> {
        let replay = self
            .replay(replay_id)?
            .ok_or(AuditStoreError::ReplayConflict)?;
        if replay.request_sha256() != request_sha256 {
            return Err(AuditStoreError::ReplayConflict);
        }
        Ok(AuditAppendReceipt::new(
            request_sha256.clone(),
            replay.entry().clone(),
            AuditAppendDisposition::Replayed,
            replay.revision(),
        ))
    }
}

impl AuditStore for DatabaseAuditStore {
    // Returns a semantically checked chronological ledger and rejects every orphaned record.
    fn ledger(&self) -> Result<AuditLedger, AuditStoreError> {
        let states = database_records::<AuditStateDatabaseRecord>(&self.database)?;
        let events = database_records::<AuditEventDatabaseRecord>(&self.database)?;
        let checkpoints = database_records::<AuditCheckpointDatabaseRecord>(&self.database)?;
        let replays = database_records::<AuditReplayDatabaseRecord>(&self.database)?;
        if states.is_empty() && events.is_empty() && checkpoints.is_empty() && replays.is_empty() {
            return AuditLedger::from_persisted(Vec::new(), 0);
        }
        if states.len() != 1 {
            return Err(AuditStoreError::Corrupt);
        }
        let state = &states[0];
        if state.value.record_id != AUDIT_STATE_RECORD_ID
            || state.value.revision != state.revision
            || usize::try_from(state.value.revision).ok() != Some(events.len())
        {
            return Err(AuditStoreError::Corrupt);
        }

        let mut checkpoint_by_sequence = BTreeMap::new();
        for checkpoint in checkpoints {
            if checkpoint.revision != 1
                || checkpoint.value.record_id != sequence_record_id(checkpoint.value.sequence)
                || checkpoint_by_sequence
                    .insert(
                        checkpoint.value.sequence,
                        checkpoint_from_record(checkpoint.value)?,
                    )
                    .is_some()
            {
                return Err(AuditStoreError::Corrupt);
            }
        }

        let mut ordered_events = Vec::with_capacity(events.len());
        for stored in events {
            if stored.revision != 1 || stored.value.event_id != stored.value.identifier() {
                return Err(AuditStoreError::Corrupt);
            }
            ordered_events.push(event_from_record(stored.value)?);
        }
        ordered_events.sort_by_key(AuditEvent::sequence);
        let mut entries = Vec::with_capacity(ordered_events.len());
        for (index, event) in ordered_events.into_iter().enumerate() {
            let expected_sequence = u64::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or(AuditStoreError::Corrupt)?;
            if event.sequence() != expected_sequence {
                return Err(AuditStoreError::Corrupt);
            }
            let checkpoint = checkpoint_by_sequence.remove(&event.sequence());
            entries.push(AuditLedgerEntry::new(event, checkpoint)?);
        }
        if !checkpoint_by_sequence.is_empty()
            || entries
                .last()
                .is_none_or(|entry| entry.event().event_hash().as_str() != state.value.head_sha256)
        {
            return Err(AuditStoreError::Corrupt);
        }
        validate_replays(&replays, &entries)?;
        AuditLedger::from_persisted(entries, state.value.revision)
    }

    // Returns one first-commit replay receipt without changing the chain.
    fn replay(
        &self,
        replay_id: &AuditReplayId,
    ) -> Result<Option<AuditReplayReceipt>, AuditStoreError> {
        let stored = match self
            .database
            .read(DatabaseQuery::<AuditReplayDatabaseRecord>::record(
                replay_id.as_str(),
            )) {
            Ok(DatabaseResult::Record(stored)) => stored,
            Ok(DatabaseResult::Records(_)) => return Err(AuditStoreError::Corrupt),
            Err(DatabaseError::NotFound { .. }) => return Ok(None),
            Err(error) => return Err(database_store_error(error)),
        };
        if stored.revision != 1 || stored.value.replay_id != replay_id.as_str() {
            return Err(AuditStoreError::Corrupt);
        }
        let request_sha256 = digest(&stored.value.request_sha256)?;
        let event_id =
            AuditEventId::parse(&stored.value.event_id).map_err(|_| AuditStoreError::Corrupt)?;
        let (entry, revision) = self.entry(&event_id)?.ok_or(AuditStoreError::Corrupt)?;
        if entry.event().sequence() != stored.value.sequence {
            return Err(AuditStoreError::Corrupt);
        }
        Ok(Some(AuditReplayReceipt::new(
            request_sha256,
            entry,
            revision,
        )))
    }

    // Returns one semantically checked event by stable identity.
    fn event(&self, event_id: &AuditEventId) -> Result<Option<AuditEvent>, AuditStoreError> {
        Ok(self
            .entry(event_id)?
            .map(|(entry, _)| entry.event().clone()))
    }

    // Atomically appends the event, optional checkpoint, replay index, and optimistic head.
    fn append(
        &self,
        expected_revision: u64,
        replay_id: &AuditReplayId,
        request_sha256: &Sha256Digest,
        entry: AuditLedgerEntry,
    ) -> Result<AuditAppendReceipt, AuditStoreError> {
        if let Some(replay) = self.replay(replay_id)? {
            if replay.request_sha256() != request_sha256 {
                return Err(AuditStoreError::ReplayConflict);
            }
            return Ok(AuditAppendReceipt::new(
                request_sha256.clone(),
                replay.entry().clone(),
                AuditAppendDisposition::Replayed,
                replay.revision(),
            ));
        }
        if entry.event().sequence() != expected_revision.saturating_add(1) {
            return Err(AuditStoreError::Corrupt);
        }
        let transaction =
            self.append_transaction(expected_revision, replay_id, request_sha256, &entry)?;
        let result = match self.database.write_transaction(transaction) {
            Ok(result) => result,
            Err(DatabaseError::IdempotencyConflict { .. }) => {
                return self.replay_after_collision(replay_id, request_sha256)
            }
            Err(error) => return Err(database_store_error(error)),
        };
        let disposition = match result.disposition() {
            DatabaseCommitDisposition::Applied => AuditAppendDisposition::Applied,
            DatabaseCommitDisposition::Replayed => AuditAppendDisposition::Replayed,
        };
        Ok(AuditAppendReceipt::new(
            request_sha256.clone(),
            entry,
            disposition,
            expected_revision + 1,
        ))
    }
}

// Reads one complete typed collection without accepting a single-record response.
fn database_records<Record: DatabaseRecord>(
    database: &DatabaseManager,
) -> Result<Vec<DatabaseStoredRecord<Record>>, AuditStoreError> {
    match database.read(DatabaseQuery::<Record>::all()) {
        Ok(DatabaseResult::Records(records)) => Ok(records),
        Ok(DatabaseResult::Record(_)) => Err(AuditStoreError::Corrupt),
        Err(error) => Err(database_store_error(error)),
    }
}

// Projects one event into its private persistence record.
fn event_record(event: &AuditEvent) -> AuditEventDatabaseRecord {
    AuditEventDatabaseRecord {
        event_id: event.event_id().as_str().to_string(),
        sequence: event.sequence(),
        correlation_id: event.correlation_id().as_str().to_string(),
        timestamp_unix_ns: event.timestamp().value(),
        node_id: event.node_id().as_str().to_string(),
        actor_type: event.actor().kind().as_str().to_string(),
        actor_id: event.actor().identifier().as_str().to_string(),
        origin_node_id: event.origin().node_id().as_str().to_string(),
        origin_interface: event.origin().interface().as_str().to_string(),
        action: event.action().as_str().to_string(),
        target: event.target().as_str().to_string(),
        before_sha256: event
            .before_sha256()
            .map(|value| value.as_str().to_string()),
        after_sha256: event.after_sha256().map(|value| value.as_str().to_string()),
        outcome: event.outcome().as_str().to_string(),
        reason: event.reason().map(|value| value.as_str().to_string()),
        previous_hash: event.previous_hash().as_str().to_string(),
        event_hash: event.event_hash().as_str().to_string(),
    }
}

// Reconstructs one validated audit event from private persistence.
fn event_from_record(record: AuditEventDatabaseRecord) -> Result<AuditEvent, AuditStoreError> {
    AuditEvent::from_persisted(
        record.sequence,
        AuditEventId::parse(&record.event_id).map_err(|_| AuditStoreError::Corrupt)?,
        AuditCorrelationId::parse(&record.correlation_id).map_err(|_| AuditStoreError::Corrupt)?,
        AuditUnixNanoseconds::new(record.timestamp_unix_ns)
            .map_err(|_| AuditStoreError::Corrupt)?,
        NodeId::parse(&record.node_id).map_err(|_| AuditStoreError::Corrupt)?,
        AuditActor::new(
            actor_type(&record.actor_type)?,
            AuditActorId::parse(&record.actor_id).map_err(|_| AuditStoreError::Corrupt)?,
        ),
        AuditOrigin::new(
            NodeId::parse(&record.origin_node_id).map_err(|_| AuditStoreError::Corrupt)?,
            origin_interface(&record.origin_interface)?,
        ),
        AuditAction::parse(&record.action).map_err(|_| AuditStoreError::Corrupt)?,
        AuditTarget::parse(&record.target).map_err(|_| AuditStoreError::Corrupt)?,
        optional_digest(record.before_sha256)?,
        optional_digest(record.after_sha256)?,
        outcome(&record.outcome)?,
        record
            .reason
            .map(|value| AuditReason::parse(&value))
            .transpose()
            .map_err(|_| AuditStoreError::Corrupt)?,
        digest(&record.previous_hash)?,
        digest(&record.event_hash)?,
    )
    .map_err(|_| AuditStoreError::Corrupt)
}

// Projects one checkpoint into its private persistence record.
fn checkpoint_record(checkpoint: &AuditCheckpoint) -> AuditCheckpointDatabaseRecord {
    AuditCheckpointDatabaseRecord {
        record_id: sequence_record_id(checkpoint.sequence()),
        sequence: checkpoint.sequence(),
        event_hash: checkpoint.event_hash().as_str().to_string(),
        signature: checkpoint.signature().to_vec(),
        created_at_unix_ns: checkpoint.created_at().value(),
    }
}

// Reconstructs one structurally valid checkpoint from private persistence.
fn checkpoint_from_record(
    record: AuditCheckpointDatabaseRecord,
) -> Result<AuditCheckpoint, AuditStoreError> {
    AuditCheckpoint::from_persisted(
        record.sequence,
        digest(&record.event_hash)?,
        record.signature,
        AuditUnixNanoseconds::new(record.created_at_unix_ns)
            .map_err(|_| AuditStoreError::Corrupt)?,
    )
    .map_err(|_| AuditStoreError::Corrupt)
}

// Verifies every replay record names one exact event and unique replay identity.
fn validate_replays(
    replays: &[DatabaseStoredRecord<AuditReplayDatabaseRecord>],
    entries: &[AuditLedgerEntry],
) -> Result<(), AuditStoreError> {
    if replays.len() != entries.len() {
        return Err(AuditStoreError::Corrupt);
    }
    let events: HashMap<&str, &AuditEvent> = entries
        .iter()
        .map(|entry| (entry.event().event_id().as_str(), entry.event()))
        .collect();
    let mut replay_ids = HashSet::new();
    let mut replayed_events = HashSet::new();
    for stored in replays {
        let record = &stored.value;
        let event = events
            .get(record.event_id.as_str())
            .ok_or(AuditStoreError::Corrupt)?;
        if stored.revision != 1
            || record.replay_id != record.identifier()
            || !replay_ids.insert(record.replay_id.as_str())
            || !replayed_events.insert(record.event_id.as_str())
            || digest(&record.request_sha256).is_err()
            || event.sequence() != record.sequence
        {
            return Err(AuditStoreError::Corrupt);
        }
    }
    Ok(())
}

// Returns the stable zero-padded sequence identity used for deterministic storage ordering.
fn sequence_record_id(sequence: u64) -> String {
    format!("{sequence:020}")
}

// Prefixes the caller replay identity without exceeding DatabaseManager's public bound.
fn database_replay_id(replay_id: &AuditReplayId) -> Result<String, AuditStoreError> {
    let value = format!("audit:{}", replay_id.as_str());
    if value.len() > 255 {
        return Err(AuditStoreError::Corrupt);
    }
    Ok(value)
}

// Parses one required lowercase SHA-256 value from persistence.
fn digest(value: &str) -> Result<Sha256Digest, AuditStoreError> {
    Sha256Digest::parse(value).map_err(|_| AuditStoreError::Corrupt)
}

// Parses one optional lowercase SHA-256 value from persistence.
fn optional_digest(value: Option<String>) -> Result<Option<Sha256Digest>, AuditStoreError> {
    value.map(|value| digest(&value)).transpose()
}

// Parses one closed actor kind from persistence.
fn actor_type(value: &str) -> Result<AuditActorType, AuditStoreError> {
    match value {
        "local-user" => Ok(AuditActorType::LocalUser),
        "controller" => Ok(AuditActorType::Controller),
        "node-candidate" => Ok(AuditActorType::NodeCandidate),
        "node" => Ok(AuditActorType::Node),
        "system" => Ok(AuditActorType::System),
        _ => Err(AuditStoreError::Corrupt),
    }
}

// Parses one closed origin interface from persistence.
fn origin_interface(value: &str) -> Result<AuditOriginInterface, AuditStoreError> {
    match value {
        "cli" => Ok(AuditOriginInterface::Cli),
        "controller" => Ok(AuditOriginInterface::Controller),
        "pairing" => Ok(AuditOriginInterface::Pairing),
        "gateway" => Ok(AuditOriginInterface::Gateway),
        "node" => Ok(AuditOriginInterface::Node),
        "system" => Ok(AuditOriginInterface::System),
        _ => Err(AuditStoreError::Corrupt),
    }
}

// Parses one closed audit outcome from persistence.
fn outcome(value: &str) -> Result<AuditOutcome, AuditStoreError> {
    match value {
        "success" => Ok(AuditOutcome::Success),
        "denied" => Ok(AuditOutcome::Denied),
        "failed" => Ok(AuditOutcome::Failed),
        _ => Err(AuditStoreError::Corrupt),
    }
}

// Maps generic database failures onto the deliberately smaller audit store surface.
fn database_store_error(error: DatabaseError) -> AuditStoreError {
    match error {
        DatabaseError::Conflict { .. } => AuditStoreError::Conflict,
        DatabaseError::IdempotencyConflict { .. } => AuditStoreError::ReplayConflict,
        DatabaseError::Corrupt { .. } | DatabaseError::InvalidInput { .. } => {
            AuditStoreError::Corrupt
        }
        DatabaseError::NotFound { .. }
        | DatabaseError::Unavailable { .. }
        | DatabaseError::Closed => AuditStoreError::Unavailable,
    }
}
