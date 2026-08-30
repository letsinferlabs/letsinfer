// SPDX-License-Identifier: AGPL-3.0-only

mod li_audit_contract;
mod li_audit_cryptography;
mod li_audit_export;
mod li_audit_store;

pub use li_audit_contract::{
    AuditAction, AuditActor, AuditActorId, AuditActorType, AuditAppendRequest, AuditCheckpoint,
    AuditCheckpointPolicy, AuditCorrelationId, AuditError, AuditEvent, AuditEventId,
    AuditIntegrityError, AuditOrigin, AuditOriginInterface, AuditOutcome, AuditReason,
    AuditReplayId, AuditStoreError, AuditTarget, AuditUnixNanoseconds, AuditVerification,
    AUDIT_GENESIS_HASH, PRODUCTION_CHECKPOINT_INTERVAL,
};
pub use li_audit_export::{AuditExport, AuditExportLimit};
pub use li_audit_store::{
    AuditAppendDisposition, AuditAppendReceipt, AuditLedger, AuditLedgerEntry, AuditReplayReceipt,
    AuditStore,
};

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use getrandom::fill;
use li_core_interface::{NodeId, Sha256Digest};

use li_audit_cryptography::{chained_event, event_request_sha256, event_sha256, request_sha256};
use li_audit_export::encode_export;

const MAX_APPEND_ATTEMPTS: usize = 8;
const MAX_LIST_EVENTS: usize = 10_000;

// Supplies audit timestamps explicitly for deterministic append and export flows.
pub trait AuditClock: Send + Sync {
    // Returns one current Unix timestamp in nanoseconds.
    fn now(&self) -> Result<AuditUnixNanoseconds, AuditError>;
}

// Reads production time from the active host clock.
#[derive(Default)]
pub struct SystemAuditClock;

impl AuditClock for SystemAuditClock {
    // Returns host time while rejecting pre-epoch or oversized values.
    fn now(&self) -> Result<AuditUnixNanoseconds, AuditError> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| AuditError::provider("clock", "system clock is before the Unix epoch"))?;
        let nanoseconds = u64::try_from(duration.as_nanos())
            .map_err(|_| AuditError::provider("clock", "system clock exceeds its range"))?;
        AuditUnixNanoseconds::new(nanoseconds)
    }
}

// Supplies unpredictable production event identities behind one deterministic test boundary.
pub trait AuditIdentityProvider: Send + Sync {
    // Returns one fresh canonical event identity.
    fn event_id(&self) -> Result<AuditEventId, AuditError>;
}

// Reads production event identity material from the operating-system CSPRNG.
#[derive(Default)]
pub struct SystemAuditIdentityProvider;

impl AuditIdentityProvider for SystemAuditIdentityProvider {
    // Returns one fresh 128-bit lowercase hexadecimal identity.
    fn event_id(&self) -> Result<AuditEventId, AuditError> {
        let mut bytes = [0_u8; 16];
        fill(&mut bytes)
            .map_err(|_| AuditError::provider("identity", "secure random source is unavailable"))?;
        let mut value = String::with_capacity(32);
        for byte in bytes {
            use std::fmt::Write;
            write!(&mut value, "{byte:02x}")
                .map_err(|_| AuditError::provider("identity", "event identity encoding failed"))?;
        }
        AuditEventId::parse(&value)
    }
}

// Signs and verifies event-hash text without exposing node private material.
pub trait AuditCheckpointCryptography: Send + Sync {
    // Signs the exact lowercase event-hash text for one periodic checkpoint.
    fn sign(&self, event_hash: &[u8]) -> Result<Vec<u8>, AuditError>;

    // Verifies one checkpoint signature against the node's pinned public identity.
    fn verify(&self, event_hash: &[u8], signature: &[u8]) -> Result<bool, AuditError>;
}

// Owns one node audit chain without owning node identity or persistence mechanics.
pub struct AuditManager {
    node_id: NodeId,
    store: Arc<dyn AuditStore>,
    clock: Arc<dyn AuditClock>,
    identities: Arc<dyn AuditIdentityProvider>,
    cryptography: Arc<dyn AuditCheckpointCryptography>,
    checkpoint_policy: AuditCheckpointPolicy,
}

impl AuditManager {
    // Creates one manager from explicit node, storage, time, identity, and signing capabilities.
    pub fn new(
        node_id: NodeId,
        store: Arc<dyn AuditStore>,
        clock: Arc<dyn AuditClock>,
        identities: Arc<dyn AuditIdentityProvider>,
        cryptography: Arc<dyn AuditCheckpointCryptography>,
        checkpoint_policy: AuditCheckpointPolicy,
    ) -> Self {
        Self {
            node_id,
            store,
            clock,
            identities,
            cryptography,
            checkpoint_policy,
        }
    }

    // Returns the exact node identity that owns this audit chain.
    pub const fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    // Appends one action exactly once and retries bounded optimistic contention.
    pub fn append(&self, request: AuditAppendRequest) -> Result<AuditAppendReceipt, AuditError> {
        let request_digest = request_sha256(&self.node_id, &request)?;
        if let Some(replay) = self.store.replay(request.replay_id())? {
            return self.replay_receipt(&request_digest, replay);
        }
        let event_id = self.identities.event_id()?;
        let timestamp = self.clock.now()?;
        for _attempt in 0..MAX_APPEND_ATTEMPTS {
            let ledger = self.store.ledger()?;
            self.verify_ledger(&ledger)?;
            let sequence = u64::try_from(ledger.entries().len())
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or_else(|| {
                    AuditError::invalid("audit sequence", "event count exceeds its range")
                })?;
            let previous_hash = ledger
                .head()
                .map(|event| event.event_hash().clone())
                .unwrap_or(genesis_hash()?);
            let event = chained_event(
                sequence,
                event_id.clone(),
                timestamp,
                self.node_id.clone(),
                &request,
                previous_hash,
            )?;
            let checkpoint = self.checkpoint(&event)?;
            let entry = AuditLedgerEntry::new(event, checkpoint)?;
            match self.store.append(
                ledger.revision(),
                request.replay_id(),
                &request_digest,
                entry.clone(),
            ) {
                Ok(receipt) => {
                    return self.validate_append_receipt(
                        &request_digest,
                        &entry,
                        ledger.revision(),
                        receipt,
                    )
                }
                Err(AuditStoreError::Conflict) => continue,
                Err(AuditStoreError::ReplayConflict) => {
                    return Err(AuditError::IdempotencyConflict)
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(AuditError::Contention)
    }

    // Returns recent events from newest to oldest under the production list bound.
    pub fn list(&self, limit: usize) -> Result<Vec<AuditEvent>, AuditError> {
        if limit == 0 || limit > MAX_LIST_EVENTS {
            return Err(AuditError::invalid(
                "audit list limit",
                "limit must be between 1 and 10000",
            ));
        }
        let ledger = self.store.ledger()?;
        Ok(ledger
            .entries()
            .iter()
            .rev()
            .take(limit)
            .map(|entry| entry.event().clone())
            .collect())
    }

    // Returns one exact event by stable identity.
    pub fn show(&self, event_id: &AuditEventId) -> Result<AuditEvent, AuditError> {
        self.store.event(event_id)?.ok_or(AuditError::NotFound)
    }

    // Verifies every event hash and required periodic checkpoint without mutation.
    pub fn verify(&self) -> Result<AuditVerification, AuditError> {
        let ledger = self.store.ledger()?;
        self.verify_ledger(&ledger)
    }

    // Returns one complete verified JSON document only when it fits explicit bounds.
    pub fn export(&self, limit: AuditExportLimit) -> Result<AuditExport, AuditError> {
        let ledger = self.store.ledger()?;
        let verification = self.verify_ledger(&ledger)?;
        let exported_at = self.clock.now()?;
        encode_export(&self.node_id, &ledger, &verification, exported_at, limit)
    }

    // Creates a periodic checkpoint before its event can enter storage.
    fn checkpoint(&self, event: &AuditEvent) -> Result<Option<AuditCheckpoint>, AuditError> {
        if !self.checkpoint_policy.requires_checkpoint(event.sequence()) {
            return Ok(None);
        }
        let signature = self
            .cryptography
            .sign(event.event_hash().as_str().as_bytes())?;
        let created_at = self.clock.now()?;
        AuditCheckpoint::from_persisted(
            event.sequence(),
            event.event_hash().clone(),
            signature,
            created_at,
        )
        .map(Some)
    }

    // Verifies one complete ledger and returns its exact head receipt.
    fn verify_ledger(&self, ledger: &AuditLedger) -> Result<AuditVerification, AuditError> {
        let mut previous_hash = genesis_hash()?;
        let mut checkpoints = 0_usize;
        let mut event_ids = HashSet::new();
        for (index, entry) in ledger.entries().iter().enumerate() {
            let event = entry.event();
            let sequence = u64::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or(AuditIntegrityError::Sequence { sequence: u64::MAX })?;
            if event.sequence() != sequence {
                return Err(AuditIntegrityError::Sequence {
                    sequence: event.sequence(),
                }
                .into());
            }
            if !event_ids.insert(event.event_id().as_str()) {
                return Err(AuditIntegrityError::EventIdentity { sequence }.into());
            }
            if event.node_id() != &self.node_id {
                return Err(AuditIntegrityError::Node { sequence }.into());
            }
            if event.previous_hash() != &previous_hash {
                return Err(AuditIntegrityError::PreviousHash { sequence }.into());
            }
            if event_sha256(event)? != *event.event_hash() {
                return Err(AuditIntegrityError::EventHash { sequence }.into());
            }
            match (
                self.checkpoint_policy.requires_checkpoint(sequence),
                entry.checkpoint(),
            ) {
                (true, None) => {
                    return Err(AuditIntegrityError::CheckpointMissing { sequence }.into())
                }
                (false, Some(_)) => {
                    return Err(AuditIntegrityError::CheckpointUnexpected { sequence }.into())
                }
                (true, Some(checkpoint)) => {
                    self.verify_checkpoint(event, checkpoint)?;
                    checkpoints += 1;
                }
                (false, None) => {}
            }
            previous_hash = event.event_hash().clone();
        }
        Ok(AuditVerification::new(
            ledger.entries().len(),
            checkpoints,
            previous_hash,
        ))
    }

    // Verifies one checkpoint's event binding, timestamp, and signature.
    fn verify_checkpoint(
        &self,
        event: &AuditEvent,
        checkpoint: &AuditCheckpoint,
    ) -> Result<(), AuditError> {
        let sequence = event.sequence();
        if checkpoint.sequence() != sequence || checkpoint.event_hash() != event.event_hash() {
            return Err(AuditIntegrityError::CheckpointHash { sequence }.into());
        }
        if checkpoint.created_at() < event.timestamp() {
            return Err(AuditIntegrityError::CheckpointTime { sequence }.into());
        }
        if !self.cryptography.verify(
            checkpoint.event_hash().as_str().as_bytes(),
            checkpoint.signature(),
        )? {
            return Err(AuditIntegrityError::CheckpointSignature { sequence }.into());
        }
        Ok(())
    }

    // Validates one persisted replay against both its request and current complete chain.
    fn replay_receipt(
        &self,
        request_sha256: &Sha256Digest,
        replay: AuditReplayReceipt,
    ) -> Result<AuditAppendReceipt, AuditError> {
        if replay.request_sha256() != request_sha256
            || event_request_sha256(replay.entry().event())? != *request_sha256
        {
            return Err(AuditError::IdempotencyConflict);
        }
        let ledger = self.store.ledger()?;
        self.verify_ledger(&ledger)?;
        if !ledger.entries().iter().any(|entry| entry == replay.entry()) {
            return Err(AuditStoreError::Corrupt.into());
        }
        Ok(AuditAppendReceipt::new(
            request_sha256.clone(),
            replay.entry().clone(),
            AuditAppendDisposition::Replayed,
            replay.revision(),
        ))
    }

    // Requires an append receipt to match either the exact write or a valid replay.
    fn validate_append_receipt(
        &self,
        request_sha256: &Sha256Digest,
        intended: &AuditLedgerEntry,
        expected_revision: u64,
        receipt: AuditAppendReceipt,
    ) -> Result<AuditAppendReceipt, AuditError> {
        if receipt.request_sha256() != request_sha256
            || event_request_sha256(receipt.entry().event())? != *request_sha256
        {
            return Err(AuditError::IdempotencyConflict);
        }
        match receipt.disposition() {
            AuditAppendDisposition::Applied
                if receipt.entry() != intended
                    || receipt.revision() != expected_revision.saturating_add(1) =>
            {
                return Err(AuditStoreError::Corrupt.into());
            }
            AuditAppendDisposition::Replayed => {
                let ledger = self.store.ledger()?;
                self.verify_ledger(&ledger)?;
                if !ledger
                    .entries()
                    .iter()
                    .any(|entry| entry == receipt.entry())
                {
                    return Err(AuditStoreError::Corrupt.into());
                }
            }
            AuditAppendDisposition::Applied => {}
        }
        Ok(receipt)
    }
}

// Returns the fixed all-zero genesis digest as a validated Core identity.
fn genesis_hash() -> Result<Sha256Digest, AuditError> {
    Sha256Digest::parse(AUDIT_GENESIS_HASH)
        .map_err(|_| AuditError::invalid("audit hash", "genesis hash is invalid"))
}
