// SPDX-License-Identifier: AGPL-3.0-only

use li_core_interface::Sha256Digest;

use crate::{AuditCheckpoint, AuditEvent, AuditEventId, AuditReplayId, AuditStoreError};

// Returns whether an append changed storage or replayed its first commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditAppendDisposition {
    Applied,
    Replayed,
}

// Stores one event and its optional atomic periodic checkpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditLedgerEntry {
    event: AuditEvent,
    checkpoint: Option<AuditCheckpoint>,
}

impl AuditLedgerEntry {
    // Creates one event entry while requiring a checkpoint to bind the same sequence and hash.
    pub fn new(
        event: AuditEvent,
        checkpoint: Option<AuditCheckpoint>,
    ) -> Result<Self, AuditStoreError> {
        if checkpoint.as_ref().is_some_and(|value| {
            value.sequence() != event.sequence() || value.event_hash() != event.event_hash()
        }) {
            return Err(AuditStoreError::Corrupt);
        }
        Ok(Self { event, checkpoint })
    }

    // Returns the complete event.
    pub const fn event(&self) -> &AuditEvent {
        &self.event
    }

    // Returns the optional checkpoint committed with this event.
    pub const fn checkpoint(&self) -> Option<&AuditCheckpoint> {
        self.checkpoint.as_ref()
    }
}

// Returns one append receipt together with replay disposition and store revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditAppendReceipt {
    request_sha256: Sha256Digest,
    entry: AuditLedgerEntry,
    disposition: AuditAppendDisposition,
    revision: u64,
}

impl AuditAppendReceipt {
    // Creates one complete optimistic append receipt.
    pub const fn new(
        request_sha256: Sha256Digest,
        entry: AuditLedgerEntry,
        disposition: AuditAppendDisposition,
        revision: u64,
    ) -> Self {
        Self {
            request_sha256,
            entry,
            disposition,
            revision,
        }
    }

    // Returns the semantic request digest bound by storage.
    pub const fn request_sha256(&self) -> &Sha256Digest {
        &self.request_sha256
    }

    // Returns the committed or replayed ledger entry.
    pub const fn entry(&self) -> &AuditLedgerEntry {
        &self.entry
    }

    // Returns whether storage changed during this call.
    pub const fn disposition(&self) -> AuditAppendDisposition {
        self.disposition
    }

    // Returns the resulting optimistic store revision.
    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

// Stores one prior replay result and its semantic request digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditReplayReceipt {
    request_sha256: Sha256Digest,
    entry: AuditLedgerEntry,
    revision: u64,
}

impl AuditReplayReceipt {
    // Creates one complete replay receipt returned by persistence.
    pub const fn new(request_sha256: Sha256Digest, entry: AuditLedgerEntry, revision: u64) -> Self {
        Self {
            request_sha256,
            entry,
            revision,
        }
    }

    // Returns the semantic request digest bound to this replay identity.
    pub const fn request_sha256(&self) -> &Sha256Digest {
        &self.request_sha256
    }

    // Returns the first committed ledger entry.
    pub const fn entry(&self) -> &AuditLedgerEntry {
        &self.entry
    }

    // Returns the current store revision observed with the replay.
    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

// Stores one complete chronological ledger snapshot at an optimistic revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditLedger {
    entries: Vec<AuditLedgerEntry>,
    revision: u64,
}

impl AuditLedger {
    // Reconstructs one persisted ledger without assuming its chain is valid.
    pub fn from_persisted(
        entries: Vec<AuditLedgerEntry>,
        revision: u64,
    ) -> Result<Self, AuditStoreError> {
        if u64::try_from(entries.len()).ok() != Some(revision) {
            return Err(AuditStoreError::Corrupt);
        }
        Ok(Self { entries, revision })
    }

    // Returns every event and checkpoint in chronological event order.
    pub fn entries(&self) -> &[AuditLedgerEntry] {
        &self.entries
    }

    // Returns the optimistic store revision.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    // Returns the latest event when the chain is non-empty.
    pub fn head(&self) -> Option<&AuditEvent> {
        self.entries.last().map(AuditLedgerEntry::event)
    }
}

// Defines the only persistence capability consumed by AuditManager.
pub trait AuditStore: Send + Sync {
    // Returns the complete ledger needed for verification and optimistic append.
    fn ledger(&self) -> Result<AuditLedger, AuditStoreError>;

    // Returns a prior append by replay identity without changing storage.
    fn replay(
        &self,
        replay_id: &AuditReplayId,
    ) -> Result<Option<AuditReplayReceipt>, AuditStoreError>;

    // Returns one event by stable identity without changing storage.
    fn event(&self, event_id: &AuditEventId) -> Result<Option<AuditEvent>, AuditStoreError>;

    // Atomically appends one event and optional checkpoint under an exact revision.
    fn append(
        &self,
        expected_revision: u64,
        replay_id: &AuditReplayId,
        request_sha256: &Sha256Digest,
        entry: AuditLedgerEntry,
    ) -> Result<AuditAppendReceipt, AuditStoreError>;
}
