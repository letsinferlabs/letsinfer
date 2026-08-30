// SPDX-License-Identifier: AGPL-3.0-only

use serde::Serialize;

use li_core_interface::NodeId;

use crate::{
    AuditCheckpoint, AuditError, AuditEvent, AuditLedger, AuditUnixNanoseconds, AuditVerification,
};

const MAX_EXPORT_BYTES: usize = 16 * 1024 * 1024;
const MAX_EXPORT_EVENTS: usize = 10_000;

// Defines explicit complete-export resource limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditExportLimit {
    events: usize,
    bytes: usize,
}

impl AuditExportLimit {
    // Creates one complete-export bound within the manager safety ceiling.
    pub fn new(events: usize, bytes: usize) -> Result<Self, AuditError> {
        if events == 0 || events > MAX_EXPORT_EVENTS || bytes == 0 || bytes > MAX_EXPORT_BYTES {
            return Err(AuditError::invalid(
                "audit export limit",
                "events must be 1..10000 and bytes must be 1..16777216",
            ));
        }
        Ok(Self { events, bytes })
    }

    // Creates the maximum supported complete-export bound.
    pub const fn maximum() -> Self {
        Self {
            events: MAX_EXPORT_EVENTS,
            bytes: MAX_EXPORT_BYTES,
        }
    }

    // Returns the maximum complete event count.
    pub const fn events(self) -> usize {
        self.events
    }

    // Returns the maximum encoded byte count.
    pub const fn bytes(self) -> usize {
        self.bytes
    }
}

// Owns one complete verified JSON export.
#[derive(Clone, Eq, PartialEq)]
pub struct AuditExport {
    bytes: Vec<u8>,
    events: usize,
}

impl AuditExport {
    // Returns the canonical single-document export bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    // Returns the complete event count encoded in this document.
    pub const fn events(&self) -> usize {
        self.events
    }
}

impl std::fmt::Debug for AuditExport {
    // Avoids duplicating the entire chain through debug output.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuditExport")
            .field("bytes", &self.bytes.len())
            .field("events", &self.events)
            .finish()
    }
}

// Encodes one verified complete ledger without exceeding caller or global bounds.
pub(crate) fn encode_export(
    node_id: &NodeId,
    ledger: &AuditLedger,
    verification: &AuditVerification,
    exported_at: AuditUnixNanoseconds,
    limit: AuditExportLimit,
) -> Result<AuditExport, AuditError> {
    if ledger.entries().len() > limit.events() {
        return Err(AuditError::ExportLimitExceeded);
    }
    let events: Vec<AuditEventDocument<'_>> = ledger
        .entries()
        .iter()
        .map(|entry| AuditEventDocument::from(entry.event()))
        .collect();
    let checkpoints: Vec<AuditCheckpointDocument> = ledger
        .entries()
        .iter()
        .filter_map(|entry| entry.checkpoint().map(AuditCheckpointDocument::from))
        .collect();
    let document = AuditExportDocument {
        schema_version: 1,
        node_id: node_id.as_str(),
        exported_at_unix_ns: exported_at.value(),
        events,
        checkpoints,
        verification: AuditVerificationDocument {
            valid: true,
            events: verification.events(),
            checkpoints: verification.checkpoints(),
            head_sha256: verification.head_sha256().as_str(),
        },
    };
    let mut bytes = serde_json::to_vec(&document)
        .map_err(|_| AuditError::provider("serialization", "audit export encoding failed"))?;
    bytes.push(b'\n');
    if bytes.len() > limit.bytes() {
        return Err(AuditError::ExportLimitExceeded);
    }
    Ok(AuditExport {
        bytes,
        events: ledger.entries().len(),
    })
}

// Defines the stable version-one complete audit export envelope.
#[derive(Serialize)]
struct AuditExportDocument<'a> {
    schema_version: u32,
    node_id: &'a str,
    exported_at_unix_ns: u64,
    events: Vec<AuditEventDocument<'a>>,
    checkpoints: Vec<AuditCheckpointDocument>,
    verification: AuditVerificationDocument<'a>,
}

// Defines one complete non-secret event projection.
#[derive(Serialize)]
struct AuditEventDocument<'a> {
    sequence: u64,
    event_id: &'a str,
    correlation_id: &'a str,
    timestamp_unix_ns: u64,
    node_id: &'a str,
    actor_type: &'a str,
    actor_id: &'a str,
    origin_node_id: &'a str,
    origin_interface: &'a str,
    action: &'a str,
    target: &'a str,
    before_sha256: Option<&'a str>,
    after_sha256: Option<&'a str>,
    outcome: &'a str,
    reason: Option<&'a str>,
    previous_hash: &'a str,
    event_hash: &'a str,
}

impl<'a> From<&'a AuditEvent> for AuditEventDocument<'a> {
    // Projects one validated event without adding a free-form content field.
    fn from(event: &'a AuditEvent) -> Self {
        Self {
            sequence: event.sequence(),
            event_id: event.event_id().as_str(),
            correlation_id: event.correlation_id().as_str(),
            timestamp_unix_ns: event.timestamp().value(),
            node_id: event.node_id().as_str(),
            actor_type: event.actor().kind().as_str(),
            actor_id: event.actor().identifier().as_str(),
            origin_node_id: event.origin().node_id().as_str(),
            origin_interface: event.origin().interface().as_str(),
            action: event.action().as_str(),
            target: event.target().as_str(),
            before_sha256: event.before_sha256().map(|value| value.as_str()),
            after_sha256: event.after_sha256().map(|value| value.as_str()),
            outcome: event.outcome().as_str(),
            reason: event.reason().map(|value| value.as_str()),
            previous_hash: event.previous_hash().as_str(),
            event_hash: event.event_hash().as_str(),
        }
    }
}

// Defines one signed checkpoint projection with standard Base64 text.
#[derive(Serialize)]
struct AuditCheckpointDocument {
    sequence: u64,
    event_hash: String,
    signature_base64: String,
    created_at_unix_ns: u64,
}

impl From<&AuditCheckpoint> for AuditCheckpointDocument {
    // Projects one checkpoint while preserving its opaque signature exactly.
    fn from(checkpoint: &AuditCheckpoint) -> Self {
        Self {
            sequence: checkpoint.sequence(),
            event_hash: checkpoint.event_hash().as_str().to_string(),
            signature_base64: base64(checkpoint.signature()),
            created_at_unix_ns: checkpoint.created_at().value(),
        }
    }
}

// Defines one verification receipt inside the export.
#[derive(Serialize)]
struct AuditVerificationDocument<'a> {
    valid: bool,
    events: usize,
    checkpoints: usize,
    head_sha256: &'a str,
}

// Encodes opaque checkpoint bytes using canonical padded Base64.
fn base64(value: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::with_capacity(value.len().div_ceil(3) * 4);
    for chunk in value.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        encoded.push(ALPHABET[(first >> 2) as usize] as char);
        encoded.push(ALPHABET[((first & 0x03) << 4 | second >> 4) as usize] as char);
        encoded.push(if chunk.len() > 1 {
            ALPHABET[((second & 0x0f) << 2 | third >> 6) as usize] as char
        } else {
            '='
        });
        encoded.push(if chunk.len() > 2 {
            ALPHABET[(third & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    encoded
}
