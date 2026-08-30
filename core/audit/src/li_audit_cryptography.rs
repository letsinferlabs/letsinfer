// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use li_core_interface::Sha256Digest;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{AuditAppendRequest, AuditError, AuditEvent, AuditEventId, AuditUnixNanoseconds};

// Produces sorted canonical JSON bytes with the production trailing newline.
pub(crate) fn canonical_event_bytes(event: &AuditEvent) -> Result<Vec<u8>, AuditError> {
    let mut fields = BTreeMap::new();
    fields.insert("action", Value::String(event.action().as_str().to_string()));
    fields.insert(
        "actor_id",
        Value::String(event.actor().identifier().as_str().to_string()),
    );
    fields.insert(
        "actor_type",
        Value::String(event.actor().kind().as_str().to_string()),
    );
    fields.insert("after_sha256", digest_value(event.after_sha256()));
    fields.insert("before_sha256", digest_value(event.before_sha256()));
    fields.insert(
        "correlation_id",
        Value::String(event.correlation_id().as_str().to_string()),
    );
    fields.insert(
        "event_id",
        Value::String(event.event_id().as_str().to_string()),
    );
    fields.insert(
        "node_id",
        Value::String(event.node_id().as_str().to_string()),
    );
    fields.insert(
        "origin_interface",
        Value::String(event.origin().interface().as_str().to_string()),
    );
    fields.insert(
        "origin_node_id",
        Value::String(event.origin().node_id().as_str().to_string()),
    );
    fields.insert(
        "outcome",
        Value::String(event.outcome().as_str().to_string()),
    );
    fields.insert(
        "previous_hash",
        Value::String(event.previous_hash().as_str().to_string()),
    );
    fields.insert(
        "reason",
        event
            .reason()
            .map(|value| Value::String(value.as_str().to_string()))
            .unwrap_or(Value::Null),
    );
    fields.insert("target", Value::String(event.target().as_str().to_string()));
    fields.insert(
        "timestamp_unix_ns",
        Value::Number(event.timestamp().value().into()),
    );
    canonical_map_bytes(fields)
}

// Computes one semantic request digest independently of time and chain position.
pub(crate) fn request_sha256(
    node_id: &li_core_interface::NodeId,
    request: &AuditAppendRequest,
) -> Result<Sha256Digest, AuditError> {
    let mut fields = BTreeMap::new();
    fields.insert(
        "action",
        Value::String(request.action().as_str().to_string()),
    );
    fields.insert(
        "actor_id",
        Value::String(request.actor().identifier().as_str().to_string()),
    );
    fields.insert(
        "actor_type",
        Value::String(request.actor().kind().as_str().to_string()),
    );
    fields.insert("after_sha256", digest_value(request.after_sha256()));
    fields.insert("before_sha256", digest_value(request.before_sha256()));
    fields.insert(
        "correlation_id",
        Value::String(request.correlation_id().as_str().to_string()),
    );
    fields.insert("node_id", Value::String(node_id.as_str().to_string()));
    fields.insert(
        "origin_interface",
        Value::String(request.origin().interface().as_str().to_string()),
    );
    fields.insert(
        "origin_node_id",
        Value::String(request.origin().node_id().as_str().to_string()),
    );
    fields.insert(
        "outcome",
        Value::String(request.outcome().as_str().to_string()),
    );
    fields.insert(
        "reason",
        request
            .reason()
            .map(|value| Value::String(value.as_str().to_string()))
            .unwrap_or(Value::Null),
    );
    fields.insert(
        "target",
        Value::String(request.target().as_str().to_string()),
    );
    let encoded = canonical_map_bytes(fields)?;
    digest(&encoded)
}

// Recomputes the semantic request digest carried by one stored event.
pub(crate) fn event_request_sha256(event: &AuditEvent) -> Result<Sha256Digest, AuditError> {
    let mut fields = BTreeMap::new();
    fields.insert("action", Value::String(event.action().as_str().to_string()));
    fields.insert(
        "actor_id",
        Value::String(event.actor().identifier().as_str().to_string()),
    );
    fields.insert(
        "actor_type",
        Value::String(event.actor().kind().as_str().to_string()),
    );
    fields.insert("after_sha256", digest_value(event.after_sha256()));
    fields.insert("before_sha256", digest_value(event.before_sha256()));
    fields.insert(
        "correlation_id",
        Value::String(event.correlation_id().as_str().to_string()),
    );
    fields.insert(
        "node_id",
        Value::String(event.node_id().as_str().to_string()),
    );
    fields.insert(
        "origin_interface",
        Value::String(event.origin().interface().as_str().to_string()),
    );
    fields.insert(
        "origin_node_id",
        Value::String(event.origin().node_id().as_str().to_string()),
    );
    fields.insert(
        "outcome",
        Value::String(event.outcome().as_str().to_string()),
    );
    fields.insert(
        "reason",
        event
            .reason()
            .map(|value| Value::String(value.as_str().to_string()))
            .unwrap_or(Value::Null),
    );
    fields.insert("target", Value::String(event.target().as_str().to_string()));
    digest(&canonical_map_bytes(fields)?)
}

// Builds one event and computes its production-compatible chain hash.
pub(crate) fn chained_event(
    sequence: u64,
    event_id: AuditEventId,
    timestamp: AuditUnixNanoseconds,
    node_id: li_core_interface::NodeId,
    request: &AuditAppendRequest,
    previous_hash: Sha256Digest,
) -> Result<AuditEvent, AuditError> {
    let placeholder = Sha256Digest::parse(crate::AUDIT_GENESIS_HASH)
        .map_err(|_| AuditError::invalid("audit hash", "genesis hash identity is invalid"))?;
    let unsigned = AuditEvent::from_persisted(
        sequence,
        event_id.clone(),
        request.correlation_id().clone(),
        timestamp,
        node_id.clone(),
        request.actor().clone(),
        request.origin().clone(),
        request.action().clone(),
        request.target().clone(),
        request.before_sha256().cloned(),
        request.after_sha256().cloned(),
        request.outcome(),
        request.reason().cloned(),
        previous_hash.clone(),
        placeholder,
    )?;
    let event_hash = event_sha256(&unsigned)?;
    AuditEvent::from_persisted(
        sequence,
        event_id,
        request.correlation_id().clone(),
        timestamp,
        node_id,
        request.actor().clone(),
        request.origin().clone(),
        request.action().clone(),
        request.target().clone(),
        request.before_sha256().cloned(),
        request.after_sha256().cloned(),
        request.outcome(),
        request.reason().cloned(),
        previous_hash,
        event_hash,
    )
}

// Recomputes one event hash from raw previous-hash bytes and canonical event bytes.
pub(crate) fn event_sha256(event: &AuditEvent) -> Result<Sha256Digest, AuditError> {
    let previous = decode_sha256(event.previous_hash())?;
    let canonical = canonical_event_bytes(event)?;
    let mut hasher = Sha256::new();
    hasher.update(previous);
    hasher.update(canonical);
    Sha256Digest::parse(&format!("{:x}", hasher.finalize()))
        .map_err(|_| AuditError::invalid("audit hash", "event hash could not be encoded"))
}

// Converts one optional digest into its exact JSON string or null value.
fn digest_value(value: Option<&Sha256Digest>) -> Value {
    value
        .map(|digest| Value::String(digest.as_str().to_string()))
        .unwrap_or(Value::Null)
}

// Serializes one sorted map without whitespace and appends one newline.
fn canonical_map_bytes(fields: BTreeMap<&str, Value>) -> Result<Vec<u8>, AuditError> {
    let mut encoded = serde_json::to_vec(&fields)
        .map_err(|_| AuditError::provider("serialization", "canonical encoding failed"))?;
    encoded.push(b'\n');
    Ok(encoded)
}

// Computes one canonical SHA-256 digest.
fn digest(value: &[u8]) -> Result<Sha256Digest, AuditError> {
    let mut hasher = Sha256::new();
    hasher.update(value);
    Sha256Digest::parse(&format!("{:x}", hasher.finalize()))
        .map_err(|_| AuditError::invalid("audit hash", "digest could not be encoded"))
}

// Decodes one validated lowercase SHA-256 identity into raw bytes.
fn decode_sha256(value: &Sha256Digest) -> Result<[u8; 32], AuditError> {
    let source = value.as_str().as_bytes();
    let mut decoded = [0_u8; 32];
    for (index, destination) in decoded.iter_mut().enumerate() {
        let high = hex_nibble(source[index * 2])?;
        let low = hex_nibble(source[index * 2 + 1])?;
        *destination = high << 4 | low;
    }
    Ok(decoded)
}

// Converts one lowercase hexadecimal byte into its numeric nibble.
fn hex_nibble(value: u8) -> Result<u8, AuditError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(AuditError::invalid(
            "audit hash",
            "digest contains invalid hexadecimal text",
        )),
    }
}
