// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeSet;

use li_core_interface::{OperationId, Sha256Digest, TechnicalName};
use serde_json::{Map, Value};

use crate::li_benchmark_evidence::{canonical_json_bytes, digest_bytes};
use crate::{
    BenchmarkError, BenchmarkEvidence, BenchmarkExecutionOutcome, BenchmarkFailure,
    BenchmarkFailureCategory, BenchmarkRecordSchema, BenchmarkRequest, BenchmarkRestoration,
    BenchmarkTelemetryReceipt,
};

const LOCAL_FAILURE_SCHEMA_NAME: &str = "li_benchmark_core_local_failure";
const LOCAL_FAILURE_SCHEMA_VERSION: u64 = 1;
const MAXIMUM_LOCAL_TELEMETRY_SAMPLES: u64 = 7 * 24 * 60 * 60 + 10 * 60;

// Stores one parsed Core-local terminal record binding.
pub(crate) struct ParsedLocalFailureEvidence {
    pub(crate) receipt: BenchmarkEvidence,
    pub(crate) request_sha256: Sha256Digest,
    pub(crate) outcome: Value,
}

// Materializes one closed Core-local failure or cancellation record.
pub(crate) fn local_failure_evidence(
    job_id: &OperationId,
    request: &BenchmarkRequest,
    outcome: &BenchmarkExecutionOutcome,
    telemetry: &BenchmarkTelemetryReceipt,
    restoration: &BenchmarkRestoration,
) -> Result<(Vec<u8>, BenchmarkEvidence), BenchmarkError> {
    let mut record = Map::new();
    record.insert(
        "job_id".to_string(),
        Value::String(job_id.as_str().to_string()),
    );
    record.insert("outcome".to_string(), local_outcome_value(outcome)?);
    record.insert(
        "request_sha256".to_string(),
        Value::String(request.sha256()?.as_str().to_string()),
    );
    record.insert(
        "restoration_receipt_id".to_string(),
        Value::String(restoration.receipt_id().as_str().to_string()),
    );
    record.insert(
        "schema_name".to_string(),
        Value::String(LOCAL_FAILURE_SCHEMA_NAME.to_string()),
    );
    record.insert(
        "schema_version".to_string(),
        Value::Number(LOCAL_FAILURE_SCHEMA_VERSION.into()),
    );
    record.insert("telemetry".to_string(), telemetry_value(telemetry)?);
    let material_sha256 = digest_bytes(&canonical_json_bytes(&Value::Object(record.clone()))?);
    record.insert(
        "material_sha256".to_string(),
        Value::String(material_sha256.as_str().to_string()),
    );
    let evidence_id = local_evidence_id(&material_sha256)?;
    record.insert(
        "id".to_string(),
        Value::String(evidence_id.as_str().to_string()),
    );
    let bytes = canonical_json_bytes(&Value::Object(record))?;
    let receipt = BenchmarkEvidence::new(
        evidence_id,
        material_sha256,
        BenchmarkRecordSchema::CoreLocalFailureV1,
        bytes.len() as u64,
    )?;
    Ok((bytes, receipt))
}

// Parses a canonical Core-local terminal record when its distinct schema name is present.
pub(crate) fn parsed_local_failure_evidence(
    object: &Map<String, Value>,
    bytes: &[u8],
) -> Result<Option<ParsedLocalFailureEvidence>, BenchmarkError> {
    if object.get("schema_name").and_then(Value::as_str) != Some(LOCAL_FAILURE_SCHEMA_NAME) {
        return Ok(None);
    }
    require_fields(
        object,
        &[
            "id",
            "job_id",
            "material_sha256",
            "outcome",
            "request_sha256",
            "restoration_receipt_id",
            "schema_name",
            "schema_version",
            "telemetry",
        ],
    )?;
    if integer(object, "schema_version")? != LOCAL_FAILURE_SCHEMA_VERSION {
        return Err(BenchmarkError::EvidenceRejected);
    }
    OperationId::parse(string(object, "job_id")?).map_err(|_| BenchmarkError::EvidenceRejected)?;
    let evidence_id = digest(object, "id")?;
    let material_sha256 = digest(object, "material_sha256")?;
    let request_sha256 = digest(object, "request_sha256")?;
    digest(object, "restoration_receipt_id")?;
    validate_telemetry(object.get("telemetry"))?;
    let outcome = validate_outcome(object.get("outcome"))?;

    let mut material = object.clone();
    material.remove("id");
    material.remove("material_sha256");
    if digest_bytes(&canonical_json_bytes(&Value::Object(material))?) != material_sha256
        || local_evidence_id(&material_sha256)? != evidence_id
    {
        return Err(BenchmarkError::EvidenceRejected);
    }
    let receipt = BenchmarkEvidence::new(
        evidence_id,
        material_sha256,
        BenchmarkRecordSchema::CoreLocalFailureV1,
        bytes.len() as u64,
    )
    .map_err(|_| BenchmarkError::EvidenceRejected)?;
    Ok(Some(ParsedLocalFailureEvidence {
        receipt,
        request_sha256,
        outcome,
    }))
}

// Projects one terminal failure or cancellation into its closed local representation.
pub(crate) fn local_outcome_value(
    outcome: &BenchmarkExecutionOutcome,
) -> Result<Value, BenchmarkError> {
    let mut value = Map::new();
    match outcome {
        BenchmarkExecutionOutcome::Failed {
            raw_evidence_sha256,
            failure,
        } => {
            value.insert(
                "category".to_string(),
                Value::String(failure.category().as_str().to_string()),
            );
            value.insert(
                "code".to_string(),
                Value::String(failure.description().code().as_str().to_string()),
            );
            value.insert("kind".to_string(), Value::String("failed".to_string()));
            value.insert(
                "message".to_string(),
                Value::String(failure.description().message().to_string()),
            );
            value.insert(
                "phase".to_string(),
                Value::String(failure.phase().as_str().to_string()),
            );
            value.insert(
                "raw_evidence_sha256".to_string(),
                optional_digest_value(raw_evidence_sha256.as_ref()),
            );
        }
        BenchmarkExecutionOutcome::Cancelled {
            raw_evidence_sha256,
        } => {
            value.insert("kind".to_string(), Value::String("cancelled".to_string()));
            value.insert(
                "raw_evidence_sha256".to_string(),
                optional_digest_value(raw_evidence_sha256.as_ref()),
            );
        }
        BenchmarkExecutionOutcome::Succeeded { .. } => {
            return Err(BenchmarkError::EvidenceRejected);
        }
    }
    Ok(Value::Object(value))
}

// Returns one closed telemetry receipt projection for local terminal evidence.
fn telemetry_value(receipt: &BenchmarkTelemetryReceipt) -> Result<Value, BenchmarkError> {
    if receipt.sample_count() > MAXIMUM_LOCAL_TELEMETRY_SAMPLES {
        return Err(BenchmarkError::EvidenceRejected);
    }
    let mut telemetry = Map::new();
    telemetry.insert(
        "receipt_id".to_string(),
        Value::String(receipt.receipt_id().as_str().to_string()),
    );
    telemetry.insert(
        "sample_count".to_string(),
        Value::Number(receipt.sample_count().into()),
    );
    Ok(Value::Object(telemetry))
}

// Validates one closed telemetry receipt embedded in local terminal evidence.
fn validate_telemetry(value: Option<&Value>) -> Result<(), BenchmarkError> {
    let telemetry = value
        .and_then(Value::as_object)
        .ok_or(BenchmarkError::EvidenceRejected)?;
    require_fields(telemetry, &["receipt_id", "sample_count"])?;
    digest(telemetry, "receipt_id")?;
    if integer(telemetry, "sample_count")? > MAXIMUM_LOCAL_TELEMETRY_SAMPLES {
        return Err(BenchmarkError::EvidenceRejected);
    }
    Ok(())
}

// Validates and normalizes one closed local failure or cancellation outcome.
fn validate_outcome(value: Option<&Value>) -> Result<Value, BenchmarkError> {
    let outcome = value
        .and_then(Value::as_object)
        .ok_or(BenchmarkError::EvidenceRejected)?;
    match string(outcome, "kind")? {
        "failed" => {
            require_fields(
                outcome,
                &[
                    "category",
                    "code",
                    "kind",
                    "message",
                    "phase",
                    "raw_evidence_sha256",
                ],
            )?;
            let category = failure_category(string(outcome, "category")?)?;
            let phase = string(outcome, "phase")?;
            TechnicalName::parse(phase).map_err(|_| BenchmarkError::EvidenceRejected)?;
            let failure = BenchmarkFailure::new(category, phase, string(outcome, "message")?)
                .map_err(|_| BenchmarkError::EvidenceRejected)?;
            if string(outcome, "code")? != failure.description().code().as_str() {
                return Err(BenchmarkError::EvidenceRejected);
            }
            optional_digest(outcome.get("raw_evidence_sha256"))?;
        }
        "cancelled" => {
            require_fields(outcome, &["kind", "raw_evidence_sha256"])?;
            optional_digest(outcome.get("raw_evidence_sha256"))?;
        }
        _ => return Err(BenchmarkError::EvidenceRejected),
    }
    Ok(Value::Object(outcome.clone()))
}

// Returns one category only when its stable evidence name is exact.
fn failure_category(value: &str) -> Result<BenchmarkFailureCategory, BenchmarkError> {
    match value {
        "crash" => Ok(BenchmarkFailureCategory::Crash),
        "out_of_memory" => Ok(BenchmarkFailureCategory::OutOfMemory),
        "protection_trip" => Ok(BenchmarkFailureCategory::ProtectionTrip),
        "output_validation" => Ok(BenchmarkFailureCategory::OutputValidation),
        "incomplete_workload" => Ok(BenchmarkFailureCategory::IncompleteWorkload),
        "restoration" => Ok(BenchmarkFailureCategory::Restoration),
        _ => Err(BenchmarkError::EvidenceRejected),
    }
}

// Returns one deterministic evidence identity over the exact terminal material digest.
fn local_evidence_id(material_sha256: &Sha256Digest) -> Result<Sha256Digest, BenchmarkError> {
    let mut identity = Map::new();
    identity.insert(
        "contract".to_string(),
        Value::String("li-benchmark-core-local-failure-identity-v1".to_string()),
    );
    identity.insert(
        "material_sha256".to_string(),
        Value::String(material_sha256.as_str().to_string()),
    );
    Ok(digest_bytes(&canonical_json_bytes(&Value::Object(
        identity,
    ))?))
}

// Returns a JSON digest or null for optional raw evidence identity.
fn optional_digest_value(value: Option<&Sha256Digest>) -> Value {
    value.map_or(Value::Null, |value| {
        Value::String(value.as_str().to_string())
    })
}

// Validates one optional digest field without accepting a missing field.
fn optional_digest(value: Option<&Value>) -> Result<(), BenchmarkError> {
    match value {
        Some(Value::Null) => Ok(()),
        Some(Value::String(value)) => Sha256Digest::parse(value)
            .map(|_| ())
            .map_err(|_| BenchmarkError::EvidenceRejected),
        Some(_) | None => Err(BenchmarkError::EvidenceRejected),
    }
}

// Requires one object to carry exactly the supplied closed fields.
fn require_fields(object: &Map<String, Value>, expected: &[&str]) -> Result<(), BenchmarkError> {
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    let observed = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if observed != expected {
        return Err(BenchmarkError::EvidenceRejected);
    }
    Ok(())
}

// Returns one required string field.
fn string<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str, BenchmarkError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or(BenchmarkError::EvidenceRejected)
}

// Returns one required unsigned integer field.
fn integer(object: &Map<String, Value>, field: &str) -> Result<u64, BenchmarkError> {
    object
        .get(field)
        .and_then(Value::as_u64)
        .ok_or(BenchmarkError::EvidenceRejected)
}

// Parses one required lowercase SHA-256 field.
fn digest(object: &Map<String, Value>, field: &str) -> Result<Sha256Digest, BenchmarkError> {
    Sha256Digest::parse(string(object, field)?).map_err(|_| BenchmarkError::EvidenceRejected)
}
