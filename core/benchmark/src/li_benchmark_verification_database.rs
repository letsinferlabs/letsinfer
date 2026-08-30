// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use li_core_interface::{
    InstallationId, LogicalModelName, OperationId, PlacementGroupId, RuntimeCandidateId,
    RuntimeInstallationId, Sha256Digest, UnixMilliseconds,
};
use li_database::{
    DatabaseCollection, DatabaseCommand, DatabaseCommitDisposition, DatabaseError, DatabaseManager,
    DatabaseQuery, DatabaseRecord, DatabaseResult, DatabaseRevision,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    BenchmarkEvidence, BenchmarkExecutionOutcome, BenchmarkFailure, BenchmarkFailureCategory,
    BenchmarkGitRevision, BenchmarkKind, BenchmarkRecordSchema, BenchmarkRequest,
    BenchmarkRestoration, BenchmarkScope, BenchmarkSignature, BenchmarkStoreError,
    BenchmarkSubject, BenchmarkTelemetryReceipt, BenchmarkVerificationArmState,
    BenchmarkVerificationChildResult, BenchmarkVerificationHandoffReceipt,
    BenchmarkVerificationPhase, BenchmarkVerificationStore, BenchmarkVerificationTransaction,
    PreparedBenchmark, RunningBenchmark, SealedBenchmarkEvidence,
    VersionedBenchmarkVerificationTransaction,
};

const SCHEMA_NAME: &str = "li_benchmark_verification_transaction";
const SCHEMA_VERSION: u32 = 1;
const IDENTIFIER_PREFIX: &str = "li_benchmark_verification_v1:";

// Stores one complete parent transaction in the shared Benchmark collection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct VerificationDatabaseRecord {
    schema_name: String,
    schema_version: u32,
    identifier: String,
    transaction: VerificationTransactionValue,
}

impl DatabaseRecord for VerificationDatabaseRecord {
    const COLLECTION: DatabaseCollection = DatabaseCollection::Benchmarks;

    // Returns the namespaced parent transaction identity.
    fn identifier(&self) -> &str {
        &self.identifier
    }
}

// Stores every parent phase field without any Runtime path or GitHub credential.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct VerificationTransactionValue {
    job_id: String,
    request_sha256: String,
    handoff: VerificationHandoffValue,
    phase: String,
    baseline: VerificationArmValue,
    candidate: Option<VerificationArmValue>,
    candidate_activation_receipt_id: Option<String>,
    baseline_restoration_receipt_id: Option<String>,
    cancellation_requested: bool,
    paired_results_sha256: Option<String>,
    created_at_unix_milliseconds: u64,
    updated_at_unix_milliseconds: u64,
}

// Stores one Node handoff identity and its two exact child requests.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct VerificationHandoffValue {
    transaction_id: String,
    receipt_id: String,
    bundle_sha256: String,
    baseline_request: VerificationRequestValue,
    candidate_request: VerificationRequestValue,
}

// Stores one complete request; paired children always use complete scope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct VerificationRequestValue {
    kind: VerificationKindValue,
    subject: VerificationSubjectValue,
}

// Stores local or exact community proposal identity without authority paths.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum VerificationKindValue {
    Local,
    Verification {
        pull_request: u64,
        proposal_head: String,
        candidate: String,
        transaction_id: String,
        verifier_bundle_sha256: String,
        candidate_subject_sha256: String,
        verifier_numeric_id: u64,
        device_id: String,
        baseline_execution_sha256: Option<String>,
    },
}

// Stores one exact Runtime/Placement benchmark subject.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct VerificationSubjectValue {
    installation_id: String,
    runtime_installation_id: String,
    model: String,
    placement_group_id: String,
    execution_sha256: String,
    benchmark_contract_sha256: String,
    target_contract_sha256: String,
}

// Stores child preparation, running, and terminal receipts in their strict order.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct VerificationArmValue {
    prepared_receipt_id: String,
    running_receipt_id: Option<String>,
    result: Option<VerificationChildResultValue>,
}

// Stores one independently restored, evidenced, and signed child terminal result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct VerificationChildResultValue {
    outcome: VerificationOutcomeValue,
    telemetry_receipt_id: String,
    telemetry_sample_count: u64,
    restoration_receipt_id: String,
    evidence_id: String,
    results_sha256: String,
    record_schema: String,
    evidence_bytes: u64,
    signature_key_id: String,
    signature: String,
    total_cells: u32,
}

// Stores one terminal child outcome and its bounded failure when present.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
enum VerificationOutcomeValue {
    Succeeded {
        raw_evidence_sha256: String,
        results_sha256: String,
        record_schema: String,
    },
    Failed {
        raw_evidence_sha256: Option<String>,
        failure_category: String,
        failure_phase: String,
        failure_message: String,
    },
    Cancelled {
        raw_evidence_sha256: Option<String>,
    },
}

// Adapts BenchmarkManager's paired parent state to DatabaseManager revisions.
pub struct DatabaseBenchmarkVerificationStore {
    database: Arc<DatabaseManager>,
}

impl DatabaseBenchmarkVerificationStore {
    // Creates one adapter without transferring DatabaseManager lifecycle ownership.
    pub const fn new(database: Arc<DatabaseManager>) -> Self {
        Self { database }
    }

    // Reads one exact validated parent transaction.
    fn read_transaction(
        &self,
        job_id: &OperationId,
    ) -> Result<Option<VersionedBenchmarkVerificationTransaction>, BenchmarkStoreError> {
        match self
            .database
            .read(DatabaseQuery::<VerificationDatabaseRecord>::record(
                identifier(job_id),
            )) {
            Ok(DatabaseResult::Record(stored)) => {
                Ok(Some(VersionedBenchmarkVerificationTransaction::new(
                    transaction(stored.value, job_id)?,
                    stored.revision,
                )?))
            }
            Ok(DatabaseResult::Records(_)) => Err(BenchmarkStoreError::Corrupt),
            Err(DatabaseError::NotFound { .. }) => Ok(None),
            Err(_) => Err(BenchmarkStoreError::Unavailable),
        }
    }
}

impl BenchmarkVerificationStore for DatabaseBenchmarkVerificationStore {
    // Reads one exact parent transaction without observing either leaf provider.
    fn read(
        &self,
        job_id: &OperationId,
    ) -> Result<Option<VersionedBenchmarkVerificationTransaction>, BenchmarkStoreError> {
        self.read_transaction(job_id)
    }

    // Creates one parent transaction exactly once.
    fn create(
        &self,
        transaction: BenchmarkVerificationTransaction,
    ) -> Result<VersionedBenchmarkVerificationTransaction, BenchmarkStoreError> {
        let record = record(&transaction)?;
        let result = self
            .database
            .write(DatabaseCommand::save(
                idempotency_key("create", &record, 0)?,
                record,
                DatabaseRevision::Missing,
            ))
            .map_err(database_error)?;
        if result.disposition() == DatabaseCommitDisposition::Replayed {
            return Err(BenchmarkStoreError::Conflict);
        }
        VersionedBenchmarkVerificationTransaction::new(transaction, result.commit().revision)
    }

    // Replaces one exact optimistic parent revision.
    fn replace(
        &self,
        transaction: BenchmarkVerificationTransaction,
        expected_revision: u64,
    ) -> Result<VersionedBenchmarkVerificationTransaction, BenchmarkStoreError> {
        if expected_revision == 0 {
            return Err(BenchmarkStoreError::Conflict);
        }
        let record = record(&transaction)?;
        let result = self
            .database
            .write(DatabaseCommand::save(
                idempotency_key("replace", &record, expected_revision)?,
                record,
                DatabaseRevision::Exact(expected_revision),
            ))
            .map_err(database_error)?;
        if result.disposition() == DatabaseCommitDisposition::Replayed {
            let replay = self
                .read_transaction(transaction.job_id())?
                .ok_or(BenchmarkStoreError::Conflict)?;
            if replay.revision() != expected_revision.saturating_add(1)
                || replay.transaction() != &transaction
            {
                return Err(BenchmarkStoreError::Conflict);
            }
            return Ok(replay);
        }
        VersionedBenchmarkVerificationTransaction::new(transaction, result.commit().revision)
    }
}

// Projects one validated parent transaction into the closed private database record.
fn record(
    transaction: &BenchmarkVerificationTransaction,
) -> Result<VerificationDatabaseRecord, BenchmarkStoreError> {
    Ok(VerificationDatabaseRecord {
        schema_name: SCHEMA_NAME.to_string(),
        schema_version: SCHEMA_VERSION,
        identifier: identifier(transaction.job_id()),
        transaction: VerificationTransactionValue {
            job_id: transaction.job_id().as_str().to_string(),
            request_sha256: transaction.request_sha256().as_str().to_string(),
            handoff: handoff_value(transaction.handoff()),
            phase: phase_name(transaction.phase()).to_string(),
            baseline: arm_value(transaction.baseline()),
            candidate: transaction.candidate().map(arm_value),
            candidate_activation_receipt_id: transaction
                .candidate_activation_receipt_id()
                .map(|value| value.as_str().to_string()),
            baseline_restoration_receipt_id: transaction
                .baseline_restoration_receipt_id()
                .map(|value| value.as_str().to_string()),
            cancellation_requested: transaction.cancellation_requested(),
            paired_results_sha256: transaction
                .paired_results_sha256()
                .map(|value| value.as_str().to_string()),
            created_at_unix_milliseconds: transaction.created_at().value(),
            updated_at_unix_milliseconds: transaction.updated_at().value(),
        },
    })
}

// Reconstructs one database record and reapplies every parent phase invariant.
fn transaction(
    record: VerificationDatabaseRecord,
    expected_job_id: &OperationId,
) -> Result<BenchmarkVerificationTransaction, BenchmarkStoreError> {
    if record.schema_name != SCHEMA_NAME
        || record.schema_version != SCHEMA_VERSION
        || record.identifier != identifier(expected_job_id)
        || record.transaction.job_id != expected_job_id.as_str()
    {
        return Err(BenchmarkStoreError::Corrupt);
    }
    let value = record.transaction;
    BenchmarkVerificationTransaction::restore(
        parse_operation(&value.job_id)?,
        parse_digest(&value.request_sha256)?,
        handoff(value.handoff)?,
        phase(&value.phase)?,
        arm(value.baseline)?,
        value.candidate.map(arm).transpose()?,
        optional_digest(value.candidate_activation_receipt_id.as_deref())?,
        optional_digest(value.baseline_restoration_receipt_id.as_deref())?,
        value.cancellation_requested,
        optional_digest(value.paired_results_sha256.as_deref())?,
        UnixMilliseconds::new(value.created_at_unix_milliseconds),
        UnixMilliseconds::new(value.updated_at_unix_milliseconds),
    )
}

// Projects one Node handoff and its exact child requests.
fn handoff_value(value: &BenchmarkVerificationHandoffReceipt) -> VerificationHandoffValue {
    VerificationHandoffValue {
        transaction_id: value.transaction_id().as_str().to_string(),
        receipt_id: value.receipt_id().as_str().to_string(),
        bundle_sha256: value.bundle_sha256().as_str().to_string(),
        baseline_request: request_value(value.baseline_request()),
        candidate_request: request_value(value.candidate_request()),
    }
}

// Reconstructs one exact Node handoff receipt.
fn handoff(
    value: VerificationHandoffValue,
) -> Result<BenchmarkVerificationHandoffReceipt, BenchmarkStoreError> {
    BenchmarkVerificationHandoffReceipt::new(
        parse_operation(&value.transaction_id)?,
        parse_digest(&value.receipt_id)?,
        parse_digest(&value.bundle_sha256)?,
        request(value.baseline_request)?,
        request(value.candidate_request)?,
    )
    .map_err(|_| BenchmarkStoreError::Corrupt)
}

// Projects one complete child request into private database fields.
fn request_value(value: &BenchmarkRequest) -> VerificationRequestValue {
    let kind = match value.kind() {
        BenchmarkKind::Local => VerificationKindValue::Local,
        BenchmarkKind::Verification {
            pull_request,
            proposal_head,
            candidate,
            transaction_id,
            verifier_bundle_sha256,
            candidate_subject_sha256,
            verifier_numeric_id,
            device_id,
            baseline_execution_sha256,
        } => VerificationKindValue::Verification {
            pull_request: *pull_request,
            proposal_head: proposal_head.as_str().to_string(),
            candidate: candidate.as_str().to_string(),
            transaction_id: transaction_id.as_str().to_string(),
            verifier_bundle_sha256: verifier_bundle_sha256.as_str().to_string(),
            candidate_subject_sha256: candidate_subject_sha256.as_str().to_string(),
            verifier_numeric_id: *verifier_numeric_id,
            device_id: device_id.as_str().to_string(),
            baseline_execution_sha256: baseline_execution_sha256
                .as_ref()
                .map(|value| value.as_str().to_string()),
        },
    };
    let subject = value.subject();
    VerificationRequestValue {
        kind,
        subject: VerificationSubjectValue {
            installation_id: subject.installation_id().as_str().to_string(),
            runtime_installation_id: subject.runtime_installation_id().as_str().to_string(),
            model: subject.model().as_str().to_string(),
            placement_group_id: subject.placement_group_id().as_str().to_string(),
            execution_sha256: subject.execution_sha256().as_str().to_string(),
            benchmark_contract_sha256: subject.benchmark_contract_sha256().as_str().to_string(),
            target_contract_sha256: subject.target_contract_sha256().as_str().to_string(),
        },
    }
}

// Reconstructs one complete child request without accepting selected workload scope.
fn request(value: VerificationRequestValue) -> Result<BenchmarkRequest, BenchmarkStoreError> {
    let kind = match value.kind {
        VerificationKindValue::Local => BenchmarkKind::Local,
        VerificationKindValue::Verification {
            pull_request,
            proposal_head,
            candidate,
            transaction_id,
            verifier_bundle_sha256,
            candidate_subject_sha256,
            verifier_numeric_id,
            device_id,
            baseline_execution_sha256,
        } => BenchmarkKind::verification(
            pull_request,
            BenchmarkGitRevision::parse(&proposal_head)
                .map_err(|_| BenchmarkStoreError::Corrupt)?,
            RuntimeCandidateId::parse(&candidate).map_err(|_| BenchmarkStoreError::Corrupt)?,
            parse_operation(&transaction_id)?,
            parse_digest(&verifier_bundle_sha256)?,
            parse_digest(&candidate_subject_sha256)?,
            verifier_numeric_id,
            parse_digest(&device_id)?,
            optional_digest(baseline_execution_sha256.as_deref())?,
        )
        .map_err(|_| BenchmarkStoreError::Corrupt)?,
    };
    let subject = value.subject;
    BenchmarkRequest::new(
        kind,
        BenchmarkScope::Complete,
        BenchmarkSubject::new(
            InstallationId::parse(&subject.installation_id)
                .map_err(|_| BenchmarkStoreError::Corrupt)?,
            RuntimeInstallationId::parse(&subject.runtime_installation_id)
                .map_err(|_| BenchmarkStoreError::Corrupt)?,
            LogicalModelName::parse(&subject.model).map_err(|_| BenchmarkStoreError::Corrupt)?,
            PlacementGroupId::parse(&subject.placement_group_id)
                .map_err(|_| BenchmarkStoreError::Corrupt)?,
            parse_digest(&subject.execution_sha256)?,
            parse_digest(&subject.benchmark_contract_sha256)?,
            parse_digest(&subject.target_contract_sha256)?,
        ),
    )
    .map_err(|_| BenchmarkStoreError::Corrupt)
}

// Projects one child state and optional complete result.
fn arm_value(value: &BenchmarkVerificationArmState) -> VerificationArmValue {
    VerificationArmValue {
        prepared_receipt_id: value.prepared_receipt().receipt_id().as_str().to_string(),
        running_receipt_id: value
            .running_receipt()
            .map(|receipt| receipt.receipt_id().as_str().to_string()),
        result: value.result().map(result_value),
    }
}

// Reconstructs one child state and receipt ordering.
fn arm(value: VerificationArmValue) -> Result<BenchmarkVerificationArmState, BenchmarkStoreError> {
    BenchmarkVerificationArmState::restore(
        PreparedBenchmark::new(parse_digest(&value.prepared_receipt_id)?),
        optional_digest(value.running_receipt_id.as_deref())?.map(RunningBenchmark::new),
        value.result.map(result).transpose()?,
    )
}

// Projects one complete child terminal result.
fn result_value(value: &BenchmarkVerificationChildResult) -> VerificationChildResultValue {
    VerificationChildResultValue {
        outcome: outcome_value(value.outcome()),
        telemetry_receipt_id: value.telemetry().receipt_id().as_str().to_string(),
        telemetry_sample_count: value.telemetry().sample_count(),
        restoration_receipt_id: value.restoration().receipt_id().as_str().to_string(),
        evidence_id: value
            .evidence()
            .evidence()
            .evidence_id()
            .as_str()
            .to_string(),
        results_sha256: value
            .evidence()
            .evidence()
            .results_sha256()
            .as_str()
            .to_string(),
        record_schema: schema_name(value.evidence().evidence().schema()).to_string(),
        evidence_bytes: value.evidence().evidence().byte_count(),
        signature_key_id: value.evidence().signature().key_id().as_str().to_string(),
        signature: value.evidence().signature().value().to_string(),
        total_cells: value.total_cells(),
    }
}

// Reconstructs one complete child terminal result and its identity bindings.
fn result(
    value: VerificationChildResultValue,
) -> Result<BenchmarkVerificationChildResult, BenchmarkStoreError> {
    let schema = schema(&value.record_schema)?;
    BenchmarkVerificationChildResult::new(
        outcome(value.outcome)?,
        BenchmarkTelemetryReceipt::new(
            parse_digest(&value.telemetry_receipt_id)?,
            value.telemetry_sample_count,
        ),
        BenchmarkRestoration::new(parse_digest(&value.restoration_receipt_id)?),
        SealedBenchmarkEvidence::new(
            BenchmarkEvidence::new(
                parse_digest(&value.evidence_id)?,
                parse_digest(&value.results_sha256)?,
                schema,
                value.evidence_bytes,
            )
            .map_err(|_| BenchmarkStoreError::Corrupt)?,
            BenchmarkSignature::new(parse_digest(&value.signature_key_id)?, &value.signature)
                .map_err(|_| BenchmarkStoreError::Corrupt)?,
        ),
        value.total_cells,
    )
    .map_err(|_| BenchmarkStoreError::Corrupt)
}

// Projects one child execution outcome.
fn outcome_value(value: &BenchmarkExecutionOutcome) -> VerificationOutcomeValue {
    match value {
        BenchmarkExecutionOutcome::Succeeded {
            raw_evidence_sha256,
            results_sha256,
            record_schema,
        } => VerificationOutcomeValue::Succeeded {
            raw_evidence_sha256: raw_evidence_sha256.as_str().to_string(),
            results_sha256: results_sha256.as_str().to_string(),
            record_schema: schema_name(*record_schema).to_string(),
        },
        BenchmarkExecutionOutcome::Failed {
            raw_evidence_sha256,
            failure,
        } => VerificationOutcomeValue::Failed {
            raw_evidence_sha256: raw_evidence_sha256
                .as_ref()
                .map(|value| value.as_str().to_string()),
            failure_category: failure.category().as_str().to_string(),
            failure_phase: failure.phase().as_str().to_string(),
            failure_message: failure.description().message().to_string(),
        },
        BenchmarkExecutionOutcome::Cancelled {
            raw_evidence_sha256,
        } => VerificationOutcomeValue::Cancelled {
            raw_evidence_sha256: raw_evidence_sha256
                .as_ref()
                .map(|value| value.as_str().to_string()),
        },
    }
}

// Reconstructs one exact child outcome and bounded failure taxonomy.
fn outcome(
    value: VerificationOutcomeValue,
) -> Result<BenchmarkExecutionOutcome, BenchmarkStoreError> {
    match value {
        VerificationOutcomeValue::Succeeded {
            raw_evidence_sha256,
            results_sha256,
            record_schema,
        } => Ok(BenchmarkExecutionOutcome::Succeeded {
            raw_evidence_sha256: parse_digest(&raw_evidence_sha256)?,
            results_sha256: parse_digest(&results_sha256)?,
            record_schema: schema(&record_schema)?,
        }),
        VerificationOutcomeValue::Failed {
            raw_evidence_sha256,
            failure_category,
            failure_phase,
            failure_message,
        } => Ok(BenchmarkExecutionOutcome::Failed {
            raw_evidence_sha256: optional_digest(raw_evidence_sha256.as_deref())?,
            failure: BenchmarkFailure::new(
                failure_category_value(&failure_category)?,
                &failure_phase,
                &failure_message,
            )
            .map_err(|_| BenchmarkStoreError::Corrupt)?,
        }),
        VerificationOutcomeValue::Cancelled {
            raw_evidence_sha256,
        } => Ok(BenchmarkExecutionOutcome::Cancelled {
            raw_evidence_sha256: optional_digest(raw_evidence_sha256.as_deref())?,
        }),
    }
}

// Returns one parent phase persistence name.
fn phase_name(value: BenchmarkVerificationPhase) -> &'static str {
    match value {
        BenchmarkVerificationPhase::Prepared => "prepared",
        BenchmarkVerificationPhase::BaselineRunning => "baseline_running",
        BenchmarkVerificationPhase::BaselineComplete => "baseline_complete",
        BenchmarkVerificationPhase::CandidateRunning => "candidate_running",
        BenchmarkVerificationPhase::CandidateComplete => "candidate_complete",
        BenchmarkVerificationPhase::Restoring => "restoring",
        BenchmarkVerificationPhase::Restored => "restored",
        BenchmarkVerificationPhase::RestorationFailed => "restoration_failed",
    }
}

// Reconstructs one exact parent phase.
fn phase(value: &str) -> Result<BenchmarkVerificationPhase, BenchmarkStoreError> {
    match value {
        "prepared" => Ok(BenchmarkVerificationPhase::Prepared),
        "baseline_running" => Ok(BenchmarkVerificationPhase::BaselineRunning),
        "baseline_complete" => Ok(BenchmarkVerificationPhase::BaselineComplete),
        "candidate_running" => Ok(BenchmarkVerificationPhase::CandidateRunning),
        "candidate_complete" => Ok(BenchmarkVerificationPhase::CandidateComplete),
        "restoring" => Ok(BenchmarkVerificationPhase::Restoring),
        "restored" => Ok(BenchmarkVerificationPhase::Restored),
        "restoration_failed" => Ok(BenchmarkVerificationPhase::RestorationFailed),
        _ => Err(BenchmarkStoreError::Corrupt),
    }
}

// Returns one child record schema persistence name.
fn schema_name(value: BenchmarkRecordSchema) -> &'static str {
    match value {
        BenchmarkRecordSchema::OciExecutionPayloadV7 => "oci_execution_payload_v7",
        BenchmarkRecordSchema::NativeExecutionPayloadV8 => "native_execution_payload_v8",
        BenchmarkRecordSchema::CoreLocalFailureV1 => "core_local_failure_v1",
        BenchmarkRecordSchema::CommunityVerificationV1 => "community_verification_v1",
    }
}

// Reconstructs only child-supported evidence schemas.
fn schema(value: &str) -> Result<BenchmarkRecordSchema, BenchmarkStoreError> {
    match value {
        "oci_execution_payload_v7" => Ok(BenchmarkRecordSchema::OciExecutionPayloadV7),
        "native_execution_payload_v8" => Ok(BenchmarkRecordSchema::NativeExecutionPayloadV8),
        "core_local_failure_v1" => Ok(BenchmarkRecordSchema::CoreLocalFailureV1),
        _ => Err(BenchmarkStoreError::Corrupt),
    }
}

// Reconstructs one stable blocking failure category.
fn failure_category_value(value: &str) -> Result<BenchmarkFailureCategory, BenchmarkStoreError> {
    match value {
        "crash" => Ok(BenchmarkFailureCategory::Crash),
        "out_of_memory" => Ok(BenchmarkFailureCategory::OutOfMemory),
        "protection_trip" => Ok(BenchmarkFailureCategory::ProtectionTrip),
        "output_validation" => Ok(BenchmarkFailureCategory::OutputValidation),
        "incomplete_workload" => Ok(BenchmarkFailureCategory::IncompleteWorkload),
        "restoration" => Ok(BenchmarkFailureCategory::Restoration),
        _ => Err(BenchmarkStoreError::Corrupt),
    }
}

// Returns one namespaced database identifier.
fn identifier(job_id: &OperationId) -> String {
    format!("{IDENTIFIER_PREFIX}{}", job_id.as_str())
}

// Derives one bounded idempotency key from the complete database payload and expected revision.
fn idempotency_key(
    action: &str,
    record: &VerificationDatabaseRecord,
    revision: u64,
) -> Result<String, BenchmarkStoreError> {
    let encoded = serde_json::to_vec(record).map_err(|_| BenchmarkStoreError::Corrupt)?;
    let mut digest = Sha256::new();
    digest.update((action.len() as u64).to_be_bytes());
    digest.update(action.as_bytes());
    digest.update(revision.to_be_bytes());
    digest.update((encoded.len() as u64).to_be_bytes());
    digest.update(encoded);
    Ok(format!(
        "li_benchmark_verification_{action}_v1:{:x}",
        digest.finalize()
    ))
}

// Maps DatabaseManager failures into the manager's stable store boundary.
fn database_error(value: DatabaseError) -> BenchmarkStoreError {
    match value {
        DatabaseError::Conflict { .. } | DatabaseError::IdempotencyConflict { .. } => {
            BenchmarkStoreError::Conflict
        }
        DatabaseError::InvalidInput { .. } | DatabaseError::Corrupt { .. } => {
            BenchmarkStoreError::Corrupt
        }
        _ => BenchmarkStoreError::Unavailable,
    }
}

// Parses one exact operation identity.
fn parse_operation(value: &str) -> Result<OperationId, BenchmarkStoreError> {
    OperationId::parse(value).map_err(|_| BenchmarkStoreError::Corrupt)
}

// Parses one exact lowercase SHA-256.
fn parse_digest(value: &str) -> Result<Sha256Digest, BenchmarkStoreError> {
    Sha256Digest::parse(value).map_err(|_| BenchmarkStoreError::Corrupt)
}

// Parses one optional exact lowercase SHA-256.
fn optional_digest(value: Option<&str>) -> Result<Option<Sha256Digest>, BenchmarkStoreError> {
    value.map(parse_digest).transpose()
}
