// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use li_core_interface::{
    InstallationId, LogicalModelName, OperationId, PlacementGroupId, RuntimeCandidateId,
    RuntimeInstallationId, Sha256Digest, TechnicalName, UnixMilliseconds,
};
use li_database::{
    DatabaseCollection, DatabaseCommit, DatabaseCommitDisposition, DatabaseError, DatabaseManager,
    DatabaseMutation, DatabaseQuery, DatabaseRecord, DatabaseResult, DatabaseRevision,
    DatabaseTransaction,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::li_benchmark_contract::benchmark_job_id;
use crate::{
    BenchmarkAuthorization, BenchmarkEvidence, BenchmarkExecutionOutcome, BenchmarkFailure,
    BenchmarkFailureCategory, BenchmarkGitRevision, BenchmarkJobPhase, BenchmarkJobRecord,
    BenchmarkKind, BenchmarkProgress, BenchmarkPublication, BenchmarkRecordSchema,
    BenchmarkRequest, BenchmarkRestoration, BenchmarkScope, BenchmarkSignature, BenchmarkStore,
    BenchmarkStoreError, BenchmarkSubject, BenchmarkTelemetryReceipt, BenchmarkTerminalIntent,
    PreparedBenchmark, RunningBenchmark, SealedBenchmarkEvidence, VersionedBenchmarkJob,
};

const ACTIVE_RECORD_IDENTIFIER: &str = "li_benchmark_active_v1";
const DATABASE_SCHEMA_NAME: &str = "li_benchmark_journal";
const DATABASE_SCHEMA_VERSION: u32 = 1;
const JOB_RECORD_PREFIX: &str = "li_benchmark_job_v1:";

// Identifies the closed private schema stored in each benchmark database record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct BenchmarkDatabaseSchema {
    name: String,
    version: u32,
}

impl BenchmarkDatabaseSchema {
    // Creates the one supported private benchmark journal schema identity.
    fn current() -> Self {
        Self {
            name: DATABASE_SCHEMA_NAME.to_string(),
            version: DATABASE_SCHEMA_VERSION,
        }
    }

    // Rejects unknown private persistence schemas before interpreting their contents.
    fn validate(&self) -> Result<(), BenchmarkStoreError> {
        if self.name != DATABASE_SCHEMA_NAME || self.version != DATABASE_SCHEMA_VERSION {
            return Err(BenchmarkStoreError::Corrupt);
        }
        Ok(())
    }
}

// Stores every row in the benchmark collection through one decodable record union.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "record_type", rename_all = "snake_case", deny_unknown_fields)]
enum BenchmarkDatabaseRecord {
    Active {
        schema: BenchmarkDatabaseSchema,
        identifier: String,
        job_id: String,
        replay_sha256: String,
    },
    Journal {
        schema: BenchmarkDatabaseSchema,
        identifier: String,
        journal: BenchmarkJournalDatabaseValue,
    },
}

impl BenchmarkDatabaseRecord {
    // Projects one active benchmark into the collection's atomic ownership record.
    fn active(record: &BenchmarkJobRecord) -> Self {
        Self::Active {
            schema: BenchmarkDatabaseSchema::current(),
            identifier: ACTIVE_RECORD_IDENTIFIER.to_string(),
            job_id: record.job_id().as_str().to_string(),
            replay_sha256: record.replay_sha256().as_str().to_string(),
        }
    }

    // Projects one validated benchmark journal into its private persistence shape.
    fn journal(record: &BenchmarkJobRecord) -> Self {
        Self::Journal {
            schema: BenchmarkDatabaseSchema::current(),
            identifier: journal_identifier(record.job_id()),
            journal: BenchmarkJournalDatabaseValue::from_record(record),
        }
    }

    // Validates and returns one active pointer identity pair.
    fn active_identity(&self) -> Result<(OperationId, Sha256Digest), BenchmarkStoreError> {
        let Self::Active {
            schema,
            identifier,
            job_id,
            replay_sha256,
        } = self
        else {
            return Err(BenchmarkStoreError::Corrupt);
        };
        schema.validate()?;
        if identifier != ACTIVE_RECORD_IDENTIFIER {
            return Err(BenchmarkStoreError::Corrupt);
        }
        Ok((parse_operation_id(job_id)?, parse_digest(replay_sha256)?))
    }

    // Validates and reconstructs one exact benchmark journal.
    fn into_journal(
        self,
        expected_job_id: &OperationId,
    ) -> Result<BenchmarkJobRecord, BenchmarkStoreError> {
        let Self::Journal {
            schema,
            identifier,
            journal,
        } = self
        else {
            return Err(BenchmarkStoreError::Corrupt);
        };
        schema.validate()?;
        if identifier != journal_identifier(expected_job_id) {
            return Err(BenchmarkStoreError::Corrupt);
        }
        let record = journal.into_record()?;
        if record.job_id() != expected_job_id {
            return Err(BenchmarkStoreError::Corrupt);
        }
        Ok(record)
    }

    // Derives and validates the operation identity carried by one arbitrary journal row.
    fn into_any_journal(self) -> Result<BenchmarkJobRecord, BenchmarkStoreError> {
        let identifier = match &self {
            Self::Journal { identifier, .. } => identifier,
            Self::Active { .. } => return Err(BenchmarkStoreError::Corrupt),
        };
        let job_id = identifier
            .strip_prefix(JOB_RECORD_PREFIX)
            .ok_or(BenchmarkStoreError::Corrupt)
            .and_then(parse_operation_id)?;
        self.into_journal(&job_id)
    }
}

impl DatabaseRecord for BenchmarkDatabaseRecord {
    const COLLECTION: DatabaseCollection = DatabaseCollection::Benchmarks;

    // Returns the exact active-pointer or journal row identity.
    fn identifier(&self) -> &str {
        match self {
            Self::Active { identifier, .. } | Self::Journal { identifier, .. } => identifier,
        }
    }
}

// Stores one complete benchmark journal without exposing persistence types to the manager.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct BenchmarkJournalDatabaseValue {
    job_id: String,
    replay_sha256: String,
    request_sha256: String,
    request: BenchmarkRequestDatabaseValue,
    authorization_receipt_id: String,
    phase: BenchmarkPhaseDatabaseValue,
    prepared_receipt_id: Option<String>,
    execution_receipt_id: Option<String>,
    progress: Option<BenchmarkProgressDatabaseValue>,
    terminal_intent: Option<BenchmarkTerminalIntentDatabaseValue>,
    outcome: Option<BenchmarkExecutionOutcomeDatabaseValue>,
    telemetry: Option<BenchmarkTelemetryDatabaseValue>,
    restoration_receipt_id: Option<String>,
    evidence: Option<SealedBenchmarkEvidenceDatabaseValue>,
    publication: Option<BenchmarkPublicationDatabaseValue>,
    created_at_unix_milliseconds: u64,
    updated_at_unix_milliseconds: u64,
}

impl BenchmarkJournalDatabaseValue {
    // Projects every restart-relevant field from one validated journal.
    fn from_record(record: &BenchmarkJobRecord) -> Self {
        Self {
            job_id: record.job_id().as_str().to_string(),
            replay_sha256: record.replay_sha256().as_str().to_string(),
            request_sha256: record.request_sha256().as_str().to_string(),
            request: BenchmarkRequestDatabaseValue::from_request(record.request()),
            authorization_receipt_id: record.authorization().receipt_id().as_str().to_string(),
            phase: BenchmarkPhaseDatabaseValue::from_phase(record.phase()),
            prepared_receipt_id: record
                .prepared()
                .map(|receipt| receipt.receipt_id().as_str().to_string()),
            execution_receipt_id: record
                .execution()
                .map(|receipt| receipt.receipt_id().as_str().to_string()),
            progress: record
                .progress()
                .map(BenchmarkProgressDatabaseValue::from_progress),
            terminal_intent: record
                .terminal_intent
                .as_ref()
                .map(BenchmarkTerminalIntentDatabaseValue::from_intent),
            outcome: record
                .outcome()
                .map(BenchmarkExecutionOutcomeDatabaseValue::from_outcome),
            telemetry: record
                .telemetry()
                .map(BenchmarkTelemetryDatabaseValue::from_receipt),
            restoration_receipt_id: record
                .restoration()
                .map(|receipt| receipt.receipt_id().as_str().to_string()),
            evidence: record
                .evidence()
                .map(SealedBenchmarkEvidenceDatabaseValue::from_evidence),
            publication: record
                .publication()
                .map(BenchmarkPublicationDatabaseValue::from_publication),
            created_at_unix_milliseconds: record.created_at().value(),
            updated_at_unix_milliseconds: record.updated_at().value(),
        }
    }

    // Reconstructs the typed journal and reapplies every manager-owned invariant.
    fn into_record(self) -> Result<BenchmarkJobRecord, BenchmarkStoreError> {
        BenchmarkJobRecord::restore(
            parse_operation_id(&self.job_id)?,
            parse_digest(&self.replay_sha256)?,
            parse_digest(&self.request_sha256)?,
            self.request.into_request()?,
            BenchmarkAuthorization::new(parse_digest(&self.authorization_receipt_id)?),
            self.phase.into_phase(),
            optional_digest(self.prepared_receipt_id.as_deref())?.map(PreparedBenchmark::new),
            optional_digest(self.execution_receipt_id.as_deref())?.map(RunningBenchmark::new),
            self.progress
                .map(BenchmarkProgressDatabaseValue::into_progress)
                .transpose()?,
            self.terminal_intent
                .map(BenchmarkTerminalIntentDatabaseValue::into_intent)
                .transpose()?,
            self.outcome
                .map(BenchmarkExecutionOutcomeDatabaseValue::into_outcome)
                .transpose()?,
            self.telemetry
                .map(BenchmarkTelemetryDatabaseValue::into_receipt)
                .transpose()?,
            optional_digest(self.restoration_receipt_id.as_deref())?.map(BenchmarkRestoration::new),
            self.evidence
                .map(SealedBenchmarkEvidenceDatabaseValue::into_evidence)
                .transpose()?,
            self.publication
                .map(BenchmarkPublicationDatabaseValue::into_publication)
                .transpose()?,
            UnixMilliseconds::new(self.created_at_unix_milliseconds),
            UnixMilliseconds::new(self.updated_at_unix_milliseconds),
        )
        .map_err(|_| BenchmarkStoreError::Corrupt)
    }
}

// Stores one exact local or community-verification request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct BenchmarkRequestDatabaseValue {
    kind: BenchmarkKindDatabaseValue,
    scope: BenchmarkScopeDatabaseValue,
    subject: BenchmarkSubjectDatabaseValue,
}

impl BenchmarkRequestDatabaseValue {
    // Projects one immutable request without changing its fingerprint inputs.
    fn from_request(request: &BenchmarkRequest) -> Self {
        Self {
            kind: BenchmarkKindDatabaseValue::from_kind(request.kind()),
            scope: BenchmarkScopeDatabaseValue::from_scope(request.scope()),
            subject: BenchmarkSubjectDatabaseValue::from_subject(request.subject()),
        }
    }

    // Reconstructs one request and reapplies verification-scope policy.
    fn into_request(self) -> Result<BenchmarkRequest, BenchmarkStoreError> {
        BenchmarkRequest::new(
            self.kind.into_kind()?,
            self.scope.into_scope()?,
            self.subject.into_subject()?,
        )
        .map_err(|_| BenchmarkStoreError::Corrupt)
    }
}

// Stores the closed local or verification mode without repository credentials.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum BenchmarkKindDatabaseValue {
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

impl BenchmarkKindDatabaseValue {
    // Projects one benchmark mode into its closed persistence union.
    fn from_kind(kind: &BenchmarkKind) -> Self {
        match kind {
            BenchmarkKind::Local => Self::Local,
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
            } => Self::Verification {
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
                    .map(|digest| digest.as_str().to_string()),
            },
        }
    }

    // Reconstructs one benchmark mode with exact proposal and verifier identities.
    fn into_kind(self) -> Result<BenchmarkKind, BenchmarkStoreError> {
        match self {
            Self::Local => Ok(BenchmarkKind::Local),
            Self::Verification {
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
                OperationId::parse(&transaction_id).map_err(|_| BenchmarkStoreError::Corrupt)?,
                parse_digest(&verifier_bundle_sha256)?,
                parse_digest(&candidate_subject_sha256)?,
                verifier_numeric_id,
                parse_digest(&device_id)?,
                optional_digest(baseline_execution_sha256.as_deref())?,
            )
            .map_err(|_| BenchmarkStoreError::Corrupt),
        }
    }
}

// Stores either the complete matrix or one bounded diagnostic selection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "scope", rename_all = "snake_case", deny_unknown_fields)]
enum BenchmarkScopeDatabaseValue {
    Complete,
    Selected { cells: Vec<String> },
}

impl BenchmarkScopeDatabaseValue {
    // Projects one typed workload scope without reordering selected cells.
    fn from_scope(scope: &BenchmarkScope) -> Self {
        match scope {
            BenchmarkScope::Complete => Self::Complete,
            BenchmarkScope::Selected(cells) => Self::Selected {
                cells: cells.iter().map(|cell| cell.as_str().to_string()).collect(),
            },
        }
    }

    // Reconstructs one bounded unique workload scope.
    fn into_scope(self) -> Result<BenchmarkScope, BenchmarkStoreError> {
        match self {
            Self::Complete => Ok(BenchmarkScope::Complete),
            Self::Selected { cells } => BenchmarkScope::selected(
                cells
                    .iter()
                    .map(|cell| {
                        TechnicalName::parse(cell).map_err(|_| BenchmarkStoreError::Corrupt)
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            )
            .map_err(|_| BenchmarkStoreError::Corrupt),
        }
    }
}

// Stores the immutable runtime, model, placement, and contract subject.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct BenchmarkSubjectDatabaseValue {
    installation_id: String,
    runtime_installation_id: String,
    model: String,
    placement_group_id: String,
    execution_sha256: String,
    benchmark_contract_sha256: String,
    target_contract_sha256: String,
}

impl BenchmarkSubjectDatabaseValue {
    // Projects one complete immutable execution subject.
    fn from_subject(subject: &BenchmarkSubject) -> Self {
        Self {
            installation_id: subject.installation_id().as_str().to_string(),
            runtime_installation_id: subject.runtime_installation_id().as_str().to_string(),
            model: subject.model().as_str().to_string(),
            placement_group_id: subject.placement_group_id().as_str().to_string(),
            execution_sha256: subject.execution_sha256().as_str().to_string(),
            benchmark_contract_sha256: subject.benchmark_contract_sha256().as_str().to_string(),
            target_contract_sha256: subject.target_contract_sha256().as_str().to_string(),
        }
    }

    // Reconstructs one exact execution subject from canonical identities.
    fn into_subject(self) -> Result<BenchmarkSubject, BenchmarkStoreError> {
        Ok(BenchmarkSubject::new(
            InstallationId::parse(&self.installation_id)
                .map_err(|_| BenchmarkStoreError::Corrupt)?,
            RuntimeInstallationId::parse(&self.runtime_installation_id)
                .map_err(|_| BenchmarkStoreError::Corrupt)?,
            LogicalModelName::parse(&self.model).map_err(|_| BenchmarkStoreError::Corrupt)?,
            PlacementGroupId::parse(&self.placement_group_id)
                .map_err(|_| BenchmarkStoreError::Corrupt)?,
            parse_digest(&self.execution_sha256)?,
            parse_digest(&self.benchmark_contract_sha256)?,
            parse_digest(&self.target_contract_sha256)?,
        ))
    }
}

// Stores one closed benchmark lifecycle phase.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum BenchmarkPhaseDatabaseValue {
    Requested,
    Prepared,
    Running,
    Stopping,
    Restoring,
    Finalizing,
    Completed,
    Failed,
    Cancelled,
}

impl BenchmarkPhaseDatabaseValue {
    // Projects one typed lifecycle phase into its stable persistence name.
    fn from_phase(phase: BenchmarkJobPhase) -> Self {
        match phase {
            BenchmarkJobPhase::Requested => Self::Requested,
            BenchmarkJobPhase::Prepared => Self::Prepared,
            BenchmarkJobPhase::Running => Self::Running,
            BenchmarkJobPhase::Stopping => Self::Stopping,
            BenchmarkJobPhase::Restoring => Self::Restoring,
            BenchmarkJobPhase::Finalizing => Self::Finalizing,
            BenchmarkJobPhase::Completed => Self::Completed,
            BenchmarkJobPhase::Failed => Self::Failed,
            BenchmarkJobPhase::Cancelled => Self::Cancelled,
        }
    }

    // Returns the corresponding typed lifecycle phase.
    fn into_phase(self) -> BenchmarkJobPhase {
        match self {
            Self::Requested => BenchmarkJobPhase::Requested,
            Self::Prepared => BenchmarkJobPhase::Prepared,
            Self::Running => BenchmarkJobPhase::Running,
            Self::Stopping => BenchmarkJobPhase::Stopping,
            Self::Restoring => BenchmarkJobPhase::Restoring,
            Self::Finalizing => BenchmarkJobPhase::Finalizing,
            Self::Completed => BenchmarkJobPhase::Completed,
            Self::Failed => BenchmarkJobPhase::Failed,
            Self::Cancelled => BenchmarkJobPhase::Cancelled,
        }
    }
}

// Stores one bounded progress snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct BenchmarkProgressDatabaseValue {
    phase: String,
    completed_cells: u32,
    total_cells: u32,
}

impl BenchmarkProgressDatabaseValue {
    // Projects one validated progress snapshot.
    fn from_progress(progress: &BenchmarkProgress) -> Self {
        Self {
            phase: progress.phase().as_str().to_string(),
            completed_cells: progress.completed_cells(),
            total_cells: progress.total_cells(),
        }
    }

    // Reconstructs one coherent progress snapshot.
    fn into_progress(self) -> Result<BenchmarkProgress, BenchmarkStoreError> {
        BenchmarkProgress::new(
            TechnicalName::parse(&self.phase).map_err(|_| BenchmarkStoreError::Corrupt)?,
            self.completed_cells,
            self.total_cells,
        )
        .map_err(|_| BenchmarkStoreError::Corrupt)
    }
}

// Stores one terminal intent before the worker has actually exited.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "intent", rename_all = "snake_case", deny_unknown_fields)]
enum BenchmarkTerminalIntentDatabaseValue {
    Failed {
        failure: BenchmarkFailureDatabaseValue,
    },
    Cancelled,
}

impl BenchmarkTerminalIntentDatabaseValue {
    // Projects one durable stop or failure intent.
    fn from_intent(intent: &BenchmarkTerminalIntent) -> Self {
        match intent {
            BenchmarkTerminalIntent::Failed(failure) => Self::Failed {
                failure: BenchmarkFailureDatabaseValue::from_failure(failure),
            },
            BenchmarkTerminalIntent::Cancelled => Self::Cancelled,
        }
    }

    // Reconstructs one typed terminal intent.
    fn into_intent(self) -> Result<BenchmarkTerminalIntent, BenchmarkStoreError> {
        match self {
            Self::Failed { failure } => {
                Ok(BenchmarkTerminalIntent::Failed(failure.into_failure()?))
            }
            Self::Cancelled => Ok(BenchmarkTerminalIntent::Cancelled),
        }
    }
}

// Stores one terminal execution outcome before restoration and evidence sealing.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
enum BenchmarkExecutionOutcomeDatabaseValue {
    Succeeded {
        raw_evidence_sha256: String,
        results_sha256: String,
        record_schema: BenchmarkEvidenceSchemaDatabaseValue,
    },
    Failed {
        raw_evidence_sha256: Option<String>,
        failure: BenchmarkFailureDatabaseValue,
    },
    Cancelled {
        raw_evidence_sha256: Option<String>,
    },
}

impl BenchmarkExecutionOutcomeDatabaseValue {
    // Projects one exact execution outcome and any immutable raw evidence identity.
    fn from_outcome(outcome: &BenchmarkExecutionOutcome) -> Self {
        match outcome {
            BenchmarkExecutionOutcome::Succeeded {
                raw_evidence_sha256,
                results_sha256,
                record_schema,
            } => Self::Succeeded {
                raw_evidence_sha256: raw_evidence_sha256.as_str().to_string(),
                results_sha256: results_sha256.as_str().to_string(),
                record_schema: BenchmarkEvidenceSchemaDatabaseValue::from_schema(*record_schema),
            },
            BenchmarkExecutionOutcome::Failed {
                raw_evidence_sha256,
                failure,
            } => Self::Failed {
                raw_evidence_sha256: raw_evidence_sha256
                    .as_ref()
                    .map(|digest| digest.as_str().to_string()),
                failure: BenchmarkFailureDatabaseValue::from_failure(failure),
            },
            BenchmarkExecutionOutcome::Cancelled {
                raw_evidence_sha256,
            } => Self::Cancelled {
                raw_evidence_sha256: raw_evidence_sha256
                    .as_ref()
                    .map(|digest| digest.as_str().to_string()),
            },
        }
    }

    // Reconstructs one terminal outcome without fabricating evidence or failures.
    fn into_outcome(self) -> Result<BenchmarkExecutionOutcome, BenchmarkStoreError> {
        match self {
            Self::Succeeded {
                raw_evidence_sha256,
                results_sha256,
                record_schema,
            } => Ok(BenchmarkExecutionOutcome::Succeeded {
                raw_evidence_sha256: parse_digest(&raw_evidence_sha256)?,
                results_sha256: parse_digest(&results_sha256)?,
                record_schema: record_schema.into_schema()?,
            }),
            Self::Failed {
                raw_evidence_sha256,
                failure,
            } => Ok(BenchmarkExecutionOutcome::Failed {
                raw_evidence_sha256: optional_digest(raw_evidence_sha256.as_deref())?,
                failure: failure.into_failure()?,
            }),
            Self::Cancelled {
                raw_evidence_sha256,
            } => Ok(BenchmarkExecutionOutcome::Cancelled {
                raw_evidence_sha256: optional_digest(raw_evidence_sha256.as_deref())?,
            }),
        }
    }
}

// Stores one bounded failure with both its category-derived code and presentation text.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct BenchmarkFailureDatabaseValue {
    category: BenchmarkFailureCategoryDatabaseValue,
    phase: String,
    code: String,
    message: String,
}

impl BenchmarkFailureDatabaseValue {
    // Projects one validated benchmark failure without dropping its stable code.
    fn from_failure(failure: &BenchmarkFailure) -> Self {
        Self {
            category: BenchmarkFailureCategoryDatabaseValue::from_category(failure.category()),
            phase: failure.phase().as_str().to_string(),
            code: failure.description().code().as_str().to_string(),
            message: failure.description().message().to_string(),
        }
    }

    // Reconstructs one bounded failure and verifies its category-derived code.
    fn into_failure(self) -> Result<BenchmarkFailure, BenchmarkStoreError> {
        let failure =
            BenchmarkFailure::new(self.category.into_category(), &self.phase, &self.message)
                .map_err(|_| BenchmarkStoreError::Corrupt)?;
        if failure.description().code().as_str() != self.code {
            return Err(BenchmarkStoreError::Corrupt);
        }
        Ok(failure)
    }
}

// Stores the closed published benchmark failure category vocabulary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum BenchmarkFailureCategoryDatabaseValue {
    Crash,
    OutOfMemory,
    ProtectionTrip,
    OutputValidation,
    IncompleteWorkload,
    Restoration,
}

impl BenchmarkFailureCategoryDatabaseValue {
    // Projects one typed failure category.
    fn from_category(category: BenchmarkFailureCategory) -> Self {
        match category {
            BenchmarkFailureCategory::Crash => Self::Crash,
            BenchmarkFailureCategory::OutOfMemory => Self::OutOfMemory,
            BenchmarkFailureCategory::ProtectionTrip => Self::ProtectionTrip,
            BenchmarkFailureCategory::OutputValidation => Self::OutputValidation,
            BenchmarkFailureCategory::IncompleteWorkload => Self::IncompleteWorkload,
            BenchmarkFailureCategory::Restoration => Self::Restoration,
        }
    }

    // Returns the corresponding typed failure category.
    fn into_category(self) -> BenchmarkFailureCategory {
        match self {
            Self::Crash => BenchmarkFailureCategory::Crash,
            Self::OutOfMemory => BenchmarkFailureCategory::OutOfMemory,
            Self::ProtectionTrip => BenchmarkFailureCategory::ProtectionTrip,
            Self::OutputValidation => BenchmarkFailureCategory::OutputValidation,
            Self::IncompleteWorkload => BenchmarkFailureCategory::IncompleteWorkload,
            Self::Restoration => BenchmarkFailureCategory::Restoration,
        }
    }
}

// Stores one immutable telemetry receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct BenchmarkTelemetryDatabaseValue {
    receipt_id: String,
    sample_count: u64,
}

impl BenchmarkTelemetryDatabaseValue {
    // Projects one complete telemetry receipt.
    fn from_receipt(receipt: &BenchmarkTelemetryReceipt) -> Self {
        Self {
            receipt_id: receipt.receipt_id().as_str().to_string(),
            sample_count: receipt.sample_count(),
        }
    }

    // Reconstructs one complete telemetry receipt.
    fn into_receipt(self) -> Result<BenchmarkTelemetryReceipt, BenchmarkStoreError> {
        Ok(BenchmarkTelemetryReceipt::new(
            parse_digest(&self.receipt_id)?,
            self.sample_count,
        ))
    }
}

// Stores the published execution-payload schema identity without renumbering it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct BenchmarkEvidenceSchemaDatabaseValue {
    name: String,
    version: u8,
}

impl BenchmarkEvidenceSchemaDatabaseValue {
    // Projects one exact successful or Core-local terminal record identity.
    fn from_schema(schema: BenchmarkRecordSchema) -> Self {
        let name = match schema {
            BenchmarkRecordSchema::OciExecutionPayloadV7 => "oci_execution_payload",
            BenchmarkRecordSchema::NativeExecutionPayloadV8 => "native_execution_payload",
            BenchmarkRecordSchema::CommunityVerificationV1 => "community_verification",
            BenchmarkRecordSchema::CoreLocalFailureV1 => "core_local_failure",
        };
        Self {
            name: name.to_string(),
            version: schema.version(),
        }
    }

    // Reconstructs only an exact supported name-and-version pair.
    fn into_schema(self) -> Result<BenchmarkRecordSchema, BenchmarkStoreError> {
        match (self.name.as_str(), self.version) {
            ("oci_execution_payload", 7) => Ok(BenchmarkRecordSchema::OciExecutionPayloadV7),
            ("native_execution_payload", 8) => Ok(BenchmarkRecordSchema::NativeExecutionPayloadV8),
            ("community_verification", 1) => Ok(BenchmarkRecordSchema::CommunityVerificationV1),
            ("core_local_failure", 1) => Ok(BenchmarkRecordSchema::CoreLocalFailureV1),
            _ => Err(BenchmarkStoreError::Corrupt),
        }
    }
}

// Stores one verified evidence receipt and its detached signature.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SealedBenchmarkEvidenceDatabaseValue {
    evidence_id: String,
    results_sha256: String,
    record_schema: BenchmarkEvidenceSchemaDatabaseValue,
    byte_count: u64,
    signature_key_id: String,
    signature: String,
}

impl SealedBenchmarkEvidenceDatabaseValue {
    // Projects one sealed evidence identity without materializing evidence bytes.
    fn from_evidence(sealed: &SealedBenchmarkEvidence) -> Self {
        Self {
            evidence_id: sealed.evidence().evidence_id().as_str().to_string(),
            results_sha256: sealed.evidence().results_sha256().as_str().to_string(),
            record_schema: BenchmarkEvidenceSchemaDatabaseValue::from_schema(
                sealed.evidence().schema(),
            ),
            byte_count: sealed.evidence().byte_count(),
            signature_key_id: sealed.signature().key_id().as_str().to_string(),
            signature: sealed.signature().value().to_string(),
        }
    }

    // Reconstructs one bounded evidence receipt with its exact published schema identity.
    fn into_evidence(self) -> Result<SealedBenchmarkEvidence, BenchmarkStoreError> {
        let evidence = BenchmarkEvidence::new(
            parse_digest(&self.evidence_id)?,
            parse_digest(&self.results_sha256)?,
            self.record_schema.into_schema()?,
            self.byte_count,
        )
        .map_err(|_| BenchmarkStoreError::Corrupt)?;
        let signature =
            BenchmarkSignature::new(parse_digest(&self.signature_key_id)?, &self.signature)
                .map_err(|_| BenchmarkStoreError::Corrupt)?;
        Ok(SealedBenchmarkEvidence::new(evidence, signature))
    }
}

// Stores one exact external GitHub publication receipt without comment or credential content.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct BenchmarkPublicationDatabaseValue {
    publication_id: String,
    verification_id: String,
    record_sha256: String,
    comment_body_sha256: String,
    pull_request: u64,
    proposal_head: String,
    candidate: String,
    candidate_benchmark_id: Option<String>,
    baseline_benchmark_id: Option<String>,
    score_sha256: String,
    restoration_id: String,
    evidence_id: String,
    device_id: String,
    signature_key_id: String,
    comment_id: u64,
    comment_url: String,
}

impl BenchmarkPublicationDatabaseValue {
    // Projects one exact verified publication receipt into closed storage fields.
    fn from_publication(publication: &BenchmarkPublication) -> Self {
        Self {
            publication_id: publication.publication_id().as_str().to_string(),
            verification_id: publication.verification_id().as_str().to_string(),
            record_sha256: publication.record_sha256().as_str().to_string(),
            comment_body_sha256: publication.comment_body_sha256().as_str().to_string(),
            pull_request: publication.pull_request(),
            proposal_head: publication.proposal_head().as_str().to_string(),
            candidate: publication.candidate().as_str().to_string(),
            candidate_benchmark_id: publication
                .candidate_benchmark_id()
                .map(|value| value.as_str().to_string()),
            baseline_benchmark_id: publication
                .baseline_benchmark_id()
                .map(|value| value.as_str().to_string()),
            score_sha256: publication.score_sha256().as_str().to_string(),
            restoration_id: publication.restoration_id().as_str().to_string(),
            evidence_id: publication.evidence_id().as_str().to_string(),
            device_id: publication.device_id().as_str().to_string(),
            signature_key_id: publication.signature_key_id().as_str().to_string(),
            comment_id: publication.comment_id(),
            comment_url: publication.comment_url().to_string(),
        }
    }

    // Reconstructs and revalidates one exact proposal/evidence/comment identity closure.
    fn into_publication(self) -> Result<BenchmarkPublication, BenchmarkStoreError> {
        let expected_publication_id = parse_digest(&self.publication_id)?;
        let publication = BenchmarkPublication::new(
            parse_digest(&self.verification_id)?,
            parse_digest(&self.record_sha256)?,
            parse_digest(&self.comment_body_sha256)?,
            self.pull_request,
            BenchmarkGitRevision::parse(&self.proposal_head)
                .map_err(|_| BenchmarkStoreError::Corrupt)?,
            RuntimeCandidateId::parse(&self.candidate).map_err(|_| BenchmarkStoreError::Corrupt)?,
            self.candidate_benchmark_id
                .map(|value| parse_digest(&value))
                .transpose()?,
            self.baseline_benchmark_id
                .map(|value| parse_digest(&value))
                .transpose()?,
            parse_digest(&self.score_sha256)?,
            parse_digest(&self.restoration_id)?,
            parse_digest(&self.evidence_id)?,
            parse_digest(&self.device_id)?,
            parse_digest(&self.signature_key_id)?,
            self.comment_id,
            self.comment_url,
        )
        .map_err(|_| BenchmarkStoreError::Corrupt)?;
        if publication.publication_id() != &expected_publication_id {
            return Err(BenchmarkStoreError::Corrupt);
        }
        Ok(publication)
    }
}

// Adapts BenchmarkManager's narrow journal contract to the shared DatabaseManager.
pub struct DatabaseBenchmarkStore {
    database: Arc<DatabaseManager>,
}

impl DatabaseBenchmarkStore {
    // Creates one adapter without taking DatabaseManager lifecycle ownership.
    pub const fn new(database: Arc<DatabaseManager>) -> Self {
        Self { database }
    }

    // Reads one exact journal row and validates its private schema and domain invariants.
    fn read_journal(
        &self,
        job_id: &OperationId,
    ) -> Result<Option<VersionedBenchmarkJob>, BenchmarkStoreError> {
        match self
            .database
            .read(DatabaseQuery::<BenchmarkDatabaseRecord>::record(
                journal_identifier(job_id),
            )) {
            Ok(DatabaseResult::Record(stored)) => Ok(Some(VersionedBenchmarkJob::new(
                stored.value.into_journal(job_id)?,
                stored.revision,
            )?)),
            Ok(DatabaseResult::Records(_)) => Err(BenchmarkStoreError::Corrupt),
            Err(DatabaseError::NotFound { .. }) => Ok(None),
            Err(error) => Err(benchmark_store_error(error)),
        }
    }

    // Resolves an idempotent replacement replay only when the current journal is exact.
    fn replaced_replay(
        &self,
        record: &BenchmarkJobRecord,
        expected_revision: u64,
    ) -> Result<VersionedBenchmarkJob, BenchmarkStoreError> {
        let current = self
            .read_journal(record.job_id())?
            .ok_or(BenchmarkStoreError::Conflict)?;
        if current.revision() != expected_revision.saturating_add(1) || current.record() != record {
            return Err(BenchmarkStoreError::Conflict);
        }
        Ok(current)
    }
}

impl BenchmarkStore for DatabaseBenchmarkStore {
    // Reads one exact operation journal.
    fn read(
        &self,
        job_id: &OperationId,
    ) -> Result<Option<VersionedBenchmarkJob>, BenchmarkStoreError> {
        self.read_journal(job_id)
    }

    // Resolves one replay digest through its deterministic benchmark operation identity.
    fn read_replay(
        &self,
        replay_sha256: &Sha256Digest,
    ) -> Result<Option<VersionedBenchmarkJob>, BenchmarkStoreError> {
        self.read_journal(
            &benchmark_job_id(replay_sha256).map_err(|_| BenchmarkStoreError::Corrupt)?,
        )
    }

    // Returns the sole active journal only when the complete collection has one exact owner.
    fn active(&self) -> Result<Option<VersionedBenchmarkJob>, BenchmarkStoreError> {
        let records = match self
            .database
            .read(DatabaseQuery::<BenchmarkDatabaseRecord>::all())
        {
            Ok(DatabaseResult::Records(records)) => records,
            Ok(DatabaseResult::Record(_)) => return Err(BenchmarkStoreError::Corrupt),
            Err(error) => return Err(benchmark_store_error(error)),
        };
        let mut pointer = None;
        let mut active_journal = None;
        for stored in records {
            match stored.value {
                value @ BenchmarkDatabaseRecord::Active { .. } => {
                    if pointer.is_some() {
                        return Err(BenchmarkStoreError::Corrupt);
                    }
                    let (job_id, replay_sha256) = value.active_identity()?;
                    pointer = Some((job_id, replay_sha256, stored.revision));
                }
                value @ BenchmarkDatabaseRecord::Journal { .. } => {
                    let record = value.into_any_journal()?;
                    if record.phase().is_terminal() {
                        continue;
                    }
                    if active_journal.is_some() {
                        return Err(BenchmarkStoreError::Corrupt);
                    }
                    active_journal = Some(VersionedBenchmarkJob::new(record, stored.revision)?);
                }
            }
        }
        match (pointer, active_journal) {
            (None, None) => Ok(None),
            (Some((job_id, replay_sha256, pointer_revision)), Some(journal))
                if journal.record().job_id() == &job_id
                    && journal.record().replay_sha256() == &replay_sha256
                    && journal.revision() == pointer_revision =>
            {
                Ok(Some(journal))
            }
            _ => Err(BenchmarkStoreError::Corrupt),
        }
    }

    // Creates one requested journal and its sole-active pointer atomically.
    fn create(
        &self,
        record: BenchmarkJobRecord,
    ) -> Result<VersionedBenchmarkJob, BenchmarkStoreError> {
        if record.phase() != BenchmarkJobPhase::Requested {
            return Err(BenchmarkStoreError::Corrupt);
        }
        let journal = BenchmarkDatabaseRecord::journal(&record);
        let active = BenchmarkDatabaseRecord::active(&record);
        let idempotency_key = database_idempotency_key("create", &record, 0)?;
        let transaction = DatabaseTransaction::new(idempotency_key)
            .map_err(benchmark_store_error)?
            .save(journal, DatabaseRevision::Missing)
            .map_err(benchmark_store_error)?
            .save(active, DatabaseRevision::Missing)
            .map_err(benchmark_store_error)?;
        let result = self
            .database
            .write_transaction(transaction)
            .map_err(benchmark_store_error)?;
        if result.disposition() == DatabaseCommitDisposition::Replayed {
            return Err(BenchmarkStoreError::Conflict);
        }
        require_commits(
            result.commit().commits(),
            record.job_id(),
            1,
            DatabaseMutation::Created,
            DatabaseMutation::Created,
        )?;
        VersionedBenchmarkJob::new(record, 1)
    }

    // Replaces one revision while atomically advancing or releasing active ownership.
    fn replace(
        &self,
        record: BenchmarkJobRecord,
        expected_revision: u64,
    ) -> Result<VersionedBenchmarkJob, BenchmarkStoreError> {
        if expected_revision == 0 {
            return Err(BenchmarkStoreError::Conflict);
        }
        let next_revision = expected_revision
            .checked_add(1)
            .ok_or(BenchmarkStoreError::Corrupt)?;
        let journal = BenchmarkDatabaseRecord::journal(&record);
        let idempotency_key = database_idempotency_key("replace", &record, expected_revision)?;
        let transaction = DatabaseTransaction::new(idempotency_key)
            .map_err(benchmark_store_error)?
            .save(journal, DatabaseRevision::Exact(expected_revision))
            .map_err(benchmark_store_error)?;
        let (transaction, pointer_mutation) = if record.phase().is_terminal() {
            (
                transaction
                    .delete::<BenchmarkDatabaseRecord>(
                        ACTIVE_RECORD_IDENTIFIER,
                        DatabaseRevision::Exact(expected_revision),
                    )
                    .map_err(benchmark_store_error)?,
                DatabaseMutation::Deleted,
            )
        } else {
            (
                transaction
                    .save(
                        BenchmarkDatabaseRecord::active(&record),
                        DatabaseRevision::Exact(expected_revision),
                    )
                    .map_err(benchmark_store_error)?,
                DatabaseMutation::Updated,
            )
        };
        let result = self
            .database
            .write_transaction(transaction)
            .map_err(benchmark_store_error)?;
        if result.disposition() == DatabaseCommitDisposition::Replayed {
            return self.replaced_replay(&record, expected_revision);
        }
        require_commits(
            result.commit().commits(),
            record.job_id(),
            next_revision,
            DatabaseMutation::Updated,
            pointer_mutation,
        )?;
        VersionedBenchmarkJob::new(record, next_revision)
    }
}

// Returns the private database identity for one benchmark journal row.
fn journal_identifier(job_id: &OperationId) -> String {
    format!("{JOB_RECORD_PREFIX}{}", job_id.as_str())
}

// Creates one bounded replay identity tied to the complete replacement payload.
fn database_idempotency_key(
    action: &str,
    record: &BenchmarkJobRecord,
    expected_revision: u64,
) -> Result<String, BenchmarkStoreError> {
    let value = BenchmarkDatabaseRecord::journal(record);
    let encoded = serde_json::to_vec(&value).map_err(|_| BenchmarkStoreError::Corrupt)?;
    let mut digest = Sha256::new();
    digest.update((action.len() as u64).to_be_bytes());
    digest.update(action.as_bytes());
    digest.update(expected_revision.to_be_bytes());
    digest.update((encoded.len() as u64).to_be_bytes());
    digest.update(encoded);
    Ok(format!("li_benchmark_{action}_v1:{:x}", digest.finalize()))
}

// Verifies the exact two-row commit shape produced by one journal transition.
fn require_commits(
    commits: &[DatabaseCommit],
    job_id: &OperationId,
    expected_revision: u64,
    journal_mutation: DatabaseMutation,
    pointer_mutation: DatabaseMutation,
) -> Result<(), BenchmarkStoreError> {
    if commits.len() != 2 {
        return Err(BenchmarkStoreError::Corrupt);
    }
    require_commit(
        &commits[0],
        &journal_identifier(job_id),
        expected_revision,
        journal_mutation,
    )?;
    require_commit(
        &commits[1],
        ACTIVE_RECORD_IDENTIFIER,
        expected_revision,
        pointer_mutation,
    )
}

// Verifies one DatabaseManager commit without accepting a cross-collection result.
fn require_commit(
    commit: &DatabaseCommit,
    identifier: &str,
    expected_revision: u64,
    mutation: DatabaseMutation,
) -> Result<(), BenchmarkStoreError> {
    if commit.collection != DatabaseCollection::Benchmarks
        || commit.identifier != identifier
        || commit.revision != expected_revision
        || commit.mutation != mutation
    {
        return Err(BenchmarkStoreError::Corrupt);
    }
    Ok(())
}

// Parses one canonical operation identity from private persistence.
fn parse_operation_id(value: &str) -> Result<OperationId, BenchmarkStoreError> {
    OperationId::parse(value).map_err(|_| BenchmarkStoreError::Corrupt)
}

// Parses one exact SHA-256 identity from private persistence.
fn parse_digest(value: &str) -> Result<Sha256Digest, BenchmarkStoreError> {
    Sha256Digest::parse(value).map_err(|_| BenchmarkStoreError::Corrupt)
}

// Parses one optional SHA-256 identity without inventing an absent receipt.
fn optional_digest(value: Option<&str>) -> Result<Option<Sha256Digest>, BenchmarkStoreError> {
    value.map(parse_digest).transpose()
}

// Maps DatabaseManager failures into the benchmark store's narrow stable surface.
fn benchmark_store_error(error: DatabaseError) -> BenchmarkStoreError {
    match error {
        DatabaseError::Conflict { .. } | DatabaseError::IdempotencyConflict { .. } => {
            BenchmarkStoreError::Conflict
        }
        DatabaseError::Corrupt { .. } | DatabaseError::InvalidInput { .. } => {
            BenchmarkStoreError::Corrupt
        }
        DatabaseError::NotFound { .. }
        | DatabaseError::Unavailable { .. }
        | DatabaseError::Closed => BenchmarkStoreError::Unavailable,
    }
}
