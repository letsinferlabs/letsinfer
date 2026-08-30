// SPDX-License-Identifier: AGPL-3.0-only

use li_core_interface::{
    InstallationId, LogicalModelName, OperationId, PlacementGroupId, RuntimeCandidateId,
    RuntimeInstallationId, Sha256Digest, TechnicalName, UnixMilliseconds,
};
use serde::{Deserialize, Serialize};

use crate::{
    BenchmarkError, BenchmarkGitRevision, BenchmarkKind, BenchmarkProgress, BenchmarkRecordSchema,
    BenchmarkRequest, BenchmarkRunPlan, BenchmarkScope, BenchmarkSubject, BenchmarkTelemetryState,
};

const SCHEMA_NAME: &str = "li_benchmark_telemetry_state";
const SCHEMA_VERSION: u64 = 1;
const INVALID_DOCUMENT_REASON: &str = "benchmark telemetry document is invalid";

// Bounds one complete telemetry-state document before allocation or domain reconstruction.
pub const BENCHMARK_TELEMETRY_STATE_MAXIMUM_DOCUMENT_BYTES: usize = 64 * 1024;

// Carries one closed schema identity at the public telemetry-state boundary.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireSchema {
    name: String,
    version: u64,
}

impl WireSchema {
    // Creates the sole schema identity accepted by this codec.
    fn current() -> Self {
        Self {
            name: SCHEMA_NAME.to_string(),
            version: SCHEMA_VERSION,
        }
    }

    // Rejects every schema identity outside the current closed contract.
    fn require_current(&self) -> Result<(), BenchmarkError> {
        if self.name != SCHEMA_NAME || self.version != SCHEMA_VERSION {
            return Err(invalid_document());
        }
        Ok(())
    }
}

// Carries one complete telemetry state with no implicit or extensible fields.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireDocument {
    schema: WireSchema,
    state: WireTelemetryState,
}

impl WireDocument {
    // Projects one validated telemetry state into its complete public representation.
    fn from_state(state: &BenchmarkTelemetryState) -> Self {
        Self {
            schema: WireSchema::current(),
            state: WireTelemetryState::from_state(state),
        }
    }

    // Reconstructs one telemetry state after closing the schema identity.
    fn into_state(self) -> Result<BenchmarkTelemetryState, BenchmarkError> {
        self.schema.require_current()?;
        self.state.into_state()
    }
}

// Carries every durable telemetry-state field without platform observations.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireTelemetryState {
    job_id: String,
    plan: WireRunPlan,
    prepared_receipt_id: String,
    session_receipt_id: String,
    opened_at_unix_milliseconds: u64,
    last_sample_at_unix_milliseconds: Option<u64>,
    sample_count: u64,
    samples_sha256: String,
    progress: Option<WireProgress>,
    sealed_at_unix_milliseconds: Option<u64>,
    sealed_receipt_id: Option<String>,
}

impl WireTelemetryState {
    // Projects one telemetry state while preserving exact times, progress, and digests.
    fn from_state(state: &BenchmarkTelemetryState) -> Self {
        Self {
            job_id: state.job_id().as_str().to_string(),
            plan: WireRunPlan::from_plan(state.plan()),
            prepared_receipt_id: state.prepared_receipt_id().as_str().to_string(),
            session_receipt_id: state.session_receipt_id().as_str().to_string(),
            opened_at_unix_milliseconds: state.opened_at().value(),
            last_sample_at_unix_milliseconds: state.last_sample_at().map(UnixMilliseconds::value),
            sample_count: state.sample_count(),
            samples_sha256: state.samples_sha256().as_str().to_string(),
            progress: state.progress().map(WireProgress::from_progress),
            sealed_at_unix_milliseconds: state.sealed_at().map(UnixMilliseconds::value),
            sealed_receipt_id: state
                .sealed_receipt_id()
                .map(|receipt| receipt.as_str().to_string()),
        }
    }

    // Reconstructs one telemetry state through every public value and domain constructor.
    fn into_state(self) -> Result<BenchmarkTelemetryState, BenchmarkError> {
        BenchmarkTelemetryState::new(
            parse_operation_id(&self.job_id)?,
            self.plan.into_plan()?,
            parse_digest(&self.prepared_receipt_id)?,
            parse_digest(&self.session_receipt_id)?,
            UnixMilliseconds::new(self.opened_at_unix_milliseconds),
            self.last_sample_at_unix_milliseconds
                .map(UnixMilliseconds::new),
            self.sample_count,
            parse_digest(&self.samples_sha256)?,
            self.progress.map(WireProgress::into_progress).transpose()?,
            self.sealed_at_unix_milliseconds.map(UnixMilliseconds::new),
            self.sealed_receipt_id
                .map(|value| parse_digest(&value))
                .transpose()?,
        )
        .map_err(|_| invalid_document())
    }
}

// Carries one exact run plan and its independently checked computed identities.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireRunPlan {
    plan_sha256: String,
    request: WireRequest,
    request_sha256: String,
    benchmark_contract_sha256: String,
    execution_sha256: String,
    target_contract_sha256: String,
    record_schema: WireRecordSchema,
    total_cells: u32,
    maximum_runtime_milliseconds: u64,
    stop_grace_milliseconds: u64,
    telemetry_interval_milliseconds: u64,
}

impl WireRunPlan {
    // Projects one immutable run plan without dropping its request or digest bindings.
    fn from_plan(plan: &BenchmarkRunPlan) -> Self {
        Self {
            plan_sha256: plan.plan_sha256().as_str().to_string(),
            request: WireRequest::from_request(plan.request()),
            request_sha256: plan.request_sha256().as_str().to_string(),
            benchmark_contract_sha256: plan.benchmark_contract_sha256().as_str().to_string(),
            execution_sha256: plan.execution_sha256().as_str().to_string(),
            target_contract_sha256: plan.target_contract_sha256().as_str().to_string(),
            record_schema: WireRecordSchema::from_record_schema(plan.record_schema()),
            total_cells: plan.total_cells(),
            maximum_runtime_milliseconds: plan.maximum_runtime_milliseconds(),
            stop_grace_milliseconds: plan.stop_grace_milliseconds(),
            telemetry_interval_milliseconds: plan.telemetry_interval_milliseconds(),
        }
    }

    // Rebuilds one run plan and rejects any transmitted identity that does not recompute exactly.
    fn into_plan(self) -> Result<BenchmarkRunPlan, BenchmarkError> {
        let expected_plan_sha256 = parse_digest(&self.plan_sha256)?;
        let expected_request_sha256 = parse_digest(&self.request_sha256)?;
        let expected_benchmark_contract_sha256 = parse_digest(&self.benchmark_contract_sha256)?;
        let expected_execution_sha256 = parse_digest(&self.execution_sha256)?;
        let expected_target_contract_sha256 = parse_digest(&self.target_contract_sha256)?;
        let request = self.request.into_request()?;
        let plan = BenchmarkRunPlan::new(
            &request,
            self.record_schema.into_record_schema(),
            self.total_cells,
            self.maximum_runtime_milliseconds,
            self.stop_grace_milliseconds,
            self.telemetry_interval_milliseconds,
        )
        .map_err(|_| invalid_document())?;
        if plan.plan_sha256() != &expected_plan_sha256
            || plan.request_sha256() != &expected_request_sha256
            || plan.benchmark_contract_sha256() != &expected_benchmark_contract_sha256
            || plan.execution_sha256() != &expected_execution_sha256
            || plan.target_contract_sha256() != &expected_target_contract_sha256
        {
            return Err(invalid_document());
        }
        Ok(plan)
    }
}

// Identifies the two publication-compatible record shapes accepted by a run plan.
#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum WireRecordSchema {
    OciExecutionPayloadV7,
    NativeExecutionPayloadV8,
}

impl WireRecordSchema {
    // Projects one validated successful record schema into its closed wire alternative.
    fn from_record_schema(schema: BenchmarkRecordSchema) -> Self {
        match schema {
            BenchmarkRecordSchema::OciExecutionPayloadV7 => Self::OciExecutionPayloadV7,
            BenchmarkRecordSchema::NativeExecutionPayloadV8 => Self::NativeExecutionPayloadV8,
            BenchmarkRecordSchema::CommunityVerificationV1 => {
                unreachable!("run plans reject paired verification record schemas")
            }
            BenchmarkRecordSchema::CoreLocalFailureV1 => {
                unreachable!("run plans reject local failure record schemas")
            }
        }
    }

    // Restores one successful record schema without accepting a failure-evidence shape.
    const fn into_record_schema(self) -> BenchmarkRecordSchema {
        match self {
            Self::OciExecutionPayloadV7 => BenchmarkRecordSchema::OciExecutionPayloadV7,
            Self::NativeExecutionPayloadV8 => BenchmarkRecordSchema::NativeExecutionPayloadV8,
        }
    }
}

// Carries one complete request through a closed kind, scope, and subject projection.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireRequest {
    kind: WireKind,
    scope: WireScope,
    subject: WireSubject,
}

impl WireRequest {
    // Projects one exact benchmark request without collapsing its meaningful alternatives.
    fn from_request(request: &BenchmarkRequest) -> Self {
        Self {
            kind: WireKind::from_kind(request.kind()),
            scope: WireScope::from_scope(request.scope()),
            subject: WireSubject::from_subject(request.subject()),
        }
    }

    // Reconstructs one request so verification and scope invariants run again.
    fn into_request(self) -> Result<BenchmarkRequest, BenchmarkError> {
        BenchmarkRequest::new(
            self.kind.into_kind()?,
            self.scope.into_scope()?,
            self.subject.into_subject()?,
        )
        .map_err(|_| invalid_document())
    }
}

// Carries the exact local or community-verification request alternative.
#[derive(Deserialize, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
enum WireKind {
    Local {},
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

impl WireKind {
    // Projects one benchmark mode including every community authority identity.
    fn from_kind(kind: &BenchmarkKind) -> Self {
        match kind {
            BenchmarkKind::Local => Self::Local {},
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

    // Reconstructs one benchmark mode through its bounded public identities.
    fn into_kind(self) -> Result<BenchmarkKind, BenchmarkError> {
        match self {
            Self::Local {} => Ok(BenchmarkKind::Local),
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
                BenchmarkGitRevision::parse(&proposal_head).map_err(|_| invalid_document())?,
                RuntimeCandidateId::parse(&candidate).map_err(|_| invalid_document())?,
                OperationId::parse(&transaction_id).map_err(|_| invalid_document())?,
                parse_digest(&verifier_bundle_sha256)?,
                parse_digest(&candidate_subject_sha256)?,
                verifier_numeric_id,
                parse_digest(&device_id)?,
                baseline_execution_sha256
                    .map(|value| parse_digest(&value))
                    .transpose()?,
            )
            .map_err(|_| invalid_document()),
        }
    }
}

// Carries either the complete contract or an ordered exact cell selection.
#[derive(Deserialize, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
enum WireScope {
    Complete {},
    Selected { cells: Vec<String> },
}

impl WireScope {
    // Projects one workload scope while retaining selected-cell order.
    fn from_scope(scope: &BenchmarkScope) -> Self {
        match scope {
            BenchmarkScope::Complete => Self::Complete {},
            BenchmarkScope::Selected(cells) => Self::Selected {
                cells: cells.iter().map(|cell| cell.as_str().to_string()).collect(),
            },
        }
    }

    // Reconstructs one scope through the bounded and unique cell constructor.
    fn into_scope(self) -> Result<BenchmarkScope, BenchmarkError> {
        match self {
            Self::Complete {} => Ok(BenchmarkScope::Complete),
            Self::Selected { cells } => BenchmarkScope::selected(
                cells
                    .iter()
                    .map(|cell| TechnicalName::parse(cell).map_err(|_| invalid_document()))
                    .collect::<Result<Vec<_>, _>>()?,
            )
            .map_err(|_| invalid_document()),
        }
    }
}

// Carries every immutable runtime, placement, and contract identity in one subject.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireSubject {
    installation_id: String,
    runtime_installation_id: String,
    model: String,
    placement_group_id: String,
    execution_sha256: String,
    benchmark_contract_sha256: String,
    target_contract_sha256: String,
}

impl WireSubject {
    // Projects one benchmark subject without weakening any typed identity.
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

    // Reconstructs one subject through every public identity parser.
    fn into_subject(self) -> Result<BenchmarkSubject, BenchmarkError> {
        Ok(BenchmarkSubject::new(
            InstallationId::parse(&self.installation_id).map_err(|_| invalid_document())?,
            RuntimeInstallationId::parse(&self.runtime_installation_id)
                .map_err(|_| invalid_document())?,
            LogicalModelName::parse(&self.model).map_err(|_| invalid_document())?,
            PlacementGroupId::parse(&self.placement_group_id).map_err(|_| invalid_document())?,
            parse_digest(&self.execution_sha256)?,
            parse_digest(&self.benchmark_contract_sha256)?,
            parse_digest(&self.target_contract_sha256)?,
        ))
    }
}

// Carries one optional progress sample in its exact model-neutral shape.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireProgress {
    phase: String,
    completed_cells: u32,
    total_cells: u32,
}

impl WireProgress {
    // Projects one progress snapshot without deriving or changing its phase.
    fn from_progress(progress: &BenchmarkProgress) -> Self {
        Self {
            phase: progress.phase().as_str().to_string(),
            completed_cells: progress.completed_cells(),
            total_cells: progress.total_cells(),
        }
    }

    // Reconstructs one progress snapshot through its typed phase and coherence checks.
    fn into_progress(self) -> Result<BenchmarkProgress, BenchmarkError> {
        BenchmarkProgress::new(
            TechnicalName::parse(&self.phase).map_err(|_| invalid_document())?,
            self.completed_cells,
            self.total_cells,
        )
        .map_err(|_| invalid_document())
    }
}

// Encodes one telemetry state as deterministic compact JSON under the closed schema identity.
pub fn encode_benchmark_telemetry_state(
    state: &BenchmarkTelemetryState,
) -> Result<Vec<u8>, BenchmarkError> {
    let document =
        serde_json::to_vec(&WireDocument::from_state(state)).map_err(|_| invalid_document())?;
    if document.is_empty() || document.len() > BENCHMARK_TELEMETRY_STATE_MAXIMUM_DOCUMENT_BYTES {
        return Err(invalid_document());
    }
    Ok(document)
}

// Decodes one bounded closed JSON document and reapplies every telemetry-domain invariant.
pub fn decode_benchmark_telemetry_state(
    document: &[u8],
) -> Result<BenchmarkTelemetryState, BenchmarkError> {
    if document.is_empty() || document.len() > BENCHMARK_TELEMETRY_STATE_MAXIMUM_DOCUMENT_BYTES {
        return Err(invalid_document());
    }
    serde_json::from_slice::<WireDocument>(document)
        .map_err(|_| invalid_document())?
        .into_state()
}

// Parses one exact operation identity while hiding interface-parser details.
fn parse_operation_id(value: &str) -> Result<OperationId, BenchmarkError> {
    OperationId::parse(value).map_err(|_| invalid_document())
}

// Parses one exact SHA-256 identity while hiding interface-parser details.
fn parse_digest(value: &str) -> Result<Sha256Digest, BenchmarkError> {
    Sha256Digest::parse(value).map_err(|_| invalid_document())
}

// Returns one stable failure for every malformed or semantically corrupt document.
const fn invalid_document() -> BenchmarkError {
    BenchmarkError::InvalidContract {
        reason: INVALID_DOCUMENT_REASON,
    }
}
