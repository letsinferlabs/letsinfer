// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeSet;
use std::fmt;

use li_core_interface::{
    FailureDescription, InstallationId, LogicalModelName, OperationId, PlacementGroupId,
    RuntimeCandidateId, RuntimeInstallationId, Sha256Digest, TechnicalName, UnixMilliseconds,
};
use sha2::{Digest, Sha256};

use crate::BenchmarkError;

const MAX_SELECTED_CELLS: usize = 128;
const MAX_EVIDENCE_BYTES: u64 = 64 << 20;
const MAX_SIGNATURE_BYTES: usize = 4096;

// Identifies one exact Git commit used by community verification.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BenchmarkGitRevision(String);

impl BenchmarkGitRevision {
    // Parses one exact lowercase 160-bit Git object identity.
    pub fn parse(value: &str) -> Result<Self, BenchmarkError> {
        if !is_lower_hex(value, 40) {
            return Err(BenchmarkError::InvalidContract {
                reason: "benchmark Git revision must be 40 lowercase hexadecimal characters",
            });
        }
        Ok(Self(value.to_string()))
    }

    // Returns the exact Git revision.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// Identifies whether a job measures local runtime behavior or verifies one proposal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BenchmarkKind {
    Local,
    Verification {
        pull_request: u64,
        proposal_head: BenchmarkGitRevision,
        candidate: RuntimeCandidateId,
        transaction_id: OperationId,
        verifier_bundle_sha256: Sha256Digest,
        candidate_subject_sha256: Sha256Digest,
        verifier_numeric_id: u64,
        device_id: Sha256Digest,
        baseline_execution_sha256: Option<Sha256Digest>,
    },
}

impl BenchmarkKind {
    // Creates one exact community-verification subject without repository credentials.
    pub fn verification(
        pull_request: u64,
        proposal_head: BenchmarkGitRevision,
        candidate: RuntimeCandidateId,
        transaction_id: OperationId,
        verifier_bundle_sha256: Sha256Digest,
        candidate_subject_sha256: Sha256Digest,
        verifier_numeric_id: u64,
        device_id: Sha256Digest,
        baseline_execution_sha256: Option<Sha256Digest>,
    ) -> Result<Self, BenchmarkError> {
        if pull_request == 0 || verifier_numeric_id == 0 {
            return Err(BenchmarkError::InvalidContract {
                reason: "verification pull request and verifier identities must be positive",
            });
        }
        Ok(Self::Verification {
            pull_request,
            proposal_head,
            candidate,
            transaction_id,
            verifier_bundle_sha256,
            candidate_subject_sha256,
            verifier_numeric_id,
            device_id,
            baseline_execution_sha256,
        })
    }

    // Returns whether this job carries community-verification authority.
    pub const fn is_verification(&self) -> bool {
        matches!(self, Self::Verification { .. })
    }
}

// Selects either the complete declared contract or exact diagnostic cells.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BenchmarkScope {
    Complete,
    Selected(Vec<TechnicalName>),
}

impl BenchmarkScope {
    // Creates one bounded unique diagnostic cell selection in caller order.
    pub fn selected(cells: Vec<TechnicalName>) -> Result<Self, BenchmarkError> {
        if cells.is_empty() || cells.len() > MAX_SELECTED_CELLS {
            return Err(BenchmarkError::InvalidContract {
                reason: "benchmark cell selection is empty or exceeds its bound",
            });
        }
        let unique: BTreeSet<&str> = cells.iter().map(|cell| cell.as_str()).collect();
        if unique.len() != cells.len() {
            return Err(BenchmarkError::InvalidContract {
                reason: "benchmark cell selection contains a duplicate",
            });
        }
        Ok(Self::Selected(cells))
    }

    // Returns whether the complete declared benchmark contract will run.
    pub const fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }
}

// Binds one benchmark to exact runtime, target, contract, and placement identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BenchmarkSubject {
    installation_id: InstallationId,
    runtime_installation_id: RuntimeInstallationId,
    model: LogicalModelName,
    placement_group_id: PlacementGroupId,
    execution_sha256: Sha256Digest,
    benchmark_contract_sha256: Sha256Digest,
    target_contract_sha256: Sha256Digest,
}

impl BenchmarkSubject {
    // Creates one model- and Engine-agnostic execution subject from immutable identities.
    pub const fn new(
        installation_id: InstallationId,
        runtime_installation_id: RuntimeInstallationId,
        model: LogicalModelName,
        placement_group_id: PlacementGroupId,
        execution_sha256: Sha256Digest,
        benchmark_contract_sha256: Sha256Digest,
        target_contract_sha256: Sha256Digest,
    ) -> Self {
        Self {
            installation_id,
            runtime_installation_id,
            model,
            placement_group_id,
            execution_sha256,
            benchmark_contract_sha256,
            target_contract_sha256,
        }
    }

    // Returns the exact installed Core identity recorded with evidence.
    pub const fn installation_id(&self) -> &InstallationId {
        &self.installation_id
    }

    // Returns the exact host-local runtime installation identity.
    pub const fn runtime_installation_id(&self) -> &RuntimeInstallationId {
        &self.runtime_installation_id
    }

    // Returns the logical model name without selecting Engine behavior.
    pub const fn model(&self) -> &LogicalModelName {
        &self.model
    }

    // Returns the exact placement group reserved for measurement.
    pub const fn placement_group_id(&self) -> &PlacementGroupId {
        &self.placement_group_id
    }

    // Returns the stable execution-semantics digest.
    pub const fn execution_sha256(&self) -> &Sha256Digest {
        &self.execution_sha256
    }

    // Returns the exact benchmark contract digest.
    pub const fn benchmark_contract_sha256(&self) -> &Sha256Digest {
        &self.benchmark_contract_sha256
    }

    // Returns the exact physical target contract digest.
    pub const fn target_contract_sha256(&self) -> &Sha256Digest {
        &self.target_contract_sha256
    }
}

// Carries one complete benchmark request through admission and restart.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BenchmarkRequest {
    kind: BenchmarkKind,
    scope: BenchmarkScope,
    subject: BenchmarkSubject,
}

impl BenchmarkRequest {
    // Creates one request while forbidding workload overrides during verification.
    pub fn new(
        kind: BenchmarkKind,
        scope: BenchmarkScope,
        subject: BenchmarkSubject,
    ) -> Result<Self, BenchmarkError> {
        if kind.is_verification() && !scope.is_complete() {
            return Err(BenchmarkError::InvalidContract {
                reason: "community verification must run the complete declared contract",
            });
        }
        Ok(Self {
            kind,
            scope,
            subject,
        })
    }

    // Returns the local or community-verification mode.
    pub const fn kind(&self) -> &BenchmarkKind {
        &self.kind
    }

    // Returns the complete or exact diagnostic workload scope.
    pub const fn scope(&self) -> &BenchmarkScope {
        &self.scope
    }

    // Returns the immutable benchmark execution subject.
    pub const fn subject(&self) -> &BenchmarkSubject {
        &self.subject
    }

    // Returns the canonical request fingerprint used for replay conflict checks.
    pub fn sha256(&self) -> Result<Sha256Digest, BenchmarkError> {
        request_sha256(self)
    }
}

// Carries one immutable admission decision without exposing authority material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BenchmarkAuthorization {
    receipt_id: Sha256Digest,
}

impl BenchmarkAuthorization {
    // Creates one opaque authorization receipt from the provider's exact decision.
    pub const fn new(receipt_id: Sha256Digest) -> Self {
        Self { receipt_id }
    }

    // Returns the receipt required to reconstruct admitted work.
    pub const fn receipt_id(&self) -> &Sha256Digest {
        &self.receipt_id
    }
}

// Carries one prepared benchmark workspace and resident-service snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedBenchmark {
    receipt_id: Sha256Digest,
}

impl PreparedBenchmark {
    // Creates one opaque preparation receipt after exact input verification.
    pub const fn new(receipt_id: Sha256Digest) -> Self {
        Self { receipt_id }
    }

    // Returns the provider receipt used for start and restoration replay.
    pub const fn receipt_id(&self) -> &Sha256Digest {
        &self.receipt_id
    }
}

// Carries one detached execution identity through observation and cancellation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunningBenchmark {
    receipt_id: Sha256Digest,
}

impl RunningBenchmark {
    // Creates one opaque running receipt bound to the benchmark operation.
    pub const fn new(receipt_id: Sha256Digest) -> Self {
        Self { receipt_id }
    }

    // Returns the provider receipt used for exact process observation.
    pub const fn receipt_id(&self) -> &Sha256Digest {
        &self.receipt_id
    }
}

// Reports bounded user-visible progress without carrying model output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BenchmarkProgress {
    phase: TechnicalName,
    completed_cells: u32,
    total_cells: u32,
}

impl BenchmarkProgress {
    // Creates one coherent progress snapshot for a non-empty workload plan.
    pub fn new(
        phase: TechnicalName,
        completed_cells: u32,
        total_cells: u32,
    ) -> Result<Self, BenchmarkError> {
        if total_cells == 0 || completed_cells > total_cells {
            return Err(BenchmarkError::InvalidContract {
                reason: "benchmark progress cell counts are inconsistent",
            });
        }
        Ok(Self {
            phase,
            completed_cells,
            total_cells,
        })
    }

    // Returns the current model-neutral lifecycle phase.
    pub const fn phase(&self) -> &TechnicalName {
        &self.phase
    }

    // Returns the number of complete workload cells.
    pub const fn completed_cells(&self) -> u32 {
        self.completed_cells
    }

    // Returns the exact number of planned workload cells.
    pub const fn total_cells(&self) -> u32 {
        self.total_cells
    }
}

// Identifies failure categories accepted by community verification evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BenchmarkFailureCategory {
    Crash,
    OutOfMemory,
    ProtectionTrip,
    OutputValidation,
    IncompleteWorkload,
    Restoration,
}

impl BenchmarkFailureCategory {
    // Returns the stable published verification category.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Crash => "crash",
            Self::OutOfMemory => "out_of_memory",
            Self::ProtectionTrip => "protection_trip",
            Self::OutputValidation => "output_validation",
            Self::IncompleteWorkload => "incomplete_workload",
            Self::Restoration => "restoration",
        }
    }
}

// Stores one bounded blocking failure suitable for durable and signed evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BenchmarkFailure {
    category: BenchmarkFailureCategory,
    phase: TechnicalName,
    description: FailureDescription,
}

impl BenchmarkFailure {
    // Creates one failure whose phase and description remain safe to persist.
    pub fn new(
        category: BenchmarkFailureCategory,
        phase: &str,
        message: &str,
    ) -> Result<Self, BenchmarkError> {
        let phase = TechnicalName::parse(phase).map_err(|_| BenchmarkError::InvalidContract {
            reason: "benchmark failure phase is invalid",
        })?;
        let code =
            TechnicalName::parse(&format!("benchmark.{}", category.as_str())).map_err(|_| {
                BenchmarkError::InvalidContract {
                    reason: "benchmark failure code is invalid",
                }
            })?;
        let description = FailureDescription::new(code, message).map_err(|_| {
            BenchmarkError::InvalidContract {
                reason: "benchmark failure description is invalid",
            }
        })?;
        Ok(Self {
            category,
            phase,
            description,
        })
    }

    // Returns the blocking failure category.
    pub const fn category(&self) -> BenchmarkFailureCategory {
        self.category
    }

    // Returns the lifecycle phase at which the failure occurred.
    pub const fn phase(&self) -> &TechnicalName {
        &self.phase
    }

    // Returns the bounded stable failure description.
    pub const fn description(&self) -> &FailureDescription {
        &self.description
    }
}

// Identifies one terminal execution result before restoration and evidence sealing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BenchmarkExecutionOutcome {
    Succeeded {
        raw_evidence_sha256: Sha256Digest,
        results_sha256: Sha256Digest,
        record_schema: BenchmarkRecordSchema,
    },
    Failed {
        raw_evidence_sha256: Option<Sha256Digest>,
        failure: BenchmarkFailure,
    },
    Cancelled {
        raw_evidence_sha256: Option<Sha256Digest>,
    },
}

impl BenchmarkExecutionOutcome {
    // Returns any immutable raw evidence produced before restoration.
    pub const fn raw_evidence_sha256(&self) -> Option<&Sha256Digest> {
        match self {
            Self::Succeeded {
                raw_evidence_sha256,
                ..
            } => Some(raw_evidence_sha256),
            Self::Failed {
                raw_evidence_sha256,
                ..
            }
            | Self::Cancelled {
                raw_evidence_sha256,
            } => raw_evidence_sha256.as_ref(),
        }
    }

    // Returns the exact successful workload-result identity when execution completed.
    pub const fn results_sha256(&self) -> Option<&Sha256Digest> {
        match self {
            Self::Succeeded { results_sha256, .. } => Some(results_sha256),
            Self::Failed { .. } | Self::Cancelled { .. } => None,
        }
    }

    // Returns the exact successful public record schema selected by the run plan.
    pub const fn record_schema(&self) -> Option<BenchmarkRecordSchema> {
        match self {
            Self::Succeeded { record_schema, .. } => Some(*record_schema),
            Self::Failed { .. } | Self::Cancelled { .. } => None,
        }
    }

    // Returns the blocking failure when execution did not succeed.
    pub const fn failure(&self) -> Option<&BenchmarkFailure> {
        match self {
            Self::Failed { failure, .. } => Some(failure),
            Self::Succeeded { .. } | Self::Cancelled { .. } => None,
        }
    }
}

// Reports whether one detached execution remains active or reached a terminal result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BenchmarkExecutionObservation {
    Running(BenchmarkProgress),
    Terminal(BenchmarkExecutionOutcome),
}

// Carries one immutable telemetry timeline receipt into evidence finalization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BenchmarkTelemetryReceipt {
    receipt_id: Sha256Digest,
    sample_count: u64,
}

impl BenchmarkTelemetryReceipt {
    // Creates one complete telemetry receipt, permitting zero samples for early failures.
    pub const fn new(receipt_id: Sha256Digest, sample_count: u64) -> Self {
        Self {
            receipt_id,
            sample_count,
        }
    }

    // Returns the immutable telemetry object identity.
    pub const fn receipt_id(&self) -> &Sha256Digest {
        &self.receipt_id
    }

    // Returns the number of fixed-interval samples retained by the provider.
    pub const fn sample_count(&self) -> u64 {
        self.sample_count
    }
}

// Proves exact resident-service restoration after every execution exit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BenchmarkRestoration {
    receipt_id: Sha256Digest,
}

impl BenchmarkRestoration {
    // Creates one successful restoration receipt.
    pub const fn new(receipt_id: Sha256Digest) -> Self {
        Self { receipt_id }
    }

    // Returns the exact restoration proof identity.
    pub const fn receipt_id(&self) -> &Sha256Digest {
        &self.receipt_id
    }
}

// Identifies the active execution-payload record schema selected by the Engine distribution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BenchmarkRecordSchema {
    OciExecutionPayloadV7,
    NativeExecutionPayloadV8,
    CommunityVerificationV1,
    CoreLocalFailureV1,
}

impl BenchmarkRecordSchema {
    // Returns the preserved published benchmark record schema version.
    pub const fn version(self) -> u8 {
        match self {
            Self::OciExecutionPayloadV7 => 7,
            Self::NativeExecutionPayloadV8 => 8,
            Self::CommunityVerificationV1 => 1,
            Self::CoreLocalFailureV1 => 1,
        }
    }

    // Returns whether this schema is a successful publication-compatible benchmark record.
    pub const fn is_success_record(self) -> bool {
        matches!(
            self,
            Self::OciExecutionPayloadV7
                | Self::NativeExecutionPayloadV8
                | Self::CommunityVerificationV1
        )
    }

    // Returns whether this is the paired signed community-verification record schema.
    pub const fn is_community_verification(self) -> bool {
        matches!(self, Self::CommunityVerificationV1)
    }
}

// Identifies one immutable schema-validated benchmark record in evidence storage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BenchmarkEvidence {
    evidence_id: Sha256Digest,
    results_sha256: Sha256Digest,
    schema: BenchmarkRecordSchema,
    byte_count: u64,
}

impl BenchmarkEvidence {
    // Creates one bounded immutable evidence receipt after record materialization.
    pub fn new(
        evidence_id: Sha256Digest,
        results_sha256: Sha256Digest,
        schema: BenchmarkRecordSchema,
        byte_count: u64,
    ) -> Result<Self, BenchmarkError> {
        if byte_count == 0 || byte_count > MAX_EVIDENCE_BYTES {
            return Err(BenchmarkError::InvalidContract {
                reason: "benchmark evidence byte count is empty or exceeds its bound",
            });
        }
        Ok(Self {
            evidence_id,
            results_sha256,
            schema,
            byte_count,
        })
    }

    // Returns the canonical immutable evidence identity.
    pub const fn evidence_id(&self) -> &Sha256Digest {
        &self.evidence_id
    }

    // Returns the exact result or Core-local terminal material identity from the record.
    pub const fn results_sha256(&self) -> &Sha256Digest {
        &self.results_sha256
    }

    // Returns the execution, paired-verification, or Core-local evidence schema.
    pub const fn schema(&self) -> BenchmarkRecordSchema {
        self.schema
    }

    // Returns the canonical evidence byte count.
    pub const fn byte_count(&self) -> u64 {
        self.byte_count
    }
}

// Carries one bounded detached signature and its canonical public-key identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BenchmarkSignature {
    key_id: Sha256Digest,
    value: String,
}

impl BenchmarkSignature {
    // Creates one URL-safe detached signature without accepting whitespace or padding.
    pub fn new(key_id: Sha256Digest, value: &str) -> Result<Self, BenchmarkError> {
        if value.is_empty()
            || value.len() > MAX_SIGNATURE_BYTES
            || value.contains('=')
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(BenchmarkError::InvalidContract {
                reason: "benchmark evidence signature is invalid",
            });
        }
        Ok(Self {
            key_id,
            value: value.to_string(),
        })
    }

    // Returns the canonical signer public-key identity.
    pub const fn key_id(&self) -> &Sha256Digest {
        &self.key_id
    }

    // Returns the detached URL-safe signature.
    pub fn value(&self) -> &str {
        &self.value
    }
}

// Binds one immutable evidence record to its independently verified signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedBenchmarkEvidence {
    evidence: BenchmarkEvidence,
    signature: BenchmarkSignature,
}

impl SealedBenchmarkEvidence {
    // Creates one sealed evidence receipt after semantic and signature verification.
    pub const fn new(evidence: BenchmarkEvidence, signature: BenchmarkSignature) -> Self {
        Self {
            evidence,
            signature,
        }
    }

    // Returns the immutable benchmark record receipt.
    pub const fn evidence(&self) -> &BenchmarkEvidence {
        &self.evidence
    }

    // Returns the verified detached signature.
    pub const fn signature(&self) -> &BenchmarkSignature {
        &self.signature
    }
}

// Presents every already-verified terminal input to the external publication boundary.
pub struct BenchmarkPublicationRequest<'a> {
    job_id: &'a OperationId,
    request: &'a BenchmarkRequest,
    outcome: &'a BenchmarkExecutionOutcome,
    restoration: &'a BenchmarkRestoration,
    sealed: &'a SealedBenchmarkEvidence,
}

impl<'a> BenchmarkPublicationRequest<'a> {
    // Creates one borrowed publication view without copying evidence or external material.
    pub const fn new(
        job_id: &'a OperationId,
        request: &'a BenchmarkRequest,
        outcome: &'a BenchmarkExecutionOutcome,
        restoration: &'a BenchmarkRestoration,
        sealed: &'a SealedBenchmarkEvidence,
    ) -> Self {
        Self {
            job_id,
            request,
            outcome,
            restoration,
            sealed,
        }
    }

    // Returns the exact durable benchmark operation identity.
    pub const fn job_id(&self) -> &OperationId {
        self.job_id
    }

    // Returns the immutable admitted benchmark request.
    pub const fn request(&self) -> &BenchmarkRequest {
        self.request
    }

    // Returns correctness, safety, and failure-bearing execution outcome.
    pub const fn outcome(&self) -> &BenchmarkExecutionOutcome {
        self.outcome
    }

    // Returns the exact successful resident-restoration proof.
    pub const fn restoration(&self) -> &BenchmarkRestoration {
        self.restoration
    }

    // Returns the semantically verified evidence and device signature.
    pub const fn sealed(&self) -> &SealedBenchmarkEvidence {
        self.sealed
    }
}

// Proves one exact signed community-verification record was published to its immutable PR head.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BenchmarkPublication {
    publication_id: Sha256Digest,
    verification_id: Sha256Digest,
    record_sha256: Sha256Digest,
    comment_body_sha256: Sha256Digest,
    pull_request: u64,
    proposal_head: BenchmarkGitRevision,
    candidate: RuntimeCandidateId,
    candidate_benchmark_id: Option<Sha256Digest>,
    baseline_benchmark_id: Option<Sha256Digest>,
    score_sha256: Sha256Digest,
    restoration_id: Sha256Digest,
    evidence_id: Sha256Digest,
    device_id: Sha256Digest,
    signature_key_id: Sha256Digest,
    comment_id: u64,
    comment_url: String,
}

impl BenchmarkPublication {
    // Creates one exact GitHub comment receipt bound to proposal and sealed-evidence identities.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        verification_id: Sha256Digest,
        record_sha256: Sha256Digest,
        comment_body_sha256: Sha256Digest,
        pull_request: u64,
        proposal_head: BenchmarkGitRevision,
        candidate: RuntimeCandidateId,
        candidate_benchmark_id: Option<Sha256Digest>,
        baseline_benchmark_id: Option<Sha256Digest>,
        score_sha256: Sha256Digest,
        restoration_id: Sha256Digest,
        evidence_id: Sha256Digest,
        device_id: Sha256Digest,
        signature_key_id: Sha256Digest,
        comment_id: u64,
        comment_url: String,
    ) -> Result<Self, BenchmarkError> {
        let expected_url = format!(
            "https://github.com/letsinferlabs/runtimes/pull/{pull_request}#issuecomment-{comment_id}"
        );
        if pull_request == 0
            || comment_id == 0
            || comment_url != expected_url
            || device_id != signature_key_id
        {
            return Err(BenchmarkError::InvalidContract {
                reason: "benchmark publication receipt identity is invalid",
            });
        }
        let publication_id = benchmark_publication_id(
            &verification_id,
            &record_sha256,
            &comment_body_sha256,
            pull_request,
            &proposal_head,
            &candidate,
            candidate_benchmark_id.as_ref(),
            baseline_benchmark_id.as_ref(),
            &score_sha256,
            &restoration_id,
            &evidence_id,
            &device_id,
            &signature_key_id,
            comment_id,
            &comment_url,
        )?;
        Ok(Self {
            publication_id,
            verification_id,
            record_sha256,
            comment_body_sha256,
            pull_request,
            proposal_head,
            candidate,
            candidate_benchmark_id,
            baseline_benchmark_id,
            score_sha256,
            restoration_id,
            evidence_id,
            device_id,
            signature_key_id,
            comment_id,
            comment_url,
        })
    }

    // Returns the deterministic complete publication receipt identity.
    pub const fn publication_id(&self) -> &Sha256Digest {
        &self.publication_id
    }

    // Returns the stable identity of the expanded verification record.
    pub const fn verification_id(&self) -> &Sha256Digest {
        &self.verification_id
    }

    // Returns the canonical expanded verification record digest.
    pub const fn record_sha256(&self) -> &Sha256Digest {
        &self.record_sha256
    }

    // Returns the exact visible summary and signed-envelope comment digest.
    pub const fn comment_body_sha256(&self) -> &Sha256Digest {
        &self.comment_body_sha256
    }

    // Returns the exact public pull request receiving the signed evidence.
    pub const fn pull_request(&self) -> u64 {
        self.pull_request
    }

    // Returns the immutable proposal head verified by the published evidence.
    pub const fn proposal_head(&self) -> &BenchmarkGitRevision {
        &self.proposal_head
    }

    // Returns the exact runtime candidate verified by the published evidence.
    pub const fn candidate(&self) -> &RuntimeCandidateId {
        &self.candidate
    }

    // Returns the measured candidate benchmark identity when the candidate produced evidence.
    pub const fn candidate_benchmark_id(&self) -> Option<&Sha256Digest> {
        self.candidate_benchmark_id.as_ref()
    }

    // Returns the exact comparison baseline benchmark identity when one was available.
    pub const fn baseline_benchmark_id(&self) -> Option<&Sha256Digest> {
        self.baseline_benchmark_id.as_ref()
    }

    // Returns the canonical aggregate-score digest, including explicit JSON null on failure.
    pub const fn score_sha256(&self) -> &Sha256Digest {
        &self.score_sha256
    }

    // Returns the exact resident-restoration receipt bound into publication.
    pub const fn restoration_id(&self) -> &Sha256Digest {
        &self.restoration_id
    }

    // Returns the sealed benchmark evidence identity.
    pub const fn evidence_id(&self) -> &Sha256Digest {
        &self.evidence_id
    }

    // Returns the exact verifier device public-key identity.
    pub const fn device_id(&self) -> &Sha256Digest {
        &self.device_id
    }

    // Returns the exact device signing-key identity.
    pub const fn signature_key_id(&self) -> &Sha256Digest {
        &self.signature_key_id
    }

    // Returns GitHub's immutable numeric comment identity.
    pub const fn comment_id(&self) -> u64 {
        self.comment_id
    }

    // Returns the canonical public GitHub comment URL.
    pub fn comment_url(&self) -> &str {
        &self.comment_url
    }

    // Requires this receipt to equal the exact verification request and sealed evidence.
    pub fn matches(&self, request: &BenchmarkPublicationRequest<'_>) -> bool {
        matches!(
            request.request().kind(),
            BenchmarkKind::Verification {
                pull_request,
                proposal_head,
                candidate,
                device_id,
                ..
            } if *pull_request == self.pull_request
                && proposal_head == &self.proposal_head
                && candidate == &self.candidate
                && device_id == &self.device_id
        ) && request.sealed().evidence().evidence_id() == &self.evidence_id
            && request.sealed().signature().key_id() == &self.signature_key_id
            && request.restoration().receipt_id() == &self.restoration_id
    }
}

// Describes the durable progress of one benchmark lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BenchmarkJobPhase {
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

impl BenchmarkJobPhase {
    // Returns whether this phase no longer owns execution or restoration work.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }
}

// Records the terminal state requested before a worker actually exits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BenchmarkTerminalIntent {
    Failed(BenchmarkFailure),
    Cancelled,
}

// Stores one complete restart-safe benchmark journal projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BenchmarkJobRecord {
    pub(crate) job_id: OperationId,
    pub(crate) replay_sha256: Sha256Digest,
    pub(crate) request_sha256: Sha256Digest,
    pub(crate) request: BenchmarkRequest,
    pub(crate) authorization: BenchmarkAuthorization,
    pub(crate) phase: BenchmarkJobPhase,
    pub(crate) prepared: Option<PreparedBenchmark>,
    pub(crate) execution: Option<RunningBenchmark>,
    pub(crate) progress: Option<BenchmarkProgress>,
    pub(crate) terminal_intent: Option<BenchmarkTerminalIntent>,
    pub(crate) outcome: Option<BenchmarkExecutionOutcome>,
    pub(crate) telemetry: Option<BenchmarkTelemetryReceipt>,
    pub(crate) restoration: Option<BenchmarkRestoration>,
    pub(crate) evidence: Option<SealedBenchmarkEvidence>,
    pub(crate) publication: Option<BenchmarkPublication>,
    pub(crate) created_at: UnixMilliseconds,
    pub(crate) updated_at: UnixMilliseconds,
}

impl BenchmarkJobRecord {
    // Creates one admitted requested journal before any external preparation.
    pub(crate) fn requested(
        replay_sha256: Sha256Digest,
        request: BenchmarkRequest,
        authorization: BenchmarkAuthorization,
        now: UnixMilliseconds,
    ) -> Result<Self, BenchmarkError> {
        if now.value() == 0 {
            return Err(BenchmarkError::InvalidContract {
                reason: "benchmark creation time must be positive",
            });
        }
        let job_id = benchmark_job_id(&replay_sha256)?;
        let request_sha256 = request.sha256()?;
        Self::restore(
            job_id,
            replay_sha256,
            request_sha256,
            request,
            authorization,
            BenchmarkJobPhase::Requested,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            now,
            now,
        )
    }

    // Reconstructs one journal from persistence while enforcing every phase invariant.
    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        job_id: OperationId,
        replay_sha256: Sha256Digest,
        request_sha256: Sha256Digest,
        request: BenchmarkRequest,
        authorization: BenchmarkAuthorization,
        phase: BenchmarkJobPhase,
        prepared: Option<PreparedBenchmark>,
        execution: Option<RunningBenchmark>,
        progress: Option<BenchmarkProgress>,
        terminal_intent: Option<BenchmarkTerminalIntent>,
        outcome: Option<BenchmarkExecutionOutcome>,
        telemetry: Option<BenchmarkTelemetryReceipt>,
        restoration: Option<BenchmarkRestoration>,
        evidence: Option<SealedBenchmarkEvidence>,
        publication: Option<BenchmarkPublication>,
        created_at: UnixMilliseconds,
        updated_at: UnixMilliseconds,
    ) -> Result<Self, BenchmarkError> {
        if benchmark_job_id(&replay_sha256)? != job_id {
            return Err(BenchmarkError::InvalidContract {
                reason: "benchmark job identity does not match its replay identity",
            });
        }
        if request.sha256()? != request_sha256 {
            return Err(BenchmarkError::InvalidContract {
                reason: "benchmark request fingerprint differs from its request",
            });
        }
        if created_at.value() == 0 || updated_at < created_at {
            return Err(BenchmarkError::InvalidContract {
                reason: "benchmark journal timestamps are invalid",
            });
        }
        let record = Self {
            job_id,
            replay_sha256,
            request_sha256,
            request,
            authorization,
            phase,
            prepared,
            execution,
            progress,
            terminal_intent,
            outcome,
            telemetry,
            restoration,
            evidence,
            publication,
            created_at,
            updated_at,
        };
        validate_record(&record)?;
        Ok(record)
    }

    // Returns the operation identity shared with every idempotent provider.
    pub const fn job_id(&self) -> &OperationId {
        &self.job_id
    }

    // Returns the hash of the caller replay key without retaining that key.
    pub const fn replay_sha256(&self) -> &Sha256Digest {
        &self.replay_sha256
    }

    // Returns the exact request fingerprint used to reject conflicting replay.
    pub const fn request_sha256(&self) -> &Sha256Digest {
        &self.request_sha256
    }

    // Returns the complete typed benchmark request.
    pub const fn request(&self) -> &BenchmarkRequest {
        &self.request
    }

    // Returns the immutable authority receipt admitted before preparation.
    pub const fn authorization(&self) -> &BenchmarkAuthorization {
        &self.authorization
    }

    // Returns the durable lifecycle phase.
    pub const fn phase(&self) -> BenchmarkJobPhase {
        self.phase
    }

    // Returns the exact preparation receipt when external state exists.
    pub const fn prepared(&self) -> Option<&PreparedBenchmark> {
        self.prepared.as_ref()
    }

    // Returns the detached execution receipt when a worker was started.
    pub const fn execution(&self) -> Option<&RunningBenchmark> {
        self.execution.as_ref()
    }

    // Returns the latest bounded progress snapshot.
    pub const fn progress(&self) -> Option<&BenchmarkProgress> {
        self.progress.as_ref()
    }

    // Returns the observed terminal execution outcome.
    pub const fn outcome(&self) -> Option<&BenchmarkExecutionOutcome> {
        self.outcome.as_ref()
    }

    // Returns the immutable telemetry receipt after collection closes.
    pub const fn telemetry(&self) -> Option<&BenchmarkTelemetryReceipt> {
        self.telemetry.as_ref()
    }

    // Returns the exact resident-service restoration receipt.
    pub const fn restoration(&self) -> Option<&BenchmarkRestoration> {
        self.restoration.as_ref()
    }

    // Returns signed, schema-validated evidence for a terminal measured job.
    pub const fn evidence(&self) -> Option<&SealedBenchmarkEvidence> {
        self.evidence.as_ref()
    }

    // Returns the exact GitHub submission receipt for terminal community verification.
    pub const fn publication(&self) -> Option<&BenchmarkPublication> {
        self.publication.as_ref()
    }

    // Returns the journal creation time.
    pub const fn created_at(&self) -> UnixMilliseconds {
        self.created_at
    }

    // Returns the most recent committed transition time.
    pub const fn updated_at(&self) -> UnixMilliseconds {
        self.updated_at
    }
}

// Couples one validated benchmark journal to its optimistic persistence revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionedBenchmarkJob {
    record: BenchmarkJobRecord,
    revision: u64,
}

impl VersionedBenchmarkJob {
    // Creates one positive optimistic revision around a validated journal.
    pub fn new(record: BenchmarkJobRecord, revision: u64) -> Result<Self, BenchmarkStoreError> {
        if revision == 0 {
            return Err(BenchmarkStoreError::Corrupt);
        }
        Ok(Self { record, revision })
    }

    // Returns the complete immutable journal snapshot.
    pub const fn record(&self) -> &BenchmarkJobRecord {
        &self.record
    }

    // Returns the optimistic revision required for replacement.
    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

// Describes one stable benchmark persistence failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BenchmarkStoreError {
    Conflict,
    Unavailable,
    Corrupt,
}

impl fmt::Display for BenchmarkStoreError {
    // Presents a stable store failure without exposing persistence details.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conflict => formatter.write_str("benchmark journal revision conflicted"),
            Self::Unavailable => formatter.write_str("benchmark journal is unavailable"),
            Self::Corrupt => formatter.write_str("benchmark journal is corrupt"),
        }
    }
}

impl std::error::Error for BenchmarkStoreError {}

// Identifies the caller-visible result of one manager mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BenchmarkDisposition {
    Started,
    Running,
    Stopping,
    Completed,
    Failed,
    Cancelled,
    Replayed,
}

// Returns one complete versioned journal and its caller-visible disposition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BenchmarkChange {
    versioned: VersionedBenchmarkJob,
    disposition: BenchmarkDisposition,
}

impl BenchmarkChange {
    // Creates one typed mutation result from its exact persisted snapshot.
    pub const fn new(versioned: VersionedBenchmarkJob, disposition: BenchmarkDisposition) -> Self {
        Self {
            versioned,
            disposition,
        }
    }

    // Returns the durable versioned journal after mutation.
    pub const fn versioned(&self) -> &VersionedBenchmarkJob {
        &self.versioned
    }

    // Returns how the caller should present this mutation.
    pub const fn disposition(&self) -> BenchmarkDisposition {
        self.disposition
    }
}

// Persists benchmark journals with one global active-job exclusion constraint.
pub trait BenchmarkStore: Send + Sync {
    // Reads one exact operation journal.
    fn read(
        &self,
        job_id: &OperationId,
    ) -> Result<Option<VersionedBenchmarkJob>, BenchmarkStoreError>;

    // Reads one journal by its hashed replay identity.
    fn read_replay(
        &self,
        replay_sha256: &Sha256Digest,
    ) -> Result<Option<VersionedBenchmarkJob>, BenchmarkStoreError>;

    // Reads the sole non-terminal benchmark when one exists.
    fn active(&self) -> Result<Option<VersionedBenchmarkJob>, BenchmarkStoreError>;

    // Creates one revision-one journal while atomically enforcing sole active ownership.
    fn create(
        &self,
        record: BenchmarkJobRecord,
    ) -> Result<VersionedBenchmarkJob, BenchmarkStoreError>;

    // Replaces one exact optimistic revision atomically.
    fn replace(
        &self,
        record: BenchmarkJobRecord,
        expected_revision: u64,
    ) -> Result<VersionedBenchmarkJob, BenchmarkStoreError>;
}

// Authorizes a local main-node benchmark or one exact community-verification identity.
pub trait BenchmarkAuthorizationProvider: Send + Sync {
    // Returns an immutable admission receipt or a generic denial.
    fn authorize(
        &self,
        job_id: &OperationId,
        request: &BenchmarkRequest,
    ) -> Result<BenchmarkAuthorization, BenchmarkError>;
}

// Owns one opaque runtime execution and exact resident-state restoration.
pub trait BenchmarkExecutionProvider: Send + Sync {
    // Verifies immutable inputs and snapshots resident intent without starting inference.
    fn prepare(
        &self,
        job_id: &OperationId,
        request: &BenchmarkRequest,
        authorization: &BenchmarkAuthorization,
    ) -> Result<PreparedBenchmark, BenchmarkError>;

    // Starts or reattaches to one exact detached execution idempotently.
    fn start(
        &self,
        job_id: &OperationId,
        request: &BenchmarkRequest,
        prepared: &PreparedBenchmark,
    ) -> Result<RunningBenchmark, BenchmarkError>;

    // Observes only the worker bound to the exact running receipt.
    fn observe(
        &self,
        job_id: &OperationId,
        running: &RunningBenchmark,
    ) -> Result<BenchmarkExecutionObservation, BenchmarkError>;

    // Requests graceful cancellation of the exact worker idempotently.
    fn request_stop(
        &self,
        job_id: &OperationId,
        running: &RunningBenchmark,
    ) -> Result<(), BenchmarkError>;

    // Stops remaining benchmark resources and restores the exact resident intent idempotently.
    fn restore(
        &self,
        job_id: &OperationId,
        request: &BenchmarkRequest,
        prepared: &PreparedBenchmark,
        running: Option<&RunningBenchmark>,
        outcome: &BenchmarkExecutionOutcome,
    ) -> Result<BenchmarkRestoration, BenchmarkError>;
}

// Persists exact fixed-interval telemetry independently of the manager journal.
pub trait BenchmarkTelemetryProvider: Send + Sync {
    // Opens or reopens one provider-owned telemetry timeline idempotently.
    fn begin(
        &self,
        job_id: &OperationId,
        request: &BenchmarkRequest,
        prepared: &PreparedBenchmark,
    ) -> Result<(), BenchmarkError>;

    // Captures one exact schema-owned sample for the current progress point.
    fn capture(
        &self,
        job_id: &OperationId,
        progress: &BenchmarkProgress,
    ) -> Result<(), BenchmarkError>;

    // Closes one timeline and returns its immutable receipt idempotently.
    fn finish(
        &self,
        job_id: &OperationId,
        outcome: &BenchmarkExecutionOutcome,
    ) -> Result<BenchmarkTelemetryReceipt, BenchmarkError>;
}

// Materializes and semantically verifies immutable schema-owned benchmark evidence.
pub trait BenchmarkEvidenceProvider: Send + Sync {
    // Persists one exact record from outcome, telemetry, and restoration receipts idempotently.
    fn finalize(
        &self,
        job_id: &OperationId,
        request: &BenchmarkRequest,
        outcome: &BenchmarkExecutionOutcome,
        telemetry: &BenchmarkTelemetryReceipt,
        restoration: &BenchmarkRestoration,
    ) -> Result<BenchmarkEvidence, BenchmarkError>;

    // Revalidates schema, hashes, identities, and restoration binding before signing.
    fn verify(
        &self,
        request: &BenchmarkRequest,
        outcome: &BenchmarkExecutionOutcome,
        evidence: &BenchmarkEvidence,
    ) -> Result<(), BenchmarkError>;
}

// Chooses the exact outer evidence contract from durable paired-execution state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BenchmarkCommunityVerificationDocument {
    Community(Vec<u8>),
    LocalFailure,
}

// Materializes and independently validates the closed public record for one paired verification.
pub trait BenchmarkCommunityVerificationDocumentProvider: Send + Sync {
    // Returns canonical community bytes only after candidate execution has durably started.
    fn document(
        &self,
        job_id: &OperationId,
        request: &BenchmarkRequest,
        outcome: &BenchmarkExecutionOutcome,
        telemetry: &BenchmarkTelemetryReceipt,
        restoration: &BenchmarkRestoration,
    ) -> Result<BenchmarkCommunityVerificationDocument, BenchmarkError>;
}

// Signs and independently verifies exact immutable benchmark evidence.
pub trait BenchmarkSigningProvider: Send + Sync {
    // Signs the exact provider-owned evidence bytes idempotently.
    fn sign(
        &self,
        job_id: &OperationId,
        evidence: &BenchmarkEvidence,
    ) -> Result<BenchmarkSignature, BenchmarkError>;

    // Verifies the detached signature against the exact evidence bytes and key identity.
    fn verify(
        &self,
        evidence: &BenchmarkEvidence,
        signature: &BenchmarkSignature,
    ) -> Result<bool, BenchmarkError>;
}

// Publishes signed community evidence idempotently after every local verification gate succeeds.
pub trait BenchmarkPublicationProvider: Send + Sync {
    // Returns one exact receipt for verification or explicit absence for an ordinary local run.
    fn publish(
        &self,
        request: &BenchmarkPublicationRequest<'_>,
    ) -> Result<Option<BenchmarkPublication>, BenchmarkError>;
}

// Preserves ordinary local benchmark behavior until a verification publisher is composed.
pub struct NoopBenchmarkPublicationProvider;

impl BenchmarkPublicationProvider for NoopBenchmarkPublicationProvider {
    // Returns no external publication only for ordinary local benchmark evidence.
    fn publish(
        &self,
        request: &BenchmarkPublicationRequest<'_>,
    ) -> Result<Option<BenchmarkPublication>, BenchmarkError> {
        if request.request().kind().is_verification() {
            return Err(BenchmarkError::PublicationRejected);
        }
        Ok(None)
    }
}

// Supplies positive wall-clock time for durable transition ordering.
pub trait BenchmarkClock: Send + Sync {
    // Returns the current Unix time in milliseconds.
    fn now(&self) -> Result<UnixMilliseconds, BenchmarkError>;
}

// Derives one complete publication receipt identity from every readback-bound field.
#[allow(clippy::too_many_arguments)]
fn benchmark_publication_id(
    verification_id: &Sha256Digest,
    record_sha256: &Sha256Digest,
    comment_body_sha256: &Sha256Digest,
    pull_request: u64,
    proposal_head: &BenchmarkGitRevision,
    candidate: &RuntimeCandidateId,
    candidate_benchmark_id: Option<&Sha256Digest>,
    baseline_benchmark_id: Option<&Sha256Digest>,
    score_sha256: &Sha256Digest,
    restoration_id: &Sha256Digest,
    evidence_id: &Sha256Digest,
    device_id: &Sha256Digest,
    signature_key_id: &Sha256Digest,
    comment_id: u64,
    comment_url: &str,
) -> Result<Sha256Digest, BenchmarkError> {
    let mut digest = Sha256::new();
    hash_part(&mut digest, b"li_benchmark_publication_v1");
    for value in [
        verification_id.as_str(),
        record_sha256.as_str(),
        comment_body_sha256.as_str(),
        proposal_head.as_str(),
        candidate.as_str(),
        score_sha256.as_str(),
        restoration_id.as_str(),
        evidence_id.as_str(),
        device_id.as_str(),
        signature_key_id.as_str(),
        comment_url,
    ] {
        hash_part(&mut digest, value.as_bytes());
    }
    hash_part(&mut digest, &pull_request.to_be_bytes());
    hash_part(&mut digest, &comment_id.to_be_bytes());
    hash_part(
        &mut digest,
        candidate_benchmark_id.map_or(b"none".as_slice(), |value| value.as_str().as_bytes()),
    );
    hash_part(
        &mut digest,
        baseline_benchmark_id.map_or(b"none".as_slice(), |value| value.as_str().as_bytes()),
    );
    parsed_digest(digest.finalize())
}

// Derives one secret-free replay identity from a bounded caller key.
pub fn replay_sha256(idempotency_key: &str) -> Result<Sha256Digest, BenchmarkError> {
    if idempotency_key.is_empty()
        || idempotency_key.len() > 255
        || idempotency_key.trim() != idempotency_key
        || idempotency_key.chars().any(char::is_control)
    {
        return Err(BenchmarkError::InvalidContract {
            reason: "benchmark idempotency key is empty, non-canonical, or exceeds its bound",
        });
    }
    let mut digest = Sha256::new();
    hash_part(&mut digest, b"li_benchmark_replay_v1");
    hash_part(&mut digest, idempotency_key.as_bytes());
    parsed_digest(digest.finalize())
}

// Derives one operation identity from the domain-separated replay digest.
pub fn benchmark_job_id(replay_sha256: &Sha256Digest) -> Result<OperationId, BenchmarkError> {
    OperationId::parse(&replay_sha256.as_str()[..32]).map_err(|_| BenchmarkError::InvalidContract {
        reason: "benchmark operation identity could not be derived",
    })
}

// Calculates one canonical typed request fingerprint without serializing a manager call.
fn request_sha256(request: &BenchmarkRequest) -> Result<Sha256Digest, BenchmarkError> {
    let mut digest = Sha256::new();
    hash_part(&mut digest, b"li_benchmark_request_v1");
    let subject = request.subject();
    for value in [
        subject.installation_id().as_str(),
        subject.runtime_installation_id().as_str(),
        subject.model().as_str(),
        subject.placement_group_id().as_str(),
        subject.execution_sha256().as_str(),
        subject.benchmark_contract_sha256().as_str(),
        subject.target_contract_sha256().as_str(),
    ] {
        hash_part(&mut digest, value.as_bytes());
    }
    match request.kind() {
        BenchmarkKind::Local => hash_part(&mut digest, b"local"),
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
        } => {
            hash_part(&mut digest, b"verification");
            hash_part(&mut digest, &pull_request.to_be_bytes());
            hash_part(&mut digest, proposal_head.as_str().as_bytes());
            hash_part(&mut digest, candidate.as_str().as_bytes());
            hash_part(&mut digest, transaction_id.as_str().as_bytes());
            hash_part(&mut digest, verifier_bundle_sha256.as_str().as_bytes());
            hash_part(&mut digest, candidate_subject_sha256.as_str().as_bytes());
            hash_part(&mut digest, &verifier_numeric_id.to_be_bytes());
            hash_part(&mut digest, device_id.as_str().as_bytes());
            hash_part(
                &mut digest,
                baseline_execution_sha256
                    .as_ref()
                    .map_or(b"none".as_slice(), |value| value.as_str().as_bytes()),
            );
        }
    }
    match request.scope() {
        BenchmarkScope::Complete => hash_part(&mut digest, b"complete"),
        BenchmarkScope::Selected(cells) => {
            hash_part(&mut digest, b"selected");
            for cell in cells {
                hash_part(&mut digest, cell.as_str().as_bytes());
            }
        }
    }
    parsed_digest(digest.finalize())
}

// Appends one length-delimited value to a domain-separated identity hash.
fn hash_part(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

// Converts one completed SHA-256 state into the shared validated digest type.
fn parsed_digest(value: impl AsRef<[u8]>) -> Result<Sha256Digest, BenchmarkError> {
    let text = value
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Sha256Digest::parse(&text).map_err(|_| BenchmarkError::InvalidContract {
        reason: "benchmark identity could not be derived",
    })
}

// Enforces every durable phase combination before a record crosses persistence.
fn validate_record(record: &BenchmarkJobRecord) -> Result<(), BenchmarkError> {
    let has_prepared = record.prepared.is_some();
    let has_execution = record.execution.is_some();
    let has_progress = record.progress.is_some();
    let has_outcome = record.outcome.is_some();
    let has_telemetry = record.telemetry.is_some();
    let has_restoration = record.restoration.is_some();
    let has_evidence = record.evidence.is_some();
    let has_publication = record.publication.is_some();
    let publication_matches = match (
        &record.publication,
        &record.outcome,
        &record.restoration,
        &record.evidence,
    ) {
        (Some(publication), Some(outcome), Some(restoration), Some(evidence)) => publication
            .matches(&BenchmarkPublicationRequest::new(
                &record.job_id,
                &record.request,
                outcome,
                restoration,
                evidence,
            )),
        (None, _, _, _) => true,
        (Some(_), _, _, _) => false,
    };
    let community_evidence = record.evidence.as_ref().is_some_and(|evidence| {
        evidence.evidence().schema() == BenchmarkRecordSchema::CommunityVerificationV1
    });
    let publication_presence_matches = has_publication == community_evidence;
    let evidence_matches_outcome = match (&record.outcome, &record.evidence) {
        (
            Some(BenchmarkExecutionOutcome::Succeeded {
                results_sha256,
                record_schema,
                ..
            }),
            Some(evidence),
        ) => {
            record_schema.is_success_record()
                && record_schema.is_community_verification()
                    == record.request.kind().is_verification()
                && evidence.evidence().schema() == *record_schema
                && evidence.evidence().results_sha256() == results_sha256
        }
        (
            Some(BenchmarkExecutionOutcome::Failed { .. })
            | Some(BenchmarkExecutionOutcome::Cancelled { .. }),
            Some(evidence),
        ) => {
            matches!(
                evidence.evidence().schema(),
                BenchmarkRecordSchema::CoreLocalFailureV1
                    | BenchmarkRecordSchema::CommunityVerificationV1
            ) && (record.request.kind().is_verification()
                || evidence.evidence().schema() == BenchmarkRecordSchema::CoreLocalFailureV1)
        }
        (_, None) => true,
        (None, Some(_)) => false,
    };
    let valid = evidence_matches_outcome
        && publication_matches
        && publication_presence_matches
        && match record.phase {
            BenchmarkJobPhase::Requested => {
                !has_prepared
                    && !has_execution
                    && !has_progress
                    && !has_outcome
                    && !has_telemetry
                    && !has_restoration
                    && !has_evidence
                    && record.terminal_intent.is_none()
            }
            BenchmarkJobPhase::Prepared => {
                has_prepared
                    && !has_execution
                    && !has_progress
                    && !has_outcome
                    && !has_telemetry
                    && !has_restoration
                    && !has_evidence
                    && record.terminal_intent.is_none()
            }
            BenchmarkJobPhase::Running => {
                has_prepared
                    && has_execution
                    && !has_outcome
                    && !has_telemetry
                    && !has_restoration
                    && !has_evidence
                    && record.terminal_intent.is_none()
            }
            BenchmarkJobPhase::Stopping => {
                has_prepared
                    && has_execution
                    && !has_outcome
                    && !has_telemetry
                    && !has_restoration
                    && !has_evidence
                    && record.terminal_intent.is_some()
            }
            BenchmarkJobPhase::Restoring => {
                has_prepared
                    && has_outcome
                    && !has_restoration
                    && !has_evidence
                    && record.terminal_intent.is_none()
            }
            BenchmarkJobPhase::Finalizing => {
                has_prepared
                    && has_outcome
                    && has_telemetry
                    && has_restoration
                    && !has_evidence
                    && record.terminal_intent.is_none()
            }
            BenchmarkJobPhase::Completed => {
                has_prepared
                    && has_outcome
                    && matches!(
                        record.outcome,
                        Some(BenchmarkExecutionOutcome::Succeeded { .. })
                    )
                    && has_telemetry
                    && has_restoration
                    && has_evidence
                    && record.terminal_intent.is_none()
            }
            BenchmarkJobPhase::Failed => {
                matches!(
                    record.outcome,
                    Some(BenchmarkExecutionOutcome::Failed { .. })
                ) && record.terminal_intent.is_none()
                    && ((!has_prepared
                        && !has_execution
                        && !has_progress
                        && !has_telemetry
                        && !has_restoration
                        && !has_evidence)
                        || (has_prepared && has_telemetry && has_restoration && has_evidence))
            }
            BenchmarkJobPhase::Cancelled => {
                matches!(
                    record.outcome,
                    Some(BenchmarkExecutionOutcome::Cancelled { .. })
                ) && record.terminal_intent.is_none()
                    && ((!has_prepared
                        && !has_execution
                        && !has_progress
                        && !has_telemetry
                        && !has_restoration
                        && !has_evidence)
                        || (has_prepared && has_telemetry && has_restoration && has_evidence))
            }
        };
    if !valid {
        return Err(BenchmarkError::InvalidContract {
            reason: "benchmark journal fields do not match its lifecycle phase",
        });
    }
    Ok(())
}

// Returns whether one value is exact lowercase hexadecimal text.
fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
