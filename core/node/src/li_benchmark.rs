// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use li_benchmark_manager::{
    BenchmarkAuthorizationProvider, BenchmarkChange, BenchmarkClock, BenchmarkDisposition,
    BenchmarkError, BenchmarkEvidenceProvider, BenchmarkExecutionProvider,
    BenchmarkFailureCategory, BenchmarkJobPhase, BenchmarkKind, BenchmarkManager, BenchmarkRequest,
    BenchmarkScope, BenchmarkSigningProvider, BenchmarkTelemetryProvider,
    BenchmarkVerificationPhase, BenchmarkVerificationStore, DatabaseBenchmarkStore,
    DatabaseBenchmarkVerificationStore, VersionedBenchmarkJob,
};
use li_core_interface::{
    InstallationId, LogicalModelName, OperationId, PlacementGroupId, RuntimeCandidateId,
    RuntimeInstallationId, Sha256Digest, TechnicalName, UnixMilliseconds,
};
use li_database::DatabaseManager;

use crate::{
    DatabaseNodeBenchmarkCandidateHandoffStore, NodeBenchmarkCandidateHandoffPhase,
    NodeBenchmarkCandidateHandoffStore,
};

// Composes one Node-owned durable BenchmarkManager over DatabaseManager and explicit providers.
#[allow(clippy::too_many_arguments)]
pub fn compose_node_benchmark_coordinator(
    database: Arc<DatabaseManager>,
    requests: Arc<dyn NodeBenchmarkRequestProvider>,
    authorization: Arc<dyn BenchmarkAuthorizationProvider>,
    execution: Arc<dyn BenchmarkExecutionProvider>,
    telemetry: Arc<dyn BenchmarkTelemetryProvider>,
    evidence: Arc<dyn BenchmarkEvidenceProvider>,
    signing: Arc<dyn BenchmarkSigningProvider>,
    clock: Arc<dyn BenchmarkClock>,
) -> NodeBenchmarkCoordinator {
    compose_node_benchmark_coordinator_with_store(
        Arc::new(DatabaseBenchmarkStore::new(database)),
        requests,
        authorization,
        execution,
        telemetry,
        evidence,
        signing,
        clock,
    )
}

// Composes one Node-owned BenchmarkManager over an exact already-shared journal adapter.
#[allow(clippy::too_many_arguments)]
pub fn compose_node_benchmark_coordinator_with_store(
    store: Arc<dyn li_benchmark_manager::BenchmarkStore>,
    requests: Arc<dyn NodeBenchmarkRequestProvider>,
    authorization: Arc<dyn BenchmarkAuthorizationProvider>,
    execution: Arc<dyn BenchmarkExecutionProvider>,
    telemetry: Arc<dyn BenchmarkTelemetryProvider>,
    evidence: Arc<dyn BenchmarkEvidenceProvider>,
    signing: Arc<dyn BenchmarkSigningProvider>,
    clock: Arc<dyn BenchmarkClock>,
) -> NodeBenchmarkCoordinator {
    let manager = Arc::new(BenchmarkManager::new(
        store,
        authorization,
        execution,
        telemetry,
        evidence,
        signing,
        clock,
    ));
    NodeBenchmarkCoordinator::new(manager, requests)
}

// Names one public benchmark context axis without exposing runtime contract internals.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum NodeBenchmarkContext {
    Context32k,
    Context64k,
    Context128k,
    Context256k,
}

impl NodeBenchmarkContext {
    // Returns the canonical prefix used by declared benchmark cell identities.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Context32k => "32k",
            Self::Context64k => "64k",
            Self::Context128k => "128k",
            Self::Context256k => "256k",
        }
    }
}

// Carries user-facing model and workload axes before exact runtime identities are resolved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeBenchmarkSelection {
    logical_model: LogicalModelName,
    concurrencies: Vec<u16>,
    contexts: Vec<NodeBenchmarkContext>,
}

impl NodeBenchmarkSelection {
    // Creates one bounded canonical selection; empty axes mean every declared value.
    pub fn new(
        logical_model: LogicalModelName,
        concurrencies: Vec<u16>,
        contexts: Vec<NodeBenchmarkContext>,
    ) -> Result<Self, BenchmarkError> {
        if concurrencies
            .iter()
            .any(|value| !matches!(value, 1 | 2 | 4 | 8 | 16))
            || concurrencies.windows(2).any(|pair| pair[0] >= pair[1])
            || contexts.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(BenchmarkError::InvalidContract {
                reason: "benchmark workload axes are invalid or non-canonical",
            });
        }
        Ok(Self {
            logical_model,
            concurrencies,
            contexts,
        })
    }

    // Returns the user-facing installed model selected for measurement.
    pub const fn logical_model(&self) -> &LogicalModelName {
        &self.logical_model
    }

    // Returns explicit concurrency axes, or an empty slice for every declared value.
    pub fn concurrencies(&self) -> &[u16] {
        &self.concurrencies
    }

    // Returns explicit context axes, or an empty slice for every declared value.
    pub fn contexts(&self) -> &[NodeBenchmarkContext] {
        &self.contexts
    }
}

// Carries one exact resolved local benchmark request and its inspectable cell plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeBenchmarkPlan {
    request: BenchmarkRequest,
    declared_cells: Vec<TechnicalName>,
    selected_cells: Vec<TechnicalName>,
}

impl NodeBenchmarkPlan {
    // Creates one exact local plan after Application resolves immutable manager identities.
    pub fn new(
        selection: &NodeBenchmarkSelection,
        request: BenchmarkRequest,
        declared_cells: Vec<TechnicalName>,
        selected_cells: Vec<TechnicalName>,
    ) -> Result<Self, BenchmarkError> {
        let unique_declared = declared_cells
            .iter()
            .map(TechnicalName::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        let unique_selected = selected_cells
            .iter()
            .map(TechnicalName::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        let scope_matches = match request.scope() {
            BenchmarkScope::Complete => selected_cells == declared_cells,
            BenchmarkScope::Selected(cells) => cells == &selected_cells,
        };
        if request.kind().is_verification()
            || request.subject().model() != selection.logical_model()
            || declared_cells.is_empty()
            || selected_cells.is_empty()
            || unique_declared.len() != declared_cells.len()
            || unique_selected.len() != selected_cells.len()
            || selected_cells
                .iter()
                .any(|cell| !unique_declared.contains(cell.as_str()))
            || !scope_matches
        {
            return Err(BenchmarkError::InvalidContract {
                reason: "resolved local benchmark plan is invalid",
            });
        }
        Ok(Self {
            request,
            declared_cells,
            selected_cells,
        })
    }

    // Returns the immutable manager request used only after plan validation succeeds.
    pub const fn request(&self) -> &BenchmarkRequest {
        &self.request
    }

    // Returns every contract-declared cell in its signed order.
    pub fn declared_cells(&self) -> &[TechnicalName] {
        &self.declared_cells
    }

    // Returns the exact cell subset that would execute in signed order.
    pub fn selected_cells(&self) -> &[TechnicalName] {
        &self.selected_cells
    }
}

// Resolves one public model/workload selection into exact manager-owned benchmark identities.
pub trait NodeBenchmarkRequestProvider: Send + Sync {
    // Returns the immutable request and exact cell plan without mutating benchmark state.
    fn resolve(
        &self,
        selection: &NodeBenchmarkSelection,
    ) -> Result<NodeBenchmarkPlan, BenchmarkError>;
}

// Projects bounded progress without exposing output, prompts, or telemetry content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeBenchmarkSnapshotProgress {
    phase: TechnicalName,
    completed_cells: u32,
    total_cells: u32,
}

// Projects exact durable paired-verification and Node handoff recovery state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeBenchmarkVerificationProjection {
    phase: BenchmarkVerificationPhase,
    handoff_transaction_id: OperationId,
    handoff_phase: NodeBenchmarkCandidateHandoffPhase,
    recovery_required: bool,
}

impl NodeBenchmarkVerificationProjection {
    // Creates one projection only when recovery state agrees with the durable parent phase.
    pub fn new(
        phase: BenchmarkVerificationPhase,
        handoff_transaction_id: OperationId,
        handoff_phase: NodeBenchmarkCandidateHandoffPhase,
    ) -> Self {
        Self {
            phase,
            handoff_transaction_id,
            handoff_phase,
            recovery_required: phase == BenchmarkVerificationPhase::RestorationFailed,
        }
    }

    // Restores one private-wire projection while rejecting fabricated recovery state.
    pub fn restore(
        phase: BenchmarkVerificationPhase,
        handoff_transaction_id: OperationId,
        handoff_phase: NodeBenchmarkCandidateHandoffPhase,
        recovery_required: bool,
    ) -> Result<Self, BenchmarkError> {
        let projection = Self::new(phase, handoff_transaction_id, handoff_phase);
        if projection.recovery_required != recovery_required {
            return Err(BenchmarkError::InvalidContract {
                reason: "benchmark verification recovery state is invalid",
            });
        }
        Ok(projection)
    }

    // Returns the durable paired parent phase.
    pub const fn phase(&self) -> BenchmarkVerificationPhase {
        self.phase
    }

    // Returns the stable paired parent phase name for CLI and private wire projections.
    pub const fn phase_name(&self) -> &'static str {
        match self.phase {
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

    // Returns the opaque Node-owned handoff transaction identity.
    pub const fn handoff_transaction_id(&self) -> &OperationId {
        &self.handoff_transaction_id
    }

    // Returns the durable Runtime/Placement handoff recovery phase.
    pub const fn handoff_phase(&self) -> NodeBenchmarkCandidateHandoffPhase {
        self.handoff_phase
    }

    // Returns the stable Node handoff phase name for status projection.
    pub const fn handoff_phase_name(&self) -> &'static str {
        match self.handoff_phase {
            NodeBenchmarkCandidateHandoffPhase::Prepared => "prepared",
            NodeBenchmarkCandidateHandoffPhase::CandidateAcquired => "candidate_acquired",
            NodeBenchmarkCandidateHandoffPhase::BaselineActivated => "baseline_activated",
            NodeBenchmarkCandidateHandoffPhase::BaselineReleasing => "baseline_releasing",
            NodeBenchmarkCandidateHandoffPhase::BaselineReleased => "baseline_released",
            NodeBenchmarkCandidateHandoffPhase::CandidateStaged => "candidate_staged",
            NodeBenchmarkCandidateHandoffPhase::CandidateRunning => "candidate_running",
            NodeBenchmarkCandidateHandoffPhase::Restoring => "restoring",
            NodeBenchmarkCandidateHandoffPhase::BaselineRestored => "baseline_restored",
            NodeBenchmarkCandidateHandoffPhase::Completed => "completed",
        }
    }

    // Returns whether durable baseline recovery still requires automatic retry.
    pub const fn recovery_required(&self) -> bool {
        self.recovery_required
    }
}

// Projects one bounded terminal verification failure without provider diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeBenchmarkTerminalFailure {
    category: BenchmarkFailureCategory,
    phase: TechnicalName,
}

impl NodeBenchmarkTerminalFailure {
    // Creates one terminal failure from durable benchmark evidence fields.
    pub const fn new(category: BenchmarkFailureCategory, phase: TechnicalName) -> Self {
        Self { category, phase }
    }

    // Returns the stable blocking failure category.
    pub const fn category(&self) -> BenchmarkFailureCategory {
        self.category
    }

    // Returns the bounded lifecycle phase where failure occurred.
    pub const fn phase(&self) -> &TechnicalName {
        &self.phase
    }
}

// Supplies paired-verification observability only from durable parent and handoff journals.
pub trait NodeBenchmarkVerificationProjectionPort: Send + Sync {
    // Returns exact paired state for one verification job or none for an ordinary benchmark.
    fn projection(
        &self,
        job_id: &OperationId,
    ) -> Result<Option<NodeBenchmarkVerificationProjection>, BenchmarkError>;
}

// Reads paired parent and handoff records from their shared DatabaseManager authority.
pub struct DatabaseNodeBenchmarkVerificationProjectionProvider {
    parent: DatabaseBenchmarkVerificationStore,
    handoff: DatabaseNodeBenchmarkCandidateHandoffStore,
}

impl DatabaseNodeBenchmarkVerificationProjectionProvider {
    // Creates one read-only provider from the exact shared database authority.
    pub fn new(database: Arc<DatabaseManager>) -> Self {
        Self {
            parent: DatabaseBenchmarkVerificationStore::new(database.clone()),
            handoff: DatabaseNodeBenchmarkCandidateHandoffStore::new(database),
        }
    }
}

impl NodeBenchmarkVerificationProjectionPort
    for DatabaseNodeBenchmarkVerificationProjectionProvider
{
    // Joins exact durable identities without consulting execution or receipt absence.
    fn projection(
        &self,
        job_id: &OperationId,
    ) -> Result<Option<NodeBenchmarkVerificationProjection>, BenchmarkError> {
        let Some(parent) = self.parent.read(job_id)? else {
            return Ok(None);
        };
        let transaction = parent.transaction();
        let transaction_id = transaction.handoff().transaction_id();
        let handoff = self
            .handoff
            .read(transaction_id)
            .map_err(|_| BenchmarkError::provider("verification state", "handoff unavailable"))?
            .ok_or_else(|| BenchmarkError::provider("verification state", "handoff unavailable"))?;
        if handoff.record().transaction_id() != transaction_id {
            return Err(BenchmarkError::InvalidContract {
                reason: "benchmark verification handoff identity is invalid",
            });
        }
        Ok(Some(NodeBenchmarkVerificationProjection::new(
            transaction.phase(),
            transaction_id.clone(),
            handoff.record().phase(),
        )))
    }
}

impl NodeBenchmarkSnapshotProgress {
    // Reconstructs one bounded private-wire progress projection.
    pub fn restore(
        phase: TechnicalName,
        completed_cells: u32,
        total_cells: u32,
    ) -> Result<Self, BenchmarkError> {
        if total_cells == 0 || completed_cells > total_cells {
            return Err(BenchmarkError::InvalidContract {
                reason: "benchmark progress is outside its declared cell count",
            });
        }
        Ok(Self {
            phase,
            completed_cells,
            total_cells,
        })
    }

    // Returns the model-neutral execution phase.
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

// Projects one secret-free durable benchmark journal for private status and CLI use.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeBenchmarkSnapshot {
    job_id: OperationId,
    revision: u64,
    kind: BenchmarkKind,
    phase: BenchmarkJobPhase,
    disposition: Option<BenchmarkDisposition>,
    request_sha256: Sha256Digest,
    core_installation_id: InstallationId,
    runtime_installation_id: RuntimeInstallationId,
    logical_model: LogicalModelName,
    placement_group_id: PlacementGroupId,
    execution_sha256: Sha256Digest,
    benchmark_contract_sha256: Sha256Digest,
    target_contract_sha256: Sha256Digest,
    authorization_receipt_id: Sha256Digest,
    prepared_receipt_id: Option<Sha256Digest>,
    running_receipt_id: Option<Sha256Digest>,
    telemetry_receipt_id: Option<Sha256Digest>,
    telemetry_sample_count: Option<u64>,
    restoration_receipt_id: Option<Sha256Digest>,
    evidence_id: Option<Sha256Digest>,
    results_sha256: Option<Sha256Digest>,
    signature_key_id: Option<Sha256Digest>,
    progress: Option<NodeBenchmarkSnapshotProgress>,
    verification: Option<NodeBenchmarkVerificationProjection>,
    terminal_failure: Option<NodeBenchmarkTerminalFailure>,
    created_at: UnixMilliseconds,
    updated_at: UnixMilliseconds,
}

impl NodeBenchmarkSnapshot {
    // Projects one validated versioned journal and optional mutation disposition.
    pub fn new(
        versioned: &VersionedBenchmarkJob,
        disposition: Option<BenchmarkDisposition>,
    ) -> Self {
        Self::new_with_verification(versioned, disposition, None)
    }

    // Projects one journal with exact paired-verification and handoff recovery state.
    pub fn new_with_verification(
        versioned: &VersionedBenchmarkJob,
        disposition: Option<BenchmarkDisposition>,
        verification: Option<NodeBenchmarkVerificationProjection>,
    ) -> Self {
        let record = versioned.record();
        let subject = record.request().subject();
        let evidence = record.evidence();
        let terminal_failure = if record.request().kind().is_verification() {
            record
                .outcome()
                .and_then(|outcome| outcome.failure())
                .map(|failure| {
                    NodeBenchmarkTerminalFailure::new(failure.category(), failure.phase().clone())
                })
        } else {
            None
        };
        Self {
            job_id: record.job_id().clone(),
            revision: versioned.revision(),
            kind: record.request().kind().clone(),
            phase: record.phase(),
            disposition,
            request_sha256: record.request_sha256().clone(),
            core_installation_id: subject.installation_id().clone(),
            runtime_installation_id: subject.runtime_installation_id().clone(),
            logical_model: subject.model().clone(),
            placement_group_id: subject.placement_group_id().clone(),
            execution_sha256: subject.execution_sha256().clone(),
            benchmark_contract_sha256: subject.benchmark_contract_sha256().clone(),
            target_contract_sha256: subject.target_contract_sha256().clone(),
            authorization_receipt_id: record.authorization().receipt_id().clone(),
            prepared_receipt_id: record
                .prepared()
                .map(|prepared| prepared.receipt_id().clone()),
            running_receipt_id: record
                .execution()
                .map(|running| running.receipt_id().clone()),
            telemetry_receipt_id: record
                .telemetry()
                .map(|telemetry| telemetry.receipt_id().clone()),
            telemetry_sample_count: record.telemetry().map(|telemetry| telemetry.sample_count()),
            restoration_receipt_id: record
                .restoration()
                .map(|restoration| restoration.receipt_id().clone()),
            evidence_id: evidence.map(|sealed| sealed.evidence().evidence_id().clone()),
            results_sha256: evidence.map(|sealed| sealed.evidence().results_sha256().clone()),
            signature_key_id: evidence.map(|sealed| sealed.signature().key_id().clone()),
            progress: record
                .progress()
                .map(|progress| NodeBenchmarkSnapshotProgress {
                    phase: progress.phase().clone(),
                    completed_cells: progress.completed_cells(),
                    total_cells: progress.total_cells(),
                }),
            verification,
            terminal_failure,
            created_at: record.created_at(),
            updated_at: record.updated_at(),
        }
    }

    // Reconstructs one secret-free private-wire snapshot after validating projection invariants.
    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        job_id: OperationId,
        revision: u64,
        kind: BenchmarkKind,
        phase: BenchmarkJobPhase,
        disposition: Option<BenchmarkDisposition>,
        request_sha256: Sha256Digest,
        core_installation_id: InstallationId,
        runtime_installation_id: RuntimeInstallationId,
        logical_model: LogicalModelName,
        placement_group_id: PlacementGroupId,
        execution_sha256: Sha256Digest,
        benchmark_contract_sha256: Sha256Digest,
        target_contract_sha256: Sha256Digest,
        authorization_receipt_id: Sha256Digest,
        prepared_receipt_id: Option<Sha256Digest>,
        running_receipt_id: Option<Sha256Digest>,
        telemetry_receipt_id: Option<Sha256Digest>,
        telemetry_sample_count: Option<u64>,
        restoration_receipt_id: Option<Sha256Digest>,
        evidence_id: Option<Sha256Digest>,
        results_sha256: Option<Sha256Digest>,
        signature_key_id: Option<Sha256Digest>,
        progress: Option<NodeBenchmarkSnapshotProgress>,
        verification: Option<NodeBenchmarkVerificationProjection>,
        terminal_failure: Option<NodeBenchmarkTerminalFailure>,
        created_at: UnixMilliseconds,
        updated_at: UnixMilliseconds,
    ) -> Result<Self, BenchmarkError> {
        if revision == 0 || created_at.value() == 0 || updated_at < created_at {
            return Err(BenchmarkError::InvalidContract {
                reason: "benchmark private snapshot revision or timestamps are invalid",
            });
        }
        if telemetry_receipt_id.is_some() != telemetry_sample_count.is_some() {
            return Err(BenchmarkError::InvalidContract {
                reason: "benchmark private snapshot telemetry fields are incomplete",
            });
        }
        let evidence_field_count = [
            evidence_id.is_some(),
            results_sha256.is_some(),
            signature_key_id.is_some(),
        ]
        .into_iter()
        .filter(|present| *present)
        .count();
        if evidence_field_count != 0 && evidence_field_count != 3 {
            return Err(BenchmarkError::InvalidContract {
                reason: "benchmark private snapshot evidence fields are incomplete",
            });
        }
        if phase == BenchmarkJobPhase::Requested
            && (prepared_receipt_id.is_some()
                || running_receipt_id.is_some()
                || telemetry_receipt_id.is_some()
                || restoration_receipt_id.is_some()
                || evidence_id.is_some()
                || progress.is_some())
        {
            return Err(BenchmarkError::InvalidContract {
                reason: "requested benchmark private snapshot has later-phase receipts",
            });
        }
        if matches!(
            phase,
            BenchmarkJobPhase::Prepared
                | BenchmarkJobPhase::Running
                | BenchmarkJobPhase::Stopping
                | BenchmarkJobPhase::Restoring
                | BenchmarkJobPhase::Finalizing
        ) && prepared_receipt_id.is_none()
        {
            return Err(BenchmarkError::InvalidContract {
                reason: "active benchmark private snapshot lacks its preparation receipt",
            });
        }
        if matches!(
            phase,
            BenchmarkJobPhase::Running | BenchmarkJobPhase::Stopping
        ) && running_receipt_id.is_none()
        {
            return Err(BenchmarkError::InvalidContract {
                reason: "executing benchmark private snapshot lacks its running receipt",
            });
        }
        if evidence_id.is_some() && !phase.is_terminal() {
            return Err(BenchmarkError::InvalidContract {
                reason: "non-terminal benchmark private snapshot contains sealed evidence",
            });
        }
        if kind.is_verification() != verification.is_some()
            || !kind.is_verification() && terminal_failure.is_some()
            || terminal_failure.is_some() && phase != BenchmarkJobPhase::Failed
        {
            return Err(BenchmarkError::InvalidContract {
                reason: "benchmark verification projection is incomplete or misplaced",
            });
        }
        Ok(Self {
            job_id,
            revision,
            kind,
            phase,
            disposition,
            request_sha256,
            core_installation_id,
            runtime_installation_id,
            logical_model,
            placement_group_id,
            execution_sha256,
            benchmark_contract_sha256,
            target_contract_sha256,
            authorization_receipt_id,
            prepared_receipt_id,
            running_receipt_id,
            telemetry_receipt_id,
            telemetry_sample_count,
            restoration_receipt_id,
            evidence_id,
            results_sha256,
            signature_key_id,
            progress,
            verification,
            terminal_failure,
            created_at,
            updated_at,
        })
    }

    // Returns the exact benchmark operation identity.
    pub const fn job_id(&self) -> &OperationId {
        &self.job_id
    }

    // Returns the optimistic journal revision.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    // Returns whether this snapshot belongs to community verification.
    pub const fn is_verification(&self) -> bool {
        self.kind.is_verification()
    }

    // Returns the exact local or community-verification authority identity.
    pub const fn kind(&self) -> &BenchmarkKind {
        &self.kind
    }

    // Returns the durable lifecycle phase.
    pub const fn phase(&self) -> BenchmarkJobPhase {
        self.phase
    }

    // Returns the optional caller-visible mutation disposition.
    pub const fn disposition(&self) -> Option<BenchmarkDisposition> {
        self.disposition
    }

    // Returns the exact benchmark request identity.
    pub const fn request_sha256(&self) -> &Sha256Digest {
        &self.request_sha256
    }

    // Returns the exact Core installation identity.
    pub const fn core_installation_id(&self) -> &InstallationId {
        &self.core_installation_id
    }

    // Returns the exact host-local Runtime installation identity.
    pub const fn runtime_installation_id(&self) -> &RuntimeInstallationId {
        &self.runtime_installation_id
    }

    // Returns the logical model identity.
    pub const fn logical_model(&self) -> &LogicalModelName {
        &self.logical_model
    }

    // Returns the exact reserved Placement group identity.
    pub const fn placement_group_id(&self) -> &PlacementGroupId {
        &self.placement_group_id
    }

    // Returns the opaque Runtime execution identity.
    pub const fn execution_sha256(&self) -> &Sha256Digest {
        &self.execution_sha256
    }

    // Returns the exact benchmark contract identity.
    pub const fn benchmark_contract_sha256(&self) -> &Sha256Digest {
        &self.benchmark_contract_sha256
    }

    // Returns the exact physical target contract identity.
    pub const fn target_contract_sha256(&self) -> &Sha256Digest {
        &self.target_contract_sha256
    }

    // Returns the immutable authorization receipt identity.
    pub const fn authorization_receipt_id(&self) -> &Sha256Digest {
        &self.authorization_receipt_id
    }

    // Returns the optional resident-snapshot preparation identity.
    pub const fn prepared_receipt_id(&self) -> Option<&Sha256Digest> {
        self.prepared_receipt_id.as_ref()
    }

    // Returns the optional detached-task identity.
    pub const fn running_receipt_id(&self) -> Option<&Sha256Digest> {
        self.running_receipt_id.as_ref()
    }

    // Returns the optional immutable telemetry receipt.
    pub const fn telemetry_receipt_id(&self) -> Option<&Sha256Digest> {
        self.telemetry_receipt_id.as_ref()
    }

    // Returns the optional telemetry sample count.
    pub const fn telemetry_sample_count(&self) -> Option<u64> {
        self.telemetry_sample_count
    }

    // Returns the optional exact resident restoration proof.
    pub const fn restoration_receipt_id(&self) -> Option<&Sha256Digest> {
        self.restoration_receipt_id.as_ref()
    }

    // Returns the optional sealed evidence identity.
    pub const fn evidence_id(&self) -> Option<&Sha256Digest> {
        self.evidence_id.as_ref()
    }

    // Returns the optional exact result identity.
    pub const fn results_sha256(&self) -> Option<&Sha256Digest> {
        self.results_sha256.as_ref()
    }

    // Returns the optional exact evidence signer identity.
    pub const fn signature_key_id(&self) -> Option<&Sha256Digest> {
        self.signature_key_id.as_ref()
    }

    // Returns the latest bounded progress projection.
    pub const fn progress(&self) -> Option<&NodeBenchmarkSnapshotProgress> {
        self.progress.as_ref()
    }

    // Returns exact paired parent and Node handoff recovery state for verification jobs.
    pub const fn verification(&self) -> Option<&NodeBenchmarkVerificationProjection> {
        self.verification.as_ref()
    }

    // Returns a bounded terminal verification failure without provider diagnostics.
    pub const fn terminal_failure(&self) -> Option<&NodeBenchmarkTerminalFailure> {
        self.terminal_failure.as_ref()
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

// Owns Node scheduling, restart polling, and private command projection over BenchmarkManager.
pub struct NodeBenchmarkCoordinator {
    manager: Arc<BenchmarkManager>,
    requests: Arc<dyn NodeBenchmarkRequestProvider>,
    verification: Option<Arc<dyn NodeBenchmarkVerificationProjectionPort>>,
}

// Defines the narrow BenchmarkManager capability consumed by the private Node API.
pub trait NodeBenchmarkApiPort: Send + Sync {
    // Resolves one read-only local benchmark plan from public model and workload axes.
    fn preview(
        &self,
        selection: NodeBenchmarkSelection,
    ) -> Result<NodeBenchmarkPlan, BenchmarkError>;

    // Starts or resumes one exact local benchmark after resolving immutable identities.
    fn start(
        &self,
        idempotency_key: &str,
        selection: NodeBenchmarkSelection,
    ) -> Result<NodeBenchmarkSnapshot, BenchmarkError>;

    // Starts one Application-verified proposal request without accepting client-supplied identities.
    fn start_verification(
        &self,
        _idempotency_key: &str,
        _pull_request_url: &str,
        _candidate: Option<&RuntimeCandidateId>,
    ) -> Result<NodeBenchmarkSnapshot, BenchmarkError> {
        Err(BenchmarkError::InvalidContract {
            reason: "benchmark verification authority is unavailable",
        })
    }

    // Returns one exact private benchmark snapshot without polling it.
    fn record(&self, job_id: &OperationId)
        -> Result<Option<NodeBenchmarkSnapshot>, BenchmarkError>;

    // Returns the sole non-terminal private benchmark snapshot.
    fn active(&self) -> Result<Option<NodeBenchmarkSnapshot>, BenchmarkError>;

    // Requests cancellation of one exact private benchmark job.
    fn stop(&self, job_id: &OperationId) -> Result<NodeBenchmarkSnapshot, BenchmarkError>;
}

// Defines the sole restart-safe benchmark capability consumed by the resident Node loop.
pub trait NodeBenchmarkPollingPort: Send + Sync {
    // Advances the sole active benchmark by one bounded observation.
    fn poll_active(&self) -> Result<Option<NodeBenchmarkSnapshot>, BenchmarkError>;
}

impl NodeBenchmarkCoordinator {
    // Creates one Node-owned benchmark role around an already-composed durable manager.
    pub const fn new(
        manager: Arc<BenchmarkManager>,
        requests: Arc<dyn NodeBenchmarkRequestProvider>,
    ) -> Self {
        Self {
            manager,
            requests,
            verification: None,
        }
    }

    // Adds exact durable paired-verification projection without changing lifecycle ownership.
    pub fn with_verification_projection(
        mut self,
        verification: Arc<dyn NodeBenchmarkVerificationProjectionPort>,
    ) -> Self {
        self.verification = Some(verification);
        self
    }

    // Resolves one exact read-only plan without invoking BenchmarkManager lifecycle providers.
    pub fn preview(
        &self,
        selection: NodeBenchmarkSelection,
    ) -> Result<NodeBenchmarkPlan, BenchmarkError> {
        self.requests.resolve(&selection)
    }

    // Starts or resumes one exact local benchmark after one fresh immutable resolution.
    pub fn start(
        &self,
        idempotency_key: &str,
        selection: NodeBenchmarkSelection,
    ) -> Result<NodeBenchmarkSnapshot, BenchmarkError> {
        let request = self.requests.resolve(&selection)?.request().clone();
        self.manager
            .start(idempotency_key, request)
            .and_then(|change| self.snapshot_change(&change))
    }

    // Starts or replays one already closed Application-verified request through BenchmarkManager.
    pub fn start_verified(
        &self,
        idempotency_key: &str,
        request: BenchmarkRequest,
    ) -> Result<NodeBenchmarkSnapshot, BenchmarkError> {
        if !request.kind().is_verification() || !request.scope().is_complete() {
            return Err(BenchmarkError::InvalidContract {
                reason: "verified benchmark request is not complete proposal authority",
            });
        }
        self.manager
            .start(idempotency_key, request)
            .and_then(|change| self.snapshot_change(&change))
    }

    // Returns one exact durable job without polling external state.
    pub fn record(
        &self,
        job_id: &OperationId,
    ) -> Result<Option<NodeBenchmarkSnapshot>, BenchmarkError> {
        self.manager
            .record(job_id)?
            .as_ref()
            .map(|record| self.snapshot(record, None))
            .transpose()
    }

    // Returns the sole non-terminal job without polling it.
    pub fn active(&self) -> Result<Option<NodeBenchmarkSnapshot>, BenchmarkError> {
        self.manager
            .active()?
            .as_ref()
            .map(|record| self.snapshot(record, None))
            .transpose()
    }

    // Advances the sole active job by one restart-safe provider observation.
    pub fn poll_active(&self) -> Result<Option<NodeBenchmarkSnapshot>, BenchmarkError> {
        let Some(active) = self.manager.active()? else {
            return Ok(None);
        };
        self.manager
            .poll(active.record().job_id())
            .and_then(|change| self.snapshot_change(&change).map(Some))
    }

    // Requests cancellation of one exact durable job.
    pub fn stop(&self, job_id: &OperationId) -> Result<NodeBenchmarkSnapshot, BenchmarkError> {
        self.manager
            .stop(job_id)
            .and_then(|change| self.snapshot_change(&change))
    }

    // Returns the shared manager only for composition and deterministic integration tests.
    pub const fn manager(&self) -> &Arc<BenchmarkManager> {
        &self.manager
    }

    // Projects one versioned benchmark using exact durable paired state when applicable.
    fn snapshot(
        &self,
        record: &VersionedBenchmarkJob,
        disposition: Option<BenchmarkDisposition>,
    ) -> Result<NodeBenchmarkSnapshot, BenchmarkError> {
        let verification = match (
            record.record().request().kind().is_verification(),
            self.verification.as_ref(),
        ) {
            (false, _) => None,
            (true, Some(provider)) => provider
                .projection(record.record().job_id())?
                .ok_or_else(|| {
                    BenchmarkError::provider(
                        "verification state",
                        "paired transaction is unavailable",
                    )
                })?
                .into(),
            (true, None) => {
                return Err(BenchmarkError::provider(
                    "verification state",
                    "paired projection is unavailable",
                ));
            }
        };
        Ok(NodeBenchmarkSnapshot::new_with_verification(
            record,
            disposition,
            verification,
        ))
    }

    // Projects one manager mutation through the same durable observability boundary.
    fn snapshot_change(
        &self,
        change: &BenchmarkChange,
    ) -> Result<NodeBenchmarkSnapshot, BenchmarkError> {
        self.snapshot(change.versioned(), Some(change.disposition()))
    }
}

impl NodeBenchmarkApiPort for NodeBenchmarkCoordinator {
    // Resolves one read-only local plan through ordinary coordinator code.
    fn preview(
        &self,
        selection: NodeBenchmarkSelection,
    ) -> Result<NodeBenchmarkPlan, BenchmarkError> {
        NodeBenchmarkCoordinator::preview(self, selection)
    }

    // Starts or resumes one exact local benchmark through ordinary coordinator code.
    fn start(
        &self,
        idempotency_key: &str,
        selection: NodeBenchmarkSelection,
    ) -> Result<NodeBenchmarkSnapshot, BenchmarkError> {
        NodeBenchmarkCoordinator::start(self, idempotency_key, selection)
    }

    // Returns one exact private benchmark through ordinary coordinator code.
    fn record(
        &self,
        job_id: &OperationId,
    ) -> Result<Option<NodeBenchmarkSnapshot>, BenchmarkError> {
        NodeBenchmarkCoordinator::record(self, job_id)
    }

    // Returns the active private benchmark through ordinary coordinator code.
    fn active(&self) -> Result<Option<NodeBenchmarkSnapshot>, BenchmarkError> {
        NodeBenchmarkCoordinator::active(self)
    }

    // Requests cancellation through ordinary coordinator code.
    fn stop(&self, job_id: &OperationId) -> Result<NodeBenchmarkSnapshot, BenchmarkError> {
        NodeBenchmarkCoordinator::stop(self, job_id)
    }
}

impl NodeBenchmarkPollingPort for NodeBenchmarkCoordinator {
    // Advances the sole active benchmark through ordinary coordinator code.
    fn poll_active(&self) -> Result<Option<NodeBenchmarkSnapshot>, BenchmarkError> {
        NodeBenchmarkCoordinator::poll_active(self)
    }
}
