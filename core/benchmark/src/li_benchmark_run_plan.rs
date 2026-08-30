// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeSet;
use std::sync::Arc;

use li_core_interface::{
    EngineDistribution, InstallationId, ModelServiceDesiredState, OperationId, PlacementGroup,
    PlacementGroupState, RuntimeInstallation, RuntimeInstallationState, Sha256Digest,
    TechnicalName,
};

use crate::{
    BenchmarkError, BenchmarkRecordSchema, BenchmarkRequest, BenchmarkRunPlan,
    BenchmarkRunPlanProvider, BenchmarkScope,
};

const TELEMETRY_INTERVAL_MILLISECONDS: u64 = 1000;
const MAXIMUM_DECLARED_CELLS: usize = 4096;

// Carries exact typed Runtime and Placement identities plus the verified benchmark contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BenchmarkRunPlanResolution {
    core_installation_id: InstallationId,
    runtime_installation: RuntimeInstallation,
    placement_group: PlacementGroup,
    benchmark_contract_sha256: Sha256Digest,
    target_contract_sha256: Sha256Digest,
    declared_cells: Vec<TechnicalName>,
    maximum_runtime_milliseconds: u64,
    stop_grace_milliseconds: u64,
}

impl BenchmarkRunPlanResolution {
    // Creates one exact model-neutral resolution from already-verified runtime source data.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        core_installation_id: InstallationId,
        runtime_installation: RuntimeInstallation,
        placement_group: PlacementGroup,
        benchmark_contract_sha256: Sha256Digest,
        target_contract_sha256: Sha256Digest,
        declared_cells: Vec<TechnicalName>,
        maximum_runtime_milliseconds: u64,
        stop_grace_milliseconds: u64,
    ) -> Result<Self, BenchmarkError> {
        let unique: BTreeSet<&str> = declared_cells.iter().map(TechnicalName::as_str).collect();
        if declared_cells.is_empty()
            || declared_cells.len() > MAXIMUM_DECLARED_CELLS
            || unique.len() != declared_cells.len()
        {
            return Err(BenchmarkError::InvalidContract {
                reason: "benchmark declared cells are empty, duplicated, or exceed their bound",
            });
        }
        Ok(Self {
            core_installation_id,
            runtime_installation,
            placement_group,
            benchmark_contract_sha256,
            target_contract_sha256,
            declared_cells,
            maximum_runtime_milliseconds,
            stop_grace_milliseconds,
        })
    }

    // Returns the exact host-local Runtime installation.
    pub const fn runtime_installation(&self) -> &RuntimeInstallation {
        &self.runtime_installation
    }

    // Returns the exact Placement group reserved for the benchmark.
    pub const fn placement_group(&self) -> &PlacementGroup {
        &self.placement_group
    }
}

// Resolves verified benchmark input snapshots without exposing manager ownership.
pub trait BenchmarkRunPlanSource: Send + Sync {
    // Returns one exact resolution for the immutable benchmark request.
    fn resolve(
        &self,
        job_id: &OperationId,
        request: &BenchmarkRequest,
    ) -> Result<BenchmarkRunPlanResolution, BenchmarkError>;
}

// Resolves one exact scheduling plan without Engine ranks, flags, or executable options.
pub struct ResolvedBenchmarkRunPlanProvider {
    source: Arc<dyn BenchmarkRunPlanSource>,
}

impl ResolvedBenchmarkRunPlanProvider {
    // Creates one plan provider from the narrow Runtime and Placement projection source.
    pub const fn new(source: Arc<dyn BenchmarkRunPlanSource>) -> Self {
        Self { source }
    }

    // Verifies every request identity against the resolved typed snapshots.
    fn require_identity(
        request: &BenchmarkRequest,
        resolution: &BenchmarkRunPlanResolution,
    ) -> Result<(), BenchmarkError> {
        let subject = request.subject();
        let installation = &resolution.runtime_installation;
        let placement = &resolution.placement_group;
        if subject.installation_id() != &resolution.core_installation_id
            || subject.runtime_installation_id() != installation.installation_id()
            || subject.model() != installation.logical_model()
            || subject.placement_group_id() != placement.placement_group_id()
            || subject.execution_sha256() != installation.runtime().execution_contract_digest()
            || subject.benchmark_contract_sha256() != &resolution.benchmark_contract_sha256
            || subject.target_contract_sha256() != &resolution.target_contract_sha256
            || installation.runtime() != placement.runtime()
            || installation.state() != RuntimeInstallationState::Available
        {
            return Err(plan_error(
                "benchmark request differs from resolved runtime identity",
            ));
        }
        Ok(())
    }

    // Requires a stable running or stopped Placement intent with exact token counting.
    fn require_placement(resolution: &BenchmarkRunPlanResolution) -> Result<(), BenchmarkError> {
        let placement = &resolution.placement_group;
        let stable = matches!(
            (placement.desired_state(), placement.state()),
            (
                ModelServiceDesiredState::Running,
                PlacementGroupState::Running
            ) | (
                ModelServiceDesiredState::Stopped,
                PlacementGroupState::Stopped
            )
        );
        let exact_token_count = placement
            .endpoint()
            .and_then(|endpoint| endpoint.token_count())
            .is_some();
        if !stable || !exact_token_count {
            return Err(plan_error(
                "benchmark placement is not stable or lacks exact token counting",
            ));
        }
        Ok(())
    }

    // Resolves the selected cell count while preserving the declared contract vocabulary.
    fn total_cells(
        request: &BenchmarkRequest,
        resolution: &BenchmarkRunPlanResolution,
    ) -> Result<u32, BenchmarkError> {
        let count = match request.scope() {
            BenchmarkScope::Complete => resolution.declared_cells.len(),
            BenchmarkScope::Selected(selected) => {
                let declared: BTreeSet<&str> = resolution
                    .declared_cells
                    .iter()
                    .map(TechnicalName::as_str)
                    .collect();
                if selected
                    .iter()
                    .any(|cell| !declared.contains(cell.as_str()))
                {
                    return Err(plan_error(
                        "benchmark cell selection is outside the declared contract",
                    ));
                }
                selected.len()
            }
        };
        u32::try_from(count).map_err(|_| plan_error("benchmark cell count exceeds its bound"))
    }
}

impl BenchmarkRunPlanProvider for ResolvedBenchmarkRunPlanProvider {
    // Produces one deterministic plan bound to exact Runtime, Placement, and contract identities.
    fn plan(
        &self,
        job_id: &OperationId,
        request: &BenchmarkRequest,
    ) -> Result<BenchmarkRunPlan, BenchmarkError> {
        let resolution = self
            .source
            .resolve(job_id, request)
            .map_err(|_| plan_error("benchmark run-plan inputs are unavailable"))?;
        Self::require_identity(request, &resolution)?;
        Self::require_placement(&resolution)?;
        let record_schema = match resolution
            .runtime_installation
            .runtime()
            .engine_distribution()
        {
            EngineDistribution::Oci { .. } => BenchmarkRecordSchema::OciExecutionPayloadV7,
            EngineDistribution::Native { .. } => BenchmarkRecordSchema::NativeExecutionPayloadV8,
        };
        BenchmarkRunPlan::new(
            request,
            record_schema,
            Self::total_cells(request, &resolution)?,
            resolution.maximum_runtime_milliseconds,
            resolution.stop_grace_milliseconds,
            TELEMETRY_INTERVAL_MILLISECONDS,
        )
    }
}

// Returns one stable redacted run-plan boundary failure.
fn plan_error(reason: &'static str) -> BenchmarkError {
    BenchmarkError::provider("execution", reason)
}
