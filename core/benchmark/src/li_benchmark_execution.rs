// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use li_core_interface::{OperationId, Sha256Digest, TechnicalName, UnixMilliseconds};
use sha2::{Digest, Sha256};

use crate::{
    BenchmarkAuthorization, BenchmarkClock, BenchmarkError, BenchmarkExecutionObservation,
    BenchmarkExecutionOutcome, BenchmarkExecutionProvider, BenchmarkFailure,
    BenchmarkFailureCategory, BenchmarkProgress, BenchmarkRecordSchema, BenchmarkRequest,
    BenchmarkRestoration, BenchmarkScope, PreparedBenchmark, RunningBenchmark,
};

const MAXIMUM_BENCHMARK_CELLS: u32 = 4096;
const MAXIMUM_BENCHMARK_RUNTIME_MILLISECONDS: u64 = 7 * 24 * 60 * 60 * 1000;
const MAXIMUM_STOP_GRACE_MILLISECONDS: u64 = 10 * 60 * 1000;
const MAXIMUM_RESULT_BYTES: u64 = 64 << 20;
const TELEMETRY_INTERVAL_MILLISECONDS: u64 = 1000;

// Resolves one exact immutable benchmark plan without exposing RuntimeManager state.
pub trait BenchmarkRunPlanProvider: Send + Sync {
    // Returns the deterministic plan for one job and exact request identity.
    fn plan(
        &self,
        job_id: &OperationId,
        request: &BenchmarkRequest,
    ) -> Result<BenchmarkRunPlan, BenchmarkError>;
}

// Binds model-neutral scheduling limits to one exact benchmark request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BenchmarkRunPlan {
    plan_sha256: Sha256Digest,
    request: BenchmarkRequest,
    request_sha256: Sha256Digest,
    benchmark_contract_sha256: Sha256Digest,
    execution_sha256: Sha256Digest,
    target_contract_sha256: Sha256Digest,
    record_schema: BenchmarkRecordSchema,
    total_cells: u32,
    maximum_runtime_milliseconds: u64,
    stop_grace_milliseconds: u64,
    telemetry_interval_milliseconds: u64,
}

impl BenchmarkRunPlan {
    // Creates one bounded plan from an already-resolved immutable request.
    pub fn new(
        request: &BenchmarkRequest,
        record_schema: BenchmarkRecordSchema,
        total_cells: u32,
        maximum_runtime_milliseconds: u64,
        stop_grace_milliseconds: u64,
        telemetry_interval_milliseconds: u64,
    ) -> Result<Self, BenchmarkError> {
        if total_cells == 0
            || total_cells > MAXIMUM_BENCHMARK_CELLS
            || !record_schema.is_success_record()
            || maximum_runtime_milliseconds == 0
            || maximum_runtime_milliseconds > MAXIMUM_BENCHMARK_RUNTIME_MILLISECONDS
            || stop_grace_milliseconds == 0
            || stop_grace_milliseconds > MAXIMUM_STOP_GRACE_MILLISECONDS
            || stop_grace_milliseconds > maximum_runtime_milliseconds
            || telemetry_interval_milliseconds != TELEMETRY_INTERVAL_MILLISECONDS
            || matches!(request.scope(), BenchmarkScope::Selected(cells) if cells.len() != total_cells as usize)
        {
            return Err(BenchmarkError::InvalidContract {
                reason: "benchmark run plan is invalid",
            });
        }
        let request_sha256 = request.sha256()?;
        let benchmark_contract_sha256 = request.subject().benchmark_contract_sha256().clone();
        let execution_sha256 = request.subject().execution_sha256().clone();
        let target_contract_sha256 = request.subject().target_contract_sha256().clone();
        let plan_sha256 = framed_digest(
            "li-benchmark-run-plan-v1",
            &[
                request_sha256.as_str(),
                benchmark_contract_sha256.as_str(),
                execution_sha256.as_str(),
                target_contract_sha256.as_str(),
                &record_schema.version().to_string(),
                &total_cells.to_string(),
                &maximum_runtime_milliseconds.to_string(),
                &stop_grace_milliseconds.to_string(),
                &telemetry_interval_milliseconds.to_string(),
            ],
        );
        Ok(Self {
            plan_sha256,
            request: request.clone(),
            request_sha256,
            benchmark_contract_sha256,
            execution_sha256,
            target_contract_sha256,
            record_schema,
            total_cells,
            maximum_runtime_milliseconds,
            stop_grace_milliseconds,
            telemetry_interval_milliseconds,
        })
    }

    // Returns the deterministic plan identity.
    pub const fn plan_sha256(&self) -> &Sha256Digest {
        &self.plan_sha256
    }

    // Returns the complete exact request required by the shell-free benchmark worker input.
    pub const fn request(&self) -> &BenchmarkRequest {
        &self.request
    }

    // Returns the exact manager request identity.
    pub const fn request_sha256(&self) -> &Sha256Digest {
        &self.request_sha256
    }

    // Returns the exact public benchmark contract identity.
    pub const fn benchmark_contract_sha256(&self) -> &Sha256Digest {
        &self.benchmark_contract_sha256
    }

    // Returns the opaque runtime execution identity.
    pub const fn execution_sha256(&self) -> &Sha256Digest {
        &self.execution_sha256
    }

    // Returns the immutable physical target contract identity.
    pub const fn target_contract_sha256(&self) -> &Sha256Digest {
        &self.target_contract_sha256
    }

    // Returns the OCI or native record schema expected from the worker.
    pub const fn record_schema(&self) -> BenchmarkRecordSchema {
        self.record_schema
    }

    // Returns the exact number of deterministic workload cells.
    pub const fn total_cells(&self) -> u32 {
        self.total_cells
    }

    // Returns the hard detached-task runtime ceiling.
    pub const fn maximum_runtime_milliseconds(&self) -> u64 {
        self.maximum_runtime_milliseconds
    }

    // Returns the graceful cancellation window before scheduler containment.
    pub const fn stop_grace_milliseconds(&self) -> u64 {
        self.stop_grace_milliseconds
    }

    // Returns the exact Watchdog/Gateway telemetry window size.
    pub const fn telemetry_interval_milliseconds(&self) -> u64 {
        self.telemetry_interval_milliseconds
    }

    // Verifies that a replayed plan still belongs to the exact request.
    fn require_request(&self, request: &BenchmarkRequest) -> Result<(), BenchmarkError> {
        if &request.sha256()? != self.request_sha256()
            || request.subject().benchmark_contract_sha256() != self.benchmark_contract_sha256()
            || request.subject().execution_sha256() != self.execution_sha256()
            || request.subject().target_contract_sha256() != self.target_contract_sha256()
        {
            return Err(BenchmarkError::InvalidContract {
                reason: "benchmark run plan differs from its request",
            });
        }
        Ok(())
    }
}

// Commands the sole typed preparation boundary over Placement, Gateway, and Watchdog.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BenchmarkExecutionPreparation {
    job_id: OperationId,
    plan: BenchmarkRunPlan,
    authorization_receipt_id: Sha256Digest,
    prepared_receipt_id: Sha256Digest,
}

impl BenchmarkExecutionPreparation {
    // Returns the benchmark operation identity.
    pub const fn job_id(&self) -> &OperationId {
        &self.job_id
    }

    // Returns the complete immutable scheduling plan.
    pub const fn plan(&self) -> &BenchmarkRunPlan {
        &self.plan
    }

    // Returns the admission receipt without authority material.
    pub const fn authorization_receipt_id(&self) -> &Sha256Digest {
        &self.authorization_receipt_id
    }

    // Returns the deterministic resident-snapshot receipt identity.
    pub const fn prepared_receipt_id(&self) -> &Sha256Digest {
        &self.prepared_receipt_id
    }
}

// Commands one shell-free typed benchmark task launch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BenchmarkExecutionLaunch {
    job_id: OperationId,
    plan: BenchmarkRunPlan,
    prepared_receipt_id: Sha256Digest,
    running_receipt_id: Sha256Digest,
}

impl BenchmarkExecutionLaunch {
    // Returns the benchmark operation identity.
    pub const fn job_id(&self) -> &OperationId {
        &self.job_id
    }

    // Returns the exact model-neutral run plan.
    pub const fn plan(&self) -> &BenchmarkRunPlan {
        &self.plan
    }

    // Returns the prepared resident-state receipt.
    pub const fn prepared_receipt_id(&self) -> &Sha256Digest {
        &self.prepared_receipt_id
    }

    // Returns the deterministic detached task identity.
    pub const fn running_receipt_id(&self) -> &Sha256Digest {
        &self.running_receipt_id
    }
}

// Identifies why the scheduler must stop one exact detached task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BenchmarkSchedulerStopReason {
    Cancellation,
    Timeout,
    InvalidResult,
}

// Carries exact immutable result identities before public evidence materialization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BenchmarkExecutionArtifact {
    raw_evidence_sha256: Sha256Digest,
    results_sha256: Sha256Digest,
    benchmark_contract_sha256: Sha256Digest,
    execution_sha256: Sha256Digest,
    target_contract_sha256: Sha256Digest,
    record_schema: BenchmarkRecordSchema,
    byte_count: u64,
}

impl BenchmarkExecutionArtifact {
    // Creates one bounded worker artifact without reading its provider-owned bytes.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        raw_evidence_sha256: Sha256Digest,
        results_sha256: Sha256Digest,
        benchmark_contract_sha256: Sha256Digest,
        execution_sha256: Sha256Digest,
        target_contract_sha256: Sha256Digest,
        record_schema: BenchmarkRecordSchema,
        byte_count: u64,
    ) -> Result<Self, BenchmarkError> {
        if byte_count == 0
            || byte_count > MAXIMUM_RESULT_BYTES
            || !record_schema.is_success_record()
        {
            return Err(BenchmarkError::InvalidContract {
                reason: "benchmark execution artifact size is invalid",
            });
        }
        Ok(Self {
            raw_evidence_sha256,
            results_sha256,
            benchmark_contract_sha256,
            execution_sha256,
            target_contract_sha256,
            record_schema,
            byte_count,
        })
    }

    // Returns the digest of exact canonical worker bytes.
    pub const fn raw_evidence_sha256(&self) -> &Sha256Digest {
        &self.raw_evidence_sha256
    }

    // Returns the schema-owned result material identity.
    pub const fn results_sha256(&self) -> &Sha256Digest {
        &self.results_sha256
    }

    // Returns the exact benchmark contract identity.
    pub const fn benchmark_contract_sha256(&self) -> &Sha256Digest {
        &self.benchmark_contract_sha256
    }

    // Returns the exact runtime execution identity.
    pub const fn execution_sha256(&self) -> &Sha256Digest {
        &self.execution_sha256
    }

    // Returns the exact target contract identity.
    pub const fn target_contract_sha256(&self) -> &Sha256Digest {
        &self.target_contract_sha256
    }

    // Returns the preserved successful record schema.
    pub const fn record_schema(&self) -> BenchmarkRecordSchema {
        self.record_schema
    }

    // Returns the bounded canonical record byte count.
    pub const fn byte_count(&self) -> u64 {
        self.byte_count
    }

    // Requires every worker identity to match the immutable run plan.
    fn matches_plan(&self, plan: &BenchmarkRunPlan) -> bool {
        self.benchmark_contract_sha256() == plan.benchmark_contract_sha256()
            && self.execution_sha256() == plan.execution_sha256()
            && self.target_contract_sha256() == plan.target_contract_sha256()
            && self.record_schema() == plan.record_schema()
    }
}

// Reports one typed scheduler terminal state without arbitrary process output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BenchmarkScheduledTerminal {
    Succeeded(BenchmarkExecutionArtifact),
    Failed {
        artifact: Option<BenchmarkExecutionArtifact>,
        failure: BenchmarkFailure,
    },
    Cancelled {
        artifact: Option<BenchmarkExecutionArtifact>,
    },
}

// Reports one exact detached task state from the scheduler.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BenchmarkScheduledState {
    Running(BenchmarkProgress),
    Terminal(BenchmarkScheduledTerminal),
}

// Binds one scheduler observation to its prepared plan and original start time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BenchmarkScheduledExecution {
    job_id: OperationId,
    plan: BenchmarkRunPlan,
    prepared_receipt_id: Sha256Digest,
    running_receipt_id: Sha256Digest,
    started_at: UnixMilliseconds,
    state: BenchmarkScheduledState,
}

impl BenchmarkScheduledExecution {
    // Creates one complete persistent scheduler observation.
    pub fn new(
        job_id: OperationId,
        plan: BenchmarkRunPlan,
        prepared_receipt_id: Sha256Digest,
        running_receipt_id: Sha256Digest,
        started_at: UnixMilliseconds,
        state: BenchmarkScheduledState,
    ) -> Result<Self, BenchmarkError> {
        if started_at.value() == 0 {
            return Err(BenchmarkError::InvalidContract {
                reason: "benchmark scheduler start time is invalid",
            });
        }
        Ok(Self {
            job_id,
            plan,
            prepared_receipt_id,
            running_receipt_id,
            started_at,
            state,
        })
    }

    // Returns the exact benchmark operation identity.
    pub const fn job_id(&self) -> &OperationId {
        &self.job_id
    }

    // Returns the immutable run plan retained across restart.
    pub const fn plan(&self) -> &BenchmarkRunPlan {
        &self.plan
    }

    // Returns the deterministic preparation identity.
    pub const fn prepared_receipt_id(&self) -> &Sha256Digest {
        &self.prepared_receipt_id
    }

    // Returns the deterministic detached-task identity.
    pub const fn running_receipt_id(&self) -> &Sha256Digest {
        &self.running_receipt_id
    }

    // Returns the first successful task start time.
    pub const fn started_at(&self) -> UnixMilliseconds {
        self.started_at
    }

    // Returns the current typed scheduler state.
    pub const fn state(&self) -> &BenchmarkScheduledState {
        &self.state
    }
}

// Commands one exact cleanup and resident-service restoration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BenchmarkExecutionRestoration {
    job_id: OperationId,
    plan: BenchmarkRunPlan,
    prepared_receipt_id: Sha256Digest,
    running_receipt_id: Option<Sha256Digest>,
    outcome: BenchmarkExecutionOutcome,
    restoration_receipt_id: Sha256Digest,
}

impl BenchmarkExecutionRestoration {
    // Returns the exact benchmark operation identity.
    pub const fn job_id(&self) -> &OperationId {
        &self.job_id
    }

    // Returns the immutable run plan whose resources must be restored.
    pub const fn plan(&self) -> &BenchmarkRunPlan {
        &self.plan
    }

    // Returns the prepared resident-state identity.
    pub const fn prepared_receipt_id(&self) -> &Sha256Digest {
        &self.prepared_receipt_id
    }

    // Returns the detached task identity when a launch occurred.
    pub const fn running_receipt_id(&self) -> Option<&Sha256Digest> {
        self.running_receipt_id.as_ref()
    }

    // Returns the exact terminal result that triggered cleanup.
    pub const fn outcome(&self) -> &BenchmarkExecutionOutcome {
        &self.outcome
    }

    // Returns the deterministic restoration proof identity.
    pub const fn restoration_receipt_id(&self) -> &Sha256Digest {
        &self.restoration_receipt_id
    }
}

// Bridges typed benchmark commands to Placement, Gateway, Watchdog, and the task runner.
pub trait BenchmarkExecutionScheduler: Send + Sync {
    // Snapshots resident intent and reserves one isolated benchmark execution idempotently.
    fn prepare(&self, command: &BenchmarkExecutionPreparation) -> Result<(), BenchmarkError>;

    // Starts or reattaches to the exact typed task without a shell.
    fn start(&self, command: &BenchmarkExecutionLaunch) -> Result<(), BenchmarkError>;

    // Returns the persistent state of only the exact detached task.
    fn observe(
        &self,
        job_id: &OperationId,
        running: &RunningBenchmark,
    ) -> Result<BenchmarkScheduledExecution, BenchmarkError>;

    // Requests bounded scheduler containment idempotently.
    fn request_stop(
        &self,
        job_id: &OperationId,
        running: &RunningBenchmark,
        reason: BenchmarkSchedulerStopReason,
    ) -> Result<(), BenchmarkError>;

    // Removes benchmark resources and restores exact resident intent idempotently.
    fn restore(&self, command: &BenchmarkExecutionRestoration) -> Result<(), BenchmarkError>;
}

// Adapts the deterministic scheduler contract to BenchmarkManager execution.
pub struct CoordinatedBenchmarkExecutionProvider {
    plans: Arc<dyn BenchmarkRunPlanProvider>,
    scheduler: Arc<dyn BenchmarkExecutionScheduler>,
    clock: Arc<dyn BenchmarkClock>,
}

impl CoordinatedBenchmarkExecutionProvider {
    // Creates one execution provider from explicit immutable-plan, scheduler, and clock ports.
    pub const fn new(
        plans: Arc<dyn BenchmarkRunPlanProvider>,
        scheduler: Arc<dyn BenchmarkExecutionScheduler>,
        clock: Arc<dyn BenchmarkClock>,
    ) -> Self {
        Self {
            plans,
            scheduler,
            clock,
        }
    }

    // Resolves and independently rebinds one plan to its exact request.
    fn plan(
        &self,
        job_id: &OperationId,
        request: &BenchmarkRequest,
    ) -> Result<BenchmarkRunPlan, BenchmarkError> {
        let plan = self
            .plans
            .plan(job_id, request)
            .map_err(|_| execution_error("execution plan is unavailable"))?;
        plan.require_request(request)?;
        Ok(plan)
    }

    // Reads one positive provider clock value without exposing its implementation.
    fn now(&self) -> Result<UnixMilliseconds, BenchmarkError> {
        self.clock
            .now()
            .map_err(|_| execution_error("execution clock is unavailable"))
            .and_then(|now| {
                (now.value() > 0)
                    .then_some(now)
                    .ok_or_else(|| execution_error("execution clock is invalid"))
            })
    }

    // Validates one scheduler observation against deterministic task identities.
    fn require_observation(
        &self,
        job_id: &OperationId,
        running: &RunningBenchmark,
        scheduled: &BenchmarkScheduledExecution,
    ) -> Result<(), BenchmarkError> {
        let expected_running =
            running_receipt(job_id, scheduled.plan(), scheduled.prepared_receipt_id());
        if scheduled.job_id() != job_id
            || scheduled.running_receipt_id() != running.receipt_id()
            || &expected_running != running.receipt_id()
        {
            return Err(execution_error("scheduler observation identity is invalid"));
        }
        Ok(())
    }

    // Converts one exact scheduler terminal state into the manager outcome contract.
    fn terminal_outcome(
        &self,
        plan: &BenchmarkRunPlan,
        terminal: &BenchmarkScheduledTerminal,
    ) -> Result<BenchmarkExecutionOutcome, BenchmarkError> {
        match terminal {
            BenchmarkScheduledTerminal::Succeeded(artifact) if artifact.matches_plan(plan) => {
                Ok(BenchmarkExecutionOutcome::Succeeded {
                    raw_evidence_sha256: artifact.raw_evidence_sha256().clone(),
                    results_sha256: artifact.results_sha256().clone(),
                    record_schema: artifact.record_schema(),
                })
            }
            BenchmarkScheduledTerminal::Succeeded(_) => Ok(invalid_result_outcome()?),
            BenchmarkScheduledTerminal::Failed { artifact, failure } => {
                let raw_evidence_sha256 = artifact
                    .as_ref()
                    .filter(|artifact| artifact.matches_plan(plan))
                    .map(|artifact| artifact.raw_evidence_sha256().clone());
                Ok(BenchmarkExecutionOutcome::Failed {
                    raw_evidence_sha256,
                    failure: failure.clone(),
                })
            }
            BenchmarkScheduledTerminal::Cancelled { artifact } => {
                let raw_evidence_sha256 = artifact
                    .as_ref()
                    .filter(|artifact| artifact.matches_plan(plan))
                    .map(|artifact| artifact.raw_evidence_sha256().clone());
                Ok(BenchmarkExecutionOutcome::Cancelled {
                    raw_evidence_sha256,
                })
            }
        }
    }
}

impl BenchmarkExecutionProvider for CoordinatedBenchmarkExecutionProvider {
    // Prepares one deterministic isolated execution without starting inference.
    fn prepare(
        &self,
        job_id: &OperationId,
        request: &BenchmarkRequest,
        authorization: &BenchmarkAuthorization,
    ) -> Result<PreparedBenchmark, BenchmarkError> {
        let plan = self.plan(job_id, request)?;
        let prepared_receipt_id = prepared_receipt(job_id, &plan);
        let command = BenchmarkExecutionPreparation {
            job_id: job_id.clone(),
            plan,
            authorization_receipt_id: authorization.receipt_id().clone(),
            prepared_receipt_id: prepared_receipt_id.clone(),
        };
        self.scheduler
            .prepare(&command)
            .map_err(|_| execution_error("execution preparation failed"))?;
        Ok(PreparedBenchmark::new(prepared_receipt_id))
    }

    // Starts or reattaches to one exact typed detached task idempotently.
    fn start(
        &self,
        job_id: &OperationId,
        request: &BenchmarkRequest,
        prepared: &PreparedBenchmark,
    ) -> Result<RunningBenchmark, BenchmarkError> {
        let plan = self.plan(job_id, request)?;
        if prepared.receipt_id() != &prepared_receipt(job_id, &plan) {
            return Err(execution_error("prepared execution identity is invalid"));
        }
        let running_receipt_id = running_receipt(job_id, &plan, prepared.receipt_id());
        let command = BenchmarkExecutionLaunch {
            job_id: job_id.clone(),
            plan,
            prepared_receipt_id: prepared.receipt_id().clone(),
            running_receipt_id: running_receipt_id.clone(),
        };
        self.scheduler
            .start(&command)
            .map_err(|_| execution_error("execution launch failed"))?;
        Ok(RunningBenchmark::new(running_receipt_id))
    }

    // Observes progress, enforces timeout, and validates exact terminal result identities.
    fn observe(
        &self,
        job_id: &OperationId,
        running: &RunningBenchmark,
    ) -> Result<BenchmarkExecutionObservation, BenchmarkError> {
        let scheduled = self
            .scheduler
            .observe(job_id, running)
            .map_err(|_| execution_error("execution observation failed"))?;
        self.require_observation(job_id, running, &scheduled)?;
        match scheduled.state() {
            BenchmarkScheduledState::Terminal(terminal) => self
                .terminal_outcome(scheduled.plan(), terminal)
                .map(BenchmarkExecutionObservation::Terminal),
            BenchmarkScheduledState::Running(progress) => {
                if progress.total_cells() != scheduled.plan().total_cells() {
                    self.scheduler
                        .request_stop(job_id, running, BenchmarkSchedulerStopReason::InvalidResult)
                        .map_err(|_| execution_error("invalid execution containment failed"))?;
                    return Ok(BenchmarkExecutionObservation::Running(stopping_progress(
                        scheduled.plan().total_cells(),
                    )?));
                }
                let now = self.now()?;
                if now < scheduled.started_at() {
                    return Err(execution_error("execution clock moved backwards"));
                }
                let deadline = scheduled
                    .started_at()
                    .value()
                    .checked_add(scheduled.plan().maximum_runtime_milliseconds())
                    .ok_or_else(|| execution_error("execution deadline is invalid"))?;
                if now.value() >= deadline {
                    self.scheduler
                        .request_stop(job_id, running, BenchmarkSchedulerStopReason::Timeout)
                        .map_err(|_| execution_error("timed-out execution containment failed"))?;
                }
                Ok(BenchmarkExecutionObservation::Running(progress.clone()))
            }
        }
    }

    // Requests graceful cancellation of only the exact running task.
    fn request_stop(
        &self,
        job_id: &OperationId,
        running: &RunningBenchmark,
    ) -> Result<(), BenchmarkError> {
        self.scheduler
            .request_stop(job_id, running, BenchmarkSchedulerStopReason::Cancellation)
            .map_err(|_| execution_error("execution cancellation failed"))
    }

    // Restores exact resident intent after every success, failure, timeout, or cancellation.
    fn restore(
        &self,
        job_id: &OperationId,
        request: &BenchmarkRequest,
        prepared: &PreparedBenchmark,
        running: Option<&RunningBenchmark>,
        outcome: &BenchmarkExecutionOutcome,
    ) -> Result<BenchmarkRestoration, BenchmarkError> {
        let plan = self.plan(job_id, request)?;
        if prepared.receipt_id() != &prepared_receipt(job_id, &plan)
            || running.is_some_and(|running| {
                running.receipt_id() != &running_receipt(job_id, &plan, prepared.receipt_id())
            })
        {
            return Err(execution_error("restoration execution identity is invalid"));
        }
        let restoration_receipt_id = restoration_receipt(
            job_id,
            &plan,
            prepared.receipt_id(),
            running.map(RunningBenchmark::receipt_id),
            outcome,
        );
        let command = BenchmarkExecutionRestoration {
            job_id: job_id.clone(),
            plan,
            prepared_receipt_id: prepared.receipt_id().clone(),
            running_receipt_id: running.map(|running| running.receipt_id().clone()),
            outcome: outcome.clone(),
            restoration_receipt_id: restoration_receipt_id.clone(),
        };
        self.scheduler
            .restore(&command)
            .map_err(|_| execution_error("resident restoration failed"))?;
        Ok(BenchmarkRestoration::new(restoration_receipt_id))
    }
}

// Returns one deterministic preparation receipt.
fn prepared_receipt(job_id: &OperationId, plan: &BenchmarkRunPlan) -> Sha256Digest {
    framed_digest(
        "li-benchmark-prepared-v1",
        &[job_id.as_str(), plan.plan_sha256().as_str()],
    )
}

// Returns one deterministic detached-task receipt.
fn running_receipt(
    job_id: &OperationId,
    plan: &BenchmarkRunPlan,
    prepared_receipt_id: &Sha256Digest,
) -> Sha256Digest {
    framed_digest(
        "li-benchmark-running-v1",
        &[
            job_id.as_str(),
            plan.plan_sha256().as_str(),
            prepared_receipt_id.as_str(),
        ],
    )
}

// Returns one deterministic restoration proof identity.
fn restoration_receipt(
    job_id: &OperationId,
    plan: &BenchmarkRunPlan,
    prepared_receipt_id: &Sha256Digest,
    running_receipt_id: Option<&Sha256Digest>,
    outcome: &BenchmarkExecutionOutcome,
) -> Sha256Digest {
    let running = running_receipt_id.map_or("none", Sha256Digest::as_str);
    let outcome = outcome_identity(outcome);
    framed_digest(
        "li-benchmark-restoration-v1",
        &[
            job_id.as_str(),
            plan.plan_sha256().as_str(),
            prepared_receipt_id.as_str(),
            running,
            &outcome,
        ],
    )
}

// Returns one stable outcome identity without raw provider output.
pub(crate) fn outcome_identity(outcome: &BenchmarkExecutionOutcome) -> String {
    match outcome {
        BenchmarkExecutionOutcome::Succeeded {
            raw_evidence_sha256,
            results_sha256,
            record_schema,
        } => format!(
            "succeeded:{}:{}:{}",
            raw_evidence_sha256.as_str(),
            results_sha256.as_str(),
            record_schema.version()
        ),
        BenchmarkExecutionOutcome::Failed {
            raw_evidence_sha256,
            failure,
        } => format!(
            "failed:{}:{}:{}:{}:{}",
            raw_evidence_sha256
                .as_ref()
                .map_or("none", Sha256Digest::as_str),
            failure.category().as_str(),
            failure.phase().as_str(),
            failure.description().code().as_str(),
            failure.description().message()
        ),
        BenchmarkExecutionOutcome::Cancelled {
            raw_evidence_sha256,
        } => format!(
            "cancelled:{}",
            raw_evidence_sha256
                .as_ref()
                .map_or("none", Sha256Digest::as_str)
        ),
    }
}

// Returns one bounded stable failure for an invalid worker result identity.
fn invalid_result_outcome() -> Result<BenchmarkExecutionOutcome, BenchmarkError> {
    Ok(BenchmarkExecutionOutcome::Failed {
        raw_evidence_sha256: None,
        failure: BenchmarkFailure::new(
            BenchmarkFailureCategory::OutputValidation,
            "result_validation",
            "benchmark result identity is invalid",
        )?,
    })
}

// Returns one stable progress state after malformed scheduler progress is contained.
fn stopping_progress(total_cells: u32) -> Result<BenchmarkProgress, BenchmarkError> {
    BenchmarkProgress::new(
        TechnicalName::parse("stopping").map_err(|_| BenchmarkError::InvalidContract {
            reason: "benchmark stopping phase is invalid",
        })?,
        0,
        total_cells,
    )
}

// Hashes one length-framed internal identity without JSON or delimiter ambiguity.
pub(crate) fn framed_digest(contract: &str, fields: &[&str]) -> Sha256Digest {
    let mut digest = Sha256::new();
    for field in std::iter::once(contract).chain(fields.iter().copied()) {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field.as_bytes());
    }
    let digest = digest.finalize();
    Sha256Digest::parse(&format!("{digest:x}")).expect("SHA-256 formatting is canonical")
}

// Returns one stable redacted execution-provider failure.
fn execution_error(reason: &'static str) -> BenchmarkError {
    BenchmarkError::provider("execution", reason)
}
