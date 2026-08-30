// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use li_core_interface::{OperationId, Sha256Digest, UnixMilliseconds};

use crate::li_benchmark_execution::{framed_digest, outcome_identity};
use crate::{
    BenchmarkClock, BenchmarkError, BenchmarkExecutionOutcome, BenchmarkProgress, BenchmarkRequest,
    BenchmarkRunPlan, BenchmarkRunPlanProvider, BenchmarkTelemetryProvider,
    BenchmarkTelemetryReceipt, PreparedBenchmark,
};

// Commands an idempotent telemetry timeline open before execution starts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BenchmarkTelemetryOpen {
    job_id: OperationId,
    plan: BenchmarkRunPlan,
    prepared_receipt_id: Sha256Digest,
    session_receipt_id: Sha256Digest,
    proposed_opened_at: UnixMilliseconds,
}

impl BenchmarkTelemetryOpen {
    // Returns the exact benchmark operation identity.
    pub const fn job_id(&self) -> &OperationId {
        &self.job_id
    }

    // Returns the immutable run plan whose system observations are sampled.
    pub const fn plan(&self) -> &BenchmarkRunPlan {
        &self.plan
    }

    // Returns the resident-state preparation identity.
    pub const fn prepared_receipt_id(&self) -> &Sha256Digest {
        &self.prepared_receipt_id
    }

    // Returns the deterministic telemetry-session identity.
    pub const fn session_receipt_id(&self) -> &Sha256Digest {
        &self.session_receipt_id
    }

    // Returns the proposed first-open time ignored by an existing replay.
    pub const fn proposed_opened_at(&self) -> UnixMilliseconds {
        self.proposed_opened_at
    }
}

// Commands materialization through one exact fixed telemetry window.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BenchmarkTelemetrySynchronization {
    job_id: OperationId,
    session_receipt_id: Sha256Digest,
    through: UnixMilliseconds,
    progress: BenchmarkProgress,
}

impl BenchmarkTelemetrySynchronization {
    // Returns the exact benchmark operation identity.
    pub const fn job_id(&self) -> &OperationId {
        &self.job_id
    }

    // Returns the deterministic open-session identity.
    pub const fn session_receipt_id(&self) -> &Sha256Digest {
        &self.session_receipt_id
    }

    // Returns the inclusive observation boundary for complete fixed windows.
    pub const fn through(&self) -> UnixMilliseconds {
        self.through
    }

    // Returns the exact model-neutral lifecycle progress accompanying the sample.
    pub const fn progress(&self) -> &BenchmarkProgress {
        &self.progress
    }
}

// Commands sealing of one exact telemetry timeline after execution terminates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BenchmarkTelemetryFinish {
    job_id: OperationId,
    session_receipt_id: Sha256Digest,
    through: UnixMilliseconds,
    outcome: BenchmarkExecutionOutcome,
}

impl BenchmarkTelemetryFinish {
    // Returns the exact benchmark operation identity.
    pub const fn job_id(&self) -> &OperationId {
        &self.job_id
    }

    // Returns the deterministic open-session identity.
    pub const fn session_receipt_id(&self) -> &Sha256Digest {
        &self.session_receipt_id
    }

    // Returns the inclusive observation boundary for final complete windows.
    pub const fn through(&self) -> UnixMilliseconds {
        self.through
    }

    // Returns the exact execution outcome bound into the sealed timeline.
    pub const fn outcome(&self) -> &BenchmarkExecutionOutcome {
        &self.outcome
    }
}

// Describes one durable telemetry timeline reconstructed across Core restart.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BenchmarkTelemetryState {
    job_id: OperationId,
    plan: BenchmarkRunPlan,
    prepared_receipt_id: Sha256Digest,
    session_receipt_id: Sha256Digest,
    opened_at: UnixMilliseconds,
    last_sample_at: Option<UnixMilliseconds>,
    sample_count: u64,
    samples_sha256: Sha256Digest,
    progress: Option<BenchmarkProgress>,
    sealed_at: Option<UnixMilliseconds>,
    sealed_receipt_id: Option<Sha256Digest>,
}

impl BenchmarkTelemetryState {
    // Creates one empty persistent timeline from an exact first-open command.
    pub fn opened(command: &BenchmarkTelemetryOpen) -> Result<Self, BenchmarkError> {
        Self::new(
            command.job_id().clone(),
            command.plan().clone(),
            command.prepared_receipt_id().clone(),
            command.session_receipt_id().clone(),
            command.proposed_opened_at(),
            None,
            0,
            empty_samples_sha256(command.job_id(), command.session_receipt_id()),
            None,
            None,
            None,
        )
    }

    // Creates one bounded persistent telemetry state returned by an injected port.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        job_id: OperationId,
        plan: BenchmarkRunPlan,
        prepared_receipt_id: Sha256Digest,
        session_receipt_id: Sha256Digest,
        opened_at: UnixMilliseconds,
        last_sample_at: Option<UnixMilliseconds>,
        sample_count: u64,
        samples_sha256: Sha256Digest,
        progress: Option<BenchmarkProgress>,
        sealed_at: Option<UnixMilliseconds>,
        sealed_receipt_id: Option<Sha256Digest>,
    ) -> Result<Self, BenchmarkError> {
        let maximum_samples = maximum_sample_count(&plan)?;
        let expected_last_sample = if sample_count == 0 {
            None
        } else {
            let elapsed = sample_count
                .checked_mul(plan.telemetry_interval_milliseconds())
                .ok_or(BenchmarkError::InvalidContract {
                    reason: "benchmark telemetry sample timeline overflowed",
                })?;
            Some(UnixMilliseconds::new(
                opened_at
                    .value()
                    .checked_add(elapsed)
                    .ok_or(BenchmarkError::InvalidContract {
                        reason: "benchmark telemetry sample time overflowed",
                    })?,
            ))
        };
        let sealed_windows_are_exact = sealed_at.is_none_or(|sealed_at| {
            sealed_at
                .value()
                .checked_sub(opened_at.value())
                .map(|elapsed| elapsed / plan.telemetry_interval_milliseconds())
                == Some(sample_count)
        });
        if opened_at.value() == 0
            || sample_count > maximum_samples
            || last_sample_at != expected_last_sample
            || progress
                .as_ref()
                .is_some_and(|progress| progress.total_cells() != plan.total_cells())
            || sealed_at.is_some() != sealed_receipt_id.is_some()
            || !sealed_windows_are_exact
        {
            return Err(BenchmarkError::InvalidContract {
                reason: "benchmark telemetry state is invalid",
            });
        }
        if sample_count == 0 && samples_sha256 != empty_samples_sha256(&job_id, &session_receipt_id)
        {
            return Err(BenchmarkError::InvalidContract {
                reason: "empty benchmark telemetry identity is invalid",
            });
        }
        Ok(Self {
            job_id,
            plan,
            prepared_receipt_id,
            session_receipt_id,
            opened_at,
            last_sample_at,
            sample_count,
            samples_sha256,
            progress,
            sealed_at,
            sealed_receipt_id,
        })
    }

    // Returns the exact benchmark operation identity.
    pub const fn job_id(&self) -> &OperationId {
        &self.job_id
    }

    // Returns the immutable run plan retained by the telemetry store.
    pub const fn plan(&self) -> &BenchmarkRunPlan {
        &self.plan
    }

    // Returns the prepared resident-state identity.
    pub const fn prepared_receipt_id(&self) -> &Sha256Digest {
        &self.prepared_receipt_id
    }

    // Returns the deterministic timeline session identity.
    pub const fn session_receipt_id(&self) -> &Sha256Digest {
        &self.session_receipt_id
    }

    // Returns the immutable first-open time.
    pub const fn opened_at(&self) -> UnixMilliseconds {
        self.opened_at
    }

    // Returns the boundary of the last complete fixed telemetry window.
    pub const fn last_sample_at(&self) -> Option<UnixMilliseconds> {
        self.last_sample_at
    }

    // Returns the number of contiguous fixed telemetry windows.
    pub const fn sample_count(&self) -> u64 {
        self.sample_count
    }

    // Returns the cumulative canonical telemetry timeline identity.
    pub const fn samples_sha256(&self) -> &Sha256Digest {
        &self.samples_sha256
    }

    // Returns the most recent progress bound to a synchronization.
    pub const fn progress(&self) -> Option<&BenchmarkProgress> {
        self.progress.as_ref()
    }

    // Returns the immutable final observation boundary when sealed.
    pub const fn sealed_at(&self) -> Option<UnixMilliseconds> {
        self.sealed_at
    }

    // Returns the immutable final receipt when the timeline is sealed.
    pub const fn sealed_receipt_id(&self) -> Option<&Sha256Digest> {
        self.sealed_receipt_id.as_ref()
    }

    // Returns a synchronized state with every complete window through one boundary.
    pub fn synchronized(
        &self,
        through: UnixMilliseconds,
        samples_sha256: Sha256Digest,
        progress: BenchmarkProgress,
    ) -> Result<Self, BenchmarkError> {
        if through < self.opened_at || self.sealed_receipt_id.is_some() {
            return Err(BenchmarkError::InvalidContract {
                reason: "benchmark telemetry synchronization is invalid",
            });
        }
        let sample_count = (through.value() - self.opened_at.value())
            / self.plan.telemetry_interval_milliseconds();
        if sample_count < self.sample_count {
            return Err(BenchmarkError::InvalidContract {
                reason: "benchmark telemetry synchronization moved backwards",
            });
        }
        let elapsed = sample_count
            .checked_mul(self.plan.telemetry_interval_milliseconds())
            .ok_or(BenchmarkError::InvalidContract {
                reason: "benchmark telemetry sample timeline overflowed",
            })?;
        let last_sample_at = if sample_count == 0 {
            None
        } else {
            Some(UnixMilliseconds::new(
                self.opened_at.value().checked_add(elapsed).ok_or(
                    BenchmarkError::InvalidContract {
                        reason: "benchmark telemetry sample time overflowed",
                    },
                )?,
            ))
        };
        Self::new(
            self.job_id.clone(),
            self.plan.clone(),
            self.prepared_receipt_id.clone(),
            self.session_receipt_id.clone(),
            self.opened_at,
            last_sample_at,
            sample_count,
            samples_sha256,
            Some(progress),
            None,
            None,
        )
    }

    // Returns one state sealed to its exact sample timeline and terminal outcome.
    pub fn sealed(
        &self,
        sealed_at: UnixMilliseconds,
        outcome: &BenchmarkExecutionOutcome,
    ) -> Result<Self, BenchmarkError> {
        if self.sealed_receipt_id.is_some() {
            let expected = telemetry_receipt(&self.job_id, self, self.sample_count, outcome);
            if self.sealed_receipt_id.as_ref() == Some(&expected) {
                return Ok(self.clone());
            }
            return Err(BenchmarkError::InvalidContract {
                reason: "benchmark telemetry seal identity is invalid",
            });
        }
        let expected_count = sealed_at
            .value()
            .checked_sub(self.opened_at.value())
            .map(|elapsed| elapsed / self.plan.telemetry_interval_milliseconds())
            .ok_or(BenchmarkError::InvalidContract {
                reason: "benchmark telemetry seal time is invalid",
            })?;
        if expected_count != self.sample_count {
            return Err(BenchmarkError::InvalidContract {
                reason: "benchmark telemetry seal windows are incomplete",
            });
        }
        let mut sealed = self.clone();
        sealed.sealed_at = Some(sealed_at);
        sealed.sealed_receipt_id = Some(telemetry_receipt(
            &self.job_id,
            &sealed,
            self.sample_count,
            outcome,
        ));
        Ok(sealed)
    }
}

// Bridges telemetry commands to durable Watchdog and Gateway observations.
pub trait BenchmarkTelemetryPort: Send + Sync {
    // Opens or returns one existing timeline without replacing its first-open time.
    fn open(
        &self,
        command: &BenchmarkTelemetryOpen,
    ) -> Result<BenchmarkTelemetryState, BenchmarkError>;

    // Reads one persistent timeline without observing or mutating live state.
    fn state(
        &self,
        job_id: &OperationId,
    ) -> Result<Option<BenchmarkTelemetryState>, BenchmarkError>;

    // Materializes every complete one-second window through the supplied boundary.
    fn synchronize(
        &self,
        command: &BenchmarkTelemetrySynchronization,
    ) -> Result<BenchmarkTelemetryState, BenchmarkError>;

    // Materializes final complete windows and seals one exact timeline idempotently.
    fn finish(
        &self,
        command: &BenchmarkTelemetryFinish,
    ) -> Result<BenchmarkTelemetryState, BenchmarkError>;
}

// Adapts persistent Watchdog/Gateway windows to the BenchmarkManager telemetry contract.
pub struct WindowedBenchmarkTelemetryProvider {
    plans: Arc<dyn BenchmarkRunPlanProvider>,
    telemetry: Arc<dyn BenchmarkTelemetryPort>,
    clock: Arc<dyn BenchmarkClock>,
}

impl WindowedBenchmarkTelemetryProvider {
    // Creates one provider from exact plan, persistent telemetry, and clock ports.
    pub const fn new(
        plans: Arc<dyn BenchmarkRunPlanProvider>,
        telemetry: Arc<dyn BenchmarkTelemetryPort>,
        clock: Arc<dyn BenchmarkClock>,
    ) -> Self {
        Self {
            plans,
            telemetry,
            clock,
        }
    }

    // Returns one positive provider clock value with stable redacted failures.
    fn now(&self) -> Result<UnixMilliseconds, BenchmarkError> {
        self.clock
            .now()
            .map_err(|_| telemetry_error("telemetry clock is unavailable"))
            .and_then(|now| {
                (now.value() > 0)
                    .then_some(now)
                    .ok_or_else(|| telemetry_error("telemetry clock is invalid"))
            })
    }

    // Reads one existing timeline or fails closed without fabricating state.
    fn state(&self, job_id: &OperationId) -> Result<BenchmarkTelemetryState, BenchmarkError> {
        self.telemetry
            .state(job_id)
            .map_err(|_| telemetry_error("telemetry state is unavailable"))?
            .ok_or_else(|| telemetry_error("telemetry timeline was not opened"))
    }

    // Requires one port state to retain the exact immutable timeline identity.
    fn require_identity(
        &self,
        state: &BenchmarkTelemetryState,
        job_id: &OperationId,
    ) -> Result<(), BenchmarkError> {
        let expected_session =
            telemetry_session_receipt(job_id, state.plan(), state.prepared_receipt_id());
        if state.job_id() != job_id || state.session_receipt_id() != &expected_session {
            return Err(telemetry_error("telemetry timeline identity is invalid"));
        }
        Ok(())
    }

    // Requires a port to materialize every complete fixed window without gaps.
    fn require_windows(
        &self,
        state: &BenchmarkTelemetryState,
        through: UnixMilliseconds,
    ) -> Result<(), BenchmarkError> {
        if through < state.opened_at() {
            return Err(telemetry_error("telemetry clock moved backwards"));
        }
        let expected = (through.value() - state.opened_at().value())
            / state.plan().telemetry_interval_milliseconds();
        if state.sample_count() != expected || expected > maximum_sample_count(state.plan())? {
            return Err(telemetry_error("telemetry sampling windows are incomplete"));
        }
        Ok(())
    }
}

impl BenchmarkTelemetryProvider for WindowedBenchmarkTelemetryProvider {
    // Opens or reconstructs one exact persistent timeline idempotently.
    fn begin(
        &self,
        job_id: &OperationId,
        request: &BenchmarkRequest,
        prepared: &PreparedBenchmark,
    ) -> Result<(), BenchmarkError> {
        let plan = self
            .plans
            .plan(job_id, request)
            .map_err(|_| telemetry_error("telemetry plan is unavailable"))?;
        if plan.request_sha256() != &request.sha256()? {
            return Err(telemetry_error("telemetry plan identity is invalid"));
        }
        let session_receipt_id = telemetry_session_receipt(job_id, &plan, prepared.receipt_id());
        let command = BenchmarkTelemetryOpen {
            job_id: job_id.clone(),
            plan,
            prepared_receipt_id: prepared.receipt_id().clone(),
            session_receipt_id,
            proposed_opened_at: self.now()?,
        };
        let state = self
            .telemetry
            .open(&command)
            .map_err(|_| telemetry_error("telemetry open failed"))?;
        self.require_identity(&state, job_id)?;
        if state.plan() != command.plan()
            || state.prepared_receipt_id() != command.prepared_receipt_id()
            || state.session_receipt_id() != command.session_receipt_id()
            || state.sealed_receipt_id().is_some()
        {
            return Err(telemetry_error("telemetry replay identity is invalid"));
        }
        Ok(())
    }

    // Captures all complete fixed windows and exact monotonic progress.
    fn capture(
        &self,
        job_id: &OperationId,
        progress: &BenchmarkProgress,
    ) -> Result<(), BenchmarkError> {
        let previous = self.state(job_id)?;
        self.require_identity(&previous, job_id)?;
        if previous.sealed_receipt_id().is_some()
            || progress.total_cells() != previous.plan().total_cells()
            || previous
                .progress()
                .is_some_and(|prior| progress.completed_cells() < prior.completed_cells())
        {
            return Err(telemetry_error("telemetry progress is invalid"));
        }
        let through = self.now()?;
        let command = BenchmarkTelemetrySynchronization {
            job_id: job_id.clone(),
            session_receipt_id: previous.session_receipt_id().clone(),
            through,
            progress: progress.clone(),
        };
        let state = self
            .telemetry
            .synchronize(&command)
            .map_err(|_| telemetry_error("telemetry synchronization failed"))?;
        self.require_identity(&state, job_id)?;
        self.require_windows(&state, through)?;
        if state.plan() != previous.plan()
            || state.opened_at() != previous.opened_at()
            || state.sealed_receipt_id().is_some()
            || state.progress() != Some(progress)
            || state.sample_count() < previous.sample_count()
        {
            return Err(telemetry_error("telemetry synchronization is invalid"));
        }
        Ok(())
    }

    // Seals all final complete windows and returns their immutable receipt idempotently.
    fn finish(
        &self,
        job_id: &OperationId,
        outcome: &BenchmarkExecutionOutcome,
    ) -> Result<BenchmarkTelemetryReceipt, BenchmarkError> {
        let previous = self.state(job_id)?;
        self.require_identity(&previous, job_id)?;
        let through = self.now()?;
        if through < previous.opened_at() {
            return Err(telemetry_error("telemetry clock moved backwards"));
        }
        let command = BenchmarkTelemetryFinish {
            job_id: job_id.clone(),
            session_receipt_id: previous.session_receipt_id().clone(),
            through,
            outcome: outcome.clone(),
        };
        let state = self
            .telemetry
            .finish(&command)
            .map_err(|_| telemetry_error("telemetry sealing failed"))?;
        self.require_identity(&state, job_id)?;
        let sealed_at = state
            .sealed_at()
            .ok_or_else(|| telemetry_error("sealed telemetry timeline is invalid"))?;
        self.require_windows(&state, sealed_at)?;
        let expected_receipt_id = telemetry_receipt(job_id, &state, state.sample_count(), outcome);
        if state.plan() != previous.plan()
            || state.opened_at() != previous.opened_at()
            || state.sample_count() < previous.sample_count()
            || state.sealed_receipt_id() != Some(&expected_receipt_id)
            || previous.sealed_at().is_none() && sealed_at != through
            || matches!(outcome, BenchmarkExecutionOutcome::Succeeded { .. })
                && state.sample_count() == 0
        {
            return Err(telemetry_error("sealed telemetry timeline is invalid"));
        }
        Ok(BenchmarkTelemetryReceipt::new(
            expected_receipt_id,
            state.sample_count(),
        ))
    }
}

// Returns the deterministic identity for one open telemetry session.
fn telemetry_session_receipt(
    job_id: &OperationId,
    plan: &BenchmarkRunPlan,
    prepared_receipt_id: &Sha256Digest,
) -> Sha256Digest {
    framed_digest(
        "li-benchmark-telemetry-session-v1",
        &[
            job_id.as_str(),
            plan.plan_sha256().as_str(),
            prepared_receipt_id.as_str(),
        ],
    )
}

// Returns the sole valid digest for an open timeline with no samples.
fn empty_samples_sha256(job_id: &OperationId, session_receipt_id: &Sha256Digest) -> Sha256Digest {
    framed_digest(
        "li-benchmark-telemetry-samples-v1",
        &[job_id.as_str(), session_receipt_id.as_str(), "0"],
    )
}

// Returns the deterministic final timeline receipt over exact samples and outcome.
fn telemetry_receipt(
    job_id: &OperationId,
    state: &BenchmarkTelemetryState,
    sample_count: u64,
    outcome: &BenchmarkExecutionOutcome,
) -> Sha256Digest {
    let outcome = outcome_identity(outcome);
    framed_digest(
        "li-benchmark-telemetry-receipt-v1",
        &[
            job_id.as_str(),
            state.plan().plan_sha256().as_str(),
            state.session_receipt_id().as_str(),
            &state.opened_at().value().to_string(),
            &sample_count.to_string(),
            state.samples_sha256().as_str(),
            &state
                .sealed_at()
                .map(UnixMilliseconds::value)
                .unwrap_or_default()
                .to_string(),
            &outcome,
        ],
    )
}

// Returns the maximum number of complete windows allowed through stop containment.
fn maximum_sample_count(plan: &BenchmarkRunPlan) -> Result<u64, BenchmarkError> {
    plan.maximum_runtime_milliseconds()
        .checked_add(plan.stop_grace_milliseconds())
        .map(|duration| duration / plan.telemetry_interval_milliseconds())
        .ok_or(BenchmarkError::InvalidContract {
            reason: "benchmark telemetry duration overflowed",
        })
}

// Returns one stable redacted telemetry-provider failure.
fn telemetry_error(reason: &'static str) -> BenchmarkError {
    BenchmarkError::provider("telemetry", reason)
}
