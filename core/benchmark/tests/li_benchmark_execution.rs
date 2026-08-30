// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use li_benchmark_manager::{
    BenchmarkAuthorization, BenchmarkClock, BenchmarkError, BenchmarkExecutionArtifact,
    BenchmarkExecutionObservation, BenchmarkExecutionOutcome, BenchmarkExecutionPreparation,
    BenchmarkExecutionProvider, BenchmarkExecutionRestoration, BenchmarkExecutionScheduler,
    BenchmarkFailure, BenchmarkFailureCategory, BenchmarkKind, BenchmarkProgress,
    BenchmarkRecordSchema, BenchmarkRequest, BenchmarkRunPlan, BenchmarkRunPlanProvider,
    BenchmarkScheduledExecution, BenchmarkScheduledState, BenchmarkScheduledTerminal,
    BenchmarkSchedulerStopReason, BenchmarkScope, BenchmarkSubject, BenchmarkTelemetryFinish,
    BenchmarkTelemetryOpen, BenchmarkTelemetryPort, BenchmarkTelemetryProvider,
    BenchmarkTelemetryState, BenchmarkTelemetrySynchronization,
    CoordinatedBenchmarkExecutionProvider, PreparedBenchmark, RunningBenchmark,
    WindowedBenchmarkTelemetryProvider,
};
use li_core_interface::{
    InstallationId, LogicalModelName, OperationId, PlacementGroupId, RuntimeInstallationId,
    Sha256Digest, TechnicalName, UnixMilliseconds,
};
use sha2::{Digest, Sha256};

// Supplies one immutable plan and optional redacted plan failure.
struct PlanProviderMock {
    plan: BenchmarkRunPlan,
    fail: AtomicBool,
}

impl BenchmarkRunPlanProvider for PlanProviderMock {
    // Returns the exact configured plan without inspecting another manager.
    fn plan(
        &self,
        _job_id: &OperationId,
        _request: &BenchmarkRequest,
    ) -> Result<BenchmarkRunPlan, BenchmarkError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(BenchmarkError::provider(
                "secret",
                "private plan path must not escape",
            ));
        }
        Ok(self.plan.clone())
    }
}

// Supplies controllable positive time and one injected failure.
struct ClockMock {
    now: AtomicU64,
    fail: AtomicBool,
}

impl ClockMock {
    // Replaces the current deterministic clock value.
    fn set(&self, now: u64) {
        self.now.store(now, Ordering::SeqCst);
    }
}

impl BenchmarkClock for ClockMock {
    // Returns the configured time without reading the host clock.
    fn now(&self) -> Result<UnixMilliseconds, BenchmarkError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(BenchmarkError::provider(
                "secret",
                "private clock failure must not escape",
            ));
        }
        Ok(UnixMilliseconds::new(self.now.load(Ordering::SeqCst)))
    }
}

// Records exact scheduler commands and returns queued detached-task states.
#[derive(Default)]
struct SchedulerMock {
    preparations: Mutex<Vec<BenchmarkExecutionPreparation>>,
    launches: Mutex<Vec<li_benchmark_manager::BenchmarkExecutionLaunch>>,
    restorations: Mutex<Vec<BenchmarkExecutionRestoration>>,
    stops: Mutex<Vec<BenchmarkSchedulerStopReason>>,
    states: Mutex<VecDeque<BenchmarkScheduledState>>,
    failures: Mutex<BTreeMap<&'static str, bool>>,
    started_at: AtomicU64,
}

impl SchedulerMock {
    // Queues one exact worker state for the next observation.
    fn push(&self, state: BenchmarkScheduledState) {
        self.states
            .lock()
            .expect("scheduler states")
            .push_back(state);
    }

    // Schedules one native boundary to fail with sensitive mock text.
    fn fail(&self, operation: &'static str) {
        self.failures
            .lock()
            .expect("scheduler failures")
            .insert(operation, true);
    }

    // Returns a failure only for one explicitly scheduled operation.
    fn check(&self, operation: &'static str) -> Result<(), BenchmarkError> {
        if self
            .failures
            .lock()
            .expect("scheduler failures")
            .remove(operation)
            .unwrap_or(false)
        {
            return Err(BenchmarkError::provider(
                "secret",
                "private scheduler output must not escape",
            ));
        }
        Ok(())
    }
}

impl BenchmarkExecutionScheduler for SchedulerMock {
    // Records one idempotent resident-state preparation.
    fn prepare(&self, command: &BenchmarkExecutionPreparation) -> Result<(), BenchmarkError> {
        self.check("prepare")?;
        self.preparations
            .lock()
            .expect("preparations")
            .push(command.clone());
        Ok(())
    }

    // Records one shell-free detached task start or reattachment.
    fn start(
        &self,
        command: &li_benchmark_manager::BenchmarkExecutionLaunch,
    ) -> Result<(), BenchmarkError> {
        self.check("start")?;
        self.launches
            .lock()
            .expect("launches")
            .push(command.clone());
        Ok(())
    }

    // Returns one queued state bound to the last exact launch command.
    fn observe(
        &self,
        job_id: &OperationId,
        _running: &RunningBenchmark,
    ) -> Result<BenchmarkScheduledExecution, BenchmarkError> {
        self.check("observe")?;
        let launch = self
            .launches
            .lock()
            .expect("launches")
            .last()
            .cloned()
            .ok_or_else(|| BenchmarkError::provider("mock", "missing launch"))?;
        let state = self
            .states
            .lock()
            .expect("scheduler states")
            .pop_front()
            .ok_or_else(|| BenchmarkError::provider("mock", "missing state"))?;
        BenchmarkScheduledExecution::new(
            job_id.clone(),
            launch.plan().clone(),
            launch.prepared_receipt_id().clone(),
            launch.running_receipt_id().clone(),
            UnixMilliseconds::new(self.started_at.load(Ordering::SeqCst)),
            state,
        )
    }

    // Records one exact stop reason without inventing process semantics.
    fn request_stop(
        &self,
        _job_id: &OperationId,
        _running: &RunningBenchmark,
        reason: BenchmarkSchedulerStopReason,
    ) -> Result<(), BenchmarkError> {
        self.check("stop")?;
        self.stops.lock().expect("stops").push(reason);
        Ok(())
    }

    // Records one complete restoration command idempotently.
    fn restore(&self, command: &BenchmarkExecutionRestoration) -> Result<(), BenchmarkError> {
        self.check("restore")?;
        self.restorations
            .lock()
            .expect("restorations")
            .push(command.clone());
        Ok(())
    }
}

// Persists telemetry state in memory while exercising the production provider contract.
#[derive(Default)]
struct TelemetryPortMock {
    state: Mutex<Option<BenchmarkTelemetryState>>,
    fail: Mutex<Option<&'static str>>,
    incomplete_windows: AtomicBool,
}

impl TelemetryPortMock {
    // Schedules one exact telemetry boundary failure.
    fn fail(&self, operation: &'static str) {
        *self.fail.lock().expect("telemetry failure") = Some(operation);
    }

    // Returns one sensitive failure only at the scheduled boundary.
    fn check(&self, operation: &'static str) -> Result<(), BenchmarkError> {
        let mut failure = self.fail.lock().expect("telemetry failure");
        if failure.as_ref().copied() == Some(operation) {
            *failure = None;
            return Err(BenchmarkError::provider(
                "secret",
                "private telemetry source must not escape",
            ));
        }
        Ok(())
    }

    // Materializes exact complete windows while retaining their cumulative identity.
    fn synchronize_state(
        state: &BenchmarkTelemetryState,
        through: UnixMilliseconds,
        progress: BenchmarkProgress,
    ) -> Result<BenchmarkTelemetryState, BenchmarkError> {
        let count = (through.value() - state.opened_at().value())
            / state.plan().telemetry_interval_milliseconds();
        let samples_sha256 = if count == 0 {
            state.samples_sha256().clone()
        } else {
            bytes_digest(format!("samples:{count}").as_bytes())
        };
        state.synchronized(through, samples_sha256, progress)
    }
}

impl BenchmarkTelemetryPort for TelemetryPortMock {
    // Opens one timeline once and returns the original state on replay.
    fn open(
        &self,
        command: &BenchmarkTelemetryOpen,
    ) -> Result<BenchmarkTelemetryState, BenchmarkError> {
        self.check("open")?;
        let mut state = self.state.lock().expect("telemetry state");
        if let Some(state) = state.as_ref() {
            return Ok(state.clone());
        }
        let opened = BenchmarkTelemetryState::opened(command)?;
        *state = Some(opened.clone());
        Ok(opened)
    }

    // Reconstructs the complete current state without mutation.
    fn state(
        &self,
        _job_id: &OperationId,
    ) -> Result<Option<BenchmarkTelemetryState>, BenchmarkError> {
        self.check("state")?;
        Ok(self.state.lock().expect("telemetry state").clone())
    }

    // Materializes every complete window unless the corruption mode is enabled.
    fn synchronize(
        &self,
        command: &BenchmarkTelemetrySynchronization,
    ) -> Result<BenchmarkTelemetryState, BenchmarkError> {
        self.check("synchronize")?;
        let mut state = self.state.lock().expect("telemetry state");
        let previous = state
            .as_ref()
            .ok_or_else(|| BenchmarkError::provider("mock", "missing telemetry"))?;
        if self.incomplete_windows.load(Ordering::SeqCst) {
            return Ok(previous.clone());
        }
        let synchronized =
            Self::synchronize_state(previous, command.through(), command.progress().clone())?;
        *state = Some(synchronized.clone());
        Ok(synchronized)
    }

    // Materializes final windows and seals once, returning the same state on replay.
    fn finish(
        &self,
        command: &BenchmarkTelemetryFinish,
    ) -> Result<BenchmarkTelemetryState, BenchmarkError> {
        self.check("finish")?;
        let mut state = self.state.lock().expect("telemetry state");
        let previous = state
            .as_ref()
            .ok_or_else(|| BenchmarkError::provider("mock", "missing telemetry"))?;
        if previous.sealed_receipt_id().is_some() {
            return Ok(previous.clone());
        }
        let progress = previous
            .progress()
            .cloned()
            .unwrap_or_else(|| progress(0, previous.plan().total_cells()));
        let synchronized = Self::synchronize_state(previous, command.through(), progress)?;
        let sealed = synchronized.sealed(command.through(), command.outcome())?;
        *state = Some(sealed.clone());
        Ok(sealed)
    }
}

// Returns one exact lowercase SHA-256 fixture.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
}

// Hashes arbitrary deterministic test bytes.
fn bytes_digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::parse(&format!("{:x}", Sha256::digest(bytes))).expect("digest")
}

// Creates one ordinary exact runtime benchmark request.
fn request() -> BenchmarkRequest {
    BenchmarkRequest::new(
        BenchmarkKind::Local,
        BenchmarkScope::Complete,
        BenchmarkSubject::new(
            InstallationId::parse(&"1".repeat(64)).expect("installation"),
            RuntimeInstallationId::parse(&"2".repeat(32)).expect("runtime installation"),
            LogicalModelName::parse("qwen").expect("model"),
            PlacementGroupId::parse(&"3".repeat(32)).expect("placement group"),
            digest('4'),
            digest('5'),
            digest('6'),
        ),
    )
    .expect("request")
}

// Creates one bounded successful-record run plan.
fn plan(request: &BenchmarkRequest) -> BenchmarkRunPlan {
    BenchmarkRunPlan::new(
        request,
        BenchmarkRecordSchema::OciExecutionPayloadV7,
        2,
        5_000,
        1_000,
        1_000,
    )
    .expect("run plan")
}

// Creates one bounded deterministic progress point.
fn progress(completed: u32, total: u32) -> BenchmarkProgress {
    BenchmarkProgress::new(
        TechnicalName::parse("measuring").expect("phase"),
        completed,
        total,
    )
    .expect("progress")
}

// Creates one valid execution artifact matching an exact plan.
fn artifact(plan: &BenchmarkRunPlan) -> BenchmarkExecutionArtifact {
    BenchmarkExecutionArtifact::new(
        digest('a'),
        digest('b'),
        plan.benchmark_contract_sha256().clone(),
        plan.execution_sha256().clone(),
        plan.target_contract_sha256().clone(),
        plan.record_schema(),
        4096,
    )
    .expect("artifact")
}

// Creates one configured execution provider and its observable boundaries.
fn execution_harness() -> (
    CoordinatedBenchmarkExecutionProvider,
    Arc<SchedulerMock>,
    Arc<ClockMock>,
    BenchmarkRequest,
    BenchmarkRunPlan,
) {
    let request = request();
    let plan = plan(&request);
    let plans = Arc::new(PlanProviderMock {
        plan: plan.clone(),
        fail: AtomicBool::new(false),
    });
    let scheduler = Arc::new(SchedulerMock {
        started_at: AtomicU64::new(1_000),
        ..SchedulerMock::default()
    });
    let clock = Arc::new(ClockMock {
        now: AtomicU64::new(1_001),
        fail: AtomicBool::new(false),
    });
    let provider =
        CoordinatedBenchmarkExecutionProvider::new(plans, scheduler.clone(), clock.clone());
    (provider, scheduler, clock, request, plan)
}

// Proves deterministic preparation, launch, success, restoration, and restart replay.
#[test]
fn execution_success_replays_every_external_command_identity() {
    let (provider, scheduler, _clock, request, plan) = execution_harness();
    let job_id = OperationId::parse(&"7".repeat(32)).expect("job");
    let authorization = BenchmarkAuthorization::new(digest('8'));

    let prepared = provider
        .prepare(&job_id, &request, &authorization)
        .expect("prepare");
    assert_eq!(
        prepared,
        provider
            .prepare(&job_id, &request, &authorization)
            .expect("prepare replay")
    );
    let running = provider.start(&job_id, &request, &prepared).expect("start");
    assert_eq!(
        running,
        provider
            .start(&job_id, &request, &prepared)
            .expect("start replay")
    );
    scheduler.push(BenchmarkScheduledState::Terminal(
        BenchmarkScheduledTerminal::Succeeded(artifact(&plan)),
    ));
    let BenchmarkExecutionObservation::Terminal(outcome) = provider
        .observe(&job_id, &running)
        .expect("terminal observation")
    else {
        panic!("expected terminal execution")
    };
    assert_eq!(
        outcome,
        BenchmarkExecutionOutcome::Succeeded {
            raw_evidence_sha256: digest('a'),
            results_sha256: digest('b'),
            record_schema: plan.record_schema(),
        }
    );
    let restored = provider
        .restore(&job_id, &request, &prepared, Some(&running), &outcome)
        .expect("restore");
    assert_eq!(
        restored,
        provider
            .restore(&job_id, &request, &prepared, Some(&running), &outcome)
            .expect("restore replay")
    );
    let preparations = scheduler.preparations.lock().expect("preparations");
    assert_eq!(preparations.len(), 2);
    assert_eq!(preparations[0], preparations[1]);
    let launches = scheduler.launches.lock().expect("launches");
    assert_eq!(launches.len(), 2);
    assert_eq!(launches[0], launches[1]);
    let restorations = scheduler.restorations.lock().expect("restorations");
    assert_eq!(restorations.len(), 2);
    assert_eq!(restorations[0], restorations[1]);
}

// Proves exact deadline containment, cancellation, and malformed-result failure evidence.
#[test]
fn execution_enforces_timeout_cancellation_and_result_identities() {
    let (provider, scheduler, clock, request, plan) = execution_harness();
    let job_id = OperationId::parse(&"7".repeat(32)).expect("job");
    let prepared = provider
        .prepare(&job_id, &request, &BenchmarkAuthorization::new(digest('8')))
        .expect("prepare");
    let running = provider.start(&job_id, &request, &prepared).expect("start");

    scheduler.push(BenchmarkScheduledState::Running(progress(1, 2)));
    clock.set(5_999);
    provider
        .observe(&job_id, &running)
        .expect("before deadline");
    assert!(scheduler.stops.lock().expect("stops").is_empty());
    scheduler.push(BenchmarkScheduledState::Running(progress(1, 2)));
    clock.set(6_000);
    provider.observe(&job_id, &running).expect("at deadline");
    provider.request_stop(&job_id, &running).expect("cancel");
    assert_eq!(
        *scheduler.stops.lock().expect("stops"),
        vec![
            BenchmarkSchedulerStopReason::Timeout,
            BenchmarkSchedulerStopReason::Cancellation,
        ]
    );

    let malformed = BenchmarkExecutionArtifact::new(
        digest('a'),
        digest('b'),
        plan.benchmark_contract_sha256().clone(),
        digest('f'),
        plan.target_contract_sha256().clone(),
        plan.record_schema(),
        4096,
    )
    .expect("malformed artifact shape");
    scheduler.push(BenchmarkScheduledState::Terminal(
        BenchmarkScheduledTerminal::Succeeded(malformed),
    ));
    let BenchmarkExecutionObservation::Terminal(BenchmarkExecutionOutcome::Failed {
        raw_evidence_sha256,
        failure,
    }) = provider
        .observe(&job_id, &running)
        .expect("malformed terminal")
    else {
        panic!("expected contained invalid result")
    };
    assert_eq!(raw_evidence_sha256, None);
    assert_eq!(
        failure.category(),
        BenchmarkFailureCategory::OutputValidation
    );
}

// Proves invalid progress containment and redaction of native scheduler failures.
#[test]
fn execution_contains_invalid_progress_and_redacts_scheduler_failures() {
    let (provider, scheduler, _clock, request, _plan) = execution_harness();
    assert!(BenchmarkExecutionArtifact::new(
        digest('a'),
        digest('b'),
        request.subject().benchmark_contract_sha256().clone(),
        request.subject().execution_sha256().clone(),
        request.subject().target_contract_sha256().clone(),
        BenchmarkRecordSchema::CoreLocalFailureV1,
        4096,
    )
    .is_err());
    assert!(BenchmarkRunPlan::new(
        &request,
        BenchmarkRecordSchema::CoreLocalFailureV1,
        2,
        5_000,
        1_000,
        1_000,
    )
    .is_err());
    let job_id = OperationId::parse(&"7".repeat(32)).expect("job");
    let prepared = provider
        .prepare(&job_id, &request, &BenchmarkAuthorization::new(digest('8')))
        .expect("prepare");
    let running = provider.start(&job_id, &request, &prepared).expect("start");
    scheduler.push(BenchmarkScheduledState::Running(progress(1, 3)));
    let BenchmarkExecutionObservation::Running(contained) = provider
        .observe(&job_id, &running)
        .expect("contain progress")
    else {
        panic!("expected stopping progress")
    };
    assert_eq!(contained.total_cells(), 2);
    assert_eq!(
        *scheduler.stops.lock().expect("stops"),
        vec![BenchmarkSchedulerStopReason::InvalidResult]
    );

    scheduler.fail("observe");
    assert_eq!(
        provider.observe(&job_id, &running),
        Err(BenchmarkError::provider(
            "execution",
            "execution observation failed"
        ))
    );
    scheduler.fail("restore");
    let failure = BenchmarkFailure::new(
        BenchmarkFailureCategory::Crash,
        "measuring",
        "worker exited",
    )
    .expect("failure");
    let outcome = BenchmarkExecutionOutcome::Failed {
        raw_evidence_sha256: None,
        failure,
    };
    assert_eq!(
        provider.restore(&job_id, &request, &prepared, Some(&running), &outcome),
        Err(BenchmarkError::provider(
            "execution",
            "resident restoration failed"
        ))
    );
}

// Proves exact one-second windows and stable telemetry receipts across delayed restart replay.
#[test]
fn telemetry_materializes_exact_windows_and_replays_sealed_receipt() {
    let request = request();
    let plan = plan(&request);
    let plans = Arc::new(PlanProviderMock {
        plan,
        fail: AtomicBool::new(false),
    });
    let port = Arc::new(TelemetryPortMock::default());
    let clock = Arc::new(ClockMock {
        now: AtomicU64::new(1_000),
        fail: AtomicBool::new(false),
    });
    let provider = WindowedBenchmarkTelemetryProvider::new(plans, port.clone(), clock.clone());
    let job_id = OperationId::parse(&"7".repeat(32)).expect("job");
    let prepared = PreparedBenchmark::new(digest('8'));
    provider.begin(&job_id, &request, &prepared).expect("begin");
    provider
        .begin(&job_id, &request, &prepared)
        .expect("begin replay");

    clock.set(2_500);
    provider.capture(&job_id, &progress(1, 2)).expect("capture");
    provider
        .capture(&job_id, &progress(1, 2))
        .expect("capture replay");
    let state = port
        .state
        .lock()
        .expect("telemetry state")
        .clone()
        .expect("state");
    assert_eq!(state.sample_count(), 1);
    assert_eq!(state.last_sample_at(), Some(UnixMilliseconds::new(2_000)));

    clock.set(3_500);
    let outcome = BenchmarkExecutionOutcome::Succeeded {
        raw_evidence_sha256: digest('a'),
        results_sha256: digest('b'),
        record_schema: BenchmarkRecordSchema::OciExecutionPayloadV7,
    };
    let receipt = provider.finish(&job_id, &outcome).expect("finish");
    assert_eq!(receipt.sample_count(), 2);
    clock.set(9_500);
    assert_eq!(
        provider.finish(&job_id, &outcome).expect("finish replay"),
        receipt
    );
    let sealed = port
        .state
        .lock()
        .expect("telemetry state")
        .clone()
        .expect("state");
    assert_eq!(sealed.sealed_at(), Some(UnixMilliseconds::new(3_500)));
}

// Proves incomplete windows, zero-sample success, and provider failures all fail closed.
#[test]
fn telemetry_rejects_incomplete_or_failed_provider_state() {
    let request = request();
    let plan = plan(&request);
    let plans = Arc::new(PlanProviderMock {
        plan,
        fail: AtomicBool::new(false),
    });
    let port = Arc::new(TelemetryPortMock::default());
    let clock = Arc::new(ClockMock {
        now: AtomicU64::new(1_000),
        fail: AtomicBool::new(false),
    });
    let provider = WindowedBenchmarkTelemetryProvider::new(plans, port.clone(), clock.clone());
    let job_id = OperationId::parse(&"7".repeat(32)).expect("job");
    provider
        .begin(&job_id, &request, &PreparedBenchmark::new(digest('8')))
        .expect("begin");
    clock.set(2_500);
    port.incomplete_windows.store(true, Ordering::SeqCst);
    assert_eq!(
        provider.capture(&job_id, &progress(1, 2)),
        Err(BenchmarkError::provider(
            "telemetry",
            "telemetry sampling windows are incomplete"
        ))
    );
    port.incomplete_windows.store(false, Ordering::SeqCst);
    port.fail("synchronize");
    assert_eq!(
        provider.capture(&job_id, &progress(1, 2)),
        Err(BenchmarkError::provider(
            "telemetry",
            "telemetry synchronization failed"
        ))
    );

    let second_request = self::request();
    let second_plan = self::plan(&second_request);
    let second_port = Arc::new(TelemetryPortMock::default());
    let second_clock = Arc::new(ClockMock {
        now: AtomicU64::new(1_000),
        fail: AtomicBool::new(false),
    });
    let second = WindowedBenchmarkTelemetryProvider::new(
        Arc::new(PlanProviderMock {
            plan: second_plan,
            fail: AtomicBool::new(false),
        }),
        second_port,
        second_clock,
    );
    second
        .begin(
            &job_id,
            &second_request,
            &PreparedBenchmark::new(digest('8')),
        )
        .expect("second begin");
    assert_eq!(
        second.finish(
            &job_id,
            &BenchmarkExecutionOutcome::Succeeded {
                raw_evidence_sha256: digest('a'),
                results_sha256: digest('b'),
                record_schema: BenchmarkRecordSchema::OciExecutionPayloadV7,
            }
        ),
        Err(BenchmarkError::provider(
            "telemetry",
            "sealed telemetry timeline is invalid"
        ))
    );
}
