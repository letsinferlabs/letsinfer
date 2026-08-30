// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use li_benchmark_manager::{
    BenchmarkAuthorization, BenchmarkAuthorizationSource, BenchmarkClock,
    BenchmarkCommunityAuthority, BenchmarkError, BenchmarkExecutionObservation,
    BenchmarkExecutionOutcome, BenchmarkExecutionPreparation, BenchmarkExecutionProvider,
    BenchmarkExecutionRestoration, BenchmarkFailure, BenchmarkFailureCategory,
    BenchmarkGitRevision, BenchmarkKind, BenchmarkProgress, BenchmarkRecordSchema,
    BenchmarkRequest, BenchmarkRunPlan, BenchmarkRunPlanProvider, BenchmarkScheduledExecution,
    BenchmarkScheduledState, BenchmarkSchedulerStopReason, BenchmarkScope, BenchmarkSubject,
    BenchmarkTelemetryProvider, BenchmarkTelemetryState, CoordinatedBenchmarkExecutionProvider,
    PreparedBenchmark, RunningBenchmark, WindowedBenchmarkTelemetryProvider,
};
use li_core_application::{
    ApplicationBenchmarkAuthorizationSource, ApplicationBenchmarkExecutionScheduler,
    ApplicationBenchmarkTelemetryPort, CoreBenchmarkCommunityAuthorityPort,
    CoreBenchmarkIsolationPort, CoreBenchmarkPortError, CoreBenchmarkTaskPort,
    CoreBenchmarkTelemetryObservation, CoreBenchmarkTelemetryObservationPort,
    CoreBenchmarkTelemetryPersistencePort, CoreBenchmarkTelemetryWindow,
};
use li_core_interface::{
    DisplayName, EntityTimestamps, InstallationId, LogicalModelName, MachineId, Node, NodeAddress,
    NodeId, NodeIdentity, NodeRole, NodeState, OperationId, PlacementGroupId,
    RuntimeInstallationId, Sha256Digest, TechnicalName, UnixMilliseconds,
};
use li_database::{DatabaseConfiguration, DatabaseManager};
use li_node_manager::NodeManager;
use sha2::{Digest, Sha256};

// Returns one exact lowercase digest fixture.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
}

// Returns one ordinary model-neutral benchmark request.
fn request() -> BenchmarkRequest {
    BenchmarkRequest::new(
        BenchmarkKind::Local,
        BenchmarkScope::Complete,
        BenchmarkSubject::new(
            InstallationId::parse(&"1".repeat(64)).expect("Core installation"),
            RuntimeInstallationId::parse(&"2".repeat(32)).expect("runtime installation"),
            LogicalModelName::parse("qwen").expect("model"),
            PlacementGroupId::parse(&"3".repeat(32)).expect("group"),
            digest('4'),
            digest('5'),
            digest('6'),
        ),
    )
    .expect("request")
}

// Returns one complete active-main Node fixture for authorization composition tests.
fn local_node() -> Node {
    Node::new(
        NodeIdentity::new(
            NodeId::parse(&"a".repeat(32)).expect("node"),
            MachineId::parse(&"b".repeat(32)).expect("machine"),
            InstallationId::parse(&"1".repeat(64)).expect("installation"),
        ),
        DisplayName::parse("homeai").expect("display name"),
        NodeRole::Main,
        NodeState::Active,
        NodeAddress::parse("homeai.local:9770").expect("address"),
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(1_000))
            .expect("timestamps"),
    )
}

// Returns one exact proposal authority without exposing repository credentials.
fn community_authority() -> BenchmarkCommunityAuthority {
    BenchmarkCommunityAuthority::new(
        42,
        BenchmarkGitRevision::parse(&"c".repeat(40)).expect("proposal revision"),
        "fixture--owner--model--target",
        digest('f'),
        7,
        digest('d'),
        Some(digest('e')),
        true,
        true,
    )
    .expect("community authority")
}

// Supplies one deterministic already-verified proposal snapshot or a redacted failure.
struct CommunityAuthorityMock {
    fail: AtomicBool,
    calls: AtomicU64,
}

impl CoreBenchmarkCommunityAuthorityPort for CommunityAuthorityMock {
    // Records the narrow provider call without retaining request or repository credentials.
    fn authority(
        &self,
        _job_id: &OperationId,
        _request: &BenchmarkRequest,
    ) -> Result<BenchmarkCommunityAuthority, CoreBenchmarkPortError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst) {
            return Err(CoreBenchmarkPortError::Unavailable);
        }
        Ok(community_authority())
    }
}

// Composes current Node authority and credential-free community acquisition with redacted errors.
#[test]
fn application_authorization_source_is_current_exact_and_redacted() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = Arc::new(
        DatabaseManager::open(DatabaseConfiguration::new(
            directory.path().join("core.sqlite3"),
        ))
        .expect("database"),
    );
    let (node, _) = NodeManager::open(database, local_node(), "initialize-node").expect("node");
    let community = Arc::new(CommunityAuthorityMock {
        fail: AtomicBool::new(false),
        calls: AtomicU64::new(0),
    });
    let source = ApplicationBenchmarkAuthorizationSource::new(Arc::new(node), community.clone());
    let job_id = OperationId::parse(&"f".repeat(32)).expect("job");
    assert_eq!(
        source
            .node_authority(&job_id, &request())
            .expect("node authority"),
        li_benchmark_manager::BenchmarkNodeAuthority::new(
            NodeId::parse(&"a".repeat(32)).expect("node"),
            NodeRole::Main,
            NodeState::Active,
        ),
    );
    assert_eq!(
        source
            .community_authority(&job_id, &request())
            .expect("community authority"),
        community_authority(),
    );
    community.fail.store(true, Ordering::SeqCst);
    assert_eq!(
        source.community_authority(&job_id, &request()),
        Err(BenchmarkError::provider(
            "authorization",
            "benchmark authority is unavailable",
        )),
    );
    assert_eq!(community.calls.load(Ordering::SeqCst), 2);
}

// Returns one bounded OCI execution plan.
fn plan(request: &BenchmarkRequest) -> BenchmarkRunPlan {
    BenchmarkRunPlan::new(
        request,
        BenchmarkRecordSchema::OciExecutionPayloadV7,
        2,
        10_000,
        1_000,
        1_000,
    )
    .expect("plan")
}

// Returns one deterministic progress snapshot.
fn progress(completed: u32) -> BenchmarkProgress {
    BenchmarkProgress::new(
        TechnicalName::parse("measuring").expect("phase"),
        completed,
        2,
    )
    .expect("progress")
}

// Returns one successful terminal outcome.
fn outcome() -> BenchmarkExecutionOutcome {
    BenchmarkExecutionOutcome::Succeeded {
        raw_evidence_sha256: digest('a'),
        results_sha256: digest('b'),
        record_schema: BenchmarkRecordSchema::OciExecutionPayloadV7,
    }
}

// Supplies one exact immutable plan to Application adapter tests.
struct PlanMock(BenchmarkRunPlan);

impl BenchmarkRunPlanProvider for PlanMock {
    // Returns the configured immutable plan without inspecting external state.
    fn plan(
        &self,
        _job_id: &OperationId,
        _request: &BenchmarkRequest,
    ) -> Result<BenchmarkRunPlan, BenchmarkError> {
        Ok(self.0.clone())
    }
}

// Supplies deterministic positive time to execution and telemetry providers.
struct ClockMock(AtomicU64);

impl ClockMock {
    // Replaces the current deterministic wall-clock value.
    fn set(&self, value: u64) {
        self.0.store(value, Ordering::SeqCst);
    }
}

impl BenchmarkClock for ClockMock {
    // Returns the configured positive wall-clock value.
    fn now(&self) -> Result<UnixMilliseconds, BenchmarkError> {
        Ok(UnixMilliseconds::new(self.0.load(Ordering::SeqCst)))
    }
}

// Records resident isolation commands and exact restoration attempts.
#[derive(Default)]
struct IsolationMock {
    preparations: Mutex<Vec<BenchmarkExecutionPreparation>>,
    restorations: Mutex<Vec<BenchmarkExecutionRestoration>>,
    fail_prepare: AtomicBool,
    fail_restore: AtomicBool,
}

impl CoreBenchmarkIsolationPort for IsolationMock {
    // Records one exact preparation or returns the configured boundary failure.
    fn prepare(
        &self,
        command: &BenchmarkExecutionPreparation,
    ) -> Result<(), CoreBenchmarkPortError> {
        self.preparations
            .lock()
            .expect("preparations")
            .push(command.clone());
        if self.fail_prepare.load(Ordering::SeqCst) {
            return Err(CoreBenchmarkPortError::Unavailable);
        }
        Ok(())
    }

    // Records one exact restoration even when task cleanup already failed.
    fn restore(
        &self,
        command: &BenchmarkExecutionRestoration,
    ) -> Result<(), CoreBenchmarkPortError> {
        self.restorations
            .lock()
            .expect("restorations")
            .push(command.clone());
        if self.fail_restore.load(Ordering::SeqCst) {
            return Err(CoreBenchmarkPortError::Unavailable);
        }
        Ok(())
    }
}

// Records detached task commands while returning deterministic typed observations.
#[derive(Default)]
struct TaskMock {
    launches: Mutex<Vec<li_benchmark_manager::BenchmarkExecutionLaunch>>,
    states: Mutex<VecDeque<BenchmarkScheduledState>>,
    stops: Mutex<Vec<BenchmarkSchedulerStopReason>>,
    cleanups: Mutex<Vec<BenchmarkExecutionRestoration>>,
    fail_start: AtomicBool,
    fail_cleanup: AtomicBool,
}

impl CoreBenchmarkTaskPort for TaskMock {
    // Records one exact launch or returns the configured boundary failure.
    fn start(
        &self,
        command: &li_benchmark_manager::BenchmarkExecutionLaunch,
    ) -> Result<(), CoreBenchmarkPortError> {
        self.launches
            .lock()
            .expect("launches")
            .push(command.clone());
        if self.fail_start.load(Ordering::SeqCst) {
            return Err(CoreBenchmarkPortError::Unavailable);
        }
        Ok(())
    }

    // Reconstructs one observation from the exact retained launch identity.
    fn observe(
        &self,
        job_id: &OperationId,
        _running: &RunningBenchmark,
    ) -> Result<BenchmarkScheduledExecution, CoreBenchmarkPortError> {
        let launch = self
            .launches
            .lock()
            .expect("launches")
            .last()
            .cloned()
            .ok_or(CoreBenchmarkPortError::InvalidState)?;
        let state = self
            .states
            .lock()
            .expect("states")
            .pop_front()
            .ok_or(CoreBenchmarkPortError::InvalidState)?;
        BenchmarkScheduledExecution::new(
            job_id.clone(),
            launch.plan().clone(),
            launch.prepared_receipt_id().clone(),
            launch.running_receipt_id().clone(),
            UnixMilliseconds::new(1_000),
            state,
        )
        .map_err(|_| CoreBenchmarkPortError::InvalidState)
    }

    // Records one exact containment reason.
    fn request_stop(
        &self,
        _job_id: &OperationId,
        _running: &RunningBenchmark,
        reason: BenchmarkSchedulerStopReason,
    ) -> Result<(), CoreBenchmarkPortError> {
        self.stops.lock().expect("stops").push(reason);
        Ok(())
    }

    // Records one cleanup and returns the configured failure after the attempt.
    fn cleanup(
        &self,
        command: &BenchmarkExecutionRestoration,
    ) -> Result<(), CoreBenchmarkPortError> {
        self.cleanups
            .lock()
            .expect("cleanups")
            .push(command.clone());
        if self.fail_cleanup.load(Ordering::SeqCst) {
            return Err(CoreBenchmarkPortError::Unavailable);
        }
        Ok(())
    }
}

// Proves exact scheduling command projection, observation, cancellation, and restoration ordering.
#[test]
fn application_scheduler_projects_exact_commands_and_restores_after_cleanup_failure() {
    let request = request();
    let plans = Arc::new(PlanMock(plan(&request)));
    let isolation = Arc::new(IsolationMock::default());
    let task = Arc::new(TaskMock::default());
    let scheduler = Arc::new(ApplicationBenchmarkExecutionScheduler::new(
        isolation.clone(),
        task.clone(),
    ));
    let clock = Arc::new(ClockMock(AtomicU64::new(1_001)));
    let execution = CoordinatedBenchmarkExecutionProvider::new(plans, scheduler, clock);
    let job_id = OperationId::parse(&"7".repeat(32)).expect("job");
    let prepared = execution
        .prepare(&job_id, &request, &BenchmarkAuthorization::new(digest('8')))
        .expect("prepare");
    let running = execution
        .start(&job_id, &request, &prepared)
        .expect("start");
    assert_eq!(
        task.launches.lock().expect("launches")[0].plan().request(),
        &request,
    );
    task.states
        .lock()
        .expect("states")
        .push_back(BenchmarkScheduledState::Running(progress(1)));
    assert_eq!(
        execution.observe(&job_id, &running).expect("observe"),
        BenchmarkExecutionObservation::Running(progress(1)),
    );
    execution.request_stop(&job_id, &running).expect("stop");
    assert_eq!(
        *task.stops.lock().expect("stops"),
        vec![BenchmarkSchedulerStopReason::Cancellation],
    );

    task.fail_cleanup.store(true, Ordering::SeqCst);
    assert_eq!(
        execution.restore(&job_id, &request, &prepared, Some(&running), &outcome()),
        Err(BenchmarkError::provider(
            "execution",
            "resident restoration failed",
        )),
    );
    assert_eq!(task.cleanups.lock().expect("cleanups").len(), 1);
    assert_eq!(
        isolation.restorations.lock().expect("restorations").len(),
        1
    );
}

// Proves scheduler provider substitution remains redacted at every external boundary.
#[test]
fn application_scheduler_redacts_provider_substitution() {
    let request = request();
    let isolation = Arc::new(IsolationMock::default());
    isolation.fail_prepare.store(true, Ordering::SeqCst);
    let task = Arc::new(TaskMock::default());
    let scheduler = Arc::new(ApplicationBenchmarkExecutionScheduler::new(isolation, task));
    let execution = CoordinatedBenchmarkExecutionProvider::new(
        Arc::new(PlanMock(plan(&request))),
        scheduler,
        Arc::new(ClockMock(AtomicU64::new(1_001))),
    );
    assert_eq!(
        execution.prepare(
            &OperationId::parse(&"7".repeat(32)).expect("job"),
            &request,
            &BenchmarkAuthorization::new(digest('8')),
        ),
        Err(BenchmarkError::provider(
            "execution",
            "execution preparation failed",
        )),
    );
}

// Persists one exact telemetry state and enforces optimistic replacement identities.
#[derive(Default)]
struct TelemetryPersistenceMock {
    state: Mutex<Option<BenchmarkTelemetryState>>,
    fail_replace: AtomicBool,
}

impl CoreBenchmarkTelemetryPersistencePort for TelemetryPersistenceMock {
    // Returns the exact persisted timeline without mutation.
    fn read(
        &self,
        _job_id: &OperationId,
    ) -> Result<Option<BenchmarkTelemetryState>, CoreBenchmarkPortError> {
        Ok(self.state.lock().expect("state").clone())
    }

    // Creates one timeline or returns the exact existing replay.
    fn open(
        &self,
        state: BenchmarkTelemetryState,
    ) -> Result<BenchmarkTelemetryState, CoreBenchmarkPortError> {
        let mut stored = self.state.lock().expect("state");
        if let Some(existing) = stored.as_ref() {
            return if existing == &state {
                Ok(existing.clone())
            } else {
                Err(CoreBenchmarkPortError::Conflict)
            };
        }
        *stored = Some(state.clone());
        Ok(state)
    }

    // Replaces one exact prior timeline or reports an optimistic conflict.
    fn replace(
        &self,
        state: BenchmarkTelemetryState,
        expected_samples_sha256: &Sha256Digest,
        expected_sealed_receipt_id: Option<&Sha256Digest>,
    ) -> Result<BenchmarkTelemetryState, CoreBenchmarkPortError> {
        if self.fail_replace.load(Ordering::SeqCst) {
            return Err(CoreBenchmarkPortError::Unavailable);
        }
        let mut stored = self.state.lock().expect("state");
        let previous = stored
            .as_ref()
            .ok_or(CoreBenchmarkPortError::InvalidState)?;
        if previous.samples_sha256() != expected_samples_sha256
            || previous.sealed_receipt_id() != expected_sealed_receipt_id
        {
            return Err(CoreBenchmarkPortError::Conflict);
        }
        *stored = Some(state.clone());
        Ok(state)
    }
}

// Produces deterministic combined telemetry identities and optional gap corruption.
#[derive(Default)]
struct TelemetryObservationMock {
    windows: Mutex<Vec<CoreBenchmarkTelemetryWindow>>,
    gap: AtomicBool,
    fail: AtomicBool,
}

impl CoreBenchmarkTelemetryObservationPort for TelemetryObservationMock {
    // Returns one canonical digest for the exact requested fixed window.
    fn observe(
        &self,
        command: &CoreBenchmarkTelemetryWindow,
    ) -> Result<CoreBenchmarkTelemetryObservation, CoreBenchmarkPortError> {
        self.windows.lock().expect("windows").push(command.clone());
        if self.fail.load(Ordering::SeqCst) {
            return Err(CoreBenchmarkPortError::Unavailable);
        }
        let sampled_at = if self.gap.load(Ordering::SeqCst) {
            UnixMilliseconds::new(command.sampled_at().value() + 1_000)
        } else {
            command.sampled_at()
        };
        let digest = Sha256Digest::parse(&format!(
            "{:x}",
            Sha256::digest(format!("sample:{}", command.sampled_at().value()).as_bytes())
        ))
        .expect("digest");
        Ok(CoreBenchmarkTelemetryObservation::new(sampled_at, digest))
    }
}

// Proves contiguous one-second materialization, restart reconstruction, sealing, and replay.
#[test]
fn application_telemetry_is_contiguous_restart_safe_and_replayable() {
    let request = request();
    let plan = plan(&request);
    let persistence = Arc::new(TelemetryPersistenceMock::default());
    let observations = Arc::new(TelemetryObservationMock::default());
    let clock = Arc::new(ClockMock(AtomicU64::new(1_000)));
    let provider = WindowedBenchmarkTelemetryProvider::new(
        Arc::new(PlanMock(plan.clone())),
        Arc::new(ApplicationBenchmarkTelemetryPort::new(
            observations.clone(),
            persistence.clone(),
        )),
        clock.clone(),
    );
    let job_id = OperationId::parse(&"7".repeat(32)).expect("job");
    provider
        .begin(&job_id, &request, &PreparedBenchmark::new(digest('8')))
        .expect("begin");
    clock.set(3_500);
    provider.capture(&job_id, &progress(1)).expect("capture");
    assert_eq!(
        observations
            .windows
            .lock()
            .expect("windows")
            .iter()
            .map(|window| window.sampled_at().value())
            .collect::<Vec<_>>(),
        vec![2_000, 3_000],
    );

    let restarted = WindowedBenchmarkTelemetryProvider::new(
        Arc::new(PlanMock(plan)),
        Arc::new(ApplicationBenchmarkTelemetryPort::new(
            observations.clone(),
            persistence,
        )),
        clock.clone(),
    );
    clock.set(5_500);
    let receipt = restarted.finish(&job_id, &outcome()).expect("finish");
    assert_eq!(receipt.sample_count(), 4);
    clock.set(9_500);
    assert_eq!(
        restarted.finish(&job_id, &outcome()).expect("replay"),
        receipt
    );
}

// Proves observation gaps, progress regression, and persistence substitution fail closed.
#[test]
fn application_telemetry_rejects_gaps_regression_and_provider_substitution() {
    let request = request();
    let plan = plan(&request);
    let persistence = Arc::new(TelemetryPersistenceMock::default());
    let observations = Arc::new(TelemetryObservationMock::default());
    let clock = Arc::new(ClockMock(AtomicU64::new(1_000)));
    let provider = WindowedBenchmarkTelemetryProvider::new(
        Arc::new(PlanMock(plan)),
        Arc::new(ApplicationBenchmarkTelemetryPort::new(
            observations.clone(),
            persistence.clone(),
        )),
        clock.clone(),
    );
    let job_id = OperationId::parse(&"7".repeat(32)).expect("job");
    provider
        .begin(&job_id, &request, &PreparedBenchmark::new(digest('8')))
        .expect("begin");
    clock.set(2_500);
    observations.gap.store(true, Ordering::SeqCst);
    assert_eq!(
        provider.capture(&job_id, &progress(1)),
        Err(BenchmarkError::provider(
            "telemetry",
            "telemetry synchronization failed",
        )),
    );
    observations.gap.store(false, Ordering::SeqCst);
    provider.capture(&job_id, &progress(1)).expect("capture");
    assert_eq!(
        provider.capture(&job_id, &progress(0)),
        Err(BenchmarkError::provider(
            "telemetry",
            "telemetry progress is invalid",
        )),
    );
    persistence.fail_replace.store(true, Ordering::SeqCst);
    clock.set(3_500);
    assert_eq!(
        provider.capture(&job_id, &progress(1)),
        Err(BenchmarkError::provider(
            "telemetry",
            "telemetry synchronization failed",
        )),
    );
}

// Proves failed outcomes still carry bounded model-neutral telemetry state.
#[test]
fn application_telemetry_seals_failed_outcome_without_secret_state() {
    let request = request();
    let persistence = Arc::new(TelemetryPersistenceMock::default());
    let provider = WindowedBenchmarkTelemetryProvider::new(
        Arc::new(PlanMock(plan(&request))),
        Arc::new(ApplicationBenchmarkTelemetryPort::new(
            Arc::new(TelemetryObservationMock::default()),
            persistence,
        )),
        Arc::new(ClockMock(AtomicU64::new(1_000))),
    );
    let job_id = OperationId::parse(&"7".repeat(32)).expect("job");
    provider
        .begin(&job_id, &request, &PreparedBenchmark::new(digest('8')))
        .expect("begin");
    let failed = BenchmarkExecutionOutcome::Failed {
        raw_evidence_sha256: None,
        failure: BenchmarkFailure::new(
            BenchmarkFailureCategory::Crash,
            "measuring",
            "worker exited",
        )
        .expect("failure"),
    };
    assert_eq!(
        provider
            .finish(&job_id, &failed)
            .expect("finish")
            .sample_count(),
        0
    );
}
