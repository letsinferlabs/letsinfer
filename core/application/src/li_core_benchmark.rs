// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::sync::Arc;

use li_benchmark_manager::{
    BenchmarkAuthorizationSource, BenchmarkClock, BenchmarkCommunityAuthority, BenchmarkError,
    BenchmarkEvidenceProvider, BenchmarkExecutionLaunch, BenchmarkExecutionPreparation,
    BenchmarkExecutionProvider, BenchmarkExecutionRestoration, BenchmarkExecutionScheduler,
    BenchmarkNodeAuthority, BenchmarkProgress, BenchmarkPublicationProvider, BenchmarkRequest,
    BenchmarkRunPlanProvider, BenchmarkRunPlanResolution, BenchmarkRunPlanSource,
    BenchmarkScheduledExecution, BenchmarkSchedulerStopReason, BenchmarkSigningProvider,
    BenchmarkStore, BenchmarkTelemetryFinish, BenchmarkTelemetryOpen, BenchmarkTelemetryPort,
    BenchmarkTelemetryProvider, BenchmarkTelemetryState, BenchmarkTelemetrySynchronization,
    BoundBenchmarkAuthorizationProvider, CoordinatedBenchmarkExecutionProvider, RunningBenchmark,
    WindowedBenchmarkTelemetryProvider,
};
use li_core_interface::{InstallationId, OperationId, Sha256Digest, UnixMilliseconds};
use li_node_manager::{
    compose_node_benchmark_coordinator_with_store, NodeBenchmarkCoordinator,
    NodeBenchmarkRequestProvider, NodeManager,
};
use li_placement_manager::{
    PlacementBenchmarkIsolationRequest, PlacementError, PlacementManager, PlacementStore,
};
use li_runtime_manager::{RuntimeInstallationStore, RuntimeManager};
use sha2::{Digest, Sha256};

// Describes one stable cross-manager Application-port failure without provider details.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreBenchmarkPortError {
    Unavailable,
    Conflict,
    InvalidState,
}

impl fmt::Display for CoreBenchmarkPortError {
    // Presents one bounded failure without native command, path, or credential content.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => formatter.write_str("benchmark application port is unavailable"),
            Self::Conflict => formatter.write_str("benchmark application state changed"),
            Self::InvalidState => formatter.write_str("benchmark application state is invalid"),
        }
    }
}

impl Error for CoreBenchmarkPortError {}

// Composes the one Node-owned BenchmarkManager from explicit existing manager/application ports.
#[allow(clippy::too_many_arguments)]
pub fn compose_core_node_benchmark(
    store: Arc<dyn BenchmarkStore>,
    requests: Arc<dyn NodeBenchmarkRequestProvider>,
    authorization: Arc<dyn BenchmarkAuthorizationSource>,
    plans: Arc<dyn BenchmarkRunPlanProvider>,
    isolation: Arc<dyn CoreBenchmarkIsolationPort>,
    tasks: Arc<dyn CoreBenchmarkTaskPort>,
    telemetry_observations: Arc<dyn CoreBenchmarkTelemetryObservationPort>,
    telemetry_persistence: Arc<dyn CoreBenchmarkTelemetryPersistencePort>,
    evidence: Arc<dyn BenchmarkEvidenceProvider>,
    signing: Arc<dyn BenchmarkSigningProvider>,
    clock: Arc<dyn BenchmarkClock>,
) -> NodeBenchmarkCoordinator {
    let execution = Arc::new(CoordinatedBenchmarkExecutionProvider::new(
        plans.clone(),
        Arc::new(ApplicationBenchmarkExecutionScheduler::new(
            isolation, tasks,
        )),
        clock.clone(),
    ));
    let telemetry = Arc::new(WindowedBenchmarkTelemetryProvider::new(
        plans,
        Arc::new(ApplicationBenchmarkTelemetryPort::new(
            telemetry_observations,
            telemetry_persistence,
        )),
        clock.clone(),
    ));
    compose_node_benchmark_coordinator_with_store(
        store,
        requests,
        Arc::new(BoundBenchmarkAuthorizationProvider::new(authorization)),
        execution,
        telemetry,
        evidence,
        signing,
        clock,
    )
}

// Composes the Node coordinator from an already-routed execution provider and terminal publisher.
#[allow(clippy::too_many_arguments)]
pub fn compose_core_node_benchmark_with_execution(
    store: Arc<dyn BenchmarkStore>,
    requests: Arc<dyn NodeBenchmarkRequestProvider>,
    authorization: Arc<dyn BenchmarkAuthorizationSource>,
    execution: Arc<dyn BenchmarkExecutionProvider>,
    telemetry: Arc<dyn BenchmarkTelemetryProvider>,
    evidence: Arc<dyn BenchmarkEvidenceProvider>,
    signing: Arc<dyn BenchmarkSigningProvider>,
    publication: Arc<dyn BenchmarkPublicationProvider>,
    clock: Arc<dyn BenchmarkClock>,
) -> NodeBenchmarkCoordinator {
    let manager = Arc::new(
        li_benchmark_manager::BenchmarkManager::new_with_publication(
            store,
            Arc::new(BoundBenchmarkAuthorizationProvider::new(authorization)),
            execution,
            telemetry,
            evidence,
            signing,
            publication,
            clock,
        ),
    );
    NodeBenchmarkCoordinator::new(manager, requests)
}

// Acquires one already-authenticated and supply-chain-verified community proposal snapshot.
pub trait CoreBenchmarkCommunityAuthorityPort: Send + Sync {
    // Resolves only the exact verification request without exposing repository credentials.
    fn authority(
        &self,
        job_id: &OperationId,
        request: &BenchmarkRequest,
    ) -> Result<BenchmarkCommunityAuthority, CoreBenchmarkPortError>;
}

// Projects current Node ownership and externally verified proposal authority into BenchmarkManager.
pub struct ApplicationBenchmarkAuthorizationSource {
    node: Arc<NodeManager>,
    community: Arc<dyn CoreBenchmarkCommunityAuthorityPort>,
}

impl ApplicationBenchmarkAuthorizationSource {
    // Creates one source from NodeManager and the credential-free community proposal boundary.
    pub const fn new(
        node: Arc<NodeManager>,
        community: Arc<dyn CoreBenchmarkCommunityAuthorityPort>,
    ) -> Self {
        Self { node, community }
    }
}

impl BenchmarkAuthorizationSource for ApplicationBenchmarkAuthorizationSource {
    // Re-reads exact persisted local identity, role, and state for every admission attempt.
    fn node_authority(
        &self,
        _job_id: &OperationId,
        _request: &BenchmarkRequest,
    ) -> Result<BenchmarkNodeAuthority, BenchmarkError> {
        let node = self
            .node
            .local_node()
            .map_err(|_| authorization_source_error())?;
        Ok(BenchmarkNodeAuthority::new(
            node.identity().node_id().clone(),
            node.role(),
            node.state(),
        ))
    }

    // Delegates proposal acquisition and verification without admitting repository semantics here.
    fn community_authority(
        &self,
        job_id: &OperationId,
        request: &BenchmarkRequest,
    ) -> Result<BenchmarkCommunityAuthority, BenchmarkError> {
        self.community
            .authority(job_id, request)
            .map_err(|_| authorization_source_error())
    }
}

// Resolves exact installed Runtime, Placement, and benchmark-contract inputs through Application.
pub struct ApplicationBenchmarkRunPlanSource {
    core_installation_id: InstallationId,
    runtime: Arc<RuntimeManager>,
    runtime_store: Arc<dyn RuntimeInstallationStore>,
    placement_store: Arc<dyn PlacementStore>,
    maximum_runtime_milliseconds: u64,
    stop_grace_milliseconds: u64,
}

impl ApplicationBenchmarkRunPlanSource {
    // Creates one source from existing manager-owned read capabilities and bounded scheduling policy.
    pub fn new(
        core_installation_id: InstallationId,
        runtime: Arc<RuntimeManager>,
        runtime_store: Arc<dyn RuntimeInstallationStore>,
        placement_store: Arc<dyn PlacementStore>,
        maximum_runtime_milliseconds: u64,
        stop_grace_milliseconds: u64,
    ) -> Result<Self, BenchmarkError> {
        if maximum_runtime_milliseconds == 0
            || stop_grace_milliseconds == 0
            || stop_grace_milliseconds > maximum_runtime_milliseconds
        {
            return Err(BenchmarkError::InvalidContract {
                reason: "benchmark execution deadlines are invalid",
            });
        }
        Ok(Self {
            core_installation_id,
            runtime,
            runtime_store,
            placement_store,
            maximum_runtime_milliseconds,
            stop_grace_milliseconds,
        })
    }
}

impl BenchmarkRunPlanSource for ApplicationBenchmarkRunPlanSource {
    // Re-resolves every immutable identity on each plan attempt so drift fails before isolation.
    fn resolve(
        &self,
        _job_id: &OperationId,
        request: &li_benchmark_manager::BenchmarkRequest,
    ) -> Result<BenchmarkRunPlanResolution, BenchmarkError> {
        let subject = request.subject();
        let installation = self
            .runtime_store
            .read(subject.runtime_installation_id())
            .map_err(|_| run_plan_error("runtime installation is unavailable"))?
            .ok_or_else(|| run_plan_error("runtime installation is unavailable"))?
            .installation()
            .clone();
        let group = self
            .placement_store
            .read(subject.placement_group_id())
            .map_err(|_| run_plan_error("placement group is unavailable"))?
            .ok_or_else(|| run_plan_error("placement group is unavailable"))?
            .record()
            .group()
            .clone();
        let execution = self
            .runtime
            .execution_manifest(subject.runtime_installation_id())
            .map_err(|_| run_plan_error("runtime execution contract is unavailable"))?;
        let benchmark = execution
            .benchmark()
            .ok_or_else(|| run_plan_error("runtime benchmark contract is unsupported"))?;
        BenchmarkRunPlanResolution::new(
            self.core_installation_id.clone(),
            installation,
            group,
            benchmark.contract_sha256().clone(),
            benchmark.target_contract_sha256().clone(),
            benchmark.declared_cells().to_vec(),
            self.maximum_runtime_milliseconds,
            self.stop_grace_milliseconds,
        )
    }
}

// Snapshots and restores resident Placement, Gateway, and Watchdog intent.
pub trait CoreBenchmarkIsolationPort: Send + Sync {
    // Reserves the exact benchmark resources and snapshots resident intent idempotently.
    fn prepare(
        &self,
        command: &BenchmarkExecutionPreparation,
    ) -> Result<(), CoreBenchmarkPortError>;

    // Restores the exact pre-benchmark resident intent idempotently.
    fn restore(
        &self,
        command: &BenchmarkExecutionRestoration,
    ) -> Result<(), CoreBenchmarkPortError>;
}

// Adapts the scheduler's opaque transaction identity to PlacementManager-owned isolation.
pub struct ApplicationBenchmarkIsolationPort {
    placements: Arc<PlacementManager>,
}

impl ApplicationBenchmarkIsolationPort {
    // Creates one adapter without exposing native cache or process operations to Application.
    pub const fn new(placements: Arc<PlacementManager>) -> Self {
        Self { placements }
    }
}

impl CoreBenchmarkIsolationPort for ApplicationBenchmarkIsolationPort {
    // Captures the exact resident process/store identity before the worker can start.
    fn prepare(
        &self,
        command: &BenchmarkExecutionPreparation,
    ) -> Result<(), CoreBenchmarkPortError> {
        let request = PlacementBenchmarkIsolationRequest::new(
            command.prepared_receipt_id().clone(),
            command
                .plan()
                .request()
                .subject()
                .placement_group_id()
                .clone(),
        );
        self.placements
            .prepare_benchmark_isolation(request)
            .map(|_| ())
            .map_err(placement_benchmark_error)
    }

    // Restores the original store and complete resident process on every terminal path.
    fn restore(
        &self,
        command: &BenchmarkExecutionRestoration,
    ) -> Result<(), CoreBenchmarkPortError> {
        let request = PlacementBenchmarkIsolationRequest::new(
            command.prepared_receipt_id().clone(),
            command
                .plan()
                .request()
                .subject()
                .placement_group_id()
                .clone(),
        );
        self.placements
            .restore_benchmark_isolation(request)
            .map(|_| ())
            .map_err(placement_benchmark_error)
    }
}

// Owns one detached model-neutral benchmark task behind the Application boundary.
pub trait CoreBenchmarkTaskPort: Send + Sync {
    // Starts or reattaches to one exact shell-free benchmark task idempotently.
    fn start(&self, command: &BenchmarkExecutionLaunch) -> Result<(), CoreBenchmarkPortError>;

    // Returns the persistent state of only the exact detached task.
    fn observe(
        &self,
        job_id: &OperationId,
        running: &RunningBenchmark,
    ) -> Result<BenchmarkScheduledExecution, CoreBenchmarkPortError>;

    // Requests bounded containment of only the exact detached task.
    fn request_stop(
        &self,
        job_id: &OperationId,
        running: &RunningBenchmark,
        reason: BenchmarkSchedulerStopReason,
    ) -> Result<(), CoreBenchmarkPortError>;

    // Removes task-owned resources on every terminal path idempotently.
    fn cleanup(
        &self,
        command: &BenchmarkExecutionRestoration,
    ) -> Result<(), CoreBenchmarkPortError>;
}

// Bridges BenchmarkManager scheduling to explicit Application-owned lifecycle ports.
pub struct ApplicationBenchmarkExecutionScheduler {
    isolation: Arc<dyn CoreBenchmarkIsolationPort>,
    task: Arc<dyn CoreBenchmarkTaskPort>,
}

impl ApplicationBenchmarkExecutionScheduler {
    // Creates one scheduler without importing or allowing direct manager-to-manager calls.
    pub const fn new(
        isolation: Arc<dyn CoreBenchmarkIsolationPort>,
        task: Arc<dyn CoreBenchmarkTaskPort>,
    ) -> Self {
        Self { isolation, task }
    }
}

impl BenchmarkExecutionScheduler for ApplicationBenchmarkExecutionScheduler {
    // Snapshots resident intent before allowing any task launch.
    fn prepare(&self, command: &BenchmarkExecutionPreparation) -> Result<(), BenchmarkError> {
        self.isolation
            .prepare(command)
            .map_err(|_| scheduler_error("benchmark isolation preparation failed"))
    }

    // Delegates one exact shell-free launch to the injected task owner.
    fn start(&self, command: &BenchmarkExecutionLaunch) -> Result<(), BenchmarkError> {
        self.task
            .start(command)
            .map_err(|_| scheduler_error("benchmark task launch failed"))
    }

    // Returns one typed persistent task observation without projecting native process output.
    fn observe(
        &self,
        job_id: &OperationId,
        running: &RunningBenchmark,
    ) -> Result<BenchmarkScheduledExecution, BenchmarkError> {
        self.task
            .observe(job_id, running)
            .map_err(|_| scheduler_error("benchmark task observation failed"))
    }

    // Requests one exact cancellation, timeout, or invalid-result containment.
    fn request_stop(
        &self,
        job_id: &OperationId,
        running: &RunningBenchmark,
        reason: BenchmarkSchedulerStopReason,
    ) -> Result<(), BenchmarkError> {
        self.task
            .request_stop(job_id, running, reason)
            .map_err(|_| scheduler_error("benchmark task containment failed"))
    }

    // Cleans task resources and attempts resident restoration even if cleanup reports failure.
    fn restore(&self, command: &BenchmarkExecutionRestoration) -> Result<(), BenchmarkError> {
        let cleanup = self.task.cleanup(command);
        let restoration = self.isolation.restore(command);
        if cleanup.is_err() || restoration.is_err() {
            return Err(scheduler_error("benchmark resident restoration failed"));
        }
        Ok(())
    }
}

// Commands one exact fixed telemetry observation window.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreBenchmarkTelemetryWindow {
    job_id: OperationId,
    session_receipt_id: Sha256Digest,
    sampled_at: UnixMilliseconds,
    progress: BenchmarkProgress,
}

impl CoreBenchmarkTelemetryWindow {
    // Creates one contiguous fixed-window command for Watchdog and Gateway aggregation.
    pub const fn new(
        job_id: OperationId,
        session_receipt_id: Sha256Digest,
        sampled_at: UnixMilliseconds,
        progress: BenchmarkProgress,
    ) -> Self {
        Self {
            job_id,
            session_receipt_id,
            sampled_at,
            progress,
        }
    }

    // Returns the exact benchmark operation identity.
    pub const fn job_id(&self) -> &OperationId {
        &self.job_id
    }

    // Returns the deterministic telemetry-session identity.
    pub const fn session_receipt_id(&self) -> &Sha256Digest {
        &self.session_receipt_id
    }

    // Returns the exact end of this fixed observation window.
    pub const fn sampled_at(&self) -> UnixMilliseconds {
        self.sampled_at
    }

    // Returns the progress state bound to this observation window.
    pub const fn progress(&self) -> &BenchmarkProgress {
        &self.progress
    }
}

// Carries the canonical identity of one materialized Watchdog/Gateway sample.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreBenchmarkTelemetryObservation {
    sampled_at: UnixMilliseconds,
    sample_sha256: Sha256Digest,
}

impl CoreBenchmarkTelemetryObservation {
    // Creates one exact sample identity without exposing the provider-owned timeline bytes.
    pub const fn new(sampled_at: UnixMilliseconds, sample_sha256: Sha256Digest) -> Self {
        Self {
            sampled_at,
            sample_sha256,
        }
    }

    // Returns the exact end of the observed one-second window.
    pub const fn sampled_at(&self) -> UnixMilliseconds {
        self.sampled_at
    }

    // Returns the canonical combined Watchdog/Gateway sample identity.
    pub const fn sample_sha256(&self) -> &Sha256Digest {
        &self.sample_sha256
    }
}

// Materializes one exact Watchdog/Gateway telemetry window at a time.
pub trait CoreBenchmarkTelemetryObservationPort: Send + Sync {
    // Persists and returns one canonical observation for the requested window idempotently.
    fn observe(
        &self,
        command: &CoreBenchmarkTelemetryWindow,
    ) -> Result<CoreBenchmarkTelemetryObservation, CoreBenchmarkPortError>;
}

// Persists complete telemetry state with exact optimistic replacement.
pub trait CoreBenchmarkTelemetryPersistencePort: Send + Sync {
    // Reads one timeline without observing or mutating live telemetry.
    fn read(
        &self,
        job_id: &OperationId,
    ) -> Result<Option<BenchmarkTelemetryState>, CoreBenchmarkPortError>;

    // Creates one timeline or returns the exact existing replay.
    fn open(
        &self,
        state: BenchmarkTelemetryState,
    ) -> Result<BenchmarkTelemetryState, CoreBenchmarkPortError>;

    // Replaces one exact previous timeline identity atomically.
    fn replace(
        &self,
        state: BenchmarkTelemetryState,
        expected_samples_sha256: &Sha256Digest,
        expected_sealed_receipt_id: Option<&Sha256Digest>,
    ) -> Result<BenchmarkTelemetryState, CoreBenchmarkPortError>;
}

// Owns contiguous telemetry materialization over injected Application observation and storage ports.
pub struct ApplicationBenchmarkTelemetryPort {
    observations: Arc<dyn CoreBenchmarkTelemetryObservationPort>,
    persistence: Arc<dyn CoreBenchmarkTelemetryPersistencePort>,
}

impl ApplicationBenchmarkTelemetryPort {
    // Creates one restart-safe telemetry bridge from explicit observation and persistence ports.
    pub const fn new(
        observations: Arc<dyn CoreBenchmarkTelemetryObservationPort>,
        persistence: Arc<dyn CoreBenchmarkTelemetryPersistencePort>,
    ) -> Self {
        Self {
            observations,
            persistence,
        }
    }

    // Reads one exact state while redacting persistence implementation failures.
    fn state(&self, job_id: &OperationId) -> Result<BenchmarkTelemetryState, BenchmarkError> {
        self.persistence
            .read(job_id)
            .map_err(|_| telemetry_error("benchmark telemetry persistence is unavailable"))?
            .ok_or_else(|| telemetry_error("benchmark telemetry timeline is unavailable"))
    }

    // Materializes every missing complete window and returns one optimistic replacement state.
    fn synchronized(
        &self,
        previous: &BenchmarkTelemetryState,
        through: UnixMilliseconds,
        progress: BenchmarkProgress,
    ) -> Result<BenchmarkTelemetryState, BenchmarkError> {
        if through < previous.opened_at()
            || previous.sealed_receipt_id().is_some()
            || progress.total_cells() != previous.plan().total_cells()
            || previous
                .progress()
                .is_some_and(|prior| progress.completed_cells() < prior.completed_cells())
        {
            return Err(telemetry_error(
                "benchmark telemetry synchronization is invalid",
            ));
        }
        let interval = previous.plan().telemetry_interval_milliseconds();
        let expected_count = (through.value() - previous.opened_at().value()) / interval;
        let mut samples_sha256 = previous.samples_sha256().clone();
        for sample_index in (previous.sample_count() + 1)..=expected_count {
            let sampled_at =
                UnixMilliseconds::new(
                    previous
                        .opened_at()
                        .value()
                        .checked_add(sample_index.checked_mul(interval).ok_or_else(|| {
                            telemetry_error("benchmark telemetry window overflowed")
                        })?)
                        .ok_or_else(|| telemetry_error("benchmark telemetry window overflowed"))?,
                );
            let command = CoreBenchmarkTelemetryWindow::new(
                previous.job_id().clone(),
                previous.session_receipt_id().clone(),
                sampled_at,
                progress.clone(),
            );
            let observation = self
                .observations
                .observe(&command)
                .map_err(|_| telemetry_error("benchmark telemetry observation failed"))?;
            if observation.sampled_at() != sampled_at {
                return Err(telemetry_error("benchmark telemetry observation has a gap"));
            }
            samples_sha256 = telemetry_samples_sha256(
                &samples_sha256,
                observation.sample_sha256(),
                sampled_at,
                &progress,
            );
        }
        previous.synchronized(through, samples_sha256, progress)
    }

    // Persists one optimistic synchronization from the exact previous state.
    fn replace(
        &self,
        previous: &BenchmarkTelemetryState,
        next: BenchmarkTelemetryState,
    ) -> Result<BenchmarkTelemetryState, BenchmarkError> {
        self.persistence
            .replace(
                next,
                previous.samples_sha256(),
                previous.sealed_receipt_id(),
            )
            .map_err(|_| telemetry_error("benchmark telemetry persistence changed"))
    }
}

impl BenchmarkTelemetryPort for ApplicationBenchmarkTelemetryPort {
    // Opens one empty persistent timeline and preserves its original first-open identity on replay.
    fn open(
        &self,
        command: &BenchmarkTelemetryOpen,
    ) -> Result<BenchmarkTelemetryState, BenchmarkError> {
        let opened = BenchmarkTelemetryState::opened(command)?;
        self.persistence
            .open(opened)
            .map_err(|_| telemetry_error("benchmark telemetry open failed"))
    }

    // Reads the complete current state without observing live telemetry.
    fn state(
        &self,
        job_id: &OperationId,
    ) -> Result<Option<BenchmarkTelemetryState>, BenchmarkError> {
        self.persistence
            .read(job_id)
            .map_err(|_| telemetry_error("benchmark telemetry persistence is unavailable"))
    }

    // Materializes and persists every complete fixed window through one exact boundary.
    fn synchronize(
        &self,
        command: &BenchmarkTelemetrySynchronization,
    ) -> Result<BenchmarkTelemetryState, BenchmarkError> {
        let previous = self.state(command.job_id())?;
        if previous.session_receipt_id() != command.session_receipt_id() {
            return Err(telemetry_error(
                "benchmark telemetry session identity changed",
            ));
        }
        let next = self.synchronized(&previous, command.through(), command.progress().clone())?;
        self.replace(&previous, next)
    }

    // Materializes final complete windows and seals the exact terminal timeline idempotently.
    fn finish(
        &self,
        command: &BenchmarkTelemetryFinish,
    ) -> Result<BenchmarkTelemetryState, BenchmarkError> {
        let previous = self.state(command.job_id())?;
        if previous.session_receipt_id() != command.session_receipt_id() {
            return Err(telemetry_error(
                "benchmark telemetry session identity changed",
            ));
        }
        if previous.sealed_receipt_id().is_some() {
            return previous.sealed(command.through(), command.outcome());
        }
        let progress = previous.progress().cloned().unwrap_or_else(|| {
            BenchmarkProgress::new(
                li_core_interface::TechnicalName::parse("finalizing")
                    .expect("static benchmark phase is valid"),
                0,
                previous.plan().total_cells(),
            )
            .expect("static benchmark progress is valid")
        });
        let synchronized = self.synchronized(&previous, command.through(), progress)?;
        let sealed = synchronized.sealed(command.through(), command.outcome())?;
        self.replace(&previous, sealed)
    }
}

// Hashes one sample into the exact prior timeline identity with length framing.
fn telemetry_samples_sha256(
    previous: &Sha256Digest,
    sample: &Sha256Digest,
    sampled_at: UnixMilliseconds,
    progress: &BenchmarkProgress,
) -> Sha256Digest {
    let mut digest = Sha256::new();
    for field in [
        "li-benchmark-application-telemetry-v1".to_string(),
        previous.as_str().to_string(),
        sample.as_str().to_string(),
        sampled_at.value().to_string(),
        progress.phase().as_str().to_string(),
        progress.completed_cells().to_string(),
        progress.total_cells().to_string(),
    ] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field.as_bytes());
    }
    Sha256Digest::parse(&format!("{:x}", digest.finalize()))
        .expect("SHA-256 formatting is canonical")
}

// Returns one stable scheduler boundary failure.
fn scheduler_error(reason: &'static str) -> BenchmarkError {
    BenchmarkError::provider("execution", reason)
}

// Maps Placement isolation failures to the stable Application boundary without native detail.
fn placement_benchmark_error(error: PlacementError) -> CoreBenchmarkPortError {
    match error {
        PlacementError::StoreConflict | PlacementError::ResourceConflict => {
            CoreBenchmarkPortError::Conflict
        }
        PlacementError::InvalidRequest { .. }
        | PlacementError::InvalidTransition
        | PlacementError::GroupNotFound => CoreBenchmarkPortError::InvalidState,
        _ => CoreBenchmarkPortError::Unavailable,
    }
}

// Returns one stable authorization-source failure without Node or repository detail.
fn authorization_source_error() -> BenchmarkError {
    BenchmarkError::provider("authorization", "benchmark authority is unavailable")
}

// Returns one stable run-plan boundary failure without provider or path detail.
fn run_plan_error(reason: &'static str) -> BenchmarkError {
    BenchmarkError::provider("execution", reason)
}

// Returns one stable telemetry boundary failure.
fn telemetry_error(reason: &'static str) -> BenchmarkError {
    BenchmarkError::provider("telemetry", reason)
}
