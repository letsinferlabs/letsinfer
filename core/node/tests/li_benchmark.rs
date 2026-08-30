// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::VecDeque;
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use li_benchmark_manager::{
    BenchmarkAuthorization, BenchmarkAuthorizationProvider, BenchmarkClock, BenchmarkDisposition,
    BenchmarkError, BenchmarkEvidence, BenchmarkEvidenceProvider, BenchmarkExecutionObservation,
    BenchmarkExecutionOutcome, BenchmarkExecutionProvider, BenchmarkGitRevision, BenchmarkJobPhase,
    BenchmarkKind, BenchmarkProgress, BenchmarkRecordSchema, BenchmarkRequest,
    BenchmarkRestoration, BenchmarkScope, BenchmarkSignature, BenchmarkSigningProvider,
    BenchmarkSubject, BenchmarkTelemetryProvider, BenchmarkTelemetryReceipt,
    BenchmarkVerificationPhase, PreparedBenchmark, RunningBenchmark,
};
use li_core_interface::{
    InstallationId, LogicalModelName, OperationId, PlacementGroupId, RuntimeCandidateId,
    RuntimeInstallationId, Sha256Digest, TechnicalName, UnixMilliseconds,
};
use li_database::{DatabaseClock, DatabaseConfiguration, DatabaseError, DatabaseManager};
use li_node_manager::{
    compose_node_benchmark_coordinator, NodeBenchmarkCandidateHandoffPhase, NodeBenchmarkPlan,
    NodeBenchmarkRequestProvider, NodeBenchmarkSelection, NodeBenchmarkVerificationProjection,
    NodeBenchmarkVerificationProjectionPort,
};

// Resolves one fixed exact request and cell plan without external state.
struct RequestMock;

// Supplies one exact paired parent/handoff projection from durable-mock values.
struct VerificationProjectionMock;

impl NodeBenchmarkVerificationProjectionPort for VerificationProjectionMock {
    // Returns one baseline-running verification projection for any verification job identity.
    fn projection(
        &self,
        _job_id: &OperationId,
    ) -> Result<Option<NodeBenchmarkVerificationProjection>, BenchmarkError> {
        Ok(Some(NodeBenchmarkVerificationProjection::new(
            BenchmarkVerificationPhase::BaselineRunning,
            OperationId::parse(&"d".repeat(32)).expect("handoff transaction"),
            NodeBenchmarkCandidateHandoffPhase::CandidateAcquired,
        )))
    }
}

impl NodeBenchmarkRequestProvider for RequestMock {
    // Returns the deterministic local request used by coordinator integration tests.
    fn resolve(
        &self,
        selection: &NodeBenchmarkSelection,
    ) -> Result<NodeBenchmarkPlan, BenchmarkError> {
        let cell = TechnicalName::parse("32k-code-c1").expect("cell");
        NodeBenchmarkPlan::new(selection, request(), vec![cell.clone()], vec![cell])
    }
}

// Supplies deterministic increasing database commit timestamps.
struct TestDatabaseClock(AtomicI64);

impl DatabaseClock for TestDatabaseClock {
    // Returns one unique database commit timestamp.
    fn now_unix_milliseconds(&self) -> Result<i64, DatabaseError> {
        Ok(self.0.fetch_add(1, Ordering::SeqCst))
    }
}

// Admits one exact benchmark and records how often authorization is resolved.
struct AuthorizationMock(AtomicUsize);

impl BenchmarkAuthorizationProvider for AuthorizationMock {
    // Returns one opaque deterministic authorization receipt.
    fn authorize(
        &self,
        _job_id: &OperationId,
        _request: &BenchmarkRequest,
    ) -> Result<BenchmarkAuthorization, BenchmarkError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(BenchmarkAuthorization::new(digest('a')))
    }
}

// Owns deterministic detached-task observations and restoration counters.
struct ExecutionMock {
    observations: Mutex<VecDeque<BenchmarkExecutionObservation>>,
    starts: AtomicUsize,
    stops: AtomicUsize,
    restorations: AtomicUsize,
}

impl ExecutionMock {
    // Adds one exact worker observation to the deterministic queue.
    fn push(&self, observation: BenchmarkExecutionObservation) {
        self.observations
            .lock()
            .expect("observations")
            .push_back(observation);
    }
}

impl BenchmarkExecutionProvider for ExecutionMock {
    // Returns one exact resident-isolation receipt.
    fn prepare(
        &self,
        _job_id: &OperationId,
        _request: &BenchmarkRequest,
        _authorization: &BenchmarkAuthorization,
    ) -> Result<PreparedBenchmark, BenchmarkError> {
        Ok(PreparedBenchmark::new(digest('b')))
    }

    // Returns one idempotent detached-worker receipt.
    fn start(
        &self,
        _job_id: &OperationId,
        _request: &BenchmarkRequest,
        _prepared: &PreparedBenchmark,
    ) -> Result<RunningBenchmark, BenchmarkError> {
        self.starts.fetch_add(1, Ordering::SeqCst);
        Ok(RunningBenchmark::new(digest('c')))
    }

    // Returns the next exact detached-worker observation.
    fn observe(
        &self,
        _job_id: &OperationId,
        _running: &RunningBenchmark,
    ) -> Result<BenchmarkExecutionObservation, BenchmarkError> {
        self.observations
            .lock()
            .expect("observations")
            .pop_front()
            .ok_or_else(|| BenchmarkError::provider("execution observation", "mock is empty"))
    }

    // Records one idempotent detached-worker cancellation request.
    fn request_stop(
        &self,
        _job_id: &OperationId,
        _running: &RunningBenchmark,
    ) -> Result<(), BenchmarkError> {
        self.stops.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    // Returns one exact resident-service restoration receipt.
    fn restore(
        &self,
        _job_id: &OperationId,
        _request: &BenchmarkRequest,
        _prepared: &PreparedBenchmark,
        _running: Option<&RunningBenchmark>,
        _outcome: &BenchmarkExecutionOutcome,
    ) -> Result<BenchmarkRestoration, BenchmarkError> {
        self.restorations.fetch_add(1, Ordering::SeqCst);
        Ok(BenchmarkRestoration::new(digest('d')))
    }
}

// Captures only bounded progress counts and emits one deterministic receipt.
struct TelemetryMock(AtomicU64);

impl BenchmarkTelemetryProvider for TelemetryMock {
    // Opens one deterministic timeline.
    fn begin(
        &self,
        _job_id: &OperationId,
        _request: &BenchmarkRequest,
        _prepared: &PreparedBenchmark,
    ) -> Result<(), BenchmarkError> {
        Ok(())
    }

    // Counts one exact progress sample without retaining raw telemetry.
    fn capture(
        &self,
        _job_id: &OperationId,
        _progress: &BenchmarkProgress,
    ) -> Result<(), BenchmarkError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    // Seals one exact sample count.
    fn finish(
        &self,
        _job_id: &OperationId,
        _outcome: &BenchmarkExecutionOutcome,
    ) -> Result<BenchmarkTelemetryReceipt, BenchmarkError> {
        Ok(BenchmarkTelemetryReceipt::new(
            digest('e'),
            self.0.load(Ordering::SeqCst),
        ))
    }
}

// Produces one exact model-neutral evidence receipt.
struct EvidenceMock;

impl BenchmarkEvidenceProvider for EvidenceMock {
    // Finalizes one evidence receipt bound to the terminal result identity.
    fn finalize(
        &self,
        _job_id: &OperationId,
        _request: &BenchmarkRequest,
        outcome: &BenchmarkExecutionOutcome,
        _telemetry: &BenchmarkTelemetryReceipt,
        _restoration: &BenchmarkRestoration,
    ) -> Result<BenchmarkEvidence, BenchmarkError> {
        let (results_sha256, schema) = match outcome {
            BenchmarkExecutionOutcome::Succeeded {
                results_sha256,
                record_schema,
                ..
            } => (results_sha256.clone(), *record_schema),
            BenchmarkExecutionOutcome::Failed { .. }
            | BenchmarkExecutionOutcome::Cancelled { .. } => {
                (digest('8'), BenchmarkRecordSchema::CoreLocalFailureV1)
            }
        };
        BenchmarkEvidence::new(digest('f'), results_sha256, schema, 4096)
    }

    // Accepts the deterministic evidence receipt.
    fn verify(
        &self,
        _request: &BenchmarkRequest,
        _outcome: &BenchmarkExecutionOutcome,
        _evidence: &BenchmarkEvidence,
    ) -> Result<(), BenchmarkError> {
        Ok(())
    }
}

// Signs and verifies one deterministic evidence identity.
struct SigningMock;

impl BenchmarkSigningProvider for SigningMock {
    // Returns one URL-safe detached signature without secret key material.
    fn sign(
        &self,
        _job_id: &OperationId,
        _evidence: &BenchmarkEvidence,
    ) -> Result<BenchmarkSignature, BenchmarkError> {
        BenchmarkSignature::new(digest('1'), "c2lnbmF0dXJl")
    }

    // Accepts the deterministic detached signature.
    fn verify(
        &self,
        _evidence: &BenchmarkEvidence,
        _signature: &BenchmarkSignature,
    ) -> Result<bool, BenchmarkError> {
        Ok(true)
    }
}

// Supplies monotonically increasing positive benchmark timestamps.
struct BenchmarkClockMock(AtomicU64);

impl BenchmarkClock for BenchmarkClockMock {
    // Returns one unique benchmark lifecycle timestamp.
    fn now(&self) -> Result<UnixMilliseconds, BenchmarkError> {
        Ok(UnixMilliseconds::new(self.0.fetch_add(1, Ordering::SeqCst)))
    }
}

// Opens one DatabaseManager on the persistent test path.
fn database(path: &std::path::Path) -> Arc<DatabaseManager> {
    Arc::new(
        DatabaseManager::open(
            DatabaseConfiguration::new(path.join("core.sqlite3"))
                .with_busy_timeout(Duration::from_secs(1))
                .with_clock(Arc::new(TestDatabaseClock(AtomicI64::new(10_000)))),
        )
        .expect("database"),
    )
}

// Returns one exact lowercase SHA-256 fixture.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
}

// Returns one exact model-neutral local benchmark request.
fn request() -> BenchmarkRequest {
    BenchmarkRequest::new(
        BenchmarkKind::Local,
        BenchmarkScope::Complete,
        BenchmarkSubject::new(
            InstallationId::parse(&"1".repeat(64)).expect("Core installation"),
            RuntimeInstallationId::parse(&"2".repeat(32)).expect("runtime installation"),
            LogicalModelName::parse("qwen").expect("logical model"),
            PlacementGroupId::parse(&"3".repeat(32)).expect("placement group"),
            digest('4'),
            digest('5'),
            digest('6'),
        ),
    )
    .expect("benchmark request")
}

// Returns one exact complete community-verification request from a closed Application authority.
fn verification_request() -> BenchmarkRequest {
    BenchmarkRequest::new(
        BenchmarkKind::verification(
            41,
            BenchmarkGitRevision::parse(&"a".repeat(40)).expect("head"),
            RuntimeCandidateId::parse("vllm--owner--model--spark").expect("candidate"),
            OperationId::parse(&"d".repeat(32)).expect("transaction"),
            digest('e'),
            digest('f'),
            73,
            digest('b'),
            Some(digest('c')),
        )
        .expect("verification kind"),
        BenchmarkScope::Complete,
        request().subject().clone(),
    )
    .expect("verification request")
}

// Returns the public model selection resolved by the deterministic request provider.
fn selection() -> NodeBenchmarkSelection {
    NodeBenchmarkSelection::new(
        LogicalModelName::parse("qwen").expect("logical model"),
        Vec::new(),
        Vec::new(),
    )
    .expect("selection")
}

// Returns one bounded deterministic benchmark progress point.
fn progress(completed: u32, total: u32) -> BenchmarkProgress {
    BenchmarkProgress::new(
        TechnicalName::parse("measuring").expect("phase"),
        completed,
        total,
    )
    .expect("progress")
}

// Reads every database artifact byte for plaintext-secret exclusion assertions.
fn database_bytes(path: &std::path::Path) -> Vec<u8> {
    let mut bytes = Vec::new();
    for entry in std::fs::read_dir(path).expect("database directory") {
        let entry = entry.expect("database entry");
        if entry.file_type().expect("entry type").is_file() {
            bytes.extend(std::fs::read(entry.path()).expect("database bytes"));
        }
    }
    bytes
}

// Proves Node resumes the sole Database-owned job and completes exact restoration after restart.
#[test]
fn node_coordinator_resumes_one_exact_job_after_restart_without_persisting_replay_secret() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let authorization = Arc::new(AuthorizationMock(AtomicUsize::new(0)));
    let execution = Arc::new(ExecutionMock {
        observations: Mutex::new(VecDeque::new()),
        starts: AtomicUsize::new(0),
        stops: AtomicUsize::new(0),
        restorations: AtomicUsize::new(0),
    });
    let telemetry = Arc::new(TelemetryMock(AtomicU64::new(0)));
    let evidence = Arc::new(EvidenceMock);
    let signing = Arc::new(SigningMock);
    let clock = Arc::new(BenchmarkClockMock(AtomicU64::new(1_700_000_000_000)));
    let first_database = database(directory.path());
    let first = compose_node_benchmark_coordinator(
        first_database.clone(),
        Arc::new(RequestMock),
        authorization.clone(),
        execution.clone(),
        telemetry.clone(),
        evidence.clone(),
        signing.clone(),
        clock.clone(),
    );
    let replay_secret = "benchmark-replay-secret-must-not-persist";
    let started = first.start(replay_secret, selection()).expect("start");
    assert_eq!(started.phase(), BenchmarkJobPhase::Running);
    assert_eq!(started.core_installation_id().as_str(), &"1".repeat(64));
    assert_eq!(started.runtime_installation_id().as_str(), &"2".repeat(32));
    assert_eq!(started.placement_group_id().as_str(), &"3".repeat(32));
    assert_eq!(started.execution_sha256(), &digest('4'));
    assert_eq!(started.benchmark_contract_sha256(), &digest('5'));
    assert_eq!(started.target_contract_sha256(), &digest('6'));
    assert_eq!(execution.starts.load(Ordering::SeqCst), 1);
    assert_eq!(
        first.start("second-job", selection()),
        Err(BenchmarkError::Busy)
    );
    let job_id = started.job_id().clone();
    drop(first);
    drop(first_database);

    assert!(!database_bytes(directory.path())
        .windows(replay_secret.len())
        .any(|window| window == replay_secret.as_bytes()));

    execution.push(BenchmarkExecutionObservation::Running(progress(1, 2)));
    let restarted_database = database(directory.path());
    let restarted = compose_node_benchmark_coordinator(
        restarted_database,
        Arc::new(RequestMock),
        authorization.clone(),
        execution.clone(),
        telemetry.clone(),
        evidence,
        signing,
        clock,
    );
    let recovered = restarted.active().expect("active").expect("running job");
    assert_eq!(recovered.job_id(), &job_id);
    assert_eq!(recovered.phase(), BenchmarkJobPhase::Running);
    let advanced = restarted
        .poll_active()
        .expect("poll progress")
        .expect("advanced job");
    assert_eq!(advanced.progress().expect("progress").completed_cells(), 1);
    assert_eq!(execution.starts.load(Ordering::SeqCst), 1);

    execution.push(BenchmarkExecutionObservation::Terminal(
        BenchmarkExecutionOutcome::Succeeded {
            raw_evidence_sha256: digest('7'),
            results_sha256: digest('8'),
            record_schema: BenchmarkRecordSchema::OciExecutionPayloadV7,
        },
    ));
    let completed = restarted
        .poll_active()
        .expect("poll terminal")
        .expect("completed job");
    assert_eq!(completed.phase(), BenchmarkJobPhase::Completed);
    assert_eq!(
        completed.disposition(),
        Some(BenchmarkDisposition::Completed)
    );
    assert!(completed.telemetry_receipt_id().is_some());
    assert_eq!(completed.telemetry_sample_count(), Some(1));
    assert!(completed.restoration_receipt_id().is_some());
    assert!(completed.evidence_id().is_some());
    assert!(restarted.active().expect("active after terminal").is_none());
    assert_eq!(execution.restorations.load(Ordering::SeqCst), 1);
    assert_eq!(authorization.0.load(Ordering::SeqCst), 1);
}

// Proves cancellation remains durable across restart and restores the resident service once.
#[test]
fn node_coordinator_resumes_cancellation_and_restoration_after_restart() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let authorization = Arc::new(AuthorizationMock(AtomicUsize::new(0)));
    let execution = Arc::new(ExecutionMock {
        observations: Mutex::new(VecDeque::new()),
        starts: AtomicUsize::new(0),
        stops: AtomicUsize::new(0),
        restorations: AtomicUsize::new(0),
    });
    let telemetry = Arc::new(TelemetryMock(AtomicU64::new(0)));
    let evidence = Arc::new(EvidenceMock);
    let signing = Arc::new(SigningMock);
    let clock = Arc::new(BenchmarkClockMock(AtomicU64::new(1_700_000_000_000)));
    let first_database = database(directory.path());
    let first = compose_node_benchmark_coordinator(
        first_database.clone(),
        Arc::new(RequestMock),
        authorization.clone(),
        execution.clone(),
        telemetry.clone(),
        evidence.clone(),
        signing.clone(),
        clock.clone(),
    );
    let started = first.start("cancel-restart", selection()).expect("start");
    let stopping = first.stop(started.job_id()).expect("stop");
    assert_eq!(stopping.phase(), BenchmarkJobPhase::Stopping);
    assert_eq!(execution.stops.load(Ordering::SeqCst), 1);
    let job_id = started.job_id().clone();
    drop(first);
    drop(first_database);

    execution.push(BenchmarkExecutionObservation::Terminal(
        BenchmarkExecutionOutcome::Cancelled {
            raw_evidence_sha256: None,
        },
    ));
    let restarted = compose_node_benchmark_coordinator(
        database(directory.path()),
        Arc::new(RequestMock),
        authorization,
        execution.clone(),
        telemetry,
        evidence,
        signing,
        clock,
    );
    assert_eq!(
        restarted.active().expect("active").expect("job").job_id(),
        &job_id
    );
    let cancelled = restarted
        .poll_active()
        .expect("poll cancelled")
        .expect("cancelled job");
    assert_eq!(cancelled.phase(), BenchmarkJobPhase::Cancelled);
    assert_eq!(
        cancelled.disposition(),
        Some(BenchmarkDisposition::Cancelled)
    );
    assert!(cancelled.restoration_receipt_id().is_some());
    assert_eq!(execution.restorations.load(Ordering::SeqCst), 1);
}

// Starts and replays only a complete Application-verified request through the real manager journal.
#[test]
fn node_coordinator_starts_one_closed_verification_request_with_replay_safety() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let execution = Arc::new(ExecutionMock {
        observations: Mutex::new(VecDeque::new()),
        starts: AtomicUsize::new(0),
        stops: AtomicUsize::new(0),
        restorations: AtomicUsize::new(0),
    });
    let coordinator = compose_node_benchmark_coordinator(
        database(directory.path()),
        Arc::new(RequestMock),
        Arc::new(AuthorizationMock(AtomicUsize::new(0))),
        execution.clone(),
        Arc::new(TelemetryMock(AtomicU64::new(0))),
        Arc::new(EvidenceMock),
        Arc::new(SigningMock),
        Arc::new(BenchmarkClockMock(AtomicU64::new(1_700_000_000_000))),
    )
    .with_verification_projection(Arc::new(VerificationProjectionMock));
    assert_eq!(
        coordinator.start_verified("invalid-local", request()),
        Err(BenchmarkError::InvalidContract {
            reason: "verified benchmark request is not complete proposal authority"
        })
    );
    let request = verification_request();
    let started = coordinator
        .start_verified("verification-replay", request.clone())
        .expect("started");
    assert!(started.is_verification());
    assert_eq!(
        started.verification().expect("verification").phase(),
        BenchmarkVerificationPhase::BaselineRunning
    );
    let replayed = coordinator
        .start_verified("verification-replay", request)
        .expect("replayed");
    assert_eq!(replayed.job_id(), started.job_id());
    assert_eq!(execution.starts.load(Ordering::SeqCst), 1);
}
