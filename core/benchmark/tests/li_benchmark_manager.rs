// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Condvar, Mutex};
use std::thread;

use li_benchmark_manager::{
    BenchmarkAuthorization, BenchmarkAuthorizationProvider, BenchmarkClock, BenchmarkDisposition,
    BenchmarkError, BenchmarkEvidence, BenchmarkEvidenceProvider, BenchmarkExecutionObservation,
    BenchmarkExecutionOutcome, BenchmarkExecutionProvider, BenchmarkFailure,
    BenchmarkFailureCategory, BenchmarkGitRevision, BenchmarkJobPhase, BenchmarkJobRecord,
    BenchmarkKind, BenchmarkManager, BenchmarkProgress, BenchmarkPublication,
    BenchmarkPublicationProvider, BenchmarkPublicationRequest, BenchmarkRecordSchema,
    BenchmarkRequest, BenchmarkRestoration, BenchmarkScope, BenchmarkSignature,
    BenchmarkSigningProvider, BenchmarkStore, BenchmarkStoreError, BenchmarkSubject,
    BenchmarkTelemetryProvider, BenchmarkTelemetryReceipt, PreparedBenchmark, RunningBenchmark,
    VersionedBenchmarkJob,
};
use li_core_interface::{
    InstallationId, LogicalModelName, OperationId, PlacementGroupId, RuntimeCandidateId,
    RuntimeInstallationId, Sha256Digest, TechnicalName, UnixMilliseconds,
};

// Stores deterministic provider failures by exact capability name.
#[derive(Default)]
struct FailurePlan(Mutex<BTreeMap<&'static str, usize>>);

impl FailurePlan {
    // Schedules one capability to fail the requested number of times.
    fn fail(&self, capability: &'static str, count: usize) {
        self.0
            .lock()
            .expect("failure plan")
            .insert(capability, count);
    }

    // Returns one redacted failure while the scheduled count remains positive.
    fn check(&self, capability: &'static str) -> Result<(), BenchmarkError> {
        let mut failures = self.0.lock().expect("failure plan");
        let Some(remaining) = failures.get_mut(capability) else {
            return Ok(());
        };
        if *remaining == 0 {
            return Ok(());
        }
        *remaining -= 1;
        Err(BenchmarkError::provider(capability, "mock failure"))
    }
}

// Stores complete optimistic benchmark journals with one active-job constraint.
#[derive(Default)]
struct MemoryStore {
    records: Mutex<HashMap<String, (BenchmarkJobRecord, u64)>>,
    replace_calls: AtomicUsize,
    fail_replace_call: Mutex<Option<usize>>,
    corrupt_reads: AtomicBool,
}

impl MemoryStore {
    // Schedules one exact optimistic replacement call to fail once.
    fn fail_replace_call(&self, call: usize) {
        *self.fail_replace_call.lock().expect("replace failure") = Some(call);
    }

    // Makes subsequent reads report semantic corruption.
    fn corrupt_reads(&self) {
        self.corrupt_reads.store(true, Ordering::SeqCst);
    }

    // Returns all currently stored records for no-mutation assertions.
    fn record_count(&self) -> usize {
        self.records.lock().expect("records").len()
    }

    // Returns one versioned clone from a stored record tuple.
    fn versioned(
        record: &(BenchmarkJobRecord, u64),
    ) -> Result<VersionedBenchmarkJob, BenchmarkStoreError> {
        VersionedBenchmarkJob::new(record.0.clone(), record.1)
    }
}

impl BenchmarkStore for MemoryStore {
    // Returns one record by exact operation identity.
    fn read(
        &self,
        job_id: &OperationId,
    ) -> Result<Option<VersionedBenchmarkJob>, BenchmarkStoreError> {
        if self.corrupt_reads.load(Ordering::SeqCst) {
            return Err(BenchmarkStoreError::Corrupt);
        }
        self.records
            .lock()
            .map_err(|_| BenchmarkStoreError::Unavailable)?
            .get(job_id.as_str())
            .map(Self::versioned)
            .transpose()
    }

    // Returns one record by its hashed replay identity.
    fn read_replay(
        &self,
        replay_sha256: &Sha256Digest,
    ) -> Result<Option<VersionedBenchmarkJob>, BenchmarkStoreError> {
        if self.corrupt_reads.load(Ordering::SeqCst) {
            return Err(BenchmarkStoreError::Corrupt);
        }
        self.records
            .lock()
            .map_err(|_| BenchmarkStoreError::Unavailable)?
            .values()
            .find(|(record, _)| record.replay_sha256() == replay_sha256)
            .map(Self::versioned)
            .transpose()
    }

    // Returns the sole non-terminal record and rejects impossible duplication.
    fn active(&self) -> Result<Option<VersionedBenchmarkJob>, BenchmarkStoreError> {
        if self.corrupt_reads.load(Ordering::SeqCst) {
            return Err(BenchmarkStoreError::Corrupt);
        }
        let records = self
            .records
            .lock()
            .map_err(|_| BenchmarkStoreError::Unavailable)?;
        let active: Vec<_> = records
            .values()
            .filter(|(record, _)| !record.phase().is_terminal())
            .collect();
        if active.len() > 1 {
            return Err(BenchmarkStoreError::Corrupt);
        }
        active
            .first()
            .map(|record| Self::versioned(record))
            .transpose()
    }

    // Creates one revision-one record while atomically excluding another active job.
    fn create(
        &self,
        record: BenchmarkJobRecord,
    ) -> Result<VersionedBenchmarkJob, BenchmarkStoreError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| BenchmarkStoreError::Unavailable)?;
        if records.contains_key(record.job_id().as_str())
            || records
                .values()
                .any(|(stored, _)| !stored.phase().is_terminal())
        {
            return Err(BenchmarkStoreError::Conflict);
        }
        records.insert(record.job_id().as_str().to_string(), (record.clone(), 1));
        VersionedBenchmarkJob::new(record, 1)
    }

    // Replaces one exact optimistic revision and increments it once.
    fn replace(
        &self,
        record: BenchmarkJobRecord,
        expected_revision: u64,
    ) -> Result<VersionedBenchmarkJob, BenchmarkStoreError> {
        let call = self.replace_calls.fetch_add(1, Ordering::SeqCst) + 1;
        let mut failure = self
            .fail_replace_call
            .lock()
            .map_err(|_| BenchmarkStoreError::Unavailable)?;
        if failure.is_some_and(|wanted| wanted == call) {
            *failure = None;
            return Err(BenchmarkStoreError::Unavailable);
        }
        drop(failure);
        let mut records = self
            .records
            .lock()
            .map_err(|_| BenchmarkStoreError::Unavailable)?;
        let stored = records
            .get_mut(record.job_id().as_str())
            .ok_or(BenchmarkStoreError::Corrupt)?;
        if stored.1 != expected_revision {
            return Err(BenchmarkStoreError::Conflict);
        }
        stored.0 = record.clone();
        stored.1 += 1;
        VersionedBenchmarkJob::new(record, stored.1)
    }
}

// Authorizes deterministic requests and optionally synchronizes concurrent callers.
struct AuthorizationMock {
    events: Arc<Mutex<Vec<String>>>,
    denied: AtomicBool,
    barrier: Mutex<Option<Arc<Barrier>>>,
}

impl AuthorizationMock {
    // Installs one barrier used to force an atomic create race.
    fn set_barrier(&self, barrier: Arc<Barrier>) {
        *self.barrier.lock().expect("authorization barrier") = Some(barrier);
    }

    // Enables one generic authority denial before any job is persisted.
    fn deny(&self) {
        self.denied.store(true, Ordering::SeqCst);
    }
}

impl BenchmarkAuthorizationProvider for AuthorizationMock {
    // Records and resolves one exact local or verification admission decision.
    fn authorize(
        &self,
        _job_id: &OperationId,
        _request: &BenchmarkRequest,
    ) -> Result<BenchmarkAuthorization, BenchmarkError> {
        record_event(&self.events, "authorization");
        let barrier = self.barrier.lock().expect("barrier").clone();
        if let Some(barrier) = barrier {
            barrier.wait();
        }
        if self.denied.load(Ordering::SeqCst) {
            return Err(BenchmarkError::AuthorizationDenied);
        }
        Ok(BenchmarkAuthorization::new(digest('a')))
    }
}

// Owns deterministic execution observations and exact provider call history.
struct ExecutionMock {
    events: Arc<Mutex<Vec<String>>>,
    failures: Arc<FailurePlan>,
    observations: Mutex<VecDeque<BenchmarkExecutionObservation>>,
    start_calls: AtomicUsize,
}

impl ExecutionMock {
    // Adds one execution observation to the deterministic worker sequence.
    fn push(&self, observation: BenchmarkExecutionObservation) {
        self.observations
            .lock()
            .expect("observations")
            .push_back(observation);
    }

    // Returns how many idempotent worker-start calls occurred.
    fn start_calls(&self) -> usize {
        self.start_calls.load(Ordering::SeqCst)
    }
}

impl BenchmarkExecutionProvider for ExecutionMock {
    // Returns one exact prepared receipt after the scheduled preflight boundary.
    fn prepare(
        &self,
        _job_id: &OperationId,
        _request: &BenchmarkRequest,
        _authorization: &BenchmarkAuthorization,
    ) -> Result<PreparedBenchmark, BenchmarkError> {
        record_event(&self.events, "execution.prepare");
        self.failures.check("execution.prepare")?;
        Ok(PreparedBenchmark::new(digest('b')))
    }

    // Returns one stable detached-worker receipt for every idempotent replay.
    fn start(
        &self,
        _job_id: &OperationId,
        _request: &BenchmarkRequest,
        _prepared: &PreparedBenchmark,
    ) -> Result<RunningBenchmark, BenchmarkError> {
        record_event(&self.events, "execution.start");
        self.start_calls.fetch_add(1, Ordering::SeqCst);
        self.failures.check("execution.start")?;
        Ok(RunningBenchmark::new(digest('c')))
    }

    // Returns the next exact worker observation without consulting a process table.
    fn observe(
        &self,
        _job_id: &OperationId,
        _running: &RunningBenchmark,
    ) -> Result<BenchmarkExecutionObservation, BenchmarkError> {
        record_event(&self.events, "execution.observe");
        self.failures.check("execution.observe")?;
        self.observations
            .lock()
            .expect("observations")
            .pop_front()
            .ok_or_else(|| BenchmarkError::provider("execution.observe", "no mock observation"))
    }

    // Records one exact idempotent worker cancellation request.
    fn request_stop(
        &self,
        _job_id: &OperationId,
        _running: &RunningBenchmark,
    ) -> Result<(), BenchmarkError> {
        record_event(&self.events, "execution.stop");
        self.failures.check("execution.stop")
    }

    // Returns one successful exact resident-service restoration receipt.
    fn restore(
        &self,
        _job_id: &OperationId,
        _request: &BenchmarkRequest,
        _prepared: &PreparedBenchmark,
        _running: Option<&RunningBenchmark>,
        _outcome: &BenchmarkExecutionOutcome,
    ) -> Result<BenchmarkRestoration, BenchmarkError> {
        record_event(&self.events, "execution.restore");
        self.failures.check("execution.restore")?;
        Ok(BenchmarkRestoration::new(digest('d')))
    }
}

// Persists a deterministic sample count behind the telemetry capability.
struct TelemetryMock {
    events: Arc<Mutex<Vec<String>>>,
    failures: Arc<FailurePlan>,
    samples: AtomicU64,
}

impl BenchmarkTelemetryProvider for TelemetryMock {
    // Opens one deterministic timeline without reading host telemetry.
    fn begin(
        &self,
        _job_id: &OperationId,
        _request: &BenchmarkRequest,
        _prepared: &PreparedBenchmark,
    ) -> Result<(), BenchmarkError> {
        record_event(&self.events, "telemetry.begin");
        self.failures.check("telemetry.begin")
    }

    // Records one schema-owned sample boundary for active progress.
    fn capture(
        &self,
        _job_id: &OperationId,
        _progress: &BenchmarkProgress,
    ) -> Result<(), BenchmarkError> {
        record_event(&self.events, "telemetry.capture");
        self.failures.check("telemetry.capture")?;
        self.samples.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    // Returns one immutable timeline receipt with the exact captured sample count.
    fn finish(
        &self,
        _job_id: &OperationId,
        _outcome: &BenchmarkExecutionOutcome,
    ) -> Result<BenchmarkTelemetryReceipt, BenchmarkError> {
        record_event(&self.events, "telemetry.finish");
        self.failures.check("telemetry.finish")?;
        Ok(BenchmarkTelemetryReceipt::new(
            digest('e'),
            self.samples.load(Ordering::SeqCst),
        ))
    }
}

// Produces deterministic immutable evidence and validates the exact request binding.
struct EvidenceMock {
    events: Arc<Mutex<Vec<String>>>,
    failures: Arc<FailurePlan>,
    verification_requests: AtomicUsize,
    verification_local_failure: AtomicBool,
}

impl BenchmarkEvidenceProvider for EvidenceMock {
    // Returns one schema-7 receipt for the complete mocked evidence document.
    fn finalize(
        &self,
        _job_id: &OperationId,
        request: &BenchmarkRequest,
        outcome: &BenchmarkExecutionOutcome,
        _telemetry: &BenchmarkTelemetryReceipt,
        _restoration: &BenchmarkRestoration,
    ) -> Result<BenchmarkEvidence, BenchmarkError> {
        record_event(&self.events, "evidence.finalize");
        self.failures.check("evidence.finalize")?;
        if request.kind().is_verification() {
            self.verification_requests.fetch_add(1, Ordering::SeqCst);
        }
        let schema = if request.kind().is_verification()
            && self.verification_local_failure.load(Ordering::SeqCst)
            && !matches!(outcome, BenchmarkExecutionOutcome::Succeeded { .. })
        {
            BenchmarkRecordSchema::CoreLocalFailureV1
        } else if request.kind().is_verification() {
            BenchmarkRecordSchema::CommunityVerificationV1
        } else if matches!(outcome, BenchmarkExecutionOutcome::Succeeded { .. }) {
            BenchmarkRecordSchema::OciExecutionPayloadV7
        } else {
            BenchmarkRecordSchema::CoreLocalFailureV1
        };
        BenchmarkEvidence::new(digest('f'), digest('1'), schema, 4096)
    }

    // Revalidates one deterministic evidence receipt at the semantic boundary.
    fn verify(
        &self,
        _request: &BenchmarkRequest,
        _outcome: &BenchmarkExecutionOutcome,
        _evidence: &BenchmarkEvidence,
    ) -> Result<(), BenchmarkError> {
        record_event(&self.events, "evidence.verify");
        self.failures.check("evidence.verify")
    }
}

// Signs deterministic evidence and can reject one exact verification attempt.
struct SigningMock {
    events: Arc<Mutex<Vec<String>>>,
    failures: Arc<FailurePlan>,
    reject_count: AtomicUsize,
}

// Returns one exact verification publication and preserves retryable failures in Finalizing.
struct PublicationMock {
    events: Arc<Mutex<Vec<String>>>,
    failures: Arc<FailurePlan>,
    calls: AtomicUsize,
}

impl BenchmarkPublicationProvider for PublicationMock {
    // Publishes only verification and returns no receipt for an ordinary local run.
    fn publish(
        &self,
        request: &BenchmarkPublicationRequest<'_>,
    ) -> Result<Option<BenchmarkPublication>, BenchmarkError> {
        record_event(&self.events, "publication.publish");
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.failures.check("publication.publish")?;
        let BenchmarkKind::Verification {
            pull_request,
            proposal_head,
            candidate,
            device_id,
            ..
        } = request.request().kind()
        else {
            return Ok(None);
        };
        if request.sealed().evidence().schema() == BenchmarkRecordSchema::CoreLocalFailureV1 {
            return Ok(None);
        }
        BenchmarkPublication::new(
            digest('9'),
            request.sealed().evidence().evidence_id().clone(),
            digest('8'),
            *pull_request,
            proposal_head.clone(),
            candidate.clone(),
            Some(digest('7')),
            Some(digest('6')),
            digest('5'),
            request.restoration().receipt_id().clone(),
            request.sealed().evidence().evidence_id().clone(),
            device_id.clone(),
            request.sealed().signature().key_id().clone(),
            11,
            format!(
                "https://github.com/letsinferlabs/runtimes/pull/{pull_request}#issuecomment-11"
            ),
        )
        .map(Some)
    }
}

impl SigningMock {
    // Schedules one validly formed signature to fail independent verification.
    fn reject_once(&self) {
        self.reject_count.store(1, Ordering::SeqCst);
    }
}

impl BenchmarkSigningProvider for SigningMock {
    // Returns one stable URL-safe detached signature for the exact evidence.
    fn sign(
        &self,
        _job_id: &OperationId,
        _evidence: &BenchmarkEvidence,
    ) -> Result<BenchmarkSignature, BenchmarkError> {
        record_event(&self.events, "signing.sign");
        self.failures.check("signing.sign")?;
        BenchmarkSignature::new(digest('2'), "c2lnbmF0dXJl")
    }

    // Independently verifies or deliberately rejects one deterministic signature.
    fn verify(
        &self,
        _evidence: &BenchmarkEvidence,
        _signature: &BenchmarkSignature,
    ) -> Result<bool, BenchmarkError> {
        record_event(&self.events, "signing.verify");
        self.failures.check("signing.verify")?;
        let remaining = self.reject_count.load(Ordering::SeqCst);
        if remaining > 0 {
            self.reject_count.fetch_sub(1, Ordering::SeqCst);
            return Ok(false);
        }
        Ok(true)
    }
}

// Supplies deterministic monotonically increasing wall time.
struct ClockMock(AtomicU64);

impl ClockMock {
    // Moves the next returned timestamp to one exact value.
    fn set(&self, value: u64) {
        self.0.store(value, Ordering::SeqCst);
    }
}

impl BenchmarkClock for ClockMock {
    // Returns one deterministic positive millisecond value.
    fn now(&self) -> Result<UnixMilliseconds, BenchmarkError> {
        Ok(UnixMilliseconds::new(self.0.fetch_add(1, Ordering::SeqCst)))
    }
}

// Owns every deterministic port used by one manager scenario.
struct Harness {
    store: Arc<MemoryStore>,
    authorization: Arc<AuthorizationMock>,
    execution: Arc<ExecutionMock>,
    telemetry: Arc<TelemetryMock>,
    evidence: Arc<EvidenceMock>,
    signing: Arc<SigningMock>,
    publication: Arc<PublicationMock>,
    clock: Arc<ClockMock>,
    failures: Arc<FailurePlan>,
    events: Arc<Mutex<Vec<String>>>,
}

impl Harness {
    // Creates one isolated manager environment with no native dependencies.
    fn new() -> Self {
        let events = Arc::new(Mutex::new(Vec::new()));
        let failures = Arc::new(FailurePlan::default());
        Self {
            store: Arc::new(MemoryStore::default()),
            authorization: Arc::new(AuthorizationMock {
                events: events.clone(),
                denied: AtomicBool::new(false),
                barrier: Mutex::new(None),
            }),
            execution: Arc::new(ExecutionMock {
                events: events.clone(),
                failures: failures.clone(),
                observations: Mutex::new(VecDeque::new()),
                start_calls: AtomicUsize::new(0),
            }),
            telemetry: Arc::new(TelemetryMock {
                events: events.clone(),
                failures: failures.clone(),
                samples: AtomicU64::new(0),
            }),
            evidence: Arc::new(EvidenceMock {
                events: events.clone(),
                failures: failures.clone(),
                verification_requests: AtomicUsize::new(0),
                verification_local_failure: AtomicBool::new(false),
            }),
            signing: Arc::new(SigningMock {
                events: events.clone(),
                failures: failures.clone(),
                reject_count: AtomicUsize::new(0),
            }),
            publication: Arc::new(PublicationMock {
                events: events.clone(),
                failures: failures.clone(),
                calls: AtomicUsize::new(0),
            }),
            clock: Arc::new(ClockMock(AtomicU64::new(1_700_000_000_000))),
            failures,
            events,
        }
    }

    // Creates a fresh manager over the same durable store and provider state.
    fn manager(&self) -> BenchmarkManager {
        BenchmarkManager::new_with_publication(
            self.store.clone(),
            self.authorization.clone(),
            self.execution.clone(),
            self.telemetry.clone(),
            self.evidence.clone(),
            self.signing.clone(),
            self.publication.clone(),
            self.clock.clone(),
        )
    }

    // Creates one local-only manager whose absent publication authority must reject verification.
    fn manager_without_publication(&self) -> BenchmarkManager {
        BenchmarkManager::new(
            self.store.clone(),
            self.authorization.clone(),
            self.execution.clone(),
            self.telemetry.clone(),
            self.evidence.clone(),
            self.signing.clone(),
            self.clock.clone(),
        )
    }

    // Returns the exact ordered external call history.
    fn events(&self) -> Vec<String> {
        self.events.lock().expect("events").clone()
    }
}

// Creates one repeated canonical SHA-256 fixture.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
}

// Creates one ordinary exact runtime benchmark request.
fn local_request() -> BenchmarkRequest {
    BenchmarkRequest::new(
        BenchmarkKind::Local,
        BenchmarkScope::Complete,
        subject("qwen"),
    )
    .expect("local request")
}

// Creates one exact community-verification request with a comparable baseline.
fn verification_request() -> BenchmarkRequest {
    BenchmarkRequest::new(
        BenchmarkKind::verification(
            123,
            BenchmarkGitRevision::parse(&"a".repeat(40)).expect("Git revision"),
            RuntimeCandidateId::parse("engine--owner--model--target").expect("candidate"),
            OperationId::parse(&"e".repeat(32)).expect("transaction"),
            digest('f'),
            digest('0'),
            42,
            digest('2'),
            Some(digest('c')),
        )
        .expect("verification kind"),
        BenchmarkScope::Complete,
        subject("qwen"),
    )
    .expect("verification request")
}

// Creates one exact subject while allowing a distinct logical model fingerprint.
fn subject(model: &str) -> BenchmarkSubject {
    BenchmarkSubject::new(
        InstallationId::parse(&"1".repeat(64)).expect("Core installation"),
        RuntimeInstallationId::parse(&"2".repeat(32)).expect("runtime installation"),
        LogicalModelName::parse(model).expect("model"),
        PlacementGroupId::parse(&"3".repeat(32)).expect("placement group"),
        digest('4'),
        digest('5'),
        digest('6'),
    )
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

// Creates one blocking execution failure with a stable category and phase.
fn failure(category: BenchmarkFailureCategory) -> BenchmarkFailure {
    BenchmarkFailure::new(category, "measuring", "mock benchmark failure").expect("failure")
}

// Adds one event without exposing provider internals to assertions.
fn record_event(events: &Arc<Mutex<Vec<String>>>, event: &str) {
    events.lock().expect("events").push(event.to_string());
}

// Runs one ordinary request to its detached running phase.
fn start_running(harness: &Harness, key: &str) -> (BenchmarkManager, OperationId) {
    let manager = harness.manager();
    let change = manager
        .start(key, local_request())
        .expect("start benchmark");
    assert_eq!(change.disposition(), BenchmarkDisposition::Running);
    (manager, change.versioned().record().job_id().clone())
}

// Proves the ordinary detached lifecycle, telemetry, restoration, signing, and replay contract.
#[test]
fn ordinary_lifecycle_seals_exact_evidence_and_replays_without_side_effects() {
    let harness = Harness::new();
    let (manager, job_id) = start_running(&harness, "ordinary");
    harness
        .execution
        .push(BenchmarkExecutionObservation::Running(progress(1, 2)));
    let running = manager.poll(&job_id).expect("poll progress");
    assert_eq!(running.disposition(), BenchmarkDisposition::Running);
    assert_eq!(
        running
            .versioned()
            .record()
            .progress()
            .expect("progress")
            .completed_cells(),
        1
    );

    harness
        .execution
        .push(BenchmarkExecutionObservation::Terminal(
            BenchmarkExecutionOutcome::Succeeded {
                raw_evidence_sha256: digest('7'),
                results_sha256: digest('1'),
                record_schema: BenchmarkRecordSchema::OciExecutionPayloadV7,
            },
        ));
    let completed = manager.poll(&job_id).expect("complete benchmark");
    assert_eq!(completed.disposition(), BenchmarkDisposition::Completed);
    let record = completed.versioned().record();
    assert_eq!(record.phase(), BenchmarkJobPhase::Completed);
    assert_eq!(record.telemetry().expect("telemetry").sample_count(), 1);
    assert_eq!(
        record
            .evidence()
            .expect("sealed evidence")
            .evidence()
            .schema()
            .version(),
        7
    );
    assert!(harness.events().ends_with(&[
        "telemetry.finish".to_string(),
        "execution.restore".to_string(),
        "evidence.finalize".to_string(),
        "evidence.verify".to_string(),
        "signing.sign".to_string(),
        "signing.verify".to_string(),
        "publication.publish".to_string(),
    ]));

    let event_count = harness.events().len();
    let replay = manager
        .start("ordinary", local_request())
        .expect("replay benchmark");
    assert_eq!(replay.disposition(), BenchmarkDisposition::Replayed);
    assert_eq!(harness.events().len(), event_count);
}

// Proves community verification retains exact authority and complete-contract identity.
#[test]
fn verification_uses_complete_contract_and_reaches_the_evidence_boundary() {
    let harness = Harness::new();
    let manager = harness.manager();
    let request = verification_request();
    let started = manager
        .start("verification", request.clone())
        .expect("start verification");
    let job_id = started.versioned().record().job_id().clone();
    harness
        .execution
        .push(BenchmarkExecutionObservation::Terminal(
            BenchmarkExecutionOutcome::Succeeded {
                raw_evidence_sha256: digest('8'),
                results_sha256: digest('1'),
                record_schema: BenchmarkRecordSchema::CommunityVerificationV1,
            },
        ));
    let completed = manager.poll(&job_id).expect("complete verification");
    assert_eq!(completed.disposition(), BenchmarkDisposition::Completed);
    assert!(completed
        .versioned()
        .record()
        .request()
        .kind()
        .is_verification());
    assert!(completed
        .versioned()
        .record()
        .request()
        .scope()
        .is_complete());
    assert_eq!(
        harness
            .evidence
            .verification_requests
            .load(Ordering::SeqCst),
        1
    );
    assert!(completed.versioned().record().publication().is_some());
    assert_eq!(harness.publication.calls.load(Ordering::SeqCst), 1);
}

// Completes a pre-candidate verification failure locally without fabricating a public receipt.
#[test]
fn verification_pre_candidate_failure_seals_local_evidence_without_publication() {
    let harness = Harness::new();
    harness
        .evidence
        .verification_local_failure
        .store(true, Ordering::SeqCst);
    let manager = harness.manager();
    let started = manager
        .start("verification-pre-candidate", verification_request())
        .expect("start verification");
    let job_id = started.versioned().record().job_id().clone();
    harness
        .execution
        .push(BenchmarkExecutionObservation::Terminal(
            BenchmarkExecutionOutcome::Failed {
                raw_evidence_sha256: None,
                failure: BenchmarkFailure::new(
                    BenchmarkFailureCategory::Crash,
                    "baseline",
                    "baseline failed before candidate activation",
                )
                .expect("failure"),
            },
        ));
    let failed = manager.poll(&job_id).expect("local terminal failure");
    assert_eq!(failed.disposition(), BenchmarkDisposition::Failed);
    assert_eq!(
        failed
            .versioned()
            .record()
            .evidence()
            .expect("evidence")
            .evidence()
            .schema(),
        BenchmarkRecordSchema::CoreLocalFailureV1
    );
    assert!(failed.versioned().record().publication().is_none());
}

// Proves publication failure remains finalizing and resumes exactly once after restart.
#[test]
fn verification_publication_failure_retries_after_restart_without_rerunning() {
    let harness = Harness::new();
    harness.failures.fail("publication.publish", 1);
    let request = verification_request();
    let manager = harness.manager();
    let started = manager
        .start("publication-restart", request.clone())
        .expect("start verification");
    let job_id = started.versioned().record().job_id().clone();
    harness
        .execution
        .push(BenchmarkExecutionObservation::Terminal(
            BenchmarkExecutionOutcome::Succeeded {
                raw_evidence_sha256: digest('8'),
                results_sha256: digest('1'),
                record_schema: BenchmarkRecordSchema::CommunityVerificationV1,
            },
        ));

    assert!(matches!(
        manager.poll(&job_id),
        Err(BenchmarkError::Provider { .. })
    ));
    let interrupted = manager
        .record(&job_id)
        .expect("read interrupted publication")
        .expect("interrupted publication");
    assert_eq!(interrupted.record().phase(), BenchmarkJobPhase::Finalizing);
    assert!(interrupted.record().publication().is_none());
    assert_eq!(harness.publication.calls.load(Ordering::SeqCst), 1);

    let completed = harness
        .manager()
        .poll(&job_id)
        .expect("resume publication after restart");
    assert_eq!(completed.disposition(), BenchmarkDisposition::Completed);
    assert!(completed.versioned().record().publication().is_some());
    assert_eq!(harness.publication.calls.load(Ordering::SeqCst), 2);

    let replay = harness
        .manager()
        .start("publication-restart", request)
        .expect("replay published verification");
    assert_eq!(replay.disposition(), BenchmarkDisposition::Replayed);
    assert_eq!(harness.publication.calls.load(Ordering::SeqCst), 2);
}

// Proves an explicitly local-only manager cannot complete a community verification.
#[test]
fn verification_without_publication_authority_fails_closed() {
    let harness = Harness::new();
    let manager = harness.manager_without_publication();
    let started = manager
        .start("missing-publication", verification_request())
        .expect("start verification");
    let job_id = started.versioned().record().job_id().clone();
    harness
        .execution
        .push(BenchmarkExecutionObservation::Terminal(
            BenchmarkExecutionOutcome::Succeeded {
                raw_evidence_sha256: digest('8'),
                results_sha256: digest('1'),
                record_schema: BenchmarkRecordSchema::CommunityVerificationV1,
            },
        ));

    assert_eq!(
        manager.poll(&job_id).expect_err("reject publication"),
        BenchmarkError::PublicationRejected
    );
    let interrupted = manager
        .record(&job_id)
        .expect("read interrupted publication")
        .expect("interrupted publication");
    assert_eq!(interrupted.record().phase(), BenchmarkJobPhase::Finalizing);
    assert!(interrupted.record().publication().is_none());
}

// Proves diagnostic selectors are local-only, unique, and request-identity material.
#[test]
fn scope_validation_rejects_verification_overrides_and_duplicate_cells() {
    let cells = vec![
        TechnicalName::parse("32k-code-c1").expect("cell"),
        TechnicalName::parse("64k-code-c1").expect("cell"),
    ];
    let selected = BenchmarkScope::selected(cells.clone()).expect("selected cells");
    let local = BenchmarkRequest::new(BenchmarkKind::Local, selected.clone(), subject("qwen"))
        .expect("local selected request");
    assert_ne!(
        local.sha256().expect("selected digest"),
        local_request().sha256().expect("full digest")
    );
    assert!(matches!(
        BenchmarkScope::selected(vec![cells[0].clone(), cells[0].clone()]),
        Err(BenchmarkError::InvalidContract { .. })
    ));
    assert!(matches!(
        BenchmarkRequest::new(
            verification_request().kind().clone(),
            selected,
            subject("qwen")
        ),
        Err(BenchmarkError::InvalidContract { .. })
    ));
}

// Proves denied authority creates no durable job or external preparation.
#[test]
fn authorization_denial_is_generic_and_precedes_persistence() {
    let harness = Harness::new();
    harness.authorization.deny();
    let error = harness
        .manager()
        .start("denied", local_request())
        .expect_err("denied benchmark");
    assert_eq!(error, BenchmarkError::AuthorizationDenied);
    assert_eq!(harness.store.record_count(), 0);
    assert_eq!(harness.events(), vec!["authorization"]);
}

// Proves one replay key is exact while a distinct active job excludes all other work.
#[test]
fn replay_conflict_and_global_active_ownership_fail_closed() {
    let harness = Harness::new();
    let manager = harness.manager();
    let started = manager
        .start("one", local_request())
        .expect("first benchmark");
    assert_eq!(started.disposition(), BenchmarkDisposition::Running);
    assert_eq!(
        manager
            .start("one", local_request())
            .expect("same replay")
            .disposition(),
        BenchmarkDisposition::Replayed
    );
    let different = BenchmarkRequest::new(
        BenchmarkKind::Local,
        BenchmarkScope::Complete,
        subject("other-model"),
    )
    .expect("different request");
    assert_eq!(
        manager
            .start("one", different)
            .expect_err("conflicting replay"),
        BenchmarkError::IdempotencyConflict
    );
    assert_eq!(
        manager
            .start("two", local_request())
            .expect_err("second active benchmark"),
        BenchmarkError::Busy
    );
}

// Proves pre-mutation failure becomes terminal without fake evidence or restoration.
#[test]
fn preparation_failure_records_a_bounded_terminal_failure_only() {
    let harness = Harness::new();
    harness.failures.fail("execution.prepare", 1);
    let failed = harness
        .manager()
        .start("prepare-failure", local_request())
        .expect("durable failed benchmark");
    let record = failed.versioned().record();
    assert_eq!(failed.disposition(), BenchmarkDisposition::Failed);
    assert_eq!(record.phase(), BenchmarkJobPhase::Failed);
    assert!(record.prepared().is_none());
    assert!(record.evidence().is_none());
    assert!(!harness.events().contains(&"execution.restore".to_string()));
}

// Proves every launch boundary after preparation restores and seals failure evidence.
#[test]
fn post_preparation_launch_failures_restore_and_seal() {
    for capability in ["telemetry.begin", "execution.start"] {
        let harness = Harness::new();
        harness.failures.fail(capability, 1);
        let failed = harness
            .manager()
            .start(capability, local_request())
            .expect("durable launch failure");
        let record = failed.versioned().record();
        assert_eq!(
            failed.disposition(),
            BenchmarkDisposition::Failed,
            "{capability}"
        );
        assert!(record.restoration().is_some(), "{capability}");
        assert!(record.evidence().is_some(), "{capability}");
        assert_eq!(
            record
                .outcome()
                .and_then(BenchmarkExecutionOutcome::failure)
                .expect("failure")
                .category(),
            BenchmarkFailureCategory::IncompleteWorkload,
            "{capability}"
        );
    }
}

// Proves a blocking worker failure is restored and retained without becoming a slow result.
#[test]
fn execution_failure_preserves_category_and_raw_evidence() {
    let harness = Harness::new();
    let (manager, job_id) = start_running(&harness, "protection");
    harness
        .execution
        .push(BenchmarkExecutionObservation::Terminal(
            BenchmarkExecutionOutcome::Failed {
                raw_evidence_sha256: Some(digest('9')),
                failure: failure(BenchmarkFailureCategory::ProtectionTrip),
            },
        ));
    let failed = manager.poll(&job_id).expect("complete failed benchmark");
    let outcome = failed.versioned().record().outcome().expect("outcome");
    assert_eq!(failed.disposition(), BenchmarkDisposition::Failed);
    assert_eq!(
        outcome.failure().expect("failure").category(),
        BenchmarkFailureCategory::ProtectionTrip
    );
    assert_eq!(outcome.raw_evidence_sha256(), Some(&digest('9')));
    assert!(failed.versioned().record().evidence().is_some());
}

// Proves required telemetry loss stops the exact worker and cannot yield successful evidence.
#[test]
fn telemetry_failure_requests_stop_and_overrides_worker_cancellation() {
    let harness = Harness::new();
    let (manager, job_id) = start_running(&harness, "telemetry-loss");
    harness.failures.fail("telemetry.capture", 1);
    harness
        .execution
        .push(BenchmarkExecutionObservation::Running(progress(1, 2)));
    let stopping = manager.poll(&job_id).expect("stop after telemetry failure");
    assert_eq!(stopping.disposition(), BenchmarkDisposition::Stopping);
    assert!(harness.events().contains(&"execution.stop".to_string()));

    harness
        .execution
        .push(BenchmarkExecutionObservation::Terminal(
            BenchmarkExecutionOutcome::Cancelled {
                raw_evidence_sha256: Some(digest('a')),
            },
        ));
    let failed = manager.poll(&job_id).expect("seal telemetry failure");
    assert_eq!(failed.disposition(), BenchmarkDisposition::Failed);
    assert_eq!(
        failed
            .versioned()
            .record()
            .outcome()
            .and_then(BenchmarkExecutionOutcome::failure)
            .expect("failure")
            .category(),
        BenchmarkFailureCategory::IncompleteWorkload
    );
}

// Proves explicit stop is durable, idempotent, and restores before cancellation becomes terminal.
#[test]
fn cancellation_waits_for_exact_worker_exit_and_restoration() {
    let harness = Harness::new();
    let (manager, job_id) = start_running(&harness, "cancel");
    let stopping = manager.stop(&job_id).expect("request stop");
    assert_eq!(stopping.disposition(), BenchmarkDisposition::Stopping);
    harness
        .execution
        .push(BenchmarkExecutionObservation::Running(progress(1, 3)));
    assert_eq!(
        manager.poll(&job_id).expect("still stopping").disposition(),
        BenchmarkDisposition::Stopping
    );
    harness
        .execution
        .push(BenchmarkExecutionObservation::Terminal(
            BenchmarkExecutionOutcome::Cancelled {
                raw_evidence_sha256: Some(digest('b')),
            },
        ));
    let cancelled = manager.poll(&job_id).expect("complete cancellation");
    assert_eq!(cancelled.disposition(), BenchmarkDisposition::Cancelled);
    assert!(cancelled.versioned().record().restoration().is_some());
    assert!(cancelled.versioned().record().evidence().is_some());
}

// Proves telemetry-close and resident-restoration failures survive restart and remain blocking.
#[test]
fn restoration_pipeline_failures_resume_and_finish_as_signed_failures() {
    for (capability, category) in [
        (
            "telemetry.finish",
            BenchmarkFailureCategory::IncompleteWorkload,
        ),
        ("execution.restore", BenchmarkFailureCategory::Restoration),
    ] {
        let harness = Harness::new();
        let (manager, job_id) = start_running(&harness, capability);
        harness.failures.fail(capability, 1);
        harness
            .execution
            .push(BenchmarkExecutionObservation::Terminal(
                BenchmarkExecutionOutcome::Succeeded {
                    raw_evidence_sha256: digest('c'),
                    results_sha256: digest('1'),
                    record_schema: BenchmarkRecordSchema::OciExecutionPayloadV7,
                },
            ));
        assert!(matches!(
            manager.poll(&job_id),
            Err(BenchmarkError::Provider { .. })
        ));
        let interrupted = manager
            .record(&job_id)
            .expect("read interrupted")
            .expect("interrupted record");
        assert_eq!(interrupted.record().phase(), BenchmarkJobPhase::Restoring);
        assert_eq!(
            interrupted
                .record()
                .outcome()
                .and_then(BenchmarkExecutionOutcome::failure)
                .expect("durable failure")
                .category(),
            category
        );

        let resumed = harness.manager().poll(&job_id).expect("resume restoration");
        assert_eq!(resumed.disposition(), BenchmarkDisposition::Failed);
        assert!(resumed.versioned().record().evidence().is_some());
    }
}

// Proves every finalization boundary remains retryable without rerunning inference.
#[test]
fn finalization_failures_remain_journaled_and_retry_idempotently() {
    for capability in [
        "evidence.finalize",
        "evidence.verify",
        "signing.sign",
        "signing.verify",
    ] {
        let harness = Harness::new();
        let (manager, job_id) = start_running(&harness, capability);
        harness.failures.fail(capability, 1);
        harness
            .execution
            .push(BenchmarkExecutionObservation::Terminal(
                BenchmarkExecutionOutcome::Succeeded {
                    raw_evidence_sha256: digest('d'),
                    results_sha256: digest('1'),
                    record_schema: BenchmarkRecordSchema::OciExecutionPayloadV7,
                },
            ));
        assert!(matches!(
            manager.poll(&job_id),
            Err(BenchmarkError::Provider { .. })
        ));
        assert_eq!(
            manager
                .record(&job_id)
                .expect("read finalizing")
                .expect("finalizing record")
                .record()
                .phase(),
            BenchmarkJobPhase::Finalizing,
            "{capability}"
        );
        assert_eq!(
            manager
                .poll(&job_id)
                .expect("retry finalization")
                .disposition(),
            BenchmarkDisposition::Completed,
            "{capability}"
        );
    }

    let harness = Harness::new();
    let (manager, job_id) = start_running(&harness, "signature-rejection");
    harness.signing.reject_once();
    harness
        .execution
        .push(BenchmarkExecutionObservation::Terminal(
            BenchmarkExecutionOutcome::Succeeded {
                raw_evidence_sha256: digest('e'),
                results_sha256: digest('1'),
                record_schema: BenchmarkRecordSchema::OciExecutionPayloadV7,
            },
        ));
    assert_eq!(
        manager.poll(&job_id).expect_err("reject signature"),
        BenchmarkError::SignatureRejected
    );
    assert_eq!(
        manager
            .poll(&job_id)
            .expect("retry signature")
            .disposition(),
        BenchmarkDisposition::Completed
    );
}

// Proves a lost prepared-to-running commit replays the same external start after restart.
#[test]
fn restart_replays_prepared_execution_after_store_failure() {
    let harness = Harness::new();
    harness.store.fail_replace_call(2);
    let manager = harness.manager();
    assert_eq!(
        manager
            .start("prepared-restart", local_request())
            .expect_err("lost running commit"),
        BenchmarkError::Store(BenchmarkStoreError::Unavailable)
    );
    assert_eq!(harness.execution.start_calls(), 1);
    let replay = harness
        .manager()
        .start("prepared-restart", local_request())
        .expect("resume prepared job");
    assert_eq!(replay.disposition(), BenchmarkDisposition::Running);
    assert_eq!(harness.execution.start_calls(), 2);
    assert_eq!(
        replay.versioned().record().phase(),
        BenchmarkJobPhase::Running
    );
}

// Proves corruption and backwards time fail before a new durable transition.
#[test]
fn persistence_corruption_and_backwards_clock_fail_closed() {
    let harness = Harness::new();
    let (manager, job_id) = start_running(&harness, "corruption");
    let updated_at = manager
        .record(&job_id)
        .expect("read record")
        .expect("record")
        .record()
        .updated_at()
        .value();
    harness.clock.set(updated_at - 1);
    harness
        .execution
        .push(BenchmarkExecutionObservation::Running(progress(1, 2)));
    assert!(matches!(
        manager.poll(&job_id),
        Err(BenchmarkError::InvalidContract { .. })
    ));
    harness.store.corrupt_reads();
    assert_eq!(
        manager.record(&job_id).expect_err("corrupt record"),
        BenchmarkError::Store(BenchmarkStoreError::Corrupt)
    );
}

// Proves two independent manager instances produce exactly one active benchmark winner.
#[test]
fn concurrent_create_has_one_global_active_winner() {
    let harness = Arc::new(Harness::new());
    harness.authorization.set_barrier(Arc::new(Barrier::new(2)));
    let mut handles = Vec::new();
    for key in ["concurrent-a", "concurrent-b"] {
        let harness = harness.clone();
        handles.push(thread::spawn(move || {
            harness.manager().start(key, local_request())
        }));
    }
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().expect("manager thread"))
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(BenchmarkError::Busy)))
            .count(),
        1
    );
    assert_eq!(harness.store.record_count(), 1);
}

// Rejects poll and stop immediately while the same manager instance owns benchmark mutation.
#[test]
fn same_manager_mutation_guard_rejects_competing_poll_and_stop() {
    struct BlockingAuthorization {
        entered: Arc<Barrier>,
        release: Arc<(Mutex<bool>, Condvar)>,
    }

    impl BenchmarkAuthorizationProvider for BlockingAuthorization {
        // Holds authorized start inside the manager mutation guard until explicitly released.
        fn authorize(
            &self,
            _job_id: &OperationId,
            _request: &BenchmarkRequest,
        ) -> Result<BenchmarkAuthorization, BenchmarkError> {
            self.entered.wait();
            let (lock, condition) = &*self.release;
            let mut released = lock.lock().expect("release");
            while !*released {
                released = condition.wait(released).expect("release wait");
            }
            Ok(BenchmarkAuthorization::new(digest('a')))
        }
    }

    let harness = Harness::new();
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let manager = Arc::new(BenchmarkManager::new_with_publication(
        harness.store.clone(),
        Arc::new(BlockingAuthorization {
            entered: entered.clone(),
            release: release.clone(),
        }),
        harness.execution.clone(),
        harness.telemetry.clone(),
        harness.evidence.clone(),
        harness.signing.clone(),
        harness.publication.clone(),
        harness.clock.clone(),
    ));
    let starting_manager = manager.clone();
    let starting = thread::spawn(move || starting_manager.start("guard-owner", local_request()));
    entered.wait();

    let competing_job = OperationId::parse(&"e".repeat(32)).expect("competing job");
    let poll = manager.poll(&competing_job);
    let stop = manager.stop(&competing_job);
    let persisted_while_held = harness.store.record_count();

    let (lock, condition) = &*release;
    *lock.lock().expect("release") = true;
    condition.notify_all();
    let started = starting.join().expect("starting thread");

    assert_eq!(poll, Err(BenchmarkError::Busy));
    assert_eq!(stop, Err(BenchmarkError::Busy));
    assert_eq!(persisted_while_held, 0);
    assert_eq!(
        started.expect("guard owner").disposition(),
        BenchmarkDisposition::Running
    );
    assert_eq!(harness.store.record_count(), 1);
}

// Proves persistence reconstruction rejects phase-field combinations that cannot exist.
#[test]
fn journal_reconstruction_rejects_semantic_corruption() {
    let harness = Harness::new();
    let manager = harness.manager();
    let started = manager
        .start("restore-shape", local_request())
        .expect("start benchmark");
    let record = started.versioned().record();
    let corrupted = BenchmarkJobRecord::restore(
        record.job_id().clone(),
        record.replay_sha256().clone(),
        record.request_sha256().clone(),
        record.request().clone(),
        record.authorization().clone(),
        BenchmarkJobPhase::Running,
        None,
        record.execution().cloned(),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        record.created_at(),
        record.updated_at(),
    );
    assert!(matches!(
        corrupted,
        Err(BenchmarkError::InvalidContract { .. })
    ));
}

// Proves evidence and signature value types enforce their native-boundary limits.
#[test]
fn evidence_and_signature_receipts_reject_unsafe_bounds() {
    assert!(matches!(
        BenchmarkEvidence::new(
            digest('1'),
            digest('2'),
            BenchmarkRecordSchema::NativeExecutionPayloadV8,
            0,
        ),
        Err(BenchmarkError::InvalidContract { .. })
    ));
    assert!(matches!(
        BenchmarkSignature::new(digest('3'), "signature with spaces"),
        Err(BenchmarkError::InvalidContract { .. })
    ));
}
