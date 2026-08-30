// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use li_core_interface::{OperationId, Sha256Digest, UnixMilliseconds};

use crate::li_benchmark_contract::{
    benchmark_job_id, replay_sha256, BenchmarkAuthorizationProvider, BenchmarkChange,
    BenchmarkClock, BenchmarkDisposition, BenchmarkEvidenceProvider, BenchmarkExecutionObservation,
    BenchmarkExecutionOutcome, BenchmarkExecutionProvider, BenchmarkFailureCategory,
    BenchmarkJobPhase, BenchmarkJobRecord, BenchmarkPublicationProvider,
    BenchmarkPublicationRequest, BenchmarkRequest, BenchmarkSigningProvider, BenchmarkStore,
    BenchmarkStoreError, BenchmarkTelemetryProvider, BenchmarkTerminalIntent,
    VersionedBenchmarkJob,
};
use crate::{benchmark_failure, BenchmarkError};

// Owns restart-safe benchmark phase ordering while providers own external mechanisms.
pub(crate) struct BenchmarkLifecycle {
    store: Arc<dyn BenchmarkStore>,
    authorization: Arc<dyn BenchmarkAuthorizationProvider>,
    execution: Arc<dyn BenchmarkExecutionProvider>,
    telemetry: Arc<dyn BenchmarkTelemetryProvider>,
    evidence: Arc<dyn BenchmarkEvidenceProvider>,
    signing: Arc<dyn BenchmarkSigningProvider>,
    publication: Arc<dyn BenchmarkPublicationProvider>,
    clock: Arc<dyn BenchmarkClock>,
}

impl BenchmarkLifecycle {
    // Creates one lifecycle from explicit persistence and external capabilities.
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        store: Arc<dyn BenchmarkStore>,
        authorization: Arc<dyn BenchmarkAuthorizationProvider>,
        execution: Arc<dyn BenchmarkExecutionProvider>,
        telemetry: Arc<dyn BenchmarkTelemetryProvider>,
        evidence: Arc<dyn BenchmarkEvidenceProvider>,
        signing: Arc<dyn BenchmarkSigningProvider>,
        publication: Arc<dyn BenchmarkPublicationProvider>,
        clock: Arc<dyn BenchmarkClock>,
    ) -> Self {
        Self {
            store,
            authorization,
            execution,
            telemetry,
            evidence,
            signing,
            publication,
            clock,
        }
    }

    // Starts a new admitted journal or resumes an interrupted pre-running phase.
    pub(crate) fn start(
        &self,
        idempotency_key: &str,
        request: BenchmarkRequest,
    ) -> Result<BenchmarkChange, BenchmarkError> {
        let (versioned, created) = self.open_record(idempotency_key, request)?;
        if !created
            && matches!(
                versioned.record().phase(),
                BenchmarkJobPhase::Running
                    | BenchmarkJobPhase::Stopping
                    | BenchmarkJobPhase::Completed
                    | BenchmarkJobPhase::Failed
                    | BenchmarkJobPhase::Cancelled
            )
        {
            return Ok(BenchmarkChange::new(
                versioned,
                BenchmarkDisposition::Replayed,
            ));
        }
        self.advance(versioned)
    }

    // Advances one existing job through a single live observation or all bounded cleanup phases.
    pub(crate) fn poll(&self, job_id: &OperationId) -> Result<BenchmarkChange, BenchmarkError> {
        let versioned = self.store.read(job_id)?.ok_or(BenchmarkError::NotFound)?;
        self.advance(versioned)
    }

    // Persists cancellation intent before signaling only the exact detached execution.
    pub(crate) fn stop(&self, job_id: &OperationId) -> Result<BenchmarkChange, BenchmarkError> {
        let versioned = self.store.read(job_id)?.ok_or(BenchmarkError::NotFound)?;
        match versioned.record().phase() {
            BenchmarkJobPhase::Requested => {
                let mut record = versioned.record().clone();
                record.outcome = Some(BenchmarkExecutionOutcome::Cancelled {
                    raw_evidence_sha256: None,
                });
                record.phase = BenchmarkJobPhase::Cancelled;
                let terminal = self.commit(record, versioned.revision())?;
                Ok(change(terminal))
            }
            BenchmarkJobPhase::Prepared => {
                let mut record = versioned.record().clone();
                record.outcome = Some(BenchmarkExecutionOutcome::Cancelled {
                    raw_evidence_sha256: None,
                });
                record.phase = BenchmarkJobPhase::Restoring;
                let restoring = self.commit(record, versioned.revision())?;
                self.advance(restoring)
            }
            BenchmarkJobPhase::Running => {
                let mut record = versioned.record().clone();
                record.terminal_intent = Some(BenchmarkTerminalIntent::Cancelled);
                record.phase = BenchmarkJobPhase::Stopping;
                let stopping = self.commit(record, versioned.revision())?;
                let running = stopping
                    .record()
                    .execution()
                    .ok_or(BenchmarkError::InvalidTransition)?;
                self.execution.request_stop(job_id, running)?;
                Ok(change(stopping))
            }
            BenchmarkJobPhase::Stopping => {
                let running = versioned
                    .record()
                    .execution()
                    .ok_or(BenchmarkError::InvalidTransition)?;
                self.execution.request_stop(job_id, running)?;
                Ok(change(versioned))
            }
            BenchmarkJobPhase::Completed
            | BenchmarkJobPhase::Failed
            | BenchmarkJobPhase::Cancelled => Ok(BenchmarkChange::new(
                versioned,
                BenchmarkDisposition::Replayed,
            )),
            BenchmarkJobPhase::Restoring | BenchmarkJobPhase::Finalizing => {
                Err(BenchmarkError::InvalidTransition)
            }
        }
    }

    // Returns one durable journal without invoking external mechanisms.
    pub(crate) fn record(
        &self,
        job_id: &OperationId,
    ) -> Result<Option<VersionedBenchmarkJob>, BenchmarkError> {
        self.store.read(job_id).map_err(Into::into)
    }

    // Returns the sole non-terminal benchmark without invoking any external provider.
    pub(crate) fn active(&self) -> Result<Option<VersionedBenchmarkJob>, BenchmarkError> {
        self.store.active().map_err(Into::into)
    }

    // Opens one matching replay or atomically creates the sole active journal.
    fn open_record(
        &self,
        idempotency_key: &str,
        request: BenchmarkRequest,
    ) -> Result<(VersionedBenchmarkJob, bool), BenchmarkError> {
        let replay = replay_sha256(idempotency_key)?;
        let request_digest = request.sha256()?;
        if let Some(versioned) = self.store.read_replay(&replay)? {
            require_same_request(versioned.record(), &request_digest)?;
            return Ok((versioned, false));
        }
        if self.store.active()?.is_some() {
            return Err(BenchmarkError::Busy);
        }
        let job_id = benchmark_job_id(&replay)?;
        let authorization = self.authorization.authorize(&job_id, &request)?;
        let now = self.now()?;
        let requested = BenchmarkJobRecord::requested(replay.clone(), request, authorization, now)?;
        match self.store.create(requested) {
            Ok(versioned) => Ok((versioned, true)),
            Err(BenchmarkStoreError::Conflict) => {
                if let Some(versioned) = self.store.read_replay(&replay)? {
                    require_same_request(versioned.record(), &request_digest)?;
                    return Ok((versioned, false));
                }
                if self.store.active()?.is_some() {
                    return Err(BenchmarkError::Busy);
                }
                Err(BenchmarkStoreError::Conflict.into())
            }
            Err(error) => Err(error.into()),
        }
    }

    // Drives non-running phases linearly and returns after one live worker observation.
    fn advance(
        &self,
        mut versioned: VersionedBenchmarkJob,
    ) -> Result<BenchmarkChange, BenchmarkError> {
        loop {
            versioned = match versioned.record().phase() {
                BenchmarkJobPhase::Requested => self.prepare(versioned)?,
                BenchmarkJobPhase::Prepared => {
                    let launched = self.launch(versioned)?;
                    if launched.record().phase() == BenchmarkJobPhase::Running {
                        return Ok(change(launched));
                    }
                    launched
                }
                BenchmarkJobPhase::Running => return self.observe_running(versioned),
                BenchmarkJobPhase::Stopping => return self.observe_stopping(versioned),
                BenchmarkJobPhase::Restoring => self.restore(versioned)?,
                BenchmarkJobPhase::Finalizing => return self.finalize(versioned),
                BenchmarkJobPhase::Completed
                | BenchmarkJobPhase::Failed
                | BenchmarkJobPhase::Cancelled => return Ok(change(versioned)),
            };
        }
    }

    // Verifies exact inputs and journals the provider-owned restoration receipt.
    fn prepare(
        &self,
        versioned: VersionedBenchmarkJob,
    ) -> Result<VersionedBenchmarkJob, BenchmarkError> {
        let mut record = versioned.record().clone();
        let prepared =
            match self
                .execution
                .prepare(record.job_id(), record.request(), record.authorization())
            {
                Ok(prepared) => prepared,
                Err(error) => return self.fail_before_preparation(versioned, error),
            };
        record.prepared = Some(prepared);
        record.phase = BenchmarkJobPhase::Prepared;
        self.commit(record, versioned.revision())
    }

    // Opens telemetry and starts one detached execution from the exact prepared receipt.
    fn launch(
        &self,
        versioned: VersionedBenchmarkJob,
    ) -> Result<VersionedBenchmarkJob, BenchmarkError> {
        let mut record = versioned.record().clone();
        let prepared = record
            .prepared()
            .ok_or(BenchmarkError::InvalidTransition)?
            .clone();
        if let Err(error) = self
            .telemetry
            .begin(record.job_id(), record.request(), &prepared)
        {
            return self.begin_restoration(versioned, error, "telemetry.begin");
        }
        let running = match self
            .execution
            .start(record.job_id(), record.request(), &prepared)
        {
            Ok(running) => running,
            Err(error) => return self.begin_restoration(versioned, error, "execution.start"),
        };
        record.execution = Some(running);
        record.phase = BenchmarkJobPhase::Running;
        self.commit(record, versioned.revision())
    }

    // Captures one active progress point or begins cleanup for one terminal worker result.
    fn observe_running(
        &self,
        versioned: VersionedBenchmarkJob,
    ) -> Result<BenchmarkChange, BenchmarkError> {
        let record = versioned.record();
        let running = record
            .execution()
            .ok_or(BenchmarkError::InvalidTransition)?;
        match self.execution.observe(record.job_id(), running)? {
            BenchmarkExecutionObservation::Running(progress) => {
                if let Err(error) = self.telemetry.capture(record.job_id(), &progress) {
                    return self.stop_after_failure(versioned, error, "telemetry.capture");
                }
                let mut updated = record.clone();
                updated.progress = Some(progress);
                let running = self.commit(updated, versioned.revision())?;
                Ok(change(running))
            }
            BenchmarkExecutionObservation::Terminal(outcome) => {
                let mut restoring = record.clone();
                restoring.outcome = Some(outcome);
                restoring.phase = BenchmarkJobPhase::Restoring;
                let restoring = self.commit(restoring, versioned.revision())?;
                self.advance(restoring)
            }
        }
    }

    // Reissues a durable stop and waits for the exact worker to report a terminal result.
    fn observe_stopping(
        &self,
        versioned: VersionedBenchmarkJob,
    ) -> Result<BenchmarkChange, BenchmarkError> {
        let record = versioned.record();
        let running = record
            .execution()
            .ok_or(BenchmarkError::InvalidTransition)?;
        self.execution.request_stop(record.job_id(), running)?;
        match self.execution.observe(record.job_id(), running)? {
            BenchmarkExecutionObservation::Running(progress) => {
                let _ = self.telemetry.capture(record.job_id(), &progress);
                let mut updated = record.clone();
                updated.progress = Some(progress);
                let stopping = self.commit(updated, versioned.revision())?;
                Ok(change(stopping))
            }
            BenchmarkExecutionObservation::Terminal(observed) => {
                let intent = record
                    .terminal_intent
                    .as_ref()
                    .ok_or(BenchmarkError::InvalidTransition)?;
                let outcome = terminal_intent_outcome(intent, &observed);
                let mut restoring = record.clone();
                restoring.terminal_intent = None;
                restoring.outcome = Some(outcome);
                restoring.phase = BenchmarkJobPhase::Restoring;
                let restoring = self.commit(restoring, versioned.revision())?;
                self.advance(restoring)
            }
        }
    }

    // Closes telemetry and restores exact resident intent before evidence can become terminal.
    fn restore(
        &self,
        versioned: VersionedBenchmarkJob,
    ) -> Result<VersionedBenchmarkJob, BenchmarkError> {
        let record = versioned.record();
        let prepared = record.prepared().ok_or(BenchmarkError::InvalidTransition)?;
        let outcome = record.outcome().ok_or(BenchmarkError::InvalidTransition)?;
        let telemetry = match self.telemetry.finish(record.job_id(), outcome) {
            Ok(telemetry) => telemetry,
            Err(error) => {
                self.remember_restoration_failure(
                    &versioned,
                    &error,
                    BenchmarkFailureCategory::IncompleteWorkload,
                    "telemetry.finish",
                )?;
                return Err(error);
            }
        };
        let restoration = match self.execution.restore(
            record.job_id(),
            record.request(),
            prepared,
            record.execution(),
            outcome,
        ) {
            Ok(restoration) => restoration,
            Err(error) => {
                self.remember_restoration_failure(
                    &versioned,
                    &error,
                    BenchmarkFailureCategory::Restoration,
                    "restoration",
                )?;
                return Err(error);
            }
        };
        let mut finalizing = record.clone();
        finalizing.telemetry = Some(telemetry);
        finalizing.restoration = Some(restoration);
        finalizing.phase = BenchmarkJobPhase::Finalizing;
        self.commit(finalizing, versioned.revision())
    }

    // Materializes, validates, signs, verifies, and journals one immutable terminal record.
    fn finalize(
        &self,
        versioned: VersionedBenchmarkJob,
    ) -> Result<BenchmarkChange, BenchmarkError> {
        let record = versioned.record();
        let outcome = record.outcome().ok_or(BenchmarkError::InvalidTransition)?;
        let telemetry = record
            .telemetry()
            .ok_or(BenchmarkError::InvalidTransition)?;
        let restoration = record
            .restoration()
            .ok_or(BenchmarkError::InvalidTransition)?;
        let evidence = self.evidence.finalize(
            record.job_id(),
            record.request(),
            outcome,
            telemetry,
            restoration,
        )?;
        self.evidence.verify(record.request(), outcome, &evidence)?;
        let signature = self.signing.sign(record.job_id(), &evidence)?;
        if !self.signing.verify(&evidence, &signature)? {
            return Err(BenchmarkError::SignatureRejected);
        }
        let sealed = crate::SealedBenchmarkEvidence::new(evidence, signature);
        let publication_request = BenchmarkPublicationRequest::new(
            record.job_id(),
            record.request(),
            outcome,
            restoration,
            &sealed,
        );
        let publication = self.publication.publish(&publication_request)?;
        let expects_publication =
            sealed.evidence().schema() == crate::BenchmarkRecordSchema::CommunityVerificationV1;
        if publication.is_some() != expects_publication
            || publication
                .as_ref()
                .is_some_and(|receipt| !receipt.matches(&publication_request))
        {
            return Err(BenchmarkError::PublicationRejected);
        }
        let mut terminal = record.clone();
        terminal.evidence = Some(sealed);
        terminal.publication = publication;
        terminal.phase = terminal_phase(outcome);
        let terminal = self.commit(terminal, versioned.revision())?;
        Ok(change(terminal))
    }

    // Records one pre-mutation failure as terminal without fabricating benchmark evidence.
    fn fail_before_preparation(
        &self,
        versioned: VersionedBenchmarkJob,
        error: BenchmarkError,
    ) -> Result<VersionedBenchmarkJob, BenchmarkError> {
        let failure = benchmark_failure(
            BenchmarkFailureCategory::IncompleteWorkload,
            "preparation",
            &error,
        )?;
        let mut record = versioned.record().clone();
        record.outcome = Some(BenchmarkExecutionOutcome::Failed {
            raw_evidence_sha256: None,
            failure,
        });
        record.phase = BenchmarkJobPhase::Failed;
        self.commit(record, versioned.revision())
    }

    // Converts a post-preparation launch failure into mandatory restoration work.
    fn begin_restoration(
        &self,
        versioned: VersionedBenchmarkJob,
        error: BenchmarkError,
        phase: &'static str,
    ) -> Result<VersionedBenchmarkJob, BenchmarkError> {
        let failure =
            benchmark_failure(BenchmarkFailureCategory::IncompleteWorkload, phase, &error)?;
        let mut record = versioned.record().clone();
        record.outcome = Some(BenchmarkExecutionOutcome::Failed {
            raw_evidence_sha256: None,
            failure,
        });
        record.phase = BenchmarkJobPhase::Restoring;
        self.commit(record, versioned.revision())
    }

    // Persists telemetry failure before requesting termination of the exact worker.
    fn stop_after_failure(
        &self,
        versioned: VersionedBenchmarkJob,
        error: BenchmarkError,
        phase: &'static str,
    ) -> Result<BenchmarkChange, BenchmarkError> {
        let failure =
            benchmark_failure(BenchmarkFailureCategory::IncompleteWorkload, phase, &error)?;
        let mut record = versioned.record().clone();
        record.terminal_intent = Some(BenchmarkTerminalIntent::Failed(failure));
        record.phase = BenchmarkJobPhase::Stopping;
        let stopping = self.commit(record, versioned.revision())?;
        let running = stopping
            .record()
            .execution()
            .ok_or(BenchmarkError::InvalidTransition)?;
        self.execution
            .request_stop(stopping.record().job_id(), running)?;
        Ok(change(stopping))
    }

    // Makes a restoration-boundary failure durable while keeping cleanup retryable.
    fn remember_restoration_failure(
        &self,
        versioned: &VersionedBenchmarkJob,
        error: &BenchmarkError,
        category: BenchmarkFailureCategory,
        phase: &'static str,
    ) -> Result<(), BenchmarkError> {
        let failure = benchmark_failure(category, phase, error)?;
        let raw_evidence_sha256 = versioned
            .record()
            .outcome()
            .and_then(BenchmarkExecutionOutcome::raw_evidence_sha256)
            .cloned();
        let mut record = versioned.record().clone();
        record.outcome = Some(BenchmarkExecutionOutcome::Failed {
            raw_evidence_sha256,
            failure,
        });
        self.commit(record, versioned.revision()).map(|_| ())
    }

    // Atomically replaces one exact journal revision with nondecreasing wall time.
    fn commit(
        &self,
        mut record: BenchmarkJobRecord,
        expected_revision: u64,
    ) -> Result<VersionedBenchmarkJob, BenchmarkError> {
        let now = self.now()?;
        if now < record.updated_at() {
            return Err(BenchmarkError::InvalidContract {
                reason: "benchmark clock moved backwards",
            });
        }
        record.updated_at = now;
        self.store
            .replace(record, expected_revision)
            .map_err(Into::into)
    }

    // Returns one positive clock value suitable for durable state.
    fn now(&self) -> Result<UnixMilliseconds, BenchmarkError> {
        let now = self.clock.now()?;
        if now.value() == 0 {
            return Err(BenchmarkError::InvalidContract {
                reason: "benchmark clock returned zero",
            });
        }
        Ok(now)
    }
}

// Requires one replay identity to retain the exact original request fingerprint.
fn require_same_request(
    record: &BenchmarkJobRecord,
    request_sha256: &Sha256Digest,
) -> Result<(), BenchmarkError> {
    if record.request_sha256() != request_sha256 {
        return Err(BenchmarkError::IdempotencyConflict);
    }
    Ok(())
}

// Converts requested cancellation or failure into one exact observed terminal outcome.
fn terminal_intent_outcome(
    intent: &BenchmarkTerminalIntent,
    observed: &BenchmarkExecutionOutcome,
) -> BenchmarkExecutionOutcome {
    let raw_evidence_sha256 = observed.raw_evidence_sha256().cloned();
    match intent {
        BenchmarkTerminalIntent::Cancelled => BenchmarkExecutionOutcome::Cancelled {
            raw_evidence_sha256,
        },
        BenchmarkTerminalIntent::Failed(failure) => BenchmarkExecutionOutcome::Failed {
            raw_evidence_sha256,
            failure: failure.clone(),
        },
    }
}

// Maps one observed outcome to its final durable phase after sealing.
fn terminal_phase(outcome: &BenchmarkExecutionOutcome) -> BenchmarkJobPhase {
    match outcome {
        BenchmarkExecutionOutcome::Succeeded { .. } => BenchmarkJobPhase::Completed,
        BenchmarkExecutionOutcome::Failed { .. } => BenchmarkJobPhase::Failed,
        BenchmarkExecutionOutcome::Cancelled { .. } => BenchmarkJobPhase::Cancelled,
    }
}

// Creates one caller-visible disposition from the exact persisted phase.
fn change(versioned: VersionedBenchmarkJob) -> BenchmarkChange {
    let disposition = match versioned.record().phase() {
        BenchmarkJobPhase::Requested | BenchmarkJobPhase::Prepared => BenchmarkDisposition::Started,
        BenchmarkJobPhase::Running
        | BenchmarkJobPhase::Restoring
        | BenchmarkJobPhase::Finalizing => BenchmarkDisposition::Running,
        BenchmarkJobPhase::Stopping => BenchmarkDisposition::Stopping,
        BenchmarkJobPhase::Completed => BenchmarkDisposition::Completed,
        BenchmarkJobPhase::Failed => BenchmarkDisposition::Failed,
        BenchmarkJobPhase::Cancelled => BenchmarkDisposition::Cancelled,
    };
    BenchmarkChange::new(versioned, disposition)
}
