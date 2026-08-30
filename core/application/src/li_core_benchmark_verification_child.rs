// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use li_benchmark_manager::{
    BenchmarkAuthorizationProvider, BenchmarkError, BenchmarkEvidenceProvider,
    BenchmarkExecutionObservation, BenchmarkExecutionProvider, BenchmarkRequest,
    BenchmarkRunPlanProvider, BenchmarkSigningProvider, BenchmarkTelemetryProvider,
    BenchmarkVerificationArm, BenchmarkVerificationChildObservation,
    BenchmarkVerificationChildProvider, BenchmarkVerificationChildResult,
    BenchmarkVerificationStore, PreparedBenchmark, RunningBenchmark, SealedBenchmarkEvidence,
};
use li_core_interface::OperationId;
use sha2::{Digest, Sha256};

// Runs each paired arm through the same ordinary benchmark provider contracts as local jobs.
pub struct ApplicationCoreBenchmarkVerificationChildProvider {
    authorization: Arc<dyn BenchmarkAuthorizationProvider>,
    plans: Arc<dyn BenchmarkRunPlanProvider>,
    execution: Arc<dyn BenchmarkExecutionProvider>,
    telemetry: Arc<dyn BenchmarkTelemetryProvider>,
    evidence: Arc<dyn BenchmarkEvidenceProvider>,
    signing: Arc<dyn BenchmarkSigningProvider>,
}

// Routes local jobs to the ordinary scheduler and verification jobs to the paired parent provider.
pub struct ApplicationCoreBenchmarkExecutionRouter {
    local: Arc<dyn BenchmarkExecutionProvider>,
    verification: Arc<dyn BenchmarkExecutionProvider>,
    verification_store: Arc<dyn BenchmarkVerificationStore>,
}

impl ApplicationCoreBenchmarkExecutionRouter {
    // Creates one router from exact already-composed providers and the parent durable store.
    pub const fn new(
        local: Arc<dyn BenchmarkExecutionProvider>,
        verification: Arc<dyn BenchmarkExecutionProvider>,
        verification_store: Arc<dyn BenchmarkVerificationStore>,
    ) -> Self {
        Self {
            local,
            verification,
            verification_store,
        }
    }

    // Returns whether one outer job owns a durable paired transaction.
    fn is_verification(&self, job_id: &OperationId) -> Result<bool, BenchmarkError> {
        self.verification_store
            .read(job_id)
            .map(|value| value.is_some())
            .map_err(Into::into)
    }
}

impl BenchmarkExecutionProvider for ApplicationCoreBenchmarkExecutionRouter {
    // Routes preparation from the immutable request kind.
    fn prepare(
        &self,
        job_id: &OperationId,
        request: &BenchmarkRequest,
        authorization: &li_benchmark_manager::BenchmarkAuthorization,
    ) -> Result<PreparedBenchmark, BenchmarkError> {
        if request.kind().is_verification() {
            self.verification.prepare(job_id, request, authorization)
        } else {
            self.local.prepare(job_id, request, authorization)
        }
    }

    // Routes launch from the immutable request kind.
    fn start(
        &self,
        job_id: &OperationId,
        request: &BenchmarkRequest,
        prepared: &PreparedBenchmark,
    ) -> Result<RunningBenchmark, BenchmarkError> {
        if request.kind().is_verification() {
            self.verification.start(job_id, request, prepared)
        } else {
            self.local.start(job_id, request, prepared)
        }
    }

    // Routes observations through durable parent existence after restart.
    fn observe(
        &self,
        job_id: &OperationId,
        running: &RunningBenchmark,
    ) -> Result<BenchmarkExecutionObservation, BenchmarkError> {
        if self.is_verification(job_id)? {
            self.verification.observe(job_id, running)
        } else {
            self.local.observe(job_id, running)
        }
    }

    // Routes cancellation through durable parent existence after restart.
    fn request_stop(
        &self,
        job_id: &OperationId,
        running: &RunningBenchmark,
    ) -> Result<(), BenchmarkError> {
        if self.is_verification(job_id)? {
            self.verification.request_stop(job_id, running)
        } else {
            self.local.request_stop(job_id, running)
        }
    }

    // Routes restoration from the immutable request kind.
    fn restore(
        &self,
        job_id: &OperationId,
        request: &BenchmarkRequest,
        prepared: &PreparedBenchmark,
        running: Option<&RunningBenchmark>,
        outcome: &li_benchmark_manager::BenchmarkExecutionOutcome,
    ) -> Result<li_benchmark_manager::BenchmarkRestoration, BenchmarkError> {
        if request.kind().is_verification() {
            self.verification
                .restore(job_id, request, prepared, running, outcome)
        } else {
            self.local
                .restore(job_id, request, prepared, running, outcome)
        }
    }
}

impl ApplicationCoreBenchmarkVerificationChildProvider {
    // Creates one child adapter without discovering or replacing any BenchmarkManager provider.
    pub const fn new(
        authorization: Arc<dyn BenchmarkAuthorizationProvider>,
        plans: Arc<dyn BenchmarkRunPlanProvider>,
        execution: Arc<dyn BenchmarkExecutionProvider>,
        telemetry: Arc<dyn BenchmarkTelemetryProvider>,
        evidence: Arc<dyn BenchmarkEvidenceProvider>,
        signing: Arc<dyn BenchmarkSigningProvider>,
    ) -> Self {
        Self {
            authorization,
            plans,
            execution,
            telemetry,
            evidence,
            signing,
        }
    }

    // Derives one stable child operation identity from the outer job and arm.
    fn child_job_id(
        job_id: &OperationId,
        arm: BenchmarkVerificationArm,
    ) -> Result<OperationId, BenchmarkError> {
        let mut digest = Sha256::new();
        digest.update(b"li-core-benchmark-verification-child-v1");
        digest.update(job_id.as_str().as_bytes());
        digest.update(arm.as_str().as_bytes());
        let value = format!("{:x}", digest.finalize());
        OperationId::parse(&value[..32]).map_err(|_| BenchmarkError::InvalidContract {
            reason: "verification child job identity could not be derived",
        })
    }
}

impl BenchmarkVerificationChildProvider for ApplicationCoreBenchmarkVerificationChildProvider {
    // Authorizes and prepares one exact ordinary child through the existing execution provider.
    fn prepare(
        &self,
        job_id: &OperationId,
        arm: BenchmarkVerificationArm,
        request: &BenchmarkRequest,
    ) -> Result<PreparedBenchmark, BenchmarkError> {
        let child_job_id = Self::child_job_id(job_id, arm)?;
        let authorization = self.authorization.authorize(&child_job_id, request)?;
        self.execution
            .prepare(&child_job_id, request, &authorization)
    }

    // Opens child telemetry and starts or reattaches to the exact detached task.
    fn start(
        &self,
        job_id: &OperationId,
        arm: BenchmarkVerificationArm,
        request: &BenchmarkRequest,
        prepared: &PreparedBenchmark,
    ) -> Result<RunningBenchmark, BenchmarkError> {
        let child_job_id = Self::child_job_id(job_id, arm)?;
        self.telemetry.begin(&child_job_id, request, prepared)?;
        self.execution.start(&child_job_id, request, prepared)
    }

    // Advances one task or seals its telemetry, restoration, evidence, and signature idempotently.
    fn observe(
        &self,
        job_id: &OperationId,
        arm: BenchmarkVerificationArm,
        request: &BenchmarkRequest,
        prepared: &PreparedBenchmark,
        running: &RunningBenchmark,
    ) -> Result<BenchmarkVerificationChildObservation, BenchmarkError> {
        let child_job_id = Self::child_job_id(job_id, arm)?;
        match self.execution.observe(&child_job_id, running)? {
            BenchmarkExecutionObservation::Running(progress) => {
                self.telemetry.capture(&child_job_id, &progress)?;
                Ok(BenchmarkVerificationChildObservation::Running(progress))
            }
            BenchmarkExecutionObservation::Terminal(outcome) => {
                let telemetry = self.telemetry.finish(&child_job_id, &outcome)?;
                let restoration = self.execution.restore(
                    &child_job_id,
                    request,
                    prepared,
                    Some(running),
                    &outcome,
                )?;
                let evidence = self.evidence.finalize(
                    &child_job_id,
                    request,
                    &outcome,
                    &telemetry,
                    &restoration,
                )?;
                self.evidence.verify(request, &outcome, &evidence)?;
                let signature = self.signing.sign(&child_job_id, &evidence)?;
                if !self.signing.verify(&evidence, &signature)? {
                    return Err(BenchmarkError::SignatureRejected);
                }
                let plan = self.plans.plan(&child_job_id, request)?;
                BenchmarkVerificationChildResult::new(
                    outcome,
                    telemetry,
                    restoration,
                    SealedBenchmarkEvidence::new(evidence, signature),
                    plan.total_cells(),
                )
                .map(BenchmarkVerificationChildObservation::Terminal)
            }
        }
    }

    // Requests cancellation of only the exact active child.
    fn request_stop(
        &self,
        job_id: &OperationId,
        arm: BenchmarkVerificationArm,
        running: &RunningBenchmark,
    ) -> Result<(), BenchmarkError> {
        self.execution
            .request_stop(&Self::child_job_id(job_id, arm)?, running)
    }

    // Performs no second cleanup because execution restoration already owns task/isolation cleanup.
    fn cleanup(
        &self,
        _job_id: &OperationId,
        _arm: BenchmarkVerificationArm,
    ) -> Result<(), BenchmarkError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use li_benchmark_manager::{
        BenchmarkAuthorization, BenchmarkEvidence, BenchmarkExecutionOutcome, BenchmarkFailure,
        BenchmarkFailureCategory, BenchmarkProgress, BenchmarkRecordSchema, BenchmarkRestoration,
        BenchmarkRunPlan, BenchmarkScope, BenchmarkSignature, BenchmarkSubject,
        BenchmarkTelemetryReceipt,
    };
    use li_core_interface::{
        InstallationId, LogicalModelName, PlacementGroupId, RuntimeInstallationId, Sha256Digest,
        TechnicalName,
    };

    use super::*;

    // Returns one exact lowercase digest fixture.
    fn digest(character: char) -> Sha256Digest {
        Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
    }

    // Returns one complete local child request.
    fn request() -> BenchmarkRequest {
        BenchmarkRequest::new(
            li_benchmark_manager::BenchmarkKind::Local,
            BenchmarkScope::Complete,
            BenchmarkSubject::new(
                InstallationId::parse(&"1".repeat(64)).expect("installation"),
                RuntimeInstallationId::parse(&"2".repeat(32)).expect("runtime"),
                LogicalModelName::parse("model").expect("model"),
                PlacementGroupId::parse(&"3".repeat(32)).expect("group"),
                digest('4'),
                digest('5'),
                digest('6'),
            ),
        )
        .expect("request")
    }

    struct AuthorizationMock;

    impl BenchmarkAuthorizationProvider for AuthorizationMock {
        // Returns one exact child authorization receipt.
        fn authorize(
            &self,
            _job_id: &OperationId,
            _request: &BenchmarkRequest,
        ) -> Result<BenchmarkAuthorization, BenchmarkError> {
            Ok(BenchmarkAuthorization::new(digest('7')))
        }
    }

    struct PlanMock;

    impl BenchmarkRunPlanProvider for PlanMock {
        // Returns one deterministic two-cell plan.
        fn plan(
            &self,
            _job_id: &OperationId,
            request: &BenchmarkRequest,
        ) -> Result<BenchmarkRunPlan, BenchmarkError> {
            BenchmarkRunPlan::new(
                request,
                BenchmarkRecordSchema::OciExecutionPayloadV7,
                2,
                10_000,
                1_000,
                1_000,
            )
        }
    }

    struct ExecutionMock {
        observation: Mutex<Option<BenchmarkExecutionObservation>>,
        restore_failure: bool,
        stops: Mutex<Vec<OperationId>>,
    }

    impl BenchmarkExecutionProvider for ExecutionMock {
        // Returns one exact child preparation receipt.
        fn prepare(
            &self,
            _job_id: &OperationId,
            _request: &BenchmarkRequest,
            _authorization: &BenchmarkAuthorization,
        ) -> Result<PreparedBenchmark, BenchmarkError> {
            Ok(PreparedBenchmark::new(digest('8')))
        }

        // Returns one exact child running receipt.
        fn start(
            &self,
            _job_id: &OperationId,
            _request: &BenchmarkRequest,
            _prepared: &PreparedBenchmark,
        ) -> Result<RunningBenchmark, BenchmarkError> {
            Ok(RunningBenchmark::new(digest('9')))
        }

        // Returns one injected task observation.
        fn observe(
            &self,
            _job_id: &OperationId,
            _running: &RunningBenchmark,
        ) -> Result<BenchmarkExecutionObservation, BenchmarkError> {
            self.observation
                .lock()
                .expect("observation")
                .take()
                .ok_or_else(|| BenchmarkError::provider("execution", "observation unavailable"))
        }

        // Records one exact child stop request.
        fn request_stop(
            &self,
            job_id: &OperationId,
            _running: &RunningBenchmark,
        ) -> Result<(), BenchmarkError> {
            self.stops.lock().expect("stops").push(job_id.clone());
            Ok(())
        }

        // Returns restoration or one injected restoration failure.
        fn restore(
            &self,
            _job_id: &OperationId,
            _request: &BenchmarkRequest,
            _prepared: &PreparedBenchmark,
            _running: Option<&RunningBenchmark>,
            _outcome: &BenchmarkExecutionOutcome,
        ) -> Result<BenchmarkRestoration, BenchmarkError> {
            if self.restore_failure {
                return Err(BenchmarkError::provider("execution", "restore failed"));
            }
            Ok(BenchmarkRestoration::new(digest('a')))
        }
    }

    struct TelemetryMock {
        captures: Mutex<u64>,
    }

    impl BenchmarkTelemetryProvider for TelemetryMock {
        // Accepts one exact child telemetry open.
        fn begin(
            &self,
            _job_id: &OperationId,
            _request: &BenchmarkRequest,
            _prepared: &PreparedBenchmark,
        ) -> Result<(), BenchmarkError> {
            Ok(())
        }

        // Records one active progress capture.
        fn capture(
            &self,
            _job_id: &OperationId,
            _progress: &BenchmarkProgress,
        ) -> Result<(), BenchmarkError> {
            *self.captures.lock().expect("captures") += 1;
            Ok(())
        }

        // Returns one exact terminal telemetry receipt.
        fn finish(
            &self,
            _job_id: &OperationId,
            _outcome: &BenchmarkExecutionOutcome,
        ) -> Result<BenchmarkTelemetryReceipt, BenchmarkError> {
            Ok(BenchmarkTelemetryReceipt::new(digest('b'), 2))
        }
    }

    struct EvidenceMock;

    impl BenchmarkEvidenceProvider for EvidenceMock {
        // Returns evidence matching one successful or failed child outcome.
        fn finalize(
            &self,
            _job_id: &OperationId,
            _request: &BenchmarkRequest,
            outcome: &BenchmarkExecutionOutcome,
            _telemetry: &BenchmarkTelemetryReceipt,
            _restoration: &BenchmarkRestoration,
        ) -> Result<BenchmarkEvidence, BenchmarkError> {
            match outcome {
                BenchmarkExecutionOutcome::Succeeded {
                    results_sha256,
                    record_schema,
                    ..
                } => {
                    BenchmarkEvidence::new(digest('c'), results_sha256.clone(), *record_schema, 100)
                }
                BenchmarkExecutionOutcome::Failed { .. }
                | BenchmarkExecutionOutcome::Cancelled { .. } => BenchmarkEvidence::new(
                    digest('c'),
                    digest('d'),
                    BenchmarkRecordSchema::CoreLocalFailureV1,
                    100,
                ),
            }
        }

        // Accepts only the deterministic evidence fixture.
        fn verify(
            &self,
            _request: &BenchmarkRequest,
            _outcome: &BenchmarkExecutionOutcome,
            evidence: &BenchmarkEvidence,
        ) -> Result<(), BenchmarkError> {
            if evidence.evidence_id() != &digest('c') {
                return Err(BenchmarkError::EvidenceRejected);
            }
            Ok(())
        }
    }

    struct SigningMock(bool);

    impl BenchmarkSigningProvider for SigningMock {
        // Returns one exact URL-safe child evidence signature.
        fn sign(
            &self,
            _job_id: &OperationId,
            _evidence: &BenchmarkEvidence,
        ) -> Result<BenchmarkSignature, BenchmarkError> {
            BenchmarkSignature::new(digest('e'), "c2lnbmF0dXJl")
        }

        // Returns the injected independent signature judgment.
        fn verify(
            &self,
            _evidence: &BenchmarkEvidence,
            _signature: &BenchmarkSignature,
        ) -> Result<bool, BenchmarkError> {
            Ok(self.0)
        }
    }

    // Creates one child adapter and exposes its execution/telemetry observations.
    fn provider(
        observation: BenchmarkExecutionObservation,
        restore_failure: bool,
        signature_valid: bool,
    ) -> (
        Arc<ExecutionMock>,
        Arc<TelemetryMock>,
        ApplicationCoreBenchmarkVerificationChildProvider,
    ) {
        let execution = Arc::new(ExecutionMock {
            observation: Mutex::new(Some(observation)),
            restore_failure,
            stops: Mutex::new(Vec::new()),
        });
        let telemetry = Arc::new(TelemetryMock {
            captures: Mutex::new(0),
        });
        (
            execution.clone(),
            telemetry.clone(),
            ApplicationCoreBenchmarkVerificationChildProvider::new(
                Arc::new(AuthorizationMock),
                Arc::new(PlanMock),
                execution,
                telemetry,
                Arc::new(EvidenceMock),
                Arc::new(SigningMock(signature_valid)),
            ),
        )
    }

    // Returns one exact successful terminal outcome.
    fn success() -> BenchmarkExecutionOutcome {
        BenchmarkExecutionOutcome::Succeeded {
            raw_evidence_sha256: digest('f'),
            results_sha256: digest('1'),
            record_schema: BenchmarkRecordSchema::OciExecutionPayloadV7,
        }
    }

    #[test]
    // Seals telemetry, restoration, evidence, signature, and plan identity after terminal success.
    fn child_provider_seals_one_complete_terminal_arm() {
        let (_execution, _telemetry, provider) = provider(
            BenchmarkExecutionObservation::Terminal(success()),
            false,
            true,
        );
        let job = OperationId::parse(&"1".repeat(32)).expect("job");
        let request = request();
        let prepared = provider
            .prepare(&job, BenchmarkVerificationArm::Baseline, &request)
            .expect("prepare");
        let running = provider
            .start(
                &job,
                BenchmarkVerificationArm::Baseline,
                &request,
                &prepared,
            )
            .expect("start");
        let terminal = provider
            .observe(
                &job,
                BenchmarkVerificationArm::Baseline,
                &request,
                &prepared,
                &running,
            )
            .expect("terminal");
        let BenchmarkVerificationChildObservation::Terminal(result) = terminal else {
            panic!("terminal");
        };
        assert_eq!(result.total_cells(), 2);
        assert_eq!(result.evidence().evidence().evidence_id(), &digest('c'));
    }

    #[test]
    // Captures running progress without finalizing evidence or restoring early.
    fn child_provider_preserves_running_progress() {
        let progress =
            BenchmarkProgress::new(TechnicalName::parse("measuring").expect("phase"), 1, 2)
                .expect("progress");
        let (_execution, telemetry, provider) = provider(
            BenchmarkExecutionObservation::Running(progress.clone()),
            false,
            true,
        );
        let observed = provider
            .observe(
                &OperationId::parse(&"1".repeat(32)).expect("job"),
                BenchmarkVerificationArm::Candidate,
                &request(),
                &PreparedBenchmark::new(digest('8')),
                &RunningBenchmark::new(digest('9')),
            )
            .expect("running");
        assert_eq!(
            observed,
            BenchmarkVerificationChildObservation::Running(progress)
        );
        assert_eq!(*telemetry.captures.lock().expect("captures"), 1);
    }

    #[test]
    // Fails before evidence publication on restoration or signature verification failure.
    fn child_provider_rejects_restore_and_signature_failures() {
        for (restore_failure, signature_valid, expected) in [
            (
                true,
                true,
                BenchmarkError::provider("execution", "restore failed"),
            ),
            (false, false, BenchmarkError::SignatureRejected),
        ] {
            let (_execution, _telemetry, provider) = provider(
                BenchmarkExecutionObservation::Terminal(if restore_failure {
                    BenchmarkExecutionOutcome::Failed {
                        raw_evidence_sha256: None,
                        failure: BenchmarkFailure::new(
                            BenchmarkFailureCategory::Crash,
                            "child",
                            "failed",
                        )
                        .expect("failure"),
                    }
                } else {
                    success()
                }),
                restore_failure,
                signature_valid,
            );
            assert_eq!(
                provider.observe(
                    &OperationId::parse(&"1".repeat(32)).expect("job"),
                    BenchmarkVerificationArm::Baseline,
                    &request(),
                    &PreparedBenchmark::new(digest('8')),
                    &RunningBenchmark::new(digest('9')),
                ),
                Err(expected)
            );
        }
    }
}
