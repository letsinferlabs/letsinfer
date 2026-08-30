// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use li_benchmark_manager::{
    benchmark_job_id, replay_sha256, BenchmarkError, BenchmarkRequest, BenchmarkSubject,
};
use li_core_interface::{OperationId, RuntimeCandidateId};
use li_node_manager::{
    NodeBenchmarkApiPort, NodeBenchmarkCoordinator, NodeBenchmarkPlan, NodeBenchmarkSelection,
    NodeBenchmarkSnapshot,
};

use crate::{
    CoreBenchmarkVerificationPreparation, CoreBenchmarkVerificationPreparationError,
    PreparedCoreBenchmarkVerification, ResolvedCoreBenchmarkVerification,
};

// Resolves and publishes one complete proposal authority without exposing its snapshot path.
pub trait CoreBenchmarkVerificationPreparationPort: Send + Sync {
    // Resolves one trusted finalizer bundle before any Runtime or Placement mutation.
    fn resolve(
        &self,
        pull_request_url: &str,
        candidate: Option<&RuntimeCandidateId>,
    ) -> Result<ResolvedCoreBenchmarkVerification, CoreBenchmarkVerificationPreparationError>;

    // Signs and publishes one exact candidate subject after Node handoff succeeds.
    fn authorize(
        &self,
        resolved: ResolvedCoreBenchmarkVerification,
        candidate: BenchmarkSubject,
        baseline: &BenchmarkSubject,
        issued_at_unix_milliseconds: u64,
    ) -> Result<PreparedCoreBenchmarkVerification, CoreBenchmarkVerificationPreparationError>;
}

impl CoreBenchmarkVerificationPreparationPort for CoreBenchmarkVerificationPreparation {
    // Runs the production oracle, subject, signer, and atomic publisher before returning a request.
    fn resolve(
        &self,
        pull_request_url: &str,
        candidate: Option<&RuntimeCandidateId>,
    ) -> Result<ResolvedCoreBenchmarkVerification, CoreBenchmarkVerificationPreparationError> {
        self.resolve_candidate(pull_request_url, candidate)
    }

    // Signs and publishes exactly the Node-prepared candidate/baseline binding.
    fn authorize(
        &self,
        resolved: ResolvedCoreBenchmarkVerification,
        candidate: BenchmarkSubject,
        baseline: &BenchmarkSubject,
        issued_at_unix_milliseconds: u64,
    ) -> Result<PreparedCoreBenchmarkVerification, CoreBenchmarkVerificationPreparationError> {
        CoreBenchmarkVerificationPreparation::authorize(
            self,
            resolved,
            candidate,
            baseline,
            issued_at_unix_milliseconds,
        )
    }
}

// Resolves the exact active resident baseline for one trusted candidate logical model.
pub trait CoreBenchmarkVerificationBaselinePort: Send + Sync {
    // Returns one unambiguous active baseline subject without changing service state.
    fn baseline(
        &self,
        candidate: &crate::CoreBenchmarkVerificationCandidate,
    ) -> Result<BenchmarkSubject, CoreBenchmarkVerificationPreparationError>;
}

// Acquires and prepares the exact candidate while retaining the baseline authoritative.
pub trait CoreBenchmarkVerificationCandidateHandoffPort: Send + Sync {
    // Returns deterministic transaction and candidate subject before private activation.
    fn prepare_candidate(
        &self,
        resolved: &ResolvedCoreBenchmarkVerification,
        baseline: &BenchmarkSubject,
    ) -> Result<(OperationId, BenchmarkSubject), CoreBenchmarkVerificationPreparationError>;

    // Restores/removes a handoff whose outer manager admission did not commit.
    fn abort(&self, transaction_id: &OperationId) -> Result<(), BenchmarkError>;
}

// Starts one exact Application-verified request through the Node-owned BenchmarkManager journal.
pub trait CoreBenchmarkVerificationStartPort: Send + Sync {
    // Starts or replays one closed complete request under the caller's idempotency identity.
    fn start_verified(
        &self,
        idempotency_key: &str,
        request: BenchmarkRequest,
    ) -> Result<NodeBenchmarkSnapshot, BenchmarkError>;
}

impl CoreBenchmarkVerificationStartPort for NodeBenchmarkCoordinator {
    // Delegates only to the coordinator's verification-specific manager entry point.
    fn start_verified(
        &self,
        idempotency_key: &str,
        request: BenchmarkRequest,
    ) -> Result<NodeBenchmarkSnapshot, BenchmarkError> {
        NodeBenchmarkCoordinator::start_verified(self, idempotency_key, request)
    }
}

// Supplies verification authority wall time behind one deterministic test boundary.
pub trait CoreBenchmarkVerificationWallClock: Send + Sync {
    // Returns one positive Unix millisecond used only for the signed authority lifetime.
    fn now_unix_milliseconds(&self) -> Result<u64, BenchmarkError>;
}

// Reads verification authority wall time from the operating-system clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemCoreBenchmarkVerificationWallClock;

impl CoreBenchmarkVerificationWallClock for SystemCoreBenchmarkVerificationWallClock {
    // Rejects pre-epoch, zero, and overflowing native wall time.
    fn now_unix_milliseconds(&self) -> Result<u64, BenchmarkError> {
        let milliseconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| BenchmarkError::provider("verification clock", "clock is unavailable"))?
            .as_millis();
        let milliseconds = u64::try_from(milliseconds)
            .map_err(|_| BenchmarkError::provider("verification clock", "clock is unavailable"))?;
        if milliseconds == 0 {
            return Err(BenchmarkError::provider(
                "verification clock",
                "clock is unavailable",
            ));
        }
        Ok(milliseconds)
    }
}

// Adds production proposal preparation to the ordinary Node-owned benchmark API.
pub struct ApplicationCoreBenchmarkVerificationApi {
    ordinary: Arc<dyn NodeBenchmarkApiPort>,
    preparation: Arc<dyn CoreBenchmarkVerificationPreparationPort>,
    baseline: Arc<dyn CoreBenchmarkVerificationBaselinePort>,
    handoff: Arc<dyn CoreBenchmarkVerificationCandidateHandoffPort>,
    verified: Arc<dyn CoreBenchmarkVerificationStartPort>,
    clock: Arc<dyn CoreBenchmarkVerificationWallClock>,
}

impl ApplicationCoreBenchmarkVerificationApi {
    // Creates one explicit composition without GitHub, filesystem, clock, or manager discovery.
    pub const fn new(
        ordinary: Arc<dyn NodeBenchmarkApiPort>,
        preparation: Arc<dyn CoreBenchmarkVerificationPreparationPort>,
        baseline: Arc<dyn CoreBenchmarkVerificationBaselinePort>,
        handoff: Arc<dyn CoreBenchmarkVerificationCandidateHandoffPort>,
        verified: Arc<dyn CoreBenchmarkVerificationStartPort>,
        clock: Arc<dyn CoreBenchmarkVerificationWallClock>,
    ) -> Self {
        Self {
            ordinary,
            preparation,
            baseline,
            handoff,
            verified,
            clock,
        }
    }
}

impl NodeBenchmarkApiPort for ApplicationCoreBenchmarkVerificationApi {
    // Preserves ordinary preview behavior through the existing Node coordinator.
    fn preview(
        &self,
        selection: NodeBenchmarkSelection,
    ) -> Result<NodeBenchmarkPlan, BenchmarkError> {
        self.ordinary.preview(selection)
    }

    // Preserves ordinary local benchmark start behavior through the existing coordinator.
    fn start(
        &self,
        idempotency_key: &str,
        selection: NodeBenchmarkSelection,
    ) -> Result<NodeBenchmarkSnapshot, BenchmarkError> {
        self.ordinary.start(idempotency_key, selection)
    }

    // Resolves all proposal identities resident-side, then starts the exact manager request.
    fn start_verification(
        &self,
        idempotency_key: &str,
        pull_request_url: &str,
        candidate: Option<&RuntimeCandidateId>,
    ) -> Result<NodeBenchmarkSnapshot, BenchmarkError> {
        if idempotency_key.is_empty() || idempotency_key.len() > 256 {
            return Err(BenchmarkError::InvalidContract {
                reason: "benchmark verification idempotency identity is invalid",
            });
        }
        let resolved = self
            .preparation
            .resolve(pull_request_url, candidate)
            .map_err(map_preparation_error)?;
        let expected_pull_request = resolved.pull_request();
        let expected_proposal_head = resolved.proposal_head().clone();
        let expected_candidate_id = resolved.candidate_id().clone();
        let expected_bundle_sha256 = resolved.candidate().bundle_sha256().clone();
        let expected_candidate_subject_sha256 = resolved.candidate().execution_sha256().clone();
        let baseline = self
            .baseline
            .baseline(resolved.candidate())
            .map_err(map_preparation_error)?;
        let expected_transaction = resolved
            .transaction_id(&baseline)
            .map_err(map_preparation_error)?;
        let (transaction_id, candidate_subject) = self
            .handoff
            .prepare_candidate(&resolved, &baseline)
            .map_err(map_preparation_error)?;
        if transaction_id != expected_transaction {
            let _ = self.handoff.abort(&transaction_id);
            return Err(BenchmarkError::AuthorizationDenied);
        }
        let issued = match self.clock.now_unix_milliseconds() {
            Ok(issued) => issued,
            Err(error) => {
                self.handoff.abort(&transaction_id)?;
                return Err(error);
            }
        };
        let prepared =
            match self
                .preparation
                .authorize(resolved, candidate_subject, &baseline, issued)
            {
                Ok(prepared) => prepared,
                Err(error) => {
                    self.handoff.abort(&transaction_id)?;
                    return Err(map_preparation_error(error));
                }
            };
        let request = prepared.request().clone();
        let request_matches = matches!(
            request.kind(),
            li_benchmark_manager::BenchmarkKind::Verification {
                pull_request,
                proposal_head,
                candidate,
                transaction_id: request_transaction_id,
                verifier_bundle_sha256,
                candidate_subject_sha256,
                baseline_execution_sha256: Some(baseline_execution_sha256),
                ..
            } if *pull_request == expected_pull_request
                && proposal_head == &expected_proposal_head
                && candidate == &expected_candidate_id
                && request_transaction_id == &transaction_id
                && verifier_bundle_sha256 == &expected_bundle_sha256
                && candidate_subject_sha256 == &expected_candidate_subject_sha256
                && baseline_execution_sha256 == baseline.execution_sha256()
        );
        if !request_matches || !request.scope().is_complete() {
            self.handoff.abort(&transaction_id)?;
            return Err(BenchmarkError::AuthorizationDenied);
        }
        let request_sha256 = request.sha256()?;
        let replay_identity = format!("li_node_benchmark_verification_{}", request_sha256.as_str());
        let job_id = benchmark_job_id(&replay_sha256(&replay_identity)?)?;
        match self.verified.start_verified(&replay_identity, request) {
            Ok(snapshot) => Ok(snapshot),
            Err(error) => {
                if matches!(self.ordinary.record(&job_id), Ok(None)) {
                    self.handoff.abort(&transaction_id)?;
                }
                Err(error)
            }
        }
    }

    // Preserves exact durable job lookup through the existing coordinator.
    fn record(
        &self,
        job_id: &OperationId,
    ) -> Result<Option<NodeBenchmarkSnapshot>, BenchmarkError> {
        self.ordinary.record(job_id)
    }

    // Preserves sole-active-job lookup through the existing coordinator.
    fn active(&self) -> Result<Option<NodeBenchmarkSnapshot>, BenchmarkError> {
        self.ordinary.active()
    }

    // Preserves exact cancellation and restoration through the existing coordinator.
    fn stop(&self, job_id: &OperationId) -> Result<NodeBenchmarkSnapshot, BenchmarkError> {
        self.ordinary.stop(job_id)
    }
}

// Maps credential, identity, and provider preparation failures into stable manager categories.
fn map_preparation_error(error: CoreBenchmarkVerificationPreparationError) -> BenchmarkError {
    match error {
        CoreBenchmarkVerificationPreparationError::InvalidInput => {
            BenchmarkError::InvalidContract {
                reason: "benchmark verification selector is invalid",
            }
        }
        CoreBenchmarkVerificationPreparationError::Conflict => BenchmarkError::IdempotencyConflict,
        CoreBenchmarkVerificationPreparationError::Unavailable => {
            BenchmarkError::provider("verification authority", "authority is unavailable")
        }
        CoreBenchmarkVerificationPreparationError::InvalidAuthority => {
            BenchmarkError::AuthorizationDenied
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use li_benchmark_manager::{
        BenchmarkDisposition, BenchmarkGitRevision, BenchmarkJobPhase, BenchmarkKind,
        BenchmarkScope, BenchmarkSubject, BenchmarkVerificationPhase,
    };
    use li_core_interface::{
        ArtifactName, ArtifactRevision, ArtifactUri, ByteCount, CpuArchitecture,
        EngineDistribution, EvidenceLabel, InstallationId, LogicalModelName, MemoryTopology,
        ModelArtifact, ModelArtifactFormat, OperatingSystem, PlacementGroupId, RuntimeIdentity,
        RuntimeInstallationId, RuntimeSource, RuntimeVersion, Sha256Digest, TargetId,
        TechnicalName, UnixMilliseconds,
    };
    use li_node_manager::{
        NodeBenchmarkCandidateHandoffPhase, NodeBenchmarkVerificationProjection,
    };
    use li_runtime_manager::{RuntimeAcceleratorVendor, RuntimeCandidate, RuntimeTarget};

    use crate::{
        CoreBenchmarkVerificationCandidate, CoreBenchmarkVerificationEngineArtifact,
        CoreBenchmarkVerificationProposal,
    };

    use super::*;

    struct OrdinaryMock(bool);

    impl NodeBenchmarkApiPort for OrdinaryMock {
        // Refuses unused ordinary preview calls in verification-focused tests.
        fn preview(
            &self,
            _selection: NodeBenchmarkSelection,
        ) -> Result<NodeBenchmarkPlan, BenchmarkError> {
            Err(BenchmarkError::NotFound)
        }

        // Refuses unused ordinary start calls in verification-focused tests.
        fn start(
            &self,
            _idempotency_key: &str,
            _selection: NodeBenchmarkSelection,
        ) -> Result<NodeBenchmarkSnapshot, BenchmarkError> {
            Err(BenchmarkError::NotFound)
        }

        // Reports no committed job when verification admission fails before persistence.
        fn record(
            &self,
            _job_id: &OperationId,
        ) -> Result<Option<NodeBenchmarkSnapshot>, BenchmarkError> {
            if self.0 {
                Ok(Some(snapshot()))
            } else {
                Ok(None)
            }
        }

        // Returns no ordinary active job for exact delegation tests.
        fn active(&self) -> Result<Option<NodeBenchmarkSnapshot>, BenchmarkError> {
            Ok(None)
        }

        // Refuses unused stop calls in verification-focused tests.
        fn stop(&self, _job_id: &OperationId) -> Result<NodeBenchmarkSnapshot, BenchmarkError> {
            Err(BenchmarkError::NotFound)
        }
    }

    struct PreparationMock {
        resolve_result:
            Result<ResolvedCoreBenchmarkVerification, CoreBenchmarkVerificationPreparationError>,
        authorize_result:
            Result<PreparedCoreBenchmarkVerification, CoreBenchmarkVerificationPreparationError>,
        calls: Mutex<Vec<String>>,
    }

    impl CoreBenchmarkVerificationPreparationPort for PreparationMock {
        // Records public selectors before returning one injected trusted resolution.
        fn resolve(
            &self,
            pull_request_url: &str,
            _candidate: Option<&RuntimeCandidateId>,
        ) -> Result<ResolvedCoreBenchmarkVerification, CoreBenchmarkVerificationPreparationError>
        {
            self.calls
                .lock()
                .expect("calls")
                .push(format!("resolve:{pull_request_url}"));
            self.resolve_result.clone()
        }

        // Records the exact post-handoff signing boundary.
        fn authorize(
            &self,
            _resolved: ResolvedCoreBenchmarkVerification,
            _candidate: BenchmarkSubject,
            _baseline: &BenchmarkSubject,
            issued_at_unix_milliseconds: u64,
        ) -> Result<PreparedCoreBenchmarkVerification, CoreBenchmarkVerificationPreparationError>
        {
            self.calls
                .lock()
                .expect("calls")
                .push(format!("authorize:{issued_at_unix_milliseconds}"));
            self.authorize_result.clone()
        }
    }

    struct BaselineMock(Result<BenchmarkSubject, CoreBenchmarkVerificationPreparationError>);

    impl CoreBenchmarkVerificationBaselinePort for BaselineMock {
        // Returns one injected current resident baseline subject.
        fn baseline(
            &self,
            _candidate: &CoreBenchmarkVerificationCandidate,
        ) -> Result<BenchmarkSubject, CoreBenchmarkVerificationPreparationError> {
            self.0.clone()
        }
    }

    struct HandoffMock {
        result: Result<(OperationId, BenchmarkSubject), CoreBenchmarkVerificationPreparationError>,
        aborts: Mutex<Vec<OperationId>>,
    }

    impl CoreBenchmarkVerificationCandidateHandoffPort for HandoffMock {
        // Returns one injected Node candidate acquisition result.
        fn prepare_candidate(
            &self,
            _resolved: &ResolvedCoreBenchmarkVerification,
            _baseline: &BenchmarkSubject,
        ) -> Result<(OperationId, BenchmarkSubject), CoreBenchmarkVerificationPreparationError>
        {
            self.result.clone()
        }

        // Records one admission-failure compensation.
        fn abort(&self, transaction_id: &OperationId) -> Result<(), BenchmarkError> {
            self.aborts
                .lock()
                .expect("aborts")
                .push(transaction_id.clone());
            Ok(())
        }
    }

    struct StartMock {
        result: Result<NodeBenchmarkSnapshot, BenchmarkError>,
        calls: Mutex<Vec<(String, BenchmarkRequest)>>,
    }

    impl CoreBenchmarkVerificationStartPort for StartMock {
        // Records one exact manager request and returns its injected replay result.
        fn start_verified(
            &self,
            idempotency_key: &str,
            request: BenchmarkRequest,
        ) -> Result<NodeBenchmarkSnapshot, BenchmarkError> {
            self.calls
                .lock()
                .expect("calls")
                .push((idempotency_key.to_string(), request));
            self.result.clone()
        }
    }

    struct ClockMock(Result<u64, BenchmarkError>);

    impl CoreBenchmarkVerificationWallClock for ClockMock {
        // Returns one exact injected authority time result.
        fn now_unix_milliseconds(&self) -> Result<u64, BenchmarkError> {
            self.0.clone()
        }
    }

    // Returns one exact lowercase digest fixture.
    fn digest(character: char) -> Sha256Digest {
        Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
    }

    // Returns one exact resident-only trusted candidate closure.
    fn trusted_candidate() -> CoreBenchmarkVerificationCandidate {
        let candidate_id =
            RuntimeCandidateId::parse("vllm--owner--model--spark").expect("candidate");
        let runtime = RuntimeIdentity::new(
            candidate_id,
            RuntimeVersion::parse("1.0.0").expect("version"),
            TargetId::parse("spark").expect("target"),
            RuntimeSource::parse(&format!(
                "ghcr.io/letsinferlabs/runtime@sha256:{}",
                "7".repeat(64)
            ))
            .expect("source"),
            EngineDistribution::oci(
                RuntimeSource::parse(&format!(
                    "ghcr.io/letsinferlabs/engine@sha256:{}",
                    "8".repeat(64)
                ))
                .expect("Engine"),
                digest('9'),
                None,
                None,
            ),
            digest('6'),
            digest('5'),
            digest('4'),
        )
        .expect("runtime");
        CoreBenchmarkVerificationCandidate::new(
            RuntimeCandidate::new(
                LogicalModelName::parse("model").expect("model"),
                runtime,
                vec![ModelArtifact::new(
                    ArtifactName::parse("model").expect("artifact"),
                    ArtifactUri::parse("hf://owner/model").expect("URI"),
                    ArtifactRevision::parse(&"1".repeat(40)).expect("revision"),
                    ModelArtifactFormat::HuggingFaceSnapshot,
                )],
                RuntimeTarget::new(
                    OperatingSystem::Linux,
                    CpuArchitecture::Arm64,
                    RuntimeAcceleratorVendor::Nvidia,
                    TechnicalName::parse("sm_121").expect("compute"),
                    1,
                    MemoryTopology::Unified,
                    None,
                    ByteCount::new(1 << 30).expect("memory"),
                )
                .expect("target"),
                EvidenceLabel::Unqualified,
                2,
                false,
                false,
            )
            .expect("candidate"),
            std::path::PathBuf::from("/test/runtime.letsinfer"),
            CoreBenchmarkVerificationEngineArtifact::Reuse,
            digest('e'),
            digest('f'),
            vec![41],
            BenchmarkGitRevision::parse(&"b".repeat(40)).expect("base"),
        )
        .expect("closure")
    }

    // Returns one trusted finalizer resolution for deterministic API orchestration.
    fn resolution() -> ResolvedCoreBenchmarkVerification {
        ResolvedCoreBenchmarkVerification::test_fixture(
            CoreBenchmarkVerificationProposal::new(
                41,
                BenchmarkGitRevision::parse(&"a".repeat(40)).expect("head"),
                RuntimeCandidateId::parse("vllm--owner--model--spark").expect("candidate"),
                73,
                digest('b'),
                None,
                digest('e'),
                true,
                true,
                true,
            )
            .with_trusted_candidate(trusted_candidate()),
        )
    }

    // Returns the exact current resident baseline subject.
    fn baseline() -> BenchmarkSubject {
        BenchmarkSubject::new(
            InstallationId::parse(&"1".repeat(64)).expect("installation"),
            RuntimeInstallationId::parse(&"8".repeat(32)).expect("runtime"),
            LogicalModelName::parse("model").expect("model"),
            PlacementGroupId::parse(&"8".repeat(32)).expect("group"),
            digest('8'),
            digest('5'),
            digest('6'),
        )
    }

    // Returns one complete closed verification request.
    fn request() -> BenchmarkRequest {
        BenchmarkRequest::new(
            BenchmarkKind::verification(
                41,
                BenchmarkGitRevision::parse(&"a".repeat(40)).expect("head"),
                RuntimeCandidateId::parse("vllm--owner--model--spark").expect("candidate"),
                resolution()
                    .transaction_id(&baseline())
                    .expect("transaction"),
                digest('e'),
                digest('f'),
                73,
                digest('b'),
                Some(digest('8')),
            )
            .expect("kind"),
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

    // Returns one coherent running verification snapshot for Application routing tests.
    fn snapshot() -> NodeBenchmarkSnapshot {
        NodeBenchmarkSnapshot::restore(
            OperationId::parse(&"7".repeat(32)).expect("job"),
            1,
            request().kind().clone(),
            BenchmarkJobPhase::Running,
            Some(BenchmarkDisposition::Started),
            digest('8'),
            InstallationId::parse(&"1".repeat(64)).expect("installation"),
            RuntimeInstallationId::parse(&"2".repeat(32)).expect("runtime"),
            LogicalModelName::parse("model").expect("model"),
            PlacementGroupId::parse(&"3".repeat(32)).expect("group"),
            digest('4'),
            digest('5'),
            digest('6'),
            digest('9'),
            Some(digest('a')),
            Some(digest('b')),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(NodeBenchmarkVerificationProjection::new(
                BenchmarkVerificationPhase::CandidateRunning,
                OperationId::parse(&"4".repeat(32)).expect("transaction"),
                NodeBenchmarkCandidateHandoffPhase::CandidateRunning,
            )),
            None,
            UnixMilliseconds::new(10),
            UnixMilliseconds::new(11),
        )
        .expect("snapshot")
    }

    // Creates one Application API and exposes its preparation and manager-start mocks.
    fn api(
        preparation_result: Result<BenchmarkRequest, CoreBenchmarkVerificationPreparationError>,
        start_result: Result<NodeBenchmarkSnapshot, BenchmarkError>,
        clock_result: Result<u64, BenchmarkError>,
    ) -> (
        ApplicationCoreBenchmarkVerificationApi,
        Arc<PreparationMock>,
        Arc<StartMock>,
        Arc<HandoffMock>,
    ) {
        let resolve_result = preparation_result
            .as_ref()
            .map(|_| resolution())
            .map_err(|error| *error);
        let authorize_result = preparation_result.clone().map(|request| {
            PreparedCoreBenchmarkVerification::test_fixture(request, trusted_candidate())
        });
        let preparation = Arc::new(PreparationMock {
            resolve_result,
            authorize_result,
            calls: Mutex::new(Vec::new()),
        });
        let start = Arc::new(StartMock {
            result: start_result,
            calls: Mutex::new(Vec::new()),
        });
        let baseline = baseline();
        let transaction = resolution().transaction_id(&baseline).expect("transaction");
        let handoff = Arc::new(HandoffMock {
            result: Ok((transaction, request().subject().clone())),
            aborts: Mutex::new(Vec::new()),
        });
        (
            ApplicationCoreBenchmarkVerificationApi::new(
                Arc::new(OrdinaryMock(false)),
                preparation.clone(),
                Arc::new(BaselineMock(Ok(baseline))),
                handoff.clone(),
                start.clone(),
                Arc::new(ClockMock(clock_result)),
            ),
            preparation,
            start,
            handoff,
        )
    }

    #[test]
    // Resolves resident authority and starts exactly its closed request under one replay identity.
    fn verification_api_passes_only_public_selectors_into_preparation() {
        let expected = request();
        let (api, preparation, start, handoff) =
            api(Ok(expected.clone()), Ok(snapshot()), Ok(1_000));
        let candidate = RuntimeCandidateId::parse("vllm--owner--model--spark").expect("candidate");
        let result = api
            .start_verification(
                "replay-key",
                "https://github.com/letsinferlabs/runtimes/pull/41",
                Some(&candidate),
            )
            .expect("started");
        assert!(result.is_verification());
        assert_eq!(
            preparation.calls.lock().expect("calls").as_slice(),
            [
                "resolve:https://github.com/letsinferlabs/runtimes/pull/41".to_string(),
                "authorize:1000".to_string(),
            ]
        );
        assert!(handoff.aborts.lock().expect("aborts").is_empty());
        assert_eq!(
            start.calls.lock().expect("calls").as_slice(),
            [(
                format!(
                    "li_node_benchmark_verification_{}",
                    expected.sha256().expect("request digest").as_str()
                ),
                expected
            )]
        );
    }

    #[test]
    // Maps every preparation rejection before any BenchmarkManager mutation is attempted.
    fn verification_api_fails_closed_at_each_preparation_boundary() {
        for (source, expected) in [
            (
                CoreBenchmarkVerificationPreparationError::InvalidInput,
                BenchmarkError::InvalidContract {
                    reason: "benchmark verification selector is invalid",
                },
            ),
            (
                CoreBenchmarkVerificationPreparationError::Conflict,
                BenchmarkError::IdempotencyConflict,
            ),
            (
                CoreBenchmarkVerificationPreparationError::Unavailable,
                BenchmarkError::provider("verification authority", "authority is unavailable"),
            ),
            (
                CoreBenchmarkVerificationPreparationError::InvalidAuthority,
                BenchmarkError::AuthorizationDenied,
            ),
        ] {
            let (api, _, start, handoff) = api(Err(source), Ok(snapshot()), Ok(1_000));
            assert_eq!(
                api.start_verification(
                    "replay-key",
                    "https://github.com/letsinferlabs/runtimes/pull/41",
                    None,
                ),
                Err(expected)
            );
            assert!(start.calls.lock().expect("calls").is_empty());
            assert!(handoff.aborts.lock().expect("aborts").is_empty());
        }
    }

    #[test]
    // Rejects a non-verification shortcut even when an injected preparation port returns it.
    fn verification_api_rejects_a_local_request_from_preparation() {
        let mut local = request();
        local = BenchmarkRequest::new(
            BenchmarkKind::Local,
            BenchmarkScope::Complete,
            local.subject().clone(),
        )
        .expect("local");
        let (api, _, start, handoff) = api(Ok(local), Ok(snapshot()), Ok(1_000));
        assert_eq!(
            api.start_verification(
                "replay-key",
                "https://github.com/letsinferlabs/runtimes/pull/41",
                None,
            ),
            Err(BenchmarkError::AuthorizationDenied)
        );
        assert!(start.calls.lock().expect("calls").is_empty());
        assert_eq!(handoff.aborts.lock().expect("aborts").len(), 1);
    }

    #[test]
    // Aborts the prepared candidate when manager admission fails and reuses one exact replay key.
    fn verification_api_compensates_admission_failure_and_replays_exact_dispatch() {
        let (failed, _, failed_start, failed_handoff) =
            api(Ok(request()), Err(BenchmarkError::Busy), Ok(1_000));
        assert_eq!(
            failed.start_verification(
                "client-replay",
                "https://github.com/letsinferlabs/runtimes/pull/41",
                None,
            ),
            Err(BenchmarkError::Busy)
        );
        assert_eq!(failed_start.calls.lock().expect("calls").len(), 1);
        assert_eq!(failed_handoff.aborts.lock().expect("aborts").len(), 1);

        let baseline = baseline();
        let transaction = resolution().transaction_id(&baseline).expect("transaction");
        let preparation = Arc::new(PreparationMock {
            resolve_result: Ok(resolution()),
            authorize_result: Ok(PreparedCoreBenchmarkVerification::test_fixture(
                request(),
                trusted_candidate(),
            )),
            calls: Mutex::new(Vec::new()),
        });
        let committed_handoff = Arc::new(HandoffMock {
            result: Ok((transaction, request().subject().clone())),
            aborts: Mutex::new(Vec::new()),
        });
        let committed_start = Arc::new(StartMock {
            result: Err(BenchmarkError::provider("store", "commit response lost")),
            calls: Mutex::new(Vec::new()),
        });
        let committed = ApplicationCoreBenchmarkVerificationApi::new(
            Arc::new(OrdinaryMock(true)),
            preparation,
            Arc::new(BaselineMock(Ok(baseline))),
            committed_handoff.clone(),
            committed_start,
            Arc::new(ClockMock(Ok(1_000))),
        );
        assert!(committed
            .start_verification(
                "client-replay",
                "https://github.com/letsinferlabs/runtimes/pull/41",
                None,
            )
            .is_err());
        assert!(committed_handoff.aborts.lock().expect("aborts").is_empty());

        let (replay, _, replay_start, replay_handoff) =
            api(Ok(request()), Ok(snapshot()), Ok(1_000));
        for _ in 0..2 {
            replay
                .start_verification(
                    "client-replay",
                    "https://github.com/letsinferlabs/runtimes/pull/41",
                    None,
                )
                .expect("replay");
        }
        let calls = replay_start.calls.lock().expect("calls");
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0], calls[1]);
        assert!(replay_handoff.aborts.lock().expect("aborts").is_empty());
    }

    #[test]
    // Aborts candidate handoff when authority time or post-handoff signing is unavailable.
    fn verification_api_compensates_each_post_handoff_authority_failure() {
        let (clock_failure, _, start, handoff) = api(
            Ok(request()),
            Ok(snapshot()),
            Err(BenchmarkError::provider("clock", "unavailable")),
        );
        assert!(clock_failure
            .start_verification(
                "client-replay",
                "https://github.com/letsinferlabs/runtimes/pull/41",
                None,
            )
            .is_err());
        assert!(start.calls.lock().expect("calls").is_empty());
        assert_eq!(handoff.aborts.lock().expect("aborts").len(), 1);

        let baseline = baseline();
        let transaction = resolution().transaction_id(&baseline).expect("transaction");
        let preparation = Arc::new(PreparationMock {
            resolve_result: Ok(resolution()),
            authorize_result: Err(CoreBenchmarkVerificationPreparationError::InvalidAuthority),
            calls: Mutex::new(Vec::new()),
        });
        let handoff = Arc::new(HandoffMock {
            result: Ok((transaction, request().subject().clone())),
            aborts: Mutex::new(Vec::new()),
        });
        let start = Arc::new(StartMock {
            result: Ok(snapshot()),
            calls: Mutex::new(Vec::new()),
        });
        let signing_failure = ApplicationCoreBenchmarkVerificationApi::new(
            Arc::new(OrdinaryMock(false)),
            preparation,
            Arc::new(BaselineMock(Ok(baseline))),
            handoff.clone(),
            start.clone(),
            Arc::new(ClockMock(Ok(1_000))),
        );
        assert_eq!(
            signing_failure.start_verification(
                "client-replay",
                "https://github.com/letsinferlabs/runtimes/pull/41",
                None,
            ),
            Err(BenchmarkError::AuthorizationDenied)
        );
        assert!(start.calls.lock().expect("calls").is_empty());
        assert_eq!(handoff.aborts.lock().expect("aborts").len(), 1);
    }

    #[test]
    // Rejects a signed request whose transaction, bundle, or finalizer subject differs after handoff.
    fn verification_api_rejects_post_handoff_identity_drift() {
        for (transaction, bundle, candidate_subject) in [
            (
                OperationId::parse(&"0".repeat(32)).expect("transaction"),
                digest('e'),
                digest('f'),
            ),
            (
                resolution()
                    .transaction_id(&baseline())
                    .expect("transaction"),
                digest('0'),
                digest('f'),
            ),
            (
                resolution()
                    .transaction_id(&baseline())
                    .expect("transaction"),
                digest('e'),
                digest('0'),
            ),
        ] {
            let drifted = BenchmarkRequest::new(
                BenchmarkKind::verification(
                    41,
                    BenchmarkGitRevision::parse(&"a".repeat(40)).expect("head"),
                    RuntimeCandidateId::parse("vllm--owner--model--spark").expect("candidate"),
                    transaction,
                    bundle,
                    candidate_subject,
                    73,
                    digest('b'),
                    Some(digest('8')),
                )
                .expect("kind"),
                BenchmarkScope::Complete,
                request().subject().clone(),
            )
            .expect("request");
            let (api, _, start, handoff) = api(Ok(drifted), Ok(snapshot()), Ok(1_000));
            assert_eq!(
                api.start_verification(
                    "client-replay",
                    "https://github.com/letsinferlabs/runtimes/pull/41",
                    None,
                ),
                Err(BenchmarkError::AuthorizationDenied)
            );
            assert!(start.calls.lock().expect("calls").is_empty());
            assert_eq!(handoff.aborts.lock().expect("aborts").len(), 1);
        }
    }

    #[test]
    // Delegates ordinary active-state reads without invoking verification preparation.
    fn ordinary_benchmark_reads_remain_on_the_existing_api() {
        let (api, preparation, start, _) = api(Ok(request()), Ok(snapshot()), Ok(1_000));
        assert_eq!(api.active().expect("active"), None);
        assert!(preparation.calls.lock().expect("calls").is_empty());
        assert!(start.calls.lock().expect("calls").is_empty());
    }
}
