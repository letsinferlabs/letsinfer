// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::{Arc, Mutex, TryLockError};
use std::time::{SystemTime, UNIX_EPOCH};

use li_core_interface::{OperationId, Sha256Digest, UnixMilliseconds};
use sha2::{Digest, Sha256};

use crate::{
    BenchmarkAuthorization, BenchmarkError, BenchmarkExecutionObservation,
    BenchmarkExecutionOutcome, BenchmarkExecutionProvider, BenchmarkProgress,
    BenchmarkRecordSchema, BenchmarkRequest, BenchmarkRestoration, BenchmarkStoreError,
    BenchmarkTelemetryReceipt, PreparedBenchmark, RunningBenchmark, SealedBenchmarkEvidence,
};

// Identifies one arm of a paired community verification without naming Engine semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BenchmarkVerificationArm {
    Baseline,
    Candidate,
}

impl BenchmarkVerificationArm {
    // Returns the stable persistence and provider identity of this arm.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::Candidate => "candidate",
        }
    }
}

// Names only parent ordering; Runtime/Placement handoff retains its own durable phase contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BenchmarkVerificationPhase {
    Prepared,
    BaselineRunning,
    BaselineComplete,
    CandidateRunning,
    CandidateComplete,
    Restoring,
    Restored,
    RestorationFailed,
}

// Carries one complete independently sealed child result used to construct paired evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BenchmarkVerificationChildResult {
    outcome: BenchmarkExecutionOutcome,
    telemetry: BenchmarkTelemetryReceipt,
    restoration: BenchmarkRestoration,
    evidence: SealedBenchmarkEvidence,
    total_cells: u32,
}

impl BenchmarkVerificationChildResult {
    // Creates one schema-consistent child result after its exact resident state was restored.
    pub fn new(
        outcome: BenchmarkExecutionOutcome,
        telemetry: BenchmarkTelemetryReceipt,
        restoration: BenchmarkRestoration,
        evidence: SealedBenchmarkEvidence,
        total_cells: u32,
    ) -> Result<Self, BenchmarkError> {
        let evidence_matches = match &outcome {
            BenchmarkExecutionOutcome::Succeeded {
                results_sha256,
                record_schema,
                ..
            } => {
                matches!(
                    record_schema,
                    BenchmarkRecordSchema::OciExecutionPayloadV7
                        | BenchmarkRecordSchema::NativeExecutionPayloadV8
                ) && evidence.evidence().schema() == *record_schema
                    && evidence.evidence().results_sha256() == results_sha256
            }
            BenchmarkExecutionOutcome::Failed { .. }
            | BenchmarkExecutionOutcome::Cancelled { .. } => {
                evidence.evidence().schema() == BenchmarkRecordSchema::CoreLocalFailureV1
            }
        };
        if total_cells == 0 || !evidence_matches {
            return Err(BenchmarkError::InvalidContract {
                reason: "verification child result is incomplete or identity-mismatched",
            });
        }
        Ok(Self {
            outcome,
            telemetry,
            restoration,
            evidence,
            total_cells,
        })
    }

    // Returns the terminal child execution outcome.
    pub const fn outcome(&self) -> &BenchmarkExecutionOutcome {
        &self.outcome
    }

    // Returns the exact child telemetry receipt.
    pub const fn telemetry(&self) -> &BenchmarkTelemetryReceipt {
        &self.telemetry
    }

    // Returns proof that this child restored its own benchmark isolation.
    pub const fn restoration(&self) -> &BenchmarkRestoration {
        &self.restoration
    }

    // Returns the independently verified and signed child evidence.
    pub const fn evidence(&self) -> &SealedBenchmarkEvidence {
        &self.evidence
    }

    // Returns the complete declared cell count shared by both arms.
    pub const fn total_cells(&self) -> u32 {
        self.total_cells
    }
}

// Reports one restart-safe child observation; terminal means child evidence and restoration exist.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BenchmarkVerificationChildObservation {
    Running(BenchmarkProgress),
    Terminal(BenchmarkVerificationChildResult),
}

// Carries the Node-owned prepared handoff without duplicating its internal phases.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BenchmarkVerificationHandoffReceipt {
    transaction_id: OperationId,
    receipt_id: Sha256Digest,
    bundle_sha256: Sha256Digest,
    baseline_request: BenchmarkRequest,
    candidate_request: BenchmarkRequest,
}

impl BenchmarkVerificationHandoffReceipt {
    // Creates one exact handoff only for a local baseline and complete verification candidate.
    pub fn new(
        transaction_id: OperationId,
        receipt_id: Sha256Digest,
        bundle_sha256: Sha256Digest,
        baseline_request: BenchmarkRequest,
        candidate_request: BenchmarkRequest,
    ) -> Result<Self, BenchmarkError> {
        if baseline_request.kind().is_verification()
            || !candidate_request.kind().is_verification()
            || !baseline_request.scope().is_complete()
            || !candidate_request.scope().is_complete()
            || baseline_request.subject().model() != candidate_request.subject().model()
            || baseline_request.subject().benchmark_contract_sha256()
                != candidate_request.subject().benchmark_contract_sha256()
            || baseline_request.subject().target_contract_sha256()
                != candidate_request.subject().target_contract_sha256()
        {
            return Err(BenchmarkError::InvalidContract {
                reason: "verification handoff requests are invalid",
            });
        }
        Ok(Self {
            transaction_id,
            receipt_id,
            bundle_sha256,
            baseline_request,
            candidate_request,
        })
    }

    // Returns the Node-owned durable Runtime/Placement handoff transaction identity.
    pub const fn transaction_id(&self) -> &OperationId {
        &self.transaction_id
    }

    // Returns the opaque Node-owned handoff identity.
    pub const fn receipt_id(&self) -> &Sha256Digest {
        &self.receipt_id
    }

    // Returns the trusted finalizer bundle identity staged by RuntimeManager.
    pub const fn bundle_sha256(&self) -> &Sha256Digest {
        &self.bundle_sha256
    }

    // Returns the exact active baseline subject and complete benchmark contract.
    pub const fn baseline_request(&self) -> &BenchmarkRequest {
        &self.baseline_request
    }

    // Returns the private candidate subject and same complete benchmark contract.
    pub const fn candidate_request(&self) -> &BenchmarkRequest {
        &self.candidate_request
    }
}

// Supplies the Node-owned exact candidate Runtime/Placement handoff and baseline restoration.
pub trait BenchmarkVerificationHandoffProvider: Send + Sync {
    // Returns an existing or atomically prepared handoff for the outer verification request.
    fn prepare(
        &self,
        job_id: &OperationId,
        request: &BenchmarkRequest,
    ) -> Result<BenchmarkVerificationHandoffReceipt, BenchmarkError>;

    // Privately activates the prepared candidate placement while retaining the baseline intent.
    fn activate_candidate(
        &self,
        job_id: &OperationId,
        receipt: &BenchmarkVerificationHandoffReceipt,
    ) -> Result<Sha256Digest, BenchmarkError>;

    // Restores the exact baseline group and its original running or stopped intent idempotently.
    fn restore_baseline(
        &self,
        job_id: &OperationId,
        receipt: &BenchmarkVerificationHandoffReceipt,
    ) -> Result<Sha256Digest, BenchmarkError>;

    // Removes only candidate-owned private placements and Runtime bytes after restoration.
    fn cleanup(
        &self,
        job_id: &OperationId,
        receipt: &BenchmarkVerificationHandoffReceipt,
    ) -> Result<(), BenchmarkError>;
}

// Runs one ordinary benchmark arm through existing execution, telemetry, evidence, and signing.
pub trait BenchmarkVerificationChildProvider: Send + Sync {
    // Prepares one arm idempotently and returns its opaque provider receipt.
    fn prepare(
        &self,
        job_id: &OperationId,
        arm: BenchmarkVerificationArm,
        request: &BenchmarkRequest,
    ) -> Result<PreparedBenchmark, BenchmarkError>;

    // Starts or reattaches to one exact prepared child.
    fn start(
        &self,
        job_id: &OperationId,
        arm: BenchmarkVerificationArm,
        request: &BenchmarkRequest,
        prepared: &PreparedBenchmark,
    ) -> Result<RunningBenchmark, BenchmarkError>;

    // Returns progress or one fully restored and signed child terminal result.
    fn observe(
        &self,
        job_id: &OperationId,
        arm: BenchmarkVerificationArm,
        request: &BenchmarkRequest,
        prepared: &PreparedBenchmark,
        running: &RunningBenchmark,
    ) -> Result<BenchmarkVerificationChildObservation, BenchmarkError>;

    // Persists stop intent and contains only the exact active child.
    fn request_stop(
        &self,
        job_id: &OperationId,
        arm: BenchmarkVerificationArm,
        running: &RunningBenchmark,
    ) -> Result<(), BenchmarkError>;

    // Removes only terminal child-owned task and telemetry resources idempotently.
    fn cleanup(
        &self,
        job_id: &OperationId,
        arm: BenchmarkVerificationArm,
    ) -> Result<(), BenchmarkError>;
}

// Stores one arm's restart-relevant provider receipts and optional terminal result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BenchmarkVerificationArmState {
    prepared: PreparedBenchmark,
    running: Option<RunningBenchmark>,
    result: Option<BenchmarkVerificationChildResult>,
}

impl BenchmarkVerificationArmState {
    // Creates one prepared arm before task launch.
    pub const fn prepared(prepared: PreparedBenchmark) -> Self {
        Self {
            prepared,
            running: None,
            result: None,
        }
    }

    // Reconstructs one exact child state after validating receipt ordering.
    pub fn restore(
        prepared: PreparedBenchmark,
        running: Option<RunningBenchmark>,
        result: Option<BenchmarkVerificationChildResult>,
    ) -> Result<Self, BenchmarkStoreError> {
        if result.is_some() && running.is_none() {
            return Err(BenchmarkStoreError::Corrupt);
        }
        Ok(Self {
            prepared,
            running,
            result,
        })
    }

    // Returns the child preparation receipt.
    pub const fn prepared_receipt(&self) -> &PreparedBenchmark {
        &self.prepared
    }

    // Returns the active child task receipt.
    pub const fn running_receipt(&self) -> Option<&RunningBenchmark> {
        self.running.as_ref()
    }

    // Returns the terminal restored child result.
    pub const fn result(&self) -> Option<&BenchmarkVerificationChildResult> {
        self.result.as_ref()
    }
}

// Stores the BenchmarkManager-owned restart-safe paired execution transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BenchmarkVerificationTransaction {
    job_id: OperationId,
    request_sha256: Sha256Digest,
    handoff: BenchmarkVerificationHandoffReceipt,
    phase: BenchmarkVerificationPhase,
    baseline: BenchmarkVerificationArmState,
    candidate: Option<BenchmarkVerificationArmState>,
    candidate_activation_receipt_id: Option<Sha256Digest>,
    baseline_restoration_receipt_id: Option<Sha256Digest>,
    cancellation_requested: bool,
    paired_results_sha256: Option<Sha256Digest>,
    created_at: UnixMilliseconds,
    updated_at: UnixMilliseconds,
}

impl BenchmarkVerificationTransaction {
    // Reconstructs one persisted parent transaction and reapplies all phase invariants.
    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        job_id: OperationId,
        request_sha256: Sha256Digest,
        handoff: BenchmarkVerificationHandoffReceipt,
        phase: BenchmarkVerificationPhase,
        baseline: BenchmarkVerificationArmState,
        candidate: Option<BenchmarkVerificationArmState>,
        candidate_activation_receipt_id: Option<Sha256Digest>,
        baseline_restoration_receipt_id: Option<Sha256Digest>,
        cancellation_requested: bool,
        paired_results_sha256: Option<Sha256Digest>,
        created_at: UnixMilliseconds,
        updated_at: UnixMilliseconds,
    ) -> Result<Self, BenchmarkStoreError> {
        if handoff
            .candidate_request()
            .sha256()
            .map_err(|_| BenchmarkStoreError::Corrupt)?
            != request_sha256
            || created_at.value() == 0
            || updated_at < created_at
            || candidate.is_some() != candidate_activation_receipt_id.is_some()
            || baseline_restoration_receipt_id.is_some()
                != (phase == BenchmarkVerificationPhase::Restored)
            || paired_results_sha256.is_some()
                && (phase != BenchmarkVerificationPhase::Restored
                    || baseline.result.is_none()
                    || candidate
                        .as_ref()
                        .and_then(|value| value.result())
                        .is_none())
        {
            return Err(BenchmarkStoreError::Corrupt);
        }
        let phase_valid = match phase {
            BenchmarkVerificationPhase::Prepared => {
                baseline.running.is_none() && baseline.result.is_none() && candidate.is_none()
            }
            BenchmarkVerificationPhase::BaselineRunning => {
                baseline.running.is_some() && baseline.result.is_none() && candidate.is_none()
            }
            BenchmarkVerificationPhase::BaselineComplete => {
                baseline.result.is_some() && candidate.is_none()
            }
            BenchmarkVerificationPhase::CandidateRunning => {
                baseline.result.is_some()
                    && candidate
                        .as_ref()
                        .is_some_and(|value| value.running.is_some() && value.result.is_none())
            }
            BenchmarkVerificationPhase::CandidateComplete => {
                baseline.result.is_some()
                    && candidate
                        .as_ref()
                        .and_then(|value| value.result())
                        .is_some()
            }
            BenchmarkVerificationPhase::Restoring => baseline.result.is_some(),
            BenchmarkVerificationPhase::Restored => baseline.result.is_some(),
            BenchmarkVerificationPhase::RestorationFailed => baseline.result.is_some(),
        };
        if !phase_valid {
            return Err(BenchmarkStoreError::Corrupt);
        }
        Ok(Self {
            job_id,
            request_sha256,
            handoff,
            phase,
            baseline,
            candidate,
            candidate_activation_receipt_id,
            baseline_restoration_receipt_id,
            cancellation_requested,
            paired_results_sha256,
            created_at,
            updated_at,
        })
    }

    // Returns the outer BenchmarkManager job identity.
    pub const fn job_id(&self) -> &OperationId {
        &self.job_id
    }

    // Returns the exact outer verification request fingerprint.
    pub const fn request_sha256(&self) -> &Sha256Digest {
        &self.request_sha256
    }

    // Returns the Node-owned candidate handoff receipt.
    pub const fn handoff(&self) -> &BenchmarkVerificationHandoffReceipt {
        &self.handoff
    }

    // Returns current parent-only phase ordering.
    pub const fn phase(&self) -> BenchmarkVerificationPhase {
        self.phase
    }

    // Returns the baseline child state.
    pub const fn baseline(&self) -> &BenchmarkVerificationArmState {
        &self.baseline
    }

    // Returns candidate child state after private activation.
    pub const fn candidate(&self) -> Option<&BenchmarkVerificationArmState> {
        self.candidate.as_ref()
    }

    // Returns whether cancellation must win over a subsequently observed child success.
    pub const fn cancellation_requested(&self) -> bool {
        self.cancellation_requested
    }

    // Returns the exact paired result identity after both arms complete.
    pub const fn paired_results_sha256(&self) -> Option<&Sha256Digest> {
        self.paired_results_sha256.as_ref()
    }

    // Returns the exact baseline restoration identity after terminal recovery.
    pub const fn baseline_restoration_receipt_id(&self) -> Option<&Sha256Digest> {
        self.baseline_restoration_receipt_id.as_ref()
    }

    // Returns the exact candidate activation identity after Node handoff.
    pub const fn candidate_activation_receipt_id(&self) -> Option<&Sha256Digest> {
        self.candidate_activation_receipt_id.as_ref()
    }

    // Returns transaction creation time.
    pub const fn created_at(&self) -> UnixMilliseconds {
        self.created_at
    }

    // Returns latest committed transition time.
    pub const fn updated_at(&self) -> UnixMilliseconds {
        self.updated_at
    }
}

// Couples one transaction to its exact optimistic store revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionedBenchmarkVerificationTransaction {
    transaction: BenchmarkVerificationTransaction,
    revision: u64,
}

impl VersionedBenchmarkVerificationTransaction {
    // Creates one positive revision around a validated parent transaction.
    pub fn new(
        transaction: BenchmarkVerificationTransaction,
        revision: u64,
    ) -> Result<Self, BenchmarkStoreError> {
        if revision == 0 {
            return Err(BenchmarkStoreError::Corrupt);
        }
        Ok(Self {
            transaction,
            revision,
        })
    }

    // Returns the exact transaction snapshot.
    pub const fn transaction(&self) -> &BenchmarkVerificationTransaction {
        &self.transaction
    }

    // Returns the optimistic revision required for replacement.
    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

// Persists parent paired execution state independently of leaf handoff and publication journals.
pub trait BenchmarkVerificationStore: Send + Sync {
    // Reads one exact transaction without observing external state.
    fn read(
        &self,
        job_id: &OperationId,
    ) -> Result<Option<VersionedBenchmarkVerificationTransaction>, BenchmarkStoreError>;

    // Creates one transaction exactly once.
    fn create(
        &self,
        transaction: BenchmarkVerificationTransaction,
    ) -> Result<VersionedBenchmarkVerificationTransaction, BenchmarkStoreError>;

    // Replaces one exact revision atomically.
    fn replace(
        &self,
        transaction: BenchmarkVerificationTransaction,
        expected_revision: u64,
    ) -> Result<VersionedBenchmarkVerificationTransaction, BenchmarkStoreError>;
}

// Supplies monotonic positive wall time for parent transaction commits.
pub trait BenchmarkVerificationClock: Send + Sync {
    // Returns one exact positive Unix millisecond.
    fn now(&self) -> Result<UnixMilliseconds, BenchmarkError>;
}

// Reads positive parent transaction time from the operating-system wall clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemBenchmarkVerificationClock;

impl BenchmarkVerificationClock for SystemBenchmarkVerificationClock {
    // Rejects pre-epoch, zero, and overflowing wall time.
    fn now(&self) -> Result<UnixMilliseconds, BenchmarkError> {
        let milliseconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| BenchmarkError::provider("verification clock", "clock unavailable"))?
            .as_millis();
        let milliseconds = u64::try_from(milliseconds)
            .map_err(|_| BenchmarkError::provider("verification clock", "clock unavailable"))?;
        if milliseconds == 0 {
            return Err(BenchmarkError::provider(
                "verification clock",
                "clock unavailable",
            ));
        }
        Ok(UnixMilliseconds::new(milliseconds))
    }
}

// Runs both child arms and restores the baseline behind one ordinary BenchmarkManager execution.
pub struct PairedBenchmarkVerificationExecutionProvider {
    store: Arc<dyn BenchmarkVerificationStore>,
    handoff: Arc<dyn BenchmarkVerificationHandoffProvider>,
    children: Arc<dyn BenchmarkVerificationChildProvider>,
    clock: Arc<dyn BenchmarkVerificationClock>,
    mutation: Mutex<()>,
}

impl PairedBenchmarkVerificationExecutionProvider {
    // Creates one parent provider from explicit Benchmark-owned state and narrow leaf ports.
    pub const fn new(
        store: Arc<dyn BenchmarkVerificationStore>,
        handoff: Arc<dyn BenchmarkVerificationHandoffProvider>,
        children: Arc<dyn BenchmarkVerificationChildProvider>,
        clock: Arc<dyn BenchmarkVerificationClock>,
    ) -> Self {
        Self {
            store,
            handoff,
            children,
            clock,
            mutation: Mutex::new(()),
        }
    }

    // Returns paired child results for evidence finalization only after baseline restoration.
    pub fn results(
        &self,
        job_id: &OperationId,
    ) -> Result<
        (
            BenchmarkVerificationChildResult,
            BenchmarkVerificationChildResult,
        ),
        BenchmarkError,
    > {
        let state = self.store.read(job_id)?.ok_or(BenchmarkError::NotFound)?;
        let transaction = state.transaction();
        if !matches!(
            transaction.phase,
            BenchmarkVerificationPhase::Restored | BenchmarkVerificationPhase::RestorationFailed
        ) {
            return Err(BenchmarkError::InvalidTransition);
        }
        Ok((
            transaction
                .baseline
                .result
                .clone()
                .ok_or(BenchmarkError::InvalidTransition)?,
            transaction
                .candidate
                .as_ref()
                .and_then(|candidate| candidate.result.clone())
                .ok_or(BenchmarkError::InvalidTransition)?,
        ))
    }

    // Returns whether candidate execution crossed its durable activation-and-start boundary.
    pub fn candidate_execution_started(
        &self,
        job_id: &OperationId,
    ) -> Result<bool, BenchmarkError> {
        let state = self.store.read(job_id)?.ok_or(BenchmarkError::NotFound)?;
        let transaction = state.transaction();
        Ok(transaction.candidate_activation_receipt_id.is_some()
            && transaction
                .candidate
                .as_ref()
                .and_then(|candidate| candidate.running.as_ref())
                .is_some())
    }

    // Returns terminal baseline restoration state without consulting the mutable Node handoff.
    pub fn restoration_passed(&self, job_id: &OperationId) -> Result<bool, BenchmarkError> {
        let state = self.store.read(job_id)?.ok_or(BenchmarkError::NotFound)?;
        match state.transaction().phase {
            BenchmarkVerificationPhase::Restored => Ok(true),
            BenchmarkVerificationPhase::RestorationFailed => Ok(false),
            _ => Err(BenchmarkError::InvalidTransition),
        }
    }

    // Returns the exact durable Node handoff transaction retained for recovery observation.
    pub fn handoff_transaction_id(
        &self,
        job_id: &OperationId,
    ) -> Result<OperationId, BenchmarkError> {
        let state = self.store.read(job_id)?.ok_or(BenchmarkError::NotFound)?;
        Ok(state.transaction().handoff.transaction_id().clone())
    }

    // Returns the stable terminal parent second reused across finalization and publication replay.
    pub fn submitted_at_unix_seconds(&self, job_id: &OperationId) -> Result<u64, BenchmarkError> {
        let state = self.store.read(job_id)?.ok_or(BenchmarkError::NotFound)?;
        if !matches!(
            state.transaction().phase,
            BenchmarkVerificationPhase::Restored | BenchmarkVerificationPhase::RestorationFailed
        ) {
            return Err(BenchmarkError::InvalidTransition);
        }
        let seconds = state.transaction().updated_at.value() / 1_000;
        if seconds == 0 {
            return Err(BenchmarkError::InvalidTransition);
        }
        Ok(seconds)
    }

    // Returns the exact child requests whose independently sealed evidence forms the outer record.
    pub fn child_requests(
        &self,
        job_id: &OperationId,
    ) -> Result<(BenchmarkRequest, BenchmarkRequest), BenchmarkError> {
        let state = self.store.read(job_id)?.ok_or(BenchmarkError::NotFound)?;
        Ok((
            state.transaction().handoff.baseline_request().clone(),
            state.transaction().handoff.candidate_request().clone(),
        ))
    }

    // Acquires exclusive parent mutation ownership without blocking another manager turn.
    fn guard(&self) -> Result<std::sync::MutexGuard<'_, ()>, BenchmarkError> {
        match self.mutation.try_lock() {
            Ok(guard) => Ok(guard),
            Err(TryLockError::WouldBlock) => Err(BenchmarkError::Busy),
            Err(TryLockError::Poisoned(_)) => Err(BenchmarkError::provider(
                "verification state",
                "paired verification ownership is unavailable",
            )),
        }
    }

    // Returns one positive nondecreasing transaction time.
    fn now(&self) -> Result<UnixMilliseconds, BenchmarkError> {
        let now = self.clock.now()?;
        if now.value() == 0 {
            return Err(BenchmarkError::InvalidContract {
                reason: "verification clock returned zero",
            });
        }
        Ok(now)
    }

    // Persists one optimistic parent transition with monotonic time.
    fn commit(
        &self,
        mut transaction: BenchmarkVerificationTransaction,
        revision: u64,
    ) -> Result<VersionedBenchmarkVerificationTransaction, BenchmarkError> {
        let now = self.now()?;
        if now < transaction.updated_at {
            return Err(BenchmarkError::InvalidContract {
                reason: "verification clock moved backwards",
            });
        }
        transaction.updated_at = now;
        self.store
            .replace(transaction, revision)
            .map_err(Into::into)
    }

    // Drives parent transitions until one child observation or terminal restoration boundary.
    fn advance(
        &self,
        mut state: VersionedBenchmarkVerificationTransaction,
    ) -> Result<BenchmarkExecutionObservation, BenchmarkError> {
        loop {
            state = match state.transaction().phase {
                BenchmarkVerificationPhase::BaselineRunning => {
                    return self.observe_arm(state, BenchmarkVerificationArm::Baseline)
                }
                BenchmarkVerificationPhase::BaselineComplete => self.start_candidate(state)?,
                BenchmarkVerificationPhase::CandidateRunning => {
                    return self.observe_arm(state, BenchmarkVerificationArm::Candidate)
                }
                BenchmarkVerificationPhase::CandidateComplete => {
                    let mut transaction = state.transaction().clone();
                    transaction.phase = BenchmarkVerificationPhase::Restoring;
                    self.commit(transaction, state.revision())?
                }
                BenchmarkVerificationPhase::Restoring => return self.restore_and_finish(state),
                BenchmarkVerificationPhase::Restored => {
                    return Ok(BenchmarkExecutionObservation::Terminal(paired_outcome(
                        state.transaction(),
                    )?))
                }
                BenchmarkVerificationPhase::RestorationFailed => {
                    return Ok(BenchmarkExecutionObservation::Terminal(paired_outcome(
                        state.transaction(),
                    )?))
                }
                BenchmarkVerificationPhase::Prepared => {
                    return Err(BenchmarkError::InvalidTransition)
                }
            }
        }
    }

    // Observes one active child and commits its complete terminal result before the next arm.
    fn observe_arm(
        &self,
        state: VersionedBenchmarkVerificationTransaction,
        arm: BenchmarkVerificationArm,
    ) -> Result<BenchmarkExecutionObservation, BenchmarkError> {
        let transaction = state.transaction();
        let arm_state = match arm {
            BenchmarkVerificationArm::Baseline => &transaction.baseline,
            BenchmarkVerificationArm::Candidate => transaction
                .candidate
                .as_ref()
                .ok_or(BenchmarkError::InvalidTransition)?,
        };
        let running = arm_state
            .running
            .as_ref()
            .ok_or(BenchmarkError::InvalidTransition)?;
        let request = match arm {
            BenchmarkVerificationArm::Baseline => transaction.handoff.baseline_request(),
            BenchmarkVerificationArm::Candidate => transaction.handoff.candidate_request(),
        };
        match self.children.observe(
            transaction.job_id(),
            arm,
            request,
            &arm_state.prepared,
            running,
        )? {
            BenchmarkVerificationChildObservation::Running(progress) => Ok(
                BenchmarkExecutionObservation::Running(paired_progress(arm, &progress)?),
            ),
            BenchmarkVerificationChildObservation::Terminal(result) => {
                let mut transaction = transaction.clone();
                match arm {
                    BenchmarkVerificationArm::Baseline => {
                        transaction.baseline.result = Some(result);
                        transaction.phase = BenchmarkVerificationPhase::BaselineComplete;
                    }
                    BenchmarkVerificationArm::Candidate => {
                        transaction
                            .candidate
                            .as_mut()
                            .ok_or(BenchmarkError::InvalidTransition)?
                            .result = Some(result);
                        transaction.phase = BenchmarkVerificationPhase::CandidateComplete;
                    }
                }
                let state = self.commit(transaction, state.revision())?;
                self.advance(state)
            }
        }
    }

    // Activates the private candidate and starts its child only after baseline terminal commit.
    fn start_candidate(
        &self,
        state: VersionedBenchmarkVerificationTransaction,
    ) -> Result<VersionedBenchmarkVerificationTransaction, BenchmarkError> {
        let transaction = state.transaction();
        if transaction.cancellation_requested
            || !matches!(
                transaction
                    .baseline
                    .result
                    .as_ref()
                    .map(|value| value.outcome()),
                Some(BenchmarkExecutionOutcome::Succeeded { .. })
            )
        {
            let mut restoring = transaction.clone();
            restoring.phase = BenchmarkVerificationPhase::Restoring;
            return self.commit(restoring, state.revision());
        }
        let activation = self
            .handoff
            .activate_candidate(transaction.job_id(), &transaction.handoff)?;
        let prepared = self.children.prepare(
            transaction.job_id(),
            BenchmarkVerificationArm::Candidate,
            transaction.handoff.candidate_request(),
        )?;
        let running = self.children.start(
            transaction.job_id(),
            BenchmarkVerificationArm::Candidate,
            transaction.handoff.candidate_request(),
            &prepared,
        )?;
        let mut candidate = BenchmarkVerificationArmState::prepared(prepared);
        candidate.running = Some(running);
        let mut updated = transaction.clone();
        updated.candidate_activation_receipt_id = Some(activation);
        updated.candidate = Some(candidate);
        updated.phase = BenchmarkVerificationPhase::CandidateRunning;
        self.commit(updated, state.revision())
    }

    // Restores the exact baseline before reporting any paired terminal outcome to BenchmarkManager.
    fn restore_and_finish(
        &self,
        state: VersionedBenchmarkVerificationTransaction,
    ) -> Result<BenchmarkExecutionObservation, BenchmarkError> {
        let transaction = state.transaction();
        let restoration = match self
            .handoff
            .restore_baseline(transaction.job_id(), &transaction.handoff)
        {
            Ok(restoration) => restoration,
            Err(_) => {
                let mut failed = transaction.clone();
                failed.phase = BenchmarkVerificationPhase::RestorationFailed;
                let failed = self.commit(failed, state.revision())?;
                return Ok(BenchmarkExecutionObservation::Terminal(paired_outcome(
                    failed.transaction(),
                )?));
            }
        };
        let mut restored = transaction.clone();
        restored.baseline_restoration_receipt_id = Some(restoration);
        restored.paired_results_sha256 = paired_results_sha256(&restored)?;
        restored.phase = BenchmarkVerificationPhase::Restored;
        let restored = self.commit(restored, state.revision())?;
        Ok(BenchmarkExecutionObservation::Terminal(paired_outcome(
            restored.transaction(),
        )?))
    }
}

impl BenchmarkExecutionProvider for PairedBenchmarkVerificationExecutionProvider {
    // Prepares Node handoff and the baseline child exactly once.
    fn prepare(
        &self,
        job_id: &OperationId,
        request: &BenchmarkRequest,
        _authorization: &BenchmarkAuthorization,
    ) -> Result<PreparedBenchmark, BenchmarkError> {
        let _guard = self.guard()?;
        let request_sha256 = request.sha256()?;
        if !request.kind().is_verification() {
            return Err(BenchmarkError::InvalidContract {
                reason: "paired execution requires a verification request",
            });
        }
        if let Some(existing) = self.store.read(job_id)? {
            if existing.transaction().request_sha256 != request_sha256 {
                return Err(BenchmarkError::IdempotencyConflict);
            }
            return Ok(PreparedBenchmark::new(transaction_receipt_id(
                existing.transaction(),
            )?));
        }
        let handoff = self.handoff.prepare(job_id, request)?;
        if handoff.candidate_request() != request {
            return Err(BenchmarkError::AuthorizationDenied);
        }
        let prepared = self.children.prepare(
            job_id,
            BenchmarkVerificationArm::Baseline,
            handoff.baseline_request(),
        )?;
        let now = self.now()?;
        let transaction = BenchmarkVerificationTransaction {
            job_id: job_id.clone(),
            request_sha256,
            handoff,
            phase: BenchmarkVerificationPhase::Prepared,
            baseline: BenchmarkVerificationArmState::prepared(prepared),
            candidate: None,
            candidate_activation_receipt_id: None,
            baseline_restoration_receipt_id: None,
            cancellation_requested: false,
            paired_results_sha256: None,
            created_at: now,
            updated_at: now,
        };
        let created = self.store.create(transaction)?;
        Ok(PreparedBenchmark::new(transaction_receipt_id(
            created.transaction(),
        )?))
    }

    // Starts or reattaches to the baseline child and returns one parent running identity.
    fn start(
        &self,
        job_id: &OperationId,
        _request: &BenchmarkRequest,
        prepared: &PreparedBenchmark,
    ) -> Result<RunningBenchmark, BenchmarkError> {
        let _guard = self.guard()?;
        let state = self.store.read(job_id)?.ok_or(BenchmarkError::NotFound)?;
        if prepared.receipt_id() != &transaction_receipt_id(state.transaction())? {
            return Err(BenchmarkError::IdempotencyConflict);
        }
        if state.transaction().phase != BenchmarkVerificationPhase::Prepared {
            return Ok(RunningBenchmark::new(transaction_running_id(
                state.transaction(),
            )?));
        }
        let transaction = state.transaction();
        let running = self.children.start(
            job_id,
            BenchmarkVerificationArm::Baseline,
            transaction.handoff.baseline_request(),
            &transaction.baseline.prepared,
        )?;
        let mut updated = transaction.clone();
        updated.baseline.running = Some(running);
        updated.phase = BenchmarkVerificationPhase::BaselineRunning;
        let updated = self.commit(updated, state.revision())?;
        Ok(RunningBenchmark::new(transaction_running_id(
            updated.transaction(),
        )?))
    }

    // Advances one child observation or retries a durable activation/restoration boundary.
    fn observe(
        &self,
        job_id: &OperationId,
        running: &RunningBenchmark,
    ) -> Result<BenchmarkExecutionObservation, BenchmarkError> {
        let _guard = self.guard()?;
        let state = self.store.read(job_id)?.ok_or(BenchmarkError::NotFound)?;
        if running.receipt_id() != &transaction_running_id(state.transaction())? {
            return Err(BenchmarkError::IdempotencyConflict);
        }
        self.advance(state)
    }

    // Durably records cancellation before signaling only the active child.
    fn request_stop(
        &self,
        job_id: &OperationId,
        running: &RunningBenchmark,
    ) -> Result<(), BenchmarkError> {
        let _guard = self.guard()?;
        let state = self.store.read(job_id)?.ok_or(BenchmarkError::NotFound)?;
        if running.receipt_id() != &transaction_running_id(state.transaction())? {
            return Err(BenchmarkError::IdempotencyConflict);
        }
        let transaction = state.transaction();
        let active = match transaction.phase {
            BenchmarkVerificationPhase::BaselineRunning => Some((
                BenchmarkVerificationArm::Baseline,
                transaction.baseline.running.as_ref(),
            )),
            BenchmarkVerificationPhase::CandidateRunning => Some((
                BenchmarkVerificationArm::Candidate,
                transaction
                    .candidate
                    .as_ref()
                    .and_then(|candidate| candidate.running.as_ref()),
            )),
            _ => None,
        };
        let mut updated = transaction.clone();
        updated.cancellation_requested = true;
        let updated = self.commit(updated, state.revision())?;
        if let Some((arm, Some(child))) = active {
            self.children.request_stop(job_id, arm, child)?;
        }
        if updated.transaction().phase == BenchmarkVerificationPhase::BaselineComplete
            || updated.transaction().phase == BenchmarkVerificationPhase::CandidateComplete
        {
            let _ = self.advance(updated)?;
        }
        Ok(())
    }

    // Reuses the already committed baseline restoration and cleans every child/handoff resource.
    fn restore(
        &self,
        job_id: &OperationId,
        _request: &BenchmarkRequest,
        _prepared: &PreparedBenchmark,
        _running: Option<&RunningBenchmark>,
        _outcome: &BenchmarkExecutionOutcome,
    ) -> Result<BenchmarkRestoration, BenchmarkError> {
        let _guard = self.guard()?;
        let state = self.store.read(job_id)?.ok_or(BenchmarkError::NotFound)?;
        let state = if matches!(
            state.transaction().phase,
            BenchmarkVerificationPhase::Restored | BenchmarkVerificationPhase::RestorationFailed
        ) {
            state
        } else {
            let mut restoring = state.transaction().clone();
            restoring.phase = BenchmarkVerificationPhase::Restoring;
            let restoring = self.commit(restoring, state.revision())?;
            let _ = self.restore_and_finish(restoring)?;
            self.store.read(job_id)?.ok_or(BenchmarkError::NotFound)?
        };
        if state.transaction().phase == BenchmarkVerificationPhase::Restored {
            self.children
                .cleanup(job_id, BenchmarkVerificationArm::Baseline)?;
            self.children
                .cleanup(job_id, BenchmarkVerificationArm::Candidate)?;
            self.handoff.cleanup(job_id, &state.transaction().handoff)?;
        }
        Ok(BenchmarkRestoration::new(match state.transaction().phase {
            BenchmarkVerificationPhase::Restored => state
                .transaction()
                .baseline_restoration_receipt_id
                .clone()
                .ok_or(BenchmarkError::InvalidTransition)?,
            BenchmarkVerificationPhase::RestorationFailed => derived_digest(
                b"li-benchmark-verification-recovery-required-v1",
                &[
                    state.transaction().job_id().as_str(),
                    state.transaction().handoff.transaction_id().as_str(),
                ],
            )?,
            _ => return Err(BenchmarkError::InvalidTransition),
        }))
    }
}

// Derives one parent prepared receipt from immutable job, request, bundle, and handoff identities.
fn transaction_receipt_id(
    transaction: &BenchmarkVerificationTransaction,
) -> Result<Sha256Digest, BenchmarkError> {
    derived_digest(
        b"li-benchmark-verification-prepared-v1",
        &[
            transaction.job_id.as_str(),
            transaction.request_sha256.as_str(),
            transaction.handoff.receipt_id().as_str(),
            transaction.handoff.bundle_sha256().as_str(),
        ],
    )
}

// Derives one stable parent running receipt that remains unchanged across child-arm transitions.
fn transaction_running_id(
    transaction: &BenchmarkVerificationTransaction,
) -> Result<Sha256Digest, BenchmarkError> {
    derived_digest(
        b"li-benchmark-verification-running-v1",
        &[
            transaction.job_id.as_str(),
            transaction.request_sha256.as_str(),
        ],
    )
}

// Projects one child progress point into the exact two-arm aggregate cell space.
fn paired_progress(
    arm: BenchmarkVerificationArm,
    progress: &BenchmarkProgress,
) -> Result<BenchmarkProgress, BenchmarkError> {
    let total = progress
        .total_cells()
        .checked_mul(2)
        .ok_or(BenchmarkError::InvalidContract {
            reason: "paired verification progress overflowed",
        })?;
    let completed = match arm {
        BenchmarkVerificationArm::Baseline => progress.completed_cells(),
        BenchmarkVerificationArm::Candidate => progress
            .total_cells()
            .checked_add(progress.completed_cells())
            .ok_or(BenchmarkError::InvalidContract {
                reason: "paired verification progress overflowed",
            })?,
    };
    BenchmarkProgress::new(
        li_core_interface::TechnicalName::parse(match arm {
            BenchmarkVerificationArm::Baseline => "verification-baseline",
            BenchmarkVerificationArm::Candidate => "verification-candidate",
        })
        .map_err(|_| BenchmarkError::InvalidContract {
            reason: "paired verification progress phase is invalid",
        })?,
        completed,
        total,
    )
}

// Derives one paired results identity only after both arm result contracts agree.
fn paired_results_sha256(
    transaction: &BenchmarkVerificationTransaction,
) -> Result<Option<Sha256Digest>, BenchmarkError> {
    let Some(baseline) = transaction.baseline.result.as_ref() else {
        return Ok(None);
    };
    let Some(candidate) = transaction
        .candidate
        .as_ref()
        .and_then(|candidate| candidate.result.as_ref())
    else {
        return Ok(None);
    };
    if baseline.total_cells != candidate.total_cells {
        return Err(BenchmarkError::InvalidContract {
            reason: "paired verification child contracts differ",
        });
    }
    let values = [
        baseline.evidence.evidence().evidence_id().as_str(),
        baseline.evidence.evidence().results_sha256().as_str(),
        candidate.evidence.evidence().evidence_id().as_str(),
        candidate.evidence.evidence().results_sha256().as_str(),
    ];
    derived_digest(b"li-benchmark-verification-results-v1", &values).map(Some)
}

// Returns the final paired outcome only after exact baseline restoration is committed.
fn paired_outcome(
    transaction: &BenchmarkVerificationTransaction,
) -> Result<BenchmarkExecutionOutcome, BenchmarkError> {
    if transaction.phase == BenchmarkVerificationPhase::RestorationFailed {
        let raw_evidence_sha256 = transaction
            .candidate
            .as_ref()
            .and_then(|candidate| candidate.result.as_ref())
            .and_then(|candidate| candidate.outcome.raw_evidence_sha256())
            .or_else(|| {
                transaction
                    .baseline
                    .result
                    .as_ref()
                    .and_then(|baseline| baseline.outcome.raw_evidence_sha256())
            })
            .cloned();
        return Ok(BenchmarkExecutionOutcome::Failed {
            raw_evidence_sha256,
            failure: crate::BenchmarkFailure::new(
                crate::BenchmarkFailureCategory::Restoration,
                "restoration",
                "baseline restoration requires recovery",
            )?,
        });
    }
    if transaction.phase != BenchmarkVerificationPhase::Restored
        || transaction.baseline_restoration_receipt_id.is_none()
    {
        return Err(BenchmarkError::InvalidTransition);
    }
    let baseline = transaction
        .baseline
        .result
        .as_ref()
        .ok_or(BenchmarkError::InvalidTransition)?;
    if transaction.cancellation_requested {
        return Ok(BenchmarkExecutionOutcome::Cancelled {
            raw_evidence_sha256: baseline.outcome.raw_evidence_sha256().cloned(),
        });
    }
    if let Some(failure) = baseline.outcome.failure() {
        return Ok(BenchmarkExecutionOutcome::Failed {
            raw_evidence_sha256: baseline.outcome.raw_evidence_sha256().cloned(),
            failure: failure.clone(),
        });
    }
    let candidate = transaction
        .candidate
        .as_ref()
        .and_then(|candidate| candidate.result.as_ref())
        .ok_or(BenchmarkError::InvalidTransition)?;
    if let Some(failure) = candidate.outcome.failure() {
        return Ok(BenchmarkExecutionOutcome::Failed {
            raw_evidence_sha256: candidate.outcome.raw_evidence_sha256().cloned(),
            failure: failure.clone(),
        });
    }
    if matches!(
        candidate.outcome,
        BenchmarkExecutionOutcome::Cancelled { .. }
    ) {
        return Ok(BenchmarkExecutionOutcome::Cancelled {
            raw_evidence_sha256: candidate.outcome.raw_evidence_sha256().cloned(),
        });
    }
    let results_sha256 = transaction
        .paired_results_sha256
        .clone()
        .ok_or(BenchmarkError::InvalidTransition)?;
    let raw_evidence_sha256 = derived_digest(
        b"li-benchmark-verification-raw-evidence-v1",
        &[
            baseline.evidence.evidence().evidence_id().as_str(),
            candidate.evidence.evidence().evidence_id().as_str(),
        ],
    )?;
    Ok(BenchmarkExecutionOutcome::Succeeded {
        raw_evidence_sha256,
        results_sha256,
        record_schema: BenchmarkRecordSchema::CommunityVerificationV1,
    })
}

// Derives one domain-separated digest from exact ordered text fields.
fn derived_digest(domain: &[u8], values: &[&str]) -> Result<Sha256Digest, BenchmarkError> {
    let mut digest = Sha256::new();
    digest.update((domain.len() as u64).to_be_bytes());
    digest.update(domain);
    for value in values {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    Sha256Digest::parse(&format!("{:x}", digest.finalize())).map_err(|_| {
        BenchmarkError::InvalidContract {
            reason: "paired verification identity could not be derived",
        }
    })
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    use li_core_interface::{
        InstallationId, LogicalModelName, PlacementGroupId, RuntimeCandidateId,
        RuntimeInstallationId,
    };

    use super::*;
    use crate::{
        BenchmarkEvidence, BenchmarkFailure, BenchmarkFailureCategory, BenchmarkGitRevision,
        BenchmarkKind, BenchmarkScope, BenchmarkSignature, BenchmarkSubject,
    };

    #[derive(Default)]
    struct StoreMock(Mutex<BTreeMap<String, VersionedBenchmarkVerificationTransaction>>);

    impl BenchmarkVerificationStore for StoreMock {
        // Returns one exact in-memory transaction snapshot.
        fn read(
            &self,
            job_id: &OperationId,
        ) -> Result<Option<VersionedBenchmarkVerificationTransaction>, BenchmarkStoreError>
        {
            Ok(self.0.lock().expect("store").get(job_id.as_str()).cloned())
        }

        // Creates one transaction once at revision one.
        fn create(
            &self,
            transaction: BenchmarkVerificationTransaction,
        ) -> Result<VersionedBenchmarkVerificationTransaction, BenchmarkStoreError> {
            let mut values = self.0.lock().expect("store");
            if values.contains_key(transaction.job_id().as_str()) {
                return Err(BenchmarkStoreError::Conflict);
            }
            let versioned = VersionedBenchmarkVerificationTransaction::new(transaction, 1)?;
            values.insert(
                versioned.transaction().job_id().as_str().to_string(),
                versioned.clone(),
            );
            Ok(versioned)
        }

        // Replaces only one exact optimistic revision.
        fn replace(
            &self,
            transaction: BenchmarkVerificationTransaction,
            expected_revision: u64,
        ) -> Result<VersionedBenchmarkVerificationTransaction, BenchmarkStoreError> {
            let mut values = self.0.lock().expect("store");
            let current = values
                .get(transaction.job_id().as_str())
                .ok_or(BenchmarkStoreError::Unavailable)?;
            if current.revision() != expected_revision {
                return Err(BenchmarkStoreError::Conflict);
            }
            let versioned =
                VersionedBenchmarkVerificationTransaction::new(transaction, expected_revision + 1)?;
            values.insert(
                versioned.transaction().job_id().as_str().to_string(),
                versioned.clone(),
            );
            Ok(versioned)
        }
    }

    struct ClockMock(AtomicU64);

    impl BenchmarkVerificationClock for ClockMock {
        // Returns one deterministic increasing transition time.
        fn now(&self) -> Result<UnixMilliseconds, BenchmarkError> {
            Ok(UnixMilliseconds::new(self.0.fetch_add(1, Ordering::SeqCst)))
        }
    }

    struct HandoffMock {
        receipt: BenchmarkVerificationHandoffReceipt,
        activation_failures: AtomicUsize,
        restoration_failures: AtomicUsize,
        activations: AtomicUsize,
        restorations: AtomicUsize,
        cleanups: AtomicUsize,
    }

    impl BenchmarkVerificationHandoffProvider for HandoffMock {
        // Returns one fixed exact Node-owned handoff.
        fn prepare(
            &self,
            _job_id: &OperationId,
            _request: &BenchmarkRequest,
        ) -> Result<BenchmarkVerificationHandoffReceipt, BenchmarkError> {
            Ok(self.receipt.clone())
        }

        // Records private candidate activation or returns one selected transient failure.
        fn activate_candidate(
            &self,
            _job_id: &OperationId,
            _receipt: &BenchmarkVerificationHandoffReceipt,
        ) -> Result<Sha256Digest, BenchmarkError> {
            self.activations.fetch_add(1, Ordering::SeqCst);
            if self
                .activation_failures
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                    value.checked_sub(1)
                })
                .is_ok()
            {
                return Err(BenchmarkError::provider("handoff", "activation failed"));
            }
            Ok(digest('a'))
        }

        // Records exact baseline restoration or returns one selected transient failure.
        fn restore_baseline(
            &self,
            _job_id: &OperationId,
            _receipt: &BenchmarkVerificationHandoffReceipt,
        ) -> Result<Sha256Digest, BenchmarkError> {
            self.restorations.fetch_add(1, Ordering::SeqCst);
            if self
                .restoration_failures
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                    value.checked_sub(1)
                })
                .is_ok()
            {
                return Err(BenchmarkError::provider("handoff", "restoration failed"));
            }
            Ok(digest('b'))
        }

        // Records terminal candidate-owned cleanup.
        fn cleanup(
            &self,
            _job_id: &OperationId,
            _receipt: &BenchmarkVerificationHandoffReceipt,
        ) -> Result<(), BenchmarkError> {
            self.cleanups.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    struct ChildMock {
        baseline: Mutex<VecDeque<BenchmarkVerificationChildObservation>>,
        candidate: Mutex<VecDeque<BenchmarkVerificationChildObservation>>,
        starts: Mutex<Vec<BenchmarkVerificationArm>>,
        stops: Mutex<Vec<BenchmarkVerificationArm>>,
        cleanups: Mutex<Vec<BenchmarkVerificationArm>>,
    }

    impl BenchmarkVerificationChildProvider for ChildMock {
        // Returns one deterministic arm-specific preparation receipt.
        fn prepare(
            &self,
            _job_id: &OperationId,
            arm: BenchmarkVerificationArm,
            _request: &BenchmarkRequest,
        ) -> Result<PreparedBenchmark, BenchmarkError> {
            Ok(PreparedBenchmark::new(match arm {
                BenchmarkVerificationArm::Baseline => digest('1'),
                BenchmarkVerificationArm::Candidate => digest('2'),
            }))
        }

        // Records one idempotent arm start and returns its deterministic task identity.
        fn start(
            &self,
            _job_id: &OperationId,
            arm: BenchmarkVerificationArm,
            _request: &BenchmarkRequest,
            _prepared: &PreparedBenchmark,
        ) -> Result<RunningBenchmark, BenchmarkError> {
            self.starts.lock().expect("starts").push(arm);
            Ok(RunningBenchmark::new(match arm {
                BenchmarkVerificationArm::Baseline => digest('3'),
                BenchmarkVerificationArm::Candidate => digest('4'),
            }))
        }

        // Returns the next exact arm observation.
        fn observe(
            &self,
            _job_id: &OperationId,
            arm: BenchmarkVerificationArm,
            _request: &BenchmarkRequest,
            _prepared: &PreparedBenchmark,
            _running: &RunningBenchmark,
        ) -> Result<BenchmarkVerificationChildObservation, BenchmarkError> {
            match arm {
                BenchmarkVerificationArm::Baseline => &self.baseline,
                BenchmarkVerificationArm::Candidate => &self.candidate,
            }
            .lock()
            .expect("observations")
            .pop_front()
            .ok_or_else(|| BenchmarkError::provider("child", "observation unavailable"))
        }

        // Records one exact active-arm stop request.
        fn request_stop(
            &self,
            _job_id: &OperationId,
            arm: BenchmarkVerificationArm,
            _running: &RunningBenchmark,
        ) -> Result<(), BenchmarkError> {
            self.stops.lock().expect("stops").push(arm);
            Ok(())
        }

        // Records one exact terminal arm cleanup.
        fn cleanup(
            &self,
            _job_id: &OperationId,
            arm: BenchmarkVerificationArm,
        ) -> Result<(), BenchmarkError> {
            self.cleanups.lock().expect("cleanups").push(arm);
            Ok(())
        }
    }

    // Returns one exact lowercase digest fixture.
    fn digest(character: char) -> Sha256Digest {
        Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
    }

    // Returns one exact candidate or baseline benchmark subject.
    fn subject(character: char) -> BenchmarkSubject {
        BenchmarkSubject::new(
            InstallationId::parse(&"5".repeat(64)).expect("installation"),
            RuntimeInstallationId::parse(&character.to_string().repeat(32)).expect("runtime"),
            LogicalModelName::parse("model").expect("model"),
            PlacementGroupId::parse(&character.to_string().repeat(32)).expect("group"),
            digest(character),
            digest('6'),
            digest('7'),
        )
    }

    // Returns one complete local baseline request.
    fn baseline_request() -> BenchmarkRequest {
        BenchmarkRequest::new(BenchmarkKind::Local, BenchmarkScope::Complete, subject('8'))
            .expect("baseline")
    }

    // Returns one complete community candidate request.
    fn candidate_request() -> BenchmarkRequest {
        BenchmarkRequest::new(
            BenchmarkKind::verification(
                41,
                BenchmarkGitRevision::parse(&"a".repeat(40)).expect("head"),
                RuntimeCandidateId::parse("vllm--owner--model--spark").expect("candidate"),
                OperationId::parse(&"d".repeat(32)).expect("transaction"),
                digest('e'),
                digest('f'),
                73,
                digest('9'),
                None,
            )
            .expect("kind"),
            BenchmarkScope::Complete,
            subject('9'),
        )
        .expect("candidate")
    }

    // Returns one exact successful or blocking child terminal result.
    fn child_result(character: char, failure: bool) -> BenchmarkVerificationChildResult {
        let (outcome, schema, results) = if failure {
            (
                BenchmarkExecutionOutcome::Failed {
                    raw_evidence_sha256: Some(digest(character)),
                    failure: BenchmarkFailure::new(
                        BenchmarkFailureCategory::Crash,
                        "child",
                        "child failed",
                    )
                    .expect("failure"),
                },
                BenchmarkRecordSchema::CoreLocalFailureV1,
                digest(character),
            )
        } else {
            (
                BenchmarkExecutionOutcome::Succeeded {
                    raw_evidence_sha256: digest(character),
                    results_sha256: digest(character),
                    record_schema: BenchmarkRecordSchema::OciExecutionPayloadV7,
                },
                BenchmarkRecordSchema::OciExecutionPayloadV7,
                digest(character),
            )
        };
        BenchmarkVerificationChildResult::new(
            outcome,
            BenchmarkTelemetryReceipt::new(digest('a'), 2),
            BenchmarkRestoration::new(digest('b')),
            SealedBenchmarkEvidence::new(
                BenchmarkEvidence::new(digest(character), results, schema, 100).expect("evidence"),
                BenchmarkSignature::new(digest('c'), "c2lnbmF0dXJl").expect("signature"),
            ),
            2,
        )
        .expect("result")
    }

    // Returns one exact signed candidate failure for the requested public blocking category.
    fn child_failure_result(
        character: char,
        category: BenchmarkFailureCategory,
    ) -> BenchmarkVerificationChildResult {
        BenchmarkVerificationChildResult::new(
            BenchmarkExecutionOutcome::Failed {
                raw_evidence_sha256: Some(digest(character)),
                failure: BenchmarkFailure::new(category, "candidate", "candidate failed")
                    .expect("failure"),
            },
            BenchmarkTelemetryReceipt::new(digest('a'), 2),
            BenchmarkRestoration::new(digest('b')),
            SealedBenchmarkEvidence::new(
                BenchmarkEvidence::new(
                    digest(character),
                    digest(character),
                    BenchmarkRecordSchema::CoreLocalFailureV1,
                    100,
                )
                .expect("evidence"),
                BenchmarkSignature::new(digest('c'), "c2lnbmF0dXJl").expect("signature"),
            ),
            2,
        )
        .expect("result")
    }

    // Creates one parent provider and exposes its deterministic leaf mocks.
    fn harness(
        baseline: Vec<BenchmarkVerificationChildObservation>,
        candidate: Vec<BenchmarkVerificationChildObservation>,
        activation_failures: usize,
        restoration_failures: usize,
    ) -> (
        Arc<StoreMock>,
        Arc<HandoffMock>,
        Arc<ChildMock>,
        PairedBenchmarkVerificationExecutionProvider,
    ) {
        let receipt = BenchmarkVerificationHandoffReceipt::new(
            OperationId::parse(&"d".repeat(32)).expect("transaction"),
            digest('d'),
            digest('e'),
            baseline_request(),
            candidate_request(),
        )
        .expect("handoff");
        let store = Arc::new(StoreMock::default());
        let handoff = Arc::new(HandoffMock {
            receipt,
            activation_failures: AtomicUsize::new(activation_failures),
            restoration_failures: AtomicUsize::new(restoration_failures),
            activations: AtomicUsize::new(0),
            restorations: AtomicUsize::new(0),
            cleanups: AtomicUsize::new(0),
        });
        let children = Arc::new(ChildMock {
            baseline: Mutex::new(baseline.into()),
            candidate: Mutex::new(candidate.into()),
            starts: Mutex::new(Vec::new()),
            stops: Mutex::new(Vec::new()),
            cleanups: Mutex::new(Vec::new()),
        });
        let provider = PairedBenchmarkVerificationExecutionProvider::new(
            store.clone(),
            handoff.clone(),
            children.clone(),
            Arc::new(ClockMock(AtomicU64::new(1_000))),
        );
        (store, handoff, children, provider)
    }

    // Prepares and starts one exact outer request.
    fn start(
        provider: &PairedBenchmarkVerificationExecutionProvider,
    ) -> (OperationId, PreparedBenchmark, RunningBenchmark) {
        let job = OperationId::parse(&"f".repeat(32)).expect("job");
        let request = candidate_request();
        let prepared = provider
            .prepare(&job, &request, &BenchmarkAuthorization::new(digest('1')))
            .expect("prepare");
        let running = provider.start(&job, &request, &prepared).expect("start");
        (job, prepared, running)
    }

    #[test]
    // Runs baseline then candidate, restores first, and exposes paired evidence only afterward.
    fn paired_execution_completes_both_arms_before_terminal_success() {
        let (store, handoff, children, provider) = harness(
            vec![BenchmarkVerificationChildObservation::Terminal(
                child_result('1', false),
            )],
            vec![
                BenchmarkVerificationChildObservation::Running(
                    BenchmarkProgress::new(
                        li_core_interface::TechnicalName::parse("measuring").expect("phase"),
                        1,
                        2,
                    )
                    .expect("progress"),
                ),
                BenchmarkVerificationChildObservation::Terminal(child_result('2', false)),
            ],
            0,
            0,
        );
        let (job, prepared, running) = start(&provider);
        let progress = provider
            .observe(&job, &running)
            .expect("candidate progress");
        let BenchmarkExecutionObservation::Running(progress) = progress else {
            panic!("running");
        };
        assert_eq!(progress.completed_cells(), 3);
        assert_eq!(progress.total_cells(), 4);
        let terminal = provider.observe(&job, &running).expect("terminal");
        assert!(matches!(
            terminal,
            BenchmarkExecutionObservation::Terminal(BenchmarkExecutionOutcome::Succeeded {
                record_schema: BenchmarkRecordSchema::CommunityVerificationV1,
                ..
            })
        ));
        let (baseline, candidate) = provider.results(&job).expect("results");
        assert_eq!(baseline.evidence().evidence().evidence_id(), &digest('1'));
        assert_eq!(candidate.evidence().evidence().evidence_id(), &digest('2'));
        provider
            .restore(
                &job,
                &candidate_request(),
                &prepared,
                Some(&running),
                match &terminal {
                    BenchmarkExecutionObservation::Terminal(outcome) => outcome,
                    _ => unreachable!(),
                },
            )
            .expect("cleanup");
        assert_eq!(handoff.restorations.load(Ordering::SeqCst), 1);
        assert_eq!(handoff.cleanups.load(Ordering::SeqCst), 1);
        assert_eq!(
            children.cleanups.lock().expect("cleanups").as_slice(),
            [
                BenchmarkVerificationArm::Baseline,
                BenchmarkVerificationArm::Candidate
            ]
        );
        assert_eq!(
            store
                .read(&job)
                .expect("state")
                .expect("transaction")
                .transaction()
                .phase(),
            BenchmarkVerificationPhase::Restored
        );
    }

    #[test]
    // Commits baseline terminal before retrying candidate activation after one transient failure.
    fn candidate_activation_failure_retries_without_rerunning_baseline() {
        let (store, handoff, children, provider) = harness(
            vec![BenchmarkVerificationChildObservation::Terminal(
                child_result('1', false),
            )],
            vec![BenchmarkVerificationChildObservation::Terminal(
                child_result('2', false),
            )],
            1,
            0,
        );
        let (job, _, running) = start(&provider);
        assert!(provider.observe(&job, &running).is_err());
        assert_eq!(
            store
                .read(&job)
                .expect("state")
                .expect("transaction")
                .transaction()
                .phase(),
            BenchmarkVerificationPhase::BaselineComplete
        );
        let terminal = provider.observe(&job, &running).expect("retry");
        assert!(matches!(
            terminal,
            BenchmarkExecutionObservation::Terminal(_)
        ));
        assert_eq!(handoff.activations.load(Ordering::SeqCst), 2);
        assert_eq!(
            children.starts.lock().expect("starts").as_slice(),
            [
                BenchmarkVerificationArm::Baseline,
                BenchmarkVerificationArm::Candidate
            ]
        );
    }

    #[test]
    // Makes restoration failure publishable while retaining the exact handoff for later recovery.
    fn restoration_failure_becomes_terminal_recovery_required_evidence() {
        let (store, handoff, children, provider) = harness(
            vec![BenchmarkVerificationChildObservation::Terminal(
                child_result('1', false),
            )],
            vec![BenchmarkVerificationChildObservation::Terminal(
                child_result('2', false),
            )],
            0,
            1,
        );
        let (job, prepared, running) = start(&provider);
        let terminal = provider.observe(&job, &running).expect("terminal failure");
        assert!(matches!(
            &terminal,
            BenchmarkExecutionObservation::Terminal(BenchmarkExecutionOutcome::Failed {
                failure,
                ..
            }) if failure.category() == crate::BenchmarkFailureCategory::Restoration
        ));
        assert_eq!(
            store
                .read(&job)
                .expect("state")
                .expect("transaction")
                .transaction()
                .phase(),
            BenchmarkVerificationPhase::RestorationFailed
        );
        assert!(!provider.restoration_passed(&job).expect("restoration"));
        assert_eq!(
            provider.handoff_transaction_id(&job).expect("handoff"),
            OperationId::parse(&"d".repeat(32)).expect("transaction")
        );
        provider.results(&job).expect("paired evidence");
        provider
            .restore(
                &job,
                &candidate_request(),
                &prepared,
                Some(&running),
                match &terminal {
                    BenchmarkExecutionObservation::Terminal(outcome) => outcome,
                    _ => unreachable!(),
                },
            )
            .expect("recovery-required receipt");
        assert_eq!(handoff.restorations.load(Ordering::SeqCst), 1);
        assert_eq!(handoff.cleanups.load(Ordering::SeqCst), 0);
        assert!(children.cleanups.lock().expect("cleanups").is_empty());
        assert_eq!(
            children.starts.lock().expect("starts").as_slice(),
            [
                BenchmarkVerificationArm::Baseline,
                BenchmarkVerificationArm::Candidate
            ]
        );
    }

    #[test]
    // Preserves every candidate safety/correctness failure after the durable candidate boundary.
    fn candidate_failure_categories_restore_then_remain_publishable() {
        for category in [
            BenchmarkFailureCategory::OutputValidation,
            BenchmarkFailureCategory::OutOfMemory,
            BenchmarkFailureCategory::ProtectionTrip,
            BenchmarkFailureCategory::Crash,
        ] {
            let (_store, handoff, _children, provider) = harness(
                vec![BenchmarkVerificationChildObservation::Terminal(
                    child_result('1', false),
                )],
                vec![BenchmarkVerificationChildObservation::Terminal(
                    child_failure_result('2', category),
                )],
                0,
                0,
            );
            let (job, _, running) = start(&provider);
            let terminal = provider.observe(&job, &running).expect("terminal");
            assert!(matches!(
                terminal,
                BenchmarkExecutionObservation::Terminal(BenchmarkExecutionOutcome::Failed {
                    failure,
                    ..
                }) if failure.category() == category
            ));
            assert!(provider
                .candidate_execution_started(&job)
                .expect("candidate"));
            assert!(provider.restoration_passed(&job).expect("restoration"));
            provider.results(&job).expect("paired results");
            assert_eq!(handoff.restorations.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    // Makes cancellation durable, stops the active child, skips candidate, and restores baseline.
    fn cancellation_wins_over_a_late_baseline_success() {
        let (_store, handoff, children, provider) = harness(
            vec![BenchmarkVerificationChildObservation::Terminal(
                child_result('1', false),
            )],
            Vec::new(),
            0,
            0,
        );
        let (job, _, running) = start(&provider);
        provider.request_stop(&job, &running).expect("stop");
        let terminal = provider.observe(&job, &running).expect("terminal");
        assert!(matches!(
            terminal,
            BenchmarkExecutionObservation::Terminal(BenchmarkExecutionOutcome::Cancelled { .. })
        ));
        assert_eq!(
            children.stops.lock().expect("stops").as_slice(),
            [BenchmarkVerificationArm::Baseline]
        );
        assert_eq!(handoff.activations.load(Ordering::SeqCst), 0);
        assert_eq!(handoff.restorations.load(Ordering::SeqCst), 1);
    }

    #[test]
    // Distinguishes cancellation after candidate start from a pre-candidate local cancellation.
    fn cancellation_after_candidate_start_retains_publishable_paired_evidence() {
        let (_store, handoff, children, provider) = harness(
            vec![BenchmarkVerificationChildObservation::Terminal(
                child_result('1', false),
            )],
            vec![
                BenchmarkVerificationChildObservation::Running(
                    BenchmarkProgress::new(
                        li_core_interface::TechnicalName::parse("measuring").expect("phase"),
                        0,
                        2,
                    )
                    .expect("progress"),
                ),
                BenchmarkVerificationChildObservation::Terminal(child_result('2', false)),
            ],
            0,
            0,
        );
        let (job, _, running) = start(&provider);
        assert!(matches!(
            provider.observe(&job, &running).expect("candidate running"),
            BenchmarkExecutionObservation::Running(_)
        ));
        provider.request_stop(&job, &running).expect("stop");
        assert!(matches!(
            provider.observe(&job, &running).expect("terminal"),
            BenchmarkExecutionObservation::Terminal(BenchmarkExecutionOutcome::Cancelled { .. })
        ));
        assert!(provider
            .candidate_execution_started(&job)
            .expect("candidate"));
        provider.results(&job).expect("paired evidence");
        assert_eq!(
            children.stops.lock().expect("stops").as_slice(),
            [BenchmarkVerificationArm::Candidate]
        );
        assert_eq!(handoff.restorations.load(Ordering::SeqCst), 1);
    }

    #[test]
    // Reconstructs from the shared durable store while a candidate child is already running.
    fn restart_resumes_candidate_without_restarting_either_child() {
        let (store, handoff, children, first) = harness(
            vec![BenchmarkVerificationChildObservation::Terminal(
                child_result('1', false),
            )],
            vec![
                BenchmarkVerificationChildObservation::Running(
                    BenchmarkProgress::new(
                        li_core_interface::TechnicalName::parse("measuring").expect("phase"),
                        0,
                        2,
                    )
                    .expect("progress"),
                ),
                BenchmarkVerificationChildObservation::Terminal(child_result('2', false)),
            ],
            0,
            0,
        );
        let (job, _, running) = start(&first);
        assert!(matches!(
            first.observe(&job, &running).expect("progress"),
            BenchmarkExecutionObservation::Running(_)
        ));
        let restarted = PairedBenchmarkVerificationExecutionProvider::new(
            store.clone(),
            handoff.clone(),
            children.clone(),
            Arc::new(ClockMock(AtomicU64::new(2_000))),
        );
        assert!(matches!(
            restarted.observe(&job, &running).expect("terminal"),
            BenchmarkExecutionObservation::Terminal(BenchmarkExecutionOutcome::Succeeded { .. })
        ));
        let submitted_at = restarted
            .submitted_at_unix_seconds(&job)
            .expect("submitted time");
        let reloaded = PairedBenchmarkVerificationExecutionProvider::new(
            store,
            handoff,
            children.clone(),
            Arc::new(ClockMock(AtomicU64::new(3_000))),
        );
        assert_eq!(
            reloaded
                .submitted_at_unix_seconds(&job)
                .expect("restart submitted time"),
            submitted_at
        );
        assert_eq!(
            children.starts.lock().expect("starts").as_slice(),
            [
                BenchmarkVerificationArm::Baseline,
                BenchmarkVerificationArm::Candidate
            ]
        );
    }

    #[test]
    // Rejects evidence/result identity drift at the child boundary before parent persistence.
    fn child_result_rejects_evidence_identity_drift() {
        let outcome = BenchmarkExecutionOutcome::Succeeded {
            raw_evidence_sha256: digest('1'),
            results_sha256: digest('1'),
            record_schema: BenchmarkRecordSchema::OciExecutionPayloadV7,
        };
        assert_eq!(
            BenchmarkVerificationChildResult::new(
                outcome,
                BenchmarkTelemetryReceipt::new(digest('2'), 1),
                BenchmarkRestoration::new(digest('3')),
                SealedBenchmarkEvidence::new(
                    BenchmarkEvidence::new(
                        digest('4'),
                        digest('5'),
                        BenchmarkRecordSchema::OciExecutionPayloadV7,
                        10,
                    )
                    .expect("evidence"),
                    BenchmarkSignature::new(digest('6'), "c2lnbmF0dXJl").expect("signature"),
                ),
                1,
            ),
            Err(BenchmarkError::InvalidContract {
                reason: "verification child result is incomplete or identity-mismatched"
            })
        );
    }

    #[test]
    // Rejects a baseline whose benchmark or target contract cannot be compared to the candidate.
    fn handoff_rejects_incomparable_baseline_contract() {
        let incompatible = BenchmarkRequest::new(
            BenchmarkKind::Local,
            BenchmarkScope::Complete,
            BenchmarkSubject::new(
                InstallationId::parse(&"5".repeat(64)).expect("installation"),
                RuntimeInstallationId::parse(&"8".repeat(32)).expect("runtime"),
                LogicalModelName::parse("model").expect("model"),
                PlacementGroupId::parse(&"8".repeat(32)).expect("group"),
                digest('8'),
                digest('0'),
                digest('7'),
            ),
        )
        .expect("baseline");
        assert_eq!(
            BenchmarkVerificationHandoffReceipt::new(
                OperationId::parse(&"d".repeat(32)).expect("transaction"),
                digest('d'),
                digest('e'),
                incompatible,
                candidate_request(),
            ),
            Err(BenchmarkError::InvalidContract {
                reason: "verification handoff requests are invalid",
            })
        );
    }
}
