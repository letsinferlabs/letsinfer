// SPDX-License-Identifier: AGPL-3.0-only

mod li_benchmark_authorization;
mod li_benchmark_contract;
mod li_benchmark_database;
mod li_benchmark_evidence;
mod li_benchmark_execution;
mod li_benchmark_failure_evidence;
mod li_benchmark_lifecycle;
mod li_benchmark_record;
mod li_benchmark_run_plan;
mod li_benchmark_signing;
mod li_benchmark_telemetry;
mod li_benchmark_telemetry_codec;
mod li_benchmark_verification;
mod li_benchmark_verification_database;

pub use li_benchmark_authorization::{
    BenchmarkAuthorizationSource, BenchmarkCommunityAuthority, BenchmarkNodeAuthority,
    BoundBenchmarkAuthorizationProvider,
};
pub use li_benchmark_contract::{
    benchmark_job_id, replay_sha256, BenchmarkAuthorization, BenchmarkAuthorizationProvider,
    BenchmarkChange, BenchmarkClock, BenchmarkCommunityVerificationDocument,
    BenchmarkCommunityVerificationDocumentProvider, BenchmarkDisposition, BenchmarkEvidence,
    BenchmarkEvidenceProvider, BenchmarkExecutionObservation, BenchmarkExecutionOutcome,
    BenchmarkExecutionProvider, BenchmarkFailure, BenchmarkFailureCategory, BenchmarkGitRevision,
    BenchmarkJobPhase, BenchmarkJobRecord, BenchmarkKind, BenchmarkProgress, BenchmarkPublication,
    BenchmarkPublicationProvider, BenchmarkPublicationRequest, BenchmarkRecordSchema,
    BenchmarkRequest, BenchmarkRestoration, BenchmarkScope, BenchmarkSignature,
    BenchmarkSigningProvider, BenchmarkStore, BenchmarkStoreError, BenchmarkSubject,
    BenchmarkTelemetryProvider, BenchmarkTelemetryReceipt, BenchmarkTerminalIntent,
    NoopBenchmarkPublicationProvider, PreparedBenchmark, RunningBenchmark, SealedBenchmarkEvidence,
    VersionedBenchmarkJob,
};
pub use li_benchmark_database::DatabaseBenchmarkStore;
pub use li_benchmark_evidence::{
    canonical_benchmark_json_bytes, validate_benchmark_evidence_bytes,
    validate_benchmark_record_bytes, BenchmarkEvidenceEntryKind, BenchmarkEvidenceFileMetadata,
    BenchmarkEvidenceIoError, BenchmarkEvidenceNativeIo, BenchmarkEvidencePublishDisposition,
    FilesystemBenchmarkEvidenceProvider, RoutedBenchmarkEvidenceProvider,
    SystemBenchmarkEvidenceNativeIo,
};
pub use li_benchmark_execution::{
    BenchmarkExecutionArtifact, BenchmarkExecutionLaunch, BenchmarkExecutionPreparation,
    BenchmarkExecutionRestoration, BenchmarkExecutionScheduler, BenchmarkRunPlan,
    BenchmarkRunPlanProvider, BenchmarkScheduledExecution, BenchmarkScheduledState,
    BenchmarkScheduledTerminal, BenchmarkSchedulerStopReason,
    CoordinatedBenchmarkExecutionProvider,
};
pub use li_benchmark_run_plan::{
    BenchmarkRunPlanResolution, BenchmarkRunPlanSource, ResolvedBenchmarkRunPlanProvider,
};
pub use li_benchmark_signing::{
    BenchmarkSigningCommand, BenchmarkSigningCommandOutput, BenchmarkSigningCommandRunner,
    OpensslBenchmarkSigningProvider, SystemBenchmarkSigningCommandRunner,
};
pub use li_benchmark_telemetry::{
    BenchmarkTelemetryFinish, BenchmarkTelemetryOpen, BenchmarkTelemetryPort,
    BenchmarkTelemetryState, BenchmarkTelemetrySynchronization, WindowedBenchmarkTelemetryProvider,
};
pub use li_benchmark_telemetry_codec::{
    decode_benchmark_telemetry_state, encode_benchmark_telemetry_state,
    BENCHMARK_TELEMETRY_STATE_MAXIMUM_DOCUMENT_BYTES,
};
pub use li_benchmark_verification::{
    BenchmarkVerificationArm, BenchmarkVerificationArmState, BenchmarkVerificationChildObservation,
    BenchmarkVerificationChildProvider, BenchmarkVerificationChildResult,
    BenchmarkVerificationClock, BenchmarkVerificationHandoffProvider,
    BenchmarkVerificationHandoffReceipt, BenchmarkVerificationPhase, BenchmarkVerificationStore,
    BenchmarkVerificationTransaction, PairedBenchmarkVerificationExecutionProvider,
    SystemBenchmarkVerificationClock, VersionedBenchmarkVerificationTransaction,
};
pub use li_benchmark_verification_database::DatabaseBenchmarkVerificationStore;

use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex, TryLockError};
use std::time::{SystemTime, UNIX_EPOCH};

use li_core_interface::{OperationId, UnixMilliseconds};

use li_benchmark_lifecycle::BenchmarkLifecycle;

// Reads positive benchmark lifecycle time from the native system clock.
#[derive(Default)]
pub struct SystemBenchmarkClock;

impl BenchmarkClock for SystemBenchmarkClock {
    // Returns current Unix time without accepting pre-epoch or overflowing clocks.
    fn now(&self) -> Result<UnixMilliseconds, BenchmarkError> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| BenchmarkError::provider("clock", "system time is unavailable"))?;
        let milliseconds = u64::try_from(duration.as_millis())
            .map_err(|_| BenchmarkError::provider("clock", "system time is unavailable"))?;
        if milliseconds == 0 {
            return Err(BenchmarkError::provider(
                "clock",
                "system time is unavailable",
            ));
        }
        Ok(UnixMilliseconds::new(milliseconds))
    }
}

// Describes one stable BenchmarkManager lifecycle failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BenchmarkError {
    InvalidContract {
        reason: &'static str,
    },
    Busy,
    IdempotencyConflict,
    NotFound,
    InvalidTransition,
    AuthorizationDenied,
    Store(BenchmarkStoreError),
    Provider {
        capability: &'static str,
        reason: &'static str,
    },
    EvidenceRejected,
    SignatureRejected,
    PublicationRejected,
}

impl BenchmarkError {
    // Creates one redacted provider failure at an exact injected boundary.
    pub const fn provider(capability: &'static str, reason: &'static str) -> Self {
        Self::Provider { capability, reason }
    }
}

impl fmt::Display for BenchmarkError {
    // Presents stable benchmark language without commands, paths, or private evidence.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidContract { reason } => {
                write!(formatter, "benchmark contract is invalid: {reason}")
            }
            Self::Busy => formatter.write_str("another benchmark is active"),
            Self::IdempotencyConflict => {
                formatter.write_str("benchmark replay identity conflicts with its request")
            }
            Self::NotFound => formatter.write_str("benchmark job was not found"),
            Self::InvalidTransition => {
                formatter.write_str("benchmark job cannot perform that transition")
            }
            Self::AuthorizationDenied => formatter.write_str("benchmark authorization is denied"),
            Self::Store(error) => write!(formatter, "{error}"),
            Self::Provider { capability, reason } => {
                write!(formatter, "benchmark {capability} failed: {reason}")
            }
            Self::EvidenceRejected => {
                formatter.write_str("benchmark evidence failed semantic verification")
            }
            Self::SignatureRejected => {
                formatter.write_str("benchmark evidence signature failed verification")
            }
            Self::PublicationRejected => {
                formatter.write_str("benchmark verification publication failed verification")
            }
        }
    }
}

impl Error for BenchmarkError {}

impl From<BenchmarkStoreError> for BenchmarkError {
    // Preserves one stable persistence failure at the manager boundary.
    fn from(error: BenchmarkStoreError) -> Self {
        Self::Store(error)
    }
}

// Owns durable benchmark admission, execution, restoration, and evidence sealing.
pub struct BenchmarkManager {
    lifecycle: BenchmarkLifecycle,
    active_mutation: Mutex<()>,
}

impl BenchmarkManager {
    // Creates one manager from explicit authority, persistence, execution, telemetry, evidence, signing, and time capabilities.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store: Arc<dyn BenchmarkStore>,
        authorization: Arc<dyn BenchmarkAuthorizationProvider>,
        execution: Arc<dyn BenchmarkExecutionProvider>,
        telemetry: Arc<dyn BenchmarkTelemetryProvider>,
        evidence: Arc<dyn BenchmarkEvidenceProvider>,
        signing: Arc<dyn BenchmarkSigningProvider>,
        clock: Arc<dyn BenchmarkClock>,
    ) -> Self {
        Self::new_with_publication(
            store,
            authorization,
            execution,
            telemetry,
            evidence,
            signing,
            Arc::new(NoopBenchmarkPublicationProvider),
            clock,
        )
    }

    // Creates one manager with an explicit terminal community-verification publisher.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_publication(
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
            lifecycle: BenchmarkLifecycle::new(
                store,
                authorization,
                execution,
                telemetry,
                evidence,
                signing,
                publication,
                clock,
            ),
            active_mutation: Mutex::new(()),
        }
    }

    // Starts or resumes one replay-safe benchmark through its running or terminal phase.
    pub fn start(
        &self,
        idempotency_key: &str,
        request: BenchmarkRequest,
    ) -> Result<BenchmarkChange, BenchmarkError> {
        let _guard = self.mutation_guard()?;
        self.lifecycle.start(idempotency_key, request)
    }

    // Advances one durable job by one observation or through its terminal cleanup phases.
    pub fn poll(&self, job_id: &OperationId) -> Result<BenchmarkChange, BenchmarkError> {
        let _guard = self.mutation_guard()?;
        self.lifecycle.poll(job_id)
    }

    // Requests cancellation without treating client detachment as cancellation.
    pub fn stop(&self, job_id: &OperationId) -> Result<BenchmarkChange, BenchmarkError> {
        let _guard = self.mutation_guard()?;
        self.lifecycle.stop(job_id)
    }

    // Returns one durable benchmark journal without invoking external providers.
    pub fn record(
        &self,
        job_id: &OperationId,
    ) -> Result<Option<VersionedBenchmarkJob>, BenchmarkError> {
        self.lifecycle.record(job_id)
    }

    // Returns the sole non-terminal benchmark journal without invoking external providers.
    pub fn active(&self) -> Result<Option<VersionedBenchmarkJob>, BenchmarkError> {
        self.lifecycle.active()
    }

    // Acquires exclusive in-process lifecycle ownership without waiting behind another mutation.
    fn mutation_guard(&self) -> Result<std::sync::MutexGuard<'_, ()>, BenchmarkError> {
        match self.active_mutation.try_lock() {
            Ok(guard) => Ok(guard),
            Err(TryLockError::WouldBlock) => Err(BenchmarkError::Busy),
            Err(TryLockError::Poisoned(_)) => Err(BenchmarkError::provider(
                "state",
                "benchmark ownership is unavailable",
            )),
        }
    }
}

// Converts one redacted manager error into bounded durable benchmark failure evidence.
pub(crate) fn benchmark_failure(
    category: BenchmarkFailureCategory,
    phase: &'static str,
    error: &BenchmarkError,
) -> Result<BenchmarkFailure, BenchmarkError> {
    let message = match error {
        BenchmarkError::InvalidContract { reason } => *reason,
        BenchmarkError::Busy => "another benchmark is active",
        BenchmarkError::IdempotencyConflict => "benchmark replay identity conflicts",
        BenchmarkError::NotFound => "benchmark job disappeared",
        BenchmarkError::InvalidTransition => "benchmark transition is invalid",
        BenchmarkError::AuthorizationDenied => "benchmark authorization is denied",
        BenchmarkError::Store(_) => "benchmark persistence failed",
        BenchmarkError::Provider { reason, .. } => *reason,
        BenchmarkError::EvidenceRejected => "benchmark evidence failed verification",
        BenchmarkError::SignatureRejected => "benchmark evidence signature failed verification",
        BenchmarkError::PublicationRejected => {
            "benchmark verification publication failed verification"
        }
    };
    BenchmarkFailure::new(category, phase, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Proves the production clock returns one positive representable lifecycle timestamp.
    #[test]
    fn system_clock_returns_positive_unix_time() {
        assert!(
            SystemBenchmarkClock
                .now()
                .expect("system benchmark clock")
                .value()
                > 0
        );
    }
}
