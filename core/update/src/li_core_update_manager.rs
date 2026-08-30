// SPDX-License-Identifier: AGPL-3.0-only

mod li_core_update_artifact_provider;
mod li_core_update_candidate_installer;
mod li_core_update_contract;
mod li_core_update_lifecycle;
mod li_core_update_prune_provider;
mod li_core_update_service_provider;

pub use li_core_update_artifact_provider::{
    CoreUpdateArtifactEntry, CoreUpdateArtifactEntryKind, CoreUpdateArtifactIo,
    CoreUpdateCandidateInstaller, CoreUpdateCandidateRequest, CoreUpdatePathKind,
    FilesystemCoreUpdateArtifactIo, FilesystemCoreUpdateArtifactProvider,
};
pub use li_core_update_candidate_installer::{
    CoreUpdateCandidateFilesystem, CoreUpdateCandidateWorkspace, CoreUpdateCommand,
    CoreUpdateCommandOutput, CoreUpdateCommandRunner, CoreUpdateReleasePlatform,
    CoreUpdateReleaseTransport, CoreUpdateSignatureVerifier, CurlCoreUpdateReleaseTransport,
    FilesystemCoreUpdateCandidateFilesystem, GithubCoreUpdateCandidateInstaller,
    ProcessCoreUpdateCommandRunner, SshKeygenCoreUpdateSignatureVerifier,
};
pub use li_core_update_contract::{
    ActivatedCoreUpdate, CoreInstallation, CoreServiceSnapshot, CoreUpdateAdmissionLease,
    CoreUpdateAdmissionProvider, CoreUpdateArtifactProvider, CoreUpdateChange,
    CoreUpdateDisposition, CoreUpdateEvent, CoreUpdatePhase, CoreUpdatePruneProvider,
    CoreUpdateRecord, CoreUpdateServiceProvider, CoreUpdateStore, CoreVersion, PreparedCoreUpdate,
    VersionedCoreUpdateRecord,
};
pub use li_core_update_lifecycle::{
    CoreUpdateReadinessClock, CoreUpdateReadinessPolicy, SystemCoreUpdateReadinessClock,
};
pub use li_core_update_prune_provider::{
    CoreUpdatePruneEntry, CoreUpdatePruneEntryKind, CoreUpdatePruneIo, CoreUpdatePrunePlan,
    CoreUpdatePruneReceipt, CoreUpdatePruneReferenceProvider, CoreUpdatePruneReferences,
    FilesystemCoreUpdatePruneIo, ReferenceAwareCoreUpdatePruneProvider,
};
pub use li_core_update_service_provider::{
    CoreUpdateNodeRole, CoreUpdateResidentService, CoreUpdateServiceContext,
    CoreUpdateServiceControl, CoreUpdateServiceMode, CoreUpdateServicePlatform,
    CoreUpdateServiceSnapshotRecord, CoreUpdateServiceSnapshotStore, CoreUpdateServiceState,
    PlatformCoreUpdateServiceProvider,
};

use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex, TryLockError};

use li_core_interface::{FailureDescription, Sha256Digest, TechnicalName};
use sha2::{Digest, Sha256};

use li_core_update_lifecycle::CoreUpdateLifecycle;

// Describes one stable update-store boundary failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoreUpdateStoreError {
    Conflict,
    Unavailable,
    Corrupt,
}

impl fmt::Display for CoreUpdateStoreError {
    // Presents a stable store failure without exposing persistence details.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conflict => formatter.write_str("Core update journal revision conflicted"),
            Self::Unavailable => formatter.write_str("Core update journal is unavailable"),
            Self::Corrupt => formatter.write_str("Core update journal is corrupt"),
        }
    }
}

impl Error for CoreUpdateStoreError {}

// Describes one stable CoreUpdateManager lifecycle failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoreUpdateError {
    InvalidContract {
        reason: &'static str,
    },
    Busy,
    IdempotencyConflict,
    Store(CoreUpdateStoreError),
    Provider {
        capability: &'static str,
        reason: &'static str,
    },
    RolledBack {
        failure: FailureDescription,
    },
    RecoveryRequired {
        failure: FailureDescription,
    },
}

impl CoreUpdateError {
    // Creates one redacted provider failure at an exact injected boundary.
    pub fn provider(capability: &'static str, reason: &'static str) -> Self {
        Self::Provider { capability, reason }
    }
}

impl fmt::Display for CoreUpdateError {
    // Presents stable update language without paths, commands, or private service state.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidContract { reason } => {
                write!(formatter, "Core update contract is invalid: {reason}")
            }
            Self::Busy => formatter.write_str("another Core update is active"),
            Self::IdempotencyConflict => {
                formatter.write_str("Core update replay identity conflicts with its request")
            }
            Self::Store(error) => write!(formatter, "{error}"),
            Self::Provider { capability, reason } => {
                write!(formatter, "Core update {capability} failed: {reason}")
            }
            Self::RolledBack { failure } => {
                write!(formatter, "Core update rolled back: {}", failure.message())
            }
            Self::RecoveryRequired { failure } => write!(
                formatter,
                "Core update requires recovery: {}",
                failure.message()
            ),
        }
    }
}

impl Error for CoreUpdateError {}

impl From<CoreUpdateStoreError> for CoreUpdateError {
    // Preserves one stable persistence failure at the manager boundary.
    fn from(error: CoreUpdateStoreError) -> Self {
        Self::Store(error)
    }
}

// Owns the complete signed Core release handoff and cleanup lifecycle.
pub struct CoreUpdateManager {
    lifecycle: CoreUpdateLifecycle,
    active_update: Mutex<()>,
}

impl CoreUpdateManager {
    // Creates one manager from explicit mechanisms and its owned readiness completion policy.
    pub fn new(
        store: Arc<dyn CoreUpdateStore>,
        admission: Arc<dyn CoreUpdateAdmissionProvider>,
        artifacts: Arc<dyn CoreUpdateArtifactProvider>,
        services: Arc<dyn CoreUpdateServiceProvider>,
        pruner: Arc<dyn CoreUpdatePruneProvider>,
        clock: Arc<dyn CoreUpdateReadinessClock>,
        readiness: CoreUpdateReadinessPolicy,
    ) -> Self {
        Self {
            lifecycle: CoreUpdateLifecycle::new(
                store, admission, artifacts, services, pruner, clock, readiness,
            ),
            active_update: Mutex::new(()),
        }
    }

    // Applies or resumes one exact signed Core update without concurrent mutation.
    pub fn update(
        &self,
        idempotency_key: &str,
        requested_version: Option<CoreVersion>,
    ) -> Result<CoreUpdateChange, CoreUpdateError> {
        let _guard = match self.active_update.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::WouldBlock) => return Err(CoreUpdateError::Busy),
            Err(TryLockError::Poisoned(_)) => {
                return Err(CoreUpdateError::Provider {
                    capability: "state",
                    reason: "update ownership is unavailable",
                });
            }
        };
        self.lifecycle.update(idempotency_key, requested_version)
    }

    // Returns one durable journal for status or explicit recovery guidance.
    pub fn record(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<VersionedCoreUpdateRecord>, CoreUpdateError> {
        self.lifecycle.record(idempotency_key)
    }
}

// Derives one stable secret-free provider identity from the caller replay key.
pub(crate) fn update_identity(idempotency_key: &str) -> Result<Sha256Digest, CoreUpdateError> {
    let mut digest = Sha256::new();
    let domain = b"li_core_update_v1";
    digest.update((domain.len() as u64).to_be_bytes());
    digest.update(domain);
    digest.update((idempotency_key.len() as u64).to_be_bytes());
    digest.update(idempotency_key.as_bytes());
    Sha256Digest::parse(&format!("{:x}", digest.finalize())).map_err(|_| {
        CoreUpdateError::InvalidContract {
            reason: "Core update identity could not be derived",
        }
    })
}

// Converts one redacted manager failure into a bounded durable description.
pub(crate) fn failure_description(
    stage: &'static str,
    error: &CoreUpdateError,
) -> Result<FailureDescription, CoreUpdateError> {
    let message = match error {
        CoreUpdateError::InvalidContract { reason } => *reason,
        CoreUpdateError::Busy => "another Core update is active",
        CoreUpdateError::IdempotencyConflict => {
            "Core update request conflicts with its replay identity"
        }
        CoreUpdateError::Store(_) => "Core update persistence failed",
        CoreUpdateError::Provider { reason, .. } => *reason,
        CoreUpdateError::RolledBack { .. } => "Core update rolled back",
        CoreUpdateError::RecoveryRequired { .. } => "Core update requires recovery",
    };
    let code = TechnicalName::parse(stage).map_err(|_| CoreUpdateError::InvalidContract {
        reason: "Core update failure code is invalid",
    })?;
    FailureDescription::new(code, message).map_err(|_| CoreUpdateError::InvalidContract {
        reason: "Core update failure could not be recorded",
    })
}
