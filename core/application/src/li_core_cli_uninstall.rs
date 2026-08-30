// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::{Arc, Mutex};

use li_core_cli::{
    CommandFailure, CommandFailureKind, CommandProgressEvent, CommandProgressPort,
    NativeUninstallModelDisposition, NativeUninstallPort, NativeUninstallReceipt,
};

use crate::{
    CoreUninstallBoundary, CoreUninstallConfirmation, CoreUninstallCoordinator, CoreUninstallError,
    CoreUninstallModelDisposition, CoreUninstallRequest, CoreUninstallTargetKind,
};

// Projects the Application-owned teardown coordinator into the public CLI capability contract.
pub struct ApplicationCoreCliUninstall {
    coordinator: Arc<CoreUninstallCoordinator>,
    completed: Mutex<Option<(NativeUninstallModelDisposition, NativeUninstallReceipt)>>,
}

impl ApplicationCoreCliUninstall {
    // Creates one native CLI adapter without weakening confirmation or target ownership policy.
    pub const fn new(coordinator: Arc<CoreUninstallCoordinator>) -> Self {
        Self {
            coordinator,
            completed: Mutex::new(None),
        }
    }
}

impl NativeUninstallPort for ApplicationCoreCliUninstall {
    // Executes one complete irreversible teardown and returns only its stable terminal projection.
    fn uninstall(
        &self,
        disposition: NativeUninstallModelDisposition,
        progress: &mut dyn CommandProgressPort,
    ) -> Result<NativeUninstallReceipt, CommandFailure> {
        if let Some((completed_disposition, completed)) = self
            .completed
            .lock()
            .map_err(|_| uninstall_operation_failure())?
            .as_ref()
        {
            if completed_disposition != &disposition {
                return Err(uninstall_operation_failure());
            }
            return Ok(NativeUninstallReceipt::new(
                completed.receipt_id().clone(),
                completed.removed_targets(),
                completed.removed_containers(),
                completed.removed_images(),
                completed.models_preserved(),
                true,
            ));
        }
        progress.report(CommandProgressEvent::Detail(
            "Validating every managed uninstall target".to_string(),
        ));
        let disposition = match disposition {
            NativeUninstallModelDisposition::KeepModels => {
                CoreUninstallModelDisposition::KeepModels
            }
            NativeUninstallModelDisposition::RemoveModels => {
                CoreUninstallModelDisposition::RemoveModels
            }
        };
        let result = self
            .coordinator
            .uninstall(&CoreUninstallRequest::new(
                CoreUninstallConfirmation::Confirmed,
                disposition,
            ))
            .map_err(uninstall_failure)?;
        let receipt = result.receipt();
        let removed_targets = CoreUninstallTargetKind::ALL
            .iter()
            .try_fold(0_u64, |total, kind| {
                u64::try_from(receipt.target_count(*kind))
                    .ok()
                    .and_then(|count| total.checked_add(count))
            })
            .ok_or_else(uninstall_receipt_failure)?;
        progress.report(CommandProgressEvent::Detail(
            "Managed services, data, and Core files are retired".to_string(),
        ));
        let completed = NativeUninstallReceipt::new(
            receipt.receipt_id().clone(),
            removed_targets,
            u64::try_from(receipt.target_count(CoreUninstallTargetKind::ManagedContainer))
                .map_err(|_| uninstall_receipt_failure())?,
            u64::try_from(receipt.target_count(CoreUninstallTargetKind::ManagedImage))
                .map_err(|_| uninstall_receipt_failure())?,
            receipt.models_preserved(),
            result.replayed(),
        );
        *self
            .completed
            .lock()
            .map_err(|_| uninstall_operation_failure())? =
            Some((disposition.into(), completed.clone()));
        Ok(completed)
    }
}

impl From<CoreUninstallModelDisposition> for NativeUninstallModelDisposition {
    // Projects one Application policy into the closed CLI equivalent without changing meaning.
    fn from(value: CoreUninstallModelDisposition) -> Self {
        match value {
            CoreUninstallModelDisposition::KeepModels => Self::KeepModels,
            CoreUninstallModelDisposition::RemoveModels => Self::RemoveModels,
        }
    }
}

// Maps one coordinator boundary failure to stable CLI recovery language.
fn uninstall_failure(error: CoreUninstallError) -> CommandFailure {
    let (kind, code, message) = match error {
        CoreUninstallError::ConfirmationRequired => (
            CommandFailureKind::Denied,
            "uninstall.confirmation_required",
            "Uninstall requires explicit confirmation.",
        ),
        CoreUninstallError::PreflightRejected | CoreUninstallError::InvalidPlan => (
            CommandFailureKind::Failed,
            "uninstall.preflight_rejected",
            "Uninstall stopped before mutation because the ownership plan is unsafe.",
        ),
        CoreUninstallError::BoundaryFailed(CoreUninstallBoundary::BenchmarkExit) => (
            CommandFailureKind::Failed,
            "uninstall.benchmark_timeout",
            "The active benchmark did not exit before the uninstall deadline.",
        ),
        CoreUninstallError::BoundaryFailed(boundary)
        | CoreUninstallError::InvalidReceipt(boundary) => (
            CommandFailureKind::Failed,
            uninstall_boundary_code(boundary),
            "Uninstall stopped at the first incomplete teardown boundary.",
        ),
        CoreUninstallError::OperationConflict => (
            CommandFailureKind::Failed,
            "uninstall.operation_conflict",
            "Another uninstall operation owns this process.",
        ),
    };
    CommandFailure::new(kind, code, message).expect("static uninstall failure contract")
}

// Returns the stable CLI identity for one irreversible teardown boundary.
const fn uninstall_boundary_code(boundary: CoreUninstallBoundary) -> &'static str {
    match boundary {
        CoreUninstallBoundary::Preflight => "uninstall.preflight_rejected",
        CoreUninstallBoundary::BenchmarkExit => "uninstall.benchmark_timeout",
        CoreUninstallBoundary::PublicExposure => "uninstall.exposure_failed",
        CoreUninstallBoundary::Workloads => "uninstall.workloads_failed",
        CoreUninstallBoundary::PlatformServices => "uninstall.services_failed",
        CoreUninstallBoundary::RuntimeArtifacts => "uninstall.runtimes_failed",
        CoreUninstallBoundary::OwnerData => "uninstall.owner_data_failed",
        CoreUninstallBoundary::ImmutableCore => "uninstall.core_retirement_failed",
    }
}

// Returns one fixed failure when a terminal receipt cannot fit the CLI wire projection.
fn uninstall_receipt_failure() -> CommandFailure {
    CommandFailure::new(
        CommandFailureKind::Failed,
        "uninstall.receipt_invalid",
        "The native uninstall receipt is invalid.",
    )
    .expect("static uninstall receipt failure")
}

// Returns one stable process-local concurrency or replay-policy failure.
fn uninstall_operation_failure() -> CommandFailure {
    CommandFailure::new(
        CommandFailureKind::Failed,
        "uninstall.operation_conflict",
        "Another uninstall request owns this process or selected a different model policy.",
    )
    .expect("static uninstall operation failure")
}
