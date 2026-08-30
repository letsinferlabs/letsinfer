// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use li_core_interface::{OperationState, Sha256Digest};
use li_core_update_manager::{
    CoreUpdateAdmissionLease, CoreUpdateAdmissionProvider, CoreUpdateError, CoreUpdatePhase,
};
use li_node_manager::{DatabaseCoreUpdateStore, NodeManager};

use crate::{CoreSetupExecutionLock, CoreSetupExecutionLockProvider};

// Supplies the exact Node operation state inspected while global update ownership is held.
pub trait ApplicationCoreUpdateOperationSource: Send + Sync {
    // Returns whether any Node-owned operation can still mutate shared state.
    fn has_active_operation(&self) -> Result<bool, CoreUpdateError>;
}

// Supplies the complete durable Core-update journal set inspected under global ownership.
pub trait ApplicationCoreUpdateJournalSource: Send + Sync {
    // Returns whether another update still owns forward mutation, cleanup, or recovery state.
    fn has_conflicting_journal(&self, update_id: &Sha256Digest) -> Result<bool, CoreUpdateError>;
}

impl ApplicationCoreUpdateJournalSource for DatabaseCoreUpdateStore {
    // Rejects every foreign journal that is not safely current, succeeded, or rolled back.
    fn has_conflicting_journal(&self, update_id: &Sha256Digest) -> Result<bool, CoreUpdateError> {
        self.records()
            .map(|records| {
                records.iter().any(|versioned| {
                    let record = versioned.record();
                    record.update_id() != update_id
                        && !matches!(
                            record.phase(),
                            CoreUpdatePhase::Current
                                | CoreUpdatePhase::Succeeded
                                | CoreUpdatePhase::RolledBack
                        )
                })
            })
            .map_err(|_| admission_error("Core update journal state is unavailable"))
    }
}

impl ApplicationCoreUpdateOperationSource for NodeManager {
    // Reads the complete durable operation set and recognizes only nonterminal mutation.
    fn has_active_operation(&self) -> Result<bool, CoreUpdateError> {
        self.operations()
            .map(|operations| {
                operations.iter().any(|operation| {
                    matches!(
                        operation.state(),
                        OperationState::Pending | OperationState::Running
                    )
                })
            })
            .map_err(|_| admission_error("Node operation state is unavailable"))
    }
}

// Retains the shared setup/update lock through the complete CoreUpdateManager call.
struct ApplicationCoreUpdateAdmissionLease {
    _lock: Box<dyn CoreSetupExecutionLock>,
}

impl CoreUpdateAdmissionLease for ApplicationCoreUpdateAdmissionLease {}

// Serializes setup and update across processes and rejects active Node operations.
pub struct ApplicationCoreUpdateAdmissionProvider {
    locks: Arc<dyn CoreSetupExecutionLockProvider>,
    operations: Arc<dyn ApplicationCoreUpdateOperationSource>,
    journals: Arc<dyn ApplicationCoreUpdateJournalSource>,
}

impl ApplicationCoreUpdateAdmissionProvider {
    // Creates one admission boundary from explicit global lock and operation authorities.
    pub const fn new(
        locks: Arc<dyn CoreSetupExecutionLockProvider>,
        operations: Arc<dyn ApplicationCoreUpdateOperationSource>,
        journals: Arc<dyn ApplicationCoreUpdateJournalSource>,
    ) -> Self {
        Self {
            locks,
            operations,
            journals,
        }
    }
}

impl CoreUpdateAdmissionProvider for ApplicationCoreUpdateAdmissionProvider {
    // Acquires cross-process ownership before inspecting any mutable Node operation state.
    fn acquire(
        &self,
        update_id: &Sha256Digest,
    ) -> Result<Box<dyn CoreUpdateAdmissionLease>, CoreUpdateError> {
        let lock = self
            .locks
            .try_acquire()
            .map_err(|_| admission_error("setup or update ownership is unavailable"))?;
        if self.operations.has_active_operation()? {
            return Err(admission_error("a Node operation is still active"));
        }
        if self.journals.has_conflicting_journal(update_id)? {
            return Err(admission_error(
                "another Core update requires completion or recovery",
            ));
        }
        Ok(Box::new(ApplicationCoreUpdateAdmissionLease {
            _lock: lock,
        }))
    }
}

// Creates one stable admission failure without retaining operation or lock diagnostics.
fn admission_error(reason: &'static str) -> CoreUpdateError {
    CoreUpdateError::provider("admission", reason)
}
