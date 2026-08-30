// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use li_core_interface::Sha256Digest;
use li_core_update_manager::{
    CoreInstallation, CoreUpdateError, CoreUpdatePhase, CoreUpdatePruneReferenceProvider,
    CoreUpdatePruneReferences,
};
use li_node_manager::DatabaseCoreUpdateStore;

// Derives exact Core and workspace retention solely from validated durable update journals.
pub struct ApplicationCoreUpdatePruneReferenceProvider {
    updates: Arc<DatabaseCoreUpdateStore>,
}

impl ApplicationCoreUpdatePruneReferenceProvider {
    // Creates one reference authority over the shared strict Core-update store.
    pub const fn new(updates: Arc<DatabaseCoreUpdateStore>) -> Self {
        Self { updates }
    }
}

impl CoreUpdatePruneReferenceProvider for ApplicationCoreUpdatePruneReferenceProvider {
    // Retains every identity needed by foreign forward or recovery state and omits completed state.
    fn references(
        &self,
        update_id: &Sha256Digest,
        _active: &CoreInstallation,
    ) -> Result<CoreUpdatePruneReferences, CoreUpdateError> {
        let records = self.updates.records().map_err(|_| {
            CoreUpdateError::provider(
                "prune references",
                "Core update journal references are unavailable",
            )
        })?;
        let mut installations = Vec::new();
        let mut workspaces = Vec::new();
        for versioned in records {
            let record = versioned.record();
            if record.update_id() == update_id || !retains_update_recovery(record.phase()) {
                continue;
            }
            if let Some(current) = record.current() {
                installations.push(current.clone());
            }
            if let Some(prepared) = record.prepared() {
                installations.push(prepared.installation().clone());
            }
            if let Some(activation) = record.activation() {
                installations.push(activation.previous().clone());
                installations.push(activation.installation().clone());
            }
            workspaces.push(record.update_id().clone());
        }
        Ok(CoreUpdatePruneReferences::new(installations, workspaces))
    }
}

// Returns whether one foreign journal can still require immutable files or staging recovery.
const fn retains_update_recovery(phase: CoreUpdatePhase) -> bool {
    !matches!(
        phase,
        CoreUpdatePhase::Current
            | CoreUpdatePhase::CleanupPending
            | CoreUpdatePhase::Succeeded
            | CoreUpdatePhase::RolledBack
    )
}
