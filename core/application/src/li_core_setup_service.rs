// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use li_core_update_manager::{CoreInstallation, CoreUpdateServiceContext};

use crate::{
    CoreServiceCutoverReceipt, CoreServiceCutoverRecovery, CoreServiceSetup, CoreServiceSetupError,
    CoreServiceSetupNodeIdentity, CoreSetupInstalledServices, CoreSetupPreparedIdentity,
    CoreSetupPreparedMaterial, CoreSetupProviderError, CoreSetupReceipt, CoreSetupRequest,
    CoreSetupServiceProvider,
};

// Isolates the already-tested native service cutover from top-level setup orchestration.
pub trait CoreSetupServiceApplication: Send + Sync {
    // Returns the platform and role owned by this native service application.
    fn context(&self) -> CoreUpdateServiceContext;

    // Applies or replays one immutable installation through native service readiness.
    fn apply(
        &self,
        installation: &CoreInstallation,
        identity: &CoreServiceSetupNodeIdentity,
    ) -> Result<CoreServiceCutoverReceipt, CoreServiceSetupError>;

    // Observes one durable interrupted restoration without changing it.
    fn recovery(&self) -> Result<CoreServiceCutoverRecovery, CoreServiceSetupError>;

    // Restores native state while retaining its durable Restored checkpoint.
    fn resume_recovery(&self) -> Result<(), CoreServiceSetupError>;

    // Clears one restored checkpoint after outer setup compensation completes.
    fn complete_recovery(&self) -> Result<(), CoreServiceSetupError>;
}

impl CoreSetupServiceApplication for CoreServiceSetup {
    // Returns the exact platform and role bound at production service composition.
    fn context(&self) -> CoreUpdateServiceContext {
        CoreServiceSetup::context(self)
    }

    // Delegates one installation to the production native cutover and health transaction.
    fn apply(
        &self,
        installation: &CoreInstallation,
        identity: &CoreServiceSetupNodeIdentity,
    ) -> Result<CoreServiceCutoverReceipt, CoreServiceSetupError> {
        CoreServiceSetup::apply_for_node(self, installation, identity)
    }

    // Delegates interrupted restoration observation to the native service owner.
    fn recovery(&self) -> Result<CoreServiceCutoverRecovery, CoreServiceSetupError> {
        CoreServiceSetup::recovery(self)
    }

    // Delegates interrupted native restoration without clearing its checkpoint.
    fn resume_recovery(&self) -> Result<(), CoreServiceSetupError> {
        CoreServiceSetup::resume_recovery(self)
    }

    // Delegates terminal recovery cleanup after outer setup compensation.
    fn complete_recovery(&self) -> Result<(), CoreServiceSetupError> {
        CoreServiceSetup::complete_recovery(self)
    }
}

// Adapts the production native service transaction into the complete Core setup phase.
pub struct ApplicationCoreSetupServiceProvider {
    application: Arc<dyn CoreSetupServiceApplication>,
}

impl ApplicationCoreSetupServiceProvider {
    // Creates the production adapter around one fully composed native service setup owner.
    pub fn new(application: Arc<CoreServiceSetup>) -> Self {
        Self { application }
    }

    // Creates one adapter from an explicit service application for deterministic verification.
    pub fn with_application(application: Arc<dyn CoreSetupServiceApplication>) -> Self {
        Self { application }
    }

    // Applies one exact request and converts only its opaque cutover receipt.
    fn applied_services(
        &self,
        request: &CoreSetupRequest,
        identity: &CoreSetupPreparedIdentity,
    ) -> Result<CoreSetupInstalledServices, CoreSetupProviderError> {
        if self.application.context() != request.context() {
            return Err(CoreSetupProviderError::unchanged(
                "resident services",
                "service context does not match the setup request",
            ));
        }
        let receipt = self
            .application
            .apply(
                request.installation(),
                &CoreServiceSetupNodeIdentity::new(identity.node_id().clone(), identity.role()),
            )
            .map_err(service_error)?;
        Ok(CoreSetupInstalledServices::new(CoreSetupReceipt::new(
            receipt.receipt_id().clone(),
        )))
    }
}

impl CoreSetupServiceProvider for ApplicationCoreSetupServiceProvider {
    // Observes one interrupted service restoration before source-bound setup replay.
    fn recovery(&self) -> Result<CoreServiceCutoverRecovery, CoreSetupProviderError> {
        self.application.recovery().map_err(service_error)
    }

    // Restores the interrupted native snapshot while retaining durable recovery authority.
    fn resume_recovery(&self) -> Result<(), CoreSetupProviderError> {
        self.application.resume_recovery().map_err(service_error)
    }

    // Clears the restored checkpoint only after reversible setup phases are compensated.
    fn complete_recovery(&self) -> Result<(), CoreSetupProviderError> {
        self.application.complete_recovery().map_err(service_error)
    }

    // Activates or health-verifies the exact resident set after reversible setup validation.
    fn apply(
        &self,
        request: &CoreSetupRequest,
        identity: &CoreSetupPreparedIdentity,
        _material: &CoreSetupPreparedMaterial,
    ) -> Result<CoreSetupInstalledServices, CoreSetupProviderError> {
        self.applied_services(request, identity)
    }
}

// Preserves rollback and recovery classifications from the native service transaction.
fn service_error(error: CoreServiceSetupError) -> CoreSetupProviderError {
    match error {
        CoreServiceSetupError::InvalidContract { reason } => {
            CoreSetupProviderError::unchanged("resident services", reason)
        }
        CoreServiceSetupError::Provider { reason, .. } => {
            CoreSetupProviderError::recovery_required("resident services", reason)
        }
        CoreServiceSetupError::RolledBack { reason } => {
            CoreSetupProviderError::rolled_back("resident services", reason)
        }
        CoreServiceSetupError::RecoveryRequired { reason } => {
            CoreSetupProviderError::recovery_required("resident services", reason)
        }
    }
}
