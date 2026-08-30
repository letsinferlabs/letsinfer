// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use li_core_update_manager::{CoreInstallation, CoreUpdateNodeRole};

use crate::{CorePairingActivationError, CorePairingActivationServicePort, CoreServiceSetup};

// Reuses the existing atomic service cutover for child activation and main compensation.
pub struct CorePairingActivationService {
    child: Arc<CoreServiceSetup>,
    main: Arc<CoreServiceSetup>,
    installation: CoreInstallation,
}

impl CorePairingActivationService {
    // Creates one role-exact service adapter over one immutable Core installation.
    pub fn new(
        child: Arc<CoreServiceSetup>,
        main: Arc<CoreServiceSetup>,
        installation: CoreInstallation,
    ) -> Result<Self, CorePairingActivationError> {
        if child.context().platform() != main.context().platform()
            || child.context().role() != CoreUpdateNodeRole::Child
            || main.context().role() != CoreUpdateNodeRole::Main
        {
            return Err(CorePairingActivationError::ServiceUnavailable);
        }
        Ok(Self {
            child,
            main,
            installation,
        })
    }
}

impl CorePairingActivationServicePort for CorePairingActivationService {
    // Applies the existing role-exact atomic service cutover to the child resident set.
    fn activate_child(&self) -> Result<(), CorePairingActivationError> {
        self.child
            .apply(&self.installation)
            .map(|_| ())
            .map_err(|_| CorePairingActivationError::ServiceUnavailable)
    }

    // Replays the committed child cutover and requires its complete readiness contract.
    fn verify_child(&self) -> Result<(), CorePairingActivationError> {
        self.child
            .apply(&self.installation)
            .map(|_| ())
            .map_err(|_| CorePairingActivationError::ServiceUnavailable)
    }

    // Applies a new atomic main cutover whose snapshot is the current child service state.
    fn restore_main(&self) -> Result<(), CorePairingActivationError> {
        self.main
            .apply(&self.installation)
            .map(|_| ())
            .map_err(|_| CorePairingActivationError::RecoveryRequired)
    }
}
