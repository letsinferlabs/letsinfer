// SPDX-License-Identifier: AGPL-3.0-only

use li_core_interface::ControllerId;

use crate::{AuthenticationStoreError, Controller};

// Returns one controller record with its exact optimistic persistence revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionedController {
    controller: Controller,
    revision: u64,
}

impl VersionedController {
    // Creates one versioned store result.
    pub const fn new(controller: Controller, revision: u64) -> Self {
        Self {
            controller,
            revision,
        }
    }

    // Returns the validated controller snapshot.
    pub const fn controller(&self) -> &Controller {
        &self.controller
    }

    // Returns the exact revision required by the next mutation.
    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

// Defines the narrow durable controller-registry capability owned by AuthenticationManager.
pub trait ControllerStore: Send + Sync {
    // Returns one exact controller identity when it exists.
    fn read(
        &self,
        controller_id: &ControllerId,
    ) -> Result<Option<VersionedController>, AuthenticationStoreError>;

    // Returns every controller record for stable listing and uniqueness validation.
    fn all(&self) -> Result<Vec<VersionedController>, AuthenticationStoreError>;

    // Creates one controller identity only when it is absent.
    fn create(
        &self,
        controller: Controller,
    ) -> Result<VersionedController, AuthenticationStoreError>;

    // Replaces one exact controller revision for activation, revocation, or explicit replacement.
    fn replace(
        &self,
        controller: Controller,
        expected_revision: u64,
    ) -> Result<VersionedController, AuthenticationStoreError>;
}
