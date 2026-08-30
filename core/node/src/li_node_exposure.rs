// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use li_core_interface::Sha256Digest;
use li_gateway_manager::{GatewayExposureCoordinator, GatewayExposureError, GatewayExposureStatus};

// Defines the Node-owned private projection of Gateway public-exposure policy.
pub trait NodeExposureApiPort: Send + Sync {
    // Reads durable exposure state and its current provider verification result.
    fn status(&self) -> Result<GatewayExposureStatus, GatewayExposureError>;

    // Enables the exact public inference exposure after Gateway readiness proves safe.
    fn enable(&self) -> Result<GatewayExposureStatus, GatewayExposureError>;

    // Disables only the exact durable public inference exposure identity.
    fn disable(&self) -> Result<GatewayExposureStatus, GatewayExposureError>;

    // Disables or replays absence only for one lease-bound configuration identity.
    fn disable_matching(
        &self,
        expected_configuration_sha256: &Sha256Digest,
    ) -> Result<GatewayExposureStatus, GatewayExposureError>;
}

// Routes private Node requests through the one composed GatewayExposureCoordinator.
pub struct ManagedNodeExposureApi {
    manager: Arc<GatewayExposureCoordinator>,
}

impl ManagedNodeExposureApi {
    // Creates one thin Node projection without duplicating Gateway policy or state.
    pub const fn new(manager: Arc<GatewayExposureCoordinator>) -> Self {
        Self { manager }
    }
}

impl NodeExposureApiPort for ManagedNodeExposureApi {
    // Delegates status and preserves the complete Gateway verification result.
    fn status(&self) -> Result<GatewayExposureStatus, GatewayExposureError> {
        self.manager.status()
    }

    // Delegates enable without translating provider or compensation failures.
    fn enable(&self) -> Result<GatewayExposureStatus, GatewayExposureError> {
        self.manager
            .enable()
            .and_then(|exposure| GatewayExposureStatus::new(Some(exposure), true))
    }

    // Delegates exact-identity disable without changing lifecycle semantics.
    fn disable(&self) -> Result<GatewayExposureStatus, GatewayExposureError> {
        self.manager
            .disable()
            .and_then(|()| GatewayExposureStatus::new(None, true))
    }

    // Delegates the lease-bound idempotent disable without weakening ordinary CLI semantics.
    fn disable_matching(
        &self,
        expected_configuration_sha256: &Sha256Digest,
    ) -> Result<GatewayExposureStatus, GatewayExposureError> {
        self.manager
            .disable_matching(expected_configuration_sha256)
            .and_then(|()| GatewayExposureStatus::new(None, true))
    }
}
