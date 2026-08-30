// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex};

use li_core_interface::Sha256Digest;
use li_core_update_manager::{
    CoreInstallation, CoreUpdateArtifactProvider, CoreUpdateDisposition, CoreUpdateError,
    CoreUpdateManager, CoreUpdatePhase, CoreVersion,
};
use sha2::{Digest, Sha256};

// Describes whether a verified release check found a newer exact Core installation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeCoreUpdateCheckDisposition {
    Current,
    UpdateAvailable,
}

impl NodeCoreUpdateCheckDisposition {
    // Returns the stable private wire name for this availability decision.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::UpdateAvailable => "update_available",
        }
    }
}

// Projects one signed read-only Core release availability decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeCoreUpdateCheck {
    current: CoreInstallation,
    available: CoreInstallation,
    disposition: NodeCoreUpdateCheckDisposition,
}

impl NodeCoreUpdateCheck {
    // Creates one availability projection only from verified immutable installations.
    pub fn new(current: CoreInstallation, available: CoreInstallation) -> Self {
        let disposition = if current.version() == available.version()
            && current.source_identity() == available.source_identity()
        {
            NodeCoreUpdateCheckDisposition::Current
        } else {
            NodeCoreUpdateCheckDisposition::UpdateAvailable
        };
        Self {
            current,
            available,
            disposition,
        }
    }

    // Returns the exact active Core installation.
    pub const fn current(&self) -> &CoreInstallation {
        &self.current
    }

    // Returns the exact signed available Core installation.
    pub const fn available(&self) -> &CoreInstallation {
        &self.available
    }

    // Returns whether the signed available identity differs from active Core.
    pub const fn disposition(&self) -> NodeCoreUpdateCheckDisposition {
        self.disposition
    }
}

// Projects one terminal CoreUpdateManager result and its durable recovery phase.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeCoreUpdateSummary {
    installation: CoreInstallation,
    disposition: CoreUpdateDisposition,
    phase: CoreUpdatePhase,
}

impl NodeCoreUpdateSummary {
    // Creates one manager-backed terminal projection after journal reread.
    pub const fn new(
        installation: CoreInstallation,
        disposition: CoreUpdateDisposition,
        phase: CoreUpdatePhase,
    ) -> Self {
        Self {
            installation,
            disposition,
            phase,
        }
    }

    // Returns the exact active immutable installation.
    pub const fn installation(&self) -> &CoreInstallation {
        &self.installation
    }

    // Returns the manager's current, updated, or cleanup-pending decision.
    pub const fn disposition(&self) -> CoreUpdateDisposition {
        self.disposition
    }

    // Returns the exact durable terminal phase after the manager call.
    pub const fn phase(&self) -> CoreUpdatePhase {
        self.phase
    }
}

// Resolves signed Core availability without activating files or services.
pub trait NodeCoreUpdateAvailabilityProvider: Send + Sync {
    // Returns active and signed available identities for latest or one exact version.
    fn check(
        &self,
        requested_version: Option<&CoreVersion>,
    ) -> Result<NodeCoreUpdateCheck, CoreUpdateError>;
}

// Checks signed availability through the same artifact verifier without moving active Core.
pub struct ArtifactNodeCoreUpdateAvailabilityProvider {
    artifacts: Arc<dyn CoreUpdateArtifactProvider>,
    active_check: Mutex<()>,
}

impl ArtifactNodeCoreUpdateAvailabilityProvider {
    // Creates one read-only adapter around an explicit signed artifact authority.
    pub const fn new(artifacts: Arc<dyn CoreUpdateArtifactProvider>) -> Self {
        Self {
            artifacts,
            active_check: Mutex::new(()),
        }
    }
}

impl NodeCoreUpdateAvailabilityProvider for ArtifactNodeCoreUpdateAvailabilityProvider {
    // Prepares, verifies, projects, and discards one candidate without journal or pointer mutation.
    fn check(
        &self,
        requested_version: Option<&CoreVersion>,
    ) -> Result<NodeCoreUpdateCheck, CoreUpdateError> {
        let _check = self.active_check.lock().map_err(|_| {
            CoreUpdateError::provider("availability", "availability ownership is unavailable")
        })?;
        let observation_id = availability_identity(requested_version)?;
        let current = self.artifacts.current(&observation_id)?;
        let prepared = self
            .artifacts
            .prepare(&observation_id, requested_version, &current)?;
        let available = prepared.installation().clone();
        self.artifacts.discard(&observation_id, &prepared)?;
        Ok(NodeCoreUpdateCheck::new(current, available))
    }
}

// Defines the manager-backed Core update capability consumed by Node private dispatch.
pub trait NodeCoreUpdateApiPort: Send + Sync {
    // Checks one signed release without moving the active installation.
    fn check(
        &self,
        requested_version: Option<CoreVersion>,
    ) -> Result<NodeCoreUpdateCheck, NodeUpdateError>;

    // Applies or replays one exact CoreUpdateManager lifecycle.
    fn update(
        &self,
        idempotency_key: &str,
        requested_version: Option<CoreVersion>,
    ) -> Result<NodeCoreUpdateSummary, NodeUpdateError>;
}

// Owns only projection and delegates all mutation to the existing CoreUpdateManager.
pub struct NodeCoreUpdateCoordinator {
    manager: Arc<CoreUpdateManager>,
    availability: Arc<dyn NodeCoreUpdateAvailabilityProvider>,
}

impl NodeCoreUpdateCoordinator {
    // Creates one Node adapter from the existing manager and a signed read-only provider.
    pub const fn new(
        manager: Arc<CoreUpdateManager>,
        availability: Arc<dyn NodeCoreUpdateAvailabilityProvider>,
    ) -> Self {
        Self {
            manager,
            availability,
        }
    }
}

impl NodeCoreUpdateApiPort for NodeCoreUpdateCoordinator {
    // Delegates exact-version or latest availability to the signed provider.
    fn check(
        &self,
        requested_version: Option<CoreVersion>,
    ) -> Result<NodeCoreUpdateCheck, NodeUpdateError> {
        self.availability
            .check(requested_version.as_ref())
            .map_err(Into::into)
    }

    // Delegates the lifecycle and then requires its exact durable terminal projection.
    fn update(
        &self,
        idempotency_key: &str,
        requested_version: Option<CoreVersion>,
    ) -> Result<NodeCoreUpdateSummary, NodeUpdateError> {
        let change = self.manager.update(idempotency_key, requested_version)?;
        let record = self
            .manager
            .record(idempotency_key)?
            .ok_or(NodeUpdateError::ProjectionUnavailable)?;
        Ok(NodeCoreUpdateSummary::new(
            change.installation().clone(),
            change.disposition(),
            record.record().phase(),
        ))
    }
}

// Names one stable Node update boundary failure without weakening manager errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodeUpdateError {
    Core(CoreUpdateError),
    ProjectionUnavailable,
}

impl fmt::Display for NodeUpdateError {
    // Preserves stable Core manager language and redacts missing projection details.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(error) => write!(formatter, "{error}"),
            Self::ProjectionUnavailable => {
                formatter.write_str("Core update projection is unavailable")
            }
        }
    }
}

impl Error for NodeUpdateError {}

impl From<CoreUpdateError> for NodeUpdateError {
    // Preserves CoreUpdateManager's closed failure contract.
    fn from(error: CoreUpdateError) -> Self {
        Self::Core(error)
    }
}

// Returns one machine-safe Core update disposition.
pub const fn core_update_disposition_name(disposition: CoreUpdateDisposition) -> &'static str {
    match disposition {
        CoreUpdateDisposition::Current => "current",
        CoreUpdateDisposition::Updated => "updated",
        CoreUpdateDisposition::CleanupPending => "cleanup_pending",
    }
}

// Returns one machine-safe durable Core update phase.
pub const fn core_update_phase_name(phase: CoreUpdatePhase) -> &'static str {
    match phase {
        CoreUpdatePhase::Requested => "requested",
        CoreUpdatePhase::Prepared => "prepared",
        CoreUpdatePhase::ServicesSnapshotted => "services_snapshotted",
        CoreUpdatePhase::Activated => "activated",
        CoreUpdatePhase::ServicesRebound => "services_rebound",
        CoreUpdatePhase::Verified => "verified",
        CoreUpdatePhase::Committed => "committed",
        CoreUpdatePhase::RollingBack => "rolling_back",
        CoreUpdatePhase::Current => "current",
        CoreUpdatePhase::CleanupPending => "cleanup_pending",
        CoreUpdatePhase::Succeeded => "succeeded",
        CoreUpdatePhase::RolledBack => "rolled_back",
        CoreUpdatePhase::RecoveryRequired => "recovery_required",
    }
}

// Derives one fixed private workspace identity from only the requested release selection.
fn availability_identity(
    requested_version: Option<&CoreVersion>,
) -> Result<Sha256Digest, CoreUpdateError> {
    let mut digest = Sha256::new();
    digest.update(b"li_core_update_availability_v1\0");
    digest.update(
        requested_version
            .map_or("latest", CoreVersion::as_str)
            .as_bytes(),
    );
    Sha256Digest::parse(&format!("{:x}", digest.finalize())).map_err(|_| {
        CoreUpdateError::provider("availability", "availability identity is unavailable")
    })
}
