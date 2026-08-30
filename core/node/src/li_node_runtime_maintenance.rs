// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::sync::Arc;

use li_core_interface::{RuntimeInstallationId, RuntimeInstallationState};
use li_runtime_manager::{RuntimeError, RuntimeEvent, RuntimeInstallationStore, RuntimeManager};

pub const MAXIMUM_RUNTIME_INSTALLATIONS: usize = 4096;

// Describes whether one exact runtime removal changed state or replayed a terminal removal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeRuntimeRemovalDisposition {
    Applied,
    Replayed,
}

// Identifies whether runtime removal retains exact model bytes for later acquisition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeRuntimeModelRetention {
    Remove,
    Preserve,
}

// Describes one bounded runtime-maintenance projection or provider failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeRuntimeMaintenanceError {
    InvalidProjection,
    Conflict,
    ProviderUnavailable,
}

impl fmt::Display for NodeRuntimeMaintenanceError {
    // Presents stable runtime-maintenance language without persistence or artifact detail.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidProjection => "runtime maintenance projection is invalid",
            Self::Conflict => "runtime installation changed during maintenance",
            Self::ProviderUnavailable => "runtime maintenance provider is unavailable",
        })
    }
}

impl Error for NodeRuntimeMaintenanceError {}

// Defines the narrow RuntimeManager removal capability composed behind Node ownership.
pub trait NodeRuntimeRemovalProvider: Send + Sync {
    // Removes one exact installation through RuntimeManager's lifecycle.
    fn remove(&self, installation_id: &RuntimeInstallationId) -> Result<(), RuntimeError>;

    // Removes one exact installation while retaining verified model bytes.
    fn remove_preserving_models(
        &self,
        _installation_id: &RuntimeInstallationId,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::ArtifactUnavailable)
    }

    // Finalizes the managed artifact root after every installation is terminally removed.
    fn finalize_cleanup(&self, _retention: NodeRuntimeModelRetention) -> Result<(), RuntimeError> {
        Err(RuntimeError::ArtifactUnavailable)
    }
}

impl NodeRuntimeRemovalProvider for RuntimeManager {
    // Delegates one exact removal without introducing another runtime lifecycle owner.
    fn remove(&self, installation_id: &RuntimeInstallationId) -> Result<(), RuntimeError> {
        let change = RuntimeManager::remove(self, installation_id)?;
        if change.installation().installation().installation_id() != installation_id
            || change.installation().installation().state() != RuntimeInstallationState::Removed
            || !matches!(
                change.event(),
                RuntimeEvent::InstallationRemoved {
                    installation_id: removed
                } if removed == installation_id
            )
        {
            return Err(RuntimeError::LifecycleUnavailable);
        }
        Ok(())
    }

    // Delegates selective model retention to RuntimeManager's lifecycle.
    fn remove_preserving_models(
        &self,
        installation_id: &RuntimeInstallationId,
    ) -> Result<(), RuntimeError> {
        let change = RuntimeManager::remove_preserving_models(self, installation_id)?;
        if change.installation().installation().installation_id() != installation_id
            || change.installation().installation().state() != RuntimeInstallationState::Removed
            || !matches!(
                change.event(),
                RuntimeEvent::InstallationRemoved {
                    installation_id: removed
                } if removed == installation_id
            )
        {
            return Err(RuntimeError::LifecycleUnavailable);
        }
        Ok(())
    }

    // Delegates complete root validation and policy-bound closure to RuntimeManager.
    fn finalize_cleanup(&self, retention: NodeRuntimeModelRetention) -> Result<(), RuntimeError> {
        RuntimeManager::finalize_cleanup(
            self,
            matches!(retention, NodeRuntimeModelRetention::Preserve),
        )
    }
}

// Defines the local-only runtime-maintenance surface consumed by uninstall.
pub trait NodeRuntimeMaintenanceApiPort: Send + Sync {
    // Returns every exact runtime installation identity in stable bounded order.
    fn installation_ids(&self) -> Result<Vec<RuntimeInstallationId>, NodeRuntimeMaintenanceError>;

    // Removes one exact runtime installation idempotently through RuntimeManager.
    fn remove(
        &self,
        installation_id: &RuntimeInstallationId,
        retention: NodeRuntimeModelRetention,
    ) -> Result<NodeRuntimeRemovalDisposition, NodeRuntimeMaintenanceError>;

    // Finalizes the RuntimeManager-owned root only after every store record is Removed.
    fn finalize_cleanup(
        &self,
        retention: NodeRuntimeModelRetention,
    ) -> Result<(), NodeRuntimeMaintenanceError>;
}

// Owns Node-local ordering across the existing runtime store and RuntimeManager.
pub struct NodeRuntimeMaintenanceCoordinator {
    runtime: Arc<dyn NodeRuntimeRemovalProvider>,
    store: Arc<dyn RuntimeInstallationStore>,
}

impl NodeRuntimeMaintenanceCoordinator {
    // Creates one adapter without opening another database or runtime lifecycle.
    pub fn new(
        runtime: Arc<dyn NodeRuntimeRemovalProvider>,
        store: Arc<dyn RuntimeInstallationStore>,
    ) -> Self {
        Self { runtime, store }
    }

    // Returns a complete bounded identity projection and rejects duplicate store records.
    pub fn installation_ids(
        &self,
    ) -> Result<Vec<RuntimeInstallationId>, NodeRuntimeMaintenanceError> {
        let installations = self.store.all().map_err(runtime_error)?;
        if installations.len() > MAXIMUM_RUNTIME_INSTALLATIONS {
            return Err(NodeRuntimeMaintenanceError::InvalidProjection);
        }
        let mut identities = installations
            .into_iter()
            .map(|installation| installation.installation().installation_id().clone())
            .collect::<Vec<_>>();
        identities.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        if identities.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(NodeRuntimeMaintenanceError::InvalidProjection);
        }
        Ok(identities)
    }

    // Removes one present record and distinguishes a terminal replay from a new transition.
    pub fn remove(
        &self,
        installation_id: &RuntimeInstallationId,
        retention: NodeRuntimeModelRetention,
    ) -> Result<NodeRuntimeRemovalDisposition, NodeRuntimeMaintenanceError> {
        let current = self
            .store
            .read(installation_id)
            .map_err(runtime_error)?
            .ok_or(NodeRuntimeMaintenanceError::Conflict)?;
        let disposition = if current.installation().state() == RuntimeInstallationState::Removed {
            NodeRuntimeRemovalDisposition::Replayed
        } else {
            NodeRuntimeRemovalDisposition::Applied
        };
        match retention {
            NodeRuntimeModelRetention::Remove => self.runtime.remove(installation_id),
            NodeRuntimeModelRetention::Preserve => {
                self.runtime.remove_preserving_models(installation_id)
            }
        }
        .map_err(runtime_error)?;
        Ok(disposition)
    }

    // Requires terminal authoritative store state before delegating root finalization.
    pub fn finalize_cleanup(
        &self,
        retention: NodeRuntimeModelRetention,
    ) -> Result<(), NodeRuntimeMaintenanceError> {
        let installations = self.store.all().map_err(runtime_error)?;
        if installations.len() > MAXIMUM_RUNTIME_INSTALLATIONS {
            return Err(NodeRuntimeMaintenanceError::InvalidProjection);
        }
        let mut identities = installations
            .iter()
            .map(|installation| installation.installation().installation_id())
            .collect::<Vec<_>>();
        identities.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        if identities.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(NodeRuntimeMaintenanceError::InvalidProjection);
        }
        if installations.iter().any(|installation| {
            installation.installation().state() != RuntimeInstallationState::Removed
        }) {
            return Err(NodeRuntimeMaintenanceError::Conflict);
        }
        self.runtime
            .finalize_cleanup(retention)
            .map_err(runtime_error)
    }
}

impl NodeRuntimeMaintenanceApiPort for NodeRuntimeMaintenanceCoordinator {
    // Returns the coordinator's complete bounded runtime identity projection.
    fn installation_ids(&self) -> Result<Vec<RuntimeInstallationId>, NodeRuntimeMaintenanceError> {
        NodeRuntimeMaintenanceCoordinator::installation_ids(self)
    }

    // Applies or replays one exact RuntimeManager-owned removal.
    fn remove(
        &self,
        installation_id: &RuntimeInstallationId,
        retention: NodeRuntimeModelRetention,
    ) -> Result<NodeRuntimeRemovalDisposition, NodeRuntimeMaintenanceError> {
        NodeRuntimeMaintenanceCoordinator::remove(self, installation_id, retention)
    }

    // Applies or safely replays complete RuntimeManager-owned root finalization.
    fn finalize_cleanup(
        &self,
        retention: NodeRuntimeModelRetention,
    ) -> Result<(), NodeRuntimeMaintenanceError> {
        NodeRuntimeMaintenanceCoordinator::finalize_cleanup(self, retention)
    }
}

// Maps optimistic conflicts separately while redacting every provider failure.
fn runtime_error(error: RuntimeError) -> NodeRuntimeMaintenanceError {
    match error {
        RuntimeError::StoreConflict | RuntimeError::InstallationNotFound => {
            NodeRuntimeMaintenanceError::Conflict
        }
        _ => NodeRuntimeMaintenanceError::ProviderUnavailable,
    }
}
