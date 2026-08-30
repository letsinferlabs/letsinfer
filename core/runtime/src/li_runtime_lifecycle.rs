// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use li_core_interface::{
    EntityTimestamps, FailureDescription, NodeId, RuntimeInstallation, RuntimeInstallationId,
    RuntimeInstallationState, TechnicalName, UnixMilliseconds,
};

use crate::{RuntimeCandidate, RuntimeError, RuntimeExactCandidateArtifacts};

// Defines immutable model, runtime, and Engine artifact acquisition.
pub trait RuntimeArtifactProvider: Send + Sync {
    // Acquires every exact artifact atomically and cleans its uncommitted bytes on failure.
    fn acquire(
        &self,
        candidate: &RuntimeCandidate,
        installation_id: &RuntimeInstallationId,
    ) -> Result<(), RuntimeError>;

    // Acquires only one preparation-verified resident closure without public reselection or refetch.
    fn acquire_exact(
        &self,
        _candidate: &RuntimeCandidate,
        _artifacts: &RuntimeExactCandidateArtifacts,
        _installation_id: &RuntimeInstallationId,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::ArtifactUnavailable)
    }

    // Verifies every materialized artifact against its immutable identity.
    fn verify(
        &self,
        candidate: &RuntimeCandidate,
        installation_id: &RuntimeInstallationId,
    ) -> Result<(), RuntimeError>;

    // Removes only the exact installation root after failure or removal.
    fn remove(&self, installation_id: &RuntimeInstallationId) -> Result<(), RuntimeError>;

    // Retains verified model bytes while removing every other exact installation artifact.
    fn remove_preserving_models(
        &self,
        _installation: &RuntimeInstallation,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::ArtifactUnavailable)
    }

    // Closes the managed root after every store-owned installation reached Removed.
    fn finalize_cleanup(
        &self,
        _installations: &[RuntimeInstallation],
        _preserve_models: bool,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::ArtifactUnavailable)
    }
}

// Returns one installation with its optimistic store revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionedRuntimeInstallation {
    installation: RuntimeInstallation,
    revision: u64,
}

impl VersionedRuntimeInstallation {
    // Creates one exact versioned installation result.
    pub const fn new(installation: RuntimeInstallation, revision: u64) -> Self {
        Self {
            installation,
            revision,
        }
    }

    // Returns the runtime installation snapshot.
    pub const fn installation(&self) -> &RuntimeInstallation {
        &self.installation
    }

    // Returns the revision required by the next transition.
    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

// Defines the narrow durable installation store consumed by RuntimeManager.
pub trait RuntimeInstallationStore: Send + Sync {
    // Returns one installation when it exists.
    fn read(
        &self,
        installation_id: &RuntimeInstallationId,
    ) -> Result<Option<VersionedRuntimeInstallation>, RuntimeError>;

    // Returns every installation in stable identity order.
    fn all(&self) -> Result<Vec<VersionedRuntimeInstallation>, RuntimeError>;

    // Creates one staging installation only when its identity is absent.
    fn create(
        &self,
        installation: RuntimeInstallation,
    ) -> Result<VersionedRuntimeInstallation, RuntimeError>;

    // Replaces one exact installation revision.
    fn replace(
        &self,
        installation: RuntimeInstallation,
        expected_revision: u64,
    ) -> Result<VersionedRuntimeInstallation, RuntimeError>;

    // Deletes one exact removed installation revision.
    fn delete(
        &self,
        installation_id: &RuntimeInstallationId,
        expected_revision: u64,
    ) -> Result<(), RuntimeError>;
}

// Supplies runtime-installation identities explicitly.
pub trait RuntimeInstallationIdentityProvider: Send + Sync {
    // Returns one new canonical runtime-installation identity.
    fn installation_id(&self) -> Result<RuntimeInstallationId, RuntimeError>;
}

// Supplies runtime lifecycle time explicitly.
pub trait RuntimeClock: Send + Sync {
    // Returns current Unix time in milliseconds.
    fn now(&self) -> Result<UnixMilliseconds, RuntimeError>;
}

// Supplies cryptographically random runtime-installation identities to production composition.
pub struct SystemRuntimeInstallationIdentityProvider;

impl RuntimeInstallationIdentityProvider for SystemRuntimeInstallationIdentityProvider {
    // Returns one lowercase 128-bit identity without process-local counters or host state.
    fn installation_id(&self) -> Result<RuntimeInstallationId, RuntimeError> {
        let mut bytes = [0_u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| RuntimeError::LifecycleUnavailable)?;
        let value = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        RuntimeInstallationId::parse(&value).map_err(|_| RuntimeError::LifecycleUnavailable)
    }
}

// Supplies wall-clock time to the production runtime lifecycle.
pub struct SystemRuntimeClock;

impl RuntimeClock for SystemRuntimeClock {
    // Returns current Unix time in milliseconds without fabricating a value on clock failure.
    fn now(&self) -> Result<UnixMilliseconds, RuntimeError> {
        let value = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| RuntimeError::LifecycleUnavailable)?
            .as_millis();
        let value = u64::try_from(value).map_err(|_| RuntimeError::LifecycleUnavailable)?;
        Ok(UnixMilliseconds::new(value))
    }
}

// Describes one completed runtime installation transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeEvent {
    InstallationAvailable {
        installation_id: RuntimeInstallationId,
    },
    InstallationFailed {
        installation_id: RuntimeInstallationId,
    },
    InstallationRemoved {
        installation_id: RuntimeInstallationId,
    },
}

// Returns one versioned installation and its completed event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeChange {
    installation: VersionedRuntimeInstallation,
    event: RuntimeEvent,
}

impl RuntimeChange {
    // Creates one completed runtime lifecycle result.
    const fn new(installation: VersionedRuntimeInstallation, event: RuntimeEvent) -> Self {
        Self {
            installation,
            event,
        }
    }

    // Returns the versioned runtime installation.
    pub const fn installation(&self) -> &VersionedRuntimeInstallation {
        &self.installation
    }

    // Returns the completed runtime event.
    pub const fn event(&self) -> &RuntimeEvent {
        &self.event
    }
}

// Owns injected acquisition, persistence, identity, and time capabilities.
pub(crate) struct RuntimeLifecycle {
    artifacts: Arc<dyn RuntimeArtifactProvider>,
    store: Arc<dyn RuntimeInstallationStore>,
    identity: Arc<dyn RuntimeInstallationIdentityProvider>,
    clock: Arc<dyn RuntimeClock>,
}

impl RuntimeLifecycle {
    // Creates one complete runtime installation lifecycle owner.
    pub(crate) fn new(
        artifacts: Arc<dyn RuntimeArtifactProvider>,
        store: Arc<dyn RuntimeInstallationStore>,
        identity: Arc<dyn RuntimeInstallationIdentityProvider>,
        clock: Arc<dyn RuntimeClock>,
    ) -> Self {
        Self {
            artifacts,
            store,
            identity,
            clock,
        }
    }

    // Stages, acquires, verifies, and activates one exact candidate installation.
    pub(crate) fn install(
        &self,
        node_id: NodeId,
        candidate: RuntimeCandidate,
    ) -> Result<RuntimeChange, RuntimeError> {
        let installation_id = self.identity.installation_id()?;
        self.install_with(node_id, installation_id, candidate, None)
    }

    // Installs one exact trusted closure under a precommitted deterministic identity.
    pub(crate) fn install_exact(
        &self,
        node_id: NodeId,
        installation_id: RuntimeInstallationId,
        candidate: RuntimeCandidate,
        artifacts: RuntimeExactCandidateArtifacts,
    ) -> Result<RuntimeChange, RuntimeError> {
        self.install_with(node_id, installation_id, candidate, Some(artifacts))
    }

    // Completes one ordinary or preparation-trusted installation through the same state machine.
    fn install_with(
        &self,
        node_id: NodeId,
        installation_id: RuntimeInstallationId,
        candidate: RuntimeCandidate,
        exact_artifacts: Option<RuntimeExactCandidateArtifacts>,
    ) -> Result<RuntimeChange, RuntimeError> {
        let created_at = self.clock.now()?;
        let staging = installation(
            installation_id.clone(),
            node_id,
            &candidate,
            RuntimeInstallationState::Staging,
            None,
            created_at,
            created_at,
        )?;
        let stored = self.store.create(staging)?;
        let acquired = exact_artifacts
            .as_ref()
            .map_or_else(
                || self.artifacts.acquire(&candidate, &installation_id),
                |artifacts| {
                    self.artifacts
                        .acquire_exact(&candidate, artifacts, &installation_id)
                },
            )
            .and_then(|_| self.artifacts.verify(&candidate, &installation_id));
        if acquired.is_err() {
            let _ = self.artifacts.remove(&installation_id);
            let failed_at = self.clock.now()?;
            let failure = FailureDescription::new(
                TechnicalName::parse("runtime_acquisition_failed")
                    .map_err(|_| RuntimeError::LifecycleUnavailable)?,
                "Runtime acquisition or verification failed",
            )
            .map_err(|_| RuntimeError::LifecycleUnavailable)?;
            let failed = installation(
                installation_id.clone(),
                stored.installation().node_id().clone(),
                &candidate,
                RuntimeInstallationState::Failed,
                Some(failure),
                stored.installation().timestamps().created_at(),
                failed_at,
            )?;
            let failed = self.store.replace(failed, stored.revision())?;
            return Ok(RuntimeChange::new(
                failed,
                RuntimeEvent::InstallationFailed { installation_id },
            ));
        }
        let available_at = self.clock.now()?;
        let available = installation(
            installation_id.clone(),
            stored.installation().node_id().clone(),
            &candidate,
            RuntimeInstallationState::Available,
            None,
            stored.installation().timestamps().created_at(),
            available_at,
        )?;
        let available = self.store.replace(available, stored.revision())?;
        Ok(RuntimeChange::new(
            available,
            RuntimeEvent::InstallationAvailable { installation_id },
        ))
    }

    // Removes one exact installation through Removing and Removed snapshots.
    pub(crate) fn remove(
        &self,
        installation_id: &RuntimeInstallationId,
        preserve_models: bool,
    ) -> Result<RuntimeChange, RuntimeError> {
        let current = self
            .store
            .read(installation_id)?
            .ok_or(RuntimeError::InstallationNotFound)?;
        if current.installation().state() == RuntimeInstallationState::Removed {
            return Ok(RuntimeChange::new(
                current,
                RuntimeEvent::InstallationRemoved {
                    installation_id: installation_id.clone(),
                },
            ));
        }
        let removing_at = self.clock.now()?;
        let removing = installation_from_existing(
            current.installation(),
            RuntimeInstallationState::Removing,
            None,
            removing_at,
        )?;
        let removing = self.store.replace(removing, current.revision())?;
        let artifact_removal = if preserve_models
            && matches!(
                current.installation().state(),
                RuntimeInstallationState::Available | RuntimeInstallationState::Removing
            ) {
            self.artifacts
                .remove_preserving_models(current.installation())
        } else {
            self.artifacts.remove(installation_id)
        };
        if artifact_removal.is_err() {
            let failed_at = self.clock.now()?;
            let failure = FailureDescription::new(
                TechnicalName::parse("runtime_removal_failed")
                    .map_err(|_| RuntimeError::LifecycleUnavailable)?,
                "Runtime removal failed",
            )
            .map_err(|_| RuntimeError::LifecycleUnavailable)?;
            let failed = installation_from_existing(
                removing.installation(),
                RuntimeInstallationState::Failed,
                Some(failure),
                failed_at,
            )?;
            let failed = self.store.replace(failed, removing.revision())?;
            return Ok(RuntimeChange::new(
                failed,
                RuntimeEvent::InstallationFailed {
                    installation_id: installation_id.clone(),
                },
            ));
        }
        let removed_at = self.clock.now()?;
        let removed = installation_from_existing(
            removing.installation(),
            RuntimeInstallationState::Removed,
            None,
            removed_at,
        )?;
        let removed = self.store.replace(removed, removing.revision())?;
        Ok(RuntimeChange::new(
            removed,
            RuntimeEvent::InstallationRemoved {
                installation_id: installation_id.clone(),
            },
        ))
    }

    // Removes and deletes every installation not retained by NodeManager references.
    pub(crate) fn prune(
        &self,
        retained: &HashSet<RuntimeInstallationId>,
    ) -> Result<Vec<RuntimeInstallationId>, RuntimeError> {
        let candidates = self.store.all()?;
        let mut pruned = Vec::new();
        for candidate in candidates {
            let installation_id = candidate.installation().installation_id().clone();
            if retained.contains(&installation_id) {
                continue;
            }
            let removed = if candidate.installation().state() == RuntimeInstallationState::Removed {
                candidate
            } else {
                self.remove(&installation_id, false)?.installation().clone()
            };
            if removed.installation().state() != RuntimeInstallationState::Removed {
                continue;
            }
            self.store.delete(&installation_id, removed.revision())?;
            pruned.push(installation_id);
        }
        Ok(pruned)
    }

    // Verifies terminal store state before closing every provider-owned cleanup residue.
    pub(crate) fn finalize_cleanup(&self, preserve_models: bool) -> Result<(), RuntimeError> {
        let installations = self.store.all()?;
        if installations.iter().any(|installation| {
            installation.installation().state() != RuntimeInstallationState::Removed
        }) {
            return Err(RuntimeError::InstallationUnavailable);
        }
        let installations = installations
            .into_iter()
            .map(|installation| installation.installation)
            .collect::<Vec<_>>();
        self.artifacts
            .finalize_cleanup(&installations, preserve_models)
    }
}

// Creates one coherent installation snapshot for a lifecycle transition.
#[allow(clippy::too_many_arguments)]
fn installation(
    installation_id: RuntimeInstallationId,
    node_id: NodeId,
    candidate: &RuntimeCandidate,
    state: RuntimeInstallationState,
    failure: Option<FailureDescription>,
    created_at: UnixMilliseconds,
    updated_at: UnixMilliseconds,
) -> Result<RuntimeInstallation, RuntimeError> {
    RuntimeInstallation::new(
        installation_id,
        node_id,
        candidate.logical_model().clone(),
        candidate.runtime().clone(),
        candidate.artifacts().to_vec(),
        candidate.evidence_label(),
        state,
        failure,
        EntityTimestamps::new(created_at, updated_at)
            .map_err(|_| RuntimeError::LifecycleUnavailable)?,
    )
    .map_err(|_| RuntimeError::LifecycleUnavailable)
}

// Copies one installation identity into a new lifecycle state.
fn installation_from_existing(
    current: &RuntimeInstallation,
    state: RuntimeInstallationState,
    failure: Option<FailureDescription>,
    updated_at: UnixMilliseconds,
) -> Result<RuntimeInstallation, RuntimeError> {
    RuntimeInstallation::new(
        current.installation_id().clone(),
        current.node_id().clone(),
        current.logical_model().clone(),
        current.runtime().clone(),
        current.artifacts().to_vec(),
        current.evidence_label(),
        state,
        failure,
        EntityTimestamps::new(current.timestamps().created_at(), updated_at)
            .map_err(|_| RuntimeError::LifecycleUnavailable)?,
    )
    .map_err(|_| RuntimeError::LifecycleUnavailable)
}
