// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use li_core_interface::{
    InstallationId, LogicalModelName, NodeId, PlacementGroupState, PlacementState, RuntimeIdentity,
    RuntimeInstallationId, Sha256Digest, TechnicalName,
};
use li_placement_manager::{
    LinuxPlacementProtectionProvider, PlacementProtectionPhase, PlacementStore,
};
use li_watchdog_manager::{
    WatchdogControllerBinding, WatchdogProtocolCapabilities, WatchdogProtocolDataError,
    WatchdogProtocolIdentityProvider, WatchdogProtocolResidentStatus, WatchdogProtocolSiteStatus,
};

use crate::{
    NodeProtectionApiError, NodeProtectionSiteStatusProvider, NodeWatchdogSessionAuthority,
};

// Carries the exact verified runtime projection required by Watchdog protocol status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeWatchdogRuntimeStatus {
    logical_model: LogicalModelName,
    runtime: RuntimeIdentity,
    engine_id: TechnicalName,
    cache_provider: TechnicalName,
    persistent_cache: bool,
}

impl NodeWatchdogRuntimeStatus {
    // Creates one verified runtime projection without accepting unbounded cache identity text.
    pub fn new(
        logical_model: LogicalModelName,
        runtime: RuntimeIdentity,
        engine_id: TechnicalName,
        cache_provider: &str,
        persistent_cache: bool,
    ) -> Result<Self, WatchdogProtocolDataError> {
        Ok(Self {
            logical_model,
            runtime,
            engine_id,
            cache_provider: TechnicalName::parse(cache_provider)
                .map_err(|_| WatchdogProtocolDataError::Unavailable)?,
            persistent_cache,
        })
    }
}

// Resolves one assigned installation through RuntimeManager's verified execution contract.
pub trait NodeWatchdogRuntimeProvider: Send + Sync {
    // Returns exact runtime and cache identity only after installation and manifest agreement.
    fn status(
        &self,
        installation_id: &RuntimeInstallationId,
    ) -> Result<NodeWatchdogRuntimeStatus, WatchdogProtocolDataError>;
}

// Projects exact Node and Placement state for one authenticated Watchdog target.
pub struct NodeWatchdogProtocolIdentityProvider {
    node_id: NodeId,
    core_release: String,
    core_source_identity: Sha256Digest,
    installation_id: String,
    capabilities: WatchdogProtocolCapabilities,
    site_status: NodeWatchdogSiteStatusProvider,
}

// Projects exact Node and Placement state for one authenticated Watchdog target.
pub struct NodeWatchdogSiteStatusProvider {
    core_release: String,
    installation_id: String,
    sessions: Arc<NodeWatchdogSessionAuthority>,
    placements: Arc<dyn PlacementStore>,
    runtimes: Arc<dyn NodeWatchdogRuntimeProvider>,
    protection: Arc<dyn LinuxPlacementProtectionProvider>,
}

impl NodeWatchdogProtocolIdentityProvider {
    // Creates one target-keyed identity projection from existing manager-owned capabilities.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        node_id: NodeId,
        core_release: String,
        core_source_identity: Sha256Digest,
        installation_id: String,
        sample_interval_milliseconds: u32,
        flush_interval_milliseconds: u32,
        physical_gpu_count: u32,
        sessions: Arc<NodeWatchdogSessionAuthority>,
        placements: Arc<dyn PlacementStore>,
        runtimes: Arc<dyn NodeWatchdogRuntimeProvider>,
        protection: Arc<dyn LinuxPlacementProtectionProvider>,
    ) -> Result<Self, WatchdogProtocolDataError> {
        let capabilities = WatchdogProtocolCapabilities::new(
            sample_interval_milliseconds,
            flush_interval_milliseconds,
            physical_gpu_count,
        )
        .map_err(|_| WatchdogProtocolDataError::Unavailable)?;
        if core_release.is_empty() || installation_id.is_empty() {
            return Err(WatchdogProtocolDataError::Unavailable);
        }
        let site_status = NodeWatchdogSiteStatusProvider::new(
            core_release.clone(),
            installation_id.clone(),
            sessions,
            placements,
            runtimes,
            protection,
        )?;
        Ok(Self {
            node_id,
            core_release,
            core_source_identity,
            installation_id,
            capabilities,
            site_status,
        })
    }
}

impl NodeWatchdogSiteStatusProvider {
    // Creates one Node-owned status projection without retaining Watchdog-local capabilities.
    pub fn new(
        core_release: String,
        installation_id: String,
        sessions: Arc<NodeWatchdogSessionAuthority>,
        placements: Arc<dyn PlacementStore>,
        runtimes: Arc<dyn NodeWatchdogRuntimeProvider>,
        protection: Arc<dyn LinuxPlacementProtectionProvider>,
    ) -> Result<Self, WatchdogProtocolDataError> {
        if core_release.is_empty() || installation_id.is_empty() {
            return Err(WatchdogProtocolDataError::Unavailable);
        }
        Ok(Self {
            core_release,
            installation_id,
            sessions,
            placements,
            runtimes,
            protection,
        })
    }

    // Resolves one binding through the exact durable group, runtime, endpoint, and protection state.
    fn status_for_binding(
        &self,
        binding: &WatchdogControllerBinding,
    ) -> Result<WatchdogProtocolSiteStatus, NodeProtectionApiError> {
        let session_target = self
            .sessions
            .target_for_binding(binding)
            .map_err(super::li_node_watchdog_session::protection_api_error)?;
        let record = self
            .placements
            .read(session_target.key().placement_group_id())
            .map_err(|_| NodeProtectionApiError::ProviderUnavailable)?
            .ok_or(NodeProtectionApiError::ProviderUnavailable)?;
        let record = record.record();
        let group = record.group();
        let mut placements = record
            .placements()
            .iter()
            .filter(|placement| placement.placement_id() == session_target.key().placement_id());
        let placement = placements
            .next()
            .ok_or(NodeProtectionApiError::ProviderUnavailable)?;
        if placements.next().is_some()
            || group.placement_group_id() != session_target.key().placement_group_id()
            || placement.placement_group_id() != session_target.key().placement_group_id()
            || group.state() != PlacementGroupState::Running
            || placement.state() != PlacementState::Running
        {
            return Err(NodeProtectionApiError::ProviderUnavailable);
        }
        let endpoint = group
            .endpoint()
            .filter(|endpoint| endpoint.health().healthy())
            .ok_or(NodeProtectionApiError::ProviderUnavailable)?;
        let runtime_status = self
            .runtimes
            .status(placement.assignment().runtime_installation_id())
            .map_err(|_| NodeProtectionApiError::ProviderUnavailable)?;
        if &runtime_status.runtime != group.runtime() {
            return Err(NodeProtectionApiError::ProviderUnavailable);
        }
        let protection = self
            .protection
            .status(placement, Some(session_target.protected().process()))
            .map_err(|_| NodeProtectionApiError::ProviderUnavailable)?;
        if protection.phase() != session_target.protected().phase() {
            return Err(NodeProtectionApiError::ProviderUnavailable);
        }
        let runtime = group.runtime();
        let maximum_context_tokens = u32::try_from(group.capacity().max_context_tokens())
            .map_err(|_| NodeProtectionApiError::ProviderUnavailable)?;
        WatchdogProtocolSiteStatus::new(
            self.core_release.clone(),
            runtime_status.logical_model.as_str().to_string(),
            runtime_status.engine_id.as_str().to_string(),
            runtime.candidate_id().as_str().to_string(),
            runtime.version().as_str().to_string(),
            runtime.manifest_digest().as_str().to_string(),
            runtime_status.cache_provider.as_str().to_string(),
            runtime_status.persistent_cache,
            u32::from(endpoint.address().port()),
            group.capacity().max_connections(),
            group.capacity().max_active_requests(),
            maximum_context_tokens,
            placement_group_state_name(group.state()).to_string(),
            placement_state_name(placement.state()).to_string(),
            protection_phase_name(protection.phase()).to_string(),
            protection.phase() == PlacementProtectionPhase::Armed,
            protection.trip_latched(),
            session_target
                .protected()
                .process()
                .container_name()
                .as_str()
                .to_string(),
            self.installation_id.clone(),
        )
        .map_err(|_| NodeProtectionApiError::ProviderUnavailable)
    }
}

impl NodeProtectionSiteStatusProvider for NodeWatchdogSiteStatusProvider {
    // Returns Node-owned status while preserving redacted authorization and conflict classes.
    fn status(
        &self,
        binding: &WatchdogControllerBinding,
    ) -> Result<WatchdogProtocolSiteStatus, NodeProtectionApiError> {
        self.status_for_binding(binding)
    }
}

impl WatchdogProtocolIdentityProvider for NodeWatchdogProtocolIdentityProvider {
    // Returns the immutable cadence and initialized physical-GPU capability document.
    fn capabilities(&self) -> Result<WatchdogProtocolCapabilities, WatchdogProtocolDataError> {
        Ok(self.capabilities.clone())
    }

    // Returns status only for the exact authenticated controller target.
    fn site_status(
        &self,
        binding: &WatchdogControllerBinding,
    ) -> Result<WatchdogProtocolSiteStatus, WatchdogProtocolDataError> {
        self.site_status
            .status_for_binding(binding)
            .map_err(|_| WatchdogProtocolDataError::Unavailable)
    }

    // Returns resident readiness from immutable Node composition without reading a placement.
    fn resident_status(&self) -> Result<WatchdogProtocolResidentStatus, WatchdogProtocolDataError> {
        WatchdogProtocolResidentStatus::ready(
            self.node_id.clone(),
            self.core_release.clone(),
            self.core_source_identity.clone(),
            InstallationId::parse(&self.installation_id)
                .map_err(|_| WatchdogProtocolDataError::Unavailable)?,
        )
        .map_err(|_| WatchdogProtocolDataError::Unavailable)
    }
}

// Returns the stable protocol name for the only accepted group state.
const fn placement_group_state_name(state: PlacementGroupState) -> &'static str {
    match state {
        PlacementGroupState::Running => "running",
        _ => "unavailable",
    }
}

// Returns the stable protocol name for the only accepted placement state.
const fn placement_state_name(state: PlacementState) -> &'static str {
    match state {
        PlacementState::Running => "running",
        _ => "unavailable",
    }
}

// Returns the exact placement protection phase vocabulary.
const fn protection_phase_name(phase: PlacementProtectionPhase) -> &'static str {
    match phase {
        PlacementProtectionPhase::Unconfigured => "unconfigured",
        PlacementProtectionPhase::Pending => "pending",
        PlacementProtectionPhase::Starting => "starting",
        PlacementProtectionPhase::Armed => "armed",
        PlacementProtectionPhase::Disarmed => "disarmed",
    }
}
