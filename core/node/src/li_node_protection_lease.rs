// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::num::NonZeroU64;
use std::sync::{Arc, Mutex};

use li_core_interface::{
    InstallationId, NodeId, NodeState, Placement, PlacementGroupId, PlacementId, UnixMilliseconds,
};
use li_gateway_manager::{
    GatewayError, GatewayPlacementProtectionLease, GatewayPlacementProtectionSnapshot,
    GatewayProtectionAuthority, GatewayProtectionLeaseProvider, GatewayRoute,
};
use li_placement_manager::{PlacementProtectedTarget, PlacementStore};
use li_watchdog_manager::{
    WatchdogProtectedEngine, WatchdogProtectionCycle, WatchdogProtectionPhase,
};

use crate::{DatabasePlacementStore, NodeManager};

const MAXIMUM_LEASE_MILLISECONDS: u64 = 60_000;

// Names stable failures at the Node-owned protection-lease boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodeProtectionLeaseError {
    InvalidContract,
    SessionUnavailable,
    RegressedCycle,
    StateUnavailable,
}

impl fmt::Display for NodeProtectionLeaseError {
    // Presents redacted protection language without native process values.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidContract => formatter.write_str("protection lease contract is invalid"),
            Self::SessionUnavailable => {
                formatter.write_str("Watchdog protection session is unavailable")
            }
            Self::RegressedCycle => formatter.write_str("Watchdog protection cycle regressed"),
            Self::StateUnavailable => formatter.write_str("protection lease state is unavailable"),
        }
    }
}

impl Error for NodeProtectionLeaseError {}

// Binds one Watchdog cycle target to its exact Node-owned placement identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeProtectionLeaseBinding {
    node_id: NodeId,
    placement_group_id: PlacementGroupId,
    placement_id: PlacementId,
    target: PlacementProtectedTarget,
}

// Carries the exact current Node lifecycle and Core installation used by route safety.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeProtectionNodeStatus {
    node_id: NodeId,
    core_installation_id: InstallationId,
    state: NodeState,
}

impl NodeProtectionNodeStatus {
    // Creates one immutable Node status observed by the NodeManager orchestrator.
    pub const fn new(
        node_id: NodeId,
        core_installation_id: InstallationId,
        state: NodeState,
    ) -> Self {
        Self {
            node_id,
            core_installation_id,
            state,
        }
    }

    // Returns the exact Node identity.
    pub const fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    // Returns the exact current Core installation identity.
    pub const fn core_installation_id(&self) -> &InstallationId {
        &self.core_installation_id
    }

    // Returns the current Node lifecycle state.
    pub const fn state(&self) -> NodeState {
        self.state
    }
}

impl NodeProtectionLeaseBinding {
    // Creates one explicit placement binding after the Node revalidates current placement state.
    pub const fn new(
        node_id: NodeId,
        placement_group_id: PlacementGroupId,
        placement_id: PlacementId,
        target: PlacementProtectedTarget,
    ) -> Self {
        Self {
            node_id,
            placement_group_id,
            placement_id,
            target,
        }
    }

    // Returns the Node that owns this placement process.
    pub const fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    // Returns the exact placement-group identity.
    pub const fn placement_group_id(&self) -> &PlacementGroupId {
        &self.placement_group_id
    }

    // Returns the exact placement identity.
    pub const fn placement_id(&self) -> &PlacementId {
        &self.placement_id
    }

    // Returns the current placement-owned process binding.
    pub const fn target(&self) -> &PlacementProtectedTarget {
        &self.target
    }
}

// Owns ephemeral protection sessions and leases inside the Node lifecycle.
// Production must allocate each supplied session generation through a durable Node-owned store.
#[derive(Default)]
pub struct NodeProtectionLeaseStore {
    state: Mutex<NodeProtectionLeaseState>,
}

impl NodeProtectionLeaseStore {
    // Creates an empty fail-closed store that requires a connected Watchdog session.
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(NodeProtectionLeaseState {
                sessions: BTreeMap::new(),
                leases: BTreeMap::new(),
            }),
        }
    }

    // Begins one authenticated session with an externally durable generation and clears old
    // leases.
    pub fn begin_watchdog_session(
        &self,
        authority: GatewayProtectionAuthority,
        connected_at: UnixMilliseconds,
        minimum_sample_sequence: NonZeroU64,
    ) -> Result<(), NodeProtectionLeaseError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| NodeProtectionLeaseError::StateUnavailable)?;
        let node_id = authority.node_id().clone();
        if let Some(session) = state.sessions.get(&node_id) {
            if session.authority == authority
                && session.minimum_sample_sequence == minimum_sample_sequence
            {
                return Ok(());
            }
            return Err(NodeProtectionLeaseError::RegressedCycle);
        }
        state.leases.retain(|_, lease| lease.node_id() != &node_id);
        state.sessions.insert(
            node_id,
            NodeProtectionSession {
                authority,
                connected_at,
                minimum_sample_sequence,
                last_sequence: None,
                last_observed_at: None,
                last_monotonic_milliseconds: None,
            },
        );
        Ok(())
    }

    // Invalidates one exact disconnected session without affecting sibling Nodes.
    pub fn end_watchdog_session(
        &self,
        node_id: &NodeId,
        watchdog_session_id: &li_core_interface::Sha256Digest,
        watchdog_session_generation: NonZeroU64,
    ) -> Result<(), NodeProtectionLeaseError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| NodeProtectionLeaseError::StateUnavailable)?;
        if state.sessions.get(node_id).is_some_and(|session| {
            session.authority.watchdog_session_id() == watchdog_session_id
                && session.authority.watchdog_session_generation() == watchdog_session_generation
        }) {
            state.sessions.remove(node_id);
            state.leases.retain(|_, lease| lease.node_id() != node_id);
        }
        Ok(())
    }

    // Atomically replaces one Node's leases only after a complete successful Watchdog cycle.
    pub fn commit_protection_cycle(
        &self,
        node_id: &NodeId,
        watchdog_session_id: &li_core_interface::Sha256Digest,
        watchdog_session_generation: NonZeroU64,
        cycle: &WatchdogProtectionCycle,
        bindings: &[NodeProtectionLeaseBinding],
        lease_milliseconds: u64,
    ) -> Result<Vec<GatewayPlacementProtectionLease>, NodeProtectionLeaseError> {
        if cycle.sample_sequence() == 0
            || lease_milliseconds == 0
            || lease_milliseconds > MAXIMUM_LEASE_MILLISECONDS
            || bindings.iter().any(|binding| binding.node_id() != node_id)
        {
            return Err(NodeProtectionLeaseError::InvalidContract);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| NodeProtectionLeaseError::StateUnavailable)?;
        let session = state
            .sessions
            .get(node_id)
            .ok_or(NodeProtectionLeaseError::SessionUnavailable)?;
        if session.authority.watchdog_session_id() != watchdog_session_id
            || session.authority.watchdog_session_generation() != watchdog_session_generation
        {
            return Err(NodeProtectionLeaseError::SessionUnavailable);
        }
        if cycle.sample_sequence() < session.minimum_sample_sequence.get()
            || cycle.observed_at_unix_milliseconds() < session.connected_at.value()
            || session
                .last_sequence
                .is_some_and(|sequence| cycle.sample_sequence() < sequence)
            || session
                .last_observed_at
                .is_some_and(|observed| cycle.observed_at_unix_milliseconds() < observed)
            || session
                .last_monotonic_milliseconds
                .is_some_and(|observed| cycle.observed_at_monotonic_milliseconds() < observed)
        {
            return Err(NodeProtectionLeaseError::RegressedCycle);
        }
        let expires_at = cycle
            .observed_at_unix_milliseconds()
            .checked_add(lease_milliseconds)
            .ok_or(NodeProtectionLeaseError::InvalidContract)?;
        let next = leases_for_cycle(session, cycle, bindings, expires_at)?;
        let current = state
            .leases
            .values()
            .filter(|lease| lease.node_id() == node_id)
            .cloned()
            .collect::<Vec<_>>();
        if session.last_sequence == Some(cycle.sample_sequence()) {
            if current == next {
                return Ok(next);
            }
            return Err(NodeProtectionLeaseError::RegressedCycle);
        }
        state.leases.retain(|_, lease| lease.node_id() != node_id);
        for lease in &next {
            state.leases.insert(
                (
                    lease.placement_group_id().clone(),
                    lease.placement_id().clone(),
                ),
                lease.clone(),
            );
        }
        let session = state
            .sessions
            .get_mut(node_id)
            .expect("validated Watchdog session remains present");
        session.last_sequence = Some(cycle.sample_sequence());
        session.last_observed_at = Some(cycle.observed_at_unix_milliseconds());
        session.last_monotonic_milliseconds = Some(cycle.observed_at_monotonic_milliseconds());
        Ok(next)
    }

    // Returns exact authorities and leases for a placement group or absence on session loss.
    pub fn placement_group_snapshot(
        &self,
        placement_group_id: &PlacementGroupId,
        expected: &[(PlacementId, NodeId)],
    ) -> Result<Option<GatewayPlacementProtectionSnapshot>, NodeProtectionLeaseError> {
        let state = self
            .state
            .lock()
            .map_err(|_| NodeProtectionLeaseError::StateUnavailable)?;
        snapshot_from_state(&state, placement_group_id, expected)
    }

    // Returns a snapshot only when every exact Node remains active on the bound installation.
    pub fn placement_group_snapshot_for_nodes(
        &self,
        placement_group_id: &PlacementGroupId,
        expected: &[(PlacementId, NodeId)],
        node_statuses: &[NodeProtectionNodeStatus],
    ) -> Result<Option<GatewayPlacementProtectionSnapshot>, NodeProtectionLeaseError> {
        let state = self
            .state
            .lock()
            .map_err(|_| NodeProtectionLeaseError::StateUnavailable)?;
        let statuses = node_statuses
            .iter()
            .map(|status| (status.node_id().clone(), status))
            .collect::<BTreeMap<_, _>>();
        let node_ids = expected
            .iter()
            .map(|(_, node_id)| node_id.clone())
            .collect::<BTreeSet<_>>();
        if statuses.len() != node_statuses.len()
            || statuses.keys().cloned().collect::<BTreeSet<_>>() != node_ids
        {
            return Ok(None);
        }
        for node_id in &node_ids {
            let Some(session) = state.sessions.get(&node_id) else {
                return Ok(None);
            };
            let status = statuses
                .get(node_id)
                .ok_or(NodeProtectionLeaseError::InvalidContract)?;
            if status.state() != NodeState::Active
                || status.core_installation_id() != session.authority.core_installation_id()
            {
                return Ok(None);
            }
        }
        snapshot_from_state(&state, placement_group_id, expected)
    }
}

// Stores one connected Watchdog authority and its monotonic cycle high-water mark.
struct NodeProtectionSession {
    authority: GatewayProtectionAuthority,
    connected_at: UnixMilliseconds,
    minimum_sample_sequence: NonZeroU64,
    last_sequence: Option<u64>,
    last_observed_at: Option<u64>,
    last_monotonic_milliseconds: Option<u64>,
}

// Stores the complete ephemeral Node-owned protection state.
#[derive(Default)]
struct NodeProtectionLeaseState {
    sessions: BTreeMap<NodeId, NodeProtectionSession>,
    leases: BTreeMap<(PlacementGroupId, PlacementId), GatewayPlacementProtectionLease>,
}

// Projects one group while the caller retains the exact session-state observation lock.
fn snapshot_from_state(
    state: &NodeProtectionLeaseState,
    placement_group_id: &PlacementGroupId,
    expected: &[(PlacementId, NodeId)],
) -> Result<Option<GatewayPlacementProtectionSnapshot>, NodeProtectionLeaseError> {
    let node_ids = expected
        .iter()
        .map(|(_, node_id)| node_id.clone())
        .collect::<BTreeSet<_>>();
    let mut authorities = Vec::new();
    for node_id in node_ids {
        let Some(session) = state.sessions.get(&node_id) else {
            return Ok(None);
        };
        authorities.push(session.authority.clone());
    }
    let leases = expected
        .iter()
        .filter_map(|(placement_id, _)| {
            state
                .leases
                .get(&(placement_group_id.clone(), placement_id.clone()))
                .cloned()
        })
        .collect();
    GatewayPlacementProtectionSnapshot::new(
        placement_group_id.clone(),
        expected.to_vec(),
        authorities,
        leases,
    )
    .map(Some)
    .map_err(|_| NodeProtectionLeaseError::InvalidContract)
}

// Resolves the exact current process target without granting Gateway manager access.
pub trait NodeProtectionTargetProvider: Send + Sync {
    // Returns the current active protection target for one placement.
    fn current_target(
        &self,
        placement: &Placement,
    ) -> Result<Option<PlacementProtectedTarget>, NodeProtectionLeaseError>;
}

// Resolves a completed Watchdog cycle to exact current Node-owned placement bindings.
pub trait NodeProtectionBindingProvider: Send + Sync {
    // Returns every unique current placement whose process appears in the completed cycle.
    fn bindings_for_cycle(
        &self,
        node_id: &NodeId,
        cycle: &WatchdogProtectionCycle,
    ) -> Result<Vec<NodeProtectionLeaseBinding>, NodeProtectionLeaseError>;
}

// Resolves authenticated Watchdog targets through current persisted placement state.
pub struct PersistedNodeProtectionBindingProvider {
    placements: Arc<DatabasePlacementStore>,
    targets: Arc<dyn NodeProtectionTargetProvider>,
}

impl PersistedNodeProtectionBindingProvider {
    // Creates one binding projection over explicit placement and live-target providers.
    pub const fn new(
        placements: Arc<DatabasePlacementStore>,
        targets: Arc<dyn NodeProtectionTargetProvider>,
    ) -> Self {
        Self {
            placements,
            targets,
        }
    }
}

impl NodeProtectionBindingProvider for PersistedNodeProtectionBindingProvider {
    // Requires every cycle target to resolve to exactly one active placement process.
    fn bindings_for_cycle(
        &self,
        node_id: &NodeId,
        cycle: &WatchdogProtectionCycle,
    ) -> Result<Vec<NodeProtectionLeaseBinding>, NodeProtectionLeaseError> {
        let mut bindings = Vec::new();
        for record in self
            .placements
            .records()
            .map_err(|_| NodeProtectionLeaseError::StateUnavailable)?
        {
            for placement in record.placements() {
                if placement.assignment().node_id() != node_id {
                    continue;
                }
                let Some(target) = self.targets.current_target(placement)? else {
                    continue;
                };
                if cycle
                    .targets()
                    .iter()
                    .any(|seed| target_matches(seed.target(), &target))
                {
                    bindings.push(NodeProtectionLeaseBinding::new(
                        node_id.clone(),
                        placement.placement_group_id().clone(),
                        placement.placement_id().clone(),
                        target,
                    ));
                }
            }
        }
        Ok(bindings)
    }
}

// Projects Node-owned sessions, placements, and live targets into Gateway's narrow boundary.
pub struct NodeGatewayProtectionLeaseProvider {
    manager: Arc<NodeManager>,
    placements: Arc<DatabasePlacementStore>,
    leases: Arc<NodeProtectionLeaseStore>,
    targets: Arc<dyn NodeProtectionTargetProvider>,
}

impl NodeGatewayProtectionLeaseProvider {
    // Creates one read-only Gateway projection from explicit Node-owned capabilities.
    pub const fn new(
        manager: Arc<NodeManager>,
        placements: Arc<DatabasePlacementStore>,
        leases: Arc<NodeProtectionLeaseStore>,
        targets: Arc<dyn NodeProtectionTargetProvider>,
    ) -> Self {
        Self {
            manager,
            placements,
            leases,
            targets,
        }
    }

    // Returns current protection for one exact group and endpoint without a synthetic route.
    pub fn snapshot_for_group(
        &self,
        placement_group_id: &PlacementGroupId,
        endpoint_node_id: &NodeId,
    ) -> Result<Option<GatewayPlacementProtectionSnapshot>, GatewayError> {
        self.snapshot_for_identity(placement_group_id, endpoint_node_id)
    }

    // Projects one exact group only while every Node and process remains active.
    fn snapshot_for_identity(
        &self,
        placement_group_id: &PlacementGroupId,
        endpoint_node_id: &NodeId,
    ) -> Result<Option<GatewayPlacementProtectionSnapshot>, GatewayError> {
        let record = self
            .placements
            .read(placement_group_id)
            .map_err(|_| gateway_protection_error())?
            .ok_or_else(gateway_protection_error)?;
        let record = record.record();
        if !record
            .placements()
            .iter()
            .any(|placement| placement.assignment().node_id() == endpoint_node_id)
        {
            return Ok(None);
        }
        let mut expected = Vec::new();
        let mut node_statuses = BTreeMap::new();
        let mut current_targets = BTreeMap::new();
        for placement in record.placements() {
            let node_id = placement.assignment().node_id().clone();
            let node = self
                .manager
                .node(&node_id)
                .map_err(|_| gateway_protection_error())?;
            node_statuses.insert(
                node_id.clone(),
                NodeProtectionNodeStatus::new(
                    node_id.clone(),
                    node.value().identity().installation_id().clone(),
                    node.value().state(),
                ),
            );
            let Some(target) = self
                .targets
                .current_target(placement)
                .map_err(|_| gateway_protection_error())?
            else {
                return Ok(None);
            };
            if target.phase() != li_placement_manager::PlacementProtectionPhase::Armed {
                return Ok(None);
            }
            current_targets.insert(placement.placement_id().clone(), target);
            expected.push((placement.placement_id().clone(), node_id));
        }
        let Some(snapshot) = self
            .leases
            .placement_group_snapshot_for_nodes(
                placement_group_id,
                &expected,
                &node_statuses.into_values().collect::<Vec<_>>(),
            )
            .map_err(|_| gateway_protection_error())?
        else {
            return Ok(None);
        };
        for placement in record.placements() {
            let target = current_targets
                .get(placement.placement_id())
                .ok_or_else(gateway_protection_error)?;
            let matching = snapshot.leases().iter().filter(|lease| {
                lease.placement_id() == placement.placement_id()
                    && lease_matches_target(lease, target)
            });
            if matching.count() != 1 {
                return Ok(None);
            }
        }
        Ok(Some(snapshot))
    }
}

impl GatewayProtectionLeaseProvider for NodeGatewayProtectionLeaseProvider {
    // Requires every running group placement to retain one current identity-bound lease.
    fn snapshot(
        &self,
        route: &GatewayRoute,
    ) -> Result<Option<GatewayPlacementProtectionSnapshot>, GatewayError> {
        self.snapshot_for_identity(route.placement_group_id(), route.endpoint_node_id())
    }
}

// Builds exact leases only when every completed-cycle target has one placement binding.
fn leases_for_cycle(
    session: &NodeProtectionSession,
    cycle: &WatchdogProtectionCycle,
    bindings: &[NodeProtectionLeaseBinding],
    expires_at: u64,
) -> Result<Vec<GatewayPlacementProtectionLease>, NodeProtectionLeaseError> {
    let mut used = BTreeSet::new();
    let mut leases = Vec::new();
    for seed in cycle.targets() {
        let matches = bindings
            .iter()
            .enumerate()
            .filter(|(_, binding)| target_matches(seed.target(), binding.target()))
            .collect::<Vec<_>>();
        if matches.len() != 1 || !used.insert(matches[0].0) {
            return Err(NodeProtectionLeaseError::InvalidContract);
        }
        let binding = matches[0].1;
        let process = binding.target().process();
        leases.push(
            GatewayPlacementProtectionLease::new(
                binding.node_id().clone(),
                binding.placement_group_id().clone(),
                binding.placement_id().clone(),
                session.authority.core_installation_id().clone(),
                session.authority.watchdog_source_identity().clone(),
                session.authority.watchdog_session_id().clone(),
                session.authority.watchdog_session_generation(),
                binding.target().generation().as_str(),
                process.container_name().clone(),
                process.container_id().clone(),
                process.process_id(),
                process.process_start_ticks(),
                process.boot_id().clone(),
                process.cgroup(),
                NonZeroU64::new(cycle.sample_sequence())
                    .ok_or(NodeProtectionLeaseError::InvalidContract)?,
                UnixMilliseconds::new(cycle.observed_at_unix_milliseconds()),
                cycle.observed_at_monotonic_milliseconds(),
                UnixMilliseconds::new(expires_at),
                true,
                false,
            )
            .map_err(|_| NodeProtectionLeaseError::InvalidContract)?,
        );
    }
    if used.len() != bindings.len() {
        return Err(NodeProtectionLeaseError::InvalidContract);
    }
    leases.sort_by(|left, right| left.placement_id().cmp(right.placement_id()));
    Ok(leases)
}

// Requires Watchdog and Placement to name one exact armed process generation.
fn target_matches(
    watchdog: &WatchdogProtectedEngine,
    placement: &PlacementProtectedTarget,
) -> bool {
    let process = placement.process();
    watchdog.phase() == WatchdogProtectionPhase::Armed
        && watchdog.generation() == placement.generation().as_str()
        && watchdog.container_name() == process.container_name().as_str()
        && watchdog.container_id() == Some(process.container_id().as_str())
        && watchdog.process_id() == Some(process.process_id())
        && watchdog.process_start_ticks() == Some(process.process_start_ticks())
        && watchdog.boot_id() == Some(process.boot_id().as_str())
        && watchdog.cgroup() == Some(process.cgroup())
}

// Requires a Gateway lease to retain the same current placement process identity.
fn lease_matches_target(
    lease: &GatewayPlacementProtectionLease,
    target: &PlacementProtectedTarget,
) -> bool {
    let process = target.process();
    lease.protection_generation() == target.generation().as_str()
        && lease.container_name() == process.container_name()
        && lease.container_id() == process.container_id()
        && lease.process_id() == process.process_id()
        && lease.process_start_ticks() == process.process_start_ticks()
        && lease.boot_id() == process.boot_id()
        && lease.cgroup() == process.cgroup()
}

// Creates one stable Gateway-facing Node protection availability failure.
const fn gateway_protection_error() -> GatewayError {
    GatewayError::provider(
        "placement protection",
        "Node protection state is unavailable",
    )
}
