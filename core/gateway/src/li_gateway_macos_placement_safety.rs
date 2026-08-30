// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, BTreeSet};

use li_core_interface::{
    InstallationId, NodeId, PlacementGroupId, PlacementId, Sha256Digest, UnixMilliseconds,
};

use crate::{GatewayError, GatewayRoute};

const MAXIMUM_MACOS_SAFETY_LEASE_MILLISECONDS: u64 = 60_000;

// Carries one exact expiring macOS Node/launchd process observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayMacOsPlacementSafetyLease {
    node_id: NodeId,
    placement_group_id: PlacementGroupId,
    placement_id: PlacementId,
    core_installation_id: InstallationId,
    executable_identity: Sha256Digest,
    launchd_label: String,
    launch_generation: Sha256Digest,
    process_id: u32,
    process_start_time_unix_milliseconds: UnixMilliseconds,
    observed_at: UnixMilliseconds,
    expires_at: UnixMilliseconds,
}

impl GatewayMacOsPlacementSafetyLease {
    // Creates one native macOS safety proof without inventing Watchdog identity.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        node_id: NodeId,
        placement_group_id: PlacementGroupId,
        placement_id: PlacementId,
        core_installation_id: InstallationId,
        executable_identity: Sha256Digest,
        launchd_label: &str,
        launch_generation: Sha256Digest,
        process_id: u32,
        process_start_time_unix_milliseconds: UnixMilliseconds,
        observed_at: UnixMilliseconds,
        expires_at: UnixMilliseconds,
    ) -> Result<Self, GatewayError> {
        if !valid_launchd_label(launchd_label)
            || process_id <= 1
            || process_start_time_unix_milliseconds.value() > observed_at.value()
            || expires_at.value() <= observed_at.value()
            || expires_at.value().saturating_sub(observed_at.value())
                > MAXIMUM_MACOS_SAFETY_LEASE_MILLISECONDS
        {
            return Err(macos_safety_error());
        }
        Ok(Self {
            node_id,
            placement_group_id,
            placement_id,
            core_installation_id,
            executable_identity,
            launchd_label: launchd_label.to_string(),
            launch_generation,
            process_id,
            process_start_time_unix_milliseconds,
            observed_at,
            expires_at,
        })
    }

    // Returns the Node that observed this native process.
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

    // Returns the exact Core installation identity.
    pub const fn core_installation_id(&self) -> &InstallationId {
        &self.core_installation_id
    }

    // Returns the immutable native executable identity.
    pub const fn executable_identity(&self) -> &Sha256Digest {
        &self.executable_identity
    }

    // Returns the exact launchd job label.
    pub fn launchd_label(&self) -> &str {
        &self.launchd_label
    }

    // Returns the immutable Node-owned launch generation.
    pub const fn launch_generation(&self) -> &Sha256Digest {
        &self.launch_generation
    }

    // Returns the exact observed process identifier.
    pub const fn process_id(&self) -> u32 {
        self.process_id
    }

    // Returns the process start time used to reject PID reuse.
    pub const fn process_start_time_unix_milliseconds(&self) -> UnixMilliseconds {
        self.process_start_time_unix_milliseconds
    }

    // Returns the Node observation time.
    pub const fn observed_at(&self) -> UnixMilliseconds {
        self.observed_at
    }

    // Returns the exclusive safety deadline.
    pub const fn expires_at(&self) -> UnixMilliseconds {
        self.expires_at
    }
}

// Carries every exact native placement required by one macOS group.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayMacOsPlacementSafetySnapshot {
    placement_group_id: PlacementGroupId,
    expected_placements: Vec<(PlacementId, NodeId)>,
    leases: Vec<GatewayMacOsPlacementSafetyLease>,
}

impl GatewayMacOsPlacementSafetySnapshot {
    // Creates one nonempty bounded macOS safety snapshot.
    pub fn new(
        placement_group_id: PlacementGroupId,
        expected_placements: Vec<(PlacementId, NodeId)>,
        leases: Vec<GatewayMacOsPlacementSafetyLease>,
    ) -> Result<Self, GatewayError> {
        if expected_placements.is_empty()
            || expected_placements.len() > 1_024
            || expected_placements.iter().collect::<BTreeSet<_>>().len()
                != expected_placements.len()
            || leases.is_empty()
            || leases.len() > 1_024
            || leases
                .iter()
                .any(|lease| lease.placement_group_id() != &placement_group_id)
        {
            return Err(macos_safety_error());
        }
        Ok(Self {
            placement_group_id,
            expected_placements,
            leases,
        })
    }

    // Returns the exact native placement-group identity.
    pub const fn placement_group_id(&self) -> &PlacementGroupId {
        &self.placement_group_id
    }

    // Returns every exact placement and owning Node required by the group.
    pub fn expected_placements(&self) -> &[(PlacementId, NodeId)] {
        &self.expected_placements
    }

    // Returns every required native process proof.
    pub fn leases(&self) -> &[GatewayMacOsPlacementSafetyLease] {
        &self.leases
    }
}

// Owns process-local high-water marks for native launchd observations.
#[derive(Default)]
pub(crate) struct GatewayMacOsPlacementSafetyState {
    latest: BTreeMap<(NodeId, PlacementId), GatewayMacOsPlacementSafetyLease>,
}

impl GatewayMacOsPlacementSafetyState {
    // Judges one complete native group and advances state only after every lease passes.
    pub(crate) fn accepts(
        &mut self,
        route: &GatewayRoute,
        snapshot: &GatewayMacOsPlacementSafetySnapshot,
        now: UnixMilliseconds,
    ) -> bool {
        let expected = snapshot
            .expected_placements()
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if snapshot.placement_group_id() != route.placement_group_id()
            || expected.len() != snapshot.expected_placements().len()
            || !expected
                .iter()
                .any(|(_, node_id)| node_id == route.endpoint_node_id())
        {
            return false;
        }
        let mut leases = BTreeMap::new();
        for lease in snapshot.leases() {
            let key = (lease.placement_id().clone(), lease.node_id().clone());
            if !expected.contains(&key)
                || leases.insert(key, lease).is_some()
                || lease.observed_at().value() > now.value()
                || lease.expires_at().value() <= now.value()
            {
                return false;
            }
            if let Some(previous) = self
                .latest
                .get(&(lease.node_id().clone(), lease.placement_id().clone()))
            {
                let binding_changed = lease.core_installation_id()
                    != previous.core_installation_id()
                    || lease.executable_identity() != previous.executable_identity()
                    || lease.launchd_label() != previous.launchd_label()
                    || lease.launch_generation() != previous.launch_generation();
                let process_regressed = lease.process_start_time_unix_milliseconds().value()
                    < previous.process_start_time_unix_milliseconds().value();
                let same_process = lease.process_id() == previous.process_id()
                    && lease.process_start_time_unix_milliseconds()
                        == previous.process_start_time_unix_milliseconds();
                if binding_changed
                    || process_regressed
                    || lease.observed_at().value() < previous.observed_at().value()
                    || (same_process && lease != previous)
                {
                    return false;
                }
            }
        }
        if leases.keys().cloned().collect::<BTreeSet<_>>() != expected {
            return false;
        }
        for lease in leases.into_values() {
            self.latest.insert(
                (lease.node_id().clone(), lease.placement_id().clone()),
                lease.clone(),
            );
        }
        true
    }
}

// Supplies macOS Node/launchd safety independently from the Linux Watchdog contract.
pub trait GatewayMacOsPlacementSafetyProvider: Send + Sync {
    // Returns current native safety or absence when any required launchd process is unavailable.
    fn snapshot(
        &self,
        route: &GatewayRoute,
    ) -> Result<Option<GatewayMacOsPlacementSafetySnapshot>, GatewayError>;
}

// Rejects empty, unsafe, or unbounded native launchd labels.
fn valid_launchd_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value.contains('.')
        && !value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
}

// Creates one stable redacted native safety-contract failure.
const fn macos_safety_error() -> GatewayError {
    GatewayError::InvalidContract {
        reason: "macOS placement safety contract is invalid",
    }
}

#[cfg(test)]
mod tests {
    use std::num::{NonZeroU32, NonZeroU64};

    use li_core_interface::{
        EndpointAddress, EndpointScheme, LogicalModelName, NodeAddress, NodeId, PlacementGroupId,
        PlacementId,
    };

    use super::{
        GatewayMacOsPlacementSafetyLease, GatewayMacOsPlacementSafetySnapshot,
        GatewayMacOsPlacementSafetyState, InstallationId, Sha256Digest, UnixMilliseconds,
    };
    use crate::{GatewayRoute, GatewayRouteTarget};

    // Returns one repeated lowercase hexadecimal identity.
    fn identity(character: char, length: usize) -> String {
        character.to_string().repeat(length)
    }

    // Returns one complete local Engine route for the protected placement group.
    fn route() -> GatewayRoute {
        GatewayRoute::new(
            PlacementGroupId::parse(&identity('1', 32)).expect("group"),
            NodeId::parse(&identity('2', 32)).expect("node"),
            LogicalModelName::parse("qwen3_8").expect("model"),
            GatewayRouteTarget::LocalEngine {
                endpoint: EndpointAddress::new(
                    EndpointScheme::Https,
                    NodeAddress::parse("127.0.0.1").expect("address"),
                    18_000,
                )
                .expect("endpoint"),
            },
            NonZeroU32::new(1).expect("capacity"),
            NonZeroU64::new(1_024).expect("context"),
            true,
            false,
            None,
            Vec::new(),
        )
        .expect("route")
    }

    // Returns one complete process lease while allowing one immutable binding to vary.
    fn lease(
        executable_character: char,
        process_id: u32,
        started_at: u64,
        observed_at: u64,
    ) -> GatewayMacOsPlacementSafetyLease {
        let route = route();
        GatewayMacOsPlacementSafetyLease::new(
            route.endpoint_node_id().clone(),
            route.placement_group_id().clone(),
            PlacementId::parse(&identity('3', 32)).expect("placement"),
            InstallationId::parse(&identity('4', 64)).expect("installation"),
            Sha256Digest::parse(&identity(executable_character, 64)).expect("executable"),
            "ai.letsinfer.engine.fixture",
            Sha256Digest::parse(&identity('6', 64)).expect("launch generation"),
            process_id,
            UnixMilliseconds::new(started_at),
            UnixMilliseconds::new(observed_at),
            UnixMilliseconds::new(observed_at + 1_000),
        )
        .expect("lease")
    }

    // Wraps one lease in the exact complete group snapshot expected by the route.
    fn snapshot(lease: GatewayMacOsPlacementSafetyLease) -> GatewayMacOsPlacementSafetySnapshot {
        let route = route();
        GatewayMacOsPlacementSafetySnapshot::new(
            route.placement_group_id().clone(),
            vec![(lease.placement_id().clone(), lease.node_id().clone())],
            vec![lease],
        )
        .expect("snapshot")
    }

    // Preserves immutable placement bindings across legitimate process restarts.
    #[test]
    fn safety_state_accepts_restart_but_rejects_binding_substitution() {
        let route = route();
        let mut state = GatewayMacOsPlacementSafetyState::default();
        assert!(state.accepts(
            &route,
            &snapshot(lease('5', 42, 900, 1_000)),
            UnixMilliseconds::new(1_000),
        ));
        assert!(state.accepts(
            &route,
            &snapshot(lease('5', 43, 1_100, 1_200)),
            UnixMilliseconds::new(1_200),
        ));
        assert!(!state.accepts(
            &route,
            &snapshot(lease('7', 44, 1_300, 1_400)),
            UnixMilliseconds::new(1_400),
        ));
    }
}
