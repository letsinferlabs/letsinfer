// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;

use li_core_interface::{
    BootId, InstallationId, NodeId, PlacementGroupId, PlacementId, Sha256Digest, TechnicalName,
    UnixMilliseconds,
};

use crate::{GatewayError, GatewayRoute};

const MAXIMUM_PROTECTION_LEASE_MILLISECONDS: u64 = 60_000;
const MAXIMUM_PROTECTED_PLACEMENTS: usize = 1_024;

// Binds one Node's protection authority to exact installed Core and Watchdog identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayProtectionAuthority {
    node_id: NodeId,
    core_installation_id: InstallationId,
    watchdog_source_identity: Sha256Digest,
    watchdog_session_id: Sha256Digest,
    watchdog_session_generation: NonZeroU64,
}

impl GatewayProtectionAuthority {
    // Creates one immutable authority for a currently connected Watchdog session.
    pub const fn new(
        node_id: NodeId,
        core_installation_id: InstallationId,
        watchdog_source_identity: Sha256Digest,
        watchdog_session_id: Sha256Digest,
        watchdog_session_generation: NonZeroU64,
    ) -> Self {
        Self {
            node_id,
            core_installation_id,
            watchdog_source_identity,
            watchdog_session_id,
            watchdog_session_generation,
        }
    }

    // Returns the Node protected by this authority.
    pub const fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    // Returns the exact installed Core identity expected on the Node.
    pub const fn core_installation_id(&self) -> &InstallationId {
        &self.core_installation_id
    }

    // Returns the immutable Watchdog executable or Core source identity expected on the Node.
    pub const fn watchdog_source_identity(&self) -> &Sha256Digest {
        &self.watchdog_source_identity
    }

    // Returns the authenticated resident session that invalidates restart-era leases.
    pub const fn watchdog_session_id(&self) -> &Sha256Digest {
        &self.watchdog_session_id
    }

    // Returns the monotonic Node-owned generation for this authenticated session.
    pub const fn watchdog_session_generation(&self) -> NonZeroU64 {
        self.watchdog_session_generation
    }
}

// Carries one expiring protection proof for an exact placement process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayPlacementProtectionLease {
    node_id: NodeId,
    placement_group_id: PlacementGroupId,
    placement_id: PlacementId,
    core_installation_id: InstallationId,
    watchdog_source_identity: Sha256Digest,
    watchdog_session_id: Sha256Digest,
    watchdog_session_generation: NonZeroU64,
    protection_generation: String,
    container_name: TechnicalName,
    container_id: Sha256Digest,
    process_id: u32,
    process_start_ticks: u64,
    boot_id: BootId,
    cgroup: String,
    sample_sequence: NonZeroU64,
    observed_at: UnixMilliseconds,
    observed_at_monotonic_milliseconds: u64,
    expires_at: UnixMilliseconds,
    armed: bool,
    trip_latched: bool,
}

impl GatewayPlacementProtectionLease {
    // Creates one complete identity-bound lease without deciding current freshness.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        node_id: NodeId,
        placement_group_id: PlacementGroupId,
        placement_id: PlacementId,
        core_installation_id: InstallationId,
        watchdog_source_identity: Sha256Digest,
        watchdog_session_id: Sha256Digest,
        watchdog_session_generation: NonZeroU64,
        protection_generation: &str,
        container_name: TechnicalName,
        container_id: Sha256Digest,
        process_id: u32,
        process_start_ticks: u64,
        boot_id: BootId,
        cgroup: &str,
        sample_sequence: NonZeroU64,
        observed_at: UnixMilliseconds,
        observed_at_monotonic_milliseconds: u64,
        expires_at: UnixMilliseconds,
        armed: bool,
        trip_latched: bool,
    ) -> Result<Self, GatewayError> {
        if !valid_protection_generation(protection_generation)
            || process_id <= 1
            || process_start_ticks == 0
            || observed_at_monotonic_milliseconds == 0
            || !valid_cgroup(cgroup)
            || expires_at.value() <= observed_at.value()
            || expires_at.value().saturating_sub(observed_at.value())
                > MAXIMUM_PROTECTION_LEASE_MILLISECONDS
        {
            return Err(protection_contract_error());
        }
        Ok(Self {
            node_id,
            placement_group_id,
            placement_id,
            core_installation_id,
            watchdog_source_identity,
            watchdog_session_id,
            watchdog_session_generation,
            protection_generation: protection_generation.to_string(),
            container_name,
            container_id,
            process_id,
            process_start_ticks,
            boot_id,
            cgroup: cgroup.to_string(),
            sample_sequence,
            observed_at,
            observed_at_monotonic_milliseconds,
            expires_at,
            armed,
            trip_latched,
        })
    }

    // Returns the Node that owns the protected process.
    pub const fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    // Returns the atomic placement group bound by this lease.
    pub const fn placement_group_id(&self) -> &PlacementGroupId {
        &self.placement_group_id
    }

    // Returns the exact placement bound by this lease.
    pub const fn placement_id(&self) -> &PlacementId {
        &self.placement_id
    }

    // Returns the installed Core identity observed by the protection authority.
    pub const fn core_installation_id(&self) -> &InstallationId {
        &self.core_installation_id
    }

    // Returns the immutable Watchdog executable or Core source identity that issued this lease.
    pub const fn watchdog_source_identity(&self) -> &Sha256Digest {
        &self.watchdog_source_identity
    }

    // Returns the authenticated Watchdog resident session that issued this lease.
    pub const fn watchdog_session_id(&self) -> &Sha256Digest {
        &self.watchdog_session_id
    }

    // Returns the monotonic Node-owned Watchdog session generation.
    pub const fn watchdog_session_generation(&self) -> NonZeroU64 {
        self.watchdog_session_generation
    }

    // Returns the placement-owned opaque protection generation.
    pub fn protection_generation(&self) -> &str {
        &self.protection_generation
    }

    // Returns the exact managed container name.
    pub const fn container_name(&self) -> &TechnicalName {
        &self.container_name
    }

    // Returns the immutable container identity.
    pub const fn container_id(&self) -> &Sha256Digest {
        &self.container_id
    }

    // Returns the host process identifier.
    pub const fn process_id(&self) -> u32 {
        self.process_id
    }

    // Returns the kernel start ticks that reject PID reuse.
    pub const fn process_start_ticks(&self) -> u64 {
        self.process_start_ticks
    }

    // Returns the exact Linux boot identity.
    pub const fn boot_id(&self) -> &BootId {
        &self.boot_id
    }

    // Returns the exact unified-cgroup path.
    pub fn cgroup(&self) -> &str {
        &self.cgroup
    }

    // Returns the nonzero Watchdog sample sequence.
    pub const fn sample_sequence(&self) -> NonZeroU64 {
        self.sample_sequence
    }

    // Returns the Unix time captured by the completed protection cycle.
    pub const fn observed_at(&self) -> UnixMilliseconds {
        self.observed_at
    }

    // Returns the boot-scoped monotonic time captured by the protection sample.
    pub const fn observed_at_monotonic_milliseconds(&self) -> u64 {
        self.observed_at_monotonic_milliseconds
    }

    // Returns the exclusive freshness deadline.
    pub const fn expires_at(&self) -> UnixMilliseconds {
        self.expires_at
    }

    // Returns whether the completed cycle observed the armed phase.
    pub const fn is_armed(&self) -> bool {
        self.armed
    }

    // Returns whether the completed cycle observed a durable trip latch.
    pub const fn trip_latched(&self) -> bool {
        self.trip_latched
    }
}

// Describes every placement and authority that one route must protect atomically.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayPlacementProtectionSnapshot {
    placement_group_id: PlacementGroupId,
    expected_placements: Vec<(PlacementId, NodeId)>,
    authorities: Vec<GatewayProtectionAuthority>,
    leases: Vec<GatewayPlacementProtectionLease>,
}

impl GatewayPlacementProtectionSnapshot {
    // Creates one bounded snapshot while preserving malformed absence for fail-closed judgment.
    pub fn new(
        placement_group_id: PlacementGroupId,
        expected_placements: Vec<(PlacementId, NodeId)>,
        authorities: Vec<GatewayProtectionAuthority>,
        leases: Vec<GatewayPlacementProtectionLease>,
    ) -> Result<Self, GatewayError> {
        if expected_placements.is_empty()
            || expected_placements.len() > MAXIMUM_PROTECTED_PLACEMENTS
            || authorities.is_empty()
            || authorities.len() > MAXIMUM_PROTECTED_PLACEMENTS
            || leases.len() > MAXIMUM_PROTECTED_PLACEMENTS
        {
            return Err(protection_contract_error());
        }
        Ok(Self {
            placement_group_id,
            expected_placements,
            authorities,
            leases,
        })
    }

    // Returns the placement group represented by this snapshot.
    pub const fn placement_group_id(&self) -> &PlacementGroupId {
        &self.placement_group_id
    }

    // Returns every exact placement and owning Node required by the group.
    pub fn expected_placements(&self) -> &[(PlacementId, NodeId)] {
        &self.expected_placements
    }

    // Returns every current Node protection authority used by the group.
    pub fn authorities(&self) -> &[GatewayProtectionAuthority] {
        &self.authorities
    }

    // Returns the current candidate leases without implying admission.
    pub fn leases(&self) -> &[GatewayPlacementProtectionLease] {
        &self.leases
    }
}

// Supplies the Linux Node-owned Watchdog snapshot without making Gateway admission policy.
// macOS requires its own typed Node/launchd safety observation before native routing is enabled.
pub trait GatewayProtectionLeaseProvider: Send + Sync {
    // Returns absence until every Node has a current authenticated Watchdog session.
    fn snapshot(
        &self,
        route: &GatewayRoute,
    ) -> Result<Option<GatewayPlacementProtectionSnapshot>, GatewayError>;
}

// Keeps Gateway closed until the Node-owned protection channel is composed.
#[derive(Default)]
pub struct UnavailableGatewayProtectionLeaseProvider;

impl GatewayProtectionLeaseProvider for UnavailableGatewayProtectionLeaseProvider {
    // Reports no current protection proof for every route.
    fn snapshot(
        &self,
        _route: &GatewayRoute,
    ) -> Result<Option<GatewayPlacementProtectionSnapshot>, GatewayError> {
        Ok(None)
    }
}

// Owns the per-process high-water marks required to reject regressed leases.
#[derive(Default)]
pub(crate) struct GatewayProtectionLeaseState {
    latest: BTreeMap<(NodeId, PlacementId), GatewayPlacementProtectionLease>,
    sessions: BTreeMap<NodeId, (NonZeroU64, Sha256Digest)>,
}

impl GatewayProtectionLeaseState {
    // Judges one complete group and advances high-water marks only after every lease passes.
    pub(crate) fn accepts(
        &mut self,
        route: &GatewayRoute,
        snapshot: &GatewayPlacementProtectionSnapshot,
        now: UnixMilliseconds,
    ) -> bool {
        let Some(leases) = valid_snapshot(route, snapshot, now) else {
            return false;
        };
        for authority in snapshot.authorities() {
            if let Some((generation, session_id)) = self.sessions.get(authority.node_id()) {
                if authority.watchdog_session_generation() < *generation
                    || (authority.watchdog_session_generation() == *generation
                        && authority.watchdog_session_id() != session_id)
                    || (authority.watchdog_session_generation() > *generation
                        && authority.watchdog_session_id() == session_id)
                {
                    return false;
                }
            }
        }
        for lease in leases.iter().copied() {
            if let Some(previous) = self
                .latest
                .get(&(lease.node_id().clone(), lease.placement_id().clone()))
            {
                let same_session = previous.watchdog_session_generation()
                    == lease.watchdog_session_generation()
                    && previous.watchdog_session_id() == lease.watchdog_session_id();
                if same_session
                    && (lease.sample_sequence() < previous.sample_sequence()
                        || lease.observed_at().value() < previous.observed_at().value()
                        || lease.observed_at_monotonic_milliseconds()
                            < previous.observed_at_monotonic_milliseconds()
                        || (lease.sample_sequence() == previous.sample_sequence()
                            && lease != previous))
                {
                    return false;
                }
            }
        }
        for authority in snapshot.authorities() {
            self.sessions.insert(
                authority.node_id().clone(),
                (
                    authority.watchdog_session_generation(),
                    authority.watchdog_session_id().clone(),
                ),
            );
        }
        for lease in leases {
            self.latest.insert(
                (lease.node_id().clone(), lease.placement_id().clone()),
                lease.clone(),
            );
        }
        true
    }
}

// Requires exact, unique, current leases for every placement and authority in one group.
fn valid_snapshot<'a>(
    route: &GatewayRoute,
    snapshot: &'a GatewayPlacementProtectionSnapshot,
    now: UnixMilliseconds,
) -> Option<Vec<&'a GatewayPlacementProtectionLease>> {
    if snapshot.placement_group_id() != route.placement_group_id() {
        return None;
    }
    let expected = snapshot
        .expected_placements()
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if expected.len() != snapshot.expected_placements().len()
        || !expected
            .iter()
            .any(|(_, node_id)| node_id == route.endpoint_node_id())
    {
        return None;
    }
    let authorities = snapshot
        .authorities()
        .iter()
        .map(|authority| (authority.node_id().clone(), authority))
        .collect::<BTreeMap<_, _>>();
    if authorities.len() != snapshot.authorities().len()
        || authorities.keys().cloned().collect::<BTreeSet<_>>()
            != expected
                .iter()
                .map(|(_, node_id)| node_id.clone())
                .collect::<BTreeSet<_>>()
    {
        return None;
    }
    let mut leases = BTreeMap::new();
    for lease in snapshot.leases() {
        let key = (lease.placement_id().clone(), lease.node_id().clone());
        let authority = *authorities.get(lease.node_id())?;
        if lease.placement_group_id() != snapshot.placement_group_id()
            || !expected.contains(&key)
            || leases.insert(key, lease).is_some()
            || lease.core_installation_id() != authority.core_installation_id()
            || lease.watchdog_source_identity() != authority.watchdog_source_identity()
            || lease.watchdog_session_id() != authority.watchdog_session_id()
            || lease.watchdog_session_generation() != authority.watchdog_session_generation()
            || !lease.is_armed()
            || lease.trip_latched()
            || lease.observed_at().value() > now.value()
            || lease.expires_at().value() <= now.value()
        {
            return None;
        }
    }
    if leases.keys().cloned().collect::<BTreeSet<_>>() != expected {
        return None;
    }
    Some(leases.into_values().collect())
}

// Returns whether one generation uses the existing opaque 128-bit identity.
fn valid_protection_generation(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

// Rejects unsafe, ambiguous, or unbounded unified-cgroup paths.
fn valid_cgroup(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 4_095
        && value.starts_with("/sys/fs/cgroup/")
        && !value.chars().any(|character| {
            character.is_control() || character.is_whitespace() || character == '='
        })
        && !value.strip_prefix("/sys/fs/cgroup/").is_some_and(|suffix| {
            suffix.is_empty()
                || suffix.ends_with('/')
                || suffix
                    .split('/')
                    .any(|component| component.is_empty() || component == "." || component == "..")
        })
}

// Creates one stable redacted protection-contract failure.
const fn protection_contract_error() -> GatewayError {
    GatewayError::InvalidContract {
        reason: "gateway placement protection contract is invalid",
    }
}
