// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::sync::Arc;

use li_core_interface::{
    EndpointAddress, EndpointOwnership, HardwareObservation, InterconnectKind,
    ModelServiceDesiredState, Node, NodeId, Placement, PlacementGroup, PlacementGroupId,
    PlacementGroupState, PlacementId, PlacementResources, PlacementState, RuntimeCandidateId,
    RuntimeInstallationId, RuntimeVersion, TargetId, TaskId, UnixMilliseconds,
};
use li_gateway_manager::GatewayTelemetrySnapshot;
use li_placement_manager::{PlacementLink, PlacementRecord};
use li_watchdog_manager::{WatchdogSample, WATCHDOG_PERCENT_UNKNOWN};

use crate::{DatabasePlacementStore, NodeManager, NodeManagerError, NodeModelServiceSummary};

const MAXIMUM_HOST_PLACEMENT_GROUPS: usize = 4_096;
const MAXIMUM_HOST_VERIFIED_LINKS: usize = 16_384;
const MAXIMUM_HOSTS: usize = 1_024;
const MAXIMUM_HOST_MODEL_SERVICES: usize = 4_096;

// Identifies whether one independently observed host section is usable now.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodeHostProjectionValue<Value> {
    Available(Value),
    Unavailable,
    NotApplicable,
}

impl<Value> NodeHostProjectionValue<Value> {
    // Returns the exact available value without inventing a fallback.
    pub const fn available(&self) -> Option<&Value> {
        match self {
            Self::Available(value) => Some(value),
            Self::Unavailable | Self::NotApplicable => None,
        }
    }

    // Returns whether the provider could not produce a current truthful value.
    pub const fn is_unavailable(&self) -> bool {
        matches!(self, Self::Unavailable)
    }

    // Returns whether this host platform or lifecycle has no such section.
    pub const fn is_not_applicable(&self) -> bool {
        matches!(self, Self::NotApplicable)
    }
}

// Names one redacted external read failure without hiding which section became unavailable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeHostReadError {
    Unavailable,
}

impl fmt::Display for NodeHostReadError {
    // Presents stable host-read language without provider or native diagnostics.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("current host projection input is unavailable")
    }
}

impl Error for NodeHostReadError {}

// Carries one placement group and its complete opaque placement membership.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeHostPlacementGroup {
    group: PlacementGroup,
    placements: Vec<Placement>,
}

impl NodeHostPlacementGroup {
    // Returns the exact PlacementManager group snapshot.
    pub const fn group(&self) -> &PlacementGroup {
        &self.group
    }

    // Returns every opaque placement required by the group.
    pub fn placements(&self) -> &[Placement] {
        &self.placements
    }
}

// Identifies one resident's current readiness without fabricating native detail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeHostServiceState {
    Ready,
    NotReady,
}

// Identifies whether placement protection currently admits execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeHostProtectionState {
    Ready,
    NotReady,
}

// Summarizes one current placement-protection observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeHostProtectionSummary {
    state: NodeHostProtectionState,
    observed_at: UnixMilliseconds,
}

impl NodeHostProtectionSummary {
    // Creates one explicit current protection judgment from the platform safety owner.
    pub const fn new(state: NodeHostProtectionState, observed_at: UnixMilliseconds) -> Self {
        Self { state, observed_at }
    }

    // Returns whether the current host protection path is ready.
    pub const fn state(&self) -> NodeHostProtectionState {
        self.state
    }

    // Returns when protection readiness was observed.
    pub const fn observed_at(&self) -> UnixMilliseconds {
        self.observed_at
    }
}

// Carries the bounded Gateway counters required by status and diagnosis.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeHostGatewayTelemetrySummary {
    observed_at: UnixMilliseconds,
    active_requests: u64,
    queued_requests: u64,
    requests_completed: u64,
    requests_failed: u64,
    input_tokens: u64,
    output_tokens: u64,
    cached_tokens: u64,
}

impl NodeHostGatewayTelemetrySummary {
    // Projects one existing Gateway snapshot without retaining model or request identities.
    pub fn from_snapshot(snapshot: &GatewayTelemetrySnapshot) -> Self {
        let counters = snapshot.counters();
        Self {
            observed_at: snapshot.observed_at(),
            active_requests: counters.active_requests(),
            queued_requests: counters.queued_requests(),
            requests_completed: counters.requests_completed(),
            requests_failed: counters.requests_failed(),
            input_tokens: counters.input_tokens(),
            output_tokens: counters.output_tokens(),
            cached_tokens: counters.cached_tokens(),
        }
    }

    // Creates one deterministic typed summary for an already validated Gateway observation.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        observed_at: UnixMilliseconds,
        active_requests: u64,
        queued_requests: u64,
        requests_completed: u64,
        requests_failed: u64,
        input_tokens: u64,
        output_tokens: u64,
        cached_tokens: u64,
    ) -> Self {
        Self {
            observed_at,
            active_requests,
            queued_requests,
            requests_completed,
            requests_failed,
            input_tokens,
            output_tokens,
            cached_tokens,
        }
    }

    // Returns when the Gateway counters were assembled.
    pub const fn observed_at(&self) -> UnixMilliseconds {
        self.observed_at
    }

    // Returns the current active request gauge.
    pub const fn active_requests(&self) -> u64 {
        self.active_requests
    }

    // Returns the current queued request gauge.
    pub const fn queued_requests(&self) -> u64 {
        self.queued_requests
    }

    // Returns cumulative completed requests.
    pub const fn requests_completed(&self) -> u64 {
        self.requests_completed
    }

    // Returns cumulative terminal request failures.
    pub const fn requests_failed(&self) -> u64 {
        self.requests_failed
    }

    // Returns cumulative exact prompt tokens.
    pub const fn input_tokens(&self) -> u64 {
        self.input_tokens
    }

    // Returns cumulative exact generated tokens.
    pub const fn output_tokens(&self) -> u64 {
        self.output_tokens
    }

    // Returns cumulative exact cached prompt tokens.
    pub const fn cached_tokens(&self) -> u64 {
        self.cached_tokens
    }
}

// Carries one current Gateway service observation and its optional counters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeHostGatewaySummary {
    state: NodeHostServiceState,
    telemetry: Option<NodeHostGatewayTelemetrySummary>,
}

impl NodeHostGatewaySummary {
    // Creates one explicit service result without turning missing telemetry into zeroes.
    pub const fn new(
        state: NodeHostServiceState,
        telemetry: Option<NodeHostGatewayTelemetrySummary>,
    ) -> Self {
        Self { state, telemetry }
    }

    // Returns current Gateway service readiness.
    pub const fn state(&self) -> NodeHostServiceState {
        self.state
    }

    // Returns current counters only when the Gateway supplied them.
    pub const fn telemetry(&self) -> Option<&NodeHostGatewayTelemetrySummary> {
        self.telemetry.as_ref()
    }
}

// Carries the bounded Watchdog host metrics required by status and diagnosis.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeHostWatchdogTelemetrySummary {
    observed_at: UnixMilliseconds,
    cpu_percent: Option<u8>,
    gpu_percent: Option<u8>,
    memory_percent: Option<u8>,
    disk_percent: Option<u8>,
    gpu_memory_percent: Option<u8>,
    active_requests: u32,
    queued_requests: u32,
}

impl NodeHostWatchdogTelemetrySummary {
    // Projects one exact Watchdog sample while preserving unknown percentages as absence.
    pub fn from_sample(sample: &WatchdogSample) -> Self {
        let telemetry = sample.telemetry();
        Self {
            observed_at: UnixMilliseconds::new(sample.unix_milliseconds()),
            cpu_percent: known_percent(telemetry.cpu_percent),
            gpu_percent: known_percent(telemetry.gpu_percent),
            memory_percent: known_percent(telemetry.memory_percent),
            disk_percent: known_percent(telemetry.disk_percent),
            gpu_memory_percent: known_percent(telemetry.gpu_memory_percent),
            active_requests: telemetry.active_requests,
            queued_requests: telemetry.queued_requests,
        }
    }

    // Creates one deterministic typed summary from already normalized optional percentages.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        observed_at: UnixMilliseconds,
        cpu_percent: Option<u8>,
        gpu_percent: Option<u8>,
        memory_percent: Option<u8>,
        disk_percent: Option<u8>,
        gpu_memory_percent: Option<u8>,
        active_requests: u32,
        queued_requests: u32,
    ) -> Result<Self, NodeHostReadError> {
        if [
            cpu_percent,
            gpu_percent,
            memory_percent,
            disk_percent,
            gpu_memory_percent,
        ]
        .into_iter()
        .flatten()
        .any(|percent| percent > 100)
        {
            return Err(NodeHostReadError::Unavailable);
        }
        Ok(Self {
            observed_at,
            cpu_percent,
            gpu_percent,
            memory_percent,
            disk_percent,
            gpu_memory_percent,
            active_requests,
            queued_requests,
        })
    }

    // Returns when the Watchdog sample was observed.
    pub const fn observed_at(&self) -> UnixMilliseconds {
        self.observed_at
    }

    // Returns current CPU utilization when supported.
    pub const fn cpu_percent(&self) -> Option<u8> {
        self.cpu_percent
    }

    // Returns current GPU utilization when supported.
    pub const fn gpu_percent(&self) -> Option<u8> {
        self.gpu_percent
    }

    // Returns current host-memory utilization when supported.
    pub const fn memory_percent(&self) -> Option<u8> {
        self.memory_percent
    }

    // Returns current storage utilization when supported.
    pub const fn disk_percent(&self) -> Option<u8> {
        self.disk_percent
    }

    // Returns current GPU-memory utilization when supported.
    pub const fn gpu_memory_percent(&self) -> Option<u8> {
        self.gpu_memory_percent
    }

    // Returns the Watchdog-observed active request gauge.
    pub const fn active_requests(&self) -> u32 {
        self.active_requests
    }

    // Returns the Watchdog-observed queued request gauge.
    pub const fn queued_requests(&self) -> u32 {
        self.queued_requests
    }
}

// Carries one current Watchdog service observation and its optional host telemetry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeHostWatchdogSummary {
    state: NodeHostServiceState,
    telemetry: Option<NodeHostWatchdogTelemetrySummary>,
}

impl NodeHostWatchdogSummary {
    // Creates one explicit service result without turning unsupported metrics into zeroes.
    pub const fn new(
        state: NodeHostServiceState,
        telemetry: Option<NodeHostWatchdogTelemetrySummary>,
    ) -> Self {
        Self { state, telemetry }
    }

    // Returns current Watchdog service readiness.
    pub const fn state(&self) -> NodeHostServiceState {
        self.state
    }

    // Returns current host telemetry only when Watchdog supplied it.
    pub const fn telemetry(&self) -> Option<&NodeHostWatchdogTelemetrySummary> {
        self.telemetry.as_ref()
    }
}

// Supplies PlacementManager aggregates without giving NodeManager mutation access.
pub trait NodeHostPlacementReadPort: Send + Sync {
    // Returns every current fully validated placement aggregate.
    fn placement_records(&self) -> Result<Vec<PlacementRecord>, NodeHostReadError>;
}

impl NodeHostPlacementReadPort for DatabasePlacementStore {
    // Reads the existing atomic PlacementManager aggregates through their native database adapter.
    fn placement_records(&self) -> Result<Vec<PlacementRecord>, NodeHostReadError> {
        self.records().map_err(|_| NodeHostReadError::Unavailable)
    }
}

// Supplies current verified node links independently from placement persistence.
pub trait NodeHostTopologyReadPort: Send + Sync {
    // Returns every currently verified model-neutral node link.
    fn verified_links(&self) -> Result<Vec<PlacementLink>, NodeHostReadError>;
}

// Supplies platform-native placement protection readiness for one exact host projection.
pub trait NodeHostProtectionReadPort: Send + Sync {
    // Returns absence only when protection does not apply to this platform or placement set.
    fn protection(
        &self,
        node: &Node,
        placement_groups: &[NodeHostPlacementGroup],
    ) -> Result<Option<NodeHostProtectionSummary>, NodeHostReadError>;
}

// Supplies resident service and telemetry summaries without exposing native control mechanisms.
pub trait NodeHostServiceReadPort: Send + Sync {
    // Returns the required Gateway summary for one exact host when observable.
    fn gateway(&self, node: &Node) -> Result<Option<NodeHostGatewaySummary>, NodeHostReadError>;

    // Returns absence for platforms without a separate Watchdog resident.
    fn watchdog(&self, node: &Node) -> Result<Option<NodeHostWatchdogSummary>, NodeHostReadError>;
}

// Groups the four explicit read-only capabilities required by one host projection.
pub struct NodeHostProjectionPorts {
    placements: Arc<dyn NodeHostPlacementReadPort>,
    topology: Arc<dyn NodeHostTopologyReadPort>,
    protection: Arc<dyn NodeHostProtectionReadPort>,
    services: Arc<dyn NodeHostServiceReadPort>,
}

impl NodeHostProjectionPorts {
    // Creates one closed read composition without granting any mutation capability.
    pub const fn new(
        placements: Arc<dyn NodeHostPlacementReadPort>,
        topology: Arc<dyn NodeHostTopologyReadPort>,
        protection: Arc<dyn NodeHostProtectionReadPort>,
        services: Arc<dyn NodeHostServiceReadPort>,
    ) -> Self {
        Self {
            placements,
            topology,
            protection,
            services,
        }
    }
}

// Carries one coherent manager-owned host read without user-interface policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeHostProjection {
    node: Node,
    hardware: Option<HardwareObservation>,
    placement_groups: NodeHostProjectionValue<Vec<NodeHostPlacementGroup>>,
    verified_links: NodeHostProjectionValue<Vec<PlacementLink>>,
    protection: NodeHostProjectionValue<NodeHostProtectionSummary>,
    gateway: NodeHostProjectionValue<NodeHostGatewaySummary>,
    watchdog: NodeHostProjectionValue<NodeHostWatchdogSummary>,
}

impl NodeHostProjection {
    // Returns the exact durable Node identity and lifecycle snapshot.
    pub const fn node(&self) -> &Node {
        &self.node
    }

    // Returns the current boot-scoped hardware observation when committed.
    pub const fn hardware(&self) -> Option<&HardwareObservation> {
        self.hardware.as_ref()
    }

    // Returns current placement groups involving this host or their availability state.
    pub const fn placement_groups(&self) -> &NodeHostProjectionValue<Vec<NodeHostPlacementGroup>> {
        &self.placement_groups
    }

    // Returns current verified links touching this host or their availability state.
    pub const fn verified_links(&self) -> &NodeHostProjectionValue<Vec<PlacementLink>> {
        &self.verified_links
    }

    // Returns current platform protection readiness or its availability state.
    pub const fn protection(&self) -> &NodeHostProjectionValue<NodeHostProtectionSummary> {
        &self.protection
    }

    // Returns current Gateway readiness and counters or their availability state.
    pub const fn gateway(&self) -> &NodeHostProjectionValue<NodeHostGatewaySummary> {
        &self.gateway
    }

    // Returns current Watchdog readiness and host telemetry or their availability state.
    pub const fn watchdog(&self) -> &NodeHostProjectionValue<NodeHostWatchdogSummary> {
        &self.watchdog
    }
}

// Carries one redacted routable endpoint without referenced credential identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeHostEndpointSnapshot {
    placement_id: PlacementId,
    node_id: NodeId,
    address: EndpointAddress,
    healthy: bool,
    memory_pressure: bool,
    temperature_millicelsius: Option<i32>,
}

impl NodeHostEndpointSnapshot {
    // Restores one already validated endpoint projection from private wire fields.
    pub fn restore(
        placement_id: PlacementId,
        node_id: NodeId,
        address: EndpointAddress,
        healthy: bool,
        memory_pressure: bool,
        temperature_millicelsius: Option<i32>,
    ) -> Result<Self, NodeHostReadError> {
        if temperature_millicelsius.is_some_and(|value| !(-1_000..=250_000).contains(&value)) {
            return Err(NodeHostReadError::Unavailable);
        }
        Ok(Self {
            placement_id,
            node_id,
            address,
            healthy,
            memory_pressure,
            temperature_millicelsius,
        })
    }

    // Returns the placement that owns this endpoint.
    pub const fn placement_id(&self) -> &PlacementId {
        &self.placement_id
    }

    // Returns the node that owns this endpoint.
    pub const fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    // Returns the structured endpoint address.
    pub const fn address(&self) -> &EndpointAddress {
        &self.address
    }

    // Returns whether the latest endpoint observation passed readiness.
    pub const fn is_healthy(&self) -> bool {
        self.healthy
    }

    // Returns whether the endpoint reports current memory pressure.
    pub const fn has_memory_pressure(&self) -> bool {
        self.memory_pressure
    }

    // Returns the current endpoint temperature when reported.
    pub const fn temperature_millicelsius(&self) -> Option<i32> {
        self.temperature_millicelsius
    }
}

// Carries one redacted opaque placement and its exact resource assignment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeHostPlacementSnapshot {
    placement_id: PlacementId,
    placement_group_id: PlacementGroupId,
    node_id: NodeId,
    runtime_installation_id: RuntimeInstallationId,
    task_id: TaskId,
    resources: PlacementResources,
    endpoint_ownership: EndpointOwnership,
    state: PlacementState,
}

impl NodeHostPlacementSnapshot {
    // Restores one already validated placement projection from private wire fields.
    #[allow(clippy::too_many_arguments)]
    pub const fn restore(
        placement_id: PlacementId,
        placement_group_id: PlacementGroupId,
        node_id: NodeId,
        runtime_installation_id: RuntimeInstallationId,
        task_id: TaskId,
        resources: PlacementResources,
        endpoint_ownership: EndpointOwnership,
        state: PlacementState,
    ) -> Self {
        Self {
            placement_id,
            placement_group_id,
            node_id,
            runtime_installation_id,
            task_id,
            resources,
            endpoint_ownership,
            state,
        }
    }

    // Projects one validated PlacementManager entity into its redacted read shape.
    fn from_placement(placement: &Placement) -> Self {
        Self::restore(
            placement.placement_id().clone(),
            placement.placement_group_id().clone(),
            placement.assignment().node_id().clone(),
            placement.assignment().runtime_installation_id().clone(),
            placement.assignment().task_id().clone(),
            placement.assignment().resources().clone(),
            placement.assignment().endpoint_ownership(),
            placement.state(),
        )
    }

    // Returns the stable placement identity.
    pub const fn placement_id(&self) -> &PlacementId {
        &self.placement_id
    }

    // Returns the owning placement-group identity.
    pub const fn placement_group_id(&self) -> &PlacementGroupId {
        &self.placement_group_id
    }

    // Returns the exact assigned node identity.
    pub const fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    // Returns the exact host-local runtime installation.
    pub const fn runtime_installation_id(&self) -> &RuntimeInstallationId {
        &self.runtime_installation_id
    }

    // Returns the opaque runtime-owned task identity.
    pub const fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    // Returns the complete Core-owned resource assignment.
    pub const fn resources(&self) -> &PlacementResources {
        &self.resources
    }

    // Returns whether this placement owns the group endpoint.
    pub const fn endpoint_ownership(&self) -> EndpointOwnership {
        self.endpoint_ownership
    }

    // Returns the latest placement lifecycle state.
    pub const fn state(&self) -> PlacementState {
        self.state
    }
}

// Carries one redacted placement group and all of its required opaque placements.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeHostPlacementGroupSnapshot {
    placement_group_id: PlacementGroupId,
    service_id: li_core_interface::ModelServiceId,
    runtime_candidate_id: RuntimeCandidateId,
    runtime_version: RuntimeVersion,
    target_id: TargetId,
    desired_state: ModelServiceDesiredState,
    state: PlacementGroupState,
    endpoint: Option<NodeHostEndpointSnapshot>,
    placements: Vec<NodeHostPlacementSnapshot>,
}

impl NodeHostPlacementGroupSnapshot {
    // Restores one closed redacted group while rechecking cross-field membership.
    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        placement_group_id: PlacementGroupId,
        service_id: li_core_interface::ModelServiceId,
        runtime_candidate_id: RuntimeCandidateId,
        runtime_version: RuntimeVersion,
        target_id: TargetId,
        desired_state: ModelServiceDesiredState,
        state: PlacementGroupState,
        endpoint: Option<NodeHostEndpointSnapshot>,
        placements: Vec<NodeHostPlacementSnapshot>,
    ) -> Result<Self, NodeHostReadError> {
        let identities = placements
            .iter()
            .map(NodeHostPlacementSnapshot::placement_id)
            .collect::<BTreeSet<_>>();
        if placements.is_empty()
            || identities.len() != placements.len()
            || placements
                .iter()
                .any(|placement| placement.placement_group_id() != &placement_group_id)
            || endpoint.as_ref().is_some_and(|endpoint| {
                !placements.iter().any(|placement| {
                    placement.placement_id() == endpoint.placement_id()
                        && placement.node_id() == endpoint.node_id()
                        && placement.endpoint_ownership() == EndpointOwnership::Owner
                })
            })
        {
            return Err(NodeHostReadError::Unavailable);
        }
        Ok(Self {
            placement_group_id,
            service_id,
            runtime_candidate_id,
            runtime_version,
            target_id,
            desired_state,
            state,
            endpoint,
            placements,
        })
    }

    // Projects one validated PlacementManager aggregate without credential references.
    fn from_group(group: &NodeHostPlacementGroup) -> Result<Self, NodeHostReadError> {
        let endpoint = group.group().endpoint().map(|endpoint| {
            NodeHostEndpointSnapshot::restore(
                endpoint.placement_id().clone(),
                endpoint.node_id().clone(),
                endpoint.address().clone(),
                endpoint.health().healthy(),
                endpoint.health().memory_pressure(),
                endpoint.health().temperature_millicelsius(),
            )
        });
        Self::restore(
            group.group().placement_group_id().clone(),
            group.group().service_id().clone(),
            group.group().runtime().candidate_id().clone(),
            group.group().runtime().version().clone(),
            group.group().runtime().target_id().clone(),
            group.group().desired_state(),
            group.group().state(),
            endpoint.transpose()?,
            group
                .placements()
                .iter()
                .map(NodeHostPlacementSnapshot::from_placement)
                .collect(),
        )
    }

    // Returns the stable placement-group identity.
    pub const fn placement_group_id(&self) -> &PlacementGroupId {
        &self.placement_group_id
    }

    // Returns the owning logical model-service identity.
    pub const fn service_id(&self) -> &li_core_interface::ModelServiceId {
        &self.service_id
    }

    // Returns the exact runtime candidate identity.
    pub const fn runtime_candidate_id(&self) -> &RuntimeCandidateId {
        &self.runtime_candidate_id
    }

    // Returns the exact runtime version.
    pub const fn runtime_version(&self) -> &RuntimeVersion {
        &self.runtime_version
    }

    // Returns the exact runtime target identity.
    pub const fn target_id(&self) -> &TargetId {
        &self.target_id
    }

    // Returns the operator's intended service state.
    pub const fn desired_state(&self) -> ModelServiceDesiredState {
        self.desired_state
    }

    // Returns the latest group lifecycle state.
    pub const fn state(&self) -> PlacementGroupState {
        self.state
    }

    // Returns the current redacted endpoint when startup completed.
    pub const fn endpoint(&self) -> Option<&NodeHostEndpointSnapshot> {
        self.endpoint.as_ref()
    }

    // Returns every required opaque placement in stable group order.
    pub fn placements(&self) -> &[NodeHostPlacementSnapshot] {
        &self.placements
    }
}

// Carries the bounded wire-safe read model for one exact host.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeHostSnapshot {
    node: Node,
    hardware: NodeHostProjectionValue<HardwareObservation>,
    placement_groups: NodeHostProjectionValue<Vec<NodeHostPlacementGroupSnapshot>>,
    verified_links: NodeHostProjectionValue<Vec<PlacementLink>>,
    protection: NodeHostProjectionValue<NodeHostProtectionSummary>,
    gateway: NodeHostProjectionValue<NodeHostGatewaySummary>,
    watchdog: NodeHostProjectionValue<NodeHostWatchdogSummary>,
}

impl NodeHostSnapshot {
    // Converts one manager-owned projection into its redacted private wire shape.
    pub fn from_projection(projection: &NodeHostProjection) -> Result<Self, NodeHostReadError> {
        let placement_groups = match projection.placement_groups() {
            NodeHostProjectionValue::Available(groups) => NodeHostProjectionValue::Available(
                groups
                    .iter()
                    .map(NodeHostPlacementGroupSnapshot::from_group)
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            NodeHostProjectionValue::Unavailable => NodeHostProjectionValue::Unavailable,
            NodeHostProjectionValue::NotApplicable => NodeHostProjectionValue::NotApplicable,
        };
        Ok(Self {
            node: projection.node().clone(),
            hardware: projection.hardware().cloned().map_or(
                NodeHostProjectionValue::Unavailable,
                NodeHostProjectionValue::Available,
            ),
            placement_groups,
            verified_links: projection.verified_links().clone(),
            protection: projection.protection().clone(),
            gateway: projection.gateway().clone(),
            watchdog: projection.watchdog().clone(),
        })
    }

    // Restores one wire-decoded host after checking every section belongs to the same node.
    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        node: Node,
        hardware: NodeHostProjectionValue<HardwareObservation>,
        placement_groups: NodeHostProjectionValue<Vec<NodeHostPlacementGroupSnapshot>>,
        verified_links: NodeHostProjectionValue<Vec<PlacementLink>>,
        protection: NodeHostProjectionValue<NodeHostProtectionSummary>,
        gateway: NodeHostProjectionValue<NodeHostGatewaySummary>,
        watchdog: NodeHostProjectionValue<NodeHostWatchdogSummary>,
    ) -> Result<Self, NodeHostReadError> {
        let node_id = node.identity().node_id();
        if hardware
            .available()
            .is_some_and(|observation| observation.node_id() != node_id)
            || placement_groups.available().is_some_and(|groups| {
                groups.iter().any(|group| {
                    !group
                        .placements()
                        .iter()
                        .any(|placement| placement.node_id() == node_id)
                })
            })
            || verified_links.available().is_some_and(|links| {
                links
                    .iter()
                    .any(|link| link.left_node_id() != node_id && link.right_node_id() != node_id)
            })
        {
            return Err(NodeHostReadError::Unavailable);
        }
        Ok(Self {
            node,
            hardware,
            placement_groups,
            verified_links,
            protection,
            gateway,
            watchdog,
        })
    }

    // Returns the durable Node identity and lifecycle snapshot.
    pub const fn node(&self) -> &Node {
        &self.node
    }

    // Returns current hardware or its explicit availability state.
    pub const fn hardware(&self) -> &NodeHostProjectionValue<HardwareObservation> {
        &self.hardware
    }

    // Returns current placement groups or their explicit availability state.
    pub const fn placement_groups(
        &self,
    ) -> &NodeHostProjectionValue<Vec<NodeHostPlacementGroupSnapshot>> {
        &self.placement_groups
    }

    // Returns current verified links or their explicit availability state.
    pub const fn verified_links(&self) -> &NodeHostProjectionValue<Vec<PlacementLink>> {
        &self.verified_links
    }

    // Returns current protection readiness or its explicit availability state.
    pub const fn protection(&self) -> &NodeHostProjectionValue<NodeHostProtectionSummary> {
        &self.protection
    }

    // Returns current Gateway readiness or its explicit availability state.
    pub const fn gateway(&self) -> &NodeHostProjectionValue<NodeHostGatewaySummary> {
        &self.gateway
    }

    // Returns current Watchdog readiness or its explicit availability state.
    pub const fn watchdog(&self) -> &NodeHostProjectionValue<NodeHostWatchdogSummary> {
        &self.watchdog
    }
}

// Carries every host projection and model service required by one CLI read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeHostInventory {
    local_node_id: NodeId,
    hosts: Vec<NodeHostSnapshot>,
    model_services: NodeHostProjectionValue<Vec<NodeModelServiceSummary>>,
}

impl NodeHostInventory {
    // Creates one closed inventory with a unique local host and bounded stable identities.
    pub fn new(
        local_node_id: NodeId,
        mut hosts: Vec<NodeHostSnapshot>,
        model_services: NodeHostProjectionValue<Vec<NodeModelServiceSummary>>,
    ) -> Result<Self, NodeHostReadError> {
        hosts.sort_by(|left, right| {
            left.node()
                .identity()
                .node_id()
                .cmp(right.node().identity().node_id())
        });
        let host_identities = hosts
            .iter()
            .map(|host| host.node().identity().node_id())
            .collect::<BTreeSet<_>>();
        if hosts.is_empty()
            || hosts.len() > MAXIMUM_HOSTS
            || host_identities.len() != hosts.len()
            || !host_identities.contains(&local_node_id)
            || model_services
                .available()
                .is_some_and(|services| services.len() > MAXIMUM_HOST_MODEL_SERVICES)
        {
            return Err(NodeHostReadError::Unavailable);
        }
        Ok(Self {
            local_node_id,
            hosts,
            model_services,
        })
    }

    // Returns the exact local Node identity anchoring this inventory.
    pub const fn local_node_id(&self) -> &NodeId {
        &self.local_node_id
    }

    // Returns every host in canonical Node identity order.
    pub fn hosts(&self) -> &[NodeHostSnapshot] {
        &self.hosts
    }

    // Returns current logical model services or their explicit availability state.
    pub const fn model_services(&self) -> &NodeHostProjectionValue<Vec<NodeModelServiceSummary>> {
        &self.model_services
    }

    // Returns the exact local host without applying a display-name fallback.
    pub fn local_host(&self) -> Option<&NodeHostSnapshot> {
        self.hosts
            .iter()
            .find(|host| host.node().identity().node_id() == &self.local_node_id)
    }
}

impl NodeManager {
    // Assembles one truthful host projection without mutating any manager or provider state.
    pub fn host_projection(
        &self,
        node_id: &NodeId,
        ports: &NodeHostProjectionPorts,
    ) -> Result<NodeHostProjection, NodeManagerError> {
        let node = self.node(node_id)?.value().clone();
        let nodes = self.nodes()?;
        if !nodes.iter().any(|known| known == &node) {
            return Err(NodeManagerError::CorruptState {
                reason: "host projection node differs from committed node inventory",
            });
        }
        let hardware = self.hardware_observation(node_id)?;
        validate_current_hardware(&node, hardware.as_ref())?;
        let known_nodes = nodes
            .iter()
            .map(|node| node.identity().node_id().clone())
            .collect::<BTreeSet<_>>();
        let placement_groups = ports
            .placements
            .placement_records()
            .and_then(|records| placement_groups(node_id, &known_nodes, records))
            .map(NodeHostProjectionValue::Available)
            .unwrap_or(NodeHostProjectionValue::Unavailable);
        let verified_links = ports
            .topology
            .verified_links()
            .and_then(|links| verified_links(node_id, &known_nodes, links))
            .map(NodeHostProjectionValue::Available)
            .unwrap_or(NodeHostProjectionValue::Unavailable);
        let protection = match &placement_groups {
            NodeHostProjectionValue::Available(groups) => {
                optional_value(ports.protection.protection(&node, groups))
            }
            NodeHostProjectionValue::Unavailable | NodeHostProjectionValue::NotApplicable => {
                NodeHostProjectionValue::Unavailable
            }
        };
        let gateway = optional_value(ports.services.gateway(&node));
        let watchdog = optional_value(ports.services.watchdog(&node));
        Ok(NodeHostProjection {
            node,
            hardware,
            placement_groups,
            verified_links,
            protection,
            gateway,
            watchdog,
        })
    }
}

// Requires the durable node pointer and hardware record to describe the same current snapshot.
fn validate_current_hardware(
    node: &Node,
    hardware: Option<&HardwareObservation>,
) -> Result<(), NodeManagerError> {
    match (node.latest_hardware_observation_id(), hardware) {
        (Some(expected), Some(observed)) if expected == observed.observation_id() => Ok(()),
        (None, None) => Ok(()),
        _ => Err(NodeManagerError::CorruptState {
            reason: "node hardware pointer differs from the current observation",
        }),
    }
}

// Selects, validates, and canonically orders groups that contain this exact host.
fn placement_groups(
    node_id: &NodeId,
    known_nodes: &BTreeSet<NodeId>,
    records: Vec<PlacementRecord>,
) -> Result<Vec<NodeHostPlacementGroup>, NodeHostReadError> {
    if records.len() > MAXIMUM_HOST_PLACEMENT_GROUPS {
        return Err(NodeHostReadError::Unavailable);
    }
    let mut groups = BTreeMap::<PlacementGroupId, NodeHostPlacementGroup>::new();
    for record in records {
        if record
            .placements()
            .iter()
            .any(|placement| !known_nodes.contains(placement.assignment().node_id()))
        {
            return Err(NodeHostReadError::Unavailable);
        }
        if !record
            .placements()
            .iter()
            .any(|placement| placement.assignment().node_id() == node_id)
        {
            continue;
        }
        let projected = NodeHostPlacementGroup {
            group: record.group().clone(),
            placements: record.placements().to_vec(),
        };
        match groups.insert(
            record.group().placement_group_id().clone(),
            projected.clone(),
        ) {
            None => {}
            Some(existing) if existing == projected => {}
            Some(_) => return Err(NodeHostReadError::Unavailable),
        }
    }
    Ok(groups.into_values().collect())
}

// Validates enrolled endpoints and returns only canonical links touching this exact host.
fn verified_links(
    node_id: &NodeId,
    known_nodes: &BTreeSet<NodeId>,
    links: Vec<PlacementLink>,
) -> Result<Vec<PlacementLink>, NodeHostReadError> {
    if links.len() > MAXIMUM_HOST_VERIFIED_LINKS
        || links.iter().any(|link| {
            !known_nodes.contains(link.left_node_id())
                || !known_nodes.contains(link.right_node_id())
        })
    {
        return Err(NodeHostReadError::Unavailable);
    }
    let mut selected = BTreeMap::new();
    for link in links
        .into_iter()
        .filter(|link| link.left_node_id() == node_id || link.right_node_id() == node_id)
    {
        if selected.insert(link_key(&link), link).is_some() {
            return Err(NodeHostReadError::Unavailable);
        }
    }
    Ok(selected.into_values().collect())
}

// Returns one orientation-independent ordering key for a current verified link.
fn link_key(link: &PlacementLink) -> (String, String, u8, bool, u64, u32) {
    let (left, right) = if link.left_node_id() < link.right_node_id() {
        (link.left_node_id(), link.right_node_id())
    } else {
        (link.right_node_id(), link.left_node_id())
    };
    (
        left.as_str().to_string(),
        right.as_str().to_string(),
        interconnect_kind_index(link.kind()),
        link.rdma(),
        link.speed_mbps(),
        link.mtu(),
    )
}

// Returns one stable ordering index without assigning compatibility policy.
const fn interconnect_kind_index(kind: InterconnectKind) -> u8 {
    match kind {
        InterconnectKind::Any => 0,
        InterconnectKind::Connectx => 1,
        InterconnectKind::Ethernet => 2,
        InterconnectKind::Wifi => 3,
        InterconnectKind::Other => 4,
    }
}

// Preserves explicit provider absence separately from temporary unavailability.
fn optional_value<Value>(
    result: Result<Option<Value>, NodeHostReadError>,
) -> NodeHostProjectionValue<Value> {
    match result {
        Ok(Some(value)) => NodeHostProjectionValue::Available(value),
        Ok(None) => NodeHostProjectionValue::NotApplicable,
        Err(_) => NodeHostProjectionValue::Unavailable,
    }
}

// Converts Watchdog's established unknown sentinel to truthful typed absence.
const fn known_percent(value: u8) -> Option<u8> {
    if value == WATCHDOG_PERCENT_UNKNOWN || value > 100 {
        None
    } else {
        Some(value)
    }
}
