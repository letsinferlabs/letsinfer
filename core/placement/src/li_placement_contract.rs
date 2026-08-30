// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use li_core_interface::{
    BootId, DeviceId, HardwareObservationId, InterconnectKind, ModelServiceDesiredState,
    ModelServiceId, NetworkInterfaceName, NodeAddress, NodeId, Placement, PlacementEndpoint,
    PlacementGroup, PlacementGroupCapacity, PlacementGroupId, PlacementGroupState, PlacementId,
    PlacementResources, PlacementState, PortRange, ResourceIdentity, ResourceLease,
    ResourceLeaseId, ResourceLeaseState, RuntimeIdentity, RuntimeInstallationId, Sha256Digest,
    TaskId, UnixMilliseconds,
};

const MAX_PLACEMENTS: usize = 64;
const MAX_LINKS: usize = 256;
const MAXIMUM_HARDWARE_OBSERVATION_AGE_MILLISECONDS: u64 = 86_400_000;

// Defines how fresh hardware and mutable-link observations must be at allocation time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlacementAdmissionPolicy {
    maximum_hardware_observation_age_milliseconds: u64,
}

impl PlacementAdmissionPolicy {
    // Creates one explicit bounded freshness policy without a hidden platform default.
    pub fn new(maximum_hardware_observation_age: Duration) -> Result<Self, PlacementError> {
        let milliseconds =
            u64::try_from(maximum_hardware_observation_age.as_millis()).map_err(|_| {
                PlacementError::InvalidRequest {
                    reason: "hardware observation age must be positive and bounded",
                }
            })?;
        if milliseconds == 0
            || milliseconds > MAXIMUM_HARDWARE_OBSERVATION_AGE_MILLISECONDS
            || Duration::from_millis(milliseconds) != maximum_hardware_observation_age
        {
            return Err(PlacementError::InvalidRequest {
                reason: "hardware observation age must be positive and bounded",
            });
        }
        Ok(Self {
            maximum_hardware_observation_age_milliseconds: milliseconds,
        })
    }

    // Returns the maximum admitted hardware observation age.
    pub const fn maximum_hardware_observation_age_milliseconds(self) -> u64 {
        self.maximum_hardware_observation_age_milliseconds
    }

    // Requires every node and mutable link fact to come from a current boot-scoped snapshot.
    pub(crate) fn validate(
        self,
        nodes: &[PlacementNodeResources],
        now: UnixMilliseconds,
    ) -> Result<(), PlacementError> {
        if nodes.iter().any(|node| {
            node.observed_at() > now
                || now.value() - node.observed_at().value()
                    > self.maximum_hardware_observation_age_milliseconds
        }) {
            return Err(PlacementError::HardwareObservationUnavailable);
        }
        Ok(())
    }
}

// Describes one opaque runtime task's generic resource requirements.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlacementTask {
    task_id: TaskId,
    device_count: u16,
    port_count: u16,
}

impl PlacementTask {
    // Creates one bounded task requirement without assigning engine semantics.
    pub fn new(
        task_id: TaskId,
        device_count: u16,
        port_count: u16,
    ) -> Result<Self, PlacementError> {
        if device_count == 0 || device_count > 64 || port_count == 0 || port_count > 32 {
            return Err(PlacementError::InvalidRequest {
                reason: "task device and port counts must be positive and bounded",
            });
        }
        Ok(Self {
            task_id,
            device_count,
            port_count,
        })
    }

    // Returns the opaque runtime task identity.
    pub const fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    // Returns the exact accelerator count requested by the runtime.
    pub const fn device_count(&self) -> u16 {
        self.device_count
    }

    // Returns the contiguous port count requested by the runtime.
    pub const fn port_count(&self) -> u16 {
        self.port_count
    }
}

// Describes one eligible node's exact allocatable resource envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlacementNodeResources {
    node_id: NodeId,
    runtime_installation_id: RuntimeInstallationId,
    hardware_observation_id: HardwareObservationId,
    boot_id: BootId,
    observed_at: UnixMilliseconds,
    address: NodeAddress,
    device_ids: Vec<DeviceId>,
    ports: PortRange,
    rdma_interface: Option<NetworkInterfaceName>,
}

impl PlacementNodeResources {
    // Creates one node envelope from authenticated observations and installation state.
    pub fn new(
        node_id: NodeId,
        runtime_installation_id: RuntimeInstallationId,
        hardware_observation_id: HardwareObservationId,
        boot_id: BootId,
        observed_at: UnixMilliseconds,
        address: NodeAddress,
        device_ids: Vec<DeviceId>,
        ports: PortRange,
        rdma_interface: Option<NetworkInterfaceName>,
    ) -> Result<Self, PlacementError> {
        let unique: HashSet<&DeviceId> = device_ids.iter().collect();
        if device_ids.is_empty() || device_ids.len() > 64 || unique.len() != device_ids.len() {
            return Err(PlacementError::InvalidRequest {
                reason: "node accelerator identities must be non-empty, unique, and bounded",
            });
        }
        Ok(Self {
            node_id,
            runtime_installation_id,
            hardware_observation_id,
            boot_id,
            observed_at,
            address,
            device_ids,
            ports,
            rdma_interface,
        })
    }

    // Returns the authenticated node identity.
    pub const fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    // Returns the exact runtime installation available on this node.
    pub const fn runtime_installation_id(&self) -> &RuntimeInstallationId {
        &self.runtime_installation_id
    }

    // Returns the exact HardwareManager observation supplying these resources and links.
    pub const fn hardware_observation_id(&self) -> &HardwareObservationId {
        &self.hardware_observation_id
    }

    // Returns the boot identity under which these hardware facts were observed.
    pub const fn boot_id(&self) -> &BootId {
        &self.boot_id
    }

    // Returns when HardwareManager observed these resources and mutable links.
    pub const fn observed_at(&self) -> UnixMilliseconds {
        self.observed_at
    }

    // Returns the node address supplied by NodeManager.
    pub const fn address(&self) -> &NodeAddress {
        &self.address
    }

    // Returns the observed accelerator identities eligible for allocation.
    pub fn device_ids(&self) -> &[DeviceId] {
        &self.device_ids
    }

    // Returns the managed port allocation envelope.
    pub const fn ports(&self) -> PortRange {
        self.ports
    }

    // Returns the verified RDMA interface when one exists.
    pub const fn rdma_interface(&self) -> Option<&NetworkInterfaceName> {
        self.rdma_interface.as_ref()
    }
}

// Describes one verified link between two eligible nodes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlacementLink {
    left_node_id: NodeId,
    right_node_id: NodeId,
    kind: InterconnectKind,
    rdma: bool,
    speed_mbps: u64,
    mtu: u32,
}

impl PlacementLink {
    // Creates one current link fact without treating it as permanent capability.
    pub fn new(
        left_node_id: NodeId,
        right_node_id: NodeId,
        kind: InterconnectKind,
        rdma: bool,
        speed_mbps: u64,
        mtu: u32,
    ) -> Result<Self, PlacementError> {
        if left_node_id == right_node_id || speed_mbps == 0 || mtu == 0 {
            return Err(PlacementError::InvalidRequest {
                reason: "placement link endpoints, speed, or MTU are invalid",
            });
        }
        Ok(Self {
            left_node_id,
            right_node_id,
            kind,
            rdma,
            speed_mbps,
            mtu,
        })
    }

    // Returns the first authenticated link endpoint.
    pub const fn left_node_id(&self) -> &NodeId {
        &self.left_node_id
    }

    // Returns the second authenticated link endpoint.
    pub const fn right_node_id(&self) -> &NodeId {
        &self.right_node_id
    }

    // Returns the model-neutral observed link kind.
    pub const fn kind(&self) -> InterconnectKind {
        self.kind
    }

    // Returns whether the observed link supports RDMA.
    pub const fn rdma(&self) -> bool {
        self.rdma
    }

    // Returns the observed link speed in megabits per second.
    pub const fn speed_mbps(&self) -> u64 {
        self.speed_mbps
    }

    // Returns the observed link MTU.
    pub const fn mtu(&self) -> u32 {
        self.mtu
    }
}

// Binds a runtime-owned task contract to eligible Core resource envelopes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlacementRequest {
    placement_group_id: PlacementGroupId,
    service_id: ModelServiceId,
    runtime: RuntimeIdentity,
    capacity: PlacementGroupCapacity,
    tasks: Vec<PlacementTask>,
    nodes: Vec<PlacementNodeResources>,
    endpoint_task_id: TaskId,
    endpoint_node_id: NodeId,
    startup_order: Vec<Vec<TaskId>>,
    links: Vec<PlacementLink>,
}

impl PlacementRequest {
    // Creates one complete placement request and validates its generic topology.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        placement_group_id: PlacementGroupId,
        service_id: ModelServiceId,
        runtime: RuntimeIdentity,
        capacity: PlacementGroupCapacity,
        tasks: Vec<PlacementTask>,
        nodes: Vec<PlacementNodeResources>,
        endpoint_task_id: TaskId,
        endpoint_node_id: NodeId,
        startup_order: Vec<Vec<TaskId>>,
        links: Vec<PlacementLink>,
    ) -> Result<Self, PlacementError> {
        if tasks.is_empty()
            || tasks.len() > MAX_PLACEMENTS
            || tasks.len() != nodes.len()
            || links.len() > MAX_LINKS
        {
            return Err(PlacementError::InvalidRequest {
                reason: "task, node, or link counts are invalid",
            });
        }
        validate_task_identities(&tasks)?;
        validate_node_identities(&nodes)?;
        validate_startup_order(&tasks, &startup_order)?;
        if !tasks.iter().any(|task| task.task_id() == &endpoint_task_id)
            || !nodes.iter().any(|node| node.node_id() == &endpoint_node_id)
        {
            return Err(PlacementError::InvalidRequest {
                reason: "endpoint task or node is outside the placement request",
            });
        }
        validate_links(&nodes, &links, capacity)?;
        Ok(Self {
            placement_group_id,
            service_id,
            runtime,
            capacity,
            tasks,
            nodes,
            endpoint_task_id,
            endpoint_node_id,
            startup_order,
            links,
        })
    }

    // Returns the exact caller-planned placement-group identity.
    pub const fn placement_group_id(&self) -> &PlacementGroupId {
        &self.placement_group_id
    }

    // Returns the logical service receiving this placement group.
    pub const fn service_id(&self) -> &ModelServiceId {
        &self.service_id
    }

    // Returns the exact runtime shared by every placement.
    pub const fn runtime(&self) -> &RuntimeIdentity {
        &self.runtime
    }

    // Returns the runtime-declared group capacity.
    pub const fn capacity(&self) -> PlacementGroupCapacity {
        self.capacity
    }

    // Returns opaque task requirements in their canonical order.
    pub fn tasks(&self) -> &[PlacementTask] {
        &self.tasks
    }

    // Returns eligible node resources in NodeManager preference order.
    pub fn nodes(&self) -> &[PlacementNodeResources] {
        &self.nodes
    }

    // Returns the task designated to own the group endpoint.
    pub const fn endpoint_task_id(&self) -> &TaskId {
        &self.endpoint_task_id
    }

    // Returns the selected node that must own the endpoint task.
    pub const fn endpoint_node_id(&self) -> &NodeId {
        &self.endpoint_node_id
    }

    // Returns runtime-declared startup phases without interpreting their meaning.
    pub fn startup_order(&self) -> &[Vec<TaskId>] {
        &self.startup_order
    }

    // Returns the verified links used to admit the topology.
    pub fn links(&self) -> &[PlacementLink] {
        &self.links
    }
}

// Groups one placement group, its placements, leases, and opaque phase order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlacementRecord {
    group: PlacementGroup,
    placements: Vec<Placement>,
    leases: Vec<ResourceLease>,
    startup_order: Vec<Vec<PlacementId>>,
    launch_plan_identities: Vec<(PlacementId, Sha256Digest)>,
}

impl PlacementRecord {
    // Creates one coherent aggregate suitable for one atomic store transaction.
    pub fn new(
        group: PlacementGroup,
        placements: Vec<Placement>,
        leases: Vec<ResourceLease>,
        startup_order: Vec<Vec<PlacementId>>,
        launch_plan_identities: Vec<(PlacementId, Sha256Digest)>,
    ) -> Result<Self, PlacementError> {
        validate_record(
            &group,
            &placements,
            &leases,
            &startup_order,
            &launch_plan_identities,
        )?;
        Ok(Self {
            group,
            placements,
            leases,
            startup_order,
            launch_plan_identities,
        })
    }

    // Returns the placement-group snapshot.
    pub const fn group(&self) -> &PlacementGroup {
        &self.group
    }

    // Returns every required placement in canonical task order.
    pub fn placements(&self) -> &[Placement] {
        &self.placements
    }

    // Returns every exact resource lease owned by the group.
    pub fn leases(&self) -> &[ResourceLease] {
        &self.leases
    }

    // Returns the opaque placement phases used for start and reverse stop.
    pub fn startup_order(&self) -> &[Vec<PlacementId>] {
        &self.startup_order
    }

    // Returns every committed launch-plan identity in placement order.
    pub fn launch_plan_identities(&self) -> &[(PlacementId, Sha256Digest)] {
        &self.launch_plan_identities
    }

    // Returns one placement's committed launch-plan identity when staged.
    pub fn launch_plan_identity(&self, placement_id: &PlacementId) -> Option<&Sha256Digest> {
        self.launch_plan_identities
            .iter()
            .find(|(identity, _)| identity == placement_id)
            .map(|(_, digest)| digest)
    }

    // Records one staged placement's immutable launch-plan identity exactly once.
    pub(crate) fn recording_launch_plan_identity(
        mut self,
        placement_id: PlacementId,
        identity: Sha256Digest,
    ) -> Result<Self, PlacementError> {
        if let Some(existing) = self.launch_plan_identity(&placement_id) {
            return if existing == &identity {
                Ok(self)
            } else {
                Err(PlacementError::StoreConflict)
            };
        }
        self.launch_plan_identities.push((placement_id, identity));
        validate_record(
            &self.group,
            &self.placements,
            &self.leases,
            &self.startup_order,
            &self.launch_plan_identities,
        )?;
        Ok(self)
    }
}

// Returns one placement aggregate with its optimistic store revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionedPlacementRecord {
    record: PlacementRecord,
    revision: u64,
}

impl VersionedPlacementRecord {
    // Creates one versioned placement aggregate.
    pub const fn new(record: PlacementRecord, revision: u64) -> Self {
        Self { record, revision }
    }

    // Returns the immutable placement aggregate.
    pub const fn record(&self) -> &PlacementRecord {
        &self.record
    }

    // Returns the revision required by the next mutation.
    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

// Defines the sole durable aggregate and resource-conflict store.
pub trait PlacementStore: Send + Sync {
    // Returns non-released resources currently owned on one node.
    fn occupied_resources(&self, node_id: &NodeId)
        -> Result<Vec<ResourceIdentity>, PlacementError>;

    // Creates one group atomically while rejecting every resource overlap.
    fn create(&self, record: PlacementRecord) -> Result<VersionedPlacementRecord, PlacementError>;

    // Returns one placement group when it exists.
    fn read(
        &self,
        placement_group_id: &PlacementGroupId,
    ) -> Result<Option<VersionedPlacementRecord>, PlacementError>;

    // Replaces one exact placement-group revision atomically.
    fn replace(
        &self,
        record: PlacementRecord,
        expected_revision: u64,
    ) -> Result<VersionedPlacementRecord, PlacementError>;
}

// Describes one current placement observation returned by a node executor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlacementObservation {
    state: PlacementState,
    endpoint: Option<PlacementEndpoint>,
    protection_trip_latched: bool,
}

impl PlacementObservation {
    // Creates one bounded current observation without applying recovery policy.
    pub const fn new(
        state: PlacementState,
        endpoint: Option<PlacementEndpoint>,
        protection_trip_latched: bool,
    ) -> Self {
        Self {
            state,
            endpoint,
            protection_trip_latched,
        }
    }

    // Returns the observed task state.
    pub const fn state(&self) -> PlacementState {
        self.state
    }

    // Returns the endpoint observed on the endpoint-owning task.
    pub const fn endpoint(&self) -> Option<&PlacementEndpoint> {
        self.endpoint.as_ref()
    }

    // Returns whether native protection requires explicit acknowledgement.
    pub const fn protection_trip_latched(&self) -> bool {
        self.protection_trip_latched
    }
}

// Defines shell-free staging and execution on authenticated nodes.
pub trait PlacementExecutor: Send + Sync {
    // Stages exact immutable inputs and returns their durable launch-plan identity.
    fn stage(&self, placement: &Placement) -> Result<Sha256Digest, PlacementError>;

    // Starts one placement and returns an endpoint only for the declared owner.
    fn start(
        &self,
        placement: &Placement,
        acknowledge_protection_trip: bool,
    ) -> Result<Option<PlacementEndpoint>, PlacementError>;

    // Stops one exact placement without releasing its immutable assignment.
    fn stop(&self, placement: &Placement) -> Result<(), PlacementError>;

    // Removes one exact placement and its task-scoped credentials.
    fn remove(&self, placement: &Placement) -> Result<(), PlacementError>;

    // Observes one exact placement without mutating it.
    fn observe(&self, placement: &Placement) -> Result<PlacementObservation, PlacementError>;
}

// Supplies every PlacementManager-owned identity explicitly.
pub trait PlacementIdentityProvider: Send + Sync {
    // Returns one placement identity for an opaque task.
    fn placement_id(&self, task_id: &TaskId) -> Result<PlacementId, PlacementError>;

    // Returns one lease identity for an exact placement resource.
    fn resource_lease_id(
        &self,
        placement_id: &PlacementId,
        resource: &ResourceIdentity,
    ) -> Result<ResourceLeaseId, PlacementError>;
}

// Supplies placement lifecycle time explicitly.
pub trait PlacementClock: Send + Sync {
    // Returns current Unix time in milliseconds.
    fn now(&self) -> Result<UnixMilliseconds, PlacementError>;
}

// Supplies cryptographically random placement and resource-lease identities in production.
pub struct SystemPlacementIdentityProvider;

impl SystemPlacementIdentityProvider {
    // Returns one lowercase 128-bit identity without shared mutable counters.
    fn identity(&self) -> Result<String, PlacementError> {
        let mut bytes = [0_u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| PlacementError::IdentityUnavailable)?;
        Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
    }
}

impl PlacementIdentityProvider for SystemPlacementIdentityProvider {
    // Returns one identity for an opaque runtime task without interpreting the task value.
    fn placement_id(&self, _task_id: &TaskId) -> Result<PlacementId, PlacementError> {
        PlacementId::parse(&self.identity()?).map_err(|_| PlacementError::IdentityUnavailable)
    }

    // Returns one independent resource lease identity without deriving it from secret state.
    fn resource_lease_id(
        &self,
        _placement_id: &PlacementId,
        _resource: &ResourceIdentity,
    ) -> Result<ResourceLeaseId, PlacementError> {
        ResourceLeaseId::parse(&self.identity()?).map_err(|_| PlacementError::IdentityUnavailable)
    }
}

// Supplies wall-clock time to production placement admission and lifecycle transitions.
pub struct SystemPlacementClock;

impl PlacementClock for SystemPlacementClock {
    // Returns current Unix time in milliseconds without masking an invalid system clock.
    fn now(&self) -> Result<UnixMilliseconds, PlacementError> {
        let value = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| PlacementError::ClockUnavailable)?
            .as_millis();
        let value = u64::try_from(value).map_err(|_| PlacementError::ClockUnavailable)?;
        Ok(UnixMilliseconds::new(value))
    }
}

// Describes one completed placement-group transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlacementEvent {
    GroupStaged {
        placement_group_id: PlacementGroupId,
    },
    GroupRunning {
        placement_group_id: PlacementGroupId,
    },
    GroupStopped {
        placement_group_id: PlacementGroupId,
    },
    GroupRecovered {
        placement_group_id: PlacementGroupId,
    },
    GroupRemoved {
        placement_group_id: PlacementGroupId,
    },
    GroupFailed {
        placement_group_id: PlacementGroupId,
    },
    GroupObserved {
        placement_group_id: PlacementGroupId,
    },
}

// Returns one versioned aggregate and its completed event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlacementChange {
    record: VersionedPlacementRecord,
    event: PlacementEvent,
}

impl PlacementChange {
    // Creates one completed placement lifecycle result.
    pub(crate) const fn new(record: VersionedPlacementRecord, event: PlacementEvent) -> Self {
        Self { record, event }
    }

    // Returns the versioned placement aggregate.
    pub const fn record(&self) -> &VersionedPlacementRecord {
        &self.record
    }

    // Returns the completed placement event.
    pub const fn event(&self) -> &PlacementEvent {
        &self.event
    }
}

// Identifies one stable placement planning or lifecycle failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlacementError {
    InvalidRequest { reason: &'static str },
    TopologyUnavailable,
    HardwareObservationUnavailable,
    ResourceUnavailable,
    ResourceConflict,
    StoreUnavailable,
    StoreConflict,
    GroupNotFound,
    InvalidTransition,
    ExecutionUnavailable,
    EndpointUnavailable,
    ProtectionUnsafe,
    IdentityUnavailable,
    ClockUnavailable,
}

impl fmt::Display for PlacementError {
    // Presents stable placement language without leaking task commands or credentials.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest { reason } => {
                write!(formatter, "placement request is invalid: {reason}")
            }
            Self::TopologyUnavailable => formatter.write_str("placement topology is unavailable"),
            Self::HardwareObservationUnavailable => {
                formatter.write_str("placement hardware observation is stale or invalid")
            }
            Self::ResourceUnavailable => formatter.write_str("placement resources are unavailable"),
            Self::ResourceConflict => {
                formatter.write_str("placement resources changed concurrently")
            }
            Self::StoreUnavailable => formatter.write_str("placement storage is unavailable"),
            Self::StoreConflict => formatter.write_str("placement group changed concurrently"),
            Self::GroupNotFound => formatter.write_str("placement group was not found"),
            Self::InvalidTransition => formatter.write_str("placement group transition is invalid"),
            Self::ExecutionUnavailable => formatter.write_str("placement execution is unavailable"),
            Self::EndpointUnavailable => {
                formatter.write_str("placement endpoint is unavailable or invalid")
            }
            Self::ProtectionUnsafe => formatter.write_str("placement protection state is unsafe"),
            Self::IdentityUnavailable => formatter.write_str("placement identity is unavailable"),
            Self::ClockUnavailable => formatter.write_str("placement clock is unavailable"),
        }
    }
}

impl Error for PlacementError {}

// Requires canonical contiguous task-N identities in declaration order.
fn validate_task_identities(tasks: &[PlacementTask]) -> Result<(), PlacementError> {
    if tasks
        .iter()
        .enumerate()
        .any(|(index, task)| task.task_id().as_str() != format!("task-{index}"))
    {
        return Err(PlacementError::InvalidRequest {
            reason: "task identities must be contiguous canonical task-N values",
        });
    }
    Ok(())
}

// Requires one unique authenticated node for every opaque task.
fn validate_node_identities(nodes: &[PlacementNodeResources]) -> Result<(), PlacementError> {
    let unique_nodes: HashSet<&NodeId> =
        nodes.iter().map(PlacementNodeResources::node_id).collect();
    let unique_observations: HashSet<&HardwareObservationId> = nodes
        .iter()
        .map(PlacementNodeResources::hardware_observation_id)
        .collect();
    if unique_nodes.len() != nodes.len() || unique_observations.len() != nodes.len() {
        return Err(PlacementError::InvalidRequest {
            reason: "placement nodes and hardware observations must be unique",
        });
    }
    Ok(())
}

// Requires phases to contain every task exactly once.
fn validate_startup_order(
    tasks: &[PlacementTask],
    startup_order: &[Vec<TaskId>],
) -> Result<(), PlacementError> {
    if startup_order.is_empty() || startup_order.iter().any(Vec::is_empty) {
        return Err(PlacementError::InvalidRequest {
            reason: "startup order requires non-empty phases",
        });
    }
    let declared: HashSet<&TaskId> = tasks.iter().map(PlacementTask::task_id).collect();
    let flattened: Vec<&TaskId> = startup_order.iter().flatten().collect();
    let unique: HashSet<&TaskId> = flattened.iter().copied().collect();
    if flattened.len() != tasks.len() || unique.len() != tasks.len() || unique != declared {
        return Err(PlacementError::InvalidRequest {
            reason: "startup order must contain every task exactly once",
        });
    }
    Ok(())
}

// Requires verified links to connect every selected node under the runtime contract.
fn validate_links(
    nodes: &[PlacementNodeResources],
    links: &[PlacementLink],
    capacity: PlacementGroupCapacity,
) -> Result<(), PlacementError> {
    let node_ids: HashSet<&NodeId> = nodes.iter().map(PlacementNodeResources::node_id).collect();
    if links.iter().any(|link| {
        !node_ids.contains(link.left_node_id()) || !node_ids.contains(link.right_node_id())
    }) {
        return Err(PlacementError::InvalidRequest {
            reason: "placement link references a node outside the request",
        });
    }
    let link_pairs: HashSet<(NodeId, NodeId)> = links
        .iter()
        .map(|link| {
            if link.left_node_id() < link.right_node_id() {
                (link.left_node_id().clone(), link.right_node_id().clone())
            } else {
                (link.right_node_id().clone(), link.left_node_id().clone())
            }
        })
        .collect();
    if link_pairs.len() != links.len() {
        return Err(PlacementError::InvalidRequest {
            reason: "placement links must identify unique node pairs",
        });
    }
    let requirement = capacity.interconnect();
    if requirement.rdma_required() && nodes.iter().any(|node| node.rdma_interface().is_none()) {
        return Err(PlacementError::TopologyUnavailable);
    }
    if nodes.len() == 1 {
        return Ok(());
    }
    let matching: Vec<&PlacementLink> = links
        .iter()
        .filter(|link| {
            (requirement.kind() == InterconnectKind::Any || link.kind() == requirement.kind())
                && (!requirement.rdma_required() || link.rdma())
                && link.speed_mbps() >= requirement.minimum_speed_mbps()
                && link.mtu() >= requirement.minimum_mtu()
        })
        .collect();
    let mut reached: HashSet<NodeId> = HashSet::from([nodes[0].node_id().clone()]);
    loop {
        let previous = reached.len();
        for link in &matching {
            if reached.contains(link.left_node_id()) {
                reached.insert(link.right_node_id().clone());
            }
            if reached.contains(link.right_node_id()) {
                reached.insert(link.left_node_id().clone());
            }
        }
        if reached.len() == previous {
            break;
        }
    }
    if reached.len() != nodes.len() {
        return Err(PlacementError::TopologyUnavailable);
    }
    Ok(())
}

// Requires an aggregate to preserve group, placement, lease, and phase ownership.
fn validate_record(
    group: &PlacementGroup,
    placements: &[Placement],
    leases: &[ResourceLease],
    startup_order: &[Vec<PlacementId>],
    launch_plan_identities: &[(PlacementId, Sha256Digest)],
) -> Result<(), PlacementError> {
    let placement_ids: Vec<&PlacementId> = placements.iter().map(Placement::placement_id).collect();
    if placement_ids.len() != group.placement_ids().len()
        || placement_ids
            .iter()
            .copied()
            .ne(group.placement_ids().iter())
        || placements
            .iter()
            .any(|placement| placement.placement_group_id() != group.placement_group_id())
    {
        return Err(PlacementError::InvalidRequest {
            reason: "placement record differs from its group",
        });
    }
    let unique_nodes: HashSet<&NodeId> = placements
        .iter()
        .map(|placement| placement.assignment().node_id())
        .collect();
    let unique_tasks: HashSet<&TaskId> = placements
        .iter()
        .map(|placement| placement.assignment().task_id())
        .collect();
    let unique_observations: HashSet<&HardwareObservationId> = placements
        .iter()
        .map(|placement| placement.assignment().hardware_observation_id())
        .collect();
    let endpoint_owners = placements
        .iter()
        .filter(|placement| {
            placement.assignment().endpoint_ownership()
                == li_core_interface::EndpointOwnership::Owner
        })
        .collect::<Vec<_>>();
    if unique_nodes.len() != placements.len()
        || unique_tasks.len() != placements.len()
        || unique_observations.len() != placements.len()
        || placements.iter().enumerate().any(|(index, placement)| {
            placement.assignment().task_id().as_str() != format!("task-{index}")
        })
        || endpoint_owners.len() != 1
        || endpoint_owners[0].placement_id() != group.endpoint_placement_id()
    {
        return Err(PlacementError::InvalidRequest {
            reason: "placement identities, observations, or endpoint ownership are inconsistent",
        });
    }
    if let Some(endpoint) = group.endpoint() {
        let owner = endpoint_owners[0];
        let ports = owner.assignment().resources().ports();
        if endpoint.node_id() != owner.assignment().node_id()
            || endpoint.address().host() != owner.assignment().address()
            || endpoint.address().port() < ports.base()
            || endpoint.address().port() > ports.last()
        {
            return Err(PlacementError::InvalidRequest {
                reason: "placement endpoint differs from its exact owner assignment",
            });
        }
    }
    let flattened: Vec<&PlacementId> = startup_order.iter().flatten().collect();
    let unique_phases: HashSet<&PlacementId> = flattened.iter().copied().collect();
    let unique_placements: HashSet<&PlacementId> = placement_ids.iter().copied().collect();
    if startup_order.is_empty()
        || startup_order.iter().any(Vec::is_empty)
        || flattened.len() != placements.len()
        || unique_phases != unique_placements
    {
        return Err(PlacementError::InvalidRequest {
            reason: "placement phase order differs from its group",
        });
    }
    let unique_leases: HashSet<&ResourceLeaseId> =
        leases.iter().map(ResourceLease::lease_id).collect();
    if unique_leases.len() != leases.len() {
        return Err(PlacementError::InvalidRequest {
            reason: "placement lease identities must be unique",
        });
    }
    let expected_lease_count = placements
        .iter()
        .map(resources_for_placement)
        .map(|resources| resources.len())
        .sum::<usize>();
    if leases.len() != expected_lease_count
        || leases.iter().enumerate().any(|(index, lease)| {
            leases.iter().skip(index + 1).any(|candidate| {
                lease.node_id() == candidate.node_id() && lease.resource() == candidate.resource()
            })
        })
    {
        return Err(PlacementError::InvalidRequest {
            reason: "placement resource ownership is duplicated or unrelated",
        });
    }
    let unique_plan_placements: HashSet<&PlacementId> = launch_plan_identities
        .iter()
        .map(|(placement_id, _)| placement_id)
        .collect();
    let ordered_plan_placements = placements
        .iter()
        .map(Placement::placement_id)
        .filter(|placement_id| unique_plan_placements.contains(placement_id))
        .collect::<Vec<_>>();
    if unique_plan_placements.len() != launch_plan_identities.len()
        || unique_plan_placements
            .iter()
            .any(|placement_id| !unique_placements.contains(*placement_id))
        || ordered_plan_placements
            != launch_plan_identities
                .iter()
                .map(|(placement_id, _)| placement_id)
                .collect::<Vec<_>>()
        || (matches!(
            group.state(),
            PlacementGroupState::Staged
                | PlacementGroupState::Starting
                | PlacementGroupState::Running
                | PlacementGroupState::Degraded
                | PlacementGroupState::Stopping
                | PlacementGroupState::Stopped
                | PlacementGroupState::Recovering
        ) && launch_plan_identities.len() != placements.len())
    {
        return Err(PlacementError::InvalidRequest {
            reason: "launch-plan identities must be unique, owned, and complete after staging",
        });
    }
    for placement in placements {
        let expected = resources_for_placement(placement);
        let owned: Vec<&ResourceLease> = leases
            .iter()
            .filter(|lease| lease.placement_id() == placement.placement_id())
            .collect();
        if owned.len() != expected.len()
            || owned
                .iter()
                .any(|lease| lease.node_id() != placement.assignment().node_id())
            || expected
                .iter()
                .any(|resource| !owned.iter().any(|lease| lease.resource() == resource))
        {
            return Err(PlacementError::InvalidRequest {
                reason: "placement leases differ from assigned resources",
            });
        }
    }
    validate_terminal_record_state(group, placements, leases)
}

// Returns every exact resource represented by one placement assignment.
fn resources_for_placement(placement: &Placement) -> Vec<ResourceIdentity> {
    let assignment = placement.assignment();
    let mut resources: Vec<ResourceIdentity> = assignment
        .resources()
        .device_ids()
        .iter()
        .cloned()
        .map(ResourceIdentity::Accelerator)
        .collect();
    let ports = assignment.resources().ports();
    resources.extend((0..ports.count()).map(|offset| {
        ResourceIdentity::Port(
            li_core_interface::NetworkPort::new(ports.base() + offset).expect("validated port"),
        )
    }));
    if let Some(interface) = assignment.resources().rdma_interface() {
        resources.push(ResourceIdentity::RdmaInterface(interface.clone()));
    }
    resources
}

// Requires complete lifecycle states to agree across the aggregate.
fn validate_terminal_record_state(
    group: &PlacementGroup,
    placements: &[Placement],
    leases: &[ResourceLease],
) -> Result<(), PlacementError> {
    let expected = match group.state() {
        PlacementGroupState::Staged => Some((PlacementState::Staged, ResourceLeaseState::Reserved)),
        PlacementGroupState::Running => Some((PlacementState::Running, ResourceLeaseState::Active)),
        PlacementGroupState::Stopped => {
            Some((PlacementState::Stopped, ResourceLeaseState::Reserved))
        }
        PlacementGroupState::Removed => {
            Some((PlacementState::Removed, ResourceLeaseState::Released))
        }
        _ => None,
    };
    if let Some((placement_state, lease_state)) = expected {
        if placements
            .iter()
            .any(|placement| placement.state() != placement_state)
            || leases.iter().any(|lease| lease.state() != lease_state)
        {
            return Err(PlacementError::InvalidRequest {
                reason: "terminal placement-group state differs from placements or leases",
            });
        }
    }
    if group.state() == PlacementGroupState::Running
        && group.desired_state() != ModelServiceDesiredState::Running
    {
        return Err(PlacementError::InvalidRequest {
            reason: "running placement group must have running intent",
        });
    }
    Ok(())
}

// Constructs one placement resource assignment for lifecycle helpers.
pub(crate) fn placement_resources(
    ports: PortRange,
    device_ids: Vec<DeviceId>,
    rdma_interface: Option<NetworkInterfaceName>,
) -> Result<PlacementResources, PlacementError> {
    PlacementResources::new(ports, device_ids, rdma_interface).map_err(|_| {
        PlacementError::InvalidRequest {
            reason: "allocated placement resources are invalid",
        }
    })
}
