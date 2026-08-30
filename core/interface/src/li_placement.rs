// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;

use crate::{
    BootId, DeviceId, EntityTimestamps, FailureDescription, HardwareObservationId, InterfaceError,
    NetworkInterfaceName, NodeAddress, NodeId, OperationId, PlacementGroupId, PlacementId,
    PortRange, RuntimeInstallationId, TaskId, UnixMilliseconds,
};

const MAX_DEVICES_PER_PLACEMENT: usize = 64;

// Identifies whether one placement owns its group's single endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointOwnership {
    Owner,
    Participant,
}

// Describes the exact resources assigned to one opaque runtime task.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlacementResources {
    ports: PortRange,
    device_ids: Vec<DeviceId>,
    rdma_interface: Option<NetworkInterfaceName>,
}

impl PlacementResources {
    // Creates one non-empty bounded accelerator and network assignment.
    pub fn new(
        ports: PortRange,
        device_ids: Vec<DeviceId>,
        rdma_interface: Option<NetworkInterfaceName>,
    ) -> Result<Self, InterfaceError> {
        let unique: HashSet<&DeviceId> = device_ids.iter().collect();
        if device_ids.is_empty()
            || device_ids.len() > MAX_DEVICES_PER_PLACEMENT
            || unique.len() != device_ids.len()
        {
            return Err(InterfaceError::new(
                "placement resources",
                "device identities must be non-empty, unique, and bounded",
            ));
        }
        Ok(Self {
            ports,
            device_ids,
            rdma_interface,
        })
    }

    // Returns the contiguous port allocation.
    pub const fn ports(&self) -> PortRange {
        self.ports
    }

    // Returns the exact accelerator identities assigned to the task.
    pub fn device_ids(&self) -> &[DeviceId] {
        &self.device_ids
    }

    // Returns the RDMA interface when the runtime requires one.
    pub const fn rdma_interface(&self) -> Option<&NetworkInterfaceName> {
        self.rdma_interface.as_ref()
    }
}

// Groups one placement's immutable task and resource assignment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlacementAssignment {
    node_id: NodeId,
    runtime_installation_id: RuntimeInstallationId,
    hardware_observation_id: HardwareObservationId,
    hardware_boot_id: BootId,
    hardware_observed_at: UnixMilliseconds,
    task_id: TaskId,
    address: NodeAddress,
    resources: PlacementResources,
    endpoint_ownership: EndpointOwnership,
}

impl PlacementAssignment {
    // Creates one exact opaque task assignment without engine rank semantics.
    pub const fn new(
        node_id: NodeId,
        runtime_installation_id: RuntimeInstallationId,
        hardware_observation_id: HardwareObservationId,
        hardware_boot_id: BootId,
        hardware_observed_at: UnixMilliseconds,
        task_id: TaskId,
        address: NodeAddress,
        resources: PlacementResources,
        endpoint_ownership: EndpointOwnership,
    ) -> Self {
        Self {
            node_id,
            runtime_installation_id,
            hardware_observation_id,
            hardware_boot_id,
            hardware_observed_at,
            task_id,
            address,
            resources,
            endpoint_ownership,
        }
    }

    // Returns the assigned node identity.
    pub const fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    // Returns the host-local runtime installation used by this task.
    pub const fn runtime_installation_id(&self) -> &RuntimeInstallationId {
        &self.runtime_installation_id
    }

    // Returns the exact hardware observation used to allocate this placement.
    pub const fn hardware_observation_id(&self) -> &HardwareObservationId {
        &self.hardware_observation_id
    }

    // Returns the boot identity under which the allocated hardware was observed.
    pub const fn hardware_boot_id(&self) -> &BootId {
        &self.hardware_boot_id
    }

    // Returns when the allocated hardware facts were observed.
    pub const fn hardware_observed_at(&self) -> UnixMilliseconds {
        self.hardware_observed_at
    }

    // Returns the opaque runtime task identity.
    pub const fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    // Returns the node address used by placement coordination.
    pub const fn address(&self) -> &NodeAddress {
        &self.address
    }

    // Returns the exact resources assigned to the task.
    pub const fn resources(&self) -> &PlacementResources {
        &self.resources
    }

    // Returns whether this task owns the group's endpoint.
    pub const fn endpoint_ownership(&self) -> EndpointOwnership {
        self.endpoint_ownership
    }
}

// Describes the latest observed lifecycle state of one placement task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlacementState {
    Pending,
    Staging,
    Staged,
    Starting,
    Running,
    Stopping,
    Stopped,
    Removing,
    Removed,
    Failed,
    Unreachable,
}

// Describes one exact placement snapshot without interpreting runtime internals.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Placement {
    placement_id: PlacementId,
    placement_group_id: PlacementGroupId,
    assignment: PlacementAssignment,
    state: PlacementState,
    active_operation_id: Option<OperationId>,
    last_failure: Option<FailureDescription>,
    timestamps: EntityTimestamps,
}

impl Placement {
    // Creates one coherent placement snapshot from an immutable assignment.
    pub fn new(
        placement_id: PlacementId,
        placement_group_id: PlacementGroupId,
        assignment: PlacementAssignment,
        state: PlacementState,
        active_operation_id: Option<OperationId>,
        last_failure: Option<FailureDescription>,
        timestamps: EntityTimestamps,
    ) -> Result<Self, InterfaceError> {
        if state == PlacementState::Failed && last_failure.is_none() {
            return Err(InterfaceError::new(
                "placement",
                "failed state requires a failure description",
            ));
        }
        Ok(Self {
            placement_id,
            placement_group_id,
            assignment,
            state,
            active_operation_id,
            last_failure,
            timestamps,
        })
    }

    // Returns the placement identity.
    pub const fn placement_id(&self) -> &PlacementId {
        &self.placement_id
    }

    // Returns the owning placement-group identity.
    pub const fn placement_group_id(&self) -> &PlacementGroupId {
        &self.placement_group_id
    }

    // Returns the immutable task and resource assignment.
    pub const fn assignment(&self) -> &PlacementAssignment {
        &self.assignment
    }

    // Returns the latest observed placement state.
    pub const fn state(&self) -> PlacementState {
        self.state
    }

    // Returns the active operation when this placement is changing.
    pub const fn active_operation_id(&self) -> Option<&OperationId> {
        self.active_operation_id.as_ref()
    }

    // Returns the most recent bounded placement failure.
    pub const fn last_failure(&self) -> Option<&FailureDescription> {
        self.last_failure.as_ref()
    }

    // Returns the placement snapshot timestamps.
    pub const fn timestamps(&self) -> EntityTimestamps {
        self.timestamps
    }
}
