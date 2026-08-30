// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    DisplayName, EntityTimestamps, HardwareObservationId, InstallationId, MachineId, NodeAddress,
    NodeId,
};

// Identifies the topology responsibility assigned to one node.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeRole {
    Main,
    Child,
}

// Describes the latest observed membership state for one node.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeState {
    Pending,
    Active,
    Draining,
    Offline,
    Removed,
}

// Groups the logical, physical, and installed identities of one node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeIdentity {
    node_id: NodeId,
    machine_id: MachineId,
    installation_id: InstallationId,
}

impl NodeIdentity {
    // Creates one explicit node identity without generating any component.
    pub const fn new(
        node_id: NodeId,
        machine_id: MachineId,
        installation_id: InstallationId,
    ) -> Self {
        Self {
            node_id,
            machine_id,
            installation_id,
        }
    }

    // Returns the enrolled node identity.
    pub const fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    // Returns the physical-machine identity.
    pub const fn machine_id(&self) -> &MachineId {
        &self.machine_id
    }

    // Returns the installed Core identity.
    pub const fn installation_id(&self) -> &InstallationId {
        &self.installation_id
    }
}

// Describes one immutable node snapshot shared between Core components.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Node {
    identity: NodeIdentity,
    display_name: DisplayName,
    role: NodeRole,
    state: NodeState,
    control_address: NodeAddress,
    latest_hardware_observation_id: Option<HardwareObservationId>,
    timestamps: EntityTimestamps,
}

impl Node {
    // Creates one coherent node snapshot from already-validated values.
    pub const fn new(
        identity: NodeIdentity,
        display_name: DisplayName,
        role: NodeRole,
        state: NodeState,
        control_address: NodeAddress,
        latest_hardware_observation_id: Option<HardwareObservationId>,
        timestamps: EntityTimestamps,
    ) -> Self {
        Self {
            identity,
            display_name,
            role,
            state,
            control_address,
            latest_hardware_observation_id,
            timestamps,
        }
    }

    // Returns the complete node identity.
    pub const fn identity(&self) -> &NodeIdentity {
        &self.identity
    }

    // Returns the user-facing node name.
    pub const fn display_name(&self) -> &DisplayName {
        &self.display_name
    }

    // Returns the node topology role.
    pub const fn role(&self) -> NodeRole {
        self.role
    }

    // Returns the latest observed node state.
    pub const fn state(&self) -> NodeState {
        self.state
    }

    // Returns the private control-plane address.
    pub const fn control_address(&self) -> &NodeAddress {
        &self.control_address
    }

    // Returns the latest hardware observation identity when one exists.
    pub const fn latest_hardware_observation_id(&self) -> Option<&HardwareObservationId> {
        self.latest_hardware_observation_id.as_ref()
    }

    // Returns the node snapshot timestamps.
    pub const fn timestamps(&self) -> EntityTimestamps {
        self.timestamps
    }
}
