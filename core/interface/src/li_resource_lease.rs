// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    DeviceId, EntityTimestamps, NetworkInterfaceName, NetworkPort, NodeId, PlacementId,
    ResourceLeaseId,
};

// Identifies one generic host resource reserved for a placement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResourceIdentity {
    Accelerator(DeviceId),
    Port(NetworkPort),
    RdmaInterface(NetworkInterfaceName),
}

// Describes the latest observed lifecycle state of one exclusive resource lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceLeaseState {
    Reserved,
    Active,
    Draining,
    Released,
}

// Describes one exact resource reservation owned by a placement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceLease {
    lease_id: ResourceLeaseId,
    placement_id: PlacementId,
    node_id: NodeId,
    resource: ResourceIdentity,
    state: ResourceLeaseState,
    timestamps: EntityTimestamps,
}

impl ResourceLease {
    // Creates one resource-lease snapshot without performing a reservation.
    pub const fn new(
        lease_id: ResourceLeaseId,
        placement_id: PlacementId,
        node_id: NodeId,
        resource: ResourceIdentity,
        state: ResourceLeaseState,
        timestamps: EntityTimestamps,
    ) -> Self {
        Self {
            lease_id,
            placement_id,
            node_id,
            resource,
            state,
            timestamps,
        }
    }

    // Returns the resource-lease identity.
    pub const fn lease_id(&self) -> &ResourceLeaseId {
        &self.lease_id
    }

    // Returns the placement that owns this lease.
    pub const fn placement_id(&self) -> &PlacementId {
        &self.placement_id
    }

    // Returns the node that owns the physical resource.
    pub const fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    // Returns the exact reserved resource identity.
    pub const fn resource(&self) -> &ResourceIdentity {
        &self.resource
    }

    // Returns the latest observed lease state.
    pub const fn state(&self) -> ResourceLeaseState {
        self.state
    }

    // Returns the lease snapshot timestamps.
    pub const fn timestamps(&self) -> EntityTimestamps {
        self.timestamps
    }
}
