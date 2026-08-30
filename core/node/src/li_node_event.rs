// SPDX-License-Identifier: AGPL-3.0-only

use li_core_interface::{HardwareObservationId, ModelServiceId, NodeId, NodeRole, OperationId};

// Describes one completed node-manager state change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodeManagerEvent {
    NodeInitialized {
        node_id: NodeId,
    },
    NodeEnrolled {
        node_id: NodeId,
    },
    NodeActivated {
        node_id: NodeId,
    },
    NodePaused {
        node_id: NodeId,
    },
    NodeMarkedOffline {
        node_id: NodeId,
    },
    NodeRemoved {
        node_id: NodeId,
    },
    LocalRoleChanged {
        node_id: NodeId,
        role: NodeRole,
    },
    HardwareRecorded {
        observation_id: HardwareObservationId,
    },
    ModelServiceCreated {
        service_id: ModelServiceId,
    },
    ModelServiceUpdated {
        service_id: ModelServiceId,
    },
    ModelServiceRemoved {
        service_id: ModelServiceId,
    },
    OperationBegan {
        operation_id: OperationId,
    },
    OperationStarted {
        operation_id: OperationId,
    },
    OperationSucceeded {
        operation_id: OperationId,
    },
    OperationFailed {
        operation_id: OperationId,
    },
    OperationCancelled {
        operation_id: OperationId,
    },
}

// Returns a committed snapshot and its optional non-replayed domain event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeManagerChange<Value> {
    value: Value,
    revision: u64,
    event: Option<NodeManagerEvent>,
}

impl<Value> NodeManagerChange<Value> {
    // Creates one result for an existing snapshot observed without mutation.
    pub(crate) const fn observed(value: Value, revision: u64) -> Self {
        Self {
            value,
            revision,
            event: None,
        }
    }

    // Creates one result after a database command resolves.
    pub(crate) const fn committed(
        value: Value,
        revision: u64,
        event: Option<NodeManagerEvent>,
    ) -> Self {
        Self {
            value,
            revision,
            event,
        }
    }

    // Returns the committed or observed entity snapshot.
    pub const fn value(&self) -> &Value {
        &self.value
    }

    // Returns the record revision required by the next mutation.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    // Returns the domain event only when this call created a new commit.
    pub const fn event(&self) -> Option<&NodeManagerEvent> {
        self.event.as_ref()
    }
}
