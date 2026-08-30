// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    EntityTimestamps, FailureDescription, InterfaceError, ModelServiceId, NodeId, OperationId,
    PlacementGroupId, PlacementId, RuntimeInstallationId, UnixMilliseconds,
};

// Identifies one manager-owned operation without describing its mechanism.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationKind {
    Install,
    Start,
    Stop,
    Restart,
    Recover,
    Remove,
    Update,
}

// Identifies the exact entity addressed by an operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperationTarget {
    Node(NodeId),
    RuntimeInstallation(RuntimeInstallationId),
    ModelService(ModelServiceId),
    PlacementGroup(PlacementGroupId),
    Placement(PlacementId),
}

// Describes the latest observed state of one manager-owned operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationState {
    Pending,
    Running,
    Succeeded,
    Failed,
    Cancelled,
}

// Describes one long-running Core operation snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Operation {
    operation_id: OperationId,
    kind: OperationKind,
    target: OperationTarget,
    state: OperationState,
    failure: Option<FailureDescription>,
    completed_at: Option<UnixMilliseconds>,
    timestamps: EntityTimestamps,
}

impl Operation {
    // Creates one coherent operation snapshot without advancing its lifecycle.
    pub fn new(
        operation_id: OperationId,
        kind: OperationKind,
        target: OperationTarget,
        state: OperationState,
        failure: Option<FailureDescription>,
        completed_at: Option<UnixMilliseconds>,
        timestamps: EntityTimestamps,
    ) -> Result<Self, InterfaceError> {
        let is_terminal = matches!(
            state,
            OperationState::Succeeded | OperationState::Failed | OperationState::Cancelled
        );
        if is_terminal != completed_at.is_some() {
            return Err(InterfaceError::new(
                "operation",
                "terminal state and completion timestamp must agree",
            ));
        }
        if state == OperationState::Failed && failure.is_none() {
            return Err(InterfaceError::new(
                "operation",
                "failed state requires a failure description",
            ));
        }
        if state != OperationState::Failed && failure.is_some() {
            return Err(InterfaceError::new(
                "operation",
                "only failed state may carry a failure description",
            ));
        }
        if completed_at
            .is_some_and(|value| value < timestamps.created_at() || value > timestamps.updated_at())
        {
            return Err(InterfaceError::new(
                "operation",
                "completion timestamp must fall within the operation timestamps",
            ));
        }
        Ok(Self {
            operation_id,
            kind,
            target,
            state,
            failure,
            completed_at,
            timestamps,
        })
    }

    // Returns the operation identity.
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    // Returns the manager-owned operation kind.
    pub const fn kind(&self) -> OperationKind {
        self.kind
    }

    // Returns the exact operation target.
    pub const fn target(&self) -> &OperationTarget {
        &self.target
    }

    // Returns the latest observed operation state.
    pub const fn state(&self) -> OperationState {
        self.state
    }

    // Returns the terminal failure when the operation failed.
    pub const fn failure(&self) -> Option<&FailureDescription> {
        self.failure.as_ref()
    }

    // Returns the completion timestamp for a terminal operation.
    pub const fn completed_at(&self) -> Option<UnixMilliseconds> {
        self.completed_at
    }

    // Returns the operation snapshot timestamps.
    pub const fn timestamps(&self) -> EntityTimestamps {
        self.timestamps
    }
}
