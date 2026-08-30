// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;

use crate::{EntityTimestamps, InterfaceError, LogicalModelName, ModelServiceId, PlacementGroupId};

const MAX_PLACEMENT_GROUPS_PER_SERVICE: usize = 256;

// Describes the operator's intended lifecycle state for one model service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelServiceDesiredState {
    Running,
    Stopped,
    Removed,
}

// Describes one main-owned logical model service snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelService {
    service_id: ModelServiceId,
    logical_model: LogicalModelName,
    desired_state: ModelServiceDesiredState,
    placement_group_ids: Vec<PlacementGroupId>,
    timestamps: EntityTimestamps,
}

impl ModelService {
    // Creates one logical service with a bounded set of independent replicas.
    pub fn new(
        service_id: ModelServiceId,
        logical_model: LogicalModelName,
        desired_state: ModelServiceDesiredState,
        placement_group_ids: Vec<PlacementGroupId>,
        timestamps: EntityTimestamps,
    ) -> Result<Self, InterfaceError> {
        let unique: HashSet<&PlacementGroupId> = placement_group_ids.iter().collect();
        if placement_group_ids.len() > MAX_PLACEMENT_GROUPS_PER_SERVICE
            || unique.len() != placement_group_ids.len()
        {
            return Err(InterfaceError::new(
                "model service",
                "placement-group identities must be unique and bounded",
            ));
        }
        Ok(Self {
            service_id,
            logical_model,
            desired_state,
            placement_group_ids,
            timestamps,
        })
    }

    // Returns the logical service identity.
    pub const fn service_id(&self) -> &ModelServiceId {
        &self.service_id
    }

    // Returns the user-facing logical model identity.
    pub const fn logical_model(&self) -> &LogicalModelName {
        &self.logical_model
    }

    // Returns the operator's intended service state.
    pub const fn desired_state(&self) -> ModelServiceDesiredState {
        self.desired_state
    }

    // Returns every independent placement group under this service.
    pub fn placement_group_ids(&self) -> &[PlacementGroupId] {
        &self.placement_group_ids
    }

    // Returns the service snapshot timestamps.
    pub const fn timestamps(&self) -> EntityTimestamps {
        self.timestamps
    }
}
