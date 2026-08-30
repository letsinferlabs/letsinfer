// SPDX-License-Identifier: AGPL-3.0-only

use li_core_interface::{
    EntityTimestamps, LogicalModelName, ModelService, ModelServiceDesiredState, ModelServiceId,
    PlacementGroupId, UnixMilliseconds,
};
use li_database::{DatabaseCollection, DatabaseRecord};
use serde::{Deserialize, Serialize};

use crate::NodeManagerError;

// Stores the private persistence projection of one logical model service.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ModelServiceDatabaseRecord {
    service_id: String,
    logical_model: String,
    desired_state: String,
    placement_group_ids: Vec<String>,
    created_at_unix_milliseconds: u64,
    updated_at_unix_milliseconds: u64,
}

impl DatabaseRecord for ModelServiceDatabaseRecord {
    const COLLECTION: DatabaseCollection = DatabaseCollection::Services;

    // Returns the stable logical service identity.
    fn identifier(&self) -> &str {
        &self.service_id
    }
}

// Projects one validated model service into private persistence.
pub(crate) fn model_service_record(service: &ModelService) -> ModelServiceDatabaseRecord {
    ModelServiceDatabaseRecord {
        service_id: service.service_id().as_str().to_string(),
        logical_model: service.logical_model().as_str().to_string(),
        desired_state: desired_state_name(service.desired_state()).to_string(),
        placement_group_ids: service
            .placement_group_ids()
            .iter()
            .map(|identity| identity.as_str().to_string())
            .collect(),
        created_at_unix_milliseconds: service.timestamps().created_at().value(),
        updated_at_unix_milliseconds: service.timestamps().updated_at().value(),
    }
}

// Reconstructs one fully validated model service from private persistence.
pub(crate) fn model_service_from_record(
    record: ModelServiceDatabaseRecord,
) -> Result<ModelService, NodeManagerError> {
    ModelService::new(
        ModelServiceId::parse(&record.service_id)?,
        LogicalModelName::parse(&record.logical_model)?,
        desired_state(&record.desired_state)?,
        record
            .placement_group_ids
            .into_iter()
            .map(|value| PlacementGroupId::parse(&value).map_err(Into::into))
            .collect::<Result<Vec<_>, NodeManagerError>>()?,
        EntityTimestamps::new(
            UnixMilliseconds::new(record.created_at_unix_milliseconds),
            UnixMilliseconds::new(record.updated_at_unix_milliseconds),
        )?,
    )
    .map_err(Into::into)
}

// Returns the private desired-state persistence name.
fn desired_state_name(state: ModelServiceDesiredState) -> &'static str {
    match state {
        ModelServiceDesiredState::Running => "running",
        ModelServiceDesiredState::Stopped => "stopped",
        ModelServiceDesiredState::Removed => "removed",
    }
}

// Parses one private desired-state persistence value.
fn desired_state(value: &str) -> Result<ModelServiceDesiredState, NodeManagerError> {
    match value {
        "running" => Ok(ModelServiceDesiredState::Running),
        "stopped" => Ok(ModelServiceDesiredState::Stopped),
        "removed" => Ok(ModelServiceDesiredState::Removed),
        _ => Err(NodeManagerError::CorruptState {
            reason: "model service desired state is invalid",
        }),
    }
}
