// SPDX-License-Identifier: AGPL-3.0-only

use li_core_interface::HardwareObservation;
use li_database::{DatabaseCollection, DatabaseRecord};
use li_hardware_manager::{decode_hardware_observation, encode_hardware_observation};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::{NodeManagerError, NodeManagerEvent};

// Defines the narrow HardwareManager capability consumed by NodeManager orchestration.
pub trait NodeHardwareObservationProvider: Send + Sync {
    // Returns one current validated local hardware observation.
    fn observe(&self) -> Result<HardwareObservation, NodeManagerError>;
}

impl NodeHardwareObservationProvider for li_hardware_manager::HardwareManager {
    // Preserves HardwareManager ownership while hiding provider mechanics from NodeManager.
    fn observe(&self) -> Result<HardwareObservation, NodeManagerError> {
        li_hardware_manager::HardwareManager::observe(self)
            .map(|change| change.observation().clone())
            .map_err(|_| NodeManagerError::InvalidHardwareObservation {
                reason: "HardwareManager could not produce a valid observation",
            })
    }
}

// Returns one durable observation and the local-node revision advanced with it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeHardwareChange {
    observation: HardwareObservation,
    node_revision: u64,
    event: Option<NodeManagerEvent>,
}

impl NodeHardwareChange {
    // Creates one result for an already-committed observation.
    pub(crate) const fn observed(observation: HardwareObservation, node_revision: u64) -> Self {
        Self {
            observation,
            node_revision,
            event: None,
        }
    }

    // Creates one result after atomic observation, node, and outbox commit.
    pub(crate) const fn committed(
        observation: HardwareObservation,
        node_revision: u64,
        event: Option<NodeManagerEvent>,
    ) -> Self {
        Self {
            observation,
            node_revision,
            event,
        }
    }

    // Returns the exact durable hardware snapshot.
    pub const fn observation(&self) -> &HardwareObservation {
        &self.observation
    }

    // Returns the local-node revision required by its next mutation.
    pub const fn node_revision(&self) -> u64 {
        self.node_revision
    }

    // Returns one event only when this call created a new commit.
    pub const fn event(&self) -> Option<&NodeManagerEvent> {
        self.event.as_ref()
    }
}

// Stores one HardwareManager-owned strict document without duplicating its wire shape.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HardwareObservationDatabaseRecord {
    node_id: String,
    observation: Box<RawValue>,
}

impl DatabaseRecord for HardwareObservationDatabaseRecord {
    const COLLECTION: DatabaseCollection = DatabaseCollection::HardwareObservations;

    // Returns the node identity whose latest observation this record replaces.
    fn identifier(&self) -> &str {
        &self.node_id
    }
}

// Encodes one validated observation through HardwareManager's strict schema boundary.
pub(crate) fn hardware_observation_record(
    observation: &HardwareObservation,
) -> Result<HardwareObservationDatabaseRecord, NodeManagerError> {
    let document = encode_hardware_observation(observation).map_err(|_| {
        NodeManagerError::InvalidHardwareObservation {
            reason: "hardware observation could not be encoded",
        }
    })?;
    let document =
        String::from_utf8(document).map_err(|_| NodeManagerError::InvalidHardwareObservation {
            reason: "hardware observation encoding is not UTF-8",
        })?;
    let encoded_observation = RawValue::from_string(document).map_err(|_| {
        NodeManagerError::InvalidHardwareObservation {
            reason: "hardware observation encoding is invalid",
        }
    })?;
    Ok(HardwareObservationDatabaseRecord {
        node_id: observation.node_id().as_str().to_string(),
        observation: encoded_observation,
    })
}

// Decodes one durable observation only through HardwareManager's strict schema boundary.
pub(crate) fn hardware_observation_from_record(
    record: HardwareObservationDatabaseRecord,
) -> Result<HardwareObservation, NodeManagerError> {
    let observation =
        decode_hardware_observation(record.observation.get().as_bytes()).map_err(|_| {
            NodeManagerError::CorruptState {
                reason: "hardware observation document is invalid",
            }
        })?;
    if observation.node_id().as_str() != record.node_id {
        return Err(NodeManagerError::CorruptState {
            reason: "hardware record identity differs from its document",
        });
    }
    Ok(observation)
}
