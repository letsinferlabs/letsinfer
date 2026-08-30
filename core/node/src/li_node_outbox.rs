// SPDX-License-Identifier: AGPL-3.0-only

use li_core_interface::{NodeRole, Sha256Digest, TechnicalName, UnixMilliseconds};
use li_database::{DatabaseCollection, DatabaseRecord};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{NodeManagerError, NodeManagerEvent};

// Identifies whether one durable domain event awaits or completed delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeOutboxState {
    Pending,
    Acknowledged,
}

// Stores one durable secret-free NodeManager event projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeOutboxEvent {
    event_id: Sha256Digest,
    kind: TechnicalName,
    entity_id: String,
    occurred_at: UnixMilliseconds,
    state: NodeOutboxState,
    acknowledged_at: Option<UnixMilliseconds>,
}

impl NodeOutboxEvent {
    // Creates one coherent pending or acknowledged outbox event.
    pub(crate) fn new(
        event_id: Sha256Digest,
        kind: TechnicalName,
        entity_id: String,
        occurred_at: UnixMilliseconds,
        state: NodeOutboxState,
        acknowledged_at: Option<UnixMilliseconds>,
    ) -> Result<Self, NodeManagerError> {
        if !is_lower_hex(&entity_id, 32)
            || !is_outbox_kind(kind.as_str())
            || (state == NodeOutboxState::Pending && acknowledged_at.is_some())
            || (state == NodeOutboxState::Acknowledged
                && acknowledged_at.is_none_or(|value| value.value() < occurred_at.value()))
        {
            return Err(NodeManagerError::CorruptState {
                reason: "outbox event is incomplete or inconsistent",
            });
        }
        Ok(Self {
            event_id,
            kind,
            entity_id,
            occurred_at,
            state,
            acknowledged_at,
        })
    }

    // Returns the deterministic event identity.
    pub const fn event_id(&self) -> &Sha256Digest {
        &self.event_id
    }

    // Returns the stable event kind.
    pub const fn kind(&self) -> &TechnicalName {
        &self.kind
    }

    // Returns the exact changed entity identity.
    pub fn entity_id(&self) -> &str {
        &self.entity_id
    }

    // Returns when the domain transition occurred.
    pub const fn occurred_at(&self) -> UnixMilliseconds {
        self.occurred_at
    }

    // Returns the durable delivery state.
    pub const fn state(&self) -> NodeOutboxState {
        self.state
    }

    // Returns when delivery was acknowledged.
    pub const fn acknowledged_at(&self) -> Option<UnixMilliseconds> {
        self.acknowledged_at
    }

    // Returns one acknowledged snapshot while preserving event identity.
    pub(crate) fn acknowledged(
        &self,
        acknowledged_at: UnixMilliseconds,
    ) -> Result<Self, NodeManagerError> {
        Self::new(
            self.event_id.clone(),
            self.kind.clone(),
            self.entity_id.clone(),
            self.occurred_at,
            NodeOutboxState::Acknowledged,
            Some(acknowledged_at),
        )
    }
}

// Returns one outbox snapshot with its optimistic database revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionedNodeOutboxEvent {
    event: NodeOutboxEvent,
    revision: u64,
}

impl VersionedNodeOutboxEvent {
    // Creates one exact versioned outbox result.
    pub(crate) const fn new(event: NodeOutboxEvent, revision: u64) -> Self {
        Self { event, revision }
    }

    // Returns the durable event snapshot.
    pub const fn event(&self) -> &NodeOutboxEvent {
        &self.event
    }

    // Returns the revision required by acknowledgment.
    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

// Stores the private persistence projection of one outbox event.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct NodeOutboxDatabaseRecord {
    event_id: String,
    kind: String,
    entity_id: String,
    occurred_at_unix_milliseconds: u64,
    state: String,
    acknowledged_at_unix_milliseconds: Option<u64>,
}

impl DatabaseRecord for NodeOutboxDatabaseRecord {
    const COLLECTION: DatabaseCollection = DatabaseCollection::Outbox;

    // Returns the deterministic event identity.
    fn identifier(&self) -> &str {
        &self.event_id
    }
}

// Creates one deterministic pending event from a committed domain event intent.
pub(crate) fn pending_outbox_event(
    idempotency_key: &str,
    event: &NodeManagerEvent,
    occurred_at: UnixMilliseconds,
) -> Result<NodeOutboxEvent, NodeManagerError> {
    let (kind, entity_id) = event_identity(event);
    let mut digest = Sha256::new();
    for value in [
        "li_node_outbox_v1",
        idempotency_key,
        kind,
        entity_id.as_str(),
    ] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    let event_id = Sha256Digest::parse(&format!("{:x}", digest.finalize()))?;
    NodeOutboxEvent::new(
        event_id,
        TechnicalName::parse(kind)?,
        entity_id,
        occurred_at,
        NodeOutboxState::Pending,
        None,
    )
}

// Projects one outbox event into private persistence.
pub(crate) fn outbox_record(event: &NodeOutboxEvent) -> NodeOutboxDatabaseRecord {
    NodeOutboxDatabaseRecord {
        event_id: event.event_id().as_str().to_string(),
        kind: event.kind().as_str().to_string(),
        entity_id: event.entity_id().to_string(),
        occurred_at_unix_milliseconds: event.occurred_at().value(),
        state: outbox_state_name(event.state()).to_string(),
        acknowledged_at_unix_milliseconds: event.acknowledged_at().map(UnixMilliseconds::value),
    }
}

// Reconstructs one validated outbox event from private persistence.
pub(crate) fn outbox_from_record(
    record: NodeOutboxDatabaseRecord,
) -> Result<NodeOutboxEvent, NodeManagerError> {
    NodeOutboxEvent::new(
        Sha256Digest::parse(&record.event_id)?,
        TechnicalName::parse(&record.kind)?,
        record.entity_id,
        UnixMilliseconds::new(record.occurred_at_unix_milliseconds),
        outbox_state(&record.state)?,
        record
            .acknowledged_at_unix_milliseconds
            .map(UnixMilliseconds::new),
    )
}

// Returns the stable event kind and changed entity identity.
fn event_identity(event: &NodeManagerEvent) -> (&'static str, String) {
    match event {
        NodeManagerEvent::NodeInitialized { node_id } => {
            ("node_initialized", node_id.as_str().to_string())
        }
        NodeManagerEvent::NodeEnrolled { node_id } => {
            ("node_enrolled", node_id.as_str().to_string())
        }
        NodeManagerEvent::NodeActivated { node_id } => {
            ("node_activated", node_id.as_str().to_string())
        }
        NodeManagerEvent::NodePaused { node_id } => ("node_paused", node_id.as_str().to_string()),
        NodeManagerEvent::NodeMarkedOffline { node_id } => {
            ("node_marked_offline", node_id.as_str().to_string())
        }
        NodeManagerEvent::NodeRemoved { node_id } => ("node_removed", node_id.as_str().to_string()),
        NodeManagerEvent::LocalRoleChanged { node_id, role } => {
            (local_role_event_kind(*role), node_id.as_str().to_string())
        }
        NodeManagerEvent::HardwareRecorded { observation_id } => {
            ("hardware_recorded", observation_id.as_str().to_string())
        }
        NodeManagerEvent::ModelServiceCreated { service_id } => {
            ("model_service_created", service_id.as_str().to_string())
        }
        NodeManagerEvent::ModelServiceUpdated { service_id } => {
            ("model_service_updated", service_id.as_str().to_string())
        }
        NodeManagerEvent::ModelServiceRemoved { service_id } => {
            ("model_service_removed", service_id.as_str().to_string())
        }
        NodeManagerEvent::OperationBegan { operation_id } => {
            ("operation_began", operation_id.as_str().to_string())
        }
        NodeManagerEvent::OperationStarted { operation_id } => {
            ("operation_started", operation_id.as_str().to_string())
        }
        NodeManagerEvent::OperationSucceeded { operation_id } => {
            ("operation_succeeded", operation_id.as_str().to_string())
        }
        NodeManagerEvent::OperationFailed { operation_id } => {
            ("operation_failed", operation_id.as_str().to_string())
        }
        NodeManagerEvent::OperationCancelled { operation_id } => {
            ("operation_cancelled", operation_id.as_str().to_string())
        }
    }
}

// Returns the stable event kind for one completed local authority change.
fn local_role_event_kind(role: NodeRole) -> &'static str {
    match role {
        NodeRole::Main => "local_became_main",
        NodeRole::Child => "local_became_child",
    }
}

// Returns the private persistence name for one outbox state.
fn outbox_state_name(state: NodeOutboxState) -> &'static str {
    match state {
        NodeOutboxState::Pending => "pending",
        NodeOutboxState::Acknowledged => "acknowledged",
    }
}

// Parses one private outbox-state persistence value.
fn outbox_state(value: &str) -> Result<NodeOutboxState, NodeManagerError> {
    match value {
        "pending" => Ok(NodeOutboxState::Pending),
        "acknowledged" => Ok(NodeOutboxState::Acknowledged),
        _ => Err(NodeManagerError::CorruptState {
            reason: "outbox state is invalid",
        }),
    }
}

// Returns whether one event kind belongs to the closed NodeManager outbox union.
fn is_outbox_kind(value: &str) -> bool {
    matches!(
        value,
        "node_initialized"
            | "node_enrolled"
            | "node_activated"
            | "node_paused"
            | "node_marked_offline"
            | "node_removed"
            | "local_became_main"
            | "local_became_child"
            | "hardware_recorded"
            | "model_service_created"
            | "model_service_updated"
            | "model_service_removed"
            | "operation_began"
            | "operation_started"
            | "operation_succeeded"
            | "operation_failed"
            | "operation_cancelled"
    )
}

// Returns whether one value is exact lowercase hexadecimal text.
fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
