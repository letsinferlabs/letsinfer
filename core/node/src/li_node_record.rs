// SPDX-License-Identifier: AGPL-3.0-only

use li_core_interface::{
    DisplayName, EntityTimestamps, FailureDescription, HardwareObservationId, InstallationId,
    MachineId, ModelServiceId, Node, NodeAddress, NodeId, NodeIdentity, NodeRole, NodeState,
    Operation, OperationId, OperationKind, OperationState, OperationTarget, PlacementGroupId,
    PlacementId, RuntimeInstallationId, TechnicalName, UnixMilliseconds,
};
use li_database::{DatabaseCollection, DatabaseRecord};
use serde::{Deserialize, Serialize};

use crate::NodeManagerError;

const LOCAL_NODE_RECORD_ID: &str = "local_node_identity";

// Stores the one local node identity independently of the enrolled-node collection.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct LocalNodeDatabaseRecord {
    record_id: String,
    node_id: String,
    machine_id: String,
    installation_id: String,
}

impl DatabaseRecord for LocalNodeDatabaseRecord {
    const COLLECTION: DatabaseCollection = DatabaseCollection::Configuration;

    // Returns the singleton local-node configuration identity.
    fn identifier(&self) -> &str {
        &self.record_id
    }
}

// Stores the private persistence projection of one node snapshot.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct NodeDatabaseRecord {
    node_id: String,
    machine_id: String,
    installation_id: String,
    display_name: String,
    role: String,
    state: String,
    control_address: String,
    latest_hardware_observation_id: Option<String>,
    created_at_unix_milliseconds: u64,
    updated_at_unix_milliseconds: u64,
}

impl DatabaseRecord for NodeDatabaseRecord {
    const COLLECTION: DatabaseCollection = DatabaseCollection::Nodes;

    // Returns the stable node identity used by private persistence.
    fn identifier(&self) -> &str {
        &self.node_id
    }
}

// Stores the private persistence projection of one operation snapshot.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct OperationDatabaseRecord {
    operation_id: String,
    kind: String,
    target_kind: String,
    target_id: String,
    state: String,
    failure_code: Option<String>,
    failure_message: Option<String>,
    completed_at_unix_milliseconds: Option<u64>,
    created_at_unix_milliseconds: u64,
    updated_at_unix_milliseconds: u64,
}

impl DatabaseRecord for OperationDatabaseRecord {
    const COLLECTION: DatabaseCollection = DatabaseCollection::Operations;

    // Returns the stable operation identity used by private persistence.
    fn identifier(&self) -> &str {
        &self.operation_id
    }
}

// Projects one local node identity into its singleton private record.
pub(crate) fn local_node_record(identity: &NodeIdentity) -> LocalNodeDatabaseRecord {
    LocalNodeDatabaseRecord {
        record_id: LOCAL_NODE_RECORD_ID.to_string(),
        node_id: identity.node_id().as_str().to_string(),
        machine_id: identity.machine_id().as_str().to_string(),
        installation_id: identity.installation_id().as_str().to_string(),
    }
}

// Reconstructs the validated local node identity from private persistence.
pub(crate) fn local_node_from_record(
    record: LocalNodeDatabaseRecord,
) -> Result<NodeIdentity, NodeManagerError> {
    if record.record_id != LOCAL_NODE_RECORD_ID {
        return Err(NodeManagerError::CorruptState {
            reason: "local node record identity is invalid",
        });
    }
    Ok(NodeIdentity::new(
        NodeId::parse(&record.node_id)?,
        MachineId::parse(&record.machine_id)?,
        InstallationId::parse(&record.installation_id)?,
    ))
}

// Returns the fixed private identity of the local-node configuration record.
pub(crate) const fn local_node_record_id() -> &'static str {
    LOCAL_NODE_RECORD_ID
}

// Projects one node snapshot into its private persistence record.
pub(crate) fn node_record(node: &Node) -> NodeDatabaseRecord {
    NodeDatabaseRecord {
        node_id: node.identity().node_id().as_str().to_string(),
        machine_id: node.identity().machine_id().as_str().to_string(),
        installation_id: node.identity().installation_id().as_str().to_string(),
        display_name: node.display_name().as_str().to_string(),
        role: node_role_name(node.role()).to_string(),
        state: node_state_name(node.state()).to_string(),
        control_address: node.control_address().as_str().to_string(),
        latest_hardware_observation_id: node
            .latest_hardware_observation_id()
            .map(|identity| identity.as_str().to_string()),
        created_at_unix_milliseconds: node.timestamps().created_at().value(),
        updated_at_unix_milliseconds: node.timestamps().updated_at().value(),
    }
}

// Reconstructs one validated node snapshot from private persistence.
pub(crate) fn node_from_record(record: NodeDatabaseRecord) -> Result<Node, NodeManagerError> {
    let latest_hardware_observation_id = record
        .latest_hardware_observation_id
        .map(|value| HardwareObservationId::parse(&value))
        .transpose()
        .map_err(NodeManagerError::from)?;
    Ok(Node::new(
        NodeIdentity::new(
            NodeId::parse(&record.node_id)?,
            MachineId::parse(&record.machine_id)?,
            InstallationId::parse(&record.installation_id)?,
        ),
        DisplayName::parse(&record.display_name)?,
        node_role(&record.role)?,
        node_state(&record.state)?,
        NodeAddress::parse(&record.control_address)?,
        latest_hardware_observation_id,
        EntityTimestamps::new(
            UnixMilliseconds::new(record.created_at_unix_milliseconds),
            UnixMilliseconds::new(record.updated_at_unix_milliseconds),
        )?,
    ))
}

// Projects one operation snapshot into its private persistence record.
pub(crate) fn operation_record(operation: &Operation) -> OperationDatabaseRecord {
    let (target_kind, target_id) = operation_target_record(operation.target());
    OperationDatabaseRecord {
        operation_id: operation.operation_id().as_str().to_string(),
        kind: operation_kind_name(operation.kind()).to_string(),
        target_kind: target_kind.to_string(),
        target_id,
        state: operation_state_name(operation.state()).to_string(),
        failure_code: operation
            .failure()
            .map(|failure| failure.code().as_str().to_string()),
        failure_message: operation
            .failure()
            .map(|failure| failure.message().to_string()),
        completed_at_unix_milliseconds: operation.completed_at().map(UnixMilliseconds::value),
        created_at_unix_milliseconds: operation.timestamps().created_at().value(),
        updated_at_unix_milliseconds: operation.timestamps().updated_at().value(),
    }
}

// Reconstructs one validated operation snapshot from private persistence.
pub(crate) fn operation_from_record(
    record: OperationDatabaseRecord,
) -> Result<Operation, NodeManagerError> {
    let failure = match (record.failure_code, record.failure_message) {
        (Some(code), Some(message)) => Some(FailureDescription::new(
            TechnicalName::parse(&code)?,
            &message,
        )?),
        (None, None) => None,
        _ => {
            return Err(NodeManagerError::CorruptState {
                reason: "operation failure record is incomplete",
            });
        }
    };
    Operation::new(
        OperationId::parse(&record.operation_id)?,
        operation_kind(&record.kind)?,
        operation_target(&record.target_kind, &record.target_id)?,
        operation_state(&record.state)?,
        failure,
        record
            .completed_at_unix_milliseconds
            .map(UnixMilliseconds::new),
        EntityTimestamps::new(
            UnixMilliseconds::new(record.created_at_unix_milliseconds),
            UnixMilliseconds::new(record.updated_at_unix_milliseconds),
        )?,
    )
    .map_err(Into::into)
}

// Returns the private persistence name for one node role.
fn node_role_name(role: NodeRole) -> &'static str {
    match role {
        NodeRole::Main => "main",
        NodeRole::Child => "child",
    }
}

// Parses one private node-role persistence value.
fn node_role(value: &str) -> Result<NodeRole, NodeManagerError> {
    match value {
        "main" => Ok(NodeRole::Main),
        "child" => Ok(NodeRole::Child),
        _ => Err(NodeManagerError::CorruptState {
            reason: "node role is invalid",
        }),
    }
}

// Returns the private persistence name for one node state.
fn node_state_name(state: NodeState) -> &'static str {
    match state {
        NodeState::Pending => "pending",
        NodeState::Active => "active",
        NodeState::Draining => "draining",
        NodeState::Offline => "offline",
        NodeState::Removed => "removed",
    }
}

// Parses one private node-state persistence value.
fn node_state(value: &str) -> Result<NodeState, NodeManagerError> {
    match value {
        "pending" => Ok(NodeState::Pending),
        "active" => Ok(NodeState::Active),
        "draining" => Ok(NodeState::Draining),
        "offline" => Ok(NodeState::Offline),
        "removed" => Ok(NodeState::Removed),
        _ => Err(NodeManagerError::CorruptState {
            reason: "node state is invalid",
        }),
    }
}

// Returns the private persistence name for one operation kind.
fn operation_kind_name(kind: OperationKind) -> &'static str {
    match kind {
        OperationKind::Install => "install",
        OperationKind::Start => "start",
        OperationKind::Stop => "stop",
        OperationKind::Restart => "restart",
        OperationKind::Recover => "recover",
        OperationKind::Remove => "remove",
        OperationKind::Update => "update",
    }
}

// Parses one private operation-kind persistence value.
fn operation_kind(value: &str) -> Result<OperationKind, NodeManagerError> {
    match value {
        "install" => Ok(OperationKind::Install),
        "start" => Ok(OperationKind::Start),
        "stop" => Ok(OperationKind::Stop),
        "restart" => Ok(OperationKind::Restart),
        "recover" => Ok(OperationKind::Recover),
        "remove" => Ok(OperationKind::Remove),
        "update" => Ok(OperationKind::Update),
        _ => Err(NodeManagerError::CorruptState {
            reason: "operation kind is invalid",
        }),
    }
}

// Returns the private persistence name for one operation state.
fn operation_state_name(state: OperationState) -> &'static str {
    match state {
        OperationState::Pending => "pending",
        OperationState::Running => "running",
        OperationState::Succeeded => "succeeded",
        OperationState::Failed => "failed",
        OperationState::Cancelled => "cancelled",
    }
}

// Parses one private operation-state persistence value.
fn operation_state(value: &str) -> Result<OperationState, NodeManagerError> {
    match value {
        "pending" => Ok(OperationState::Pending),
        "running" => Ok(OperationState::Running),
        "succeeded" => Ok(OperationState::Succeeded),
        "failed" => Ok(OperationState::Failed),
        "cancelled" => Ok(OperationState::Cancelled),
        _ => Err(NodeManagerError::CorruptState {
            reason: "operation state is invalid",
        }),
    }
}

// Projects one typed operation target into private persistence values.
fn operation_target_record(target: &OperationTarget) -> (&'static str, String) {
    match target {
        OperationTarget::Node(identity) => ("node", identity.as_str().to_string()),
        OperationTarget::RuntimeInstallation(identity) => {
            ("runtime_installation", identity.as_str().to_string())
        }
        OperationTarget::ModelService(identity) => ("model_service", identity.as_str().to_string()),
        OperationTarget::PlacementGroup(identity) => {
            ("placement_group", identity.as_str().to_string())
        }
        OperationTarget::Placement(identity) => ("placement", identity.as_str().to_string()),
    }
}

// Reconstructs one typed operation target from private persistence.
fn operation_target(kind: &str, identity: &str) -> Result<OperationTarget, NodeManagerError> {
    match kind {
        "node" => Ok(OperationTarget::Node(NodeId::parse(identity)?)),
        "runtime_installation" => Ok(OperationTarget::RuntimeInstallation(
            RuntimeInstallationId::parse(identity)?,
        )),
        "model_service" => Ok(OperationTarget::ModelService(ModelServiceId::parse(
            identity,
        )?)),
        "placement_group" => Ok(OperationTarget::PlacementGroup(PlacementGroupId::parse(
            identity,
        )?)),
        "placement" => Ok(OperationTarget::Placement(PlacementId::parse(identity)?)),
        _ => Err(NodeManagerError::CorruptState {
            reason: "operation target kind is invalid",
        }),
    }
}
