// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::sync::Arc;

use li_core_interface::{
    DisplayName, EntityTimestamps, InstallationId, MachineId, Node, NodeAddress, NodeId,
    NodeIdentity, NodeRole, NodeState, Sha256Digest, UnixMilliseconds,
};
use li_database::{
    DatabaseCollection, DatabaseCommit, DatabaseCommitDisposition, DatabaseError, DatabaseManager,
    DatabaseQuery, DatabaseRecord, DatabaseResult, DatabaseRevision, DatabaseStoredRecord,
    DatabaseTransaction,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::li_node_event::NodeManagerEvent;
use crate::li_node_outbox::{
    outbox_from_record, outbox_record, pending_outbox_event, NodeOutboxDatabaseRecord,
    NodeOutboxState,
};
use crate::li_node_record::{
    local_node_from_record, local_node_record, local_node_record_id, node_from_record, node_record,
    LocalNodeDatabaseRecord, NodeDatabaseRecord,
};

pub const NODE_SETUP_IDENTITY_SCHEMA_NAME: &str = "li_node_setup_identity";
pub const NODE_SETUP_IDENTITY_SCHEMA_VERSION: u32 = 1;

const SETUP_IDENTITY_RECORD_ID: &str = "li_core_setup_identity";
const MAXIMUM_IDEMPOTENCY_KEY_BYTES: usize = 255;
const MAXIMUM_SETUP_ATTEMPTS: u32 = 64;

// Carries every explicit public value needed to create or verify the local Node identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeSetupIdentityInput {
    request_id: Sha256Digest,
    machine_id: MachineId,
    installation_id: InstallationId,
    display_name: DisplayName,
    role: NodeRole,
    control_address: NodeAddress,
    observed_at: UnixMilliseconds,
}

impl NodeSetupIdentityInput {
    // Creates one deterministic setup input without reading native state or time implicitly.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        request_id: Sha256Digest,
        machine_id: MachineId,
        installation_id: InstallationId,
        display_name: DisplayName,
        role: NodeRole,
        control_address: NodeAddress,
        observed_at: UnixMilliseconds,
    ) -> Self {
        Self {
            request_id,
            machine_id,
            installation_id,
            display_name,
            role,
            control_address,
            observed_at,
        }
    }

    // Returns the caller-owned setup idempotency identity.
    pub const fn request_id(&self) -> &Sha256Digest {
        &self.request_id
    }
}

// Returns the exact durable public closure needed by Core setup and rollback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeSetupIdentity {
    receipt_identity: Sha256Digest,
    node: Node,
}

impl NodeSetupIdentity {
    // Returns the setup ownership or verified pre-existing receipt.
    pub const fn receipt_identity(&self) -> &Sha256Digest {
        &self.receipt_identity
    }

    // Returns the exact committed local Node snapshot.
    pub const fn node(&self) -> &Node {
        &self.node
    }
}

// Describes one stable local identity preparation or rollback failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeSetupIdentityError {
    Conflict,
    ReceiptMismatch,
    Corrupt,
    Unavailable,
    RecoveryRequired,
}

impl fmt::Display for NodeSetupIdentityError {
    // Presents stable identity language without database paths or persisted values.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conflict => formatter.write_str("local Node identity conflicts with setup input"),
            Self::ReceiptMismatch => {
                formatter.write_str("local Node rollback receipt is not authoritative")
            }
            Self::Corrupt => formatter.write_str("local Node identity state is corrupt"),
            Self::Unavailable => formatter.write_str("local Node identity state is unavailable"),
            Self::RecoveryRequired => formatter.write_str("local Node identity requires recovery"),
        }
    }
}

impl Error for NodeSetupIdentityError {}

// Owns the exact atomic DatabaseManager boundary for initial local Node setup.
pub struct DatabaseNodeSetupIdentityStore {
    database: Arc<DatabaseManager>,
}

impl DatabaseNodeSetupIdentityStore {
    // Creates one store over the shared process DatabaseManager authority.
    pub const fn new(database: Arc<DatabaseManager>) -> Self {
        Self { database }
    }

    // Creates all four setup-owned records atomically or exactly replays durable state.
    pub fn prepare(
        &self,
        input: NodeSetupIdentityInput,
    ) -> Result<NodeSetupIdentity, NodeSetupIdentityError> {
        if let Some(marker) =
            optional_record::<NodeSetupIdentityRecord>(&self.database, SETUP_IDENTITY_RECORD_ID)?
        {
            return prepared_setup_identity(&self.database, marker, &input);
        }
        let existing = existing_local_identity(&self.database);
        if let Some(marker) =
            optional_record::<NodeSetupIdentityRecord>(&self.database, SETUP_IDENTITY_RECORD_ID)?
        {
            return prepared_setup_identity(&self.database, marker, &input);
        }
        if let Some(existing) = existing? {
            if setup_owned_identity_without_marker(&existing, &input)? {
                return Err(NodeSetupIdentityError::RecoveryRequired);
            }
            return observed_identity(existing, &input);
        }
        for attempt in 1..=MAXIMUM_SETUP_ATTEMPTS {
            let prepared = new_setup_identity(&input, attempt)?;
            match create_setup_identity(&self.database, &input, attempt, &prepared) {
                Ok(disposition) => {
                    if let Some(marker) = optional_record::<NodeSetupIdentityRecord>(
                        &self.database,
                        SETUP_IDENTITY_RECORD_ID,
                    )? {
                        return prepared_setup_identity(&self.database, marker, &input);
                    }
                    if disposition == DatabaseCommitDisposition::Applied {
                        return Err(NodeSetupIdentityError::RecoveryRequired);
                    }
                }
                Err(NodeSetupIdentityError::Conflict) => {
                    let marker = optional_record::<NodeSetupIdentityRecord>(
                        &self.database,
                        SETUP_IDENTITY_RECORD_ID,
                    )?
                    .ok_or(NodeSetupIdentityError::RecoveryRequired)?;
                    return prepared_setup_identity(&self.database, marker, &input);
                }
                Err(error) => return Err(error),
            }
        }
        Err(NodeSetupIdentityError::RecoveryRequired)
    }

    // Deletes only the exact unchanged four-record closure owned by one setup receipt.
    pub fn rollback(&self, receipt_identity: &Sha256Digest) -> Result<(), NodeSetupIdentityError> {
        let Some(marker) =
            optional_record::<NodeSetupIdentityRecord>(&self.database, SETUP_IDENTITY_RECORD_ID)?
        else {
            return self.replay_or_verify_non_owned_rollback(receipt_identity);
        };
        let closure = setup_closure(&self.database, &marker)?;
        if &closure.receipt_identity != receipt_identity {
            return Err(NodeSetupIdentityError::ReceiptMismatch);
        }
        if marker.revision != 1
            || closure.local_revision != 1
            || closure.node_revision != 1
            || closure.outbox_revision != 1
        {
            return Err(NodeSetupIdentityError::RecoveryRequired);
        }
        delete_setup_identity(&self.database, receipt_identity, &closure)
    }

    // Replays one completed deletion or proves an exact pre-existing identity is non-owned.
    fn replay_or_verify_non_owned_rollback(
        &self,
        receipt_identity: &Sha256Digest,
    ) -> Result<(), NodeSetupIdentityError> {
        match replay_setup_identity_deletion(&self.database, receipt_identity) {
            Ok(DatabaseCommitDisposition::Replayed) => return Ok(()),
            Ok(DatabaseCommitDisposition::Applied) => {
                return Err(NodeSetupIdentityError::RecoveryRequired)
            }
            Err(NodeSetupIdentityError::Conflict) => {}
            Err(error) => return Err(error),
        }
        let Some(existing) = existing_local_identity(&self.database)? else {
            return Err(NodeSetupIdentityError::ReceiptMismatch);
        };
        if existing.identity().node_id() == &node_id_from_receipt(receipt_identity)? {
            return Err(NodeSetupIdentityError::RecoveryRequired);
        }
        if &observed_receipt(&existing)? == receipt_identity {
            Ok(())
        } else {
            Err(NodeSetupIdentityError::ReceiptMismatch)
        }
    }
}

// Projects the private nested persistence schema identity.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NodeSetupIdentitySchema {
    name: String,
    version: u32,
}

// Persists public closure ownership without any secret bytes.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NodeSetupIdentityRecord {
    record_id: String,
    schema: NodeSetupIdentitySchema,
    request_id: String,
    attempt: u32,
    receipt_identity: String,
    node_id: String,
    machine_id: String,
    installation_id: String,
    display_name: String,
    role: String,
    control_address: String,
    observed_at_unix_milliseconds: u64,
    outbox_event_id: String,
}

impl DatabaseRecord for NodeSetupIdentityRecord {
    const COLLECTION: DatabaseCollection = DatabaseCollection::Configuration;

    // Returns the fixed singleton setup-ownership record identity.
    fn identifier(&self) -> &str {
        &self.record_id
    }
}

// Holds one completely validated setup-owned closure and each rollback revision.
struct VersionedSetupClosure {
    receipt_identity: Sha256Digest,
    node: Node,
    outbox_event_id: Sha256Digest,
    local_revision: u64,
    node_revision: u64,
    outbox_revision: u64,
}

// Creates one deterministic setup-owned public closure from explicit input.
fn new_setup_identity(
    input: &NodeSetupIdentityInput,
    attempt: u32,
) -> Result<NodeSetupIdentity, NodeSetupIdentityError> {
    let receipt_identity = setup_receipt(input, attempt)?;
    let node_id = node_id_from_receipt(&receipt_identity)?;
    let node = Node::new(
        NodeIdentity::new(
            node_id,
            input.machine_id.clone(),
            input.installation_id.clone(),
        ),
        input.display_name.clone(),
        input.role,
        NodeState::Active,
        input.control_address.clone(),
        None,
        EntityTimestamps::new(input.observed_at, input.observed_at)
            .map_err(|_| NodeSetupIdentityError::Corrupt)?,
    );
    Ok(NodeSetupIdentity {
        receipt_identity,
        node,
    })
}

// Creates the setup marker, local identity, active Node, and initialization outbox atomically.
fn create_setup_identity(
    database: &DatabaseManager,
    input: &NodeSetupIdentityInput,
    attempt: u32,
    prepared: &NodeSetupIdentity,
) -> Result<DatabaseCommitDisposition, NodeSetupIdentityError> {
    let event = NodeManagerEvent::NodeInitialized {
        node_id: prepared.node.identity().node_id().clone(),
    };
    let outbox = pending_outbox_event(
        prepared.receipt_identity.as_str(),
        &event,
        input.observed_at,
    )
    .map_err(|_| NodeSetupIdentityError::Corrupt)?;
    let marker = marker_record(input, attempt, prepared, outbox.event_id());
    let transaction = DatabaseTransaction::new(prepare_key(prepared.receipt_identity())?)
        .and_then(|value| value.save(marker, DatabaseRevision::Missing))
        .and_then(|value| {
            value.save(
                local_node_record(prepared.node.identity()),
                DatabaseRevision::Missing,
            )
        })
        .and_then(|value| value.save(node_record(&prepared.node), DatabaseRevision::Missing))
        .and_then(|value| value.save(outbox_record(&outbox), DatabaseRevision::Missing))
        .map_err(database_contract_error)?;
    let result = database
        .write_transaction(transaction)
        .map_err(database_write_error)?;
    validate_creation_commits(
        result.commit().commits(),
        prepared.node.identity().node_id(),
        outbox.event_id(),
    )?;
    Ok(result.disposition())
}

// Reconstructs and validates one setup-owned closure after restart or concurrent creation.
fn prepared_setup_identity(
    database: &DatabaseManager,
    marker: DatabaseStoredRecord<NodeSetupIdentityRecord>,
    input: &NodeSetupIdentityInput,
) -> Result<NodeSetupIdentity, NodeSetupIdentityError> {
    let closure = setup_closure(database, &marker)?;
    if marker_request(&marker.value)? != *input.request_id()
        || closure.node.identity().machine_id() != &input.machine_id
        || closure.node.identity().installation_id() != &input.installation_id
        || closure.node.display_name() != &input.display_name
        || closure.node.role() != input.role
        || closure.node.control_address() != &input.control_address
    {
        return Err(NodeSetupIdentityError::Conflict);
    }
    Ok(NodeSetupIdentity {
        receipt_identity: closure.receipt_identity,
        node: closure.node,
    })
}

// Validates all four marker-owned records and reconstructs their public closure.
fn setup_closure(
    database: &DatabaseManager,
    marker: &DatabaseStoredRecord<NodeSetupIdentityRecord>,
) -> Result<VersionedSetupClosure, NodeSetupIdentityError> {
    validate_marker(&marker.value)?;
    let receipt_identity = digest(&marker.value.receipt_identity)?;
    let node_id =
        NodeId::parse(&marker.value.node_id).map_err(|_| NodeSetupIdentityError::Corrupt)?;
    if node_id_from_receipt(&receipt_identity)? != node_id {
        return Err(NodeSetupIdentityError::Corrupt);
    }
    let local = required_record::<LocalNodeDatabaseRecord>(database, local_node_record_id())?;
    let local_identity =
        local_node_from_record(local.value).map_err(|_| NodeSetupIdentityError::Corrupt)?;
    let stored_node = required_record::<NodeDatabaseRecord>(database, node_id.as_str())?;
    let node = node_from_record(stored_node.value).map_err(|_| NodeSetupIdentityError::Corrupt)?;
    let outbox_event_id = digest(&marker.value.outbox_event_id)?;
    let stored_outbox =
        required_record::<NodeOutboxDatabaseRecord>(database, outbox_event_id.as_str())?;
    let outbox =
        outbox_from_record(stored_outbox.value).map_err(|_| NodeSetupIdentityError::Corrupt)?;
    if marker.revision != 1
        || local.revision != 1
        || stored_node.revision != 1
        || stored_outbox.revision != 1
    {
        return Err(NodeSetupIdentityError::RecoveryRequired);
    }
    if local_identity != *node.identity()
        || node.identity().node_id() != &node_id
        || node.identity().machine_id().as_str() != marker.value.machine_id
        || node.identity().installation_id().as_str() != marker.value.installation_id
        || node.display_name().as_str() != marker.value.display_name
        || role_name(node.role()) != marker.value.role
        || node.control_address().as_str() != marker.value.control_address
        || node.state() != NodeState::Active
        || node.latest_hardware_observation_id().is_some()
        || node.timestamps().created_at().value() != marker.value.observed_at_unix_milliseconds
        || node.timestamps().updated_at().value() != marker.value.observed_at_unix_milliseconds
        || outbox.event_id() != &outbox_event_id
        || outbox.entity_id() != node_id.as_str()
        || outbox.kind().as_str() != "node_initialized"
        || outbox.occurred_at().value() != marker.value.observed_at_unix_milliseconds
        || outbox.state() != NodeOutboxState::Pending
        || outbox.acknowledged_at().is_some()
        || setup_receipt_from_marker(&marker.value)? != receipt_identity
    {
        return Err(NodeSetupIdentityError::Corrupt);
    }
    Ok(VersionedSetupClosure {
        receipt_identity,
        node,
        outbox_event_id,
        local_revision: local.revision,
        node_revision: stored_node.revision,
        outbox_revision: stored_outbox.revision,
    })
}

// Returns one exact pre-existing local identity only when its two records are complete.
fn existing_local_identity(
    database: &DatabaseManager,
) -> Result<Option<Node>, NodeSetupIdentityError> {
    let local = optional_record::<LocalNodeDatabaseRecord>(database, local_node_record_id())?;
    let Some(local) = local else {
        let nodes = database
            .read(DatabaseQuery::<NodeDatabaseRecord>::all())
            .map_err(database_read_error)?;
        return match nodes {
            DatabaseResult::Records(values) if values.is_empty() => Ok(None),
            DatabaseResult::Records(_) | DatabaseResult::Record(_) => {
                Err(NodeSetupIdentityError::Corrupt)
            }
        };
    };
    let identity =
        local_node_from_record(local.value).map_err(|_| NodeSetupIdentityError::Corrupt)?;
    let node = required_record::<NodeDatabaseRecord>(database, identity.node_id().as_str())?;
    let node = node_from_record(node.value).map_err(|_| NodeSetupIdentityError::Corrupt)?;
    if node.identity() != &identity {
        return Err(NodeSetupIdentityError::Corrupt);
    }
    Ok(Some(node))
}

// Returns one exact pre-existing replay without claiming rollback ownership.
fn observed_identity(
    existing: Node,
    input: &NodeSetupIdentityInput,
) -> Result<NodeSetupIdentity, NodeSetupIdentityError> {
    if existing.identity().machine_id() != &input.machine_id
        || existing.identity().installation_id() != &input.installation_id
        || existing.display_name() != &input.display_name
        || existing.role() != input.role
        || existing.control_address() != &input.control_address
        || existing.state() != NodeState::Active
    {
        return Err(NodeSetupIdentityError::Conflict);
    }
    Ok(NodeSetupIdentity {
        receipt_identity: observed_receipt(&existing)?,
        node: existing,
    })
}

// Recognizes a setup-derived Node whose private ownership marker was lost or removed alone.
fn setup_owned_identity_without_marker(
    existing: &Node,
    input: &NodeSetupIdentityInput,
) -> Result<bool, NodeSetupIdentityError> {
    if existing.identity().machine_id() != &input.machine_id
        || existing.identity().installation_id() != &input.installation_id
        || existing.display_name() != &input.display_name
        || existing.role() != input.role
        || existing.control_address() != &input.control_address
        || existing.state() != NodeState::Active
        || existing.latest_hardware_observation_id().is_some()
        || existing.timestamps().created_at() != existing.timestamps().updated_at()
    {
        return Ok(false);
    }
    let original_input = NodeSetupIdentityInput::new(
        input.request_id.clone(),
        input.machine_id.clone(),
        input.installation_id.clone(),
        input.display_name.clone(),
        input.role,
        input.control_address.clone(),
        existing.timestamps().created_at(),
    );
    for attempt in 1..=MAXIMUM_SETUP_ATTEMPTS {
        let receipt = setup_receipt(&original_input, attempt)?;
        if node_id_from_receipt(&receipt)? == *existing.identity().node_id() {
            return Ok(true);
        }
    }
    Ok(false)
}

// Atomically deletes all four unchanged setup-owned records.
fn delete_setup_identity(
    database: &DatabaseManager,
    receipt_identity: &Sha256Digest,
    closure: &VersionedSetupClosure,
) -> Result<(), NodeSetupIdentityError> {
    let transaction = deletion_transaction(receipt_identity, closure)?;
    let result = database
        .write_transaction(transaction)
        .map_err(|error| match error {
            DatabaseError::Conflict { .. } => NodeSetupIdentityError::RecoveryRequired,
            error => database_write_error(error),
        })?;
    validate_deletion_commits(
        result.commit().commits(),
        closure.node.identity().node_id(),
        &closure.outbox_event_id,
    )
}

// Reissues one deterministic deletion to distinguish exact rollback replay from absence.
fn replay_setup_identity_deletion(
    database: &DatabaseManager,
    receipt_identity: &Sha256Digest,
) -> Result<DatabaseCommitDisposition, NodeSetupIdentityError> {
    let node_id = node_id_from_receipt(receipt_identity)?;
    let event = NodeManagerEvent::NodeInitialized {
        node_id: node_id.clone(),
    };
    let outbox = pending_outbox_event(receipt_identity.as_str(), &event, UnixMilliseconds::new(0))
        .map_err(|_| NodeSetupIdentityError::Corrupt)?;
    let closure = VersionedSetupClosure {
        receipt_identity: receipt_identity.clone(),
        node: Node::new(
            NodeIdentity::new(
                node_id,
                MachineId::parse(&"0".repeat(32)).map_err(|_| NodeSetupIdentityError::Corrupt)?,
                InstallationId::parse(&"0".repeat(64))
                    .map_err(|_| NodeSetupIdentityError::Corrupt)?,
            ),
            DisplayName::parse("rollback").map_err(|_| NodeSetupIdentityError::Corrupt)?,
            NodeRole::Main,
            NodeState::Active,
            NodeAddress::parse("rollback.invalid").map_err(|_| NodeSetupIdentityError::Corrupt)?,
            None,
            EntityTimestamps::new(UnixMilliseconds::new(0), UnixMilliseconds::new(0))
                .map_err(|_| NodeSetupIdentityError::Corrupt)?,
        ),
        outbox_event_id: outbox.event_id().clone(),
        local_revision: 1,
        node_revision: 1,
        outbox_revision: 1,
    };
    let transaction = deletion_transaction(receipt_identity, &closure)?;
    database
        .write_transaction(transaction)
        .map(|result| result.disposition())
        .map_err(|error| match error {
            DatabaseError::Conflict { .. } | DatabaseError::NotFound { .. } => {
                NodeSetupIdentityError::Conflict
            }
            error => database_write_error(error),
        })
}

// Creates one exact four-record deletion transaction from a receipt-derived closure.
fn deletion_transaction(
    receipt_identity: &Sha256Digest,
    closure: &VersionedSetupClosure,
) -> Result<DatabaseTransaction, NodeSetupIdentityError> {
    DatabaseTransaction::new(rollback_key(receipt_identity)?)
        .and_then(|value| {
            value.delete::<NodeSetupIdentityRecord>(
                SETUP_IDENTITY_RECORD_ID,
                DatabaseRevision::Exact(1),
            )
        })
        .and_then(|value| {
            value.delete::<LocalNodeDatabaseRecord>(
                local_node_record_id(),
                DatabaseRevision::Exact(closure.local_revision),
            )
        })
        .and_then(|value| {
            value.delete::<NodeDatabaseRecord>(
                closure.node.identity().node_id().as_str(),
                DatabaseRevision::Exact(closure.node_revision),
            )
        })
        .and_then(|value| {
            value.delete::<NodeOutboxDatabaseRecord>(
                closure.outbox_event_id.as_str(),
                DatabaseRevision::Exact(closure.outbox_revision),
            )
        })
        .map_err(database_contract_error)
}

// Creates the closed marker projection for one exact four-record setup closure.
fn marker_record(
    input: &NodeSetupIdentityInput,
    attempt: u32,
    prepared: &NodeSetupIdentity,
    outbox_event_id: &Sha256Digest,
) -> NodeSetupIdentityRecord {
    NodeSetupIdentityRecord {
        record_id: SETUP_IDENTITY_RECORD_ID.to_string(),
        schema: NodeSetupIdentitySchema {
            name: NODE_SETUP_IDENTITY_SCHEMA_NAME.to_string(),
            version: NODE_SETUP_IDENTITY_SCHEMA_VERSION,
        },
        request_id: input.request_id.as_str().to_string(),
        attempt,
        receipt_identity: prepared.receipt_identity.as_str().to_string(),
        node_id: prepared.node.identity().node_id().as_str().to_string(),
        machine_id: prepared.node.identity().machine_id().as_str().to_string(),
        installation_id: prepared
            .node
            .identity()
            .installation_id()
            .as_str()
            .to_string(),
        display_name: prepared.node.display_name().as_str().to_string(),
        role: role_name(prepared.node.role()).to_string(),
        control_address: prepared.node.control_address().as_str().to_string(),
        observed_at_unix_milliseconds: input.observed_at.value(),
        outbox_event_id: outbox_event_id.as_str().to_string(),
    }
}

// Requires one marker to retain exact schema and bounded typed fields.
fn validate_marker(marker: &NodeSetupIdentityRecord) -> Result<(), NodeSetupIdentityError> {
    if marker.record_id != SETUP_IDENTITY_RECORD_ID
        || marker.schema.name != NODE_SETUP_IDENTITY_SCHEMA_NAME
        || marker.schema.version != NODE_SETUP_IDENTITY_SCHEMA_VERSION
        || marker.attempt == 0
        || marker.attempt > MAXIMUM_SETUP_ATTEMPTS
        || marker_request(marker).is_err()
        || digest(&marker.receipt_identity).is_err()
        || NodeId::parse(&marker.node_id).is_err()
        || MachineId::parse(&marker.machine_id).is_err()
        || InstallationId::parse(&marker.installation_id).is_err()
        || DisplayName::parse(&marker.display_name).is_err()
        || parse_role(&marker.role).is_err()
        || NodeAddress::parse(&marker.control_address).is_err()
        || digest(&marker.outbox_event_id).is_err()
    {
        return Err(NodeSetupIdentityError::Corrupt);
    }
    Ok(())
}

// Derives the setup-owned receipt from every mutation-relevant explicit input.
fn setup_receipt(
    input: &NodeSetupIdentityInput,
    attempt: u32,
) -> Result<Sha256Digest, NodeSetupIdentityError> {
    let observed_at = input.observed_at.value().to_string();
    let attempt = attempt.to_string();
    digest_fields(&[
        "li_node_setup_owned_identity_v1",
        input.request_id.as_str(),
        input.machine_id.as_str(),
        input.installation_id.as_str(),
        input.display_name.as_str(),
        role_name(input.role),
        input.control_address.as_str(),
        &observed_at,
        &attempt,
    ])
}

// Recomputes one setup-owned receipt from its strict marker projection.
fn setup_receipt_from_marker(
    marker: &NodeSetupIdentityRecord,
) -> Result<Sha256Digest, NodeSetupIdentityError> {
    let observed_at = marker.observed_at_unix_milliseconds.to_string();
    let attempt = marker.attempt.to_string();
    digest_fields(&[
        "li_node_setup_owned_identity_v1",
        &marker.request_id,
        &marker.machine_id,
        &marker.installation_id,
        &marker.display_name,
        &marker.role,
        &marker.control_address,
        &observed_at,
        &attempt,
    ])
}

// Derives a non-owning receipt from one exact pre-existing public Node closure.
fn observed_receipt(node: &Node) -> Result<Sha256Digest, NodeSetupIdentityError> {
    digest_fields(&[
        "li_node_setup_observed_identity_v1",
        node.identity().node_id().as_str(),
        node.identity().machine_id().as_str(),
        node.identity().installation_id().as_str(),
        node.display_name().as_str(),
        role_name(node.role()),
        node.control_address().as_str(),
    ])
}

// Derives the stable logical Node identity recoverable from its rollback receipt.
fn node_id_from_receipt(receipt_identity: &Sha256Digest) -> Result<NodeId, NodeSetupIdentityError> {
    let value = digest_fields(&["li_node_setup_node_id_v1", receipt_identity.as_str()])?;
    NodeId::parse(&value.as_str()[..32]).map_err(|_| NodeSetupIdentityError::Corrupt)
}

// Hashes one ordered typed field list using explicit length framing.
fn digest_fields(fields: &[&str]) -> Result<Sha256Digest, NodeSetupIdentityError> {
    let mut digest = Sha256::new();
    for field in fields {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field.as_bytes());
    }
    Sha256Digest::parse(&format!("{:x}", digest.finalize()))
        .map_err(|_| NodeSetupIdentityError::Corrupt)
}

// Parses one canonical SHA-256 persistence identity.
fn digest(value: &str) -> Result<Sha256Digest, NodeSetupIdentityError> {
    Sha256Digest::parse(value).map_err(|_| NodeSetupIdentityError::Corrupt)
}

// Parses the exact request identity stored by one marker.
fn marker_request(
    marker: &NodeSetupIdentityRecord,
) -> Result<Sha256Digest, NodeSetupIdentityError> {
    digest(&marker.request_id)
}

// Returns one exact bounded preparation transaction key.
fn prepare_key(receipt_identity: &Sha256Digest) -> Result<String, NodeSetupIdentityError> {
    bounded_key(format!(
        "li_core_setup_identity_prepare:{}",
        receipt_identity.as_str()
    ))
}

// Returns one exact bounded rollback transaction key.
fn rollback_key(receipt_identity: &Sha256Digest) -> Result<String, NodeSetupIdentityError> {
    bounded_key(format!(
        "li_core_setup_identity_rollback:{}",
        receipt_identity.as_str()
    ))
}

// Requires one manager-owned idempotency key to fit DatabaseManager's public boundary.
fn bounded_key(value: String) -> Result<String, NodeSetupIdentityError> {
    if value.is_empty() || value.len() > MAXIMUM_IDEMPOTENCY_KEY_BYTES {
        return Err(NodeSetupIdentityError::Corrupt);
    }
    Ok(value)
}

// Reads one optional typed record while preserving corrupt and unavailable distinctions.
fn optional_record<Record: DatabaseRecord>(
    database: &DatabaseManager,
    identifier: &str,
) -> Result<Option<DatabaseStoredRecord<Record>>, NodeSetupIdentityError> {
    match database.read(DatabaseQuery::<Record>::record(identifier)) {
        Ok(DatabaseResult::Record(record)) => Ok(Some(record)),
        Ok(DatabaseResult::Records(_)) => Err(NodeSetupIdentityError::Corrupt),
        Err(DatabaseError::NotFound { .. }) => Ok(None),
        Err(error) => Err(database_read_error(error)),
    }
}

// Reads one required typed record without converting absence into a new record.
fn required_record<Record: DatabaseRecord>(
    database: &DatabaseManager,
    identifier: &str,
) -> Result<DatabaseStoredRecord<Record>, NodeSetupIdentityError> {
    optional_record(database, identifier)?.ok_or(NodeSetupIdentityError::RecoveryRequired)
}

// Validates the exact ordered commits returned by one four-record creation.
fn validate_creation_commits(
    commits: &[DatabaseCommit],
    node_id: &NodeId,
    outbox_event_id: &Sha256Digest,
) -> Result<(), NodeSetupIdentityError> {
    if commits.len() != 4
        || commits[0].collection != DatabaseCollection::Configuration
        || commits[0].identifier != SETUP_IDENTITY_RECORD_ID
        || commits[1].collection != DatabaseCollection::Configuration
        || commits[1].identifier != local_node_record_id()
        || commits[2].collection != DatabaseCollection::Nodes
        || commits[2].identifier != node_id.as_str()
        || commits[3].collection != DatabaseCollection::Outbox
        || commits[3].identifier != outbox_event_id.as_str()
        || commits.iter().any(|commit| commit.revision != 1)
    {
        return Err(NodeSetupIdentityError::RecoveryRequired);
    }
    Ok(())
}

// Validates the exact ordered commits returned by one four-record deletion.
fn validate_deletion_commits(
    commits: &[DatabaseCommit],
    node_id: &NodeId,
    outbox_event_id: &Sha256Digest,
) -> Result<(), NodeSetupIdentityError> {
    if commits.len() != 4
        || commits[0].collection != DatabaseCollection::Configuration
        || commits[0].identifier != SETUP_IDENTITY_RECORD_ID
        || commits[1].collection != DatabaseCollection::Configuration
        || commits[1].identifier != local_node_record_id()
        || commits[2].collection != DatabaseCollection::Nodes
        || commits[2].identifier != node_id.as_str()
        || commits[3].collection != DatabaseCollection::Outbox
        || commits[3].identifier != outbox_event_id.as_str()
        || commits.iter().any(|commit| commit.revision != 2)
    {
        return Err(NodeSetupIdentityError::RecoveryRequired);
    }
    Ok(())
}

// Maps one read failure to stable corruption or availability language.
fn database_read_error(error: DatabaseError) -> NodeSetupIdentityError {
    match error {
        DatabaseError::Corrupt { .. }
        | DatabaseError::InvalidInput { .. }
        | DatabaseError::IdempotencyConflict { .. }
        | DatabaseError::Conflict { .. } => NodeSetupIdentityError::Corrupt,
        DatabaseError::Unavailable { .. } | DatabaseError::Closed => {
            NodeSetupIdentityError::Unavailable
        }
        DatabaseError::NotFound { .. } => NodeSetupIdentityError::Corrupt,
    }
}

// Maps one contract construction failure before database mutation.
fn database_contract_error(_error: DatabaseError) -> NodeSetupIdentityError {
    NodeSetupIdentityError::Corrupt
}

// Maps one transaction failure while preserving a safe concurrent-create conflict.
fn database_write_error(error: DatabaseError) -> NodeSetupIdentityError {
    match error {
        DatabaseError::Conflict { .. } => NodeSetupIdentityError::Conflict,
        DatabaseError::Unavailable { .. } | DatabaseError::Closed => {
            NodeSetupIdentityError::RecoveryRequired
        }
        DatabaseError::Corrupt { .. }
        | DatabaseError::InvalidInput { .. }
        | DatabaseError::IdempotencyConflict { .. }
        | DatabaseError::NotFound { .. } => NodeSetupIdentityError::RecoveryRequired,
    }
}

// Parses one stable main or child role.
fn parse_role(value: &str) -> Result<NodeRole, NodeSetupIdentityError> {
    match value {
        "main" => Ok(NodeRole::Main),
        "child" => Ok(NodeRole::Child),
        _ => Err(NodeSetupIdentityError::Corrupt),
    }
}

// Returns the stable private persistence spelling for one role.
const fn role_name(role: NodeRole) -> &'static str {
    match role {
        NodeRole::Main => "main",
        NodeRole::Child => "child",
    }
}
