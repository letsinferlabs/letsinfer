// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;
use std::sync::Arc;

use li_core_interface::{
    BootId, CredentialId, DeviceId, EndpointAddress, EndpointHealth, EndpointOwnership,
    EndpointScheme, EntityTimestamps, FailureDescription, HardwareObservationId, InterconnectKind,
    InterconnectRequirement, ModelServiceDesiredState, ModelServiceId, NetworkInterfaceName,
    NetworkPort, NodeAddress, NodeId, OperationId, Placement, PlacementAssignment,
    PlacementEndpoint, PlacementGroup, PlacementGroupCapacity, PlacementGroupId,
    PlacementGroupState, PlacementId, PlacementResources, PlacementState, PortRange,
    ResourceIdentity, ResourceLease, ResourceLeaseId, ResourceLeaseState, RuntimeCandidateId,
    RuntimeIdentity, RuntimeInstallationId, RuntimeSource, RuntimeVersion, Sha256Digest, TargetId,
    TaskId, TechnicalName, TokenCountContract, TokenCountProtocol, UnixMilliseconds,
};
use li_database::{
    DatabaseCollection, DatabaseCommitDisposition, DatabaseError, DatabaseManager, DatabaseQuery,
    DatabaseRecord, DatabaseResult, DatabaseRevision, DatabaseTransaction,
};
use li_placement_manager::{
    PlacementError, PlacementRecord, PlacementStore, VersionedPlacementRecord,
};
use serde::{Deserialize, Serialize};

use crate::li_runtime_database::{engine_distribution, engine_record, EngineDatabaseRecord};

const RESOURCE_INDEX_IDENTIFIER: &str = "li_placement_resource_index_v1";

// Stores one bounded stable failure inside a private placement record.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct FailureDatabaseRecord {
    code: String,
    message: String,
}

// Stores one exact runtime identity shared by a placement group.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct RuntimeIdentityDatabaseRecord {
    candidate_id: String,
    version: String,
    target_id: String,
    source: String,
    engine: EngineDatabaseRecord,
    runtime_digest: String,
    manifest_digest: String,
    execution_contract_digest: String,
}

// Stores one generic interconnect requirement without engine policy.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct InterconnectDatabaseRecord {
    kind: String,
    rdma_required: bool,
    minimum_speed_mbps: u64,
    minimum_mtu: u32,
}

// Stores one placement-group serving-capacity contract.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct CapacityDatabaseRecord {
    max_connections: u32,
    max_active_requests: u32,
    max_context_tokens: u64,
    interconnect: InterconnectDatabaseRecord,
}

// Stores one exact token-count endpoint contract.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct TokenCountDatabaseRecord {
    path: String,
    protocol: String,
}

// Stores one bounded endpoint health snapshot.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct EndpointHealthDatabaseRecord {
    healthy: bool,
    memory_pressure: bool,
    temperature_millicelsius: Option<i32>,
    prefix_keys: Vec<String>,
}

// Stores one routable placement-group endpoint without credential material.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct EndpointDatabaseRecord {
    placement_id: String,
    node_id: String,
    scheme: String,
    host: String,
    port: u16,
    credential_id: String,
    ca_credential_id: Option<String>,
    token_count: Option<TokenCountDatabaseRecord>,
    max_active_requests: u32,
    max_context_tokens: u64,
    health: EndpointHealthDatabaseRecord,
}

// Stores one placement-group snapshot inside its aggregate record.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct PlacementGroupDatabaseRecord {
    service_id: String,
    runtime: RuntimeIdentityDatabaseRecord,
    placement_ids: Vec<String>,
    endpoint_placement_id: String,
    endpoint: Option<EndpointDatabaseRecord>,
    capacity: CapacityDatabaseRecord,
    desired_state: String,
    state: String,
    failure: Option<FailureDatabaseRecord>,
    created_at_unix_milliseconds: u64,
    updated_at_unix_milliseconds: u64,
}

// Stores one exact placement resource assignment.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct PlacementResourcesDatabaseRecord {
    port_base: u16,
    port_count: u16,
    device_ids: Vec<String>,
    rdma_interface: Option<String>,
}

// Stores one immutable opaque task assignment.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct PlacementAssignmentDatabaseRecord {
    node_id: String,
    runtime_installation_id: String,
    hardware_observation_id: String,
    hardware_boot_id: String,
    hardware_observed_at_unix_milliseconds: u64,
    task_id: String,
    address: String,
    resources: PlacementResourcesDatabaseRecord,
    endpoint_ownership: String,
}

// Stores one placement task snapshot inside its group aggregate.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct PlacementDatabaseEntry {
    placement_id: String,
    assignment: PlacementAssignmentDatabaseRecord,
    state: String,
    active_operation_id: Option<String>,
    failure: Option<FailureDatabaseRecord>,
    created_at_unix_milliseconds: u64,
    updated_at_unix_milliseconds: u64,
}

// Stores one closed generic resource identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum ResourceDatabaseRecord {
    Accelerator { device_id: String },
    Port { port: u16 },
    RdmaInterface { interface: String },
}

// Stores one exact resource lease inside its placement aggregate.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct ResourceLeaseDatabaseRecord {
    lease_id: String,
    placement_id: String,
    node_id: String,
    resource: ResourceDatabaseRecord,
    state: String,
    created_at_unix_milliseconds: u64,
    updated_at_unix_milliseconds: u64,
}

// Stores the complete PlacementManager aggregate as one optimistic record.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct PlacementAggregateDatabaseRecord {
    placement_group_id: String,
    group: PlacementGroupDatabaseRecord,
    placements: Vec<PlacementDatabaseEntry>,
    leases: Vec<ResourceLeaseDatabaseRecord>,
    startup_order: Vec<Vec<String>>,
    launch_plan_identities: Vec<LaunchPlanIdentityDatabaseRecord>,
}

// Stores one placement's independently durable launch-plan identity.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct LaunchPlanIdentityDatabaseRecord {
    placement_id: String,
    digest: String,
}

impl DatabaseRecord for PlacementAggregateDatabaseRecord {
    const COLLECTION: DatabaseCollection = DatabaseCollection::Placements;

    // Returns the exact placement-group identity.
    fn identifier(&self) -> &str {
        &self.placement_group_id
    }
}

// Stores one resource owner in the global optimistic allocation index.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ResourceIndexEntryDatabaseRecord {
    node_id: String,
    resource: ResourceDatabaseRecord,
    placement_group_id: String,
    placement_id: String,
    lease_id: String,
}

// Stores all active resource ownership behind one transaction conflict point.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct ResourceIndexDatabaseRecord {
    identifier: String,
    entries: Vec<ResourceIndexEntryDatabaseRecord>,
}

impl DatabaseRecord for ResourceIndexDatabaseRecord {
    const COLLECTION: DatabaseCollection = DatabaseCollection::Configuration;

    // Returns the fixed private resource-index identity.
    fn identifier(&self) -> &str {
        &self.identifier
    }
}

// Adapts PlacementManager's aggregate store to DatabaseManager transactions.
pub struct DatabasePlacementStore {
    database: Arc<DatabaseManager>,
}

impl DatabasePlacementStore {
    // Creates one adapter without transferring DatabaseManager lifecycle ownership.
    pub const fn new(database: Arc<DatabaseManager>) -> Self {
        Self { database }
    }

    // Returns every fully validated placement aggregate in stable identity order.
    pub fn records(&self) -> Result<Vec<PlacementRecord>, PlacementError> {
        match self
            .database
            .read(DatabaseQuery::<PlacementAggregateDatabaseRecord>::all())
        {
            Ok(DatabaseResult::Records(records)) => records
                .into_iter()
                .map(|stored| placement_record(stored.value))
                .collect(),
            Ok(DatabaseResult::Record(_)) => Err(PlacementError::StoreUnavailable),
            Err(error) => Err(placement_store_error(error)),
        }
    }

    // Returns the validated allocation index and its optimistic revision.
    pub(crate) fn resource_index(
        &self,
    ) -> Result<(ResourceIndexDatabaseRecord, DatabaseRevision), PlacementError> {
        match self
            .database
            .read(DatabaseQuery::<ResourceIndexDatabaseRecord>::record(
                RESOURCE_INDEX_IDENTIFIER,
            )) {
            Ok(DatabaseResult::Record(stored)) => {
                validate_resource_index(&stored.value)?;
                Ok((stored.value, DatabaseRevision::Exact(stored.revision)))
            }
            Ok(DatabaseResult::Records(_)) => Err(PlacementError::StoreUnavailable),
            Err(DatabaseError::NotFound { .. }) => Ok((
                ResourceIndexDatabaseRecord {
                    identifier: RESOURCE_INDEX_IDENTIFIER.to_string(),
                    entries: Vec::new(),
                },
                DatabaseRevision::Missing,
            )),
            Err(error) => Err(placement_store_error(error)),
        }
    }
}

impl DatabasePlacementStore {
    // Returns the exact placement and launch-plan bindings consumed by macOS Gateway safety.
    pub fn gateway_macos_safety_input(
        &self,
        placement_group_id: &li_core_interface::PlacementGroupId,
    ) -> Result<crate::NodeGatewayMacOsSafetyInput, crate::NodeGatewayApiError> {
        let matching = self
            .records()
            .map_err(|_| crate::NodeGatewayApiError::Unavailable)?
            .into_iter()
            .filter(|record| record.group().placement_group_id() == placement_group_id)
            .collect::<Vec<_>>();
        if matching.len() != 1 {
            return Err(crate::NodeGatewayApiError::CorruptState);
        }
        let record = &matching[0];
        let placements = record
            .placements()
            .iter()
            .map(|placement| {
                let identity = record
                    .launch_plan_identity(placement.placement_id())
                    .cloned()
                    .ok_or(crate::NodeGatewayApiError::CorruptState)?;
                Ok(crate::NodeGatewayMacOsPlacement::new(
                    placement.clone(),
                    identity,
                ))
            })
            .collect::<Result<Vec<_>, crate::NodeGatewayApiError>>()?;
        crate::NodeGatewayMacOsSafetyInput::new(placement_group_id.clone(), placements)
    }
}

impl PlacementStore for DatabasePlacementStore {
    // Returns every non-released resource currently owned on one node.
    fn occupied_resources(
        &self,
        node_id: &NodeId,
    ) -> Result<Vec<ResourceIdentity>, PlacementError> {
        let (index, _) = self.resource_index()?;
        index
            .entries
            .into_iter()
            .filter(|entry| entry.node_id == node_id.as_str())
            .map(|entry| resource(entry.resource))
            .collect()
    }

    // Creates one aggregate and updates the global resource index atomically.
    fn create(&self, record: PlacementRecord) -> Result<VersionedPlacementRecord, PlacementError> {
        let placement_group_id = record.group().placement_group_id().clone();
        let (index, index_revision) = self.resource_index()?;
        let index = resource_index_with_record(index, &record)?;
        let transaction =
            DatabaseTransaction::new(format!("placement:create:{}", placement_group_id.as_str()))
                .map_err(placement_store_error)?
                .save(
                    placement_database_record(&record),
                    DatabaseRevision::Missing,
                )
                .map_err(placement_store_error)?
                .save(index, index_revision)
                .map_err(placement_store_error)?;
        let result = self
            .database
            .write_transaction(transaction)
            .map_err(placement_store_error)?;
        require_applied(result.disposition())?;
        let revision = aggregate_revision(result.commit().commits(), placement_group_id.as_str())?;
        Ok(VersionedPlacementRecord::new(record, revision))
    }

    // Returns one fully validated aggregate when it exists.
    fn read(
        &self,
        placement_group_id: &PlacementGroupId,
    ) -> Result<Option<VersionedPlacementRecord>, PlacementError> {
        match self
            .database
            .read(DatabaseQuery::<PlacementAggregateDatabaseRecord>::record(
                placement_group_id.as_str(),
            )) {
            Ok(DatabaseResult::Record(stored)) => Ok(Some(VersionedPlacementRecord::new(
                placement_record(stored.value)?,
                stored.revision,
            ))),
            Ok(DatabaseResult::Records(_)) => Err(PlacementError::StoreUnavailable),
            Err(DatabaseError::NotFound { .. }) => Ok(None),
            Err(error) => Err(placement_store_error(error)),
        }
    }

    // Replaces one aggregate and its resource ownership under two exact revisions.
    fn replace(
        &self,
        record: PlacementRecord,
        expected_revision: u64,
    ) -> Result<VersionedPlacementRecord, PlacementError> {
        let placement_group_id = record.group().placement_group_id().clone();
        let (index, index_revision) = self.resource_index()?;
        if !index
            .entries
            .iter()
            .any(|entry| entry.placement_group_id == placement_group_id.as_str())
            && record
                .leases()
                .iter()
                .any(|lease| lease.state() != ResourceLeaseState::Released)
        {
            return Err(PlacementError::StoreUnavailable);
        }
        let index = resource_index_with_record(index, &record)?;
        let transaction = DatabaseTransaction::new(format!(
            "placement:replace:{}:{expected_revision}",
            placement_group_id.as_str()
        ))
        .map_err(placement_store_error)?
        .save(
            placement_database_record(&record),
            DatabaseRevision::Exact(expected_revision),
        )
        .map_err(placement_store_error)?
        .save(index, index_revision)
        .map_err(placement_store_error)?;
        let result = self
            .database
            .write_transaction(transaction)
            .map_err(placement_store_error)?;
        require_applied(result.disposition())?;
        let revision = aggregate_revision(result.commit().commits(), placement_group_id.as_str())?;
        Ok(VersionedPlacementRecord::new(record, revision))
    }
}

// Replaces one group's resource entries and rejects overlap with every other group.
pub(crate) fn resource_index_with_record(
    mut index: ResourceIndexDatabaseRecord,
    record: &PlacementRecord,
) -> Result<ResourceIndexDatabaseRecord, PlacementError> {
    let placement_group_id = record.group().placement_group_id();
    index
        .entries
        .retain(|entry| entry.placement_group_id != placement_group_id.as_str());
    for lease in record
        .leases()
        .iter()
        .filter(|lease| lease.state() != ResourceLeaseState::Released)
    {
        let entry = ResourceIndexEntryDatabaseRecord {
            node_id: lease.node_id().as_str().to_string(),
            resource: resource_record(lease.resource()),
            placement_group_id: placement_group_id.as_str().to_string(),
            placement_id: lease.placement_id().as_str().to_string(),
            lease_id: lease.lease_id().as_str().to_string(),
        };
        if index.entries.iter().any(|existing| {
            existing.node_id == entry.node_id && existing.resource == entry.resource
        }) {
            return Err(PlacementError::ResourceConflict);
        }
        index.entries.push(entry);
    }
    index.entries.sort_by_key(resource_index_key);
    validate_resource_index(&index)?;
    Ok(index)
}

// Returns one stable sort and uniqueness key for an indexed resource.
fn resource_index_key(entry: &ResourceIndexEntryDatabaseRecord) -> String {
    let resource = match &entry.resource {
        ResourceDatabaseRecord::Accelerator { device_id } => format!("accelerator:{device_id}"),
        ResourceDatabaseRecord::Port { port } => format!("port:{port:05}"),
        ResourceDatabaseRecord::RdmaInterface { interface } => format!("rdma:{interface}"),
    };
    format!("{}:{resource}", entry.node_id)
}

// Validates every private resource-index identity and uniqueness invariant.
fn validate_resource_index(index: &ResourceIndexDatabaseRecord) -> Result<(), PlacementError> {
    if index.identifier != RESOURCE_INDEX_IDENTIFIER {
        return Err(PlacementError::StoreUnavailable);
    }
    let mut resources = HashSet::new();
    let mut leases = HashSet::new();
    for entry in &index.entries {
        NodeId::parse(&entry.node_id).map_err(|_| PlacementError::StoreUnavailable)?;
        PlacementGroupId::parse(&entry.placement_group_id)
            .map_err(|_| PlacementError::StoreUnavailable)?;
        PlacementId::parse(&entry.placement_id).map_err(|_| PlacementError::StoreUnavailable)?;
        ResourceLeaseId::parse(&entry.lease_id).map_err(|_| PlacementError::StoreUnavailable)?;
        resource(entry.resource.clone())?;
        if !resources.insert(resource_index_key(entry)) || !leases.insert(entry.lease_id.as_str()) {
            return Err(PlacementError::StoreUnavailable);
        }
    }
    if index
        .entries
        .windows(2)
        .any(|values| resource_index_key(&values[0]) >= resource_index_key(&values[1]))
    {
        return Err(PlacementError::StoreUnavailable);
    }
    Ok(())
}

// Returns the aggregate commit revision from one two-record transaction.
fn aggregate_revision(
    commits: &[li_database::DatabaseCommit],
    placement_group_id: &str,
) -> Result<u64, PlacementError> {
    if commits.len() != 2
        || commits[0].collection != DatabaseCollection::Placements
        || commits[0].identifier != placement_group_id
        || commits[1].collection != DatabaseCollection::Configuration
        || commits[1].identifier != RESOURCE_INDEX_IDENTIFIER
    {
        return Err(PlacementError::StoreUnavailable);
    }
    Ok(commits[0].revision)
}

// Requires one transaction to apply rather than replay a completed lifecycle mutation.
fn require_applied(disposition: DatabaseCommitDisposition) -> Result<(), PlacementError> {
    match disposition {
        DatabaseCommitDisposition::Applied => Ok(()),
        DatabaseCommitDisposition::Replayed => Err(PlacementError::StoreConflict),
    }
}

// Converts DatabaseManager failures to PlacementStore's narrow surface.
fn placement_store_error(error: DatabaseError) -> PlacementError {
    match error {
        DatabaseError::Conflict { .. } | DatabaseError::IdempotencyConflict { .. } => {
            PlacementError::StoreConflict
        }
        DatabaseError::NotFound { .. }
        | DatabaseError::InvalidInput { .. }
        | DatabaseError::Corrupt { .. }
        | DatabaseError::Unavailable { .. }
        | DatabaseError::Closed => PlacementError::StoreUnavailable,
    }
}

// Projects one complete PlacementManager aggregate into private database fields.
pub(crate) fn placement_database_record(
    record: &PlacementRecord,
) -> PlacementAggregateDatabaseRecord {
    PlacementAggregateDatabaseRecord {
        placement_group_id: record.group().placement_group_id().as_str().to_string(),
        group: placement_group_record(record.group()),
        placements: record
            .placements()
            .iter()
            .map(placement_entry_record)
            .collect(),
        leases: record.leases().iter().map(resource_lease_record).collect(),
        startup_order: record
            .startup_order()
            .iter()
            .map(|phase| {
                phase
                    .iter()
                    .map(|identity| identity.as_str().to_string())
                    .collect()
            })
            .collect(),
        launch_plan_identities: record
            .launch_plan_identities()
            .iter()
            .map(|(placement_id, digest)| LaunchPlanIdentityDatabaseRecord {
                placement_id: placement_id.as_str().to_string(),
                digest: digest.as_str().to_string(),
            })
            .collect(),
    }
}

// Projects one placement-group snapshot into private database fields.
fn placement_group_record(group: &PlacementGroup) -> PlacementGroupDatabaseRecord {
    PlacementGroupDatabaseRecord {
        service_id: group.service_id().as_str().to_string(),
        runtime: runtime_identity_record(group.runtime()),
        placement_ids: group
            .placement_ids()
            .iter()
            .map(|identity| identity.as_str().to_string())
            .collect(),
        endpoint_placement_id: group.endpoint_placement_id().as_str().to_string(),
        endpoint: group.endpoint().map(endpoint_record),
        capacity: capacity_record(group.capacity()),
        desired_state: desired_state_name(group.desired_state()).to_string(),
        state: group_state_name(group.state()).to_string(),
        failure: group.last_failure().map(failure_record),
        created_at_unix_milliseconds: group.timestamps().created_at().value(),
        updated_at_unix_milliseconds: group.timestamps().updated_at().value(),
    }
}

// Projects one exact runtime identity into private placement fields.
fn runtime_identity_record(runtime: &RuntimeIdentity) -> RuntimeIdentityDatabaseRecord {
    RuntimeIdentityDatabaseRecord {
        candidate_id: runtime.candidate_id().as_str().to_string(),
        version: runtime.version().as_str().to_string(),
        target_id: runtime.target_id().as_str().to_string(),
        source: runtime.source().as_str().to_string(),
        engine: engine_record(runtime.engine_distribution()),
        runtime_digest: runtime.runtime_digest().as_str().to_string(),
        manifest_digest: runtime.manifest_digest().as_str().to_string(),
        execution_contract_digest: runtime.execution_contract_digest().as_str().to_string(),
    }
}

// Projects one immutable placement snapshot into private database fields.
fn placement_entry_record(placement: &Placement) -> PlacementDatabaseEntry {
    let assignment = placement.assignment();
    let resources = assignment.resources();
    PlacementDatabaseEntry {
        placement_id: placement.placement_id().as_str().to_string(),
        assignment: PlacementAssignmentDatabaseRecord {
            node_id: assignment.node_id().as_str().to_string(),
            runtime_installation_id: assignment.runtime_installation_id().as_str().to_string(),
            hardware_observation_id: assignment.hardware_observation_id().as_str().to_string(),
            hardware_boot_id: assignment.hardware_boot_id().as_str().to_string(),
            hardware_observed_at_unix_milliseconds: assignment.hardware_observed_at().value(),
            task_id: assignment.task_id().as_str().to_string(),
            address: assignment.address().as_str().to_string(),
            resources: PlacementResourcesDatabaseRecord {
                port_base: resources.ports().base(),
                port_count: resources.ports().count(),
                device_ids: resources
                    .device_ids()
                    .iter()
                    .map(|identity| identity.as_str().to_string())
                    .collect(),
                rdma_interface: resources
                    .rdma_interface()
                    .map(|value| value.as_str().to_string()),
            },
            endpoint_ownership: endpoint_ownership_name(assignment.endpoint_ownership())
                .to_string(),
        },
        state: placement_state_name(placement.state()).to_string(),
        active_operation_id: placement
            .active_operation_id()
            .map(|identity| identity.as_str().to_string()),
        failure: placement.last_failure().map(failure_record),
        created_at_unix_milliseconds: placement.timestamps().created_at().value(),
        updated_at_unix_milliseconds: placement.timestamps().updated_at().value(),
    }
}

// Projects one resource lease into private database fields.
fn resource_lease_record(lease: &ResourceLease) -> ResourceLeaseDatabaseRecord {
    ResourceLeaseDatabaseRecord {
        lease_id: lease.lease_id().as_str().to_string(),
        placement_id: lease.placement_id().as_str().to_string(),
        node_id: lease.node_id().as_str().to_string(),
        resource: resource_record(lease.resource()),
        state: lease_state_name(lease.state()).to_string(),
        created_at_unix_milliseconds: lease.timestamps().created_at().value(),
        updated_at_unix_milliseconds: lease.timestamps().updated_at().value(),
    }
}

// Projects one generic resource identity into a closed private union.
fn resource_record(resource: &ResourceIdentity) -> ResourceDatabaseRecord {
    match resource {
        ResourceIdentity::Accelerator(device_id) => ResourceDatabaseRecord::Accelerator {
            device_id: device_id.as_str().to_string(),
        },
        ResourceIdentity::Port(port) => ResourceDatabaseRecord::Port { port: port.value() },
        ResourceIdentity::RdmaInterface(interface) => ResourceDatabaseRecord::RdmaInterface {
            interface: interface.as_str().to_string(),
        },
    }
}

// Projects one endpoint without reading any referenced credential material.
fn endpoint_record(endpoint: &PlacementEndpoint) -> EndpointDatabaseRecord {
    EndpointDatabaseRecord {
        placement_id: endpoint.placement_id().as_str().to_string(),
        node_id: endpoint.node_id().as_str().to_string(),
        scheme: endpoint_scheme_name(endpoint.address().scheme()).to_string(),
        host: endpoint.address().host().as_str().to_string(),
        port: endpoint.address().port(),
        credential_id: endpoint.credential_id().as_str().to_string(),
        ca_credential_id: endpoint
            .ca_credential_id()
            .map(|identity| identity.as_str().to_string()),
        token_count: endpoint
            .token_count()
            .map(|contract| TokenCountDatabaseRecord {
                path: contract.path().to_string(),
                protocol: token_count_protocol_name(contract.protocol()).to_string(),
            }),
        max_active_requests: endpoint.max_active_requests(),
        max_context_tokens: endpoint.max_context_tokens(),
        health: EndpointHealthDatabaseRecord {
            healthy: endpoint.health().healthy(),
            memory_pressure: endpoint.health().memory_pressure(),
            temperature_millicelsius: endpoint.health().temperature_millicelsius(),
            prefix_keys: endpoint
                .health()
                .prefix_keys()
                .iter()
                .map(|value| value.as_str().to_string())
                .collect(),
        },
    }
}

// Projects one group capacity and interconnect requirement.
fn capacity_record(capacity: PlacementGroupCapacity) -> CapacityDatabaseRecord {
    let interconnect = capacity.interconnect();
    CapacityDatabaseRecord {
        max_connections: capacity.max_connections(),
        max_active_requests: capacity.max_active_requests(),
        max_context_tokens: capacity.max_context_tokens(),
        interconnect: InterconnectDatabaseRecord {
            kind: interconnect_kind_name(interconnect.kind()).to_string(),
            rdma_required: interconnect.rdma_required(),
            minimum_speed_mbps: interconnect.minimum_speed_mbps(),
            minimum_mtu: interconnect.minimum_mtu(),
        },
    }
}

// Projects one bounded failure without changing its stable language.
fn failure_record(failure: &FailureDescription) -> FailureDatabaseRecord {
    FailureDatabaseRecord {
        code: failure.code().as_str().to_string(),
        message: failure.message().to_string(),
    }
}

// Reconstructs one validated PlacementManager aggregate from private persistence.
fn placement_record(
    record: PlacementAggregateDatabaseRecord,
) -> Result<PlacementRecord, PlacementError> {
    let placement_group_id = PlacementGroupId::parse(&record.placement_group_id)
        .map_err(|_| PlacementError::StoreUnavailable)?;
    let group = placement_group(placement_group_id.clone(), record.group)?;
    let placements = record
        .placements
        .into_iter()
        .map(|value| placement(placement_group_id.clone(), value))
        .collect::<Result<Vec<_>, PlacementError>>()?;
    let leases = record
        .leases
        .into_iter()
        .map(resource_lease)
        .collect::<Result<Vec<_>, PlacementError>>()?;
    let startup_order = record
        .startup_order
        .into_iter()
        .map(|phase| {
            phase
                .into_iter()
                .map(|identity| {
                    PlacementId::parse(&identity).map_err(|_| PlacementError::StoreUnavailable)
                })
                .collect()
        })
        .collect::<Result<Vec<Vec<PlacementId>>, PlacementError>>()?;
    let launch_plan_identities = record
        .launch_plan_identities
        .into_iter()
        .map(|identity| {
            Ok((
                PlacementId::parse(&identity.placement_id)
                    .map_err(|_| PlacementError::StoreUnavailable)?,
                Sha256Digest::parse(&identity.digest)
                    .map_err(|_| PlacementError::StoreUnavailable)?,
            ))
        })
        .collect::<Result<Vec<_>, PlacementError>>()?;
    PlacementRecord::new(
        group,
        placements,
        leases,
        startup_order,
        launch_plan_identities,
    )
    .map_err(|_| PlacementError::StoreUnavailable)
}

// Reconstructs one validated placement-group snapshot.
fn placement_group(
    placement_group_id: PlacementGroupId,
    record: PlacementGroupDatabaseRecord,
) -> Result<PlacementGroup, PlacementError> {
    PlacementGroup::new(
        placement_group_id,
        ModelServiceId::parse(&record.service_id).map_err(|_| PlacementError::StoreUnavailable)?,
        runtime_identity(record.runtime)?,
        record
            .placement_ids
            .into_iter()
            .map(|identity| {
                PlacementId::parse(&identity).map_err(|_| PlacementError::StoreUnavailable)
            })
            .collect::<Result<Vec<_>, PlacementError>>()?,
        PlacementId::parse(&record.endpoint_placement_id)
            .map_err(|_| PlacementError::StoreUnavailable)?,
        record.endpoint.map(endpoint).transpose()?,
        capacity(record.capacity)?,
        desired_state(&record.desired_state)?,
        group_state(&record.state)?,
        record.failure.map(failure).transpose()?,
        timestamps(
            record.created_at_unix_milliseconds,
            record.updated_at_unix_milliseconds,
        )?,
    )
    .map_err(|_| PlacementError::StoreUnavailable)
}

// Reconstructs one exact runtime identity from private placement fields.
fn runtime_identity(
    record: RuntimeIdentityDatabaseRecord,
) -> Result<RuntimeIdentity, PlacementError> {
    RuntimeIdentity::new(
        RuntimeCandidateId::parse(&record.candidate_id)
            .map_err(|_| PlacementError::StoreUnavailable)?,
        RuntimeVersion::parse(&record.version).map_err(|_| PlacementError::StoreUnavailable)?,
        TargetId::parse(&record.target_id).map_err(|_| PlacementError::StoreUnavailable)?,
        RuntimeSource::parse(&record.source).map_err(|_| PlacementError::StoreUnavailable)?,
        engine_distribution(record.engine).map_err(|_| PlacementError::StoreUnavailable)?,
        Sha256Digest::parse(&record.runtime_digest)
            .map_err(|_| PlacementError::StoreUnavailable)?,
        Sha256Digest::parse(&record.manifest_digest)
            .map_err(|_| PlacementError::StoreUnavailable)?,
        Sha256Digest::parse(&record.execution_contract_digest)
            .map_err(|_| PlacementError::StoreUnavailable)?,
    )
    .map_err(|_| PlacementError::StoreUnavailable)
}

// Reconstructs one immutable placement snapshot.
fn placement(
    placement_group_id: PlacementGroupId,
    record: PlacementDatabaseEntry,
) -> Result<Placement, PlacementError> {
    let resources = record.assignment.resources;
    Placement::new(
        PlacementId::parse(&record.placement_id).map_err(|_| PlacementError::StoreUnavailable)?,
        placement_group_id,
        PlacementAssignment::new(
            NodeId::parse(&record.assignment.node_id)
                .map_err(|_| PlacementError::StoreUnavailable)?,
            RuntimeInstallationId::parse(&record.assignment.runtime_installation_id)
                .map_err(|_| PlacementError::StoreUnavailable)?,
            HardwareObservationId::parse(&record.assignment.hardware_observation_id)
                .map_err(|_| PlacementError::StoreUnavailable)?,
            BootId::parse(&record.assignment.hardware_boot_id)
                .map_err(|_| PlacementError::StoreUnavailable)?,
            UnixMilliseconds::new(record.assignment.hardware_observed_at_unix_milliseconds),
            TaskId::parse(&record.assignment.task_id)
                .map_err(|_| PlacementError::StoreUnavailable)?,
            NodeAddress::parse(&record.assignment.address)
                .map_err(|_| PlacementError::StoreUnavailable)?,
            PlacementResources::new(
                PortRange::new(resources.port_base, resources.port_count)
                    .map_err(|_| PlacementError::StoreUnavailable)?,
                resources
                    .device_ids
                    .into_iter()
                    .map(|identity| {
                        DeviceId::parse(&identity).map_err(|_| PlacementError::StoreUnavailable)
                    })
                    .collect::<Result<Vec<_>, PlacementError>>()?,
                resources
                    .rdma_interface
                    .map(|value| NetworkInterfaceName::parse(&value))
                    .transpose()
                    .map_err(|_| PlacementError::StoreUnavailable)?,
            )
            .map_err(|_| PlacementError::StoreUnavailable)?,
            endpoint_ownership(&record.assignment.endpoint_ownership)?,
        ),
        placement_state(&record.state)?,
        record
            .active_operation_id
            .map(|identity| OperationId::parse(&identity))
            .transpose()
            .map_err(|_| PlacementError::StoreUnavailable)?,
        record.failure.map(failure).transpose()?,
        timestamps(
            record.created_at_unix_milliseconds,
            record.updated_at_unix_milliseconds,
        )?,
    )
    .map_err(|_| PlacementError::StoreUnavailable)
}

// Reconstructs one exact resource lease from private fields.
fn resource_lease(record: ResourceLeaseDatabaseRecord) -> Result<ResourceLease, PlacementError> {
    Ok(ResourceLease::new(
        ResourceLeaseId::parse(&record.lease_id).map_err(|_| PlacementError::StoreUnavailable)?,
        PlacementId::parse(&record.placement_id).map_err(|_| PlacementError::StoreUnavailable)?,
        NodeId::parse(&record.node_id).map_err(|_| PlacementError::StoreUnavailable)?,
        resource(record.resource)?,
        lease_state(&record.state)?,
        timestamps(
            record.created_at_unix_milliseconds,
            record.updated_at_unix_milliseconds,
        )?,
    ))
}

// Reconstructs one closed generic resource identity.
fn resource(record: ResourceDatabaseRecord) -> Result<ResourceIdentity, PlacementError> {
    match record {
        ResourceDatabaseRecord::Accelerator { device_id } => Ok(ResourceIdentity::Accelerator(
            DeviceId::parse(&device_id).map_err(|_| PlacementError::StoreUnavailable)?,
        )),
        ResourceDatabaseRecord::Port { port } => Ok(ResourceIdentity::Port(
            NetworkPort::new(port).map_err(|_| PlacementError::StoreUnavailable)?,
        )),
        ResourceDatabaseRecord::RdmaInterface { interface } => Ok(ResourceIdentity::RdmaInterface(
            NetworkInterfaceName::parse(&interface)
                .map_err(|_| PlacementError::StoreUnavailable)?,
        )),
    }
}

// Reconstructs one routable endpoint and its bounded health snapshot.
fn endpoint(record: EndpointDatabaseRecord) -> Result<PlacementEndpoint, PlacementError> {
    PlacementEndpoint::new(
        PlacementId::parse(&record.placement_id).map_err(|_| PlacementError::StoreUnavailable)?,
        NodeId::parse(&record.node_id).map_err(|_| PlacementError::StoreUnavailable)?,
        EndpointAddress::new(
            endpoint_scheme(&record.scheme)?,
            NodeAddress::parse(&record.host).map_err(|_| PlacementError::StoreUnavailable)?,
            record.port,
        )
        .map_err(|_| PlacementError::StoreUnavailable)?,
        CredentialId::parse(&record.credential_id).map_err(|_| PlacementError::StoreUnavailable)?,
        record
            .ca_credential_id
            .map(|identity| CredentialId::parse(&identity))
            .transpose()
            .map_err(|_| PlacementError::StoreUnavailable)?,
        record.token_count.map(token_count).transpose()?,
        record.max_active_requests,
        record.max_context_tokens,
        EndpointHealth::new(
            record.health.healthy,
            record.health.memory_pressure,
            record.health.temperature_millicelsius,
            record
                .health
                .prefix_keys
                .into_iter()
                .map(|value| {
                    TechnicalName::parse(&value).map_err(|_| PlacementError::StoreUnavailable)
                })
                .collect::<Result<Vec<_>, PlacementError>>()?,
        )
        .map_err(|_| PlacementError::StoreUnavailable)?,
    )
    .map_err(|_| PlacementError::StoreUnavailable)
}

// Reconstructs one exact token-count contract.
fn token_count(record: TokenCountDatabaseRecord) -> Result<TokenCountContract, PlacementError> {
    TokenCountContract::new(&record.path, token_count_protocol(&record.protocol)?)
        .map_err(|_| PlacementError::StoreUnavailable)
}

// Reconstructs one runtime-qualified capacity and interconnect requirement.
fn capacity(record: CapacityDatabaseRecord) -> Result<PlacementGroupCapacity, PlacementError> {
    PlacementGroupCapacity::new(
        record.max_connections,
        record.max_active_requests,
        record.max_context_tokens,
        InterconnectRequirement::new(
            interconnect_kind(&record.interconnect.kind)?,
            record.interconnect.rdma_required,
            record.interconnect.minimum_speed_mbps,
            record.interconnect.minimum_mtu,
        ),
    )
    .map_err(|_| PlacementError::StoreUnavailable)
}

// Reconstructs one bounded stable failure.
fn failure(record: FailureDatabaseRecord) -> Result<FailureDescription, PlacementError> {
    FailureDescription::new(
        TechnicalName::parse(&record.code).map_err(|_| PlacementError::StoreUnavailable)?,
        &record.message,
    )
    .map_err(|_| PlacementError::StoreUnavailable)
}

// Reconstructs one coherent timestamp pair.
fn timestamps(created_at: u64, updated_at: u64) -> Result<EntityTimestamps, PlacementError> {
    EntityTimestamps::new(
        UnixMilliseconds::new(created_at),
        UnixMilliseconds::new(updated_at),
    )
    .map_err(|_| PlacementError::StoreUnavailable)
}

// Returns the private persistence name for one desired service state.
fn desired_state_name(value: ModelServiceDesiredState) -> &'static str {
    match value {
        ModelServiceDesiredState::Running => "running",
        ModelServiceDesiredState::Stopped => "stopped",
        ModelServiceDesiredState::Removed => "removed",
    }
}

// Parses one private desired service state.
fn desired_state(value: &str) -> Result<ModelServiceDesiredState, PlacementError> {
    match value {
        "running" => Ok(ModelServiceDesiredState::Running),
        "stopped" => Ok(ModelServiceDesiredState::Stopped),
        "removed" => Ok(ModelServiceDesiredState::Removed),
        _ => Err(PlacementError::StoreUnavailable),
    }
}

// Returns the private persistence name for one placement-group state.
fn group_state_name(value: PlacementGroupState) -> &'static str {
    match value {
        PlacementGroupState::Staging => "staging",
        PlacementGroupState::Staged => "staged",
        PlacementGroupState::Starting => "starting",
        PlacementGroupState::Running => "running",
        PlacementGroupState::Degraded => "degraded",
        PlacementGroupState::Stopping => "stopping",
        PlacementGroupState::Stopped => "stopped",
        PlacementGroupState::Recovering => "recovering",
        PlacementGroupState::Removing => "removing",
        PlacementGroupState::Removed => "removed",
        PlacementGroupState::Failed => "failed",
    }
}

// Parses one private placement-group state.
fn group_state(value: &str) -> Result<PlacementGroupState, PlacementError> {
    match value {
        "staging" => Ok(PlacementGroupState::Staging),
        "staged" => Ok(PlacementGroupState::Staged),
        "starting" => Ok(PlacementGroupState::Starting),
        "running" => Ok(PlacementGroupState::Running),
        "degraded" => Ok(PlacementGroupState::Degraded),
        "stopping" => Ok(PlacementGroupState::Stopping),
        "stopped" => Ok(PlacementGroupState::Stopped),
        "recovering" => Ok(PlacementGroupState::Recovering),
        "removing" => Ok(PlacementGroupState::Removing),
        "removed" => Ok(PlacementGroupState::Removed),
        "failed" => Ok(PlacementGroupState::Failed),
        _ => Err(PlacementError::StoreUnavailable),
    }
}

// Returns the private persistence name for endpoint ownership.
fn endpoint_ownership_name(value: EndpointOwnership) -> &'static str {
    match value {
        EndpointOwnership::Owner => "owner",
        EndpointOwnership::Participant => "participant",
    }
}

// Parses one private endpoint-ownership value.
fn endpoint_ownership(value: &str) -> Result<EndpointOwnership, PlacementError> {
    match value {
        "owner" => Ok(EndpointOwnership::Owner),
        "participant" => Ok(EndpointOwnership::Participant),
        _ => Err(PlacementError::StoreUnavailable),
    }
}

// Returns the private persistence name for one placement state.
fn placement_state_name(value: PlacementState) -> &'static str {
    match value {
        PlacementState::Pending => "pending",
        PlacementState::Staging => "staging",
        PlacementState::Staged => "staged",
        PlacementState::Starting => "starting",
        PlacementState::Running => "running",
        PlacementState::Stopping => "stopping",
        PlacementState::Stopped => "stopped",
        PlacementState::Removing => "removing",
        PlacementState::Removed => "removed",
        PlacementState::Failed => "failed",
        PlacementState::Unreachable => "unreachable",
    }
}

// Parses one private placement state.
fn placement_state(value: &str) -> Result<PlacementState, PlacementError> {
    match value {
        "pending" => Ok(PlacementState::Pending),
        "staging" => Ok(PlacementState::Staging),
        "staged" => Ok(PlacementState::Staged),
        "starting" => Ok(PlacementState::Starting),
        "running" => Ok(PlacementState::Running),
        "stopping" => Ok(PlacementState::Stopping),
        "stopped" => Ok(PlacementState::Stopped),
        "removing" => Ok(PlacementState::Removing),
        "removed" => Ok(PlacementState::Removed),
        "failed" => Ok(PlacementState::Failed),
        "unreachable" => Ok(PlacementState::Unreachable),
        _ => Err(PlacementError::StoreUnavailable),
    }
}

// Returns the private persistence name for one resource-lease state.
fn lease_state_name(value: ResourceLeaseState) -> &'static str {
    match value {
        ResourceLeaseState::Reserved => "reserved",
        ResourceLeaseState::Active => "active",
        ResourceLeaseState::Draining => "draining",
        ResourceLeaseState::Released => "released",
    }
}

// Parses one private resource-lease state.
fn lease_state(value: &str) -> Result<ResourceLeaseState, PlacementError> {
    match value {
        "reserved" => Ok(ResourceLeaseState::Reserved),
        "active" => Ok(ResourceLeaseState::Active),
        "draining" => Ok(ResourceLeaseState::Draining),
        "released" => Ok(ResourceLeaseState::Released),
        _ => Err(PlacementError::StoreUnavailable),
    }
}

// Returns the private persistence name for one endpoint scheme.
fn endpoint_scheme_name(value: EndpointScheme) -> &'static str {
    match value {
        EndpointScheme::Http => "http",
        EndpointScheme::Https => "https",
    }
}

// Parses one private endpoint scheme.
fn endpoint_scheme(value: &str) -> Result<EndpointScheme, PlacementError> {
    match value {
        "http" => Ok(EndpointScheme::Http),
        "https" => Ok(EndpointScheme::Https),
        _ => Err(PlacementError::StoreUnavailable),
    }
}

// Returns the private persistence name for one token-count protocol.
fn token_count_protocol_name(value: TokenCountProtocol) -> &'static str {
    match value {
        TokenCountProtocol::LetsInferV1 => "letsinfer_v1",
    }
}

// Parses one private token-count protocol.
fn token_count_protocol(value: &str) -> Result<TokenCountProtocol, PlacementError> {
    match value {
        "letsinfer_v1" => Ok(TokenCountProtocol::LetsInferV1),
        _ => Err(PlacementError::StoreUnavailable),
    }
}

// Returns the private persistence name for one model-neutral interconnect kind.
fn interconnect_kind_name(value: InterconnectKind) -> &'static str {
    match value {
        InterconnectKind::Any => "any",
        InterconnectKind::Connectx => "connectx",
        InterconnectKind::Ethernet => "ethernet",
        InterconnectKind::Wifi => "wifi",
        InterconnectKind::Other => "other",
    }
}

// Parses one private model-neutral interconnect kind.
fn interconnect_kind(value: &str) -> Result<InterconnectKind, PlacementError> {
    match value {
        "any" => Ok(InterconnectKind::Any),
        "connectx" => Ok(InterconnectKind::Connectx),
        "ethernet" => Ok(InterconnectKind::Ethernet),
        "wifi" => Ok(InterconnectKind::Wifi),
        "other" => Ok(InterconnectKind::Other),
        _ => Err(PlacementError::StoreUnavailable),
    }
}
