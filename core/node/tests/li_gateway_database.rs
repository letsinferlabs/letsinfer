// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use li_core_interface::{
    CredentialId, DeviceId, EndpointAddress, EndpointHealth, EndpointOwnership, EndpointScheme,
    EngineDistribution, EntityTimestamps, InterconnectKind, InterconnectRequirement,
    LogicalModelName, ModelService, ModelServiceDesiredState, ModelServiceId, NetworkPort, Node,
    NodeAddress, NodeId, Placement, PlacementAssignment, PlacementEndpoint, PlacementGroup,
    PlacementGroupCapacity, PlacementGroupId, PlacementGroupState, PlacementId, PlacementResources,
    PlacementState, PortRange, ResourceIdentity, ResourceLease, ResourceLeaseId,
    ResourceLeaseState, RuntimeCandidateId, RuntimeIdentity, RuntimeInstallationId, RuntimeSource,
    RuntimeVersion, Sha256Digest, TargetId, TaskId, TechnicalName, UnixMilliseconds,
};
use li_database::{DatabaseConfiguration, DatabaseManager};
use li_gateway_manager::{GatewayRouteProvider, GatewayRouteTarget};
use li_node_manager::{DatabasePlacementStore, NodeGatewayRouteProvider, NodeManager};
use li_placement_manager::{PlacementRecord, PlacementStore};

// Returns one exact runtime identity for a route fixture.
fn runtime_identity() -> RuntimeIdentity {
    RuntimeIdentity::new(
        RuntimeCandidateId::parse("sglang--radixark--qwen3.8--dgx-spark").expect("candidate"),
        RuntimeVersion::parse("1.0.0").expect("version"),
        TargetId::parse("dgx-spark").expect("target"),
        RuntimeSource::parse(&format!("ghcr.io/runtime/qwen@sha256:{}", "a".repeat(64)))
            .expect("runtime source"),
        EngineDistribution::oci(
            RuntimeSource::parse(&format!("ghcr.io/engine/qwen@sha256:{}", "b".repeat(64)))
                .expect("Engine source"),
            Sha256Digest::parse(&"c".repeat(64)).expect("Engine identity"),
            None,
            Some(Sha256Digest::parse(&"d".repeat(64)).expect("payload")),
        ),
        Sha256Digest::parse(&"a".repeat(64)).expect("runtime digest"),
        Sha256Digest::parse(&"e".repeat(64)).expect("manifest"),
        Sha256Digest::parse(&"f".repeat(64)).expect("execution"),
    )
    .expect("runtime")
}

// Returns one complete running placement aggregate for the local node.
fn running_record() -> PlacementRecord {
    let service_id = ModelServiceId::parse(&"4".repeat(32)).expect("service");
    let group_id = PlacementGroupId::parse(&"5".repeat(32)).expect("group");
    let placement_id = PlacementId::parse(&"6".repeat(32)).expect("placement");
    let node_id = NodeId::parse(&"1".repeat(32)).expect("node");
    let device_id = DeviceId::parse("GPU-A").expect("GPU");
    let resources = PlacementResources::new(
        PortRange::new(18_000, 1).expect("ports"),
        vec![device_id.clone()],
        None,
    )
    .expect("resources");
    let placement = Placement::new(
        placement_id.clone(),
        group_id.clone(),
        PlacementAssignment::new(
            node_id.clone(),
            RuntimeInstallationId::parse(&"2".repeat(32)).expect("installation"),
            li_core_interface::HardwareObservationId::parse(&"6".repeat(32))
                .expect("hardware observation"),
            li_core_interface::BootId::parse("11111111-2222-3333-4444-555555555555").expect("boot"),
            UnixMilliseconds::new(900),
            TaskId::parse("task-0").expect("task"),
            NodeAddress::parse("homeai.local").expect("address"),
            resources,
            EndpointOwnership::Owner,
        ),
        PlacementState::Running,
        None,
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(2_000))
            .expect("timestamps"),
    )
    .expect("placement");
    let endpoint = PlacementEndpoint::new(
        placement_id.clone(),
        node_id.clone(),
        EndpointAddress::new(
            EndpointScheme::Https,
            NodeAddress::parse("homeai.local").expect("address"),
            18_000,
        )
        .expect("endpoint"),
        CredentialId::parse(&"3".repeat(32)).expect("credential"),
        Some(CredentialId::parse(&"8".repeat(32)).expect("CA")),
        None,
        4,
        262_144,
        EndpointHealth::new(
            true,
            true,
            Some(52_000),
            vec![TechnicalName::parse("ledger").expect("prefix")],
        )
        .expect("health"),
    )
    .expect("endpoint");
    let group = PlacementGroup::new(
        group_id,
        service_id,
        runtime_identity(),
        vec![placement_id.clone()],
        placement_id.clone(),
        Some(endpoint),
        PlacementGroupCapacity::new(
            8,
            4,
            262_144,
            InterconnectRequirement::new(InterconnectKind::Any, false, 0, 0),
        )
        .expect("capacity"),
        ModelServiceDesiredState::Running,
        PlacementGroupState::Running,
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(2_000))
            .expect("timestamps"),
    )
    .expect("group");
    let leases = [
        ResourceIdentity::Accelerator(device_id),
        ResourceIdentity::Port(NetworkPort::new(18_000).expect("port")),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, resource)| {
        ResourceLease::new(
            ResourceLeaseId::parse(&format!("{:032x}", 7 + index)).expect("lease"),
            placement_id.clone(),
            node_id.clone(),
            resource,
            ResourceLeaseState::Active,
            EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(2_000))
                .expect("timestamps"),
        )
    })
    .collect();
    PlacementRecord::new(
        group,
        vec![placement],
        leases,
        vec![vec![placement_id.clone()]],
        vec![(
            placement_id,
            Sha256Digest::parse(&"9".repeat(64)).expect("plan"),
        )],
    )
    .expect("record")
}

// Opens the shared database, NodeManager, placement store, and route provider.
fn composition(
    directory: &tempfile::TempDir,
) -> (
    Arc<NodeManager>,
    Arc<DatabasePlacementStore>,
    NodeGatewayRouteProvider,
) {
    let database = Arc::new(
        DatabaseManager::open(DatabaseConfiguration::new(
            directory.path().join("core.sqlite3"),
        ))
        .expect("database"),
    );
    let manager = Arc::new(
        NodeManager::open(database.clone(), local_node(), "initialize-node")
            .expect("manager")
            .0,
    );
    let placements = Arc::new(DatabasePlacementStore::new(database));
    let provider = NodeGatewayRouteProvider::new(manager.clone(), placements.clone());
    (manager, placements, provider)
}

// Returns one ordinary active local main node.
fn local_node() -> Node {
    Node::new(
        li_core_interface::NodeIdentity::new(
            NodeId::parse(&"1".repeat(32)).expect("node"),
            li_core_interface::MachineId::parse(&"2".repeat(32)).expect("machine"),
            li_core_interface::InstallationId::parse(&"3".repeat(64)).expect("installation"),
        ),
        li_core_interface::DisplayName::parse("Home AI").expect("name"),
        li_core_interface::NodeRole::Main,
        li_core_interface::NodeState::Active,
        NodeAddress::parse("homeai.local").expect("address"),
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(1_000))
            .expect("timestamps"),
    )
}

// Returns one empty stopped model service for the running record fixture.
fn model_service() -> ModelService {
    ModelService::new(
        ModelServiceId::parse(&"4".repeat(32)).expect("service"),
        LogicalModelName::parse("qwen3_8").expect("model"),
        ModelServiceDesiredState::Stopped,
        Vec::new(),
        EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(1_000))
            .expect("timestamps"),
    )
    .expect("service")
}

// Projects only a running NodeManager-owned service and its exact PlacementManager endpoint.
#[test]
fn provider_projects_running_local_route_and_hides_stopped_service() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (manager, placements, provider) = composition(&directory);
    let service = model_service();
    manager
        .create_model_service("create", service.clone())
        .expect("create");
    let record = running_record();
    placements.create(record.clone()).expect("placement");
    let attached = manager
        .attach_placement_group(
            "attach",
            service.service_id(),
            record.group().placement_group_id().clone(),
            1,
            UnixMilliseconds::new(2_000),
        )
        .expect("attach");
    manager
        .transition_model_service(
            "run",
            service.service_id(),
            ModelServiceDesiredState::Running,
            attached.revision(),
            UnixMilliseconds::new(3_000),
        )
        .expect("run");
    let routes = provider.routes(service.logical_model()).expect("routes");
    assert_eq!(routes.len(), 1);
    assert_eq!(
        routes[0].placement_group_id(),
        record.group().placement_group_id()
    );
    assert!(routes[0].has_memory_pressure());
    assert_eq!(routes[0].temperature_millicelsius(), Some(52_000));
    assert_eq!(routes[0].prefix_keys().len(), 1);
    assert!(matches!(
        routes[0].target(),
        GatewayRouteTarget::LocalEngine { .. }
    ));

    manager
        .transition_model_service(
            "stop",
            service.service_id(),
            ModelServiceDesiredState::Stopped,
            attached.revision() + 1,
            UnixMilliseconds::new(4_000),
        )
        .expect("stop");
    assert!(provider
        .routes(service.logical_model())
        .expect("stopped routes")
        .is_empty());
}

// Rejects a running logical service that references absent placement state.
#[test]
fn provider_fails_closed_on_missing_placement_group() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (manager, _placements, provider) = composition(&directory);
    let service = model_service();
    manager
        .create_model_service("create", service.clone())
        .expect("create");
    let attached = manager
        .attach_placement_group(
            "attach",
            service.service_id(),
            PlacementGroupId::parse(&"5".repeat(32)).expect("group"),
            1,
            UnixMilliseconds::new(2_000),
        )
        .expect("attach");
    manager
        .transition_model_service(
            "run",
            service.service_id(),
            ModelServiceDesiredState::Running,
            attached.revision(),
            UnixMilliseconds::new(3_000),
        )
        .expect("run");
    assert!(provider.routes(service.logical_model()).is_err());
}
