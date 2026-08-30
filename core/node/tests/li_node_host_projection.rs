// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use li_core_interface::{
    BootId, ByteCount, CpuArchitecture, DeviceId, DisplayName, EndpointOwnership,
    EngineDistribution, EntityTimestamps, HardwareObservation, HardwareObservationId,
    InstallationId, InterconnectKind, InterconnectRequirement, MachineId, ModelServiceDesiredState,
    ModelServiceId, NetworkPort, Node, NodeAddress, NodeId, NodeIdentity, NodeRole, NodeState,
    OperatingSystem, Placement, PlacementAssignment, PlacementGroup, PlacementGroupCapacity,
    PlacementGroupId, PlacementGroupState, PlacementId, PlacementResources, PlacementState,
    PlatformIdentity, PortRange, ProcessorObservation, ResourceIdentity, ResourceLease,
    ResourceLeaseId, ResourceLeaseState, RuntimeCandidateId, RuntimeIdentity,
    RuntimeInstallationId, RuntimeSource, RuntimeVersion, Sha256Digest, TargetId, TaskId,
    UnixMilliseconds,
};
use li_database::{DatabaseClock, DatabaseConfiguration, DatabaseError, DatabaseManager};
use li_node_manager::{
    NodeHostGatewaySummary, NodeHostGatewayTelemetrySummary, NodeHostPlacementGroup,
    NodeHostPlacementReadPort, NodeHostProjectionPorts, NodeHostProtectionReadPort,
    NodeHostProtectionState, NodeHostProtectionSummary, NodeHostReadError, NodeHostServiceReadPort,
    NodeHostServiceState, NodeHostTopologyReadPort, NodeHostWatchdogSummary,
    NodeHostWatchdogTelemetrySummary, NodeManager,
};
use li_placement_manager::{PlacementLink, PlacementRecord};

// Supplies deterministic increasing database commit timestamps.
struct TestClock(AtomicI64);

impl DatabaseClock for TestClock {
    // Returns one unique timestamp for every new database commit.
    fn now_unix_milliseconds(&self) -> Result<i64, DatabaseError> {
        Ok(self.0.fetch_add(1, Ordering::SeqCst))
    }
}

// Supplies deterministic independent projection sections and records their requested host.
struct MockHostReadPorts {
    placements: Option<Vec<PlacementRecord>>,
    links: Option<Vec<PlacementLink>>,
    protection: Option<Option<NodeHostProtectionSummary>>,
    gateway: Option<Option<NodeHostGatewaySummary>>,
    watchdog: Option<Option<NodeHostWatchdogSummary>>,
    placement_calls: AtomicUsize,
    topology_calls: AtomicUsize,
    protection_nodes: Mutex<Vec<NodeId>>,
    gateway_nodes: Mutex<Vec<NodeId>>,
    watchdog_nodes: Mutex<Vec<NodeId>>,
}

impl MockHostReadPorts {
    // Creates one fully available provider composition from exact immutable fixture inputs.
    fn complete(placements: Vec<PlacementRecord>, links: Vec<PlacementLink>) -> Self {
        Self {
            placements: Some(placements),
            links: Some(links),
            protection: Some(Some(NodeHostProtectionSummary::new(
                NodeHostProtectionState::Ready,
                UnixMilliseconds::new(4_000),
            ))),
            gateway: Some(Some(NodeHostGatewaySummary::new(
                NodeHostServiceState::Ready,
                Some(NodeHostGatewayTelemetrySummary::new(
                    UnixMilliseconds::new(4_001),
                    2,
                    1,
                    10,
                    1,
                    1_000,
                    500,
                    250,
                )),
            ))),
            watchdog: Some(Some(NodeHostWatchdogSummary::new(
                NodeHostServiceState::Ready,
                Some(
                    NodeHostWatchdogTelemetrySummary::new(
                        UnixMilliseconds::new(4_002),
                        Some(20),
                        Some(30),
                        Some(40),
                        Some(50),
                        None,
                        2,
                        1,
                    )
                    .expect("watchdog telemetry"),
                ),
            ))),
            placement_calls: AtomicUsize::new(0),
            topology_calls: AtomicUsize::new(0),
            protection_nodes: Mutex::new(Vec::new()),
            gateway_nodes: Mutex::new(Vec::new()),
            watchdog_nodes: Mutex::new(Vec::new()),
        }
    }
}

impl NodeHostPlacementReadPort for MockHostReadPorts {
    // Returns the configured placement aggregate set or an explicit unavailable result.
    fn placement_records(&self) -> Result<Vec<PlacementRecord>, NodeHostReadError> {
        self.placement_calls.fetch_add(1, Ordering::SeqCst);
        self.placements
            .clone()
            .ok_or(NodeHostReadError::Unavailable)
    }
}

impl NodeHostTopologyReadPort for MockHostReadPorts {
    // Returns the configured verified links or an explicit unavailable result.
    fn verified_links(&self) -> Result<Vec<PlacementLink>, NodeHostReadError> {
        self.topology_calls.fetch_add(1, Ordering::SeqCst);
        self.links.clone().ok_or(NodeHostReadError::Unavailable)
    }
}

impl NodeHostProtectionReadPort for MockHostReadPorts {
    // Records the exact host and returns the configured protection observation.
    fn protection(
        &self,
        node: &Node,
        _placement_groups: &[NodeHostPlacementGroup],
    ) -> Result<Option<NodeHostProtectionSummary>, NodeHostReadError> {
        self.protection_nodes
            .lock()
            .expect("protection nodes")
            .push(node.identity().node_id().clone());
        self.protection
            .clone()
            .ok_or(NodeHostReadError::Unavailable)
    }
}

impl NodeHostServiceReadPort for MockHostReadPorts {
    // Records the exact host and returns the configured Gateway observation.
    fn gateway(&self, node: &Node) -> Result<Option<NodeHostGatewaySummary>, NodeHostReadError> {
        self.gateway_nodes
            .lock()
            .expect("Gateway nodes")
            .push(node.identity().node_id().clone());
        self.gateway.clone().ok_or(NodeHostReadError::Unavailable)
    }

    // Records the exact host and returns the configured Watchdog observation.
    fn watchdog(&self, node: &Node) -> Result<Option<NodeHostWatchdogSummary>, NodeHostReadError> {
        self.watchdog_nodes
            .lock()
            .expect("Watchdog nodes")
            .push(node.identity().node_id().clone());
        self.watchdog.clone().ok_or(NodeHostReadError::Unavailable)
    }
}

// Returns one canonical repeated identity of the requested width.
fn identity(character: char, length: usize) -> String {
    character.to_string().repeat(length)
}

// Returns one coherent immutable timestamp fixture.
fn timestamps() -> EntityTimestamps {
    EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(1_000))
        .expect("timestamps")
}

// Returns one coherent node fixture with globally distinct stable identities.
fn node(character: char, name: &str, role: NodeRole, state: NodeState, address: &str) -> Node {
    let machine_character =
        char::from_digit(character.to_digit(16).expect("hex") + 1, 16).expect("machine character");
    let installation_character = char::from_digit(character.to_digit(16).expect("hex") + 2, 16)
        .expect("installation character");
    Node::new(
        NodeIdentity::new(
            NodeId::parse(&identity(character, 32)).expect("node"),
            MachineId::parse(&identity(machine_character, 32)).expect("machine"),
            InstallationId::parse(&identity(installation_character, 64)).expect("installation"),
        ),
        DisplayName::parse(name).expect("display name"),
        role,
        state,
        NodeAddress::parse(address).expect("address"),
        None,
        timestamps(),
    )
}

// Returns the ordinary active local main fixture.
fn main_node() -> Node {
    node(
        '1',
        "Home AI",
        NodeRole::Main,
        NodeState::Active,
        "homeai.local",
    )
}

// Returns one ordinary pending child fixture.
fn child_node(character: char, name: &str, address: &str) -> Node {
    node(
        character,
        name,
        NodeRole::Child,
        NodeState::Pending,
        address,
    )
}

// Opens one isolated database with deterministic native dependencies.
fn database(directory: &tempfile::TempDir) -> Arc<DatabaseManager> {
    Arc::new(
        DatabaseManager::open(
            DatabaseConfiguration::new(directory.path().join("core.sqlite3"))
                .with_busy_timeout(Duration::from_secs(1))
                .with_clock(Arc::new(TestClock(AtomicI64::new(10_000)))),
        )
        .expect("database manager"),
    )
}

// Opens one local manager and returns its initial optimistic node revision.
fn manager(directory: &tempfile::TempDir) -> (NodeManager, u64) {
    let (manager, initialized) =
        NodeManager::open(database(directory), main_node(), "initialize-node")
            .expect("node manager");
    (manager, initialized.revision())
}

// Returns one current hardware snapshot for the local node.
fn hardware(node_id: NodeId) -> HardwareObservation {
    HardwareObservation::new(
        HardwareObservationId::parse(&identity('d', 32)).expect("hardware observation"),
        node_id,
        BootId::parse("boot-fixture").expect("boot"),
        PlatformIdentity::new(OperatingSystem::Linux, CpuArchitecture::Arm64),
        ProcessorObservation::new(DisplayName::parse("NVIDIA Grace").expect("CPU"), 20)
            .expect("processor"),
        ByteCount::new(128 * 1024 * 1024 * 1024).expect("memory"),
        Vec::new(),
        Vec::new(),
        UnixMilliseconds::new(2_000),
    )
    .expect("hardware")
}

// Returns one sealed model-neutral runtime identity for placement fixtures.
fn runtime_identity() -> RuntimeIdentity {
    RuntimeIdentity::new(
        RuntimeCandidateId::parse("engine--owner--model--target").expect("candidate"),
        RuntimeVersion::parse("1.0.0").expect("version"),
        TargetId::parse("target").expect("target"),
        RuntimeSource::parse(&format!(
            "ghcr.io/letsinferlabs/runtime@sha256:{}",
            identity('a', 64)
        ))
        .expect("runtime source"),
        EngineDistribution::oci(
            RuntimeSource::parse(&format!(
                "ghcr.io/letsinferlabs/engine@sha256:{}",
                identity('b', 64)
            ))
            .expect("Engine source"),
            Sha256Digest::parse(&identity('b', 64)).expect("Engine identity"),
            None,
            None,
        ),
        Sha256Digest::parse(&identity('a', 64)).expect("runtime digest"),
        Sha256Digest::parse(&identity('c', 64)).expect("manifest digest"),
        Sha256Digest::parse(&identity('d', 64)).expect("execution digest"),
    )
    .expect("runtime identity")
}

// Returns one complete stopped placement aggregate over the supplied authenticated nodes.
fn placement_record(
    group_character: char,
    service_character: char,
    nodes: &[Node],
) -> PlacementRecord {
    let group_number =
        usize::try_from(group_character.to_digit(16).expect("group hex")).expect("group number");
    let group_id = PlacementGroupId::parse(&identity(group_character, 32)).expect("group");
    let placement_ids = (0..nodes.len())
        .map(|index| {
            PlacementId::parse(&format!("{}{:x}", identity(group_character, 31), index))
                .expect("placement")
        })
        .collect::<Vec<_>>();
    let mut leases = Vec::new();
    let placements = nodes
        .iter()
        .enumerate()
        .map(|(index, node)| {
            let port = 18_000 + u16::try_from(group_number * 100 + index).expect("port index");
            let device =
                DeviceId::parse(&format!("GPU-{group_character}-{index}")).expect("device");
            let placement = Placement::new(
                placement_ids[index].clone(),
                group_id.clone(),
                PlacementAssignment::new(
                    node.identity().node_id().clone(),
                    RuntimeInstallationId::parse(&format!(
                        "{:032x}",
                        group_number * 100 + index + 1
                    ))
                    .expect("runtime installation"),
                    HardwareObservationId::parse(&format!(
                        "{:032x}",
                        group_number * 100 + index + 50
                    ))
                    .expect("hardware observation"),
                    BootId::parse(&format!("boot-{group_character}-{index}")).expect("boot"),
                    UnixMilliseconds::new(900),
                    TaskId::parse(&format!("task-{index}")).expect("task"),
                    node.control_address().clone(),
                    PlacementResources::new(
                        PortRange::new(port, 1).expect("ports"),
                        vec![device.clone()],
                        None,
                    )
                    .expect("resources"),
                    if index == 0 {
                        EndpointOwnership::Owner
                    } else {
                        EndpointOwnership::Participant
                    },
                ),
                PlacementState::Stopped,
                None,
                None,
                timestamps(),
            )
            .expect("placement");
            for (resource_index, resource) in [
                ResourceIdentity::Accelerator(device),
                ResourceIdentity::Port(NetworkPort::new(port).expect("port")),
            ]
            .into_iter()
            .enumerate()
            {
                leases.push(ResourceLease::new(
                    ResourceLeaseId::parse(&format!(
                        "{:032x}",
                        group_number * 1_000 + index * 10 + resource_index
                    ))
                    .expect("lease"),
                    placement_ids[index].clone(),
                    node.identity().node_id().clone(),
                    resource,
                    ResourceLeaseState::Reserved,
                    timestamps(),
                ));
            }
            placement
        })
        .collect::<Vec<_>>();
    let group = PlacementGroup::new(
        group_id,
        ModelServiceId::parse(&identity(service_character, 32)).expect("service"),
        runtime_identity(),
        placement_ids.clone(),
        placement_ids[0].clone(),
        None,
        PlacementGroupCapacity::new(
            8,
            4,
            262_144,
            InterconnectRequirement::new(InterconnectKind::Any, false, 0, 0),
        )
        .expect("capacity"),
        ModelServiceDesiredState::Stopped,
        PlacementGroupState::Stopped,
        None,
        timestamps(),
    )
    .expect("placement group");
    PlacementRecord::new(
        group,
        placements,
        leases,
        vec![placement_ids.clone()],
        placement_ids
            .into_iter()
            .map(|placement_id| {
                (
                    placement_id,
                    Sha256Digest::parse(&identity('e', 64)).expect("launch plan"),
                )
            })
            .collect(),
    )
    .expect("placement record")
}

// Returns one verified current link fixture between two exact nodes.
fn link(left: &Node, right: &Node) -> PlacementLink {
    PlacementLink::new(
        left.identity().node_id().clone(),
        right.identity().node_id().clone(),
        InterconnectKind::Connectx,
        true,
        200_000,
        1_500,
    )
    .expect("link")
}

// Adapts one shared deterministic mock to every explicit host read port.
fn projection_ports(mock: Arc<MockHostReadPorts>) -> NodeHostProjectionPorts {
    NodeHostProjectionPorts::new(mock.clone(), mock.clone(), mock.clone(), mock)
}

// Assembles every available section and filters unrelated placement and topology state.
#[test]
fn host_projection_assembles_one_complete_truthful_snapshot() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (manager, revision) = manager(&directory);
    let main = manager.local_node().expect("main");
    let child = child_node('4', "Child", "child.local");
    let sibling = child_node('7', "Sibling", "sibling.local");
    manager
        .enroll_child("enroll-child", child.clone())
        .expect("child");
    manager
        .enroll_child("enroll-sibling", sibling.clone())
        .expect("sibling");
    let hardware = hardware(main.identity().node_id().clone());
    manager
        .record_local_hardware_observation("record-hardware", revision, hardware.clone())
        .expect("record hardware");
    let selected_record = placement_record('8', 'a', &[main.clone(), child.clone()]);
    let unrelated_record = placement_record('9', 'b', &[child.clone(), sibling.clone()]);
    let selected_link = link(&main, &child);
    let mock = Arc::new(MockHostReadPorts::complete(
        vec![unrelated_record, selected_record.clone()],
        vec![link(&child, &sibling), selected_link.clone()],
    ));
    let projection = manager
        .host_projection(main.identity().node_id(), &projection_ports(mock.clone()))
        .expect("projection");

    assert_eq!(projection.node().identity(), main.identity());
    assert_eq!(projection.hardware(), Some(&hardware));
    let groups = projection
        .placement_groups()
        .available()
        .expect("placement groups");
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].group(), selected_record.group());
    assert_eq!(groups[0].placements(), selected_record.placements());
    assert_eq!(
        projection
            .verified_links()
            .available()
            .expect("verified links"),
        &[selected_link]
    );
    assert_eq!(
        projection
            .protection()
            .available()
            .expect("protection")
            .state(),
        NodeHostProtectionState::Ready
    );
    let gateway = projection.gateway().available().expect("Gateway");
    assert_eq!(gateway.state(), NodeHostServiceState::Ready);
    assert_eq!(
        gateway
            .telemetry()
            .expect("Gateway telemetry")
            .active_requests(),
        2
    );
    let watchdog = projection.watchdog().available().expect("Watchdog");
    assert_eq!(watchdog.state(), NodeHostServiceState::Ready);
    assert_eq!(
        watchdog
            .telemetry()
            .expect("Watchdog telemetry")
            .gpu_percent(),
        Some(30)
    );
    assert_eq!(mock.placement_calls.load(Ordering::SeqCst), 1);
    assert_eq!(mock.topology_calls.load(Ordering::SeqCst), 1);
}

// Preserves useful durable state while each unavailable or inapplicable live section stays typed.
#[test]
fn host_projection_preserves_partial_and_unavailable_sections() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (manager, _) = manager(&directory);
    let main = manager.local_node().expect("main");
    let mock = Arc::new(MockHostReadPorts {
        placements: None,
        links: None,
        protection: Some(Some(NodeHostProtectionSummary::new(
            NodeHostProtectionState::Ready,
            UnixMilliseconds::new(4_000),
        ))),
        gateway: None,
        watchdog: Some(None),
        placement_calls: AtomicUsize::new(0),
        topology_calls: AtomicUsize::new(0),
        protection_nodes: Mutex::new(Vec::new()),
        gateway_nodes: Mutex::new(Vec::new()),
        watchdog_nodes: Mutex::new(Vec::new()),
    });
    let projection = manager
        .host_projection(main.identity().node_id(), &projection_ports(mock.clone()))
        .expect("partial projection");

    assert_eq!(projection.node().identity(), main.identity());
    assert!(projection.hardware().is_none());
    assert!(projection.placement_groups().is_unavailable());
    assert!(projection.verified_links().is_unavailable());
    assert!(projection.protection().is_unavailable());
    assert!(projection.gateway().is_unavailable());
    assert!(projection.watchdog().is_not_applicable());
    assert!(mock
        .protection_nodes
        .lock()
        .expect("protection nodes")
        .is_empty());
}

// Restricts a child projection to groups and verified links that contain that exact child.
#[test]
fn host_projection_enforces_child_visibility_without_losing_group_membership() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (manager, _) = manager(&directory);
    let main = manager.local_node().expect("main");
    let child = child_node('4', "Child", "child.local");
    let sibling = child_node('7', "Sibling", "sibling.local");
    manager
        .enroll_child("enroll-child", child.clone())
        .expect("child");
    manager
        .enroll_child("enroll-sibling", sibling.clone())
        .expect("sibling");
    let child_record = placement_record('8', 'a', &[main.clone(), child.clone()]);
    let unrelated_record = placement_record('9', 'b', &[main.clone(), sibling.clone()]);
    let child_link = link(&main, &child);
    let mock = Arc::new(MockHostReadPorts::complete(
        vec![unrelated_record, child_record.clone()],
        vec![link(&main, &sibling), child_link.clone()],
    ));
    let projection = manager
        .host_projection(child.identity().node_id(), &projection_ports(mock.clone()))
        .expect("child projection");

    assert_eq!(projection.node().role(), NodeRole::Child);
    assert!(projection.hardware().is_none());
    let groups = projection
        .placement_groups()
        .available()
        .expect("placement groups");
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].group(), child_record.group());
    assert_eq!(groups[0].placements(), child_record.placements());
    assert_eq!(
        projection
            .verified_links()
            .available()
            .expect("verified links"),
        &[child_link]
    );
    for observed in [
        &mock.protection_nodes,
        &mock.gateway_nodes,
        &mock.watchdog_nodes,
    ] {
        assert_eq!(
            observed.lock().expect("observed nodes").as_slice(),
            &[child.identity().node_id().clone()]
        );
    }
}

// Reconstructs an identical read after restart without mutating durable or injected state.
#[test]
fn host_projection_is_restart_and_replay_stable() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (manager, revision) = manager(&directory);
    let main = manager.local_node().expect("main");
    manager
        .record_local_hardware_observation(
            "record-hardware",
            revision,
            hardware(main.identity().node_id().clone()),
        )
        .expect("record hardware");
    let mock = Arc::new(MockHostReadPorts::complete(
        vec![placement_record('8', 'a', std::slice::from_ref(&main))],
        Vec::new(),
    ));
    let ports = projection_ports(mock.clone());
    let first = manager
        .host_projection(main.identity().node_id(), &ports)
        .expect("first projection");
    manager.close().expect("close manager");

    let manager = NodeManager::load(database(&directory)).expect("reload manager");
    let second = manager
        .host_projection(main.identity().node_id(), &ports)
        .expect("replayed projection");
    assert_eq!(second, first);
    assert_eq!(mock.placement_calls.load(Ordering::SeqCst), 2);
    assert_eq!(mock.topology_calls.load(Ordering::SeqCst), 2);
}
