// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use li_benchmark_manager::{BenchmarkError, BenchmarkScope};
use li_core_application::ApplicationBenchmarkRequestProvider;
use li_core_interface::{
    ArtifactName, ArtifactRevision, ArtifactUri, BootId, DeviceId, DisplayName, EndpointOwnership,
    EngineDistribution, EntityTimestamps, EvidenceLabel, HardwareObservationId, InstallationId,
    InterconnectKind, InterconnectRequirement, LogicalModelName, MachineId, ModelArtifact,
    ModelArtifactFormat, ModelService, ModelServiceDesiredState, ModelServiceId, NetworkPort, Node,
    NodeAddress, NodeId, NodeIdentity, NodeRole, NodeState, Placement, PlacementGroup,
    PlacementGroupCapacity, PlacementGroupId, PlacementGroupState, PlacementId, PlacementResources,
    PlacementState, PortRange, ResourceIdentity, ResourceLease, ResourceLeaseId,
    ResourceLeaseState, RuntimeCandidateId, RuntimeIdentity, RuntimeInstallation,
    RuntimeInstallationId, RuntimeInstallationState, RuntimeSource, RuntimeVersion, Sha256Digest,
    TargetId, TaskId, TechnicalName, UnixMilliseconds,
};
use li_database::{DatabaseConfiguration, DatabaseManager};
use li_node_manager::{
    NodeBenchmarkContext, NodeBenchmarkRequestProvider, NodeBenchmarkSelection, NodeManager,
};
use li_placement_manager::{
    PlacementError, PlacementRecord, PlacementStore, VersionedPlacementRecord,
};
use li_runtime_manager::{
    RuntimeBenchmarkContract, RuntimeCatalogProvider, RuntimeError, RuntimeExecutionContainer,
    RuntimeExecutionDistribution, RuntimeExecutionImageReference, RuntimeExecutionManifest,
    RuntimeExecutionManifestProvider, RuntimeExecutionPlatform, RuntimeExecutionReadiness,
    RuntimeExecutionServing, RuntimeExecutionTask, RuntimeInstallationStore, RuntimeManager,
    RuntimeTaskLauncher, VersionedRuntimeInstallation,
};
use sha2::{Digest, Sha256};

// Supplies no catalog candidates because request resolution uses only installed manager state.
struct EmptyCatalog;

impl RuntimeCatalogProvider for EmptyCatalog {
    // Rejects accidental catalog selection from the local benchmark resolver.
    fn candidates(
        &self,
        _model: &LogicalModelName,
    ) -> Result<Vec<li_runtime_manager::RuntimeCandidate>, RuntimeError> {
        Err(RuntimeError::CatalogUnavailable)
    }
}

// Stores deterministic runtime snapshots while leaving mutation owned by RuntimeManager tests.
#[derive(Default)]
struct RuntimeStoreMock {
    installations: Mutex<BTreeMap<String, VersionedRuntimeInstallation>>,
}

impl RuntimeStoreMock {
    // Replaces the exact fixture installation visible to the resolver.
    fn set(&self, installation: RuntimeInstallation) {
        self.installations.lock().expect("installations").insert(
            installation.installation_id().as_str().to_string(),
            VersionedRuntimeInstallation::new(installation, 1),
        );
    }

    // Removes one fixture installation to exercise absence.
    fn remove(&self, installation_id: &RuntimeInstallationId) {
        self.installations
            .lock()
            .expect("installations")
            .remove(installation_id.as_str());
    }
}

impl RuntimeInstallationStore for RuntimeStoreMock {
    // Returns one exact fixture installation without deriving a fallback.
    fn read(
        &self,
        installation_id: &RuntimeInstallationId,
    ) -> Result<Option<VersionedRuntimeInstallation>, RuntimeError> {
        Ok(self
            .installations
            .lock()
            .expect("installations")
            .get(installation_id.as_str())
            .cloned())
    }

    // Returns every fixture installation in canonical identity order.
    fn all(&self) -> Result<Vec<VersionedRuntimeInstallation>, RuntimeError> {
        Ok(self
            .installations
            .lock()
            .expect("installations")
            .values()
            .cloned()
            .collect())
    }

    // Rejects lifecycle mutation outside this read-only resolver fixture.
    fn create(
        &self,
        _installation: RuntimeInstallation,
    ) -> Result<VersionedRuntimeInstallation, RuntimeError> {
        Err(RuntimeError::StoreUnavailable)
    }

    // Rejects lifecycle replacement outside this read-only resolver fixture.
    fn replace(
        &self,
        _installation: RuntimeInstallation,
        _expected_revision: u64,
    ) -> Result<VersionedRuntimeInstallation, RuntimeError> {
        Err(RuntimeError::StoreUnavailable)
    }

    // Rejects lifecycle deletion outside this read-only resolver fixture.
    fn delete(
        &self,
        _installation_id: &RuntimeInstallationId,
        _expected_revision: u64,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::StoreUnavailable)
    }
}

// Stores deterministic placement aggregates in exact group identity order.
#[derive(Default)]
struct PlacementStoreMock {
    records: Mutex<BTreeMap<String, VersionedPlacementRecord>>,
}

impl PlacementStoreMock {
    // Replaces one exact aggregate visible to the resolver.
    fn set(&self, record: PlacementRecord) {
        self.records.lock().expect("records").insert(
            record.group().placement_group_id().as_str().to_string(),
            VersionedPlacementRecord::new(record, 1),
        );
    }
}

impl PlacementStore for PlacementStoreMock {
    // Rejects resource discovery outside this read-only resolver fixture.
    fn occupied_resources(
        &self,
        _node_id: &NodeId,
    ) -> Result<Vec<ResourceIdentity>, PlacementError> {
        Err(PlacementError::StoreUnavailable)
    }

    // Rejects placement creation outside this read-only resolver fixture.
    fn create(&self, _record: PlacementRecord) -> Result<VersionedPlacementRecord, PlacementError> {
        Err(PlacementError::StoreUnavailable)
    }

    // Returns one exact fixture aggregate without discovering another group.
    fn read(
        &self,
        placement_group_id: &PlacementGroupId,
    ) -> Result<Option<VersionedPlacementRecord>, PlacementError> {
        Ok(self
            .records
            .lock()
            .expect("records")
            .get(placement_group_id.as_str())
            .cloned())
    }

    // Rejects placement replacement outside this read-only resolver fixture.
    fn replace(
        &self,
        _record: PlacementRecord,
        _expected_revision: u64,
    ) -> Result<VersionedPlacementRecord, PlacementError> {
        Err(PlacementError::StoreUnavailable)
    }
}

// Stores deterministic verified execution projections by exact installation identity.
#[derive(Default)]
struct ManifestMock {
    manifests: Mutex<BTreeMap<String, RuntimeExecutionManifest>>,
}

impl ManifestMock {
    // Replaces one exact execution projection visible through RuntimeManager.
    fn set(&self, manifest: RuntimeExecutionManifest) {
        self.manifests
            .lock()
            .expect("manifests")
            .insert(manifest.installation_id().as_str().to_string(), manifest);
    }

    // Removes one exact execution projection to exercise manifest absence.
    fn remove(&self, installation_id: &RuntimeInstallationId) {
        self.manifests
            .lock()
            .expect("manifests")
            .remove(installation_id.as_str());
    }
}

impl RuntimeExecutionManifestProvider for ManifestMock {
    // Returns only the exact configured verified execution projection.
    fn manifest(
        &self,
        installation_id: &RuntimeInstallationId,
    ) -> Result<RuntimeExecutionManifest, RuntimeError> {
        self.manifests
            .lock()
            .expect("manifests")
            .get(installation_id.as_str())
            .cloned()
            .ok_or(RuntimeError::ExecutionManifestUnavailable)
    }
}

// Retains one complete resolver graph and its mutable deterministic provider ports.
struct Fixture {
    _directory: tempfile::TempDir,
    provider: ApplicationBenchmarkRequestProvider,
    runtime_store: Arc<RuntimeStoreMock>,
    placement_store: Arc<PlacementStoreMock>,
    manifests: Arc<ManifestMock>,
    first_installation_id: RuntimeInstallationId,
    first_group_id: PlacementGroupId,
}

// Returns one repeated lowercase fixture identity.
fn identity(character: char, count: usize) -> String {
    character.to_string().repeat(count)
}

// Returns one canonical fixture digest.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&identity(character, 64)).expect("digest")
}

// Returns the SHA-256 of exact benchmark contract bytes.
fn bytes_digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::parse(&format!("{:x}", Sha256::digest(bytes))).expect("digest")
}

// Returns one complete active-main local Node identity.
fn local_node() -> Node {
    Node::new(
        NodeIdentity::new(
            NodeId::parse(&identity('1', 32)).expect("node"),
            MachineId::parse(&identity('2', 32)).expect("machine"),
            InstallationId::parse(&identity('3', 64)).expect("Core installation"),
        ),
        DisplayName::parse("Home AI").expect("display name"),
        NodeRole::Main,
        NodeState::Active,
        NodeAddress::parse("homeai.local:9770").expect("address"),
        None,
        timestamps(),
    )
}

// Returns one stable fixture timestamp pair.
fn timestamps() -> EntityTimestamps {
    EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(1_000))
        .expect("timestamps")
}

// Returns one sealed runtime identity shared by installation and placement fixtures.
fn runtime_identity(execution_character: char) -> RuntimeIdentity {
    let engine_reference = RuntimeSource::parse(&format!(
        "ghcr.io/letsinferlabs/engine-images@sha256:{}",
        identity('4', 64)
    ))
    .expect("Engine reference");
    RuntimeIdentity::new(
        RuntimeCandidateId::parse("engine--owner--model--target").expect("candidate"),
        RuntimeVersion::parse("1.0.0").expect("version"),
        TargetId::parse("fixture-target").expect("target"),
        RuntimeSource::parse(&format!(
            "ghcr.io/letsinferlabs/runtime-artifacts@sha256:{}",
            identity('5', 64)
        ))
        .expect("runtime source"),
        EngineDistribution::oci(engine_reference, digest('6'), None, Some(digest('7'))),
        digest('8'),
        digest('9'),
        digest(execution_character),
    )
    .expect("runtime identity")
}

// Returns one runtime installation in the requested lifecycle state.
fn installation(
    installation_id: RuntimeInstallationId,
    node_id: NodeId,
    model: &str,
    runtime: RuntimeIdentity,
    state: RuntimeInstallationState,
) -> RuntimeInstallation {
    RuntimeInstallation::new(
        installation_id,
        node_id,
        LogicalModelName::parse(model).expect("model"),
        runtime,
        vec![ModelArtifact::new(
            ArtifactName::parse("model").expect("artifact name"),
            ArtifactUri::parse("hf://Owner/Model").expect("artifact URI"),
            ArtifactRevision::parse(&identity('a', 40)).expect("artifact revision"),
            ModelArtifactFormat::HuggingFaceSnapshot,
        )],
        EvidenceLabel::Unknown,
        state,
        None,
        timestamps(),
    )
    .expect("installation")
}

// Returns one complete stopped aggregate with one canonical task assignment.
fn placement_record(
    group_id: PlacementGroupId,
    service_id: ModelServiceId,
    installation: &RuntimeInstallation,
) -> PlacementRecord {
    let placement_id = PlacementId::parse(&identity('b', 32)).expect("placement");
    let device_id = DeviceId::parse("GPU-fixture").expect("device");
    let ports = PortRange::new(18_000, 1).expect("ports");
    let placement = Placement::new(
        placement_id.clone(),
        group_id.clone(),
        li_core_interface::PlacementAssignment::new(
            installation.node_id().clone(),
            installation.installation_id().clone(),
            HardwareObservationId::parse(&identity('c', 32)).expect("observation"),
            BootId::parse("boot-fixture").expect("boot"),
            UnixMilliseconds::new(1_000),
            TaskId::parse("task-0").expect("task"),
            NodeAddress::parse("homeai.local").expect("address"),
            PlacementResources::new(ports, vec![device_id.clone()], None).expect("resources"),
            EndpointOwnership::Owner,
        ),
        PlacementState::Stopped,
        None,
        None,
        timestamps(),
    )
    .expect("placement");
    let group = PlacementGroup::new(
        group_id,
        service_id,
        installation.runtime().clone(),
        vec![placement_id.clone()],
        placement_id.clone(),
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
    .expect("group");
    let leases = [
        ResourceIdentity::Accelerator(device_id),
        ResourceIdentity::Port(NetworkPort::new(18_000).expect("port")),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, resource)| {
        ResourceLease::new(
            ResourceLeaseId::parse(&format!("{:032x}", index + 1)).expect("lease"),
            placement_id.clone(),
            installation.node_id().clone(),
            resource,
            ResourceLeaseState::Reserved,
            timestamps(),
        )
    })
    .collect();
    PlacementRecord::new(
        group,
        vec![placement],
        leases,
        vec![vec![placement_id.clone()]],
        vec![(placement_id, digest('d'))],
    )
    .expect("placement record")
}

// Returns one verified execution projection with an optional benchmark contract.
fn manifest(
    installation_id: RuntimeInstallationId,
    model: &str,
    cells: Option<&[&str]>,
) -> RuntimeExecutionManifest {
    let task = RuntimeExecutionTask::new(
        TaskId::parse("task-0").expect("task"),
        RuntimeTaskLauncher::Manifest,
        Vec::new(),
        1,
        1,
        true,
        RuntimeExecutionReadiness::Manifest,
    )
    .expect("task");
    let reference = RuntimeSource::parse(&format!(
        "ghcr.io/letsinferlabs/engine-images@sha256:{}",
        identity('4', 64)
    ))
    .expect("reference");
    let manifest = RuntimeExecutionManifest::new(
        installation_id,
        LogicalModelName::parse(model).expect("model"),
        RuntimeExecutionPlatform::LinuxArm64,
        TechnicalName::parse("engine").expect("engine"),
        RuntimeExecutionDistribution::Oci {
            identity_reference: reference.clone(),
            execution_reference: RuntimeExecutionImageReference::distribution(&reference),
            immutable_id: digest('6'),
        },
        Vec::new(),
        Vec::new(),
        "fixture-cache".to_string(),
        true,
        RuntimeExecutionContainer::new(
            64 * 1024 * 1024 * 1024,
            8 * 1024 * 1024 * 1024,
            Duration::from_secs(900),
            Some("0-7".to_string()),
        )
        .expect("container"),
        RuntimeExecutionServing::new(8, 4, 262_144, "/v1/letsinfer/token-count".to_string())
            .expect("serving"),
        PathBuf::from("/managed/runtime"),
        PathBuf::from("/managed/model"),
        PathBuf::from("/managed/engine"),
        PathBuf::from("/managed/cache"),
        vec![task],
        vec![vec![TaskId::parse("task-0").expect("task")]],
    )
    .expect("manifest");
    let Some(cells) = cells else {
        return manifest;
    };
    let document = b"{\"schema_version\":8}\n".to_vec();
    manifest.with_benchmark(
        RuntimeBenchmarkContract::new(
            bytes_digest(&document),
            digest('e'),
            document,
            cells
                .iter()
                .map(|cell| TechnicalName::parse(cell).expect("cell"))
                .collect(),
        )
        .expect("benchmark contract"),
    )
}

// Opens one complete manager-backed resolver fixture with two ordered placement groups.
fn fixture(cells: &[&str]) -> Fixture {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database = Arc::new(
        DatabaseManager::open(DatabaseConfiguration::new(
            directory.path().join("core.sqlite3"),
        ))
        .expect("database"),
    );
    let node = Arc::new(
        NodeManager::open(database, local_node(), "initialize-node")
            .expect("node")
            .0,
    );
    let model = LogicalModelName::parse("fixture-model").expect("model");
    let service = ModelService::new(
        ModelServiceId::parse(&identity('f', 32)).expect("service"),
        model,
        ModelServiceDesiredState::Stopped,
        Vec::new(),
        timestamps(),
    )
    .expect("service");
    let created = node
        .create_model_service("create-service", service.clone())
        .expect("create service");
    let first_group_id = PlacementGroupId::parse(&identity('1', 32)).expect("first group");
    let second_group_id = PlacementGroupId::parse(&identity('2', 32)).expect("second group");
    let first_attached = node
        .attach_placement_group(
            "attach-first",
            service.service_id(),
            first_group_id.clone(),
            created.revision(),
            UnixMilliseconds::new(2_000),
        )
        .expect("attach first");
    node.attach_placement_group(
        "attach-second",
        service.service_id(),
        second_group_id.clone(),
        first_attached.revision(),
        UnixMilliseconds::new(3_000),
    )
    .expect("attach second");

    let runtime_store = Arc::new(RuntimeStoreMock::default());
    let placement_store = Arc::new(PlacementStoreMock::default());
    let manifests = Arc::new(ManifestMock::default());
    let first_installation_id =
        RuntimeInstallationId::parse(&identity('3', 32)).expect("first installation");
    let second_installation_id =
        RuntimeInstallationId::parse(&identity('4', 32)).expect("second installation");
    let first_installation = installation(
        first_installation_id.clone(),
        NodeId::parse(&identity('1', 32)).expect("node"),
        "fixture-model",
        runtime_identity('a'),
        RuntimeInstallationState::Available,
    );
    let second_installation = installation(
        second_installation_id.clone(),
        NodeId::parse(&identity('2', 32)).expect("node"),
        "fixture-model",
        runtime_identity('b'),
        RuntimeInstallationState::Available,
    );
    runtime_store.set(first_installation.clone());
    runtime_store.set(second_installation.clone());
    placement_store.set(placement_record(
        first_group_id.clone(),
        service.service_id().clone(),
        &first_installation,
    ));
    placement_store.set(placement_record(
        second_group_id,
        service.service_id().clone(),
        &second_installation,
    ));
    manifests.set(manifest(
        first_installation_id.clone(),
        "fixture-model",
        Some(cells),
    ));
    manifests.set(manifest(
        second_installation_id,
        "fixture-model",
        Some(cells),
    ));
    let runtime = Arc::new(
        RuntimeManager::new(Arc::new(EmptyCatalog)).with_execution_provider(manifests.clone()),
    );
    let provider = ApplicationBenchmarkRequestProvider::new(
        node,
        runtime,
        runtime_store.clone(),
        placement_store.clone(),
    );
    Fixture {
        _directory: directory,
        provider,
        runtime_store,
        placement_store,
        manifests,
        first_installation_id,
        first_group_id,
    }
}

// Returns one public selection for the fixture logical model.
fn selection(
    concurrencies: Vec<u16>,
    contexts: Vec<NodeBenchmarkContext>,
) -> NodeBenchmarkSelection {
    NodeBenchmarkSelection::new(
        LogicalModelName::parse("fixture-model").expect("model"),
        concurrencies,
        contexts,
    )
    .expect("selection")
}

// Proves complete resolution binds the local Core and first canonical service assignments.
#[test]
fn application_request_provider_resolves_complete_canonical_manager_state() {
    let cells = [
        "short-code-c1",
        "short-prose-c1",
        "ttftcold-code-c1",
        "ttftwarm-code-c1",
        "32k-code-c1",
        "64k-code-c2",
    ];
    let fixture = fixture(&cells);
    let plan = fixture
        .provider
        .resolve(&selection(Vec::new(), Vec::new()))
        .expect("plan");
    assert_eq!(plan.declared_cells(), plan.selected_cells());
    assert!(matches!(plan.request().scope(), BenchmarkScope::Complete));
    assert_eq!(
        plan.request().subject().installation_id().as_str(),
        identity('3', 64)
    );
    assert_eq!(
        plan.request().subject().runtime_installation_id(),
        &fixture.first_installation_id
    );
    assert_eq!(
        plan.request().subject().placement_group_id(),
        &fixture.first_group_id
    );
    assert_eq!(
        plan.selected_cells()
            .iter()
            .map(TechnicalName::as_str)
            .collect::<Vec<_>>(),
        cells
    );
}

// Proves selected context and concurrency axes form a signed-order cross-product only.
#[test]
fn application_request_provider_filters_the_exact_selected_cross_product() {
    let fixture = fixture(&[
        "short-code-c1",
        "short-prose-c4",
        "ttftcold-code-c1",
        "ttftwarm-code-c1",
        "32k-code-c1",
        "32k-prose-c2",
        "32k-prose-c4",
        "64k-code-c4",
        "64k-prose-c1",
        "128k-code-c1",
    ]);
    let plan = fixture
        .provider
        .resolve(&selection(
            vec![1, 4],
            vec![
                NodeBenchmarkContext::Context32k,
                NodeBenchmarkContext::Context64k,
            ],
        ))
        .expect("plan");
    let selected = ["32k-code-c1", "32k-prose-c4", "64k-code-c4", "64k-prose-c1"];
    assert_eq!(
        plan.selected_cells()
            .iter()
            .map(TechnicalName::as_str)
            .collect::<Vec<_>>(),
        selected
    );
    assert_eq!(
        plan.request().scope(),
        &BenchmarkScope::Selected(
            selected
                .iter()
                .map(|cell| TechnicalName::parse(cell).expect("cell"))
                .collect()
        )
    );
}

// Proves an uninstalled logical model fails before Placement or Runtime discovery.
#[test]
fn application_request_provider_rejects_an_absent_model() {
    let fixture = fixture(&["32k-code-c1"]);
    let selection = NodeBenchmarkSelection::new(
        LogicalModelName::parse("absent-model").expect("model"),
        Vec::new(),
        Vec::new(),
    )
    .expect("selection");
    assert_eq!(
        fixture.provider.resolve(&selection),
        Err(BenchmarkError::provider(
            "selection",
            "installed model is unavailable"
        ))
    );
}

// Proves missing or identity-divergent installation and manifest state always fails closed.
#[test]
fn application_request_provider_rejects_missing_and_incoherent_manager_state() {
    let fixture = fixture(&["32k-code-c1"]);
    let selection = selection(Vec::new(), Vec::new());
    fixture.runtime_store.remove(&fixture.first_installation_id);
    assert_eq!(
        fixture.provider.resolve(&selection),
        Err(BenchmarkError::provider(
            "selection",
            "runtime installation is unavailable"
        ))
    );

    let record = fixture
        .placement_store
        .read(&fixture.first_group_id)
        .expect("read")
        .expect("record");
    let assignment = &record.record().placements()[0].assignment();
    let staging = installation(
        fixture.first_installation_id.clone(),
        assignment.node_id().clone(),
        "fixture-model",
        record.record().group().runtime().clone(),
        RuntimeInstallationState::Staging,
    );
    fixture.runtime_store.set(staging);
    assert_eq!(
        fixture.provider.resolve(&selection),
        Err(BenchmarkError::provider(
            "selection",
            "runtime installation identity is inconsistent"
        ))
    );

    let divergent = installation(
        fixture.first_installation_id.clone(),
        assignment.node_id().clone(),
        "fixture-model",
        runtime_identity('c'),
        RuntimeInstallationState::Available,
    );
    fixture.runtime_store.set(divergent);
    assert_eq!(
        fixture.provider.resolve(&selection),
        Err(BenchmarkError::provider(
            "selection",
            "runtime installation identity is inconsistent"
        ))
    );

    let available = installation(
        fixture.first_installation_id.clone(),
        assignment.node_id().clone(),
        "fixture-model",
        record.record().group().runtime().clone(),
        RuntimeInstallationState::Available,
    );
    fixture.runtime_store.set(available);
    fixture.manifests.remove(&fixture.first_installation_id);
    assert_eq!(
        fixture.provider.resolve(&selection),
        Err(BenchmarkError::provider(
            "selection",
            "runtime execution manifest is unavailable"
        ))
    );

    fixture.manifests.set(manifest(
        fixture.first_installation_id.clone(),
        "different-model",
        Some(&["32k-code-c1"]),
    ));
    assert_eq!(
        fixture.provider.resolve(&selection),
        Err(BenchmarkError::provider(
            "selection",
            "runtime execution manifest identity is inconsistent"
        ))
    );

    fixture.manifests.set(manifest(
        fixture.first_installation_id.clone(),
        "fixture-model",
        None,
    ));
    assert_eq!(
        fixture.provider.resolve(&selection),
        Err(BenchmarkError::provider(
            "selection",
            "runtime benchmark contract is unsupported"
        ))
    );
}

// Proves a valid public axis combination still fails when the signed contract has no match.
#[test]
fn application_request_provider_rejects_an_empty_selected_workload() {
    let fixture = fixture(&["32k-code-c1"]);
    assert_eq!(
        fixture
            .provider
            .resolve(&selection(vec![4], vec![NodeBenchmarkContext::Context64k])),
        Err(BenchmarkError::provider(
            "selection",
            "benchmark workload selection is empty"
        ))
    );
}

// Proves a typed but out-of-contract signed cell cannot enter a local benchmark plan.
#[test]
fn application_request_provider_rejects_an_incoherent_manifest_cell() {
    let fixture = fixture(&["future-code-c1"]);
    assert_eq!(
        fixture.provider.resolve(&selection(Vec::new(), Vec::new())),
        Err(BenchmarkError::provider(
            "selection",
            "runtime benchmark cell identity is invalid"
        ))
    );
}
