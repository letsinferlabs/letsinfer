// SPDX-License-Identifier: AGPL-3.0-only

use li_core_interface::{
    Accelerator, AcceleratorMemory, AcceleratorVendor, ArtifactName, ArtifactRevision, ArtifactUri,
    BootId, ByteCount, ComputeCapability, CpuArchitecture, CredentialId, DeviceId, DisplayName,
    EndpointAddress, EndpointHealth, EndpointOwnership, EndpointScheme, EngineDistribution,
    EntityTimestamps, EvidenceLabel, FailureDescription, GgufFileIdentity, HardwareObservation,
    HardwareObservationId, InstallationId, InterconnectKind, InterconnectObservation,
    InterconnectObservationKind, InterconnectRequirement, LogicalModelName, MachineId,
    MemoryTopology, ModelArtifact, ModelArtifactFormat, ModelService, ModelServiceDesiredState,
    ModelServiceId, NetworkInterfaceName, NetworkPort, Node, NodeAddress, NodeId, NodeIdentity,
    NodeRole, NodeState, OperatingSystem, Operation, OperationId, OperationKind, OperationState,
    OperationTarget, Placement, PlacementAssignment, PlacementEndpoint, PlacementGroup,
    PlacementGroupCapacity, PlacementGroupId, PlacementGroupState, PlacementId, PlacementResources,
    PlacementState, PlatformIdentity, PortRange, ProcessorObservation, ResourceIdentity,
    ResourceLease, ResourceLeaseId, ResourceLeaseState, RuntimeCandidateId, RuntimeIdentity,
    RuntimeInstallation, RuntimeInstallationId, RuntimeInstallationState, RuntimeSource,
    RuntimeVersion, Sha256Digest, TargetId, TaskId, TechnicalName, TokenCountContract,
    TokenCountProtocol, UnixMilliseconds,
};

// Returns one canonical 32-character identity fixture.
fn identity(character: char) -> String {
    character.to_string().repeat(32)
}

// Returns one coherent timestamp fixture.
fn timestamps() -> EntityTimestamps {
    EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(2_000))
        .expect("timestamps")
}

// Returns one bounded failure fixture.
fn failure() -> FailureDescription {
    FailureDescription::new(
        TechnicalName::parse("fixture_failure").expect("failure code"),
        "Fixture failure",
    )
    .expect("failure")
}

// Returns one exact immutable runtime fixture.
fn runtime() -> RuntimeIdentity {
    RuntimeIdentity::new(
        RuntimeCandidateId::parse("sglang--radixark--qwen3.8--dgx-spark").expect("candidate"),
        RuntimeVersion::parse("1.0.0-rc.1").expect("version"),
        TargetId::parse("dgx-spark").expect("target"),
        RuntimeSource::parse(&format!(
            "ghcr.io/letsinferlabs/runtime@sha256:{}",
            "a".repeat(64)
        ))
        .expect("source"),
        EngineDistribution::oci(
            RuntimeSource::parse(&format!("ghcr.io/engine@sha256:{}", "9".repeat(64)))
                .expect("Engine source"),
            Sha256Digest::parse(&"8".repeat(64)).expect("Engine identity"),
            None,
            None,
        ),
        Sha256Digest::parse(&"b".repeat(64)).expect("runtime digest"),
        Sha256Digest::parse(&"c".repeat(64)).expect("manifest digest"),
        Sha256Digest::parse(&"d".repeat(64)).expect("execution digest"),
    )
    .expect("runtime identity")
}

// Returns one exact upstream model artifact fixture.
fn artifact(name: &str) -> ModelArtifact {
    ModelArtifact::new(
        ArtifactName::parse(name).expect("artifact name"),
        ArtifactUri::parse("hf://RadixArk/Qwen3.8").expect("artifact URI"),
        ArtifactRevision::parse(&"e".repeat(40)).expect("artifact revision"),
        ModelArtifactFormat::HuggingFaceSnapshot,
    )
}

// Preserves snapshot and exact-GGUF artifact formats without fabricated digests.
#[test]
fn model_artifact_formats_are_closed_and_validated() {
    assert!(matches!(
        artifact("model").format(),
        ModelArtifactFormat::HuggingFaceSnapshot
    ));
    let gguf = GgufFileIdentity::new(
        "model.gguf",
        Sha256Digest::parse(&"a".repeat(64)).expect("digest"),
        Some(1024),
    )
    .expect("GGUF");
    let artifact = ModelArtifact::new(
        ArtifactName::parse("gguf").expect("name"),
        ArtifactUri::parse("hf://Owner/Model").expect("URI"),
        ArtifactRevision::parse(&"b".repeat(40)).expect("revision"),
        ModelArtifactFormat::GgufFile(gguf),
    );
    assert!(matches!(
        artifact.format(),
        ModelArtifactFormat::GgufFile(_)
    ));
    assert!(GgufFileIdentity::new(
        "../model.gguf",
        Sha256Digest::parse(&"a".repeat(64)).expect("digest"),
        Some(1024),
    )
    .is_err());
}

// Returns one endpoint fixture owned by the selected placement.
fn endpoint(placement_id: PlacementId, max_active_requests: u32) -> PlacementEndpoint {
    PlacementEndpoint::new(
        placement_id,
        NodeId::parse(&identity('1')).expect("node"),
        EndpointAddress::new(
            EndpointScheme::Https,
            NodeAddress::parse("127.0.0.1").expect("endpoint host"),
            8_000,
        )
        .expect("endpoint address"),
        CredentialId::parse(&identity('2')).expect("credential"),
        Some(CredentialId::parse(&identity('3')).expect("CA credential")),
        Some(
            TokenCountContract::new("/v1/token-count", TokenCountProtocol::LetsInferV1)
                .expect("token count"),
        ),
        max_active_requests,
        32_768,
        EndpointHealth::new(
            true,
            false,
            Some(65_000),
            vec![TechnicalName::parse("prefix-a").expect("prefix")],
        )
        .expect("health"),
    )
    .expect("endpoint")
}

// Keeps logical, physical, and installed node identities separate in one snapshot.
#[test]
fn node_snapshot_preserves_distinct_identities() {
    let node = Node::new(
        NodeIdentity::new(
            NodeId::parse(&identity('1')).expect("node"),
            MachineId::parse(&identity('2')).expect("machine"),
            InstallationId::parse(&"3".repeat(64)).expect("installation"),
        ),
        DisplayName::parse("Home AI").expect("display name"),
        NodeRole::Main,
        NodeState::Active,
        NodeAddress::parse("homeai.local").expect("address"),
        Some(HardwareObservationId::parse(&identity('4')).expect("observation")),
        timestamps(),
    );
    assert_eq!(node.identity().node_id().as_str(), identity('1'));
    assert_eq!(node.identity().machine_id().as_str(), identity('2'));
    assert_eq!(node.identity().installation_id().as_str(), "3".repeat(64));
    assert_eq!(node.role(), NodeRole::Main);
    assert_eq!(node.state(), NodeState::Active);
}

// Distinguishes unified and discrete memory without inferring admission policy.
#[test]
fn accelerator_memory_requires_coherent_physical_topology() {
    assert!(AcceleratorMemory::new(MemoryTopology::Unified, None, None).is_ok());
    assert!(AcceleratorMemory::new(
        MemoryTopology::Discrete,
        Some(ByteCount::new(32 * 1024 * 1024 * 1024).expect("framebuffer")),
        None,
    )
    .is_ok());
    assert!(AcceleratorMemory::new(MemoryTopology::Discrete, None, None).is_err());
    assert!(AcceleratorMemory::new(
        MemoryTopology::Unified,
        Some(ByteCount::new(1024).expect("framebuffer")),
        None,
    )
    .is_err());
    let apple = Accelerator::new(
        DeviceId::parse("APPLE-fixture").expect("device"),
        AcceleratorVendor::Apple,
        DisplayName::parse("Apple M4 Max").expect("accelerator name"),
        AcceleratorMemory::new(MemoryTopology::Unified, None, None).expect("memory"),
        ComputeCapability::Metal {
            family: TechnicalName::parse("apple9").expect("family"),
            version: TechnicalName::parse("metal4").expect("Metal version"),
        },
    );
    assert_eq!(apple.vendor(), &AcceleratorVendor::Apple);
}

// Rejects a local runtime source that names different bytes than its identity.
#[test]
fn runtime_identity_rejects_a_changed_local_digest() {
    let source_digest = "a".repeat(64);
    assert!(RuntimeIdentity::new(
        RuntimeCandidateId::parse("sglang--radixark--qwen3.8--dgx-spark").expect("candidate"),
        RuntimeVersion::parse("1.0.0").expect("version"),
        TargetId::parse("dgx-spark").expect("target"),
        RuntimeSource::parse(&format!("letsinfer-object:sha256:{source_digest}")).expect("source"),
        EngineDistribution::oci(
            RuntimeSource::parse(&format!("ghcr.io/engine@sha256:{}", "9".repeat(64)))
                .expect("Engine source"),
            Sha256Digest::parse(&"8".repeat(64)).expect("Engine identity"),
            None,
            None,
        ),
        Sha256Digest::parse(&"b".repeat(64)).expect("runtime digest"),
        Sha256Digest::parse(&"c".repeat(64)).expect("manifest digest"),
        Sha256Digest::parse(&"d".repeat(64)).expect("execution digest"),
    )
    .is_err());
}

// Captures mutable topology in a boot-scoped observation and validates references.
#[test]
fn hardware_observation_rejects_duplicate_or_unknown_accelerators() {
    let device = DeviceId::parse("GPU-fixture").expect("device");
    let accelerator = Accelerator::new(
        device.clone(),
        AcceleratorVendor::Nvidia,
        DisplayName::parse("NVIDIA Fixture").expect("accelerator name"),
        AcceleratorMemory::new(
            MemoryTopology::Discrete,
            Some(ByteCount::new(32 * 1024 * 1024 * 1024).expect("framebuffer")),
            Some(TechnicalName::parse("vram").expect("addressing")),
        )
        .expect("memory"),
        ComputeCapability::Cuda {
            architecture: TechnicalName::parse("sm_120").expect("architecture"),
            maximum_version: Some(TechnicalName::parse("cuda_13.0").expect("CUDA")),
        },
    );
    let link = InterconnectObservation::new(
        InterconnectObservationKind::Pcie,
        None,
        vec![device.clone()],
        true,
        None,
        None,
    )
    .expect("link");
    let observation = HardwareObservation::new(
        HardwareObservationId::parse(&identity('4')).expect("observation"),
        NodeId::parse(&identity('1')).expect("node"),
        BootId::parse("boot-fixture").expect("boot"),
        PlatformIdentity::new(OperatingSystem::Linux, CpuArchitecture::Arm64),
        ProcessorObservation::new(DisplayName::parse("Grace CPU").expect("CPU"), 20)
            .expect("processor"),
        ByteCount::new(128 * 1024 * 1024 * 1024).expect("host memory"),
        vec![accelerator.clone()],
        vec![link],
        UnixMilliseconds::new(2_000),
    )
    .expect("observation");
    assert_eq!(observation.accelerators().len(), 1);

    assert!(HardwareObservation::new(
        HardwareObservationId::parse(&identity('4')).expect("observation"),
        NodeId::parse(&identity('1')).expect("node"),
        BootId::parse("boot-fixture").expect("boot"),
        PlatformIdentity::new(OperatingSystem::Linux, CpuArchitecture::Arm64),
        ProcessorObservation::new(DisplayName::parse("Grace CPU").expect("CPU"), 20)
            .expect("processor"),
        ByteCount::new(128).expect("host memory"),
        vec![accelerator.clone(), accelerator],
        Vec::new(),
        UnixMilliseconds::new(2_000),
    )
    .is_err());

    let unknown_link = InterconnectObservation::new(
        InterconnectObservationKind::Nvlink,
        None,
        vec![DeviceId::parse("GPU-unknown").expect("unknown device")],
        true,
        Some(100_000),
        None,
    )
    .expect("unknown link");
    assert!(HardwareObservation::new(
        HardwareObservationId::parse(&identity('4')).expect("observation"),
        NodeId::parse(&identity('1')).expect("node"),
        BootId::parse("boot-fixture").expect("boot"),
        PlatformIdentity::new(OperatingSystem::Linux, CpuArchitecture::Arm64),
        ProcessorObservation::new(DisplayName::parse("Grace CPU").expect("CPU"), 20)
            .expect("processor"),
        ByteCount::new(128).expect("host memory"),
        Vec::new(),
        vec![unknown_link],
        UnixMilliseconds::new(2_000),
    )
    .is_err());
}

// Treats evidence as descriptive metadata rather than an installation gate.
#[test]
fn every_evidence_label_can_describe_an_available_installation() {
    for label in [
        EvidenceLabel::Qualified,
        EvidenceLabel::Unqualified,
        EvidenceLabel::Unknown,
    ] {
        let installation = RuntimeInstallation::new(
            RuntimeInstallationId::parse(&identity('5')).expect("runtime installation"),
            NodeId::parse(&identity('1')).expect("node"),
            LogicalModelName::parse("qwen3.8").expect("model"),
            runtime(),
            vec![artifact("model")],
            label,
            RuntimeInstallationState::Available,
            None,
            timestamps(),
        )
        .expect("available installation");
        assert_eq!(installation.evidence_label(), label);
        assert_eq!(installation.state(), RuntimeInstallationState::Available);
    }
}

// Rejects ambiguous artifact sets and incomplete failed installation snapshots.
#[test]
fn runtime_installation_requires_unique_artifacts_and_failure_details() {
    let common = || {
        (
            RuntimeInstallationId::parse(&identity('5')).expect("runtime installation"),
            NodeId::parse(&identity('1')).expect("node"),
            LogicalModelName::parse("qwen3.8").expect("model"),
        )
    };
    let (installation_id, node_id, logical_model) = common();
    assert!(RuntimeInstallation::new(
        installation_id,
        node_id,
        logical_model,
        runtime(),
        vec![artifact("model"), artifact("model")],
        EvidenceLabel::Unknown,
        RuntimeInstallationState::Staging,
        None,
        timestamps(),
    )
    .is_err());
    let (installation_id, node_id, logical_model) = common();
    assert!(RuntimeInstallation::new(
        installation_id,
        node_id,
        logical_model,
        runtime(),
        vec![artifact("model")],
        EvidenceLabel::Unqualified,
        RuntimeInstallationState::Failed,
        None,
        timestamps(),
    )
    .is_err());
}

// Keeps replica identities unique beneath one logical model service.
#[test]
fn model_service_rejects_duplicate_placement_groups() {
    let group = PlacementGroupId::parse(&identity('6')).expect("group");
    assert!(ModelService::new(
        ModelServiceId::parse(&identity('7')).expect("service"),
        LogicalModelName::parse("qwen3.8").expect("model"),
        ModelServiceDesiredState::Running,
        vec![group.clone(), group],
        timestamps(),
    )
    .is_err());
    assert!(ModelService::new(
        ModelServiceId::parse(&identity('7')).expect("service"),
        LogicalModelName::parse("qwen3.8").expect("model"),
        ModelServiceDesiredState::Running,
        Vec::new(),
        timestamps(),
    )
    .is_ok());
}

// Keeps placement resources exact, non-empty, and free of duplicate devices.
#[test]
fn placement_resources_reject_duplicate_devices() {
    let device = DeviceId::parse("GPU-fixture").expect("device");
    assert!(PlacementResources::new(
        PortRange::new(9_000, 2).expect("ports"),
        vec![device.clone(), device],
        None,
    )
    .is_err());
    assert!(PlacementResources::new(
        PortRange::new(9_000, 2).expect("ports"),
        vec![DeviceId::parse("GPU-fixture").expect("device")],
        Some(NetworkInterfaceName::parse("enp1s0").expect("interface")),
    )
    .is_ok());
}

// Preserves opaque task identity and requires failures for failed placements.
#[test]
fn placement_snapshot_requires_coherent_failure_state() {
    let assignment = PlacementAssignment::new(
        NodeId::parse(&identity('1')).expect("node"),
        RuntimeInstallationId::parse(&identity('5')).expect("runtime installation"),
        HardwareObservationId::parse(&identity('4')).expect("hardware observation"),
        BootId::parse("11111111-2222-3333-4444-555555555555").expect("boot"),
        UnixMilliseconds::new(900),
        TaskId::parse("task-0").expect("task"),
        NodeAddress::parse("homeai.local").expect("address"),
        PlacementResources::new(
            PortRange::new(9_000, 2).expect("ports"),
            vec![DeviceId::parse("GPU-fixture").expect("device")],
            None,
        )
        .expect("resources"),
        EndpointOwnership::Owner,
    );
    assert!(Placement::new(
        PlacementId::parse(&identity('8')).expect("placement"),
        PlacementGroupId::parse(&identity('6')).expect("group"),
        assignment.clone(),
        PlacementState::Failed,
        None,
        None,
        timestamps(),
    )
    .is_err());
    assert!(Placement::new(
        PlacementId::parse(&identity('8')).expect("placement"),
        PlacementGroupId::parse(&identity('6')).expect("group"),
        assignment,
        PlacementState::Failed,
        Some(OperationId::parse(&identity('9')).expect("operation")),
        Some(failure()),
        timestamps(),
    )
    .is_ok());
}

// Requires one member-owned endpoint and keeps endpoint limits within group capacity.
#[test]
fn placement_group_requires_one_coherent_endpoint() {
    let placement_id = PlacementId::parse(&identity('8')).expect("placement");
    let capacity = PlacementGroupCapacity::new(
        64,
        8,
        65_536,
        InterconnectRequirement::new(InterconnectKind::Any, false, 0, 0),
    )
    .expect("capacity");
    let group = PlacementGroup::new(
        PlacementGroupId::parse(&identity('6')).expect("group"),
        ModelServiceId::parse(&identity('7')).expect("service"),
        runtime(),
        vec![placement_id.clone()],
        placement_id.clone(),
        Some(endpoint(placement_id.clone(), 8)),
        capacity,
        ModelServiceDesiredState::Running,
        PlacementGroupState::Running,
        None,
        timestamps(),
    )
    .expect("placement group");
    assert_eq!(group.placement_ids(), &[placement_id.clone()]);
    assert!(group.endpoint().is_some());

    assert!(PlacementGroup::new(
        PlacementGroupId::parse(&identity('6')).expect("group"),
        ModelServiceId::parse(&identity('7')).expect("service"),
        runtime(),
        vec![placement_id.clone()],
        placement_id.clone(),
        None,
        capacity,
        ModelServiceDesiredState::Running,
        PlacementGroupState::Running,
        None,
        timestamps(),
    )
    .is_err());
    assert!(PlacementGroup::new(
        PlacementGroupId::parse(&identity('6')).expect("group"),
        ModelServiceId::parse(&identity('7')).expect("service"),
        runtime(),
        vec![placement_id.clone()],
        placement_id.clone(),
        Some(endpoint(placement_id.clone(), 9)),
        capacity,
        ModelServiceDesiredState::Running,
        PlacementGroupState::Running,
        None,
        timestamps(),
    )
    .is_err());
    let other_placement = PlacementId::parse(&identity('a')).expect("other placement");
    assert!(PlacementGroup::new(
        PlacementGroupId::parse(&identity('6')).expect("group"),
        ModelServiceId::parse(&identity('7')).expect("service"),
        runtime(),
        vec![placement_id.clone()],
        other_placement.clone(),
        Some(endpoint(other_placement, 8)),
        capacity,
        ModelServiceDesiredState::Running,
        PlacementGroupState::Running,
        None,
        timestamps(),
    )
    .is_err());
}

// Rejects ambiguous or remote token-count paths at the interface boundary.
#[test]
fn token_count_contract_requires_a_local_absolute_path() {
    assert!(TokenCountContract::new("/v1/token-count", TokenCountProtocol::LetsInferV1).is_ok());
    assert!(TokenCountContract::new("v1/token-count", TokenCountProtocol::LetsInferV1).is_err());
    assert!(TokenCountContract::new(
        "https://engine/token-count",
        TokenCountProtocol::LetsInferV1
    )
    .is_err());
}

// Represents accelerator, port, and RDMA reservations through one typed lease shape.
#[test]
fn resource_lease_supports_generic_core_resources() {
    let placement_id = PlacementId::parse(&identity('8')).expect("placement");
    let node_id = NodeId::parse(&identity('1')).expect("node");
    let resources = [
        ResourceIdentity::Accelerator(DeviceId::parse("GPU-fixture").expect("device")),
        ResourceIdentity::Port(NetworkPort::new(9_000).expect("port")),
        ResourceIdentity::RdmaInterface(NetworkInterfaceName::parse("enp1s0").expect("interface")),
    ];
    for (index, resource) in resources.into_iter().enumerate() {
        let character = char::from_digit((index + 1) as u32, 16).expect("identity character");
        let lease = ResourceLease::new(
            ResourceLeaseId::parse(&identity(character)).expect("lease"),
            placement_id.clone(),
            node_id.clone(),
            resource,
            ResourceLeaseState::Reserved,
            timestamps(),
        );
        assert_eq!(lease.state(), ResourceLeaseState::Reserved);
    }
}

// Requires terminal operation timestamps and failure details to agree with state.
#[test]
fn operation_snapshot_rejects_incoherent_terminal_state() {
    let operation_id = OperationId::parse(&identity('9')).expect("operation");
    let target = OperationTarget::PlacementGroup(
        PlacementGroupId::parse(&identity('6')).expect("placement group"),
    );
    assert!(Operation::new(
        operation_id.clone(),
        OperationKind::Start,
        target.clone(),
        OperationState::Running,
        None,
        Some(UnixMilliseconds::new(1_500)),
        timestamps(),
    )
    .is_err());
    assert!(Operation::new(
        operation_id.clone(),
        OperationKind::Start,
        target.clone(),
        OperationState::Succeeded,
        None,
        Some(UnixMilliseconds::new(3_000)),
        timestamps(),
    )
    .is_err());
    assert!(Operation::new(
        operation_id.clone(),
        OperationKind::Start,
        target.clone(),
        OperationState::Failed,
        None,
        Some(UnixMilliseconds::new(1_500)),
        timestamps(),
    )
    .is_err());
    let operation = Operation::new(
        operation_id,
        OperationKind::Start,
        target,
        OperationState::Failed,
        Some(failure()),
        Some(UnixMilliseconds::new(1_500)),
        timestamps(),
    )
    .expect("failed operation");
    assert_eq!(operation.state(), OperationState::Failed);
    assert!(operation.failure().is_some());
}
