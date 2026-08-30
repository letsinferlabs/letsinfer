// SPDX-License-Identifier: AGPL-3.0-only

mod li_engine_distribution;
mod li_evidence_label;
mod li_hardware_observation;
mod li_identity;
mod li_interface_error;
mod li_model_service;
mod li_node;
mod li_operation;
mod li_placement;
mod li_placement_group;
mod li_resource_lease;
mod li_runtime_installation;
mod li_value;

pub use li_engine_distribution::{EngineDistribution, NativeEngineKind};
pub use li_evidence_label::EvidenceLabel;
pub use li_hardware_observation::{
    Accelerator, AcceleratorDriver, AcceleratorMemory, AcceleratorTelemetry, AcceleratorVendor,
    ComputeCapability, HardwareObservation, InterconnectObservation, InterconnectObservationKind,
    MemoryTopology, PlatformIdentity, ProcessorObservation,
};
pub use li_identity::{
    ApiKeyId, ControllerId, CredentialId, HardwareObservationId, InstallationId, MachineId,
    ModelServiceId, NodeId, OperationId, PairingInviteId, PlacementGroupId, PlacementId,
    ResourceLeaseId, RuntimeInstallationId,
};
pub use li_interface_error::InterfaceError;
pub use li_model_service::{ModelService, ModelServiceDesiredState};
pub use li_node::{Node, NodeIdentity, NodeRole, NodeState};
pub use li_operation::{Operation, OperationKind, OperationState, OperationTarget};
pub use li_placement::{
    EndpointOwnership, Placement, PlacementAssignment, PlacementResources, PlacementState,
};
pub use li_placement_group::{
    EndpointHealth, InterconnectKind, InterconnectRequirement, PlacementEndpoint, PlacementGroup,
    PlacementGroupCapacity, PlacementGroupState, TokenCountContract, TokenCountProtocol,
};
pub use li_resource_lease::{ResourceIdentity, ResourceLease, ResourceLeaseState};
pub use li_runtime_installation::{
    GgufFileIdentity, ModelArtifact, ModelArtifactFormat, RuntimeIdentity, RuntimeInstallation,
    RuntimeInstallationState,
};
pub use li_value::{
    ArtifactName, ArtifactRevision, ArtifactUri, BootId, ByteCount, CpuArchitecture, DeviceId,
    DisplayName, EndpointAddress, EndpointScheme, EntityTimestamps, FailureDescription,
    LogicalModelName, NetworkInterfaceName, NetworkPort, NodeAddress, OperatingSystem, PortRange,
    RuntimeCandidateId, RuntimeSource, RuntimeVersion, Sha256Digest, TargetId, TaskId,
    TechnicalName, UnixMilliseconds,
};
