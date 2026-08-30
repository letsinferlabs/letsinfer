// SPDX-License-Identifier: AGPL-3.0-only

use li_core_interface::{
    Accelerator, AcceleratorDriver, AcceleratorMemory, AcceleratorTelemetry, AcceleratorVendor,
    BootId, ByteCount, ComputeCapability, CpuArchitecture, DeviceId, DisplayName,
    HardwareObservation, HardwareObservationId, InterconnectObservation,
    InterconnectObservationKind, MemoryTopology, NetworkInterfaceName, NodeId, OperatingSystem,
    PlatformIdentity, ProcessorObservation, TechnicalName, UnixMilliseconds,
};
use serde::{Deserialize, Serialize};

use crate::HardwareError;

const HARDWARE_OBSERVATION_SCHEMA_NAME: &str = "li_hardware_observation";
const HARDWARE_OBSERVATION_SCHEMA_VERSION: u64 = 1;
const MAX_DOCUMENT_BYTES: usize = 4 * 1024 * 1024;

// Wraps one required nullable field so missing and explicit null remain distinct.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(transparent)]
struct Nullable<Value>(Option<Value>);

// Stores one complete closed hardware observation document.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HardwareObservationDocument {
    schema: HardwareSchemaIdentity,
    observation_id: String,
    node_id: String,
    boot_id: String,
    platform: HardwarePlatformDocument,
    processor: HardwareProcessorDocument,
    memory_bytes: u64,
    accelerators: Vec<HardwareAcceleratorDocument>,
    interconnects: Vec<HardwareInterconnectDocument>,
    observed_at_unix_milliseconds: u64,
}

// Stores the nested Let's Infer hardware schema identity.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HardwareSchemaIdentity {
    name: String,
    version: u64,
}

// Stores one closed platform projection.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HardwarePlatformDocument {
    operating_system: HardwareOperatingSystem,
    architecture: HardwareArchitecture,
}

// Stores one supported operating-system label.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum HardwareOperatingSystem {
    Linux,
    Macos,
}

// Stores one supported CPU-architecture label.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum HardwareArchitecture {
    Arm64,
    X86_64,
}

// Stores one closed processor projection.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HardwareProcessorDocument {
    model: String,
    logical_cpu_count: u16,
}

// Stores one complete accelerator projection.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HardwareAcceleratorDocument {
    device_id: String,
    vendor: HardwareAcceleratorVendorDocument,
    name: String,
    memory: HardwareAcceleratorMemoryDocument,
    compute: HardwareComputeCapabilityDocument,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    driver: Nullable<HardwareAcceleratorDriverDocument>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    telemetry: Nullable<HardwareAcceleratorTelemetryDocument>,
}

// Stores one closed accelerator-vendor union.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum HardwareAcceleratorVendorDocument {
    Nvidia,
    Apple,
    Other { name: String },
}

// Stores one complete accelerator-memory projection.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HardwareAcceleratorMemoryDocument {
    topology: HardwareMemoryTopology,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    framebuffer_bytes: Nullable<u64>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    addressing_mode: Nullable<String>,
}

// Stores one closed memory-topology label.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum HardwareMemoryTopology {
    Unified,
    Discrete,
    Unknown,
}

// Stores one closed compute-capability union.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "api", rename_all = "snake_case", deny_unknown_fields)]
enum HardwareComputeCapabilityDocument {
    Cuda {
        architecture: String,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        maximum_version: Nullable<String>,
    },
    Metal {
        family: String,
        version: String,
    },
    Other {
        api_name: String,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        capability: Nullable<String>,
    },
}

// Stores one exact observed accelerator-driver identity.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HardwareAcceleratorDriverDocument {
    source: String,
    version: String,
}

// Stores one complete nullable telemetry sample.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HardwareAcceleratorTelemetryDocument {
    #[serde(deserialize_with = "deserialize_required_nullable")]
    temperature_millicelsius: Nullable<i32>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    graphics_clock_mhz: Nullable<u32>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    memory_clock_mhz: Nullable<u32>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    utilization_per_mille: Nullable<u16>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    power_milliwatts: Nullable<u64>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    framebuffer_used_bytes: Nullable<u64>,
}

// Stores one complete mutable interconnect projection.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HardwareInterconnectDocument {
    kind: HardwareInterconnectKind,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    interface: Nullable<String>,
    device_ids: Vec<String>,
    is_available: bool,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    speed_mbps: Nullable<u64>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    mtu: Nullable<u32>,
}

// Stores one closed interconnect-kind label.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum HardwareInterconnectKind {
    Pcie,
    Nvlink,
    Rdma,
    Ethernet,
    Wifi,
    Other,
}

// Decodes one explicit value or null while rejecting a missing containing object key.
fn deserialize_required_nullable<'de, Deserializer, Value>(
    deserializer: Deserializer,
) -> Result<Nullable<Value>, Deserializer::Error>
where
    Deserializer: serde::Deserializer<'de>,
    Value: Deserialize<'de>,
{
    Option::<Value>::deserialize(deserializer).map(Nullable)
}

// Encodes one validated hardware observation through the closed schema-1 boundary.
pub fn encode_hardware_observation(
    observation: &HardwareObservation,
) -> Result<Vec<u8>, HardwareError> {
    let document = document_from_observation(observation);
    let mut bytes = serde_json::to_vec(&document).map_err(|_| invalid_document())?;
    if bytes.len() >= MAX_DOCUMENT_BYTES {
        return Err(invalid_document());
    }
    bytes.push(b'\n');
    Ok(bytes)
}

// Decodes one bounded duplicate-rejecting hardware observation document.
pub fn decode_hardware_observation(bytes: &[u8]) -> Result<HardwareObservation, HardwareError> {
    if bytes.is_empty() || bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(invalid_document());
    }
    let document: HardwareObservationDocument =
        serde_json::from_slice(bytes).map_err(|_| invalid_document())?;
    if document.schema.name != HARDWARE_OBSERVATION_SCHEMA_NAME
        || document.schema.version != HARDWARE_OBSERVATION_SCHEMA_VERSION
    {
        return Err(invalid_document());
    }
    observation_from_document(document)
}

// Projects one validated observation into the exact wire representation.
fn document_from_observation(observation: &HardwareObservation) -> HardwareObservationDocument {
    HardwareObservationDocument {
        schema: HardwareSchemaIdentity {
            name: HARDWARE_OBSERVATION_SCHEMA_NAME.to_string(),
            version: HARDWARE_OBSERVATION_SCHEMA_VERSION,
        },
        observation_id: observation.observation_id().as_str().to_string(),
        node_id: observation.node_id().as_str().to_string(),
        boot_id: observation.boot_id().as_str().to_string(),
        platform: HardwarePlatformDocument {
            operating_system: operating_system_document(observation.platform().operating_system()),
            architecture: architecture_document(observation.platform().architecture()),
        },
        processor: HardwareProcessorDocument {
            model: observation.processor().model().as_str().to_string(),
            logical_cpu_count: observation.processor().logical_cpu_count(),
        },
        memory_bytes: observation.memory_bytes().value(),
        accelerators: observation
            .accelerators()
            .iter()
            .map(accelerator_document)
            .collect(),
        interconnects: observation
            .interconnects()
            .iter()
            .map(interconnect_document)
            .collect(),
        observed_at_unix_milliseconds: observation.observed_at().value(),
    }
}

// Reconstructs one validated observation from its closed wire representation.
fn observation_from_document(
    document: HardwareObservationDocument,
) -> Result<HardwareObservation, HardwareError> {
    HardwareObservation::new(
        HardwareObservationId::parse(&document.observation_id)?,
        NodeId::parse(&document.node_id)?,
        BootId::parse(&document.boot_id)?,
        PlatformIdentity::new(
            operating_system(document.platform.operating_system),
            architecture(document.platform.architecture),
        ),
        ProcessorObservation::new(
            DisplayName::parse(&document.processor.model)?,
            document.processor.logical_cpu_count,
        )?,
        ByteCount::new(document.memory_bytes)?,
        document
            .accelerators
            .into_iter()
            .map(accelerator_from_document)
            .collect::<Result<Vec<_>, _>>()?,
        document
            .interconnects
            .into_iter()
            .map(interconnect_from_document)
            .collect::<Result<Vec<_>, _>>()?,
        UnixMilliseconds::new(document.observed_at_unix_milliseconds),
    )
    .map_err(Into::into)
}

// Projects one accelerator and every nullable observation field.
fn accelerator_document(accelerator: &Accelerator) -> HardwareAcceleratorDocument {
    HardwareAcceleratorDocument {
        device_id: accelerator.device_id().as_str().to_string(),
        vendor: accelerator_vendor_document(accelerator.vendor()),
        name: accelerator.name().as_str().to_string(),
        memory: HardwareAcceleratorMemoryDocument {
            topology: memory_topology_document(accelerator.memory().topology()),
            framebuffer_bytes: Nullable(
                accelerator
                    .memory()
                    .framebuffer_bytes()
                    .map(ByteCount::value),
            ),
            addressing_mode: Nullable(
                accelerator
                    .memory()
                    .addressing_mode()
                    .map(|value| value.as_str().to_string()),
            ),
        },
        compute: compute_document(accelerator.compute()),
        driver: Nullable(
            accelerator
                .driver()
                .map(|driver| HardwareAcceleratorDriverDocument {
                    source: driver.source().as_str().to_string(),
                    version: driver.version().as_str().to_string(),
                }),
        ),
        telemetry: Nullable(accelerator.telemetry().map(telemetry_document)),
    }
}

// Reconstructs one validated accelerator without applying hardware policy.
fn accelerator_from_document(
    document: HardwareAcceleratorDocument,
) -> Result<Accelerator, HardwareError> {
    let mut accelerator = Accelerator::new(
        DeviceId::parse(&document.device_id)?,
        accelerator_vendor(document.vendor)?,
        DisplayName::parse(&document.name)?,
        AcceleratorMemory::new(
            memory_topology(document.memory.topology),
            document
                .memory
                .framebuffer_bytes
                .0
                .map(ByteCount::new)
                .transpose()?,
            document
                .memory
                .addressing_mode
                .0
                .as_deref()
                .map(TechnicalName::parse)
                .transpose()?,
        )?,
        compute_from_document(document.compute)?,
    );
    if let Some(driver) = document.driver.0 {
        accelerator = accelerator.with_driver(AcceleratorDriver::new(
            TechnicalName::parse(&driver.source)?,
            TechnicalName::parse(&driver.version)?,
        ));
    }
    if let Some(telemetry) = document.telemetry.0 {
        accelerator = accelerator.with_telemetry(AcceleratorTelemetry::new(
            telemetry.temperature_millicelsius.0,
            telemetry.graphics_clock_mhz.0,
            telemetry.memory_clock_mhz.0,
            telemetry.utilization_per_mille.0,
            telemetry.power_milliwatts.0,
            telemetry.framebuffer_used_bytes.0,
        )?);
    }
    Ok(accelerator)
}

// Projects one closed accelerator-vendor union.
fn accelerator_vendor_document(vendor: &AcceleratorVendor) -> HardwareAcceleratorVendorDocument {
    match vendor {
        AcceleratorVendor::Nvidia => HardwareAcceleratorVendorDocument::Nvidia,
        AcceleratorVendor::Apple => HardwareAcceleratorVendorDocument::Apple,
        AcceleratorVendor::Other(name) => HardwareAcceleratorVendorDocument::Other {
            name: name.as_str().to_string(),
        },
    }
}

// Reconstructs one closed accelerator-vendor union.
fn accelerator_vendor(
    vendor: HardwareAcceleratorVendorDocument,
) -> Result<AcceleratorVendor, HardwareError> {
    Ok(match vendor {
        HardwareAcceleratorVendorDocument::Nvidia => AcceleratorVendor::Nvidia,
        HardwareAcceleratorVendorDocument::Apple => AcceleratorVendor::Apple,
        HardwareAcceleratorVendorDocument::Other { name } => {
            AcceleratorVendor::Other(TechnicalName::parse(&name)?)
        }
    })
}

// Projects one closed compute-capability union.
fn compute_document(compute: &ComputeCapability) -> HardwareComputeCapabilityDocument {
    match compute {
        ComputeCapability::Cuda {
            architecture,
            maximum_version,
        } => HardwareComputeCapabilityDocument::Cuda {
            architecture: architecture.as_str().to_string(),
            maximum_version: Nullable(
                maximum_version
                    .as_ref()
                    .map(|value| value.as_str().to_string()),
            ),
        },
        ComputeCapability::Metal { family, version } => HardwareComputeCapabilityDocument::Metal {
            family: family.as_str().to_string(),
            version: version.as_str().to_string(),
        },
        ComputeCapability::Other { api, capability } => HardwareComputeCapabilityDocument::Other {
            api_name: api.as_str().to_string(),
            capability: Nullable(capability.as_ref().map(|value| value.as_str().to_string())),
        },
    }
}

// Reconstructs one closed compute-capability union.
fn compute_from_document(
    compute: HardwareComputeCapabilityDocument,
) -> Result<ComputeCapability, HardwareError> {
    Ok(match compute {
        HardwareComputeCapabilityDocument::Cuda {
            architecture,
            maximum_version,
        } => ComputeCapability::Cuda {
            architecture: TechnicalName::parse(&architecture)?,
            maximum_version: maximum_version
                .0
                .as_deref()
                .map(TechnicalName::parse)
                .transpose()?,
        },
        HardwareComputeCapabilityDocument::Metal { family, version } => ComputeCapability::Metal {
            family: TechnicalName::parse(&family)?,
            version: TechnicalName::parse(&version)?,
        },
        HardwareComputeCapabilityDocument::Other {
            api_name,
            capability,
        } => ComputeCapability::Other {
            api: TechnicalName::parse(&api_name)?,
            capability: capability
                .0
                .as_deref()
                .map(TechnicalName::parse)
                .transpose()?,
        },
    })
}

// Projects one complete nullable telemetry sample.
fn telemetry_document(telemetry: AcceleratorTelemetry) -> HardwareAcceleratorTelemetryDocument {
    HardwareAcceleratorTelemetryDocument {
        temperature_millicelsius: Nullable(telemetry.temperature_millicelsius()),
        graphics_clock_mhz: Nullable(telemetry.graphics_clock_mhz()),
        memory_clock_mhz: Nullable(telemetry.memory_clock_mhz()),
        utilization_per_mille: Nullable(telemetry.utilization_per_mille()),
        power_milliwatts: Nullable(telemetry.power_milliwatts()),
        framebuffer_used_bytes: Nullable(telemetry.framebuffer_used_bytes()),
    }
}

// Projects one mutable interconnect observation.
fn interconnect_document(interconnect: &InterconnectObservation) -> HardwareInterconnectDocument {
    HardwareInterconnectDocument {
        kind: interconnect_kind_document(interconnect.kind()),
        interface: Nullable(
            interconnect
                .interface()
                .map(|value| value.as_str().to_string()),
        ),
        device_ids: interconnect
            .device_ids()
            .iter()
            .map(|value| value.as_str().to_string())
            .collect(),
        is_available: interconnect.is_available(),
        speed_mbps: Nullable(interconnect.speed_mbps()),
        mtu: Nullable(interconnect.mtu()),
    }
}

// Reconstructs one mutable interconnect observation.
fn interconnect_from_document(
    document: HardwareInterconnectDocument,
) -> Result<InterconnectObservation, HardwareError> {
    InterconnectObservation::new(
        interconnect_kind(document.kind),
        document
            .interface
            .0
            .as_deref()
            .map(NetworkInterfaceName::parse)
            .transpose()?,
        document
            .device_ids
            .iter()
            .map(|value| DeviceId::parse(value))
            .collect::<Result<Vec<_>, _>>()?,
        document.is_available,
        document.speed_mbps.0,
        document.mtu.0,
    )
    .map_err(Into::into)
}

// Projects one supported operating-system label.
const fn operating_system_document(value: OperatingSystem) -> HardwareOperatingSystem {
    match value {
        OperatingSystem::Linux => HardwareOperatingSystem::Linux,
        OperatingSystem::Macos => HardwareOperatingSystem::Macos,
    }
}

// Reconstructs one supported operating-system label.
const fn operating_system(value: HardwareOperatingSystem) -> OperatingSystem {
    match value {
        HardwareOperatingSystem::Linux => OperatingSystem::Linux,
        HardwareOperatingSystem::Macos => OperatingSystem::Macos,
    }
}

// Projects one supported CPU-architecture label.
const fn architecture_document(value: CpuArchitecture) -> HardwareArchitecture {
    match value {
        CpuArchitecture::Arm64 => HardwareArchitecture::Arm64,
        CpuArchitecture::X86_64 => HardwareArchitecture::X86_64,
    }
}

// Reconstructs one supported CPU-architecture label.
const fn architecture(value: HardwareArchitecture) -> CpuArchitecture {
    match value {
        HardwareArchitecture::Arm64 => CpuArchitecture::Arm64,
        HardwareArchitecture::X86_64 => CpuArchitecture::X86_64,
    }
}

// Projects one closed memory-topology label.
const fn memory_topology_document(value: MemoryTopology) -> HardwareMemoryTopology {
    match value {
        MemoryTopology::Unified => HardwareMemoryTopology::Unified,
        MemoryTopology::Discrete => HardwareMemoryTopology::Discrete,
        MemoryTopology::Unknown => HardwareMemoryTopology::Unknown,
    }
}

// Reconstructs one closed memory-topology label.
const fn memory_topology(value: HardwareMemoryTopology) -> MemoryTopology {
    match value {
        HardwareMemoryTopology::Unified => MemoryTopology::Unified,
        HardwareMemoryTopology::Discrete => MemoryTopology::Discrete,
        HardwareMemoryTopology::Unknown => MemoryTopology::Unknown,
    }
}

// Projects one closed interconnect-kind label.
const fn interconnect_kind_document(
    value: InterconnectObservationKind,
) -> HardwareInterconnectKind {
    match value {
        InterconnectObservationKind::Pcie => HardwareInterconnectKind::Pcie,
        InterconnectObservationKind::Nvlink => HardwareInterconnectKind::Nvlink,
        InterconnectObservationKind::Rdma => HardwareInterconnectKind::Rdma,
        InterconnectObservationKind::Ethernet => HardwareInterconnectKind::Ethernet,
        InterconnectObservationKind::Wifi => HardwareInterconnectKind::Wifi,
        InterconnectObservationKind::Other => HardwareInterconnectKind::Other,
    }
}

// Reconstructs one closed interconnect-kind label.
const fn interconnect_kind(value: HardwareInterconnectKind) -> InterconnectObservationKind {
    match value {
        HardwareInterconnectKind::Pcie => InterconnectObservationKind::Pcie,
        HardwareInterconnectKind::Nvlink => InterconnectObservationKind::Nvlink,
        HardwareInterconnectKind::Rdma => InterconnectObservationKind::Rdma,
        HardwareInterconnectKind::Ethernet => InterconnectObservationKind::Ethernet,
        HardwareInterconnectKind::Wifi => InterconnectObservationKind::Wifi,
        HardwareInterconnectKind::Other => InterconnectObservationKind::Other,
    }
}

// Returns one stable redacted failure for malformed or unsupported hardware documents.
const fn invalid_document() -> HardwareError {
    HardwareError::InvalidObservation {
        reason: "hardware observation document is invalid",
    }
}
