// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;

use crate::{
    BootId, ByteCount, CpuArchitecture, DeviceId, DisplayName, HardwareObservationId,
    InterfaceError, NetworkInterfaceName, NodeId, OperatingSystem, TechnicalName, UnixMilliseconds,
};

const MAX_ACCELERATORS: usize = 64;
const MAX_INTERCONNECTS: usize = 256;

// Identifies one accelerator vendor without assuming a fixed future set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AcceleratorVendor {
    Nvidia,
    Apple,
    Other(TechnicalName),
}

// Describes the physical memory topology exposed by one accelerator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryTopology {
    Unified,
    Discrete,
    Unknown,
}

// Describes the accelerator memory facts required for target matching.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceleratorMemory {
    topology: MemoryTopology,
    framebuffer_bytes: Option<ByteCount>,
    addressing_mode: Option<TechnicalName>,
}

impl AcceleratorMemory {
    // Creates one coherent accelerator memory description.
    pub fn new(
        topology: MemoryTopology,
        framebuffer_bytes: Option<ByteCount>,
        addressing_mode: Option<TechnicalName>,
    ) -> Result<Self, InterfaceError> {
        if topology == MemoryTopology::Discrete && framebuffer_bytes.is_none() {
            return Err(InterfaceError::new(
                "accelerator memory",
                "discrete memory requires a framebuffer capacity",
            ));
        }
        if topology == MemoryTopology::Unified && framebuffer_bytes.is_some() {
            return Err(InterfaceError::new(
                "accelerator memory",
                "unified memory cannot declare a discrete framebuffer capacity",
            ));
        }
        Ok(Self {
            topology,
            framebuffer_bytes,
            addressing_mode,
        })
    }

    // Returns the physical accelerator memory topology.
    pub const fn topology(&self) -> MemoryTopology {
        self.topology
    }

    // Returns discrete framebuffer capacity when one exists.
    pub const fn framebuffer_bytes(&self) -> Option<ByteCount> {
        self.framebuffer_bytes
    }

    // Returns the platform addressing mode when it was observed.
    pub const fn addressing_mode(&self) -> Option<&TechnicalName> {
        self.addressing_mode.as_ref()
    }
}

// Describes one model-neutral compute API capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ComputeCapability {
    Cuda {
        architecture: TechnicalName,
        maximum_version: Option<TechnicalName>,
    },
    Metal {
        family: TechnicalName,
        version: TechnicalName,
    },
    Other {
        api: TechnicalName,
        capability: Option<TechnicalName>,
    },
}

// Describes one observed accelerator driver without applying compatibility policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceleratorDriver {
    source: TechnicalName,
    version: TechnicalName,
}

impl AcceleratorDriver {
    // Creates one exact platform-reported driver identity.
    pub const fn new(source: TechnicalName, version: TechnicalName) -> Self {
        Self { source, version }
    }

    // Returns the native provider which reported this driver.
    pub const fn source(&self) -> &TechnicalName {
        &self.source
    }

    // Returns the exact platform-reported driver version.
    pub const fn version(&self) -> &TechnicalName {
        &self.version
    }
}

// Describes mutable live accelerator telemetry at one observation instant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcceleratorTelemetry {
    temperature_millicelsius: Option<i32>,
    graphics_clock_mhz: Option<u32>,
    memory_clock_mhz: Option<u32>,
    utilization_per_mille: Option<u16>,
    power_milliwatts: Option<u64>,
    framebuffer_used_bytes: Option<u64>,
}

impl AcceleratorTelemetry {
    // Creates one bounded telemetry snapshot without inferring health policy.
    pub fn new(
        temperature_millicelsius: Option<i32>,
        graphics_clock_mhz: Option<u32>,
        memory_clock_mhz: Option<u32>,
        utilization_per_mille: Option<u16>,
        power_milliwatts: Option<u64>,
        framebuffer_used_bytes: Option<u64>,
    ) -> Result<Self, InterfaceError> {
        if temperature_millicelsius.is_some_and(|value| !(-1_000..=250_000).contains(&value)) {
            return Err(InterfaceError::new(
                "accelerator telemetry",
                "temperature must be between -1 and 250 degrees Celsius",
            ));
        }
        if utilization_per_mille.is_some_and(|value| value > 1_000) {
            return Err(InterfaceError::new(
                "accelerator telemetry",
                "utilization must be between 0 and 1000 per mille",
            ));
        }
        Ok(Self {
            temperature_millicelsius,
            graphics_clock_mhz,
            memory_clock_mhz,
            utilization_per_mille,
            power_milliwatts,
            framebuffer_used_bytes,
        })
    }

    // Returns temperature in thousandths of one degree Celsius.
    pub const fn temperature_millicelsius(self) -> Option<i32> {
        self.temperature_millicelsius
    }

    // Returns the current graphics clock in MHz.
    pub const fn graphics_clock_mhz(self) -> Option<u32> {
        self.graphics_clock_mhz
    }

    // Returns the current memory clock in MHz.
    pub const fn memory_clock_mhz(self) -> Option<u32> {
        self.memory_clock_mhz
    }

    // Returns accelerator utilization in per-mille units.
    pub const fn utilization_per_mille(self) -> Option<u16> {
        self.utilization_per_mille
    }

    // Returns current power draw in milliwatts.
    pub const fn power_milliwatts(self) -> Option<u64> {
        self.power_milliwatts
    }

    // Returns current framebuffer use, including zero.
    pub const fn framebuffer_used_bytes(self) -> Option<u64> {
        self.framebuffer_used_bytes
    }
}

// Describes one physical accelerator observed on a node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Accelerator {
    device_id: DeviceId,
    vendor: AcceleratorVendor,
    name: DisplayName,
    memory: AcceleratorMemory,
    compute: ComputeCapability,
    driver: Option<AcceleratorDriver>,
    telemetry: Option<AcceleratorTelemetry>,
}

impl Accelerator {
    // Creates one accelerator snapshot from platform-observed facts.
    pub const fn new(
        device_id: DeviceId,
        vendor: AcceleratorVendor,
        name: DisplayName,
        memory: AcceleratorMemory,
        compute: ComputeCapability,
    ) -> Self {
        Self {
            device_id,
            vendor,
            name,
            memory,
            compute,
            driver: None,
            telemetry: None,
        }
    }

    // Attaches one observed driver identity without interpreting compatibility.
    pub fn with_driver(mut self, driver: AcceleratorDriver) -> Self {
        self.driver = Some(driver);
        self
    }

    // Attaches one live telemetry sample without changing accelerator identity.
    pub fn with_telemetry(mut self, telemetry: AcceleratorTelemetry) -> Self {
        self.telemetry = Some(telemetry);
        self
    }

    // Returns the platform-stable accelerator identity.
    pub const fn device_id(&self) -> &DeviceId {
        &self.device_id
    }

    // Returns the observed accelerator vendor.
    pub const fn vendor(&self) -> &AcceleratorVendor {
        &self.vendor
    }

    // Returns the observed accelerator name.
    pub const fn name(&self) -> &DisplayName {
        &self.name
    }

    // Returns the physical memory description.
    pub const fn memory(&self) -> &AcceleratorMemory {
        &self.memory
    }

    // Returns the model-neutral compute capability.
    pub const fn compute(&self) -> &ComputeCapability {
        &self.compute
    }

    // Returns the observed native driver when the platform exposed it.
    pub const fn driver(&self) -> Option<&AcceleratorDriver> {
        self.driver.as_ref()
    }

    // Returns live telemetry when the platform provider exposed it.
    pub const fn telemetry(&self) -> Option<AcceleratorTelemetry> {
        self.telemetry
    }
}

// Identifies one observed host or accelerator interconnect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterconnectObservationKind {
    Pcie,
    Nvlink,
    Rdma,
    Ethernet,
    Wifi,
    Other,
}

// Describes one mutable topology link captured in a hardware observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterconnectObservation {
    kind: InterconnectObservationKind,
    interface: Option<NetworkInterfaceName>,
    device_ids: Vec<DeviceId>,
    is_available: bool,
    speed_mbps: Option<u64>,
    mtu: Option<u32>,
}

impl InterconnectObservation {
    // Creates one bounded link observation without treating it as permanent capability.
    pub fn new(
        kind: InterconnectObservationKind,
        interface: Option<NetworkInterfaceName>,
        device_ids: Vec<DeviceId>,
        is_available: bool,
        speed_mbps: Option<u64>,
        mtu: Option<u32>,
    ) -> Result<Self, InterfaceError> {
        if interface.is_none() && device_ids.is_empty() {
            return Err(InterfaceError::new(
                "interconnect observation",
                "observation requires an interface or accelerator identity",
            ));
        }
        if device_ids.len() > MAX_ACCELERATORS || !all_unique(&device_ids) {
            return Err(InterfaceError::new(
                "interconnect observation",
                "accelerator identities must be unique and bounded",
            ));
        }
        if speed_mbps == Some(0) || mtu == Some(0) {
            return Err(InterfaceError::new(
                "interconnect observation",
                "observed speed and MTU must be positive when available",
            ));
        }
        Ok(Self {
            kind,
            interface,
            device_ids,
            is_available,
            speed_mbps,
            mtu,
        })
    }

    // Returns the observed interconnect kind.
    pub const fn kind(&self) -> InterconnectObservationKind {
        self.kind
    }

    // Returns the native interface when the link has one.
    pub const fn interface(&self) -> Option<&NetworkInterfaceName> {
        self.interface.as_ref()
    }

    // Returns the accelerators observed on this link.
    pub fn device_ids(&self) -> &[DeviceId] {
        &self.device_ids
    }

    // Returns whether the link was available at observation time.
    pub const fn is_available(&self) -> bool {
        self.is_available
    }

    // Returns the observed link speed when one was available.
    pub const fn speed_mbps(&self) -> Option<u64> {
        self.speed_mbps
    }

    // Returns the observed MTU when one was available.
    pub const fn mtu(&self) -> Option<u32> {
        self.mtu
    }
}

// Groups the stable operating-system and CPU architecture identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlatformIdentity {
    operating_system: OperatingSystem,
    architecture: CpuArchitecture,
}

impl PlatformIdentity {
    // Creates one supported platform identity.
    pub const fn new(operating_system: OperatingSystem, architecture: CpuArchitecture) -> Self {
        Self {
            operating_system,
            architecture,
        }
    }

    // Returns the host operating system.
    pub const fn operating_system(self) -> OperatingSystem {
        self.operating_system
    }

    // Returns the host CPU architecture.
    pub const fn architecture(self) -> CpuArchitecture {
        self.architecture
    }
}

// Describes one host CPU observation without encoding vendor-specific policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessorObservation {
    model: DisplayName,
    logical_cpu_count: u16,
}

impl ProcessorObservation {
    // Creates one CPU observation with at least one logical processor.
    pub fn new(model: DisplayName, logical_cpu_count: u16) -> Result<Self, InterfaceError> {
        if logical_cpu_count == 0 {
            return Err(InterfaceError::new(
                "processor observation",
                "logical CPU count must be greater than zero",
            ));
        }
        Ok(Self {
            model,
            logical_cpu_count,
        })
    }

    // Returns the observed CPU model.
    pub const fn model(&self) -> &DisplayName {
        &self.model
    }

    // Returns the observed logical CPU count.
    pub const fn logical_cpu_count(&self) -> u16 {
        self.logical_cpu_count
    }
}

// Describes one immutable snapshot of mutable node hardware facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HardwareObservation {
    observation_id: HardwareObservationId,
    node_id: NodeId,
    boot_id: BootId,
    platform: PlatformIdentity,
    processor: ProcessorObservation,
    memory_bytes: ByteCount,
    accelerators: Vec<Accelerator>,
    interconnects: Vec<InterconnectObservation>,
    observed_at: UnixMilliseconds,
}

impl HardwareObservation {
    // Creates one bounded hardware snapshot and validates every link reference.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        observation_id: HardwareObservationId,
        node_id: NodeId,
        boot_id: BootId,
        platform: PlatformIdentity,
        processor: ProcessorObservation,
        memory_bytes: ByteCount,
        accelerators: Vec<Accelerator>,
        interconnects: Vec<InterconnectObservation>,
        observed_at: UnixMilliseconds,
    ) -> Result<Self, InterfaceError> {
        if accelerators.len() > MAX_ACCELERATORS
            || !all_unique(
                &accelerators
                    .iter()
                    .map(|accelerator| accelerator.device_id().clone())
                    .collect::<Vec<_>>(),
            )
        {
            return Err(InterfaceError::new(
                "hardware observation",
                "accelerator identities must be unique and bounded",
            ));
        }
        if interconnects.len() > MAX_INTERCONNECTS {
            return Err(InterfaceError::new(
                "hardware observation",
                "interconnect observations exceed the supported bound",
            ));
        }
        let observed_devices: HashSet<&DeviceId> =
            accelerators.iter().map(Accelerator::device_id).collect();
        if interconnects.iter().any(|interconnect| {
            interconnect
                .device_ids()
                .iter()
                .any(|device_id| !observed_devices.contains(device_id))
        }) {
            return Err(InterfaceError::new(
                "hardware observation",
                "interconnect references an accelerator outside the observation",
            ));
        }
        Ok(Self {
            observation_id,
            node_id,
            boot_id,
            platform,
            processor,
            memory_bytes,
            accelerators,
            interconnects,
            observed_at,
        })
    }

    // Returns this hardware observation identity.
    pub const fn observation_id(&self) -> &HardwareObservationId {
        &self.observation_id
    }

    // Returns the node whose hardware was observed.
    pub const fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    // Returns the boot identity that scopes mutable topology facts.
    pub const fn boot_id(&self) -> &BootId {
        &self.boot_id
    }

    // Returns the host platform identity.
    pub const fn platform(&self) -> PlatformIdentity {
        self.platform
    }

    // Returns the host processor observation.
    pub const fn processor(&self) -> &ProcessorObservation {
        &self.processor
    }

    // Returns the observed host memory capacity.
    pub const fn memory_bytes(&self) -> ByteCount {
        self.memory_bytes
    }

    // Returns the observed physical accelerators.
    pub fn accelerators(&self) -> &[Accelerator] {
        &self.accelerators
    }

    // Returns the mutable links captured in this exact snapshot.
    pub fn interconnects(&self) -> &[InterconnectObservation] {
        &self.interconnects
    }

    // Returns when the platform facts were observed.
    pub const fn observed_at(&self) -> UnixMilliseconds {
        self.observed_at
    }
}

// Returns whether every value appears exactly once.
fn all_unique<Value: Eq + std::hash::Hash>(values: &[Value]) -> bool {
    let mut unique = HashSet::with_capacity(values.len());
    values.iter().all(|value| unique.insert(value))
}
