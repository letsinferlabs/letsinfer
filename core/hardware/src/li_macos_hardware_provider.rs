// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use li_core_interface::{
    Accelerator, AcceleratorMemory, AcceleratorVendor, BootId, ByteCount, ComputeCapability,
    CpuArchitecture, DeviceId, DisplayName, MemoryTopology, OperatingSystem, PlatformIdentity,
    ProcessorObservation, TechnicalName,
};

use crate::{HardwareError, HardwareNativeIo, HardwareProvider, HardwareSnapshot};

const MAX_ACCELERATORS: usize = 64;

// Supplies every native macOS hardware dependency explicitly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacOsHardwareConfiguration {
    sysctl_command: PathBuf,
    metal_probe_command: PathBuf,
}

impl MacOsHardwareConfiguration {
    // Creates one macOS provider configuration from absolute native commands.
    pub fn new(
        sysctl_command: PathBuf,
        metal_probe_command: PathBuf,
    ) -> Result<Self, HardwareError> {
        require_absolute(&sysctl_command)?;
        require_absolute(&metal_probe_command)?;
        Ok(Self {
            sysctl_command,
            metal_probe_command,
        })
    }
}

// Observes Apple host and Metal device facts through injected native I/O.
pub struct MacOsHardwareProvider {
    configuration: MacOsHardwareConfiguration,
    io: Arc<dyn HardwareNativeIo>,
}

impl MacOsHardwareProvider {
    // Creates one macOS provider without discovering native dependencies.
    pub const fn new(
        configuration: MacOsHardwareConfiguration,
        io: Arc<dyn HardwareNativeIo>,
    ) -> Self {
        Self { configuration, io }
    }

    // Returns one exact sysctl value through the injected command.
    fn sysctl(&self, name: &str) -> Result<String, HardwareError> {
        let value = self
            .io
            .run(&self.configuration.sysctl_command, &["-n", name])?;
        let value = value.trim();
        if value.is_empty() {
            return Err(HardwareError::InvalidObservation {
                reason: "macOS sysctl value is empty",
            });
        }
        Ok(value.to_string())
    }
}

impl HardwareProvider for MacOsHardwareProvider {
    // Returns the supported Apple Silicon platform identity.
    fn platform(&self) -> PlatformIdentity {
        PlatformIdentity::new(OperatingSystem::Macos, CpuArchitecture::Arm64)
    }

    // Observes current macOS host and Metal accelerator facts.
    fn observe(&self) -> Result<HardwareSnapshot, HardwareError> {
        let boot_id = BootId::parse(&self.sysctl("kern.bootsessionuuid")?)?;
        let processor = ProcessorObservation::new(
            DisplayName::parse(&self.sysctl("machdep.cpu.brand_string")?)?,
            self.sysctl("hw.logicalcpu")?.parse().map_err(|_| {
                HardwareError::InvalidObservation {
                    reason: "macOS logical CPU count is invalid",
                }
            })?,
        )?;
        let memory_bytes = ByteCount::new(self.sysctl("hw.memsize")?.parse().map_err(|_| {
            HardwareError::InvalidObservation {
                reason: "macOS memory capacity is invalid",
            }
        })?)?;
        let metal = self.io.run(&self.configuration.metal_probe_command, &[])?;
        let accelerators = parse_metal_devices(&metal)?;
        Ok(HardwareSnapshot::new(
            boot_id,
            self.platform(),
            processor,
            memory_bytes,
            accelerators,
            Vec::new(),
        ))
    }
}

// Parses the bounded tab-separated output of the core-owned Metal helper.
fn parse_metal_devices(value: &str) -> Result<Vec<Accelerator>, HardwareError> {
    let mut accelerators = Vec::new();
    let mut device_ids = HashSet::new();
    for line in value.lines().filter(|line| !line.trim().is_empty()) {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() != 4 {
            return Err(HardwareError::InvalidObservation {
                reason: "Metal probe field count is invalid",
            });
        }
        if accelerators.len() >= MAX_ACCELERATORS
            || !is_numbered_label(fields[2], "apple")
            || !is_numbered_label(fields[3], "metal")
        {
            return Err(HardwareError::InvalidObservation {
                reason: "Metal probe capability is invalid or unbounded",
            });
        }
        let device_id = DeviceId::parse(fields[0])?;
        if !device_ids.insert(device_id.clone()) {
            return Err(HardwareError::InvalidObservation {
                reason: "Metal accelerator identity is duplicated",
            });
        }
        accelerators.push(Accelerator::new(
            device_id,
            AcceleratorVendor::Apple,
            DisplayName::parse(fields[1])?,
            AcceleratorMemory::new(MemoryTopology::Unified, None, None)?,
            ComputeCapability::Metal {
                family: TechnicalName::parse(fields[2])?,
                version: TechnicalName::parse(fields[3])?,
            },
        ));
    }
    if accelerators.is_empty() {
        return Err(HardwareError::InvalidObservation {
            reason: "Metal probe returned no accelerator",
        });
    }
    Ok(accelerators)
}

// Returns whether one capability label has a fixed prefix and positive numeric generation.
fn is_numbered_label(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|generation| {
        !generation.is_empty()
            && generation.bytes().all(|byte| byte.is_ascii_digit())
            && generation.parse::<u16>().is_ok_and(|value| value > 0)
    })
}

// Requires one configured native command path to be absolute.
fn require_absolute(path: &Path) -> Result<(), HardwareError> {
    if !path.is_absolute() {
        return Err(HardwareError::InvalidObservation {
            reason: "macOS hardware command must be absolute",
        });
    }
    Ok(())
}
