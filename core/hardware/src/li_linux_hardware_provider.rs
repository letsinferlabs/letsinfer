// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use li_core_interface::{
    Accelerator, AcceleratorDriver, AcceleratorMemory, AcceleratorTelemetry, AcceleratorVendor,
    BootId, ByteCount, ComputeCapability, CpuArchitecture, DeviceId, DisplayName,
    InterconnectObservation, InterconnectObservationKind, MemoryTopology, NetworkInterfaceName,
    OperatingSystem, PlatformIdentity, ProcessorObservation, TechnicalName,
};

use crate::{HardwareError, HardwareNativeIo, HardwareProvider, HardwareSnapshot};

const NVIDIA_QUERY: &str = "uuid,name,memory.total,memory.used,temperature.gpu,clocks.current.graphics,clocks.current.memory,utilization.gpu,power.draw,compute_cap,driver_version";
const MAX_ACCELERATORS: usize = 64;
const MAX_INTERCONNECTS: usize = 256;

// Supplies every native Linux dependency explicitly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxHardwareConfiguration {
    architecture: CpuArchitecture,
    boot_id_path: PathBuf,
    cpuinfo_path: PathBuf,
    meminfo_path: PathBuf,
    nvidia_smi_command: Option<PathBuf>,
    rdma_command: Option<PathBuf>,
}

impl LinuxHardwareConfiguration {
    // Creates one Linux provider configuration from absolute paths and commands.
    pub fn new(
        architecture: CpuArchitecture,
        boot_id_path: PathBuf,
        cpuinfo_path: PathBuf,
        meminfo_path: PathBuf,
        nvidia_smi_command: Option<PathBuf>,
        rdma_command: Option<PathBuf>,
    ) -> Result<Self, HardwareError> {
        for path in [&boot_id_path, &cpuinfo_path, &meminfo_path] {
            require_absolute(path, "Linux hardware file path must be absolute")?;
        }
        for command in [nvidia_smi_command.as_ref(), rdma_command.as_ref()]
            .into_iter()
            .flatten()
        {
            require_absolute(command, "Linux hardware command must be absolute")?;
        }
        Ok(Self {
            architecture,
            boot_id_path,
            cpuinfo_path,
            meminfo_path,
            nvidia_smi_command,
            rdma_command,
        })
    }
}

// Observes Linux host and NVIDIA device facts through injected native I/O.
pub struct LinuxHardwareProvider {
    configuration: LinuxHardwareConfiguration,
    io: Arc<dyn HardwareNativeIo>,
}

impl LinuxHardwareProvider {
    // Creates one Linux provider without discovering native dependencies.
    pub const fn new(
        configuration: LinuxHardwareConfiguration,
        io: Arc<dyn HardwareNativeIo>,
    ) -> Self {
        Self { configuration, io }
    }
}

impl HardwareProvider for LinuxHardwareProvider {
    // Returns this provider's exact Linux platform identity.
    fn platform(&self) -> PlatformIdentity {
        PlatformIdentity::new(OperatingSystem::Linux, self.configuration.architecture)
    }

    // Observes current Linux, NVIDIA, PCIe/NVLink, and RDMA facts.
    fn observe(&self) -> Result<HardwareSnapshot, HardwareError> {
        let boot_id = BootId::parse(self.io.read_text(&self.configuration.boot_id_path)?.trim())?;
        let cpuinfo = self.io.read_text(&self.configuration.cpuinfo_path)?;
        let meminfo = self.io.read_text(&self.configuration.meminfo_path)?;
        let processor = parse_processor(&cpuinfo)?;
        let memory_bytes = parse_memory(&meminfo)?;
        let accelerators = match &self.configuration.nvidia_smi_command {
            Some(command) => {
                let cuda_version = parse_nvidia_cuda_version(&self.io.run(command, &[])?)?;
                parse_nvidia_csv(
                    &self.io.run(
                        command,
                        &[
                            &format!("--query-gpu={NVIDIA_QUERY}"),
                            "--format=csv,noheader,nounits",
                        ],
                    )?,
                    &cuda_version,
                )?
            }
            None => Vec::new(),
        };
        let mut interconnects = match &self.configuration.nvidia_smi_command {
            Some(command) if accelerators.len() > 1 => {
                parse_nvidia_topology(&self.io.run(command, &["topo", "-m"])?, &accelerators)?
            }
            _ => Vec::new(),
        };
        if let Some(command) = &self.configuration.rdma_command {
            interconnects.extend(parse_rdma_links(&self.io.run(command, &["link", "show"])?)?);
        }
        Ok(HardwareSnapshot::new(
            boot_id,
            self.platform(),
            processor,
            memory_bytes,
            accelerators,
            interconnects,
        ))
    }
}

// Parses CPU model and logical count from procfs without vendor assumptions.
fn parse_processor(value: &str) -> Result<ProcessorObservation, HardwareError> {
    let model = value.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        matches!(name.trim(), "model name" | "Hardware" | "Processor").then_some(value.trim())
    });
    let logical_count = value
        .lines()
        .filter(|line| {
            line.split_once(':')
                .is_some_and(|(name, _)| name.trim() == "processor")
        })
        .count();
    let logical_count =
        u16::try_from(logical_count).map_err(|_| HardwareError::InvalidObservation {
            reason: "Linux logical CPU count exceeds the supported range",
        })?;
    ProcessorObservation::new(
        DisplayName::parse(model.ok_or(HardwareError::InvalidObservation {
            reason: "Linux CPU model is unavailable",
        })?)?,
        logical_count,
    )
    .map_err(Into::into)
}

// Parses online host memory capacity from procfs kilobytes.
fn parse_memory(value: &str) -> Result<ByteCount, HardwareError> {
    let kilobytes = value.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.trim() != "MemTotal" {
            return None;
        }
        value.split_whitespace().next()?.parse::<u64>().ok()
    });
    let bytes = kilobytes.and_then(|value| value.checked_mul(1024)).ok_or(
        HardwareError::InvalidObservation {
            reason: "Linux memory capacity is unavailable or invalid",
        },
    )?;
    ByteCount::new(bytes).map_err(Into::into)
}

// Parses bounded nvidia-smi CSV observations in query order.
fn parse_nvidia_csv(
    value: &str,
    cuda_version: &TechnicalName,
) -> Result<Vec<Accelerator>, HardwareError> {
    let mut accelerators = Vec::new();
    let mut device_ids = HashSet::new();
    for line in value.lines().filter(|line| !line.trim().is_empty()) {
        let fields: Vec<&str> = line.split(',').map(str::trim).collect();
        if fields.len() != 11 {
            return Err(HardwareError::InvalidObservation {
                reason: "nvidia-smi CSV field count is invalid",
            });
        }
        if accelerators.len() >= MAX_ACCELERATORS {
            return Err(HardwareError::InvalidObservation {
                reason: "NVIDIA accelerator count exceeds the supported range",
            });
        }
        let device_id = DeviceId::parse(fields[0])?;
        if !device_ids.insert(device_id.clone()) {
            return Err(HardwareError::InvalidObservation {
                reason: "NVIDIA accelerator identity is duplicated",
            });
        }
        let framebuffer_mebibytes = optional_u64(fields[2])?;
        let topology = if framebuffer_mebibytes.is_some() {
            MemoryTopology::Discrete
        } else {
            MemoryTopology::Unified
        };
        let framebuffer_bytes = match framebuffer_mebibytes {
            Some(value) => Some(ByteCount::new(value.checked_mul(1024 * 1024).ok_or(
                HardwareError::InvalidObservation {
                    reason: "NVIDIA framebuffer capacity overflowed",
                },
            )?)?),
            None => None,
        };
        let compute = compute_architecture(fields[9])?;
        let temperature = optional_decimal_milli(fields[4])?
            .map(i32::try_from)
            .transpose()
            .map_err(|_| HardwareError::InvalidObservation {
                reason: "NVIDIA temperature exceeds the supported range",
            })?;
        let framebuffer_used_bytes = match optional_u64(fields[3])? {
            Some(value) => Some(value.checked_mul(1024 * 1024).ok_or(
                HardwareError::InvalidObservation {
                    reason: "NVIDIA framebuffer use overflowed",
                },
            )?),
            None => None,
        };
        if framebuffer_used_bytes
            .is_some_and(|used| framebuffer_bytes.is_some_and(|capacity| used > capacity.value()))
        {
            return Err(HardwareError::InvalidObservation {
                reason: "NVIDIA framebuffer use exceeds observed capacity",
            });
        }
        let utilization = optional_decimal_milli(fields[7])?
            .map(|value| u16::try_from(value / 100))
            .transpose()
            .map_err(|_| HardwareError::InvalidObservation {
                reason: "NVIDIA utilization exceeds the supported range",
            })?;
        let accelerator = Accelerator::new(
            device_id,
            AcceleratorVendor::Nvidia,
            DisplayName::parse(fields[1])?,
            AcceleratorMemory::new(
                topology,
                framebuffer_bytes,
                Some(TechnicalName::parse(
                    if topology == MemoryTopology::Discrete {
                        "vram"
                    } else {
                        "unified"
                    },
                )?),
            )?,
            ComputeCapability::Cuda {
                architecture: compute,
                maximum_version: Some(cuda_version.clone()),
            },
        )
        .with_driver(AcceleratorDriver::new(
            TechnicalName::parse("nvidia")?,
            TechnicalName::parse(fields[10])?,
        ))
        .with_telemetry(AcceleratorTelemetry::new(
            temperature,
            optional_u32(fields[5])?,
            optional_u32(fields[6])?,
            utilization,
            optional_decimal_milli(fields[8])?,
            framebuffer_used_bytes,
        )?);
        accelerators.push(accelerator);
    }
    if accelerators.is_empty() {
        return Err(HardwareError::InvalidObservation {
            reason: "nvidia-smi returned no accelerator",
        });
    }
    Ok(accelerators)
}

// Parses the driver-reported maximum CUDA API label without judging compatibility.
fn parse_nvidia_cuda_version(value: &str) -> Result<TechnicalName, HardwareError> {
    let version = value.lines().find_map(|line| {
        let (_, suffix) = line.split_once("CUDA Version:")?;
        suffix
            .split(|character: char| character.is_whitespace() || character == '|')
            .find(|value| !value.is_empty())
    });
    let version = version.ok_or(HardwareError::InvalidObservation {
        reason: "NVIDIA CUDA capability is unavailable",
    })?;
    if !version
        .split('.')
        .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(HardwareError::InvalidObservation {
            reason: "NVIDIA CUDA capability is invalid",
        });
    }
    TechnicalName::parse(&format!("cuda_{version}")).map_err(Into::into)
}

// Parses the nvidia-smi topology matrix into pairwise PCIe or NVLink observations.
fn parse_nvidia_topology(
    value: &str,
    accelerators: &[Accelerator],
) -> Result<Vec<InterconnectObservation>, HardwareError> {
    let mut rows = vec![None; accelerators.len()];
    let mut header_observed = false;
    for line in value.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if !header_observed
            && fields.len() >= accelerators.len()
            && fields
                .iter()
                .take(accelerators.len())
                .enumerate()
                .all(|(index, label)| *label == format!("GPU{index}"))
        {
            header_observed = true;
            continue;
        }
        let Some(label) = fields.first() else {
            continue;
        };
        let Some(index) = label.strip_prefix("GPU") else {
            continue;
        };
        let index = index
            .parse::<usize>()
            .map_err(|_| HardwareError::InvalidObservation {
                reason: "NVIDIA topology row identity is invalid",
            })?;
        if index >= accelerators.len()
            || fields.len() < accelerators.len() + 1
            || fields.get(index + 1) != Some(&"X")
            || rows[index].is_some()
        {
            return Err(HardwareError::InvalidObservation {
                reason: "NVIDIA topology matrix is incomplete or duplicated",
            });
        }
        rows[index] = Some(
            fields[1..=accelerators.len()]
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
        );
    }
    if !header_observed || rows.iter().any(Option::is_none) {
        return Err(HardwareError::InvalidObservation {
            reason: "NVIDIA topology matrix is incomplete or duplicated",
        });
    }
    let rows: Vec<Vec<String>> = rows.into_iter().flatten().collect();
    let mut links = Vec::new();
    for left_index in 0..accelerators.len() {
        for right_index in (left_index + 1)..accelerators.len() {
            let relation = &rows[left_index][right_index];
            if relation != &rows[right_index][left_index] {
                return Err(HardwareError::InvalidObservation {
                    reason: "NVIDIA topology matrix is asymmetric",
                });
            }
            let kind = if relation.starts_with("NV") {
                InterconnectObservationKind::Nvlink
            } else if matches!(relation.as_str(), "PIX" | "PXB" | "PHB" | "NODE" | "SYS") {
                InterconnectObservationKind::Pcie
            } else if relation == "N/A" {
                continue;
            } else if relation == "X" {
                return Err(HardwareError::InvalidObservation {
                    reason: "NVIDIA topology diagonal marker appears between accelerators",
                });
            } else {
                InterconnectObservationKind::Other
            };
            links.push(InterconnectObservation::new(
                kind,
                None,
                vec![
                    accelerators[left_index].device_id().clone(),
                    accelerators[right_index].device_id().clone(),
                ],
                true,
                None,
                None,
            )?);
        }
    }
    Ok(links)
}

// Parses active and inactive RDMA netdev links from `rdma link show`.
fn parse_rdma_links(value: &str) -> Result<Vec<InterconnectObservation>, HardwareError> {
    let mut links = Vec::new();
    let mut interfaces = HashSet::new();
    for line in value.lines().filter(|line| !line.trim().is_empty()) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let netdev_index = fields.iter().position(|field| *field == "netdev");
        let interface = netdev_index.and_then(|index| fields.get(index + 1)).ok_or(
            HardwareError::InvalidObservation {
                reason: "RDMA link is missing its network interface",
            },
        )?;
        let interface = NetworkInterfaceName::parse(interface)?;
        let state = fields
            .windows(2)
            .find(|pair| pair[0] == "state")
            .map(|pair| pair[1])
            .ok_or(HardwareError::InvalidObservation {
                reason: "RDMA link is missing its state",
            })?;
        if links.len() >= MAX_INTERCONNECTS || !interfaces.insert(interface.clone()) {
            return Err(HardwareError::InvalidObservation {
                reason: "RDMA link identity is duplicated or unbounded",
            });
        }
        links.push(InterconnectObservation::new(
            InterconnectObservationKind::Rdma,
            Some(interface),
            Vec::new(),
            state == "ACTIVE",
            None,
            None,
        )?);
    }
    Ok(links)
}

// Parses one optional integer field using nvidia-smi unavailable markers.
fn optional_u64(value: &str) -> Result<Option<u64>, HardwareError> {
    if matches!(value, "N/A" | "[N/A]" | "") {
        return Ok(None);
    }
    value
        .parse()
        .map(Some)
        .map_err(|_| HardwareError::InvalidObservation {
            reason: "NVIDIA integer telemetry is invalid",
        })
}

// Parses one optional u32 telemetry field.
fn optional_u32(value: &str) -> Result<Option<u32>, HardwareError> {
    optional_u64(value)?
        .map(u32::try_from)
        .transpose()
        .map_err(|_| HardwareError::InvalidObservation {
            reason: "NVIDIA telemetry exceeds the supported range",
        })
}

// Parses one optional decimal value into thousandths without floating-point state.
fn optional_decimal_milli(value: &str) -> Result<Option<u64>, HardwareError> {
    if matches!(value, "N/A" | "[N/A]" | "") {
        return Ok(None);
    }
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || (value.contains('.')
            && (fraction.is_empty()
                || fraction.len() > 3
                || !fraction.bytes().all(|byte| byte.is_ascii_digit())))
    {
        return Err(HardwareError::InvalidObservation {
            reason: "NVIDIA decimal telemetry is invalid",
        });
    }
    let whole: u64 = whole
        .parse()
        .map_err(|_| HardwareError::InvalidObservation {
            reason: "NVIDIA decimal telemetry is invalid",
        })?;
    let mut fraction = fraction.as_bytes().to_vec();
    while fraction.len() < 3 {
        fraction.push(b'0');
    }
    let fraction = std::str::from_utf8(&fraction)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    whole
        .checked_mul(1_000)
        .and_then(|value| value.checked_add(fraction))
        .map(Some)
        .ok_or(HardwareError::InvalidObservation {
            reason: "NVIDIA decimal telemetry overflowed",
        })
}

// Converts CUDA compute capability to canonical sm_N identity.
fn compute_architecture(value: &str) -> Result<TechnicalName, HardwareError> {
    let (major, minor) = value
        .split_once('.')
        .ok_or(HardwareError::InvalidObservation {
            reason: "NVIDIA compute capability is invalid",
        })?;
    if major.is_empty()
        || minor.is_empty()
        || !major.bytes().all(|byte| byte.is_ascii_digit())
        || !minor.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(HardwareError::InvalidObservation {
            reason: "NVIDIA compute capability is invalid",
        });
    }
    TechnicalName::parse(&format!("sm_{major}{minor}")).map_err(Into::into)
}

// Requires one configured native path to be absolute.
fn require_absolute(path: &Path, reason: &'static str) -> Result<(), HardwareError> {
    if !path.is_absolute() {
        return Err(HardwareError::InvalidObservation { reason });
    }
    Ok(())
}
