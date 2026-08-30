// SPDX-License-Identifier: AGPL-3.0-only

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use li_core_interface::{
    ComputeCapability, CpuArchitecture, InterconnectObservationKind, OperatingSystem,
};
use li_hardware_manager::{
    HardwareError, HardwareNativeIo, HardwareProvider, LinuxHardwareConfiguration,
    LinuxHardwareProvider, MacOsHardwareConfiguration, MacOsHardwareProvider,
};

const NVIDIA_CSV: &str = concat!(
    "GPU-0, NVIDIA RTX, 32768, 1024, 65, 2500, 2000, 50, 350.5, 12.0, 580.95.05\n",
    "GPU-1, NVIDIA RTX, 32768, 2048, 66, 2450, 1950, 25, 340.0, 12.0, 580.95.05\n"
);

// Stores every injected Linux native input independently.
#[derive(Clone)]
struct LinuxFixtureIo {
    boot_id: Result<String, HardwareError>,
    cpuinfo: Result<String, HardwareError>,
    meminfo: Result<String, HardwareError>,
    nvidia_banner: Result<String, HardwareError>,
    nvidia_csv: Result<String, HardwareError>,
    nvidia_topology: Result<String, HardwareError>,
    rdma: Result<String, HardwareError>,
}

impl Default for LinuxFixtureIo {
    // Returns a complete two-GPU Linux fixture with NVLink and RDMA.
    fn default() -> Self {
        Self {
            boot_id: Ok("boot-linux\n".to_string()),
            cpuinfo: Ok(concat!(
                "processor : 0\nmodel name : Fixture CPU\n",
                "processor : 1\nmodel name : Fixture CPU\n"
            )
            .to_string()),
            meminfo: Ok("MemTotal: 131072 kB\n".to_string()),
            nvidia_banner: Ok(concat!(
                "NVIDIA-SMI 580.95.05 Driver Version: 580.95.05 ",
                "CUDA Version: 13.0\n"
            )
            .to_string()),
            nvidia_csv: Ok(NVIDIA_CSV.to_string()),
            nvidia_topology: Ok("        GPU0 GPU1\nGPU0    X    NV4\nGPU1    NV4  X\n".to_string()),
            rdma: Ok(
                "link mlx5_0/1 state ACTIVE physical_state LINK_UP netdev enp1s0\n".to_string(),
            ),
        }
    }
}

impl HardwareNativeIo for LinuxFixtureIo {
    // Returns the exact configured Linux pseudo-file result.
    fn read_text(&self, path: &Path) -> Result<String, HardwareError> {
        match path.to_str() {
            Some("/proc/boot_id") => self.boot_id.clone(),
            Some("/proc/cpuinfo") => self.cpuinfo.clone(),
            Some("/proc/meminfo") => self.meminfo.clone(),
            _ => Err(HardwareError::ProviderUnavailable),
        }
    }

    // Returns the exact configured NVIDIA or RDMA result by fixed arguments.
    fn run(&self, command: &Path, arguments: &[&str]) -> Result<String, HardwareError> {
        match command.to_str() {
            Some("/usr/bin/nvidia-smi") if arguments.is_empty() => self.nvidia_banner.clone(),
            Some("/usr/bin/nvidia-smi")
                if arguments
                    .first()
                    .is_some_and(|value| value.starts_with("--query-gpu=")) =>
            {
                self.nvidia_csv.clone()
            }
            Some("/usr/bin/nvidia-smi") if arguments == ["topo", "-m"] => {
                self.nvidia_topology.clone()
            }
            Some("/usr/bin/rdma") if arguments == ["link", "show"] => self.rdma.clone(),
            _ => Err(HardwareError::ProviderUnavailable),
        }
    }
}

// Stores every injected macOS native input independently.
#[derive(Clone)]
struct MacOsFixtureIo {
    boot_id: Result<String, HardwareError>,
    cpu_model: Result<String, HardwareError>,
    logical_cpu_count: Result<String, HardwareError>,
    memory_bytes: Result<String, HardwareError>,
    metal: Result<String, HardwareError>,
}

impl Default for MacOsFixtureIo {
    // Returns one complete Apple Silicon and Metal fixture.
    fn default() -> Self {
        Self {
            boot_id: Ok("BOOT-MAC\n".to_string()),
            cpu_model: Ok("Apple M4 Max\n".to_string()),
            logical_cpu_count: Ok("16\n".to_string()),
            memory_bytes: Ok("137438953472\n".to_string()),
            metal: Ok("APPLE-0000000000000001\tApple M4 Max\tapple9\tmetal4\n".to_string()),
        }
    }
}

impl HardwareNativeIo for MacOsFixtureIo {
    // Rejects file reads because this provider contract uses fixed commands only.
    fn read_text(&self, _path: &Path) -> Result<String, HardwareError> {
        Err(HardwareError::ProviderUnavailable)
    }

    // Returns the exact configured sysctl or Metal probe result.
    fn run(&self, command: &Path, arguments: &[&str]) -> Result<String, HardwareError> {
        match (command.to_str(), arguments) {
            (Some("/usr/sbin/sysctl"), ["-n", "kern.bootsessionuuid"]) => self.boot_id.clone(),
            (Some("/usr/sbin/sysctl"), ["-n", "machdep.cpu.brand_string"]) => {
                self.cpu_model.clone()
            }
            (Some("/usr/sbin/sysctl"), ["-n", "hw.logicalcpu"]) => self.logical_cpu_count.clone(),
            (Some("/usr/sbin/sysctl"), ["-n", "hw.memsize"]) => self.memory_bytes.clone(),
            (Some("/opt/li_hardware_macos_probe"), []) => self.metal.clone(),
            _ => Err(HardwareError::ProviderUnavailable),
        }
    }
}

// Fails one exact injected native boundary while delegating all other calls.
struct FailAtIo<Inner> {
    inner: Inner,
    failure_index: usize,
    next_index: AtomicUsize,
}

impl<Inner> FailAtIo<Inner> {
    // Creates one deterministic native boundary failure injector.
    const fn new(inner: Inner, failure_index: usize) -> Self {
        Self {
            inner,
            failure_index,
            next_index: AtomicUsize::new(0),
        }
    }

    // Returns whether the current native boundary must fail.
    fn should_fail(&self) -> bool {
        self.next_index.fetch_add(1, Ordering::SeqCst) == self.failure_index
    }
}

impl<Inner: HardwareNativeIo> HardwareNativeIo for FailAtIo<Inner> {
    // Fails or delegates one exact native file read.
    fn read_text(&self, path: &Path) -> Result<String, HardwareError> {
        if self.should_fail() {
            return Err(HardwareError::ProviderUnavailable);
        }
        self.inner.read_text(path)
    }

    // Fails or delegates one exact native command invocation.
    fn run(&self, command: &Path, arguments: &[&str]) -> Result<String, HardwareError> {
        if self.should_fail() {
            return Err(HardwareError::ProviderUnavailable);
        }
        self.inner.run(command, arguments)
    }
}

// Creates one configured Linux provider for an injected architecture and I/O contract.
fn linux_provider(
    architecture: CpuArchitecture,
    io: Arc<dyn HardwareNativeIo>,
) -> LinuxHardwareProvider {
    LinuxHardwareProvider::new(
        LinuxHardwareConfiguration::new(
            architecture,
            "/proc/boot_id".into(),
            "/proc/cpuinfo".into(),
            "/proc/meminfo".into(),
            Some("/usr/bin/nvidia-smi".into()),
            Some("/usr/bin/rdma".into()),
        )
        .expect("configuration"),
        io,
    )
}

// Creates one configured macOS provider for an injected I/O contract.
fn macos_provider(io: Arc<dyn HardwareNativeIo>) -> MacOsHardwareProvider {
    MacOsHardwareProvider::new(
        MacOsHardwareConfiguration::new(
            "/usr/sbin/sysctl".into(),
            "/opt/li_hardware_macos_probe".into(),
        )
        .expect("configuration"),
        io,
    )
}

// Parses complete Linux arm64 and x86_64 facts without applying qualification policy.
#[test]
fn linux_provider_observes_both_architectures() {
    for architecture in [CpuArchitecture::Arm64, CpuArchitecture::X86_64] {
        let provider = linux_provider(architecture, Arc::new(LinuxFixtureIo::default()));
        let snapshot = provider.observe().expect("Linux observation");
        assert_eq!(
            snapshot.platform().operating_system(),
            OperatingSystem::Linux
        );
        assert_eq!(snapshot.platform().architecture(), architecture);
        assert_eq!(snapshot.accelerators().len(), 2);
        assert_eq!(
            snapshot.accelerators()[0]
                .driver()
                .expect("driver")
                .version()
                .as_str(),
            "580.95.05"
        );
        assert!(matches!(
            snapshot.accelerators()[0].compute(),
            ComputeCapability::Cuda {
                architecture,
                maximum_version: Some(version)
            } if architecture.as_str() == "sm_120" && version.as_str() == "cuda_13.0"
        ));
        let telemetry = snapshot.accelerators()[0].telemetry().expect("telemetry");
        assert_eq!(telemetry.temperature_millicelsius(), Some(65_000));
        assert_eq!(telemetry.graphics_clock_mhz(), Some(2_500));
        assert_eq!(telemetry.memory_clock_mhz(), Some(2_000));
        assert_eq!(telemetry.utilization_per_mille(), Some(500));
        assert_eq!(telemetry.power_milliwatts(), Some(350_500));
        assert_eq!(telemetry.framebuffer_used_bytes(), Some(1024 * 1024 * 1024));
        assert!(snapshot
            .interconnects()
            .iter()
            .any(|link| link.kind() == InterconnectObservationKind::Nvlink));
        assert!(snapshot
            .interconnects()
            .iter()
            .any(|link| link.kind() == InterconnectObservationKind::Rdma));
    }
}

// Represents optional NVIDIA and RDMA mechanisms as absent observations.
#[test]
fn linux_provider_observes_cpu_only_host() {
    let configuration = LinuxHardwareConfiguration::new(
        CpuArchitecture::Arm64,
        "/proc/boot_id".into(),
        "/proc/cpuinfo".into(),
        "/proc/meminfo".into(),
        None,
        None,
    )
    .expect("configuration");
    let snapshot = LinuxHardwareProvider::new(configuration, Arc::new(LinuxFixtureIo::default()))
        .observe()
        .expect("CPU-only observation");
    assert!(snapshot.accelerators().is_empty());
    assert!(snapshot.interconnects().is_empty());
}

// Rejects every Linux native provider failure without returning partial state.
#[test]
fn linux_provider_fails_at_every_native_boundary() {
    for failure_index in 0..7 {
        let provider = linux_provider(
            CpuArchitecture::X86_64,
            Arc::new(FailAtIo::new(LinuxFixtureIo::default(), failure_index)),
        );
        assert_eq!(
            provider.observe().expect_err("native boundary failure"),
            HardwareError::ProviderUnavailable,
            "boundary {failure_index}"
        );
    }
}

// Rejects malformed Linux CPU, memory, NVIDIA, topology, and RDMA facts.
#[test]
fn linux_provider_rejects_malformed_native_facts() {
    let mut cases = Vec::new();
    let mut fixture = LinuxFixtureIo::default();
    fixture.cpuinfo = Ok("processor : 0\n".to_string());
    cases.push(fixture);
    let mut fixture = LinuxFixtureIo::default();
    fixture.meminfo = Ok("MemTotal: overflow kB\n".to_string());
    cases.push(fixture);
    let mut fixture = LinuxFixtureIo::default();
    fixture.nvidia_banner = Ok("CUDA Version: future\n".to_string());
    cases.push(fixture);
    for csv in [
        "GPU-bad,Too Few Fields\n",
        "",
        concat!(
            "GPU-0, NVIDIA RTX, 32768, 1024, 65, 2500, 2000, 50, 350.5, 12.0, 580.95.05\n",
            "GPU-0, NVIDIA RTX, 32768, 1024, 65, 2500, 2000, 50, 350.5, 12.0, 580.95.05\n"
        ),
        "GPU-0, NVIDIA RTX, 1, 2, 65, 2500, 2000, 50, 350.5, 12.0, 580.95.05\n",
        "GPU-0, NVIDIA RTX, 32768, 1, 65.1234, 2500, 2000, 50, 350.5, 12.0, 580.95.05\n",
        "GPU-0, NVIDIA RTX, 32768, 1, 65, 2500, 2000, 101, 350.5, 12.0, 580.95.05\n",
        "GPU-0, NVIDIA RTX, 32768, 1, 65, 2500, 2000, 50, 350.5, bad, 580.95.05\n",
        "GPU-0, NVIDIA RTX, 32768, 1, 65, 2500, 2000, 50, 350.5, 12.0, bad driver\n",
    ] {
        let mut fixture = LinuxFixtureIo::default();
        fixture.nvidia_csv = Ok(csv.to_string());
        cases.push(fixture);
    }
    for topology in [
        "GPU0 X NV4\n",
        "GPU0 X NV4\nGPU0 X NV4\nGPU1 NV4 X\n",
        "GPU0 X NV4\nGPU1 SYS X\n",
        "GPU0 X X\nGPU1 X X\n",
    ] {
        let mut fixture = LinuxFixtureIo::default();
        fixture.nvidia_topology = Ok(topology.to_string());
        cases.push(fixture);
    }
    for rdma in [
        "link mlx5_0/1 state ACTIVE\n",
        "link mlx5_0/1 netdev enp1s0\n",
        concat!(
            "link mlx5_0/1 state ACTIVE netdev enp1s0\n",
            "link mlx5_1/1 state DOWN netdev enp1s0\n"
        ),
    ] {
        let mut fixture = LinuxFixtureIo::default();
        fixture.rdma = Ok(rdma.to_string());
        cases.push(fixture);
    }
    let mut fixture = LinuxFixtureIo::default();
    fixture.nvidia_csv = Ok((0..65)
        .map(|index| {
            format!(
                "GPU-{index}, NVIDIA RTX, 32768, 1, 65, 2500, 2000, 50, 350.5, 12.0, 580.95.05\n"
            )
        })
        .collect());
    cases.push(fixture);
    let mut fixture = LinuxFixtureIo::default();
    fixture.rdma = Ok((0..257)
        .map(|index| format!("link mlx5_{index}/1 state ACTIVE netdev enp{index}s0\n"))
        .collect());
    cases.push(fixture);
    for (index, fixture) in cases.into_iter().enumerate() {
        assert!(
            matches!(
                linux_provider(CpuArchitecture::X86_64, Arc::new(fixture)).observe(),
                Err(HardwareError::InvalidObservation { .. }) | Err(HardwareError::Interface(_))
            ),
            "case {index}"
        );
    }
}

// Preserves complete GPU matrix relations and explicit active/inactive RDMA rows.
#[test]
fn linux_provider_observes_multi_gpu_and_link_matrix() {
    let mut fixture = LinuxFixtureIo::default();
    fixture.nvidia_csv = Ok(concat!(
        "GPU-0, NVIDIA RTX, 32768, 1, 60, 1, 1, 1, 1, 12.0, 580.95.05\n",
        "GPU-1, NVIDIA RTX, 32768, 1, 60, 1, 1, 1, 1, 12.0, 580.95.05\n",
        "GPU-2, NVIDIA RTX, 32768, 1, 60, 1, 1, 1, 1, 12.0, 580.95.05\n"
    )
    .to_string());
    fixture.nvidia_topology = Ok(concat!(
        "GPU0 GPU1 GPU2\n",
        "GPU0 X NV4 SYS\n",
        "GPU1 NV4 X N/A\n",
        "GPU2 SYS N/A X\n"
    )
    .to_string());
    fixture.rdma = Ok(concat!(
        "link mlx5_0/1 state ACTIVE netdev enp1s0\n",
        "link mlx5_1/1 state DOWN netdev enp2s0\n"
    )
    .to_string());
    let snapshot = linux_provider(CpuArchitecture::Arm64, Arc::new(fixture))
        .observe()
        .expect("matrix observation");
    assert_eq!(snapshot.accelerators().len(), 3);
    assert_eq!(
        snapshot
            .interconnects()
            .iter()
            .filter(|link| link.kind() == InterconnectObservationKind::Nvlink)
            .count(),
        1
    );
    assert_eq!(
        snapshot
            .interconnects()
            .iter()
            .filter(|link| link.kind() == InterconnectObservationKind::Pcie)
            .count(),
        1
    );
    let rdma: Vec<_> = snapshot
        .interconnects()
        .iter()
        .filter(|link| link.kind() == InterconnectObservationKind::Rdma)
        .collect();
    assert_eq!(rdma.len(), 2);
    assert!(rdma[0].is_available());
    assert!(!rdma[1].is_available());
    assert!(rdma.iter().all(|link| link.device_ids().is_empty()));
}

// Parses Apple host and Metal family/version labels through fixed native commands.
#[test]
fn macos_provider_observes_injected_native_facts() {
    let snapshot = macos_provider(Arc::new(MacOsFixtureIo::default()))
        .observe()
        .expect("macOS observation");
    assert_eq!(snapshot.processor().model().as_str(), "Apple M4 Max");
    assert_eq!(snapshot.accelerators().len(), 1);
    assert_eq!(
        snapshot.accelerators()[0].device_id().as_str(),
        "APPLE-0000000000000001"
    );
    assert!(matches!(
        snapshot.accelerators()[0].compute(),
        ComputeCapability::Metal { family, version }
            if family.as_str() == "apple9" && version.as_str() == "metal4"
    ));
}

// Rejects every macOS native provider failure without returning partial state.
#[test]
fn macos_provider_fails_at_every_native_boundary() {
    for failure_index in 0..5 {
        let provider = macos_provider(Arc::new(FailAtIo::new(
            MacOsFixtureIo::default(),
            failure_index,
        )));
        assert_eq!(
            provider.observe().expect_err("native boundary failure"),
            HardwareError::ProviderUnavailable,
            "boundary {failure_index}"
        );
    }
}

// Rejects missing, partial, duplicate, and malformed Apple Metal observations.
#[test]
fn macos_provider_rejects_malformed_native_facts() {
    let mut cases = Vec::new();
    let mut fixture = MacOsFixtureIo::default();
    fixture.boot_id = Ok("\n".to_string());
    cases.push(fixture);
    let mut fixture = MacOsFixtureIo::default();
    fixture.logical_cpu_count = Ok("zero\n".to_string());
    cases.push(fixture);
    let mut fixture = MacOsFixtureIo::default();
    fixture.memory_bytes = Ok("0\n".to_string());
    cases.push(fixture);
    for metal in [
        "",
        "APPLE-1\tApple M4 Max\tapple9\n",
        "APPLE-1\tApple M4 Max\tapple_unknown\tmetal4\n",
        "APPLE-1\tApple M4 Max\tapple9\tmetal0\n",
        concat!(
            "APPLE-1\tApple M4 Max\tapple9\tmetal4\n",
            "APPLE-1\tApple M4 Max\tapple9\tmetal4\n"
        ),
    ] {
        let mut fixture = MacOsFixtureIo::default();
        fixture.metal = Ok(metal.to_string());
        cases.push(fixture);
    }
    let mut fixture = MacOsFixtureIo::default();
    fixture.metal = Ok((0..65)
        .map(|index| format!("APPLE-{index:016x}\tApple GPU\tapple9\tmetal4\n"))
        .collect());
    cases.push(fixture);
    for (index, fixture) in cases.into_iter().enumerate() {
        assert!(
            matches!(
                macos_provider(Arc::new(fixture)).observe(),
                Err(HardwareError::InvalidObservation { .. }) | Err(HardwareError::Interface(_))
            ),
            "case {index}"
        );
    }
}

// Rejects non-absolute native provider dependencies before any observation.
#[test]
fn provider_configurations_reject_relative_native_paths() {
    assert!(matches!(
        LinuxHardwareConfiguration::new(
            CpuArchitecture::Arm64,
            "boot_id".into(),
            "/proc/cpuinfo".into(),
            "/proc/meminfo".into(),
            None,
            None,
        ),
        Err(HardwareError::InvalidObservation { .. })
    ));
    assert!(matches!(
        MacOsHardwareConfiguration::new("sysctl".into(), "/probe".into()),
        Err(HardwareError::InvalidObservation { .. })
    ));
}

// Keeps native provider diagnostics stable and redacted from supplied data.
#[test]
fn provider_errors_do_not_echo_native_input() {
    let secret = "secret-native-value";
    let mut fixture = LinuxFixtureIo::default();
    fixture.nvidia_csv = Ok(secret.to_string());
    let error = linux_provider(CpuArchitecture::X86_64, Arc::new(fixture))
        .observe()
        .expect_err("invalid native input");
    assert!(!error.to_string().contains(secret));
}
