// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use li_watchdog_manager::{
    LinuxWatchdogSampleProvider, WatchdogError, WatchdogLinuxCapability, WatchdogLinuxClock,
    WatchdogLinuxClocks, WatchdogLinuxFilesystemUsage, WatchdogLinuxGpuProvider,
    WatchdogLinuxGpuSample, WatchdogLinuxHostFileProvider, WatchdogLinuxSampleLayout,
    WatchdogSampleProvider, WATCHDOG_CLOCK_UNKNOWN, WATCHDOG_PERCENT_UNKNOWN,
    WATCHDOG_SAMPLE_GPU_AVAILABLE, WATCHDOG_SAMPLE_THROTTLED, WATCHDOG_TEMP_UNKNOWN,
};

type Capability<T> = Result<WatchdogLinuxCapability<T>, WatchdogError>;

// Supplies an ordered deterministic clock plan.
struct ClockMock {
    plans: Mutex<VecDeque<Result<WatchdogLinuxClocks, WatchdogError>>>,
}

impl ClockMock {
    // Creates one clock from exact wall and monotonic millisecond pairs.
    fn new(values: &[(u64, u64)]) -> Self {
        Self {
            plans: Mutex::new(
                values
                    .iter()
                    .map(|(unix, monotonic)| WatchdogLinuxClocks::new(*unix, *monotonic))
                    .collect(),
            ),
        }
    }
}

impl WatchdogLinuxClock for ClockMock {
    // Returns the next exact pair without consulting the test host.
    fn clocks(&self) -> Result<WatchdogLinuxClocks, WatchdogError> {
        self.plans
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| Err(WatchdogError::provider("clock mock", "exhausted")))
    }
}

// Supplies bounded native file, directory, and filesystem plans by exact path.
#[derive(Default)]
struct HostFileMock {
    reads: Mutex<BTreeMap<PathBuf, VecDeque<Capability<Vec<u8>>>>>,
    entries: Mutex<BTreeMap<PathBuf, VecDeque<Capability<Vec<String>>>>>,
    filesystems: Mutex<BTreeMap<PathBuf, VecDeque<Capability<WatchdogLinuxFilesystemUsage>>>>,
}

impl HostFileMock {
    // Appends one available UTF-8 file result for an exact native path.
    fn push_text(&self, path: &str, value: &str) {
        self.reads
            .lock()
            .unwrap()
            .entry(PathBuf::from(path))
            .or_default()
            .push_back(Ok(WatchdogLinuxCapability::Available(
                value.as_bytes().to_vec(),
            )));
    }

    // Appends one available directory listing for an exact native root.
    fn push_entries(&self, path: &str, values: &[&str]) {
        self.entries
            .lock()
            .unwrap()
            .entry(PathBuf::from(path))
            .or_default()
            .push_back(Ok(WatchdogLinuxCapability::Available(
                values.iter().map(|value| value.to_string()).collect(),
            )));
    }

    // Appends one available filesystem-capacity result.
    fn push_filesystem(&self, path: &str, total: u64, available: u64) {
        self.filesystems
            .lock()
            .unwrap()
            .entry(PathBuf::from(path))
            .or_default()
            .push_back(
                WatchdogLinuxFilesystemUsage::new(total, available)
                    .map(WatchdogLinuxCapability::Available),
            );
    }
}

impl WatchdogLinuxHostFileProvider for HostFileMock {
    // Returns one queued file result or an explicit unsupported capability.
    fn read(
        &self,
        path: &Path,
        _maximum_bytes: usize,
    ) -> Result<WatchdogLinuxCapability<Vec<u8>>, WatchdogError> {
        self.reads
            .lock()
            .unwrap()
            .get_mut(path)
            .and_then(VecDeque::pop_front)
            .unwrap_or(Ok(WatchdogLinuxCapability::Unsupported))
    }

    // Returns one queued directory result or an explicit unsupported capability.
    fn entries(
        &self,
        path: &Path,
        _maximum_entries: usize,
    ) -> Result<WatchdogLinuxCapability<Vec<String>>, WatchdogError> {
        self.entries
            .lock()
            .unwrap()
            .get_mut(path)
            .and_then(VecDeque::pop_front)
            .unwrap_or(Ok(WatchdogLinuxCapability::Unsupported))
    }

    // Returns one queued capacity result or an explicit unsupported capability.
    fn filesystem_usage(
        &self,
        path: &Path,
    ) -> Result<WatchdogLinuxCapability<WatchdogLinuxFilesystemUsage>, WatchdogError> {
        self.filesystems
            .lock()
            .unwrap()
            .get_mut(path)
            .and_then(VecDeque::pop_front)
            .unwrap_or(Ok(WatchdogLinuxCapability::Unsupported))
    }
}

// Supplies ordered GPU capability or failure results.
struct GpuMock {
    plans: Mutex<VecDeque<Capability<WatchdogLinuxGpuSample>>>,
}

impl GpuMock {
    // Creates one GPU provider from exact queued outcomes.
    fn new(plans: Vec<Capability<WatchdogLinuxGpuSample>>) -> Self {
        Self {
            plans: Mutex::new(plans.into()),
        }
    }
}

impl WatchdogLinuxGpuProvider for GpuMock {
    // Returns the next device-provider outcome without reading this machine.
    fn sample(&self) -> Result<WatchdogLinuxCapability<WatchdogLinuxGpuSample>, WatchdogError> {
        self.plans
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Ok(WatchdogLinuxCapability::Unsupported))
    }
}

// Returns the production path identity while retaining completely mocked native I/O.
fn layout() -> WatchdogLinuxSampleLayout {
    WatchdogLinuxSampleLayout::system()
}

// Queues all ordinary native sources once with caller-selected cumulative counters.
fn queue_ordinary_sources(
    files: &HostFileMock,
    cpu: &str,
    disk_read_sectors: u64,
    disk_write_sectors: u64,
    network_receive: u64,
    network_transmit: u64,
) {
    files.push_text("/proc/stat", cpu);
    files.push_text(
        "/proc/meminfo",
        "MemTotal: 16777216 kB\nMemAvailable: 12582912 kB\nSwapTotal: 1024 kB\nSwapFree: 512 kB\n",
    );
    files.push_text("/proc/loadavg", "1.25 0.50 0.25 1/100 123\n");
    files.push_text(
        "/proc/diskstats",
        &format!(
            "259 0 nvme0n1 1 0 {disk_read_sectors} 0 1 0 {disk_write_sectors} 0\n259 1 nvme0n1p1 1 0 999999 0 1 0 999999 0\n"
        ),
    );
    files.push_text(
        "/proc/net/dev",
        &format!(
            "Inter-| Receive | Transmit\n lo: 999 0 0 0 0 0 0 0 999 0 0 0 0 0 0 0\n eth0: {network_receive} 0 0 0 0 0 0 0 {network_transmit} 0 0 0 0 0 0 0\n"
        ),
    );
    files.push_entries("/sys/devices/system/cpu/cpufreq", &["policy0", "noise"]);
    files.push_text(
        "/sys/devices/system/cpu/cpufreq/policy0/scaling_cur_freq",
        "2200000\n",
    );
    files.push_entries("/sys/class/thermal", &["thermal_zone0", "thermal_zone1"]);
    files.push_text("/sys/class/thermal/thermal_zone0/temp", "55000\n");
    files.push_text("/sys/class/thermal/thermal_zone1/temp", "61000\n");
    files.push_entries("/sys/class/hwmon", &["hwmon0", "hwmon1"]);
    files.push_text("/sys/class/hwmon/hwmon0/name", "nvme\n");
    files.push_text("/sys/class/hwmon/hwmon0/temp1_input", "47000\n");
    files.push_text("/sys/class/hwmon/hwmon1/name", "coretemp\n");
    files.push_filesystem("/", 16 << 30, 12 << 30);
}

// Proves interval sampling, hardware hooks, fixed sentinels, and rates match the C record contract.
#[test]
fn linux_sampler_projects_two_complete_native_intervals() {
    let files = Arc::new(HostFileMock::default());
    queue_ordinary_sources(
        &files,
        "cpu 100 0 100 800 0\ncpu0 50 0 50 400 0\ncpu1 50 0 50 400 0\n",
        100,
        200,
        1_000,
        2_000,
    );
    queue_ordinary_sources(
        &files,
        "cpu 120 0 120 860 0\ncpu0 60 0 60 430 0\ncpu1 60 0 60 430 0\n",
        1_124,
        1_224,
        1_049_576,
        526_288,
    );
    let gpu = WatchdogLinuxGpuSample::new(
        80,
        60,
        [80, 60, 10, 20, 30, 40],
        650,
        1_250,
        true,
        2_100,
        4_000,
    )
    .unwrap();
    let provider = LinuxWatchdogSampleProvider::new(
        layout(),
        Arc::new(ClockMock::new(&[
            (1_700_000_000_000, 1_000),
            (1_700_000_001_000, 2_000),
        ])),
        files,
        Arc::new(GpuMock::new(vec![
            Ok(WatchdogLinuxCapability::Available(gpu.clone())),
            Ok(WatchdogLinuxCapability::Available(gpu)),
        ])),
    );

    let first = provider.sample(1).unwrap();
    let second = provider.sample(2).unwrap();

    assert_eq!(first.telemetry().cpu_percent, WATCHDOG_PERCENT_UNKNOWN);
    assert_eq!(first.telemetry().cpu_core_count, 2);
    assert_eq!(first.telemetry().disk_read_kib_s, 0);
    assert_eq!(second.telemetry().cpu_percent, 40);
    assert_eq!(&second.telemetry().cpu_core_percent[..2], &[40, 40]);
    assert_eq!(second.telemetry().memory_percent, 25);
    assert_eq!(second.telemetry().memory_used_mib, 4_096);
    assert_eq!(second.telemetry().load1_centi, 125);
    assert_eq!(second.telemetry().disk_percent, 25);
    assert_eq!(second.telemetry().disk_read_kib_s, 512);
    assert_eq!(second.telemetry().disk_write_kib_s, 512);
    assert_eq!(second.telemetry().network_rx_kib_s, 1_024);
    assert_eq!(second.telemetry().network_tx_kib_s, 512);
    assert_eq!(second.telemetry().cpu_clock_mhz, 2_200);
    assert_eq!(second.telemetry().system_temp_deci_c, 610);
    assert_eq!(second.telemetry().nvme_temp_deci_c, 470);
    assert_eq!(second.telemetry().gpu_percent, 80);
    assert_eq!(second.telemetry().flags & WATCHDOG_SAMPLE_GPU_AVAILABLE, 2);
    assert_eq!(second.telemetry().flags & WATCHDOG_SAMPLE_THROTTLED, 4);
}

// Proves every optional Linux mechanism remains explicitly unavailable rather than reporting zero.
#[test]
fn linux_sampler_preserves_unknown_values_for_unsupported_optional_capabilities() {
    let files = Arc::new(HostFileMock::default());
    files.push_text("/proc/stat", "cpu 1 2 3 4\ncpu0 1 2 3 4\n");
    files.push_text(
        "/proc/meminfo",
        "MemTotal: 4096 kB\nMemAvailable: 2048 kB\n",
    );
    let provider = LinuxWatchdogSampleProvider::new(
        layout(),
        Arc::new(ClockMock::new(&[(10, 20)])),
        files,
        Arc::new(GpuMock::new(vec![Ok(WatchdogLinuxCapability::Unsupported)])),
    );

    let sample = provider.sample(1).unwrap();
    let telemetry = sample.telemetry();

    assert_eq!(telemetry.cpu_clock_mhz, WATCHDOG_CLOCK_UNKNOWN);
    assert_eq!(telemetry.system_temp_deci_c, WATCHDOG_TEMP_UNKNOWN);
    assert_eq!(telemetry.nvme_temp_deci_c, WATCHDOG_TEMP_UNKNOWN);
    assert_eq!(telemetry.gpu_temp_deci_c, WATCHDOG_TEMP_UNKNOWN);
    assert_eq!(telemetry.gpu_percent, WATCHDOG_PERCENT_UNKNOWN);
    assert_eq!(telemetry.disk_percent, WATCHDOG_PERCENT_UNKNOWN);
    assert_eq!(telemetry.flags & WATCHDOG_SAMPLE_GPU_AVAILABLE, 0);
}

// Proves provider failure never advances cumulative baselines and a retry remains deterministic.
#[test]
fn linux_sampler_commits_baselines_only_after_every_provider_succeeds() {
    let files = Arc::new(HostFileMock::default());
    for cpu in [
        "cpu 100 0 0 900\ncpu0 100 0 0 900\n",
        "cpu 200 0 0 900\ncpu0 200 0 0 900\n",
        "cpu 300 0 0 900\ncpu0 300 0 0 900\n",
    ] {
        files.push_text("/proc/stat", cpu);
        files.push_text(
            "/proc/meminfo",
            "MemTotal: 4096 kB\nMemAvailable: 2048 kB\n",
        );
    }
    let provider = LinuxWatchdogSampleProvider::new(
        layout(),
        Arc::new(ClockMock::new(&[(10, 1_000), (20, 2_000), (30, 3_000)])),
        files,
        Arc::new(GpuMock::new(vec![
            Ok(WatchdogLinuxCapability::Unsupported),
            Err(WatchdogError::provider("GPU mock", "failed")),
            Ok(WatchdogLinuxCapability::Unsupported),
        ])),
    );

    assert!(provider.sample(1).is_ok());
    assert!(provider.sample(2).is_err());
    let retry = provider.sample(2).unwrap();

    assert_eq!(retry.sequence(), 2);
    assert_eq!(retry.telemetry().cpu_percent, 100);
}

// Proves malformed required sources, stale clocks, GPU bounds, and layout traversal fail closed.
#[test]
fn linux_sampler_rejects_invalid_native_contracts() {
    assert!(WatchdogLinuxGpuSample::new(101, 0, [0; 6], 0, 0, false, 1, 1,).is_err());
    assert!(WatchdogLinuxSampleLayout::new(
        PathBuf::from("relative/stat"),
        PathBuf::from("/proc/meminfo"),
        PathBuf::from("/proc/loadavg"),
        PathBuf::from("/proc/diskstats"),
        PathBuf::from("/proc/net/dev"),
        PathBuf::from("/sys/cpu"),
        PathBuf::from("/sys/thermal"),
        PathBuf::from("/sys/hwmon"),
        PathBuf::from("/"),
    )
    .is_err());

    let files = Arc::new(HostFileMock::default());
    files.push_text("/proc/stat", "intr 1 2 3\n");
    files.push_text(
        "/proc/meminfo",
        "MemTotal: 4096 kB\nMemAvailable: 2048 kB\n",
    );
    let provider = LinuxWatchdogSampleProvider::new(
        layout(),
        Arc::new(ClockMock::new(&[(10, 20)])),
        files,
        Arc::new(GpuMock::new(Vec::new())),
    );
    assert!(provider.sample(1).is_err());

    let files = Arc::new(HostFileMock::default());
    for _ in 0..2 {
        files.push_text("/proc/stat", "cpu 1 2 3 4\n");
        files.push_text(
            "/proc/meminfo",
            "MemTotal: 4096 kB\nMemAvailable: 2048 kB\n",
        );
    }
    let provider = LinuxWatchdogSampleProvider::new(
        layout(),
        Arc::new(ClockMock::new(&[(10, 20), (11, 20)])),
        files,
        Arc::new(GpuMock::new(Vec::new())),
    );
    assert!(provider.sample(1).is_ok());
    assert!(provider.sample(2).is_err());
}
