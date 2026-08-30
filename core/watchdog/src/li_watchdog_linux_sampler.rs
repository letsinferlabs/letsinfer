// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::{
    UnsupportedWatchdogGatewayTelemetryProvider, WatchdogError,
    WatchdogGatewayTelemetrySampleProvider, WatchdogSample, WatchdogSampleProvider,
    WatchdogSampleTelemetry, WATCHDOG_CLOCK_UNKNOWN, WATCHDOG_GPU_ENGINES, WATCHDOG_MAX_CPU_CORES,
    WATCHDOG_PERCENT_UNKNOWN, WATCHDOG_SAMPLE_GPU_AVAILABLE, WATCHDOG_SAMPLE_THROTTLED,
    WATCHDOG_TEMP_UNKNOWN,
};

const MAX_NATIVE_PATH_BYTES: usize = 4_095;
const MAX_PROC_STAT_BYTES: usize = 64 * 1_024;
const MAX_MEMINFO_BYTES: usize = 16 * 1_024;
const MAX_LOADAVG_BYTES: usize = 256;
const MAX_COUNTER_BYTES: usize = 256 * 1_024;
const MAX_DIRECTORY_ENTRIES: usize = 1_024;
const MAX_SMALL_VALUE_BYTES: usize = 256;

// Distinguishes a supported native value from a capability the host does not expose.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WatchdogLinuxCapability<T> {
    Available(T),
    Unsupported,
}

// Carries one exact pair of wall and monotonic clocks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchdogLinuxClocks {
    unix_milliseconds: u64,
    monotonic_milliseconds: u64,
}

impl WatchdogLinuxClocks {
    // Creates one positive clock pair suitable for a durable sample.
    pub fn new(unix_milliseconds: u64, monotonic_milliseconds: u64) -> Result<Self, WatchdogError> {
        if unix_milliseconds == 0 || monotonic_milliseconds == 0 {
            return Err(WatchdogError::InvalidContract {
                reason: "Linux Watchdog clocks must be positive",
            });
        }
        Ok(Self {
            unix_milliseconds,
            monotonic_milliseconds,
        })
    }

    // Returns wall time in Unix milliseconds.
    pub const fn unix_milliseconds(self) -> u64 {
        self.unix_milliseconds
    }

    // Returns process-independent monotonic time in milliseconds.
    pub const fn monotonic_milliseconds(self) -> u64 {
        self.monotonic_milliseconds
    }
}

// Supplies the two clocks consumed by one Linux sampling transaction.
pub trait WatchdogLinuxClock: Send + Sync {
    // Reads one internally consistent wall and monotonic clock pair.
    fn clocks(&self) -> Result<WatchdogLinuxClocks, WatchdogError>;
}

// Carries exact filesystem capacity without imposing telemetry representation limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchdogLinuxFilesystemUsage {
    total_bytes: u64,
    available_bytes: u64,
}

impl WatchdogLinuxFilesystemUsage {
    // Creates one filesystem capacity observation with available space inside total space.
    pub fn new(total_bytes: u64, available_bytes: u64) -> Result<Self, WatchdogError> {
        if total_bytes == 0 || available_bytes > total_bytes {
            return Err(WatchdogError::InvalidContract {
                reason: "Linux filesystem capacity is invalid",
            });
        }
        Ok(Self {
            total_bytes,
            available_bytes,
        })
    }

    // Returns total filesystem capacity in bytes.
    pub const fn total_bytes(self) -> u64 {
        self.total_bytes
    }

    // Returns currently available filesystem capacity in bytes.
    pub const fn available_bytes(self) -> u64 {
        self.available_bytes
    }
}

// Isolates bounded read-only Linux procfs, sysfs, and filesystem operations.
pub trait WatchdogLinuxHostFileProvider: Send + Sync {
    // Reads at most the caller-declared number of bytes without following a final link.
    fn read(
        &self,
        path: &Path,
        maximum_bytes: usize,
    ) -> Result<WatchdogLinuxCapability<Vec<u8>>, WatchdogError>;

    // Lists at most the caller-declared number of UTF-8 directory entries.
    fn entries(
        &self,
        path: &Path,
        maximum_entries: usize,
    ) -> Result<WatchdogLinuxCapability<Vec<String>>, WatchdogError>;

    // Reads filesystem capacity for one exact mount path.
    fn filesystem_usage(
        &self,
        path: &Path,
    ) -> Result<WatchdogLinuxCapability<WatchdogLinuxFilesystemUsage>, WatchdogError>;
}

// Carries one already-aggregated optional GPU observation from a device provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogLinuxGpuSample {
    gpu_percent: u8,
    memory_percent: u8,
    engine_percent: [u8; WATCHDOG_GPU_ENGINES],
    temperature_deci_c: i16,
    power_deci_w: u16,
    throttled: bool,
    gpu_clock_mhz: u32,
    vram_clock_mhz: u32,
}

impl WatchdogLinuxGpuSample {
    // Creates one bounded aggregate without fabricating unavailable device values.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        gpu_percent: u8,
        memory_percent: u8,
        engine_percent: [u8; WATCHDOG_GPU_ENGINES],
        temperature_deci_c: i16,
        power_deci_w: u16,
        throttled: bool,
        gpu_clock_mhz: u32,
        vram_clock_mhz: u32,
    ) -> Result<Self, WatchdogError> {
        if !valid_percent(gpu_percent)
            || !valid_percent(memory_percent)
            || engine_percent
                .into_iter()
                .any(|value| !valid_percent(value))
            || (temperature_deci_c != WATCHDOG_TEMP_UNKNOWN
                && !(-1_000..=2_500).contains(&temperature_deci_c))
            || !valid_clock(gpu_clock_mhz)
            || !valid_clock(vram_clock_mhz)
        {
            return Err(WatchdogError::InvalidContract {
                reason: "Linux GPU sample is outside the native record bounds",
            });
        }
        Ok(Self {
            gpu_percent,
            memory_percent,
            engine_percent,
            temperature_deci_c,
            power_deci_w,
            throttled,
            gpu_clock_mhz,
            vram_clock_mhz,
        })
    }
}

// Supplies one optional aggregate from a concrete Linux GPU implementation.
pub trait WatchdogLinuxGpuProvider: Send + Sync {
    // Samples every configured device or reports that the GPU mechanism is unsupported.
    fn sample(&self) -> Result<WatchdogLinuxCapability<WatchdogLinuxGpuSample>, WatchdogError>;
}

// Describes every native path used by the Linux sampler composition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogLinuxSampleLayout {
    proc_stat: PathBuf,
    meminfo: PathBuf,
    loadavg: PathBuf,
    diskstats: PathBuf,
    network_devices: PathBuf,
    cpu_frequency_root: PathBuf,
    thermal_root: PathBuf,
    hardware_monitor_root: PathBuf,
    storage_root: PathBuf,
}

impl WatchdogLinuxSampleLayout {
    // Creates one explicit Linux native layout after closing traversal and length ambiguity.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        proc_stat: PathBuf,
        meminfo: PathBuf,
        loadavg: PathBuf,
        diskstats: PathBuf,
        network_devices: PathBuf,
        cpu_frequency_root: PathBuf,
        thermal_root: PathBuf,
        hardware_monitor_root: PathBuf,
        storage_root: PathBuf,
    ) -> Result<Self, WatchdogError> {
        for path in [
            &proc_stat,
            &meminfo,
            &loadavg,
            &diskstats,
            &network_devices,
            &cpu_frequency_root,
            &thermal_root,
            &hardware_monitor_root,
            &storage_root,
        ] {
            validate_native_path(path)?;
        }
        Ok(Self {
            proc_stat,
            meminfo,
            loadavg,
            diskstats,
            network_devices,
            cpu_frequency_root,
            thermal_root,
            hardware_monitor_root,
            storage_root,
        })
    }

    // Returns the production Linux procfs, sysfs, and root-filesystem layout.
    pub fn system() -> Self {
        Self::new(
            PathBuf::from("/proc/stat"),
            PathBuf::from("/proc/meminfo"),
            PathBuf::from("/proc/loadavg"),
            PathBuf::from("/proc/diskstats"),
            PathBuf::from("/proc/net/dev"),
            PathBuf::from("/sys/devices/system/cpu/cpufreq"),
            PathBuf::from("/sys/class/thermal"),
            PathBuf::from("/sys/class/hwmon"),
            PathBuf::from("/"),
        )
        .expect("fixed Linux Watchdog sample layout")
    }
}

// Reads Linux clocks directly without retaining mutable sampling state.
#[derive(Default)]
pub struct SystemWatchdogLinuxClock;

impl WatchdogLinuxClock for SystemWatchdogLinuxClock {
    // Reads realtime and monotonic clock_gettime values through fixed clock identities.
    fn clocks(&self) -> Result<WatchdogLinuxClocks, WatchdogError> {
        WatchdogLinuxClocks::new(
            system_clock_milliseconds(libc::CLOCK_REALTIME)?,
            system_clock_milliseconds(libc::CLOCK_MONOTONIC)?,
        )
    }
}

// Performs bounded read-only operations against fixed native paths.
#[derive(Default)]
pub struct SystemWatchdogLinuxHostFileProvider;

impl WatchdogLinuxHostFileProvider for SystemWatchdogLinuxHostFileProvider {
    // Reads one fixed native file through a close-on-exec descriptor.
    fn read(
        &self,
        path: &Path,
        maximum_bytes: usize,
    ) -> Result<WatchdogLinuxCapability<Vec<u8>>, WatchdogError> {
        if maximum_bytes == 0 || maximum_bytes > MAX_COUNTER_BYTES {
            return Err(native_sample_error("native read bound is invalid"));
        }
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(WatchdogLinuxCapability::Unsupported)
            }
            Err(_) => return Err(native_sample_error("native file could not be opened")),
        };
        read_bounded_file(file, maximum_bytes).map(WatchdogLinuxCapability::Available)
    }

    // Lists one fixed native directory under an explicit entry bound.
    fn entries(
        &self,
        path: &Path,
        maximum_entries: usize,
    ) -> Result<WatchdogLinuxCapability<Vec<String>>, WatchdogError> {
        if maximum_entries == 0 || maximum_entries > MAX_DIRECTORY_ENTRIES {
            return Err(native_sample_error("native directory bound is invalid"));
        }
        let directory = match fs::read_dir(path) {
            Ok(directory) => directory,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(WatchdogLinuxCapability::Unsupported)
            }
            Err(_) => return Err(native_sample_error("native directory could not be opened")),
        };
        let mut entries = Vec::new();
        for entry in directory {
            let entry = entry.map_err(|_| native_sample_error("native directory changed"))?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| native_sample_error("native directory name is not UTF-8"))?;
            entries.push(name);
            if entries.len() > maximum_entries {
                return Err(native_sample_error("native directory exceeded its bound"));
            }
        }
        entries.sort();
        Ok(WatchdogLinuxCapability::Available(entries))
    }

    // Reads one fixed filesystem capacity with checked native arithmetic.
    fn filesystem_usage(
        &self,
        path: &Path,
    ) -> Result<WatchdogLinuxCapability<WatchdogLinuxFilesystemUsage>, WatchdogError> {
        let path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| native_sample_error("filesystem path is invalid"))?;
        let mut details = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        // SAFETY: the path is NUL-terminated and statvfs initializes details on success.
        let result = unsafe { libc::statvfs(path.as_ptr(), details.as_mut_ptr()) };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::NotFound {
                return Ok(WatchdogLinuxCapability::Unsupported);
            }
            return Err(native_sample_error("filesystem capacity is unavailable"));
        }
        // SAFETY: a successful statvfs call initialized every field in details.
        let details = unsafe { details.assume_init() };
        let fragment = details.f_frsize as u128;
        let total = u128::from(details.f_blocks).saturating_mul(fragment);
        let available = u128::from(details.f_bavail).saturating_mul(fragment);
        let total = u64::try_from(total).unwrap_or(u64::MAX);
        let available = u64::try_from(available).unwrap_or(u64::MAX).min(total);
        WatchdogLinuxFilesystemUsage::new(total, available).map(WatchdogLinuxCapability::Available)
    }
}

// Reports an explicit unsupported GPU capability until a device provider is composed.
#[derive(Default)]
pub struct UnsupportedWatchdogLinuxGpuProvider;

impl WatchdogLinuxGpuProvider for UnsupportedWatchdogLinuxGpuProvider {
    // Preserves native unknown sentinels without converting absence into zero utilization.
    fn sample(&self) -> Result<WatchdogLinuxCapability<WatchdogLinuxGpuSample>, WatchdogError> {
        Ok(WatchdogLinuxCapability::Unsupported)
    }
}

// Owns Linux sampling baselines while delegating every native read to injected providers.
pub struct LinuxWatchdogSampleProvider {
    layout: WatchdogLinuxSampleLayout,
    clock: Arc<dyn WatchdogLinuxClock>,
    files: Arc<dyn WatchdogLinuxHostFileProvider>,
    gpu: Arc<dyn WatchdogLinuxGpuProvider>,
    gateway: Arc<dyn WatchdogGatewayTelemetrySampleProvider>,
    state: Mutex<LinuxWatchdogSampleState>,
}

impl LinuxWatchdogSampleProvider {
    // Creates one sampler with no fabricated first-sample utilization baseline.
    pub fn new(
        layout: WatchdogLinuxSampleLayout,
        clock: Arc<dyn WatchdogLinuxClock>,
        files: Arc<dyn WatchdogLinuxHostFileProvider>,
        gpu: Arc<dyn WatchdogLinuxGpuProvider>,
    ) -> Self {
        Self {
            layout,
            clock,
            files,
            gpu,
            gateway: Arc::new(UnsupportedWatchdogGatewayTelemetryProvider),
            state: Mutex::new(LinuxWatchdogSampleState::default()),
        }
    }

    // Creates one sampler with explicit GPU and gateway telemetry providers.
    pub fn new_with_gateway(
        layout: WatchdogLinuxSampleLayout,
        clock: Arc<dyn WatchdogLinuxClock>,
        files: Arc<dyn WatchdogLinuxHostFileProvider>,
        gpu: Arc<dyn WatchdogLinuxGpuProvider>,
        gateway: Arc<dyn WatchdogGatewayTelemetrySampleProvider>,
    ) -> Self {
        Self {
            layout,
            clock,
            files,
            gpu,
            gateway,
            state: Mutex::new(LinuxWatchdogSampleState::default()),
        }
    }

    // Creates the production Linux sampler with explicit unsupported GPU state.
    pub fn system() -> Self {
        Self::new(
            WatchdogLinuxSampleLayout::system(),
            Arc::new(SystemWatchdogLinuxClock),
            Arc::new(SystemWatchdogLinuxHostFileProvider),
            Arc::new(UnsupportedWatchdogLinuxGpuProvider),
        )
    }

    // Collects one complete telemetry payload and its next committed baseline.
    fn telemetry(
        &self,
        clocks: WatchdogLinuxClocks,
        previous: &LinuxWatchdogSampleState,
    ) -> Result<(WatchdogSampleTelemetry, LinuxWatchdogSampleState), WatchdogError> {
        if previous.has_baseline
            && clocks.monotonic_milliseconds() <= previous.monotonic_milliseconds
        {
            return Err(native_sample_error("monotonic clock did not advance"));
        }
        let mut telemetry = WatchdogSampleTelemetry::default();
        let cpu_source = required_text(
            self.files
                .read(&self.layout.proc_stat, MAX_PROC_STAT_BYTES)?,
            "procfs CPU counters are unsupported",
        )?;
        let cpu = parse_cpu_counters(&cpu_source)?;
        apply_cpu(&mut telemetry, &cpu, previous);

        let memory_source = required_text(
            self.files.read(&self.layout.meminfo, MAX_MEMINFO_BYTES)?,
            "procfs memory counters are unsupported",
        )?;
        apply_memory(&mut telemetry, &parse_meminfo(&memory_source)?);
        apply_load(
            &mut telemetry,
            optional_text(self.files.read(&self.layout.loadavg, MAX_LOADAVG_BYTES)?)?.as_deref(),
        )?;
        apply_filesystem(
            &mut telemetry,
            self.files.filesystem_usage(&self.layout.storage_root)?,
        );

        let disk = optional_text(self.files.read(&self.layout.diskstats, MAX_COUNTER_BYTES)?)?
            .map(|source| parse_disk_counters(&source))
            .transpose()?
            .unwrap_or_default();
        let network = optional_text(
            self.files
                .read(&self.layout.network_devices, MAX_COUNTER_BYTES)?,
        )?
        .map(|source| parse_network_counters(&source))
        .transpose()?
        .unwrap_or_default();
        let elapsed = clocks
            .monotonic_milliseconds()
            .saturating_sub(previous.monotonic_milliseconds);
        apply_rates(&mut telemetry, disk, network, elapsed, previous);

        telemetry.cpu_clock_mhz = self.cpu_clock()?;
        telemetry.system_temp_deci_c =
            self.highest_temperature(&self.layout.thermal_root, false)?;
        telemetry.nvme_temp_deci_c =
            self.highest_temperature(&self.layout.hardware_monitor_root, true)?;
        apply_gpu(&mut telemetry, self.gpu.sample()?);
        if let WatchdogLinuxCapability::Available(gateway) =
            self.gateway.sample(clocks.unix_milliseconds())?
        {
            gateway.apply(&mut telemetry);
        }

        let next = LinuxWatchdogSampleState {
            cpu: cpu.aggregate,
            cores: cpu.cores,
            disk,
            network,
            monotonic_milliseconds: clocks.monotonic_milliseconds(),
            has_baseline: true,
        };
        Ok((telemetry, next))
    }

    // Resolves the maximum current CPU policy frequency or the native unknown sentinel.
    fn cpu_clock(&self) -> Result<u32, WatchdogError> {
        let entries = match self
            .files
            .entries(&self.layout.cpu_frequency_root, MAX_DIRECTORY_ENTRIES)?
        {
            WatchdogLinuxCapability::Available(entries) => entries,
            WatchdogLinuxCapability::Unsupported => return Ok(WATCHDOG_CLOCK_UNKNOWN),
        };
        let mut maximum_kilohertz = 0_u64;
        for entry in entries {
            if !policy_name(&entry) {
                continue;
            }
            let path = self
                .layout
                .cpu_frequency_root
                .join(entry)
                .join("scaling_cur_freq");
            let Some(source) = optional_text(self.files.read(&path, MAX_SMALL_VALUE_BYTES)?)?
            else {
                continue;
            };
            let value = parse_single_u64(&source, "CPU frequency is malformed")?;
            maximum_kilohertz = maximum_kilohertz.max(value);
        }
        if maximum_kilohertz == 0 {
            return Ok(WATCHDOG_CLOCK_UNKNOWN);
        }
        Ok(saturating_u32(
            (maximum_kilohertz.saturating_add(500)) / 1_000,
        ))
    }

    // Resolves the highest valid system or NVMe temperature under a bounded native root.
    fn highest_temperature(
        &self,
        root: &Path,
        require_nvme_name: bool,
    ) -> Result<i16, WatchdogError> {
        let entries = match self.files.entries(root, MAX_DIRECTORY_ENTRIES)? {
            WatchdogLinuxCapability::Available(entries) => entries,
            WatchdogLinuxCapability::Unsupported => return Ok(WATCHDOG_TEMP_UNKNOWN),
        };
        let mut highest = None;
        for entry in entries {
            if !safe_component(&entry) {
                continue;
            }
            let entry_root = root.join(&entry);
            let temperature_path = if require_nvme_name {
                let Some(name) = optional_text(
                    self.files
                        .read(&entry_root.join("name"), MAX_SMALL_VALUE_BYTES)?,
                )?
                else {
                    continue;
                };
                if !name.trim().starts_with("nvme") {
                    continue;
                }
                entry_root.join("temp1_input")
            } else {
                entry_root.join("temp")
            };
            let Some(source) =
                optional_text(self.files.read(&temperature_path, MAX_SMALL_VALUE_BYTES)?)?
            else {
                continue;
            };
            let millicelsius = source
                .trim()
                .parse::<i64>()
                .map_err(|_| native_sample_error("temperature value is malformed"))?;
            if !(-100_000..=250_000).contains(&millicelsius) {
                continue;
            }
            highest = Some(highest.map_or(millicelsius, |value: i64| value.max(millicelsius)));
        }
        let Some(highest) = highest else {
            return Ok(WATCHDOG_TEMP_UNKNOWN);
        };
        i16::try_from(highest / 100)
            .map_err(|_| native_sample_error("temperature value exceeds its record bound"))
    }
}

impl WatchdogSampleProvider for LinuxWatchdogSampleProvider {
    // Samples one transaction and commits baselines only after every required boundary succeeds.
    fn sample(&self, sequence: u64) -> Result<WatchdogSample, WatchdogError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| WatchdogError::StateUnavailable)?;
        let clocks = self.clock.clocks()?;
        let (telemetry, next) = self.telemetry(clocks, &state)?;
        let sample = WatchdogSample::with_telemetry(
            sequence,
            clocks.unix_milliseconds(),
            clocks.monotonic_milliseconds(),
            telemetry,
        )?;
        *state = next;
        Ok(sample)
    }
}

// Stores one Linux CPU counter from procfs.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct CpuCounter {
    total: u64,
    idle: u64,
}

// Stores one complete bounded CPU counter set.
struct CpuCounters {
    aggregate: CpuCounter,
    cores: Vec<CpuCounter>,
}

// Stores monotonically increasing disk byte counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct DiskCounters {
    read_bytes: u64,
    write_bytes: u64,
}

// Stores monotonically increasing non-loopback network byte counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct NetworkCounters {
    received_bytes: u64,
    transmitted_bytes: u64,
}

// Stores fields required to project Linux memory telemetry and safety input.
struct MemoryCounters {
    total_kib: u64,
    available_kib: u64,
}

// Owns the last committed native counters used for interval calculations.
#[derive(Default)]
struct LinuxWatchdogSampleState {
    cpu: CpuCounter,
    cores: Vec<CpuCounter>,
    disk: DiskCounters,
    network: NetworkCounters,
    monotonic_milliseconds: u64,
    has_baseline: bool,
}

// Reads one file completely under its exact caller-owned byte bound.
fn read_bounded_file(file: File, maximum_bytes: usize) -> Result<Vec<u8>, WatchdogError> {
    let mut payload = Vec::new();
    file.take(maximum_bytes as u64 + 1)
        .read_to_end(&mut payload)
        .map_err(|_| native_sample_error("native file could not be read"))?;
    if payload.len() > maximum_bytes {
        return Err(native_sample_error("native file exceeded its byte bound"));
    }
    Ok(payload)
}

// Converts one required native capability into strict UTF-8 text.
fn required_text(
    capability: WatchdogLinuxCapability<Vec<u8>>,
    unsupported_reason: &'static str,
) -> Result<String, WatchdogError> {
    match capability {
        WatchdogLinuxCapability::Available(value) => String::from_utf8(value)
            .map_err(|_| native_sample_error("native file is not valid UTF-8")),
        WatchdogLinuxCapability::Unsupported => Err(native_sample_error(unsupported_reason)),
    }
}

// Converts one optional native capability into strict UTF-8 text when present.
fn optional_text(
    capability: WatchdogLinuxCapability<Vec<u8>>,
) -> Result<Option<String>, WatchdogError> {
    match capability {
        WatchdogLinuxCapability::Available(value) => String::from_utf8(value)
            .map(Some)
            .map_err(|_| native_sample_error("native file is not valid UTF-8")),
        WatchdogLinuxCapability::Unsupported => Ok(None),
    }
}

// Parses aggregate and per-core procfs counters under the native record bound.
fn parse_cpu_counters(source: &str) -> Result<CpuCounters, WatchdogError> {
    let mut aggregate = None;
    let mut cores = Vec::new();
    for line in source.lines() {
        let Some(name) = line.split_whitespace().next() else {
            continue;
        };
        if name == "cpu" {
            if aggregate.replace(parse_cpu_counter(line)?).is_some() {
                return Err(native_sample_error("aggregate CPU counter is duplicated"));
            }
            continue;
        }
        if name.strip_prefix("cpu").is_some_and(|value| {
            !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
        }) && cores.len() < WATCHDOG_MAX_CPU_CORES
        {
            cores.push(parse_cpu_counter(line)?);
        }
    }
    let aggregate =
        aggregate.ok_or_else(|| native_sample_error("aggregate CPU counter is missing"))?;
    Ok(CpuCounters { aggregate, cores })
}

// Parses one procfs CPU counter with checked accumulation.
fn parse_cpu_counter(line: &str) -> Result<CpuCounter, WatchdogError> {
    let fields = line
        .split_whitespace()
        .skip(1)
        .map(|field| {
            field
                .parse::<u64>()
                .map_err(|_| native_sample_error("CPU counter is malformed"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if fields.len() < 4 || fields.len() > 10 {
        return Err(native_sample_error("CPU counter field count is invalid"));
    }
    let total = fields.iter().try_fold(0_u64, |sum, value| {
        sum.checked_add(*value)
            .ok_or_else(|| native_sample_error("CPU counter overflowed"))
    })?;
    let idle = fields[3].saturating_add(fields.get(4).copied().unwrap_or(0));
    Ok(CpuCounter { total, idle })
}

// Projects interval CPU utilization while retaining explicit unknown first samples.
fn apply_cpu(
    telemetry: &mut WatchdogSampleTelemetry,
    current: &CpuCounters,
    previous: &LinuxWatchdogSampleState,
) {
    telemetry.cpu_core_count = u8::try_from(current.cores.len()).expect("bounded CPU core count");
    telemetry.cpu_percent = counter_usage(current.aggregate, previous.cpu, previous.has_baseline);
    for (index, counter) in current.cores.iter().enumerate() {
        telemetry.cpu_core_percent[index] = counter_usage(
            *counter,
            previous.cores.get(index).copied().unwrap_or_default(),
            previous.has_baseline && index < previous.cores.len(),
        );
    }
}

// Converts two cumulative CPU counters into a bounded utilization percentage.
fn counter_usage(current: CpuCounter, previous: CpuCounter, has_baseline: bool) -> u8 {
    if !has_baseline || current.total <= previous.total {
        return WATCHDOG_PERCENT_UNKNOWN;
    }
    let total = current.total - previous.total;
    let idle = current.idle.saturating_sub(previous.idle).min(total);
    percentage(total.saturating_sub(idle), total)
}

// Parses the exact Linux memory counters required by telemetry and protection.
fn parse_meminfo(source: &str) -> Result<MemoryCounters, WatchdogError> {
    let fields = parse_kib_fields(source)?;
    let total_kib = required_counter(&fields, "MemTotal")?;
    let available_kib = required_counter(&fields, "MemAvailable")?;
    if total_kib == 0 || available_kib > total_kib {
        return Err(native_sample_error("memory counters are invalid"));
    }
    Ok(MemoryCounters {
        total_kib,
        available_kib,
    })
}

// Parses unique procfs memory fields expressed in KiB.
fn parse_kib_fields(source: &str) -> Result<BTreeMap<&str, u64>, WatchdogError> {
    let mut fields = BTreeMap::new();
    for line in source.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let parts = value.split_whitespace().collect::<Vec<_>>();
        if parts.is_empty() || parts.len() > 2 || (parts.len() == 2 && parts[1] != "kB") {
            return Err(native_sample_error("memory counter is malformed"));
        }
        let value = parts[0]
            .parse::<u64>()
            .map_err(|_| native_sample_error("memory counter is malformed"))?;
        if fields.insert(name, value).is_some() {
            return Err(native_sample_error("memory counter is duplicated"));
        }
    }
    Ok(fields)
}

// Returns one required named counter from a parsed procfs document.
fn required_counter(
    fields: &BTreeMap<&str, u64>,
    name: &'static str,
) -> Result<u64, WatchdogError> {
    fields
        .get(name)
        .copied()
        .ok_or_else(|| native_sample_error("required memory counter is missing"))
}

// Projects Linux memory counters into the fixed native record.
fn apply_memory(telemetry: &mut WatchdogSampleTelemetry, memory: &MemoryCounters) {
    let used_kib = memory.total_kib.saturating_sub(memory.available_kib);
    telemetry.memory_percent = percentage(used_kib, memory.total_kib);
    telemetry.memory_used_mib = saturating_u32(used_kib / 1_024);
    telemetry.memory_total_mib = saturating_u32(memory.total_kib / 1_024);
}

// Projects an optional one-minute load value without changing its wire scale.
fn apply_load(
    telemetry: &mut WatchdogSampleTelemetry,
    source: Option<&str>,
) -> Result<(), WatchdogError> {
    let Some(source) = source else {
        return Ok(());
    };
    let value = source
        .split_whitespace()
        .next()
        .ok_or_else(|| native_sample_error("load average is empty"))?
        .parse::<f64>()
        .map_err(|_| native_sample_error("load average is malformed"))?;
    if !value.is_finite() || value < 0.0 {
        return Err(native_sample_error("load average is invalid"));
    }
    telemetry.load1_centi = (value.mul_add(100.0, 0.5) as u64).min(u64::from(u16::MAX)) as u16;
    Ok(())
}

// Projects optional root-filesystem capacity into fixed MiB fields.
fn apply_filesystem(
    telemetry: &mut WatchdogSampleTelemetry,
    capability: WatchdogLinuxCapability<WatchdogLinuxFilesystemUsage>,
) {
    let WatchdogLinuxCapability::Available(usage) = capability else {
        return;
    };
    let used = usage.total_bytes().saturating_sub(usage.available_bytes());
    telemetry.disk_percent = percentage(used, usage.total_bytes());
    telemetry.disk_used_mib = saturating_u32(used / (1_024 * 1_024));
    telemetry.disk_total_mib = saturating_u32(usage.total_bytes() / (1_024 * 1_024));
}

// Parses aggregate byte counters from supported physical Linux block devices.
fn parse_disk_counters(source: &str) -> Result<DiskCounters, WatchdogError> {
    let mut counters = DiskCounters::default();
    for line in source.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 10 || !physical_disk(fields[2]) {
            continue;
        }
        let read_sectors = fields[5]
            .parse::<u64>()
            .map_err(|_| native_sample_error("disk counter is malformed"))?;
        let write_sectors = fields[9]
            .parse::<u64>()
            .map_err(|_| native_sample_error("disk counter is malformed"))?;
        counters.read_bytes = counters
            .read_bytes
            .saturating_add(read_sectors.saturating_mul(512));
        counters.write_bytes = counters
            .write_bytes
            .saturating_add(write_sectors.saturating_mul(512));
    }
    Ok(counters)
}

// Returns whether one Linux block-device name represents a whole physical disk.
fn physical_disk(name: &str) -> bool {
    if let Some(suffix) = name.strip_prefix("nvme") {
        return !suffix.is_empty() && !suffix.contains('p');
    }
    if let Some(suffix) = name.strip_prefix("mmcblk") {
        return !suffix.is_empty() && !suffix.contains('p');
    }
    (name.starts_with("sd") || name.starts_with("vd"))
        && name.len() == 3
        && name.as_bytes()[2].is_ascii_alphabetic()
}

// Parses aggregate non-loopback network byte counters.
fn parse_network_counters(source: &str) -> Result<NetworkCounters, WatchdogError> {
    let mut counters = NetworkCounters::default();
    for line in source.lines() {
        let Some((name, values)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if name == "lo" {
            continue;
        }
        if name.is_empty() || !safe_interface(name) {
            return Err(native_sample_error("network interface name is invalid"));
        }
        let fields = values.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 16 {
            return Err(native_sample_error("network counter is malformed"));
        }
        counters.received_bytes = counters.received_bytes.saturating_add(
            fields[0]
                .parse::<u64>()
                .map_err(|_| native_sample_error("network counter is malformed"))?,
        );
        counters.transmitted_bytes = counters.transmitted_bytes.saturating_add(
            fields[8]
                .parse::<u64>()
                .map_err(|_| native_sample_error("network counter is malformed"))?,
        );
    }
    Ok(counters)
}

// Projects disk and network deltas after a successful prior sample.
fn apply_rates(
    telemetry: &mut WatchdogSampleTelemetry,
    disk: DiskCounters,
    network: NetworkCounters,
    elapsed_milliseconds: u64,
    previous: &LinuxWatchdogSampleState,
) {
    telemetry.disk_read_kib_s = rate_kib(
        disk.read_bytes,
        previous.disk.read_bytes,
        elapsed_milliseconds,
        previous.has_baseline,
    );
    telemetry.disk_write_kib_s = rate_kib(
        disk.write_bytes,
        previous.disk.write_bytes,
        elapsed_milliseconds,
        previous.has_baseline,
    );
    telemetry.network_rx_kib_s = rate_kib(
        network.received_bytes,
        previous.network.received_bytes,
        elapsed_milliseconds,
        previous.has_baseline,
    );
    telemetry.network_tx_kib_s = rate_kib(
        network.transmitted_bytes,
        previous.network.transmitted_bytes,
        elapsed_milliseconds,
        previous.has_baseline,
    );
}

// Converts one monotonic byte-counter delta into saturated KiB per second.
fn rate_kib(current: u64, previous: u64, elapsed_milliseconds: u64, baseline: bool) -> u32 {
    if !baseline || elapsed_milliseconds == 0 || current < previous {
        return 0;
    }
    let bytes_per_second =
        u128::from(current - previous).saturating_mul(1_000) / u128::from(elapsed_milliseconds);
    saturating_u32(u64::try_from(bytes_per_second / 1_024).unwrap_or(u64::MAX))
}

// Projects an available GPU aggregate or preserves every unknown sentinel.
fn apply_gpu(
    telemetry: &mut WatchdogSampleTelemetry,
    capability: WatchdogLinuxCapability<WatchdogLinuxGpuSample>,
) {
    let WatchdogLinuxCapability::Available(gpu) = capability else {
        return;
    };
    telemetry.flags |= WATCHDOG_SAMPLE_GPU_AVAILABLE;
    if gpu.throttled {
        telemetry.flags |= WATCHDOG_SAMPLE_THROTTLED;
    }
    telemetry.gpu_percent = gpu.gpu_percent;
    telemetry.gpu_memory_percent = gpu.memory_percent;
    telemetry.gpu_engine_percent = gpu.engine_percent;
    telemetry.gpu_temp_deci_c = gpu.temperature_deci_c;
    telemetry.power_deci_w = gpu.power_deci_w;
    telemetry.gpu_clock_mhz = gpu.gpu_clock_mhz;
    telemetry.vram_clock_mhz = gpu.vram_clock_mhz;
}

// Parses one whitespace-trimmed positive native integer.
fn parse_single_u64(source: &str, reason: &'static str) -> Result<u64, WatchdogError> {
    let value = source
        .trim()
        .parse::<u64>()
        .map_err(|_| native_sample_error(reason))?;
    if value == 0 {
        return Err(native_sample_error(reason));
    }
    Ok(value)
}

// Returns one rounded bounded percentage or the exact unknown sentinel.
fn percentage(used: u64, total: u64) -> u8 {
    if total == 0 {
        return WATCHDOG_PERCENT_UNKNOWN;
    }
    let value = (u128::from(used).saturating_mul(100) + u128::from(total / 2)) / u128::from(total);
    u8::try_from(value.min(100)).expect("bounded percentage")
}

// Saturates one native counter to the fixed record width.
fn saturating_u32(value: u64) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

// Returns whether one native record percentage is measured or explicitly unknown.
fn valid_percent(value: u8) -> bool {
    value <= 100 || value == WATCHDOG_PERCENT_UNKNOWN
}

// Returns whether one clock is measured or explicitly unknown.
fn valid_clock(value: u32) -> bool {
    value != 0 || value == WATCHDOG_CLOCK_UNKNOWN
}

// Returns whether one cpufreq directory has the exact policy-number vocabulary.
fn policy_name(value: &str) -> bool {
    value.strip_prefix("policy").is_some_and(|suffix| {
        !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
    })
}

// Returns whether one native directory component cannot escape its selected root.
fn safe_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
}

// Returns whether one Linux interface name uses the kernel's bounded visible vocabulary.
fn safe_interface(value: &str) -> bool {
    value.len() <= 15
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

// Rejects relative, traversing, NUL-containing, or unbounded native paths.
fn validate_native_path(path: &Path) -> Result<(), WatchdogError> {
    let bytes = path.as_os_str().as_bytes();
    if !path.is_absolute()
        || bytes.is_empty()
        || bytes.len() > MAX_NATIVE_PATH_BYTES
        || bytes.contains(&0)
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(WatchdogError::InvalidContract {
            reason: "Linux Watchdog native path is invalid",
        });
    }
    Ok(())
}

// Reads one POSIX clock and converts it to checked milliseconds.
fn system_clock_milliseconds(clock: libc::clockid_t) -> Result<u64, WatchdogError> {
    let mut value = std::mem::MaybeUninit::<libc::timespec>::uninit();
    // SAFETY: clock_gettime initializes value on success for the fixed clock identity.
    let result = unsafe { libc::clock_gettime(clock, value.as_mut_ptr()) };
    if result != 0 {
        return Err(native_sample_error("native clock is unavailable"));
    }
    // SAFETY: a successful clock_gettime call initialized both timespec fields.
    let value = unsafe { value.assume_init() };
    if value.tv_sec < 0 || value.tv_nsec < 0 {
        return Err(native_sample_error(
            "native clock returned a negative value",
        ));
    }
    let milliseconds = u128::try_from(value.tv_sec)
        .unwrap_or(u128::MAX)
        .saturating_mul(1_000)
        .saturating_add(u128::try_from(value.tv_nsec).unwrap_or(u128::MAX) / 1_000_000);
    u64::try_from(milliseconds).map_err(|_| native_sample_error("native clock overflowed"))
}

// Creates one stable redacted Linux sampling failure.
const fn native_sample_error(reason: &'static str) -> WatchdogError {
    WatchdogError::provider("Linux sampling", reason)
}
