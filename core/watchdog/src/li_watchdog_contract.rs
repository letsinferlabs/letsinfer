// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

const MAX_DESCRIPTOR_BYTES: usize = 2_048;
const MAX_GENERATION_BYTES: usize = 32;
const MAX_CONTAINER_NAME_BYTES: usize = 128;
const CONTAINER_ID_BYTES: usize = 64;
const BOOT_ID_BYTES: usize = 36;
const MAX_CGROUP_BYTES: usize = 4_095;
const MAX_TARGETS: usize = 64;

pub const WATCHDOG_MAX_CPU_CORES: usize = 32;
pub const WATCHDOG_GPU_ENGINES: usize = 6;
pub const WATCHDOG_PERCENT_UNKNOWN: u8 = u8::MAX;
pub const WATCHDOG_TEMP_UNKNOWN: i16 = i16::MIN;
pub const WATCHDOG_CLOCK_UNKNOWN: u32 = u32::MAX;
pub const WATCHDOG_SAMPLE_ROLLUP: u8 = 1 << 0;
pub const WATCHDOG_SAMPLE_GPU_AVAILABLE: u8 = 1 << 1;
pub const WATCHDOG_SAMPLE_THROTTLED: u8 = 1 << 2;
pub const WATCHDOG_SAMPLE_GATEWAY_AVAILABLE: u8 = 1 << 3;

// Describes one stable Watchdog contract or provider failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WatchdogError {
    InvalidContract {
        reason: &'static str,
    },
    Provider {
        capability: &'static str,
        reason: &'static str,
    },
    StateUnavailable,
}

impl WatchdogError {
    // Creates one redacted provider failure at an exact native boundary.
    pub const fn provider(capability: &'static str, reason: &'static str) -> Self {
        Self::Provider { capability, reason }
    }
}

impl fmt::Display for WatchdogError {
    // Presents stable Watchdog language without paths or process identities.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidContract { reason } => {
                write!(formatter, "Watchdog contract is invalid: {reason}")
            }
            Self::Provider { capability, reason } => {
                write!(formatter, "Watchdog {capability} failed: {reason}")
            }
            Self::StateUnavailable => formatter.write_str("Watchdog state is unavailable"),
        }
    }
}

impl Error for WatchdogError {}

// Stores the complete runtime-declared protection threshold contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchdogSafetyThresholds {
    warning_available_bytes: u64,
    graceful_available_bytes: u64,
    emergency_available_bytes: u64,
    swap_stop_bytes: u64,
    psi_some_microseconds: u64,
    psi_full_microseconds: u64,
    state_failures: u32,
    containment_grace_milliseconds: u32,
}

impl WatchdogSafetyThresholds {
    // Creates one exact ordered threshold set without supplying safety defaults.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        warning_available_bytes: u64,
        graceful_available_bytes: u64,
        emergency_available_bytes: u64,
        swap_stop_bytes: u64,
        psi_some_microseconds: u64,
        psi_full_microseconds: u64,
        state_failures: u32,
        containment_grace_milliseconds: u32,
    ) -> Result<Self, WatchdogError> {
        if warning_available_bytes <= graceful_available_bytes
            || graceful_available_bytes <= emergency_available_bytes
            || emergency_available_bytes == 0
            || swap_stop_bytes == 0
            || psi_some_microseconds == 0
            || psi_full_microseconds == 0
            || state_failures < 2
            || !(1..=30_000).contains(&containment_grace_milliseconds)
        {
            return Err(WatchdogError::InvalidContract {
                reason: "protection thresholds are incomplete or incorrectly ordered",
            });
        }
        Ok(Self {
            warning_available_bytes,
            graceful_available_bytes,
            emergency_available_bytes,
            swap_stop_bytes,
            psi_some_microseconds,
            psi_full_microseconds,
            state_failures,
            containment_grace_milliseconds,
        })
    }

    // Returns the host-memory warning floor used only for telemetry events.
    pub const fn warning_available_bytes(self) -> u64 {
        self.warning_available_bytes
    }

    // Returns the declared graceful-reserve floor without making it a trip gate.
    pub const fn graceful_available_bytes(self) -> u64 {
        self.graceful_available_bytes
    }

    // Returns the declared emergency floor without making it a trip gate.
    pub const fn emergency_available_bytes(self) -> u64 {
        self.emergency_available_bytes
    }

    // Returns the swap observation threshold without making it a trip gate.
    pub const fn swap_stop_bytes(self) -> u64 {
        self.swap_stop_bytes
    }

    // Returns the partial-pressure observation threshold.
    pub const fn psi_some_microseconds(self) -> u64 {
        self.psi_some_microseconds
    }

    // Returns the full-pressure observation threshold.
    pub const fn psi_full_microseconds(self) -> u64 {
        self.psi_full_microseconds
    }

    // Returns the repeated descriptor-failure warning threshold.
    pub const fn state_failures(self) -> u32 {
        self.state_failures
    }

    // Returns the graceful containment interval before escalation.
    pub const fn containment_grace_milliseconds(self) -> u32 {
        self.containment_grace_milliseconds
    }
}

// Identifies the explicit lifecycle phase of one protected placement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchdogProtectionPhase {
    Pending,
    Starting,
    Armed,
    Disarmed,
}

// Binds Watchdog to one exact process, boot, container, and cgroup generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogProtectedEngine {
    generation: String,
    phase: WatchdogProtectionPhase,
    container_name: String,
    container_id: Option<String>,
    process_id: Option<u32>,
    process_start_ticks: Option<u64>,
    boot_id: Option<String>,
    cgroup: Option<String>,
}

impl WatchdogProtectedEngine {
    // Parses the existing version-one descriptor without widening its vocabulary.
    pub fn parse(value: &str) -> Result<Self, WatchdogError> {
        if value.is_empty()
            || value.len() > MAX_DESCRIPTOR_BYTES
            || value.contains('\r')
            || value.contains('\0')
        {
            return Err(invalid_descriptor());
        }
        let mut fields = BTreeMap::new();
        for line in value.lines() {
            let (name, field) = line.split_once('=').ok_or_else(invalid_descriptor)?;
            if name.is_empty() || field.contains('=') || fields.insert(name, field).is_some() {
                return Err(invalid_descriptor());
            }
        }
        let expected = [
            "boot_id",
            "cgroup",
            "container_id",
            "container_name",
            "generation",
            "phase",
            "pid",
            "start_ticks",
            "version",
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        if fields.keys().copied().collect::<BTreeSet<_>>() != expected
            || fields.get("version") != Some(&"1")
        {
            return Err(invalid_descriptor());
        }
        let generation = required_lower_hex(fields["generation"], MAX_GENERATION_BYTES)?;
        let phase = match fields["phase"] {
            "pending" => WatchdogProtectionPhase::Pending,
            "starting" => WatchdogProtectionPhase::Starting,
            "armed" => WatchdogProtectionPhase::Armed,
            "disarmed" => WatchdogProtectionPhase::Disarmed,
            _ => return Err(invalid_descriptor()),
        };
        let container_name = fields["container_name"];
        if !safe_token(container_name, MAX_CONTAINER_NAME_BYTES) {
            return Err(invalid_descriptor());
        }
        let container_id = optional_lower_hex(fields["container_id"], CONTAINER_ID_BYTES)?;
        let process_id = optional_positive(fields["pid"], i32::MAX as u64)?
            .map(|number| u32::try_from(number).expect("bounded process identity"));
        if process_id.is_some_and(|process_id| process_id <= 1) {
            return Err(invalid_descriptor());
        }
        let process_start_ticks = optional_positive(fields["start_ticks"], u64::MAX)?;
        let boot_id = optional_safe_token(fields["boot_id"], BOOT_ID_BYTES, true)?;
        let cgroup = optional_cgroup(fields["cgroup"])?;
        let process_bound = matches!(
            phase,
            WatchdogProtectionPhase::Starting | WatchdogProtectionPhase::Armed
        );
        if [
            container_id.is_some(),
            process_id.is_some(),
            process_start_ticks.is_some(),
            boot_id.is_some(),
            cgroup.is_some(),
        ]
        .into_iter()
        .any(|present| present != process_bound)
        {
            return Err(invalid_descriptor());
        }
        Ok(Self {
            generation,
            phase,
            container_name: container_name.to_string(),
            container_id,
            process_id,
            process_start_ticks,
            boot_id,
            cgroup,
        })
    }

    // Returns the immutable protection generation identity.
    pub fn generation(&self) -> &str {
        &self.generation
    }

    // Returns the declared protection phase.
    pub const fn phase(&self) -> WatchdogProtectionPhase {
        self.phase
    }

    // Returns the stable managed container name.
    pub fn container_name(&self) -> &str {
        &self.container_name
    }

    // Returns the exact container identity while the process is bound.
    pub fn container_id(&self) -> Option<&str> {
        self.container_id.as_deref()
    }

    // Returns the exact process identity while the process is bound.
    pub const fn process_id(&self) -> Option<u32> {
        self.process_id
    }

    // Returns the kernel start ticks that prevent PID-reuse drift.
    pub const fn process_start_ticks(&self) -> Option<u64> {
        self.process_start_ticks
    }

    // Returns the exact boot identity while the process is bound.
    pub fn boot_id(&self) -> Option<&str> {
        self.boot_id.as_deref()
    }

    // Returns the exact cgroup path while the process is bound.
    pub fn cgroup(&self) -> Option<&str> {
        self.cgroup.as_deref()
    }
}

// Carries every pressure and cgroup counter observed for one protected process.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WatchdogSafetyInput {
    pub available_bytes: u64,
    pub swap_used_bytes: u64,
    pub psi_some_delta_microseconds: u64,
    pub psi_full_delta_microseconds: u64,
    pub cgroup_oom_delta: u64,
    pub cgroup_oom_kill_delta: u64,
    pub cgroup_oom_group_kill_delta: u64,
    pub cgroup_max_delta: u64,
}

// Identifies whether the exact protected process is still resident.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchdogProcessState {
    Running,
    Exited,
}

// Carries one complete target observation from the platform protection provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogProtectionObservation {
    target: WatchdogProtectedEngine,
    process_state: WatchdogProcessState,
    safety: WatchdogSafetyInput,
    trip_latched: bool,
}

impl WatchdogProtectionObservation {
    // Creates one exact protection observation without changing its lifecycle.
    pub const fn new(
        target: WatchdogProtectedEngine,
        process_state: WatchdogProcessState,
        safety: WatchdogSafetyInput,
        trip_latched: bool,
    ) -> Self {
        Self {
            target,
            process_state,
            safety,
            trip_latched,
        }
    }

    // Returns the immutable protected process binding.
    pub const fn target(&self) -> &WatchdogProtectedEngine {
        &self.target
    }

    // Returns whether the exact bound process still exists.
    pub const fn process_state(&self) -> WatchdogProcessState {
        self.process_state
    }

    // Returns the complete pressure and cgroup observation.
    pub const fn safety(&self) -> WatchdogSafetyInput {
        self.safety
    }

    // Returns whether this generation already has a durable trip latch.
    pub const fn trip_latched(&self) -> bool {
        self.trip_latched
    }
}

// Identifies the containment signal selected from observed kernel evidence.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum WatchdogSafetyAction {
    Stop,
    Kill,
}

// Describes one durable safety event without arbitrary process output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogSafetyEvent {
    kind: &'static str,
    reason: &'static str,
    severity: u8,
    generation: String,
    sequence: u64,
    action: Option<WatchdogSafetyAction>,
    containment_complete: Option<bool>,
}

impl WatchdogSafetyEvent {
    // Creates one bounded event from closed Watchdog vocabulary.
    pub(crate) fn new(
        kind: &'static str,
        reason: &'static str,
        severity: u8,
        generation: &str,
        sequence: u64,
        action: Option<WatchdogSafetyAction>,
        containment_complete: Option<bool>,
    ) -> Self {
        Self {
            kind,
            reason,
            severity,
            generation: generation.to_string(),
            sequence,
            action,
            containment_complete,
        }
    }

    // Returns the stable event kind.
    pub const fn kind(&self) -> &'static str {
        self.kind
    }

    // Returns the stable event reason.
    pub const fn reason(&self) -> &'static str {
        self.reason
    }

    // Returns the severity from informational through critical.
    pub const fn severity(&self) -> u8 {
        self.severity
    }

    // Returns the exact protection generation.
    pub fn generation(&self) -> &str {
        &self.generation
    }

    // Returns the sample sequence that triggered the event.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    // Returns the requested containment action when this is a trip.
    pub const fn action(&self) -> Option<WatchdogSafetyAction> {
        self.action
    }

    // Returns whether containment completed when this is a trip.
    pub const fn containment_complete(&self) -> Option<bool> {
        self.containment_complete
    }
}

// Carries the complete engine-neutral payload owned by the native sample record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogSampleTelemetry {
    pub cpu_core_count: u8,
    pub flags: u8,
    pub cpu_percent: u8,
    pub gpu_percent: u8,
    pub memory_percent: u8,
    pub disk_percent: u8,
    pub gpu_memory_percent: u8,
    pub workload_type: u8,
    pub cpu_core_percent: [u8; WATCHDOG_MAX_CPU_CORES],
    pub gpu_engine_percent: [u8; WATCHDOG_GPU_ENGINES],
    pub system_temp_deci_c: i16,
    pub gpu_temp_deci_c: i16,
    pub nvme_temp_deci_c: i16,
    pub power_deci_w: u16,
    pub load1_centi: u16,
    pub memory_used_mib: u32,
    pub memory_total_mib: u32,
    pub disk_used_mib: u32,
    pub disk_total_mib: u32,
    pub network_rx_kib_s: u32,
    pub network_tx_kib_s: u32,
    pub disk_read_kib_s: u32,
    pub disk_write_kib_s: u32,
    pub workload_id: u32,
    pub cpu_clock_mhz: u32,
    pub gpu_clock_mhz: u32,
    pub vram_clock_mhz: u32,
    pub system_ram_clock_mhz: u32,
    pub active_requests: u32,
    pub queued_requests: u32,
    pub connected_clients: u32,
    pub requests_received: u64,
    pub requests_admitted: u64,
    pub requests_completed: u64,
    pub requests_failed: u64,
    pub requests_cancelled: u64,
    pub requests_retried: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cached_tokens: u64,
    pub queue_milliseconds: u64,
    pub ttft_milliseconds: u64,
    pub decode_milliseconds: u64,
    pub exact_token_requests: u64,
    pub prefix_cache_hits: u64,
    pub usage_records_dropped: u64,
    pub usage_write_errors: u64,
}

impl Default for WatchdogSampleTelemetry {
    // Creates the exact unknown-value baseline used by the C v2 sample record.
    fn default() -> Self {
        Self {
            cpu_core_count: 0,
            flags: 0,
            cpu_percent: WATCHDOG_PERCENT_UNKNOWN,
            gpu_percent: WATCHDOG_PERCENT_UNKNOWN,
            memory_percent: WATCHDOG_PERCENT_UNKNOWN,
            disk_percent: WATCHDOG_PERCENT_UNKNOWN,
            gpu_memory_percent: WATCHDOG_PERCENT_UNKNOWN,
            workload_type: 0,
            cpu_core_percent: [WATCHDOG_PERCENT_UNKNOWN; WATCHDOG_MAX_CPU_CORES],
            gpu_engine_percent: [WATCHDOG_PERCENT_UNKNOWN; WATCHDOG_GPU_ENGINES],
            system_temp_deci_c: WATCHDOG_TEMP_UNKNOWN,
            gpu_temp_deci_c: WATCHDOG_TEMP_UNKNOWN,
            nvme_temp_deci_c: WATCHDOG_TEMP_UNKNOWN,
            power_deci_w: 0,
            load1_centi: 0,
            memory_used_mib: 0,
            memory_total_mib: 0,
            disk_used_mib: 0,
            disk_total_mib: 0,
            network_rx_kib_s: 0,
            network_tx_kib_s: 0,
            disk_read_kib_s: 0,
            disk_write_kib_s: 0,
            workload_id: 0,
            cpu_clock_mhz: WATCHDOG_CLOCK_UNKNOWN,
            gpu_clock_mhz: WATCHDOG_CLOCK_UNKNOWN,
            vram_clock_mhz: WATCHDOG_CLOCK_UNKNOWN,
            system_ram_clock_mhz: WATCHDOG_CLOCK_UNKNOWN,
            active_requests: 0,
            queued_requests: 0,
            connected_clients: 0,
            requests_received: 0,
            requests_admitted: 0,
            requests_completed: 0,
            requests_failed: 0,
            requests_cancelled: 0,
            requests_retried: 0,
            input_tokens: 0,
            output_tokens: 0,
            cached_tokens: 0,
            queue_milliseconds: 0,
            ttft_milliseconds: 0,
            decode_milliseconds: 0,
            exact_token_requests: 0,
            prefix_cache_hits: 0,
            usage_records_dropped: 0,
            usage_write_errors: 0,
        }
    }
}

// Carries one model-neutral resident telemetry sample into storage and safety policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogSample {
    sequence: u64,
    unix_milliseconds: u64,
    monotonic_milliseconds: u64,
    telemetry: WatchdogSampleTelemetry,
}

impl WatchdogSample {
    // Creates one positive ordered sample identity.
    pub fn new(
        sequence: u64,
        unix_milliseconds: u64,
        monotonic_milliseconds: u64,
    ) -> Result<Self, WatchdogError> {
        Self::with_telemetry(
            sequence,
            unix_milliseconds,
            monotonic_milliseconds,
            WatchdogSampleTelemetry::default(),
        )
    }

    // Creates one positive ordered sample with the complete native telemetry payload.
    pub fn with_telemetry(
        sequence: u64,
        unix_milliseconds: u64,
        monotonic_milliseconds: u64,
        telemetry: WatchdogSampleTelemetry,
    ) -> Result<Self, WatchdogError> {
        if sequence == 0 || unix_milliseconds == 0 || monotonic_milliseconds == 0 {
            return Err(WatchdogError::InvalidContract {
                reason: "sample sequence and clocks must be positive",
            });
        }
        if usize::from(telemetry.cpu_core_count) > WATCHDOG_MAX_CPU_CORES {
            return Err(WatchdogError::InvalidContract {
                reason: "sample CPU core count exceeds the native record bound",
            });
        }
        Ok(Self {
            sequence,
            unix_milliseconds,
            monotonic_milliseconds,
            telemetry,
        })
    }

    // Reconstructs one CRC-verified C record without narrowing its historical values.
    pub(crate) fn from_record(
        sequence: u64,
        unix_milliseconds: u64,
        monotonic_milliseconds: u64,
        telemetry: WatchdogSampleTelemetry,
    ) -> Result<Self, WatchdogError> {
        if usize::from(telemetry.cpu_core_count) > WATCHDOG_MAX_CPU_CORES {
            return Err(WatchdogError::InvalidContract {
                reason: "sample CPU core count exceeds the native record bound",
            });
        }
        Ok(Self {
            sequence,
            unix_milliseconds,
            monotonic_milliseconds,
            telemetry,
        })
    }

    // Returns the durable monotonic sample sequence.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    // Returns wall time in Unix milliseconds.
    pub const fn unix_milliseconds(&self) -> u64 {
        self.unix_milliseconds
    }

    // Returns process-independent monotonic time in milliseconds.
    pub const fn monotonic_milliseconds(&self) -> u64 {
        self.monotonic_milliseconds
    }

    // Returns the complete immutable engine-neutral telemetry payload.
    pub const fn telemetry(&self) -> &WatchdogSampleTelemetry {
        &self.telemetry
    }
}

// Carries one complete Watchdog tick receipt without exposing provider internals.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogTick {
    sample: WatchdogSample,
    events: Vec<WatchdogSafetyEvent>,
    active_targets: usize,
    protection_cycle: crate::WatchdogProtectionCycle,
}

impl WatchdogTick {
    // Creates one bounded complete tick receipt.
    pub(crate) fn new(
        sample: WatchdogSample,
        events: Vec<WatchdogSafetyEvent>,
        active_targets: usize,
        protection_cycle: crate::WatchdogProtectionCycle,
    ) -> Self {
        Self {
            sample,
            events,
            active_targets,
            protection_cycle,
        }
    }

    // Returns the exact stored sample.
    pub const fn sample(&self) -> &WatchdogSample {
        &self.sample
    }

    // Returns ordered safety events emitted during this tick.
    pub fn events(&self) -> &[WatchdogSafetyEvent] {
        &self.events
    }

    // Returns the number of bounded target observations.
    pub const fn active_targets(&self) -> usize {
        self.active_targets
    }

    // Returns the safe targets proven by this one complete protection cycle.
    pub const fn protection_cycle(&self) -> &crate::WatchdogProtectionCycle {
        &self.protection_cycle
    }
}

// Rejects a malformed version-one protection descriptor.
fn invalid_descriptor() -> WatchdogError {
    WatchdogError::InvalidContract {
        reason: "protected placement descriptor is invalid",
    }
}

// Requires one exact lowercase hexadecimal value.
fn required_lower_hex(value: &str, length: usize) -> Result<String, WatchdogError> {
    if !is_lower_hex(value, length) {
        return Err(invalid_descriptor());
    }
    Ok(value.to_string())
}

// Parses one optional lowercase hexadecimal value represented by a dash when absent.
fn optional_lower_hex(value: &str, length: usize) -> Result<Option<String>, WatchdogError> {
    if value == "-" {
        Ok(None)
    } else {
        required_lower_hex(value, length).map(Some)
    }
}

// Parses one optional positive integer represented by a dash when absent.
fn optional_positive(value: &str, maximum: u64) -> Result<Option<u64>, WatchdogError> {
    if value == "-" {
        return Ok(None);
    }
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid_descriptor());
    }
    let number = value.parse::<u64>().map_err(|_| invalid_descriptor())?;
    if number == 0 || number > maximum {
        return Err(invalid_descriptor());
    }
    Ok(Some(number))
}

// Parses one optional safe token with an exact or bounded length.
fn optional_safe_token(
    value: &str,
    maximum: usize,
    exact: bool,
) -> Result<Option<String>, WatchdogError> {
    if value == "-" {
        return Ok(None);
    }
    if !safe_token(value, maximum) || (exact && value.len() != maximum) {
        return Err(invalid_descriptor());
    }
    Ok(Some(value.to_string()))
}

// Parses one optional cgroup path under the exact Linux cgroup filesystem.
fn optional_cgroup(value: &str) -> Result<Option<String>, WatchdogError> {
    if value == "-" {
        return Ok(None);
    }
    let suffix = value.strip_prefix("/sys/fs/cgroup/");
    if value.len() > MAX_CGROUP_BYTES
        || suffix.is_none()
        || suffix.is_some_and(|suffix| {
            suffix.is_empty()
                || suffix.ends_with('/')
                || suffix
                    .split('/')
                    .any(|component| component.is_empty() || component == "." || component == "..")
        })
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'_' | b'.' | b':' | b'-')
        })
    {
        return Err(invalid_descriptor());
    }
    Ok(Some(value.to_string()))
}

// Returns whether one token uses only the existing descriptor vocabulary.
fn safe_token(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

// Returns whether one value is exact lowercase hexadecimal text.
fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

// Returns the shared hard target bound used by native providers and tests.
pub const fn maximum_watchdog_targets() -> usize {
    MAX_TARGETS
}
