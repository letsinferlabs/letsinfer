// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    WatchdogError, WatchdogSample, WatchdogSampleTelemetry, WATCHDOG_CLOCK_UNKNOWN,
    WATCHDOG_GPU_ENGINES, WATCHDOG_MAX_CPU_CORES, WATCHDOG_PERCENT_UNKNOWN, WATCHDOG_SAMPLE_ROLLUP,
    WATCHDOG_TEMP_UNKNOWN,
};

// Accumulates one unsigned average with C-compatible wrapping totals.
#[derive(Clone, Copy, Debug, Default)]
struct UnsignedAccumulator {
    total: u64,
    count: u32,
}

impl UnsignedAccumulator {
    // Adds one unsigned observation exactly as the C accumulator does.
    fn add(&mut self, value: u64) {
        self.total = self.total.wrapping_add(value);
        self.count = self.count.wrapping_add(1);
    }

    // Returns the rounded unsigned average or zero for an empty accumulator.
    fn average(&self) -> u64 {
        if self.count == 0 {
            return 0;
        }
        self.total.wrapping_add(u64::from(self.count) / 2) / u64::from(self.count)
    }
}

// Accumulates one signed temperature average while excluding its unknown sentinel.
#[derive(Clone, Copy, Debug, Default)]
struct SignedAccumulator {
    total: i64,
    count: u32,
}

impl SignedAccumulator {
    // Adds one known signed temperature observation.
    fn add_temperature(&mut self, value: i16) {
        if value != WATCHDOG_TEMP_UNKNOWN {
            self.total = self.total.wrapping_add(i64::from(value));
            self.count = self.count.wrapping_add(1);
        }
    }

    // Returns the truncated signed average or the exact unknown sentinel.
    fn average_temperature(&self) -> i16 {
        if self.count == 0 {
            return WATCHDOG_TEMP_UNKNOWN;
        }
        let average = self.total / i64::from(self.count);
        i16::try_from(average).unwrap_or(WATCHDOG_TEMP_UNKNOWN)
    }
}

// Owns one in-memory C-compatible time-bucket rollup lifecycle.
#[derive(Clone, Debug)]
pub struct WatchdogRollup {
    interval_milliseconds: u64,
    bucket: u64,
    sample_count: u32,
    latest: Option<WatchdogSample>,
    cpu: UnsignedAccumulator,
    gpu: UnsignedAccumulator,
    memory: UnsignedAccumulator,
    disk: UnsignedAccumulator,
    gpu_memory: UnsignedAccumulator,
    cores: [UnsignedAccumulator; WATCHDOG_MAX_CPU_CORES],
    engines: [UnsignedAccumulator; WATCHDOG_GPU_ENGINES],
    system_temp: SignedAccumulator,
    gpu_temp: SignedAccumulator,
    nvme_temp: SignedAccumulator,
    power: UnsignedAccumulator,
    load: UnsignedAccumulator,
    memory_used: UnsignedAccumulator,
    disk_used: UnsignedAccumulator,
    network_rx: UnsignedAccumulator,
    network_tx: UnsignedAccumulator,
    disk_read: UnsignedAccumulator,
    disk_write: UnsignedAccumulator,
    cpu_clock: UnsignedAccumulator,
    gpu_clock: UnsignedAccumulator,
    vram_clock: UnsignedAccumulator,
    system_ram_clock: UnsignedAccumulator,
    active_requests: UnsignedAccumulator,
    connected_clients: UnsignedAccumulator,
    queued_requests: UnsignedAccumulator,
}

impl WatchdogRollup {
    // Creates one empty nonzero time-bucket accumulator.
    pub fn new(interval_milliseconds: u64) -> Result<Self, WatchdogError> {
        if interval_milliseconds == 0 {
            return Err(WatchdogError::InvalidContract {
                reason: "Watchdog rollup interval must be positive",
            });
        }
        Ok(Self::empty(interval_milliseconds))
    }

    // Adds one sample and returns the previous bucket when rotation completes it.
    pub fn push(&mut self, sample: &WatchdogSample) -> Option<WatchdogSample> {
        let bucket = sample.unix_milliseconds() / self.interval_milliseconds;
        if self.sample_count == 0 {
            self.bucket = bucket;
            self.accumulate(sample);
            return None;
        }
        if bucket == self.bucket {
            self.accumulate(sample);
            return None;
        }
        let completed = self.complete();
        *self = Self::empty(self.interval_milliseconds);
        self.bucket = bucket;
        self.accumulate(sample);
        completed
    }

    // Completes the current partial bucket and resets this rollup.
    pub fn complete_partial(&mut self) -> Option<WatchdogSample> {
        let completed = self.complete();
        *self = Self::empty(self.interval_milliseconds);
        completed
    }

    // Creates one empty accumulator while preserving its immutable interval.
    fn empty(interval_milliseconds: u64) -> Self {
        Self {
            interval_milliseconds,
            bucket: 0,
            sample_count: 0,
            latest: None,
            cpu: UnsignedAccumulator::default(),
            gpu: UnsignedAccumulator::default(),
            memory: UnsignedAccumulator::default(),
            disk: UnsignedAccumulator::default(),
            gpu_memory: UnsignedAccumulator::default(),
            cores: [UnsignedAccumulator::default(); WATCHDOG_MAX_CPU_CORES],
            engines: [UnsignedAccumulator::default(); WATCHDOG_GPU_ENGINES],
            system_temp: SignedAccumulator::default(),
            gpu_temp: SignedAccumulator::default(),
            nvme_temp: SignedAccumulator::default(),
            power: UnsignedAccumulator::default(),
            load: UnsignedAccumulator::default(),
            memory_used: UnsignedAccumulator::default(),
            disk_used: UnsignedAccumulator::default(),
            network_rx: UnsignedAccumulator::default(),
            network_tx: UnsignedAccumulator::default(),
            disk_read: UnsignedAccumulator::default(),
            disk_write: UnsignedAccumulator::default(),
            cpu_clock: UnsignedAccumulator::default(),
            gpu_clock: UnsignedAccumulator::default(),
            vram_clock: UnsignedAccumulator::default(),
            system_ram_clock: UnsignedAccumulator::default(),
            active_requests: UnsignedAccumulator::default(),
            connected_clients: UnsignedAccumulator::default(),
            queued_requests: UnsignedAccumulator::default(),
        }
    }

    // Accumulates every averaged field and retains the exact latest counter snapshot.
    fn accumulate(&mut self, sample: &WatchdogSample) {
        let telemetry = sample.telemetry();
        self.latest = Some(sample.clone());
        self.sample_count = self.sample_count.wrapping_add(1);
        add_percent(&mut self.cpu, telemetry.cpu_percent);
        add_percent(&mut self.gpu, telemetry.gpu_percent);
        add_percent(&mut self.memory, telemetry.memory_percent);
        add_percent(&mut self.disk, telemetry.disk_percent);
        add_percent(&mut self.gpu_memory, telemetry.gpu_memory_percent);
        for (accumulator, value) in self
            .cores
            .iter_mut()
            .zip(telemetry.cpu_core_percent.iter())
            .take(usize::from(telemetry.cpu_core_count))
        {
            add_percent(accumulator, *value);
        }
        for (accumulator, value) in self
            .engines
            .iter_mut()
            .zip(telemetry.gpu_engine_percent.iter())
        {
            add_percent(accumulator, *value);
        }
        self.system_temp
            .add_temperature(telemetry.system_temp_deci_c);
        self.gpu_temp.add_temperature(telemetry.gpu_temp_deci_c);
        self.nvme_temp.add_temperature(telemetry.nvme_temp_deci_c);
        self.power.add(u64::from(telemetry.power_deci_w));
        self.load.add(u64::from(telemetry.load1_centi));
        self.memory_used.add(u64::from(telemetry.memory_used_mib));
        self.disk_used.add(u64::from(telemetry.disk_used_mib));
        self.network_rx.add(u64::from(telemetry.network_rx_kib_s));
        self.network_tx.add(u64::from(telemetry.network_tx_kib_s));
        self.disk_read.add(u64::from(telemetry.disk_read_kib_s));
        self.disk_write.add(u64::from(telemetry.disk_write_kib_s));
        add_clock(&mut self.cpu_clock, telemetry.cpu_clock_mhz);
        add_clock(&mut self.gpu_clock, telemetry.gpu_clock_mhz);
        add_clock(&mut self.vram_clock, telemetry.vram_clock_mhz);
        add_clock(&mut self.system_ram_clock, telemetry.system_ram_clock_mhz);
        self.active_requests
            .add(u64::from(telemetry.active_requests));
        self.connected_clients
            .add(u64::from(telemetry.connected_clients));
        self.queued_requests
            .add(u64::from(telemetry.queued_requests));
    }

    // Projects the current bucket using averages and latest monotonic counters.
    fn complete(&self) -> Option<WatchdogSample> {
        let latest = self.latest.as_ref()?;
        let source = latest.telemetry();
        let mut telemetry = WatchdogSampleTelemetry {
            cpu_core_count: source.cpu_core_count,
            flags: source.flags | WATCHDOG_SAMPLE_ROLLUP,
            cpu_percent: average_percent(&self.cpu),
            gpu_percent: average_percent(&self.gpu),
            memory_percent: average_percent(&self.memory),
            disk_percent: average_percent(&self.disk),
            gpu_memory_percent: average_percent(&self.gpu_memory),
            workload_type: source.workload_type,
            system_temp_deci_c: self.system_temp.average_temperature(),
            gpu_temp_deci_c: self.gpu_temp.average_temperature(),
            nvme_temp_deci_c: self.nvme_temp.average_temperature(),
            power_deci_w: saturating_u16(self.power.average()),
            load1_centi: saturating_u16(self.load.average()),
            memory_used_mib: saturating_u32(self.memory_used.average()),
            memory_total_mib: source.memory_total_mib,
            disk_used_mib: saturating_u32(self.disk_used.average()),
            disk_total_mib: source.disk_total_mib,
            network_rx_kib_s: saturating_u32(self.network_rx.average()),
            network_tx_kib_s: saturating_u32(self.network_tx.average()),
            disk_read_kib_s: saturating_u32(self.disk_read.average()),
            disk_write_kib_s: saturating_u32(self.disk_write.average()),
            workload_id: source.workload_id,
            cpu_clock_mhz: average_clock(&self.cpu_clock),
            gpu_clock_mhz: average_clock(&self.gpu_clock),
            vram_clock_mhz: average_clock(&self.vram_clock),
            system_ram_clock_mhz: average_clock(&self.system_ram_clock),
            active_requests: saturating_u32(self.active_requests.average()),
            queued_requests: saturating_u32(self.queued_requests.average()),
            connected_clients: saturating_u32(self.connected_clients.average()),
            requests_received: source.requests_received,
            requests_admitted: source.requests_admitted,
            requests_completed: source.requests_completed,
            requests_failed: source.requests_failed,
            requests_cancelled: source.requests_cancelled,
            requests_retried: source.requests_retried,
            input_tokens: source.input_tokens,
            output_tokens: source.output_tokens,
            cached_tokens: source.cached_tokens,
            queue_milliseconds: source.queue_milliseconds,
            ttft_milliseconds: source.ttft_milliseconds,
            decode_milliseconds: source.decode_milliseconds,
            exact_token_requests: source.exact_token_requests,
            prefix_cache_hits: source.prefix_cache_hits,
            usage_records_dropped: source.usage_records_dropped,
            usage_write_errors: source.usage_write_errors,
            ..WatchdogSampleTelemetry::default()
        };
        for (output, accumulator) in telemetry
            .cpu_core_percent
            .iter_mut()
            .zip(self.cores.iter())
            .take(usize::from(telemetry.cpu_core_count))
        {
            *output = average_percent(accumulator);
        }
        for (output, accumulator) in telemetry
            .gpu_engine_percent
            .iter_mut()
            .zip(self.engines.iter())
        {
            *output = average_percent(accumulator);
        }
        WatchdogSample::from_record(
            latest.sequence(),
            self.bucket.wrapping_mul(self.interval_milliseconds),
            latest.monotonic_milliseconds(),
            telemetry,
        )
        .ok()
    }
}

// Adds one known percentage while excluding the exact unknown sentinel.
fn add_percent(accumulator: &mut UnsignedAccumulator, value: u8) {
    if value != WATCHDOG_PERCENT_UNKNOWN {
        accumulator.add(u64::from(value));
    }
}

// Adds one known clock while excluding the exact unknown sentinel.
fn add_clock(accumulator: &mut UnsignedAccumulator, value: u32) {
    if value != WATCHDOG_CLOCK_UNKNOWN {
        accumulator.add(u64::from(value));
    }
}

// Returns a rounded percentage capped to its native semantic range.
fn average_percent(accumulator: &UnsignedAccumulator) -> u8 {
    if accumulator.count == 0 {
        WATCHDOG_PERCENT_UNKNOWN
    } else {
        accumulator.average().min(100) as u8
    }
}

// Returns a rounded clock or the exact unknown sentinel.
fn average_clock(accumulator: &UnsignedAccumulator) -> u32 {
    if accumulator.count == 0 {
        WATCHDOG_CLOCK_UNKNOWN
    } else {
        saturating_u32(accumulator.average())
    }
}

// Narrows one average to its exact unsigned 16-bit record field.
fn saturating_u16(value: u64) -> u16 {
    value.min(u64::from(u16::MAX)) as u16
}

// Narrows one average to its exact unsigned 32-bit record field.
fn saturating_u32(value: u64) -> u32 {
    value.min(u64::from(u32::MAX)) as u32
}
