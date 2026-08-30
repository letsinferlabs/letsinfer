// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use li_benchmark_worker::NativeBenchmarkTelemetrySource;
use li_core_interface::Sha256Digest;
use li_watchdog_manager::{WatchdogSample, WatchdogSampleTelemetry};
use sha2::{Digest, Sha256};

use crate::{
    CoreBenchmarkPortError, CoreBenchmarkTelemetryObservation,
    CoreBenchmarkTelemetryObservationPort, CoreBenchmarkTelemetryWindow,
};

const WATCHDOG_BUCKET_MILLISECONDS: u64 = 1_000;

// Materializes exact one-second benchmark observations from authenticated Watchdog history.
pub struct WatchdogCoreBenchmarkTelemetryObservationPort {
    source: Arc<dyn NativeBenchmarkTelemetrySource>,
}

impl WatchdogCoreBenchmarkTelemetryObservationPort {
    // Creates one observation adapter around the shared production Watchdog source.
    pub const fn new(source: Arc<dyn NativeBenchmarkTelemetrySource>) -> Self {
        Self { source }
    }
}

impl CoreBenchmarkTelemetryObservationPort for WatchdogCoreBenchmarkTelemetryObservationPort {
    // Queries one exact ending bucket and rejects missing, duplicate, or drifting samples.
    fn observe(
        &self,
        command: &CoreBenchmarkTelemetryWindow,
    ) -> Result<CoreBenchmarkTelemetryObservation, CoreBenchmarkPortError> {
        let sampled_at = command.sampled_at().value();
        let start = sampled_at
            .checked_sub(WATCHDOG_BUCKET_MILLISECONDS)
            .ok_or(CoreBenchmarkPortError::InvalidState)?;
        let end = sampled_at
            .checked_sub(1)
            .ok_or(CoreBenchmarkPortError::InvalidState)?;
        let samples = self
            .source
            .query_range(start, end)
            .map_err(|_| CoreBenchmarkPortError::Unavailable)?;
        let [sample] = samples.as_slice() else {
            return Err(CoreBenchmarkPortError::InvalidState);
        };
        if !(start..=end).contains(&sample.unix_milliseconds()) {
            return Err(CoreBenchmarkPortError::InvalidState);
        }
        Ok(CoreBenchmarkTelemetryObservation::new(
            command.sampled_at(),
            sample_sha256(sample)?,
        ))
    }
}

// Hashes one complete typed Watchdog sample with fixed field order and widths.
fn sample_sha256(sample: &WatchdogSample) -> Result<Sha256Digest, CoreBenchmarkPortError> {
    let mut digest = Sha256::new();
    digest.update(b"li-benchmark-watchdog-sample\0v1\0");
    digest.update(sample.sequence().to_be_bytes());
    digest.update(sample.unix_milliseconds().to_be_bytes());
    digest.update(sample.monotonic_milliseconds().to_be_bytes());
    hash_telemetry(&mut digest, sample.telemetry());
    Sha256Digest::parse(&format!("{:x}", digest.finalize()))
        .map_err(|_| CoreBenchmarkPortError::InvalidState)
}

// Appends every native telemetry field using its declared fixed-width representation.
fn hash_telemetry(digest: &mut Sha256, telemetry: &WatchdogSampleTelemetry) {
    digest.update([
        telemetry.cpu_core_count,
        telemetry.flags,
        telemetry.cpu_percent,
        telemetry.gpu_percent,
        telemetry.memory_percent,
        telemetry.disk_percent,
        telemetry.gpu_memory_percent,
        telemetry.workload_type,
    ]);
    digest.update(telemetry.cpu_core_percent);
    digest.update(telemetry.gpu_engine_percent);
    macro_rules! append {
        ($($value:expr),+ $(,)?) => { $(digest.update($value.to_be_bytes());)+ };
    }
    append!(
        telemetry.system_temp_deci_c,
        telemetry.gpu_temp_deci_c,
        telemetry.nvme_temp_deci_c,
        telemetry.power_deci_w,
        telemetry.load1_centi,
        telemetry.memory_used_mib,
        telemetry.memory_total_mib,
        telemetry.disk_used_mib,
        telemetry.disk_total_mib,
        telemetry.network_rx_kib_s,
        telemetry.network_tx_kib_s,
        telemetry.disk_read_kib_s,
        telemetry.disk_write_kib_s,
        telemetry.workload_id,
        telemetry.cpu_clock_mhz,
        telemetry.gpu_clock_mhz,
        telemetry.vram_clock_mhz,
        telemetry.system_ram_clock_mhz,
        telemetry.active_requests,
        telemetry.queued_requests,
        telemetry.connected_clients,
        telemetry.requests_received,
        telemetry.requests_admitted,
        telemetry.requests_completed,
        telemetry.requests_failed,
        telemetry.requests_cancelled,
        telemetry.requests_retried,
        telemetry.input_tokens,
        telemetry.output_tokens,
        telemetry.cached_tokens,
        telemetry.queue_milliseconds,
        telemetry.ttft_milliseconds,
        telemetry.decode_milliseconds,
        telemetry.exact_token_requests,
        telemetry.prefix_cache_hits,
        telemetry.usage_records_dropped,
        telemetry.usage_write_errors,
    );
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use li_benchmark_manager::BenchmarkProgress;
    use li_benchmark_worker::BenchmarkWorkerError;
    use li_core_interface::{OperationId, TechnicalName, UnixMilliseconds};

    use super::*;

    struct FixedSource(Mutex<Result<Vec<WatchdogSample>, BenchmarkWorkerError>>);

    impl NativeBenchmarkTelemetrySource for FixedSource {
        // Returns the injected exact history result for every deterministic query.
        fn query_range(
            &self,
            _start: u64,
            _end: u64,
        ) -> Result<Vec<WatchdogSample>, BenchmarkWorkerError> {
            self.0.lock().expect("source").clone()
        }
    }

    // Creates one fixed telemetry-window command.
    fn command() -> CoreBenchmarkTelemetryWindow {
        CoreBenchmarkTelemetryWindow::new(
            OperationId::parse(&"a".repeat(32)).expect("job"),
            Sha256Digest::parse(&"b".repeat(64)).expect("session"),
            UnixMilliseconds::new(10_000),
            BenchmarkProgress::new(TechnicalName::parse("measure").expect("phase"), 1, 2)
                .expect("progress"),
        )
    }

    // Creates one source adapter from an injected provider result.
    fn adapter(
        result: Result<Vec<WatchdogSample>, BenchmarkWorkerError>,
    ) -> WatchdogCoreBenchmarkTelemetryObservationPort {
        WatchdogCoreBenchmarkTelemetryObservationPort::new(Arc::new(FixedSource(Mutex::new(
            result,
        ))))
    }

    #[test]
    // Proves identical raw evidence has one stable observation identity on replay.
    fn exact_sample_is_stable_on_replay() {
        let sample = WatchdogSample::new(7, 9_999, 8_000).expect("sample");
        let adapter = adapter(Ok(vec![sample]));
        let first = adapter.observe(&command()).expect("observation");
        let replay = adapter.observe(&command()).expect("replay");
        assert_eq!(first, replay);
        assert_eq!(first.sampled_at(), UnixMilliseconds::new(10_000));
    }

    #[test]
    // Rejects every ambiguous or incomplete one-second sample result.
    fn gap_duplicate_and_out_of_window_samples_are_rejected() {
        let command = command();
        assert_eq!(
            adapter(Ok(vec![])).observe(&command),
            Err(CoreBenchmarkPortError::InvalidState)
        );
        let sample = WatchdogSample::new(7, 9_999, 8_000).expect("sample");
        assert_eq!(
            adapter(Ok(vec![sample.clone(), sample])).observe(&command),
            Err(CoreBenchmarkPortError::InvalidState)
        );
        let outside = WatchdogSample::new(8, 10_000, 8_001).expect("outside");
        assert_eq!(
            adapter(Ok(vec![outside])).observe(&command),
            Err(CoreBenchmarkPortError::InvalidState)
        );
    }

    #[test]
    // Redacts provider details behind the stable unavailable classification.
    fn provider_failure_is_redacted_as_unavailable() {
        let failure = BenchmarkWorkerError::invalid("private provider detail");
        assert_eq!(
            adapter(Err(failure)).observe(&command()),
            Err(CoreBenchmarkPortError::Unavailable)
        );
    }
}
