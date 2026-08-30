// SPDX-License-Identifier: AGPL-3.0-only

mod li_benchmark_execution;
mod li_benchmark_native;
mod li_benchmark_prompt;
mod li_benchmark_system;
mod li_benchmark_watchdog;

use std::error::Error;
use std::fmt;

pub use li_benchmark_execution::{
    run_native_benchmark_controlled, NativeBenchmarkRouteInput, NativeBenchmarkStreamMeasurement,
    NativeBenchmarkStreamRequest, NativeBenchmarkTransport, NativeBenchmarkWorkerInput,
    NativeBenchmarkWorkerOutput,
};
pub use li_benchmark_native::NativeGatewayBenchmarkTransport;
pub use li_benchmark_prompt::{
    materialize_native_benchmark, NativeBenchmarkCell, NativeBenchmarkContract,
    NativeBenchmarkFixture, NativeBenchmarkMaterialization, NativeBenchmarkRequest,
};
pub use li_benchmark_system::run_native_benchmark_file;
pub use li_benchmark_watchdog::{
    NativeBenchmarkClock, NativeBenchmarkTelemetrySource, NativeBenchmarkWatchdogInput,
    NativeBenchmarkWatchdogTransport, SystemNativeBenchmarkClock,
    SystemNativeBenchmarkWatchdogTransport, WatchdogBenchmarkTelemetrySource,
};

// Describes one stable native benchmark-worker failure without private request data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BenchmarkWorkerError {
    reason: &'static str,
}

impl BenchmarkWorkerError {
    // Creates one bounded contract or provider failure from static redacted language.
    pub const fn invalid(reason: &'static str) -> Self {
        Self { reason }
    }

    // Returns the stable redacted failure reason.
    pub const fn reason(self) -> &'static str {
        self.reason
    }

    // Creates the one distinct cancellation result consumed by restart polling.
    pub const fn cancelled() -> Self {
        Self {
            reason: "native benchmark was cancelled",
        }
    }

    // Returns whether this failure is the exact task-owned cancellation result.
    pub fn is_cancelled(self) -> bool {
        self.reason == "native benchmark was cancelled"
    }
}

impl fmt::Display for BenchmarkWorkerError {
    // Presents one stable worker failure without request, prompt, or credential content.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason)
    }
}

impl Error for BenchmarkWorkerError {}
