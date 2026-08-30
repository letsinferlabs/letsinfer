// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use li_watchdog_manager::{
    WatchdogError, WatchdogGatewayTelemetryFile, WatchdogGatewayTelemetryFileProvider,
    WatchdogGatewayTelemetryProvider, WatchdogLinuxCapability, WatchdogSampleTelemetry,
    WATCHDOG_SAMPLE_GATEWAY_AVAILABLE,
};

// Returns one complete unchanged C gateway telemetry-v2 record.
fn telemetry_source(received: u64) -> Vec<u8> {
    format!(
        concat!(
            "version=2\nactive_requests=1\nconnected_clients=2\nqueued_requests=3\n",
            "requests_received={}\nrequests_admitted=5\nrequests_completed=4\n",
            "requests_failed=1\nrequests_cancelled=2\nrequests_retried=3\n",
            "input_tokens=100\noutput_tokens=50\ncached_tokens=25\n",
            "queue_milliseconds=10\nttft_milliseconds=20\ndecode_milliseconds=30\n",
            "exact_token_requests=4\nprefix_cache_hits=2\n",
            "usage_records_dropped=0\nusage_write_errors=0\n"
        ),
        received
    )
    .into_bytes()
}

// Creates one safe injected telemetry file observation.
fn file(bytes: Vec<u8>, inode: u64, modified: u64) -> WatchdogGatewayTelemetryFile {
    WatchdogGatewayTelemetryFile::new(bytes, 501, 0o600, 1, true, true, 9, inode, modified)
}

// Supplies a deterministic sequence of absent, unsafe, or complete file reads.
struct MockFiles {
    reads: Mutex<
        VecDeque<Result<WatchdogLinuxCapability<WatchdogGatewayTelemetryFile>, WatchdogError>>,
    >,
}

impl WatchdogGatewayTelemetryFileProvider for MockFiles {
    // Returns the next observation and proves the unchanged C byte bound.
    fn read(
        &self,
        _path: &Path,
        maximum_bytes: usize,
    ) -> Result<WatchdogLinuxCapability<WatchdogGatewayTelemetryFile>, WatchdogError> {
        assert_eq!(maximum_bytes, 4_096);
        self.reads.lock().unwrap().pop_front().unwrap()
    }
}

// Creates one stateful reader around injected file observations.
fn provider(
    reads: Vec<Result<WatchdogLinuxCapability<WatchdogGatewayTelemetryFile>, WatchdogError>>,
) -> WatchdogGatewayTelemetryProvider {
    WatchdogGatewayTelemetryProvider::new(
        PathBuf::from("/var/lib/letsinfer/gateway/telemetry.state"),
        501,
        Box::new(MockFiles {
            reads: Mutex::new(reads.into()),
        }),
    )
    .unwrap()
}

#[test]
// Parses and applies all 19 gateway fields before setting the availability flag.
fn gateway_telemetry_applies_one_complete_fresh_record() {
    let provider = provider(vec![Ok(WatchdogLinuxCapability::Available(file(
        telemetry_source(6),
        10,
        10_000,
    )))]);
    let WatchdogLinuxCapability::Available(gateway) = provider.sample(11_000).unwrap() else {
        panic!("fresh gateway telemetry must be available")
    };
    let mut telemetry = WatchdogSampleTelemetry::default();
    gateway.apply(&mut telemetry);
    assert_eq!(telemetry.flags, WATCHDOG_SAMPLE_GATEWAY_AVAILABLE);
    assert_eq!(
        (
            telemetry.active_requests,
            telemetry.connected_clients,
            telemetry.queued_requests
        ),
        (1, 2, 3)
    );
    assert_eq!(
        (
            telemetry.requests_received,
            telemetry.input_tokens,
            telemetry.output_tokens
        ),
        (6, 100, 50)
    );
    assert_eq!(
        (telemetry.exact_token_requests, telemetry.prefix_cache_hits),
        (4, 2)
    );
}

#[test]
// Treats an absent or stale complete snapshot as unavailable without zero counters.
fn gateway_telemetry_preserves_absent_and_stale_states() {
    let provider = provider(vec![
        Ok(WatchdogLinuxCapability::Unsupported),
        Ok(WatchdogLinuxCapability::Available(file(
            telemetry_source(6),
            10,
            1_000,
        ))),
    ]);
    assert_eq!(
        provider.sample(10_000).unwrap(),
        WatchdogLinuxCapability::Unsupported
    );
    assert_eq!(
        provider.sample(10_000).unwrap(),
        WatchdogLinuxCapability::Unsupported
    );
}

#[test]
// Rejects malformed, duplicate, incomplete, oversized, and unsafe file observations.
fn gateway_telemetry_rejects_every_closed_file_and_schema_failure() {
    let valid = telemetry_source(6);
    let malformed = [
        b"version=3\n".to_vec(),
        [valid.clone(), b"active_requests=1\n".to_vec()].concat(),
        String::from_utf8(valid.clone())
            .unwrap()
            .replace("output_tokens=50\n", "")
            .into_bytes(),
        String::from_utf8(valid.clone())
            .unwrap()
            .replace("active_requests=1", "active_requests=-1")
            .into_bytes(),
    ];
    for bytes in malformed {
        let provider = provider(vec![Ok(WatchdogLinuxCapability::Available(file(
            bytes, 10, 10_000,
        )))]);
        assert!(provider.sample(11_000).is_err());
    }
    let unsafe_file =
        WatchdogGatewayTelemetryFile::new(valid, 502, 0o644, 2, true, false, 9, 10, 10_000);
    let provider = provider(vec![Ok(WatchdogLinuxCapability::Available(unsafe_file))]);
    assert!(provider.sample(11_000).is_err());
}

#[test]
// Rejects same-file replay regression but accepts a lower counter after atomic restart replacement.
fn gateway_telemetry_distinguishes_regression_from_restart() {
    let provider = provider(vec![
        Ok(WatchdogLinuxCapability::Available(file(
            telemetry_source(10),
            10,
            10_000,
        ))),
        Ok(WatchdogLinuxCapability::Available(file(
            telemetry_source(9),
            10,
            11_000,
        ))),
        Ok(WatchdogLinuxCapability::Available(file(
            telemetry_source(1),
            11,
            12_000,
        ))),
    ]);
    assert!(provider.sample(10_500).is_ok());
    assert!(provider.sample(11_500).is_err());
    assert!(provider.sample(12_500).is_ok());
}

#[test]
// Rejects a content change at the same inode and modification identity as partial replacement.
fn gateway_telemetry_rejects_partial_same_identity_replacement() {
    let provider = provider(vec![
        Ok(WatchdogLinuxCapability::Available(file(
            telemetry_source(10),
            10,
            10_000,
        ))),
        Ok(WatchdogLinuxCapability::Available(file(
            telemetry_source(11),
            10,
            10_000,
        ))),
    ]);
    assert!(provider.sample(10_500).is_ok());
    assert!(provider.sample(10_500).is_err());
}
