// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeSet, VecDeque};
use std::sync::{Arc, Mutex};

use li_watchdog_manager::{
    validate_watchdog_nvml_symbol_contract, NvmlWatchdogLinuxGpuProvider, WatchdogError,
    WatchdogLinuxCapability, WatchdogLinuxGpuProvider, WatchdogLinuxGpuSample,
    WatchdogNvmlDeviceSample, WatchdogNvmlPort, WatchdogNvmlSymbolProvider, WATCHDOG_CLOCK_UNKNOWN,
    WATCHDOG_PERCENT_UNKNOWN, WATCHDOG_TEMP_UNKNOWN,
};

// Creates one complete injected NVML device observation.
fn device(
    uuid: &str,
    gpu: Option<u8>,
    memory: Option<u8>,
    temperature: Option<i16>,
    power: Option<u32>,
    throttled: bool,
    gpu_clock: Option<u32>,
    memory_clock: Option<u32>,
) -> WatchdogNvmlDeviceSample {
    WatchdogNvmlDeviceSample::new(
        uuid,
        gpu,
        memory,
        [gpu, memory, Some(10), Some(20), Some(30), Some(40)],
        temperature,
        power,
        Some(u64::from(throttled)),
        gpu_clock,
        memory_clock,
    )
    .unwrap()
}

// Supplies deterministic device sets and native failures.
struct MockNvmlPort {
    samples: Mutex<
        VecDeque<Result<WatchdogLinuxCapability<Vec<WatchdogNvmlDeviceSample>>, WatchdogError>>,
    >,
}

impl WatchdogNvmlPort for MockNvmlPort {
    // Returns the next complete injected NVML transaction.
    fn devices(
        &self,
    ) -> Result<WatchdogLinuxCapability<Vec<WatchdogNvmlDeviceSample>>, WatchdogError> {
        self.samples.lock().unwrap().pop_front().unwrap()
    }
}

// Creates one GPU provider around a single injected NVML result.
fn provider(
    sample: Result<WatchdogLinuxCapability<Vec<WatchdogNvmlDeviceSample>>, WatchdogError>,
) -> NvmlWatchdogLinuxGpuProvider {
    NvmlWatchdogLinuxGpuProvider::new(Arc::new(MockNvmlPort {
        samples: Mutex::new(vec![sample].into()),
    }))
}

#[test]
// Aggregates multiple unique GPUs by maximum utilization and clocks and summed power.
fn nvml_aggregates_multiple_identity_checked_devices() {
    let devices = vec![
        device(
            "GPU-aaaaaaaaaaaaaaaa",
            Some(20),
            Some(30),
            Some(50),
            Some(100_000),
            false,
            Some(1_000),
            Some(2_000),
        ),
        device(
            "GPU-bbbbbbbbbbbbbbbb",
            Some(80),
            Some(60),
            Some(70),
            Some(200_000),
            true,
            Some(1_500),
            Some(2_500),
        ),
    ];
    let actual = provider(Ok(WatchdogLinuxCapability::Available(devices)))
        .sample()
        .unwrap();
    let expected = WatchdogLinuxGpuSample::new(
        80,
        60,
        [80, 60, 10, 20, 30, 40],
        700,
        3_000,
        true,
        1_500,
        2_500,
    )
    .unwrap();
    assert_eq!(actual, WatchdogLinuxCapability::Available(expected));
}

#[test]
// Preserves unsupported and unavailable fields without fabricating utilization zeros.
fn nvml_preserves_missing_library_and_optional_value_states() {
    assert_eq!(
        provider(Ok(WatchdogLinuxCapability::Unsupported))
            .sample()
            .unwrap(),
        WatchdogLinuxCapability::Unsupported
    );
    let unknown = WatchdogNvmlDeviceSample::new(
        "GPU-aaaaaaaaaaaaaaaa",
        None,
        None,
        [None; 6],
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap();
    let actual = provider(Ok(WatchdogLinuxCapability::Available(vec![unknown])))
        .sample()
        .unwrap();
    let expected = WatchdogLinuxGpuSample::new(
        WATCHDOG_PERCENT_UNKNOWN,
        WATCHDOG_PERCENT_UNKNOWN,
        [WATCHDOG_PERCENT_UNKNOWN; 6],
        WATCHDOG_TEMP_UNKNOWN,
        0,
        false,
        WATCHDOG_CLOCK_UNKNOWN,
        WATCHDOG_CLOCK_UNKNOWN,
    )
    .unwrap();
    assert_eq!(actual, WatchdogLinuxCapability::Available(expected));
}

#[test]
// Rejects zero, excessive, duplicate, malformed, and provider-failed device transactions.
fn nvml_rejects_every_device_identity_and_bound_failure() {
    assert!(provider(Ok(WatchdogLinuxCapability::Available(Vec::new())))
        .sample()
        .is_err());
    let duplicate = device(
        "GPU-aaaaaaaaaaaaaaaa",
        Some(1),
        Some(1),
        None,
        None,
        false,
        None,
        None,
    );
    assert!(provider(Ok(WatchdogLinuxCapability::Available(vec![
        duplicate.clone(),
        duplicate
    ])))
    .sample()
    .is_err());
    let excessive = vec![
        device(
            "GPU-aaaaaaaaaaaaaaaa",
            None,
            None,
            None,
            None,
            false,
            None,
            None
        );
        65
    ];
    assert!(provider(Ok(WatchdogLinuxCapability::Available(excessive)))
        .sample()
        .is_err());
    assert!(WatchdogNvmlDeviceSample::new(
        "bad uuid", None, None, [None; 6], None, None, None, None, None
    )
    .is_err());
    assert!(provider(Err(WatchdogError::StateUnavailable))
        .sample()
        .is_err());
}

// Supplies a selected set of available dynamic ABI symbols.
struct MockSymbols {
    names: BTreeSet<&'static str>,
}

impl WatchdogNvmlSymbolProvider for MockSymbols {
    // Returns whether the exact symbol was injected.
    fn has_symbol(&self, name: &str) -> bool {
        self.names.contains(name)
    }
}

#[test]
// Requires every versioned initialization, enumeration, and UUID identity symbol.
fn nvml_symbol_negotiation_fails_closed_on_each_missing_symbol() {
    let required = [
        "nvmlInit_v2",
        "nvmlShutdown",
        "nvmlDeviceGetCount_v2",
        "nvmlDeviceGetHandleByIndex_v2",
        "nvmlDeviceGetUUID",
    ];
    assert!(validate_watchdog_nvml_symbol_contract(&MockSymbols {
        names: required.into_iter().collect(),
    })
    .is_ok());
    for missing in required {
        let names = required
            .into_iter()
            .filter(|name| *name != missing)
            .collect();
        assert!(validate_watchdog_nvml_symbol_contract(&MockSymbols { names }).is_err());
    }
}
