// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use li_core_interface::{
    Accelerator, AcceleratorMemory, AcceleratorTelemetry, AcceleratorVendor, BootId, ByteCount,
    ComputeCapability, CpuArchitecture, DeviceId, DisplayName, HardwareObservationId,
    InterconnectObservation, InterconnectObservationKind, MemoryTopology, NodeId, OperatingSystem,
    PlatformIdentity, ProcessorObservation, TechnicalName, UnixMilliseconds,
};
use li_hardware_manager::{
    HardwareClock, HardwareError, HardwareEvent, HardwareIdentityProvider, HardwareManager,
    HardwareObservationFreshness, HardwareProvider, HardwareSnapshot,
};

// Returns one Linux NVIDIA hardware snapshot with mutable telemetry.
fn snapshot(temperature: i32) -> HardwareSnapshot {
    snapshot_with_identity("boot-fixture", "GPU-fixture", temperature)
}

// Returns one Linux NVIDIA snapshot with explicit boot and device identities.
fn snapshot_with_identity(boot_id: &str, device_id: &str, temperature: i32) -> HardwareSnapshot {
    let device = DeviceId::parse(device_id).expect("device");
    let accelerator = Accelerator::new(
        device.clone(),
        AcceleratorVendor::Nvidia,
        DisplayName::parse("NVIDIA Fixture").expect("name"),
        AcceleratorMemory::new(
            MemoryTopology::Discrete,
            Some(ByteCount::new(32 * 1024 * 1024 * 1024).expect("framebuffer")),
            Some(TechnicalName::parse("vram").expect("addressing")),
        )
        .expect("memory"),
        ComputeCapability::Cuda {
            architecture: TechnicalName::parse("sm_120").expect("architecture"),
            maximum_version: Some(TechnicalName::parse("cuda_13.0").expect("CUDA")),
        },
    )
    .with_telemetry(
        AcceleratorTelemetry::new(
            Some(temperature),
            Some(2_500),
            Some(2_000),
            Some(500),
            Some(350_000),
            Some(1_024),
        )
        .expect("telemetry"),
    );
    HardwareSnapshot::new(
        BootId::parse(boot_id).expect("boot"),
        PlatformIdentity::new(OperatingSystem::Linux, CpuArchitecture::X86_64),
        ProcessorObservation::new(DisplayName::parse("Fixture CPU").expect("CPU"), 16)
            .expect("processor"),
        ByteCount::new(128 * 1024 * 1024 * 1024).expect("memory"),
        vec![accelerator],
        vec![InterconnectObservation::new(
            InterconnectObservationKind::Pcie,
            None,
            vec![device],
            true,
            None,
            None,
        )
        .expect("interconnect")],
    )
}

// Supplies mutable deterministic provider output.
struct TestProvider {
    platform: PlatformIdentity,
    snapshot: Mutex<HardwareSnapshot>,
    should_fail: AtomicU8,
}

impl HardwareProvider for TestProvider {
    // Returns the configured provider platform.
    fn platform(&self) -> PlatformIdentity {
        self.platform
    }

    // Returns the configured snapshot or stable provider failure.
    fn observe(&self) -> Result<HardwareSnapshot, HardwareError> {
        if self.should_fail.load(Ordering::SeqCst) != 0 {
            return Err(HardwareError::ProviderUnavailable);
        }
        self.snapshot
            .lock()
            .map(|snapshot| snapshot.clone())
            .map_err(|_| HardwareError::StateUnavailable)
    }
}

// Supplies deterministic unique observation identities.
struct TestIdentity {
    next_value: AtomicU8,
}

impl HardwareIdentityProvider for TestIdentity {
    // Returns one distinct canonical observation identity.
    fn observation_id(&self) -> Result<HardwareObservationId, HardwareError> {
        let value = self.next_value.fetch_add(1, Ordering::SeqCst);
        HardwareObservationId::parse(&format!("{value:02x}").repeat(16)).map_err(Into::into)
    }
}

// Supplies deterministic increasing observation time.
struct TestClock {
    next_value: AtomicU64,
}

// Supplies one scripted sequence of observation identities.
struct SequenceIdentity {
    values: Mutex<VecDeque<Result<HardwareObservationId, HardwareError>>>,
}

impl HardwareIdentityProvider for SequenceIdentity {
    // Returns the next identity result without fabricating a replacement.
    fn observation_id(&self) -> Result<HardwareObservationId, HardwareError> {
        self.values
            .lock()
            .map_err(|_| HardwareError::StateUnavailable)?
            .pop_front()
            .unwrap_or(Err(HardwareError::IdentityUnavailable))
    }
}

// Supplies one scripted sequence of observation times.
struct SequenceClock {
    values: Mutex<VecDeque<Result<UnixMilliseconds, HardwareError>>>,
}

impl HardwareClock for SequenceClock {
    // Returns the next clock result without silently substituting local time.
    fn now(&self) -> Result<UnixMilliseconds, HardwareError> {
        self.values
            .lock()
            .map_err(|_| HardwareError::StateUnavailable)?
            .pop_front()
            .unwrap_or(Err(HardwareError::ClockUnavailable))
    }
}

impl HardwareClock for TestClock {
    // Returns one increasing observation timestamp.
    fn now(&self) -> Result<UnixMilliseconds, HardwareError> {
        Ok(UnixMilliseconds::new(
            self.next_value.fetch_add(1, Ordering::SeqCst),
        ))
    }
}

// Creates one manager and retains its mutable provider.
fn manager() -> (Arc<HardwareManager>, Arc<TestProvider>) {
    let platform = PlatformIdentity::new(OperatingSystem::Linux, CpuArchitecture::X86_64);
    let provider = Arc::new(TestProvider {
        platform,
        snapshot: Mutex::new(snapshot(65_000)),
        should_fail: AtomicU8::new(0),
    });
    let manager = Arc::new(HardwareManager::new(
        NodeId::parse(&"1".repeat(32)).expect("node"),
        provider.clone(),
        Arc::new(TestIdentity {
            next_value: AtomicU8::new(1),
        }),
        Arc::new(TestClock {
            next_value: AtomicU64::new(1_000),
        }),
    ));
    (manager, provider)
}

// Creates one manager from exact scripted identity and clock results.
fn scripted_manager(
    identities: Vec<Result<HardwareObservationId, HardwareError>>,
    times: Vec<Result<UnixMilliseconds, HardwareError>>,
) -> (HardwareManager, Arc<TestProvider>) {
    let platform = PlatformIdentity::new(OperatingSystem::Linux, CpuArchitecture::X86_64);
    let provider = Arc::new(TestProvider {
        platform,
        snapshot: Mutex::new(snapshot(65_000)),
        should_fail: AtomicU8::new(0),
    });
    let manager = HardwareManager::new(
        NodeId::parse(&"1".repeat(32)).expect("node"),
        provider.clone(),
        Arc::new(SequenceIdentity {
            values: Mutex::new(identities.into()),
        }),
        Arc::new(SequenceClock {
            values: Mutex::new(times.into()),
        }),
    );
    (manager, provider)
}

// Parses one deterministic observation identity for scripted manager tests.
fn observation_id(value: char) -> HardwareObservationId {
    HardwareObservationId::parse(&value.to_string().repeat(32)).expect("observation identity")
}

// Distinguishes first observation, unchanged refresh, and semantic change.
#[test]
fn manager_classifies_hardware_observations() {
    let (manager, provider) = manager();
    let first = manager.observe().expect("first observation");
    assert!(matches!(
        first.event(),
        HardwareEvent::HardwareObserved { .. }
    ));
    let refreshed = manager.observe().expect("refresh");
    assert!(matches!(
        refreshed.event(),
        HardwareEvent::HardwareRefreshed { .. }
    ));
    *provider.snapshot.lock().expect("snapshot") = snapshot(70_000);
    let changed = manager.observe().expect("changed observation");
    assert!(matches!(
        changed.event(),
        HardwareEvent::HardwareChanged { .. }
    ));
    assert_eq!(
        manager
            .latest()
            .expect("latest")
            .expect("observation")
            .accelerators()[0]
            .telemetry()
            .expect("telemetry")
            .temperature_millicelsius(),
        Some(70_000)
    );
}

// Rejects a provider snapshot that claims another platform.
#[test]
fn manager_rejects_provider_platform_mismatch() {
    let (manager, provider) = manager();
    *provider.snapshot.lock().expect("snapshot") = HardwareSnapshot::new(
        BootId::parse("boot-fixture").expect("boot"),
        PlatformIdentity::new(OperatingSystem::Macos, CpuArchitecture::Arm64),
        ProcessorObservation::new(DisplayName::parse("Apple CPU").expect("CPU"), 10)
            .expect("processor"),
        ByteCount::new(128).expect("memory"),
        Vec::new(),
        Vec::new(),
    );
    assert_eq!(
        manager.observe().expect_err("mismatch"),
        HardwareError::PlatformMismatch
    );
    assert!(manager.latest().expect("latest").is_none());
}

// Preserves provider failure without fabricating stale current facts.
#[test]
fn manager_fails_closed_when_provider_is_unavailable() {
    let (manager, provider) = manager();
    provider.should_fail.store(1, Ordering::SeqCst);
    assert_eq!(
        manager.observe().expect_err("provider failure"),
        HardwareError::ProviderUnavailable
    );
    assert!(manager.latest().expect("latest").is_none());
}

// Retains the previous complete observation when a later provider read fails.
#[test]
fn manager_retains_latest_when_refresh_provider_fails() {
    let (manager, provider) = manager();
    let first = manager.observe().expect("first observation");
    provider.should_fail.store(1, Ordering::SeqCst);
    assert_eq!(
        manager.observe().expect_err("provider failure"),
        HardwareError::ProviderUnavailable
    );
    assert_eq!(
        manager.latest().expect("latest").expect("observation"),
        *first.observation()
    );
}

// Rejects identity and clock failures before replacing the latest observation.
#[test]
fn manager_retains_latest_across_identity_and_clock_failures() {
    let identities = vec![
        Ok(observation_id('1')),
        Err(HardwareError::IdentityUnavailable),
        Ok(observation_id('2')),
    ];
    let times = vec![
        Ok(UnixMilliseconds::new(1_000)),
        Err(HardwareError::ClockUnavailable),
    ];
    let (manager, _) = scripted_manager(identities, times);
    let first = manager.observe().expect("first observation");
    assert_eq!(
        manager.observe().expect_err("identity failure"),
        HardwareError::IdentityUnavailable
    );
    assert_eq!(
        manager.observe().expect_err("clock failure"),
        HardwareError::ClockUnavailable
    );
    assert_eq!(
        manager.latest().expect("latest").expect("observation"),
        *first.observation()
    );
}

// Rejects duplicate identities and backward clocks while preserving prior state.
#[test]
fn manager_rejects_replayed_identity_and_backward_time() {
    let identities = vec![
        Ok(observation_id('1')),
        Ok(observation_id('1')),
        Ok(observation_id('2')),
    ];
    let times = vec![
        Ok(UnixMilliseconds::new(1_000)),
        Ok(UnixMilliseconds::new(1_001)),
        Ok(UnixMilliseconds::new(999)),
    ];
    let (manager, _) = scripted_manager(identities, times);
    let first = manager.observe().expect("first observation");
    for reason in ["duplicate identity", "backward time"] {
        assert!(matches!(
            manager.observe().expect_err(reason),
            HardwareError::InvalidObservation { .. }
        ));
        assert_eq!(
            manager.latest().expect("latest").expect("observation"),
            *first.observation()
        );
    }
}

// Binds mutable topology freshness to the exact observation and boot identities.
#[test]
fn manager_classifies_current_stale_and_future_observations() {
    let (manager, _) = manager();
    let observed = manager.observe().expect("observation");
    let current = manager
        .latest_at(UnixMilliseconds::new(1_100), 100)
        .expect("current")
        .expect("latest");
    assert_eq!(current.observation(), observed.observation());
    assert_eq!(current.freshness(), HardwareObservationFreshness::Current);
    let stale = manager
        .latest_at(UnixMilliseconds::new(1_101), 100)
        .expect("stale")
        .expect("latest");
    assert_eq!(
        stale.freshness(),
        HardwareObservationFreshness::Stale {
            age_milliseconds: 101
        }
    );
    assert!(matches!(
        manager.latest_at(UnixMilliseconds::new(999), 100),
        Err(HardwareError::InvalidObservation { .. })
    ));
    assert!(matches!(
        manager.latest_at(UnixMilliseconds::new(1_100), 0),
        Err(HardwareError::InvalidObservation { .. })
    ));
}

// Reports boot and device identity rollover as an exact semantic hardware change.
#[test]
fn manager_observes_boot_and_device_identity_rollover() {
    let (manager, provider) = manager();
    let first = manager.observe().expect("first observation");
    *provider.snapshot.lock().expect("snapshot") =
        snapshot_with_identity("boot-restarted", "GPU-replaced", 65_000);
    let changed = manager.observe().expect("changed observation");
    assert!(matches!(
        changed.event(),
        HardwareEvent::HardwareChanged {
            previous_observation_id,
            ..
        } if previous_observation_id == first.observation().observation_id()
    ));
    assert_eq!(changed.observation().boot_id().as_str(), "boot-restarted");
    assert_eq!(
        changed.observation().accelerators()[0].device_id().as_str(),
        "GPU-replaced"
    );
}

// Serializes concurrent observations while retaining a complete latest snapshot.
#[test]
fn manager_serializes_concurrent_refresh() {
    let (manager, _) = manager();
    let workers: Vec<_> = (0..8)
        .map(|_| {
            let manager = Arc::clone(&manager);
            thread::spawn(move || manager.observe())
        })
        .collect();
    let results: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().expect("worker").expect("observation"))
        .collect();
    assert_eq!(results.len(), 8);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result.event(), HardwareEvent::HardwareObserved { .. }))
            .count(),
        1
    );
    assert!(manager.latest().expect("latest").is_some());
}

// Rejects impossible telemetry before it can enter a provider snapshot.
#[test]
fn telemetry_contract_rejects_impossible_values() {
    assert!(AcceleratorTelemetry::new(Some(251_000), None, None, None, None, None).is_err());
    assert!(AcceleratorTelemetry::new(None, None, None, Some(1_001), None, None).is_err());
}
