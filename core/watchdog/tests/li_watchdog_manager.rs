// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use li_watchdog_manager::{
    maximum_watchdog_targets, WatchdogError, WatchdogManager, WatchdogProcessState,
    WatchdogProtectedEngine, WatchdogProtectionCycle, WatchdogProtectionObservation,
    WatchdogProtectionPhase, WatchdogProtectionProvider, WatchdogSafetyAction, WatchdogSafetyEvent,
    WatchdogSafetyInput, WatchdogSafetyThresholds, WatchdogSample, WatchdogSampleProvider,
    WatchdogStorageProvider,
};

const ARMED_DESCRIPTOR: &str = "version=1\
\ngeneration=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
\nphase=armed\
\ncontainer_name=li_engine\
\ncontainer_id=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\
\npid=1234\
\nstart_ticks=5678\
\nboot_id=12345678-1234-1234-1234-123456789abc\
\ncgroup=/sys/fs/cgroup/user.slice/li_engine\n";

const DISARMED_DESCRIPTOR: &str = "version=1\
\ngeneration=cccccccccccccccccccccccccccccccc\
\nphase=disarmed\
\ncontainer_name=li_engine\
\ncontainer_id=-\
\npid=-\
\nstart_ticks=-\
\nboot_id=-\
\ncgroup=-\n";

// Produces deterministic samples and can fail the exact provider boundary.
struct SampleMock {
    calls: Mutex<Vec<u64>>,
    fail: AtomicBool,
}

impl SampleMock {
    // Creates one available deterministic sampler.
    fn new() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            fail: AtomicBool::new(false),
        }
    }
}

impl WatchdogSampleProvider for SampleMock {
    // Returns clocks derived only from the requested durable sequence.
    fn sample(&self, sequence: u64) -> Result<WatchdogSample, WatchdogError> {
        self.calls.lock().unwrap().push(sequence);
        if self.fail.load(Ordering::SeqCst) {
            return Err(WatchdogError::provider("sample", "unavailable"));
        }
        WatchdogSample::new(sequence, 1_700_000_000_000 + sequence, 10_000 + sequence)
    }
}

// Returns queued target observations and records every mutation boundary.
struct ProtectionMock {
    plans: Mutex<VecDeque<Result<Vec<WatchdogProtectionObservation>, WatchdogError>>>,
    events: Arc<Mutex<Vec<String>>>,
    containment_complete: AtomicBool,
    contain_failure: AtomicBool,
    latch_failures: AtomicUsize,
}

impl ProtectionMock {
    // Creates one protection provider from an ordered observation plan.
    fn new(
        events: Arc<Mutex<Vec<String>>>,
        plans: Vec<Vec<WatchdogProtectionObservation>>,
    ) -> Self {
        Self {
            plans: Mutex::new(plans.into_iter().map(Ok).collect()),
            events,
            containment_complete: AtomicBool::new(true),
            contain_failure: AtomicBool::new(false),
            latch_failures: AtomicUsize::new(0),
        }
    }
}

impl WatchdogProtectionProvider for ProtectionMock {
    // Returns the next exact target set without inspecting host state.
    fn observations(
        &self,
        _sample: &WatchdogSample,
    ) -> Result<Vec<WatchdogProtectionObservation>, WatchdogError> {
        self.events.lock().unwrap().push("observe".to_string());
        self.plans
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| Ok(Vec::new()))
    }

    // Records one deliberate-exit acknowledgment.
    fn acknowledge_disarmed(&self, target: &WatchdogProtectedEngine) -> Result<(), WatchdogError> {
        self.events
            .lock()
            .unwrap()
            .push(format!("ack:{}", target.generation()));
        Ok(())
    }

    // Records one durable trip latch before any containment call.
    fn latch_trip(
        &self,
        target: &WatchdogProtectedEngine,
        action: WatchdogSafetyAction,
        reason: &'static str,
        _input: WatchdogSafetyInput,
    ) -> Result<(), WatchdogError> {
        self.events
            .lock()
            .unwrap()
            .push(format!("latch:{}:{action:?}:{reason}", target.generation()));
        if self.latch_failures.load(Ordering::SeqCst) > 0 {
            self.latch_failures.fetch_sub(1, Ordering::SeqCst);
            return Err(WatchdogError::provider("trip", "unavailable"));
        }
        Ok(())
    }

    // Records exact containment and returns its configured completeness.
    fn contain(
        &self,
        target: &WatchdogProtectedEngine,
        action: WatchdogSafetyAction,
        grace_milliseconds: u32,
    ) -> Result<bool, WatchdogError> {
        self.events.lock().unwrap().push(format!(
            "contain:{}:{action:?}:{grace_milliseconds}",
            target.generation()
        ));
        if self.contain_failure.load(Ordering::SeqCst) {
            return Err(WatchdogError::provider("contain", "unavailable"));
        }
        Ok(self.containment_complete.load(Ordering::SeqCst))
    }
}

// Stores idempotent sample and event identities with explicit flush failures.
struct StorageMock {
    next_sequence: AtomicU64,
    events: Arc<Mutex<Vec<String>>>,
    flush_failures: AtomicUsize,
    event_failures: AtomicUsize,
}

impl StorageMock {
    // Creates one durable head and shared ordering log.
    fn new(next_sequence: u64, events: Arc<Mutex<Vec<String>>>) -> Self {
        Self {
            next_sequence: AtomicU64::new(next_sequence),
            events,
            flush_failures: AtomicUsize::new(0),
            event_failures: AtomicUsize::new(0),
        }
    }
}

impl WatchdogStorageProvider for StorageMock {
    // Returns the configured durable next sequence.
    fn next_sequence(&self) -> Result<u64, WatchdogError> {
        Ok(self.next_sequence.load(Ordering::SeqCst))
    }

    // Records one sample identity in the shared ordering log.
    fn record_sample(&self, sample: &WatchdogSample) -> Result<(), WatchdogError> {
        self.events
            .lock()
            .unwrap()
            .push(format!("sample:{}", sample.sequence()));
        Ok(())
    }

    // Records one event identity or fails the configured boundary.
    fn record_event(&self, event: &WatchdogSafetyEvent) -> Result<(), WatchdogError> {
        self.events.lock().unwrap().push(format!(
            "event:{}:{}:{}",
            event.generation(),
            event.kind(),
            event.sequence()
        ));
        if self.event_failures.load(Ordering::SeqCst) > 0 {
            self.event_failures.fetch_sub(1, Ordering::SeqCst);
            return Err(WatchdogError::provider("event", "unavailable"));
        }
        Ok(())
    }

    // Records or rejects one explicit crash-consistency boundary.
    fn flush(&self) -> Result<(), WatchdogError> {
        self.events.lock().unwrap().push("flush".to_string());
        if self.flush_failures.load(Ordering::SeqCst) > 0 {
            self.flush_failures.fetch_sub(1, Ordering::SeqCst);
            return Err(WatchdogError::provider("flush", "unavailable"));
        }
        Ok(())
    }
}

// Owns one complete deterministic manager environment.
struct Harness {
    samples: Arc<SampleMock>,
    protection: Arc<ProtectionMock>,
    storage: Arc<StorageMock>,
    events: Arc<Mutex<Vec<String>>>,
}

impl Harness {
    // Creates one manager environment from exact observation plans.
    fn new(plans: Vec<Vec<WatchdogProtectionObservation>>) -> Self {
        let events = Arc::new(Mutex::new(Vec::new()));
        Self {
            samples: Arc::new(SampleMock::new()),
            protection: Arc::new(ProtectionMock::new(events.clone(), plans)),
            storage: Arc::new(StorageMock::new(1, events.clone())),
            events,
        }
    }

    // Creates one manager over the harness providers.
    fn manager(&self) -> WatchdogManager {
        WatchdogManager::new(
            thresholds(),
            self.samples.clone(),
            self.protection.clone(),
            self.storage.clone(),
        )
        .unwrap()
    }
}

// Creates the exact ordered runtime threshold fixture.
fn thresholds() -> WatchdogSafetyThresholds {
    WatchdogSafetyThresholds::new(
        16 << 30,
        8 << 30,
        4 << 30,
        1 << 30,
        500_000,
        100_000,
        3,
        5_000,
    )
    .unwrap()
}

// Creates one armed target observation with selected safety and process facts.
fn observation(
    safety: WatchdogSafetyInput,
    process_state: WatchdogProcessState,
    trip_latched: bool,
) -> WatchdogProtectionObservation {
    WatchdogProtectionObservation::new(
        WatchdogProtectedEngine::parse(ARMED_DESCRIPTOR).unwrap(),
        process_state,
        safety,
        trip_latched,
    )
}

// Creates one armed observation with a distinct protection generation.
fn observation_with_generation(
    generation: char,
    safety: WatchdogSafetyInput,
    process_state: WatchdogProcessState,
    trip_latched: bool,
) -> WatchdogProtectionObservation {
    let descriptor = ARMED_DESCRIPTOR.replace(
        &format!("generation={}", "a".repeat(32)),
        &format!("generation={}", generation.to_string().repeat(32)),
    );
    WatchdogProtectionObservation::new(
        WatchdogProtectedEngine::parse(&descriptor).unwrap(),
        process_state,
        safety,
        trip_latched,
    )
}

// Creates one disarmed target observation without live process material.
fn disarmed() -> WatchdogProtectionObservation {
    WatchdogProtectionObservation::new(
        WatchdogProtectedEngine::parse(DISARMED_DESCRIPTOR).unwrap(),
        WatchdogProcessState::Exited,
        WatchdogSafetyInput::default(),
        false,
    )
}

// Proves threshold ordering and every descriptor field bind the exact process generation.
#[test]
fn thresholds_and_protection_descriptors_are_closed() {
    assert!(WatchdogSafetyThresholds::new(4, 3, 2, 1, 1, 1, 2, 30_000).is_ok());
    assert!(WatchdogSafetyThresholds::new(3, 3, 2, 1, 1, 1, 2, 30_000).is_err());
    assert!(WatchdogSafetyThresholds::new(4, 3, 2, 1, 1, 1, 1, 30_000).is_err());
    assert!(WatchdogSafetyThresholds::new(4, 3, 2, 1, 1, 1, 2, 30_001).is_err());

    let target = WatchdogProtectedEngine::parse(ARMED_DESCRIPTOR).unwrap();
    assert_eq!(target.phase(), WatchdogProtectionPhase::Armed);
    assert_eq!(target.container_name(), "li_engine");
    assert_eq!(target.process_id(), Some(1234));
    assert_eq!(target.process_start_ticks(), Some(5678));
    assert_eq!(target.cgroup(), Some("/sys/fs/cgroup/user.slice/li_engine"));
    assert_eq!(
        WatchdogProtectedEngine::parse(DISARMED_DESCRIPTOR)
            .unwrap()
            .process_id(),
        None
    );

    for invalid in [
        ARMED_DESCRIPTOR.replace("version=1", "version=2"),
        ARMED_DESCRIPTOR.replace("phase=armed", "phase=unknown"),
        ARMED_DESCRIPTOR.replace("pid=1234", "pid=-"),
        ARMED_DESCRIPTOR.replace("cgroup=/sys/fs/cgroup/", "cgroup=/tmp/"),
        ARMED_DESCRIPTOR.replace(
            "cgroup=/sys/fs/cgroup/user.slice/li_engine",
            "cgroup=/sys/fs/cgroup//user.slice/li_engine",
        ),
        ARMED_DESCRIPTOR.replace(
            "cgroup=/sys/fs/cgroup/user.slice/li_engine",
            "cgroup=/sys/fs/cgroup/user.slice/./li_engine",
        ),
        ARMED_DESCRIPTOR.replace(
            "cgroup=/sys/fs/cgroup/user.slice/li_engine",
            "cgroup=/sys/fs/cgroup/user.slice/li_engine/",
        ),
        format!("{ARMED_DESCRIPTOR}unknown=value\n"),
        ARMED_DESCRIPTOR.replace("generation=aaaaaaaa", "generation=AAAAAAAA"),
    ] {
        assert!(WatchdogProtectedEngine::parse(&invalid).is_err());
    }
}

// Proves authenticated cycle rehydration remains bounded, nonzero, armed, and duplicate-free.
#[test]
fn authenticated_protection_cycle_report_is_closed() {
    let armed = WatchdogProtectedEngine::parse(ARMED_DESCRIPTOR).unwrap();
    assert!(
        WatchdogProtectionCycle::from_authenticated_report(1, 1_000, 100, vec![armed.clone()],)
            .is_ok()
    );
    for (sequence, unix, monotonic, targets) in [
        (0, 1_000, 100, vec![armed.clone()]),
        (1, 0, 100, vec![armed.clone()]),
        (1, 1_000, 0, vec![armed.clone()]),
        (1, 1_000, 100, vec![armed.clone(), armed.clone()]),
        (
            1,
            1_000,
            100,
            vec![WatchdogProtectedEngine::parse(
                &ARMED_DESCRIPTOR.replace("phase=armed", "phase=starting"),
            )
            .unwrap()],
        ),
    ] {
        assert!(WatchdogProtectionCycle::from_authenticated_report(
            sequence, unix, monotonic, targets,
        )
        .is_err());
    }
}

// Proves ordinary samples resume at the durable sequence and advance exactly once.
#[test]
fn ordinary_tick_records_one_sample_without_safety_mutation() {
    let harness = Harness::new(vec![vec![observation(
        WatchdogSafetyInput {
            available_bytes: 32 << 30,
            ..WatchdogSafetyInput::default()
        },
        WatchdogProcessState::Running,
        false,
    )]]);
    harness.storage.next_sequence.store(41, Ordering::SeqCst);
    let manager = harness.manager();

    let tick = manager.tick().unwrap();

    assert_eq!(tick.sample().sequence(), 41);
    assert_eq!(tick.active_targets(), 1);
    assert!(tick.events().is_empty());
    assert_eq!(tick.protection_cycle().sample_sequence(), 41);
    assert_eq!(tick.protection_cycle().targets().len(), 1);
    assert_eq!(
        tick.protection_cycle().targets()[0].target(),
        &WatchdogProtectedEngine::parse(ARMED_DESCRIPTOR).unwrap()
    );
    assert_eq!(
        harness.events.lock().unwrap().as_slice(),
        ["observe", "sample:41"]
    );
}

// Proves only armed, running, untripped targets survive a complete successful cycle.
#[test]
fn protection_cycle_excludes_static_ack_trip_and_exited_targets() {
    let safe = observation_with_generation(
        'a',
        WatchdogSafetyInput {
            available_bytes: 32 << 30,
            ..WatchdogSafetyInput::default()
        },
        WatchdogProcessState::Running,
        false,
    );
    let already_tripped = observation_with_generation(
        'b',
        WatchdogSafetyInput::default(),
        WatchdogProcessState::Running,
        true,
    );
    let exited = observation_with_generation(
        'c',
        WatchdogSafetyInput::default(),
        WatchdogProcessState::Exited,
        false,
    );
    let harness = Harness::new(vec![vec![safe, already_tripped, exited]]);
    let tick = harness.manager().tick().expect("complete cycle");

    assert_eq!(tick.active_targets(), 3);
    assert_eq!(tick.protection_cycle().targets().len(), 1);
    assert_eq!(
        tick.protection_cycle().observed_at_unix_milliseconds(),
        tick.sample().unix_milliseconds()
    );
    assert_eq!(
        tick.protection_cycle().observed_at_monotonic_milliseconds(),
        tick.sample().monotonic_milliseconds()
    );
    assert!(tick.events().iter().any(|event| {
        event.kind() == "engine.exit" && event.action() == Some(WatchdogSafetyAction::Stop)
    }));
}

// Proves a failed protection boundary yields no cycle receipt that Node could lease.
#[test]
fn failed_tick_cannot_produce_a_protection_cycle() {
    let harness = Harness::new(vec![vec![observation(
        WatchdogSafetyInput::default(),
        WatchdogProcessState::Exited,
        false,
    )]]);
    harness.protection.latch_failures.store(1, Ordering::SeqCst);

    assert!(harness.manager().tick().is_err());
}

// Proves memory warnings are telemetry-only, deduplicated, and rearm after recovery.
#[test]
fn host_pressure_warns_without_containment_and_rearms() {
    let low = WatchdogSafetyInput {
        available_bytes: 8 << 30,
        swap_used_bytes: 2 << 30,
        psi_some_delta_microseconds: 900_000,
        psi_full_delta_microseconds: 200_000,
        cgroup_oom_delta: 1,
        cgroup_max_delta: 1,
        ..WatchdogSafetyInput::default()
    };
    let high = WatchdogSafetyInput {
        available_bytes: 32 << 30,
        ..WatchdogSafetyInput::default()
    };
    let harness = Harness::new(vec![
        vec![observation(low, WatchdogProcessState::Running, false)],
        vec![observation(low, WatchdogProcessState::Running, false)],
        vec![observation(high, WatchdogProcessState::Running, false)],
        vec![observation(low, WatchdogProcessState::Running, false)],
    ]);
    let manager = harness.manager();

    let first = manager.tick().unwrap();
    let second = manager.tick().unwrap();
    let recovered = manager.tick().unwrap();
    let rearmed = manager.tick().unwrap();

    assert_eq!(first.events().len(), 1);
    assert!(second.events().is_empty());
    assert!(recovered.events().is_empty());
    assert_eq!(rearmed.events().len(), 1);
    assert!(!harness
        .events
        .lock()
        .unwrap()
        .iter()
        .any(|event| event.starts_with("contain:")));
}

// Proves a kernel OOM kill flushes, latches, contains, records, and flushes in order.
#[test]
fn cgroup_oom_kill_trips_with_exact_crash_ordering() {
    let harness = Harness::new(vec![vec![observation(
        WatchdogSafetyInput {
            available_bytes: 8 << 30,
            cgroup_oom_kill_delta: 1,
            ..WatchdogSafetyInput::default()
        },
        WatchdogProcessState::Running,
        false,
    )]]);
    let manager = harness.manager();

    let tick = manager.tick().unwrap();

    assert_eq!(tick.events().len(), 1);
    assert_eq!(tick.events()[0].kind(), "protection.trip");
    assert_eq!(tick.events()[0].action(), Some(WatchdogSafetyAction::Kill));
    assert_eq!(tick.events()[0].containment_complete(), Some(true));
    assert_eq!(
        harness.events.lock().unwrap().as_slice(),
        [
            "observe",
            "sample:1",
            "flush",
            "latch:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:Kill:cgroup_oom_kill",
            "contain:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:Kill:5000",
            "event:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:protection.trip:1",
            "flush",
        ]
    );
}

// Proves the durable protection latch remains authoritative when diagnostic event publication fails.
#[test]
fn durable_trip_latch_prevents_recontainment_after_event_publication_failure() {
    let trip = WatchdogSafetyInput {
        cgroup_oom_kill_delta: 1,
        ..WatchdogSafetyInput::default()
    };
    let harness = Harness::new(vec![
        vec![observation(trip, WatchdogProcessState::Running, false)],
        vec![observation(trip, WatchdogProcessState::Running, true)],
    ]);
    harness.storage.event_failures.store(1, Ordering::SeqCst);
    let manager = harness.manager();

    assert!(manager.tick().is_err());
    let recovered = manager.tick().unwrap();

    assert_eq!(recovered.sample().sequence(), 1);
    assert!(recovered.events().is_empty());
    assert_eq!(
        harness.events.lock().unwrap().as_slice(),
        [
            "observe",
            "sample:1",
            "flush",
            "latch:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:Kill:cgroup_oom_kill",
            "contain:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:Kill:5000",
            "event:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:protection.trip:1",
            "observe",
            "sample:1",
        ]
    );
}

// Proves exact process exit uses a stop trip while disarmed work is only acknowledged.
#[test]
fn process_exit_and_disarm_have_distinct_lifecycles() {
    let harness = Harness::new(vec![
        vec![observation(
            WatchdogSafetyInput::default(),
            WatchdogProcessState::Exited,
            false,
        )],
        vec![disarmed()],
    ]);
    let manager = harness.manager();

    let exited = manager.tick().unwrap();
    let disarmed = manager.tick().unwrap();

    assert_eq!(exited.events()[0].kind(), "engine.exit");
    assert_eq!(
        exited.events()[0].action(),
        Some(WatchdogSafetyAction::Stop)
    );
    assert!(disarmed.events().is_empty());
    let events = harness.events.lock().unwrap();
    assert!(events
        .iter()
        .any(|event| event == "ack:cccccccccccccccccccccccccccccccc"));
    assert_eq!(
        events
            .iter()
            .filter(|event| event.starts_with("contain:"))
            .count(),
        1
    );
}

// Proves flush failure prevents both trip mutation and sequence advancement until retry.
#[test]
fn pre_containment_flush_failure_retries_the_same_sequence_safely() {
    let trip = observation(
        WatchdogSafetyInput {
            cgroup_oom_group_kill_delta: 1,
            ..WatchdogSafetyInput::default()
        },
        WatchdogProcessState::Running,
        false,
    );
    let harness = Harness::new(vec![vec![trip.clone()], vec![trip]]);
    harness.storage.flush_failures.store(1, Ordering::SeqCst);
    let manager = harness.manager();

    assert!(manager.tick().is_err());
    let replay = manager.tick().unwrap();

    assert_eq!(replay.sample().sequence(), 1);
    assert_eq!(harness.samples.calls.lock().unwrap().as_slice(), [1, 1]);
    let events = harness.events.lock().unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|event| event.starts_with("latch:"))
            .count(),
        1
    );
}

// Proves containment provider failure remains a durable critical trip result.
#[test]
fn containment_failure_is_recorded_without_losing_the_trip() {
    let harness = Harness::new(vec![vec![observation(
        WatchdogSafetyInput {
            cgroup_oom_kill_delta: 1,
            ..WatchdogSafetyInput::default()
        },
        WatchdogProcessState::Running,
        false,
    )]]);
    harness
        .protection
        .contain_failure
        .store(true, Ordering::SeqCst);
    let manager = harness.manager();

    let tick = manager.tick().unwrap();

    assert_eq!(tick.events()[0].containment_complete(), Some(false));
    assert_eq!(tick.events()[0].severity(), 3);
    assert_eq!(tick.sample().sequence(), 1);
}

// Proves target identity is unique and hard bounded before any containment mutation.
#[test]
fn target_set_rejects_duplicate_or_unbounded_observations() {
    let duplicate = observation(
        WatchdogSafetyInput::default(),
        WatchdogProcessState::Running,
        false,
    );
    let harness = Harness::new(vec![vec![duplicate.clone(), duplicate]]);
    assert!(harness.manager().tick().is_err());
    assert!(harness
        .events
        .lock()
        .unwrap()
        .iter()
        .all(|event| !event.starts_with("sample:")));

    let mut targets = Vec::new();
    for index in 0..=maximum_watchdog_targets() {
        let generation = format!("{index:032x}");
        let descriptor = ARMED_DESCRIPTOR.replace(
            "generation=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &format!("generation={generation}"),
        );
        targets.push(WatchdogProtectionObservation::new(
            WatchdogProtectedEngine::parse(&descriptor).unwrap(),
            WatchdogProcessState::Running,
            WatchdogSafetyInput::default(),
            false,
        ));
    }
    let harness = Harness::new(vec![targets]);
    assert!(harness.manager().tick().is_err());
}
