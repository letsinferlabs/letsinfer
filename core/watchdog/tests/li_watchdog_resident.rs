// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::VecDeque;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use li_watchdog_manager::{
    SystemWatchdogResidentSignalAdapter, SystemWatchdogResidentSignalState, WatchdogConfiguration,
    WatchdogControllerAllowlist, WatchdogControllerAllowlistSource, WatchdogControllerRegistry,
    WatchdogControllerRegistryReloader, WatchdogControllerRegistryStore, WatchdogError,
    WatchdogResident, WatchdogResidentClock, WatchdogResidentConfigurationSource,
    WatchdogResidentOutcome, WatchdogResidentService, WatchdogResidentSignalSource,
    WatchdogResidentSignals, WatchdogResidentWake, WatchdogResidentWakeReason,
};

// Serializes tests that temporarily own process-global native signal handling.
static NATIVE_SIGNAL_TEST_LOCK: Mutex<()> = Mutex::new(());

// Returns one complete exact resident configuration.
fn configuration(port: u16) -> WatchdogConfiguration {
    let source = serde_json::to_vec(&serde_json::json!({
        "schema": {"name": "li_watchdog_configuration", "version": 2},
        "installation_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "node_id": "11111111111111111111111111111111",
        "core_release": "0.1.0",
        "core_source_identity": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "listener": {"address": "127.0.0.1", "port": port},
        "node_protection": {"socket_path": "/run/user/1000/letsinfer/node_protection.sock", "read_timeout_milliseconds": 1000, "write_timeout_milliseconds": 1000},
        "paths": {
            "data_directory": "/var/lib/letsinfer/watchdog",
            "server_certificate_path": "/etc/letsinfer/watchdog/server.crt",
            "server_private_key_path": "/etc/letsinfer/watchdog/server.key",
            "controller_ca_path": "/etc/letsinfer/watchdog/controller-ca.crt",
            "controller_allowlist_path": "/etc/letsinfer/watchdog/controllers.allow",
            "controller_snapshot_path": "/var/lib/letsinfer/watchdog/controllers.snapshot",
            "site_state_path": "/var/lib/letsinfer/watchdog/letsinfer.state",
            "gateway_metrics_path": "/var/lib/letsinfer/gateway/telemetry.state",
            "protection_root_path": "/var/lib/letsinfer/watchdog/protected-placements",
            "node_database_path": "/var/lib/letsinfer/core.sqlite3",
            "runtime_installation_root": "/var/lib/letsinfer/runtime-installations",
            "runtime_cache_root": "/var/cache/letsinfer/runtimes"
        },
        "cadence": {"sample_interval_milliseconds": 1000, "flush_interval_milliseconds": 2000},
        "maximum_controllers": 16,
        "providers": {"gpu": "nvml", "gateway_counters": "gateway_telemetry_v2"},
        "thresholds": {
            "warning_available_bytes": 17179869184_u64,
            "graceful_available_bytes": 8589934592_u64,
            "emergency_available_bytes": 4294967296_u64,
            "swap_stop_bytes": 1073741824_u64,
            "psi_some_microseconds": 100000,
            "psi_full_microseconds": 50000,
            "state_failures": 3,
            "containment_grace_milliseconds": 5000
        }
    }))
    .unwrap();
    WatchdogConfiguration::parse(&source).unwrap()
}

// Supplies a deterministic sequence of initial and reload configurations.
struct MockConfigurationSource {
    configurations: Mutex<VecDeque<WatchdogConfiguration>>,
}

impl WatchdogResidentConfigurationSource for MockConfigurationSource {
    // Returns the next exact injected configuration.
    fn load(&self) -> Result<WatchdogConfiguration, WatchdogError> {
        self.configurations
            .lock()
            .unwrap()
            .pop_front()
            .ok_or(WatchdogError::StateUnavailable)
    }
}

// Records resident lifecycle actions and injects selected failures.
struct MockService {
    events: Arc<Mutex<Vec<&'static str>>>,
    tick_fails: bool,
    reload_fails: bool,
}

impl WatchdogResidentService for MockService {
    // Records or rejects one deterministic sample tick.
    fn tick(&self) -> Result<(), WatchdogError> {
        self.events.lock().unwrap().push("tick");
        if self.tick_fails {
            Err(WatchdogError::StateUnavailable)
        } else {
            Ok(())
        }
    }

    // Records one explicit durable flush boundary.
    fn flush(&self) -> Result<(), WatchdogError> {
        self.events.lock().unwrap().push("flush");
        Ok(())
    }

    // Records or rejects one exact controller-registry reload.
    fn reload_controller_registry(
        &self,
        _configuration: &WatchdogConfiguration,
    ) -> Result<(), WatchdogError> {
        self.events.lock().unwrap().push("reload");
        if self.reload_fails {
            Err(WatchdogError::StateUnavailable)
        } else {
            Ok(())
        }
    }
}

// Owns one injected monotonic time value shared by clock and wake mocks.
struct Timeline {
    now: Mutex<u64>,
}

// Reads one shared injected monotonic timeline.
struct MockClock(Arc<Timeline>);

impl WatchdogResidentClock for MockClock {
    // Returns the current injected monotonic value.
    fn monotonic_milliseconds(&self) -> Result<u64, WatchdogError> {
        Ok(*self.0.now.lock().unwrap())
    }
}

// Advances one shared timeline to each requested deadline.
struct MockWake {
    timeline: Arc<Timeline>,
    returns_early: bool,
}

impl WatchdogResidentWake for MockWake {
    // Advances to the deadline unless the test injects a broken early wake.
    fn wait_until(
        &self,
        deadline_milliseconds: u64,
    ) -> Result<WatchdogResidentWakeReason, WatchdogError> {
        if !self.returns_early {
            *self.timeline.now.lock().unwrap() = deadline_milliseconds;
        }
        Ok(WatchdogResidentWakeReason::Deadline)
    }
}

// Supplies one deterministic sequence of coalesced signal observations.
struct MockSignals {
    pending: Mutex<VecDeque<WatchdogResidentSignals>>,
}

impl WatchdogResidentSignalSource for MockSignals {
    // Returns the next signal set or an empty set.
    fn take_pending(&self) -> Result<WatchdogResidentSignals, WatchdogError> {
        Ok(self
            .pending
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(WatchdogResidentSignals::none))
    }
}

// Builds one deterministic resident manager and returns its shared action log.
fn resident(
    configurations: Vec<WatchdogConfiguration>,
    signals: Vec<WatchdogResidentSignals>,
    tick_fails: bool,
    reload_fails: bool,
    returns_early: bool,
) -> (WatchdogResident, Arc<Mutex<Vec<&'static str>>>) {
    let events = Arc::new(Mutex::new(Vec::new()));
    let timeline = Arc::new(Timeline { now: Mutex::new(0) });
    let manager = WatchdogResident::new(
        Box::new(MockConfigurationSource {
            configurations: Mutex::new(configurations.into()),
        }),
        Box::new(MockService {
            events: events.clone(),
            tick_fails,
            reload_fails,
        }),
        Box::new(MockClock(timeline.clone())),
        Box::new(MockWake {
            timeline,
            returns_early,
        }),
        Box::new(MockSignals {
            pending: Mutex::new(signals.into()),
        }),
    )
    .unwrap();
    (manager, events)
}

#[test]
// Samples immediately, skips catch-up bursts, flushes on cadence, and flushes at SIGTERM.
fn resident_runs_bounded_cadences_and_clean_shutdown() {
    let terminate = WatchdogResidentSignals::from_native_signal(libc::SIGTERM).unwrap();
    let (manager, events) = resident(
        vec![configuration(7443)],
        vec![
            WatchdogResidentSignals::none(),
            WatchdogResidentSignals::none(),
            WatchdogResidentSignals::none(),
            terminate,
        ],
        false,
        false,
        false,
    );
    assert_eq!(manager.run().unwrap(), WatchdogResidentOutcome::Stopped);
    assert_eq!(
        *events.lock().unwrap(),
        vec!["tick", "tick", "tick", "flush", "flush"]
    );
}

#[test]
// Reloads controller trust once only after the complete immutable configuration matches.
fn resident_reloads_exact_configuration_before_sampling() {
    let reload = WatchdogResidentSignals::from_native_signal(libc::SIGHUP).unwrap();
    let stop = WatchdogResidentSignals::from_native_signal(libc::SIGINT).unwrap();
    let (manager, events) = resident(
        vec![configuration(7443), configuration(7443)],
        vec![reload, stop],
        false,
        false,
        false,
    );
    assert_eq!(manager.run().unwrap(), WatchdogResidentOutcome::Stopped);
    assert_eq!(*events.lock().unwrap(), vec!["reload", "tick", "flush"]);
}

#[test]
// Rejects mutable configuration drift and flushes without applying controller trust.
fn resident_fails_closed_on_reload_configuration_drift() {
    let reload = WatchdogResidentSignals::from_native_signal(libc::SIGHUP).unwrap();
    let (manager, events) = resident(
        vec![configuration(7443), configuration(7444)],
        vec![reload],
        false,
        false,
        false,
    );
    assert!(manager.run().is_err());
    assert_eq!(*events.lock().unwrap(), vec!["flush"]);
}

#[test]
// Flushes and exits on either sampling failure or exact registry reload failure.
fn resident_flushes_terminal_provider_failures() {
    let (tick_manager, tick_events) = resident(
        vec![configuration(7443)],
        vec![WatchdogResidentSignals::none()],
        true,
        false,
        false,
    );
    assert!(tick_manager.run().is_err());
    assert_eq!(*tick_events.lock().unwrap(), vec!["tick", "flush"]);

    let reload = WatchdogResidentSignals::from_native_signal(libc::SIGHUP).unwrap();
    let (reload_manager, reload_events) = resident(
        vec![configuration(7443), configuration(7443)],
        vec![reload],
        false,
        true,
        false,
    );
    assert!(reload_manager.run().is_err());
    assert_eq!(*reload_events.lock().unwrap(), vec!["reload", "flush"]);
}

#[test]
// Rejects a deadline wake that could otherwise create an unbounded busy loop.
fn resident_rejects_early_deadline_wake() {
    let (manager, events) = resident(
        vec![configuration(7443)],
        vec![WatchdogResidentSignals::none()],
        false,
        false,
        true,
    );
    assert!(manager.run().is_err());
    assert_eq!(*events.lock().unwrap(), vec!["tick", "flush"]);
}

#[test]
// Coalesces supported native signals, preserves stop priority, and clears them once.
fn resident_signal_state_maps_and_clears_native_signals() {
    let signals = SystemWatchdogResidentSignalState::new();
    signals.record_native_signal(libc::SIGHUP).unwrap();
    signals.record_native_signal(libc::SIGTERM).unwrap();
    let pending = signals.take_pending().unwrap();
    assert!(pending.should_reload());
    assert!(pending.should_stop());
    assert_eq!(
        signals.take_pending().unwrap(),
        WatchdogResidentSignals::none()
    );
    assert!(signals.record_native_signal(libc::SIGUSR1).is_err());
}

#[test]
// Gives shutdown precedence when termination and reload are coalesced in one wake.
fn resident_shutdown_precedes_coalesced_reload() {
    let reload = WatchdogResidentSignals::from_native_signal(libc::SIGHUP).unwrap();
    let stop = WatchdogResidentSignals::from_native_signal(libc::SIGTERM).unwrap();
    let (manager, events) = resident(
        vec![configuration(7443)],
        vec![reload.merged(stop)],
        false,
        false,
        false,
    );
    assert_eq!(manager.run().unwrap(), WatchdogResidentOutcome::Stopped);
    assert_eq!(*events.lock().unwrap(), vec!["flush"]);
}

#[test]
// Interrupts an absolute wait, coalesces signals, and drains them exactly once.
fn native_signal_adapter_wakes_and_coalesces_without_a_handler() {
    let _guard = NATIVE_SIGNAL_TEST_LOCK.lock().unwrap();
    let adapter = SystemWatchdogResidentSignalAdapter::install().unwrap();
    let notifier = adapter.clone();
    let thread = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(10));
        notifier.record_native_signal(libc::SIGHUP).unwrap();
        notifier.record_native_signal(libc::SIGINT).unwrap();
    });
    assert_eq!(
        adapter.wait_until(u64::MAX).unwrap(),
        WatchdogResidentWakeReason::Signal
    );
    thread.join().unwrap();
    let pending = adapter.take_pending().unwrap();
    assert!(pending.should_reload());
    assert!(pending.should_stop());
    assert_eq!(
        adapter.take_pending().unwrap(),
        WatchdogResidentSignals::none()
    );
}

#[test]
// Stops and joins each native sigwait worker before another adapter is installed.
fn native_signal_adapter_stops_and_joins_without_leaking_workers() {
    let _guard = NATIVE_SIGNAL_TEST_LOCK.lock().unwrap();
    for _ in 0..3 {
        let adapter = SystemWatchdogResidentSignalAdapter::install().unwrap();
        adapter.record_native_signal(libc::SIGHUP).unwrap();
        assert!(adapter.take_pending().unwrap().should_reload());
        drop(adapter);
    }
}

// Supplies exact allowlist replacements or injected read failures.
struct MockAllowlistSource {
    allowlists: Mutex<VecDeque<Result<WatchdogControllerAllowlist, WatchdogError>>>,
}

impl WatchdogControllerAllowlistSource for MockAllowlistSource {
    // Returns the next owner-bound allowlist and verifies the configured source identity.
    fn load(
        &self,
        path: &Path,
        owner_user_id: u32,
    ) -> Result<WatchdogControllerAllowlist, WatchdogError> {
        assert_eq!(path, Path::new("/etc/letsinfer/watchdog/controllers.allow"));
        assert_eq!(owner_user_id, 501);
        self.allowlists.lock().unwrap().pop_front().unwrap()
    }
}

// Creates one exact version-one allowlist under the configuration installation identity.
fn allowlist(
    installation: char,
    controller: char,
    certificate: char,
) -> WatchdogControllerAllowlist {
    let source = format!(
        "version=1\ninstallation_id={}\ncontroller={},{}\n",
        installation.to_string().repeat(64),
        controller.to_string().repeat(32),
        certificate.to_string().repeat(64),
    );
    WatchdogControllerAllowlist::parse(source.as_bytes()).unwrap()
}

#[test]
// Retains the last-good registry after invalid replacement and publishes a valid one atomically.
fn controller_registry_reloader_validates_identity_before_atomic_swap() {
    let initial = Arc::new(WatchdogControllerRegistry::new(allowlist('a', 'a', '1'), 1).unwrap());
    let store = Arc::new(WatchdogControllerRegistryStore::new(initial.clone()));
    let source = Arc::new(MockAllowlistSource {
        allowlists: Mutex::new(
            vec![Ok(allowlist('b', 'b', '2')), Ok(allowlist('a', 'b', '2'))].into(),
        ),
    });
    let reloader = WatchdogControllerRegistryReloader::new(store.clone(), source, 501);
    assert!(reloader.reload(&configuration(7443)).is_err());
    let (generation, retained) = store.current().unwrap();
    assert_eq!(generation, 1);
    assert!(Arc::ptr_eq(&retained, &initial));

    reloader.reload(&configuration(7443)).unwrap();
    let (generation, replacement) = store.current().unwrap();
    assert_eq!(generation, 2);
    assert!(!Arc::ptr_eq(&replacement, &initial));
}
