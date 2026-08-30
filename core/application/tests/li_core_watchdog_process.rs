// SPDX-License-Identifier: AGPL-3.0-only

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex};

#[cfg(not(target_os = "linux"))]
use li_core_application::run_core_watchdog_process;
use li_core_application::{
    CoreWatchdogNetworkServer, CoreWatchdogProcess, CoreWatchdogProcessArguments,
    CoreWatchdogProcessError, CoreWatchdogResidentRunner, CoreWatchdogRunControl,
};
use li_watchdog_manager::WatchdogResidentOutcome;

// Stores listener state shared across one deterministic server lifecycle.
struct MockServerState {
    shutdown_requested: bool,
    events: Vec<&'static str>,
}

// Implements a blocking listener with independently injectable serve and shutdown failures.
struct MockServer {
    state: Mutex<MockServerState>,
    wake: Condvar,
    serve_fails: bool,
    shutdown_fails: bool,
}

impl MockServer {
    // Creates one listener whose successful serve waits for explicit shutdown.
    fn new(serve_fails: bool, shutdown_fails: bool) -> Self {
        Self {
            state: Mutex::new(MockServerState {
                shutdown_requested: false,
                events: Vec::new(),
            }),
            wake: Condvar::new(),
            serve_fails,
            shutdown_fails,
        }
    }

    // Returns the exact lifecycle events recorded by this listener.
    fn events(&self) -> Vec<&'static str> {
        self.state.lock().expect("server state").events.clone()
    }
}

impl CoreWatchdogNetworkServer for MockServer {
    // Fails immediately or waits until shutdown closes the deterministic accept loop.
    fn serve(&self) -> Result<(), CoreWatchdogProcessError> {
        let mut state = self.state.lock().expect("server state");
        state.events.push("serve");
        if self.serve_fails {
            return Err(CoreWatchdogProcessError::ListenerUnavailable);
        }
        while !state.shutdown_requested {
            state = self.wake.wait(state).expect("server wake");
        }
        state.events.push("joined");
        Ok(())
    }

    // Records terminal shutdown, wakes serve, and returns the injected result.
    fn shutdown(&self) -> Result<(), CoreWatchdogProcessError> {
        let mut state = self.state.lock().expect("server state");
        state.events.push("shutdown");
        state.shutdown_requested = true;
        self.wake.notify_all();
        if self.shutdown_fails {
            Err(CoreWatchdogProcessError::ListenerUnavailable)
        } else {
            Ok(())
        }
    }
}

// Stores process-local stop state shared by resident and listener failure paths.
struct MockRunState {
    stop_requested: bool,
    events: Vec<&'static str>,
}

// Supplies deterministic resident stop and wake behavior.
struct MockRunControl {
    state: Mutex<MockRunState>,
    wake: Condvar,
    request_fails: bool,
}

impl MockRunControl {
    // Creates one initially running process-local control.
    fn new(request_fails: bool) -> Self {
        Self {
            state: Mutex::new(MockRunState {
                stop_requested: false,
                events: Vec::new(),
            }),
            wake: Condvar::new(),
            request_fails,
        }
    }

    // Returns the exact process-local lifecycle events.
    fn events(&self) -> Vec<&'static str> {
        self.state.lock().expect("run state").events.clone()
    }
}

impl CoreWatchdogRunControl for MockRunControl {
    // Records and wakes one process-local stop unless failure is injected.
    fn request_stop(&self) -> Result<(), CoreWatchdogProcessError> {
        let mut state = self.state.lock().expect("run state");
        state.events.push("request_stop");
        if self.request_fails {
            return Err(CoreWatchdogProcessError::ResidentUnavailable);
        }
        state.stop_requested = true;
        self.wake.notify_all();
        Ok(())
    }
}

// Supplies immediate or stop-driven resident completion.
struct MockResident {
    control: Arc<MockRunControl>,
    wait_for_stop: bool,
    fails: bool,
}

impl CoreWatchdogResidentRunner for MockResident {
    // Records entry, waits when requested, and returns the injected terminal result.
    fn run(&self) -> Result<WatchdogResidentOutcome, CoreWatchdogProcessError> {
        let mut state = self.control.state.lock().expect("run state");
        state.events.push("resident");
        while self.wait_for_stop && !state.stop_requested {
            state = self.control.wake.wait(state).expect("resident wake");
        }
        if self.fails {
            Err(CoreWatchdogProcessError::ResidentUnavailable)
        } else {
            Ok(WatchdogResidentOutcome::Stopped)
        }
    }
}

// Parses only the exact CoreProcessLayout invocation and rejects aliases or defaults.
#[test]
fn process_arguments_match_core_process_layout_exactly() {
    let parsed = CoreWatchdogProcessArguments::parse([
        OsString::from("--configuration"),
        OsString::from("/etc/letsinfer/li_watchdog.json"),
    ])
    .expect("arguments");
    assert_eq!(
        parsed.configuration_path(),
        PathBuf::from("/etc/letsinfer/li_watchdog.json")
    );
    for arguments in [
        vec![],
        vec![OsString::from("--configuration")],
        vec![OsString::from("--config"), OsString::from("/private/value")],
        vec![
            OsString::from("--configuration"),
            OsString::from("relative.json"),
        ],
        vec![
            OsString::from("--configuration"),
            OsString::from("/etc/li_watchdog.json"),
            OsString::from("extra"),
        ],
    ] {
        assert_eq!(
            CoreWatchdogProcessArguments::parse(arguments).expect_err("invalid arguments"),
            CoreWatchdogProcessError::InvalidArguments
        );
    }
}

// Keeps the native executable explicit on unsupported hosts instead of selecting a fallback.
#[cfg(not(target_os = "linux"))]
#[test]
fn process_entrypoint_rejects_unsupported_platform_without_fallback() {
    assert_eq!(
        run_core_watchdog_process([
            OsString::from("--configuration"),
            OsString::from("/etc/letsinfer/li_watchdog.json"),
        ])
        .expect_err("unsupported platform"),
        CoreWatchdogProcessError::UnsupportedPlatform
    );
}

// Stops and joins the listener after ordinary resident completion.
#[test]
fn process_completes_symmetric_resident_and_listener_shutdown() {
    let server = Arc::new(MockServer::new(false, false));
    let control = Arc::new(MockRunControl::new(false));
    let resident = Arc::new(MockResident {
        control: control.clone(),
        wait_for_stop: false,
        fails: false,
    });
    let process = CoreWatchdogProcess::new(server.clone(), resident, control);
    assert_eq!(
        process.run().expect("process"),
        WatchdogResidentOutcome::Stopped
    );
    let events = server.events();
    assert_eq!(events.iter().filter(|event| **event == "serve").count(), 1);
    assert_eq!(
        events.iter().filter(|event| **event == "shutdown").count(),
        1
    );
    assert_eq!(events.iter().filter(|event| **event == "joined").count(), 1);
}

// Wakes the resident and preserves a terminal listener failure after joining its worker.
#[test]
fn process_propagates_listener_failure_through_clean_resident_stop() {
    let server = Arc::new(MockServer::new(true, false));
    let control = Arc::new(MockRunControl::new(false));
    let resident = Arc::new(MockResident {
        control: control.clone(),
        wait_for_stop: true,
        fails: false,
    });
    let process = CoreWatchdogProcess::new(server.clone(), resident, control.clone());
    assert_eq!(
        process.run().expect_err("listener failure"),
        CoreWatchdogProcessError::ListenerUnavailable
    );
    assert_eq!(control.events(), vec!["resident", "request_stop"]);
    let events = server.events();
    assert_eq!(events.iter().filter(|event| **event == "serve").count(), 1);
    assert_eq!(
        events.iter().filter(|event| **event == "shutdown").count(),
        1
    );
}

// Shuts down and joins the listener after resident or shutdown failure without masking the first error.
#[test]
fn process_rolls_back_listener_for_resident_and_shutdown_failures() {
    for (resident_fails, shutdown_fails, expected) in [
        (true, false, CoreWatchdogProcessError::ResidentUnavailable),
        (false, true, CoreWatchdogProcessError::ListenerUnavailable),
    ] {
        let server = Arc::new(MockServer::new(false, shutdown_fails));
        let control = Arc::new(MockRunControl::new(false));
        let resident = Arc::new(MockResident {
            control: control.clone(),
            wait_for_stop: false,
            fails: resident_fails,
        });
        let process = CoreWatchdogProcess::new(server.clone(), resident, control);
        assert_eq!(process.run().expect_err("process failure"), expected);
        let events = server.events();
        assert_eq!(events.iter().filter(|event| **event == "serve").count(), 1);
        assert_eq!(
            events.iter().filter(|event| **event == "shutdown").count(),
            1
        );
        assert_eq!(events.iter().filter(|event| **event == "joined").count(), 1);
    }
}

// Keeps configuration values and native identities out of all stable failure diagnostics.
#[test]
fn process_errors_are_closed_and_secret_free() {
    let sensitive = "/private/token/controller-secret.pem";
    for error in [
        CoreWatchdogProcessError::InvalidArguments,
        CoreWatchdogProcessError::UnsupportedPlatform,
        CoreWatchdogProcessError::ConfigurationUnavailable,
        CoreWatchdogProcessError::CompositionUnavailable,
        CoreWatchdogProcessError::ListenerUnavailable,
        CoreWatchdogProcessError::ResidentUnavailable,
        CoreWatchdogProcessError::ThreadUnavailable,
    ] {
        let diagnostic = format!("{error:?}: {error}");
        assert!(!diagnostic.contains(sensitive));
        assert!(!diagnostic.contains("certificate"));
        assert!(!diagnostic.contains("controller-secret"));
    }
}
