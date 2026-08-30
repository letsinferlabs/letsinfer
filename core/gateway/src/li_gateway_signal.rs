// SPDX-License-Identifier: AGPL-3.0-only

use std::os::unix::thread::JoinHandleExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;

use crate::{
    GatewayProcessRunControl, GatewayProcessRunControlError, GatewayTelemetryFailureHandler,
    GatewayTelemetryResidentError,
};

static GATEWAY_SIGNAL_CONTROL_INSTALLED: AtomicBool = AtomicBool::new(false);

// Identifies the highest-precedence reason a resident Gateway should stop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayProcessStopReason {
    Requested,
    NativeSignal,
}

// Stores coalesced stop state shared by the blocking caller and sigwait worker.
struct GatewayProcessSignalState {
    reason: Option<GatewayProcessStopReason>,
    sequence: u64,
    stopping_worker: bool,
    failed: bool,
}

// Owns safe signal coalescing and blocking wakeups outside native handlers.
struct GatewayProcessSignalShared {
    state: Mutex<GatewayProcessSignalState>,
    wake: Condvar,
}

impl GatewayProcessSignalShared {
    // Creates one empty resident signal state.
    fn new() -> Self {
        Self {
            state: Mutex::new(GatewayProcessSignalState {
                reason: None,
                sequence: 1,
                stopping_worker: false,
                failed: false,
            }),
            wake: Condvar::new(),
        }
    }

    // Records a programmatic stop unless a native signal already has precedence.
    fn request_stop(&self) -> Result<(), GatewayProcessRunControlError> {
        self.record(GatewayProcessStopReason::Requested)
    }

    // Coalesces one native stop and gives it precedence over a requested stop.
    fn record_native_stop(&self) -> Result<(), GatewayProcessRunControlError> {
        self.record(GatewayProcessStopReason::NativeSignal)
    }

    // Records one stop reason and wakes every current blocking caller.
    fn record(
        &self,
        reason: GatewayProcessStopReason,
    ) -> Result<(), GatewayProcessRunControlError> {
        let mut state = self.state.lock().map_err(|_| run_control_error())?;
        state.reason = match (state.reason, reason) {
            (Some(GatewayProcessStopReason::NativeSignal), _) => {
                Some(GatewayProcessStopReason::NativeSignal)
            }
            (_, GatewayProcessStopReason::NativeSignal) => {
                Some(GatewayProcessStopReason::NativeSignal)
            }
            (existing, GatewayProcessStopReason::Requested) => {
                existing.or(Some(GatewayProcessStopReason::Requested))
            }
        };
        state.sequence = match state.sequence.checked_add(1) {
            Some(sequence) => sequence,
            None => {
                state.failed = true;
                self.wake.notify_all();
                return Err(run_control_error());
            }
        };
        self.wake.notify_all();
        Ok(())
    }

    // Blocks until one stop reason exists or the native signal worker fails.
    fn wait_for_stop(&self) -> Result<(), GatewayProcessRunControlError> {
        let mut state = self.state.lock().map_err(|_| run_control_error())?;
        while state.reason.is_none() && !state.failed && !state.stopping_worker {
            state = self.wake.wait(state).map_err(|_| run_control_error())?;
        }
        if state.reason.is_some() && !state.failed {
            Ok(())
        } else {
            Err(run_control_error())
        }
    }

    // Returns the current coalesced reason without consuming its restart evidence.
    fn stop_reason(
        &self,
    ) -> Result<Option<GatewayProcessStopReason>, GatewayProcessRunControlError> {
        self.state
            .lock()
            .map(|state| state.reason)
            .map_err(|_| run_control_error())
    }

    // Marks the worker terminal and wakes callers before its private signal interruption.
    fn stop_worker(&self) -> Result<(), GatewayProcessRunControlError> {
        let mut state = self.state.lock().map_err(|_| run_control_error())?;
        state.stopping_worker = true;
        self.wake.notify_all();
        Ok(())
    }

    // Returns whether the private wake should end the exact signal worker.
    fn is_stopping_worker(&self) -> bool {
        self.state
            .lock()
            .map(|state| state.stopping_worker)
            .unwrap_or(true)
    }

    // Fails every wait after an unexpected native signal-worker exit.
    fn worker_did_fail(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.failed = true;
            self.wake.notify_all();
        }
    }
}

// Owns one native signal mask, one joinable sigwait worker, and deterministic cleanup.
pub struct SystemGatewayProcessRunControl {
    shared: Arc<GatewayProcessSignalShared>,
    worker: Mutex<Option<JoinHandle<()>>>,
    previous_mask: libc::sigset_t,
    installing_thread: libc::pthread_t,
    restored: AtomicBool,
}

impl SystemGatewayProcessRunControl {
    // Blocks resident stop signals and starts exactly one joinable sigwait worker.
    pub fn install() -> Result<Self, GatewayProcessRunControlError> {
        if GATEWAY_SIGNAL_CONTROL_INSTALLED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(run_control_error());
        }
        match Self::install_after_reservation() {
            Ok(control) => Ok(control),
            Err(error) => {
                GATEWAY_SIGNAL_CONTROL_INSTALLED.store(false, Ordering::Release);
                Err(error)
            }
        }
    }

    // Installs the native signal boundary after exclusive process ownership is reserved.
    fn install_after_reservation() -> Result<Self, GatewayProcessRunControlError> {
        let signal_set = gateway_signal_set()?;
        let mut previous_mask = unsafe { std::mem::zeroed() };
        // SAFETY: both signal sets are initialized and pthread_sigmask writes previous_mask.
        if unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &signal_set, &mut previous_mask) } != 0 {
            return Err(run_control_error());
        }
        let shared = Arc::new(GatewayProcessSignalShared::new());
        let worker_shared = shared.clone();
        let worker = std::thread::Builder::new()
            .name("li_gateway_signal".to_string())
            .spawn(move || run_signal_worker(signal_set, worker_shared));
        let worker = match worker {
            Ok(worker) => worker,
            Err(_) => {
                // SAFETY: previous_mask was captured for this same current thread above.
                unsafe {
                    libc::pthread_sigmask(libc::SIG_SETMASK, &previous_mask, std::ptr::null_mut())
                };
                return Err(run_control_error());
            }
        };
        Ok(Self {
            shared,
            worker: Mutex::new(Some(worker)),
            previous_mask,
            // SAFETY: pthread_self returns the stable identity of the installing thread.
            installing_thread: unsafe { libc::pthread_self() },
            restored: AtomicBool::new(false),
        })
    }

    // Wakes the resident process through one idempotent programmatic stop request.
    pub fn request_stop(&self) -> Result<(), GatewayProcessRunControlError> {
        self.shared.request_stop()
    }

    // Returns the coalesced reason while preserving native-signal precedence.
    pub fn stop_reason(
        &self,
    ) -> Result<Option<GatewayProcessStopReason>, GatewayProcessRunControlError> {
        self.shared.stop_reason()
    }

    // Stops and joins the exact signal worker and restores the installing thread's mask once.
    pub fn join(&self) -> Result<(), GatewayProcessRunControlError> {
        // SAFETY: pthread_self and pthread_equal only inspect live pthread identities.
        if unsafe { libc::pthread_equal(libc::pthread_self(), self.installing_thread) } == 0 {
            return Err(run_control_error());
        }
        self.shared.stop_worker()?;
        let worker = self.worker.lock().map_err(|_| run_control_error())?.take();
        if let Some(worker) = worker {
            // SAFETY: as_pthread_t identifies this live join handle and SIGHUP is blocked.
            if unsafe { libc::pthread_kill(worker.as_pthread_t(), libc::SIGHUP) } != 0 {
                return Err(run_control_error());
            }
            worker.join().map_err(|_| run_control_error())?;
        }
        if !self.restored.swap(true, Ordering::AcqRel) {
            // SAFETY: previous_mask belongs to this verified installing thread.
            if unsafe {
                libc::pthread_sigmask(libc::SIG_SETMASK, &self.previous_mask, std::ptr::null_mut())
            } != 0
            {
                return Err(run_control_error());
            }
            GATEWAY_SIGNAL_CONTROL_INSTALLED.store(false, Ordering::Release);
        }
        Ok(())
    }
}

impl GatewayProcessRunControl for SystemGatewayProcessRunControl {
    // Blocks until one native or programmatic stop has been safely coalesced.
    fn wait_for_stop(&self) -> Result<(), GatewayProcessRunControlError> {
        self.shared.wait_for_stop()
    }
}

impl GatewayTelemetryFailureHandler for SystemGatewayProcessRunControl {
    // Wakes the ordinary process stop path when telemetry can no longer advance.
    fn telemetry_did_fail(&self) -> Result<(), GatewayTelemetryResidentError> {
        self.request_stop()
            .map_err(|_| GatewayTelemetryResidentError::FailureNotificationFailed)
    }
}

impl Drop for SystemGatewayProcessRunControl {
    // Prevents the native sigwait worker from surviving its process-control owner.
    fn drop(&mut self) {
        let _ = self.join();
    }
}

// Waits synchronously for supported blocked signals and records them outside a handler.
fn run_signal_worker(signal_set: libc::sigset_t, shared: Arc<GatewayProcessSignalShared>) {
    loop {
        let mut signal = 0;
        // SAFETY: signal_set is initialized and signal is writable for synchronous sigwait.
        let result = unsafe { libc::sigwait(&signal_set, &mut signal) };
        if result != 0 {
            shared.worker_did_fail();
            return;
        }
        if shared.is_stopping_worker() {
            return;
        }
        if shared.record_native_stop().is_err() {
            shared.worker_did_fail();
            return;
        }
    }
}

// Builds the exact native signal set consumed synchronously by the Gateway worker.
fn gateway_signal_set() -> Result<libc::sigset_t, GatewayProcessRunControlError> {
    let mut signal_set = unsafe { std::mem::zeroed() };
    // SAFETY: signal_set is writable and every added signal is a valid constant.
    if unsafe { libc::sigemptyset(&mut signal_set) } != 0
        || unsafe { libc::sigaddset(&mut signal_set, libc::SIGTERM) } != 0
        || unsafe { libc::sigaddset(&mut signal_set, libc::SIGINT) } != 0
        || unsafe { libc::sigaddset(&mut signal_set, libc::SIGHUP) } != 0
    {
        return Err(run_control_error());
    }
    Ok(signal_set)
}

// Creates the only redacted native run-control failure.
const fn run_control_error() -> GatewayProcessRunControlError {
    GatewayProcessRunControlError::unavailable()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // Coalesces repeated requested stops without changing their reason.
    fn requested_stops_are_idempotent() {
        let shared = GatewayProcessSignalShared::new();
        shared.request_stop().unwrap();
        shared.request_stop().unwrap();
        assert_eq!(
            shared.stop_reason().unwrap(),
            Some(GatewayProcessStopReason::Requested)
        );
        assert!(shared.wait_for_stop().is_ok());
    }

    #[test]
    // Gives any native signal precedence over an already requested programmatic stop.
    fn native_signal_has_stop_precedence() {
        let shared = GatewayProcessSignalShared::new();
        shared.request_stop().unwrap();
        shared.record_native_stop().unwrap();
        shared.request_stop().unwrap();
        assert_eq!(
            shared.stop_reason().unwrap(),
            Some(GatewayProcessStopReason::NativeSignal)
        );
    }

    #[test]
    // Wakes, stops, and joins one real native worker without leaking installation ownership.
    fn native_control_stops_joins_and_restarts() {
        let control = SystemGatewayProcessRunControl::install().unwrap();
        control.telemetry_did_fail().unwrap();
        assert!(control.wait_for_stop().is_ok());
        assert_eq!(
            control.shared.stop_reason().unwrap(),
            Some(GatewayProcessStopReason::Requested)
        );
        assert!(control.join().is_ok());
        assert!(control.join().is_ok());

        let restarted = SystemGatewayProcessRunControl::install().unwrap();
        restarted.request_stop().unwrap();
        assert!(restarted.wait_for_stop().is_ok());
        assert!(restarted.join().is_ok());
    }
}
