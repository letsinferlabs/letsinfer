// SPDX-License-Identifier: AGPL-3.0-only

use std::os::unix::thread::JoinHandleExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::{
    NodeResidentError, NodeResidentRunControl, NodeResidentRunDecision, NodeResidentRunSignal,
};

static NODE_SIGNAL_CONTROL_INSTALLED: AtomicBool = AtomicBool::new(false);

// Owns one native signal mask, one joinable sigwait worker, and the Node stop signal.
pub struct SystemNodeResidentRunControl {
    signal: Arc<NodeResidentRunSignal>,
    worker: Mutex<Option<JoinHandle<()>>>,
    previous_mask: libc::sigset_t,
    installing_thread: libc::pthread_t,
    stopping_worker: Arc<AtomicBool>,
    worker_failed: Arc<AtomicBool>,
    restored: AtomicBool,
}

impl SystemNodeResidentRunControl {
    // Blocks resident stop signals before any Node-owned thread is created.
    pub fn install() -> Result<Self, NodeResidentError> {
        if NODE_SIGNAL_CONTROL_INSTALLED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(NodeResidentError::RunControlFailed);
        }
        match Self::install_after_reservation() {
            Ok(control) => Ok(control),
            Err(error) => {
                NODE_SIGNAL_CONTROL_INSTALLED.store(false, Ordering::Release);
                Err(error)
            }
        }
    }

    // Installs the signal worker after exclusive process ownership is reserved.
    fn install_after_reservation() -> Result<Self, NodeResidentError> {
        let signal_set = node_signal_set()?;
        let mut previous_mask = unsafe { std::mem::zeroed() };
        // SAFETY: both signal sets are initialized and pthread_sigmask writes previous_mask.
        if unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &signal_set, &mut previous_mask) } != 0 {
            return Err(NodeResidentError::RunControlFailed);
        }
        let signal = Arc::new(NodeResidentRunSignal::new());
        let stopping_worker = Arc::new(AtomicBool::new(false));
        let worker_failed = Arc::new(AtomicBool::new(false));
        let worker_signal = signal.clone();
        let worker_stopping = stopping_worker.clone();
        let worker_failure = worker_failed.clone();
        let worker = std::thread::Builder::new()
            .name("li_node_signal".to_string())
            .spawn(move || {
                run_signal_worker(signal_set, worker_signal, worker_stopping, worker_failure)
            });
        let worker = match worker {
            Ok(worker) => worker,
            Err(_) => {
                // SAFETY: previous_mask was captured for this same current thread.
                unsafe {
                    libc::pthread_sigmask(libc::SIG_SETMASK, &previous_mask, std::ptr::null_mut())
                };
                return Err(NodeResidentError::RunControlFailed);
            }
        };
        Ok(Self {
            signal,
            worker: Mutex::new(Some(worker)),
            previous_mask,
            // SAFETY: pthread_self returns the stable identity of the installing thread.
            installing_thread: unsafe { libc::pthread_self() },
            stopping_worker,
            worker_failed,
            restored: AtomicBool::new(false),
        })
    }

    // Stops and joins the exact signal worker before restoring the caller's native mask.
    pub fn join(&self) -> Result<(), NodeResidentError> {
        // SAFETY: pthread_self and pthread_equal only inspect live pthread identities.
        if unsafe { libc::pthread_equal(libc::pthread_self(), self.installing_thread) } == 0 {
            return Err(NodeResidentError::RunControlFailed);
        }
        self.stopping_worker.store(true, Ordering::Release);
        let worker = self
            .worker
            .lock()
            .map_err(|_| NodeResidentError::RunControlFailed)?
            .take();
        if let Some(worker) = worker {
            // SAFETY: as_pthread_t identifies this live worker and SIGHUP is blocked there.
            if unsafe { libc::pthread_kill(worker.as_pthread_t(), libc::SIGHUP) } != 0 {
                return Err(NodeResidentError::RunControlFailed);
            }
            worker
                .join()
                .map_err(|_| NodeResidentError::RunControlFailed)?;
        }
        if !self.restored.swap(true, Ordering::AcqRel) {
            // SAFETY: previous_mask belongs to this verified installing thread.
            if unsafe {
                libc::pthread_sigmask(libc::SIG_SETMASK, &self.previous_mask, std::ptr::null_mut())
            } != 0
            {
                return Err(NodeResidentError::RunControlFailed);
            }
            NODE_SIGNAL_CONTROL_INSTALLED.store(false, Ordering::Release);
        }
        if self.worker_failed.load(Ordering::Acquire) {
            Err(NodeResidentError::RunControlFailed)
        } else {
            Ok(())
        }
    }
}

impl NodeResidentRunControl for SystemNodeResidentRunControl {
    // Reports a native worker failure as terminal instead of leaving the daemon detached.
    fn is_stop_requested(&self) -> Result<bool, NodeResidentError> {
        if self.worker_failed.load(Ordering::Acquire) {
            return Err(NodeResidentError::RunControlFailed);
        }
        self.signal.is_stop_requested()
    }

    // Delegates bounded cadence waiting to the condition-backed resident signal.
    fn wait(&self, cadence: Duration) -> Result<NodeResidentRunDecision, NodeResidentError> {
        if self.worker_failed.load(Ordering::Acquire) {
            return Err(NodeResidentError::RunControlFailed);
        }
        self.signal.wait(cadence)
    }

    // Wakes the ordinary resident cleanup path without invoking a native handler.
    fn request_stop(&self) -> Result<(), NodeResidentError> {
        self.signal.request_stop()
    }
}

impl Drop for SystemNodeResidentRunControl {
    // Prevents the sigwait worker or blocked mask from surviving its process owner.
    fn drop(&mut self) {
        let _ = self.join();
    }
}

// Waits synchronously for one supported signal and wakes the ordinary Node stop path.
fn run_signal_worker(
    signal_set: libc::sigset_t,
    signal: Arc<NodeResidentRunSignal>,
    stopping_worker: Arc<AtomicBool>,
    worker_failed: Arc<AtomicBool>,
) {
    loop {
        let mut received = 0;
        // SAFETY: signal_set is initialized and received is writable for synchronous sigwait.
        let result = unsafe { libc::sigwait(&signal_set, &mut received) };
        if result != 0 {
            worker_failed.store(true, Ordering::Release);
            let _ = signal.signal_stop();
            return;
        }
        if stopping_worker.load(Ordering::Acquire) {
            return;
        }
        if signal.signal_stop().is_err() {
            worker_failed.store(true, Ordering::Release);
        }
        return;
    }
}

// Builds the exact native signal set consumed synchronously by the Node worker.
fn node_signal_set() -> Result<libc::sigset_t, NodeResidentError> {
    let mut signal_set = unsafe { std::mem::zeroed() };
    // SAFETY: signal_set is writable and every added signal is a valid constant.
    if unsafe { libc::sigemptyset(&mut signal_set) } != 0
        || unsafe { libc::sigaddset(&mut signal_set, libc::SIGTERM) } != 0
        || unsafe { libc::sigaddset(&mut signal_set, libc::SIGINT) } != 0
        || unsafe { libc::sigaddset(&mut signal_set, libc::SIGHUP) } != 0
    {
        return Err(NodeResidentError::RunControlFailed);
    }
    Ok(signal_set)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Proves programmatic stop, joined native cleanup, and subsequent installation reuse.
    #[test]
    fn process_run_control_stops_and_restores_exact_native_ownership() {
        let control = SystemNodeResidentRunControl::install().expect("control");
        assert!(!control.is_stop_requested().expect("state"));
        control.request_stop().expect("stop");
        assert!(control.is_stop_requested().expect("state"));
        control.join().expect("join");
        let restarted = SystemNodeResidentRunControl::install().expect("restart");
        restarted.join().expect("restart join");
    }
}
