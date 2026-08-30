// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::thread::JoinHandleExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::{
    WatchdogConfiguration, WatchdogConfigurationLoader, WatchdogControllerAllowlist,
    WatchdogControllerRegistryStore, WatchdogError, WatchdogProtocolService,
};

const WATCHDOG_CONTROLLER_ALLOWLIST_MAX_BYTES: usize = 12_288;

// Identifies why the resident wait boundary returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchdogResidentWakeReason {
    Deadline,
    Signal,
}

// Stores one coalesced set of native resident signals.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WatchdogResidentSignals {
    terminate: bool,
    interrupt: bool,
    reload: bool,
}

impl WatchdogResidentSignals {
    // Creates one empty signal set.
    pub const fn none() -> Self {
        Self {
            terminate: false,
            interrupt: false,
            reload: false,
        }
    }

    // Maps exactly SIGTERM, SIGINT, and SIGHUP into the closed resident vocabulary.
    pub fn from_native_signal(signal: i32) -> Result<Self, WatchdogError> {
        match signal {
            libc::SIGTERM => Ok(Self {
                terminate: true,
                ..Self::none()
            }),
            libc::SIGINT => Ok(Self {
                interrupt: true,
                ..Self::none()
            }),
            libc::SIGHUP => Ok(Self {
                reload: true,
                ..Self::none()
            }),
            _ => Err(resident_error("native signal is unsupported")),
        }
    }

    // Returns whether either native termination signal requested clean shutdown.
    pub const fn should_stop(self) -> bool {
        self.terminate || self.interrupt
    }

    // Returns whether SIGHUP requested an exact safe reload.
    pub const fn should_reload(self) -> bool {
        self.reload
    }

    // Combines independently observed signal flags without losing termination.
    pub const fn merged(self, other: Self) -> Self {
        Self {
            terminate: self.terminate || other.terminate,
            interrupt: self.interrupt || other.interrupt,
            reload: self.reload || other.reload,
        }
    }
}

// Supplies one monotonic resident timeline.
pub trait WatchdogResidentClock: Send + Sync {
    // Returns monotonic milliseconds since an arbitrary fixed origin.
    fn monotonic_milliseconds(&self) -> Result<u64, WatchdogError>;
}

// Suspends resident work until a deadline or native signal wakeup.
pub trait WatchdogResidentWake: Send + Sync {
    // Waits no later than the absolute monotonic deadline.
    fn wait_until(
        &self,
        deadline_milliseconds: u64,
    ) -> Result<WatchdogResidentWakeReason, WatchdogError>;
}

// Supplies and atomically clears pending native resident signals.
pub trait WatchdogResidentSignalSource: Send + Sync {
    // Returns every signal observed since the preceding call.
    fn take_pending(&self) -> Result<WatchdogResidentSignals, WatchdogError>;
}

// Loads one complete immutable resident configuration for initial start or reload.
pub trait WatchdogResidentConfigurationSource: Send + Sync {
    // Returns one owner-validated exact configuration.
    fn load(&self) -> Result<WatchdogConfiguration, WatchdogError>;
}

impl WatchdogResidentConfigurationSource for WatchdogConfigurationLoader {
    // Delegates to the strict owner-only configuration loader.
    fn load(&self) -> Result<WatchdogConfiguration, WatchdogError> {
        WatchdogConfigurationLoader::load(self)
    }
}

// Exposes only the service actions owned by the resident cadence boundary.
pub trait WatchdogResidentService: Send + Sync {
    // Commits and publishes one complete Watchdog sample.
    fn tick(&self) -> Result<(), WatchdogError>;

    // Flushes all durable Watchdog state at its explicit lifecycle boundary.
    fn flush(&self) -> Result<(), WatchdogError>;

    // Re-reads and atomically applies controller trust for an unchanged configuration.
    fn reload_controller_registry(
        &self,
        configuration: &WatchdogConfiguration,
    ) -> Result<(), WatchdogError>;
}

// Reports the only successful terminal state of the resident cadence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchdogResidentOutcome {
    Stopped,
}

// Owns sampling cadence, flush cadence, signal ordering, and safe reload orchestration.
pub struct WatchdogResident {
    configuration: WatchdogConfiguration,
    configuration_source: Box<dyn WatchdogResidentConfigurationSource>,
    service: Box<dyn WatchdogResidentService>,
    clock: Box<dyn WatchdogResidentClock>,
    wake: Box<dyn WatchdogResidentWake>,
    signals: Box<dyn WatchdogResidentSignalSource>,
}

impl WatchdogResident {
    // Creates one resident boundary only after the initial exact configuration is loaded.
    pub fn new(
        configuration_source: Box<dyn WatchdogResidentConfigurationSource>,
        service: Box<dyn WatchdogResidentService>,
        clock: Box<dyn WatchdogResidentClock>,
        wake: Box<dyn WatchdogResidentWake>,
        signals: Box<dyn WatchdogResidentSignalSource>,
    ) -> Result<Self, WatchdogError> {
        let configuration = configuration_source.load()?;
        Ok(Self {
            configuration,
            configuration_source,
            service,
            clock,
            wake,
            signals,
        })
    }

    // Runs exact monotonic sampling and flush cadences until a clean native stop signal.
    pub fn run(&self) -> Result<WatchdogResidentOutcome, WatchdogError> {
        let started_at = self.clock.monotonic_milliseconds()?;
        let sample_interval = u64::from(self.configuration.sample_interval_milliseconds());
        let flush_interval = u64::from(self.configuration.flush_interval_milliseconds());
        let mut next_sample = started_at;
        let mut next_flush = started_at
            .checked_add(flush_interval)
            .ok_or_else(|| resident_error("resident flush deadline overflowed"))?;

        loop {
            let pending = self.signals.take_pending()?;
            if pending.should_stop() {
                self.service.flush()?;
                return Ok(WatchdogResidentOutcome::Stopped);
            }
            if pending.should_reload() {
                if let Err(error) = self.reload() {
                    return self.fail_after_flush(error);
                }
            }

            let now = self.clock.monotonic_milliseconds()?;
            if now >= next_sample {
                if let Err(error) = self.service.tick() {
                    return self.fail_after_flush(error);
                }
                next_sample = advanced_deadline(next_sample, sample_interval, now)?;
            }
            if now >= next_flush {
                if let Err(error) = self.service.flush() {
                    return Err(error);
                }
                next_flush = now
                    .checked_add(flush_interval)
                    .ok_or_else(|| resident_error("resident flush deadline overflowed"))?;
            }

            let deadline = next_sample.min(next_flush);
            let wake_reason = self.wake.wait_until(deadline)?;
            if wake_reason == WatchdogResidentWakeReason::Deadline
                && self.clock.monotonic_milliseconds()? < deadline
            {
                return self.fail_after_flush(resident_error(
                    "resident wake returned before its deadline",
                ));
            }
        }
    }

    // Reloads trust only when every immutable configuration byte has the same meaning.
    fn reload(&self) -> Result<(), WatchdogError> {
        let replacement = self.configuration_source.load()?;
        if replacement != self.configuration {
            return Err(resident_error(
                "immutable configuration changed during reload",
            ));
        }
        self.service.reload_controller_registry(&replacement)
    }

    // Flushes durable state before returning one terminal resident failure.
    fn fail_after_flush<T>(&self, error: WatchdogError) -> Result<T, WatchdogError> {
        self.service.flush()?;
        Err(error)
    }
}

// Stores coalesced native signal state without coupling handlers to resident work.
pub struct SystemWatchdogResidentSignalState {
    terminate: AtomicBool,
    interrupt: AtomicBool,
    reload: AtomicBool,
}

impl SystemWatchdogResidentSignalState {
    // Creates one empty signal state for the future process signal adapter.
    pub const fn new() -> Self {
        Self {
            terminate: AtomicBool::new(false),
            interrupt: AtomicBool::new(false),
            reload: AtomicBool::new(false),
        }
    }

    // Records one supported native signal without performing resident work in its handler.
    pub fn record_native_signal(&self, signal: i32) -> Result<(), WatchdogError> {
        let observed = WatchdogResidentSignals::from_native_signal(signal)?;
        if observed.terminate {
            self.terminate.store(true, Ordering::Release);
        }
        if observed.interrupt {
            self.interrupt.store(true, Ordering::Release);
        }
        if observed.reload {
            self.reload.store(true, Ordering::Release);
        }
        Ok(())
    }
}

impl Default for SystemWatchdogResidentSignalState {
    // Creates one empty native signal state.
    fn default() -> Self {
        Self::new()
    }
}

impl WatchdogResidentSignalSource for SystemWatchdogResidentSignalState {
    // Atomically returns and clears every coalesced native signal flag.
    fn take_pending(&self) -> Result<WatchdogResidentSignals, WatchdogError> {
        Ok(WatchdogResidentSignals {
            terminate: self.terminate.swap(false, Ordering::AcqRel),
            interrupt: self.interrupt.swap(false, Ordering::AcqRel),
            reload: self.reload.swap(false, Ordering::AcqRel),
        })
    }
}

// Translates blocked native process signals into safe resident wakeups on one worker.
#[derive(Clone)]
pub struct SystemWatchdogResidentSignalAdapter {
    inner: Arc<SystemWatchdogResidentSignalAdapterInner>,
}

struct SystemWatchdogResidentSignalAdapterInner {
    shared: Arc<SystemWatchdogResidentSignalShared>,
    worker: Mutex<Option<JoinHandle<()>>>,
    previous_mask: libc::sigset_t,
}

struct SystemWatchdogResidentSignalShared {
    state: Mutex<SystemWatchdogResidentSignalAdapterState>,
    wake: Condvar,
}

struct SystemWatchdogResidentSignalAdapterState {
    pending: WatchdogResidentSignals,
    sequence: u64,
    stopping: bool,
}

impl SystemWatchdogResidentSignalAdapter {
    // Blocks the three native signals and starts one bounded sigwait worker.
    pub fn install() -> Result<Self, WatchdogError> {
        let signal_set = resident_signal_set()?;
        let mut previous_mask = unsafe { std::mem::zeroed() };
        // SAFETY: both signal sets are initialized and pthread_sigmask writes previous_mask.
        if unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &signal_set, &mut previous_mask) } != 0 {
            return Err(signal_error("native signal mask could not be installed"));
        }
        let shared = Arc::new(SystemWatchdogResidentSignalShared {
            state: Mutex::new(SystemWatchdogResidentSignalAdapterState {
                pending: WatchdogResidentSignals::none(),
                sequence: 1,
                stopping: false,
            }),
            wake: Condvar::new(),
        });
        let worker_shared = shared.clone();
        let worker = std::thread::Builder::new()
            .name("li_watchdog_signal".to_string())
            .spawn(move || run_signal_worker(signal_set, worker_shared));
        let worker = match worker {
            Ok(worker) => worker,
            Err(_) => {
                // SAFETY: previous_mask was returned for this current thread above.
                unsafe {
                    libc::pthread_sigmask(libc::SIG_SETMASK, &previous_mask, std::ptr::null_mut())
                };
                return Err(signal_error("native signal worker could not be started"));
            }
        };
        Ok(Self {
            inner: Arc::new(SystemWatchdogResidentSignalAdapterInner {
                shared,
                worker: Mutex::new(Some(worker)),
                previous_mask,
            }),
        })
    }

    // Records one supported signal through the same coalescing and wake path as sigwait.
    pub fn record_native_signal(&self, signal: i32) -> Result<(), WatchdogError> {
        self.inner.shared.record(signal)
    }

    // Requests one clean process-local stop through the same coalesced resident wake path.
    pub fn request_stop(&self) -> Result<(), WatchdogError> {
        self.inner.shared.record(libc::SIGTERM)
    }
}

impl WatchdogResidentSignalSource for SystemWatchdogResidentSignalAdapter {
    // Atomically drains all coalesced native signals.
    fn take_pending(&self) -> Result<WatchdogResidentSignals, WatchdogError> {
        let mut state = self
            .inner
            .shared
            .state
            .lock()
            .map_err(|_| WatchdogError::StateUnavailable)?;
        let pending = state.pending;
        state.pending = WatchdogResidentSignals::none();
        Ok(pending)
    }
}

impl WatchdogResidentClock for SystemWatchdogResidentSignalAdapter {
    // Returns the same positive monotonic clock used by absolute resident waits.
    fn monotonic_milliseconds(&self) -> Result<u64, WatchdogError> {
        system_monotonic_milliseconds()
    }
}

impl WatchdogResidentWake for SystemWatchdogResidentSignalAdapter {
    // Waits until the absolute monotonic deadline or a coalesced native signal arrives.
    fn wait_until(
        &self,
        deadline_milliseconds: u64,
    ) -> Result<WatchdogResidentWakeReason, WatchdogError> {
        let mut state = self
            .inner
            .shared
            .state
            .lock()
            .map_err(|_| WatchdogError::StateUnavailable)?;
        let initial_sequence = state.sequence;
        loop {
            if state.sequence != initial_sequence
                || state.pending != WatchdogResidentSignals::none()
            {
                return Ok(WatchdogResidentWakeReason::Signal);
            }
            let now = system_monotonic_milliseconds()?;
            if now >= deadline_milliseconds {
                return Ok(WatchdogResidentWakeReason::Deadline);
            }
            let duration = Duration::from_millis(deadline_milliseconds - now);
            let (next, _) = self
                .inner
                .shared
                .wake
                .wait_timeout(state, duration)
                .map_err(|_| WatchdogError::StateUnavailable)?;
            state = next;
        }
    }
}

impl SystemWatchdogResidentSignalShared {
    // Coalesces one supported signal and wakes every interrupted resident wait.
    fn record(&self, signal: i32) -> Result<(), WatchdogError> {
        let observed = WatchdogResidentSignals::from_native_signal(signal)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| WatchdogError::StateUnavailable)?;
        state.pending = state.pending.merged(observed);
        state.sequence = state
            .sequence
            .checked_add(1)
            .ok_or_else(|| signal_error("native signal sequence overflowed"))?;
        self.wake.notify_all();
        Ok(())
    }
}

impl Drop for SystemWatchdogResidentSignalAdapterInner {
    // Wakes, stops, and joins the exact sigwait worker before restoring the caller mask.
    fn drop(&mut self) {
        if let Ok(mut state) = self.shared.state.lock() {
            state.stopping = true;
            self.shared.wake.notify_all();
        }
        if let Ok(mut worker) = self.worker.lock() {
            if let Some(worker) = worker.take() {
                // SAFETY: as_pthread_t identifies this live join handle and SIGHUP is blocked.
                unsafe { libc::pthread_kill(worker.as_pthread_t(), libc::SIGHUP) };
                let _ = worker.join();
            }
        }
        // SAFETY: previous_mask was captured by install for the owning resident thread.
        unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, &self.previous_mask, std::ptr::null_mut())
        };
    }
}

// Loads one exact controller allowlist without owning registry mutation.
pub trait WatchdogControllerAllowlistSource: Send + Sync {
    // Reads and parses one owner-only allowlist from its configured path.
    fn load(
        &self,
        path: &Path,
        owner_user_id: u32,
    ) -> Result<WatchdogControllerAllowlist, WatchdogError>;
}

// Reads the C version-one allowlist through one stable no-follow descriptor.
pub struct SystemWatchdogControllerAllowlistSource;

impl WatchdogControllerAllowlistSource for SystemWatchdogControllerAllowlistSource {
    // Requires one owner-matching mode-0600 single-link regular allowlist file.
    fn load(
        &self,
        path: &Path,
        owner_user_id: u32,
    ) -> Result<WatchdogControllerAllowlist, WatchdogError> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| signal_error("controller allowlist could not be opened"))?;
        let initial = file
            .metadata()
            .map_err(|_| signal_error("controller allowlist metadata is unavailable"))?;
        if !initial.file_type().is_file()
            || initial.uid() != owner_user_id
            || initial.mode() & 0o777 != 0o600
            || initial.nlink() != 1
            || initial.len() == 0
            || initial.len() > WATCHDOG_CONTROLLER_ALLOWLIST_MAX_BYTES as u64
        {
            return Err(signal_error("controller allowlist identity is unsafe"));
        }
        let mut bytes = Vec::with_capacity(initial.len() as usize);
        file.by_ref()
            .take(WATCHDOG_CONTROLLER_ALLOWLIST_MAX_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| signal_error("controller allowlist could not be read"))?;
        let final_metadata = file
            .metadata()
            .map_err(|_| signal_error("controller allowlist metadata is unavailable"))?;
        if bytes.len() as u64 != initial.len() || !same_file(&initial, &final_metadata) {
            return Err(signal_error("controller allowlist changed during read"));
        }
        WatchdogControllerAllowlist::parse(&bytes)
    }
}

// Composes the existing protocol service with atomic controller trust reload.
pub struct WatchdogResidentProtocolService {
    service: Arc<WatchdogProtocolService>,
    reloader: Arc<WatchdogControllerRegistryReloader>,
}

// Owns exact allowlist loading and atomic last-good registry replacement.
pub struct WatchdogControllerRegistryReloader {
    registries: Arc<WatchdogControllerRegistryStore>,
    allowlists: Arc<dyn WatchdogControllerAllowlistSource>,
    owner_user_id: u32,
}

impl WatchdogControllerRegistryReloader {
    // Creates one reloader from an exact shared store and owner-bound source.
    pub fn new(
        registries: Arc<WatchdogControllerRegistryStore>,
        allowlists: Arc<dyn WatchdogControllerAllowlistSource>,
        owner_user_id: u32,
    ) -> Self {
        Self {
            registries,
            allowlists,
            owner_user_id,
        }
    }

    // Loads, verifies, persists, and atomically publishes one controller replacement.
    pub fn reload(&self, configuration: &WatchdogConfiguration) -> Result<(), WatchdogError> {
        let allowlist = self.allowlists.load(
            configuration.controller_allowlist_path(),
            self.owner_user_id,
        )?;
        if allowlist.installation_id() != configuration.installation_id() {
            return Err(signal_error(
                "controller allowlist installation identity differs",
            ));
        }
        self.registries.reload(allowlist).map(|_| ())
    }
}

impl WatchdogResidentProtocolService {
    // Creates one resident service from complete protocol and reload owners.
    pub fn new(
        service: Arc<WatchdogProtocolService>,
        reloader: Arc<WatchdogControllerRegistryReloader>,
    ) -> Self {
        Self { service, reloader }
    }
}

impl WatchdogResidentService for WatchdogResidentProtocolService {
    // Commits and publishes one complete existing protocol-service tick.
    fn tick(&self) -> Result<(), WatchdogError> {
        self.service.tick().map(|_| ())
    }

    // Flushes the exact existing manager storage boundary.
    fn flush(&self) -> Result<(), WatchdogError> {
        self.service.flush()
    }

    // Loads and atomically installs one same-installation controller allowlist.
    fn reload_controller_registry(
        &self,
        configuration: &WatchdogConfiguration,
    ) -> Result<(), WatchdogError> {
        self.reloader.reload(configuration)
    }
}

// Waits synchronously for supported blocked signals and records them outside a handler.
fn run_signal_worker(signal_set: libc::sigset_t, shared: Arc<SystemWatchdogResidentSignalShared>) {
    loop {
        let mut signal = 0;
        // SAFETY: signal_set is initialized and signal is writable for synchronous sigwait.
        let result = unsafe { libc::sigwait(&signal_set, &mut signal) };
        if result != 0 {
            return;
        }
        let stopping = shared
            .state
            .lock()
            .map(|state| state.stopping)
            .unwrap_or(true);
        if stopping {
            return;
        }
        if shared.record(signal).is_err() {
            return;
        }
    }
}

// Builds the exact native signal set consumed synchronously by the worker.
fn resident_signal_set() -> Result<libc::sigset_t, WatchdogError> {
    let mut signal_set = unsafe { std::mem::zeroed() };
    // SAFETY: signal_set is writable and every added signal is a valid constant.
    if unsafe { libc::sigemptyset(&mut signal_set) } != 0
        || unsafe { libc::sigaddset(&mut signal_set, libc::SIGTERM) } != 0
        || unsafe { libc::sigaddset(&mut signal_set, libc::SIGINT) } != 0
        || unsafe { libc::sigaddset(&mut signal_set, libc::SIGHUP) } != 0
    {
        return Err(signal_error("native signal set could not be created"));
    }
    Ok(signal_set)
}

// Reads one positive monotonic deadline clock for interruptible waits.
fn system_monotonic_milliseconds() -> Result<u64, WatchdogError> {
    let mut value = std::mem::MaybeUninit::<libc::timespec>::uninit();
    // SAFETY: clock_gettime initializes value on success for CLOCK_MONOTONIC.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, value.as_mut_ptr()) } != 0 {
        return Err(signal_error("native monotonic clock is unavailable"));
    }
    // SAFETY: successful clock_gettime initialized value.
    let value = unsafe { value.assume_init() };
    u64::try_from(value.tv_sec)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000))
        .and_then(|milliseconds| {
            u64::try_from(value.tv_nsec)
                .ok()
                .and_then(|nanoseconds| milliseconds.checked_add(nanoseconds / 1_000_000))
        })
        .filter(|milliseconds| *milliseconds > 0)
        .ok_or_else(|| signal_error("native monotonic clock is invalid"))
}

// Compares allowlist descriptor identity across its complete bounded read.
fn same_file(initial: &std::fs::Metadata, final_metadata: &std::fs::Metadata) -> bool {
    initial.dev() == final_metadata.dev()
        && initial.ino() == final_metadata.ino()
        && initial.uid() == final_metadata.uid()
        && initial.mode() == final_metadata.mode()
        && initial.nlink() == final_metadata.nlink()
        && initial.len() == final_metadata.len()
        && initial.mtime() == final_metadata.mtime()
        && initial.mtime_nsec() == final_metadata.mtime_nsec()
}

// Creates one redacted native resident signal or reload failure.
const fn signal_error(reason: &'static str) -> WatchdogError {
    WatchdogError::provider("resident signal", reason)
}

// Advances one cadence without an unbounded catch-up burst after scheduler delay.
fn advanced_deadline(previous: u64, interval: u64, now: u64) -> Result<u64, WatchdogError> {
    let next = previous
        .checked_add(interval)
        .ok_or_else(|| resident_error("resident sample deadline overflowed"))?;
    if next > now {
        return Ok(next);
    }
    now.checked_add(interval)
        .ok_or_else(|| resident_error("resident sample deadline overflowed"))
}

// Creates one stable redacted resident-boundary failure.
const fn resident_error(reason: &'static str) -> WatchdogError {
    WatchdogError::InvalidContract { reason }
}
