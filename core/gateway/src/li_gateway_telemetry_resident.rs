// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::{
    GatewayError, GatewayHttpSurface, GatewayManager, GatewayProcess,
    GatewayTelemetryRuntimeCounterProvider, GatewayTelemetryRuntimeCounters,
};

const MINIMUM_TELEMETRY_CADENCE: Duration = Duration::from_millis(100);
const MAXIMUM_TELEMETRY_CADENCE: Duration = Duration::from_secs(5);

// Supplies usage-writer counters that are independent of listener ownership.
pub trait GatewayUsageRuntimeCounterProvider: Send + Sync {
    // Returns dropped and failed durable-usage writes in that order.
    fn usage_counters(&self) -> Result<(u64, u64), GatewayError>;
}

// Notifies the resident process when Watchdog telemetry can no longer advance.
pub trait GatewayTelemetryFailureHandler: Send + Sync {
    // Wakes the process run-control path after one periodic publication fails.
    fn telemetry_did_fail(&self) -> Result<(), GatewayTelemetryResidentError>;
}

// Joins retained listener counts with the Database-owned usage writer counters.
pub struct GatewayProcessRuntimeCounterProvider {
    process: Mutex<Option<Weak<GatewayProcess>>>,
    usage: Arc<dyn GatewayUsageRuntimeCounterProvider>,
}

impl GatewayProcessRuntimeCounterProvider {
    // Creates one unbound runtime counter adapter before listener startup.
    pub const fn new(usage: Arc<dyn GatewayUsageRuntimeCounterProvider>) -> Self {
        Self {
            process: Mutex::new(None),
            usage,
        }
    }

    // Binds the one exact retained process after every configured listener starts.
    pub fn bind(&self, process: &Arc<GatewayProcess>) -> Result<(), GatewayError> {
        let mut retained = self
            .process
            .lock()
            .map_err(|_| GatewayError::StateUnavailable)?;
        if retained.as_ref().and_then(Weak::upgrade).is_some() {
            return Err(GatewayError::InvalidContract {
                reason: "Gateway runtime counters are already bound",
            });
        }
        *retained = Some(Arc::downgrade(process));
        Ok(())
    }
}

impl GatewayTelemetryRuntimeCounterProvider for GatewayProcessRuntimeCounterProvider {
    // Reads both retained listener gauges and current usage-writer failures atomically enough.
    fn counters(&self) -> Result<GatewayTelemetryRuntimeCounters, GatewayError> {
        let process = self
            .process
            .lock()
            .map_err(|_| GatewayError::StateUnavailable)?
            .as_ref()
            .and_then(Weak::upgrade)
            .ok_or_else(|| {
                GatewayError::provider(
                    "telemetry_runtime_counters",
                    "Gateway process is unavailable",
                )
            })?;
        let connected_clients = process
            .active_connections(GatewayHttpSurface::Public)
            .checked_add(process.active_connections(GatewayHttpSurface::PrivateRelay))
            .and_then(|count| u32::try_from(count).ok())
            .ok_or(GatewayError::InvalidContract {
                reason: "Gateway connected-client count is out of range",
            })?;
        let (usage_records_dropped, usage_write_errors) = self.usage.usage_counters()?;
        Ok(GatewayTelemetryRuntimeCounters::new(
            connected_clients,
            usage_records_dropped,
            usage_write_errors,
        ))
    }
}

// Names one stable telemetry-resident startup, wait, or join failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayTelemetryResidentError {
    InvalidCadence,
    InitialPublicationFailed,
    WorkerStartFailed,
    WorkerStateUnavailable,
    PeriodicPublicationFailed,
    FailureNotificationFailed,
    WorkerPanicked,
}

impl fmt::Display for GatewayTelemetryResidentError {
    // Presents fixed telemetry lifecycle language without native path or thread detail.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCadence => formatter.write_str("Gateway telemetry cadence is invalid"),
            Self::InitialPublicationFailed => {
                formatter.write_str("Gateway telemetry could not be published")
            }
            Self::WorkerStartFailed => {
                formatter.write_str("Gateway telemetry worker could not start")
            }
            Self::WorkerStateUnavailable => {
                formatter.write_str("Gateway telemetry worker state is unavailable")
            }
            Self::PeriodicPublicationFailed => {
                formatter.write_str("Gateway telemetry publication failed")
            }
            Self::FailureNotificationFailed => {
                formatter.write_str("Gateway telemetry failure could not stop the process")
            }
            Self::WorkerPanicked => formatter.write_str("Gateway telemetry worker failed"),
        }
    }
}

impl Error for GatewayTelemetryResidentError {}

// Schedules interruptible publication cadence without coupling lifecycle tests to wall time.
pub trait GatewayTelemetryCadenceWaiter: Send + Sync {
    // Waits for one cadence and returns whether another publication should run.
    fn wait(&self, cadence: Duration) -> Result<bool, GatewayTelemetryResidentError>;

    // Interrupts any active wait and permanently requests worker shutdown.
    fn stop(&self) -> Result<(), GatewayTelemetryResidentError>;
}

// Stores the production one-way stop signal and its native interruptible cadence wait.
pub struct SystemGatewayTelemetryCadenceWaiter {
    stopped: Mutex<bool>,
    wake: Condvar,
}

impl SystemGatewayTelemetryCadenceWaiter {
    // Creates one unsignalled telemetry cadence owner.
    pub const fn new() -> Self {
        Self {
            stopped: Mutex::new(false),
            wake: Condvar::new(),
        }
    }
}

impl Default for SystemGatewayTelemetryCadenceWaiter {
    // Creates one production cadence waiter with no pending stop request.
    fn default() -> Self {
        Self::new()
    }
}

impl GatewayTelemetryCadenceWaiter for SystemGatewayTelemetryCadenceWaiter {
    // Waits for one cadence and returns whether another publication should run.
    fn wait(&self, cadence: Duration) -> Result<bool, GatewayTelemetryResidentError> {
        let stopped = self
            .stopped
            .lock()
            .map_err(|_| GatewayTelemetryResidentError::WorkerStateUnavailable)?;
        let (stopped, _) = self
            .wake
            .wait_timeout_while(stopped, cadence, |stopped| !*stopped)
            .map_err(|_| GatewayTelemetryResidentError::WorkerStateUnavailable)?;
        Ok(!*stopped)
    }

    // Publishes the one-way stop state before interrupting its cadence wait.
    fn stop(&self) -> Result<(), GatewayTelemetryResidentError> {
        *self
            .stopped
            .lock()
            .map_err(|_| GatewayTelemetryResidentError::WorkerStateUnavailable)? = true;
        self.wake.notify_all();
        Ok(())
    }
}

// Owns one periodic telemetry worker until deterministic stop and join complete.
pub struct GatewayTelemetryResident {
    waiter: Arc<dyn GatewayTelemetryCadenceWaiter>,
    worker: Mutex<Option<JoinHandle<Result<(), GatewayTelemetryResidentError>>>>,
}

impl GatewayTelemetryResident {
    // Publishes readiness once and starts one fixed-cadence resident worker.
    pub fn start(
        manager: Arc<GatewayManager>,
        cadence: Duration,
        failure: Arc<dyn GatewayTelemetryFailureHandler>,
    ) -> Result<Self, GatewayTelemetryResidentError> {
        Self::start_with_waiter(
            manager,
            cadence,
            Arc::new(SystemGatewayTelemetryCadenceWaiter::new()),
            failure,
        )
    }

    // Starts one worker over an injected interruptible cadence boundary.
    pub fn start_with_waiter(
        manager: Arc<GatewayManager>,
        cadence: Duration,
        waiter: Arc<dyn GatewayTelemetryCadenceWaiter>,
        failure: Arc<dyn GatewayTelemetryFailureHandler>,
    ) -> Result<Self, GatewayTelemetryResidentError> {
        if !(MINIMUM_TELEMETRY_CADENCE..=MAXIMUM_TELEMETRY_CADENCE).contains(&cadence) {
            return Err(GatewayTelemetryResidentError::InvalidCadence);
        }
        manager
            .publish_telemetry()
            .map_err(|_| GatewayTelemetryResidentError::InitialPublicationFailed)?;
        let worker_waiter = waiter.clone();
        let worker = thread::Builder::new()
            .name("li_gateway_telemetry".to_string())
            .spawn(move || run_telemetry(manager, cadence, worker_waiter, failure))
            .map_err(|_| GatewayTelemetryResidentError::WorkerStartFailed)?;
        Ok(Self {
            waiter,
            worker: Mutex::new(Some(worker)),
        })
    }

    // Interrupts the current cadence wait without consuming the worker result.
    pub fn stop(&self) -> Result<(), GatewayTelemetryResidentError> {
        self.waiter.stop()
    }

    // Stops and joins the exact telemetry worker idempotently.
    pub fn join(&self) -> Result<(), GatewayTelemetryResidentError> {
        self.stop()?;
        let worker = self
            .worker
            .lock()
            .map_err(|_| GatewayTelemetryResidentError::WorkerStateUnavailable)?
            .take();
        worker.map_or(Ok(()), |worker| {
            worker
                .join()
                .map_err(|_| GatewayTelemetryResidentError::WorkerPanicked)?
        })
    }
}

impl Drop for GatewayTelemetryResident {
    // Prevents the cadence worker from surviving its process composition owner.
    fn drop(&mut self) {
        let _ = self.join();
    }
}

// Publishes at the fixed cadence while keeping individual I/O failures health-visible.
fn run_telemetry(
    manager: Arc<GatewayManager>,
    cadence: Duration,
    waiter: Arc<dyn GatewayTelemetryCadenceWaiter>,
    failure: Arc<dyn GatewayTelemetryFailureHandler>,
) -> Result<(), GatewayTelemetryResidentError> {
    while waiter.wait(cadence)? {
        if manager.publish_telemetry().is_err() {
            failure
                .telemetry_did_fail()
                .map_err(|_| GatewayTelemetryResidentError::FailureNotificationFailed)?;
            return Err(GatewayTelemetryResidentError::PeriodicPublicationFailed);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    use li_core_interface::{ApiKeyId, LogicalModelName, NodeId, UnixMilliseconds};

    use super::*;
    use crate::{
        GatewayAuthenticationProvider, GatewayMode, GatewayPrincipal,
        GatewayRelayAuthorizationProvider, GatewayRoute, GatewayRouteProvider,
        GatewayTelemetryPublisher, GatewayUsageRecord, GatewayUsageStore,
    };

    // Supplies a monotonic deterministic clock for publication snapshots.
    struct Clock(AtomicU64);

    impl crate::GatewayClock for Clock {
        // Advances one millisecond for every observation.
        fn now(&self) -> Result<UnixMilliseconds, GatewayError> {
            Ok(UnixMilliseconds::new(self.0.fetch_add(1, Ordering::SeqCst)))
        }
    }

    // Rejects every unused public authentication attempt.
    struct Authentication;

    impl GatewayAuthenticationProvider for Authentication {
        // Keeps authentication outside telemetry-only tests.
        fn authenticate(
            &self,
            _bearer_token: &str,
            _model: &LogicalModelName,
        ) -> Result<GatewayPrincipal, GatewayError> {
            Err(GatewayError::AuthenticationDenied)
        }
    }

    // Rejects every unused relay authentication attempt.
    struct Relay;

    impl GatewayRelayAuthorizationProvider for Relay {
        // Keeps relay authorization outside telemetry-only tests.
        fn authorize(&self, _relay_credential: &str) -> Result<NodeId, GatewayError> {
            Err(GatewayError::RelayDenied)
        }
    }

    // Supplies an empty current route set to telemetry-only tests.
    struct Routes;

    impl GatewayRouteProvider for Routes {
        // Returns no active placement group.
        fn routes(&self, _model: &LogicalModelName) -> Result<Vec<GatewayRoute>, GatewayError> {
            Ok(Vec::new())
        }
    }

    // Supplies no durable usage to telemetry-only tests.
    struct Usage;

    impl GatewayUsageStore for Usage {
        // Returns an empty rolling window.
        fn recent(
            &self,
            _key_id: &ApiKeyId,
            _since: UnixMilliseconds,
        ) -> Result<Vec<GatewayUsageRecord>, GatewayError> {
            Ok(Vec::new())
        }

        // Accepts an unreachable completion record.
        fn record(&self, _usage: &GatewayUsageRecord) -> Result<(), GatewayError> {
            Ok(())
        }
    }

    // Counts publications and optionally rejects the initial publication.
    struct Publisher {
        count: AtomicU64,
        reject: AtomicBool,
    }

    impl GatewayTelemetryPublisher for Publisher {
        // Records one call before applying the configured deterministic failure.
        fn publish_atomically(
            &self,
            _snapshot: &crate::GatewayTelemetrySnapshot,
        ) -> Result<(), GatewayError> {
            self.count.fetch_add(1, Ordering::SeqCst);
            if self.reject.load(Ordering::SeqCst) {
                Err(GatewayError::provider("publisher", "rejected"))
            } else {
                Ok(())
            }
        }
    }

    // Releases exact worker decisions without sleeping or consulting wall time.
    struct Cadence {
        decisions: Mutex<VecDeque<Result<bool, GatewayTelemetryResidentError>>>,
        wake: Condvar,
    }

    // Counts terminal periodic publication notifications without controlling a real process.
    struct Failure {
        calls: AtomicU64,
    }

    impl GatewayTelemetryFailureHandler for Failure {
        // Records one exact terminal notification.
        fn telemetry_did_fail(&self) -> Result<(), GatewayTelemetryResidentError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    // Creates one observable deterministic failure handler.
    fn failure() -> Arc<Failure> {
        Arc::new(Failure {
            calls: AtomicU64::new(0),
        })
    }

    impl Cadence {
        // Creates one blocked deterministic cadence scheduler.
        fn new() -> Self {
            Self {
                decisions: Mutex::new(VecDeque::new()),
                wake: Condvar::new(),
            }
        }

        // Queues one publication before the eventual stop decision.
        fn publish(&self) {
            self.decisions.lock().unwrap().push_back(Ok(true));
            self.wake.notify_all();
        }

        // Queues one deterministic waiter failure.
        fn fail(&self) {
            self.decisions
                .lock()
                .unwrap()
                .push_back(Err(GatewayTelemetryResidentError::WorkerStateUnavailable));
            self.wake.notify_all();
        }
    }

    impl GatewayTelemetryCadenceWaiter for Cadence {
        // Blocks only on explicit test decisions and never on elapsed time.
        fn wait(&self, _cadence: Duration) -> Result<bool, GatewayTelemetryResidentError> {
            let mut decisions = self.decisions.lock().unwrap();
            while decisions.is_empty() {
                decisions = self.wake.wait(decisions).unwrap();
            }
            decisions.pop_front().unwrap()
        }

        // Queues the terminal decision behind all earlier publication decisions.
        fn stop(&self) -> Result<(), GatewayTelemetryResidentError> {
            self.decisions.lock().unwrap().push_back(Ok(false));
            self.wake.notify_all();
            Ok(())
        }
    }

    // Creates one telemetry-only manager and its observable publisher.
    fn manager(reject: bool) -> (Arc<crate::GatewayManager>, Arc<Publisher>) {
        let publisher = Arc::new(Publisher {
            count: AtomicU64::new(0),
            reject: AtomicBool::new(reject),
        });
        let manager = crate::GatewayManager::new_with_telemetry(
            GatewayMode::Main {
                local_node_id: NodeId::parse(&"1".repeat(32)).unwrap(),
            },
            Arc::new(Authentication),
            Arc::new(Relay),
            Arc::new(Routes),
            Arc::new(crate::UnavailableGatewayProtectionLeaseProvider),
            Arc::new(Clock(AtomicU64::new(1_000))),
            Arc::new(Usage),
            publisher.clone(),
        )
        .unwrap();
        (Arc::new(manager), publisher)
    }

    // Rejects invalid cadence and initial publication failure before starting a worker.
    #[test]
    fn startup_fails_closed_before_worker_ownership() {
        let (healthy, _) = manager(false);
        assert!(matches!(
            GatewayTelemetryResident::start_with_waiter(
                healthy,
                Duration::from_millis(99),
                Arc::new(Cadence::new()),
                failure(),
            ),
            Err(GatewayTelemetryResidentError::InvalidCadence)
        ));
        let (rejecting, publisher) = manager(true);
        assert!(matches!(
            GatewayTelemetryResident::start_with_waiter(
                rejecting,
                Duration::from_millis(100),
                Arc::new(Cadence::new()),
                failure(),
            ),
            Err(GatewayTelemetryResidentError::InitialPublicationFailed)
        ));
        assert_eq!(publisher.count.load(Ordering::SeqCst), 1);
    }

    // Publishes explicit cadence decisions then stops and joins idempotently without sleeps.
    #[test]
    fn injected_cadence_publishes_and_joins_deterministically() {
        let (manager, publisher) = manager(false);
        let cadence = Arc::new(Cadence::new());
        let resident = GatewayTelemetryResident::start_with_waiter(
            manager,
            Duration::from_millis(100),
            cadence.clone(),
            failure(),
        )
        .unwrap();
        cadence.publish();
        resident.join().unwrap();
        resident.join().unwrap();
        assert_eq!(publisher.count.load(Ordering::SeqCst), 2);
    }

    // Returns an injected scheduling failure while preserving complete worker ownership.
    #[test]
    fn injected_wait_failure_is_returned_by_join() {
        let (manager, _) = manager(false);
        let cadence = Arc::new(Cadence::new());
        let resident = GatewayTelemetryResident::start_with_waiter(
            manager,
            Duration::from_millis(100),
            cadence.clone(),
            failure(),
        )
        .unwrap();
        cadence.fail();
        assert_eq!(
            resident.join(),
            Err(GatewayTelemetryResidentError::WorkerStateUnavailable)
        );
        assert!(resident.join().is_ok());
    }

    // Makes one later publication failure terminal and notifies process control exactly once.
    #[test]
    fn later_publication_failure_stops_the_resident_without_sleeping() {
        let (manager, publisher) = manager(false);
        let cadence = Arc::new(Cadence::new());
        let failure = failure();
        let resident = GatewayTelemetryResident::start_with_waiter(
            manager,
            Duration::from_millis(100),
            cadence.clone(),
            failure.clone(),
        )
        .unwrap();
        publisher.reject.store(true, Ordering::SeqCst);
        cadence.publish();
        assert_eq!(
            resident.join(),
            Err(GatewayTelemetryResidentError::PeriodicPublicationFailed)
        );
        assert_eq!(publisher.count.load(Ordering::SeqCst), 2);
        assert_eq!(failure.calls.load(Ordering::SeqCst), 1);
        assert!(resident.join().is_ok());
    }
}
