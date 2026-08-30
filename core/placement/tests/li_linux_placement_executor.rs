// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use li_core_interface::{
    BootId, CredentialId, DeviceId, EndpointAddress, EndpointHealth, EndpointOwnership,
    EndpointScheme, EntityTimestamps, NetworkInterfaceName, NodeAddress, NodeId, Placement,
    PlacementAssignment, PlacementEndpoint, PlacementGroupId, PlacementId, PlacementResources,
    PlacementState, PortRange, RuntimeInstallationId, Sha256Digest, TaskId, UnixMilliseconds,
};
use li_placement_manager::{
    LinuxPlacementExecutionObservation, LinuxPlacementExecutionProvider,
    LinuxPlacementExecutionState, LinuxPlacementExecutor, LinuxPlacementProtectionProvider,
    LinuxProtectedProcessIdentity, PlacementError, PlacementExecutor,
    PlacementProtectionGeneration, PlacementProtectionPhase, PlacementProtectionStatus,
};

// Returns one exact placement fixture with configurable endpoint ownership and state.
fn placement(endpoint_ownership: EndpointOwnership, state: PlacementState) -> Placement {
    Placement::new(
        PlacementId::parse(&"1".repeat(32)).expect("placement"),
        PlacementGroupId::parse(&"2".repeat(32)).expect("group"),
        PlacementAssignment::new(
            NodeId::parse(&"3".repeat(32)).expect("node"),
            RuntimeInstallationId::parse(&"4".repeat(32)).expect("installation"),
            li_core_interface::HardwareObservationId::parse(&"6".repeat(32))
                .expect("hardware observation"),
            li_core_interface::BootId::parse("11111111-2222-3333-4444-555555555555").expect("boot"),
            li_core_interface::UnixMilliseconds::new(900),
            TaskId::parse("task-0").expect("task"),
            NodeAddress::parse("spark.local").expect("address"),
            PlacementResources::new(
                PortRange::new(18_000, 2).expect("ports"),
                vec![DeviceId::parse("GPU-A").expect("GPU")],
                Some(NetworkInterfaceName::parse("enp1s0f0np0").expect("RDMA")),
            )
            .expect("resources"),
            endpoint_ownership,
        ),
        state,
        None,
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(1_000))
            .expect("timestamps"),
    )
    .expect("placement")
}

// Returns one complete exact Linux process identity.
fn process() -> LinuxProtectedProcessIdentity {
    LinuxProtectedProcessIdentity::new(
        li_core_interface::TechnicalName::parse(&format!("li_placement_{}", "1".repeat(32)))
            .expect("name"),
        Sha256Digest::parse(&"5".repeat(64)).expect("container"),
        1_234,
        9_876,
        BootId::parse("11111111-2222-3333-4444-555555555555").expect("boot"),
        "/sys/fs/cgroup/user.slice/user-1000.slice/placement.scope",
    )
    .expect("process")
}

// Returns one endpoint whose identity matches the supplied placement.
fn endpoint(placement: &Placement, healthy: bool) -> PlacementEndpoint {
    PlacementEndpoint::new(
        placement.placement_id().clone(),
        placement.assignment().node_id().clone(),
        EndpointAddress::new(
            EndpointScheme::Https,
            placement.assignment().address().clone(),
            placement.assignment().resources().ports().base(),
        )
        .expect("endpoint address"),
        CredentialId::parse(&"6".repeat(32)).expect("credential"),
        Some(CredentialId::parse(&"7".repeat(32)).expect("CA")),
        None,
        4,
        262_144,
        EndpointHealth::new(healthy, false, None, Vec::new()).expect("health"),
    )
    .expect("endpoint")
}

// Mocks exact shell-free process operations and their observations.
struct MockExecution {
    trace: Arc<Mutex<Vec<String>>>,
    failures: Mutex<HashSet<String>>,
    observation: Mutex<LinuxPlacementExecutionObservation>,
    ready: AtomicBool,
    missing_endpoint: AtomicBool,
    unhealthy_endpoint: AtomicBool,
    participant_endpoint: AtomicBool,
    foreign_process: AtomicBool,
}

impl MockExecution {
    // Creates one staged execution provider with ordinary success behavior.
    fn new(trace: Arc<Mutex<Vec<String>>>, _placement: &Placement) -> Self {
        Self {
            trace,
            failures: Mutex::new(HashSet::new()),
            observation: Mutex::new(
                LinuxPlacementExecutionObservation::new(
                    LinuxPlacementExecutionState::Staged,
                    None,
                    false,
                    None,
                )
                .expect("observation"),
            ),
            ready: AtomicBool::new(true),
            missing_endpoint: AtomicBool::new(false),
            unhealthy_endpoint: AtomicBool::new(false),
            participant_endpoint: AtomicBool::new(false),
            foreign_process: AtomicBool::new(false),
        }
    }

    // Configures one exact process boundary to fail.
    fn fail(&self, action: &str) {
        self.failures
            .lock()
            .expect("failures")
            .insert(action.to_string());
    }

    // Returns whether the configured process boundary must fail.
    fn should_fail(&self, action: &str) -> bool {
        self.failures.lock().expect("failures").contains(action)
    }

    // Records one stable process-boundary event.
    fn record(&self, action: &str) {
        self.trace
            .lock()
            .expect("trace")
            .push(format!("execution.{action}"));
    }

    // Replaces the current deterministic execution observation.
    fn set_observation(&self, observation: LinuxPlacementExecutionObservation) {
        *self.observation.lock().expect("observation") = observation;
    }
}

impl LinuxPlacementExecutionProvider for MockExecution {
    // Returns configured staging success or failure.
    fn stage(&self, _placement: &Placement) -> Result<Sha256Digest, PlacementError> {
        self.record("stage");
        if self.should_fail("stage") {
            Err(PlacementError::ExecutionUnavailable)
        } else {
            Ok(Sha256Digest::parse(&"d".repeat(64)).expect("plan identity"))
        }
    }

    // Returns one exact process identity after the configured start boundary.
    fn start(
        &self,
        _placement: &Placement,
    ) -> Result<LinuxProtectedProcessIdentity, PlacementError> {
        self.record("start");
        if self.should_fail("start") {
            Err(PlacementError::ExecutionUnavailable)
        } else if self.foreign_process.load(Ordering::SeqCst) {
            LinuxProtectedProcessIdentity::new(
                li_core_interface::TechnicalName::parse("li_placement_foreign").expect("name"),
                Sha256Digest::parse(&"5".repeat(64)).expect("container"),
                1_234,
                9_876,
                BootId::parse("11111111-2222-3333-4444-555555555555").expect("boot"),
                "/sys/fs/cgroup/user.slice/user-1000.slice/placement.scope",
            )
        } else {
            Ok(process())
        }
    }

    // Returns configured readiness after recording the bounded wait.
    fn wait_until_ready(
        &self,
        _placement: &Placement,
        _process: &LinuxProtectedProcessIdentity,
    ) -> Result<bool, PlacementError> {
        self.record("ready");
        if self.should_fail("ready") {
            Err(PlacementError::ExecutionUnavailable)
        } else {
            Ok(self.ready.load(Ordering::SeqCst))
        }
    }

    // Returns a valid, absent, unhealthy, or participant endpoint as configured.
    fn endpoint(
        &self,
        placement: &Placement,
        _process: &LinuxProtectedProcessIdentity,
    ) -> Result<Option<PlacementEndpoint>, PlacementError> {
        self.record("endpoint");
        if self.should_fail("endpoint") {
            return Err(PlacementError::EndpointUnavailable);
        }
        if self.missing_endpoint.load(Ordering::SeqCst) {
            return Ok(None);
        }
        match placement.assignment().endpoint_ownership() {
            EndpointOwnership::Owner => Ok(Some(endpoint(
                placement,
                !self.unhealthy_endpoint.load(Ordering::SeqCst),
            ))),
            EndpointOwnership::Participant if self.participant_endpoint.load(Ordering::SeqCst) => {
                Ok(Some(endpoint(placement, true)))
            }
            EndpointOwnership::Participant => Ok(None),
        }
    }

    // Records exact incomplete-start cleanup and its configured failure.
    fn rollback_start(
        &self,
        _placement: &Placement,
        _process: Option<&LinuxProtectedProcessIdentity>,
    ) -> Result<(), PlacementError> {
        self.record("rollback");
        if self.should_fail("rollback") {
            Err(PlacementError::ExecutionUnavailable)
        } else {
            Ok(())
        }
    }

    // Records exact planned stop and its configured failure.
    fn stop(&self, _placement: &Placement) -> Result<(), PlacementError> {
        self.record("stop");
        if self.should_fail("stop") {
            Err(PlacementError::ExecutionUnavailable)
        } else {
            Ok(())
        }
    }

    // Records exact staged-input removal and its configured failure.
    fn remove(&self, _placement: &Placement) -> Result<(), PlacementError> {
        self.record("remove");
        if self.should_fail("remove") {
            Err(PlacementError::ExecutionUnavailable)
        } else {
            Ok(())
        }
    }

    // Returns the configured current process observation.
    fn observe(
        &self,
        _placement: &Placement,
    ) -> Result<LinuxPlacementExecutionObservation, PlacementError> {
        self.record("observe");
        if self.should_fail("observe") {
            Err(PlacementError::ExecutionUnavailable)
        } else {
            Ok(self.observation.lock().expect("observation").clone())
        }
    }
}

// Mocks Watchdog phase acknowledgement and exact trip behavior.
struct MockProtection {
    trace: Arc<Mutex<Vec<String>>>,
    failures: Mutex<HashSet<String>>,
    status: Mutex<PlacementProtectionStatus>,
    acknowledge_result: AtomicBool,
    reported_trip: AtomicBool,
    trip_on_bind_failure: AtomicBool,
}

impl MockProtection {
    // Creates one unconfigured protection provider.
    fn new(trace: Arc<Mutex<Vec<String>>>) -> Self {
        Self {
            trace,
            failures: Mutex::new(HashSet::new()),
            status: Mutex::new(PlacementProtectionStatus::new(
                PlacementProtectionPhase::Unconfigured,
                false,
            )),
            acknowledge_result: AtomicBool::new(true),
            reported_trip: AtomicBool::new(false),
            trip_on_bind_failure: AtomicBool::new(false),
        }
    }

    // Configures one exact Watchdog boundary to fail.
    fn fail(&self, action: &str) {
        self.failures
            .lock()
            .expect("failures")
            .insert(action.to_string());
    }

    // Returns whether the configured Watchdog boundary must fail.
    fn should_fail(&self, action: &str) -> bool {
        self.failures.lock().expect("failures").contains(action)
    }

    // Records one stable Watchdog-boundary event.
    fn record(&self, action: &str) {
        self.trace
            .lock()
            .expect("trace")
            .push(format!("protection.{action}"));
    }

    // Replaces current deterministic protection state.
    fn set_status(&self, phase: PlacementProtectionPhase, trip_latched: bool) {
        *self.status.lock().expect("status") = PlacementProtectionStatus::new(phase, trip_latched);
    }
}

impl LinuxPlacementProtectionProvider for MockProtection {
    // Creates and records one deterministic pending generation.
    fn begin(
        &self,
        _placement: &Placement,
    ) -> Result<PlacementProtectionGeneration, PlacementError> {
        self.record("begin");
        if self.should_fail("begin") {
            return Err(PlacementError::ProtectionUnsafe);
        }
        self.set_status(PlacementProtectionPhase::Pending, false);
        PlacementProtectionGeneration::parse(&"8".repeat(32))
    }

    // Records exact process binding before changing the phase to starting.
    fn bind_starting(
        &self,
        _placement: &Placement,
        _generation: &PlacementProtectionGeneration,
        _process: &LinuxProtectedProcessIdentity,
    ) -> Result<(), PlacementError> {
        self.record("bind");
        if self.should_fail("bind") {
            if self.trip_on_bind_failure.load(Ordering::SeqCst) {
                self.reported_trip.store(true, Ordering::SeqCst);
            }
            return Err(PlacementError::ProtectionUnsafe);
        }
        self.set_status(PlacementProtectionPhase::Starting, false);
        Ok(())
    }

    // Records and applies exact armed protection.
    fn arm(
        &self,
        _placement: &Placement,
        _generation: &PlacementProtectionGeneration,
        _process: &LinuxProtectedProcessIdentity,
    ) -> Result<(), PlacementError> {
        self.record("arm");
        if self.should_fail("arm") {
            return Err(PlacementError::ProtectionUnsafe);
        }
        self.set_status(PlacementProtectionPhase::Armed, false);
        Ok(())
    }

    // Records planned disarm and returns the acknowledged phase.
    fn disarm(&self, _placement: &Placement) -> Result<PlacementProtectionStatus, PlacementError> {
        self.record("disarm");
        if self.should_fail("disarm") {
            return Err(PlacementError::ProtectionUnsafe);
        }
        let trip = self.status.lock().expect("status").trip_latched();
        self.set_status(PlacementProtectionPhase::Disarmed, trip);
        Ok(*self.status.lock().expect("status"))
    }

    // Returns current phase and trip state after recording the observation.
    fn status(
        &self,
        _placement: &Placement,
        _process: Option<&LinuxProtectedProcessIdentity>,
    ) -> Result<PlacementProtectionStatus, PlacementError> {
        self.record("status");
        if self.should_fail("status") {
            Err(PlacementError::ProtectionUnsafe)
        } else {
            let status = *self.status.lock().expect("status");
            Ok(PlacementProtectionStatus::new(
                status.phase(),
                status.trip_latched() || self.reported_trip.load(Ordering::SeqCst),
            ))
        }
    }

    // Clears only the configured exact trip when acknowledgement succeeds.
    fn acknowledge_trip(&self, _placement: &Placement) -> Result<bool, PlacementError> {
        self.record("acknowledge");
        if self.should_fail("acknowledge") {
            return Err(PlacementError::ProtectionUnsafe);
        }
        let acknowledged = self.acknowledge_result.load(Ordering::SeqCst);
        if acknowledged {
            let phase = self.status.lock().expect("status").phase();
            self.set_status(phase, false);
            self.reported_trip.store(false, Ordering::SeqCst);
        }
        Ok(acknowledged)
    }

    // Retires one disarmed slot or returns the configured failure.
    fn retire(&self, _placement: &Placement) -> Result<(), PlacementError> {
        self.record("retire");
        if self.should_fail("retire") {
            return Err(PlacementError::ProtectionUnsafe);
        }
        self.set_status(PlacementProtectionPhase::Unconfigured, false);
        Ok(())
    }
}

// Groups one executor and its retained deterministic boundaries.
struct Fixture {
    executor: LinuxPlacementExecutor,
    execution: Arc<MockExecution>,
    protection: Arc<MockProtection>,
    trace: Arc<Mutex<Vec<String>>>,
    placement: Placement,
}

// Creates one ordinary endpoint-owning protected executor fixture.
fn fixture() -> Fixture {
    fixture_with_ownership(EndpointOwnership::Owner)
}

// Creates one protected executor fixture with explicit endpoint ownership.
fn fixture_with_ownership(endpoint_ownership: EndpointOwnership) -> Fixture {
    let placement = placement(endpoint_ownership, PlacementState::Staged);
    let trace = Arc::new(Mutex::new(Vec::new()));
    let execution = Arc::new(MockExecution::new(trace.clone(), &placement));
    let protection = Arc::new(MockProtection::new(trace.clone()));
    let executor = LinuxPlacementExecutor::new(execution.clone(), protection.clone());
    Fixture {
        executor,
        execution,
        protection,
        trace,
        placement,
    }
}

// Returns the captured cross-provider event sequence.
fn trace(fixture: &Fixture) -> Vec<String> {
    fixture.trace.lock().expect("trace").clone()
}

// Rejects incomplete process identities and malformed protection generations.
#[test]
fn protected_identity_values_fail_closed() {
    assert!(LinuxProtectedProcessIdentity::new(
        li_core_interface::TechnicalName::parse(&format!("li_placement_{}", "1".repeat(32)))
            .expect("name"),
        Sha256Digest::parse(&"5".repeat(64)).expect("container"),
        0,
        1,
        BootId::parse("11111111-2222-3333-4444-555555555555").expect("boot"),
        "/sys/fs/cgroup/scope",
    )
    .is_err());
    assert!(LinuxProtectedProcessIdentity::new(
        li_core_interface::TechnicalName::parse(&format!("li_placement_{}", "1".repeat(32)))
            .expect("name"),
        Sha256Digest::parse(&"5".repeat(64)).expect("container"),
        1,
        1,
        BootId::parse("11111111-2222-3333-4444-555555555555").expect("boot"),
        "/sys/fs/cgroup/../foreign",
    )
    .is_err());
    assert!(PlacementProtectionGeneration::parse("ABC").is_err());
}

// Delegates staging without creating or mutating a Watchdog slot.
#[test]
fn staging_uses_only_the_sealed_execution_provider() {
    let fixture = fixture();
    fixture.executor.stage(&fixture.placement).expect("stage");
    assert_eq!(trace(&fixture), vec!["execution.stage"]);
    fixture.execution.fail("stage");
    assert_eq!(
        fixture
            .executor
            .stage(&fixture.placement)
            .expect_err("stage failure"),
        PlacementError::ExecutionUnavailable
    );
}

// Orders pending, process binding, readiness, arming, and endpoint publication exactly.
#[test]
fn protected_start_arms_only_after_runtime_readiness() {
    let fixture = fixture();
    let result = fixture
        .executor
        .start(&fixture.placement, false)
        .expect("start");
    assert!(result.is_some());
    assert_eq!(
        trace(&fixture),
        vec![
            "protection.status",
            "protection.begin",
            "execution.start",
            "protection.bind",
            "execution.ready",
            "protection.arm",
            "execution.endpoint",
        ]
    );
}

// Acknowledges one explicit recovery trip before creating the next generation.
#[test]
fn protected_recovery_acknowledges_before_start() {
    let fixture = fixture();
    fixture
        .protection
        .set_status(PlacementProtectionPhase::Disarmed, true);
    fixture
        .executor
        .start(&fixture.placement, true)
        .expect("recovery start");
    let events = trace(&fixture);
    assert_eq!(
        &events[..4],
        [
            "protection.status",
            "protection.acknowledge",
            "protection.status",
            "protection.begin",
        ]
    );
}

// Rejects unsafe phase, durable trip, status, acknowledgement, and generation failures.
#[test]
fn protected_start_fails_at_every_preflight_boundary() {
    let armed = fixture();
    armed
        .protection
        .set_status(PlacementProtectionPhase::Armed, false);
    assert_eq!(
        armed
            .executor
            .start(&armed.placement, false)
            .expect_err("armed preflight"),
        PlacementError::ProtectionUnsafe
    );

    let ordinary_trip = fixture();
    ordinary_trip
        .protection
        .set_status(PlacementProtectionPhase::Disarmed, true);
    assert_eq!(
        ordinary_trip
            .executor
            .start(&ordinary_trip.placement, false)
            .expect_err("ordinary trip"),
        PlacementError::ProtectionUnsafe
    );

    let denied_acknowledgement = fixture();
    denied_acknowledgement
        .protection
        .set_status(PlacementProtectionPhase::Disarmed, true);
    denied_acknowledgement
        .protection
        .acknowledge_result
        .store(false, Ordering::SeqCst);
    assert_eq!(
        denied_acknowledgement
            .executor
            .start(&denied_acknowledgement.placement, true)
            .expect_err("denied acknowledgement"),
        PlacementError::ProtectionUnsafe
    );

    let status_failure = fixture();
    status_failure.protection.fail("status");
    assert_eq!(
        status_failure
            .executor
            .start(&status_failure.placement, false)
            .expect_err("status failure"),
        PlacementError::ProtectionUnsafe
    );

    let generation_failure = fixture();
    generation_failure.protection.fail("begin");
    assert_eq!(
        generation_failure
            .executor
            .start(&generation_failure.placement, false)
            .expect_err("generation failure"),
        PlacementError::ProtectionUnsafe
    );
    assert!(!trace(&generation_failure).contains(&"execution.start".to_string()));
}

// Rolls back every incomplete start boundary while preserving its primary error.
#[test]
fn protected_start_rolls_back_every_external_failure() {
    for boundary in ["start", "bind", "ready", "arm", "endpoint"] {
        let fixture = fixture();
        if matches!(boundary, "bind" | "arm") {
            fixture.protection.fail(boundary);
        } else {
            fixture.execution.fail(boundary);
        }
        let result = fixture.executor.start(&fixture.placement, false);
        assert!(result.is_err(), "{boundary}");
        let events = trace(&fixture);
        assert!(
            events.contains(&"execution.rollback".to_string()),
            "{boundary}"
        );
        assert!(
            events.contains(&"protection.disarm".to_string()),
            "{boundary}"
        );
    }
    let fixture = fixture();
    fixture.execution.ready.store(false, Ordering::SeqCst);
    assert!(fixture.executor.start(&fixture.placement, false).is_err());
    assert!(trace(&fixture).contains(&"execution.rollback".to_string()));
}

// Rolls back an invalid endpoint even though protection reached its armed phase.
#[test]
fn invalid_endpoint_is_never_left_armed_or_running() {
    let fixture = fixture();
    fixture
        .execution
        .missing_endpoint
        .store(true, Ordering::SeqCst);
    assert_eq!(
        fixture
            .executor
            .start(&fixture.placement, false)
            .expect_err("missing endpoint"),
        PlacementError::EndpointUnavailable
    );
    let events = trace(&fixture);
    assert_eq!(
        &events[events.len() - 3..],
        [
            "protection.status",
            "protection.disarm",
            "execution.rollback"
        ]
    );
}

// Rejects a process whose li_ container identity belongs to another placement.
#[test]
fn protected_start_rejects_foreign_process_identity() {
    let fixture = fixture();
    fixture
        .execution
        .foreign_process
        .store(true, Ordering::SeqCst);
    assert_eq!(
        fixture
            .executor
            .start(&fixture.placement, false)
            .expect_err("foreign process"),
        PlacementError::ProtectionUnsafe
    );
    assert!(trace(&fixture).contains(&"execution.rollback".to_string()));
    assert!(!trace(&fixture).contains(&"protection.bind".to_string()));
}

// Preserves a real durable trip while still removing the incomplete process.
#[test]
fn start_rollback_never_clears_a_real_trip() {
    let fixture = fixture();
    fixture.protection.fail("bind");
    fixture
        .protection
        .trip_on_bind_failure
        .store(true, Ordering::SeqCst);
    assert!(fixture.executor.start(&fixture.placement, false).is_err());
    let events = trace(&fixture);
    assert!(!events.contains(&"protection.disarm".to_string()));
    assert!(events.contains(&"execution.rollback".to_string()));
}

// Does not let compensating cleanup failures replace the original start failure.
#[test]
fn start_cleanup_failure_does_not_hide_the_primary_error() {
    let fixture = fixture();
    fixture.execution.fail("start");
    fixture.execution.fail("rollback");
    fixture.protection.fail("disarm");
    assert_eq!(
        fixture
            .executor
            .start(&fixture.placement, false)
            .expect_err("start failure"),
        PlacementError::ExecutionUnavailable
    );
}

// Requires acknowledged disarm before invoking the exact process stop.
#[test]
fn planned_stop_disarms_before_process_mutation() {
    let fixture = fixture();
    fixture
        .protection
        .set_status(PlacementProtectionPhase::Armed, false);
    fixture.executor.stop(&fixture.placement).expect("stop");
    assert_eq!(trace(&fixture), vec!["protection.disarm", "execution.stop"]);
}

// Blocks process stop when Watchdog disarm or process mutation fails.
#[test]
fn planned_stop_fails_at_each_external_boundary() {
    let protection_failure = fixture();
    protection_failure.protection.fail("disarm");
    assert_eq!(
        protection_failure
            .executor
            .stop(&protection_failure.placement)
            .expect_err("disarm failure"),
        PlacementError::ProtectionUnsafe
    );
    assert!(!trace(&protection_failure).contains(&"execution.stop".to_string()));

    let execution_failure = fixture();
    execution_failure.execution.fail("stop");
    assert_eq!(
        execution_failure
            .executor
            .stop(&execution_failure.placement)
            .expect_err("stop failure"),
        PlacementError::ExecutionUnavailable
    );
}

// Rejects removal while the process runs or protection remains armed.
#[test]
fn removal_rejects_every_unsafe_live_state() {
    let running = fixture();
    running.execution.set_observation(
        LinuxPlacementExecutionObservation::new(
            LinuxPlacementExecutionState::Running,
            Some(process()),
            true,
            Some(endpoint(&running.placement, true)),
        )
        .expect("observation"),
    );
    assert_eq!(
        running
            .executor
            .remove(&running.placement)
            .expect_err("running"),
        PlacementError::ProtectionUnsafe
    );

    let armed = fixture();
    armed
        .protection
        .set_status(PlacementProtectionPhase::Armed, false);
    assert_eq!(
        armed.executor.remove(&armed.placement).expect_err("armed"),
        PlacementError::ProtectionUnsafe
    );
}

// Retires a disarmed slot before deleting staged inputs.
#[test]
fn removal_retires_disarmed_protection_then_staged_inputs() {
    let fixture = fixture();
    fixture
        .protection
        .set_status(PlacementProtectionPhase::Disarmed, false);
    fixture.executor.remove(&fixture.placement).expect("remove");
    assert_eq!(
        trace(&fixture),
        vec![
            "execution.observe",
            "protection.status",
            "protection.retire",
            "execution.remove",
        ]
    );
}

// Acknowledges only a disarmed failed-process trip before retiring its slot.
#[test]
fn removal_acknowledges_disarmed_trip_before_retirement() {
    let fixture = fixture();
    fixture
        .protection
        .set_status(PlacementProtectionPhase::Disarmed, true);
    fixture.executor.remove(&fixture.placement).expect("remove");
    assert_eq!(
        trace(&fixture),
        vec![
            "execution.observe",
            "protection.status",
            "protection.acknowledge",
            "protection.status",
            "protection.retire",
            "execution.remove",
        ]
    );
}

// Blocks removal when acknowledgement, retirement, or staged cleanup fails.
#[test]
fn removal_fails_at_each_external_boundary() {
    let acknowledgement = fixture();
    acknowledgement
        .protection
        .set_status(PlacementProtectionPhase::Disarmed, true);
    acknowledgement
        .protection
        .acknowledge_result
        .store(false, Ordering::SeqCst);
    assert_eq!(
        acknowledgement
            .executor
            .remove(&acknowledgement.placement)
            .expect_err("acknowledgement"),
        PlacementError::ProtectionUnsafe
    );

    let retirement = fixture();
    retirement
        .protection
        .set_status(PlacementProtectionPhase::Disarmed, false);
    retirement.protection.fail("retire");
    assert_eq!(
        retirement
            .executor
            .remove(&retirement.placement)
            .expect_err("retirement"),
        PlacementError::ProtectionUnsafe
    );

    let cleanup = fixture();
    cleanup
        .protection
        .set_status(PlacementProtectionPhase::Disarmed, false);
    cleanup.execution.fail("remove");
    assert_eq!(
        cleanup
            .executor
            .remove(&cleanup.placement)
            .expect_err("cleanup"),
        PlacementError::ExecutionUnavailable
    );
}

// Reports one running placement only when readiness and armed protection agree.
#[test]
fn observation_requires_ready_execution_and_armed_protection() {
    let fixture = fixture();
    fixture.execution.set_observation(
        LinuxPlacementExecutionObservation::new(
            LinuxPlacementExecutionState::Running,
            Some(process()),
            true,
            Some(endpoint(&fixture.placement, true)),
        )
        .expect("observation"),
    );
    fixture
        .protection
        .set_status(PlacementProtectionPhase::Armed, false);
    let observation = fixture
        .executor
        .observe(&fixture.placement)
        .expect("observe");
    assert_eq!(observation.state(), PlacementState::Running);
    assert!(observation.endpoint().is_some());

    fixture
        .protection
        .set_status(PlacementProtectionPhase::Disarmed, false);
    assert_eq!(
        fixture
            .executor
            .observe(&fixture.placement)
            .expect("unarmed observation")
            .state(),
        PlacementState::Failed
    );

    fixture.execution.set_observation(
        LinuxPlacementExecutionObservation::new(
            LinuxPlacementExecutionState::Running,
            Some(process()),
            false,
            None,
        )
        .expect("not-ready observation"),
    );
    fixture
        .protection
        .set_status(PlacementProtectionPhase::Armed, false);
    assert_eq!(
        fixture
            .executor
            .observe(&fixture.placement)
            .expect("not-ready observation")
            .state(),
        PlacementState::Failed
    );
}

// Gives a durable Watchdog trip precedence over apparently healthy execution.
#[test]
fn observation_never_hides_a_durable_trip() {
    let fixture = fixture();
    fixture.execution.set_observation(
        LinuxPlacementExecutionObservation::new(
            LinuxPlacementExecutionState::Running,
            Some(process()),
            true,
            Some(endpoint(&fixture.placement, true)),
        )
        .expect("observation"),
    );
    fixture
        .protection
        .set_status(PlacementProtectionPhase::Armed, true);
    let observation = fixture
        .executor
        .observe(&fixture.placement)
        .expect("observe");
    assert_eq!(observation.state(), PlacementState::Failed);
    assert!(observation.protection_trip_latched());
    assert!(observation.endpoint().is_none());
}

// Maps absent execution through the durable staged, stopped, removed, and unsafe states.
#[test]
fn observation_maps_absence_from_durable_placement_state() {
    for (durable, expected) in [
        (PlacementState::Staged, PlacementState::Staged),
        (PlacementState::Stopped, PlacementState::Stopped),
        (PlacementState::Removed, PlacementState::Removed),
        (PlacementState::Running, PlacementState::Failed),
    ] {
        let mut fixture = fixture();
        fixture.placement = placement(EndpointOwnership::Owner, durable);
        fixture.execution.set_observation(
            LinuxPlacementExecutionObservation::new(
                LinuxPlacementExecutionState::Absent,
                None,
                false,
                None,
            )
            .expect("observation"),
        );
        assert_eq!(
            fixture
                .executor
                .observe(&fixture.placement)
                .expect("observe")
                .state(),
            expected
        );
    }
}

// Rejects participant endpoint publication during start and observation.
#[test]
fn participant_never_publishes_an_endpoint() {
    let fixture = fixture_with_ownership(EndpointOwnership::Participant);
    assert!(fixture
        .executor
        .start(&fixture.placement, false)
        .expect("participant start")
        .is_none());
    fixture
        .execution
        .participant_endpoint
        .store(true, Ordering::SeqCst);
    fixture.execution.set_observation(
        LinuxPlacementExecutionObservation::new(
            LinuxPlacementExecutionState::Running,
            Some(process()),
            true,
            Some(endpoint(&fixture.placement, true)),
        )
        .expect("observation"),
    );
    fixture
        .protection
        .set_status(PlacementProtectionPhase::Armed, false);
    assert_eq!(
        fixture
            .executor
            .observe(&fixture.placement)
            .expect_err("participant endpoint"),
        PlacementError::EndpointUnavailable
    );
}

// Propagates execution and protection observation failures without fabricated state.
#[test]
fn observation_fails_at_each_external_boundary() {
    let execution = fixture();
    execution.execution.fail("observe");
    assert_eq!(
        execution
            .executor
            .observe(&execution.placement)
            .expect_err("execution observation"),
        PlacementError::ExecutionUnavailable
    );

    let protection = fixture();
    protection.protection.fail("status");
    assert_eq!(
        protection
            .executor
            .observe(&protection.placement)
            .expect_err("protection observation"),
        PlacementError::ProtectionUnsafe
    );
}
