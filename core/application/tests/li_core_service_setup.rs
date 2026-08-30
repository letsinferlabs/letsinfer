// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::{Arc, Mutex};
use std::time::Duration;

use li_core_application::{
    CoreNativeServiceSupervisor, CoreProcessPlatform, CoreResidentProcess, CoreServiceCutoverBegin,
    CoreServiceCutoverProvider, CoreServiceCutoverReceipt, CoreServiceCutoverRecovery,
    CoreServiceDefinition, CoreServiceSetup, CoreServiceSetupError, CoreServiceSetupHealthProvider,
    CoreServiceSetupObservation, CoreServiceSetupPreflight, CoreServiceSetupWaiter,
};
use li_core_interface::Sha256Digest;
use li_core_update_manager::{
    CoreInstallation, CoreUpdateError, CoreUpdateNodeRole, CoreUpdateServiceContext,
    CoreUpdateServicePlatform, CoreUpdateServiceState, CoreVersion,
};

// Records the complete cross-provider setup transaction without native definition bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
enum SetupEvent {
    Preflight,
    Begin(
        CoreUpdateServiceContext,
        CoreInstallation,
        Vec<CoreResidentProcess>,
    ),
    Install(CoreResidentProcess),
    Ready(CoreProcessPlatform, CoreResidentProcess),
    Commit(Sha256Digest),
    Restore(Sha256Digest),
}

// Selects one deterministic setup failure boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SetupFailure {
    None,
    AlreadyCommitted,
    Begin,
    Install(CoreResidentProcess),
    ReadinessFalse(CoreResidentProcess),
    ReadinessFalseOnce(CoreResidentProcess),
    ReadinessError(CoreResidentProcess),
    Commit,
    Restore,
}

// Mocks native resident installation and readiness against one shared ordered event log.
struct SupervisorMock {
    failure: Mutex<SetupFailure>,
    events: Arc<Mutex<Vec<SetupEvent>>>,
}

impl SupervisorMock {
    // Creates one deterministic native service fixture.
    fn new(failure: SetupFailure, events: Arc<Mutex<Vec<SetupEvent>>>) -> Self {
        Self {
            failure: Mutex::new(failure),
            events,
        }
    }
}

impl CoreNativeServiceSupervisor for SupervisorMock {
    // Rejects observation because first setup consumes only installation and readiness.
    fn observe(
        &self,
        _platform: CoreProcessPlatform,
        _process: CoreResidentProcess,
    ) -> Result<CoreUpdateServiceState, CoreUpdateError> {
        Err(CoreUpdateError::provider(
            "test supervisor",
            "unexpected observation",
        ))
    }

    // Records one install unless the exact resident owns the injected failure.
    fn install(
        &self,
        definition: &CoreServiceDefinition,
        active: bool,
    ) -> Result<(), CoreUpdateError> {
        assert!(active, "first setup must activate every resident");
        self.events
            .lock()
            .expect("events")
            .push(SetupEvent::Install(definition.process()));
        if *self.failure.lock().expect("failure") == SetupFailure::Install(definition.process()) {
            return Err(CoreUpdateError::provider(
                "test supervisor",
                "injected installation failure",
            ));
        }
        Ok(())
    }

    // Records exact readiness and returns the resident-specific injected outcome.
    fn is_ready(
        &self,
        platform: CoreProcessPlatform,
        process: CoreResidentProcess,
        definition: Option<&CoreServiceDefinition>,
        active: bool,
    ) -> Result<bool, CoreUpdateError> {
        assert_eq!(
            definition.map(CoreServiceDefinition::process),
            Some(process)
        );
        assert!(active, "first setup must require every resident active");
        self.events
            .lock()
            .expect("events")
            .push(SetupEvent::Ready(platform, process));
        let mut failure = self.failure.lock().expect("failure");
        match *failure {
            SetupFailure::ReadinessFalse(failed) if failed == process => Ok(false),
            SetupFailure::ReadinessFalseOnce(failed) if failed == process => {
                *failure = SetupFailure::None;
                Ok(false)
            }
            SetupFailure::ReadinessError(failed) if failed == process => Err(
                CoreUpdateError::provider("test supervisor", "injected readiness failure"),
            ),
            _ => Ok(true),
        }
    }

    // Rejects direct restoration because cutover receipts own whole-set compensation.
    fn restore(
        &self,
        _platform: CoreProcessPlatform,
        _process: CoreResidentProcess,
        _definition: Option<&CoreServiceDefinition>,
        _active: bool,
    ) -> Result<(), CoreUpdateError> {
        Err(CoreUpdateError::provider(
            "test supervisor",
            "unexpected direct restoration",
        ))
    }
}

// Captures fixed readiness waits without delaying deterministic tests.
#[derive(Default)]
struct WaiterMock {
    durations: Mutex<Vec<Duration>>,
    now: Mutex<Duration>,
}

impl CoreServiceSetupWaiter for WaiterMock {
    // Returns the exact injected monotonic instant.
    fn now(&self) -> Result<Duration, CoreServiceSetupError> {
        Ok(*self.now.lock().expect("now"))
    }

    // Records one readiness interval for deadline and stability assertions.
    fn wait(&self, duration: Duration) -> Result<(), CoreServiceSetupError> {
        self.durations.lock().expect("durations").push(duration);
        *self.now.lock().expect("now") += duration;
        Ok(())
    }
}

// Records that every preflight completes before durable cutover begin.
struct PreflightMock {
    events: Arc<Mutex<Vec<SetupEvent>>>,
}

impl CoreServiceSetupPreflight for PreflightMock {
    // Records one complete preflight without touching native state.
    fn verify(
        &self,
        _context: CoreUpdateServiceContext,
        _installation: &CoreInstallation,
        _commands: &[li_core_application::CoreResidentProcessCommand],
    ) -> Result<(), CoreServiceSetupError> {
        self.events
            .lock()
            .expect("events")
            .push(SetupEvent::Preflight);
        Ok(())
    }
}

// Reports exact Gateway health and Linux memory readiness for setup transaction tests.
struct HealthMock;

impl CoreServiceSetupHealthProvider for HealthMock {
    // Reports one concrete healthy observation for every fixture resident.
    fn resident_health(
        &self,
        _context: CoreUpdateServiceContext,
        _process: CoreResidentProcess,
        _timeout: Duration,
    ) -> Result<CoreServiceSetupObservation, CoreServiceSetupError> {
        Ok(CoreServiceSetupObservation::Ready)
    }

    // Reports the emitted Linux envelope ready and macOS absence explicitly unsupported.
    fn memory_envelope(
        &self,
        context: CoreUpdateServiceContext,
        _definition: &CoreServiceDefinition,
        _timeout: Duration,
    ) -> Result<CoreServiceSetupObservation, CoreServiceSetupError> {
        Ok(match context.platform() {
            CoreUpdateServicePlatform::Linux => CoreServiceSetupObservation::Ready,
            CoreUpdateServicePlatform::Macos => CoreServiceSetupObservation::Unsupported,
        })
    }
}

// Rejects setup before cutover begin for preflight-order assertions.
struct RejectingPreflight;

impl CoreServiceSetupPreflight for RejectingPreflight {
    // Returns one stable preflight failure without observing native services.
    fn verify(
        &self,
        _context: CoreUpdateServiceContext,
        _installation: &CoreInstallation,
        _commands: &[li_core_application::CoreResidentProcessCommand],
    ) -> Result<(), CoreServiceSetupError> {
        Err(CoreServiceSetupError::provider(
            "service preflight",
            "injected preflight failure",
        ))
    }
}

// Advances monotonic time inside each native readiness command.
struct TimedSupervisor {
    clock: Arc<WaiterMock>,
}

impl CoreNativeServiceSupervisor for TimedSupervisor {
    // Rejects observation because setup never calls it.
    fn observe(
        &self,
        _platform: CoreProcessPlatform,
        _process: CoreResidentProcess,
    ) -> Result<CoreUpdateServiceState, CoreUpdateError> {
        Err(CoreUpdateError::provider(
            "timed supervisor",
            "unexpected observation",
        ))
    }

    // Accepts deterministic fixture installation without changing time.
    fn install(
        &self,
        _definition: &CoreServiceDefinition,
        _active: bool,
    ) -> Result<(), CoreUpdateError> {
        Ok(())
    }

    // Consumes the whole 90-second budget inside one command before returning ready.
    fn is_ready(
        &self,
        _platform: CoreProcessPlatform,
        _process: CoreResidentProcess,
        _definition: Option<&CoreServiceDefinition>,
        _active: bool,
    ) -> Result<bool, CoreUpdateError> {
        *self.clock.now.lock().expect("now") += Duration::from_secs(90);
        Ok(true)
    }

    // Rejects direct restoration because the cutover owns compensation.
    fn restore(
        &self,
        _platform: CoreProcessPlatform,
        _process: CoreResidentProcess,
        _definition: Option<&CoreServiceDefinition>,
        _active: bool,
    ) -> Result<(), CoreUpdateError> {
        Err(CoreUpdateError::provider(
            "timed supervisor",
            "unexpected restore",
        ))
    }
}

// Consumes the readiness budget at the final memory observation of a stable Linux window.
struct DeadlineMemoryHealth {
    clock: Arc<WaiterMock>,
    observations: Mutex<usize>,
}

impl CoreServiceSetupHealthProvider for DeadlineMemoryHealth {
    // Keeps semantic resident health ready so the test isolates the memory deadline boundary.
    fn resident_health(
        &self,
        _context: CoreUpdateServiceContext,
        _process: CoreResidentProcess,
        _timeout: Duration,
    ) -> Result<CoreServiceSetupObservation, CoreServiceSetupError> {
        Ok(CoreServiceSetupObservation::Ready)
    }

    // Advances exactly the fifteenth Linux memory observation to the absolute deadline.
    fn memory_envelope(
        &self,
        _context: CoreUpdateServiceContext,
        _definition: &CoreServiceDefinition,
        _timeout: Duration,
    ) -> Result<CoreServiceSetupObservation, CoreServiceSetupError> {
        let mut observations = self.observations.lock().expect("observations");
        *observations += 1;
        if *observations == 15 {
            *self.clock.now.lock().expect("now") = Duration::from_secs(90);
        }
        Ok(CoreServiceSetupObservation::Ready)
    }
}

// Returns an explicit unsupported state for one selected role-health check.
struct UnsupportedHealth {
    process: CoreResidentProcess,
}

impl CoreServiceSetupHealthProvider for UnsupportedHealth {
    // Never turns the selected unsupported role into a healthy observation.
    fn resident_health(
        &self,
        _context: CoreUpdateServiceContext,
        process: CoreResidentProcess,
        _timeout: Duration,
    ) -> Result<CoreServiceSetupObservation, CoreServiceSetupError> {
        Ok(if process == self.process {
            CoreServiceSetupObservation::Unsupported
        } else {
            CoreServiceSetupObservation::Ready
        })
    }

    // Keeps Linux memory ready so this fixture isolates role health.
    fn memory_envelope(
        &self,
        _context: CoreUpdateServiceContext,
        _definition: &CoreServiceDefinition,
        _timeout: Duration,
    ) -> Result<CoreServiceSetupObservation, CoreServiceSetupError> {
        Ok(CoreServiceSetupObservation::Ready)
    }
}

// Mocks durable native-state snapshot, commit, and whole-set restoration.
struct CutoverMock {
    failure: Mutex<SetupFailure>,
    events: Arc<Mutex<Vec<SetupEvent>>>,
    receipt: CoreServiceCutoverReceipt,
}

impl CutoverMock {
    // Creates one cutover fixture with a stable replay receipt.
    fn new(failure: SetupFailure, events: Arc<Mutex<Vec<SetupEvent>>>) -> Self {
        Self {
            failure: Mutex::new(failure),
            events,
            receipt: CoreServiceCutoverReceipt::new(digest('f')),
        }
    }
}

impl CoreServiceCutoverProvider for CutoverMock {
    // Records the exact platform, installation, and complete resident set before mutation.
    fn begin(
        &self,
        context: CoreUpdateServiceContext,
        installation: &CoreInstallation,
        definitions: &[CoreServiceDefinition],
    ) -> Result<CoreServiceCutoverBegin, CoreServiceSetupError> {
        self.events.lock().expect("events").push(SetupEvent::Begin(
            context,
            installation.clone(),
            definitions
                .iter()
                .map(CoreServiceDefinition::process)
                .collect(),
        ));
        if *self.failure.lock().expect("failure") == SetupFailure::Begin {
            return Err(CoreServiceSetupError::provider(
                "cutover snapshot",
                "injected begin failure",
            ));
        }
        if *self.failure.lock().expect("failure") == SetupFailure::AlreadyCommitted {
            return Ok(CoreServiceCutoverBegin::AlreadyCommitted(
                self.receipt.clone(),
            ));
        }
        Ok(CoreServiceCutoverBegin::Prepared(self.receipt.clone()))
    }

    // Records commit or leaves the durable receipt available after an injected failure.
    fn commit(&self, receipt: &CoreServiceCutoverReceipt) -> Result<(), CoreServiceSetupError> {
        assert_eq!(receipt, &self.receipt);
        self.events
            .lock()
            .expect("events")
            .push(SetupEvent::Commit(receipt.receipt_id().clone()));
        if *self.failure.lock().expect("failure") == SetupFailure::Commit {
            return Err(CoreServiceSetupError::provider(
                "cutover commit",
                "injected commit failure",
            ));
        }
        Ok(())
    }

    // Records whole-set compensation and optionally reports incomplete recovery.
    fn restore(&self, receipt: &CoreServiceCutoverReceipt) -> Result<(), CoreServiceSetupError> {
        assert_eq!(receipt, &self.receipt);
        self.events
            .lock()
            .expect("events")
            .push(SetupEvent::Restore(receipt.receipt_id().clone()));
        if *self.failure.lock().expect("failure") == SetupFailure::Restore {
            return Err(CoreServiceSetupError::provider(
                "cutover restoration",
                "injected restore failure",
            ));
        }
        Ok(())
    }

    // Reports no interrupted restoration in ordinary service-setup tests.
    fn recovery(&self) -> Result<CoreServiceCutoverRecovery, CoreServiceSetupError> {
        Ok(CoreServiceCutoverRecovery::None)
    }

    // Rejects unreachable pre-journal recovery in ordinary service-setup tests.
    fn resume_recovery(&self) -> Result<(), CoreServiceSetupError> {
        Err(CoreServiceSetupError::RecoveryRequired {
            reason: "test recovery is unavailable",
        })
    }

    // Accepts idempotent cleanup when the fixture has no recovery checkpoint.
    fn complete_recovery(&self) -> Result<(), CoreServiceSetupError> {
        Ok(())
    }
}

// Creates one canonical SHA-256 fixture.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
}

// Creates one immutable Core installation fixture.
fn installation() -> CoreInstallation {
    CoreInstallation::new(CoreVersion::parse("1.2.3").expect("version"), digest('a'))
}

// Composes one setup fixture with shared deterministic providers.
fn setup(
    platform: CoreUpdateServicePlatform,
    role: CoreUpdateNodeRole,
    supervisor_failure: SetupFailure,
    cutover_failure: SetupFailure,
) -> (
    CoreServiceSetup,
    Arc<Mutex<Vec<SetupEvent>>>,
    Arc<WaiterMock>,
) {
    let events = Arc::new(Mutex::new(Vec::new()));
    let supervisor = Arc::new(SupervisorMock::new(supervisor_failure, events.clone()));
    let cutover = Arc::new(CutoverMock::new(cutover_failure, events.clone()));
    let waiter = Arc::new(WaiterMock::default());
    let setup = CoreServiceSetup::new_with_waiter(
        CoreUpdateServiceContext::new(platform, role),
        std::path::PathBuf::from("/var/lib/letsinfer"),
        std::path::PathBuf::from("/var/lib/letsinfer/configuration"),
        supervisor,
        cutover,
        Arc::new(PreflightMock {
            events: events.clone(),
        }),
        Arc::new(HealthMock),
        waiter.clone(),
    )
    .expect("setup");
    (setup, events, waiter)
}

// Returns a copy of the complete shared event history.
fn events(events: &Arc<Mutex<Vec<SetupEvent>>>) -> Vec<SetupEvent> {
    events.lock().expect("events").clone()
}

// Installs and verifies the complete Linux set before committing its durable snapshot.
#[test]
fn linux_setup_orders_snapshot_three_residents_readiness_and_commit() {
    let (setup, history, waiter) = setup(
        CoreUpdateServicePlatform::Linux,
        CoreUpdateNodeRole::Main,
        SetupFailure::None,
        SetupFailure::None,
    );
    let installation = installation();
    let receipt = setup.apply(&installation).expect("apply");
    assert_eq!(receipt.receipt_id(), &digest('f'));
    let history = events(&history);
    assert_eq!(
        history.get(1),
        Some(&SetupEvent::Begin(
            CoreUpdateServiceContext::new(
                CoreUpdateServicePlatform::Linux,
                CoreUpdateNodeRole::Main,
            ),
            installation,
            vec![
                CoreResidentProcess::Node,
                CoreResidentProcess::Watchdog,
                CoreResidentProcess::Gateway,
            ],
        ))
    );
    assert_eq!(history.first(), Some(&SetupEvent::Preflight));
    assert_eq!(
        history[2..5],
        [
            SetupEvent::Install(CoreResidentProcess::Node),
            SetupEvent::Install(CoreResidentProcess::Watchdog),
            SetupEvent::Install(CoreResidentProcess::Gateway),
        ]
    );
    let expected_observation = [
        SetupEvent::Ready(CoreProcessPlatform::Linux, CoreResidentProcess::Node),
        SetupEvent::Ready(CoreProcessPlatform::Linux, CoreResidentProcess::Watchdog),
        SetupEvent::Ready(CoreProcessPlatform::Linux, CoreResidentProcess::Gateway),
    ];
    assert_eq!(history.len(), 21);
    for observation in history[5..20].chunks(3) {
        assert_eq!(observation, expected_observation);
    }
    assert_eq!(history.last(), Some(&SetupEvent::Commit(digest('f'))));
    assert_eq!(waiter.durations.lock().expect("durations").len(), 4);
}

// Resets the stability window after one transient resident readiness miss.
#[test]
fn readiness_requires_five_new_complete_observations_after_a_transient_miss() {
    let (setup, history, waiter) = setup(
        CoreUpdateServicePlatform::Linux,
        CoreUpdateNodeRole::Main,
        SetupFailure::ReadinessFalseOnce(CoreResidentProcess::Watchdog),
        SetupFailure::None,
    );
    setup.apply(&installation()).expect("apply");
    let history = events(&history);
    assert_eq!(
        history
            .iter()
            .filter(|event| matches!(event, SetupEvent::Ready(_, CoreResidentProcess::Node)))
            .count(),
        6
    );
    assert_eq!(
        history
            .iter()
            .filter(|event| matches!(event, SetupEvent::Ready(_, CoreResidentProcess::Gateway)))
            .count(),
        5
    );
    assert_eq!(
        history
            .iter()
            .filter(|event| matches!(event, SetupEvent::Ready(_, CoreResidentProcess::Watchdog)))
            .count(),
        6
    );
    assert_eq!(waiter.durations.lock().expect("durations").len(), 5);
    assert!(matches!(history.last(), Some(SetupEvent::Commit(_))));
}

// Preserves child context while installing only the two supported macOS agents.
#[test]
fn macos_child_setup_excludes_a_fabricated_watchdog_service() {
    let (setup, history, _) = setup(
        CoreUpdateServicePlatform::Macos,
        CoreUpdateNodeRole::Child,
        SetupFailure::None,
        SetupFailure::None,
    );
    setup.apply(&installation()).expect("apply");
    assert_eq!(
        events(&history)
            .into_iter()
            .filter_map(|event| match event {
                SetupEvent::Begin(context, _, processes) => Some((context, processes)),
                _ => None,
            })
            .collect::<Vec<_>>(),
        [(
            CoreUpdateServiceContext::new(
                CoreUpdateServicePlatform::Macos,
                CoreUpdateNodeRole::Child,
            ),
            vec![CoreResidentProcess::Node, CoreResidentProcess::Gateway],
        )]
    );
    assert!(!events(&history).iter().any(|event| matches!(
        event,
        SetupEvent::Install(CoreResidentProcess::Watchdog)
            | SetupEvent::Ready(_, CoreResidentProcess::Watchdog)
    )));
}

// Proves node role never suppresses a platform resident or invents an unsupported one.
#[test]
fn platform_and_role_matrix_preserves_the_complete_resident_set() {
    for (platform, role, expected) in [
        (
            CoreUpdateServicePlatform::Linux,
            CoreUpdateNodeRole::Main,
            vec![
                CoreResidentProcess::Node,
                CoreResidentProcess::Watchdog,
                CoreResidentProcess::Gateway,
            ],
        ),
        (
            CoreUpdateServicePlatform::Linux,
            CoreUpdateNodeRole::Child,
            vec![
                CoreResidentProcess::Node,
                CoreResidentProcess::Watchdog,
                CoreResidentProcess::Gateway,
            ],
        ),
        (
            CoreUpdateServicePlatform::Macos,
            CoreUpdateNodeRole::Main,
            vec![CoreResidentProcess::Node, CoreResidentProcess::Gateway],
        ),
        (
            CoreUpdateServicePlatform::Macos,
            CoreUpdateNodeRole::Child,
            vec![CoreResidentProcess::Node, CoreResidentProcess::Gateway],
        ),
    ] {
        let (setup, history, _) = setup(platform, role, SetupFailure::None, SetupFailure::None);
        setup.apply(&installation()).expect("apply");
        let history = events(&history);
        assert_eq!(
            history.iter().find_map(|event| match event {
                SetupEvent::Begin(context, _, processes) => Some((*context, processes.clone())),
                _ => None,
            }),
            Some((
                CoreUpdateServiceContext::new(platform, role),
                expected.clone()
            ))
        );
        assert_eq!(
            history
                .iter()
                .filter_map(|event| match event {
                    SetupEvent::Install(process) => Some(*process),
                    _ => None,
                })
                .collect::<Vec<_>>(),
            expected
        );
    }
}

// Performs no native mutation when the durable pre-mutation snapshot cannot be created.
#[test]
fn begin_failure_stops_before_installation() {
    let (setup, history, _) = setup(
        CoreUpdateServicePlatform::Linux,
        CoreUpdateNodeRole::Main,
        SetupFailure::None,
        SetupFailure::Begin,
    );
    assert!(matches!(
        setup.apply(&installation()),
        Err(CoreServiceSetupError::Provider {
            capability: "cutover snapshot",
            ..
        })
    ));
    assert!(matches!(
        events(&history).as_slice(),
        [SetupEvent::Preflight, SetupEvent::Begin(_, _, _)]
    ));
}

// Restores once after a middle install failure and never touches later residents.
#[test]
fn middle_install_failure_restores_without_continuing() {
    let (setup, history, _) = setup(
        CoreUpdateServicePlatform::Linux,
        CoreUpdateNodeRole::Main,
        SetupFailure::Install(CoreResidentProcess::Watchdog),
        SetupFailure::None,
    );
    assert_eq!(
        setup.apply(&installation()),
        Err(CoreServiceSetupError::RolledBack {
            reason: "a resident service could not be installed",
        })
    );
    assert_eq!(
        events(&history)[2..],
        [
            SetupEvent::Install(CoreResidentProcess::Node),
            SetupEvent::Install(CoreResidentProcess::Watchdog),
            SetupEvent::Restore(digest('f')),
        ]
    );
}

// Treats both a negative readiness judgment and a provider error as rollback boundaries.
#[test]
fn readiness_false_and_error_each_restore_the_snapshot() {
    for failure in [
        SetupFailure::ReadinessFalse(CoreResidentProcess::Watchdog),
        SetupFailure::ReadinessError(CoreResidentProcess::Watchdog),
    ] {
        let (setup, history, _) = setup(
            CoreUpdateServicePlatform::Linux,
            CoreUpdateNodeRole::Main,
            failure,
            SetupFailure::None,
        );
        assert_eq!(
            setup.apply(&installation()),
            Err(CoreServiceSetupError::RolledBack {
                reason: "a resident service did not become ready",
            })
        );
        let history = events(&history);
        assert_eq!(history.last(), Some(&SetupEvent::Restore(digest('f'))));
        assert!(!history.contains(&SetupEvent::Ready(
            CoreProcessPlatform::Linux,
            CoreResidentProcess::Gateway,
        )));
        assert!(!history
            .iter()
            .any(|event| matches!(event, SetupEvent::Commit(_))));
    }
}

// Escalates incomplete compensation instead of claiming the old services were restored.
#[test]
fn restoration_failure_requires_explicit_recovery() {
    let (setup, history, _) = setup(
        CoreUpdateServicePlatform::Linux,
        CoreUpdateNodeRole::Main,
        SetupFailure::Install(CoreResidentProcess::Node),
        SetupFailure::Restore,
    );
    assert_eq!(
        setup.apply(&installation()),
        Err(CoreServiceSetupError::RecoveryRequired {
            reason: "a resident service could not be installed",
        })
    );
    assert_eq!(
        events(&history).last(),
        Some(&SetupEvent::Restore(digest('f')))
    );
}

// Keeps the verified new resident set in place when only receipt cleanup cannot commit.
#[test]
fn commit_failure_never_rolls_back_verified_services() {
    let (setup, history, _) = setup(
        CoreUpdateServicePlatform::Macos,
        CoreUpdateNodeRole::Main,
        SetupFailure::None,
        SetupFailure::Commit,
    );
    assert!(matches!(
        setup.apply(&installation()),
        Err(CoreServiceSetupError::Provider {
            capability: "cutover commit",
            ..
        })
    ));
    let history = events(&history);
    assert!(matches!(history.last(), Some(SetupEvent::Commit(_))));
    assert!(!history
        .iter()
        .any(|event| matches!(event, SetupEvent::Restore(_))));
}

// Verifies a committed replay without reinstalling, recommitting, or restoring any service.
#[test]
fn committed_replay_is_verify_only() {
    let (setup, history, waiter) = setup(
        CoreUpdateServicePlatform::Linux,
        CoreUpdateNodeRole::Main,
        SetupFailure::None,
        SetupFailure::AlreadyCommitted,
    );
    let receipt = setup.apply(&installation()).expect("committed replay");
    assert_eq!(receipt.receipt_id(), &digest('f'));
    let history = events(&history);
    assert!(matches!(history.first(), Some(SetupEvent::Preflight)));
    assert!(matches!(history.get(1), Some(SetupEvent::Begin(_, _, _))));
    assert_eq!(
        history
            .iter()
            .filter(|event| matches!(event, SetupEvent::Ready(_, _)))
            .count(),
        15
    );
    assert!(!history.iter().any(|event| matches!(
        event,
        SetupEvent::Install(_) | SetupEvent::Commit(_) | SetupEvent::Restore(_)
    )));
    assert_eq!(waiter.durations.lock().expect("durations").len(), 4);
}

// Fails closed without mutation when a previously committed resident set is no longer ready.
#[test]
fn committed_replay_readiness_failure_requires_recovery() {
    let (setup, history, _) = setup(
        CoreUpdateServicePlatform::Linux,
        CoreUpdateNodeRole::Main,
        SetupFailure::ReadinessFalse(CoreResidentProcess::Watchdog),
        SetupFailure::AlreadyCommitted,
    );
    assert_eq!(
        setup.apply(&installation()),
        Err(CoreServiceSetupError::RecoveryRequired {
            reason: "committed resident services did not verify ready",
        })
    );
    assert!(!events(&history).iter().any(|event| matches!(
        event,
        SetupEvent::Install(_) | SetupEvent::Commit(_) | SetupEvent::Restore(_)
    )));
}

// Proves preflight failure precedes cutover begin, native installation, and readiness.
#[test]
fn preflight_failure_has_no_cutover_or_native_side_effects() {
    let history = Arc::new(Mutex::new(Vec::new()));
    let waiter = Arc::new(WaiterMock::default());
    let setup = CoreServiceSetup::new_with_waiter(
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Main),
        std::path::PathBuf::from("/var/lib/letsinfer"),
        std::path::PathBuf::from("/var/lib/letsinfer/configuration"),
        Arc::new(SupervisorMock::new(SetupFailure::None, history.clone())),
        Arc::new(CutoverMock::new(SetupFailure::None, history.clone())),
        Arc::new(RejectingPreflight),
        Arc::new(HealthMock),
        waiter,
    )
    .expect("setup");
    assert!(matches!(
        setup.apply(&installation()),
        Err(CoreServiceSetupError::Provider {
            capability: "service preflight",
            ..
        })
    ));
    assert!(events(&history).is_empty());
}

// Includes time spent inside native commands in the single absolute 90-second deadline.
#[test]
fn readiness_deadline_includes_native_command_time() {
    let history = Arc::new(Mutex::new(Vec::new()));
    let waiter = Arc::new(WaiterMock::default());
    let setup = CoreServiceSetup::new_with_waiter(
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Main),
        std::path::PathBuf::from("/var/lib/letsinfer"),
        std::path::PathBuf::from("/var/lib/letsinfer/configuration"),
        Arc::new(TimedSupervisor {
            clock: waiter.clone(),
        }),
        Arc::new(CutoverMock::new(SetupFailure::None, history.clone())),
        Arc::new(PreflightMock {
            events: history.clone(),
        }),
        Arc::new(HealthMock),
        waiter.clone(),
    )
    .expect("setup");
    assert_eq!(
        setup.apply(&installation()),
        Err(CoreServiceSetupError::RolledBack {
            reason: "a resident service did not become ready",
        })
    );
    assert!(waiter.durations.lock().expect("durations").is_empty());
    assert_eq!(*waiter.now.lock().expect("now"), Duration::from_secs(90));
    assert!(matches!(
        events(&history).last(),
        Some(SetupEvent::Restore(_))
    ));
}

// Refuses to commit when the final stable memory observation exhausts the shared deadline.
#[test]
fn readiness_deadline_includes_the_final_memory_observation() {
    let history = Arc::new(Mutex::new(Vec::new()));
    let waiter = Arc::new(WaiterMock::default());
    let setup = CoreServiceSetup::new_with_waiter(
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Main),
        std::path::PathBuf::from("/var/lib/letsinfer"),
        std::path::PathBuf::from("/var/lib/letsinfer/configuration"),
        Arc::new(SupervisorMock::new(SetupFailure::None, history.clone())),
        Arc::new(CutoverMock::new(SetupFailure::None, history.clone())),
        Arc::new(PreflightMock {
            events: history.clone(),
        }),
        Arc::new(DeadlineMemoryHealth {
            clock: waiter.clone(),
            observations: Mutex::new(0),
        }),
        waiter,
    )
    .expect("setup");

    assert_eq!(
        setup.apply(&installation()),
        Err(CoreServiceSetupError::RolledBack {
            reason: "a resident service did not become ready",
        })
    );
    let history = events(&history);
    assert!(matches!(history.last(), Some(SetupEvent::Restore(_))));
    assert!(!history
        .iter()
        .any(|event| matches!(event, SetupEvent::Commit(_))));
}

// Fails closed for unsupported Node, Watchdog, and Gateway health without committing.
#[test]
fn unsupported_resident_health_never_commits() {
    for process in [
        CoreResidentProcess::Node,
        CoreResidentProcess::Watchdog,
        CoreResidentProcess::Gateway,
    ] {
        let history = Arc::new(Mutex::new(Vec::new()));
        let waiter = Arc::new(WaiterMock::default());
        let setup = CoreServiceSetup::new_with_waiter(
            CoreUpdateServiceContext::new(
                CoreUpdateServicePlatform::Linux,
                CoreUpdateNodeRole::Main,
            ),
            std::path::PathBuf::from("/var/lib/letsinfer"),
            std::path::PathBuf::from("/var/lib/letsinfer/configuration"),
            Arc::new(SupervisorMock::new(SetupFailure::None, history.clone())),
            Arc::new(CutoverMock::new(SetupFailure::None, history.clone())),
            Arc::new(PreflightMock {
                events: history.clone(),
            }),
            Arc::new(UnsupportedHealth { process }),
            waiter,
        )
        .expect("setup");
        assert_eq!(
            setup.apply(&installation()),
            Err(CoreServiceSetupError::RolledBack {
                reason: "a resident service did not become ready",
            })
        );
        let history = events(&history);
        assert!(matches!(history.last(), Some(SetupEvent::Restore(_))));
        assert!(!history
            .iter()
            .any(|event| matches!(event, SetupEvent::Commit(_))));
    }
}

// Rejects overlapping mutable and immutable roots before either provider is invoked.
#[test]
fn unsafe_roots_fail_before_snapshot_or_native_mutation() {
    let history = Arc::new(Mutex::new(Vec::new()));
    let result = CoreServiceSetup::new(
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Main),
        std::path::PathBuf::from("/var/lib/letsinfer"),
        std::path::PathBuf::from("/var/lib/letsinfer/core"),
        Arc::new(SupervisorMock::new(SetupFailure::None, history.clone())),
        Arc::new(CutoverMock::new(SetupFailure::None, history.clone())),
        Arc::new(PreflightMock {
            events: history.clone(),
        }),
        Arc::new(HealthMock),
    );
    assert!(matches!(
        result,
        Err(CoreServiceSetupError::InvalidContract {
            reason: "service roots are unsafe",
        })
    ));
    assert!(events(&history).is_empty());
}
