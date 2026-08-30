// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::{Arc, Mutex};
use std::time::Duration;

use li_core_application::{
    ApplicationCoreUpdateServiceControl, CoreNativeServiceSupervisor, CoreProcessLayout,
    CoreProcessPlatform, CoreResidentProcess, CoreServiceDefinition, CoreServiceDefinitionProvider,
};
use li_core_interface::Sha256Digest;
use li_core_update_manager::{
    CoreInstallation, CoreUpdateError, CoreUpdateNodeRole, CoreUpdateResidentService,
    CoreUpdateServiceContext, CoreUpdateServiceControl, CoreUpdateServiceMode,
    CoreUpdateServicePlatform, CoreUpdateServiceState, CoreVersion,
};

// Stores one deterministic native call without retaining service-definition bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
enum SupervisorEvent {
    Observe(CoreProcessPlatform, CoreResidentProcess),
    Install(CoreResidentProcess, Sha256Digest, bool),
    Ready(
        CoreProcessPlatform,
        CoreResidentProcess,
        Option<Sha256Digest>,
        bool,
    ),
    Restore(
        CoreProcessPlatform,
        CoreResidentProcess,
        Option<Sha256Digest>,
        bool,
    ),
}

// Mocks exact native service state, decisions, failures, and ordered mutations.
struct SupervisorMock {
    observed: Mutex<CoreUpdateServiceState>,
    ready: Mutex<Result<bool, CoreUpdateError>>,
    fail_install: Mutex<bool>,
    fail_restore: Mutex<bool>,
    ready_timeouts: Mutex<Vec<Duration>>,
    events: Mutex<Vec<SupervisorEvent>>,
}

impl SupervisorMock {
    // Creates one native supervisor fixture around an exact initial state.
    fn new(observed: CoreUpdateServiceState) -> Self {
        Self {
            observed: Mutex::new(observed),
            ready: Mutex::new(Ok(true)),
            fail_install: Mutex::new(false),
            fail_restore: Mutex::new(false),
            ready_timeouts: Mutex::new(Vec::new()),
            events: Mutex::new(Vec::new()),
        }
    }

    // Returns and clears the exact native-service call sequence.
    fn take_events(&self) -> Vec<SupervisorEvent> {
        std::mem::take(&mut *self.events.lock().expect("events"))
    }
}

impl CoreNativeServiceSupervisor for SupervisorMock {
    // Returns the configured observation after recording the requested identity.
    fn observe(
        &self,
        platform: CoreProcessPlatform,
        process: CoreResidentProcess,
    ) -> Result<CoreUpdateServiceState, CoreUpdateError> {
        self.events
            .lock()
            .expect("events")
            .push(SupervisorEvent::Observe(platform, process));
        Ok(self.observed.lock().expect("observed").clone())
    }

    // Records one exact definition install or injects a redacted boundary failure.
    fn install(
        &self,
        definition: &CoreServiceDefinition,
        active: bool,
    ) -> Result<(), CoreUpdateError> {
        if *self.fail_install.lock().expect("fail install") {
            return Err(CoreUpdateError::provider(
                "native service",
                "injected install failure",
            ));
        }
        self.events
            .lock()
            .expect("events")
            .push(SupervisorEvent::Install(
                definition.process(),
                definition.sha256().clone(),
                active,
            ));
        Ok(())
    }

    // Records the exact expected definition and returns the configured readiness result.
    fn is_ready(
        &self,
        platform: CoreProcessPlatform,
        process: CoreResidentProcess,
        definition: Option<&CoreServiceDefinition>,
        active: bool,
    ) -> Result<bool, CoreUpdateError> {
        self.events
            .lock()
            .expect("events")
            .push(SupervisorEvent::Ready(
                platform,
                process,
                definition.map(|value| value.sha256().clone()),
                active,
            ));
        self.ready.lock().expect("ready").clone()
    }

    // Captures the exact caller-owned deadline before delegating the readiness decision.
    fn is_ready_with_timeout(
        &self,
        platform: CoreProcessPlatform,
        process: CoreResidentProcess,
        definition: Option<&CoreServiceDefinition>,
        active: bool,
        timeout: Duration,
    ) -> Result<bool, CoreUpdateError> {
        self.ready_timeouts.lock().expect("timeouts").push(timeout);
        self.is_ready(platform, process, definition, active)
    }

    // Records one exact prior definition or absence or injects a restoration failure.
    fn restore(
        &self,
        platform: CoreProcessPlatform,
        process: CoreResidentProcess,
        definition: Option<&CoreServiceDefinition>,
        active: bool,
    ) -> Result<(), CoreUpdateError> {
        if *self.fail_restore.lock().expect("fail restore") {
            return Err(CoreUpdateError::provider(
                "native service",
                "injected restore failure",
            ));
        }
        self.events
            .lock()
            .expect("events")
            .push(SupervisorEvent::Restore(
                platform,
                process,
                definition.map(|value| value.sha256().clone()),
                active,
            ));
        Ok(())
    }
}

// Creates one exact immutable installation fixture.
fn installation(version: &str, identity_byte: char) -> CoreInstallation {
    CoreInstallation::new(
        CoreVersion::parse(version).expect("version"),
        Sha256Digest::parse(&identity_byte.to_string().repeat(64)).expect("identity"),
    )
}

// Generates the exact service definition expected from the production composition.
fn definition(
    platform: CoreProcessPlatform,
    installation: &CoreInstallation,
    process: CoreResidentProcess,
) -> CoreServiceDefinition {
    let root = std::path::PathBuf::from("/var/lib/letsinfer/core/versions")
        .join(installation.version().as_str())
        .join(installation.source_identity().as_str());
    let layout = CoreProcessLayout::new(
        platform,
        root,
        std::path::PathBuf::from("/var/lib/letsinfer/configuration"),
        std::path::PathBuf::from("/var/lib/letsinfer/logs"),
    )
    .expect("layout");
    CoreServiceDefinitionProvider
        .definition(platform, &layout.command(process).expect("command"))
        .expect("definition")
}

// Composes one Linux control fixture with an explicit native supervisor mock.
fn linux_control(
    role: CoreUpdateNodeRole,
) -> (ApplicationCoreUpdateServiceControl, Arc<SupervisorMock>) {
    let supervisor = Arc::new(SupervisorMock::new(
        CoreUpdateServiceState::new(CoreUpdateResidentService::Node, None, None).expect("state"),
    ));
    let control = ApplicationCoreUpdateServiceControl::new(
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, role),
        std::path::PathBuf::from("/var/lib/letsinfer"),
        std::path::PathBuf::from("/var/lib/letsinfer/configuration"),
        supervisor.clone(),
    )
    .expect("control");
    (control, supervisor)
}

// Generates exact Linux definitions for manager-selected modes without duplicating mode policy.
#[test]
fn linux_rebind_applies_manager_selected_mode_without_local_judgment() {
    let (control, supervisor) = linux_control(CoreUpdateNodeRole::Main);
    let candidate = installation("1.2.3", 'a');
    control
        .rebind_service(
            CoreUpdateResidentService::Gateway,
            CoreUpdateServiceMode::PublicGateway,
            &candidate,
            true,
        )
        .expect("rebind");
    let expected = definition(
        CoreProcessPlatform::Linux,
        &candidate,
        CoreResidentProcess::Gateway,
    );
    control
        .rebind_service(
            CoreUpdateResidentService::Gateway,
            CoreUpdateServiceMode::PrivateGateway,
            &candidate,
            true,
        )
        .expect("second manager-selected rebind");
    assert_eq!(
        supervisor.take_events(),
        vec![
            SupervisorEvent::Install(
                CoreResidentProcess::Gateway,
                expected.sha256().clone(),
                true,
            ),
            SupervisorEvent::Install(
                CoreResidentProcess::Gateway,
                expected.sha256().clone(),
                true,
            ),
        ]
    );
}

// Verifies both an exact loaded candidate and an exact unloaded service without mutation.
#[test]
fn readiness_covers_exact_definition_and_exact_absence() {
    let (control, supervisor) = linux_control(CoreUpdateNodeRole::Child);
    let candidate = installation("2.0.0", 'b');
    assert!(control
        .service_is_ready(
            CoreUpdateResidentService::Gateway,
            CoreUpdateServiceMode::PrivateGateway,
            Some(&candidate),
            true,
        )
        .expect("loaded readiness"));
    assert!(control
        .service_is_ready(
            CoreUpdateResidentService::Node,
            CoreUpdateServiceMode::Node,
            None,
            false,
        )
        .expect("absent readiness"));
    let gateway = definition(
        CoreProcessPlatform::Linux,
        &candidate,
        CoreResidentProcess::Gateway,
    );
    assert_eq!(
        supervisor.take_events(),
        vec![
            SupervisorEvent::Ready(
                CoreProcessPlatform::Linux,
                CoreResidentProcess::Gateway,
                Some(gateway.sha256().clone()),
                true,
            ),
            SupervisorEvent::Ready(
                CoreProcessPlatform::Linux,
                CoreResidentProcess::Node,
                None,
                false,
            ),
        ]
    );
}

// Caps the update provider's remaining deadline to the native supervisor's strict bound.
#[test]
fn readiness_passes_one_bounded_deadline_into_the_native_supervisor() {
    let (control, supervisor) = linux_control(CoreUpdateNodeRole::Main);
    let candidate = installation("2.0.0", 'b');
    assert!(control
        .service_is_ready_with_timeout(
            CoreUpdateResidentService::Node,
            CoreUpdateServiceMode::Node,
            Some(&candidate),
            true,
            Duration::from_secs(300),
        )
        .expect("ready"));
    assert_eq!(
        *supervisor.ready_timeouts.lock().expect("timeouts"),
        [Duration::from_secs(90)]
    );
    assert!(control
        .service_is_ready_with_timeout(
            CoreUpdateResidentService::Node,
            CoreUpdateServiceMode::Node,
            Some(&candidate),
            true,
            Duration::ZERO,
        )
        .is_err());
    assert_eq!(supervisor.take_events().len(), 1);
}

// Restores the previous content identity and rejects a snapshot that cannot reproduce it.
#[test]
fn restoration_requires_the_exact_previous_definition_identity() {
    let (control, supervisor) = linux_control(CoreUpdateNodeRole::Main);
    let previous = installation("1.9.0", 'c');
    let prior_definition = definition(
        CoreProcessPlatform::Linux,
        &previous,
        CoreResidentProcess::Node,
    );
    let state = CoreUpdateServiceState::new(
        CoreUpdateResidentService::Node,
        Some(prior_definition.sha256().clone()),
        Some(prior_definition.sha256().clone()),
    )
    .expect("state");
    control.restore_service(&state, &previous).expect("restore");
    assert_eq!(
        supervisor.take_events(),
        vec![SupervisorEvent::Restore(
            CoreProcessPlatform::Linux,
            CoreResidentProcess::Node,
            Some(prior_definition.sha256().clone()),
            true,
        )]
    );
    let foreign = CoreUpdateServiceState::new(
        CoreUpdateResidentService::Node,
        Some(Sha256Digest::parse(&"f".repeat(64)).expect("foreign")),
        None,
    )
    .expect("foreign state");
    assert!(control.restore_service(&foreign, &previous).is_err());
    assert!(supervisor.take_events().is_empty());
}

// Preserves an unloaded prior service as absence rather than inventing a definition.
#[test]
fn restoration_preserves_an_unloaded_prior_service() {
    let (control, supervisor) = linux_control(CoreUpdateNodeRole::Main);
    let previous = installation("1.8.0", 'd');
    let state = CoreUpdateServiceState::new(CoreUpdateResidentService::Watchdog, None, None)
        .expect("state");
    control
        .restore_service(&state, &previous)
        .expect("restore absence");
    assert_eq!(
        supervisor.take_events(),
        vec![SupervisorEvent::Restore(
            CoreProcessPlatform::Linux,
            CoreResidentProcess::Watchdog,
            None,
            false,
        )]
    );
}

// Rejects unsupported macOS Watchdog and a supervisor identity mismatch before policy proceeds.
#[test]
fn unsupported_or_mismatched_native_service_identity_fails_closed() {
    let supervisor = Arc::new(SupervisorMock::new(
        CoreUpdateServiceState::new(CoreUpdateResidentService::Gateway, None, None).expect("state"),
    ));
    let control = ApplicationCoreUpdateServiceControl::new(
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Macos, CoreUpdateNodeRole::Main),
        std::path::PathBuf::from("/Users/test/Library/Application Support/LetsInfer"),
        std::path::PathBuf::from("/Users/test/Library/Application Support/LetsInfer/configuration"),
        supervisor.clone(),
    )
    .expect("control");
    assert!(control
        .rebind_service(
            CoreUpdateResidentService::Watchdog,
            CoreUpdateServiceMode::Watchdog,
            &installation("3.0.0", 'e'),
            true,
        )
        .is_err());
    assert!(control
        .observe_service(CoreUpdateResidentService::Node)
        .is_err());
    assert_eq!(
        supervisor.take_events(),
        vec![SupervisorEvent::Observe(
            CoreProcessPlatform::Macos,
            CoreResidentProcess::Node,
        )]
    );
}

// Propagates native failures without recording a successful mutation or weakening the request.
#[test]
fn native_install_and_readiness_failures_propagate_without_fallback() {
    let (control, supervisor) = linux_control(CoreUpdateNodeRole::Main);
    *supervisor.fail_install.lock().expect("fail install") = true;
    assert!(control
        .rebind_service(
            CoreUpdateResidentService::Node,
            CoreUpdateServiceMode::Node,
            &installation("5.0.0", '6'),
            true,
        )
        .is_err());
    assert!(supervisor.take_events().is_empty());
    *supervisor.ready.lock().expect("ready") = Err(CoreUpdateError::provider(
        "native service",
        "injected readiness failure",
    ));
    assert!(control
        .service_is_ready(
            CoreUpdateResidentService::Node,
            CoreUpdateServiceMode::Node,
            None,
            false,
        )
        .is_err());
    assert_eq!(supervisor.take_events().len(), 1);
}

// Rejects unsafe relative composition roots before any native capability can be called.
#[test]
fn unsafe_service_roots_fail_before_native_composition() {
    let supervisor = Arc::new(SupervisorMock::new(
        CoreUpdateServiceState::new(CoreUpdateResidentService::Node, None, None).expect("state"),
    ));
    assert!(ApplicationCoreUpdateServiceControl::new(
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Main),
        std::path::PathBuf::from("relative"),
        std::path::PathBuf::from("/var/lib/letsinfer/configuration"),
        supervisor.clone(),
    )
    .is_err());
    assert!(supervisor.take_events().is_empty());
}
