// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::{Arc, Mutex};
use std::time::Duration;

use li_core_application::{
    CoreResidentProcess, CoreServiceSetupError, CoreServiceSetupObservation,
    CoreServiceSetupResidentHealth, CoreServiceSetupResidentHealthRouter,
};
use li_core_update_manager::{
    CoreUpdateNodeRole, CoreUpdateServiceContext, CoreUpdateServicePlatform,
};

// Records exact routing calls while returning one deterministic health outcome.
struct ResidentHealthMock {
    outcome: Result<CoreServiceSetupObservation, CoreServiceSetupError>,
    calls: Mutex<Vec<(CoreUpdateServiceContext, CoreResidentProcess, Duration)>>,
}

impl ResidentHealthMock {
    // Creates one isolated process-health mock with no hidden defaults.
    fn new(outcome: Result<CoreServiceSetupObservation, CoreServiceSetupError>) -> Self {
        Self {
            outcome,
            calls: Mutex::new(Vec::new()),
        }
    }
}

impl CoreServiceSetupResidentHealth for ResidentHealthMock {
    // Records one exact delegated request and returns the configured observation.
    fn observe(
        &self,
        context: CoreUpdateServiceContext,
        process: CoreResidentProcess,
        timeout: Duration,
    ) -> Result<CoreServiceSetupObservation, CoreServiceSetupError> {
        self.calls
            .lock()
            .expect("calls")
            .push((context, process, timeout));
        self.outcome.clone()
    }
}

// Returns one deterministic process-health provider.
fn provider(
    outcome: Result<CoreServiceSetupObservation, CoreServiceSetupError>,
) -> Arc<ResidentHealthMock> {
    Arc::new(ResidentHealthMock::new(outcome))
}

// Returns the exact platform and role context selected by a test.
fn context(
    platform: CoreUpdateServicePlatform,
    role: CoreUpdateNodeRole,
) -> CoreUpdateServiceContext {
    CoreUpdateServiceContext::new(platform, role)
}

// Requires Linux to provide Node, Gateway, and Watchdog exactly once.
#[test]
fn linux_router_rejects_missing_duplicate_and_foreign_service_sets() {
    let ready = provider(Ok(CoreServiceSetupObservation::Ready));
    for residents in [
        vec![
            (CoreResidentProcess::Node, ready.clone() as Arc<_>),
            (CoreResidentProcess::Gateway, ready.clone() as Arc<_>),
        ],
        vec![
            (CoreResidentProcess::Node, ready.clone() as Arc<_>),
            (CoreResidentProcess::Gateway, ready.clone() as Arc<_>),
            (CoreResidentProcess::Watchdog, ready.clone() as Arc<_>),
            (CoreResidentProcess::Watchdog, ready.clone() as Arc<_>),
        ],
    ] {
        assert!(CoreServiceSetupResidentHealthRouter::new(
            CoreUpdateServicePlatform::Linux,
            residents,
        )
        .is_err());
    }
}

// Requires macOS to provide only Node and Gateway without silently accepting Watchdog.
#[test]
fn macos_router_rejects_missing_or_linux_only_service_sets() {
    let ready = provider(Ok(CoreServiceSetupObservation::Ready));
    for residents in [
        vec![(CoreResidentProcess::Node, ready.clone() as Arc<_>)],
        vec![
            (CoreResidentProcess::Node, ready.clone() as Arc<_>),
            (CoreResidentProcess::Gateway, ready.clone() as Arc<_>),
            (CoreResidentProcess::Watchdog, ready.clone() as Arc<_>),
        ],
    ] {
        assert!(CoreServiceSetupResidentHealthRouter::new(
            CoreUpdateServicePlatform::Macos,
            residents,
        )
        .is_err());
    }
}

// Delegates each Linux role to only its own adapter with byte-for-byte request values.
#[test]
fn linux_router_dispatches_every_service_without_cross_role_fallback() {
    let node = provider(Ok(CoreServiceSetupObservation::Ready));
    let gateway = provider(Ok(CoreServiceSetupObservation::NotReady));
    let watchdog = provider(Ok(CoreServiceSetupObservation::Unsupported));
    let router = CoreServiceSetupResidentHealthRouter::new(
        CoreUpdateServicePlatform::Linux,
        vec![
            (CoreResidentProcess::Node, node.clone()),
            (CoreResidentProcess::Gateway, gateway.clone()),
            (CoreResidentProcess::Watchdog, watchdog.clone()),
        ],
    )
    .expect("router");
    let context = context(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Child);
    let timeout = Duration::from_millis(917);
    for (process, expected) in [
        (
            CoreResidentProcess::Node,
            CoreServiceSetupObservation::Ready,
        ),
        (
            CoreResidentProcess::Gateway,
            CoreServiceSetupObservation::NotReady,
        ),
        (
            CoreResidentProcess::Watchdog,
            CoreServiceSetupObservation::Unsupported,
        ),
    ] {
        assert_eq!(
            router
                .observe(context, process, timeout)
                .expect("observation"),
            expected
        );
    }
    for (provider, process) in [
        (node, CoreResidentProcess::Node),
        (gateway, CoreResidentProcess::Gateway),
        (watchdog, CoreResidentProcess::Watchdog),
    ] {
        assert_eq!(
            *provider.calls.lock().expect("calls"),
            vec![(context, process, timeout)]
        );
    }
}

// Preserves a concrete role-health failure without retrying another provider.
#[test]
fn router_propagates_provider_failure_exactly_once() {
    let failure =
        CoreServiceSetupError::provider("Gateway health", "Gateway health response is invalid");
    let node = provider(Ok(CoreServiceSetupObservation::Ready));
    let gateway = provider(Err(failure.clone()));
    let router = CoreServiceSetupResidentHealthRouter::new(
        CoreUpdateServicePlatform::Macos,
        vec![
            (CoreResidentProcess::Node, node.clone()),
            (CoreResidentProcess::Gateway, gateway.clone()),
        ],
    )
    .expect("router");
    assert_eq!(
        router.observe(
            context(CoreUpdateServicePlatform::Macos, CoreUpdateNodeRole::Main,),
            CoreResidentProcess::Gateway,
            Duration::from_secs(1),
        ),
        Err(failure)
    );
    assert!(node.calls.lock().expect("calls").is_empty());
    assert_eq!(gateway.calls.lock().expect("calls").len(), 1);
}

// Rejects platform drift and a zero deadline before invoking any resident provider.
#[test]
fn router_rejects_invalid_requests_before_dispatch() {
    let node = provider(Ok(CoreServiceSetupObservation::Ready));
    let gateway = provider(Ok(CoreServiceSetupObservation::Ready));
    let router = CoreServiceSetupResidentHealthRouter::new(
        CoreUpdateServicePlatform::Macos,
        vec![
            (CoreResidentProcess::Node, node.clone()),
            (CoreResidentProcess::Gateway, gateway.clone()),
        ],
    )
    .expect("router");
    for (request_context, timeout) in [
        (
            context(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Main),
            Duration::from_secs(1),
        ),
        (
            context(CoreUpdateServicePlatform::Macos, CoreUpdateNodeRole::Main),
            Duration::ZERO,
        ),
    ] {
        assert!(router
            .observe(request_context, CoreResidentProcess::Node, timeout)
            .is_err());
    }
    assert!(node.calls.lock().expect("calls").is_empty());
    assert!(gateway.calls.lock().expect("calls").is_empty());
}
