// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::VecDeque;
use std::num::{NonZeroU32, NonZeroU64};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use li_authentication_manager::ApiKeyLimits;
use li_core_interface::{
    ApiKeyId, BootId, EndpointAddress, EndpointScheme, InstallationId, LogicalModelName,
    NodeAddress, NodeId, PlacementGroupId, PlacementId, Sha256Digest, TechnicalName,
    UnixMilliseconds,
};
use li_gateway_manager::{
    GatewayAdmission, GatewayAuthenticationProvider, GatewayChatCompletionRequest, GatewayClock,
    GatewayError, GatewayExactUsage, GatewayExecution, GatewayExecutionFailure,
    GatewayExecutionProvider, GatewayMacOsPlacementSafetyLease,
    GatewayMacOsPlacementSafetyProvider, GatewayMacOsPlacementSafetySnapshot, GatewayManager,
    GatewayMode, GatewayPlacementProtectionLease, GatewayPlacementProtectionSnapshot,
    GatewayPrincipal, GatewayProtectionAuthority, GatewayProtectionLeaseProvider,
    GatewayQueueTicket, GatewayQueueWaiter, GatewayRelayAuthorizationProvider, GatewayRequest,
    GatewayReservation, GatewayResponseHead, GatewayResponseHeader, GatewayResponseWriter,
    GatewayRoute, GatewayRouteProvider, GatewayRouteTarget, GatewayTelemetryPublisher,
    GatewayTelemetrySnapshot, GatewayUsageRecord, GatewayUsageStore,
};

// Supplies deterministic time without consulting the host clock.
struct ClockMock {
    now: AtomicU64,
}

impl GatewayClock for ClockMock {
    // Returns the exact test-controlled timestamp.
    fn now(&self) -> Result<UnixMilliseconds, GatewayError> {
        Ok(UnixMilliseconds::new(self.now.load(Ordering::SeqCst)))
    }
}

// Returns one fixed public principal and counts authentication boundaries.
struct AuthenticationMock {
    calls: AtomicUsize,
}

impl GatewayAuthenticationProvider for AuthenticationMock {
    // Projects one unrestricted principal without observing bearer material.
    fn authenticate(
        &self,
        _bearer_token: &str,
        _model: &LogicalModelName,
    ) -> Result<GatewayPrincipal, GatewayError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(GatewayPrincipal::new(
            api_key_id('a'),
            ApiKeyLimits::new(None, None, None, None),
        ))
    }
}

// Authorizes the fixed main node for private child-relay tests.
struct RelayAuthorizationMock;

impl GatewayRelayAuthorizationProvider for RelayAuthorizationMock {
    // Returns the main-node identity bound by the fixture credential.
    fn authorize(&self, _relay_credential: &str) -> Result<NodeId, GatewayError> {
        Ok(node_id('1'))
    }
}

// Supplies one immutable deterministic route snapshot.
struct RouteMock {
    routes: Vec<GatewayRoute>,
}

impl GatewayRouteProvider for RouteMock {
    // Returns all current routes for the requested fixture model.
    fn routes(&self, _model: &LogicalModelName) -> Result<Vec<GatewayRoute>, GatewayError> {
        Ok(self.routes.clone())
    }
}

// Supplies one fresh exact lease for every execution route fixture.
struct ProtectionMock {
    sequence: AtomicU64,
}

impl GatewayProtectionLeaseProvider for ProtectionMock {
    // Returns a current single-placement snapshot for the selected route.
    fn snapshot(
        &self,
        route: &GatewayRoute,
    ) -> Result<Option<GatewayPlacementProtectionSnapshot>, GatewayError> {
        let sequence = self.sequence.fetch_add(1, Ordering::SeqCst) + 1;
        let placement_id =
            PlacementId::parse(route.placement_group_id().as_str()).expect("placement identity");
        let core = InstallationId::parse(&identity('a', 64)).expect("Core");
        let watchdog = digest('b');
        let session = digest('c');
        let session_generation = NonZeroU64::new(1).expect("session generation");
        let lease = GatewayPlacementProtectionLease::new(
            route.endpoint_node_id().clone(),
            route.placement_group_id().clone(),
            placement_id.clone(),
            core.clone(),
            watchdog.clone(),
            session.clone(),
            session_generation,
            &identity('e', 32),
            TechnicalName::parse("li_placement_fixture").expect("container"),
            digest('f'),
            42,
            84,
            BootId::parse("12345678-1234-1234-1234-123456789abc").expect("boot"),
            "/sys/fs/cgroup/li_fixture",
            NonZeroU64::new(sequence).expect("sequence"),
            UnixMilliseconds::new(100_000),
            100_000,
            UnixMilliseconds::new(101_000),
            true,
            false,
        )?;
        Ok(Some(GatewayPlacementProtectionSnapshot::new(
            route.placement_group_id().clone(),
            vec![(placement_id, route.endpoint_node_id().clone())],
            vec![GatewayProtectionAuthority::new(
                route.endpoint_node_id().clone(),
                core,
                watchdog,
                session,
                session_generation,
            )],
            vec![lease],
        )?))
    }
}

// Supplies exact native macOS safety and allows deterministic loss before Engine forwarding.
struct MacOsSafetyMock {
    available: AtomicBool,
    calls: AtomicUsize,
}

impl GatewayMacOsPlacementSafetyProvider for MacOsSafetyMock {
    // Returns one complete local launchd process proof only while safety remains available.
    fn snapshot(
        &self,
        route: &GatewayRoute,
    ) -> Result<Option<GatewayMacOsPlacementSafetySnapshot>, GatewayError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if !self.available.load(Ordering::SeqCst) {
            return Ok(None);
        }
        let placement_id =
            PlacementId::parse(route.placement_group_id().as_str()).expect("placement identity");
        let lease = GatewayMacOsPlacementSafetyLease::new(
            route.endpoint_node_id().clone(),
            route.placement_group_id().clone(),
            placement_id.clone(),
            InstallationId::parse(&identity('a', 64)).expect("Core"),
            digest('b'),
            "ai.letsinfer.engine.fixture",
            digest('c'),
            42,
            UnixMilliseconds::new(99_000),
            UnixMilliseconds::new(100_000),
            UnixMilliseconds::new(101_000),
        )?;
        GatewayMacOsPlacementSafetySnapshot::new(
            route.placement_group_id().clone(),
            vec![(placement_id, route.endpoint_node_id().clone())],
            vec![lease],
        )
        .map(Some)
    }
}

// Discards deterministic telemetry without weakening its publication boundary.
struct TelemetryMock;

impl GatewayTelemetryPublisher for TelemetryMock {
    // Accepts one complete snapshot without adding test-observable behavior.
    fn publish_atomically(&self, _snapshot: &GatewayTelemetrySnapshot) -> Result<(), GatewayError> {
        Ok(())
    }
}

// Records completed exact usage and returns no prior rolling-window records.
#[derive(Default)]
struct UsageMock {
    records: Mutex<Vec<GatewayUsageRecord>>,
}

impl GatewayUsageStore for UsageMock {
    // Returns an empty deterministic restart window.
    fn recent(
        &self,
        _key_id: &ApiKeyId,
        _since: UnixMilliseconds,
    ) -> Result<Vec<GatewayUsageRecord>, GatewayError> {
        Ok(Vec::new())
    }

    // Appends one completed exact usage record.
    fn record(&self, usage: &GatewayUsageRecord) -> Result<(), GatewayError> {
        self.records
            .lock()
            .expect("usage records")
            .push(usage.clone());
        Ok(())
    }
}

// Describes one deterministic native execution attempt.
enum AttemptPlan {
    Complete {
        body: Vec<u8>,
        usage: GatewayExactUsage,
    },
    FailBefore(GatewayExecutionFailure),
    FailAfterHead(GatewayExecutionFailure),
    FailAfterBody(GatewayExecutionFailure),
    CompleteWithoutHead(GatewayExactUsage),
    OversizedBody,
}

// Replays exact attempt plans while recording route and request observations.
struct ExecutionProviderMock {
    plans: Mutex<VecDeque<AttemptPlan>>,
    placement_groups: Mutex<Vec<PlacementGroupId>>,
    paths: Mutex<Vec<&'static str>>,
    bodies: Mutex<Vec<Vec<u8>>>,
}

impl ExecutionProviderMock {
    // Creates one provider with a closed ordered attempt script.
    fn new(plans: Vec<AttemptPlan>) -> Self {
        Self {
            plans: Mutex::new(plans.into()),
            placement_groups: Mutex::new(Vec::new()),
            paths: Mutex::new(Vec::new()),
            bodies: Mutex::new(Vec::new()),
        }
    }

    // Returns one ordinary successful attempt plan.
    fn complete(input_tokens: u64, output_tokens: u64) -> AttemptPlan {
        AttemptPlan::Complete {
            body: b"{\"id\":\"completion\"}".to_vec(),
            usage: GatewayExactUsage::new(input_tokens, output_tokens, 2).expect("usage"),
        }
    }

    // Returns the number of native forwarding attempts made.
    fn call_count(&self) -> usize {
        self.placement_groups.lock().expect("groups").len()
    }
}

impl GatewayExecutionProvider for ExecutionProviderMock {
    // Replays one scripted attempt through the real bounded output boundary.
    fn forward(
        &self,
        route: &GatewayRoute,
        request: &GatewayChatCompletionRequest,
        response: &mut dyn GatewayResponseWriter,
    ) -> Result<GatewayExactUsage, GatewayExecutionFailure> {
        self.placement_groups
            .lock()
            .expect("groups")
            .push(route.placement_group_id().clone());
        self.paths.lock().expect("paths").push(request.path());
        self.bodies
            .lock()
            .expect("bodies")
            .push(request.body().to_vec());
        let plan = self
            .plans
            .lock()
            .expect("plans")
            .pop_front()
            .ok_or_else(|| GatewayExecutionFailure::terminal_backend("missing mock plan"))?;
        let head = response_head();
        match plan {
            AttemptPlan::Complete { body, usage } => {
                response.write_head(&head)?;
                response.write_body(&body)?;
                Ok(usage)
            }
            AttemptPlan::FailBefore(error) => Err(error),
            AttemptPlan::FailAfterHead(error) => {
                response.write_head(&head)?;
                Err(error)
            }
            AttemptPlan::FailAfterBody(error) => {
                response.write_head(&head)?;
                response.write_body(b"partial")?;
                Err(error)
            }
            AttemptPlan::CompleteWithoutHead(usage) => Ok(usage),
            AttemptPlan::OversizedBody => {
                response.write_head(&head)?;
                let megabyte = vec![b'x'; 1024 * 1024];
                for _ in 0..65 {
                    response.write_body(&megabyte)?;
                }
                unreachable!("bounded writer must reject the sixty-fifth MiB")
            }
        }
    }
}

// Waits without blocking when the manager never queues an execution request.
struct ImmediateQueueWaiter;

impl GatewayQueueWaiter for ImmediateQueueWaiter {
    // Fails if an ordinary immediate-admission test unexpectedly enters the queue.
    fn wait(&self, _ticket: &GatewayQueueTicket) -> Result<(), GatewayError> {
        Err(GatewayError::provider("queue_wait", "unexpected mock wait"))
    }
}

// Releases one fixture reservation or returns one injected native wait failure.
struct QueueWaiterMock {
    manager: Arc<GatewayManager>,
    release: Mutex<Option<GatewayReservation>>,
    calls: AtomicUsize,
    fail: bool,
}

impl GatewayQueueWaiter for QueueWaiterMock {
    // Performs exactly one deterministic queue-state transition.
    fn wait(&self, _ticket: &GatewayQueueTicket) -> Result<(), GatewayError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err(GatewayError::provider("queue_wait", "mock failure"));
        }
        if let Some(reservation) = self.release.lock().expect("release").take() {
            self.manager.cancel(reservation)?;
        }
        Ok(())
    }
}

// Records committed output and can inject a caller-side write failure.
#[derive(Default)]
struct ResponseWriterMock {
    heads: Vec<GatewayResponseHead>,
    body_bytes: usize,
    body_prefix: Vec<u8>,
    fail_head: bool,
    fail_body: bool,
    disconnected: bool,
}

impl GatewayResponseWriter for ResponseWriterMock {
    // Reports the test-controlled caller connection state during queue waits.
    fn client_is_connected(&mut self) -> Result<bool, GatewayExecutionFailure> {
        Ok(!self.disconnected)
    }

    // Records one response head or simulates a disconnected caller.
    fn write_head(&mut self, head: &GatewayResponseHead) -> Result<(), GatewayExecutionFailure> {
        if self.fail_head {
            return Err(GatewayExecutionFailure::client("mock client failure"));
        }
        self.heads.push(head.clone());
        Ok(())
    }

    // Records bounded byte counts without retaining a potentially large response.
    fn write_body(&mut self, body: &[u8]) -> Result<(), GatewayExecutionFailure> {
        if self.fail_body {
            return Err(GatewayExecutionFailure::client("mock client failure"));
        }
        self.body_bytes += body.len();
        if self.body_prefix.len() < 256 {
            let remaining = 256 - self.body_prefix.len();
            self.body_prefix
                .extend_from_slice(&body[..body.len().min(remaining)]);
        }
        Ok(())
    }
}

// Groups the manager with the providers observed by execution tests.
struct TestEnvironment {
    manager: Arc<GatewayManager>,
    authentication: Arc<AuthenticationMock>,
    usage: Arc<UsageMock>,
}

// Creates one complete deterministic Gateway composition.
fn environment(mode: GatewayMode, routes: Vec<GatewayRoute>) -> TestEnvironment {
    let authentication = Arc::new(AuthenticationMock {
        calls: AtomicUsize::new(0),
    });
    let usage = Arc::new(UsageMock::default());
    let manager = Arc::new(
        GatewayManager::new(
            mode,
            authentication.clone(),
            Arc::new(RelayAuthorizationMock),
            Arc::new(RouteMock { routes }),
            Arc::new(ProtectionMock {
                sequence: AtomicU64::new(0),
            }),
            Arc::new(ClockMock {
                now: AtomicU64::new(100_000),
            }),
            usage.clone(),
        )
        .expect("gateway"),
    );
    TestEnvironment {
        manager,
        authentication,
        usage,
    }
}

// Creates one macOS child composition using the native placement-safety authority.
fn macos_child_environment(
    routes: Vec<GatewayRoute>,
    safety: Arc<MacOsSafetyMock>,
) -> TestEnvironment {
    let authentication = Arc::new(AuthenticationMock {
        calls: AtomicUsize::new(0),
    });
    let usage = Arc::new(UsageMock::default());
    let manager = Arc::new(
        GatewayManager::new_with_macos_safety_and_telemetry(
            GatewayMode::Child {
                local_node_id: node_id('2'),
                main_node_id: node_id('1'),
            },
            authentication.clone(),
            Arc::new(RelayAuthorizationMock),
            Arc::new(RouteMock { routes }),
            safety,
            Arc::new(ClockMock {
                now: AtomicU64::new(100_000),
            }),
            usage.clone(),
            Arc::new(TelemetryMock),
        )
        .expect("gateway"),
    );
    TestEnvironment {
        manager,
        authentication,
        usage,
    }
}

// Returns one repeated canonical identity.
fn identity(character: char, length: usize) -> String {
    character.to_string().repeat(length)
}

// Returns one canonical node identity.
fn node_id(character: char) -> NodeId {
    NodeId::parse(&identity(character, 32)).expect("node")
}

// Returns one canonical placement-group identity.
fn placement_group_id(character: char) -> PlacementGroupId {
    PlacementGroupId::parse(&identity(character, 32)).expect("placement group")
}

// Returns one canonical API-key identity.
fn api_key_id(character: char) -> ApiKeyId {
    ApiKeyId::parse(&identity(character, 32)).expect("API key")
}

// Returns one canonical SHA-256 identity.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&identity(character, 64)).expect("digest")
}

// Returns the ordinary logical-model fixture.
fn model() -> LogicalModelName {
    LogicalModelName::parse("qwen3_8").expect("model")
}

// Returns one exact token-counted request.
fn request(character: char, queue_milliseconds: u64) -> GatewayRequest {
    GatewayRequest::new(
        digest(character),
        model(),
        NonZeroU64::new(10).expect("context"),
        NonZeroU64::new(10).expect("output"),
        None,
        queue_milliseconds,
    )
    .expect("request")
}

// Returns one bounded normalized chat-completions request.
fn chat_request(character: char, queue_milliseconds: u64) -> GatewayChatCompletionRequest {
    GatewayChatCompletionRequest::new(
        request(character, queue_milliseconds),
        b"{\"model\":\"qwen3_8\",\"messages\":[]}".to_vec(),
    )
    .expect("chat request")
}

// Returns one deterministic route with an explicit target and temperature.
fn route(
    group_character: char,
    node_character: char,
    capacity: u32,
    temperature_millicelsius: u32,
    target: GatewayRouteTarget,
) -> GatewayRoute {
    GatewayRoute::new(
        placement_group_id(group_character),
        node_id(node_character),
        model(),
        target,
        NonZeroU32::new(capacity).expect("capacity"),
        NonZeroU64::new(1_024).expect("context"),
        true,
        false,
        Some(temperature_millicelsius),
        Vec::new(),
    )
    .expect("route")
}

// Returns one local Engine route.
fn local_route(
    group_character: char,
    node_character: char,
    capacity: u32,
    temperature_millicelsius: u32,
) -> GatewayRoute {
    route(
        group_character,
        node_character,
        capacity,
        temperature_millicelsius,
        GatewayRouteTarget::LocalEngine {
            endpoint: EndpointAddress::new(
                EndpointScheme::Https,
                NodeAddress::parse("127.0.0.1").expect("address"),
                18_000,
            )
            .expect("endpoint"),
        },
    )
}

// Returns one validated ordinary OpenAI response head.
fn response_head() -> GatewayResponseHead {
    GatewayResponseHead::new(
        200,
        vec![GatewayResponseHeader::new("Content-Type", "application/json").expect("content type")],
    )
    .expect("response head")
}

// Creates one execution role from deterministic provider and waiter fixtures.
fn execution(
    manager: Arc<GatewayManager>,
    plans: Vec<AttemptPlan>,
    queue_waiter: Arc<dyn GatewayQueueWaiter>,
) -> (GatewayExecution, Arc<ExecutionProviderMock>) {
    let provider = Arc::new(ExecutionProviderMock::new(plans));
    (
        GatewayExecution::new(manager, provider.clone(), queue_waiter),
        provider,
    )
}

// Forwards one ordinary public request and records exact usage once.
#[test]
fn public_execution_forwards_only_chat_completions_and_records_exact_usage() {
    let environment = environment(
        GatewayMode::Main {
            local_node_id: node_id('1'),
        },
        vec![local_route('3', '1', 1, 40_000)],
    );
    let (execution, provider) = execution(
        environment.manager.clone(),
        vec![ExecutionProviderMock::complete(10, 4)],
        Arc::new(ImmediateQueueWaiter),
    );
    let mut response = ResponseWriterMock::default();

    let receipt = execution
        .forward_public("secret", chat_request('1', 0), &mut response)
        .expect("execution");

    assert_eq!(receipt.placement_group_id(), &placement_group_id('3'));
    assert_eq!(receipt.status_code(), 200);
    assert_eq!(receipt.attempt_count(), 1);
    assert_eq!(receipt.response_body_bytes(), 19);
    assert_eq!(receipt.usage().cached_tokens(), 2);
    assert_eq!(response.heads.len(), 1);
    assert_eq!(response.body_prefix, b"{\"id\":\"completion\"}");
    assert_eq!(
        provider.paths.lock().expect("paths").as_slice(),
        ["/v1/chat/completions"]
    );
    assert_eq!(
        provider.bodies.lock().expect("bodies")[0],
        chat_request('f', 0).body()
    );
    assert_eq!(environment.authentication.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        environment.usage.records.lock().expect("usage")[0].tokens(),
        14
    );
    assert_eq!(environment.manager.counts().expect("counts"), (0, 0));
}

// Waits through the manager-owned FIFO queue before executing exactly once.
#[test]
fn queued_execution_waits_for_capacity_without_owning_queue_policy() {
    let environment = environment(
        GatewayMode::Main {
            local_node_id: node_id('1'),
        },
        vec![local_route('3', '1', 1, 40_000)],
    );
    let GatewayAdmission::Admitted(blocker) = environment
        .manager
        .admit_public("secret", request('1', 0))
        .expect("blocker")
    else {
        panic!("blocker reservation");
    };
    let waiter = Arc::new(QueueWaiterMock {
        manager: environment.manager.clone(),
        release: Mutex::new(Some(blocker)),
        calls: AtomicUsize::new(0),
        fail: false,
    });
    let (execution, provider) = execution(
        environment.manager.clone(),
        vec![ExecutionProviderMock::complete(10, 3)],
        waiter.clone(),
    );
    let mut response = ResponseWriterMock::default();

    execution
        .forward_public("secret", chat_request('2', 1_000), &mut response)
        .expect("queued execution");

    assert_eq!(waiter.calls.load(Ordering::SeqCst), 1);
    assert_eq!(provider.call_count(), 1);
    assert_eq!(environment.manager.counts().expect("counts"), (0, 0));
}

// Retries one backend failure only while no response bytes are committed.
#[test]
fn retryable_pre_output_failure_moves_once_without_reauthentication() {
    let second = route(
        '4',
        '2',
        1,
        50_000,
        GatewayRouteTarget::ChildRelay {
            address: NodeAddress::parse("child.local").expect("child address"),
        },
    );
    let environment = environment(
        GatewayMode::Main {
            local_node_id: node_id('1'),
        },
        vec![local_route('3', '1', 1, 40_000), second],
    );
    let (execution, provider) = execution(
        environment.manager.clone(),
        vec![
            AttemptPlan::FailBefore(GatewayExecutionFailure::retryable_backend(
                "mock connection failure",
            )),
            ExecutionProviderMock::complete(10, 4),
        ],
        Arc::new(ImmediateQueueWaiter),
    );
    let mut response = ResponseWriterMock::default();

    let receipt = execution
        .forward_public("secret", chat_request('1', 0), &mut response)
        .expect("retried execution");

    assert_eq!(receipt.attempt_count(), 2);
    assert_eq!(receipt.placement_group_id(), &placement_group_id('4'));
    assert_eq!(response.heads.len(), 1);
    assert_eq!(environment.authentication.calls.load(Ordering::SeqCst), 1);
    assert_eq!(environment.usage.records.lock().expect("usage").len(), 1);
    assert_eq!(
        provider.placement_groups.lock().expect("groups").as_slice(),
        [placement_group_id('3'), placement_group_id('4')]
    );
}

// Never replays a request after either response headers or response bytes commit.
#[test]
fn committed_output_failure_matrix_never_retries() {
    for plan in [
        AttemptPlan::FailAfterHead(GatewayExecutionFailure::retryable_backend(
            "mock response failure",
        )),
        AttemptPlan::FailAfterBody(GatewayExecutionFailure::retryable_backend(
            "mock stream failure",
        )),
    ] {
        let environment = environment(
            GatewayMode::Main {
                local_node_id: node_id('1'),
            },
            vec![
                local_route('3', '1', 1, 40_000),
                local_route('4', '1', 1, 50_000),
            ],
        );
        let (execution, provider) = execution(
            environment.manager.clone(),
            vec![plan, ExecutionProviderMock::complete(10, 2)],
            Arc::new(ImmediateQueueWaiter),
        );
        let mut response = ResponseWriterMock::default();

        assert!(matches!(
            execution.forward_public("secret", chat_request('1', 0), &mut response),
            Err(GatewayError::Provider {
                capability: "execution_after_output",
                ..
            })
        ));
        assert_eq!(provider.call_count(), 1);
        assert_eq!(environment.manager.counts().expect("counts"), (0, 0));
        assert!(environment.usage.records.lock().expect("usage").is_empty());
    }
}

// Treats caller disconnection as terminal without cooling a healthy backend.
#[test]
fn client_output_failure_never_retries_or_changes_backend_health() {
    let environment = environment(
        GatewayMode::Main {
            local_node_id: node_id('1'),
        },
        vec![
            local_route('3', '1', 1, 40_000),
            local_route('4', '1', 1, 50_000),
        ],
    );
    let (execution, provider) = execution(
        environment.manager.clone(),
        vec![ExecutionProviderMock::complete(10, 2)],
        Arc::new(ImmediateQueueWaiter),
    );
    let mut response = ResponseWriterMock {
        fail_head: true,
        ..ResponseWriterMock::default()
    };

    assert!(matches!(
        execution.forward_public("secret", chat_request('1', 0), &mut response),
        Err(GatewayError::Provider {
            capability: "execution_before_output",
            ..
        })
    ));
    assert_eq!(provider.call_count(), 1);
    let GatewayAdmission::Admitted(reservation) = environment
        .manager
        .admit_public("secret", request('2', 0))
        .expect("subsequent admission")
    else {
        panic!("subsequent reservation");
    };
    assert_eq!(
        reservation.route().placement_group_id(),
        &placement_group_id('3')
    );
    environment.manager.cancel(reservation).expect("cancel");
}

// Cancels a still-owned queue ticket when the native wait mechanism fails.
#[test]
fn queue_wait_failure_releases_only_the_queued_request() {
    let environment = environment(
        GatewayMode::Main {
            local_node_id: node_id('1'),
        },
        vec![local_route('3', '1', 1, 40_000)],
    );
    let GatewayAdmission::Admitted(blocker) = environment
        .manager
        .admit_public("secret", request('1', 0))
        .expect("blocker")
    else {
        panic!("blocker reservation");
    };
    let waiter = Arc::new(QueueWaiterMock {
        manager: environment.manager.clone(),
        release: Mutex::new(None),
        calls: AtomicUsize::new(0),
        fail: true,
    });
    let (execution, provider) = execution(
        environment.manager.clone(),
        vec![ExecutionProviderMock::complete(10, 2)],
        waiter,
    );
    let mut response = ResponseWriterMock::default();

    assert!(matches!(
        execution.forward_public("secret", chat_request('2', 1_000), &mut response),
        Err(GatewayError::Provider {
            capability: "queue_wait",
            ..
        })
    ));
    assert_eq!(provider.call_count(), 0);
    assert_eq!(environment.manager.counts().expect("counts"), (1, 0));
    environment.manager.cancel(blocker).expect("cancel blocker");
}

// Cancels a queued request immediately when its caller socket is already disconnected.
#[test]
fn queued_client_disconnect_releases_capacity_without_waiting_or_forwarding() {
    let environment = environment(
        GatewayMode::Main {
            local_node_id: node_id('1'),
        },
        vec![local_route('3', '1', 1, 40_000)],
    );
    let GatewayAdmission::Admitted(blocker) = environment
        .manager
        .admit_public("secret", request('1', 0))
        .expect("blocker")
    else {
        panic!("blocker reservation");
    };
    let waiter = Arc::new(QueueWaiterMock {
        manager: environment.manager.clone(),
        release: Mutex::new(None),
        calls: AtomicUsize::new(0),
        fail: false,
    });
    let (execution, provider) = execution(
        environment.manager.clone(),
        vec![ExecutionProviderMock::complete(10, 2)],
        waiter.clone(),
    );
    let mut response = ResponseWriterMock {
        disconnected: true,
        ..ResponseWriterMock::default()
    };

    assert!(matches!(
        execution.forward_public("secret", chat_request('2', 1_000), &mut response),
        Err(GatewayError::Provider {
            capability: "queue_wait",
            ..
        })
    ));
    assert_eq!(waiter.calls.load(Ordering::SeqCst), 0);
    assert_eq!(provider.call_count(), 0);
    assert_eq!(environment.manager.counts().expect("counts"), (1, 0));
    environment.manager.cancel(blocker).expect("cancel blocker");
}

// Rejects unsafe request, usage, header, and response-size boundaries deterministically.
#[test]
fn forwarding_bounds_fail_closed_without_leaking_capacity() {
    assert!(GatewayChatCompletionRequest::new(request('1', 0), Vec::new()).is_err());
    assert!(
        GatewayChatCompletionRequest::new(request('2', 0), vec![b'x'; 32 * 1024 * 1024 + 1])
            .is_err()
    );
    assert!(GatewayExactUsage::new(1, 1, 2).is_err());
    assert!(GatewayExactUsage::new(u64::MAX, 1, 0).is_err());
    assert!(GatewayResponseHeader::new("Connection", "close").is_err());
    let duplicate = GatewayResponseHeader::new("x-test", "one").expect("header");
    assert!(GatewayResponseHead::new(200, vec![duplicate.clone(), duplicate]).is_err());

    let environment = environment(
        GatewayMode::Main {
            local_node_id: node_id('1'),
        },
        vec![local_route('3', '1', 1, 40_000)],
    );
    let (execution, provider) = execution(
        environment.manager.clone(),
        vec![AttemptPlan::OversizedBody],
        Arc::new(ImmediateQueueWaiter),
    );
    let mut response = ResponseWriterMock::default();
    assert!(matches!(
        execution.forward_public("secret", chat_request('3', 0), &mut response),
        Err(GatewayError::Provider {
            capability: "execution_after_output",
            ..
        })
    ));
    assert_eq!(provider.call_count(), 1);
    assert_eq!(response.body_bytes, 64 * 1024 * 1024);
    assert_eq!(environment.manager.counts().expect("counts"), (0, 0));
}

// Rejects provider completion without output or usage matching the admitted envelope.
#[test]
fn provider_completion_contract_failure_matrix_releases_reservations() {
    let invalid_usage = GatewayExactUsage::new(9, 2, 0).expect("usage shape");
    for plan in [
        AttemptPlan::CompleteWithoutHead(GatewayExactUsage::new(10, 2, 0).expect("usage")),
        AttemptPlan::Complete {
            body: b"{}".to_vec(),
            usage: invalid_usage,
        },
    ] {
        let environment = environment(
            GatewayMode::Main {
                local_node_id: node_id('1'),
            },
            vec![local_route('3', '1', 1, 40_000)],
        );
        let (execution, _) = execution(
            environment.manager.clone(),
            vec![plan],
            Arc::new(ImmediateQueueWaiter),
        );
        let mut response = ResponseWriterMock::default();
        assert!(execution
            .forward_public("secret", chat_request('1', 0), &mut response)
            .is_err());
        assert_eq!(environment.manager.counts().expect("counts"), (0, 0));
        assert!(environment.usage.records.lock().expect("usage").is_empty());
    }
}

// Forwards the same execution contract through an authenticated child-private surface.
#[test]
fn child_execution_accepts_only_the_main_relay_surface() {
    let environment = environment(
        GatewayMode::Child {
            local_node_id: node_id('2'),
            main_node_id: node_id('1'),
        },
        vec![local_route('3', '2', 1, 40_000)],
    );
    let (execution, provider) = execution(
        environment.manager.clone(),
        vec![ExecutionProviderMock::complete(10, 2)],
        Arc::new(ImmediateQueueWaiter),
    );
    let mut response = ResponseWriterMock::default();

    assert!(matches!(
        execution.forward_public("secret", chat_request('1', 0), &mut response),
        Err(GatewayError::PublicUnavailableOnChild)
    ));
    execution
        .forward_relay("relay", chat_request('2', 0), &mut response)
        .expect("relay execution");
    assert_eq!(provider.call_count(), 1);
    assert!(environment.usage.records.lock().expect("usage").is_empty());
    assert_eq!(environment.manager.counts().expect("counts"), (0, 0));
}

// Repeats local native safety admission on an authenticated child before Engine forwarding.
#[test]
fn child_execution_requires_current_macos_safety_before_engine_forwarding() {
    let safety = Arc::new(MacOsSafetyMock {
        available: AtomicBool::new(false),
        calls: AtomicUsize::new(0),
    });
    let environment =
        macos_child_environment(vec![local_route('3', '2', 1, 40_000)], safety.clone());
    let (execution, provider) = execution(
        environment.manager.clone(),
        vec![ExecutionProviderMock::complete(10, 2)],
        Arc::new(ImmediateQueueWaiter),
    );
    let mut response = ResponseWriterMock::default();

    assert!(matches!(
        execution.forward_relay("relay", chat_request('1', 0), &mut response),
        Err(GatewayError::NoRoute)
    ));
    assert_eq!(provider.call_count(), 0);
    safety.available.store(true, Ordering::SeqCst);
    execution
        .forward_relay("relay", chat_request('2', 0), &mut response)
        .expect("protected relay execution");
    assert_eq!(safety.calls.load(Ordering::SeqCst), 2);
    assert_eq!(provider.call_count(), 1);
}
