// SPDX-License-Identifier: AGPL-3.0-only

use std::num::NonZeroU64;
use std::sync::{Arc, Mutex};

use li_core_interface::{LogicalModelName, Sha256Digest};
use li_gateway_manager::{
    GatewayChatCompletionRequest, GatewayError, GatewayExecutionFailure, GatewayHttpError,
    GatewayHttpExecutionProvider, GatewayHttpHandler, GatewayHttpHealthProvider, GatewayHttpMethod,
    GatewayHttpModelList, GatewayHttpModelListProvider, GatewayHttpModelProvider,
    GatewayHttpOutcome, GatewayHttpRelayTokenProvider, GatewayHttpRequest,
    GatewayHttpRequestIdProvider, GatewayHttpSurface, GatewayHttpTokenProvider,
    GatewayResponseHead, GatewayResponseHeader, GatewayResponseWriter,
    LETSINFER_RELAY_TOKEN_COUNT_PATH,
};
use serde_json::Value;

const REQUEST_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

// Records the normalized model name requested from the resolver.
struct MockModelProvider {
    calls: Mutex<Vec<String>>,
    result: Result<LogicalModelName, GatewayHttpError>,
}

impl MockModelProvider {
    // Creates one deterministic model resolver.
    fn new(result: Result<LogicalModelName, GatewayHttpError>) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            result,
        }
    }
}

impl GatewayHttpModelProvider for MockModelProvider {
    // Records the requested alias and returns its configured canonical result.
    fn resolve(&self, requested_model: &str) -> Result<LogicalModelName, GatewayHttpError> {
        self.calls.lock().unwrap().push(requested_model.to_string());
        self.result.clone()
    }
}

// Records readiness reads and returns one deterministic health result.
struct MockHealthProvider {
    calls: Mutex<u32>,
    result: Result<bool, GatewayHttpError>,
}

impl GatewayHttpHealthProvider for MockHealthProvider {
    // Returns configured readiness after recording the public read.
    fn health(&self) -> Result<bool, GatewayHttpError> {
        *self.calls.lock().unwrap() += 1;
        self.result.clone()
    }
}

// Records authenticated discovery calls and returns one bounded model snapshot.
struct MockModelListProvider {
    calls: Mutex<Vec<String>>,
    result: Result<GatewayHttpModelList, GatewayHttpError>,
}

impl GatewayHttpModelListProvider for MockModelListProvider {
    // Records the bearer privately for the test and returns the configured snapshot.
    fn models(&self, bearer_token: &str) -> Result<GatewayHttpModelList, GatewayHttpError> {
        self.calls.lock().unwrap().push(bearer_token.to_string());
        self.result.clone()
    }
}

// Records the exact canonical body sent through token counting.
struct MockTokenProvider {
    bodies: Mutex<Vec<(String, Vec<u8>)>>,
    result: Result<NonZeroU64, GatewayHttpError>,
}

impl MockTokenProvider {
    // Creates one deterministic exact-token provider.
    fn new(result: Result<NonZeroU64, GatewayHttpError>) -> Self {
        Self {
            bodies: Mutex::new(Vec::new()),
            result,
        }
    }
}

impl GatewayHttpTokenProvider for MockTokenProvider {
    // Records the normalized request and returns the configured exact count.
    fn count(
        &self,
        _bearer_token: &str,
        model: &LogicalModelName,
        normalized_body: &[u8],
    ) -> Result<NonZeroU64, GatewayHttpError> {
        self.bodies
            .lock()
            .unwrap()
            .push((model.as_str().to_string(), normalized_body.to_vec()));
        self.result.clone()
    }
}

// Records authenticated child token-count calls independently of public preparation.
struct MockRelayTokenProvider {
    calls: Mutex<Vec<(String, String, Vec<u8>)>>,
    result: Result<NonZeroU64, GatewayHttpError>,
}

impl GatewayHttpRelayTokenProvider for MockRelayTokenProvider {
    // Records the relay credential, canonical model, and normalized body.
    fn count(
        &self,
        relay_credential: &str,
        model: &LogicalModelName,
        normalized_body: &[u8],
    ) -> Result<NonZeroU64, GatewayHttpError> {
        self.calls.lock().unwrap().push((
            relay_credential.to_string(),
            model.as_str().to_string(),
            normalized_body.to_vec(),
        ));
        self.result.clone()
    }
}

// Returns a fixed collision-resistant request identity.
struct MockRequestIdProvider {
    calls: Mutex<u32>,
    result: Result<Sha256Digest, GatewayHttpError>,
}

impl MockRequestIdProvider {
    // Creates one deterministic request-identity provider.
    fn new(result: Result<Sha256Digest, GatewayHttpError>) -> Self {
        Self {
            calls: Mutex::new(0),
            result,
        }
    }
}

impl GatewayHttpRequestIdProvider for MockRequestIdProvider {
    // Counts requests and returns the configured identity.
    fn next(&self) -> Result<Sha256Digest, GatewayHttpError> {
        *self.calls.lock().unwrap() += 1;
        self.result.clone()
    }
}

// Describes one deterministic execution outcome around the response boundary.
#[derive(Clone)]
enum MockExecutionPlan {
    Success,
    FailureBefore(GatewayError),
    FailureAfter(GatewayError),
}

// Records public and relay forwarding without using live managers or sockets.
struct MockExecutionProvider {
    calls: Mutex<Vec<(GatewayHttpSurface, String, GatewayChatCompletionRequest)>>,
    plan: MockExecutionPlan,
}

impl MockExecutionProvider {
    // Creates one deterministic forwarding mock.
    fn new(plan: MockExecutionPlan) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            plan,
        }
    }

    // Runs the configured output and failure sequence.
    fn forward(
        &self,
        surface: GatewayHttpSurface,
        credential: &str,
        request: GatewayChatCompletionRequest,
        response: &mut dyn GatewayResponseWriter,
    ) -> Result<(), GatewayError> {
        self.calls
            .lock()
            .unwrap()
            .push((surface, credential.to_string(), request));
        match &self.plan {
            MockExecutionPlan::FailureBefore(error) => return Err(error.clone()),
            MockExecutionPlan::Success | MockExecutionPlan::FailureAfter(_) => {}
        }
        let head = GatewayResponseHead::new(
            200,
            vec![GatewayResponseHeader::new("content-type", "application/json").unwrap()],
        )
        .unwrap();
        response
            .write_head(&head)
            .map_err(|_| GatewayError::provider("client", "response head failed"))?;
        response
            .write_body(br#"{"ok":true}"#)
            .map_err(|_| GatewayError::provider("client", "response body failed"))?;
        match &self.plan {
            MockExecutionPlan::FailureAfter(error) => Err(error.clone()),
            MockExecutionPlan::Success => Ok(()),
            MockExecutionPlan::FailureBefore(_) => unreachable!(),
        }
    }
}

impl GatewayHttpExecutionProvider for MockExecutionProvider {
    // Records one public forwarding call.
    fn forward_public(
        &self,
        bearer_token: &str,
        request: GatewayChatCompletionRequest,
        response: &mut dyn GatewayResponseWriter,
    ) -> Result<(), GatewayError> {
        self.forward(GatewayHttpSurface::Public, bearer_token, request, response)
    }

    // Records one private relay forwarding call.
    fn forward_relay(
        &self,
        relay_credential: &str,
        request: GatewayChatCompletionRequest,
        response: &mut dyn GatewayResponseWriter,
    ) -> Result<(), GatewayError> {
        self.forward(
            GatewayHttpSurface::PrivateRelay,
            relay_credential,
            request,
            response,
        )
    }
}

// Captures ordered response output and can simulate a disconnected client.
#[derive(Default)]
struct MockResponseWriter {
    heads: Vec<GatewayResponseHead>,
    body: Vec<u8>,
    fail_head: bool,
    fail_body: bool,
}

impl GatewayResponseWriter for MockResponseWriter {
    // Records or rejects one response head.
    fn write_head(&mut self, head: &GatewayResponseHead) -> Result<(), GatewayExecutionFailure> {
        if self.fail_head {
            return Err(GatewayExecutionFailure::client("client closed before head"));
        }
        self.heads.push(head.clone());
        Ok(())
    }

    // Records or rejects one response body fragment.
    fn write_body(&mut self, body: &[u8]) -> Result<(), GatewayExecutionFailure> {
        if self.fail_body {
            return Err(GatewayExecutionFailure::client("client closed during body"));
        }
        self.body.extend_from_slice(body);
        Ok(())
    }
}

// Creates one canonical model used across request-boundary tests.
fn model() -> LogicalModelName {
    LogicalModelName::parse("model-a").unwrap()
}

// Creates one deterministic handler and returns its inspectable providers.
fn handler(
    surface: GatewayHttpSurface,
    token_result: Result<NonZeroU64, GatewayHttpError>,
    execution_plan: MockExecutionPlan,
) -> (
    GatewayHttpHandler,
    Arc<MockModelProvider>,
    Arc<MockTokenProvider>,
    Arc<MockRequestIdProvider>,
    Arc<MockExecutionProvider>,
) {
    let models = Arc::new(MockModelProvider::new(Ok(model())));
    let tokens = Arc::new(MockTokenProvider::new(token_result));
    let request_ids = Arc::new(MockRequestIdProvider::new(Ok(Sha256Digest::parse(
        REQUEST_ID,
    )
    .unwrap())));
    let execution = Arc::new(MockExecutionProvider::new(execution_plan));
    let handler = GatewayHttpHandler::new(
        surface,
        2_000,
        models.clone(),
        tokens.clone(),
        request_ids.clone(),
        execution.clone(),
    )
    .unwrap();
    (handler, models, tokens, request_ids, execution)
}

// Creates one complete public-read handler and its inspectable providers.
fn public_read_handler(
    health_result: Result<bool, GatewayHttpError>,
    model_result: Result<GatewayHttpModelList, GatewayHttpError>,
) -> (
    GatewayHttpHandler,
    Arc<MockHealthProvider>,
    Arc<MockModelListProvider>,
) {
    let models = Arc::new(MockModelProvider::new(Ok(model())));
    let health = Arc::new(MockHealthProvider {
        calls: Mutex::new(0),
        result: health_result,
    });
    let model_list = Arc::new(MockModelListProvider {
        calls: Mutex::new(Vec::new()),
        result: model_result,
    });
    let tokens = Arc::new(MockTokenProvider::new(Ok(NonZeroU64::new(1).unwrap())));
    let request_ids = Arc::new(MockRequestIdProvider::new(Ok(Sha256Digest::parse(
        REQUEST_ID,
    )
    .unwrap())));
    let execution = Arc::new(MockExecutionProvider::new(MockExecutionPlan::Success));
    let handler = GatewayHttpHandler::new_with_public_reads(
        2_000,
        models,
        health.clone(),
        model_list.clone(),
        tokens,
        request_ids,
        execution,
    )
    .unwrap();
    (handler, health, model_list)
}

// Creates one ordinary authenticated JSON request.
fn request(body: &[u8]) -> GatewayHttpRequest {
    GatewayHttpRequest::new(
        GatewayHttpMethod::Post,
        "/v1/chat/completions",
        vec![
            (
                "Authorization".to_string(),
                "Bearer private-value".to_string(),
            ),
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Content-Length".to_string(), body.len().to_string()),
        ],
        body.to_vec(),
    )
    .unwrap()
}

// Parses one client error body for stable contract assertions.
fn error_document(response: &MockResponseWriter) -> Value {
    serde_json::from_slice(&response.body).unwrap()
}

// Creates one bounded bodyless public GET with an optional bearer.
fn get_request(path: &str, bearer: Option<&str>) -> GatewayHttpRequest {
    let headers = bearer
        .map(|value| vec![("Authorization".to_string(), format!("Bearer {value}"))])
        .unwrap_or_default();
    GatewayHttpRequest::new(GatewayHttpMethod::Get, path, headers, Vec::new()).unwrap()
}

// Proves public preparation normalizes aliases before exact counting and execution.
#[test]
fn public_request_is_normalized_counted_and_forwarded_once() {
    let (handler, models, tokens, request_ids, execution) = handler(
        GatewayHttpSurface::Public,
        Ok(NonZeroU64::new(12).unwrap()),
        MockExecutionPlan::Success,
    );
    let body = br#"{"model":"alias-a","messages":[],"max_tokens":8,"prompt_cache_key":"prefix-a"}"#;
    let mut response = MockResponseWriter::default();

    let outcome = handler.handle(&request(body), &mut response).unwrap();

    assert_eq!(outcome, GatewayHttpOutcome::Forwarded);
    assert_eq!(models.calls.lock().unwrap().as_slice(), ["alias-a"]);
    let token_calls = tokens.bodies.lock().unwrap();
    assert_eq!(token_calls.len(), 1);
    assert_eq!(token_calls[0].0, "model-a");
    let normalized: Value = serde_json::from_slice(&token_calls[0].1).unwrap();
    assert_eq!(normalized["model"], "model-a");
    assert_eq!(*request_ids.calls.lock().unwrap(), 1);
    let calls = execution.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, GatewayHttpSurface::Public);
    assert_eq!(calls[0].1, "private-value");
    assert_eq!(calls[0].2.request().context_tokens().get(), 12);
    assert_eq!(calls[0].2.request().maximum_output_tokens().get(), 8);
    assert!(calls[0].2.request().prefix_key().is_some());
    assert_eq!(response.heads[0].status_code(), 200);
}

// Proves the private surface uses only the relay execution entry point.
#[test]
fn private_surface_forwards_only_through_relay_authorization() {
    let (handler, _, _, _, execution) = handler(
        GatewayHttpSurface::PrivateRelay,
        Ok(NonZeroU64::new(4).unwrap()),
        MockExecutionPlan::Success,
    );
    let mut response = MockResponseWriter::default();

    let outcome = handler
        .handle(
            &request(br#"{"model":"model-a","messages":[],"max_completion_tokens":2}"#),
            &mut response,
        )
        .unwrap();

    assert_eq!(outcome, GatewayHttpOutcome::Forwarded);
    let calls = execution.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, GatewayHttpSurface::PrivateRelay);
}

// Proves only the private surface exposes the fixed authenticated token-count relay path.
#[test]
fn private_token_count_relay_is_fixed_authenticated_and_exact() {
    let models = Arc::new(MockModelProvider::new(Ok(model())));
    let tokens = Arc::new(MockTokenProvider::new(Ok(NonZeroU64::new(99).unwrap())));
    let relay_tokens = Arc::new(MockRelayTokenProvider {
        calls: Mutex::new(Vec::new()),
        result: Ok(NonZeroU64::new(12).unwrap()),
    });
    let request_ids = Arc::new(MockRequestIdProvider::new(Ok(Sha256Digest::parse(
        REQUEST_ID,
    )
    .unwrap())));
    let execution = Arc::new(MockExecutionProvider::new(MockExecutionPlan::Success));
    let handler = GatewayHttpHandler::new_with_relay_tokens(
        GatewayHttpSurface::PrivateRelay,
        0,
        models,
        tokens.clone(),
        Some(relay_tokens.clone()),
        request_ids.clone(),
        execution.clone(),
    )
    .unwrap();
    let body = br#"{"model":"alias-a","messages":[{"role":"user","content":"hello"}]}"#;
    let request = GatewayHttpRequest::new(
        GatewayHttpMethod::Post,
        LETSINFER_RELAY_TOKEN_COUNT_PATH,
        vec![
            (
                "authorization".to_string(),
                "Bearer relay-value".to_string(),
            ),
            ("content-type".to_string(), "application/json".to_string()),
        ],
        body.to_vec(),
    )
    .unwrap();
    let mut response = MockResponseWriter::default();

    let outcome = handler.handle(&request, &mut response).unwrap();

    assert_eq!(outcome, GatewayHttpOutcome::TokenCounted);
    assert!(tokens.bodies.lock().unwrap().is_empty());
    assert_eq!(*request_ids.calls.lock().unwrap(), 0);
    assert!(execution.calls.lock().unwrap().is_empty());
    let calls = relay_tokens.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "relay-value");
    assert_eq!(calls[0].1, "model-a");
    let normalized: Value = serde_json::from_slice(&calls[0].2).unwrap();
    assert_eq!(normalized["model"], "model-a");
    let response_document: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(response_document["object"], "token_count");
    assert_eq!(response_document["model"], "model-a");
    assert_eq!(response_document["prompt_tokens"], 12);

    let public = GatewayHttpHandler::new(
        GatewayHttpSurface::Public,
        0,
        Arc::new(MockModelProvider::new(Ok(model()))),
        tokens,
        request_ids,
        execution,
    )
    .unwrap();
    let mut public_response = MockResponseWriter::default();
    assert_eq!(
        public.handle(&request, &mut public_response).unwrap(),
        GatewayHttpOutcome::Rejected { status_code: 404 }
    );
}

// Proves distinct malformed request boundaries fail before token counting or execution.
#[test]
fn malformed_request_matrix_fails_before_admission() {
    let cases = [
        (
            GatewayHttpMethod::Get,
            "/v1/chat/completions",
            "application/json",
            br#"{"model":"model-a","max_tokens":1}"#.as_slice(),
            404,
        ),
        (
            GatewayHttpMethod::Post,
            "/v1/other",
            "application/json",
            br#"{"model":"model-a","max_tokens":1}"#.as_slice(),
            404,
        ),
        (
            GatewayHttpMethod::Post,
            "/v1/chat/completions",
            "text/plain",
            br#"{"model":"model-a","max_tokens":1}"#.as_slice(),
            415,
        ),
        (
            GatewayHttpMethod::Post,
            "/v1/chat/completions",
            "application/json",
            br#"{"model":"model-a","max_tokens":0}"#.as_slice(),
            400,
        ),
        (
            GatewayHttpMethod::Post,
            "/v1/chat/completions",
            "application/json",
            br#"{"model":"model-a","max_tokens":2,"max_completion_tokens":3}"#.as_slice(),
            400,
        ),
    ];
    for (method, path, content_type, body, expected_status) in cases {
        let (handler, _, tokens, request_ids, execution) = handler(
            GatewayHttpSurface::Public,
            Ok(NonZeroU64::new(1).unwrap()),
            MockExecutionPlan::Success,
        );
        let request = GatewayHttpRequest::new(
            method,
            path,
            vec![
                ("authorization".to_string(), "Bearer value".to_string()),
                ("content-type".to_string(), content_type.to_string()),
            ],
            body.to_vec(),
        )
        .unwrap();
        let mut response = MockResponseWriter::default();

        let outcome = handler.handle(&request, &mut response).unwrap();

        assert_eq!(
            outcome,
            GatewayHttpOutcome::Rejected {
                status_code: expected_status
            }
        );
        assert!(tokens.bodies.lock().unwrap().is_empty());
        assert_eq!(*request_ids.calls.lock().unwrap(), 0);
        assert!(execution.calls.lock().unwrap().is_empty());
    }
}

// Proves ambiguous headers, length mismatches, and unsafe metadata fail closed.
#[test]
fn http_metadata_contract_rejects_ambiguous_input() {
    let duplicate = GatewayHttpRequest::new(
        GatewayHttpMethod::Post,
        "/v1/chat/completions",
        vec![
            ("Authorization".to_string(), "Bearer a".to_string()),
            ("authorization".to_string(), "Bearer b".to_string()),
        ],
        vec![1],
    );
    assert_eq!(duplicate.unwrap_err().code(), "invalid_request");

    let body = br#"{"model":"model-a","max_tokens":1}"#;
    let mismatch = GatewayHttpRequest::new(
        GatewayHttpMethod::Post,
        "/v1/chat/completions",
        vec![
            ("authorization".to_string(), "Bearer a".to_string()),
            ("content-type".to_string(), "application/json".to_string()),
            ("content-length".to_string(), "1".to_string()),
        ],
        body.to_vec(),
    )
    .unwrap();
    let (handler, _, _, _, _) = handler(
        GatewayHttpSurface::Public,
        Ok(NonZeroU64::new(1).unwrap()),
        MockExecutionPlan::Success,
    );
    let mut response = MockResponseWriter::default();
    assert_eq!(
        handler.handle(&mismatch, &mut response).unwrap(),
        GatewayHttpOutcome::Rejected { status_code: 400 }
    );
}

// Proves exact-token failure never allocates a request identity or execution reservation.
#[test]
fn exact_token_failure_stops_before_execution() {
    let (handler, _, _, request_ids, execution) = handler(
        GatewayHttpSurface::Public,
        Err(GatewayHttpError::new(
            503,
            "exact_context_unavailable",
            "exact token counting is unavailable",
        )),
        MockExecutionPlan::Success,
    );
    let mut response = MockResponseWriter::default();

    let outcome = handler
        .handle(
            &request(br#"{"model":"model-a","messages":[],"max_tokens":2}"#),
            &mut response,
        )
        .unwrap();

    assert_eq!(outcome, GatewayHttpOutcome::Rejected { status_code: 503 });
    assert_eq!(*request_ids.calls.lock().unwrap(), 0);
    assert!(execution.calls.lock().unwrap().is_empty());
    assert_eq!(
        error_document(&response)["error"]["type"],
        "exact_context_unavailable"
    );
}

// Proves manager policy failures map to stable redacted HTTP categories.
#[test]
fn gateway_failure_categories_are_stable_and_redacted() {
    let cases = [
        (GatewayError::AuthenticationDenied, 401, "unauthorized"),
        (GatewayError::RequestRateLimit, 429, "rate_limit_exceeded"),
        (
            GatewayError::ContextTooLarge,
            400,
            "context_length_exceeded",
        ),
        (
            GatewayError::provider("secret-capability", "secret-value"),
            503,
            "placement_unavailable",
        ),
    ];
    for (failure, expected_status, expected_code) in cases {
        let (handler, _, _, _, _) = handler(
            GatewayHttpSurface::Public,
            Ok(NonZeroU64::new(2).unwrap()),
            MockExecutionPlan::FailureBefore(failure),
        );
        let mut response = MockResponseWriter::default();

        let outcome = handler
            .handle(
                &request(br#"{"model":"model-a","messages":[],"max_tokens":2}"#),
                &mut response,
            )
            .unwrap();

        assert_eq!(
            outcome,
            GatewayHttpOutcome::Rejected {
                status_code: expected_status
            }
        );
        let document = error_document(&response);
        assert_eq!(document["error"]["type"], expected_code);
        let text = String::from_utf8(response.body).unwrap();
        assert!(!text.contains("secret-capability"));
        assert!(!text.contains("secret-value"));
        assert!(!text.contains("private-value"));
    }
}

// Proves failures after response commitment never append a second JSON response.
#[test]
fn committed_backend_failure_terminates_without_replay() {
    let (handler, _, _, _, _) = handler(
        GatewayHttpSurface::Public,
        Ok(NonZeroU64::new(2).unwrap()),
        MockExecutionPlan::FailureAfter(GatewayError::provider(
            "execution_after_output",
            "backend closed",
        )),
    );
    let mut response = MockResponseWriter::default();

    let outcome = handler
        .handle(
            &request(br#"{"model":"model-a","messages":[],"max_tokens":2}"#),
            &mut response,
        )
        .unwrap();

    assert_eq!(outcome, GatewayHttpOutcome::TerminatedAfterOutput);
    assert_eq!(response.heads.len(), 1);
    assert_eq!(response.body, br#"{"ok":true}"#);
}

// Proves a client write failure closes the request without another response attempt.
#[test]
fn disconnected_client_is_terminal_without_error_replay() {
    let (handler, _, _, _, _) = handler(
        GatewayHttpSurface::Public,
        Ok(NonZeroU64::new(2).unwrap()),
        MockExecutionPlan::Success,
    );
    let mut response = MockResponseWriter {
        fail_head: true,
        ..MockResponseWriter::default()
    };

    let outcome = handler
        .handle(
            &request(br#"{"model":"model-a","messages":[],"max_tokens":2}"#),
            &mut response,
        )
        .unwrap();

    assert_eq!(outcome, GatewayHttpOutcome::ClientDisconnected);
    assert!(response.heads.is_empty());
    assert!(response.body.is_empty());
}

// Proves readiness is unauthenticated, fixed, fail-closed, and framing-safe.
#[test]
fn public_health_reports_current_readiness_without_leaking_provider_failures() {
    for (result, status_code, status) in [
        (Ok(true), 200, "ok"),
        (Ok(false), 503, "degraded"),
        (
            Err(GatewayHttpError::new(500, "private", "sensitive detail")),
            503,
            "degraded",
        ),
    ] {
        let (handler, health, _) = public_read_handler(
            result,
            Ok(GatewayHttpModelList::new(1, Vec::new()).unwrap()),
        );
        let mut response = MockResponseWriter::default();

        let outcome = handler
            .handle(&get_request("/health", None), &mut response)
            .unwrap();

        assert_eq!(outcome, GatewayHttpOutcome::HealthReported);
        assert_eq!(response.heads[0].status_code(), status_code);
        assert_eq!(
            serde_json::from_slice::<Value>(&response.body).unwrap(),
            serde_json::json!({"status": status})
        );
        assert_eq!(*health.calls.lock().unwrap(), 1);
    }

    let (handler, health, _) = public_read_handler(
        Ok(true),
        Ok(GatewayHttpModelList::new(1, Vec::new()).unwrap()),
    );
    let malformed = GatewayHttpRequest::new(
        GatewayHttpMethod::Get,
        "/health",
        vec![("Content-Length".to_string(), "1".to_string())],
        b"x".to_vec(),
    )
    .unwrap();
    let mut response = MockResponseWriter::default();
    assert_eq!(
        handler.handle(&malformed, &mut response).unwrap(),
        GatewayHttpOutcome::Rejected { status_code: 400 }
    );
    assert_eq!(*health.calls.lock().unwrap(), 0);
}

// Proves model discovery authenticates once and emits stable sorted OpenAI rows.
#[test]
fn public_model_discovery_is_authenticated_filtered_and_stably_ordered() {
    let snapshot = GatewayHttpModelList::new(
        88,
        vec![
            LogicalModelName::parse("model-b").unwrap(),
            LogicalModelName::parse("alias-a").unwrap(),
        ],
    )
    .unwrap();
    let (handler, _, models) = public_read_handler(Ok(true), Ok(snapshot));
    let mut response = MockResponseWriter::default();

    let outcome = handler
        .handle(
            &get_request("/v1/models", Some("private-value")),
            &mut response,
        )
        .unwrap();

    assert_eq!(outcome, GatewayHttpOutcome::ModelsListed);
    assert_eq!(response.heads[0].status_code(), 200);
    let document: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(document["object"], "list");
    assert_eq!(document["data"][0]["id"], "alias-a");
    assert_eq!(document["data"][1]["id"], "model-b");
    assert_eq!(document["data"][0]["created"], 88);
    assert_eq!(document["data"][0]["owned_by"], "letsinfer");
    assert_eq!(models.calls.lock().unwrap().as_slice(), ["private-value"]);

    let mut denied = MockResponseWriter::default();
    assert_eq!(
        handler
            .handle(&get_request("/v1/models", None), &mut denied)
            .unwrap(),
        GatewayHttpOutcome::Rejected { status_code: 401 }
    );
    assert_eq!(models.calls.lock().unwrap().len(), 1);
}

// Proves discovery snapshots reject ambiguity and remain absent on a child surface.
#[test]
fn model_discovery_contract_is_unique_bounded_and_public_only() {
    assert!(GatewayHttpModelList::new(1, vec![model(), model()]).is_err());
    let too_many = (0..4_097)
        .map(|index| LogicalModelName::parse(&format!("model-{index}")).unwrap())
        .collect();
    assert!(GatewayHttpModelList::new(1, too_many).is_err());

    let (handler, _, _, _, _) = handler(
        GatewayHttpSurface::PrivateRelay,
        Ok(NonZeroU64::new(1).unwrap()),
        MockExecutionPlan::Success,
    );
    let mut response = MockResponseWriter::default();
    assert_eq!(
        handler
            .handle(&get_request("/health", None), &mut response)
            .unwrap(),
        GatewayHttpOutcome::Rejected { status_code: 404 }
    );
}

// Proves handler configuration enforces the manager's queue-time bound.
#[test]
fn queue_configuration_is_bounded_before_serving() {
    let models = Arc::new(MockModelProvider::new(Ok(model())));
    let tokens = Arc::new(MockTokenProvider::new(Ok(NonZeroU64::new(1).unwrap())));
    let request_ids = Arc::new(MockRequestIdProvider::new(Ok(Sha256Digest::parse(
        REQUEST_ID,
    )
    .unwrap())));
    let execution = Arc::new(MockExecutionProvider::new(MockExecutionPlan::Success));

    let result = GatewayHttpHandler::new(
        GatewayHttpSurface::Public,
        300_001,
        models,
        tokens,
        request_ids,
        execution,
    );

    assert_eq!(result.err().unwrap().code(), "configuration_invalid");
}
