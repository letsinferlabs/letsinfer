// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::num::NonZeroU64;
use std::sync::Arc;

use li_core_interface::{LogicalModelName, Sha256Digest};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{
    GatewayChatCompletionRequest, GatewayError, GatewayExecution, GatewayExecutionFailure,
    GatewayRequest, GatewayResponseHead, GatewayResponseHeader, GatewayResponseWriter,
};

const CHAT_COMPLETIONS_PATH: &str = "/v1/chat/completions";
const HEALTH_PATH: &str = "/health";
const MODELS_PATH: &str = "/v1/models";
pub const LETSINFER_RELAY_TOKEN_COUNT_PATH: &str = "/li/token-count";
const MAX_REQUEST_BODY_BYTES: usize = 32 * 1024 * 1024;
const MAX_REQUEST_HEADERS: usize = 64;
const MAX_REQUEST_HEADER_BYTES: usize = 64 * 1024;
const MAX_REQUEST_HEADER_NAME_BYTES: usize = 128;
const MAX_REQUEST_HEADER_VALUE_BYTES: usize = 8 * 1024;
const MAX_BEARER_BYTES: usize = 512;
const MAX_PREFIX_KEY_BYTES: usize = 256;
const MAX_QUEUE_MILLISECONDS: u64 = 5 * 60 * 1_000;
const MAX_LISTED_MODELS: usize = 4_096;

// Identifies the bounded HTTP method accepted by the native listener seam.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayHttpMethod {
    Get,
    Post,
    Options,
}

// Identifies whether one listener exposes public inference or the private relay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayHttpSurface {
    Public,
    PrivateRelay,
}

// Carries one parsed bounded HTTP request without retaining socket ownership.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayHttpRequest {
    method: GatewayHttpMethod,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl GatewayHttpRequest {
    // Creates one closed request after normalizing and bounding its HTTP metadata.
    pub fn new(
        method: GatewayHttpMethod,
        path: &str,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) -> Result<Self, GatewayHttpError> {
        let header_count = headers.len();
        let mut normalized = Vec::with_capacity(headers.len());
        let mut names = HashSet::new();
        let mut header_bytes = 0usize;
        for (name, value) in headers {
            let name = name.to_ascii_lowercase();
            header_bytes = header_bytes
                .checked_add(name.len())
                .and_then(|length| length.checked_add(value.len()))
                .and_then(|length| length.checked_add(4))
                .ok_or_else(GatewayHttpError::invalid_request)?;
            if name.is_empty()
                || name.len() > MAX_REQUEST_HEADER_NAME_BYTES
                || !name.bytes().all(is_header_name_byte)
                || value.len() > MAX_REQUEST_HEADER_VALUE_BYTES
                || !value.bytes().all(is_header_value_byte)
                || !names.insert(name.clone())
            {
                return Err(GatewayHttpError::invalid_request());
            }
            normalized.push((name, value));
        }
        if path.is_empty()
            || path.len() > 2_048
            || !path.starts_with('/')
            || path.chars().any(char::is_control)
            || header_count > MAX_REQUEST_HEADERS
            || header_bytes > MAX_REQUEST_HEADER_BYTES
            || body.len() > MAX_REQUEST_BODY_BYTES
        {
            return Err(GatewayHttpError::invalid_request());
        }
        normalized.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(Self {
            method,
            path: path.to_string(),
            headers: normalized,
            body,
        })
    }

    // Returns the parsed request method.
    pub const fn method(&self) -> GatewayHttpMethod {
        self.method
    }

    // Returns the exact absolute request target.
    pub fn path(&self) -> &str {
        &self.path
    }

    // Returns one normalized header value when present.
    pub fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .binary_search_by(|(candidate, _)| candidate.cmp(&name))
            .ok()
            .map(|index| self.headers[index].1.as_str())
    }

    // Returns the bounded request body.
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

// Describes one stable client-facing request failure without secret material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayHttpError {
    status_code: u16,
    code: &'static str,
    message: &'static str,
}

impl GatewayHttpError {
    // Creates one closed client-facing failure from stable bounded fields.
    pub const fn new(status_code: u16, code: &'static str, message: &'static str) -> Self {
        Self {
            status_code,
            code,
            message,
        }
    }

    // Returns one generic malformed-request failure.
    fn invalid_request() -> Self {
        Self::new(400, "invalid_request", "request is invalid")
    }

    // Returns the exact HTTP status sent before any backend output.
    pub const fn status_code(&self) -> u16 {
        self.status_code
    }

    // Returns the stable OpenAI-compatible error code.
    pub const fn code(&self) -> &'static str {
        self.code
    }

    // Returns the redacted client-facing explanation.
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

impl fmt::Display for GatewayHttpError {
    // Presents only the stable redacted client-facing explanation.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl Error for GatewayHttpError {}

// Resolves a requested model or alias to one canonical logical model identity.
pub trait GatewayHttpModelProvider: Send + Sync {
    // Returns the canonical model permitted on this Gateway surface.
    fn resolve(&self, requested_model: &str) -> Result<LogicalModelName, GatewayHttpError>;
}

// Reports fail-closed readiness for the public Gateway listener.
pub trait GatewayHttpHealthProvider: Send + Sync {
    // Returns current readiness or a redacted provider failure.
    fn health(&self) -> Result<bool, GatewayHttpError>;
}

// Carries one authenticated, bounded model-discovery snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayHttpModelList {
    created_at_unix: u64,
    models: Vec<LogicalModelName>,
}

impl GatewayHttpModelList {
    // Creates one sorted unique model list under the public response bound.
    pub fn new(
        created_at_unix: u64,
        mut models: Vec<LogicalModelName>,
    ) -> Result<Self, GatewayHttpError> {
        if models.len() > MAX_LISTED_MODELS {
            return Err(public_read_error());
        }
        models.sort();
        if models.windows(2).any(|values| values[0] == values[1]) {
            return Err(public_read_error());
        }
        Ok(Self {
            created_at_unix,
            models,
        })
    }

    // Returns the observation time used by every OpenAI-compatible model row.
    pub const fn created_at_unix(&self) -> u64 {
        self.created_at_unix
    }

    // Returns canonical models and authorized aliases in stable order.
    pub fn models(&self) -> &[LogicalModelName] {
        &self.models
    }
}

// Authenticates and filters the public model-discovery surface.
pub trait GatewayHttpModelListProvider: Send + Sync {
    // Returns the models visible to one bearer credential.
    fn models(&self, bearer_token: &str) -> Result<GatewayHttpModelList, GatewayHttpError>;
}

// Counts exact rendered input tokens without exposing Engine-specific semantics.
pub trait GatewayHttpTokenProvider: Send + Sync {
    // Returns the positive exact input-token count for one normalized request.
    fn count(
        &self,
        bearer_token: &str,
        model: &LogicalModelName,
        normalized_body: &[u8],
    ) -> Result<NonZeroU64, GatewayHttpError>;
}

// Authorizes a main relay and counts one exact request on the child local Engine.
pub trait GatewayHttpRelayTokenProvider: Send + Sync {
    // Returns the positive exact input-token count for one authenticated relay request.
    fn count(
        &self,
        relay_credential: &str,
        model: &LogicalModelName,
        normalized_body: &[u8],
    ) -> Result<NonZeroU64, GatewayHttpError>;
}

// Supplies collision-resistant request identities through an injectable boundary.
pub trait GatewayHttpRequestIdProvider: Send + Sync {
    // Returns one unused immutable request identity.
    fn next(&self) -> Result<Sha256Digest, GatewayHttpError>;
}

// Executes one prepared request on exactly one configured Gateway surface.
pub trait GatewayHttpExecutionProvider: Send + Sync {
    // Authenticates and forwards one public request.
    fn forward_public(
        &self,
        bearer_token: &str,
        request: GatewayChatCompletionRequest,
        response: &mut dyn GatewayResponseWriter,
    ) -> Result<(), GatewayError>;

    // Authenticates and forwards one main-to-child relay request.
    fn forward_relay(
        &self,
        relay_credential: &str,
        request: GatewayChatCompletionRequest,
        response: &mut dyn GatewayResponseWriter,
    ) -> Result<(), GatewayError>;
}

impl GatewayHttpExecutionProvider for GatewayExecution {
    // Delegates public execution without changing reservation ownership.
    fn forward_public(
        &self,
        bearer_token: &str,
        request: GatewayChatCompletionRequest,
        response: &mut dyn GatewayResponseWriter,
    ) -> Result<(), GatewayError> {
        self.forward_public(bearer_token, request, response)
            .map(|_| ())
    }

    // Delegates private relay execution without changing reservation ownership.
    fn forward_relay(
        &self,
        relay_credential: &str,
        request: GatewayChatCompletionRequest,
        response: &mut dyn GatewayResponseWriter,
    ) -> Result<(), GatewayError> {
        self.forward_relay(relay_credential, request, response)
            .map(|_| ())
    }
}

// Describes the terminal connection outcome of one handled HTTP request.
#[derive(Debug, Eq, PartialEq)]
pub enum GatewayHttpOutcome {
    Forwarded,
    TokenCounted,
    HealthReported,
    ModelsListed,
    Rejected { status_code: u16 },
    TerminatedAfterOutput,
    ClientDisconnected,
}

// Owns HTTP request validation and delegates all admission policy to GatewayManager.
pub struct GatewayHttpHandler {
    surface: GatewayHttpSurface,
    maximum_queue_milliseconds: u64,
    models: Arc<dyn GatewayHttpModelProvider>,
    health: Option<Arc<dyn GatewayHttpHealthProvider>>,
    model_list: Option<Arc<dyn GatewayHttpModelListProvider>>,
    tokens: Arc<dyn GatewayHttpTokenProvider>,
    relay_tokens: Option<Arc<dyn GatewayHttpRelayTokenProvider>>,
    request_ids: Arc<dyn GatewayHttpRequestIdProvider>,
    execution: Arc<dyn GatewayHttpExecutionProvider>,
}

impl GatewayHttpHandler {
    // Creates one public or private handler from explicit preparation and execution roles.
    pub fn new(
        surface: GatewayHttpSurface,
        maximum_queue_milliseconds: u64,
        models: Arc<dyn GatewayHttpModelProvider>,
        tokens: Arc<dyn GatewayHttpTokenProvider>,
        request_ids: Arc<dyn GatewayHttpRequestIdProvider>,
        execution: Arc<dyn GatewayHttpExecutionProvider>,
    ) -> Result<Self, GatewayHttpError> {
        Self::new_configured(
            surface,
            maximum_queue_milliseconds,
            models,
            None,
            None,
            tokens,
            None,
            request_ids,
            execution,
        )
    }

    // Creates one handler with the authenticated child token-count relay surface enabled.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_relay_tokens(
        surface: GatewayHttpSurface,
        maximum_queue_milliseconds: u64,
        models: Arc<dyn GatewayHttpModelProvider>,
        tokens: Arc<dyn GatewayHttpTokenProvider>,
        relay_tokens: Option<Arc<dyn GatewayHttpRelayTokenProvider>>,
        request_ids: Arc<dyn GatewayHttpRequestIdProvider>,
        execution: Arc<dyn GatewayHttpExecutionProvider>,
    ) -> Result<Self, GatewayHttpError> {
        Self::new_configured(
            surface,
            maximum_queue_milliseconds,
            models,
            None,
            None,
            tokens,
            relay_tokens,
            request_ids,
            execution,
        )
    }

    // Creates one complete public handler with readiness and model discovery.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_public_reads(
        maximum_queue_milliseconds: u64,
        models: Arc<dyn GatewayHttpModelProvider>,
        health: Arc<dyn GatewayHttpHealthProvider>,
        model_list: Arc<dyn GatewayHttpModelListProvider>,
        tokens: Arc<dyn GatewayHttpTokenProvider>,
        request_ids: Arc<dyn GatewayHttpRequestIdProvider>,
        execution: Arc<dyn GatewayHttpExecutionProvider>,
    ) -> Result<Self, GatewayHttpError> {
        Self::new_configured(
            GatewayHttpSurface::Public,
            maximum_queue_milliseconds,
            models,
            Some(health),
            Some(model_list),
            tokens,
            None,
            request_ids,
            execution,
        )
    }

    // Validates and stores one explicit set of surface capabilities.
    #[allow(clippy::too_many_arguments)]
    fn new_configured(
        surface: GatewayHttpSurface,
        maximum_queue_milliseconds: u64,
        models: Arc<dyn GatewayHttpModelProvider>,
        health: Option<Arc<dyn GatewayHttpHealthProvider>>,
        model_list: Option<Arc<dyn GatewayHttpModelListProvider>>,
        tokens: Arc<dyn GatewayHttpTokenProvider>,
        relay_tokens: Option<Arc<dyn GatewayHttpRelayTokenProvider>>,
        request_ids: Arc<dyn GatewayHttpRequestIdProvider>,
        execution: Arc<dyn GatewayHttpExecutionProvider>,
    ) -> Result<Self, GatewayHttpError> {
        if maximum_queue_milliseconds > MAX_QUEUE_MILLISECONDS {
            return Err(GatewayHttpError::new(
                500,
                "configuration_invalid",
                "Gateway queue configuration is invalid",
            ));
        }
        Ok(Self {
            surface,
            maximum_queue_milliseconds,
            models,
            health,
            model_list,
            tokens,
            relay_tokens,
            request_ids,
            execution,
        })
    }

    // Returns the only network surface this handler may serve.
    pub const fn surface(&self) -> GatewayHttpSurface {
        self.surface
    }

    // Returns whether a public handler carries both mandatory read capabilities.
    pub(crate) fn has_public_reads(&self) -> bool {
        self.health.is_some() && self.model_list.is_some()
    }

    // Validates, prepares, and forwards one request without owning socket mechanics.
    pub fn handle(
        &self,
        request: &GatewayHttpRequest,
        response: &mut dyn GatewayResponseWriter,
    ) -> Result<GatewayHttpOutcome, GatewayExecutionFailure> {
        let mut response = TrackedGatewayResponse::new(response);
        if self.surface == GatewayHttpSurface::Public
            && request.method() == GatewayHttpMethod::Get
            && request.path() == HEALTH_PATH
        {
            return self.handle_health(request, &mut response);
        }
        if self.surface == GatewayHttpSurface::Public
            && request.method() == GatewayHttpMethod::Get
            && request.path() == MODELS_PATH
        {
            return self.handle_model_list(request, &mut response);
        }
        if self.surface == GatewayHttpSurface::PrivateRelay
            && request.method() == GatewayHttpMethod::Post
            && request.path() == LETSINFER_RELAY_TOKEN_COUNT_PATH
        {
            return self.handle_relay_token_count(request, &mut response);
        }
        let prepared = self.prepare(request);
        let outcome = match prepared {
            Ok((credential, request)) => match self.surface {
                GatewayHttpSurface::Public => {
                    self.execution
                        .forward_public(&credential, request, &mut response)
                }
                GatewayHttpSurface::PrivateRelay => {
                    self.execution
                        .forward_relay(&credential, request, &mut response)
                }
            }
            .map_err(HandlerFailure::Gateway),
            Err(error) => Err(HandlerFailure::Http(error)),
        };
        match outcome {
            Ok(()) => Ok(GatewayHttpOutcome::Forwarded),
            Err(_) if response.write_failed => Ok(GatewayHttpOutcome::ClientDisconnected),
            Err(_) if response.started => Ok(GatewayHttpOutcome::TerminatedAfterOutput),
            Err(HandlerFailure::Http(error)) => write_error(&mut response, &error),
            Err(HandlerFailure::Gateway(error)) => {
                write_error(&mut response, &gateway_http_error(&error))
            }
        }
    }

    // Emits one parser or listener rejection through the same redacted response contract.
    pub fn reject(
        &self,
        error: &GatewayHttpError,
        response: &mut dyn GatewayResponseWriter,
    ) -> Result<GatewayHttpOutcome, GatewayExecutionFailure> {
        let mut response = TrackedGatewayResponse::new(response);
        write_error(&mut response, error)
    }

    // Emits one fixed readiness document without authenticating a client.
    fn handle_health(
        &self,
        request: &GatewayHttpRequest,
        response: &mut TrackedGatewayResponse<'_>,
    ) -> Result<GatewayHttpOutcome, GatewayExecutionFailure> {
        if let Err(error) = validate_empty_get(request) {
            return write_error(response, &error);
        }
        let healthy = self
            .health
            .as_ref()
            .is_some_and(|provider| provider.health().unwrap_or(false));
        let status = if healthy { "ok" } else { "degraded" };
        write_json_response(
            response,
            if healthy { 200 } else { 503 },
            &json!({"status": status}),
        )?;
        Ok(GatewayHttpOutcome::HealthReported)
    }

    // Authenticates and emits one sorted OpenAI-compatible model list.
    fn handle_model_list(
        &self,
        request: &GatewayHttpRequest,
        response: &mut TrackedGatewayResponse<'_>,
    ) -> Result<GatewayHttpOutcome, GatewayExecutionFailure> {
        let snapshot = validate_empty_get(request)
            .and_then(|()| bearer_credential(request))
            .and_then(|credential| {
                self.model_list
                    .as_ref()
                    .ok_or_else(public_read_error)?
                    .models(&credential)
            });
        let snapshot = match snapshot {
            Ok(snapshot) => snapshot,
            Err(error) => return write_error(response, &error),
        };
        let data = snapshot
            .models()
            .iter()
            .map(|model| {
                json!({
                    "id": model.as_str(),
                    "object": "model",
                    "created": snapshot.created_at_unix(),
                    "owned_by": "letsinfer",
                })
            })
            .collect::<Vec<_>>();
        write_json_response(response, 200, &json!({"object": "list", "data": data}))?;
        Ok(GatewayHttpOutcome::ModelsListed)
    }

    // Normalizes one exact chat-completions request before acquiring live capacity.
    fn prepare(
        &self,
        request: &GatewayHttpRequest,
    ) -> Result<(String, GatewayChatCompletionRequest), GatewayHttpError> {
        validate_request_envelope(request)?;
        let credential = bearer_credential(request)?;
        let mut document: Value = serde_json::from_slice(request.body()).map_err(|_| {
            GatewayHttpError::new(400, "invalid_json", "request body is not valid JSON")
        })?;
        let object = document.as_object_mut().ok_or_else(|| {
            GatewayHttpError::new(400, "invalid_request", "request body must be an object")
        })?;
        let requested_model = object.get("model").and_then(Value::as_str).ok_or_else(|| {
            GatewayHttpError::new(400, "model_required", "request must contain a model")
        })?;
        let model = self.models.resolve(requested_model)?;
        let maximum_output_tokens = maximum_output_tokens(object)?;
        let prefix_key = object
            .get("prompt_cache_key")
            .map(prefix_identity)
            .transpose()?;
        object.insert(
            "model".to_string(),
            Value::String(model.as_str().to_string()),
        );
        let normalized_body = serde_json::to_vec(&document).map_err(|_| {
            GatewayHttpError::new(400, "invalid_request", "request cannot be normalized")
        })?;
        if normalized_body.len() > MAX_REQUEST_BODY_BYTES {
            return Err(GatewayHttpError::new(
                413,
                "request_too_large",
                "request body exceeds 32 MiB",
            ));
        }
        let context_tokens = self.tokens.count(&credential, &model, &normalized_body)?;
        let request_id = self.request_ids.next()?;
        let request = GatewayRequest::new(
            request_id,
            model,
            context_tokens,
            maximum_output_tokens,
            prefix_key,
            self.maximum_queue_milliseconds,
        )
        .map_err(|_| {
            GatewayHttpError::new(
                400,
                "token_budget_invalid",
                "request token budget is invalid",
            )
        })?;
        let request =
            GatewayChatCompletionRequest::new(request, normalized_body).map_err(|_| {
                GatewayHttpError::new(400, "invalid_request", "request body is invalid")
            })?;
        Ok((credential, request))
    }

    // Authenticates and answers one fixed child-relay token-count request locally.
    fn handle_relay_token_count(
        &self,
        request: &GatewayHttpRequest,
        response: &mut TrackedGatewayResponse<'_>,
    ) -> Result<GatewayHttpOutcome, GatewayExecutionFailure> {
        let outcome = self.prepare_relay_token_count(request);
        match outcome {
            Ok((model, prompt_tokens)) => {
                let body = serde_json::to_vec(&json!({
                    "model": model.as_str(),
                    "object": "token_count",
                    "prompt_tokens": prompt_tokens.get(),
                }))
                .map_err(|_| {
                    GatewayExecutionFailure::terminal_backend(
                        "token-count response cannot be encoded",
                    )
                })?;
                let head = GatewayResponseHead::new(
                    200,
                    vec![
                        GatewayResponseHeader::new("content-type", "application/json").map_err(
                            |_| {
                                GatewayExecutionFailure::terminal_backend(
                                    "token-count response is invalid",
                                )
                            },
                        )?,
                    ],
                )
                .map_err(|_| {
                    GatewayExecutionFailure::terminal_backend("token-count response is invalid")
                })?;
                response.write_head(&head)?;
                response.write_body(&body)?;
                Ok(GatewayHttpOutcome::TokenCounted)
            }
            Err(error) => write_error(response, &error),
        }
    }

    // Normalizes one exact OpenAI body before the authenticated relay count provider runs.
    fn prepare_relay_token_count(
        &self,
        request: &GatewayHttpRequest,
    ) -> Result<(LogicalModelName, NonZeroU64), GatewayHttpError> {
        validate_json_envelope(request)?;
        let credential = bearer_credential(request)?;
        let mut document: Value = serde_json::from_slice(request.body()).map_err(|_| {
            GatewayHttpError::new(400, "invalid_json", "request body is not valid JSON")
        })?;
        let object = document.as_object_mut().ok_or_else(|| {
            GatewayHttpError::new(400, "invalid_request", "request body must be an object")
        })?;
        let requested_model = object.get("model").and_then(Value::as_str).ok_or_else(|| {
            GatewayHttpError::new(400, "model_required", "request must contain a model")
        })?;
        if object
            .get("messages")
            .and_then(Value::as_array)
            .is_none_or(Vec::is_empty)
        {
            return Err(GatewayHttpError::new(
                400,
                "messages_required",
                "request must contain messages",
            ));
        }
        let model = self.models.resolve(requested_model)?;
        object.insert(
            "model".to_string(),
            Value::String(model.as_str().to_string()),
        );
        let normalized_body = serde_json::to_vec(&document).map_err(|_| {
            GatewayHttpError::new(400, "invalid_request", "request cannot be normalized")
        })?;
        let provider = self.relay_tokens.as_ref().ok_or_else(|| {
            GatewayHttpError::new(
                503,
                "exact_context_unavailable",
                "child exact token counting is unavailable",
            )
        })?;
        let prompt_tokens = provider.count(&credential, &model, &normalized_body)?;
        Ok((model, prompt_tokens))
    }
}

// Distinguishes local request rejection from manager or provider failures.
enum HandlerFailure {
    Http(GatewayHttpError),
    Gateway(GatewayError),
}

// Tracks whether output became visible or the client rejected a write.
struct TrackedGatewayResponse<'a> {
    response: &'a mut dyn GatewayResponseWriter,
    started: bool,
    write_failed: bool,
}

impl<'a> TrackedGatewayResponse<'a> {
    // Creates one uncommitted response tracker.
    const fn new(response: &'a mut dyn GatewayResponseWriter) -> Self {
        Self {
            response,
            started: false,
            write_failed: false,
        }
    }
}

impl GatewayResponseWriter for TrackedGatewayResponse<'_> {
    // Delegates caller liveness before any queued execution begins.
    fn client_is_connected(&mut self) -> Result<bool, GatewayExecutionFailure> {
        self.response.client_is_connected()
    }

    // Records successful head commitment and client-output failure.
    fn write_head(&mut self, head: &GatewayResponseHead) -> Result<(), GatewayExecutionFailure> {
        let result = self.response.write_head(head);
        match result {
            Ok(()) => self.started = true,
            Err(_) => self.write_failed = true,
        }
        result
    }

    // Records client-output failure without changing head commitment state.
    fn write_body(&mut self, body: &[u8]) -> Result<(), GatewayExecutionFailure> {
        let result = self.response.write_body(body);
        if result.is_err() {
            self.write_failed = true;
        }
        result
    }
}

// Validates the only inference request envelope accepted by this handler.
fn validate_request_envelope(request: &GatewayHttpRequest) -> Result<(), GatewayHttpError> {
    if request.method() != GatewayHttpMethod::Post || request.path() != CHAT_COMPLETIONS_PATH {
        return Err(GatewayHttpError::new(
            404,
            "not_found",
            "only the supported inference surface is available",
        ));
    }
    validate_json_envelope(request)
}

// Validates common JSON body framing independently of the selected private path.
fn validate_json_envelope(request: &GatewayHttpRequest) -> Result<(), GatewayHttpError> {
    if request.body().is_empty() {
        return Err(GatewayHttpError::new(
            400,
            "invalid_request",
            "request body is empty",
        ));
    }
    if request.header("transfer-encoding").is_some() {
        return Err(GatewayHttpError::new(
            400,
            "unsupported_transfer_encoding",
            "chunked request bodies are unsupported",
        ));
    }
    let content_type = request.header("content-type").unwrap_or("");
    if !is_json_content_type(content_type) {
        return Err(GatewayHttpError::new(
            415,
            "unsupported_media_type",
            "content type must be application/json",
        ));
    }
    if let Some(length) = request.header("content-length") {
        let length = length.parse::<usize>().map_err(|_| {
            GatewayHttpError::new(400, "invalid_request", "content length is invalid")
        })?;
        if length != request.body().len() {
            return Err(GatewayHttpError::new(
                400,
                "invalid_request",
                "content length does not match the request body",
            ));
        }
    }
    Ok(())
}

// Requires one bodyless GET without ambiguous request framing.
fn validate_empty_get(request: &GatewayHttpRequest) -> Result<(), GatewayHttpError> {
    if request.method() != GatewayHttpMethod::Get
        || !request.body().is_empty()
        || request.header("transfer-encoding").is_some()
        || request
            .header("content-length")
            .is_some_and(|value| value != "0")
    {
        return Err(GatewayHttpError::new(
            400,
            "invalid_request",
            "GET request framing is invalid",
        ));
    }
    Ok(())
}

// Extracts one bounded bearer value without returning it in a failure.
fn bearer_credential(request: &GatewayHttpRequest) -> Result<String, GatewayHttpError> {
    let authorization = request.header("authorization").unwrap_or("");
    let Some((scheme, value)) = authorization.split_once(' ') else {
        return Err(GatewayHttpError::new(
            401,
            "unauthorized",
            "a bearer credential is required",
        ));
    };
    if !scheme.eq_ignore_ascii_case("bearer")
        || value.is_empty()
        || value.len() > MAX_BEARER_BYTES
        || value.chars().any(char::is_whitespace)
    {
        return Err(GatewayHttpError::new(
            401,
            "unauthorized",
            "a bearer credential is required",
        ));
    }
    Ok(value.to_string())
}

// Returns one unambiguous positive completion-token reservation.
fn maximum_output_tokens(
    object: &serde_json::Map<String, Value>,
) -> Result<NonZeroU64, GatewayHttpError> {
    let maximum = object.get("max_tokens");
    let completion = object.get("max_completion_tokens");
    if maximum.is_some() && completion.is_some() && maximum != completion {
        return Err(GatewayHttpError::new(
            400,
            "token_budget_invalid",
            "completion token fields conflict",
        ));
    }
    maximum
        .or(completion)
        .and_then(Value::as_u64)
        .and_then(NonZeroU64::new)
        .ok_or_else(|| {
            GatewayHttpError::new(
                400,
                "token_budget_required",
                "a positive completion token limit is required",
            )
        })
}

// Derives the same bounded prefix identity used by placement route facts.
fn prefix_identity(value: &Value) -> Result<Sha256Digest, GatewayHttpError> {
    let value = value.as_str().ok_or_else(|| {
        GatewayHttpError::new(
            400,
            "prefix_key_invalid",
            "prompt cache key must be a string",
        )
    })?;
    if value.is_empty() || value.len() > MAX_PREFIX_KEY_BYTES {
        return Err(GatewayHttpError::new(
            400,
            "prefix_key_invalid",
            "prompt cache key is empty or exceeds 256 bytes",
        ));
    }
    let mut digest = Sha256::new();
    let domain = b"li_gateway_prefix_v1";
    digest.update((domain.len() as u64).to_be_bytes());
    digest.update(domain);
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value.as_bytes());
    Sha256Digest::parse(&format!("{:x}", digest.finalize())).map_err(|_| {
        GatewayHttpError::new(
            500,
            "identity_unavailable",
            "request identity is unavailable",
        )
    })
}

// Maps internal policy failures to a bounded client-facing HTTP contract.
fn gateway_http_error(error: &GatewayError) -> GatewayHttpError {
    match error {
        GatewayError::AuthenticationDenied | GatewayError::RelayDenied => {
            GatewayHttpError::new(401, "unauthorized", "credential is invalid or expired")
        }
        GatewayError::RequestRateLimit
        | GatewayError::TokenRateLimit
        | GatewayError::ConcurrencyLimit => {
            GatewayHttpError::new(429, "rate_limit_exceeded", "request policy limit reached")
        }
        GatewayError::ContextTooLarge => GatewayHttpError::new(
            400,
            "context_length_exceeded",
            "request exceeds every available placement context",
        ),
        GatewayError::InvalidContract { .. } => {
            GatewayHttpError::new(400, "invalid_request", "request contract is invalid")
        }
        GatewayError::PublicUnavailableOnChild
        | GatewayError::PrivateRelayUnavailableOnMain
        | GatewayError::NoRoute
        | GatewayError::CapacityUnavailable
        | GatewayError::QueueFull
        | GatewayError::QueueExpired
        | GatewayError::RequestNotFound
        | GatewayError::Provider { .. }
        | GatewayError::StateUnavailable
        | GatewayError::DuplicateRequest => GatewayHttpError::new(
            503,
            "placement_unavailable",
            "inference service is temporarily unavailable",
        ),
    }
}

// Writes one complete OpenAI-compatible error only before response commitment.
fn write_error(
    response: &mut TrackedGatewayResponse<'_>,
    error: &GatewayHttpError,
) -> Result<GatewayHttpOutcome, GatewayExecutionFailure> {
    let body = serde_json::to_vec(&json!({
        "error": {
            "message": error.message(),
            "type": error.code(),
        }
    }))
    .map_err(|_| GatewayExecutionFailure::terminal_backend("error response is unavailable"))?;
    let headers = vec![
        GatewayResponseHeader::new("content-type", "application/json")
            .map_err(|_| GatewayExecutionFailure::terminal_backend("error response is invalid"))?,
    ];
    let head = GatewayResponseHead::new(error.status_code(), headers)
        .map_err(|_| GatewayExecutionFailure::terminal_backend("error response is invalid"))?;
    response.write_head(&head)?;
    response.write_body(&body)?;
    Ok(GatewayHttpOutcome::Rejected {
        status_code: error.status_code(),
    })
}

// Writes one complete bounded JSON response before returning its semantic outcome.
fn write_json_response(
    response: &mut TrackedGatewayResponse<'_>,
    status_code: u16,
    document: &Value,
) -> Result<(), GatewayExecutionFailure> {
    let body = serde_json::to_vec(document)
        .map_err(|_| GatewayExecutionFailure::terminal_backend("JSON response is unavailable"))?;
    let head = GatewayResponseHead::new(
        status_code,
        vec![
            GatewayResponseHeader::new("content-type", "application/json").map_err(|_| {
                GatewayExecutionFailure::terminal_backend("JSON response is invalid")
            })?,
        ],
    )
    .map_err(|_| GatewayExecutionFailure::terminal_backend("JSON response is invalid"))?;
    response.write_head(&head)?;
    response.write_body(&body)
}

// Returns one stable fail-closed error for an unavailable public read provider.
fn public_read_error() -> GatewayHttpError {
    GatewayHttpError::new(
        503,
        "gateway_unavailable",
        "Gateway public state is temporarily unavailable",
    )
}

// Returns whether one content type is JSON with at most a UTF-8 charset parameter.
fn is_json_content_type(value: &str) -> bool {
    let mut parts = value.split(';').map(str::trim);
    if !parts
        .next()
        .is_some_and(|media| media.eq_ignore_ascii_case("application/json"))
    {
        return false;
    }
    parts.all(|parameter| parameter.eq_ignore_ascii_case("charset=utf-8"))
}

// Returns whether one ASCII byte is legal in an HTTP field name.
fn is_header_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

// Returns whether one request-header byte is visible ASCII or horizontal tab.
fn is_header_value_byte(byte: u8) -> bool {
    byte == b'\t' || (b' '..=b'~').contains(&byte)
}
