// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use li_core_interface::{
    EndpointAddress, EndpointScheme, LogicalModelName, Sha256Digest, TokenCountContract,
    TokenCountProtocol,
};
use serde_json::Value;

use crate::li_gateway_usage::{instrument_stream_usage, request_is_streaming, GatewayUsageParser};
use crate::{
    GatewayChatCompletionRequest, GatewayExactUsage, GatewayExecutionFailure,
    GatewayExecutionProvider, GatewayNativeClientIdentity, GatewayNativeFileIo,
    GatewayNativeHttpFailure, GatewayNativeHttpIo, GatewayNativeHttpRequest,
    GatewayNativeHttpResponseObserver, GatewayNativeIoError, GatewayNativeIoFailurePhase,
    GatewayNativeResponseHead, GatewayNativeTlsConfiguration, GatewayResponseHead,
    GatewayResponseHeader, GatewayResponseWriter, GatewayRoute, GatewayRouteTarget,
};

pub const LETSINFER_TOKEN_COUNT_PROTOCOL: &str = "letsinfer-token-count-v1";
const CHAT_COMPLETIONS_PATH: &str = "/v1/chat/completions";
const MAX_BEARER_BYTES: usize = 512;
const MAX_CA_BYTES: usize = 128 * 1024;
const MAX_CERTIFICATE_BYTES: usize = 128 * 1024;
const MAX_PRIVATE_KEY_BYTES: usize = 128 * 1024;
const MAX_TOKEN_COUNT_RESPONSE_BYTES: usize = 128 * 1024;

// Identifies whether one native target is a local Engine or a private child relay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GatewayNativeTargetKind {
    LocalEngine,
    ChildRelay,
}

// Binds one route to exact HTTPS, credential, CA, and optional mTLS file references.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayNativeTarget {
    kind: GatewayNativeTargetKind,
    host: String,
    port: u16,
    owner_user_id: u32,
    bearer_file: PathBuf,
    ca_file: PathBuf,
    expected_server_leaf_sha256: Option<Sha256Digest>,
    client_certificate_file: Option<PathBuf>,
    client_private_key_file: Option<PathBuf>,
    token_count: Option<TokenCountContract>,
}

impl GatewayNativeTarget {
    // Creates one local Engine target bound to its exact HTTPS endpoint.
    pub fn local_engine(
        endpoint: &EndpointAddress,
        owner_user_id: u32,
        bearer_file: PathBuf,
        ca_file: PathBuf,
        token_count: Option<TokenCountContract>,
    ) -> Result<Self, GatewayNativeIoError> {
        if endpoint.scheme() != EndpointScheme::Https {
            return Err(GatewayNativeIoError::terminal_before_head(
                "local Engine transport must use HTTPS",
            ));
        }
        Self::new(
            GatewayNativeTargetKind::LocalEngine,
            endpoint.host().as_str(),
            endpoint.port(),
            owner_user_id,
            bearer_file,
            ca_file,
            None,
            None,
            None,
            token_count,
        )
    }

    // Creates one child-relay target that requires a private client TLS identity.
    #[allow(clippy::too_many_arguments)]
    pub fn child_relay(
        host: &str,
        port: u16,
        owner_user_id: u32,
        bearer_file: PathBuf,
        ca_file: PathBuf,
        expected_server_leaf_sha256: Sha256Digest,
        client_certificate_file: PathBuf,
        client_private_key_file: PathBuf,
        token_count: Option<TokenCountContract>,
    ) -> Result<Self, GatewayNativeIoError> {
        Self::new(
            GatewayNativeTargetKind::ChildRelay,
            host,
            port,
            owner_user_id,
            bearer_file,
            ca_file,
            Some(expected_server_leaf_sha256),
            Some(client_certificate_file),
            Some(client_private_key_file),
            token_count,
        )
    }

    // Creates one closed target after rejecting ambiguous identities and file references.
    #[allow(clippy::too_many_arguments)]
    fn new(
        kind: GatewayNativeTargetKind,
        host: &str,
        port: u16,
        owner_user_id: u32,
        bearer_file: PathBuf,
        ca_file: PathBuf,
        expected_server_leaf_sha256: Option<Sha256Digest>,
        client_certificate_file: Option<PathBuf>,
        client_private_key_file: Option<PathBuf>,
        token_count: Option<TokenCountContract>,
    ) -> Result<Self, GatewayNativeIoError> {
        let identity_complete =
            client_certificate_file.is_some() == client_private_key_file.is_some();
        let identity_required = kind == GatewayNativeTargetKind::ChildRelay;
        let paths = [
            Some(&bearer_file),
            Some(&ca_file),
            client_certificate_file.as_ref(),
            client_private_key_file.as_ref(),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        let unique = paths.iter().collect::<HashSet<_>>().len() == paths.len();
        if host.is_empty()
            || host.len() > 255
            || host.chars().any(char::is_whitespace)
            || port == 0
            || !identity_complete
            || identity_required != client_certificate_file.is_some()
            || identity_required != expected_server_leaf_sha256.is_some()
            || paths.iter().any(|path| !path.is_absolute())
            || !unique
        {
            return Err(GatewayNativeIoError::terminal_before_head(
                "native Gateway target is incomplete or ambiguous",
            ));
        }
        Ok(Self {
            kind,
            host: host.to_string(),
            port,
            owner_user_id,
            bearer_file,
            ca_file,
            expected_server_leaf_sha256,
            client_certificate_file,
            client_private_key_file,
            token_count,
        })
    }

    // Returns whether this target is reached through one authenticated child relay.
    pub const fn is_child_relay(&self) -> bool {
        matches!(self.kind, GatewayNativeTargetKind::ChildRelay)
    }

    // Returns the exact native target host.
    pub fn host(&self) -> &str {
        &self.host
    }

    // Returns the exact native target port.
    pub const fn port(&self) -> u16 {
        self.port
    }

    // Returns the only user permitted to read target credential material.
    pub const fn owner_user_id(&self) -> u32 {
        self.owner_user_id
    }

    // Returns the absolute bearer credential file reference.
    pub fn bearer_file(&self) -> &std::path::Path {
        &self.bearer_file
    }

    // Returns the absolute server CA file reference.
    pub fn ca_file(&self) -> &std::path::Path {
        &self.ca_file
    }

    // Returns the pinned server leaf identity required for a child relay.
    pub const fn expected_server_leaf_sha256(&self) -> Option<&Sha256Digest> {
        self.expected_server_leaf_sha256.as_ref()
    }

    // Returns the absolute relay client certificate file when required.
    pub fn client_certificate_file(&self) -> Option<&std::path::Path> {
        self.client_certificate_file.as_deref()
    }

    // Returns the absolute relay client private-key file when required.
    pub fn client_private_key_file(&self) -> Option<&std::path::Path> {
        self.client_private_key_file.as_deref()
    }

    // Returns the exact Engine-owned token-count contract when declared.
    pub const fn token_count(&self) -> Option<&TokenCountContract> {
        self.token_count.as_ref()
    }
}

// Resolves native HTTPS and credential references for one selected route.
pub trait GatewayNativeTargetProvider: Send + Sync {
    // Returns the exact target bound to one immutable Gateway route.
    fn target(&self, route: &GatewayRoute) -> Result<GatewayNativeTarget, GatewayNativeIoError>;
}

// Owns fixed HTTPS forwarding over injected native file, TLS, and network mechanisms.
pub struct GatewayNativeExecutionProvider {
    targets: Arc<dyn GatewayNativeTargetProvider>,
    files: Arc<dyn GatewayNativeFileIo>,
    http: Arc<dyn GatewayNativeHttpIo>,
}

impl GatewayNativeExecutionProvider {
    // Creates one production forwarding role from exact native dependencies.
    pub const fn new(
        targets: Arc<dyn GatewayNativeTargetProvider>,
        files: Arc<dyn GatewayNativeFileIo>,
        http: Arc<dyn GatewayNativeHttpIo>,
    ) -> Self {
        Self {
            targets,
            files,
            http,
        }
    }

    // Builds one exact native request after validating route, files, and TLS identity.
    fn request(
        &self,
        route: &GatewayRoute,
        request: &GatewayChatCompletionRequest,
    ) -> Result<(GatewayNativeHttpRequest, bool), GatewayExecutionFailure> {
        if request.path() != CHAT_COMPLETIONS_PATH {
            return Err(GatewayExecutionFailure::terminal_backend(
                "Gateway execution path is unsupported",
            ));
        }
        let target = self.targets.target(route).map_err(native_error)?;
        validate_target(route, &target)?;
        let bearer = read_bearer(self.files.as_ref(), &target)?;
        let tls = read_tls(self.files.as_ref(), &target)?;
        let streaming = request_is_streaming(request.body())?;
        let body = instrument_stream_usage(request.body())?;
        if body.len() > 32 * 1024 * 1024 {
            return Err(GatewayExecutionFailure::terminal_backend(
                "instrumented chat-completions request exceeds 32 MiB",
            ));
        }
        let headers = fixed_headers(
            &target,
            request.request().request_id().as_str(),
            &bearer,
            body.len(),
        );
        let request = GatewayNativeHttpRequest::chat_completions(
            &target.host,
            target.port,
            headers,
            body,
            tls,
        )
        .map_err(native_error)?;
        Ok((request, streaming))
    }
}

impl GatewayExecutionProvider for GatewayNativeExecutionProvider {
    // Streams one local Engine or child-relay attempt with exact pre-output retry semantics.
    fn forward(
        &self,
        route: &GatewayRoute,
        request: &GatewayChatCompletionRequest,
        response: &mut dyn GatewayResponseWriter,
    ) -> Result<GatewayExactUsage, GatewayExecutionFailure> {
        let (native_request, streaming) = self.request(route, request)?;
        let mut observer = ExecutionResponseObserver::new(response, streaming);
        let outcome = self.http.send(&native_request, &mut observer);
        match outcome {
            Ok(()) if observer.retryable_status => Err(GatewayExecutionFailure::retryable_backend(
                "native backend returned 5xx",
            )),
            Ok(()) if observer.redirect_status => Err(GatewayExecutionFailure::terminal_backend(
                "native backend redirect is forbidden",
            )),
            Ok(()) if observer.client_error_status => {
                GatewayExactUsage::new(request.request().context_tokens().get(), 0, 0).map_err(
                    |_| {
                        GatewayExecutionFailure::terminal_backend(
                            "client-error usage cannot be represented",
                        )
                    },
                )
            }
            Ok(()) => observer.finish(),
            Err(GatewayNativeHttpFailure::Output(failure)) => Err(failure),
            Err(GatewayNativeHttpFailure::Native(error)) if observer.output_started => {
                Err(GatewayExecutionFailure::terminal_backend(error.reason()))
            }
            Err(GatewayNativeHttpFailure::Native(error)) => Err(native_error(error)),
        }
    }
}

// Counts exact rendered-chat tokens through the declared letsinfer-token-count-v1 contract.
pub struct GatewayTokenCountClient {
    targets: Arc<dyn GatewayNativeTargetProvider>,
    files: Arc<dyn GatewayNativeFileIo>,
    http: Arc<dyn GatewayNativeHttpIo>,
}

impl GatewayTokenCountClient {
    // Creates one exact token-count client over the same native trust boundary as execution.
    pub const fn new(
        targets: Arc<dyn GatewayNativeTargetProvider>,
        files: Arc<dyn GatewayNativeFileIo>,
        http: Arc<dyn GatewayNativeHttpIo>,
    ) -> Self {
        Self {
            targets,
            files,
            http,
        }
    }

    // Validates and forwards one exact OpenAI request without engine-specific translation.
    pub fn count(
        &self,
        route: &GatewayRoute,
        model: &LogicalModelName,
        openai_body: &[u8],
    ) -> Result<u64, GatewayExecutionFailure> {
        validate_token_count_request(model, openai_body)?;
        let target = self.targets.target(route).map_err(native_error)?;
        validate_target(route, &target)?;
        let bearer = read_bearer(self.files.as_ref(), &target)?;
        let tls = read_tls(self.files.as_ref(), &target)?;
        let token_count = target.token_count.as_ref().ok_or_else(|| {
            GatewayExecutionFailure::terminal_backend(
                "selected placement has no exact token-count contract",
            )
        })?;
        if token_count.protocol() != TokenCountProtocol::LetsInferV1 {
            return Err(GatewayExecutionFailure::terminal_backend(
                "selected placement token-count protocol is unsupported",
            ));
        }
        let headers = fixed_headers(
            &target,
            route.placement_group_id().as_str(),
            &bearer,
            openai_body.len(),
        );
        let request = GatewayNativeHttpRequest::token_count(
            &target.host,
            target.port,
            token_count.path(),
            headers,
            openai_body.to_vec(),
            tls,
        )
        .map_err(native_error)?;
        let mut observer = TokenCountResponseObserver::default();
        match self.http.send(&request, &mut observer) {
            Ok(()) => observer.finish(model),
            Err(GatewayNativeHttpFailure::Output(failure)) => Err(failure),
            Err(GatewayNativeHttpFailure::Native(error)) => Err(native_error(error)),
        }
    }
}

// Collects bounded execution response metadata and exact cumulative usage.
struct ExecutionResponseObserver<'a> {
    response: &'a mut dyn GatewayResponseWriter,
    usage: Option<GatewayUsageParser>,
    streaming: bool,
    output_started: bool,
    retryable_status: bool,
    redirect_status: bool,
    client_error_status: bool,
}

impl<'a> ExecutionResponseObserver<'a> {
    // Creates one uncommitted observer for a known JSON or SSE response mode.
    const fn new(response: &'a mut dyn GatewayResponseWriter, streaming: bool) -> Self {
        Self {
            response,
            usage: None,
            streaming,
            output_started: false,
            retryable_status: false,
            redirect_status: false,
            client_error_status: false,
        }
    }

    // Returns exact cumulative usage only after a complete successful response.
    fn finish(self) -> Result<GatewayExactUsage, GatewayExecutionFailure> {
        self.usage
            .ok_or_else(|| {
                GatewayExecutionFailure::terminal_backend(
                    "native backend completed without a response head",
                )
            })?
            .finish()
    }
}

impl GatewayNativeHttpResponseObserver for ExecutionResponseObserver<'_> {
    // Classifies status before committing one filtered end-to-end response head.
    fn receive_head(
        &mut self,
        head: &GatewayNativeResponseHead,
    ) -> Result<(), GatewayExecutionFailure> {
        if self.usage.is_some()
            || self.retryable_status
            || self.redirect_status
            || self.client_error_status
        {
            return Err(GatewayExecutionFailure::terminal_backend(
                "native backend emitted more than one response head",
            ));
        }
        if head.status_code() >= 500 {
            self.retryable_status = true;
            return Ok(());
        }
        if (300..400).contains(&head.status_code()) {
            self.redirect_status = true;
            return Ok(());
        }
        let headers = end_to_end_headers(head.headers())?;
        let response_head =
            GatewayResponseHead::new(head.status_code(), headers).map_err(|_| {
                GatewayExecutionFailure::terminal_backend(
                    "native backend response headers are invalid",
                )
            })?;
        self.response.write_head(&response_head)?;
        self.output_started = true;
        self.client_error_status = head.status_code() >= 400;
        self.usage = Some(GatewayUsageParser::new(self.streaming));
        Ok(())
    }

    // Parses exact usage before committing each ordered body fragment.
    fn receive_body(&mut self, body: &[u8]) -> Result<(), GatewayExecutionFailure> {
        if self.retryable_status || self.redirect_status {
            return Ok(());
        }
        let usage = self.usage.as_mut().ok_or_else(|| {
            GatewayExecutionFailure::terminal_backend(
                "native backend emitted response bytes before its head",
            )
        })?;
        if !self.client_error_status {
            usage.feed(body)?;
        }
        self.response.write_body(body)
    }
}

// Collects one closed bounded token-count response without forwarding it.
#[derive(Default)]
struct TokenCountResponseObserver {
    status_code: Option<u16>,
    body: Vec<u8>,
}

impl TokenCountResponseObserver {
    // Validates one exact token-count response identity and positive count.
    fn finish(self, model: &LogicalModelName) -> Result<u64, GatewayExecutionFailure> {
        if self.status_code != Some(200) {
            return Err(GatewayExecutionFailure::retryable_backend(
                "exact token counting returned a non-success status",
            ));
        }
        parse_token_count_response(model, &self.body)
    }
}

impl GatewayNativeHttpResponseObserver for TokenCountResponseObserver {
    // Accepts exactly one bounded token-count response head.
    fn receive_head(
        &mut self,
        head: &GatewayNativeResponseHead,
    ) -> Result<(), GatewayExecutionFailure> {
        if self.status_code.replace(head.status_code()).is_some() {
            return Err(GatewayExecutionFailure::terminal_backend(
                "token-count backend emitted more than one response head",
            ));
        }
        Ok(())
    }

    // Accumulates one bounded token-count response body.
    fn receive_body(&mut self, body: &[u8]) -> Result<(), GatewayExecutionFailure> {
        let length = self
            .body
            .len()
            .checked_add(body.len())
            .filter(|length| *length <= MAX_TOKEN_COUNT_RESPONSE_BYTES)
            .ok_or_else(|| {
                GatewayExecutionFailure::terminal_backend("token-count response exceeds 128 KiB")
            })?;
        self.body.reserve(length - self.body.len());
        self.body.extend_from_slice(body);
        Ok(())
    }
}

// Reads and validates one private bearer file without retaining its path in failures.
fn read_bearer(
    files: &dyn GatewayNativeFileIo,
    target: &GatewayNativeTarget,
) -> Result<GatewayPrivateBearer, GatewayExecutionFailure> {
    let file = files
        .read_no_follow(&target.bearer_file, MAX_BEARER_BYTES)
        .map_err(native_error)?;
    if file.owner_user_id() != target.owner_user_id
        || file.mode() != 0o600
        || file.link_count() != 1
    {
        return Err(GatewayExecutionFailure::terminal_backend(
            "native bearer file is not private and user-owned",
        ));
    }
    GatewayPrivateBearer::new(file.bytes())
}

// Reads a pinned CA and optional private client identity through exact file references.
fn read_tls(
    files: &dyn GatewayNativeFileIo,
    target: &GatewayNativeTarget,
) -> Result<GatewayNativeTlsConfiguration, GatewayExecutionFailure> {
    let ca = files
        .read_no_follow(&target.ca_file, MAX_CA_BYTES)
        .map_err(native_error)?;
    if ca.owner_user_id() != target.owner_user_id || ca.mode() != 0o600 || ca.link_count() != 1 {
        return Err(GatewayExecutionFailure::terminal_backend(
            "native pinned CA is not immutable and user-owned",
        ));
    }
    let client_identity = match (
        &target.client_certificate_file,
        &target.client_private_key_file,
    ) {
        (Some(certificate_file), Some(private_key_file)) => {
            let certificate = files
                .read_no_follow(certificate_file, MAX_CERTIFICATE_BYTES)
                .map_err(native_error)?;
            let private_key = files
                .read_no_follow(private_key_file, MAX_PRIVATE_KEY_BYTES)
                .map_err(native_error)?;
            if certificate.owner_user_id() != target.owner_user_id
                || certificate.mode() != 0o600
                || certificate.link_count() != 1
                || private_key.owner_user_id() != target.owner_user_id
                || private_key.mode() != 0o600
                || private_key.link_count() != 1
            {
                return Err(GatewayExecutionFailure::terminal_backend(
                    "native client TLS identity is not private and user-owned",
                ));
            }
            Some(
                GatewayNativeClientIdentity::new(
                    certificate.bytes().to_vec(),
                    private_key.bytes().to_vec(),
                )
                .map_err(native_error)?,
            )
        }
        (None, None) => None,
        _ => {
            return Err(GatewayExecutionFailure::terminal_backend(
                "native client TLS identity is incomplete",
            ));
        }
    };
    GatewayNativeTlsConfiguration::new(
        &target.host,
        ca.bytes().to_vec(),
        target.expected_server_leaf_sha256.clone(),
        client_identity,
    )
    .map_err(native_error)
}

// Binds one native target back to the immutable route selected by GatewayManager.
fn validate_target(
    route: &GatewayRoute,
    target: &GatewayNativeTarget,
) -> Result<(), GatewayExecutionFailure> {
    let matches = match route.target() {
        GatewayRouteTarget::LocalEngine { endpoint } => {
            target.kind == GatewayNativeTargetKind::LocalEngine
                && endpoint.scheme() == EndpointScheme::Https
                && target.host == endpoint.host().as_str()
                && target.port == endpoint.port()
        }
        GatewayRouteTarget::ChildRelay { address } => {
            target.kind == GatewayNativeTargetKind::ChildRelay
                && target.host == address.as_str()
                && target.expected_server_leaf_sha256.is_some()
                && target.client_certificate_file.is_some()
                && target.client_private_key_file.is_some()
        }
    };
    if !matches {
        return Err(GatewayExecutionFailure::terminal_backend(
            "native target does not match the selected Gateway route",
        ));
    }
    Ok(())
}

// Builds the only end-to-end request headers sent to an Engine or child relay.
fn fixed_headers(
    target: &GatewayNativeTarget,
    request_id: &str,
    bearer: &GatewayPrivateBearer,
    body_bytes: usize,
) -> Vec<(String, String)> {
    vec![
        (
            "accept".to_string(),
            "application/json, text/event-stream".to_string(),
        ),
        (
            "authorization".to_string(),
            format!("Bearer {}", bearer.as_str()),
        ),
        ("connection".to_string(), "close".to_string()),
        ("content-length".to_string(), body_bytes.to_string()),
        ("content-type".to_string(), "application/json".to_string()),
        ("host".to_string(), host_header(&target.host, target.port)),
        ("x-letsinfer-request-id".to_string(), request_id.to_string()),
    ]
}

// Returns one RFC-compatible Host field for DNS, IPv4, or IPv6 targets.
fn host_header(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

// Filters hop-by-hop and server-owned headers before caller-visible commitment.
fn end_to_end_headers(
    headers: &[(String, String)],
) -> Result<Vec<GatewayResponseHeader>, GatewayExecutionFailure> {
    let mut result = Vec::new();
    for (name, value) in headers {
        if is_forbidden_response_header(name) {
            continue;
        }
        result.push(GatewayResponseHeader::new(name, value).map_err(|_| {
            GatewayExecutionFailure::terminal_backend("native backend response header is unsafe")
        })?);
    }
    Ok(result)
}

// Rejects hop-by-hop, transport-sized, credential, and server-owned response fields.
fn is_forbidden_response_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "authorization"
            | "connection"
            | "content-length"
            | "date"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "server"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    ) || name.to_ascii_lowercase().starts_with("access-control-")
}

// Validates the exact original OpenAI request required by letsinfer-token-count-v1.
fn validate_token_count_request(
    model: &LogicalModelName,
    body: &[u8],
) -> Result<(), GatewayExecutionFailure> {
    let value: Value = serde_json::from_slice(body).map_err(|_| {
        GatewayExecutionFailure::terminal_backend("token-count request is not valid JSON")
    })?;
    let document = value.as_object().ok_or_else(|| {
        GatewayExecutionFailure::terminal_backend("token-count request must be an object")
    })?;
    if document.get("model").and_then(Value::as_str) != Some(model.as_str())
        || document
            .get("messages")
            .and_then(Value::as_array)
            .is_none_or(Vec::is_empty)
    {
        return Err(GatewayExecutionFailure::terminal_backend(
            "token-count request model or messages are invalid",
        ));
    }
    Ok(())
}

// Parses one closed normalized letsinfer-token-count-v1 response.
fn parse_token_count_response(
    model: &LogicalModelName,
    body: &[u8],
) -> Result<u64, GatewayExecutionFailure> {
    let value: Value = serde_json::from_slice(body).map_err(|_| {
        GatewayExecutionFailure::terminal_backend("token-count response is not valid JSON")
    })?;
    let document = value.as_object().ok_or_else(|| {
        GatewayExecutionFailure::terminal_backend("token-count response must be an object")
    })?;
    let expected = HashSet::from(["model", "object", "prompt_tokens"]);
    let actual = document.keys().map(String::as_str).collect::<HashSet<_>>();
    let prompt_tokens = document.get("prompt_tokens").and_then(Value::as_u64);
    if actual != expected
        || document.get("object").and_then(Value::as_str) != Some("token_count")
        || document.get("model").and_then(Value::as_str) != Some(model.as_str())
        || prompt_tokens.is_none_or(|value| value == 0)
    {
        return Err(GatewayExecutionFailure::terminal_backend(
            "invalid Let's Infer token-count response",
        ));
    }
    Ok(prompt_tokens.expect("positive token count"))
}

// Maps one native failure to the existing execution retry contract.
fn native_error(error: GatewayNativeIoError) -> GatewayExecutionFailure {
    if error.phase() == GatewayNativeIoFailurePhase::BeforeResponseHead && error.is_retryable() {
        GatewayExecutionFailure::retryable_backend(error.reason())
    } else {
        GatewayExecutionFailure::terminal_backend(error.reason())
    }
}

// Stores one private bearer while redacting diagnostics and clearing storage on drop.
struct GatewayPrivateBearer(String);

impl GatewayPrivateBearer {
    // Creates one bounded ASCII bearer without leading, trailing, or embedded whitespace.
    fn new(bytes: &[u8]) -> Result<Self, GatewayExecutionFailure> {
        let value = std::str::from_utf8(bytes).map_err(|_| {
            GatewayExecutionFailure::terminal_backend("native bearer is not valid ASCII")
        })?;
        let value = value.trim_end_matches(['\r', '\n']);
        if value.len() < 32
            || value.len() > MAX_BEARER_BYTES
            || !value.is_ascii()
            || value.chars().any(char::is_whitespace)
        {
            return Err(GatewayExecutionFailure::terminal_backend(
                "native bearer is invalid",
            ));
        }
        Ok(Self(value.to_string()))
    }

    // Returns private bearer material only to the fixed authorization-header builder.
    fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for GatewayPrivateBearer {
    // Prevents bearer material from entering diagnostics.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GatewayPrivateBearer([REDACTED])")
    }
}

impl Drop for GatewayPrivateBearer {
    // Overwrites bearer storage before releasing its allocation.
    fn drop(&mut self) {
        let length = self.0.len();
        self.0.clear();
        self.0.extend(std::iter::repeat_n('\0', length));
    }
}
