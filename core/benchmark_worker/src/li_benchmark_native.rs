// SPDX-License-Identifier: AGPL-3.0-only

use std::num::{NonZeroU32, NonZeroU64};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use li_core_interface::{
    EndpointAddress, EndpointScheme, LogicalModelName, NodeAddress, NodeId, PlacementGroupId,
    Sha256Digest, TokenCountContract, TokenCountProtocol,
};
use li_gateway_manager::{
    GatewayChatCompletionRequest, GatewayExecutionProvider, GatewayNativeExecutionProvider,
    GatewayNativeIoError, GatewayNativeTarget, GatewayNativeTargetProvider, GatewayRequest,
    GatewayResponseHead, GatewayResponseWriter, GatewayRoute, GatewayRouteTarget,
    GatewayTokenCountClient, SystemGatewayNativeFileIo, SystemGatewayNativeHttpIo,
};
use serde_json::{json, Value};

use crate::{
    BenchmarkWorkerError, NativeBenchmarkRouteInput, NativeBenchmarkStreamMeasurement,
    NativeBenchmarkStreamRequest, NativeBenchmarkTransport,
};

const MAXIMUM_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

// Resolves one already-validated immutable local target for every exact route request.
struct FixedNativeBenchmarkTarget {
    target: GatewayNativeTarget,
}

impl GatewayNativeTargetProvider for FixedNativeBenchmarkTarget {
    // Returns the sealed local target while Gateway independently binds it to the route.
    fn target(&self, _route: &GatewayRoute) -> Result<GatewayNativeTarget, GatewayNativeIoError> {
        Ok(self.target.clone())
    }
}

// Runs benchmark token counting and streams through the existing native Gateway trust boundary.
pub struct NativeGatewayBenchmarkTransport {
    route: GatewayRoute,
    model: LogicalModelName,
    tokens: GatewayTokenCountClient,
    execution: GatewayNativeExecutionProvider,
}

impl NativeGatewayBenchmarkTransport {
    // Creates one native HTTPS transport from exact route and private credential references.
    pub fn new(
        route: &NativeBenchmarkRouteInput,
        model: &str,
    ) -> Result<Self, BenchmarkWorkerError> {
        let model = LogicalModelName::parse(model).map_err(|_| native_contract_error())?;
        let host = NodeAddress::parse(&route.host).map_err(|_| native_contract_error())?;
        let endpoint = EndpointAddress::new(EndpointScheme::Https, host, route.port)
            .map_err(|_| native_contract_error())?;
        let target = GatewayNativeTarget::local_engine(
            &endpoint,
            route.owner_user_id,
            PathBuf::from(&route.bearer_file),
            PathBuf::from(&route.ca_file),
            Some(
                TokenCountContract::new(&route.token_count_path, TokenCountProtocol::LetsInferV1)
                    .map_err(|_| native_contract_error())?,
            ),
        )
        .map_err(|_| native_contract_error())?;
        let route = GatewayRoute::new(
            PlacementGroupId::parse(&route.placement_group_id)
                .map_err(|_| native_contract_error())?,
            NodeId::parse(&route.endpoint_node_id).map_err(|_| native_contract_error())?,
            model.clone(),
            GatewayRouteTarget::LocalEngine { endpoint },
            NonZeroU32::new(route.max_active_requests).ok_or_else(native_contract_error)?,
            NonZeroU64::new(route.max_context_tokens).ok_or_else(native_contract_error)?,
            true,
            false,
            None,
            Vec::new(),
        )
        .map_err(|_| native_contract_error())?;
        let targets: Arc<dyn GatewayNativeTargetProvider> =
            Arc::new(FixedNativeBenchmarkTarget { target });
        let files = Arc::new(SystemGatewayNativeFileIo);
        let http = Arc::new(SystemGatewayNativeHttpIo);
        Ok(Self {
            route,
            model,
            tokens: GatewayTokenCountClient::new(targets.clone(), files.clone(), http.clone()),
            execution: GatewayNativeExecutionProvider::new(targets, files, http),
        })
    }

    // Creates the exact OpenAI token-count request used by the schema-8 Python oracle.
    fn count_body(&self, prompt: &str) -> Result<Vec<u8>, BenchmarkWorkerError> {
        serde_json::to_vec(&json!({
            "model": self.model.as_str(),
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 1,
            "temperature": 0
        }))
        .map_err(|_| native_execution_error())
    }

    // Creates one exact streaming OpenAI request without Engine-specific options.
    fn execution_body(
        &self,
        request: &NativeBenchmarkStreamRequest,
    ) -> Result<Vec<u8>, BenchmarkWorkerError> {
        serde_json::to_vec(&json!({
            "model": self.model.as_str(),
            "messages": [{"role": "user", "content": request.prompt()}],
            "max_tokens": request.generation().output_tokens,
            "temperature": request.generation().temperature,
            "seed": request.generation().seed,
            "stream": true,
            "stream_options": {"include_usage": true}
        }))
        .map_err(|_| native_execution_error())
    }
}

impl NativeBenchmarkTransport for NativeGatewayBenchmarkTransport {
    // Counts exact rendered-chat tokens through letsinfer-token-count-v1.
    fn count_tokens(&self, model: &str, prompt: &str) -> Result<u64, BenchmarkWorkerError> {
        if model != self.model.as_str() {
            return Err(native_contract_error());
        }
        self.tokens
            .count(&self.route, &self.model, &self.count_body(prompt)?)
            .map_err(|_| native_execution_error())
    }

    // Streams one exact request and retains only usage, first-byte timing, and finish semantics.
    fn execute(
        &self,
        request: &NativeBenchmarkStreamRequest,
    ) -> Result<NativeBenchmarkStreamMeasurement, BenchmarkWorkerError> {
        if request.model() != self.model.as_str()
            || request
                .prompt_tokens()
                .checked_add(request.generation().output_tokens)
                .is_none_or(|demand| demand > self.route.max_context_tokens().get())
        {
            return Err(native_contract_error());
        }
        let gateway_request = GatewayRequest::new(
            Sha256Digest::parse(request.request_id()).map_err(|_| native_contract_error())?,
            self.model.clone(),
            NonZeroU64::new(request.prompt_tokens()).ok_or_else(native_contract_error)?,
            NonZeroU64::new(request.generation().output_tokens)
                .ok_or_else(native_contract_error)?,
            None,
            0,
        )
        .map_err(|_| native_contract_error())?;
        let request =
            GatewayChatCompletionRequest::new(gateway_request, self.execution_body(request)?)
                .map_err(|_| native_contract_error())?;
        let started = Instant::now();
        let mut writer = NativeBenchmarkResponseWriter::new(started);
        let usage = self
            .execution
            .forward(&self.route, &request, &mut writer)
            .map_err(|_| native_execution_error())?;
        let elapsed = started.elapsed().as_secs_f64();
        let ttft = writer
            .first_body_at
            .ok_or_else(native_execution_error)?
            .duration_since(started)
            .as_secs_f64();
        NativeBenchmarkStreamMeasurement::new(
            usage.output_tokens(),
            usage.cached_tokens(),
            elapsed,
            ttft,
            response_has_natural_stop(&writer.body),
        )
    }
}

// Captures bounded response bytes and exact first-body time from the Gateway writer boundary.
struct NativeBenchmarkResponseWriter {
    started: Instant,
    first_body_at: Option<Instant>,
    status_code: Option<u16>,
    body: Vec<u8>,
}

impl NativeBenchmarkResponseWriter {
    // Creates one empty writer bound to the request's monotonic start.
    const fn new(started: Instant) -> Self {
        Self {
            started,
            first_body_at: None,
            status_code: None,
            body: Vec::new(),
        }
    }
}

impl GatewayResponseWriter for NativeBenchmarkResponseWriter {
    // Accepts exactly one successful response head.
    fn write_head(
        &mut self,
        head: &GatewayResponseHead,
    ) -> Result<(), li_gateway_manager::GatewayExecutionFailure> {
        if self.status_code.replace(head.status_code()).is_some() || head.status_code() != 200 {
            return Err(
                li_gateway_manager::GatewayExecutionFailure::terminal_backend(
                    "benchmark Engine response status is invalid",
                ),
            );
        }
        Ok(())
    }

    // Captures bounded ordered response bytes and their first-byte time.
    fn write_body(
        &mut self,
        body: &[u8],
    ) -> Result<(), li_gateway_manager::GatewayExecutionFailure> {
        if self.status_code != Some(200)
            || self
                .body
                .len()
                .checked_add(body.len())
                .is_none_or(|length| length > MAXIMUM_RESPONSE_BYTES)
        {
            return Err(
                li_gateway_manager::GatewayExecutionFailure::terminal_backend(
                    "benchmark Engine response body is invalid",
                ),
            );
        }
        if self.first_body_at.is_none() && !body.is_empty() {
            self.first_body_at = Some(Instant::now().max(self.started));
        }
        self.body.extend_from_slice(body);
        Ok(())
    }
}

// Returns whether the complete JSON or SSE response contains an exact natural-stop finish reason.
fn response_has_natural_stop(body: &[u8]) -> bool {
    if let Ok(value) = serde_json::from_slice::<Value>(body) {
        return value_has_natural_stop(&value);
    }
    std::str::from_utf8(body).is_ok_and(|body| {
        body.lines().any(|line| {
            line.strip_prefix("data:")
                .map(str::trim)
                .filter(|value| *value != "[DONE]")
                .and_then(|value| serde_json::from_str::<Value>(value).ok())
                .is_some_and(|value| value_has_natural_stop(&value))
        })
    })
}

// Returns whether one OpenAI response object declares finish_reason=stop.
fn value_has_natural_stop(value: &Value) -> bool {
    value
        .get("choices")
        .and_then(Value::as_array)
        .is_some_and(|choices| {
            choices
                .iter()
                .any(|choice| choice.get("finish_reason").and_then(Value::as_str) == Some("stop"))
        })
}

// Returns one redacted static native-route contract failure.
const fn native_contract_error() -> BenchmarkWorkerError {
    BenchmarkWorkerError::invalid("native benchmark route is invalid")
}

// Returns one redacted static native transport failure.
const fn native_execution_error() -> BenchmarkWorkerError {
    BenchmarkWorkerError::invalid("native benchmark transport failed")
}
