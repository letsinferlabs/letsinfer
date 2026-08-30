// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;
use std::sync::Arc;

use li_core_interface::PlacementGroupId;

use crate::li_gateway_telemetry::GatewayTelemetryTiming;
use crate::{
    GatewayAdmission, GatewayError, GatewayManager, GatewayQueueStatus, GatewayQueueTicket,
    GatewayRequest, GatewayReservation, GatewayRoute,
};

const CHAT_COMPLETIONS_PATH: &str = "/v1/chat/completions";
const MAX_REQUEST_BODY_BYTES: usize = 32 * 1024 * 1024;
const MAX_RESPONSE_BODY_BYTES: usize = 64 * 1024 * 1024;
const MAX_RESPONSE_HEADERS: usize = 64;
const MAX_RESPONSE_HEADER_BYTES: usize = 64 * 1024;
const MAX_RESPONSE_HEADER_NAME_BYTES: usize = 128;
const MAX_RESPONSE_HEADER_VALUE_BYTES: usize = 8 * 1024;
const MAX_QUEUE_WAIT_CYCLES: usize = 4_096;
const MAX_EXECUTION_ATTEMPTS: u16 = 64;

// Carries one bounded normalized OpenAI chat-completions request into execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayChatCompletionRequest {
    request: GatewayRequest,
    body: Vec<u8>,
}

impl GatewayChatCompletionRequest {
    // Creates one bounded request whose JSON validation remains at the HTTP boundary.
    pub fn new(request: GatewayRequest, body: Vec<u8>) -> Result<Self, GatewayError> {
        if body.is_empty() || body.len() > MAX_REQUEST_BODY_BYTES {
            return Err(GatewayError::InvalidContract {
                reason: "chat-completions request body is empty or exceeds 32 MiB",
            });
        }
        Ok(Self { request, body })
    }

    // Returns the only inference path this execution boundary forwards.
    pub const fn path(&self) -> &'static str {
        CHAT_COMPLETIONS_PATH
    }

    // Returns the exact request admitted by GatewayManager.
    pub const fn request(&self) -> &GatewayRequest {
        &self.request
    }

    // Returns the bounded normalized JSON bytes without bearer material.
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

// Carries exact cumulative Engine usage required to finish live quota accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GatewayExactUsage {
    input_tokens: u64,
    output_tokens: u64,
    cached_tokens: u64,
}

impl GatewayExactUsage {
    // Creates coherent exact usage without accepting overflow or impossible cache counts.
    pub fn new(
        input_tokens: u64,
        output_tokens: u64,
        cached_tokens: u64,
    ) -> Result<Self, GatewayError> {
        if cached_tokens > input_tokens || input_tokens.checked_add(output_tokens).is_none() {
            return Err(GatewayError::InvalidContract {
                reason: "chat-completions usage is inconsistent or overflows",
            });
        }
        Ok(Self {
            input_tokens,
            output_tokens,
            cached_tokens,
        })
    }

    // Returns exact prompt tokens observed by the Engine.
    pub const fn input_tokens(self) -> u64 {
        self.input_tokens
    }

    // Returns exact generated tokens observed by the Engine.
    pub const fn output_tokens(self) -> u64 {
        self.output_tokens
    }

    // Returns exact prompt tokens restored from compatible cache state.
    pub const fn cached_tokens(self) -> u64 {
        self.cached_tokens
    }

    // Verifies that exact execution usage matches the already-admitted token envelope.
    fn validate_for(self, request: &GatewayRequest) -> Result<(), GatewayError> {
        if self.input_tokens != request.context_tokens().get()
            || self.output_tokens > request.maximum_output_tokens().get()
        {
            return Err(GatewayError::InvalidContract {
                reason: "exact Engine usage does not match the admitted token envelope",
            });
        }
        Ok(())
    }
}

// Describes the source and retry policy of one execution-boundary failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayExecutionFailureKind {
    RetryableBackend,
    TerminalBackend,
    Client,
}

// Describes one redacted failure returned by an injected execution or output provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayExecutionFailure {
    kind: GatewayExecutionFailureKind,
    reason: &'static str,
}

impl GatewayExecutionFailure {
    // Creates one backend failure that may move to a sibling only before output begins.
    pub const fn retryable_backend(reason: &'static str) -> Self {
        Self {
            kind: GatewayExecutionFailureKind::RetryableBackend,
            reason,
        }
    }

    // Creates one backend contract failure that must terminate without replay.
    pub const fn terminal_backend(reason: &'static str) -> Self {
        Self {
            kind: GatewayExecutionFailureKind::TerminalBackend,
            reason,
        }
    }

    // Creates one client-output failure that must not change backend health.
    pub const fn client(reason: &'static str) -> Self {
        Self {
            kind: GatewayExecutionFailureKind::Client,
            reason,
        }
    }

    // Returns the failure source and retry policy.
    pub const fn kind(&self) -> GatewayExecutionFailureKind {
        self.kind
    }

    // Returns one stable redacted explanation without request or credential material.
    pub const fn reason(&self) -> &'static str {
        self.reason
    }
}

// Carries one normalized safe response header across the native output boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayResponseHeader {
    name: String,
    value: String,
}

impl GatewayResponseHeader {
    // Creates one lowercase end-to-end response header without hop-by-hop fields.
    pub fn new(name: &str, value: &str) -> Result<Self, GatewayError> {
        let name = name.to_ascii_lowercase();
        if name.is_empty()
            || name.len() > MAX_RESPONSE_HEADER_NAME_BYTES
            || !name.bytes().all(is_header_name_byte)
            || is_forbidden_response_header(&name)
            || value.len() > MAX_RESPONSE_HEADER_VALUE_BYTES
            || !value.bytes().all(is_header_value_byte)
        {
            return Err(GatewayError::InvalidContract {
                reason: "chat-completions response header is unsafe or exceeds its bound",
            });
        }
        Ok(Self {
            name,
            value: value.to_string(),
        })
    }

    // Returns the normalized lowercase response-header name.
    pub fn name(&self) -> &str {
        &self.name
    }

    // Returns the bounded response-header value.
    pub fn value(&self) -> &str {
        &self.value
    }
}

// Carries one bounded response status and end-to-end header set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayResponseHead {
    status_code: u16,
    headers: Vec<GatewayResponseHeader>,
}

impl GatewayResponseHead {
    // Creates one response head with unique bounded end-to-end headers.
    pub fn new(
        status_code: u16,
        headers: Vec<GatewayResponseHeader>,
    ) -> Result<Self, GatewayError> {
        let mut names = HashSet::new();
        let header_bytes = headers.iter().try_fold(0usize, |size, header| {
            size.checked_add(header.name.len())
                .and_then(|value| value.checked_add(header.value.len()))
                .and_then(|value| value.checked_add(4))
        });
        if !(100..=599).contains(&status_code)
            || headers.len() > MAX_RESPONSE_HEADERS
            || header_bytes.is_none_or(|size| size > MAX_RESPONSE_HEADER_BYTES)
            || headers
                .iter()
                .any(|header| !names.insert(header.name.clone()))
        {
            return Err(GatewayError::InvalidContract {
                reason: "chat-completions response head is invalid or exceeds its bound",
            });
        }
        Ok(Self {
            status_code,
            headers,
        })
    }

    // Returns the exact backend status code sent to the caller.
    pub const fn status_code(&self) -> u16 {
        self.status_code
    }

    // Returns the normalized bounded end-to-end response headers.
    pub fn headers(&self) -> &[GatewayResponseHeader] {
        &self.headers
    }
}

// Writes response output while allowing the execution boundary to observe commit state.
pub trait GatewayResponseWriter {
    // Reports whether the caller can still receive output while a request is queued.
    fn client_is_connected(&mut self) -> Result<bool, GatewayExecutionFailure> {
        Ok(true)
    }

    // Commits one validated response head to the inference caller.
    fn write_head(&mut self, head: &GatewayResponseHead) -> Result<(), GatewayExecutionFailure>;

    // Writes one ordered response-body fragment to the inference caller.
    fn write_body(&mut self, body: &[u8]) -> Result<(), GatewayExecutionFailure>;
}

// Forwards one admitted request to a local Engine or authenticated child relay.
pub trait GatewayExecutionProvider: Send + Sync {
    // Streams one attempt and returns exact cumulative usage only after a complete response.
    fn forward(
        &self,
        route: &GatewayRoute,
        request: &GatewayChatCompletionRequest,
        response: &mut dyn GatewayResponseWriter,
    ) -> Result<GatewayExactUsage, GatewayExecutionFailure>;
}

// Waits for a queue state change without owning admission or polling policy.
pub trait GatewayQueueWaiter: Send + Sync {
    // Waits once for capacity, cancellation, or the request's existing deadline.
    fn wait(&self, ticket: &GatewayQueueTicket) -> Result<(), GatewayError>;
}

// Records one completed forwarding lifecycle without retaining request bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayExecutionReceipt {
    placement_group_id: PlacementGroupId,
    status_code: u16,
    attempt_count: u16,
    queued_milliseconds: u64,
    response_body_bytes: usize,
    usage: GatewayExactUsage,
}

impl GatewayExecutionReceipt {
    // Returns the placement group that produced the committed response.
    pub const fn placement_group_id(&self) -> &PlacementGroupId {
        &self.placement_group_id
    }

    // Returns the exact committed backend response status.
    pub const fn status_code(&self) -> u16 {
        self.status_code
    }

    // Returns how many distinct forwarding attempts were made.
    pub const fn attempt_count(&self) -> u16 {
        self.attempt_count
    }

    // Returns the accumulated Gateway queue duration.
    pub const fn queued_milliseconds(&self) -> u64 {
        self.queued_milliseconds
    }

    // Returns exact response-body bytes committed to the caller.
    pub const fn response_body_bytes(&self) -> usize {
        self.response_body_bytes
    }

    // Returns exact cumulative Engine usage charged at completion.
    pub const fn usage(&self) -> GatewayExactUsage {
        self.usage
    }
}

// Coordinates admission, waiting, forwarding, retries, and exact completion accounting.
pub struct GatewayExecution {
    manager: Arc<GatewayManager>,
    provider: Arc<dyn GatewayExecutionProvider>,
    queue_waiter: Arc<dyn GatewayQueueWaiter>,
}

impl GatewayExecution {
    // Creates one execution role from the Gateway owner and its two native mechanisms.
    pub const fn new(
        manager: Arc<GatewayManager>,
        provider: Arc<dyn GatewayExecutionProvider>,
        queue_waiter: Arc<dyn GatewayQueueWaiter>,
    ) -> Self {
        Self {
            manager,
            provider,
            queue_waiter,
        }
    }

    // Authenticates, admits, and forwards one public main-gateway request.
    pub fn forward_public(
        &self,
        bearer_token: &str,
        request: GatewayChatCompletionRequest,
        response: &mut dyn GatewayResponseWriter,
    ) -> Result<GatewayExecutionReceipt, GatewayError> {
        let admission = self
            .manager
            .admit_public(bearer_token, request.request.clone())?;
        self.forward(admission, request, response)
    }

    // Authenticates, admits, and forwards one private main-to-child relay request.
    pub fn forward_relay(
        &self,
        relay_credential: &str,
        request: GatewayChatCompletionRequest,
        response: &mut dyn GatewayResponseWriter,
    ) -> Result<GatewayExecutionReceipt, GatewayError> {
        let admission = self
            .manager
            .admit_relay(relay_credential, request.request.clone())?;
        self.forward(admission, request, response)
    }

    // Runs one bounded execution lifecycle until completion or a terminal failure.
    fn forward(
        &self,
        admission: GatewayAdmission,
        request: GatewayChatCompletionRequest,
        response: &mut dyn GatewayResponseWriter,
    ) -> Result<GatewayExecutionReceipt, GatewayError> {
        let mut admission = admission;
        let mut attempt_count = 0u16;
        loop {
            let reservation = self.reservation(admission, response)?;
            attempt_count = attempt_count.saturating_add(1);
            let dispatched_at = self.manager.telemetry_observed_at();
            let mut bounded_response = BoundedResponseWriter::new(response, &self.manager);
            let outcome =
                self.provider
                    .forward(reservation.route(), &request, &mut bounded_response);
            let completed_at = self.manager.telemetry_observed_at();
            let output_started = bounded_response.has_started();
            let status_code = bounded_response.status_code();
            let response_body_bytes = bounded_response.body_bytes();
            let timing = GatewayTelemetryTiming::from_observations(
                reservation.queued_milliseconds(),
                dispatched_at,
                bounded_response.first_body_at(),
                completed_at,
            );
            drop(bounded_response);

            match outcome {
                Ok(usage) => {
                    let status_code = match status_code {
                        Some(status_code) => status_code,
                        None => {
                            self.manager.fail_execution(reservation, timing)?;
                            return Err(GatewayError::provider(
                                "execution",
                                "provider completed without a response head",
                            ));
                        }
                    };
                    if let Err(error) = usage.validate_for(request.request()) {
                        self.manager.fail_execution(reservation, timing)?;
                        return Err(error);
                    }
                    let placement_group_id = reservation.route().placement_group_id().clone();
                    let queued_milliseconds = reservation.queued_milliseconds();
                    self.manager
                        .complete_execution(reservation, usage, timing)?;
                    return Ok(GatewayExecutionReceipt {
                        placement_group_id,
                        status_code,
                        attempt_count,
                        queued_milliseconds,
                        response_body_bytes,
                        usage,
                    });
                }
                Err(failure) if failure.kind() == GatewayExecutionFailureKind::Client => {
                    self.manager.cancel_execution(reservation, timing)?;
                    return Err(execution_error(&failure, output_started));
                }
                Err(failure) if output_started => {
                    self.manager.fail_execution(reservation, timing)?;
                    return Err(execution_error(&failure, true));
                }
                Err(failure) if failure.kind() != GatewayExecutionFailureKind::RetryableBackend => {
                    self.manager.fail_execution(reservation, timing)?;
                    return Err(execution_error(&failure, false));
                }
                Err(failure) if attempt_count >= MAX_EXECUTION_ATTEMPTS => {
                    self.manager.fail_execution(reservation, timing)?;
                    return Err(GatewayError::provider(
                        "execution_before_output",
                        if failure.reason().is_empty() {
                            "retry limit reached"
                        } else {
                            failure.reason()
                        },
                    ));
                }
                Err(_) => {
                    admission = self.manager.retry_before_output(reservation)?;
                }
            }
        }
    }

    // Resolves immediate admission or waits through one bounded FIFO queue lifecycle.
    fn reservation(
        &self,
        admission: GatewayAdmission,
        response: &mut dyn GatewayResponseWriter,
    ) -> Result<GatewayReservation, GatewayError> {
        match admission {
            GatewayAdmission::Admitted(reservation) => Ok(reservation),
            GatewayAdmission::Queued(ticket) => self.wait_for_reservation(ticket, response),
        }
    }

    // Polls Gateway-owned queue state around an injected native wait primitive.
    fn wait_for_reservation(
        &self,
        ticket: GatewayQueueTicket,
        response: &mut dyn GatewayResponseWriter,
    ) -> Result<GatewayReservation, GatewayError> {
        for _ in 0..MAX_QUEUE_WAIT_CYCLES {
            match self.manager.poll_queue(&ticket) {
                Ok(GatewayQueueStatus::Admitted(reservation)) => return Ok(reservation),
                Ok(GatewayQueueStatus::Waiting) => {
                    if !client_is_connected(response) {
                        return Err(self.cancel_queue_after_error(
                            ticket,
                            GatewayError::provider(
                                "queue_wait",
                                "client disconnected while queued",
                            ),
                        ));
                    }
                    if let Err(error) = self.queue_waiter.wait(&ticket) {
                        return Err(self.cancel_queue_after_error(ticket, error));
                    }
                }
                Err(error) => return Err(self.cancel_queue_after_error(ticket, error)),
            }
        }
        Err(self.cancel_queue_after_error(
            ticket,
            GatewayError::provider("queue_wait", "wait cycle bound exceeded"),
        ))
    }

    // Releases one still-owned queue ticket while preserving its primary failure.
    fn cancel_queue_after_error(
        &self,
        ticket: GatewayQueueTicket,
        error: GatewayError,
    ) -> GatewayError {
        match self.manager.fail_queue(ticket) {
            Ok(()) | Err(GatewayError::RequestNotFound) => error,
            Err(cleanup_error) => cleanup_error,
        }
    }
}

// Converts native connection observation failures into a closed disconnected result.
fn client_is_connected(response: &mut dyn GatewayResponseWriter) -> bool {
    response.client_is_connected().unwrap_or(false)
}

// Tracks committed output and enforces aggregate response bounds around one writer.
struct BoundedResponseWriter<'a> {
    writer: &'a mut dyn GatewayResponseWriter,
    manager: &'a GatewayManager,
    status_code: Option<u16>,
    body_bytes: usize,
    first_body_at: Option<u64>,
}

impl<'a> BoundedResponseWriter<'a> {
    // Creates one uncommitted response boundary around the caller-owned writer.
    const fn new(writer: &'a mut dyn GatewayResponseWriter, manager: &'a GatewayManager) -> Self {
        Self {
            writer,
            manager,
            status_code: None,
            body_bytes: 0,
            first_body_at: None,
        }
    }

    // Returns whether a response head has become visible to the caller.
    const fn has_started(&self) -> bool {
        self.status_code.is_some()
    }

    // Returns the committed response status when output has begun.
    const fn status_code(&self) -> Option<u16> {
        self.status_code
    }

    // Returns exact body bytes successfully committed to the caller.
    const fn body_bytes(&self) -> usize {
        self.body_bytes
    }

    // Returns when the first non-empty response bytes reached the caller boundary.
    const fn first_body_at(&self) -> Option<u64> {
        self.first_body_at
    }
}

impl GatewayResponseWriter for BoundedResponseWriter<'_> {
    // Delegates caller liveness without changing output commitment state.
    fn client_is_connected(&mut self) -> Result<bool, GatewayExecutionFailure> {
        self.writer.client_is_connected()
    }

    // Commits exactly one response head before any body bytes.
    fn write_head(&mut self, head: &GatewayResponseHead) -> Result<(), GatewayExecutionFailure> {
        if self.status_code.is_some() {
            return Err(GatewayExecutionFailure::terminal_backend(
                "provider emitted more than one response head",
            ));
        }
        self.writer.write_head(head)?;
        self.status_code = Some(head.status_code());
        Ok(())
    }

    // Commits one body fragment while enforcing ordered aggregate output bounds.
    fn write_body(&mut self, body: &[u8]) -> Result<(), GatewayExecutionFailure> {
        if self.status_code.is_none() {
            return Err(GatewayExecutionFailure::terminal_backend(
                "provider emitted a response body before its head",
            ));
        }
        let body_bytes = self.body_bytes.checked_add(body.len()).ok_or_else(|| {
            GatewayExecutionFailure::terminal_backend("response body size overflowed")
        })?;
        if body_bytes > MAX_RESPONSE_BODY_BYTES {
            return Err(GatewayExecutionFailure::terminal_backend(
                "response body exceeds 64 MiB",
            ));
        }
        self.writer.write_body(body)?;
        self.body_bytes = body_bytes;
        if !body.is_empty() && self.first_body_at.is_none() {
            self.first_body_at = self.manager.telemetry_observed_at();
        }
        Ok(())
    }
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

// Returns whether one response-header byte is visible ASCII or horizontal tab.
fn is_header_value_byte(byte: u8) -> bool {
    byte == b'\t' || (b' '..=b'~').contains(&byte)
}

// Rejects hop-by-hop, credential, server-identity, and transport-sized fields.
fn is_forbidden_response_header(name: &str) -> bool {
    matches!(
        name,
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
    ) || name.starts_with("access-control-")
}

// Maps one provider failure to a stable phase-specific Gateway failure.
fn execution_error(failure: &GatewayExecutionFailure, output_started: bool) -> GatewayError {
    GatewayError::provider(
        if output_started {
            "execution_after_output"
        } else {
            "execution_before_output"
        },
        failure.reason(),
    )
}
