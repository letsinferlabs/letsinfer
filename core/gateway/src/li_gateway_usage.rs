// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use serde_json::Value;

use crate::{GatewayExactUsage, GatewayExecutionFailure};

const MAX_USAGE_DOCUMENT_BYTES: usize = 128 * 1024;
const MAX_USAGE_CHOICES: usize = 4096;

// Reconciles bounded OpenAI JSON or fragmented SSE cumulative usage observations.
pub(crate) struct GatewayUsageParser {
    streaming: bool,
    document: Vec<u8>,
    pending_line: Vec<u8>,
    discard_line: bool,
    input_tokens: u64,
    cached_tokens: u64,
    aggregate_output_tokens: u64,
    choice_output_tokens: BTreeMap<u64, u64>,
    saw_exact: bool,
}

impl GatewayUsageParser {
    // Creates one parser whose mode is fixed by the validated response content type.
    pub(crate) const fn new(streaming: bool) -> Self {
        Self {
            streaming,
            document: Vec::new(),
            pending_line: Vec::new(),
            discard_line: false,
            input_tokens: 0,
            cached_tokens: 0,
            aggregate_output_tokens: 0,
            choice_output_tokens: BTreeMap::new(),
            saw_exact: false,
        }
    }

    // Consumes one arbitrarily fragmented body chunk within the parser's fixed memory bound.
    pub(crate) fn feed(&mut self, bytes: &[u8]) -> Result<(), GatewayExecutionFailure> {
        if self.streaming {
            self.feed_sse(bytes)
        } else {
            let length = self
                .document
                .len()
                .checked_add(bytes.len())
                .filter(|length| *length <= MAX_USAGE_DOCUMENT_BYTES)
                .ok_or_else(|| {
                    GatewayExecutionFailure::terminal_backend(
                        "OpenAI JSON usage document exceeds 128 KiB",
                    )
                })?;
            self.document.reserve(length - self.document.len());
            self.document.extend_from_slice(bytes);
            Ok(())
        }
    }

    // Produces one exact cumulative usage result without double-counting SSE fragments.
    pub(crate) fn finish(mut self) -> Result<GatewayExactUsage, GatewayExecutionFailure> {
        if self.streaming {
            if !self.pending_line.is_empty() && !self.discard_line {
                let line = std::mem::take(&mut self.pending_line);
                self.observe_sse_line(&line)?;
            }
        } else {
            let document: Value = serde_json::from_slice(&self.document).map_err(|_| {
                GatewayExecutionFailure::terminal_backend("OpenAI JSON response is malformed")
            })?;
            let observation = usage_observation(&document)?.ok_or_else(|| {
                GatewayExecutionFailure::terminal_backend(
                    "OpenAI JSON response has no exact cumulative usage",
                )
            })?;
            self.observe(observation)?;
        }
        if !self.saw_exact {
            return Err(GatewayExecutionFailure::terminal_backend(
                "OpenAI response has no exact cumulative usage",
            ));
        }
        let choice_output_tokens = self
            .choice_output_tokens
            .values()
            .try_fold(0u64, |total, value| total.checked_add(*value));
        let output_tokens = choice_output_tokens
            .map(|value| value.max(self.aggregate_output_tokens))
            .ok_or_else(|| {
                GatewayExecutionFailure::terminal_backend("OpenAI usage output tokens overflow")
            })?;
        GatewayExactUsage::new(self.input_tokens, output_tokens, self.cached_tokens).map_err(|_| {
            GatewayExecutionFailure::terminal_backend("OpenAI cumulative usage is inconsistent")
        })
    }

    // Consumes fragmented SSE lines and discards any one line that exceeds 128 KiB.
    fn feed_sse(&mut self, bytes: &[u8]) -> Result<(), GatewayExecutionFailure> {
        for byte in bytes {
            if *byte == b'\n' {
                if !self.discard_line {
                    let line = std::mem::take(&mut self.pending_line);
                    self.observe_sse_line(&line)?;
                } else {
                    self.pending_line.clear();
                }
                self.discard_line = false;
                continue;
            }
            if self.discard_line {
                continue;
            }
            self.pending_line.push(*byte);
            if self.pending_line.len() > MAX_USAGE_DOCUMENT_BYTES {
                self.pending_line.clear();
                self.discard_line = true;
            }
        }
        Ok(())
    }

    // Parses one SSE data line and observes exact usage when the event carries it.
    fn observe_sse_line(&mut self, line: &[u8]) -> Result<(), GatewayExecutionFailure> {
        let candidate = trim_ascii(line);
        let Some(candidate) = candidate.strip_prefix(b"data:") else {
            return Ok(());
        };
        let candidate = trim_ascii(candidate);
        if candidate == b"[DONE]" || !candidate.starts_with(b"{") {
            return Ok(());
        }
        let value: Value = serde_json::from_slice(candidate).map_err(|_| {
            GatewayExecutionFailure::terminal_backend("OpenAI SSE usage event is malformed")
        })?;
        if let Some(observation) = usage_observation(&value)? {
            self.observe(observation)?;
        }
        Ok(())
    }

    // Reconciles one cumulative observation by monotonic maxima per aggregate or choice.
    fn observe(&mut self, observation: UsageObservation) -> Result<(), GatewayExecutionFailure> {
        self.saw_exact = true;
        self.input_tokens = self.input_tokens.max(observation.input_tokens);
        self.cached_tokens = self.cached_tokens.max(observation.cached_tokens);
        if let Some(choice_index) = observation.choice_index {
            if !self.choice_output_tokens.contains_key(&choice_index)
                && self.choice_output_tokens.len() >= MAX_USAGE_CHOICES
            {
                return Err(GatewayExecutionFailure::terminal_backend(
                    "OpenAI SSE usage has too many choices",
                ));
            }
            let value = self.choice_output_tokens.entry(choice_index).or_default();
            *value = (*value).max(observation.output_tokens);
        } else {
            self.aggregate_output_tokens =
                self.aggregate_output_tokens.max(observation.output_tokens);
        }
        Ok(())
    }
}

// Carries one exact cumulative usage event and its optional per-choice identity.
struct UsageObservation {
    input_tokens: u64,
    output_tokens: u64,
    cached_tokens: u64,
    choice_index: Option<u64>,
}

// Parses one exact OpenAI usage object while rejecting malformed present fields.
fn usage_observation(value: &Value) -> Result<Option<UsageObservation>, GatewayExecutionFailure> {
    let Some(document) = value.as_object() else {
        return Err(GatewayExecutionFailure::terminal_backend(
            "OpenAI response must be an object",
        ));
    };
    let Some(usage) = document.get("usage") else {
        return Ok(None);
    };
    let usage = usage.as_object().ok_or_else(|| {
        GatewayExecutionFailure::terminal_backend("OpenAI usage must be an object")
    })?;
    let input_tokens = integer_alias(usage, "prompt_tokens", "input_tokens")?;
    let output_tokens = integer_alias(usage, "completion_tokens", "output_tokens")?;
    let cached_tokens = match usage.get("prompt_tokens_details") {
        None | Some(Value::Null) => 0,
        Some(Value::Object(details)) => details
            .get("cached_tokens")
            .map(nonnegative_integer)
            .transpose()?
            .unwrap_or(0),
        Some(_) => {
            return Err(GatewayExecutionFailure::terminal_backend(
                "OpenAI prompt token details are malformed",
            ));
        }
    };
    if cached_tokens > input_tokens {
        return Err(GatewayExecutionFailure::terminal_backend(
            "OpenAI cached tokens exceed prompt tokens",
        ));
    }
    let choice_index = document
        .get("choices")
        .and_then(Value::as_array)
        .filter(|choices| choices.len() == 1)
        .and_then(|choices| choices[0].as_object())
        .and_then(|choice| choice.get("index"))
        .map(nonnegative_integer)
        .transpose()?;
    Ok(Some(UsageObservation {
        input_tokens,
        output_tokens,
        cached_tokens,
        choice_index,
    }))
}

// Reads one required non-negative integer from either accepted OpenAI field spelling.
fn integer_alias(
    object: &serde_json::Map<String, Value>,
    primary: &'static str,
    alternate: &'static str,
) -> Result<u64, GatewayExecutionFailure> {
    let value = object
        .get(primary)
        .or_else(|| object.get(alternate))
        .ok_or_else(|| {
            GatewayExecutionFailure::terminal_backend("OpenAI usage token count is missing")
        })?;
    nonnegative_integer(value)
}

// Converts one JSON number to a non-negative integral token count.
fn nonnegative_integer(value: &Value) -> Result<u64, GatewayExecutionFailure> {
    value.as_u64().ok_or_else(|| {
        GatewayExecutionFailure::terminal_backend(
            "OpenAI usage token count must be a non-negative integer",
        )
    })
}

// Adds protocol-required streaming usage without changing non-streaming requests.
pub(crate) fn instrument_stream_usage(body: &[u8]) -> Result<Vec<u8>, GatewayExecutionFailure> {
    let mut value: Value = serde_json::from_slice(body).map_err(|_| {
        GatewayExecutionFailure::terminal_backend("chat-completions request is not valid JSON")
    })?;
    let document = value.as_object_mut().ok_or_else(|| {
        GatewayExecutionFailure::terminal_backend("chat-completions request must be an object")
    })?;
    if document.get("stream") != Some(&Value::Bool(true)) {
        return Ok(body.to_vec());
    }
    let options = document
        .entry("stream_options")
        .or_insert_with(|| Value::Object(serde_json::Map::new()))
        .as_object_mut()
        .ok_or_else(|| {
            GatewayExecutionFailure::terminal_backend(
                "chat-completions stream_options must be an object",
            )
        })?;
    options.insert("include_usage".to_string(), Value::Bool(true));
    serde_json::to_vec(&value).map_err(|_| {
        GatewayExecutionFailure::terminal_backend("chat-completions request cannot be encoded")
    })
}

// Returns whether the normalized request asks for an SSE response.
pub(crate) fn request_is_streaming(body: &[u8]) -> Result<bool, GatewayExecutionFailure> {
    let value: Value = serde_json::from_slice(body).map_err(|_| {
        GatewayExecutionFailure::terminal_backend("chat-completions request is not valid JSON")
    })?;
    let document = value.as_object().ok_or_else(|| {
        GatewayExecutionFailure::terminal_backend("chat-completions request must be an object")
    })?;
    Ok(document.get("stream") == Some(&Value::Bool(true)))
}

// Trims only HTTP/SSE ASCII whitespace without decoding untrusted bytes.
fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}
