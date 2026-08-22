#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Engine-neutral exact rendered-chat token-count protocol.

Every Engine OCI adapter accepts the original OpenAI request at the fixed
protocol endpoint. Core deliberately performs no engine-specific translation:
the adapter that owns the tokenizer and chat template owns exact counting too.
"""

from __future__ import annotations

import json
from typing import Any


LETSINFER_TOKEN_COUNT_PROTOCOL = "letsinfer-token-count-v1"
TOKEN_COUNT_PROTOCOLS = frozenset({LETSINFER_TOKEN_COUNT_PROTOCOL})


class TokenCountError(ValueError):
    """A token-count request or response violates the stable protocol."""


def _request_object(model: str, body: bytes) -> dict[str, Any]:
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TokenCountError("request body is not valid JSON") from error
    if not isinstance(value, dict):
        raise TokenCountError("request body must be an object")
    if value.get("model") != model:
        raise TokenCountError("request model does not match the selected runtime")
    messages = value.get("messages")
    if not isinstance(messages, list) or not messages:
        raise TokenCountError("request.messages must be a non-empty list")
    return value


def prepare_token_count_request(
    protocol: str, model: str, openai_body: bytes
) -> bytes:
    """Validate and forward the exact OpenAI request to its Engine adapter."""

    if protocol != LETSINFER_TOKEN_COUNT_PROTOCOL:
        raise TokenCountError("unsupported token-count protocol")
    _request_object(model, openai_body)
    return openai_body


def parse_token_count_response(protocol: str, model: str, body: bytes) -> int:
    """Validate one normalized Engine adapter token-count response."""

    if protocol != LETSINFER_TOKEN_COUNT_PROTOCOL:
        raise TokenCountError("unsupported token-count protocol")
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TokenCountError("token-count response is not valid JSON") from error
    if not isinstance(value, dict) or set(value) != {
        "object",
        "model",
        "prompt_tokens",
    }:
        raise TokenCountError("invalid Let's Infer token-count response")
    if value.get("object") != "token_count" or value.get("model") != model:
        raise TokenCountError("token-count identity mismatch")
    count = value.get("prompt_tokens")
    if not isinstance(count, int) or isinstance(count, bool) or count <= 0:
        raise TokenCountError("token count must be a positive integer")
    return count
