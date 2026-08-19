#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Exact rendered-chat token-count protocol adapters.

The public gateway accepts OpenAI chat-completion requests. Some engines expose
their exact tokenizer through a different wire contract; this module translates
only request shapes that can be represented without changing the rendered chat
and rejects everything else.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any


LETSINFER_TOKEN_COUNT_PROTOCOL = "letsinfer-token-count-v1"
SGLANG_ANTHROPIC_TOKEN_COUNT_PROTOCOL = "sglang-anthropic-count-tokens-v1"
SGLANG_OPENAI_TOKENIZE_PATH = "/v1/tokenize"
SGLANG_TOKENIZE_RESPONSE_MAX_BYTES = 64 * 1024 * 1024
TOKEN_COUNT_PROTOCOLS = frozenset(
    {
        LETSINFER_TOKEN_COUNT_PROTOCOL,
        SGLANG_ANTHROPIC_TOKEN_COUNT_PROTOCOL,
    }
)


class TokenCountError(ValueError):
    """A token-count request or response cannot be normalized exactly."""


def prepare_sglang_tokenize_request(model: str, body: bytes) -> bytes:
    """Build SGLang's exact OpenAI-chat tokenize request without lossy translation."""
    try:
        request = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TokenCountError("request body is not valid JSON") from error
    request = _object(request, "request")
    if request.get("model") != model:
        raise TokenCountError("request model does not match the selected runtime")
    messages = request.get("messages")
    if not isinstance(messages, list) or not messages:
        raise TokenCountError("request.messages must be a non-empty list")

    # These names belong to SGLang's TokenizeRequest itself. An OpenAI chat
    # request may contain them as ignored extension fields, but allowing them
    # to change tokenize behavior would no longer reproduce inference exactly.
    request.pop("prompt", None)
    request.pop("add_special_tokens", None)
    return json.dumps(request, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def parse_sglang_tokenize_response(chunks: Iterable[bytes]) -> int:
    """Validate SGLang's token-id response in bounded memory and return its count."""

    class Cursor:
        def __init__(self) -> None:
            self.chunks = iter(chunks)
            self.chunk = b""
            self.offset = 0
            self.total = 0
            self.pushed: int | None = None

        def take(self) -> int | None:
            if self.pushed is not None:
                value = self.pushed
                self.pushed = None
                return value
            while self.offset >= len(self.chunk):
                try:
                    chunk = next(self.chunks)
                except StopIteration:
                    return None
                if not isinstance(chunk, bytes):
                    raise TokenCountError("SGLang tokenize response chunks must be bytes")
                self.total += len(chunk)
                if self.total > SGLANG_TOKENIZE_RESPONSE_MAX_BYTES:
                    raise TokenCountError("SGLang tokenize response exceeds its size limit")
                self.chunk = chunk
                self.offset = 0
                if not chunk:
                    continue
            value = self.chunk[self.offset]
            self.offset += 1
            return value

        def push(self, value: int) -> None:
            if self.pushed is not None:
                raise TokenCountError("invalid SGLang tokenize response parser state")
            self.pushed = value

    cursor = Cursor()
    whitespace = {9, 10, 13, 32}

    def nonspace() -> int | None:
        value = cursor.take()
        while value in whitespace:
            value = cursor.take()
        return value

    def expect(value: int) -> None:
        if nonspace() != value:
            raise TokenCountError("invalid SGLang tokenize response")

    def key(name: bytes) -> None:
        expect(ord('"'))
        for value in name:
            if cursor.take() != value:
                raise TokenCountError("invalid SGLang tokenize response")
        if cursor.take() != ord('"'):
            raise TokenCountError("invalid SGLang tokenize response")

    def integer(first: int | None = None) -> int:
        value = nonspace() if first is None else first
        if value is None or not ord("0") <= value <= ord("9"):
            raise TokenCountError("invalid SGLang tokenize response integer")
        leading_zero = value == ord("0")
        result = value - ord("0")
        digits = 1
        while True:
            value = cursor.take()
            if value is not None and ord("0") <= value <= ord("9"):
                if leading_zero:
                    raise TokenCountError("invalid SGLang tokenize response integer")
                result = result * 10 + value - ord("0")
                digits += 1
                continue
            if value is not None:
                cursor.push(value)
            if digits == 0:
                raise TokenCountError("invalid SGLang tokenize response integer")
            return result

    expect(ord("{"))
    key(b"tokens")
    expect(ord(":"))
    expect(ord("["))
    token_count = 0
    value = nonspace()
    if value != ord("]"):
        while True:
            integer(value)
            token_count += 1
            delimiter = nonspace()
            if delimiter == ord("]"):
                break
            if delimiter != ord(","):
                raise TokenCountError("invalid SGLang tokenize token array")
            value = nonspace()

    expect(ord(","))
    key(b"count")
    expect(ord(":"))
    declared_count = integer()
    expect(ord(","))
    key(b"max_model_len")
    expect(ord(":"))
    max_model_len = integer()
    expect(ord("}"))
    if nonspace() is not None:
        raise TokenCountError("SGLang tokenize response has trailing data")
    if token_count <= 0 or declared_count != token_count or max_model_len <= 0:
        raise TokenCountError("invalid SGLang tokenize response counts")
    return token_count


def _object(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TokenCountError(f"{where} must be an object")
    return value


def _nonempty_string(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise TokenCountError(f"{where} must be a non-empty string")
    return value


def _image_source(value: Any, where: str) -> dict[str, str]:
    image = _object(value, where)
    if set(image) != {"url"}:
        raise TokenCountError(f"{where} must contain only url")
    url = _nonempty_string(image.get("url"), f"{where}.url")
    if url.startswith("data:"):
        metadata, separator, data = url.partition(",")
        prefix = "data:"
        suffix = ";base64"
        if (
            not separator
            or not metadata.startswith(prefix)
            or not metadata.endswith(suffix)
            or not data
        ):
            raise TokenCountError(f"{where}.url has an invalid data URL")
        media_type = metadata[len(prefix) : -len(suffix)]
        if not media_type or any(character.isspace() for character in media_type):
            raise TokenCountError(f"{where}.url has an invalid media type")
        return {
            "type": "base64",
            "media_type": media_type,
            "data": data,
        }
    if not url.startswith(("http://", "https://")):
        raise TokenCountError(f"{where}.url must be HTTP(S) or a base64 data URL")
    return {"type": "url", "url": url}


def _content_blocks(value: Any, where: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise TokenCountError(f"{where} must be a non-empty content list")
    blocks: list[dict[str, Any]] = []
    for index, raw in enumerate(value):
        item_where = f"{where}[{index}]"
        item = _object(raw, item_where)
        kind = item.get("type")
        if kind == "text" and set(item) == {"type", "text"}:
            text = item.get("text")
            if not isinstance(text, str):
                raise TokenCountError(f"{item_where}.text must be a string")
            blocks.append({"type": "text", "text": text})
        elif kind == "image_url" and set(item) == {"type", "image_url"}:
            blocks.append(
                {
                    "type": "image",
                    "source": _image_source(item.get("image_url"), f"{item_where}.image_url"),
                }
            )
        else:
            raise TokenCountError(f"{item_where} is not an exactly supported content block")
    return blocks


def _message_content(value: Any, where: str, *, allow_null: bool = False) -> Any:
    if isinstance(value, str):
        return value
    if value is None and allow_null:
        return None
    return _content_blocks(value, where)


def _tool_calls(value: Any, where: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise TokenCountError(f"{where} must be a non-empty list")
    blocks: list[dict[str, Any]] = []
    for index, raw in enumerate(value):
        item_where = f"{where}[{index}]"
        item = _object(raw, item_where)
        if set(item) != {"id", "type", "function"} or item.get("type") != "function":
            raise TokenCountError(f"{item_where} must be one exact function call")
        function = _object(item.get("function"), f"{item_where}.function")
        if set(function) != {"name", "arguments"}:
            raise TokenCountError(
                f"{item_where}.function must contain only name and arguments"
            )
        arguments = function.get("arguments")
        if not isinstance(arguments, str):
            raise TokenCountError(f"{item_where}.function.arguments must be JSON text")
        try:
            parsed = json.loads(arguments)
        except json.JSONDecodeError as error:
            raise TokenCountError(
                f"{item_where}.function.arguments must be valid JSON"
            ) from error
        if not isinstance(parsed, dict):
            raise TokenCountError(
                f"{item_where}.function.arguments must encode an object"
            )
        blocks.append(
            {
                "type": "tool_use",
                "id": _nonempty_string(item.get("id"), f"{item_where}.id"),
                "name": _nonempty_string(function.get("name"), f"{item_where}.function.name"),
                "input": parsed,
            }
        )
    return blocks


def _tools(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise TokenCountError("request.tools must be a non-empty list")
    converted: list[dict[str, Any]] = []
    for index, raw in enumerate(value):
        where = f"request.tools[{index}]"
        tool = _object(raw, where)
        if set(tool) != {"type", "function"} or tool.get("type") != "function":
            raise TokenCountError(f"{where} must be one exact function tool")
        function = _object(tool.get("function"), f"{where}.function")
        allowed = {"name", "description", "parameters"}
        if set(function) - allowed or not {"name", "parameters"}.issubset(function):
            raise TokenCountError(
                f"{where}.function must contain name, parameters, and optional description"
            )
        parameters = _object(function.get("parameters"), f"{where}.function.parameters")
        converted_tool: dict[str, Any] = {
            "name": _nonempty_string(function.get("name"), f"{where}.function.name"),
            "input_schema": parameters,
        }
        description = function.get("description")
        if description is not None:
            if not isinstance(description, str):
                raise TokenCountError(f"{where}.function.description must be a string")
            converted_tool["description"] = description
        converted.append(converted_tool)
    return converted


def _tool_choice(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        choices = {"none": "none", "auto": "auto", "required": "any"}
        if value not in choices:
            raise TokenCountError("request.tool_choice is unsupported")
        return {"type": choices[value]}
    choice = _object(value, "request.tool_choice")
    if set(choice) != {"type", "function"} or choice.get("type") != "function":
        raise TokenCountError("request.tool_choice must select one exact function")
    function = _object(choice.get("function"), "request.tool_choice.function")
    if set(function) != {"name"}:
        raise TokenCountError("request.tool_choice.function must contain only name")
    return {
        "type": "tool",
        "name": _nonempty_string(function.get("name"), "request.tool_choice.function.name"),
    }


def _sglang_request(model: str, body: bytes) -> bytes:
    try:
        request = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TokenCountError("request body is not valid JSON") from error
    request = _object(request, "request")
    if request.get("model") != model:
        raise TokenCountError("request model does not match the selected runtime")
    messages = request.get("messages")
    if not isinstance(messages, list) or not messages:
        raise TokenCountError("request.messages must be a non-empty list")

    system_blocks: list[dict[str, str]] = []
    converted_messages: list[dict[str, Any]] = []
    system_seen = False
    for index, raw in enumerate(messages):
        where = f"request.messages[{index}]"
        message = _object(raw, where)
        role = message.get("role")
        if role not in {"system", "user", "assistant", "tool"}:
            raise TokenCountError(f"{where}.role is unsupported")
        allowed = {"role", "content"}
        if role == "assistant":
            allowed.add("tool_calls")
        elif role == "tool":
            allowed.add("tool_call_id")
        if set(message) - allowed:
            raise TokenCountError(f"{where} contains unsupported rendered-chat fields")

        if role == "system":
            if system_seen or converted_messages:
                raise TokenCountError(
                    f"{where} must be the request's single leading system message"
                )
            system_seen = True
            content = _message_content(message.get("content"), f"{where}.content")
            blocks = [{"type": "text", "text": content}] if isinstance(content, str) else content
            if any(block.get("type") != "text" for block in blocks):
                raise TokenCountError(f"{where}.content cannot contain non-text system content")
            system_blocks.extend(blocks)
            continue

        if role == "tool":
            tool_call_id = _nonempty_string(
                message.get("tool_call_id"), f"{where}.tool_call_id"
            )
            content = _message_content(message.get("content"), f"{where}.content")
            converted_messages.append(
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": tool_call_id,
                            "content": content,
                        }
                    ],
                }
            )
            continue

        content = _message_content(
            message.get("content"),
            f"{where}.content",
            allow_null=role == "assistant" and "tool_calls" in message,
        )
        if role == "assistant" and "tool_calls" in message:
            blocks = [] if content is None else (
                [{"type": "text", "text": content}] if isinstance(content, str) else content
            )
            blocks.extend(_tool_calls(message["tool_calls"], f"{where}.tool_calls"))
            converted_messages.append({"role": role, "content": blocks})
        else:
            converted_messages.append({"role": role, "content": content})

    normalized: dict[str, Any] = {"model": model, "messages": converted_messages}
    if system_blocks:
        normalized["system"] = system_blocks
    if "tools" in request:
        normalized["tools"] = _tools(request["tools"])
    if "tool_choice" in request:
        normalized["tool_choice"] = _tool_choice(request["tool_choice"])

    template_kwargs = request.get("chat_template_kwargs")
    if template_kwargs is not None:
        if not isinstance(template_kwargs, dict) or set(template_kwargs) != {"enable_thinking"}:
            raise TokenCountError(
                "request.chat_template_kwargs must contain only enable_thinking"
            )
        enable_thinking = template_kwargs.get("enable_thinking")
        if not isinstance(enable_thinking, bool):
            raise TokenCountError("request.chat_template_kwargs.enable_thinking must be boolean")
        normalized["thinking"] = (
            {"type": "enabled", "budget_tokens": 1024}
            if enable_thinking
            else {"type": "disabled"}
        )

    return json.dumps(normalized, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def prepare_token_count_request(
    protocol: str, model: str, openai_body: bytes
) -> bytes:
    """Translate an OpenAI chat request to the engine's exact count operation."""
    if protocol == LETSINFER_TOKEN_COUNT_PROTOCOL:
        return openai_body
    if protocol == SGLANG_ANTHROPIC_TOKEN_COUNT_PROTOCOL:
        return _sglang_request(model, openai_body)
    raise TokenCountError("unsupported token-count protocol")


def parse_token_count_response(protocol: str, model: str, body: bytes) -> int:
    """Validate and normalize one engine token-count response."""
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TokenCountError("token-count response is not valid JSON") from error
    if protocol == LETSINFER_TOKEN_COUNT_PROTOCOL:
        if not isinstance(value, dict) or set(value) != {
            "object",
            "model",
            "prompt_tokens",
        }:
            raise TokenCountError("invalid Let's Infer token-count response")
        if value.get("object") != "token_count" or value.get("model") != model:
            raise TokenCountError("token-count identity mismatch")
        count = value.get("prompt_tokens")
    elif protocol == SGLANG_ANTHROPIC_TOKEN_COUNT_PROTOCOL:
        if not isinstance(value, dict) or set(value) != {"input_tokens"}:
            raise TokenCountError("invalid SGLang token-count response")
        count = value.get("input_tokens")
    else:
        raise TokenCountError("unsupported token-count protocol")
    if not isinstance(count, int) or isinstance(count, bool) or count <= 0:
        raise TokenCountError("token count must be a positive integer")
    return count
