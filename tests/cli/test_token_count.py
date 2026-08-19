# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import json
import unittest

from core.token_count import (
    LETSINFER_TOKEN_COUNT_PROTOCOL,
    SGLANG_ANTHROPIC_TOKEN_COUNT_PROTOCOL,
    TokenCountError,
    parse_sglang_tokenize_response,
    parse_token_count_response,
    prepare_sglang_tokenize_request,
    prepare_token_count_request,
)


class TokenCountAdapterTests(unittest.TestCase):
    def test_sglang_translates_system_tools_calls_and_results(self) -> None:
        request = {
            "model": "fixture-model",
            "messages": [
                {"role": "system", "content": "Be precise."},
                {"role": "user", "content": "List files."},
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {
                                "name": "files_list",
                                "arguments": "{\"path\":\".\"}",
                            },
                        }
                    ],
                },
                {
                    "role": "tool",
                    "tool_call_id": "call_1",
                    "content": "AGENTS.md",
                },
            ],
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "files_list",
                        "description": "List files",
                        "parameters": {
                            "type": "object",
                            "properties": {"path": {"type": "string"}},
                            "required": ["path"],
                        },
                    },
                }
            ],
            "tool_choice": {
                "type": "function",
                "function": {"name": "files_list"},
            },
            "chat_template_kwargs": {"enable_thinking": False},
            "max_tokens": 128,
            "temperature": 0,
        }
        actual = json.loads(
            prepare_token_count_request(
                SGLANG_ANTHROPIC_TOKEN_COUNT_PROTOCOL,
                "fixture-model",
                json.dumps(request).encode(),
            )
        )
        self.assertEqual(actual["system"], [{"type": "text", "text": "Be precise."}])
        self.assertEqual(actual["messages"][1]["content"][0]["type"], "tool_use")
        self.assertEqual(actual["messages"][1]["content"][0]["input"], {"path": "."})
        self.assertEqual(actual["messages"][2]["content"][0]["type"], "tool_result")
        self.assertEqual(actual["tools"][0]["input_schema"]["type"], "object")
        self.assertEqual(actual["tool_choice"], {"type": "tool", "name": "files_list"})
        self.assertEqual(actual["thinking"], {"type": "disabled"})
        self.assertNotIn("max_tokens", actual)

    def test_sglang_rejects_lossy_or_malformed_chat_shapes(self) -> None:
        cases = [
            {
                "model": "fixture-model",
                "messages": [
                    {"role": "user", "content": "hello"},
                    {"role": "system", "content": "late"},
                ],
            },
            {
                "model": "fixture-model",
                "messages": [
                    {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call_1",
                                "type": "function",
                                "function": {"name": "tool", "arguments": "[]"},
                            }
                        ],
                    }
                ],
            },
            {
                "model": "fixture-model",
                "messages": [{"role": "developer", "content": "hello"}],
            },
        ]
        for request in cases:
            with self.subTest(request=request), self.assertRaises(TokenCountError):
                prepare_token_count_request(
                    SGLANG_ANTHROPIC_TOKEN_COUNT_PROTOCOL,
                    "fixture-model",
                    json.dumps(request).encode(),
                )

    def test_sglang_response_is_normalized_fail_closed(self) -> None:
        self.assertEqual(
            parse_token_count_response(
                SGLANG_ANTHROPIC_TOKEN_COUNT_PROTOCOL,
                "fixture-model",
                b'{"input_tokens":123}',
            ),
            123,
        )
        for payload in (
            b'{"input_tokens":true}',
            b'{"input_tokens":123,"extra":1}',
            b'{"prompt_tokens":123}',
        ):
            with self.subTest(payload=payload), self.assertRaises(TokenCountError):
                parse_token_count_response(
                    SGLANG_ANTHROPIC_TOKEN_COUNT_PROTOCOL,
                    "fixture-model",
                    payload,
                )

    def test_sglang_openai_tokenize_fallback_preserves_reasoning_history(self) -> None:
        request = {
            "model": "fixture-model",
            "messages": [
                {"role": "user", "content": "hello"},
                {
                    "role": "assistant",
                    "content": "hi",
                    "reasoning_content": "thinking",
                },
                {"role": "user", "content": "again"},
            ],
            "max_tokens": 1,
            "prompt": "must not override messages",
            "add_special_tokens": True,
        }
        actual = json.loads(
            prepare_sglang_tokenize_request(
                "fixture-model", json.dumps(request).encode()
            )
        )
        self.assertEqual(
            actual["messages"][1]["reasoning_content"], "thinking"
        )
        self.assertEqual(actual["max_tokens"], 1)
        self.assertNotIn("prompt", actual)
        self.assertNotIn("add_special_tokens", actual)

    def test_sglang_tokenize_response_streams_and_validates_exact_count(self) -> None:
        token_ids = list(range(30_000))
        payload = json.dumps(
            {
                "tokens": token_ids,
                "count": len(token_ids),
                "max_model_len": 1_000_000,
            },
            separators=(",", ":"),
        ).encode()
        self.assertGreater(len(payload), 128 * 1024)
        chunks = (payload[index : index + 997] for index in range(0, len(payload), 997))
        self.assertEqual(parse_sglang_tokenize_response(chunks), len(token_ids))
        with self.assertRaises(TokenCountError):
            parse_sglang_tokenize_response(
                [b'{"tokens":[1,2],"count":3,"max_model_len":100}']
            )

    def test_native_letsinfer_protocol_remains_unchanged(self) -> None:
        request = b'{"model":"fixture-model","messages":[]}'
        self.assertIs(
            prepare_token_count_request(
                LETSINFER_TOKEN_COUNT_PROTOCOL, "fixture-model", request
            ),
            request,
        )
        self.assertEqual(
            parse_token_count_response(
                LETSINFER_TOKEN_COUNT_PROTOCOL,
                "fixture-model",
                b'{"object":"token_count","model":"fixture-model","prompt_tokens":9}',
            ),
            9,
        )


if __name__ == "__main__":
    unittest.main()
