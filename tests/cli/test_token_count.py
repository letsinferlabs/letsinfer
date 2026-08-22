# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import json
import unittest

from core.exact_tokens import (
    LETSINFER_TOKEN_COUNT_PROTOCOL,
    TokenCountError,
    parse_token_count_response,
    prepare_token_count_request,
)


class TokenCountAdapterTests(unittest.TestCase):
    def test_request_is_forwarded_byte_for_byte(self) -> None:
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
            "tools": [{"type": "function", "function": {"name": "tool"}}],
        }
        payload = json.dumps(request, separators=(",", ":")).encode()
        self.assertIs(
            prepare_token_count_request(
                LETSINFER_TOKEN_COUNT_PROTOCOL, "fixture-model", payload
            ),
            payload,
        )

    def test_response_is_normalized_fail_closed(self) -> None:
        self.assertEqual(
            parse_token_count_response(
                LETSINFER_TOKEN_COUNT_PROTOCOL,
                "fixture-model",
                b'{"object":"token_count","model":"fixture-model","prompt_tokens":9}',
            ),
            9,
        )
        for payload in (
            b'{"object":"token_count","model":"fixture-model","prompt_tokens":true}',
            b'{"object":"token_count","model":"other","prompt_tokens":9}',
            b'{"object":"token_count","model":"fixture-model","prompt_tokens":9,"extra":1}',
        ):
            with self.subTest(payload=payload), self.assertRaises(TokenCountError):
                parse_token_count_response(
                    LETSINFER_TOKEN_COUNT_PROTOCOL, "fixture-model", payload
                )

    def test_request_identity_and_shape_are_validated(self) -> None:
        for request in (
            {"model": "other", "messages": [{"role": "user", "content": "x"}]},
            {"model": "fixture-model", "messages": []},
            [],
        ):
            with self.subTest(request=request), self.assertRaises(TokenCountError):
                prepare_token_count_request(
                    LETSINFER_TOKEN_COUNT_PROTOCOL,
                    "fixture-model",
                    json.dumps(request).encode(),
                )

    def test_unknown_protocol_is_rejected(self) -> None:
        with self.assertRaises(TokenCountError):
            prepare_token_count_request(
                "engine-specific-v1",
                "fixture-model",
                b'{"model":"fixture-model","messages":[{"role":"user","content":"x"}]}',
            )


if __name__ == "__main__":
    unittest.main()
