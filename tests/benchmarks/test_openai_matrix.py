#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit checks for the engine-neutral OpenAI-v1 matrix contract."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import tempfile
import threading
import unittest
from unittest import mock


REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[2]
MODULE_PATH = REPOSITORY_ROOT / "benchmarks/openai_matrix.py"
SPEC = importlib.util.spec_from_file_location("openai_matrix", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MATRIX = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MATRIX)


class OpenAIMatrixTests(unittest.TestCase):
    def release(self, engine: str = "sglang") -> dict:
        return {
            "schema_version": 1,
            "release": "example-r1",
            "engine": {"name": engine, "api_protocol": "openai-v1"},
            "model": {
                "id": "example/model",
                "alias": "example",
                "artifact": "model",
            },
            "artifacts": [
                {
                    "name": "model",
                    "format": "huggingface-snapshot",
                    "repository": "example/model",
                    "revision": "a" * 40,
                }
            ],
            "image": {"immutable_id": "sha256:" + "b" * 64},
            "serving": {
                "qualified": False,
                "max_connections": 8,
                "max_active_requests": 1,
                "max_context_tokens": 262144,
            },
        }

    def test_release_semantics_fail_before_source_tree_reads(self) -> None:
        with (
            mock.patch.object(
                MATRIX,
                "validate_release_manifest",
                side_effect=MATRIX.QualificationError("semantic failure"),
            ) as semantics,
            mock.patch.object(MATRIX, "verify_letsinfer_release_sources") as sources,
            self.assertRaisesRegex(MATRIX.QualificationError, "semantic failure"),
        ):
            MATRIX.validate_release_sources({}, pathlib.Path("/unread"))

        semantics.assert_called_once_with({})
        sources.assert_not_called()

    def write_contract(
        self, root: pathlib.Path, *, second_cell_reuses: bool = False
    ) -> pathlib.Path:
        first = root / "first.txt"
        second = root / "second.txt"
        first.write_text("first prompt", encoding="utf-8")
        second.write_text("second prompt", encoding="utf-8")
        cells = [
            {
                "name": "short-x1",
                "fixtures": ["first"],
                "max_tokens": 32,
                "min_completion_tokens": 1,
                "require_natural_stop": True,
            },
            {
                "name": "short-x1-b",
                "fixtures": ["first" if second_cell_reuses else "second"],
                "max_tokens": 32,
                "min_completion_tokens": 1,
                "require_natural_stop": True,
            },
        ]
        contract = {
            "schema_version": 1,
            "engine": "sglang",
            "model_id": "example/model",
            "model_revision": "a" * 40,
            "tokenizer_identity": {"revision": "a" * 40},
            "request_options": {"seed": 0},
            "fixtures": [
                {
                    "name": "first",
                    "path": first.name,
                    "sha256": MATRIX.sha256_file(first),
                    "expected_prompt_tokens": 4,
                },
                {
                    "name": "second",
                    "path": second.name,
                    "sha256": MATRIX.sha256_file(second),
                    "expected_prompt_tokens": 4,
                },
            ],
            "cells": cells,
        }
        path = root / "fixtures.json"
        path.write_text(json.dumps(contract), encoding="utf-8")
        return path

    def test_release_contract_is_engine_neutral(self) -> None:
        for engine in ("vllm", "sglang", "llama.cpp"):
            release, observed_engine, model = MATRIX.validate_release_manifest(
                self.release(engine)
            )
            self.assertEqual((release, observed_engine, model), (
                "example-r1", engine, "example/model"
            ))

    def test_served_model_name_uses_public_alias(self) -> None:
        manifest = self.release("sglang")
        manifest["model"]["alias"] = "public-model"
        self.assertEqual(MATRIX.served_model_name(manifest), "public-model")

    def test_fixture_contract_hashes_and_allocates_disjoint_cells(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_contract(pathlib.Path(directory))
            fixtures, cells, tokenizer = MATRIX.load_fixture_contract(
                path,
                engine_name="sglang",
                model_id="example/model",
                model_revision="a" * 40,
            )
        self.assertEqual([row["name"] for row in fixtures], ["first", "second"])
        self.assertEqual([row["name"] for row in cells], ["short-x1", "short-x1-b"])
        self.assertEqual(cells[0]["request_options"], {"seed": 0})
        self.assertEqual(cells[0]["temperature"], 0.0)
        self.assertEqual(fixtures[0]["messages"], [{"role": "user", "content": "first prompt"}])
        self.assertEqual(tokenizer, {"revision": "a" * 40})

    def test_fixture_preserves_system_and_user_messages(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            system = root / "system.md"
            user = root / "user.md"
            system.write_text("system context", encoding="utf-8")
            user.write_text("user question", encoding="utf-8")
            contract = {
                "schema_version": 1,
                "engine": "sglang",
                "model_id": "example/model",
                "model_revision": "a" * 40,
                "tokenizer_identity": {"revision": "a" * 40},
                "temperature": 1,
                "fixtures": [
                    {
                        "name": "historical",
                        "messages": [
                            {
                                "role": "system",
                                "path": system.name,
                                "sha256": MATRIX.sha256_file(system),
                            },
                            {
                                "role": "user",
                                "path": user.name,
                                "sha256": MATRIX.sha256_file(user),
                            },
                        ],
                        "expected_prompt_tokens": 8,
                    }
                ],
                "cells": [
                    {
                        "name": "historical",
                        "fixtures": ["historical"],
                        "max_tokens": 128,
                        "min_completion_tokens": 1,
                        "require_natural_stop": False,
                    }
                ],
            }
            path = root / "fixtures.json"
            path.write_text(json.dumps(contract), encoding="utf-8")
            fixtures, cells, _ = MATRIX.load_fixture_contract(
                path,
                engine_name="sglang",
                model_id="example/model",
                model_revision="a" * 40,
            )
        self.assertEqual(
            fixtures[0]["messages"],
            [
                {"role": "system", "content": "system context"},
                {"role": "user", "content": "user question"},
            ],
        )
        self.assertEqual(cells[0]["temperature"], 1.0)

    def test_messages_require_a_user_role(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            prompt = root / "prompt.md"
            prompt.write_text("context", encoding="utf-8")
            contract = {
                "schema_version": 1,
                "engine": "sglang",
                "model_id": "example/model",
                "model_revision": "a" * 40,
                "tokenizer_identity": {"revision": "a" * 40},
                "fixtures": [
                    {
                        "name": "bad",
                        "messages": [
                            {
                                "role": "system",
                                "path": prompt.name,
                                "sha256": MATRIX.sha256_file(prompt),
                            }
                        ],
                        "expected_prompt_tokens": 1,
                    }
                ],
                "cells": [
                    {
                        "name": "bad",
                        "fixtures": ["bad"],
                        "max_tokens": 1,
                        "min_completion_tokens": 1,
                        "require_natural_stop": False,
                    }
                ],
            }
            path = root / "fixtures.json"
            path.write_text(json.dumps(contract), encoding="utf-8")
            with self.assertRaisesRegex(MATRIX.QualificationError, "user message"):
                MATRIX.load_fixture_contract(
                    path,
                    engine_name="sglang",
                    model_id="example/model",
                    model_revision="a" * 40,
                )

    def test_fixture_reuse_across_cells_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_contract(
                pathlib.Path(directory), second_cell_reuses=True
            )
            with self.assertRaisesRegex(
                MATRIX.QualificationError, "globally disjoint"
            ):
                MATRIX.load_fixture_contract(
                    path,
                    engine_name="sglang",
                    model_id="example/model",
                    model_revision="a" * 40,
                )

    def test_request_options_cannot_change_measurement_contract(self) -> None:
        for key in MATRIX.PROTECTED_REQUEST_KEYS:
            with self.assertRaises(MATRIX.QualificationError):
                MATRIX.validate_request_options({key: 1}, "options")

    def test_failed_stream_retains_incremental_wire_journal(self) -> None:
        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *_arguments):
                return False

            def __iter__(self):
                yield b'data: {"choices":[{"delta":{"content":"partial"}}]}\n'
                yield b"data: [DONE]\n"

        fixture = {
            "name": "partial-stream",
            "sha256": "a" * 64,
            "messages": [{"role": "user", "content": "prompt"}],
            "message_files": ["prompt.md"],
            "expected_prompt_tokens": 1,
        }
        with tempfile.TemporaryDirectory() as directory:
            journal = pathlib.Path(directory) / "stream.jsonl"
            with mock.patch.object(
                MATRIX.urllib.request, "urlopen", return_value=Response()
            ):
                with self.assertRaisesRegex(
                    MATRIX.QualificationError, "no OpenAI usage object"
                ):
                    MATRIX.measure_stream(
                        base_url="https://127.0.0.1:8000",
                        context=mock.Mock(),
                        api_key="test-key",
                        model_id="example/model",
                        fixture=fixture,
                        max_tokens=8,
                        min_completion_tokens=1,
                        require_natural_stop=False,
                        request_options={},
                        temperature=0.0,
                        timeout=30,
                        barrier=threading.Barrier(1),
                        stream_path=journal,
                    )
            journal_text = journal.read_text(encoding="utf-8")
            rows = [json.loads(line) for line in journal_text.splitlines()]
        self.assertEqual(
            [row["kind"] for row in rows],
            ["request", "response-line", "response-line", "response-eof", "error"],
        )
        self.assertEqual(rows[-1]["error_type"], "QualificationError")
        self.assertNotIn("test-key", journal_text)

    def test_stream_rejects_boolean_engine_token_counters(self) -> None:
        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *_arguments):
                return False

            def __iter__(self):
                yield (
                    b'data: {"choices":[{"delta":{"content":"x"},'
                    b'"finish_reason":"stop"}],"usage":{"prompt_tokens":true,'
                    b'"completion_tokens":1,"prompt_tokens_details":'
                    b'{"cached_tokens":false}}}\n'
                )
                yield b"data: [DONE]\n"

        fixture = {
            "name": "boolean-usage",
            "sha256": "a" * 64,
            "messages": [{"role": "user", "content": "prompt"}],
            "message_files": ["prompt.md"],
            "expected_prompt_tokens": 1,
        }
        with tempfile.TemporaryDirectory() as directory:
            journal = pathlib.Path(directory) / "stream.jsonl"
            with mock.patch.object(
                MATRIX.urllib.request, "urlopen", return_value=Response()
            ):
                with self.assertRaisesRegex(
                    MATRIX.QualificationError, "prompt token drift"
                ):
                    MATRIX.measure_stream(
                        base_url="https://127.0.0.1:8000",
                        context=mock.Mock(),
                        api_key="test-key",
                        model_id="example/model",
                        fixture=fixture,
                        max_tokens=8,
                        min_completion_tokens=1,
                        require_natural_stop=False,
                        request_options={},
                        temperature=0.0,
                        timeout=30,
                        barrier=threading.Barrier(1),
                        stream_path=journal,
                    )

    def test_run_cell_allocates_one_stream_journal_per_fixture(self) -> None:
        cell = {
            "name": "short-c2",
            "fixtures": [
                {"name": "first", "sha256": "a" * 64},
                {"name": "second", "sha256": "b" * 64},
            ],
            "max_tokens": 8,
            "min_completion_tokens": 1,
            "require_natural_stop": False,
            "request_options": {},
            "temperature": 0.0,
        }

        def measured(**arguments):
            return {
                "fixture": arguments["fixture"]["name"],
                "completion_tokens": 1,
            }

        with tempfile.TemporaryDirectory() as directory:
            streams = pathlib.Path(directory) / "streams"
            with mock.patch.object(
                MATRIX, "measure_stream", side_effect=measured
            ) as call:
                result = MATRIX.run_cell(
                    cell=cell,
                    phase="matrix",
                    base_url="https://127.0.0.1:8000",
                    context=mock.Mock(),
                    api_key="test-key",
                    model_id="example/model",
                    timeout=30,
                    stream_directory=streams,
                )
        self.assertEqual(result["streams"], 2)
        self.assertEqual(
            {row.kwargs["stream_path"].name for row in call.call_args_list},
            {"00.jsonl", "01.jsonl"},
        )

    def test_container_identity_includes_engine_and_exact_image(self) -> None:
        release = self.release("llama.cpp")
        inspection = {
            "Id": "container-id",
            "Image": release["image"]["immutable_id"],
            "RestartCount": 0,
            "Config": {
                "Labels": {
                    "io.letsinfer.managed": "true",
                    "io.letsinfer.release": "example-r1",
                    "io.letsinfer.model": "example",
                    "io.letsinfer.engine": "llama.cpp",
                }
            },
            "State": {
                "Running": True,
                "Status": "running",
                "Health": {"Status": "healthy"},
                "OOMKilled": False,
                "StartedAt": "2026-08-12T00:00:00Z",
            },
        }
        summary = MATRIX.validate_container(inspection, release)
        self.assertEqual(summary["health"], "healthy")
        inspection["Config"]["Labels"]["io.letsinfer.engine"] = "vllm"
        with self.assertRaisesRegex(MATRIX.QualificationError, "identity mismatch"):
            MATRIX.validate_container(inspection, release)

    def test_group_container_uses_runtime_readiness_without_docker_health(self) -> None:
        release = self.release()
        inspection = {
            "Id": "placement-container-id",
            "Image": release["image"]["immutable_id"],
            "RestartCount": 0,
            "Config": {
                "Labels": {
                    "io.letsinfer.managed": "true",
                    "io.letsinfer.release": "example-r1",
                    "io.letsinfer.model": "example",
                    "io.letsinfer.engine": "sglang",
                }
            },
            "State": {
                "Running": True,
                "Status": "running",
                "OOMKilled": False,
                "StartedAt": "2026-08-12T00:00:00Z",
            },
        }
        with self.assertRaisesRegex(
            MATRIX.QualificationError, "not running and healthy"
        ):
            MATRIX.validate_container(inspection, release)

        summary = MATRIX.validate_container(
            inspection, release, require_docker_health=False
        )
        self.assertTrue(summary["running"])
        self.assertIsNone(summary["health"])

    def test_pair_equality_compares_output_tokens_and_finish_reason(self) -> None:
        row = {
            "fixture": "first",
            "output": "same",
            "completion_tokens": 3,
            "finish_reasons": ["stop"],
        }
        first = {"requests": [dict(row)]}
        repeat = {"requests": [dict(row)]}
        self.assertTrue(MATRIX.assert_pair_equal(first, repeat))
        repeat["requests"][0]["completion_tokens"] = 4
        self.assertFalse(MATRIX.assert_pair_equal(first, repeat))

    def test_source_attestation_is_required_without_git(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            commit = "a" * 40
            with self.assertRaisesRegex(
                MATRIX.QualificationError, "source-attestation"
            ):
                MATRIX.source_identity(root, commit, None)
            attestation = root / "source.json"
            attestation.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "clean": True,
                        "commit": commit,
                        "tree": "b" * 40,
                    }
                ),
                encoding="utf-8",
            )
            identity = MATRIX.source_identity(root, commit, attestation)
            self.assertEqual(identity["kind"], "deployment-attestation")

    def test_measured_commit_must_be_full_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(
            MATRIX.QualificationError, "full 40-hex"
        ):
            MATRIX.source_identity(pathlib.Path(directory), "abc1234", None)

    def test_http_and_https_base_urls_are_supported(self) -> None:
        self.assertEqual(
            MATRIX.validate_base_url("http://127.0.0.1:8000"),
            "http://127.0.0.1:8000",
        )
        self.assertEqual(
            MATRIX.validate_base_url("https://public.example"),
            "https://public.example",
        )

    def test_preflight_checks_inference_auth_not_model_list_privacy(self) -> None:
        models = {"data": [{"id": "example/model"}]}
        with (
            mock.patch.object(
                MATRIX,
                "request_json",
                side_effect=[(200, None), (200, models)],
            ),
            mock.patch.object(
                MATRIX,
                "inference_auth_status",
                side_effect=[401, 400],
            ),
        ):
            result = MATRIX.preflight(
                "https://127.0.0.1:8000",
                mock.sentinel.tls_context,
                30,
                "secret",
                "example/model",
            )
        self.assertEqual(result["anonymous_inference_status"], 401)
        self.assertEqual(result["authenticated_inference_probe_status"], 400)
        self.assertEqual(result["authenticated_models_status"], 200)

    def test_preflight_rejects_unprotected_inference(self) -> None:
        with (
            mock.patch.object(
                MATRIX,
                "request_json",
                side_effect=[(200, None), (200, {"data": [{"id": "example/model"}]})],
            ),
            mock.patch.object(
                MATRIX,
                "inference_auth_status",
                side_effect=[400, 400],
            ),
            self.assertRaisesRegex(MATRIX.QualificationError, "expected 401"),
        ):
            MATRIX.preflight(
                "https://127.0.0.1:8000",
                mock.sentinel.tls_context,
                30,
                "secret",
                "example/model",
            )


if __name__ == "__main__":
    unittest.main()
