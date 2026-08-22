#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Focused tests for the sealed-runtime matrix runner."""

from __future__ import annotations

import importlib.util
import hashlib
import json
import pathlib
import tempfile
import types
import unittest
from unittest import mock

from tools.source_archive import (
    PUBLIC_DIRECTORIES,
    PUBLIC_ROOT_FILES,
    public_files,
    source_manifest,
)


BENCHMARK_DIR = pathlib.Path(__file__).resolve().parents[2] / "benchmarks"
MODULE_SPEC = importlib.util.spec_from_file_location(
    "runtime_matrix", BENCHMARK_DIR / "runtime_matrix.py"
)
assert MODULE_SPEC is not None and MODULE_SPEC.loader is not None
runtime_matrix = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(runtime_matrix)


class RuntimeMatrixTests(unittest.TestCase):
    def test_runtime_config_uses_the_nested_benchmark_contract(self) -> None:
        contract = {
            "tokenizer": {
                "model_sha256": "1" * 64,
                "engine_image_sha256": "2" * 64,
            },
            "cases": [
                {"id": context, "concurrencies": list(runtime_matrix.CONCURRENCIES)}
                for context in runtime_matrix.CONTEXTS
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "runtime.json"
            path.write_text(
                json.dumps({"benchmark": {"contract": contract, "record": None}}),
                encoding="ascii",
            )
            with (
                mock.patch.object(
                    runtime_matrix.prompt_generator, "validate_benchmark_contract"
                ),
                mock.patch.object(
                    runtime_matrix, "benchmark_model_sha256", return_value="1" * 64
                ),
            ):
                loaded = runtime_matrix.load_benchmark_contract(
                    path, {"image": {"immutable_id": "sha256:" + "2" * 64}}
                )

        self.assertEqual(loaded, contract)

    def test_progress_records_completed_current_and_future_workloads(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "progress.json"
            prior = (
                runtime_matrix._PROGRESS_FILE,
                runtime_matrix._PROGRESS_STARTED_UNIX_NS,
                runtime_matrix._EXPECTED_MINUTES,
                runtime_matrix._SELECTED_CELLS,
                list(runtime_matrix._COMPLETED_CELLS),
                runtime_matrix._CURRENT_CELL,
            )
            try:
                runtime_matrix._PROGRESS_FILE = path
                runtime_matrix._PROGRESS_STARTED_UNIX_NS = 1
                runtime_matrix._EXPECTED_MINUTES = (18, 37)
                runtime_matrix._SELECTED_CELLS = (
                    "32k-c1",
                    "64k-c1",
                    "128k-c1",
                )
                runtime_matrix._COMPLETED_CELLS = ["32k-c1"]
                runtime_matrix._CURRENT_CELL = "64k-c1"
                runtime_matrix._write_benchmark_progress(
                    "workload:64k-c1:loading",
                    "Loading runtime for 64k-c1",
                    "running",
                )
                value = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(value["completed_cells"], ["32k-c1"])
                self.assertEqual(value["current_cell"], "64k-c1")
                self.assertEqual(
                    value["selected_cells"],
                    ["32k-c1", "64k-c1", "128k-c1"],
                )
            finally:
                (
                    runtime_matrix._PROGRESS_FILE,
                    runtime_matrix._PROGRESS_STARTED_UNIX_NS,
                    runtime_matrix._EXPECTED_MINUTES,
                    runtime_matrix._SELECTED_CELLS,
                    runtime_matrix._COMPLETED_CELLS,
                    runtime_matrix._CURRENT_CELL,
                ) = prior

    def _control_bundle(
        self, parent: pathlib.Path, manifest: dict
    ) -> tuple[pathlib.Path, pathlib.Path, str]:
        staging = parent / "staging"
        staging.mkdir()
        for name in PUBLIC_ROOT_FILES:
            (staging / name).write_text(f"{name}\n", encoding="utf-8")
        for name in PUBLIC_DIRECTORIES:
            path = staging / name
            path.mkdir(parents=True)
            (path / "source.txt").write_text(f"{name}\n", encoding="utf-8")
        release = staging / "runtime-execution.json"
        release.write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        core_manifest = source_manifest(public_files(staging))
        (staging / "SOURCE-MANIFEST.json").write_bytes(
            runtime_matrix.benchmark_record.canonical_bytes(core_manifest)
        )
        core_identity = hashlib.sha256(
            runtime_matrix.benchmark_record.canonical_bytes(core_manifest)
        ).hexdigest()
        manifest_identity = hashlib.sha256(release.read_bytes()).hexdigest()
        bundle_identity = hashlib.sha256(
            runtime_matrix.benchmark_record.canonical_bytes(
                {
                    "schema_version": 1,
                    "core_source_sha256": core_identity,
                    "runtime_manifest_sha256": manifest_identity,
                }
            )
        ).hexdigest()
        root = parent / bundle_identity
        staging.rename(root)
        return root, root / "runtime-execution.json", core_identity

    def test_composite_control_bundle_is_accepted_and_core_tampering_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = pathlib.Path(directory)
            measured_commit = "a" * 40
            manifest = {
                "serving": {"gate": {"measured_commit": measured_commit}},
            }
            root, release, core_identity = self._control_bundle(parent, manifest)

            identity = runtime_matrix.verified_source_identity(
                root, release, manifest, measured_commit, None
            )
            self.assertEqual(identity["kind"], "verified-control-bundle")
            self.assertEqual(identity["core_source_sha256"], core_identity)
            self.assertEqual(
                identity["execution_manifest_sha256"],
                hashlib.sha256(release.read_bytes()).hexdigest(),
            )

            (root / "core" / "source.txt").write_text(
                "tampered\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(
                runtime_matrix.RuntimeMatrixError, "core source manifest mismatch"
            ):
                runtime_matrix.verified_source_identity(
                    root, release, manifest, measured_commit, None
                )

    def test_materializer_and_cells_launch_on_the_backend_port(self) -> None:
        arguments = types.SimpleNamespace(
            letsinfer_bin=pathlib.Path("/opt/letsinfer"),
            engine_port=18000,
            container="letsinfer-benchmark",
        )
        command = runtime_matrix._serve_command(
            arguments,
            "model/engine/target",
            pathlib.Path("/stores/materialization"),
            pathlib.Path("/launches/materialization"),
        )
        self.assertEqual(command[command.index("--port") + 1], "18000")
        self.assertEqual(command[command.index("--name") + 1], "letsinfer-benchmark")
        self.assertIn("--qualification-mode", command)

    def setUp(self) -> None:
        self.cells = {
            f"{context}-{domain}-c{concurrency}": {
                "name": f"{context}-{domain}-c{concurrency}",
                "prompt_domain": domain,
                "prompt_suite": "letsinfer-code-prose-v1",
                "prompt_set_sha256": "3" * 64,
                "target_prompt_tokens": 262_144,
                "fixtures": [
                    {"expected_prompt_tokens": 262_144}
                    for _ in range(concurrency)
                ],
                "max_tokens": 128,
            }
            for context in runtime_matrix.CONTEXTS
            for domain in runtime_matrix.prompt_generator.DOMAINS
            for concurrency in runtime_matrix.CONCURRENCIES
        }

    def test_no_selectors_selects_complete_matrix(self) -> None:
        arguments = types.SimpleNamespace(
            c1=False,
            c2=False,
            c4=False,
            c8=False,
            c16=False,
            context_32k=False,
            context_64k=False,
            context_128k=False,
            context_256k=False,
        )
        concurrencies, contexts = runtime_matrix.selected_axes(arguments)
        self.assertEqual(concurrencies, [1, 2, 4, 8, 16])
        self.assertEqual(contexts, ["32k", "64k", "128k", "256k"])

    def test_selectors_form_cross_product_with_c1_first(self) -> None:
        arguments = types.SimpleNamespace(
            c1=True,
            c2=False,
            c4=False,
            c8=True,
            c16=False,
            context_32k=False,
            context_64k=True,
            context_128k=True,
            context_256k=False,
        )
        concurrencies, contexts = runtime_matrix.selected_axes(arguments)
        selected = runtime_matrix.select_cells(
            self.cells, concurrencies, contexts
        )
        self.assertEqual(
            [cell["name"] for cell in selected],
            [
                "64k-code-c1",
                "64k-prose-c1",
                "128k-code-c1",
                "128k-prose-c1",
                "64k-code-c8",
                "64k-prose-c8",
                "128k-code-c8",
                "128k-prose-c8",
            ],
        )

    def test_generated_partial_plan_validates_only_materialized_cells(self) -> None:
        manifest = {
            "model": {"id": "fixture-model", "artifact": "model"},
            "artifacts": [
                {
                    "name": "model",
                    "revision": "a" * 40,
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            prompt = root / "prompts/64k-code-s00.md"
            prompt.parent.mkdir()
            prompt.write_text("fixture prompt\n", encoding="utf-8")
            prompt_sha = hashlib.sha256(prompt.read_bytes()).hexdigest()
            public = [
                {
                    "relative_path": "prompts/64k-code-s00.md",
                    "sha256": prompt_sha,
                    "expected_prompt_tokens": 65536,
                }
            ]
            plan = {
                "schema_version": 2,
                "prompt_suite": "letsinfer-code-prose-v1",
                "model_id": "fixture-model",
                "model_revision": "a" * 40,
                "tokenizer_identity": {"capability": "exact"},
                "sample_interval_seconds": 5,
                "request": {
                    "max_tokens": 128,
                    "min_completion_tokens": 128,
                    "require_natural_stop": False,
                    "temperature": 0,
                    "options": {"seed": 42},
                },
                "prompt_set_sha256": runtime_matrix.prompt_set_sha256(public),
                "fixtures": [
                    {
                        "name": "64k-code-s00",
                        "path": "prompts/64k-code-s00.md",
                        "sha256": prompt_sha,
                        "expected_prompt_tokens": 65536,
                        "prompt_domain": "code",
                    }
                ],
                "contexts": [
                    {
                        "name": "64k",
                        "target_prompt_tokens": 65536,
                        "cells": {"code-c1": ["64k-code-s00"]},
                        "sealed_c1": None,
                    }
                ],
            }
            path = root / "runtime-matrix.json"
            path.write_text(json.dumps(plan), encoding="utf-8")
            _, cells = runtime_matrix.load_prompt_plan(path, manifest)

        self.assertEqual(list(cells), ["64k-code-c1"])

    def test_partial_plan_rejects_unmaterialized_selection(self) -> None:
        with self.assertRaisesRegex(
            runtime_matrix.RuntimeMatrixError, "does not define selected cell"
        ):
            runtime_matrix.select_cells(
                {"64k-code-c1": self.cells["64k-code-c1"]},
                [1, 4],
                ["64k"],
                "code",
            )

    def test_prompt_set_hash_binds_paths_and_content_hashes(self) -> None:
        rows = [
            {"relative_path": "a.md", "sha256": "1" * 64},
            {"relative_path": "b.md", "sha256": "2" * 64},
        ]
        first = runtime_matrix.prompt_set_sha256(rows)
        self.assertEqual(first, runtime_matrix.prompt_set_sha256(list(reversed(rows))))
        rows[0]["sha256"] = "3" * 64
        self.assertNotEqual(first, runtime_matrix.prompt_set_sha256(rows))

    def test_sample_interval_is_bound_by_plan(self) -> None:
        plan = {"sample_interval_seconds": 5}
        self.assertEqual(runtime_matrix.bind_sample_interval(None, plan), 5)
        self.assertEqual(runtime_matrix.bind_sample_interval(5, plan), 5)
        with self.assertRaisesRegex(
            runtime_matrix.RuntimeMatrixError, "must match the sealed plan"
        ):
            runtime_matrix.bind_sample_interval(1, plan)

    def test_sample_interval_rejects_invalid_plan(self) -> None:
        with self.assertRaisesRegex(
            runtime_matrix.RuntimeMatrixError, "must be from 1 through 60"
        ):
            runtime_matrix.bind_sample_interval(
                None, {"sample_interval_seconds": 61}
            )

    def test_token_count_client_accepts_only_count_and_exact_model(self) -> None:
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps(
            {
                "object": "token_count",
                "model": "fixture-model",
                "prompt_tokens": 32768,
            }
        ).encode()
        counter = runtime_matrix.token_count_client(
            base_url="https://127.0.0.1:8000",
            path="/v1/token-count",
            protocol="letsinfer-token-count-v1",
            api_key="secret",
            tls_context=mock.sentinel.tls,
            model_id="fixture-model",
            timeout=30,
        )
        with mock.patch.object(
            runtime_matrix.urllib.request, "urlopen", return_value=response
        ) as request:
            self.assertEqual(counter("prompt"), 32768)
        sent = request.call_args.args[0]
        self.assertEqual(sent.get_header("Authorization"), "Bearer secret")

        response.__enter__.return_value.read.return_value = json.dumps(
            {
                "object": "token_count",
                "model": "other-model",
                "prompt_tokens": 32768,
            }
        ).encode()
        with (
            mock.patch.object(
                runtime_matrix.urllib.request, "urlopen", return_value=response
            ),
            self.assertRaisesRegex(
                runtime_matrix.RuntimeMatrixError, "identity mismatch"
            ),
        ):
            counter("prompt")

    def test_measured_commit_defaults_to_runtime_gate(self) -> None:
        manifest = {
            "serving": {"gate": {"measured_commit": "a" * 40}}
        }
        self.assertEqual(
            runtime_matrix.resolve_measured_commit(None, manifest), "a" * 40
        )
        self.assertEqual(
            runtime_matrix.resolve_measured_commit("b" * 40, manifest), "b" * 40
        )

    def test_hash_addressed_control_bundle_is_a_source_identity(self) -> None:
        manifest = {
            "serving": {"gate": {"measured_commit": "a" * 40}},
        }
        with tempfile.TemporaryDirectory() as directory:
            root, path, _core_identity = self._control_bundle(
                pathlib.Path(directory), manifest
            )
            manifest_sha = hashlib.sha256(path.read_bytes()).hexdigest()
            identity = runtime_matrix.verified_source_identity(
                root, path, manifest, "a" * 40, None
            )

        self.assertEqual(identity["kind"], "verified-control-bundle")
        self.assertEqual(identity["commit"], "a" * 40)
        self.assertEqual(identity["execution_manifest_sha256"], manifest_sha)

    def test_control_bundle_rejects_an_unsealed_commit(self) -> None:
        manifest = {
            "serving": {"gate": {"measured_commit": "a" * 40}},
        }
        with tempfile.TemporaryDirectory() as directory:
            root, path, _core_identity = self._control_bundle(
                pathlib.Path(directory), manifest
            )
            with self.assertRaisesRegex(
                runtime_matrix.RuntimeMatrixError, "sealed measured commit"
            ):
                runtime_matrix.verified_source_identity(
                    root, path, manifest, "b" * 40, None
                )

    def test_post_load_memory_requires_stable_warning_headroom(self) -> None:
        manifest = {
            "watchdog": {
                "protection": {"warning_available_bytes": 12 * 1024**3}
            }
        }
        with (
            mock.patch.object(
                runtime_matrix,
                "host_mem_available_bytes",
                side_effect=[13 * 1024**3, 12 * 1024**3, 14 * 1024**3],
            ),
            mock.patch.object(runtime_matrix.time, "sleep"),
        ):
            result = runtime_matrix.require_post_load_warning_headroom(manifest)
        self.assertTrue(result["passed"])
        self.assertEqual(result["minimum_available_bytes"], 12 * 1024**3)
        self.assertEqual(len(result["observed_available_bytes"]), 3)

    def test_post_load_memory_rejects_below_warning_line(self) -> None:
        manifest = {
            "watchdog": {
                "protection": {"warning_available_bytes": 12 * 1024**3}
            }
        }
        with (
            mock.patch.object(
                runtime_matrix,
                "host_mem_available_bytes",
                side_effect=[13 * 1024**3, 12 * 1024**3 - 1, 14 * 1024**3],
            ),
            mock.patch.object(runtime_matrix.time, "sleep"),
            self.assertRaisesRegex(
                runtime_matrix.RuntimeMatrixError,
                "below the manifest warning line",
            ),
        ):
            runtime_matrix.require_post_load_warning_headroom(manifest)

    def test_complete_matrix_is_capacity_safe_for_sixteen(self) -> None:
        manifest = {
            "serving": {
                "max_connections": 16,
                "max_active_requests": 10,
                "max_context_tokens": 557_056,
            }
        }
        selected = runtime_matrix.select_cells(
            self.cells,
            list(runtime_matrix.CONCURRENCIES),
            list(runtime_matrix.CONTEXTS),
        )
        capacity = runtime_matrix.validate_capacity(manifest, selected)
        self.assertEqual(len(selected), 40)
        self.assertEqual(capacity["selected_max_concurrency"], 16)
        self.assertEqual(capacity["runtime_max_active_requests"], 10)

    def test_runtime_manifest_path_is_a_valid_runtime_argument(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest_path = pathlib.Path(directory) / "runtime-execution.json"
            manifest_path.write_text(
                json.dumps({"release": "example-model-example-engine-r1"}),
                encoding="utf-8",
            )
            resolved, selector = runtime_matrix.resolve_runtime(
                str(manifest_path), pathlib.Path("/unused/letsinfer")
            )
        self.assertEqual(resolved, manifest_path.resolve())
        self.assertEqual(selector, "example-model-example-engine-r1")

    def test_contract_cells_are_derived_without_runtime_prompt_assets(self) -> None:
        contract = {
            "request": {"output_tokens": 128},
            "cases": [
                {
                    "id": "32k",
                    "prompt_tokens": 32768,
                    "concurrencies": [1, 4],
                }
            ],
        }
        cells = runtime_matrix.contract_cells(contract)
        self.assertEqual(
            sorted(cells),
            ["32k-code-c1", "32k-code-c4", "32k-prose-c1", "32k-prose-c4"],
        )
        self.assertEqual(len(cells["32k-code-c4"]["fixtures"]), 4)
        self.assertEqual(
            cells["32k-code-c1"]["fixtures"][0]["expected_prompt_tokens"], 32768
        )

    def test_expected_duration_scales_with_selected_prompt_volume(self) -> None:
        short = [{"fixtures": [{"expected_prompt_tokens": 32_768}]}]
        long = [{"fixtures": [{"expected_prompt_tokens": 262_144}]}]
        short_range = runtime_matrix.expected_duration_range(
            short, includes_materializer=True
        )
        long_range = runtime_matrix.expected_duration_range(
            long, includes_materializer=True
        )
        self.assertLess(short_range[0], long_range[0])
        self.assertLess(short_range[1], long_range[1])
        self.assertLessEqual(short_range[0], short_range[1])

    def test_installed_runtime_name_resolves_to_exact_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest_path = pathlib.Path(directory) / "runtime-execution.json"
            manifest_path.write_text("{}", encoding="utf-8")
            response = types.SimpleNamespace(
                returncode=0,
                stderr="",
                stdout=json.dumps(
                    {
                        "runtime": {
                            "name": "example-model/example-engine/example-target",
                            "manifest_path": str(manifest_path),
                        },
                        "release": "example-model-example-engine-r1",
                    }
                ),
            )
            with mock.patch.object(
                runtime_matrix.common, "run_command", return_value=response
            ):
                resolved, selector = runtime_matrix.resolve_runtime(
                    "example-model/example-engine/example-target",
                    pathlib.Path("/opt/letsinfer"),
                )
        self.assertEqual(resolved, manifest_path.resolve())
        self.assertEqual(selector, "example-model/example-engine/example-target")

    def test_isolated_result_records_same_cell_cache_reuse(self) -> None:
        cell = {
            "name": "64k-c1",
            "fixtures": [{"expected_prompt_tokens": 65_536}],
        }
        runtime_matrix.validate_isolated_cache_evidence(
            cell, {"requests": [{"cached_prompt_tokens": 0}]}
        )
        runtime_matrix.validate_isolated_cache_evidence(
            cell, {"requests": [{"cached_prompt_tokens": None}]}
        )
        runtime_matrix.validate_isolated_cache_evidence(
            cell, {"requests": [{"cached_prompt_tokens": 64}]}
        )
        summary = runtime_matrix.summarize(
            cell,
            {
                "requests": [
                    {
                        "prompt_tokens": 65_536,
                        "completion_tokens": 128,
                        "decode_tokens_per_second": 24.0,
                        "ttft_ms": 100.0,
                        "wall_ms": 1000.0,
                        "cached_prompt_tokens": None,
                    }
                ],
                "batch_wall_ms": 1000.0,
                "job_completion_tokens_per_second": 24.0,
            },
        )
        self.assertEqual(summary["cached_prompt_tokens"]["max"], 0.0)
        with self.assertRaisesRegex(runtime_matrix.RuntimeMatrixError, "invalid cache"):
            runtime_matrix.validate_isolated_cache_evidence(
                cell, {"requests": [{"cached_prompt_tokens": False}]}
            )
        with self.assertRaisesRegex(runtime_matrix.RuntimeMatrixError, "invalid cache"):
            runtime_matrix.validate_isolated_cache_evidence(
                cell, {"requests": [{"cached_prompt_tokens": -1}]}
            )

    def test_failure_log_capture_preserves_both_docker_streams(self) -> None:
        response = types.SimpleNamespace(
            returncode=0,
            stdout="engine output\n",
            stderr="engine diagnostic\n",
        )
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory)
            with mock.patch.object(
                runtime_matrix.common,
                "run_command",
                return_value=response,
            ) as run:
                runtime_matrix.capture_container_logs("benchmark", output)

            self.assertEqual(
                run.call_args.args[0],
                [
                    "docker",
                    "container",
                    "logs",
                    "--timestamps",
                    "benchmark",
                ],
            )
            self.assertEqual(
                (output / "container-stdout.log").read_text(), "engine output\n"
            )
            self.assertEqual(
                (output / "container-stderr.log").read_text(),
                "engine diagnostic\n",
            )
            metadata = json.loads((output / "container-logs.json").read_text())
            self.assertEqual(metadata["returncode"], 0)
            self.assertEqual(len(metadata["stdout_sha256"]), 64)
            self.assertEqual(len(metadata["stderr_sha256"]), 64)

    def test_isolated_matrix_uses_one_process_and_store_per_cell(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            output = root / "evidence"
            manifest_path = root / "runtime-execution.json"
            runtime_config = root / "runtime.json"
            plan_path = root / "plan.json"
            manifest_path.write_text('{"release":"release-r1"}', encoding="utf-8")
            runtime_matrix.common.write_json_atomic(
                runtime_config,
                {
                    "id": "sglang--example--model--dgx-spark",
                    "version": "1.2.3",
                    "model": {"uri": "hf://example/model", "artifact": "model"},
                    "artifacts": [
                        {"name": "model", "revision": "4" * 40}
                    ],
                    "engine": {
                        "oci": {
                            "reference": "ghcr.io/example/engine@sha256:" + "5" * 64
                        }
                    },
                    "target": {"id": "dgx-spark"},
                },
            )
            plan_path.write_text("{}", encoding="utf-8")
            arguments = types.SimpleNamespace(
                output_directory=output,
                store_root=None,
                launch_directory=None,
                container="letsinfer-benchmark",
                letsinfer_bin=pathlib.Path("/opt/letsinfer"),
                engine_port=18000,
                base_url="https://127.0.0.1:8000",
                api_key_file=root / "api-key",
                token_count_api_key_file=root / "engine-api-key",
                ca_cert_file=root / "server.crt",
                measured_commit="a" * 40,
                watchdog_trip_file=root / "trip.json",
                timeout=3600,
                sample_interval_seconds=5,
                source_attestation=None,
                installation_id="1" * 64,
                benchmark_timestamp_unix_ns=1_800_000_000_123_456_789,
                benchmark_contract_sha256="2" * 64,
                runtime_config=runtime_config,
                watchdog_port=9768,
                watchdog_ca_file=root / "controller-ca.crt",
                watchdog_controller_cert_file=root / "local-controller.crt",
                watchdog_controller_key_file=root / "local-controller.key",
            )
            cells = [
                {
                    "name": "32k-code-c1",
                    "prompt_domain": "code",
                    "prompt_suite": "letsinfer-code-prose-v1",
                    "prompt_set_sha256": "3" * 64,
                    "target_prompt_tokens": 32_768,
                    "fixtures": [{}],
                    "max_tokens": 128,
                },
                {
                    "name": "32k-prose-c1",
                    "prompt_domain": "prose",
                    "prompt_suite": "letsinfer-code-prose-v1",
                    "prompt_set_sha256": "4" * 64,
                    "target_prompt_tokens": 32_768,
                    "fixtures": [{}],
                    "max_tokens": 128,
                },
            ]
            process_number = 0

            def worker(command: list[str]) -> types.SimpleNamespace:
                nonlocal process_number
                process_number += 1
                self.assertEqual(
                    command[command.index("--base-url") + 1],
                    "https://127.0.0.1:18000",
                )
                self.assertEqual(
                    command[command.index("--api-key-file") + 1],
                    str(root / "engine-api-key"),
                )
                result_root = pathlib.Path(
                    command[command.index("--output-directory") + 1]
                )
                domain = command[command.index("--prompt-domain") + 1]
                cell = f"32k-{domain}-c1"
                runtime_matrix.common.write_json_atomic(
                    result_root / "results.json",
                    {
                        "qualification_passed": True,
                        "selected_cells": [cell],
                        "container_before": {"id": f"container-{process_number}"},
                        "summaries": [
                            {
                                "cell": cell,
                                "concurrency": 1,
                                "prompt_tokens": [
                                    32_711 if domain == "code" else 32_719
                                ],
                                "decode_tokens_per_second": {"mean": 24.5},
                                "ttft_ms": {
                                    "mean": 32_000.0,
                                    "p50": 32_000.0,
                                    "p95": 32_000.0,
                                },
                                "cached_prompt_tokens": {"max": 0.0},
                                "aggregate_completion_tokens_per_second": 3.5,
                                "measurement_started_unix_ms": 1_800_000_000_000,
                                "measurement_ended_unix_ms": 1_800_000_002_000,
                            }
                        ],
                    },
                )
                return types.SimpleNamespace(returncode=0, stdout="", stderr="")

            with (
                mock.patch.object(
                    runtime_matrix, "_require_container_absent"
                ) as require_absent,
                mock.patch.object(
                    runtime_matrix, "_command_output", return_value=""
                ) as lifecycle,
                mock.patch.object(
                    runtime_matrix.common, "run_command", side_effect=worker
                ),
                mock.patch.object(
                    runtime_matrix.watchdog_client,
                    "query_range",
                    return_value=[
                        {
                            "sequence": 1,
                            "unix_ms": 1_800_000_000_000,
                            "cpu_percent": 50,
                            "gpu_percent": 90,
                            "system_temp_deci_c": 650,
                            "gpu_temp_deci_c": 700,
                            "disk_percent": 71,
                            "nvme_temp_deci_c": 470,
                            "disk_read_kib_s": 512,
                            "disk_write_kib_s": 256,
                            "cpu_clock_mhz": 3200,
                            "gpu_clock_mhz": 1500,
                            "vram_clock_mhz": -1,
                            "system_ram_clock_mhz": -1,
                        },
                        {
                            "sequence": 2,
                            "unix_ms": 1_800_000_001_000,
                            "cpu_percent": 55,
                            "gpu_percent": 95,
                            "system_temp_deci_c": 660,
                            "gpu_temp_deci_c": 710,
                            "disk_percent": 72,
                            "nvme_temp_deci_c": 485,
                            "disk_read_kib_s": 1024,
                            "disk_write_kib_s": 512,
                            "cpu_clock_mhz": 3800,
                            "gpu_clock_mhz": 2100,
                            "vram_clock_mhz": -1,
                            "system_ram_clock_mhz": -1,
                        },
                    ],
                ),
            ):
                runtime_matrix.run_isolated_matrix(
                    arguments,
                    manifest_path,
                    "model/engine/target",
                    {"release": "release-r1"},
                    plan_path,
                    cells,
                    {"commit": "a" * 40},
                )

            require_absent.assert_not_called()

            index = json.loads((output / "matrix-index.json").read_text())
            self.assertEqual(process_number, 2)
            self.assertEqual(lifecycle.call_count, 4)
            launch_commands = [
                call.args[0]
                for call in lifecycle.call_args_list
                if "serve" in call.args[0]
            ]
            self.assertEqual(len(launch_commands), 2)
            self.assertTrue(
                all(
                    command[command.index("--port") + 1] == "18000"
                    for command in launch_commands
                )
            )
            self.assertTrue(index["fresh_process_per_cell"])
            self.assertTrue(index["fresh_store_per_cell"])
            self.assertEqual(
                [row["container_id"] for row in index["cells"]],
                ["container-1", "container-2"],
            )
            public = json.loads((output / "benchmark.json").read_text())
            self.assertEqual(public["installation_id"], "1" * 64)
            self.assertEqual(
                [row["is_prefix_cached"] for row in public["results"]],
                [False, False],
            )
            self.assertEqual(
                [row["prompt_domain"] for row in public["results"]],
                ["code", "prose"],
            )


if __name__ == "__main__":
    unittest.main()
