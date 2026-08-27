#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit checks for the resumable engine-neutral load contract."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest import mock


REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[2]
MODULE_PATH = REPOSITORY_ROOT / "benchmarks/openai_load.py"
SPEC = importlib.util.spec_from_file_location("openai_load", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
LOAD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LOAD)


class OpenAILoadTests(unittest.TestCase):
    def test_standard_prompt_protocol_is_generated_evidence_only(self) -> None:
        prompt_root = MODULE_PATH.parent / "prompts"
        protocol = (prompt_root / "PROTOCOL.md").read_text(encoding="utf-8")
        self.assertIn("runtime.json.benchmark", protocol)
        self.assertIn("exact tokenizer-count capability", protocol)
        self.assertIn("Never commit or package materialized prompts", protocol)
        for filename in ("context.md", "concurrency.md", "retrieval.md"):
            prompt = (prompt_root / filename).read_text(encoding="utf-8")
            self.assertIn("{{FIXTURE_ID}}", prompt)
            self.assertIn("{{MARKER}}", prompt)
            self.assertIn("{{BODY}}", prompt)

    def make_plan(self, root: pathlib.Path) -> pathlib.Path:
        fixture = root / "prompt.txt"
        fixture.write_text("test prompt", encoding="utf-8")
        fixture_manifest = {
            "schema_version": 1,
            "engine": "sglang",
            "model_id": "example/model",
            "model_revision": "a" * 40,
            "tokenizer_identity": {"revision": "a" * 40},
            "request_options": {"seed": 0},
            "fixtures": [
                {
                    "name": "prompt",
                    "path": fixture.name,
                    "sha256": LOAD.common.sha256_file(fixture),
                    "expected_prompt_tokens": 3,
                }
            ],
            "cells": [
                {
                    "name": "single",
                    "fixtures": ["prompt"],
                    "max_tokens": 16,
                    "min_completion_tokens": 1,
                    "require_natural_stop": False,
                }
            ],
        }
        (root / "fixtures.json").write_text(
            json.dumps(fixture_manifest), encoding="utf-8"
        )
        plan = {
            "schema_version": 1,
            "sample_interval_seconds": 5,
            "tasks": [
                {
                    "name": "single-soak",
                    "cell": "single",
                    "warmup_waves": 1,
                    "measured_waves": 3,
                    "cooldown_seconds": 0,
                    "require_output_equality": True,
                }
            ],
        }
        path = root / "plan.json"
        path.write_text(json.dumps(plan), encoding="utf-8")
        return path

    def test_plan_is_engine_bound_and_expands_stable_waves(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_plan(pathlib.Path(directory))
            plan, _, cells, _ = LOAD.load_plan(
                path,
                fixture_path=path.with_name("fixtures.json"),
                engine_name="sglang",
                model_id="example/model",
                model_revision="a" * 40,
            )
            waves = LOAD.expected_waves(plan)
        self.assertEqual(len(waves), 4)
        self.assertEqual(waves[0]["relative_path"], "waves/single-soak/warmup-0001.json")
        self.assertEqual(waves[-1]["relative_path"], "waves/single-soak/measured-0003.json")
        self.assertEqual(len(cells["single"]["fixtures"]), 1)

    def test_task_selection_preserves_plan_order_and_rejects_bad_names(self) -> None:
        plan = {
            "tasks": [
                {"name": "first"},
                {"name": "second"},
                {"name": "third"},
            ]
        }
        selected = LOAD.select_tasks(plan, ["third", "first"])
        self.assertEqual(
            [task["name"] for task in selected["tasks"]], ["first", "third"]
        )
        self.assertIs(LOAD.select_tasks(plan, []), plan)
        with self.assertRaisesRegex(LOAD.LoadError, "must not be repeated"):
            LOAD.select_tasks(plan, ["first", "first"])
        with self.assertRaisesRegex(LOAD.LoadError, "unknown --task"):
            LOAD.select_tasks(plan, ["missing"])

    def test_result_envelope_cannot_be_downgraded_by_input_schema(self) -> None:
        document = LOAD.result_envelope(
            {"schema_version": 1, "release": "example"},
            {"schema_version": 1, "qualification_passed": True},
        )
        self.assertEqual(document["schema_version"], 1)
        self.assertEqual(document["contract"], "letsinfer-openai-v1-load-v1")
        self.assertEqual(document["release"], "example")

    def test_resume_requires_the_exact_input_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "results"
            plan = {"tasks": [{"name": "one"}]}
            state = LOAD.initialize_state(
                output, inputs={"a": 1}, plan=plan, resume=False
            )
            resumed = LOAD.initialize_state(
                output, inputs={"a": 1}, plan=plan, resume=True
            )
            self.assertEqual(resumed["run_identity"], state["run_identity"])
            with self.assertRaisesRegex(LOAD.LoadError, "exact requested run"):
                LOAD.initialize_state(
                    output, inputs={"a": 2}, plan=plan, resume=True
                )

    def test_resume_rejects_tampered_saved_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "results"
            plan = {"tasks": [{"name": "one"}]}
            LOAD.initialize_state(output, inputs={"a": 1}, plan=plan, resume=False)
            (output / "inputs.json").write_text('{"a": 2}\n', encoding="utf-8")
            with self.assertRaisesRegex(LOAD.LoadError, "saved inputs or plan"):
                LOAD.initialize_state(
                    output, inputs={"a": 1}, plan=plan, resume=True
                )

    def test_orphan_atomic_wave_is_recovered_without_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "results"
            plan = {
                "tasks": [
                    {
                        "name": "one",
                        "cell": "single",
                        "streams": 1,
                        "warmup_waves": 0,
                        "measured_waves": 1,
                    }
                ]
            }
            state = LOAD.initialize_state(
                output, inputs={"a": 1}, plan=plan, resume=False
            )
            expected = LOAD.expected_waves(plan)
            path = output / expected[0]["relative_path"]
            LOAD.common.write_json_atomic(
                path,
                {
                    "task": "one",
                    "phase": "measured",
                    "wave_index": 1,
                    "result": {
                        "cell": "single",
                        "phase": "measured",
                        "streams": 1,
                        "requests": [{}],
                    },
                },
            )
            LOAD.reconcile_waves(output, state, expected)
            self.assertEqual(len(state["completed_waves"]), 1)
            self.assertEqual(
                state["completed_waves"][0]["sha256"], LOAD.common.sha256_file(path)
            )

    def test_percentiles_are_interpolated_and_not_nearest_rank(self) -> None:
        values = [1.0, 2.0, 3.0, 4.0]
        self.assertEqual(LOAD.percentile(values, 0.5), 2.5)
        self.assertAlmostEqual(LOAD.percentile(values, 0.95), 3.85)

    def test_cold_and_warm_phases_are_compared_and_cache_proven(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory)
            task = {
                "name": "context",
                "cell": "single",
                "streams": 1,
                "warmup_waves": 1,
                "measured_waves": 1,
                "require_output_equality": True,
            }
            expected = [
                {
                    "task": "context",
                    "phase": phase,
                    "relative_path": f"waves/context/{phase}-0001.json",
                }
                for phase in ("warmup", "measured")
            ]

            def wave(cached: int) -> dict:
                request = {
                    "fixture": "prompt",
                    "output": "same output",
                    "completion_tokens": 2,
                    "finish_reasons": ["length"],
                    "cached_prompt_tokens": cached,
                    "cache_write_tokens": 10 - cached,
                    "ttft_ms": 10.0,
                    "wall_ms": 20.0,
                    "decode_tokens_per_second": 100.0,
                }
                return {
                    "result": {
                        "requests": [request],
                        "batch_wall_ms": 20.0,
                        "job_completion_tokens_per_second": 100.0,
                    }
                }

            for row, cached in zip(expected, (0, 9)):
                LOAD.common.write_json_atomic(
                    output / row["relative_path"], wave(cached)
                )
            requirements = {
                "warmup": "miss",
                "measured": "hit",
                "minimum_hit_tokens": 1,
            }
            _, summary = LOAD.task_results(
                output, task, expected, requirements
            )
            self.assertTrue(summary["outputs_equal"])
            self.assertEqual(
                summary["phases"]["warmup"]["cached_prompt_tokens"]["mean"], 0
            )
            self.assertEqual(
                summary["phases"]["measured"]["cached_prompt_tokens"]["mean"], 9
            )

            LOAD.common.write_json_atomic(
                output / expected[1]["relative_path"], wave(0)
            )
            with self.assertRaisesRegex(LOAD.LoadError, "expected at least"):
                LOAD.task_results(output, task, expected, requirements)

            divergent = wave(9)
            divergent["result"]["requests"][0]["output"] = "different"
            LOAD.common.write_json_atomic(
                output / expected[1]["relative_path"], divergent
            )
            with self.assertRaisesRegex(LOAD.LoadError, "cold/warm output divergence"):
                LOAD.task_results(output, task, expected, requirements)

            task["require_output_equality"] = False
            _, divergence_summary = LOAD.task_results(
                output, task, expected, requirements
            )
            self.assertFalse(divergence_summary["outputs_equal"])

    def test_monitor_stops_container_before_memory_reserve_is_exhausted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            monitor = LOAD.TelemetryMonitor(
                pathlib.Path(directory) / "telemetry.jsonl",
                "letsinfer-test",
                5,
                16,
                pathlib.Path(directory) / "protection-trip.json",
            )
            with (
                mock.patch.object(
                    LOAD,
                    "telemetry_sample",
                    return_value={"host": {"MemAvailable_kib": 2 * 1048576}},
                ),
                mock.patch.object(LOAD.common, "run_command") as run,
            ):
                monitor._capture_once()  # pylint: disable=protected-access
        self.assertIn("fell below", monitor.errors[0])
        run.assert_any_call(
            ["docker", "stop", "--time", "10", "letsinfer-test"]
        )

    def test_monitor_context_handles_failed_initial_sample(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            monitor = LOAD.TelemetryMonitor(
                pathlib.Path(directory) / "telemetry.jsonl",
                "letsinfer-test",
                5,
                16,
                pathlib.Path(directory) / "protection-trip.json",
            )
            with mock.patch.object(
                LOAD, "telemetry_sample", side_effect=LOAD.LoadError("unavailable")
            ):
                with monitor:
                    pass
        self.assertFalse(monitor.thread_started)
        self.assertIn("unavailable", monitor.errors[0])

    def test_monitor_fails_on_transient_container_health_loss(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = pathlib.Path(directory) / "telemetry.jsonl"
            monitor = LOAD.TelemetryMonitor(
                evidence,
                "letsinfer-test",
                5,
                16,
                pathlib.Path(directory) / "protection-trip.json",
            )
            with mock.patch.object(
                LOAD,
                "telemetry_sample",
                return_value={
                    "host": {"MemAvailable_kib": 32 * 1048576},
                    "container": {
                        "running": True,
                        "status": "running",
                        "health": "unhealthy",
                        "oom_killed": False,
                    },
                },
            ):
                self.assertFalse(
                    monitor._capture_once()  # pylint: disable=protected-access
                )
            self.assertIn("became unhealthy", monitor.errors[0])
            records = [json.loads(line) for line in evidence.read_text().splitlines()]
            self.assertEqual(records[-1]["container_fault"], monitor.errors[0])

    def test_group_monitor_uses_runtime_readiness_without_docker_health(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            monitor = LOAD.TelemetryMonitor(
                pathlib.Path(directory) / "telemetry.jsonl",
                "letsinfer-group-test",
                5,
                16,
                pathlib.Path(directory) / "protection-trip.json",
                require_docker_health=False,
            )
            with mock.patch.object(
                LOAD,
                "telemetry_sample",
                return_value={
                    "host": {"MemAvailable_kib": 32 * 1048576},
                    "container": {
                        "running": True,
                        "status": "running",
                        "health": None,
                        "oom_killed": False,
                    },
                },
            ):
                self.assertTrue(
                    monitor._capture_once()  # pylint: disable=protected-access
                )
            self.assertEqual(monitor.errors, [])

    def test_monitor_fails_closed_on_latched_watchdog_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            trip = pathlib.Path(directory) / "protection-trip.json"
            trip.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "action": "stop",
                        "reason": "host_memory_below_graceful_floor",
                    }
                ),
                encoding="utf-8",
            )
            trip.chmod(0o600)
            monitor = LOAD.TelemetryMonitor(
                pathlib.Path(directory) / "telemetry.jsonl",
                "letsinfer-test",
                5,
                16,
                trip,
            )
            with mock.patch.object(LOAD.common, "run_command") as run:
                self.assertFalse(monitor._capture_once())  # pylint: disable=protected-access
        self.assertIn("Watchdog protection trip latched", monitor.errors[0])
        run.assert_any_call(["docker", "stop", "--time", "10", "letsinfer-test"])

    def test_protection_trip_rejects_public_or_invalid_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            trip = pathlib.Path(directory) / "protection-trip.json"
            trip.write_text("{}\n", encoding="utf-8")
            trip.chmod(0o644)
            with self.assertRaisesRegex(LOAD.LoadError, "private and user-owned"):
                LOAD.protection_trip(trip)
            trip.chmod(0o600)
            with self.assertRaisesRegex(LOAD.LoadError, "invalid Watchdog"):
                LOAD.protection_trip(trip)

    def test_result_finalization_is_recovered_without_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "results"
            plan = {"tasks": [{"name": "one"}]}
            state = LOAD.initialize_state(
                output, inputs={"a": 1}, plan=plan, resume=False
            )
            LOAD.common.write_json_atomic(
                output / "results.json",
                {
                    "run_identity": state["run_identity"],
                    "qualification_passed": True,
                },
            )
            self.assertTrue(LOAD.reconcile_results(output, state))
            expected_sha = LOAD.common.sha256_file(output / "results.json")
            self.assertEqual(state["results_sha256"], expected_sha)
            self.assertEqual(state["status"], "complete")
            self.assertEqual(
                (output / "results.sha256").read_text(encoding="utf-8"),
                f"{expected_sha}  results.json\n",
            )

    def test_orphan_failure_is_recovered_and_hashed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "results"
            plan = {"tasks": [{"name": "one"}]}
            state = LOAD.initialize_state(
                output, inputs={"a": 1}, plan=plan, resume=False
            )
            path = output / "failures" / "attempt-0000.json"
            LOAD.common.write_json_atomic(
                path,
                {
                    "run_identity": state["run_identity"],
                    "attempt": 0,
                    "error": "interrupted",
                },
            )
            LOAD.reconcile_failures(output, state)
            self.assertEqual(len(state["failure_history"]), 1)
            self.assertEqual(
                state["failure_history"][0]["sha256"], LOAD.common.sha256_file(path)
            )

    def test_load_tasks_cannot_reuse_a_cell(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_plan(pathlib.Path(directory))
            document = json.loads(path.read_text(encoding="utf-8"))
            document["tasks"].append(
                {
                    "name": "same-cell-again",
                    "cell": "single",
                    "warmup_waves": 0,
                    "measured_waves": 1,
                    "cooldown_seconds": 0,
                    "require_output_equality": True,
                }
            )
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(LOAD.LoadError, "disjoint cells"):
                LOAD.load_plan(
                    path,
                    fixture_path=path.with_name("fixtures.json"),
                    engine_name="sglang",
                    model_id="example/model",
                    model_revision="a" * 40,
                )

    def test_checked_in_load_plans_are_valid_and_engine_neutral(self) -> None:
        plans = MODULE_PATH.parent / "load-plans"
        expected_tasks = {
            "single-stream.json": 3,
            "agent-concurrency.json": 3,
            "single-stream-soak.json": 1,
            "agent-concurrency-soak.json": 1,
        }
        for filename, task_count in expected_tasks.items():
            with self.subTest(plan=filename), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                plan_path = plans / filename
                plan_document = json.loads(plan_path.read_text(encoding="utf-8"))
                fixtures = []
                cells = []
                for task in plan_document["tasks"]:
                    streams = int(task["cell"].rsplit("x", 1)[1].split("-", 1)[0])
                    fixture_names = []
                    for index in range(streams):
                        name = f"{task['cell']}-s{index:02d}"
                        path = root / f"{name}.txt"
                        path.write_text(name, encoding="utf-8")
                        fixtures.append(
                            {
                                "name": name,
                                "path": path.name,
                                "sha256": LOAD.common.sha256_file(path),
                                "expected_prompt_tokens": 1,
                            }
                        )
                        fixture_names.append(name)
                    cells.append(
                        {
                            "name": task["cell"],
                            "fixtures": fixture_names,
                            "max_tokens": 16,
                            "min_completion_tokens": 1,
                            "require_natural_stop": False,
                        }
                    )
                fixture_path = root / "fixtures.json"
                fixture_path.write_text(
                    json.dumps(
                        {
                            "schema_version": 1,
                            "engine": "vllm",
                            "model_id": "example/model",
                            "model_revision": "a" * 40,
                            "tokenizer_identity": {"revision": "a" * 40},
                            "fixtures": fixtures,
                            "cells": cells,
                        }
                    ),
                    encoding="utf-8",
                )
                parsed, _, _, _ = LOAD.load_plan(
                    plan_path,
                    fixture_path=fixture_path,
                    engine_name="vllm",
                    model_id="example/model",
                    model_revision="a" * 40,
                )
                self.assertEqual(len(parsed["tasks"]), task_count)

    def test_workload_cannot_exceed_serving_connection_or_context_capacity(self) -> None:
        manifest = {
            "serving": {
                "max_connections": 4,
                "max_active_requests": 1,
                "max_context_tokens": 4096,
            },
        }
        task = {
            "name": "load",
            "cell": "cell",
            "streams": 5,
        }
        cell = {
            "max_tokens": 128,
            "fixtures": [{"name": "prompt", "expected_prompt_tokens": 1024}],
        }
        with self.assertRaisesRegex(LOAD.LoadError, "admits 4"):
            LOAD.validate_workload_capacity(
                manifest, {"tasks": [task]}, {"cell": cell}
            )
        task["streams"] = 4
        cell["fixtures"][0]["expected_prompt_tokens"] = 4000
        with self.assertRaisesRegex(LOAD.LoadError, "above the 4096-token context"):
            LOAD.validate_workload_capacity(
                manifest, {"tasks": [task]}, {"cell": cell}
            )


if __name__ == "__main__":
    unittest.main()
