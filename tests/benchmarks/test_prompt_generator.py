#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Determinism and evidence tests for the standard prompt generator."""

from __future__ import annotations

import hashlib
import json
import pathlib
import tempfile
import unittest

from benchmarks import prompt_generator


def contract() -> dict[str, object]:
    return {
        "schema_version": 2,
        "suite": "letsinfer-code-prose-v1",
        "generator": {"id": "letsinfer-code-prose", "version": 2},
        "tokenizer": {
            "capability": "engine-rendered-chat-count-v1",
            "model_sha256": "1" * 64,
            "engine_image_sha256": "2" * 64,
            "render_contract": "openai-chat-user-v1",
        },
        "request": {
            "output_tokens": 32,
            "min_completion_tokens": 1,
            "require_natural_stop": True,
            "temperature": 0,
            "seed": 42,
        },
        "sample_interval_seconds": 5,
        "cases": [
            {
                "id": "fixture",
                "prompt_tokens": 2048,
                "concurrencies": [1],
            }
        ],
    }


def short_workload_contract() -> dict[str, object]:
    value = contract()
    value["schema_version"] = 5
    value["generator"]["version"] = 5  # type: ignore[index]
    value["domains"] = ["code"]
    value["execution"] = {
        "isolation": "fresh-matrix",
        "prefix_state": "shared",
        "samples_per_cell": 1,
        "stream_prefix": "shared-body",
    }
    value["short"] = {
        "domains": ["code", "prose"],
        "prompt_tokens": 256,
        "request": {
            "output_tokens": 512,
            "min_completion_tokens": 512,
            "require_natural_stop": False,
            "temperature": 0,
            "seed": 42042,
        },
    }
    value["request"] = {
        "output_tokens": 128,
        "min_completion_tokens": 128,
        "require_natural_stop": False,
        "temperature": 0,
        "seed": 42042,
    }
    value["cases"] = [
        {"id": "32k", "prompt_tokens": 32768, "concurrencies": [1, 2, 4]}
    ]
    return value


def short_concurrency_contract() -> dict[str, object]:
    value = short_workload_contract()
    value["schema_version"] = 6
    value["generator"]["version"] = 6  # type: ignore[index]
    value["short"]["concurrencies"] = [1, 2, 4]  # type: ignore[index]
    return value


def ttft_cache_contract() -> dict[str, object]:
    value = short_concurrency_contract()
    value["schema_version"] = 7
    value["generator"]["version"] = 7  # type: ignore[index]
    value["ttft_cache"] = {
        "prompt_tokens": 64_000,
        "prompt_domain": "code",
        "repetitions": 2,
        "request": {
            "output_tokens": 1,
            "min_completion_tokens": 1,
            "require_natural_stop": False,
            "temperature": 0,
            "seed": 42042,
        },
    }
    return value


def execution_payload_contract() -> dict[str, object]:
    value = ttft_cache_contract()
    value["schema_version"] = 8
    value["generator"]["version"] = 8  # type: ignore[index]
    value["execution"]["isolation"] = "fresh-context"  # type: ignore[index]
    value["tokenizer"]["engine_payload_sha256"] = value["tokenizer"].pop(  # type: ignore[index,union-attr]
        "engine_image_sha256"
    )
    return value


class PromptGeneratorTests(unittest.TestCase):
    def test_schema_eight_retains_short_shared_and_ttft_workloads(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "schema-eight"
            plan_path = prompt_generator.materialize(
                execution_payload_contract(),
                output,
                len,
                model_id="fixture-model",
                model_revision="a" * 40,
            )
            plan = json.loads(plan_path.read_text(encoding="utf-8"))
            contexts = {row["name"]: row for row in plan["contexts"]}

        self.assertEqual(
            list(contexts), ["short", "32k", "ttftcold", "ttftwarm"]
        )
        self.assertEqual(
            sorted(contexts["short"]["cells"]),
            [
                "code-c1",
                "code-c2",
                "code-c4",
                "prose-c1",
                "prose-c2",
                "prose-c4",
            ],
        )
        self.assertEqual(len(plan["fixtures"]), 14)

    def test_schema_seven_materializes_one_exact_64k_ttft_reload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "schema-seven"
            plan_path = prompt_generator.materialize(
                ttft_cache_contract(),
                output,
                len,
                model_id="fixture-model",
                model_revision="a" * 40,
            )
            plan = json.loads(plan_path.read_text(encoding="utf-8"))
            contexts = {row["name"]: row for row in plan["contexts"]}
            cold_name = contexts["ttftcold"]["cells"]["code-c1"][0]
            warm_name = contexts["ttftwarm"]["cells"]["code-c1"][0]
            fixtures = {row["name"]: row for row in plan["fixtures"]}
            cold = (output / fixtures[cold_name]["path"]).read_bytes()
            warm = (output / fixtures[warm_name]["path"]).read_bytes()

        self.assertEqual(
            [row["name"] for row in plan["contexts"]],
            ["short", "32k", "ttftcold", "ttftwarm"],
        )
        self.assertEqual(contexts["ttftcold"]["request"]["max_tokens"], 1)
        self.assertEqual(fixtures[cold_name]["sha256"], fixtures[warm_name]["sha256"])
        self.assertEqual(cold, warm)

    def test_schema_six_materializes_short_c1_c2_c4_for_both_domains(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            plan_path = prompt_generator.materialize(
                short_concurrency_contract(),
                pathlib.Path(directory) / "schema-six",
                len,
                model_id="fixture-model",
                model_revision="a" * 40,
            )
            plan = json.loads(plan_path.read_text(encoding="utf-8"))

        self.assertEqual(len(plan["fixtures"]), 12)
        self.assertEqual(
            list(plan["contexts"][0]["cells"]),
            ["code-c1", "code-c2", "code-c4", "prose-c1", "prose-c2", "prose-c4"],
        )

    def test_schema_five_adds_fixed_short_code_and_prose_before_long_cells(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "schema-five"
            plan_path = prompt_generator.materialize(
                short_workload_contract(),
                output,
                len,
                model_id="fixture-model",
                model_revision="a" * 40,
            )
            plan = json.loads(plan_path.read_text(encoding="utf-8"))
            prompts = {
                row["name"]: (output / row["path"]).read_text(encoding="utf-8")
                for row in plan["fixtures"]
            }

        self.assertEqual(plan["schema_version"], 3)
        self.assertEqual([row["name"] for row in plan["contexts"]], ["short", "32k"])
        self.assertEqual(plan["contexts"][0]["request"]["max_tokens"], 512)
        self.assertEqual(plan["contexts"][1]["request"]["max_tokens"], 128)
        self.assertEqual(len(plan["fixtures"]), 6)
        self.assertEqual(
            prompts["short-code-s00"],
            "Implement a production-quality TypeScript JSON-RPC client with retries, "
            "cancellation, schema validation, and tests. Keep writing useful code and "
            "tests until the completion budget is exhausted.",
        )
        self.assertEqual(
            prompts["short-prose-s00"],
            "Write a polished long-form explanation of how a small coastal city can "
            "prepare for a week-long power outage. Use concrete scenes, practical "
            "tradeoffs, and clear paragraphs. Keep writing useful prose until the "
            "completion budget is exhausted.",
        )

    def test_schema_four_streams_share_the_complete_ledger_prefix(self) -> None:
        value = contract()
        value["schema_version"] = 4
        value["generator"]["version"] = 4  # type: ignore[index]
        value["domains"] = ["code"]
        value["execution"] = {
            "isolation": "fresh-matrix",
            "prefix_state": "shared",
            "samples_per_cell": 1,
            "stream_prefix": "shared-body",
        }
        value["cases"][0]["concurrencies"] = [1, 2, 4]  # type: ignore[index]
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "schema-four"
            plan_path = prompt_generator.materialize(
                value,
                output,
                len,
                model_id="fixture-model",
                model_revision="a" * 40,
            )
            plan = json.loads(plan_path.read_text(encoding="utf-8"))
            prompts = [
                (output / row["path"]).read_text(encoding="utf-8")
                for row in plan["fixtures"]
            ]

        boundary = "--- END EVENT LEDGER ---"
        prefixes = [text.split(boundary, 1)[0] for text in prompts]
        self.assertEqual(len(prompts), 4)
        self.assertTrue(all(prefix == prefixes[0] for prefix in prefixes[1:]))
        self.assertEqual(len(set(prompts)), 4)

    def test_schema_three_materializes_only_declared_domains(self) -> None:
        value = contract()
        value["schema_version"] = 3
        value["generator"]["version"] = 3  # type: ignore[index]
        value["domains"] = ["code"]
        value["execution"] = {
            "isolation": "fresh-matrix",
            "prefix_state": "shared",
            "samples_per_cell": 1,
        }
        value["cases"][0]["concurrencies"] = [1, 2, 4]  # type: ignore[index]
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "schema-three"
            plan_path = prompt_generator.materialize(
                value,
                output,
                len,
                model_id="fixture-model",
                model_revision="a" * 40,
            )
            plan = json.loads(plan_path.read_text(encoding="utf-8"))

        self.assertEqual(plan["prompt_suite"], "letsinfer-code-prose-v1")
        self.assertEqual(len(plan["fixtures"]), 4)
        self.assertTrue(
            all(row["prompt_domain"] == "code" for row in plan["fixtures"])
        )
        self.assertEqual(
            sorted(plan["contexts"][0]["cells"]),
            ["code-c1", "code-c2", "code-c4"],
        )

    def test_materialization_is_deterministic_and_hash_bound(self) -> None:
        # Character count is a deliberately simple exact adapter double.
        counter = len
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            first = root / "first"
            second = root / "second"
            first_plan = prompt_generator.materialize(
                contract(),
                first,
                counter,
                model_id="fixture-model",
                model_revision="a" * 40,
            )
            second_plan = prompt_generator.materialize(
                contract(),
                second,
                counter,
                model_id="fixture-model",
                model_revision="a" * 40,
            )
            self.assertEqual(first_plan.read_bytes(), second_plan.read_bytes())
            first_prompts = sorted((first / "prompts").iterdir())
            second_prompts = sorted((second / "prompts").iterdir())
            self.assertEqual(len(first_prompts), 2)
            self.assertEqual(
                [path.read_bytes() for path in first_prompts],
                [path.read_bytes() for path in second_prompts],
            )
            self.assertNotEqual(first_prompts[0].read_bytes(), first_prompts[1].read_bytes())

            plan = json.loads(first_plan.read_text(encoding="utf-8"))
            row = plan["fixtures"][0]
            first_prompt = first / row["path"]
            self.assertEqual(
                row["sha256"], hashlib.sha256(first_prompt.read_bytes()).hexdigest()
            )
            self.assertEqual(row["expected_prompt_tokens"], len(first_prompt.read_text()))
            materialization = json.loads(
                (first / "materialization.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                materialization["prompt_set_sha256"], plan["prompt_set_sha256"]
            )
            self.assertEqual(
                materialization["plan_sha256"],
                hashlib.sha256(first_plan.read_bytes()).hexdigest(),
            )

    def test_prompt_bytes_do_not_depend_on_model_tokenizer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            first = root / "first"
            second = root / "second"
            first_plan = prompt_generator.materialize(
                contract(), first, len, model_id="model-a", model_revision="a" * 40
            )
            second_plan = prompt_generator.materialize(
                contract(),
                second,
                lambda text: max(1, len(text) // 2),
                model_id="model-b",
                model_revision="b" * 40,
            )
            self.assertEqual(
                [path.read_bytes() for path in sorted((first / "prompts").iterdir())],
                [path.read_bytes() for path in sorted((second / "prompts").iterdir())],
            )
            first_counts = [row["expected_prompt_tokens"] for row in json.loads(first_plan.read_text())["fixtures"]]
            second_counts = [row["expected_prompt_tokens"] for row in json.loads(second_plan.read_text())["fixtures"]]
            self.assertNotEqual(first_counts, second_counts)

    def test_materialization_writes_only_selected_cells(self) -> None:
        value = contract()
        value["cases"][0]["concurrencies"] = [1, 4]  # type: ignore[index]
        with tempfile.TemporaryDirectory() as directory:
            plan_path = prompt_generator.materialize(
                value,
                pathlib.Path(directory) / "out",
                len,
                model_id="fixture-model",
                model_revision="a" * 40,
                selected_cells=["fixture-code-c1"],
            )
            plan = json.loads(plan_path.read_text(encoding="utf-8"))
        self.assertEqual(len(plan["fixtures"]), 1)
        self.assertEqual(
            plan["contexts"][0]["cells"],
            {"code-c1": ["fixture-code-s00"]},
        )


if __name__ == "__main__":
    unittest.main()
