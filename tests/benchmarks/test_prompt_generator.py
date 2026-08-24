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


class PromptGeneratorTests(unittest.TestCase):
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
