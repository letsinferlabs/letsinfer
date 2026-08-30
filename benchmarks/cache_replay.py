#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Prove restart-persistent cache reuse across two completed load runs."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import sys
from typing import Any


BENCHMARK_DIR = pathlib.Path(__file__).resolve().parent
if str(BENCHMARK_DIR) not in sys.path:
    sys.path.insert(0, str(BENCHMARK_DIR))
import openai_matrix as common  # pylint: disable=wrong-import-position


class CacheReplayError(common.QualificationError):
    """The population/restore evidence does not prove persistent reuse."""


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-manifest", type=pathlib.Path, required=True)
    parser.add_argument("--population-directory", type=pathlib.Path, required=True)
    parser.add_argument("--restored-directory", type=pathlib.Path, required=True)
    parser.add_argument("--output-directory", type=pathlib.Path, required=True)
    return parser.parse_args()


def read_completed(directory: pathlib.Path, label: str) -> dict[str, Any]:
    if directory.is_symlink() or not directory.is_dir():
        raise CacheReplayError(f"{label} evidence must be a regular directory")
    results_path = directory / "results.json"
    checksum_path = directory / "results.sha256"
    result = common.read_json_object(results_path, f"{label} results")
    digest = common.sha256_file(results_path)
    try:
        checksum = checksum_path.read_text(encoding="utf-8")
    except OSError as error:
        raise CacheReplayError(f"cannot read {label} results checksum: {error}") from error
    if checksum != f"{digest}  results.json\n":
        raise CacheReplayError(f"{label} results checksum is missing or invalid")
    if (
        type(result.get("schema_version")) is not int
        or result.get("schema_version") != 1
        or result.get("contract") != "letsinfer-openai-v1-load-v1"
        or result.get("qualification_passed") is not True
    ):
        raise CacheReplayError(f"{label} is not completed load-v3 evidence")
    result["_results_sha256"] = digest
    return result


def _task_map(result: dict[str, Any], label: str) -> dict[str, dict[str, Any]]:
    tasks = result.get("tasks")
    if not isinstance(tasks, list) or not tasks:
        raise CacheReplayError(f"{label} results have no task summaries")
    mapped: dict[str, dict[str, Any]] = {}
    for task in tasks:
        if not isinstance(task, dict) or not isinstance(task.get("cell"), str):
            raise CacheReplayError(f"{label} has an invalid task summary")
        if task["cell"] in mapped:
            raise CacheReplayError(f"{label} repeats cell {task['cell']}")
        mapped[task["cell"]] = task
    return mapped


def _read_wave(
    directory: pathlib.Path, task_name: str, phase: str, index: int
) -> dict[str, Any]:
    path = directory / "waves" / task_name / f"{phase}-{index:04d}.json"
    wave = common.read_json_object(path, "cache replay wave")
    result = wave.get("result")
    if not isinstance(result, dict):
        raise CacheReplayError(f"wave has no result: {path}")
    return result


def _requests(result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = result.get("requests")
    if not isinstance(rows, list) or not rows:
        raise CacheReplayError("cache replay wave has no requests")
    mapped: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("fixture"), str):
            raise CacheReplayError("cache replay wave has an invalid request")
        if row["fixture"] in mapped:
            raise CacheReplayError(f"cache replay wave repeats {row['fixture']}")
        mapped[row["fixture"]] = row
    return mapped


def _cache_tokens(row: dict[str, Any], label: str, *, hit: bool) -> int:
    value = row.get("cached_prompt_tokens")
    if not isinstance(value, int) or isinstance(value, bool):
        raise CacheReplayError(f"{label} lacks engine-reported cached prompt tokens")
    if hit and value <= 0:
        raise CacheReplayError(f"{label} did not report a cache hit")
    if not hit and value != 0:
        raise CacheReplayError(f"{label} was not an uncached request")
    return value


def _timing(row: dict[str, Any]) -> dict[str, Any]:
    return {
        key: row.get(key)
        for key in (
            "prompt_tokens",
            "completion_tokens",
            "cached_prompt_tokens",
            "cache_write_tokens",
            "ttft_ms",
            "wall_ms",
            "decode_tokens_per_second",
            "output_sha256",
        )
    }


def compare_runs(
    population_directory: pathlib.Path,
    population: dict[str, Any],
    restored_directory: pathlib.Path,
    restored: dict[str, Any],
    cache_provider: str,
    output_policy: str,
) -> dict[str, Any]:
    identity_fields = (
        "release",
        "engine",
        "model_id",
        "model_revision",
        "measured_commit",
        "release_manifest_sha256",
        "fixture_manifest_sha256",
        "server_command_sha256",
        "runner_sha256",
        "source_identity",
        "workload_capacity",
    )
    for field in identity_fields:
        if population.get(field) != restored.get(field):
            raise CacheReplayError(
                f"population/restored evidence differs at {field}"
            )
    population_container = population.get("container_identity") or {}
    restored_container = restored.get("container_identity") or {}
    if population_container.get("image") != restored_container.get("image"):
        raise CacheReplayError("population/restored image identity differs")
    if (
        population_container.get("id") == restored_container.get("id")
        and population_container.get("started_at")
        == restored_container.get("started_at")
    ):
        raise CacheReplayError("cache replay did not cross an engine restart")

    population_tasks = _task_map(population, "population")
    restored_tasks = _task_map(restored, "restored")
    if population_tasks.keys() != restored_tasks.keys():
        raise CacheReplayError("population/restored cells differ")

    if output_policy not in {"all-phases-exact", "restored-repeat-exact"}:
        raise CacheReplayError(
            f"cache replay output policy is invalid: {output_policy}"
        )
    strict_cross_mode = output_policy == "all-phases-exact"
    cells: list[dict[str, Any]] = []
    for cell in sorted(population_tasks):
        population_task = population_tasks[cell]
        restored_task = restored_tasks[cell]
        if population_task.get("warmup_waves", 0) < 1:
            raise CacheReplayError(f"population cell {cell} has no cold wave")
        if population_task.get("measured_waves", 0) < 1:
            raise CacheReplayError(f"population cell {cell} has no hot wave")
        if restored_task.get("measured_waves", 0) < 2:
            raise CacheReplayError(
                f"restored cell {cell} needs two cache-hit waves"
            )

        cold = _read_wave(
            population_directory, population_task["name"], "warmup", 1
        )
        hot = _read_wave(
            population_directory, population_task["name"], "measured", 1
        )
        restored_first = _read_wave(
            restored_directory, restored_task["name"], "measured", 1
        )
        restored_second = _read_wave(
            restored_directory, restored_task["name"], "measured", 2
        )
        cold_hot_equal = common.assert_pair_equal(cold, hot)
        cold_restored_equal = common.assert_pair_equal(cold, restored_first)
        restored_equal = common.assert_pair_equal(restored_first, restored_second)
        if not restored_equal:
            raise CacheReplayError(
                f"restart-restored output divergence in cell {cell}"
            )
        if strict_cross_mode and not (cold_hot_equal and cold_restored_equal):
            raise CacheReplayError(
                f"cold/hot/restored output divergence in exact-capsule cell {cell}"
            )

        phase_rows = {
            "cold": _requests(cold),
            "hot": _requests(hot),
            "restored_first": _requests(restored_first),
            "restored_second": _requests(restored_second),
        }
        fixture_names = phase_rows["cold"].keys()
        if any(rows.keys() != fixture_names for rows in phase_rows.values()):
            raise CacheReplayError(f"cache replay fixtures differ in cell {cell}")
        fixtures: list[dict[str, Any]] = []
        for fixture in sorted(fixture_names):
            cold_row = phase_rows["cold"][fixture]
            hot_row = phase_rows["hot"][fixture]
            first_row = phase_rows["restored_first"][fixture]
            second_row = phase_rows["restored_second"][fixture]
            _cache_tokens(cold_row, f"{cell}/{fixture} cold", hit=False)
            _cache_tokens(hot_row, f"{cell}/{fixture} hot", hit=True)
            _cache_tokens(first_row, f"{cell}/{fixture} restored-1", hit=True)
            _cache_tokens(second_row, f"{cell}/{fixture} restored-2", hit=True)
            fixtures.append(
                {
                    "fixture": fixture,
                    "cold": _timing(cold_row),
                    "hot": _timing(hot_row),
                    "restored_first": _timing(first_row),
                    "restored_second": _timing(second_row),
                }
            )
        cells.append(
            {
                "cell": cell,
                "cold_hot_outputs_equal": cold_hot_equal,
                "cold_restored_outputs_equal": cold_restored_equal,
                "restored_outputs_equal": restored_equal,
                "fixtures": fixtures,
            }
        )
    return {
        "schema_version": 1,
        "contract": "letsinfer-restart-cache-replay-v1",
        "cache_provider": cache_provider,
        "output_policy": output_policy,
        "cross_mode_exactness_required": strict_cross_mode,
        "population_results_sha256": population["_results_sha256"],
        "restored_results_sha256": restored["_results_sha256"],
        "measured_commit": population["measured_commit"],
        "release": population["release"],
        "engine": population["engine"],
        "model_id": population["model_id"],
        "model_revision": population["model_revision"],
        "source_identity": population["source_identity"],
        "image": population_container["image"],
        "population_container": population_container,
        "restored_container": restored_container,
        "cells": cells,
        "qualification_passed": True,
    }


def main() -> int:
    arguments = parse_arguments()
    if arguments.output_directory.exists():
        raise CacheReplayError(
            f"refusing existing output directory: {arguments.output_directory}"
        )
    manifest = common.read_json_object(arguments.release_manifest, "release manifest")
    source_root = pathlib.Path(__file__).resolve().parents[1]
    release, engine, model_id = common.validate_release_sources(manifest, source_root)
    if manifest.get("cache", {}).get("persistent") is not True:
        raise CacheReplayError("release does not declare persistent cache support")
    population = read_completed(arguments.population_directory, "population")
    restored = read_completed(arguments.restored_directory, "restored")
    expected_manifest_hash = common.sha256_file(arguments.release_manifest)
    for label, result in (("population", population), ("restored", restored)):
        if (
            result.get("release") != release
            or result.get("engine") != engine
            or result.get("model_id") != model_id
            or result.get("release_manifest_sha256") != expected_manifest_hash
        ):
            raise CacheReplayError(f"{label} evidence does not match the release")
    report = compare_runs(
        arguments.population_directory,
        population,
        arguments.restored_directory,
        restored,
        manifest["cache"]["provider"],
        manifest["cache"]["replay_output_policy"],
    )
    report["captured_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
    arguments.output_directory.mkdir(parents=True)
    results_path = arguments.output_directory / "results.json"
    common.write_json_atomic(results_path, report)
    results_sha = common.sha256_file(results_path)
    common.write_text_atomic(
        arguments.output_directory / "results.sha256",
        f"{results_sha}  results.json\n",
    )
    print(
        f"PASS {release} cache={manifest['cache']['provider']} "
        f"cells={len(report['cells'])} results_sha256={results_sha}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except common.QualificationError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
