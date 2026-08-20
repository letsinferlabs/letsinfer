#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Materialize Let's Infer's fixed, model-neutral code/prose prompts.

The generator owns prompt bytes. Runtime tokenizers only count the complete
rendered requests after generation; they never resize or rewrite a prompt.
That makes every suite/version/context/domain/stream byte-identical across
models while retaining exact per-model token evidence.
"""

from __future__ import annotations

import hashlib
import pathlib
import sys
from collections.abc import Callable, Iterable
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.runtime_packs import (  # noqa: E402
    BENCHMARK_GENERATOR,
    BENCHMARK_GENERATOR_VERSION,
    BENCHMARK_RENDER_CONTRACT,
    BENCHMARK_SUITE,
    BENCHMARK_TOKENIZER_CAPABILITY,
    canonical_bytes,
    sha256_file,
    validate_benchmark_contract,
)


PROMPTS = pathlib.Path(__file__).resolve().parent / "prompts"
DOMAINS = ("code", "prose")
TEMPLATES = {domain: PROMPTS / f"{domain}.md" for domain in DOMAINS}
NODES = ("amber", "blue", "calm", "green", "north", "plain", "silver", "west")
ITEMS = ("batch", "event", "item", "key", "record", "signal", "task", "value")
STATES = ("clean", "final", "open", "ready", "safe", "stable", "valid", "warm")
ACTIONS = ("checked", "joined", "kept", "moved", "read", "saved", "sorted", "wrote")
CHECKS = ("boundary", "order", "range", "retry", "state", "time", "type", "value")


class PromptGenerationError(ValueError):
    """A benchmark contract could not be materialized exactly."""


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def prompt_set_sha256(rows: list[dict[str, Any]]) -> str:
    """Hash a prompt set by stable relative path and content hash."""
    digest = hashlib.sha256()
    for row in sorted(rows, key=lambda item: item["relative_path"]):
        digest.update(row["relative_path"].encode("utf-8"))
        digest.update(b"\0")
        digest.update(row["sha256"].encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def _next(state: int) -> int:
    state ^= (state << 13) & 0xFFFFFFFF
    state ^= state >> 17
    state ^= (state << 5) & 0xFFFFFFFF
    return state & 0xFFFFFFFF


def _source_text(seed: int, target_prompt_tokens: int) -> str:
    """Create the canonical event ledger without consulting a tokenizer."""
    word_budget = max(256, int(target_prompt_tokens * 0.96))
    state = (seed & 0xFFFFFFFF) or 0x9E3779B9
    words: list[str] = []
    while len(words) < word_budget:
        chosen: list[str] = []
        for values in (NODES, ITEMS, STATES, ACTIONS, CHECKS, NODES, ITEMS, STATES):
            state = _next(state)
            chosen.append(values[state % len(values)])
        sentence = (
            "The {0} node {3} the {1} after the {4} check and kept the "
            "{6} in the {7} state while the {5} node recorded the result."
        ).format(*chosen).split()
        remaining = word_budget - len(words)
        words.extend(sentence[:remaining])
    lines = [
        " ".join(words[index : index + 24])
        for index in range(0, len(words), 24)
    ]
    return ".\n".join(lines) + ".\n"


def _render(
    template: str,
    *,
    fixture_id: str,
    marker: str,
    slot: int,
    body: str,
) -> str:
    rendered = (
        template.replace("{{FIXTURE_ID}}", fixture_id)
        .replace("{{MARKER}}", marker)
        .replace("{{SLOT}}", str(slot))
        .replace("{{BODY}}", body)
    )
    if "{{" in rendered or "}}" in rendered:
        raise PromptGenerationError("benchmark template has an unresolved placeholder")
    return rendered


def contract_cells(contract: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return both standard prompt domains for every declared matrix cell."""
    validate_benchmark_contract(contract)
    request = contract["request"]
    cells: dict[str, dict[str, Any]] = {}
    for case in contract["cases"]:
        for concurrency in case["concurrencies"]:
            for domain in DOMAINS:
                name = f"{case['id']}-{domain}-c{concurrency}"
                cells[name] = {
                    "name": name,
                    "context": case["id"],
                    "prompt_domain": domain,
                    "prompt_suite": BENCHMARK_SUITE,
                    "target_prompt_tokens": case["prompt_tokens"],
                    "concurrency": concurrency,
                    "max_tokens": request["output_tokens"],
                }
    return cells


def materialize(
    contract: dict[str, Any],
    output: pathlib.Path,
    count_tokens: Callable[[str], int],
    *,
    model_id: str,
    model_revision: str,
    selected_cells: Iterable[str] | None = None,
) -> pathlib.Path:
    """Write canonical prompt bytes and their exact per-model token counts."""
    validate_benchmark_contract(contract)
    output = output.resolve(strict=False)
    if output.exists():
        raise PromptGenerationError(f"refusing existing materialization: {output}")
    all_cells = contract_cells(contract)
    selected = set(selected_cells or all_cells)
    unknown = sorted(selected - set(all_cells))
    if unknown:
        raise PromptGenerationError("unknown benchmark cell(s): " + ", ".join(unknown))
    if not selected:
        raise PromptGenerationError("no benchmark cells selected")

    output.mkdir(parents=True)
    prompt_root = output / "prompts"
    prompt_root.mkdir()
    fixtures: list[dict[str, Any]] = []
    fixture_rows: dict[tuple[str, str, int], dict[str, Any]] = {}
    contexts: list[dict[str, Any]] = []
    request = contract["request"]

    for case in contract["cases"]:
        cell_map: dict[str, list[str]] = {}
        selected_for_case = [
            all_cells[name]
            for name in selected
            if all_cells[name]["context"] == case["id"]
        ]
        if not selected_for_case:
            continue
        for domain in DOMAINS:
            domain_cells = [
                row for row in selected_for_case if row["prompt_domain"] == domain
            ]
            if not domain_cells:
                continue
            template = TEMPLATES[domain].read_text(encoding="utf-8")
            maximum = max(row["concurrency"] for row in domain_cells)
            for slot in range(maximum):
                fixture_id = f"{case['id']}-{domain}-s{slot:02d}"
                seed_material = (
                    f"{BENCHMARK_SUITE}\0{case['id']}\0{slot}".encode("utf-8")
                )
                seed = int.from_bytes(
                    hashlib.sha256(seed_material).digest()[:4], "big"
                )
                marker = (
                    "LETSINFER-"
                    + hashlib.sha256(seed_material).hexdigest()[:24].upper()
                )
                text = _render(
                    template,
                    fixture_id=fixture_id,
                    marker=marker,
                    slot=slot,
                    body=_source_text(seed, case["prompt_tokens"]),
                )
                observed = count_tokens(text)
                if (
                    not isinstance(observed, int)
                    or isinstance(observed, bool)
                    or observed <= 0
                ):
                    raise PromptGenerationError(
                        f"token counter returned an invalid count for {fixture_id}"
                    )
                path = prompt_root / f"{fixture_id}.md"
                path.write_text(text, encoding="utf-8")
                row = {
                    "name": fixture_id,
                    "path": path.relative_to(output).as_posix(),
                    "sha256": sha256_file(path),
                    "expected_prompt_tokens": observed,
                    "prompt_domain": domain,
                }
                fixtures.append(row)
                fixture_rows[(case["id"], domain, slot)] = row
            for cell in sorted(domain_cells, key=lambda row: row["concurrency"]):
                rows = [
                    fixture_rows[(case["id"], domain, slot)]
                    for slot in range(cell["concurrency"])
                ]
                cell_map[f"{domain}-c{cell['concurrency']}"] = [
                    row["name"] for row in rows
                ]
        contexts.append(
            {
                "name": case["id"],
                "target_prompt_tokens": case["prompt_tokens"],
                "cells": cell_map,
                "sealed_c1": None,
            }
        )

    public_rows = [
        {"relative_path": row["path"], "sha256": row["sha256"]}
        for row in fixtures
    ]
    prompt_set = prompt_set_sha256(public_rows)
    template_hashes = {domain: sha256_file(TEMPLATES[domain]) for domain in DOMAINS}
    identity = {
        "schema_version": 2,
        "suite": BENCHMARK_SUITE,
        "generator": {
            "id": BENCHMARK_GENERATOR,
            "version": BENCHMARK_GENERATOR_VERSION,
            "sha256": sha256_file(pathlib.Path(__file__).resolve()),
        },
        "templates": template_hashes,
        "benchmark_config_sha256": sha256_bytes(canonical_bytes(contract)),
        "tokenizer": contract["tokenizer"],
        "render_contract": BENCHMARK_RENDER_CONTRACT,
        "prompt_set_sha256": prompt_set,
    }
    plan = {
        "schema_version": 2,
        "prompt_suite": BENCHMARK_SUITE,
        "model_id": model_id,
        "model_revision": model_revision,
        "tokenizer_identity": contract["tokenizer"],
        "sample_interval_seconds": contract["sample_interval_seconds"],
        "request": {
            "max_tokens": request["output_tokens"],
            "min_completion_tokens": request["min_completion_tokens"],
            "require_natural_stop": request["require_natural_stop"],
            "temperature": request["temperature"],
            "options": {"seed": request["seed"]},
        },
        "prompt_set_sha256": prompt_set,
        "fixtures": fixtures,
        "contexts": contexts,
        "materialization": identity,
    }
    plan_path = output / "runtime-matrix.json"
    plan_path.write_bytes(canonical_bytes(plan))
    identity["plan_sha256"] = sha256_file(plan_path)
    (output / "materialization.json").write_bytes(canonical_bytes(identity))
    return plan_path
