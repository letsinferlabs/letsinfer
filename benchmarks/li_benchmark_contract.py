#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Benchmark-owned schema, generator, and immutable model identity contracts."""

from __future__ import annotations

import hashlib
import json
import math
import pathlib
import re
from typing import Any


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
BENCHMARK_SCHEMA_VERSION = 2
SHARED_BENCHMARK_SCHEMA_VERSION = 3
PREFIX_SHARED_BENCHMARK_SCHEMA_VERSION = 4
SHORT_WORKLOAD_BENCHMARK_SCHEMA_VERSION = 5
SHORT_CONCURRENCY_BENCHMARK_SCHEMA_VERSION = 6
TTFT_CACHE_BENCHMARK_SCHEMA_VERSION = 7
EXECUTION_PAYLOAD_BENCHMARK_SCHEMA_VERSION = 8
BENCHMARK_SUITE = "letsinfer-code-prose-v1"
BENCHMARK_GENERATOR = "letsinfer-code-prose"
BENCHMARK_GENERATOR_VERSION = 2
SHARED_BENCHMARK_GENERATOR_VERSION = 3
PREFIX_SHARED_BENCHMARK_GENERATOR_VERSION = 4
SHORT_WORKLOAD_BENCHMARK_GENERATOR_VERSION = 5
SHORT_CONCURRENCY_BENCHMARK_GENERATOR_VERSION = 6
TTFT_CACHE_BENCHMARK_GENERATOR_VERSION = 7
EXECUTION_PAYLOAD_BENCHMARK_GENERATOR_VERSION = 8
CONTEXT_ISOLATED_BENCHMARK_ISOLATION = "fresh-context"
BENCHMARK_TOKENIZER_CAPABILITY = "engine-rendered-chat-count-v1"
BENCHMARK_RENDER_CONTRACT = "openai-chat-user-v1"


class BenchmarkContractError(ValueError):
    """A benchmark contract or immutable model identity is invalid."""


# Returns canonical JSON bytes with one trailing newline.
def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


# Hashes one exact file without reading it into one unbounded allocation.
def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def benchmark_model_sha256(manifest: dict[str, Any]) -> str:
    """Bind benchmark tokenization to one exact model artifact identity."""
    model = manifest.get("model")
    if not isinstance(model, dict):
        raise BenchmarkContractError("release model identity is missing")
    artifact_name = model.get("artifact")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifact_name, str) or not isinstance(artifacts, list):
        raise BenchmarkContractError("release model artifact identity is missing")
    matches = [
        artifact
        for artifact in artifacts
        if isinstance(artifact, dict) and artifact.get("name") == artifact_name
    ]
    if len(matches) != 1:
        raise BenchmarkContractError("release model artifact identity is ambiguous")
    artifact = matches[0]
    file_sha = artifact.get("sha256")
    if isinstance(file_sha, str) and SHA256_RE.fullmatch(file_sha):
        return file_sha
    repository = artifact.get("repository")
    revision = artifact.get("revision")
    if not isinstance(repository, str) or not repository or not isinstance(revision, str):
        raise BenchmarkContractError("release model snapshot identity is incomplete")
    return hashlib.sha256(
        canonical_bytes({"repository": repository, "revision": revision})
    ).hexdigest()


def validate_benchmark_contract(value: Any) -> dict[str, Any]:
    """Validate the declarative, engine-neutral runtime benchmark contract."""
    where = "runtime.benchmark"
    common_fields = {
        "schema_version",
        "suite",
        "generator",
        "tokenizer",
        "request",
        "sample_interval_seconds",
        "cases",
    }
    schema_version = value.get("schema_version") if isinstance(value, dict) else None
    if schema_version == BENCHMARK_SCHEMA_VERSION:
        required = common_fields
    elif schema_version in {
        SHARED_BENCHMARK_SCHEMA_VERSION,
        PREFIX_SHARED_BENCHMARK_SCHEMA_VERSION,
    }:
        required = common_fields | {"domains", "execution"}
    elif schema_version in {
        SHORT_WORKLOAD_BENCHMARK_SCHEMA_VERSION,
        SHORT_CONCURRENCY_BENCHMARK_SCHEMA_VERSION,
    }:
        required = common_fields | {"domains", "execution", "short"}
    elif schema_version in {
        TTFT_CACHE_BENCHMARK_SCHEMA_VERSION,
        EXECUTION_PAYLOAD_BENCHMARK_SCHEMA_VERSION,
    }:
        required = common_fields | {"domains", "execution", "short", "ttft_cache"}
    else:
        required = common_fields
    if not isinstance(value, dict) or set(value) != required:
        raise BenchmarkContractError(
            f"{where} must contain exactly {', '.join(sorted(required))}"
        )
    if (
        type(value.get("schema_version")) is not int
        or value.get("schema_version")
        not in {
            BENCHMARK_SCHEMA_VERSION,
            SHARED_BENCHMARK_SCHEMA_VERSION,
            PREFIX_SHARED_BENCHMARK_SCHEMA_VERSION,
            SHORT_WORKLOAD_BENCHMARK_SCHEMA_VERSION,
            SHORT_CONCURRENCY_BENCHMARK_SCHEMA_VERSION,
            TTFT_CACHE_BENCHMARK_SCHEMA_VERSION,
            EXECUTION_PAYLOAD_BENCHMARK_SCHEMA_VERSION,
        }
    ):
        raise BenchmarkContractError(f"{where}.schema_version is unsupported")
    if value.get("suite") != BENCHMARK_SUITE:
        raise BenchmarkContractError(f"{where}.suite is unsupported")

    generator = value.get("generator")
    if not isinstance(generator, dict) or set(generator) != {"id", "version"}:
        raise BenchmarkContractError(f"{where}.generator must contain exactly id and version")
    expected_generator_version = {
        BENCHMARK_SCHEMA_VERSION: BENCHMARK_GENERATOR_VERSION,
        SHARED_BENCHMARK_SCHEMA_VERSION: SHARED_BENCHMARK_GENERATOR_VERSION,
        PREFIX_SHARED_BENCHMARK_SCHEMA_VERSION: (
            PREFIX_SHARED_BENCHMARK_GENERATOR_VERSION
        ),
        SHORT_WORKLOAD_BENCHMARK_SCHEMA_VERSION: (
            SHORT_WORKLOAD_BENCHMARK_GENERATOR_VERSION
        ),
        SHORT_CONCURRENCY_BENCHMARK_SCHEMA_VERSION: (
            SHORT_CONCURRENCY_BENCHMARK_GENERATOR_VERSION
        ),
        TTFT_CACHE_BENCHMARK_SCHEMA_VERSION: TTFT_CACHE_BENCHMARK_GENERATOR_VERSION,
        EXECUTION_PAYLOAD_BENCHMARK_SCHEMA_VERSION: (
            EXECUTION_PAYLOAD_BENCHMARK_GENERATOR_VERSION
        ),
    }[value["schema_version"]]
    if (
        generator.get("id") != BENCHMARK_GENERATOR
        or type(generator.get("version")) is not int
        or generator.get("version") != expected_generator_version
    ):
        raise BenchmarkContractError(f"{where}.generator is unsupported")

    if value["schema_version"] in {
        SHARED_BENCHMARK_SCHEMA_VERSION,
        PREFIX_SHARED_BENCHMARK_SCHEMA_VERSION,
        SHORT_WORKLOAD_BENCHMARK_SCHEMA_VERSION,
        SHORT_CONCURRENCY_BENCHMARK_SCHEMA_VERSION,
        TTFT_CACHE_BENCHMARK_SCHEMA_VERSION,
        EXECUTION_PAYLOAD_BENCHMARK_SCHEMA_VERSION,
    }:
        domains = value.get("domains")
        if (
            not isinstance(domains, list)
            or not domains
            or domains != [domain for domain in ("code", "prose") if domain in domains]
        ):
            raise BenchmarkContractError(
                f"{where}.domains must be a non-empty ordered subset of code and prose"
            )
        execution = value.get("execution")
        execution_fields = {"isolation", "prefix_state", "samples_per_cell"}
        if value["schema_version"] in {
            PREFIX_SHARED_BENCHMARK_SCHEMA_VERSION,
            SHORT_WORKLOAD_BENCHMARK_SCHEMA_VERSION,
            SHORT_CONCURRENCY_BENCHMARK_SCHEMA_VERSION,
            TTFT_CACHE_BENCHMARK_SCHEMA_VERSION,
            EXECUTION_PAYLOAD_BENCHMARK_SCHEMA_VERSION,
        }:
            execution_fields.add("stream_prefix")
        if not isinstance(execution, dict) or set(execution) != execution_fields:
            raise BenchmarkContractError(
                f"{where}.execution must contain exactly "
                + ", ".join(sorted(execution_fields))
            )
        allowed_isolations = {"fresh-matrix"}
        if value["schema_version"] == EXECUTION_PAYLOAD_BENCHMARK_SCHEMA_VERSION:
            allowed_isolations.add(CONTEXT_ISOLATED_BENCHMARK_ISOLATION)
        if execution.get("isolation") not in allowed_isolations:
            expected = " or ".join(sorted(allowed_isolations))
            raise BenchmarkContractError(
                f"{where}.execution.isolation must be {expected}"
            )
        if execution.get("prefix_state") != "shared":
            raise BenchmarkContractError(
                f"{where}.execution.prefix_state must be shared"
            )
        if execution.get("samples_per_cell") != 1:
            raise BenchmarkContractError(
                f"{where}.execution.samples_per_cell must be 1"
            )
        if (
            value["schema_version"]
            in {
                PREFIX_SHARED_BENCHMARK_SCHEMA_VERSION,
                SHORT_WORKLOAD_BENCHMARK_SCHEMA_VERSION,
                SHORT_CONCURRENCY_BENCHMARK_SCHEMA_VERSION,
                TTFT_CACHE_BENCHMARK_SCHEMA_VERSION,
                EXECUTION_PAYLOAD_BENCHMARK_SCHEMA_VERSION,
            }
            and execution.get("stream_prefix") != "shared-body"
        ):
            raise BenchmarkContractError(
                f"{where}.execution.stream_prefix must be shared-body"
            )

    tokenizer = value.get("tokenizer")
    engine_identity_field = (
        "engine_payload_sha256"
        if value["schema_version"] == EXECUTION_PAYLOAD_BENCHMARK_SCHEMA_VERSION
        else "engine_image_sha256"
    )
    tokenizer_fields = {
        "capability",
        "model_sha256",
        engine_identity_field,
        "render_contract",
    }
    if not isinstance(tokenizer, dict) or set(tokenizer) != tokenizer_fields:
        raise BenchmarkContractError(
            f"{where}.tokenizer must contain exactly "
            + ", ".join(sorted(tokenizer_fields))
        )
    if tokenizer.get("capability") != BENCHMARK_TOKENIZER_CAPABILITY:
        raise BenchmarkContractError(f"{where}.tokenizer.capability is unsupported")
    if tokenizer.get("render_contract") != BENCHMARK_RENDER_CONTRACT:
        raise BenchmarkContractError(f"{where}.tokenizer.render_contract is unsupported")
    for field in ("model_sha256", engine_identity_field):
        if not isinstance(tokenizer.get(field), str) or not SHA256_RE.fullmatch(
            tokenizer[field]
        ):
            raise BenchmarkContractError(f"{where}.tokenizer.{field} must be a SHA-256")

    request = value.get("request")
    _validate_benchmark_request(request, f"{where}.request")

    if value["schema_version"] in {
        SHORT_WORKLOAD_BENCHMARK_SCHEMA_VERSION,
        SHORT_CONCURRENCY_BENCHMARK_SCHEMA_VERSION,
        TTFT_CACHE_BENCHMARK_SCHEMA_VERSION,
        EXECUTION_PAYLOAD_BENCHMARK_SCHEMA_VERSION,
    }:
        short = value.get("short")
        short_fields = {
            "domains",
            "prompt_tokens",
            "request",
        }
        if value["schema_version"] in {
            SHORT_CONCURRENCY_BENCHMARK_SCHEMA_VERSION,
            TTFT_CACHE_BENCHMARK_SCHEMA_VERSION,
            EXECUTION_PAYLOAD_BENCHMARK_SCHEMA_VERSION,
        }:
            short_fields.add("concurrencies")
        if not isinstance(short, dict) or set(short) != short_fields:
            raise BenchmarkContractError(
                f"{where}.short must contain exactly "
                + ", ".join(sorted(short_fields))
            )
        if short.get("domains") != ["code", "prose"]:
            raise BenchmarkContractError(
                f"{where}.short.domains must be exactly code and prose"
            )
        prompt_tokens = short.get("prompt_tokens")
        if (
            not isinstance(prompt_tokens, int)
            or isinstance(prompt_tokens, bool)
            or prompt_tokens <= 0
        ):
            raise BenchmarkContractError(f"{where}.short.prompt_tokens must be positive")
        _validate_benchmark_request(short.get("request"), f"{where}.short.request")
        if (
            value["schema_version"]
            in {
                SHORT_CONCURRENCY_BENCHMARK_SCHEMA_VERSION,
                TTFT_CACHE_BENCHMARK_SCHEMA_VERSION,
                EXECUTION_PAYLOAD_BENCHMARK_SCHEMA_VERSION,
            }
            and short.get("concurrencies") != [1, 2, 4]
        ):
            raise BenchmarkContractError(
                f"{where}.short.concurrencies must be exactly 1, 2, and 4"
            )

    if value["schema_version"] in {
        TTFT_CACHE_BENCHMARK_SCHEMA_VERSION,
        EXECUTION_PAYLOAD_BENCHMARK_SCHEMA_VERSION,
    }:
        ttft_cache = value.get("ttft_cache")
        if not isinstance(ttft_cache, dict) or set(ttft_cache) != {
            "prompt_tokens",
            "prompt_domain",
            "repetitions",
            "request",
        }:
            raise BenchmarkContractError(
                f"{where}.ttft_cache must contain exactly prompt_tokens, "
                "prompt_domain, repetitions, and request"
            )
        if ttft_cache.get("prompt_tokens") != 64_000:
            raise BenchmarkContractError(
                f"{where}.ttft_cache.prompt_tokens must be exactly 64000"
            )
        if ttft_cache.get("prompt_domain") != "code":
            raise BenchmarkContractError(
                f"{where}.ttft_cache.prompt_domain must be code"
            )
        if ttft_cache.get("repetitions") != 2:
            raise BenchmarkContractError(
                f"{where}.ttft_cache.repetitions must be exactly 2"
            )
        ttft_request = _validate_benchmark_request(
            ttft_cache.get("request"), f"{where}.ttft_cache.request"
        )
        if (
            ttft_request["output_tokens"] != 1
            or ttft_request["min_completion_tokens"] != 1
            or ttft_request["require_natural_stop"] is not False
            or float(ttft_request["temperature"]) != 0.0
        ):
            raise BenchmarkContractError(
                f"{where}.ttft_cache.request must request exactly one deterministic token"
            )

    interval = value.get("sample_interval_seconds")
    if (
        not isinstance(interval, int)
        or isinstance(interval, bool)
        or interval not in range(1, 61)
    ):
        raise BenchmarkContractError(
            f"{where}.sample_interval_seconds must be from 1 through 60"
        )

    cases = value.get("cases")
    if not isinstance(cases, list) or not cases:
        raise BenchmarkContractError(f"{where}.cases must be a non-empty list")
    seen: set[str] = set()
    for index, case in enumerate(cases):
        case_where = f"{where}.cases[{index}]"
        if not isinstance(case, dict) or set(case) != {
            "id",
            "prompt_tokens",
            "concurrencies",
        }:
            raise BenchmarkContractError(
                f"{case_where} must contain exactly id, prompt_tokens, and "
                "concurrencies"
            )
        case_id = case.get("id")
        if not isinstance(case_id, str) or not SAFE_NAME_RE.fullmatch(case_id):
            raise BenchmarkContractError(f"{case_where}.id must be a lowercase safe name")
        if case_id in seen:
            raise BenchmarkContractError(f"duplicate runtime benchmark case: {case_id}")
        seen.add(case_id)
        prompt_tokens = case.get("prompt_tokens")
        if (
            not isinstance(prompt_tokens, int)
            or isinstance(prompt_tokens, bool)
            or prompt_tokens <= 0
        ):
            raise BenchmarkContractError(f"{case_where}.prompt_tokens must be positive")
        concurrencies = case.get("concurrencies")
        if (
            not isinstance(concurrencies, list)
            or not concurrencies
            or any(
                not isinstance(item, int)
                or isinstance(item, bool)
                or item <= 0
                or item > 128
                for item in concurrencies
            )
            or concurrencies != sorted(set(concurrencies))
        ):
            raise BenchmarkContractError(
                f"{case_where}.concurrencies must be sorted unique values from 1 through 128"
            )
    return value


def _validate_benchmark_request(request: Any, where: str) -> dict[str, Any]:
    """Validate one long- or short-workload request contract."""
    request_fields = {
        "output_tokens",
        "min_completion_tokens",
        "require_natural_stop",
        "temperature",
        "seed",
    }
    if not isinstance(request, dict) or set(request) != request_fields:
        raise BenchmarkContractError(
            f"{where} must contain exactly "
            + ", ".join(sorted(request_fields))
        )
    for field in ("output_tokens", "min_completion_tokens"):
        item = request.get(field)
        if not isinstance(item, int) or isinstance(item, bool) or item <= 0:
            raise BenchmarkContractError(f"{where}.{field} must be positive")
    temperature = request.get("temperature")
    if (
        not isinstance(temperature, (int, float))
        or isinstance(temperature, bool)
        or float(temperature) < 0
        or not math.isfinite(float(temperature))
    ):
        raise BenchmarkContractError(
            f"{where}.temperature must be finite and non-negative"
        )
    if request["min_completion_tokens"] > request["output_tokens"]:
        raise BenchmarkContractError(
            f"{where}.min_completion_tokens cannot exceed output_tokens"
        )
    seed = request.get("seed")
    if not isinstance(seed, int) or isinstance(seed, bool) or seed < 0:
        raise BenchmarkContractError(f"{where}.seed must be non-negative")
    if not isinstance(request.get("require_natural_stop"), bool):
        raise BenchmarkContractError(
            f"{where}.require_natural_stop must be boolean"
        )
    return request
