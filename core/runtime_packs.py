#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Immutable Let's Infer runtime-pack artifacts and local installation receipts."""

from __future__ import annotations

import base64
import contextlib
import dataclasses
import datetime as dt
import hashlib
import io
import json
import math
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from typing import Any

from core.orchestration import OrchestrationError, validate_target_binding
from core.paths import config_root, data_root, runtime_root


RUNTIME_CONFIG = "runtime.json"
RUNTIME_DESCRIPTOR = "letsinfer-runtime.json"
RUNTIME_SCHEMA_VERSION = 5
ENGINE_PROTOCOL_VERSION = 2
ARTIFACT_SCHEMA_VERSION = 5
CATALOG_SCHEMA_VERSION = 6
DEFAULT_CATALOG_URL = (
    "https://github.com/letsinferlabs/runtimes/releases/latest/download/catalog.json"
)
BUILTIN_CATALOG_PUBLIC_KEY = (
    pathlib.Path(__file__).resolve().parent / "trust" / "catalog-public-key.pem"
)
PACK_MEDIA_TYPE = "application/vnd.letsinfer.runtime.v5+tar"
REGISTRY_DIGEST_RE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
AUTHOR_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,38})$")
LICENSE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]{0,126}$")
MAX_PACK_BYTES = 1 << 30
MAX_PACK_FILES = 10_000
MAX_OCI_MANIFEST_BYTES = 4 << 20
MAX_OCI_TOKEN_BYTES = 64 << 10
MAX_CATALOG_BYTES = 4 << 20
MAX_CATALOG_SIGNATURE_BYTES = 16 << 10
SAFE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
BENCHMARK_SCHEMA_VERSION = 2
BENCHMARK_SUITE = "letsinfer-code-prose-v1"
BENCHMARK_GENERATOR = "letsinfer-code-prose"
BENCHMARK_GENERATOR_VERSION = 2
BENCHMARK_TOKENIZER_CAPABILITY = "engine-rendered-chat-count-v1"
BENCHMARK_RENDER_CONTRACT = "openai-chat-user-v1"
SELECTION_SCHEMA_VERSION = 3
SELECTION_FIELDS = {
    "schema_version",
    "candidate_id",
    "logical_model",
    "engine",
    "target",
    "target_contract_sha256",
    "version",
    "digest",
    "object_root",
    "manifest_path",
    "control_root",
    "installed_at",
    "installed_at_unix_ns",
    "hardware_fingerprint_sha256",
    "installation_id",
    "policy",
    "authorization",
    "source",
    "history",
}


class RuntimePackError(ValueError):
    """A runtime source, artifact, catalog, or receipt is invalid."""


class _OciAuthenticationRequired(RuntimePackError):
    """A registry requires credentials unavailable to the native public puller."""


@dataclasses.dataclass(frozen=True)
class RuntimePack:
    root: pathlib.Path
    descriptor: dict[str, Any]
    runtime: dict[str, Any]
    digest: str

    @property
    def runtime_path(self) -> pathlib.Path:
        return self.root / RUNTIME_CONFIG


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def _semantic_version_key(value: str) -> tuple[Any, ...]:
    match = re.fullmatch(
        r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
        r"(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?",
        value,
    )
    if match is None:
        raise RuntimePackError(f"runtime version is not semantic: {value}")
    prerelease = match[4]
    if prerelease is None:
        pre_key: tuple[Any, ...] = (1,)
    else:
        pre_key = (
            0,
            *(
                (0, int(item)) if item.isdecimal() else (1, item)
                for item in prerelease.split(".")
            ),
        )
    return int(match[1]), int(match[2]), int(match[3]), pre_key


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_object(path: pathlib.Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimePackError(f"cannot read {label} {path}: {error}") from error
    if not isinstance(value, dict):
        raise RuntimePackError(f"{label} must be a JSON object: {path}")
    return value


def _catalog_github_identity(
    value: Any, where: str, *, allow_organization: bool
) -> int:
    account_types = {"User", "Organization"} if allow_organization else {"User"}
    if (
        not isinstance(value, dict)
        or set(value) != {"github_login", "github_id", "github_type"}
        or not isinstance(value.get("github_login"), str)
        or re.fullmatch(
            r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})", value["github_login"]
        )
        is None
        or not isinstance(value.get("github_id"), int)
        or isinstance(value.get("github_id"), bool)
        or value["github_id"] <= 0
        or value.get("github_type") not in account_types
    ):
        raise RuntimePackError(f"catalog GitHub identity for {where} is invalid")
    return value["github_id"]


def _relative_path(value: Any, where: str) -> pathlib.PurePosixPath:
    if not isinstance(value, str) or not value:
        raise RuntimePackError(f"{where} must be a non-empty relative path")
    path = pathlib.PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise RuntimePackError(f"{where} must be a contained relative path")
    return path


def validate_target_contract(value: Any, where: str = "target") -> dict[str, Any]:
    """Validate the portable capability contract behind a target identifier."""
    if not isinstance(value, dict) or set(value) != {
        "id",
        "platform",
        "accelerator",
        "memory",
        "placement",
    }:
        raise RuntimePackError(
            f"{where} must contain exactly id, platform, accelerator, memory, and placement"
        )
    target_id = value.get("id")
    target_platform = value.get("platform")
    if not isinstance(target_id, str) or not SAFE_NAME_RE.fullmatch(target_id):
        raise RuntimePackError(f"{where}.id must be a lowercase safe name")
    if not isinstance(target_platform, str) or not re.fullmatch(
        r"[a-z0-9._-]+/[a-z0-9._-]+", target_platform
    ):
        raise RuntimePackError(f"{where}.platform must be os/architecture")

    accelerator = value.get("accelerator")
    required_accelerator = {
        "vendor",
        "architecture",
        "count",
        "partitioning",
    }
    allowed_accelerator = required_accelerator | {"minimum_memory_gib"}
    if not isinstance(accelerator, dict) or not required_accelerator.issubset(
        accelerator
    ) or set(accelerator) - allowed_accelerator:
        raise RuntimePackError(f"{where}.accelerator has invalid capability fields")
    for key in ("vendor", "architecture"):
        if not isinstance(accelerator.get(key), str) or not SAFE_NAME_RE.fullmatch(
            accelerator[key]
        ):
            raise RuntimePackError(
                f"{where}.accelerator.{key} must be a lowercase safe name"
            )
    count = accelerator.get("count")
    if not isinstance(count, int) or isinstance(count, bool) or count <= 0:
        raise RuntimePackError(f"{where}.accelerator.count must be positive")
    if accelerator.get("partitioning") not in {"full-device", "mig"}:
        raise RuntimePackError(
            f"{where}.accelerator.partitioning must be full-device or mig"
        )
    accelerator_floor = accelerator.get("minimum_memory_gib")
    if accelerator_floor is not None and (
        not isinstance(accelerator_floor, int)
        or isinstance(accelerator_floor, bool)
        or accelerator_floor <= 0
    ):
        raise RuntimePackError(
            f"{where}.accelerator.minimum_memory_gib must be positive"
        )

    memory = value.get("memory")
    if not isinstance(memory, dict) or set(memory) != {
        "topology",
        "minimum_total_gib",
    }:
        raise RuntimePackError(
            f"{where}.memory must contain exactly topology and minimum_total_gib"
        )
    if memory.get("topology") not in {"unified", "discrete"}:
        raise RuntimePackError(f"{where}.memory.topology must be unified or discrete")
    memory_floor = memory.get("minimum_total_gib")
    if (
        not isinstance(memory_floor, int)
        or isinstance(memory_floor, bool)
        or memory_floor <= 0
    ):
        raise RuntimePackError(f"{where}.memory.minimum_total_gib must be positive")

    placement = value.get("placement")
    if not isinstance(placement, dict) or set(placement) != {
        "strategy",
        "node_count",
        "interconnect",
    }:
        raise RuntimePackError(
            f"{where}.placement must contain exactly strategy, node_count, and interconnect"
        )
    strategy = placement.get("strategy")
    if strategy not in {"single", "parallel"}:
        raise RuntimePackError(f"{where}.placement.strategy is invalid")
    node_count = placement.get("node_count")
    if (
        not isinstance(node_count, int)
        or isinstance(node_count, bool)
        or node_count <= 0
        or node_count > 64
    ):
        raise RuntimePackError(f"{where}.placement.node_count must be between 1 and 64")
    if strategy == "single" and node_count != 1:
        raise RuntimePackError(f"{where}.placement single strategy requires one node")
    interconnect = placement.get("interconnect")
    if not isinstance(interconnect, dict) or set(interconnect) != {
        "kind",
        "rdma_required",
        "minimum_speed_mbps",
        "minimum_mtu",
    }:
        raise RuntimePackError(f"{where}.placement.interconnect has invalid fields")
    if interconnect.get("kind") not in {"any", "connectx", "ethernet", "wifi", "other"}:
        raise RuntimePackError(f"{where}.placement.interconnect.kind is invalid")
    if not isinstance(interconnect.get("rdma_required"), bool):
        raise RuntimePackError(f"{where}.placement.interconnect.rdma_required must be boolean")
    for key in ("minimum_speed_mbps", "minimum_mtu"):
        amount = interconnect.get(key)
        if not isinstance(amount, int) or isinstance(amount, bool) or amount < 0:
            raise RuntimePackError(f"{where}.placement.interconnect.{key} must be non-negative")
    if strategy != "parallel" and (
        interconnect["rdma_required"]
        or interconnect["minimum_speed_mbps"]
        or interconnect["minimum_mtu"]
        or interconnect["kind"] != "any"
    ):
        raise RuntimePackError(
            f"{where}.placement interconnect constraints require parallel strategy"
        )
    return value


def target_matches(contract: dict[str, Any], device: dict[str, Any]) -> bool:
    """Return whether one probed device satisfies a target capability contract."""
    try:
        validate_target_contract(contract)
        expected_accelerator = contract["accelerator"]
        actual_accelerator = device["accelerator"]
        expected_memory = contract["memory"]
        actual_memory = device["memory"]
        if contract["platform"] != device["platform"]:
            return False
        actual_count = actual_accelerator.get("count")
        if not isinstance(actual_count, int) or isinstance(actual_count, bool):
            return False
        for key in ("vendor", "architecture", "partitioning"):
            if expected_accelerator[key] != actual_accelerator[key]:
                return False
        if actual_count < expected_accelerator["count"]:
            return False
        accelerator_floor = expected_accelerator.get("minimum_memory_gib")
        if accelerator_floor is not None:
            actual_floor = actual_accelerator.get("minimum_memory_gib")
            if (
                not isinstance(actual_floor, int)
                or isinstance(actual_floor, bool)
                or actual_floor < accelerator_floor
            ):
                return False
        total_gib = actual_memory.get("total_gib")
        return (
            expected_memory["topology"] == actual_memory["topology"]
            and isinstance(total_gib, int)
            and not isinstance(total_gib, bool)
            and total_gib >= expected_memory["minimum_total_gib"]
        )
    except (KeyError, TypeError, RuntimePackError):
        return False


def target_contract_sha256(contract: dict[str, Any]) -> str:
    """Return the canonical identity of one validated hardware target."""
    validate_target_contract(contract)
    return hashlib.sha256(canonical_bytes(contract)).hexdigest()


def benchmark_model_sha256(manifest: dict[str, Any]) -> str:
    """Bind benchmark tokenization to one exact model artifact identity."""
    model = manifest.get("model")
    if not isinstance(model, dict):
        raise RuntimePackError("release model identity is missing")
    artifact_name = model.get("artifact")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifact_name, str) or not isinstance(artifacts, list):
        raise RuntimePackError("release model artifact identity is missing")
    matches = [
        artifact
        for artifact in artifacts
        if isinstance(artifact, dict) and artifact.get("name") == artifact_name
    ]
    if len(matches) != 1:
        raise RuntimePackError("release model artifact identity is ambiguous")
    artifact = matches[0]
    file_sha = artifact.get("sha256")
    if isinstance(file_sha, str) and SHA256_RE.fullmatch(file_sha):
        return file_sha
    repository = artifact.get("repository")
    revision = artifact.get("revision")
    if not isinstance(repository, str) or not repository or not isinstance(revision, str):
        raise RuntimePackError("release model snapshot identity is incomplete")
    return hashlib.sha256(
        canonical_bytes({"repository": repository, "revision": revision})
    ).hexdigest()


def validate_benchmark_contract(value: Any) -> dict[str, Any]:
    """Validate the declarative, engine-neutral runtime benchmark contract."""
    where = "runtime.benchmark"
    required = {
        "schema_version",
        "suite",
        "generator",
        "tokenizer",
        "request",
        "sample_interval_seconds",
        "cases",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise RuntimePackError(
            f"{where} must contain exactly {', '.join(sorted(required))}"
        )
    if (
        type(value.get("schema_version")) is not int
        or value.get("schema_version") != BENCHMARK_SCHEMA_VERSION
    ):
        raise RuntimePackError(f"{where}.schema_version is unsupported")
    if value.get("suite") != BENCHMARK_SUITE:
        raise RuntimePackError(f"{where}.suite is unsupported")

    generator = value.get("generator")
    if not isinstance(generator, dict) or set(generator) != {"id", "version"}:
        raise RuntimePackError(f"{where}.generator must contain exactly id and version")
    if (
        generator.get("id") != BENCHMARK_GENERATOR
        or type(generator.get("version")) is not int
        or generator.get("version") != BENCHMARK_GENERATOR_VERSION
    ):
        raise RuntimePackError(f"{where}.generator is unsupported")

    tokenizer = value.get("tokenizer")
    tokenizer_fields = {
        "capability",
        "model_sha256",
        "engine_image_sha256",
        "render_contract",
    }
    if not isinstance(tokenizer, dict) or set(tokenizer) != tokenizer_fields:
        raise RuntimePackError(
            f"{where}.tokenizer must contain exactly "
            + ", ".join(sorted(tokenizer_fields))
        )
    if tokenizer.get("capability") != BENCHMARK_TOKENIZER_CAPABILITY:
        raise RuntimePackError(f"{where}.tokenizer.capability is unsupported")
    if tokenizer.get("render_contract") != BENCHMARK_RENDER_CONTRACT:
        raise RuntimePackError(f"{where}.tokenizer.render_contract is unsupported")
    for field in ("model_sha256", "engine_image_sha256"):
        if not isinstance(tokenizer.get(field), str) or not SHA256_RE.fullmatch(
            tokenizer[field]
        ):
            raise RuntimePackError(f"{where}.tokenizer.{field} must be a SHA-256")

    request = value.get("request")
    request_fields = {
        "output_tokens",
        "min_completion_tokens",
        "require_natural_stop",
        "temperature",
        "seed",
    }
    if not isinstance(request, dict) or set(request) != request_fields:
        raise RuntimePackError(
            f"{where}.request must contain exactly "
            + ", ".join(sorted(request_fields))
        )
    for field in ("output_tokens", "min_completion_tokens"):
        item = request.get(field)
        if not isinstance(item, int) or isinstance(item, bool) or item <= 0:
            raise RuntimePackError(f"{where}.request.{field} must be positive")
    temperature = request.get("temperature")
    if (
        not isinstance(temperature, (int, float))
        or isinstance(temperature, bool)
        or float(temperature) < 0
        or not math.isfinite(float(temperature))
    ):
        raise RuntimePackError(
            f"{where}.request.temperature must be finite and non-negative"
        )
    if request["min_completion_tokens"] > request["output_tokens"]:
        raise RuntimePackError(
            f"{where}.request.min_completion_tokens cannot exceed output_tokens"
        )
    seed = request.get("seed")
    if not isinstance(seed, int) or isinstance(seed, bool) or seed < 0:
        raise RuntimePackError(f"{where}.request.seed must be non-negative")
    if not isinstance(request.get("require_natural_stop"), bool):
        raise RuntimePackError(
            f"{where}.request.require_natural_stop must be boolean"
        )

    interval = value.get("sample_interval_seconds")
    if (
        not isinstance(interval, int)
        or isinstance(interval, bool)
        or interval not in range(1, 61)
    ):
        raise RuntimePackError(
            f"{where}.sample_interval_seconds must be from 1 through 60"
        )

    cases = value.get("cases")
    if not isinstance(cases, list) or not cases:
        raise RuntimePackError(f"{where}.cases must be a non-empty list")
    seen: set[str] = set()
    for index, case in enumerate(cases):
        case_where = f"{where}.cases[{index}]"
        if not isinstance(case, dict) or set(case) != {
            "id",
            "prompt_tokens",
            "concurrencies",
        }:
            raise RuntimePackError(
                f"{case_where} must contain exactly id, prompt_tokens, and "
                "concurrencies"
            )
        case_id = case.get("id")
        if not isinstance(case_id, str) or not SAFE_NAME_RE.fullmatch(case_id):
            raise RuntimePackError(f"{case_where}.id must be a lowercase safe name")
        if case_id in seen:
            raise RuntimePackError(f"duplicate runtime benchmark case: {case_id}")
        seen.add(case_id)
        prompt_tokens = case.get("prompt_tokens")
        if (
            not isinstance(prompt_tokens, int)
            or isinstance(prompt_tokens, bool)
            or prompt_tokens <= 0
        ):
            raise RuntimePackError(f"{case_where}.prompt_tokens must be positive")
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
            raise RuntimePackError(
                f"{case_where}.concurrencies must be sorted unique values from 1 through 128"
            )
    return value


def normalize_hf_uri(value: Any, where: str = "model URI") -> tuple[str, str, str]:
    """Validate an exact Hugging Face URI and return owner, repository, and disk slug."""

    if not isinstance(value, str):
        raise RuntimePackError(f"{where} must be an hf://owner/repository URI")
    match = re.fullmatch(r"hf://([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+)", value)
    if match is None:
        raise RuntimePackError(f"{where} must be an hf://owner/repository URI")
    owner, repository = match.groups()
    return owner, repository, f"{owner.lower()}--{repository.lower()}"


def candidate_id(engine: str, model_uri: str, target: str) -> str:
    if not isinstance(engine, str) or not SAFE_NAME_RE.fullmatch(engine):
        raise RuntimePackError("runtime.engine.id must be a lowercase safe name")
    owner, repository, _slug = normalize_hf_uri(model_uri, "runtime.model.uri")
    if not isinstance(target, str) or not SAFE_NAME_RE.fullmatch(target):
        raise RuntimePackError("runtime.target.id must be a lowercase safe name")
    return "--".join((engine, owner.lower(), repository.lower(), target))


def _runtime_metadata(value: dict[str, Any]) -> dict[str, Any]:
    fields = {
        "schema_version",
        "id",
        "version",
        "logical_model",
        "target",
        "engine",
        "model",
        "artifacts",
        "container",
        "cache",
        "serving",
        "benchmark",
        "orchestration",
    }
    if type(value.get("schema_version")) is not int or value.get("schema_version") != RUNTIME_SCHEMA_VERSION:
        raise RuntimePackError("unsupported runtime schema_version")
    unknown = set(value) - fields
    if unknown:
        raise RuntimePackError(
            f"runtime source has unsupported fields: {', '.join(sorted(unknown))}"
        )
    for key in ("id", "version", "logical_model"):
        if not isinstance(value.get(key), str) or not value[key]:
            raise RuntimePackError(f"runtime.{key} must be a non-empty string")
    if not SAFE_NAME_RE.fullmatch(value["logical_model"]):
        raise RuntimePackError("runtime.logical_model must be a lowercase safe name")
    if not VERSION_RE.fullmatch(value["version"]):
        raise RuntimePackError("runtime.version must be semantic version syntax")
    target = validate_target_contract(value.get("target"), "runtime.target")
    engine = value.get("engine")
    required_engine = {
        "id",
        "protocol",
        "oci",
        "model_format",
        "cache_provider",
        "arguments",
        "environment",
    }
    if not isinstance(engine, dict) or set(engine) != required_engine:
        raise RuntimePackError(
            "runtime.engine must contain exactly id, protocol, oci, model_format, "
            "cache_provider, arguments, and environment"
        )
    engine_id = engine.get("id")
    if not isinstance(engine_id, str) or not SAFE_NAME_RE.fullmatch(engine_id):
        raise RuntimePackError("runtime.engine.id must be a lowercase safe name")
    protocol = engine.get("protocol")
    if not isinstance(protocol, dict) or set(protocol) != {"version"}:
        raise RuntimePackError("runtime.engine.protocol must contain exactly version")
    if type(protocol.get("version")) is not int or protocol["version"] != ENGINE_PROTOCOL_VERSION:
        raise RuntimePackError(
            f"runtime.engine.protocol.version must be {ENGINE_PROTOCOL_VERSION}"
        )
    oci = engine.get("oci")
    if not isinstance(oci, dict) or set(oci) not in (
        {"reference", "immutable_id"},
        {"reference", "immutable_id", "base"},
    ):
        raise RuntimePackError("runtime.engine.oci has invalid fields")
    if not REGISTRY_DIGEST_RE.fullmatch(oci.get("reference", "")):
        raise RuntimePackError("runtime.engine.oci.reference must be digest-pinned")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", oci.get("immutable_id", "")):
        raise RuntimePackError("runtime.engine.oci.immutable_id must be a SHA-256 image ID")
    if "base" in oci and not REGISTRY_DIGEST_RE.fullmatch(oci.get("base", "")):
        raise RuntimePackError("runtime.engine.oci.base must be digest-pinned")
    for key in ("model_format", "cache_provider"):
        if not isinstance(engine.get(key), str) or not SAFE_NAME_RE.fullmatch(engine[key]):
            raise RuntimePackError(f"runtime.engine.{key} must be a lowercase safe name")
    if not isinstance(engine.get("arguments"), list) or any(
        not isinstance(item, str) or not item for item in engine["arguments"]
    ):
        raise RuntimePackError("runtime.engine.arguments must contain non-empty strings")
    if not isinstance(engine.get("environment"), dict) or any(
        not isinstance(key, str)
        or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) is None
        or key.startswith("LETSINFER_")
        or not isinstance(item, str)
        for key, item in engine["environment"].items()
    ):
        raise RuntimePackError(
            "runtime.engine.environment must be a portable string map without LETSINFER_ names"
        )

    model = value.get("model")
    if not isinstance(model, dict) or set(model) != {"uri", "artifact", "acquisition"}:
        raise RuntimePackError("runtime.model must contain exactly uri, artifact, and acquisition")
    normalize_hf_uri(model.get("uri"), "runtime.model.uri")
    acquisition = model.get("acquisition")
    if not isinstance(acquisition, dict) or set(acquisition) != {"image"} or not REGISTRY_DIGEST_RE.fullmatch(acquisition.get("image", "")):
        raise RuntimePackError("runtime.model.acquisition.image must be digest-pinned")

    artifacts = value.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise RuntimePackError("runtime.artifacts must be a non-empty list")
    names: set[str] = set()
    primary_uri: str | None = None
    for index, artifact in enumerate(artifacts):
        where = f"runtime.artifacts[{index}]"
        if not isinstance(artifact, dict):
            raise RuntimePackError(f"{where} must be an object")
        name = artifact.get("name")
        if not isinstance(name, str) or not SAFE_NAME_RE.fullmatch(name) or name in names:
            raise RuntimePackError(f"{where}.name must be a unique lowercase safe name")
        names.add(name)
        normalize_hf_uri(artifact.get("uri"), f"{where}.uri")
        artifact_format = artifact.get("format")
        common_fields = {"name", "uri", "format", "revision"}
        if artifact_format == "huggingface-snapshot":
            expected_fields = common_fields
        elif artifact_format == "gguf-file":
            expected_fields = common_fields | {"filename", "sha256"}
            if "bytes" in artifact:
                expected_fields.add("bytes")
        else:
            raise RuntimePackError(
                f"{where}.format must be huggingface-snapshot or gguf-file"
            )
        if set(artifact) != expected_fields:
            raise RuntimePackError(
                f"{where} must contain exactly {', '.join(sorted(expected_fields))}"
            )
        revision = artifact.get("revision")
        if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise RuntimePackError(f"{where}.revision must be a full commit SHA")
        if name == model.get("artifact"):
            primary_uri = artifact["uri"]
        if artifact_format == "gguf-file":
            filename = artifact.get("filename")
            if (
                not isinstance(filename, str)
                or not filename.endswith(".gguf")
                or "/" in filename
                or "\\" in filename
            ):
                raise RuntimePackError(f"{where}.filename must name one contained .gguf file")
            if not isinstance(artifact.get("sha256"), str) or not SHA256_RE.fullmatch(
                artifact["sha256"]
            ):
                raise RuntimePackError(f"{where}.sha256 must be a SHA-256")
            if "bytes" in artifact and (
                not isinstance(artifact["bytes"], int)
                or isinstance(artifact["bytes"], bool)
                or artifact["bytes"] <= 0
            ):
                raise RuntimePackError(f"{where}.bytes must be positive")
    if primary_uri is None:
        raise RuntimePackError("runtime.model.artifact must identify one runtime artifact")
    if primary_uri != model["uri"]:
        raise RuntimePackError("runtime.model.uri must equal the primary artifact URI")
    ordered_names = [artifact["name"] for artifact in artifacts]
    if ordered_names[0] != model["artifact"] or ordered_names[1:] != sorted(ordered_names[1:]):
        raise RuntimePackError(
            "runtime.artifacts must put the primary artifact first and sort the rest by name"
        )
    primary_format = next(
        artifact["format"] for artifact in artifacts if artifact["name"] == model["artifact"]
    )
    if primary_format != engine["model_format"]:
        raise RuntimePackError(
            "runtime primary artifact format must match runtime.engine.model_format"
        )

    cache = value.get("cache")
    if not isinstance(cache, dict) or set(cache) != {
        "provider", "persistent", "prewarm", "replay_output_policy", "config"
    }:
        raise RuntimePackError(
            "runtime.cache must contain exactly provider, persistent, prewarm, "
            "replay_output_policy, and config"
        )
    if cache.get("provider") != engine["cache_provider"]:
        raise RuntimePackError("runtime.cache.provider must match engine.cache_provider")
    if not isinstance(cache.get("persistent"), bool) or not isinstance(cache.get("prewarm"), bool):
        raise RuntimePackError("runtime.cache persistent and prewarm must be boolean")
    if not isinstance(cache.get("config"), dict):
        raise RuntimePackError("runtime.cache.config must be an object")
    if cache["persistent"]:
        if cache.get("replay_output_policy") not in {
            "all-phases-exact", "restored-repeat-exact"
        }:
            raise RuntimePackError(
                "persistent runtime.cache requires an exact replay_output_policy"
            )
    elif cache.get("replay_output_policy") is not None:
        raise RuntimePackError(
            "non-persistent runtime.cache.replay_output_policy must be null"
        )

    container = value.get("container")
    if not isinstance(container, dict) or "model_cache" in container:
        raise RuntimePackError(
            "runtime.container must be an object and cannot override the model store"
        )

    serving = value.get("serving")
    if not isinstance(serving, dict):
        raise RuntimePackError("runtime.serving must be an object")
    if {"qualified", "blocked_by"}.intersection(serving):
        raise RuntimePackError(
            "runtime.serving cannot grant qualification or define blocked_by"
        )

    expected_id = candidate_id(engine_id, model["uri"], target["id"])
    if value["id"] != expected_id:
        raise RuntimePackError(
            "runtime.id must equal <engine>--<hf-owner>--<hf-model>--<target>"
        )

    benchmark = value.get("benchmark")
    if not isinstance(benchmark, dict) or set(benchmark) != {"contract"}:
        raise RuntimePackError("runtime.benchmark must contain exactly contract")
    contract = benchmark.get("contract")
    if not isinstance(contract, dict):
        raise RuntimePackError("runtime.benchmark.contract must be an object")
    if contract.get("schema_version") == BENCHMARK_SCHEMA_VERSION:
        validate_benchmark_contract(contract)
    try:
        validate_target_binding(value.get("orchestration"), target["placement"])
    except OrchestrationError as error:
        raise RuntimePackError(str(error)) from error
    return value


def validate_runtime_config(value: dict[str, Any]) -> dict[str, Any]:
    """Validate one authoritative schema-v5 execution configuration in memory."""

    return _runtime_metadata(value)


def _descriptor_metadata(value: dict[str, Any]) -> dict[str, Any]:
    fields = {
        "artifact_schema_version",
        "media_type",
        "runtime_sha256",
        "candidate",
        "files",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise RuntimePackError("runtime artifact descriptor fields are invalid")
    if type(value.get("artifact_schema_version")) is not int or value["artifact_schema_version"] != ARTIFACT_SCHEMA_VERSION:
        raise RuntimePackError("unsupported runtime artifact_schema_version")
    if value.get("media_type") != PACK_MEDIA_TYPE:
        raise RuntimePackError(f"runtime.media_type must be {PACK_MEDIA_TYPE}")
    if not isinstance(value.get("runtime_sha256"), str) or not SHA256_RE.fullmatch(value["runtime_sha256"]):
        raise RuntimePackError("runtime.runtime_sha256 must be a SHA-256")
    candidate = value.get("candidate")
    if not isinstance(candidate, dict) or set(candidate) != {
        "id", "version", "logical_model", "engine", "target"
    }:
        raise RuntimePackError("runtime candidate summary is invalid")
    for key in ("id", "version", "logical_model", "engine", "target"):
        if not isinstance(candidate.get(key), str) or not candidate[key]:
            raise RuntimePackError(f"runtime candidate {key} is invalid")
    files = value.get("files")
    if not isinstance(files, list) or not files:
        raise RuntimePackError("runtime.files must be a non-empty list")
    return value


def _ignored_source_path(relative: pathlib.PurePath) -> bool:
    return (
        ".git" in relative.parts
        or "__pycache__" in relative.parts
        or relative.name == RUNTIME_DESCRIPTOR
        or relative.as_posix() == "release.json"
        or (
            len(relative.parts) == 1
            and relative.name.startswith("benchmark")
            and relative.suffix == ".json"
        )
        or relative.name == ".DS_Store"
        or relative.suffix in {".pyc", ".pyo", ".letsinfer"}
    )


def _source_files(root: pathlib.Path) -> list[pathlib.Path]:
    if root.is_symlink() or not root.is_dir():
        raise RuntimePackError(f"runtime source must be a regular directory: {root}")
    files: list[pathlib.Path] = []
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if _ignored_source_path(relative):
            continue
        if path.is_symlink():
            raise RuntimePackError(f"runtime source cannot contain symlinks: {relative}")
        if path.is_file():
            files.append(path)
        elif not path.is_dir():
            raise RuntimePackError(f"runtime source contains unsupported entry: {relative}")
    return sorted(files, key=lambda path: path.relative_to(root).as_posix())


def describe_source(root: pathlib.Path) -> RuntimePack:
    root = root.expanduser().resolve(strict=True)
    config = _runtime_metadata(_read_object(root / RUNTIME_CONFIG, "runtime config"))
    files = _source_files(root)
    relative_names = {path.relative_to(root).as_posix() for path in files}
    if RUNTIME_CONFIG not in relative_names:
        raise RuntimePackError(f"runtime source is missing {RUNTIME_CONFIG}")
    if len(files) > MAX_PACK_FILES:
        raise RuntimePackError(f"runtime source exceeds {MAX_PACK_FILES} files")
    records = []
    total = 0
    for path in files:
        size = path.stat().st_size
        total += size
        if total > MAX_PACK_BYTES:
            raise RuntimePackError("runtime source exceeds the 1 GiB source-pack limit")
        records.append(
            {
                "path": path.relative_to(root).as_posix(),
                "bytes": size,
                "mode": 0o755 if os.access(path, os.X_OK) else 0o644,
                "sha256": sha256_file(path),
            }
        )
    runtime_sha256 = sha256_file(root / RUNTIME_CONFIG)
    if runtime_sha256 != next(
        record["sha256"] for record in records if record["path"] == RUNTIME_CONFIG
    ):
        raise RuntimePackError("runtime.json identity changed while describing source")
    descriptor = {
        "artifact_schema_version": ARTIFACT_SCHEMA_VERSION,
        "media_type": PACK_MEDIA_TYPE,
        "runtime_sha256": runtime_sha256,
        "candidate": {
            "id": config["id"],
            "version": config["version"],
            "logical_model": config["logical_model"],
            "engine": config["engine"]["id"],
            "target": config["target"]["id"],
        },
        "files": records,
    }
    digest = hashlib.sha256(canonical_bytes(descriptor)).hexdigest()
    return RuntimePack(root=root, descriptor=descriptor, runtime=config, digest=digest)


def verify_descriptor(root: pathlib.Path) -> RuntimePack:
    root = root.expanduser().resolve(strict=True)
    descriptor_path = root / RUNTIME_DESCRIPTOR
    descriptor = _descriptor_metadata(
        _read_object(descriptor_path, "runtime descriptor")
    )
    seen: set[str] = set()
    expected_files: set[str] = set()
    total = 0
    if len(descriptor["files"]) > MAX_PACK_FILES:
        raise RuntimePackError(f"runtime artifact exceeds {MAX_PACK_FILES} files")
    for index, record in enumerate(descriptor["files"]):
        where = f"runtime.files[{index}]"
        if not isinstance(record, dict):
            raise RuntimePackError(f"{where} must be an object")
        relative = _relative_path(record.get("path"), f"{where}.path").as_posix()
        if relative == RUNTIME_DESCRIPTOR or relative in seen:
            raise RuntimePackError(f"duplicate or reserved runtime path: {relative}")
        size = record.get("bytes")
        mode = record.get("mode")
        digest = record.get("sha256")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise RuntimePackError(f"{where}.bytes must be non-negative")
        if mode not in {0o644, 0o755}:
            raise RuntimePackError(f"{where}.mode must be 0644 or 0755")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise RuntimePackError(f"{where}.sha256 must be a SHA-256")
        path = root / relative
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(root)
        except (OSError, ValueError) as error:
            raise RuntimePackError(f"runtime file escapes its artifact: {relative}") from error
        if path.is_symlink() or not resolved.is_file():
            raise RuntimePackError(f"runtime file is not regular: {relative}")
        details = resolved.stat()
        actual_mode = stat.S_IMODE(details.st_mode)
        if (
            details.st_size != size
            or actual_mode not in {0o644, 0o755}
            or actual_mode != mode
            or sha256_file(resolved) != digest
        ):
            raise RuntimePackError(f"runtime file identity mismatch: {relative}")
        total += size
        if total > MAX_PACK_BYTES:
            raise RuntimePackError("runtime artifact exceeds the 1 GiB source-pack limit")
        seen.add(relative)
        expected_files.add(relative)
    actual_files = {
        path.relative_to(root).as_posix()
        for path in _source_files(root)
        if path.name != RUNTIME_DESCRIPTOR
    }
    if actual_files != expected_files:
        missing = sorted(expected_files - actual_files)
        extra = sorted(actual_files - expected_files)
        raise RuntimePackError(
            f"runtime artifact file set mismatch (missing={missing}, extra={extra})"
        )
    if RUNTIME_CONFIG not in expected_files:
        raise RuntimePackError("runtime.json is not pinned in runtime.files")
    runtime_path = root / RUNTIME_CONFIG
    if sha256_file(runtime_path) != descriptor["runtime_sha256"]:
        raise RuntimePackError("runtime.json differs from the artifact descriptor")
    runtime = _runtime_metadata(_read_object(runtime_path, "runtime config"))
    expected_candidate = {
        "id": runtime["id"],
        "version": runtime["version"],
        "logical_model": runtime["logical_model"],
        "engine": runtime["engine"]["id"],
        "target": runtime["target"]["id"],
    }
    if descriptor["candidate"] != expected_candidate:
        raise RuntimePackError("runtime candidate summary differs from runtime.json")
    digest = hashlib.sha256(canonical_bytes(descriptor)).hexdigest()
    return RuntimePack(root=root, descriptor=descriptor, runtime=runtime, digest=digest)


def build_archive(source: pathlib.Path, output: pathlib.Path) -> RuntimePack:
    source = source.expanduser().resolve(strict=True)
    if (source / "benchmark.md").exists():
        raise RuntimePackError("runtime benchmark results must use benchmark.json")
    pack = describe_source(source)
    output = output.expanduser().resolve(strict=False)
    try:
        output.relative_to(pack.root)
    except ValueError:
        pass
    else:
        raise RuntimePackError("runtime archive output must be outside its source directory")
    if output.exists():
        raise RuntimePackError(f"refusing to overwrite runtime archive: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor_data = canonical_bytes(pack.descriptor)
    with tempfile.NamedTemporaryFile(
        prefix=f".{output.name}.", suffix=".tmp", dir=output.parent, delete=False
    ) as temporary:
        temporary_path = pathlib.Path(temporary.name)
    try:
        with tarfile.open(temporary_path, "w") as archive:
            descriptor_info = tarfile.TarInfo(RUNTIME_DESCRIPTOR)
            descriptor_info.size = len(descriptor_data)
            descriptor_info.mode = 0o644
            descriptor_info.mtime = descriptor_info.uid = descriptor_info.gid = 0
            descriptor_info.uname = descriptor_info.gname = ""
            archive.addfile(descriptor_info, io.BytesIO(descriptor_data))
            for record in pack.descriptor["files"]:
                path = pack.root / record["path"]
                info = tarfile.TarInfo(record["path"])
                info.size = record["bytes"]
                info.mode = record["mode"]
                info.mtime = info.uid = info.gid = 0
                info.uname = info.gname = ""
                with path.open("rb") as handle:
                    archive.addfile(info, handle)
        os.chmod(temporary_path, 0o644)
        temporary_path.replace(output)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise
    return pack


def _extract_archive(archive_path: pathlib.Path, destination: pathlib.Path) -> None:
    total = 0
    try:
        archive = tarfile.open(archive_path, "r:*")
    except (OSError, tarfile.TarError) as error:
        raise RuntimePackError(f"cannot open runtime archive {archive_path}: {error}") from error
    with archive:
        seen: set[str] = set()
        for count, member in enumerate(archive, start=1):
            if count > MAX_PACK_FILES + 1:
                raise RuntimePackError(
                    f"runtime archive exceeds {MAX_PACK_FILES + 1} members"
                )
            relative = _relative_path(member.name, "runtime archive member")
            relative_name = relative.as_posix()
            if relative_name in seen:
                raise RuntimePackError(
                    f"runtime archive contains a duplicate path: {relative}"
                )
            seen.add(relative_name)
            if not member.isfile():
                raise RuntimePackError(f"runtime archive contains a non-file: {relative}")
            total += member.size
            if total > MAX_PACK_BYTES:
                raise RuntimePackError("runtime archive exceeds the 1 GiB source-pack limit")
            target = destination / relative_name
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            source = archive.extractfile(member)
            if source is None:
                raise RuntimePackError(f"cannot read runtime archive member: {relative}")
            with source, target.open("xb") as handle:
                shutil.copyfileobj(source, handle)
            target.chmod(0o755 if member.mode & 0o111 else 0o644)


def _companion_executable(name: str) -> str | None:
    executable = shutil.which(name)
    if executable is not None:
        return executable
    launcher_directory = os.environ.get("LETSINFER_LAUNCHER_DIR")
    if launcher_directory:
        candidate = pathlib.Path(launcher_directory) / name
        try:
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
        except OSError:
            return None
    invocation = pathlib.Path(sys.argv[0]).expanduser()
    if invocation.parent == pathlib.Path("."):
        resolved = shutil.which(sys.argv[0])
        if resolved is None:
            return None
        invocation = pathlib.Path(resolved)
    elif not invocation.is_absolute():
        invocation = pathlib.Path.cwd() / invocation
    candidate = invocation.parent / name
    try:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    except OSError:
        return None
    return None


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_arguments: Any, **_keywords: Any) -> None:
        return None


_OCI_OPENER = urllib.request.build_opener(_NoRedirectHandler())
_OCI_MANIFEST_ACCEPT = ", ".join(
    (
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.oci.artifact.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    )
)


def _oci_open(request: urllib.request.Request) -> Any:
    current = request
    for _redirect in range(6):
        try:
            return _OCI_OPENER.open(current, timeout=30)
        except urllib.error.HTTPError as error:
            if error.code not in {301, 302, 303, 307, 308}:
                raise
            location = error.headers.get("Location")
            error.close()
            if not location:
                raise RuntimePackError(
                    "OCI registry redirect has no location"
                ) from error
            next_url = urllib.parse.urljoin(current.full_url, location)
            old = urllib.parse.urlsplit(current.full_url)
            new = urllib.parse.urlsplit(next_url)
            if (
                new.scheme != "https"
                or not new.hostname
                or new.username is not None
                or new.password is not None
            ):
                raise RuntimePackError("OCI registry redirected away from HTTPS")
            headers = {key: value for key, value in current.header_items()}
            if (old.scheme, old.hostname, old.port) != (
                new.scheme,
                new.hostname,
                new.port,
            ):
                headers = {
                    key: value
                    for key, value in headers.items()
                    if key.lower() not in {"authorization", "host"}
                }
            current = urllib.request.Request(next_url, headers=headers)
    raise RuntimePackError("OCI registry exceeded the redirect limit")


def _read_oci_response(response: Any, *, limit: int, label: str) -> bytes:
    final_url = urllib.parse.urlsplit(response.geturl())
    if final_url.scheme != "https":
        raise RuntimePackError(f"OCI {label} redirected away from HTTPS")
    data = response.read(limit + 1)
    if len(data) > limit:
        raise RuntimePackError(f"OCI {label} exceeds {limit} bytes")
    return data


def _bearer_challenge_parameters(value: str | None) -> dict[str, str]:
    if not value or not value[:7].lower() == "bearer ":
        raise _OciAuthenticationRequired(
            "OCI registry requires unsupported authentication"
        )
    parameters: dict[str, str] = {}
    for match in re.finditer(
        r'([A-Za-z][A-Za-z0-9_-]*)=(?:"([^"\\]*(?:\\.[^"\\]*)*)"|([^,\s]+))',
        value[7:],
    ):
        raw = match.group(2) if match.group(2) is not None else match.group(3)
        parameters[match.group(1).lower()] = raw.replace(r'\"', '"').replace(
            r"\\", "\\"
        )
    if "realm" not in parameters:
        raise _OciAuthenticationRequired(
            "OCI registry bearer challenge has no realm"
        )
    return parameters


def _public_bearer_token(challenge: str | None, repository: str) -> str:
    parameters = _bearer_challenge_parameters(challenge)
    realm = urllib.parse.urlsplit(parameters["realm"])
    if (
        realm.scheme != "https"
        or not realm.hostname
        or realm.username is not None
        or realm.password is not None
        or realm.fragment
    ):
        raise _OciAuthenticationRequired(
            "OCI registry bearer realm is not safe HTTPS"
        )
    query = [
        (key, value)
        for key, value in urllib.parse.parse_qsl(
            realm.query, keep_blank_values=True
        )
        if key not in {"service", "scope"}
    ]
    if "service" in parameters:
        query.append(("service", parameters["service"]))
    query.append(
        ("scope", parameters.get("scope", f"repository:{repository}:pull"))
    )
    token_url = urllib.parse.urlunsplit(
        (
            realm.scheme,
            realm.netloc,
            realm.path,
            urllib.parse.urlencode(query),
            "",
        )
    )
    request = urllib.request.Request(
        token_url,
        headers={"Accept": "application/json", "User-Agent": "letsinfer/oci-pull"},
    )
    try:
        with _oci_open(request) as response:
            data = _read_oci_response(
                response, limit=MAX_OCI_TOKEN_BYTES, label="token response"
            )
    except urllib.error.HTTPError as error:
        if error.code in {401, 403}:
            raise _OciAuthenticationRequired(
                "OCI registry requires credentials"
            ) from error
        raise RuntimePackError(
            f"cannot request OCI registry bearer token: HTTP {error.code}"
        ) from error
    except OSError as error:
        raise RuntimePackError(
            f"cannot request OCI registry bearer token: {error}"
        ) from error
    try:
        document = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimePackError("OCI registry token response is invalid JSON") from error
    token = document.get("token") if isinstance(document, dict) else None
    if not isinstance(token, str) or not token:
        token = document.get("access_token") if isinstance(document, dict) else None
    if (
        not isinstance(token, str)
        or not token
        or any(character.isspace() for character in token)
    ):
        raise _OciAuthenticationRequired(
            "OCI registry returned no usable public token"
        )
    return token


def _open_public_oci_request(
    request: urllib.request.Request, repository: str
) -> Any:
    try:
        return _oci_open(request)
    except urllib.error.HTTPError as error:
        if error.code not in {401, 403}:
            raise RuntimePackError(
                f"cannot read OCI registry object: HTTP {error.code}"
            ) from error
        challenge = error.headers.get("WWW-Authenticate")
        error.close()
    token = _public_bearer_token(challenge, repository)
    authenticated = urllib.request.Request(
        request.full_url,
        headers={key: value for key, value in request.header_items()},
    )
    authenticated.add_header("Authorization", f"Bearer {token}")
    try:
        return _oci_open(authenticated)
    except urllib.error.HTTPError as error:
        if error.code in {401, 403}:
            raise _OciAuthenticationRequired(
                "OCI registry requires credentials"
            ) from error
        raise RuntimePackError(
            f"cannot read OCI registry object: HTTP {error.code}"
        ) from error
    except OSError as error:
        raise RuntimePackError(f"cannot read OCI registry object: {error}") from error


def _native_pull_public_oci(reference: str, destination: pathlib.Path) -> None:
    name, expected_manifest = reference.rsplit("@", 1)
    registry, separator, repository = name.partition("/")
    repository_parts = repository.split("/")
    if (
        not separator
        or not registry
        or not repository
        or not re.fullmatch(r"[A-Za-z0-9.-]+(?::[0-9]+)?", registry)
        or not re.fullmatch(r"[A-Za-z0-9._/-]+", repository)
        or any(part in {"", ".", ".."} for part in repository_parts)
    ):
        raise RuntimePackError("OCI runtime reference has an invalid registry path")
    repository_path = urllib.parse.quote(repository, safe="/")
    manifest_url = (
        f"https://{registry}/v2/{repository_path}/manifests/"
        f"{expected_manifest}"
    )
    manifest_request = urllib.request.Request(
        manifest_url,
        headers={
            "Accept": _OCI_MANIFEST_ACCEPT,
            "User-Agent": "letsinfer/oci-pull",
        },
    )
    try:
        with _open_public_oci_request(manifest_request, repository) as response:
            manifest_data = _read_oci_response(
                response, limit=MAX_OCI_MANIFEST_BYTES, label="manifest"
            )
    except OSError as error:
        raise RuntimePackError(f"cannot read OCI registry manifest: {error}") from error
    manifest_digest = "sha256:" + hashlib.sha256(manifest_data).hexdigest()
    if manifest_digest != expected_manifest:
        raise RuntimePackError(
            "OCI runtime manifest digest differs from its reference"
        )
    try:
        manifest = json.loads(manifest_data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimePackError("OCI runtime manifest is invalid JSON") from error
    if (
        not isinstance(manifest, dict)
        or manifest.get("schemaVersion") != 2
        or manifest.get("mediaType")
        not in {
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.oci.artifact.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.v2+json",
        }
    ):
        raise RuntimePackError("OCI runtime manifest schema is unsupported")
    layers = manifest.get("layers")
    if (
        not isinstance(layers, list)
        or len(layers) != 1
        or not isinstance(layers[0], dict)
    ):
        raise RuntimePackError("OCI runtime manifest must contain exactly one layer")
    layer = layers[0]
    layer_digest = layer.get("digest")
    layer_size = layer.get("size")
    media_type = layer.get("mediaType")
    annotations = layer.get("annotations")
    title = (
        annotations.get("org.opencontainers.image.title")
        if isinstance(annotations, dict)
        else None
    )
    if not isinstance(layer_digest, str) or not re.fullmatch(
        r"sha256:[0-9a-f]{64}", layer_digest
    ):
        raise RuntimePackError("OCI runtime layer digest is invalid")
    if (
        type(layer_size) is not int
        or layer_size <= 0
        or layer_size > MAX_PACK_BYTES
    ):
        raise RuntimePackError("OCI runtime layer size is invalid")
    if media_type != PACK_MEDIA_TYPE and title != "runtime.letsinfer":
        raise RuntimePackError("OCI runtime layer media type is unsupported")
    blob_url = f"https://{registry}/v2/{repository_path}/blobs/{layer_digest}"
    blob_request = urllib.request.Request(
        blob_url,
        headers={"Accept": media_type, "User-Agent": "letsinfer/oci-pull"},
    )
    partial = destination / ".runtime.letsinfer.partial"
    output = destination / "runtime.letsinfer"
    digest = hashlib.sha256()
    total = 0
    try:
        with _open_public_oci_request(blob_request, repository) as response:
            final_url = urllib.parse.urlsplit(response.geturl())
            if final_url.scheme != "https":
                raise RuntimePackError("OCI runtime layer redirected away from HTTPS")
            length = response.headers.get("Content-Length")
            if length is not None:
                try:
                    content_length = int(length)
                except ValueError as error:
                    raise RuntimePackError(
                        "OCI runtime layer Content-Length is invalid"
                    ) from error
                if content_length != layer_size:
                    raise RuntimePackError(
                        "OCI runtime layer size differs from its manifest"
                    )
            with partial.open("xb") as handle:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > layer_size or total > MAX_PACK_BYTES:
                        raise RuntimePackError(
                            "OCI runtime layer exceeds its declared size"
                        )
                    digest.update(chunk)
                    handle.write(chunk)
        if total != layer_size:
            raise RuntimePackError("OCI runtime layer size differs from its manifest")
        if "sha256:" + digest.hexdigest() != layer_digest:
            raise RuntimePackError("OCI runtime layer digest differs from its manifest")
        partial.replace(output)
    except RuntimePackError:
        if partial.exists():
            partial.unlink()
        raise
    except OSError as error:
        if partial.exists():
            partial.unlink()
        raise RuntimePackError(f"cannot read OCI runtime layer: {error}") from error


def _pull_oci(reference: str, destination: pathlib.Path) -> None:
    if not REGISTRY_DIGEST_RE.fullmatch(reference):
        raise RuntimePackError("OCI runtime references must be pinned by sha256 digest")
    try:
        _native_pull_public_oci(reference, destination)
        return
    except _OciAuthenticationRequired as native_error:
        executable = _companion_executable("oras")
        if executable is None:
            raise RuntimePackError(
                "OCI runtime requires registry authentication; install or configure oras"
            ) from native_error
    result = subprocess.run(
        [executable, "pull", "--output", str(destination), reference],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip() or "unknown oras error"
        raise RuntimePackError(f"cannot pull OCI runtime {reference}: {detail}")


@contextlib.contextmanager
def materialize(source: str | os.PathLike[str]) -> Iterator[RuntimePack]:
    raw = os.fspath(source)
    path = pathlib.Path(raw).expanduser()
    if path.exists():
        if path.is_dir():
            descriptor_path = path / RUNTIME_DESCRIPTOR
            yield verify_descriptor(path) if descriptor_path.is_file() else describe_source(path)
            return
        with tempfile.TemporaryDirectory(prefix="letsinfer-runtime-") as temporary:
            root = pathlib.Path(temporary)
            _extract_archive(path.resolve(strict=True), root)
            yield verify_descriptor(root)
            return
    if REGISTRY_DIGEST_RE.fullmatch(raw):
        with tempfile.TemporaryDirectory(prefix="letsinfer-oci-runtime-") as temporary:
            root = pathlib.Path(temporary)
            _pull_oci(raw, root)
            archives = list(root.glob("*.letsinfer"))
            if not (root / RUNTIME_DESCRIPTOR).is_file() and len(archives) == 1:
                unpacked = root / "unpacked"
                unpacked.mkdir(mode=0o700)
                _extract_archive(archives[0], unpacked)
                root = unpacked
            yield verify_descriptor(root)
            return
    raise RuntimePackError(f"runtime source does not exist or is not digest-pinned OCI: {raw}")


def default_runtime_home() -> pathlib.Path:
    return runtime_root()


def _private_directory(path: pathlib.Path) -> None:
    if path.is_symlink():
        raise RuntimePackError(f"runtime storage cannot be a symlink: {path}")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)


def store_pack(pack: RuntimePack, home: pathlib.Path | None = None) -> pathlib.Path:
    runtime_home = (home or default_runtime_home()).expanduser()
    objects = runtime_home / ".objects"
    _private_directory(objects)
    destination = objects / pack.digest
    if destination.exists():
        installed = verify_descriptor(destination)
        if installed.digest != pack.digest:
            raise RuntimePackError("installed runtime object digest mismatch")
        return destination
    staging = pathlib.Path(tempfile.mkdtemp(prefix=f".{pack.digest}.", dir=objects))
    staging.chmod(0o700)
    try:
        (staging / RUNTIME_DESCRIPTOR).write_bytes(canonical_bytes(pack.descriptor))
        for record in pack.descriptor["files"]:
            source = pack.root / record["path"]
            target = staging / record["path"]
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copy2(source, target)
            target.chmod(record["mode"])
        verify_descriptor(staging)
        try:
            staging.replace(destination)
        except FileExistsError:
            verify_descriptor(destination)
            shutil.rmtree(staging)
    except BaseException:
        if staging.exists():
            shutil.rmtree(staging)
        raise
    return destination


def selection_key(logical_model: str) -> str:
    if not isinstance(logical_model, str) or not SAFE_NAME_RE.fullmatch(logical_model):
        raise RuntimePackError("logical model selection key is invalid")
    return logical_model


def installation_identity(
    hardware_fingerprint_sha256: str,
    runtime_digest: str,
    installed_at_unix_ns: int,
) -> str:
    """Return the private, cryptographic identity of one runtime installation."""
    for value, label in (
        (hardware_fingerprint_sha256, "hardware fingerprint"),
        (runtime_digest, "runtime digest"),
    ):
        if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
            raise RuntimePackError(f"installation {label} must be a SHA-256")
    if (
        not isinstance(installed_at_unix_ns, int)
        or isinstance(installed_at_unix_ns, bool)
        or installed_at_unix_ns <= 0
    ):
        raise RuntimePackError("installation timestamp must be positive Unix nanoseconds")
    material = {
        "contract": "letsinfer-installation-v1",
        "hardware_fingerprint_sha256": hardware_fingerprint_sha256,
        "installed_at_unix_ns": installed_at_unix_ns,
        "runtime_digest": runtime_digest,
    }
    return hashlib.sha256(canonical_bytes(material)).hexdigest()


def _validate_selection(value: dict[str, Any], label: str) -> None:
    if (
        type(value.get("schema_version")) is not int
        or value.get("schema_version") != SELECTION_SCHEMA_VERSION
        or set(value) != SELECTION_FIELDS
    ):
        raise RuntimePackError(f"invalid runtime selection receipt: {label}")
    for key in (
        "digest",
        "hardware_fingerprint_sha256",
        "installation_id",
        "target_contract_sha256",
    ):
        if not isinstance(value.get(key), str) or not SHA256_RE.fullmatch(value[key]):
            raise RuntimePackError(f"invalid runtime selection {key}: {label}")
    timestamp = value.get("installed_at_unix_ns")
    if (
        not isinstance(timestamp, int)
        or isinstance(timestamp, bool)
        or timestamp <= 0
    ):
        raise RuntimePackError(f"invalid runtime selection timestamp: {label}")
    expected_installation = installation_identity(
        value["hardware_fingerprint_sha256"], value["digest"], timestamp
    )
    if value["installation_id"] != expected_installation:
        raise RuntimePackError(f"runtime selection installation identity mismatch: {label}")
    if not isinstance(value.get("target"), str) or not SAFE_NAME_RE.fullmatch(
        value["target"]
    ):
        raise RuntimePackError(f"invalid runtime selection target: {label}")
    for key in ("candidate_id", "logical_model", "engine"):
        if not isinstance(value.get(key), str) or not SAFE_NAME_RE.fullmatch(value[key]):
            raise RuntimePackError(f"invalid runtime selection {key}: {label}")
    authorization = value.get("authorization")
    if (
        not isinstance(authorization, dict)
        or set(authorization) != {"qualified", "authority"}
        or not isinstance(authorization.get("qualified"), bool)
        or authorization.get("authority") not in {"signed-catalog", "direct"}
        or (authorization["authority"] == "signed-catalog")
        != authorization["qualified"]
    ):
        raise RuntimePackError(f"invalid runtime selection authorization: {label}")


def selections(home: pathlib.Path | None = None) -> list[dict[str, Any]]:
    root = (
        home.expanduser() / "selections"
        if home is not None
        else data_root() / "active"
    )
    if not root.exists():
        return []
    if root.is_symlink() or not root.is_dir():
        raise RuntimePackError(f"runtime selections must be a regular directory: {root}")
    values: list[dict[str, Any]] = []
    for path in sorted(root.glob("*.json")):
        value = _read_object(path, "runtime selection")
        _validate_selection(value, str(path))
        expected_name = f"{selection_key(value['logical_model'])}.json"
        if path.name != expected_name:
            raise RuntimePackError(f"runtime selection filename mismatch: {path}")
        values.append(value)
    return values


def _publish_candidate_view(receipt: dict[str, Any], runtime_home: pathlib.Path) -> None:
    """Atomically expose the active runtime at runtimes/<candidate-id>."""

    source = pathlib.Path(receipt["object_root"]).expanduser().resolve(strict=True)
    installed = verify_descriptor(source)
    if installed.digest != receipt["digest"] or installed.runtime["id"] != receipt["candidate_id"]:
        raise RuntimePackError("candidate view source differs from its selection receipt")
    destination = runtime_home / receipt["candidate_id"]
    staging = pathlib.Path(
        tempfile.mkdtemp(prefix=f".{receipt['candidate_id']}.incoming-", dir=runtime_home)
    )
    staging.chmod(0o700)
    previous: pathlib.Path | None = None
    try:
        for path in sorted(source.rglob("*")):
            relative = path.relative_to(source)
            target = staging / relative
            if path.is_dir():
                target.mkdir(mode=0o700)
            elif path.is_file() and not path.is_symlink():
                try:
                    os.link(path, target)
                except OSError:
                    shutil.copy2(path, target)
            else:
                raise RuntimePackError(f"runtime candidate view contains unsafe entry: {relative}")
        verify_descriptor(staging)
        if destination.exists():
            if destination.is_symlink() or not destination.is_dir():
                raise RuntimePackError(f"runtime candidate path is unsafe: {destination}")
            previous = runtime_home / f".{receipt['candidate_id']}.previous-{os.getpid()}"
            destination.replace(previous)
        staging.replace(destination)
        if previous is not None:
            shutil.rmtree(previous)
    except BaseException:
        if staging.exists():
            shutil.rmtree(staging)
        if previous is not None and previous.exists() and not destination.exists():
            previous.replace(destination)
        raise


def _prune_runtime_objects(runtime_home: pathlib.Path) -> None:
    objects = runtime_home / ".objects"
    if not objects.is_dir() or objects.is_symlink():
        return
    retained: set[str] = set()
    for receipt in selections():
        retained.add(receipt["digest"])
        retained.update(
            item["digest"]
            for item in receipt["history"]
            if isinstance(item, dict) and isinstance(item.get("digest"), str)
        )
    for path in objects.iterdir():
        if path.is_dir() and not path.is_symlink() and SHA256_RE.fullmatch(path.name) and path.name not in retained:
            shutil.rmtree(path)


def write_selection(
    receipt: dict[str, Any], home: pathlib.Path | None = None
) -> pathlib.Path:
    runtime_home = (home or default_runtime_home()).expanduser()
    root = runtime_home / "selections" if home is not None else data_root() / "active"
    _private_directory(root)
    path = root / f"{selection_key(receipt['logical_model'])}.json"
    previous: dict[str, Any] | None = None
    if path.is_file():
        previous = _read_object(path, "runtime selection")
        _validate_selection(previous, str(path))
    supplied_history = receipt.get("history")
    if supplied_history:
        history = list(supplied_history)
    else:
        history = list(previous.get("history", [])) if previous else []
    if previous and previous.get("digest") != receipt.get("digest"):
        history.append(
            {
                key: previous[key]
                for key in (
                    "candidate_id",
                    "logical_model",
                    "engine",
                    "target",
                    "target_contract_sha256",
                    "version",
                    "digest",
                    "object_root",
                    "manifest_path",
                    "control_root",
                    "installed_at",
                    "installed_at_unix_ns",
                    "hardware_fingerprint_sha256",
                    "installation_id",
                    "policy",
                    "authorization",
                    "source",
                )
                if key in previous
            }
        )
    value = dict(receipt)
    value["schema_version"] = SELECTION_SCHEMA_VERSION
    value["history"] = history[-1:]
    _validate_selection(value, "new receipt")
    return _commit_selection(value, path, runtime_home, prune=home is None)


def _commit_selection(
    value: dict[str, Any],
    path: pathlib.Path,
    runtime_home: pathlib.Path,
    *,
    prune: bool,
) -> pathlib.Path:
    """Commit one already-validated receipt and its immutable candidate view."""

    _validate_selection(value, "committed receipt")
    data = canonical_bytes(value)
    with tempfile.NamedTemporaryFile(
        prefix=f".{path.name}.", dir=path.parent, delete=False
    ) as handle:
        temporary = pathlib.Path(handle.name)
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    temporary.chmod(0o600)
    temporary.replace(path)
    _private_directory(runtime_home)
    _publish_candidate_view(value, runtime_home)
    if prune:
        _prune_runtime_objects(runtime_home)
    return path


def restore_selection(
    replacement: dict[str, Any],
    previous: dict[str, Any] | None,
    home: pathlib.Path | None = None,
) -> None:
    """Restore the exact prior receipt after a failed service activation."""

    _validate_selection(replacement, "replacement receipt")
    if previous is not None:
        _validate_selection(previous, "previous receipt")
        if previous["logical_model"] != replacement["logical_model"]:
            raise RuntimePackError("runtime selection rollback model mismatch")
    runtime_home = (home or default_runtime_home()).expanduser()
    root = runtime_home / "selections" if home is not None else data_root() / "active"
    path = root / f"{selection_key(replacement['logical_model'])}.json"
    if not path.is_file() or path.is_symlink():
        if previous is None and not path.exists():
            return
        raise RuntimePackError("runtime selection rollback receipt is unavailable")
    current = _read_object(path, "runtime selection")
    _validate_selection(current, str(path))
    if previous is not None and current["digest"] == previous["digest"]:
        return
    if current["digest"] != replacement["digest"]:
        raise RuntimePackError("runtime selection changed during activation rollback")
    if previous is not None:
        _commit_selection(previous, path, runtime_home, prune=home is None)
        return

    candidate = runtime_home / replacement["candidate_id"]
    if candidate.exists():
        if candidate.is_symlink() or not candidate.is_dir():
            raise RuntimePackError("runtime candidate rollback path is unsafe")
        installed = verify_descriptor(candidate)
        if installed.digest != replacement["digest"]:
            raise RuntimePackError("runtime candidate changed during activation rollback")
    path.unlink()
    if candidate.exists():
        shutil.rmtree(candidate)
    if home is None:
        _prune_runtime_objects(runtime_home)


def new_receipt(
    pack: RuntimePack,
    *,
    object_root: pathlib.Path,
    manifest_path: pathlib.Path,
    control_root: pathlib.Path,
    source: str,
    policy: str,
    qualified: bool,
    hardware_fingerprint_sha256: str,
    target_contract_sha256: str,
    installed_at_unix_ns: int,
) -> dict[str, Any]:
    if not SHA256_RE.fullmatch(target_contract_sha256):
        raise RuntimePackError("target contract identity must be a SHA-256")
    installation_id = installation_identity(
        hardware_fingerprint_sha256, pack.digest, installed_at_unix_ns
    )
    return {
        "schema_version": SELECTION_SCHEMA_VERSION,
        "candidate_id": pack.runtime["id"],
        "logical_model": pack.runtime["logical_model"],
        "engine": pack.runtime["engine"]["id"],
        "target": pack.runtime["target"]["id"],
        "target_contract_sha256": target_contract_sha256,
        "version": pack.runtime["version"],
        "digest": pack.digest,
        "object_root": str(object_root),
        "manifest_path": str(manifest_path),
        "control_root": str(control_root),
        "installed_at": dt.datetime.fromtimestamp(
            installed_at_unix_ns / 1_000_000_000,
            tz=dt.timezone.utc,
        ).isoformat(),
        "installed_at_unix_ns": installed_at_unix_ns,
        "hardware_fingerprint_sha256": hardware_fingerprint_sha256,
        "installation_id": installation_id,
        "policy": policy,
        "authorization": {
            "qualified": qualified,
            "authority": "signed-catalog" if qualified else "direct",
        },
        "source": source,
        "history": [],
    }


def _catalog_public_key(explicit: str | None) -> pathlib.Path | None:
    configured = explicit or os.environ.get("LETSINFER_CATALOG_PUBLIC_KEY")
    if configured:
        return pathlib.Path(configured).expanduser()
    default = config_root() / "catalog-public-key.pem"
    return default if default.is_file() else BUILTIN_CATALOG_PUBLIC_KEY


def _remote_bytes(location: str, *, limit: int, label: str) -> bytes:
    if not location.startswith("https://"):
        raise RuntimePackError(f"remote {label} must use HTTPS")
    try:
        with urllib.request.urlopen(location, timeout=15) as response:
            if not response.geturl().startswith("https://"):
                raise RuntimePackError(f"{label} redirected away from HTTPS")
            data = response.read(limit + 1)
    except OSError as error:
        raise RuntimePackError(f"cannot read {label} {location}: {error}") from error
    if len(data) > limit:
        raise RuntimePackError(f"{label} exceeds {limit} bytes")
    return data


def _verify_catalog_signature(
    data: bytes,
    signature_data: bytes,
    public_key: pathlib.Path,
) -> None:
    if public_key.is_symlink() or not public_key.is_file():
        raise RuntimePackError("runtime catalog public key must be a regular file")
    try:
        signature_document = json.loads(signature_data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimePackError("runtime catalog signature is invalid JSON") from error
    required = {
        "schema_version",
        "algorithm",
        "key_id_sha256",
        "catalog_sha256",
        "signature_base64",
    }
    if (
        not isinstance(signature_document, dict)
        or set(signature_document) != required
        or type(signature_document.get("schema_version")) is not int
        or signature_document.get("schema_version") != 1
        or signature_document.get("algorithm") != "ed25519"
    ):
        raise RuntimePackError("runtime catalog signature schema is unsupported")
    catalog_sha256 = hashlib.sha256(data).hexdigest()
    if signature_document.get("catalog_sha256") != catalog_sha256:
        raise RuntimePackError("runtime catalog signature content identity differs")
    try:
        public_der = subprocess.run(
            [
                "openssl",
                "pkey",
                "-pubin",
                "-in",
                str(public_key),
                "-outform",
                "DER",
            ],
            check=True,
            capture_output=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        raise RuntimePackError("runtime catalog public key is invalid") from error
    key_id = hashlib.sha256(public_der).hexdigest()
    if signature_document.get("key_id_sha256") != key_id:
        raise RuntimePackError("runtime catalog signature uses an untrusted key")
    try:
        signature = base64.b64decode(
            signature_document.get("signature_base64", ""), validate=True
        )
    except (ValueError, TypeError) as error:
        raise RuntimePackError("runtime catalog signature encoding is invalid") from error
    if len(signature) != 64:
        raise RuntimePackError("runtime catalog signature length is invalid")
    with tempfile.TemporaryDirectory(prefix="letsinfer-catalog-verify-") as directory:
        root = pathlib.Path(directory)
        catalog_path = root / "catalog.json"
        signature_path = root / "catalog.sig"
        catalog_path.write_bytes(data)
        signature_path.write_bytes(signature)
        try:
            subprocess.run(
                [
                    "openssl",
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-inkey",
                    str(public_key),
                    "-rawin",
                    "-in",
                    str(catalog_path),
                    "-sigfile",
                    str(signature_path),
                ],
                check=True,
                capture_output=True,
            )
        except (OSError, subprocess.CalledProcessError) as error:
            raise RuntimePackError("runtime catalog signature verification failed") from error


def load_catalog(
    location: str, *, public_key: str | None = None
) -> dict[str, Any]:
    remote = location.startswith(("https://", "http://"))
    if remote:
        data = _remote_bytes(
            location, limit=MAX_CATALOG_BYTES, label="runtime catalog"
        )
        signature_data = _remote_bytes(
            location + ".sig",
            limit=MAX_CATALOG_SIGNATURE_BYTES,
            label="runtime catalog signature",
        )
        key_path = _catalog_public_key(public_key)
        if key_path is None:
            raise RuntimePackError(
                "remote runtime catalog requires an installed public trust key"
            )
        _verify_catalog_signature(data, signature_data, key_path)
    else:
        catalog_path = pathlib.Path(location).expanduser()
        try:
            data = catalog_path.read_bytes()
        except OSError as error:
            raise RuntimePackError(
                f"cannot read runtime catalog {catalog_path}: {error}"
            ) from error
        if len(data) > MAX_CATALOG_BYTES:
            raise RuntimePackError("runtime catalog exceeds 4 MiB")
        signature_path = catalog_path.with_name(catalog_path.name + ".sig")
        if signature_path.exists():
            key_path = _catalog_public_key(public_key)
            if key_path is None:
                raise RuntimePackError(
                    "signed runtime catalog requires an installed public trust key"
                )
            try:
                signature_data = signature_path.read_bytes()
            except OSError as error:
                raise RuntimePackError(
                    f"cannot read runtime catalog signature {signature_path}: {error}"
                ) from error
            if len(signature_data) > MAX_CATALOG_SIGNATURE_BYTES:
                raise RuntimePackError("runtime catalog signature exceeds 16384 bytes")
            _verify_catalog_signature(data, signature_data, key_path)
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimePackError(f"runtime catalog is invalid JSON: {error}") from error
    if (
        not isinstance(value, dict)
        or type(value.get("schema_version")) is not int
        or value.get("schema_version") != CATALOG_SCHEMA_VERSION
        or set(value)
        != {"schema_version", "recommendation_policy", "targets", "models"}
    ):
        raise RuntimePackError("unsupported runtime catalog schema_version")
    policy = value.get("recommendation_policy")
    if (
        not isinstance(policy, dict)
        or set(policy)
        != {
            "id",
            "benchmark_suite",
            "metric",
            "cache",
            "tie_breakers",
        }
        or policy.get("id") != "letsinfer-throughput-geomean-v1"
        or policy.get("benchmark_suite") != BENCHMARK_SUITE
        or policy.get("metric") != "aggregate_tps"
        or policy.get("cache") != "uncached"
        or policy.get("tie_breakers") != ["score", "version", "candidate"]
    ):
        raise RuntimePackError("runtime catalog recommendation policy is unsupported")
    targets = value.get("targets")
    if not isinstance(targets, dict) or not targets:
        raise RuntimePackError("runtime catalog targets must be a non-empty object")
    for target_id, target_record in targets.items():
        if not isinstance(target_id, str) or not SAFE_NAME_RE.fullmatch(target_id):
            raise RuntimePackError("runtime catalog target identifier is invalid")
        if not isinstance(target_record, dict) or set(target_record) != {"match"}:
            raise RuntimePackError(
                f"catalog target {target_id} must contain exactly match"
            )
        contract = validate_target_contract(
            target_record["match"], f"catalog target {target_id}.match"
        )
        if contract["id"] != target_id:
            raise RuntimePackError(
                f"catalog target key {target_id} differs from match.id"
            )
    models = value.get("models")
    if not isinstance(models, dict):
        raise RuntimePackError("runtime catalog models must be an object")
    for model, record in models.items():
        if (
            not isinstance(model, str)
            or not SAFE_NAME_RE.fullmatch(model)
            or not isinstance(record, dict)
            or set(record) != {"targets"}
        ):
            raise RuntimePackError("runtime catalog model entries must be objects")
        model_targets = record.get("targets")
        if not isinstance(model_targets, dict) or not model_targets:
            raise RuntimePackError(f"catalog model {model} has no target variants")
        for target_id, target_record in model_targets.items():
            if not isinstance(target_id, str) or not SAFE_NAME_RE.fullmatch(target_id):
                raise RuntimePackError(f"catalog target for {model} is invalid")
            if target_id not in targets:
                raise RuntimePackError(
                    f"catalog model {model} references unknown target {target_id}"
                )
            if (
                not isinstance(target_record, dict)
                or set(target_record) != {"recommended", "candidates"}
            ):
                raise RuntimePackError(f"catalog target {model}/{target_id} is invalid")
            recommended = target_record.get("recommended")
            candidates = target_record.get("candidates")
            if (
                (
                    recommended is not None
                    and (
                        not isinstance(recommended, dict)
                        or set(recommended) != {"candidate", "version"}
                        or not isinstance(recommended.get("candidate"), str)
                        or not SAFE_NAME_RE.fullmatch(recommended["candidate"])
                        or not isinstance(recommended.get("version"), str)
                        or not VERSION_RE.fullmatch(recommended["version"])
                    )
                )
                or not isinstance(candidates, dict)
                or not candidates
            ):
                raise RuntimePackError(
                    f"catalog target {model}/{target_id} is missing recommendation data"
                )
            if recommended is not None and recommended["candidate"] not in candidates:
                raise RuntimePackError(
                    f"catalog recommendation for {model}/{target_id} is not a runtime candidate"
                )
            for candidate, candidate_record in candidates.items():
                if (
                    not isinstance(candidate, str)
                    or not SAFE_NAME_RE.fullmatch(candidate)
                    or not isinstance(candidate_record, dict)
                    or set(candidate_record) != {"latest", "releases"}
                ):
                    raise RuntimePackError(
                        f"catalog candidate entry for {model}/{candidate}/{target_id} is invalid"
                    )
                latest = candidate_record.get("latest")
                releases = candidate_record.get("releases")
                if (
                    not isinstance(latest, str)
                    or not VERSION_RE.fullmatch(latest)
                    or not isinstance(releases, dict)
                    or not releases
                    or latest not in releases
                ):
                    raise RuntimePackError(
                        f"catalog releases for {model}/{candidate}/{target_id} are invalid"
                    )
                for version, release in releases.items():
                    where = f"{model}/{candidate}@{version}/{target_id}"
                    if (
                        not isinstance(version, str)
                        or not VERSION_RE.fullmatch(version)
                        or not isinstance(release, dict)
                        or set(release)
                        != {
                            "authors",
                            "license",
                            "source",
                            "engine",
                            "engine_oci",
                            "model_uri",
                            "benchmark",
                            "provenance",
                            "verification",
                        }
                    ):
                        raise RuntimePackError(f"catalog release entry for {where} is invalid")
                    authors = release.get("authors")
                    if (
                        not isinstance(authors, list)
                        or not authors
                        or len(authors) > 32
                    ):
                        raise RuntimePackError(f"catalog authors for {where} are invalid")
                    author_ids = [
                        _catalog_github_identity(
                            author, f"{where}.authors[{index}]", allow_organization=True
                        )
                        for index, author in enumerate(authors)
                    ]
                    if len(author_ids) != len(set(author_ids)):
                        raise RuntimePackError(f"catalog authors for {where} are duplicated")
                    if not LICENSE_RE.fullmatch(str(release.get("license"))):
                        raise RuntimePackError(f"catalog license for {where} is invalid")
                    if not REGISTRY_DIGEST_RE.fullmatch(release.get("source", "")):
                        raise RuntimePackError(
                            f"catalog source for {where} must be digest-pinned OCI"
                        )
                    engine = release.get("engine")
                    if not isinstance(engine, str) or not SAFE_NAME_RE.fullmatch(engine):
                        raise RuntimePackError(f"catalog engine for {where} is invalid")
                    if not REGISTRY_DIGEST_RE.fullmatch(release.get("engine_oci", "")):
                        raise RuntimePackError(
                            f"catalog Engine OCI for {where} must be digest-pinned"
                        )
                    normalize_hf_uri(
                        release.get("model_uri"), f"catalog model URI for {where}"
                    )
                    expected_candidate = candidate_id(
                        engine, release["model_uri"], target_id
                    )
                    if candidate != expected_candidate:
                        raise RuntimePackError(
                            f"catalog candidate key {candidate} differs from its exact identities"
                        )
                    benchmark = release.get("benchmark")
                    if benchmark is None:
                        raise RuntimePackError(
                            f"qualified catalog release {where} has no benchmark"
                        )
                    if not isinstance(benchmark, dict) or set(benchmark) != {
                        "id",
                        "suite",
                        "score",
                    }:
                        raise RuntimePackError(f"catalog benchmark for {where} is invalid")
                    if not isinstance(benchmark.get("id"), str) or not SHA256_RE.fullmatch(
                        benchmark["id"]
                    ):
                        raise RuntimePackError("catalog benchmark id must be a SHA-256")
                    if benchmark.get("suite") != policy["benchmark_suite"]:
                        raise RuntimePackError("catalog benchmark suite is unsupported")
                    score = benchmark.get("score")
                    if (
                        not isinstance(score, (int, float))
                        or isinstance(score, bool)
                        or not math.isfinite(score)
                        or score <= 0
                    ):
                        raise RuntimePackError(
                            "catalog benchmark score must be positive and finite"
                        )
                    provenance = release.get("provenance")
                    verification = release.get("verification")
                    if not isinstance(provenance, dict) or not isinstance(
                        verification, dict
                    ):
                        raise RuntimePackError(
                            f"catalog qualification metadata for {where} is invalid"
                        )
                    method = verification.get("method")
                    if method == "maintainer-qualified-pre-community-v1":
                        if (
                            set(verification) != {"method", "verifiers"}
                            or verification.get("verifiers") != []
                            or set(provenance)
                            != {
                                "method",
                                "repository",
                                "pull_request",
                                "pull_request_url",
                                "proposal_head_sha",
                                "qualified_commit_sha",
                            }
                            or provenance.get("method") != method
                        ):
                            raise RuntimePackError(
                                f"catalog migrated qualification for {where} is invalid"
                            )
                    elif method == "community-consensus-v1":
                        if (
                            set(verification)
                            != {
                                "method",
                                "consensus_path",
                                "consensus_sha256",
                                "verifiers",
                            }
                            or set(provenance)
                            != {
                                "repository",
                                "pull_request",
                                "pull_request_url",
                                "proposal_head_sha",
                                "execution_sha256",
                                "qualified_commit_sha",
                                "consensus_sha256",
                            }
                            or verification.get("consensus_sha256")
                            != provenance.get("consensus_sha256")
                            or not SHA256_RE.fullmatch(
                                str(verification.get("consensus_sha256"))
                            )
                            or verification.get("consensus_path")
                            != f"{candidate}/benchmark.consensus.json"
                            or not SHA256_RE.fullmatch(
                                str(provenance.get("execution_sha256"))
                            )
                            or not isinstance(verification.get("verifiers"), list)
                            or len(verification["verifiers"]) < 3
                        ):
                            raise RuntimePackError(
                                f"catalog community qualification for {where} is invalid"
                            )
                    elif method == "runtime-contract-migration-v1":
                        verification_fields = {
                            "method",
                            "from_version",
                            "from_source",
                            "benchmark_record_path",
                            "benchmark_record_sha256",
                            "execution_contract_sha256",
                            "verifiers",
                        }
                        provenance_fields = {
                            "method",
                            "repository",
                            "pull_request",
                            "pull_request_url",
                            "proposal_head_sha",
                            "qualified_commit_sha",
                            "from_version",
                            "from_source",
                            "benchmark_record_sha256",
                            "execution_contract_sha256",
                        }
                        from_version = verification.get("from_version")
                        if (
                            set(verification) != verification_fields
                            or set(provenance) != provenance_fields
                            or provenance.get("method") != method
                            or not isinstance(from_version, str)
                            or not VERSION_RE.fullmatch(from_version)
                            or _semantic_version_key(from_version)
                            >= _semantic_version_key(version)
                            or verification.get("from_source")
                            != provenance.get("from_source")
                            or not REGISTRY_DIGEST_RE.fullmatch(
                                str(verification.get("from_source"))
                            )
                            or verification.get("from_source") == release["source"]
                            or verification.get("benchmark_record_path")
                            != f"{candidate}/benchmark.previous.json"
                            or verification.get("benchmark_record_sha256")
                            != provenance.get("benchmark_record_sha256")
                            or not SHA256_RE.fullmatch(
                                str(verification.get("benchmark_record_sha256"))
                            )
                            or verification.get("execution_contract_sha256")
                            != provenance.get("execution_contract_sha256")
                            or not SHA256_RE.fullmatch(
                                str(verification.get("execution_contract_sha256"))
                            )
                            or not isinstance(verification.get("verifiers"), list)
                        ):
                            raise RuntimePackError(
                                f"catalog runtime contract migration for {where} is invalid"
                            )
                    else:
                        raise RuntimePackError(
                            f"catalog qualification method for {where} is invalid"
                        )
                    if (
                        provenance.get("repository") != "letsinferlabs/runtimes"
                        or not isinstance(provenance.get("pull_request"), int)
                        or isinstance(provenance.get("pull_request"), bool)
                        or provenance["pull_request"] <= 0
                        or provenance.get("pull_request_url")
                        != "https://github.com/letsinferlabs/runtimes/pull/"
                        + str(provenance["pull_request"])
                        or not re.fullmatch(
                            r"[0-9a-f]{40}", str(provenance.get("proposal_head_sha"))
                        )
                        or not re.fullmatch(
                            r"[0-9a-f]{40}", str(provenance.get("qualified_commit_sha"))
                        )
                    ):
                        raise RuntimePackError(
                            f"catalog provenance for {where} is invalid"
                        )
                    verifiers = verification.get("verifiers")
                    if not isinstance(verifiers, list) or len(verifiers) > 64:
                        raise RuntimePackError(
                            f"catalog verifiers for {where} are invalid"
                        )
                    verifier_ids = [
                        _catalog_github_identity(
                            verifier,
                            f"{where}.verifiers[{index}]",
                            allow_organization=False,
                        )
                        for index, verifier in enumerate(verifiers)
                    ]
                    if len(verifier_ids) != len(set(verifier_ids)):
                        raise RuntimePackError(
                            f"catalog verifiers for {where} are duplicated"
                        )
            if recommended is not None:
                recommended_candidate = candidates[recommended["candidate"]]
                recommended_release = recommended_candidate["releases"].get(
                    recommended["version"]
                )
                if not isinstance(recommended_release, dict):
                    raise RuntimePackError(
                        f"catalog recommendation for {model}/{target_id} is not qualified"
                    )
    return value


def catalog_target_contract(catalog: dict[str, Any], target: str) -> dict[str, Any]:
    """Return one canonical target contract from a validated catalog."""
    record = catalog["targets"].get(target)
    if not isinstance(record, dict):
        raise RuntimePackError(f"runtime catalog has no target definition: {target}")
    return record["match"]


def compatible_catalog_targets(
    catalog: dict[str, Any], device: dict[str, Any]
) -> list[str]:
    """Return all globally declared targets compatible with one host probe."""
    return sorted(
        target_id
        for target_id, record in catalog["targets"].items()
        if target_matches(record["match"], device)
    )


def catalog_release(
    catalog: dict[str, Any],
    model: str,
    runtime: str | None,
    target: str | None = None,
    device: dict[str, Any] | None = None,
) -> tuple[str, str, str, str, str]:
    record = catalog["models"].get(model)
    if not isinstance(record, dict):
        raise RuntimePackError(f"model is not present in runtime catalog: {model}")
    targets = record["targets"]
    if target is not None:
        target_record = targets.get(target)
        if not isinstance(target_record, dict):
            raise RuntimePackError(f"runtime catalog has no {target} target for {model}")
        selected_target = target
        contract = catalog_target_contract(catalog, target)
        if device is not None:
            if not target_matches(contract, device):
                raise RuntimePackError(
                    f"host does not satisfy runtime target {model}/{target}"
                )
    else:
        if device is None:
            raise RuntimePackError("automatic runtime target selection requires a device probe")
        matches = [
            (target_id, candidate)
            for target_id, candidate in targets.items()
            if target_matches(catalog_target_contract(catalog, target_id), device)
        ]
        if not matches:
            raise RuntimePackError(f"runtime catalog has no compatible target for {model}")
        if len(matches) > 1:
            choices = ", ".join(sorted(item[0] for item in matches))
            raise RuntimePackError(
                "runtime catalog target contracts are ambiguous for this host "
                f"({choices})"
            )
        selected_target, target_record = matches[0]
        contract = catalog_target_contract(catalog, selected_target)
    recommendation = target_record["recommended"]
    if runtime is None and recommendation is None:
        raise RuntimePackError(
            f"runtime catalog has no qualified candidate for {model}/{selected_target}"
        )
    selected_runtime = runtime or recommendation["candidate"]
    candidate = target_record["candidates"].get(selected_runtime)
    if not isinstance(candidate, dict):
        raise RuntimePackError(
            f"runtime catalog has no {selected_runtime} candidate for {model}/{selected_target}"
        )
    selected_version = (
        candidate["latest"] if runtime is not None else recommendation["version"]
    )
    release = candidate["releases"].get(selected_version)
    if not isinstance(release, dict):
        raise RuntimePackError(
            f"runtime catalog release is unavailable: {selected_runtime}@{selected_version}"
        )
    return (
        selected_target,
        target_contract_sha256(contract),
        selected_runtime,
        selected_version,
        release["source"],
    )


def catalog_release_record(
    catalog: dict[str, Any], model: str, target: str, candidate: str, version: str
) -> dict[str, Any]:
    """Return one exact validated catalog release record."""

    try:
        return catalog["models"][model]["targets"][target]["candidates"][candidate][
            "releases"
        ][version]
    except (KeyError, TypeError) as error:
        raise RuntimePackError(
            f"runtime catalog release is unavailable: {model}/{candidate}@{version}/{target}"
        ) from error


def resolved_catalog_location(explicit: str | None = None) -> str | None:
    if explicit:
        return explicit
    configured = os.environ.get("LETSINFER_CATALOG")
    if configured:
        return configured
    default = config_root() / "catalog.json"
    return str(default) if default.is_file() else DEFAULT_CATALOG_URL
