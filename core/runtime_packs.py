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
import urllib.request
from collections.abc import Iterator, Sequence
from typing import Any

from core.orchestration import OrchestrationError, validate_orchestration_contract


RUNTIME_CONFIG = "runtime.json"
RUNTIME_DESCRIPTOR = "letsinfer-runtime.json"
RUNTIME_SCHEMA_VERSION = 2
ARTIFACT_SCHEMA_VERSION = 2
CATALOG_SCHEMA_VERSION = 3
DEFAULT_CATALOG_URL = (
    "https://raw.githubusercontent.com/letsinferlabs/catalog/main/catalog.json"
)
BUILTIN_CATALOG_PUBLIC_KEY = (
    pathlib.Path(__file__).resolve().parent / "trust" / "catalog-public-key.pem"
)
PACK_MEDIA_TYPE = "application/vnd.letsinfer.runtime.v2+tar"
REGISTRY_DIGEST_RE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
MAX_PACK_BYTES = 1 << 30
MAX_PACK_FILES = 10_000
MAX_CATALOG_BYTES = 4 << 20
MAX_CATALOG_SIGNATURE_BYTES = 16 << 10
SAFE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
BENCHMARK_SCHEMA_VERSION = 1
BENCHMARK_SUITE = "letsinfer-standard-context-v1"
BENCHMARK_GENERATOR = "letsinfer-synthetic-document"
BENCHMARK_GENERATOR_VERSION = 1
BENCHMARK_TOKENIZER_CAPABILITY = "engine-rendered-chat-count-v1"
BENCHMARK_RENDER_CONTRACT = "openai-chat-user-v1"
SELECTION_SCHEMA_VERSION = 1
SELECTION_FIELDS = {
    "schema_version",
    "name",
    "model",
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
    "source",
    "history",
}


class RuntimePackError(ValueError):
    """A runtime source, artifact, catalog, or receipt is invalid."""


@dataclasses.dataclass(frozen=True)
class RuntimePack:
    root: pathlib.Path
    descriptor: dict[str, Any]
    digest: str

    @property
    def release_path(self) -> pathlib.Path:
        return self.root / self.descriptor["release_manifest"]


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


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
        "member_count",
        "engine_strategy",
        "interconnect",
    }:
        raise RuntimePackError(
            f"{where}.placement must contain exactly strategy, member_count, "
            "engine_strategy, and interconnect"
        )
    strategy = placement.get("strategy")
    if strategy not in {"single", "replicated", "distributed"}:
        raise RuntimePackError(f"{where}.placement.strategy is invalid")
    member_count = placement.get("member_count")
    if (
        not isinstance(member_count, int)
        or isinstance(member_count, bool)
        or member_count <= 0
        or member_count > 64
    ):
        raise RuntimePackError(f"{where}.placement.member_count must be between 1 and 64")
    if strategy == "single" and member_count != 1:
        raise RuntimePackError(f"{where}.placement single strategy requires one member")
    if strategy in {"replicated", "distributed"} and member_count < 2:
        raise RuntimePackError(f"{where}.placement {strategy} strategy requires multiple members")
    engine_strategy = placement.get("engine_strategy")
    if not isinstance(engine_strategy, str) or not SAFE_NAME_RE.fullmatch(engine_strategy):
        raise RuntimePackError(f"{where}.placement.engine_strategy is invalid")
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
    if strategy != "distributed" and (
        interconnect["rdma_required"]
        or interconnect["minimum_speed_mbps"]
        or interconnect["minimum_mtu"]
        or interconnect["kind"] != "any"
    ):
        raise RuntimePackError(
            f"{where}.placement interconnect constraints require distributed strategy"
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
        for key in ("vendor", "architecture", "count", "partitioning"):
            if expected_accelerator[key] != actual_accelerator[key]:
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
    file_sha = model.get("sha256")
    if isinstance(file_sha, str) and SHA256_RE.fullmatch(file_sha):
        return file_sha
    repository = model.get("repository") or model.get("id")
    revision = model.get("revision")
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
            "workload",
            "prompt_tokens",
            "concurrencies",
            "seed",
        }:
            raise RuntimePackError(
                f"{case_where} must contain exactly id, workload, prompt_tokens, "
                "concurrencies, and seed"
            )
        case_id = case.get("id")
        if not isinstance(case_id, str) or not SAFE_NAME_RE.fullmatch(case_id):
            raise RuntimePackError(f"{case_where}.id must be a lowercase safe name")
        if case_id in seen:
            raise RuntimePackError(f"duplicate runtime benchmark case: {case_id}")
        seen.add(case_id)
        if case.get("workload") != "context-summary-v1":
            raise RuntimePackError(f"{case_where}.workload is unsupported")
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
        case_seed = case.get("seed")
        if not isinstance(case_seed, int) or isinstance(case_seed, bool) or case_seed < 0:
            raise RuntimePackError(f"{case_where}.seed must be non-negative")
    return value


def _metadata(value: dict[str, Any], *, descriptor: bool) -> dict[str, Any]:
    schema_version = value.get("schema_version")
    if type(schema_version) is not int or schema_version != RUNTIME_SCHEMA_VERSION:
        raise RuntimePackError("unsupported runtime schema_version")
    fields = {
        "schema_version",
        "name",
        "version",
        "model",
        "engine",
        "target",
        "status",
        "release_manifest",
        "core_compatibility",
        "benchmark",
        "orchestration",
        "parent",
    }
    if descriptor:
        fields.update({"artifact_schema_version", "media_type", "files"})
    unknown = set(value) - fields
    if unknown:
        kind = "descriptor" if descriptor else "source"
        raise RuntimePackError(
            f"runtime {kind} has unsupported fields: {', '.join(sorted(unknown))}"
        )
    for key in ("name", "version", "model", "engine", "status", "release_manifest"):
        if not isinstance(value.get(key), str) or not value[key]:
            raise RuntimePackError(f"runtime.{key} must be a non-empty string")
    for key in ("model", "engine"):
        if not SAFE_NAME_RE.fullmatch(value[key]):
            raise RuntimePackError(f"runtime.{key} must be a lowercase safe name")
    target = value.get("target")
    if not isinstance(target, str) or not SAFE_NAME_RE.fullmatch(target):
        raise RuntimePackError("runtime.target must be a lowercase safe name")
    expected_name = f"{value['model']}/{value['engine']}/{target}"
    if value["name"] != expected_name:
        raise RuntimePackError("runtime.name must equal model/engine/target")
    if not VERSION_RE.fullmatch(value["version"]):
        raise RuntimePackError("runtime.version must be semantic version syntax")
    if value["status"] not in {"candidate", "stable"}:
        raise RuntimePackError("runtime.status must be candidate or stable")
    _relative_path(value["release_manifest"], "runtime.release_manifest")
    compatibility = value.get("core_compatibility")
    if not isinstance(compatibility, dict):
        raise RuntimePackError("runtime.core_compatibility must be an object")
    if (
        set(compatibility) != {"api"}
        or type(compatibility.get("api")) is not int
        or compatibility.get("api") != 1
    ):
        raise RuntimePackError("runtime.core_compatibility.api must be 1")
    if "benchmark" in value:
        validate_benchmark_contract(value["benchmark"])
    if "orchestration" in value:
        try:
            validate_orchestration_contract(value["orchestration"])
        except OrchestrationError as error:
            raise RuntimePackError(str(error)) from error
    if "parent" in value:
        parent = value["parent"]
        if not isinstance(parent, dict) or set(parent) != {
            "release",
            "manifest_sha256",
        }:
            raise RuntimePackError(
                "runtime.parent must contain exactly release and manifest_sha256"
            )
        if not isinstance(parent.get("release"), str) or not parent["release"]:
            raise RuntimePackError("runtime.parent.release must be non-empty")
        if not isinstance(parent.get("manifest_sha256"), str) or not SHA256_RE.fullmatch(
            parent["manifest_sha256"]
        ):
            raise RuntimePackError("runtime.parent.manifest_sha256 must be a SHA-256")
    if descriptor:
        files = value.get("files")
        if not isinstance(files, list) or not files:
            raise RuntimePackError("runtime.files must be a non-empty list")
        artifact_schema = value.get("artifact_schema_version")
        if type(artifact_schema) is not int or artifact_schema != ARTIFACT_SCHEMA_VERSION:
            raise RuntimePackError("unsupported runtime artifact_schema_version")
        if value.get("media_type") != PACK_MEDIA_TYPE:
            raise RuntimePackError(
                f"runtime.media_type must be {PACK_MEDIA_TYPE}"
            )
    elif any(
        key in value for key in ("artifact_schema_version", "media_type", "files")
    ):
        raise RuntimePackError(
            "source runtime.json cannot contain built artifact fields"
        )
    return value


def _ignored_source_path(relative: pathlib.PurePath) -> bool:
    return (
        ".git" in relative.parts
        or "__pycache__" in relative.parts
        or relative.name == RUNTIME_DESCRIPTOR
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
    config = _metadata(_read_object(root / RUNTIME_CONFIG, "runtime config"), descriptor=False)
    files = _source_files(root)
    relative_names = {path.relative_to(root).as_posix() for path in files}
    if RUNTIME_CONFIG not in relative_names:
        raise RuntimePackError(f"runtime source is missing {RUNTIME_CONFIG}")
    if config["release_manifest"] not in relative_names:
        raise RuntimePackError(
            f"runtime source is missing release manifest {config['release_manifest']}"
        )
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
    descriptor = dict(config)
    descriptor["artifact_schema_version"] = ARTIFACT_SCHEMA_VERSION
    descriptor["media_type"] = PACK_MEDIA_TYPE
    descriptor["files"] = records
    digest = hashlib.sha256(canonical_bytes(descriptor)).hexdigest()
    return RuntimePack(root=root, descriptor=descriptor, digest=digest)


def verify_descriptor(root: pathlib.Path) -> RuntimePack:
    root = root.expanduser().resolve(strict=True)
    descriptor_path = root / RUNTIME_DESCRIPTOR
    descriptor = _metadata(
        _read_object(descriptor_path, "runtime descriptor"), descriptor=True
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
    if descriptor["release_manifest"] not in expected_files:
        raise RuntimePackError("runtime release manifest is not pinned in runtime.files")
    digest = hashlib.sha256(canonical_bytes(descriptor)).hexdigest()
    return RuntimePack(root=root, descriptor=descriptor, digest=digest)


def build_archive(source: pathlib.Path, output: pathlib.Path) -> RuntimePack:
    source = source.expanduser().resolve(strict=True)
    if (source / "benchmark.md").exists():
        raise RuntimePackError("runtime benchmark results must use benchmark.json")
    benchmark_path = source / "benchmark.json"
    if benchmark_path.exists():
        validator = pathlib.Path(__file__).resolve().parents[1] / "benchmarks/benchmark_record.py"
        result = subprocess.run(
            [sys.executable, str(validator), str(benchmark_path)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip() or "unknown validation error"
            raise RuntimePackError(f"invalid runtime benchmark.json: {detail}")
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


def _pull_oci(reference: str, destination: pathlib.Path) -> None:
    if not REGISTRY_DIGEST_RE.fullmatch(reference):
        raise RuntimePackError("OCI runtime references must be pinned by sha256 digest")
    executable = _companion_executable("oras")
    if executable is None:
        raise RuntimePackError("OCI runtime installation requires the oras CLI")
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
    override = os.environ.get("LETSINFER_RUNTIME_HOME")
    if override:
        return pathlib.Path(override).expanduser()
    data_override = os.environ.get("LETSINFER_DATA_HOME")
    root = pathlib.Path(data_override).expanduser() if data_override else pathlib.Path.home() / ".local/share/letsinfer"
    return root / "runtimes"


def _private_directory(path: pathlib.Path) -> None:
    if path.is_symlink():
        raise RuntimePackError(f"runtime storage cannot be a symlink: {path}")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)


def store_pack(pack: RuntimePack, home: pathlib.Path | None = None) -> pathlib.Path:
    runtime_home = (home or default_runtime_home()).expanduser()
    objects = runtime_home / "objects"
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


def selection_key(name: str, engine: str) -> str:
    return hashlib.sha256(f"{name}\0{engine}".encode()).hexdigest()


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


def selections(home: pathlib.Path | None = None) -> list[dict[str, Any]]:
    root = (home or default_runtime_home()).expanduser() / "selections"
    if not root.exists():
        return []
    if root.is_symlink() or not root.is_dir():
        raise RuntimePackError(f"runtime selections must be a regular directory: {root}")
    values: list[dict[str, Any]] = []
    for path in sorted(root.glob("*.json")):
        value = _read_object(path, "runtime selection")
        _validate_selection(value, str(path))
        expected_name = f"{selection_key(value['name'], value['engine'])}.json"
        if path.name != expected_name:
            raise RuntimePackError(f"runtime selection filename mismatch: {path}")
        values.append(value)
    return values


def write_selection(
    receipt: dict[str, Any], home: pathlib.Path | None = None
) -> pathlib.Path:
    runtime_home = (home or default_runtime_home()).expanduser()
    root = runtime_home / "selections"
    _private_directory(root)
    path = root / f"{selection_key(receipt['name'], receipt['engine'])}.json"
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
                    "name",
                    "model",
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
                    "source",
                )
                if key in previous
            }
        )
    value = dict(receipt)
    value["schema_version"] = SELECTION_SCHEMA_VERSION
    value["history"] = history[-20:]
    _validate_selection(value, "new receipt")
    data = canonical_bytes(value)
    with tempfile.NamedTemporaryFile(
        prefix=f".{path.name}.", dir=root, delete=False
    ) as handle:
        temporary = pathlib.Path(handle.name)
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    temporary.chmod(0o600)
    temporary.replace(path)
    return path


def new_receipt(
    pack: RuntimePack,
    *,
    object_root: pathlib.Path,
    manifest_path: pathlib.Path,
    control_root: pathlib.Path,
    source: str,
    policy: str,
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
        "name": pack.descriptor["name"],
        "model": pack.descriptor["model"],
        "engine": pack.descriptor["engine"],
        "target": pack.descriptor["target"],
        "target_contract_sha256": target_contract_sha256,
        "version": pack.descriptor["version"],
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
        "source": source,
        "history": [],
    }


def _catalog_public_key(explicit: str | None) -> pathlib.Path | None:
    configured = explicit or os.environ.get("LETSINFER_CATALOG_PUBLIC_KEY")
    if configured:
        return pathlib.Path(configured).expanduser()
    config_override = os.environ.get("LETSINFER_CONFIG_HOME")
    root = (
        pathlib.Path(config_override).expanduser()
        if config_override
        else pathlib.Path.home() / ".config/letsinfer"
    )
    default = root / "catalog-public-key.pem"
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
        or set(value) != {"schema_version", "targets", "models"}
    ):
        raise RuntimePackError("unsupported runtime catalog schema_version")
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
                or set(target_record) != {"recommended", "engines"}
            ):
                raise RuntimePackError(f"catalog target {model}/{target_id} is invalid")
            recommended = target_record.get("recommended")
            engines = target_record.get("engines")
            if (
                not isinstance(recommended, str)
                or not SAFE_NAME_RE.fullmatch(recommended)
                or not isinstance(engines, dict)
                or not engines
            ):
                raise RuntimePackError(
                    f"catalog target {model}/{target_id} is missing recommendation data"
                )
            if recommended not in engines:
                raise RuntimePackError(
                    f"catalog recommendation for {model}/{target_id} is not an engine variant"
                )
            for engine, release in engines.items():
                if (
                    not isinstance(engine, str)
                    or not SAFE_NAME_RE.fullmatch(engine)
                    or not isinstance(release, dict)
                    or set(release) != {"version", "source"}
                ):
                    raise RuntimePackError(
                        f"catalog engine entry for {model}/{engine}/{target_id} is invalid"
                    )
                if not VERSION_RE.fullmatch(release.get("version", "")):
                    raise RuntimePackError(
                        f"catalog version for {model}/{engine}/{target_id} is invalid"
                    )
                if not REGISTRY_DIGEST_RE.fullmatch(release.get("source", "")):
                    raise RuntimePackError(
                        f"catalog source for {model}/{engine}/{target_id} must be digest-pinned OCI"
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
    engine: str | None,
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
    selected_engine = engine or target_record["recommended"]
    release = target_record["engines"].get(selected_engine)
    if not isinstance(release, dict):
        raise RuntimePackError(
            f"runtime catalog has no {selected_engine} variant for {model}/{selected_target}"
        )
    return (
        selected_target,
        target_contract_sha256(contract),
        selected_engine,
        release["version"],
        release["source"],
    )


def resolved_catalog_location(explicit: str | None = None) -> str | None:
    if explicit:
        return explicit
    configured = os.environ.get("LETSINFER_CATALOG")
    if configured:
        return configured
    config_override = os.environ.get("LETSINFER_CONFIG_HOME")
    root = pathlib.Path(config_override).expanduser() if config_override else pathlib.Path.home() / ".config/letsinfer"
    default = root / "catalog.json"
    return str(default) if default.is_file() else DEFAULT_CATALOG_URL


def _is_option_token(token: str) -> bool:
    return token.startswith("--") or bool(
        re.fullmatch(r"-[A-Za-z][A-Za-z0-9_-]*(?:=.*)?", token)
    )


def overlay_clauses(tokens: Sequence[str]) -> list[list[str]]:
    """Split native options without knowing an engine's option schema."""
    clauses: list[list[str]] = []
    current: list[str] | None = None
    for token in tokens:
        if token == "--":
            raise RuntimePackError("the engine argument list cannot contain another -- separator")
        if _is_option_token(token):
            current = [token]
            clauses.append(current)
        elif current is None:
            raise RuntimePackError(
                f"engine argument values must follow an option; unexpected {token!r}"
            )
        else:
            current.append(token)
    if not clauses:
        raise RuntimePackError("no engine arguments were supplied after --")
    return clauses


def clause_key(clause: Sequence[str]) -> str:
    if not clause or not _is_option_token(clause[0]) or clause[0] == "--":
        raise RuntimePackError("engine argument clauses must begin with an option")
    return clause[0].split("=", 1)[0]


def apply_overlay(
    parent: Sequence[Sequence[str]],
    supplied: Sequence[Sequence[str]],
    without: Sequence[str],
) -> tuple[list[list[str]], dict[str, list[Any]]]:
    removals = list(dict.fromkeys(without))
    if any(
        not _is_option_token(value) or value == "--" or "=" in value
        for value in removals
    ):
        raise RuntimePackError("--without values must be exact option names")
    supplied_groups: dict[str, list[list[str]]] = {}
    supplied_order: list[str] = []
    for raw_clause in supplied:
        clause = list(raw_clause)
        key = clause_key(clause)
        if key in removals:
            raise RuntimePackError(f"engine argument cannot be supplied and removed: {key}")
        if key not in supplied_groups:
            supplied_groups[key] = []
            supplied_order.append(key)
        supplied_groups[key].append(clause)
    parent_keys = [clause_key(clause) for clause in parent]
    resolved: list[list[str]] = []
    emitted: set[str] = set()
    replaced: list[Any] = []
    removed: list[Any] = []
    for raw_clause, key in zip(parent, parent_keys):
        clause = list(raw_clause)
        if key in removals:
            removed.append(clause)
            continue
        if key in supplied_groups:
            if key not in emitted:
                resolved.extend(supplied_groups[key])
                replaced.append({
                    "before": [
                        list(item)
                        for item, item_key in zip(parent, parent_keys)
                        if item_key == key
                    ],
                    "after": supplied_groups[key],
                })
                emitted.add(key)
            continue
        resolved.append(clause)
    added: list[Any] = []
    for key in supplied_order:
        if key not in parent_keys:
            resolved.extend(supplied_groups[key])
            added.extend(supplied_groups[key])
    return resolved, {"removed": removed, "replaced": replaced, "added": added}


def flatten_clauses(clauses: Sequence[Sequence[str]]) -> tuple[str, ...]:
    return tuple(token for clause in clauses for token in clause)
