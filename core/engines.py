#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Fail-closed inference-engine adapters for Let's Infer runtime manifests."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import re
import shlex
from typing import Any

from .runtime_packs import apply_overlay, clause_key, flatten_clauses, overlay_clauses
from .token_count import (
    LETSINFER_TOKEN_COUNT_PROTOCOL,
    SGLANG_ANTHROPIC_TOKEN_COUNT_PROTOCOL,
)


class EngineManifestError(ValueError):
    """An engine-specific manifest value is missing or unsafe."""


@dataclasses.dataclass(frozen=True)
class EngineAdapter:
    name: str
    model_format: str
    cache_provider: str
    requires_runtime_plugins: bool
    persistent_cache: bool
    api_key_mode: str
    evidence_contract: str
    token_count_path: str | None = None
    token_count_protocol: str | None = None


@dataclasses.dataclass(frozen=True)
class EngineLaunch:
    command: tuple[str, ...]
    shell_setup: str
    environment: tuple[tuple[str, str], ...]
    mount_runtime_plugins: bool
    mount_prefix_store: bool
    prewarm: str
    engine_argument_offset: int
    protected_arguments: frozenset[str]
    health_path: str = "/health"
    models_path: str = "/v1/models"


ENVIRONMENT_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
PROTECTED_ENVIRONMENT_NAMES = {
    "HF_HOME",
    "HF_HUB_OFFLINE",
    "PIP_DISABLE_PIP_VERSION_CHECK",
    "PIP_NO_CACHE_DIR",
    "PYTHONPATH",
    "VLLM_API_KEY",
    "DS4_DSPARK_MODEL",
    "DS4_LETSINFER_CACHE",
    "DS4_LETSINFER_CACHE_DIR",
    "DS4_LETSINFER_CACHE_LIB",
    "DS4_LETSINFER_CACHE_MB",
    "DS4_LETSINFER_CACHE_TTL_S",
    "DS4_LETSINFER_CACHE_MIN_TOKENS",
    "DS4_LETSINFER_CACHE_RESIDENT_MB",
    "DS4_LETSINFER_CACHE_DIRECT",
    "DS4_LETSINFER_CACHE_CAPTURE",
    "DS4_LETSINFER_CACHE_PREFIX",
    "SGLANG_HICACHE_FILE_BACKEND_STORAGE_DIR",
}


ADAPTERS = {
    "vllm": EngineAdapter(
        name="vllm",
        model_format="huggingface-snapshot",
        cache_provider="letsinfer-prefix-v1",
        requires_runtime_plugins=True,
        persistent_cache=True,
        api_key_mode="environment",
        evidence_contract="vllm-letsinfer-prefix-v1",
    ),
    "sglang": EngineAdapter(
        name="sglang",
        model_format="huggingface-snapshot",
        cache_provider="sglang-hicache-file-v1",
        requires_runtime_plugins=False,
        persistent_cache=True,
        api_key_mode="config-file",
        evidence_contract="sglang-hicache-file-v1",
        token_count_path="/v1/messages/count_tokens",
        token_count_protocol=SGLANG_ANTHROPIC_TOKEN_COUNT_PROTOCOL,
    ),
    "llama.cpp": EngineAdapter(
        name="llama.cpp",
        model_format="gguf-file",
        cache_provider="native-prompt-v1",
        requires_runtime_plugins=False,
        persistent_cache=False,
        api_key_mode="file",
        evidence_contract="llama.cpp-native-prompt-v1",
    ),
    "dwarfstar": EngineAdapter(
        name="dwarfstar",
        model_format="dwarfstar-gguf-pair",
        cache_provider="dwarfstar-letsinfer-prefix-v1",
        requires_runtime_plugins=True,
        persistent_cache=True,
        api_key_mode="gateway-file",
        evidence_contract="dwarfstar-letsinfer-prefix-v1",
        token_count_path="/v1/token-count",
        token_count_protocol=LETSINFER_TOKEN_COUNT_PROTOCOL,
    ),
}

SGLANG_CACHE_PROVIDERS = {
    "sglang-radix-v1": False,
    "sglang-hicache-file-v1": True,
    "sglang-letsinfer-prefix-v1": True,
}


def adapter_for(manifest: dict[str, Any]) -> EngineAdapter:
    engine = manifest.get("engine")
    if not isinstance(engine, dict):
        raise EngineManifestError("manifest.engine must be an object")
    name = engine.get("name")
    if name not in ADAPTERS:
        supported = ", ".join(sorted(ADAPTERS))
        raise EngineManifestError(
            f"manifest.engine.name must be one of: {supported}"
        )
    return ADAPTERS[name]


def cache_provider_for(manifest: dict[str, Any]) -> str:
    cache = manifest.get("cache")
    if not isinstance(cache, dict) or not isinstance(cache.get("provider"), str):
        raise EngineManifestError("manifest.cache.provider must be a string")
    return cache["provider"]


def persistent_cache_for(manifest: dict[str, Any]) -> bool:
    cache = manifest.get("cache")
    if not isinstance(cache, dict) or not isinstance(cache.get("persistent"), bool):
        raise EngineManifestError("manifest.cache.persistent must be boolean")
    return cache["persistent"]


def evidence_contract_for(manifest: dict[str, Any]) -> str:
    adapter = adapter_for(manifest)
    return cache_provider_for(manifest) if adapter.name == "sglang" else adapter.evidence_contract


def requires_core_cache_plugin(manifest: dict[str, Any]) -> bool:
    return (
        adapter_for(manifest).name == "sglang"
        and cache_provider_for(manifest) == "sglang-letsinfer-prefix-v1"
    )


def _require(mapping: dict[str, Any], key: str, expected: type, where: str) -> Any:
    value = mapping.get(key)
    if not isinstance(value, expected):
        raise EngineManifestError(f"{where}.{key} must be {expected.__name__}")
    return value


def _positive_int(mapping: dict[str, Any], key: str, where: str) -> int:
    value = mapping.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise EngineManifestError(f"{where}.{key} must be positive")
    return value


def _nonnegative_int(mapping: dict[str, Any], key: str, where: str) -> int:
    value = mapping.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise EngineManifestError(f"{where}.{key} must be non-negative")
    return value


def _gguf_artifact(model: dict[str, Any], where: str) -> None:
    filename = _require(model, "filename", str, where)
    if not filename.endswith(".gguf") or "/" in filename or "\\" in filename:
        raise EngineManifestError(
            f"{where}.filename must name one contained .gguf file"
        )
    digest = _require(model, "sha256", str, where)
    if len(digest) != 64 or any(
        character not in "0123456789abcdef" for character in digest
    ):
        raise EngineManifestError(f"{where}.sha256 must be a lowercase SHA-256")


def _huggingface_artifact(model: dict[str, Any], where: str) -> None:
    repository = _require(model, "repository", str, where)
    if not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*",
        repository,
    ):
        raise EngineManifestError(f"{where}.repository must be one exact owner/name")
    cache_repository = _require(model, "cache_repository", str, where)
    expected_cache = f"models--{repository.replace('/', '--')}"
    if cache_repository != expected_cache:
        raise EngineManifestError(
            f"{where}.cache_repository must be {expected_cache!r}"
        )


def validate_engine_manifest(manifest: dict[str, Any]) -> EngineAdapter:
    adapter = adapter_for(manifest)
    engine = manifest["engine"]
    allowed_engine_fields = {
        "name",
        "model_format",
        "api_protocol",
        "cache_provider",
        "arguments",
        "environment",
    }
    unknown_engine_fields = set(engine) - allowed_engine_fields
    if unknown_engine_fields:
        raise EngineManifestError(
            "manifest.engine has unsupported fields: "
            + ", ".join(sorted(unknown_engine_fields))
        )
    if "runtime" in manifest:
        raise EngineManifestError(
            "manifest.runtime is unsupported; native engine configuration belongs "
            "in manifest.engine.arguments and manifest.engine.environment"
        )
    expected = {
        "model_format": adapter.model_format,
        "api_protocol": "openai-v1",
    }
    if adapter.name == "sglang":
        provider = engine.get("cache_provider")
        if provider not in SGLANG_CACHE_PROVIDERS:
            raise EngineManifestError(
                "manifest.engine.cache_provider must be one of: "
                + ", ".join(sorted(SGLANG_CACHE_PROVIDERS))
            )
    else:
        expected["cache_provider"] = adapter.cache_provider
    for key, value in expected.items():
        if engine.get(key) != value:
            raise EngineManifestError(
                f"manifest.engine.{key} must be {value!r} for {adapter.name}"
            )

    environment = engine.get("environment", {})
    if not isinstance(environment, dict):
        raise EngineManifestError("manifest.engine.environment must be an object")
    for name, value in environment.items():
        if not isinstance(name, str) or ENVIRONMENT_NAME_RE.fullmatch(name) is None:
            raise EngineManifestError(
                "manifest.engine.environment names must be portable environment names"
            )
        if name.startswith("LETSINFER_") or name in PROTECTED_ENVIRONMENT_NAMES:
            raise EngineManifestError(
                f"manifest.engine.environment cannot change Let's Infer-owned {name}"
            )
        if value is not None and not isinstance(value, str):
            raise EngineManifestError(
                f"manifest.engine.environment.{name} must be a string or null"
            )

    arguments = engine.get("arguments")
    if arguments is not None:
        if (
            not isinstance(arguments, list)
            or not arguments
            or not all(isinstance(value, str) and value for value in arguments)
        ):
            raise EngineManifestError(
                "manifest.engine.arguments must contain non-empty native engine arguments"
            )
        try:
            overlay_clauses(arguments)
        except ValueError as error:
            raise EngineManifestError(str(error)) from error

    model = manifest["model"]
    model_fields = {
        "alias",
        "id",
        "revision",
        "cache_repository",
        "acquisition_image",
    }
    if adapter.model_format == "gguf-file":
        model_fields.update({"filename", "sha256"})
    elif adapter.model_format == "dwarfstar-gguf-pair":
        model_fields.update({"repository", "filename", "sha256", "bytes", "drafter"})
    unknown_model_fields = set(model) - model_fields
    if unknown_model_fields:
        raise EngineManifestError(
            "manifest.model has unsupported fields: "
            + ", ".join(sorted(unknown_model_fields))
        )
    if adapter.model_format in {"gguf-file", "dwarfstar-gguf-pair"}:
        _gguf_artifact(model, "manifest.model")
    if adapter.model_format == "dwarfstar-gguf-pair":
        _huggingface_artifact(model, "manifest.model")
        _positive_int(model, "bytes", "manifest.model")
        drafter = _require(model, "drafter", dict, "manifest.model")
        expected_drafter_fields = {
            "repository",
            "cache_repository",
            "revision",
            "filename",
            "sha256",
            "bytes",
        }
        if set(drafter) != expected_drafter_fields:
            raise EngineManifestError(
                "manifest.model.drafter must contain exactly "
                + ", ".join(sorted(expected_drafter_fields))
            )
        _huggingface_artifact(drafter, "manifest.model.drafter")
        _require(drafter, "revision", str, "manifest.model.drafter")
        if len(drafter["revision"]) != 40 or any(
            character not in "0123456789abcdef"
            for character in drafter["revision"]
        ):
            raise EngineManifestError(
                "manifest.model.drafter.revision must be an exact 40-hex revision"
            )
        _gguf_artifact(drafter, "manifest.model.drafter")
        _positive_int(drafter, "bytes", "manifest.model.drafter")

    _require(manifest, "serving", dict, "manifest")
    cache = _require(manifest, "cache", dict, "manifest")
    cache_fields = {
        "vllm": {
            "provider",
            "persistent",
            "prewarm",
            "replay_output_policy",
            "durable_capacity_bytes",
            "resident_capacity_bytes",
            "native_capacity_bytes",
            "min_tokens",
            "exact_capsules_with_mtp",
        },
        "sglang": (
            {"provider", "persistent", "prewarm"}
            if engine["cache_provider"] == "sglang-radix-v1"
            else {
                "provider",
                "persistent",
                "prewarm",
                "replay_output_policy",
                "host_cache_gib",
                "durable_capacity_bytes",
            }
            | (
                {
                    "resident_capacity_bytes",
                    "ttl_seconds",
                    "direct_reads",
                }
                if engine["cache_provider"] == "sglang-letsinfer-prefix-v1"
                else set()
            )
        ),
        "llama.cpp": {"provider", "persistent", "prewarm"},
        "dwarfstar": {
            "provider",
            "persistent",
            "prewarm",
            "replay_output_policy",
            "durable_capacity_bytes",
            "resident_capacity_bytes",
            "ttl_seconds",
            "min_tokens",
            "direct_reads",
            "capture",
            "prefix_lookup",
        },
    }[adapter.name]
    unknown_cache_fields = set(cache) - cache_fields
    if unknown_cache_fields:
        raise EngineManifestError(
            "manifest.cache has unsupported fields: "
            + ", ".join(sorted(unknown_cache_fields))
        )
    expected_provider = engine["cache_provider"]
    if cache.get("provider") != expected_provider:
        raise EngineManifestError(
            f"manifest.cache.provider must be {expected_provider!r} for {adapter.name}"
        )
    expected_persistent = (
        SGLANG_CACHE_PROVIDERS[expected_provider]
        if adapter.name == "sglang"
        else adapter.persistent_cache
    )
    if cache.get("persistent") is not expected_persistent:
        raise EngineManifestError(
            f"manifest.cache.persistent must be {expected_persistent!r} for {adapter.name}"
        )
    if expected_persistent and cache.get("replay_output_policy") not in {
        "all-phases-exact",
        "restored-repeat-exact",
    }:
        raise EngineManifestError(
            "manifest.cache.replay_output_policy must be all-phases-exact "
            "or restored-repeat-exact"
        )

    if adapter.name == "vllm":
        for key in (
            "durable_capacity_bytes",
            "resident_capacity_bytes",
            "native_capacity_bytes",
            "min_tokens",
        ):
            _positive_int(cache, key, "manifest.cache")
        if cache.get("prewarm") is not True:
            raise EngineManifestError("vLLM Let's Infer prefix cache must prewarm before readiness")
        if not isinstance(cache.get("exact_capsules_with_mtp"), bool):
            raise EngineManifestError(
                "manifest.cache.exact_capsules_with_mtp must be boolean"
            )
    elif adapter.name == "sglang":
        if expected_provider == "sglang-radix-v1":
            if cache.get("prewarm") is not False:
                raise EngineManifestError("SGLang RadixAttention has no persistent prewarm")
        else:
            if cache.get("prewarm") is not True:
                raise EngineManifestError("SGLang persistent cache must prewarm before readiness")
            _positive_int(cache, "host_cache_gib", "manifest.cache")
            _positive_int(cache, "durable_capacity_bytes", "manifest.cache")
            if cache["durable_capacity_bytes"] % (1 << 20):
                raise EngineManifestError(
                    "manifest.cache.durable_capacity_bytes must be an exact number of MiB"
                )
            if expected_provider == "sglang-letsinfer-prefix-v1":
                _nonnegative_int(cache, "resident_capacity_bytes", "manifest.cache")
                _positive_int(cache, "ttl_seconds", "manifest.cache")
                if cache["resident_capacity_bytes"] % (1 << 20):
                    raise EngineManifestError(
                        "manifest.cache.resident_capacity_bytes must be an exact number of MiB"
                    )
                if not isinstance(cache.get("direct_reads"), bool):
                    raise EngineManifestError("manifest.cache.direct_reads must be boolean")
    elif adapter.name == "llama.cpp":
        if cache.get("prewarm") is not True:
            raise EngineManifestError("llama.cpp prompt cache must prewarm before readiness")
    else:
        if cache.get("prewarm") is not True:
            raise EngineManifestError(
                "DwarfStar Let's Infer prefix cache must prewarm before readiness"
            )
        for key in ("durable_capacity_bytes", "ttl_seconds", "min_tokens"):
            _positive_int(cache, key, "manifest.cache")
        _nonnegative_int(cache, "resident_capacity_bytes", "manifest.cache")
        for key in ("direct_reads", "capture", "prefix_lookup"):
            if not isinstance(cache.get(key), bool):
                raise EngineManifestError(f"manifest.cache.{key} must be boolean")
        for key in ("durable_capacity_bytes", "resident_capacity_bytes"):
            if cache[key] % (1 << 20):
                raise EngineManifestError(
                    f"manifest.cache.{key} must be an exact number of MiB"
                )

    return adapter


def _artifact_container_path(model: dict[str, Any]) -> str:
    snapshot = (
        f"/root/.cache/huggingface/hub/{model['cache_repository']}"
        f"/snapshots/{model['revision']}"
    )
    if "filename" in model:
        return f"{snapshot}/{model['filename']}"
    return snapshot


def model_container_path(manifest: dict[str, Any]) -> str:
    return _artifact_container_path(manifest["model"])


def dwarfstar_drafter_container_path(manifest: dict[str, Any]) -> str:
    if adapter_for(manifest).name != "dwarfstar":
        raise EngineManifestError("DwarfStar drafter path requested for another engine")
    return _artifact_container_path(manifest["model"]["drafter"])


def _compact_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _vllm_launch(manifest: dict[str, Any], serving: dict[str, Any], port: int) -> EngineLaunch:
    model = manifest["model"]
    cache = manifest["cache"]
    kv_transfer = _compact_json(
        {
            "kv_connector": "LetsInferPrefixConnector",
            "kv_role": "kv_both",
            "kv_connector_module_path": "letsinfer_prefix_connector.connector",
            "kv_connector_extra_config": {
                "min_tokens": cache["min_tokens"],
                "capacity_bytes": cache["durable_capacity_bytes"],
                "resident_capacity_bytes": cache["resident_capacity_bytes"],
                "native_capacity_bytes": cache["native_capacity_bytes"],
                "exact_capsules_with_mtp": cache["exact_capsules_with_mtp"],
            },
        }
    )
    wheel = next(
        entry["path"]
        for entry in manifest["runtime_plugins"]["artifacts"]
        if entry["path"].endswith(".whl")
    )
    command = (
        "vllm",
        "serve",
        model_container_path(manifest),
        "--served-model-name",
        model["alias"],
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--ssl-keyfile",
        "/run/secrets/letsinfer-tls.key",
        "--ssl-certfile",
        "/run/secrets/letsinfer-tls.crt",
        "--disable-fastapi-docs",
        "--disable-uvicorn-access-log",
        "--enable-request-id-headers",
        "--kv-transfer-config",
        kv_transfer,
    )
    setup = (
        "IFS= read -r VLLM_API_KEY < /run/secrets/letsinfer-api-key; "
        "export VLLM_API_KEY; "
        "python3 -m pip install -q --no-index --no-deps "
        f"--target /tmp/letsinfer-python /plugins/{wheel}; "
        "export PYTHONPATH=/tmp/letsinfer-python:/plugins; "
    )
    environment = (
        ("HF_HOME", "/root/.cache/huggingface"),
        ("HF_HUB_OFFLINE", "1"),
        ("PYTHONPATH", "/plugins"),
        ("PIP_DISABLE_PIP_VERSION_CHECK", "1"),
        ("PIP_NO_CACHE_DIR", "1"),
    )
    return EngineLaunch(
        command=command,
        shell_setup=setup,
        environment=environment,
        mount_runtime_plugins=True,
        mount_prefix_store=True,
        prewarm="letsinfer-prefix",
        engine_argument_offset=3,
        protected_arguments=frozenset(
            {
                "--served-model-name",
                "--host",
                "--port",
                "--ssl-keyfile",
                "--ssl-certfile",
                "--kv-transfer-config",
            }
        ),
    )


def _sglang_launch(manifest: dict[str, Any], serving: dict[str, Any], port: int) -> EngineLaunch:
    model = manifest["model"]
    cache = manifest["cache"]
    provider = cache["provider"]
    command = [
        "python3",
        "-m",
        "sglang.launch_server",
        "--model-path",
        model_container_path(manifest),
        "--served-model-name",
        model["alias"],
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--ssl-keyfile",
        "/run/secrets/letsinfer-tls.key",
        "--ssl-certfile",
        "/run/secrets/letsinfer-tls.crt",
        "--config",
        "/tmp/letsinfer-sglang.yaml",
        "--enable-cache-report",
    ]
    if provider != "sglang-radix-v1":
        command.extend(
            [
                "--enable-hierarchical-cache",
                "--hicache-size",
                str(cache["host_cache_gib"]),
                "--hicache-write-policy",
                "write_through",
                "--hicache-storage-backend",
                "dynamic" if provider == "sglang-letsinfer-prefix-v1" else "file",
                "--hicache-storage-prefetch-policy",
                "wait_complete",
            ]
        )
        extra = (
            {
                "backend_name": "letsinfer",
                "module_path": "letsinfer_sglang_cache.backend",
                "class_name": "LetsInferHiCacheStorage",
                "capacity_bytes": cache["durable_capacity_bytes"],
                "resident_capacity_bytes": cache["resident_capacity_bytes"],
                "ttl_seconds": cache["ttl_seconds"],
                "direct_reads": cache["direct_reads"],
            }
            if provider == "sglang-letsinfer-prefix-v1"
            else {"max_size": cache["durable_capacity_bytes"]}
        )
        command.extend(
            ["--hicache-storage-backend-extra-config", _compact_json(extra)]
        )
    setup = (
        "IFS= read -r LETSINFER_API_KEY < /run/secrets/letsinfer-api-key; "
        "printf 'api-key: %s\\nlog-level: warning\\n' \"$LETSINFER_API_KEY\" "
        "> /tmp/letsinfer-sglang.yaml; "
        "chmod 600 /tmp/letsinfer-sglang.yaml; unset LETSINFER_API_KEY; "
    )
    if provider == "sglang-letsinfer-prefix-v1":
        setup += (
            "python3 -m pip install -q --no-index --no-deps "
            "--target /tmp/letsinfer-python /plugins/*.whl; "
            "export PYTHONPATH=/tmp/letsinfer-python:/plugins; "
        )
    environment = [("HF_HOME", "/root/.cache/huggingface"), ("HF_HUB_OFFLINE", "1")]
    if provider == "sglang-hicache-file-v1":
        environment.append(
            ("SGLANG_HICACHE_FILE_BACKEND_STORAGE_DIR", "/root/.cache/letsinfer-prefix-store")
        )
    elif provider == "sglang-letsinfer-prefix-v1":
        environment.extend(
            [
                ("LETSINFER_PREFIX_STORE_DIR", "/root/.cache/letsinfer-prefix-store"),
                ("PYTHONPATH", "/plugins"),
                ("PIP_DISABLE_PIP_VERSION_CHECK", "1"),
                ("PIP_NO_CACHE_DIR", "1"),
            ]
        )
    return EngineLaunch(
        command=tuple(command),
        shell_setup=setup,
        environment=tuple(environment),
        mount_runtime_plugins=provider == "sglang-letsinfer-prefix-v1",
        mount_prefix_store=provider != "sglang-radix-v1",
        prewarm="openai",
        engine_argument_offset=3,
        protected_arguments=frozenset(
            {
                "--model-path",
                "--served-model-name",
                "--host",
                "--port",
                "--ssl-keyfile",
                "--ssl-certfile",
                "--config",
                "--enable-hierarchical-cache",
                "--hicache-size",
                "--hicache-write-policy",
                "--hicache-storage-backend",
                "--hicache-storage-prefetch-policy",
                "--hicache-storage-backend-extra-config",
                "--enable-cache-report",
            }
        ),
    )


def _llama_cpp_launch(
    manifest: dict[str, Any], serving: dict[str, Any], port: int
) -> EngineLaunch:
    model = manifest["model"]
    command = [
        "/app/llama-server",
        "--model",
        model_container_path(manifest),
        "--alias",
        model["id"],
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--api-key-file",
        "/run/secrets/letsinfer-api-key",
        "--ssl-key-file",
        "/run/secrets/letsinfer-tls.key",
        "--ssl-cert-file",
        "/run/secrets/letsinfer-tls.crt",
        "--no-webui",
    ]
    return EngineLaunch(
        command=tuple(command),
        shell_setup="",
        environment=(("HF_HUB_OFFLINE", "1"),),
        mount_runtime_plugins=False,
        mount_prefix_store=False,
        prewarm="openai",
        engine_argument_offset=1,
        protected_arguments=frozenset(
            {
                "--model",
                "-m",
                "--alias",
                "-a",
                "--host",
                "--port",
                "--api-key-file",
                "--ssl-key-file",
                "--ssl-cert-file",
                "--no-webui",
            }
        ),
    )


def _dwarfstar_launch(
    manifest: dict[str, Any], serving: dict[str, Any], port: int
) -> EngineLaunch:
    model = manifest["model"]
    cache = manifest["cache"]
    backend_port_marker = "@LETSINFER_BACKEND_PORT@"
    command = (
        "python3",
        "/plugins/dwarfstar_gateway.py",
        "--listen-host",
        "127.0.0.1",
        "--listen-port",
        str(port),
        "--backend-host",
        "127.0.0.1",
        "--backend-port",
        "0",
        "--api-key-file",
        "/run/secrets/letsinfer-api-key",
        "--tls-cert-file",
        "/run/secrets/letsinfer-tls.crt",
        "--tls-key-file",
        "/run/secrets/letsinfer-tls.key",
        "--expected-model",
        model["id"],
        "--max-connections",
        str(serving["max_connections"]),
        "--max-active-requests",
        str(serving["max_active_requests"]),
        "--shutdown-timeout-seconds",
        "110",
        "--",
        "/opt/dwarfstar/ds4-server",
        "--model",
        model_container_path(manifest),
        "--dspark",
        dwarfstar_drafter_container_path(manifest),
        "--host",
        "127.0.0.1",
        "--port",
        backend_port_marker,
        "--mem-floor-gb",
        str(
            manifest["container"]["runtime_min_available_gib"]
        ),
        "--no-update-check",
    )
    environment = (
        ("HF_HOME", "/root/.cache/huggingface"),
        ("HF_HUB_OFFLINE", "1"),
        ("DS4_DSPARK_MODEL", dwarfstar_drafter_container_path(manifest)),
        ("DS4_LETSINFER_CACHE", "1"),
        ("DS4_LETSINFER_CACHE_DIR", "/root/.cache/letsinfer-prefix-store/dwarfstar"),
        ("DS4_LETSINFER_CACHE_LIB", "/plugins/libletsinfer_prefix_capi.so"),
        ("DS4_LETSINFER_CACHE_MB", str(cache["durable_capacity_bytes"] >> 20)),
        ("DS4_LETSINFER_CACHE_TTL_S", str(cache["ttl_seconds"])),
        ("DS4_LETSINFER_CACHE_MIN_TOKENS", str(cache["min_tokens"])),
        ("DS4_LETSINFER_CACHE_RESIDENT_MB", str(cache["resident_capacity_bytes"] >> 20)),
        ("DS4_LETSINFER_CACHE_DIRECT", "1" if cache["direct_reads"] else "0"),
        ("DS4_LETSINFER_CACHE_CAPTURE", "1" if cache["capture"] else "0"),
        ("DS4_LETSINFER_CACHE_PREFIX", "1" if cache["prefix_lookup"] else "0"),
    )
    return EngineLaunch(
        command=command,
        shell_setup="",
        environment=environment,
        mount_runtime_plugins=True,
        mount_prefix_store=True,
        prewarm="openai",
        engine_argument_offset=command.index("/opt/dwarfstar/ds4-server") + 1,
        protected_arguments=frozenset(
            {
                "--model",
                "--dspark",
                "--host",
                "--port",
                "--mem-floor-gb",
                "--no-update-check",
            }
        ),
    )


def _apply_environment_overrides(
    launch: EngineLaunch, manifest: dict[str, Any]
) -> EngineLaunch:
    overrides = manifest["engine"].get("environment", {})
    if not overrides:
        return launch
    environment = dict(launch.environment)
    for name, value in overrides.items():
        if value is None:
            environment.pop(name, None)
        else:
            environment[name] = value
    return dataclasses.replace(
        launch,
        environment=tuple(sorted(environment.items())),
    )


def _apply_runtime_arguments(
    launch: EngineLaunch, manifest: dict[str, Any]
) -> EngineLaunch:
    """Overlay runtime-owned native flags without encoding their schema in core."""
    tokens = manifest["engine"].get("arguments")
    if tokens is None:
        return launch
    try:
        parent = overlay_clauses(
            launch.command[launch.engine_argument_offset :]
        )
        supplied = overlay_clauses(tokens)
        changed = {
            clause_key(clause) for clause in supplied
        }.intersection(launch.protected_arguments)
        if changed:
            raise EngineManifestError(
                "runtime cannot change Let's Infer-owned engine argument "
                + ", ".join(sorted(changed))
            )
        resolved, _ = apply_overlay(parent, supplied, ())
    except ValueError as error:
        if isinstance(error, EngineManifestError):
            raise
        raise EngineManifestError(str(error)) from error
    return dataclasses.replace(
        launch,
        command=(
            *launch.command[: launch.engine_argument_offset],
            *flatten_clauses(resolved),
        ),
    )


def launch_for(
    manifest: dict[str, Any], serving: dict[str, Any], port: int
) -> EngineLaunch:
    adapter = adapter_for(manifest)
    if adapter.name == "vllm":
        launch = _vllm_launch(manifest, serving, port)
    elif adapter.name == "sglang":
        launch = _sglang_launch(manifest, serving, port)
    elif adapter.name == "llama.cpp":
        launch = _llama_cpp_launch(manifest, serving, port)
    else:
        launch = _dwarfstar_launch(manifest, serving, port)

    launch = _apply_runtime_arguments(launch, manifest)
    launch = _apply_environment_overrides(launch, manifest)

    derivation = manifest.get("derivation")
    if derivation is None:
        return launch
    clauses = derivation.get("resolved_engine_arguments")
    if not isinstance(clauses, list) or not clauses:
        raise EngineManifestError(
            "manifest.derivation.resolved_engine_arguments must be non-empty"
        )
    normalized: list[list[str]] = []
    for index, clause in enumerate(clauses):
        if (
            not isinstance(clause, list)
            or not clause
            or not all(isinstance(token, str) and token for token in clause)
        ):
            raise EngineManifestError(
                f"manifest.derivation.resolved_engine_arguments[{index}] is invalid"
            )
        try:
            clause_key(clause)
        except ValueError as error:
            raise EngineManifestError(str(error)) from error
        normalized.append(clause)
    arguments = flatten_clauses(normalized)
    try:
        parent_clauses = overlay_clauses(
            launch.command[launch.engine_argument_offset :]
        )
    except ValueError as error:
        raise EngineManifestError(str(error)) from error
    for protected in launch.protected_arguments:
        before = [clause for clause in parent_clauses if clause_key(clause) == protected]
        after = [clause for clause in normalized if clause_key(clause) == protected]
        if before != after:
            raise EngineManifestError(
                f"derived runtime cannot change Let's Infer-owned engine argument {protected}"
            )
    digest = hashlib.sha256(
        json.dumps(
            list(arguments), separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    ).hexdigest()
    if digest != derivation.get("resolved_arguments_sha256"):
        raise EngineManifestError(
            "manifest.derivation resolved engine argument digest mismatch"
        )
    return dataclasses.replace(
        launch,
        command=(
            *launch.command[: launch.engine_argument_offset],
            *arguments,
        ),
    )


def shell_command(launch: EngineLaunch) -> str:
    """Quote an engine command for the container's private launch shell."""
    return shlex.join(launch.command)
