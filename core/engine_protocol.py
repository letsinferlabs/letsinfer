#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Engine-agnostic boundary for Let's Infer Engine OCI images.

Core never imports an upstream engine or carries a version registry. Every
Engine OCI implements protocol v1 at one fixed executable and consumes the
authoritative runtime.json mounted by core.
"""

from __future__ import annotations

import dataclasses
import re
import shlex
from typing import Any

from .exact_tokens import LETSINFER_TOKEN_COUNT_PROTOCOL


ENGINE_PROTOCOL_VERSION = 1
ENGINE_ADAPTER = "/opt/letsinfer/bin/engine-adapter"
ENGINE_API_PROTOCOL = "openai-v1"
ENGINE_HEALTH_PATH = "/health"
ENGINE_MODELS_PATH = "/v1/models"
ENGINE_TELEMETRY_PATH = "/v1/letsinfer/telemetry"
ENGINE_TOKEN_COUNT_PATH = "/v1/letsinfer/token-count"
ENVIRONMENT_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
ARTIFACT_NAME_RE = re.compile(r"[a-z][a-z0-9._-]{0,62}")
ARTIFACT_REFERENCE_RE = re.compile(r"\$\{artifact:([a-z][a-z0-9._-]{0,62})\}")
SAFE_NAME_RE = re.compile(r"[a-z0-9][a-z0-9._-]*")


class EngineManifestError(ValueError):
    """A generic Engine OCI contract value is missing or unsafe."""


@dataclasses.dataclass(frozen=True)
class EngineAdapter:
    """Runtime-derived metadata; this is deliberately not an engine registry."""

    name: str
    model_format: str
    cache_provider: str
    persistent_cache: bool
    evidence_contract: str = "letsinfer-engine-protocol-v1"
    token_count_path: str = ENGINE_TOKEN_COUNT_PATH
    token_count_protocol: str = LETSINFER_TOKEN_COUNT_PROTOCOL


@dataclasses.dataclass(frozen=True)
class EngineLaunch:
    command: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    mount_prefix_store: bool
    prewarm: str
    health_path: str = ENGINE_HEALTH_PATH
    models_path: str = ENGINE_MODELS_PATH


def _require(mapping: dict[str, Any], key: str, expected: type, where: str) -> Any:
    value = mapping.get(key)
    if not isinstance(value, expected):
        raise EngineManifestError(f"{where}.{key} must be {expected.__name__}")
    return value


def adapter_for(manifest: dict[str, Any]) -> EngineAdapter:
    engine = _require(manifest, "engine", dict, "manifest")
    cache = _require(manifest, "cache", dict, "manifest")
    name = _require(engine, "name", str, "manifest.engine")
    model_format = _require(engine, "model_format", str, "manifest.engine")
    cache_provider = _require(engine, "cache_provider", str, "manifest.engine")
    persistent = cache.get("persistent")
    for value, where in (
        (name, "manifest.engine.name"),
        (model_format, "manifest.engine.model_format"),
        (cache_provider, "manifest.engine.cache_provider"),
    ):
        if SAFE_NAME_RE.fullmatch(value) is None:
            raise EngineManifestError(f"{where} must be a lowercase safe name")
    if not isinstance(persistent, bool):
        raise EngineManifestError("manifest.cache.persistent must be boolean")
    return EngineAdapter(
        name=name,
        model_format=model_format,
        cache_provider=cache_provider,
        persistent_cache=persistent,
    )


def cache_provider_for(manifest: dict[str, Any]) -> str:
    return adapter_for(manifest).cache_provider


def persistent_cache_for(manifest: dict[str, Any]) -> bool:
    return adapter_for(manifest).persistent_cache


def evidence_contract_for(_manifest: dict[str, Any]) -> str:
    return "letsinfer-engine-protocol-v1"


def artifact_storage_slug(artifact: dict[str, Any]) -> str:
    repository = _require(artifact, "repository", str, "artifact")
    if re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*",
        repository,
    ) is None:
        raise EngineManifestError("artifact.repository must be one exact owner/name")
    return repository.replace("/", "--").lower()


def artifacts_for(manifest: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise EngineManifestError("manifest.artifacts must be a non-empty array")
    return tuple(artifacts)


def artifact_for(manifest: dict[str, Any], name: str) -> dict[str, Any]:
    matches = [artifact for artifact in artifacts_for(manifest) if artifact.get("name") == name]
    if len(matches) != 1:
        raise EngineManifestError(f"manifest references unknown artifact {name!r}")
    return matches[0]


def _artifact_container_path(artifact: dict[str, Any]) -> str:
    snapshot = f"/models/{artifact_storage_slug(artifact)}/{artifact['revision']}"
    if artifact["format"] == "gguf-file":
        return f"{snapshot}/{artifact['filename']}"
    return snapshot


def artifact_container_path(manifest: dict[str, Any], name: str) -> str:
    return _artifact_container_path(artifact_for(manifest, name))


def model_container_path(manifest: dict[str, Any]) -> str:
    return artifact_container_path(manifest, manifest["model"]["artifact"])


def expand_artifact_references(
    manifest: dict[str, Any], tokens: tuple[str, ...] | list[str]
) -> tuple[str, ...]:
    """Validate and resolve whole-token references for adapter conformance tests."""

    resolved: list[str] = []
    for token in tokens:
        match = ARTIFACT_REFERENCE_RE.fullmatch(token)
        if match is not None:
            resolved.append(artifact_container_path(manifest, match.group(1)))
        elif "${artifact:" in token:
            raise EngineManifestError(
                "artifact references must occupy one complete engine argument token"
            )
        else:
            resolved.append(token)
    return tuple(resolved)


def _validate_artifacts(manifest: dict[str, Any], model_format: str) -> None:
    names: set[str] = set()
    for index, artifact in enumerate(artifacts_for(manifest)):
        where = f"manifest.artifacts[{index}]"
        if not isinstance(artifact, dict):
            raise EngineManifestError(f"{where} must be an object")
        name = _require(artifact, "name", str, where)
        if ARTIFACT_NAME_RE.fullmatch(name) is None or name in names:
            raise EngineManifestError(f"{where}.name must be a unique portable name")
        names.add(name)
        artifact_format = _require(artifact, "format", str, where)
        if artifact_format not in {"huggingface-snapshot", "gguf-file"}:
            raise EngineManifestError(f"{where}.format is unsupported")
        artifact_storage_slug(artifact)
        revision = _require(artifact, "revision", str, where)
        if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
            raise EngineManifestError(f"{where}.revision must be an exact 40-hex revision")
        if artifact_format == "gguf-file":
            filename = _require(artifact, "filename", str, where)
            digest = _require(artifact, "sha256", str, where)
            if not filename.endswith(".gguf") or "/" in filename or "\\" in filename:
                raise EngineManifestError(f"{where}.filename must be one contained .gguf file")
            if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                raise EngineManifestError(f"{where}.sha256 must be a lowercase SHA-256")
    primary = artifact_for(manifest, manifest["model"]["artifact"])
    if primary["format"] != model_format:
        raise EngineManifestError(
            "manifest.model.artifact format must match manifest.engine.model_format"
        )


def validate_engine_manifest(manifest: dict[str, Any]) -> EngineAdapter:
    """Validate the stable protocol boundary without knowing upstream options."""

    adapter = adapter_for(manifest)
    engine = manifest["engine"]
    if set(engine) != {
        "name",
        "model_format",
        "api_protocol",
        "cache_provider",
        "arguments",
        "environment",
    }:
        raise EngineManifestError("manifest.engine fields do not match Engine protocol v1")
    if engine["api_protocol"] != ENGINE_API_PROTOCOL:
        raise EngineManifestError("manifest.engine.api_protocol must be openai-v1")
    arguments = engine.get("arguments")
    if not isinstance(arguments, list) or any(
        not isinstance(value, str) or not value for value in arguments
    ):
        raise EngineManifestError("manifest.engine.arguments must be a string array")
    environment = engine.get("environment")
    if not isinstance(environment, dict):
        raise EngineManifestError("manifest.engine.environment must be an object")
    for name, value in environment.items():
        if ENVIRONMENT_NAME_RE.fullmatch(name) is None or not isinstance(value, str):
            raise EngineManifestError("manifest.engine.environment must be a portable string map")
        if name.startswith("LETSINFER_"):
            raise EngineManifestError(
                f"manifest.engine.environment cannot change protocol-owned {name}"
            )
    _validate_artifacts(manifest, adapter.model_format)
    expand_artifact_references(manifest, arguments)
    cache = manifest["cache"]
    if set(cache) != {
        "provider",
        "persistent",
        "prewarm",
        "replay_output_policy",
        "config",
    }:
        raise EngineManifestError(
            "manifest.cache must contain provider, persistent, prewarm, "
            "replay_output_policy, and config"
        )
    if cache["provider"] != adapter.cache_provider:
        raise EngineManifestError("manifest.cache.provider must match engine.cache_provider")
    if not isinstance(cache["prewarm"], bool) or not isinstance(cache["config"], dict):
        raise EngineManifestError("manifest.cache prewarm/config values are invalid")
    if adapter.persistent_cache:
        if cache["replay_output_policy"] not in {
            "all-phases-exact",
            "restored-repeat-exact",
        }:
            raise EngineManifestError(
                "persistent cache requires an exact replay_output_policy"
            )
    elif cache["replay_output_policy"] is not None:
        raise EngineManifestError(
            "non-persistent cache replay_output_policy must be null"
        )
    return adapter


def launch_for(
    manifest: dict[str, Any], serving: dict[str, Any], port: int
) -> EngineLaunch:
    """Create the one protocol-v1 launch used for every Engine OCI."""

    validate_engine_manifest(manifest)
    if not isinstance(port, int) or isinstance(port, bool) or port not in range(1, 65536):
        raise EngineManifestError("engine port must be between 1 and 65535")
    if not isinstance(serving, dict):
        raise EngineManifestError("manifest.serving must be an object")
    environment = {
        "LETSINFER_ENGINE_PROTOCOL": str(ENGINE_PROTOCOL_VERSION),
        "LETSINFER_RUNTIME_CONFIG": "/opt/letsinfer/runtime-pack/runtime.json",
        "LETSINFER_RUNTIME_ROOT": "/opt/letsinfer/runtime-pack",
        "LETSINFER_MODEL_ROOT": "/models",
        "LETSINFER_CACHE_ROOT": "/root/.cache/letsinfer-prefix-store",
        "LETSINFER_LISTEN_HOST": "127.0.0.1",
        "LETSINFER_LISTEN_PORT": str(port),
        "LETSINFER_API_KEY_FILE": "/run/secrets/letsinfer-api-key",
        "LETSINFER_TLS_CERT_FILE": "/run/secrets/letsinfer-tls.crt",
        "LETSINFER_TLS_KEY_FILE": "/run/secrets/letsinfer-tls.key",
        "LETSINFER_SERVED_MODEL": manifest["model"]["alias"],
    }
    return EngineLaunch(
        command=(ENGINE_ADAPTER, "serve"),
        environment=tuple(sorted(environment.items())),
        mount_prefix_store=manifest["cache"]["persistent"],
        prewarm="openai",
    )


def shell_command(launch: EngineLaunch) -> str:
    return shlex.join(launch.command)
