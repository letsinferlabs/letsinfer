#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Serve immutable, independently qualified Let's Infer inference releases."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import getpass
import hashlib
import hmac
import http.server
import json
import os
import pathlib
import platform
import re
import secrets
import shlex
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Iterable, Mapping, Sequence

# A hash-addressed control bundle must not mutate itself when Python imports
# the adjacent engine registry. Runtime caches belong outside the bundle.
sys.dont_write_bytecode = True

from . import PRODUCT_VERSION
from .cache_plugins import (
    CachePluginError,
    install_sglang_plugin,
    verify_sglang_plugin,
)
from .actions import (
    ACTIONS,
    AuditPolicy,
    CommandScope,
    action as command_action,
    help_label,
    validate_registry,
)
from .engines import (
    ADAPTERS,
    EngineManifestError,
    adapter_for,
    artifact_cache_repository,
    cache_provider_for,
    evidence_contract_for,
    launch_for,
    persistent_cache_for,
    requires_core_cache_plugin,
    shell_command,
    validate_engine_manifest,
)
from .exposure import (
    ExposureError,
    INFERENCE_TARGET as PUBLIC_INFERENCE_TARGET,
    disable_tailscale,
    enable_tailscale,
    verify_tailscale,
)
from .orchestration import (
    build_group_plan,
    MemberAgent,
    MemberJobError,
    MemberJobStore,
    OrchestrationError,
    credential_sha256 as group_credential_sha256,
    validate_group_document,
    validate_target_binding,
)
from .orchestration.coordinator import (
    allocate_group_ports,
    EngineGroupOrchestrator,
    GroupOrchestrationError,
)
from .runtime_packs import (
    RUNTIME_CONFIG,
    RUNTIME_SCHEMA_VERSION,
    RuntimePack,
    RuntimePackError,
    apply_overlay,
    build_archive,
    canonical_bytes,
    catalog_release,
    catalog_target_contract,
    clause_key,
    compatible_catalog_targets,
    default_runtime_home,
    describe_source,
    flatten_clauses,
    load_catalog,
    materialize,
    new_receipt,
    overlay_clauses,
    resolved_catalog_location,
    selections,
    store_pack,
    target_matches,
    target_contract_sha256,
    validate_target_contract,
    verify_descriptor,
    write_selection,
)
from . import benchmark_jobs, ui
from .platform import macos as macos_services
from .site.state import (
    SiteError,
    SiteStore,
    config_root as site_config_root,
    data_root as site_data_root,
    identity_json,
    identity_path as site_identity_path,
    member_certificate_path as site_member_certificate_path,
    member_proof,
    prepare_member_identity,
    read_identity as read_site_identity,
    setup_site,
)
from .site.control import (
    DEFAULT_PORT as SITE_CONTROL_PORT,
    ControlError,
    FactsPublisher,
    fetch_member_job_status,
    SiteControlServer,
    SiteControlState,
    fetch_member_group_status,
    fetch_member_facts,
    join_site,
    request_member_link_probe,
    submit_member_group_job,
)
from .site.discovery import Publisher as DiscoveryPublisher
from .site.discovery import advertisement as discovery_advertisement
from .site.discovery import publisher_command as discovery_publisher_command
from .site.inventory import (
    InventoryError,
    collect_local_facts,
    select_direct_connectx_interface,
    verify_direct_connectx_peer,
    verify_direct_connectx_interface,
)
from .site.move import (
    LocalMoveTransaction,
    PreparedMove,
    apply_prepared_move,
    plan_local_move,
    prepare_local_move,
)
from .site.links import LinkError, LinkStore
from .site.topology import (
    TargetPlacement,
    TopologyError,
    TopologyGraph,
    validate_member_facts,
)
from .site.telemetry import TelemetryAggregator, TelemetryError, TelemetryPublisher
from .site.controller import (
    DEFAULT_PORT as CONTROLLER_CONTROL_PORT,
    ControllerError,
    ControllerPrincipal,
    ControllerServer,
    ControllerState,
    tls_context as controller_tls_context,
)
from .site.administration import SiteAdministration
from .site.adoption import (
    PROTOCOL as ADOPTION_PROTOCOL,
    AdoptionError,
    resolve_direct_peer,
)


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
MANIFEST_CODE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
REGISTRY_DIGEST_RE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
WATCHDOG_PROTOCOL_VERSION = 3
MANAGED_LABEL = "io.letsinfer.managed"
MANIFEST_SHA_LABEL = "io.letsinfer.manifest-sha256"
RUNTIME_DIGEST_LABEL = "io.letsinfer.runtime-digest"
RELEASE_LABEL = "io.letsinfer.release"
MODEL_LABEL = "io.letsinfer.model"
PORT_LABEL = "io.letsinfer.port"
SECURITY_LABEL = "io.letsinfer.security"
ENGINE_LABEL = "io.letsinfer.engine"
TARGET_PLATFORM_LABEL = "io.letsinfer.target-platform"
TARGET_ID_LABEL = "io.letsinfer.target"
ACCELERATOR_ARCHITECTURE_LABEL = "io.letsinfer.accelerator-architecture"
MEMORY_MODEL_LABEL = "io.letsinfer.memory-model"
GPU_COUNT_LABEL = "io.letsinfer.gpu-count"
GPU_PARTITIONING_LABEL = "io.letsinfer.gpu-partitioning"
GROUP_ID_LABEL = "io.letsinfer.group"
GROUP_MEMBER_LABEL = "io.letsinfer.group-member"
GROUP_ROLE_LABEL = "io.letsinfer.group-role"
SECURITY_PROFILE = "tls-api-key-v1"
SERVICE_CONFIG_VERSION = 3
CORE_SOURCE_MANIFEST = "SOURCE-MANIFEST.json"
SERVICE_NAME = "letsinfer.service"
ENGINE_SERVICE_NAME = "letsinfer-engine.service"
GATEWAY_SERVICE_NAME = "letsinfer-gateway.service"
SITE_SERVICE_NAME = "letsinfer-site.service"
RECOVERY_SERVICE_NAME = "letsinfer-recovery.service"
RECOVERY_TIMER_NAME = "letsinfer-recovery.timer"


def _macos_service_label(name: str) -> str | None:
    return {
        SITE_SERVICE_NAME: macos_services.SITE_LABEL,
        GATEWAY_SERVICE_NAME: macos_services.GATEWAY_LABEL,
    }.get(name)
CONTROL_PLANE_MEMORY_HIGH_BYTES = 24 * 1024 * 1024
CONTROL_PLANE_MEMORY_LIMIT_BYTES = 30 * 1024 * 1024
SITE_AGENT_MEMORY_HIGH_BYTES = 64 * 1024 * 1024
SITE_AGENT_MEMORY_LIMIT_BYTES = 96 * 1024 * 1024
SITE_AGENT_TASK_LIMIT = 32
GATEWAY_MEMORY_HIGH_BYTES = 64 * 1024 * 1024
GATEWAY_MEMORY_LIMIT_BYTES = 96 * 1024 * 1024
PROTECTION_STATE_NAME = "protected-engine.state"
PROTECTION_ACK_NAME = "protected-engine.ack"
PROTECTION_TRIP_NAME = "protection-trip.json"
PROTECTION_ROOT_NAME = "protected-engines"
WATCHDOG_PUBLIC_STATE_DIRECTORY = "service-state"
CONTROLLER_PAIRING_PROTOCOL = "letsinfer-controller-pair-v1"
CONTROLLER_PAIRING_PORT = 9769
CONTROLLER_PAIRING_TIMEOUT_SECONDS = 180
CONTROLLER_PAIRING_MIN_TIMEOUT_SECONDS = 30
CONTROLLER_CERTIFICATE_DAYS = 36500
CONTROLLER_MAX = 64
MIN_API_KEY_BYTES = 32

# Full branding is reserved for help and health/status views. Public mutations
# use one compact, interactive stderr activity/result line while their durable
# result (including one-time secrets) remains byte-for-byte on stdout.
ACTION_PROGRESS: Mapping[str, tuple[str, str]] = {
    "setup": ("Creating the site", "Site ready"),
    "update": ("Updating Let's Infer core", "Core updated"),
    "site.move": ("Preparing the site move", "Site move ready"),
    "topology.probe": ("Probing the member link", "Member link verified"),
    "topology.plan": ("Planning model placement", "Placement plan ready"),
    "member.prepare": ("Preparing the member identity", "Member identity ready"),
    "member.join": ("Joining the site", "Site joined"),
    "member.invite": ("Creating the member invitation", "Member invitation ready"),
    "member.approve": ("Approving the member", "Member approved"),
    "member.sync": ("Refreshing member facts", "Member facts refreshed"),
    "member.drain": ("Draining the member", "Member drained"),
    "member.resume": ("Resuming the member", "Member active"),
    "member.remove": ("Removing the member", "Member removed"),
    "alias.set": ("Saving the model alias", "Model alias saved"),
    "alias.remove": ("Removing the model alias", "Model alias removed"),
    "pack": ("Building the runtime pack", "Runtime pack built"),
    "derive": ("Deriving the runtime", "Runtime derived"),
    "upgrade": ("Resolving the runtime upgrade", "Runtime upgraded"),
    "rollback": ("Restoring the previous runtime", "Runtime restored"),
    "verify": ("Verifying the runtime", "Runtime verified"),
    "acquire": ("Acquiring the model", "Model acquired"),
    "install": ("Installing the runtime", "Runtime installed"),
    "serve": ("Starting inference", "Inference ready"),
    "start": ("Starting inference", "Inference ready"),
    "restart": ("Restarting inference", "Inference ready"),
    "recover": ("Recovering inference", "Inference recovered"),
    "expose": ("Enabling public inference", "Public inference enabled"),
    "unexpose": ("Disabling public inference", "Public inference disabled"),
    "pair": ("Opening controller pairing", "Pairing session closed"),
    "controllers.forget": ("Revoking the controller", "Controller revoked"),
    "key.create": ("Creating the API key", "API key created"),
    "key.rotate": ("Rotating the API key", "API key rotated"),
    "key.revoke": ("Revoking the API key", "API key revoked"),
    "key.policy": ("Updating the API key policy", "API key policy updated"),
    "stop": ("Stopping inference", "Inference stopped"),
    "uninstall": ("Removing the service", "Service removed"),
}


class LetsInferError(RuntimeError):
    """A user-actionable release or launch error."""


def normalize_platform(value: str) -> str:
    """Return the canonical Docker-style Linux platform name."""
    lowered = value.strip().lower()
    if "/" in lowered:
        system_name, architecture = lowered.split("/", 1)
    else:
        system_name, architecture = "linux", lowered
    architecture = {
        "aarch64": "arm64",
        "x86_64": "amd64",
    }.get(architecture, architecture)
    return f"{system_name}/{architecture}"


def host_platform() -> str:
    return normalize_platform(f"{platform.system()}/{platform.machine()}")


def target_contract(manifest: dict[str, Any]) -> dict[str, Any]:
    """Resolve the manifest's required portable target capability contract."""
    target = manifest.get("target")
    if not isinstance(target, dict):
        raise LetsInferError("manifest.target must be dict")
    try:
        return validate_target_contract(target, "manifest.target")
    except RuntimePackError as error:
        raise LetsInferError(str(error)) from error


def source_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[1]


def releases_dir() -> pathlib.Path:
    override = os.environ.get("LETSINFER_RELEASES_DIR")
    return pathlib.Path(override) if override else source_root() / "releases"


def expanded_path(value: str | os.PathLike[str]) -> pathlib.Path:
    return pathlib.Path(value).expanduser().resolve(strict=False)


def absolute_user_path(value: str | os.PathLike[str]) -> pathlib.Path:
    return pathlib.Path(os.path.abspath(pathlib.Path(value).expanduser()))


def default_plugin_root(
    manifest: dict[str, Any], manifest_sha256: str
) -> pathlib.Path:
    plugins = manifest.get("runtime_plugins")
    if isinstance(plugins, dict) and isinstance(plugins.get("default_root"), str):
        return expanded_path(plugins["default_root"]) / manifest_sha256
    return (
        site_data_root()
        / "runtime"
        / manifest["release"]
        / manifest_sha256
    )


def default_store_root(manifest: dict[str, Any]) -> pathlib.Path:
    return pathlib.Path.home() / ".cache/letsinfer/prefix-store" / manifest["release"]


def default_runtime_cache_root(manifest: dict[str, Any]) -> pathlib.Path:
    image_id = manifest["image"]["immutable_id"].removeprefix("sha256:")
    return pathlib.Path.home() / ".cache/letsinfer/runtime" / image_id


def default_api_key_path() -> pathlib.Path:
    return site_config_root() / "api-key"


def default_engine_api_key_path() -> pathlib.Path:
    return site_config_root() / "engine/api-key"


def default_tls_cert_path() -> pathlib.Path:
    return site_config_root() / "tls/server.crt"


def default_tls_key_path() -> pathlib.Path:
    return site_config_root() / "tls/server.key"


def default_control_parent() -> pathlib.Path:
    return site_data_root() / "control"


def default_watchdog_runtime_parent() -> pathlib.Path:
    return site_data_root() / "watchdog/runtime"


def default_watchdog_data_root() -> pathlib.Path:
    return site_data_root() / "watchdog/data-v1"


def default_gateway_telemetry_path() -> pathlib.Path:
    return site_data_root() / "gateway/telemetry.state"


def default_engine_group_root() -> pathlib.Path:
    return site_data_root() / "engine-groups"


def default_watchdog_cert_path() -> pathlib.Path:
    return site_config_root() / "watchdog/server.crt"


def default_watchdog_key_path() -> pathlib.Path:
    return site_config_root() / "watchdog/server.key"


def default_watchdog_controller_ca_path() -> pathlib.Path:
    return site_config_root() / "watchdog/controller-ca.crt"


def default_watchdog_controller_ca_key_path() -> pathlib.Path:
    return site_config_root() / "watchdog/controller-ca.key"


def default_watchdog_local_controller_cert_path() -> pathlib.Path:
    return site_config_root() / "watchdog/local-controller.crt"


def default_watchdog_local_controller_key_path() -> pathlib.Path:
    return site_config_root() / "watchdog/local-controller.key"


def default_installation_identity_path() -> pathlib.Path:
    return site_identity_path()


def default_controller_allowlist_path() -> pathlib.Path:
    return site_config_root() / "watchdog/controllers.allow"


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise LetsInferError(f"cannot read manifest {path}: {error}") from error
    if not isinstance(value, dict):
        raise LetsInferError(f"manifest {path} is not a JSON object")
    return value


def _require(mapping: dict[str, Any], key: str, expected: type, where: str) -> Any:
    value = mapping.get(key)
    if not isinstance(value, expected):
        raise LetsInferError(f"{where}.{key} must be {expected.__name__}")
    return value


def _reject_unknown_fields(
    mapping: dict[str, Any], allowed: set[str], where: str
) -> None:
    unknown = set(mapping) - allowed
    if unknown:
        raise LetsInferError(
            f"{where} has unsupported fields: {', '.join(sorted(unknown))}"
        )


def _validate_artifact_entries(entries: Any, where: str) -> None:
    if not isinstance(entries, list) or not entries:
        raise LetsInferError(f"{where} must be a non-empty list")
    paths: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise LetsInferError(f"{where}[{index}] must be an object")
        allowed_fields = {"path", "sha256"}
        if where == "runtime_plugins.artifacts":
            allowed_fields.add("source_path")
        _reject_unknown_fields(entry, allowed_fields, f"{where}[{index}]")
        path = _require(entry, "path", str, f"{where}[{index}]")
        digest = _require(entry, "sha256", str, f"{where}[{index}]")
        pure = pathlib.PurePosixPath(path)
        if not path or pure.is_absolute() or ".." in pure.parts or "." in pure.parts:
            raise LetsInferError(f"{where}[{index}].path must be relative and contained")
        if path in paths:
            raise LetsInferError(f"duplicate artifact path: {path}")
        if not SHA256_RE.fullmatch(digest):
            raise LetsInferError(f"{where}[{index}].sha256 is not a SHA-256")
        source_path = entry.get("source_path")
        if source_path is not None:
            if not isinstance(source_path, str):
                raise LetsInferError(f"{where}[{index}].source_path must be str")
            source_pure = pathlib.PurePosixPath(source_path)
            if (
                not source_path
                or source_pure.is_absolute()
                or ".." in source_pure.parts
                or "." in source_pure.parts
            ):
                raise LetsInferError(
                    f"{where}[{index}].source_path must be relative and contained"
                )
        paths.add(path)


def _validate_stable_evidence(
    manifest: dict[str, Any], adapter: Any
) -> None:
    artifacts = {
        entry["path"]: entry["sha256"]
        for entry in manifest.get("source_artifacts", [])
    }
    gate = manifest["serving"]["gate"]
    common = _require(gate, "common", dict, "manifest.serving.gate")
    engine = _require(gate, "engine", dict, "manifest.serving.gate")
    expected_contracts = {
        "common": "letsinfer-openai-v1-common",
        "engine": evidence_contract_for(manifest),
    }
    commits: set[str] = set()
    references: set[str] = set()
    for lane_name, lane in (("common", common), ("engine", engine)):
        where = f"manifest.serving.gate.{lane_name}"
        if not isinstance(lane, dict):
            raise LetsInferError(f"{where} must be an object")
        _reject_unknown_fields(
            lane,
            {"contract", "measured_commit", "evidence_reference", "results_sha256"},
            where,
        )
        contract = _require(lane, "contract", str, where)
        if contract != expected_contracts[lane_name]:
            raise LetsInferError(
                f"{where}.contract must be {expected_contracts[lane_name]!r}"
            )
        commit = _require(lane, "measured_commit", str, where)
        if not re.fullmatch(r"[0-9a-f]{40}", commit):
            raise LetsInferError(f"{where}.measured_commit must be full 40-hex")
        commits.add(commit)
        reference = _require(lane, "evidence_reference", str, where)
        pure = pathlib.PurePosixPath(reference)
        if (
            not reference.startswith("evidence/")
            or pure.is_absolute()
            or ".." in pure.parts
            or "." in pure.parts
        ):
            raise LetsInferError(
                f"{where}.evidence_reference must be a contained evidence/ path"
            )
        digest = _require(lane, "results_sha256", str, where)
        if not SHA256_RE.fullmatch(digest):
            raise LetsInferError(f"{where}.results_sha256 is invalid")
        if artifacts.get(reference) != digest:
            raise LetsInferError(
                f"{where}.evidence_reference must be source-pinned with its results SHA-256"
            )
        if reference in references:
            raise LetsInferError("stable serving evidence references must be distinct")
        references.add(reference)
    if len(commits) != 1 or gate["measured_commit"] not in commits:
        raise LetsInferError("serving common, engine, and gate commits must match")
    evidence_directory = pathlib.PurePosixPath(gate["evidence_directory"])
    if (
        not gate["evidence_directory"].startswith("evidence/")
        or evidence_directory.is_absolute()
        or ".." in evidence_directory.parts
        or "." in evidence_directory.parts
    ):
        raise LetsInferError("manifest.serving.gate.evidence_directory must be portable")
    if gate["results_sha256"] != engine["results_sha256"]:
        raise LetsInferError("serving gate results must identify its engine evidence")


def validate_manifest(manifest: dict[str, Any]) -> None:
    prose_fields = {"comment", "comments", "description", "note", "notes", "reason"}

    def reject_prose_fields(value: Any, where: str) -> None:
        if isinstance(value, dict):
            forbidden = prose_fields.intersection(value)
            if forbidden:
                raise LetsInferError(
                    f"{where} contains forbidden prose fields: "
                    + ", ".join(sorted(forbidden))
                )
            for key, child in value.items():
                reject_prose_fields(child, f"{where}.{key}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                reject_prose_fields(child, f"{where}[{index}]")
        elif isinstance(value, str) and any(character.isspace() for character in value):
            raise LetsInferError(f"{where} must not contain prose or whitespace")

    if not isinstance(manifest, dict):
        raise LetsInferError("manifest must be an object")
    reject_prose_fields(manifest, "manifest")
    if "runtime" in manifest:
        raise LetsInferError(
            "manifest.runtime is unsupported; native engine configuration belongs "
            "in manifest.engine.arguments and manifest.engine.environment"
        )
    _reject_unknown_fields(
        manifest,
        {
            "schema_version",
            "release",
            "status",
            "target",
            "engine",
            "model",
            "artifacts",
            "image",
            "source_artifacts",
            "runtime_plugins",
            "container",
            "watchdog",
            "cache",
            "serving",
            "derivation",
        },
        "manifest",
    )
    if type(manifest.get("schema_version")) is not int or manifest.get("schema_version") != 1:
        raise LetsInferError("unsupported manifest schema_version")
    _require(manifest, "release", str, "manifest")
    status = _require(manifest, "status", str, "manifest")
    if status not in {"candidate", "stable"}:
        raise LetsInferError("manifest.status must be candidate or stable")
    target = target_contract(manifest)

    model = _require(manifest, "model", dict, "manifest")
    for key in ("alias", "id", "artifact"):
        _require(model, key, str, "manifest.model")
    acquisition_image = _require(
        model, "acquisition_image", str, "manifest.model"
    )
    if not REGISTRY_DIGEST_RE.fullmatch(acquisition_image):
        raise LetsInferError("manifest.model.acquisition_image must be digest-pinned")

    image = _require(manifest, "image", dict, "manifest")
    _reject_unknown_fields(
        image,
        {"distribution", "reference", "immutable_id", "base"},
        "manifest.image",
    )
    distribution = _require(image, "distribution", str, "manifest.image")
    _require(image, "reference", str, "manifest.image")
    immutable_id = _require(image, "immutable_id", str, "manifest.image")
    base = _require(image, "base", str, "manifest.image")
    if distribution not in {"local-image-id", "registry-digest"}:
        raise LetsInferError("manifest.image.distribution is invalid")
    if not IMAGE_ID_RE.fullmatch(immutable_id):
        raise LetsInferError("manifest.image.immutable_id must be an exact image ID")
    if not REGISTRY_DIGEST_RE.fullmatch(base):
        raise LetsInferError("manifest.image.base must be digest-pinned")
    if (
        distribution == "registry-digest"
        and not REGISTRY_DIGEST_RE.fullmatch(image["reference"])
    ):
        raise LetsInferError("registry image reference must be digest-pinned")
    if distribution == "local-image-id" and image["reference"] != immutable_id:
        raise LetsInferError("local image reference must equal its immutable image ID")

    source_artifacts = manifest.get("source_artifacts")
    if source_artifacts is not None:
        _validate_artifact_entries(source_artifacts, "source_artifacts")
    try:
        adapter = adapter_for(manifest)
    except EngineManifestError as error:
        raise LetsInferError(str(error)) from error
    if adapter.requires_runtime_plugins:
        plugins = _require(manifest, "runtime_plugins", dict, "manifest")
        expected_plugin_fields = (
            {"default_root", "artifacts", "wheel_builder"}
            if adapter.name == "vllm"
            else {"default_root", "artifacts", "native_builder"}
        )
        _reject_unknown_fields(
            plugins, expected_plugin_fields, "manifest.runtime_plugins"
        )
        _require(plugins, "default_root", str, "manifest.runtime_plugins")
        _validate_artifact_entries(plugins.get("artifacts"), "runtime_plugins.artifacts")
        runtime_paths = {entry["path"] for entry in plugins["artifacts"]}
        if adapter.name == "vllm":
            required_runtime_paths = {
                "letsinfer_prefix_connector/__init__.py",
                "letsinfer_prefix_connector/connector.py",
                "prewarm_prefixes.py",
            }
            if not required_runtime_paths.issubset(runtime_paths):
                raise LetsInferError("runtime plugin set omits connector or prewarm files")
            if len([path for path in runtime_paths if path.endswith(".whl")]) != 1:
                raise LetsInferError("runtime plugin set must pin exactly one wheel")
            wheel_path = next(path for path in runtime_paths if path.endswith(".whl"))
            platform_architecture = target["platform"].split("/", 1)[1]
            wheel_architectures = {
                "arm64": ("aarch64", "arm64"),
                "amd64": ("x86_64", "amd64"),
            }.get(platform_architecture, (platform_architecture,))
            wheel_name = pathlib.PurePosixPath(wheel_path).name
            platform_tags = wheel_name[:-4].rsplit("-", 1)[-1].split(".")
            if not any(
                tag == architecture or tag.endswith(f"_{architecture}")
                for tag in platform_tags
                for architecture in wheel_architectures
            ):
                raise LetsInferError(
                    "runtime wheel architecture does not match manifest.target.platform"
                )
            builder = _require(
                plugins, "wheel_builder", dict, "manifest.runtime_plugins"
            )
            _reject_unknown_fields(
                builder,
                {"image", "source_root", "source_date_epoch", "arguments"},
                "manifest.runtime_plugins.wheel_builder",
            )
            builder_image = _require(
                builder, "image", str, "manifest.runtime_plugins.wheel_builder"
            )
            if not REGISTRY_DIGEST_RE.fullmatch(builder_image):
                raise LetsInferError("runtime wheel builder image must be digest-pinned")
            builder_source_root = _require(
                builder, "source_root", str, "manifest.runtime_plugins.wheel_builder"
            )
            builder_source = pathlib.PurePosixPath(builder_source_root)
            if builder_source.is_absolute() or ".." in builder_source.parts:
                raise LetsInferError(
                    "runtime wheel builder source_root must be relative and contained"
                )
            if (
                not isinstance(builder.get("source_date_epoch"), int)
                or isinstance(builder.get("source_date_epoch"), bool)
                or builder["source_date_epoch"] <= 0
            ):
                raise LetsInferError(
                    "runtime wheel builder source_date_epoch must be positive"
                )
            arguments = builder.get("arguments")
            if not isinstance(arguments, list) or not arguments or not all(
                isinstance(value, str) and value for value in arguments
            ):
                raise LetsInferError(
                    "runtime wheel builder arguments must be non-empty strings"
                )
        elif adapter.name == "dwarfstar":
            required_runtime_paths = {
                "dwarfstar_gateway.py",
                "libletsinfer_prefix_capi.so",
            }
            if runtime_paths != required_runtime_paths:
                raise LetsInferError(
                    "DwarfStar runtime plugin set must contain its gateway and "
                    "Let's Infer native cache bridge"
                )
            if "wheel_builder" in plugins:
                raise LetsInferError(
                    "DwarfStar runtime plugins cannot declare a wheel builder"
                )
            builder = _require(
                plugins, "native_builder", dict, "manifest.runtime_plugins"
            )
            _reject_unknown_fields(
                builder,
                {
                    "image",
                    "source_root",
                    "source_date_epoch",
                    "entrypoint",
                    "arguments",
                    "output",
                },
                "manifest.runtime_plugins.native_builder",
            )
            builder_image = _require(
                builder, "image", str, "manifest.runtime_plugins.native_builder"
            )
            if not REGISTRY_DIGEST_RE.fullmatch(builder_image):
                raise LetsInferError(
                    "runtime native builder image must be digest-pinned"
                )
            builder_source_root = _require(
                builder,
                "source_root",
                str,
                "manifest.runtime_plugins.native_builder",
            )
            builder_source = pathlib.PurePosixPath(builder_source_root)
            if builder_source.is_absolute() or ".." in builder_source.parts:
                raise LetsInferError(
                    "runtime native builder source_root must be relative and contained"
                )
            if (
                not isinstance(builder.get("source_date_epoch"), int)
                or isinstance(builder.get("source_date_epoch"), bool)
                or builder["source_date_epoch"] <= 0
            ):
                raise LetsInferError(
                    "runtime native builder source_date_epoch must be positive"
                )
            entrypoint = builder.get("entrypoint")
            if not isinstance(entrypoint, str) or not entrypoint:
                raise LetsInferError(
                    "runtime native builder entrypoint must be non-empty"
                )
            arguments = builder.get("arguments")
            if not isinstance(arguments, list) or not arguments or not all(
                isinstance(value, str) and value for value in arguments
            ):
                raise LetsInferError(
                    "runtime native builder arguments must be non-empty strings"
                )
            output_value = builder.get("output")
            if not isinstance(output_value, str) or not output_value:
                raise LetsInferError(
                    "runtime native builder output must be non-empty"
                )
            output = pathlib.PurePosixPath(output_value)
            if output.is_absolute() or any(
                part in {"", ".", ".."} for part in output.parts
            ):
                raise LetsInferError(
                    "runtime native builder output must be relative and contained"
                )
            if output.name != "libletsinfer_prefix_capi.so":
                raise LetsInferError(
                    "runtime native builder output must be libletsinfer_prefix_capi.so"
                )
    elif "runtime_plugins" in manifest:
        raise LetsInferError(
            f"{adapter.name} releases cannot declare runtime_plugins"
        )

    container = _require(manifest, "container", dict, "manifest")
    container_fields = {
        "memory_bytes",
        "shm_bytes",
        "cpuset_cpus",
        "min_available_gib",
        "runtime_min_available_gib",
        "startup_timeout_seconds",
        "model_cache",
        "min_gpu_free_gib",
        "runtime_min_gpu_free_gib",
    }
    _reject_unknown_fields(container, container_fields, "manifest.container")
    cpuset_cpus = container.get("cpuset_cpus")
    if cpuset_cpus is not None:
        if (
            not isinstance(cpuset_cpus, str)
            or not cpuset_cpus
            or len(cpuset_cpus) > 1024
            or re.fullmatch(r"(?:0|[1-9][0-9]*)(?:-(?:0|[1-9][0-9]*))?(?:,(?:0|[1-9][0-9]*)(?:-(?:0|[1-9][0-9]*))?)*", cpuset_cpus)
            is None
        ):
            raise LetsInferError(
                "manifest.container.cpuset_cpus must be a canonical Docker CPU set"
            )
        previous_end = -1
        for clause in cpuset_cpus.split(","):
            start_text, separator, end_text = clause.partition("-")
            start = int(start_text)
            end = int(end_text) if separator else start
            if end < start or start <= previous_end or end > 8191:
                raise LetsInferError(
                    "manifest.container.cpuset_cpus ranges must be ascending, "
                    "non-overlapping CPU indices through 8191"
                )
            previous_end = end
    for key in (
        "memory_bytes",
        "shm_bytes",
        "min_available_gib",
        "runtime_min_available_gib",
        "startup_timeout_seconds",
    ):
        if (
            not isinstance(container.get(key), int)
            or isinstance(container.get(key), bool)
            or container[key] <= 0
        ):
            raise LetsInferError(f"manifest.container.{key} must be positive")
    runtime_min_available_gib = container["runtime_min_available_gib"]
    if (
        not isinstance(runtime_min_available_gib, int)
        or isinstance(runtime_min_available_gib, bool)
        or runtime_min_available_gib <= 0
    ):
        raise LetsInferError(
            "manifest.container.runtime_min_available_gib must be positive"
        )
    if runtime_min_available_gib >= container["min_available_gib"]:
        raise LetsInferError(
            "manifest.container.runtime_min_available_gib must be below the launch floor"
        )
    gpu_floor_keys = ("min_gpu_free_gib", "runtime_min_gpu_free_gib")
    if target["memory"]["topology"] == "unified":
        if any(key in container for key in gpu_floor_keys):
            raise LetsInferError(
                "unified-memory targets cannot declare separate GPU-memory floors"
            )
    else:
        for key in gpu_floor_keys:
            if (
                not isinstance(container.get(key), int)
                or isinstance(container.get(key), bool)
                or container[key] <= 0
            ):
                raise LetsInferError(f"manifest.container.{key} must be positive")
        if container["runtime_min_gpu_free_gib"] >= container["min_gpu_free_gib"]:
            raise LetsInferError(
                "manifest.container.runtime_min_gpu_free_gib must be below the launch floor"
            )
    _require(container, "model_cache", str, "manifest.container")

    watchdog = _require(manifest, "watchdog", dict, "manifest")
    _reject_unknown_fields(
        watchdog,
        {
            "listen",
            "protocol_version",
            "port",
            "sample_interval_ms",
            "flush_interval_ms",
            "max_controllers",
            "memory_high_bytes",
            "memory_max_bytes",
            "protection",
            "build",
        },
        "manifest.watchdog",
    )
    _require(watchdog, "listen", str, "manifest.watchdog")
    for key in (
        "protocol_version",
        "port",
        "sample_interval_ms",
        "flush_interval_ms",
        "max_controllers",
        "memory_high_bytes",
        "memory_max_bytes",
    ):
        if (
            not isinstance(watchdog.get(key), int)
            or isinstance(watchdog.get(key), bool)
            or watchdog[key] <= 0
        ):
            raise LetsInferError(f"manifest.watchdog.{key} must be positive")
    if watchdog["protocol_version"] != WATCHDOG_PROTOCOL_VERSION:
        raise LetsInferError(
            "manifest.watchdog.protocol_version must be "
            f"{WATCHDOG_PROTOCOL_VERSION}"
        )
    if watchdog["port"] not in range(1, 65536):
        raise LetsInferError("manifest.watchdog.port must be between 1 and 65535")
    if watchdog["max_controllers"] > 4:
        raise LetsInferError("manifest.watchdog.max_controllers cannot exceed 4")
    if watchdog["memory_high_bytes"] > watchdog["memory_max_bytes"]:
        raise LetsInferError("manifest.watchdog memory high cannot exceed memory max")
    if watchdog["memory_max_bytes"] != CONTROL_PLANE_MEMORY_LIMIT_BYTES:
        raise LetsInferError(
            f"manifest.watchdog.memory_max_bytes must be {CONTROL_PLANE_MEMORY_LIMIT_BYTES}"
        )
    protection = _require(watchdog, "protection", dict, "manifest.watchdog")
    _reject_unknown_fields(
        protection,
        {
            "warning_available_bytes",
            "graceful_available_bytes",
            "emergency_available_bytes",
            "swap_stop_bytes",
            "psi_some_us",
            "psi_full_us",
            "state_failures",
            "containment_grace_ms",
        },
        "manifest.watchdog.protection",
    )
    for key in (
        "warning_available_bytes",
        "graceful_available_bytes",
        "emergency_available_bytes",
        "swap_stop_bytes",
        "psi_some_us",
        "psi_full_us",
        "state_failures",
        "containment_grace_ms",
    ):
        if (
            not isinstance(protection.get(key), int)
            or isinstance(protection[key], bool)
            or protection[key] <= 0
        ):
            raise LetsInferError(f"manifest.watchdog.protection.{key} must be positive")
    if not (
        protection["warning_available_bytes"]
        > protection["graceful_available_bytes"]
        > protection["emergency_available_bytes"]
    ):
        raise LetsInferError(
            "manifest.watchdog protection memory thresholds must satisfy "
            "warning > graceful > emergency"
        )
    runtime_floor_bytes = container["runtime_min_available_gib"] * (1 << 30)
    if protection["warning_available_bytes"] < runtime_floor_bytes:
        raise LetsInferError(
            "manifest.watchdog protection warning threshold must be at least the "
            "runtime host-memory floor"
        )
    if protection["state_failures"] < 2:
        raise LetsInferError("manifest.watchdog protection state failures must be at least 2")
    if protection["containment_grace_ms"] > 30000:
        raise LetsInferError("manifest.watchdog protection grace cannot exceed 30000 ms")
    build = _require(watchdog, "build", dict, "manifest.watchdog")
    _reject_unknown_fields(
        build,
        {"source_root", "target", "output"},
        "manifest.watchdog.build",
    )
    for key, expected in (
        ("source_root", "watchdog"),
        ("target", "letsinfer_watchdog"),
        ("output", "letsinfer-watchdog"),
    ):
        if _require(build, key, str, "manifest.watchdog.build") != expected:
            raise LetsInferError(
                f"manifest.watchdog.build.{key} must be {expected!r}"
            )

    serving = _require(manifest, "serving", dict, "manifest")
    allowed_serving_fields = {
        "qualified",
        "max_connections",
        "max_active_requests",
        "max_context_tokens",
        "gate",
        "blocked_by",
    }
    unknown_serving_fields = set(serving) - allowed_serving_fields
    if unknown_serving_fields:
        raise LetsInferError(
            "manifest.serving has unsupported fields; native engine settings belong "
            "in manifest.engine.arguments or manifest.engine.environment: "
            + ", ".join(sorted(unknown_serving_fields))
        )
    if not isinstance(serving.get("qualified"), bool):
        raise LetsInferError("manifest.serving.qualified must be boolean")
    for key in ("max_connections", "max_active_requests", "max_context_tokens"):
        value = serving.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise LetsInferError(f"manifest.serving.{key} must be positive")
    if serving["max_active_requests"] > serving["max_connections"]:
        raise LetsInferError(
            "manifest.serving.max_active_requests cannot exceed max_connections"
        )
    gate = _require(serving, "gate", dict, "manifest.serving")
    _reject_unknown_fields(
        gate,
        {
            "measured_commit",
            "bench_block",
            "evidence_directory",
            "results_sha256",
            "common",
            "engine",
        },
        "manifest.serving.gate",
    )
    for key in ("measured_commit", "bench_block", "evidence_directory", "results_sha256"):
        _require(gate, key, str, "manifest.serving.gate")
    if not MANIFEST_CODE_RE.fullmatch(gate["bench_block"]):
        raise LetsInferError("manifest.serving.gate.bench_block must be a machine identifier")
    if not SHA256_RE.fullmatch(gate["results_sha256"]):
        raise LetsInferError("manifest.serving.gate.results_sha256 is invalid")
    if not serving["qualified"]:
        blocked_by = serving.get("blocked_by")
        if not isinstance(blocked_by, str) or not MANIFEST_CODE_RE.fullmatch(blocked_by):
            raise LetsInferError(
                "unqualified serving configuration requires a machine-identifier blocked_by"
            )

    derivation = manifest.get("derivation")
    if derivation is not None:
        if not isinstance(derivation, dict):
            raise LetsInferError("manifest.derivation must be an object")
        _reject_unknown_fields(
            derivation,
            {
                "name",
                "parent_release",
                "parent_manifest_sha256",
                "without",
                "supplied_engine_arguments",
                "resolved_engine_arguments",
                "resolved_arguments_sha256",
                "diff",
            },
            "manifest.derivation",
        )
        for key in ("name", "parent_release", "parent_manifest_sha256"):
            _require(derivation, key, str, "manifest.derivation")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", derivation["name"]):
            raise LetsInferError("manifest.derivation.name contains unsupported characters")
        if not SHA256_RE.fullmatch(derivation["parent_manifest_sha256"]):
            raise LetsInferError("manifest.derivation.parent_manifest_sha256 is invalid")
        if manifest["status"] != "candidate" or serving["qualified"]:
            raise LetsInferError("derived runtimes must remain unqualified candidates")
        if model["alias"] != derivation["name"]:
            raise LetsInferError("derived runtime alias must equal manifest.derivation.name")
        without = derivation.get("without")
        if not isinstance(without, list) or not all(
            isinstance(value, str) and "=" not in value for value in without
        ):
            raise LetsInferError("manifest.derivation.without must contain option names")
        try:
            for value in without:
                clause_key([value])
        except RuntimePackError as error:
            raise LetsInferError(str(error)) from error
        resolved = derivation.get("resolved_engine_arguments")
        if not isinstance(resolved, list) or not resolved:
            raise LetsInferError(
                "manifest.derivation.resolved_engine_arguments must be non-empty"
            )
        for index, clause in enumerate(resolved):
            if (
                not isinstance(clause, list)
                or not clause
                or not all(isinstance(token, str) and token for token in clause)
            ):
                raise LetsInferError(
                    f"manifest.derivation.resolved_engine_arguments[{index}] is invalid"
                )
            try:
                clause_key(clause)
            except RuntimePackError as error:
                raise LetsInferError(str(error)) from error
        resolved_digest = _require(
            derivation, "resolved_arguments_sha256", str, "manifest.derivation"
        )
        actual_digest = hashlib.sha256(
            json.dumps(
                list(flatten_clauses(resolved)),
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
        if resolved_digest != actual_digest:
            raise LetsInferError("manifest.derivation resolved argument digest mismatch")
        difference = derivation.get("diff")
        if not isinstance(difference, dict) or set(difference) != {
            "removed",
            "replaced",
            "added",
        }:
            raise LetsInferError("manifest.derivation.diff is invalid")

    try:
        validate_engine_manifest(manifest)
        launch_for(manifest, serving, 8000)
    except EngineManifestError as error:
        raise LetsInferError(str(error)) from error

    if status == "stable":
        if distribution != "registry-digest":
            raise LetsInferError("stable releases require a pullable registry digest")
        if not persistent_cache_for(manifest):
            raise LetsInferError(
                f"stable {adapter.name} releases require a qualified persistent-cache adapter"
            )
        if not serving["qualified"]:
            raise LetsInferError("stable release has an unqualified serving configuration")
        _validate_stable_evidence(manifest, adapter)


def _contained_regular_file(root: pathlib.Path, relative: str) -> pathlib.Path:
    root_resolved = root.resolve(strict=True)
    path = root / relative
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root_resolved)
    except (OSError, ValueError) as error:
        raise LetsInferError(f"pinned artifact escapes its root: {path}") from error
    if path.is_symlink() or not resolved.is_file():
        raise LetsInferError(f"pinned artifact is not a regular in-tree file: {path}")
    return resolved


def verify_artifacts(root: pathlib.Path, entries: Iterable[dict[str, str]]) -> None:
    if root.is_symlink() or not root.is_dir():
        raise LetsInferError(f"artifact root is not a regular directory: {root}")
    for entry in entries:
        try:
            path = _contained_regular_file(root, entry["path"])
        except FileNotFoundError as error:
            raise LetsInferError(f"missing pinned artifact: {root / entry['path']}") from error
        actual = sha256_file(path)
        if actual != entry["sha256"]:
            raise LetsInferError(
                f"artifact SHA-256 mismatch: {path} (expected {entry['sha256']}, got {actual})"
            )


def verify_release_sources(manifest: dict[str, Any], root: pathlib.Path) -> None:
    artifacts = manifest.get("source_artifacts", [])
    verify_artifacts(root, artifacts)
    pinned_paths = {entry["path"] for entry in artifacts}
    adapter = adapter_for(manifest)
    if adapter.requires_runtime_plugins:
        source_hashes = {
            entry["path"]: entry["sha256"] for entry in artifacts
        }
        for entry in manifest["runtime_plugins"]["artifacts"]:
            if entry["path"].endswith((".whl", ".so")):
                continue
            source_path = entry.get("source_path")
            if not isinstance(source_path, str):
                raise LetsInferError(
                    f"runtime artifact {entry['path']} has no explicit source_path"
                )
            if source_path in source_hashes and source_hashes[source_path] != entry["sha256"]:
                raise LetsInferError(
                    f"runtime artifact must have an identical source pin: {source_path}"
                )
    if adapter.name != "vllm":
        return

    base_lines = [
        line.strip()
        for line in (root / "image/BASE_IMAGE").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if base_lines != [manifest["image"]["base"]]:
        raise LetsInferError("manifest base image does not match image/BASE_IMAGE")

    series = [
        line.strip()
        for line in (root / "patches/series").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    expected = {f"patches/{name}" for name in series}
    expected.update(f"patches/{name.removesuffix('.patch')}.verify.py" for name in series)
    pinned = {
        entry["path"]
        for entry in artifacts
        if entry["path"].startswith("patches/") and entry["path"] != "patches/series"
    }
    if pinned != expected:
        raise LetsInferError("manifest patch artifacts do not exactly match patches/series")

def manifests(
    directory: pathlib.Path | None = None,
) -> list[tuple[pathlib.Path, dict[str, Any]]]:
    explicit_directory = directory is not None or bool(os.environ.get("LETSINFER_RELEASES_DIR"))
    root = directory or releases_dir()
    found: list[tuple[pathlib.Path, dict[str, Any]]] = []
    for path in sorted(root.glob("*.json")):
        if not path.is_file() or path.name.startswith("."):
            continue
        manifest = read_json(path)
        validate_manifest(manifest)
        found.append((path, manifest))
    if not found and explicit_directory:
        raise LetsInferError(f"no release manifests under {root}")
    return found


def manifest_source_root(manifest_path: pathlib.Path) -> pathlib.Path:
    """Return the immutable control root containing a releases/ manifest."""
    if manifest_path.parent.name != "releases":
        return source_root()
    return manifest_path.parent.parent


def installed_runtime_manifests() -> list[tuple[pathlib.Path, dict[str, Any], dict[str, Any]]]:
    found: list[tuple[pathlib.Path, dict[str, Any], dict[str, Any]]] = []
    try:
        receipts = selections()
    except RuntimePackError as error:
        raise LetsInferError(str(error)) from error
    for receipt in receipts:
        object_root = pathlib.Path(receipt["object_root"]).expanduser()
        try:
            pack = verify_descriptor(object_root)
        except RuntimePackError as error:
            raise LetsInferError(str(error)) from error
        if pack.digest != receipt["digest"]:
            raise LetsInferError(
                f"installed runtime receipt digest mismatch: {receipt['name']}"
            )
        control_root = pathlib.Path(receipt["control_root"]).expanduser()
        manifest_path = pathlib.Path(receipt["manifest_path"]).expanduser()
        _, manifest = validate_control_bundle(
            control_root,
            manifest_path,
            sha256_file(manifest_path),
        )
        if (
            pack.descriptor["model"] != receipt["model"]
            or pack.descriptor["engine"] != receipt["engine"]
            or pack.descriptor["target"] != receipt["target"]
            or manifest["model"]["alias"] != receipt["model"]
            or adapter_for(manifest).name != receipt["engine"]
            or target_contract(manifest)["id"] != receipt["target"]
            or target_contract_sha256(target_contract(manifest))
            != receipt["target_contract_sha256"]
        ):
            raise LetsInferError(
                f"installed runtime receipt identity mismatch: {receipt['name']}"
            )
        found.append((manifest_path, manifest, receipt))
    return found


def runtime_receipt_for_manifest(manifest_path: pathlib.Path) -> dict[str, Any] | None:
    target = manifest_path.resolve(strict=False)
    for candidate_path, _, receipt in installed_runtime_manifests():
        if candidate_path.resolve(strict=True) == target:
            return receipt
    return None


def resolve_model(
    name: str,
    engine: str | None = None,
    directory: pathlib.Path | None = None,
    target: str | None = None,
) -> tuple[pathlib.Path, dict[str, Any]]:
    available = manifests(directory)
    runtime_names: dict[tuple[str, str, str], str] = {}
    if directory is None:
        selected_runtimes: dict[
            tuple[str, str, str],
            tuple[pathlib.Path, dict[str, Any], dict[str, Any]],
        ] = {}
        for path, manifest, receipt in installed_runtime_manifests():
            target_id = target_contract(manifest)["id"]
            key = (manifest["model"]["alias"], adapter_for(manifest).name, target_id)
            candidate_rank = receipt["installed_at"]
            current = selected_runtimes.get(key)
            if current is not None:
                current_receipt = current[2]
                current_rank = current_receipt["installed_at"]
                if candidate_rank <= current_rank:
                    continue
            selected_runtimes[key] = (path, manifest, receipt)
        for key in sorted(selected_runtimes):
            path, manifest, receipt = selected_runtimes[key]
            target_id = key[2]
            available = [
                item
                for item in available
                if (
                    item[1]["model"]["alias"],
                    adapter_for(item[1]).name,
                    target_contract(item[1])["id"],
                )
                != key
            ]
            available.append((path, manifest))
            runtime_names[(manifest["release"], adapter_for(manifest).name, target_id)] = receipt[
                "name"
            ]
    matches: list[tuple[pathlib.Path, dict[str, Any]]] = []
    model_id_matches: list[tuple[pathlib.Path, dict[str, Any]]] = []
    for path, manifest in available:
        model = manifest["model"]
        target_id = target_contract(manifest)["id"]
        runtime_name = runtime_names.get(
            (manifest["release"], adapter_for(manifest).name, target_id)
        )
        engine_name = adapter_for(manifest).name
        variant_name = f"{model['alias']}/{engine_name}/{target_id}"
        exact_names = {
            manifest["release"],
            model["alias"],
            runtime_name,
            variant_name,
        }
        if (engine is None or engine_name == engine) and (
            target is None or target_id == target
        ):
            if name in exact_names:
                matches.append((path, manifest))
            elif name == model["id"]:
                model_id_matches.append((path, manifest))
    if not matches:
        matches = model_id_matches
    if len(matches) > 1 and target is None:
        try:
            device = host_device_fingerprint()
        except LetsInferError:
            device = None
        if device is not None:
            compatible = [
                item for item in matches if target_matches(target_contract(item[1]), device)
            ]
            if compatible:
                matches = compatible
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        choices = ", ".join(
            sorted(
                f"{adapter_for(item).name}/{target_contract(item)['id']}:{item['release']}"
                for _, item in matches
            )
        )
        raise LetsInferError(
            f"model name is ambiguous across runtime variants ({choices}); "
            "specify --engine and/or --target"
        )
    raise LetsInferError(f"unknown model: {name}")


def compact_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def docker_command(
    manifest: dict[str, Any],
    *,
    name: str,
    manifest_sha256: str,
    runtime_digest: str | None,
    port: int,
    model_cache: pathlib.Path,
    plugin_root: pathlib.Path,
    store_root: pathlib.Path,
    runtime_cache_root: pathlib.Path,
    api_key_file: pathlib.Path,
    tls_cert_file: pathlib.Path,
    tls_key_file: pathlib.Path,
    group_context: Mapping[str, Any] | None = None,
    group_config_file: pathlib.Path | None = None,
    runtime_artifact_root: pathlib.Path | None = None,
) -> list[str]:
    if not SHA256_RE.fullmatch(manifest_sha256):
        raise LetsInferError("container manifest identity must be a SHA-256")
    if runtime_digest is not None and not SHA256_RE.fullmatch(runtime_digest):
        raise LetsInferError("container runtime identity must be a SHA-256")
    container = manifest["container"]
    adapter = adapter_for(manifest)
    target = target_contract(manifest)
    launch = launch_for(manifest, manifest["serving"], port)
    runtime_command: tuple[str, ...] | None = None
    if group_context is not None:
        required_group = {
            "group_id", "member_id", "rank", "role_rank", "role", "launcher",
            "command", "environment", "port_base", "port_count",
            "inference_endpoint", "readiness",
        }
        if set(group_context) != required_group:
            raise LetsInferError("engine-group container context is invalid")
        if (
            not re.fullmatch(r"[0-9a-f]{32}", str(group_context["group_id"]))
            or not re.fullmatch(r"[0-9a-f]{32}", str(group_context["member_id"]))
            or group_context["port_base"] != port
            or not isinstance(group_context["port_count"], int)
            or isinstance(group_context["port_count"], bool)
            or group_context["port_count"] not in range(1, 33)
            or group_config_file is None
            or runtime_artifact_root is None
        ):
            raise LetsInferError("engine-group container identity is invalid")
        if group_context["launcher"] == "runtime-command":
            raw_command = group_context["command"]
            if not isinstance(raw_command, list) or not raw_command:
                raise LetsInferError("runtime-owned engine-group command is invalid")
            runtime_command = tuple(raw_command)
        elif group_context["launcher"] != "manifest" or group_context["command"] != []:
            raise LetsInferError("engine-group launcher is invalid")
    elif group_config_file is not None or runtime_artifact_root is not None:
        raise LetsInferError("engine-group mounts require a group context")
    inner = None if runtime_command is not None else (
        "set -euo pipefail; umask 077; "
        + launch.shell_setup
        + "exec "
        + shell_command(launch)
    )
    # Startup readiness is verified separately through the authenticated API.
    # Docker health is liveness: long prefills may occupy an engine's HTTP loop,
    # but its kernel listener must remain present for queued requests.
    health_command = f"bash -c ': >/dev/tcp/127.0.0.1/{port}'"
    command = [
        "docker",
        "run",
        "-d",
        "--pull",
        "never",
        "--restart",
        "no",
        "--name",
        name,
        "--label",
        f"{MANAGED_LABEL}=true",
        "--label",
        f"{MANIFEST_SHA_LABEL}={manifest_sha256}",
        *(
            ["--label", f"{RUNTIME_DIGEST_LABEL}={runtime_digest}"]
            if runtime_digest is not None
            else []
        ),
        "--label",
        f"{RELEASE_LABEL}={manifest['release']}",
        "--label",
        f"{MODEL_LABEL}={manifest['model']['alias']}",
        "--label",
        f"{PORT_LABEL}={port}",
        "--label",
        f"{SECURITY_LABEL}={SECURITY_PROFILE}",
        "--label",
        f"{ENGINE_LABEL}={adapter.name}",
        "--label",
        f"{TARGET_ID_LABEL}={target['id']}",
        "--label",
        f"{TARGET_PLATFORM_LABEL}={target['platform']}",
        "--label",
        f"{ACCELERATOR_ARCHITECTURE_LABEL}={target['accelerator']['architecture']}",
        "--label",
        f"{MEMORY_MODEL_LABEL}={target['memory']['topology']}",
        "--label",
        f"{GPU_COUNT_LABEL}={target['accelerator']['count']}",
        "--label",
        f"{GPU_PARTITIONING_LABEL}={target['accelerator']['partitioning']}",
        *(
            [
                "--label", f"{GROUP_ID_LABEL}={group_context['group_id']}",
                "--label", f"{GROUP_MEMBER_LABEL}={group_context['member_id']}",
                "--label", f"{GROUP_ROLE_LABEL}={group_context['role']}",
            ]
            if group_context is not None
            else []
        ),
        "--init",
        "--user",
        f"{os.getuid()}:{os.getgid()}",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges=true",
        "--pids-limit",
        "4096",
        "--stop-timeout",
        "120",
        *(
            [
                "--health-cmd", health_command,
                "--health-interval", "30s",
                "--health-timeout", "5s",
                "--health-retries", "3",
                "--health-start-period", f"{container['startup_timeout_seconds']}s",
            ]
            if runtime_command is None
            else ["--no-healthcheck"]
        ),
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,exec,size=8589934592",
        "--entrypoint",
        runtime_command[0] if runtime_command is not None else "bash",
        "--network",
        "host",
        "--ipc",
        "host",
        "--gpus",
        "all",
        "--memory",
        str(container["memory_bytes"]),
        "--memory-swap",
        str(container["memory_bytes"]),
        *(
            ["--cpuset-cpus", container["cpuset_cpus"]]
            if "cpuset_cpus" in container
            else []
        ),
        "--shm-size",
        str(container["shm_bytes"]),
        "-v",
        f"{runtime_cache_root}:/root",
        "-v",
        f"{model_cache / 'hub'}:/root/.cache/huggingface/hub:ro",
        "-v",
        f"{api_key_file}:/run/secrets/letsinfer-api-key:ro",
        "-v",
        f"{tls_cert_file}:/run/secrets/letsinfer-tls.crt:ro",
        "-v",
        f"{tls_key_file}:/run/secrets/letsinfer-tls.key:ro",
        "-e",
        "HOME=/root",
        "-e",
        "USER=letsinfer",
        "-e",
        "LOGNAME=letsinfer",
    ]
    if group_context is not None:
        group_path = pathlib.Path(group_config_file).expanduser()
        runtime_path = pathlib.Path(runtime_artifact_root).expanduser()
        command.extend([
            "-v", f"{group_path}:/run/letsinfer/group.json:ro",
            "-v", f"{runtime_path}:/opt/letsinfer/runtime-pack:ro",
            "-e", "LETSINFER_GROUP_CONFIG=/run/letsinfer/group.json",
            "-e", f"LETSINFER_GROUP_ID={group_context['group_id']}",
            "-e", f"LETSINFER_MEMBER_ID={group_context['member_id']}",
            "-e", f"LETSINFER_MEMBER_RANK={group_context['rank']}",
            "-e", f"LETSINFER_ROLE={group_context['role']}",
            "-e", f"LETSINFER_ROLE_RANK={group_context['role_rank']}",
            "-e", f"LETSINFER_PORT_BASE={group_context['port_base']}",
            "-e", f"LETSINFER_PORT_COUNT={group_context['port_count']}",
            "-e", f"LETSINFER_ENGINE_PORT={group_context['port_base'] if group_context['inference_endpoint'] else -1}",
            "-e", "LETSINFER_ENGINE_CREDENTIAL_FILE=/run/secrets/letsinfer-api-key",
            "-e", "LETSINFER_TLS_CERT_FILE=/run/secrets/letsinfer-tls.crt",
            "-e", "LETSINFER_TLS_KEY_FILE=/run/secrets/letsinfer-tls.key",
        ])
    if launch.mount_runtime_plugins:
        command.extend(["-v", f"{plugin_root}:/plugins:ro"])
    if launch.mount_prefix_store:
        command.extend(["-v", f"{store_root}:/root/.cache/letsinfer-prefix-store"])
    for key, value in launch.environment:
        command.extend(["-e", f"{key}={value}"])
    if group_context is not None:
        static_environment = group_context["environment"]
        if not isinstance(static_environment, dict):
            raise LetsInferError("engine-group environment is invalid")
        existing_names = {key for key, _value in launch.environment}
        if existing_names.intersection(static_environment):
            raise LetsInferError("runtime group environment cannot replace adapter-owned values")
        for key, value in sorted(static_environment.items()):
            command.extend(["-e", f"{key}={value}"])
    command.append(manifest["image"]["reference"])
    if runtime_command is not None:
        command.extend(runtime_command[1:])
    else:
        command.extend(["-c", str(inner)])
    return command


def parse_mem_available_gib(text: str) -> int:
    for line in text.splitlines():
        fields = line.split()
        if fields and fields[0] == "MemAvailable:" and len(fields) >= 2:
            return int(fields[1]) // 1048576
    raise LetsInferError("MemAvailable is missing from /proc/meminfo")


def parse_mem_total_gib(text: str) -> int:
    for line in text.splitlines():
        fields = line.split()
        if fields and fields[0] == "MemTotal:" and len(fields) >= 2:
            return int(fields[1]) // 1048576
    raise LetsInferError("MemTotal is missing from /proc/meminfo")


def gpu_count() -> int:
    result = run(["nvidia-smi", "-L"], check=False)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise LetsInferError(f"cannot enumerate NVIDIA GPUs: {detail}")
    count = sum(1 for line in result.stdout.splitlines() if line.startswith("GPU "))
    if count == 0:
        raise LetsInferError("nvidia-smi did not report any physical NVIDIA GPUs")
    return count


def gpu_partitioning_mode(expected_count: int) -> str:
    result = run(
        [
            "nvidia-smi",
            "--query-gpu=index,mig.mode.current",
            "--format=csv,noheader",
        ],
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise LetsInferError(f"cannot inspect NVIDIA GPU partitioning: {detail}")
    rows = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if len(rows) != expected_count:
        raise LetsInferError(
            f"nvidia-smi reported {len(rows)} GPU partitioning row(s); expected "
            f"{expected_count}"
        )
    modes: list[str] = []
    indices: set[int] = set()
    for row in rows:
        fields = [field.strip() for field in row.split(",")]
        if len(fields) != 2:
            raise LetsInferError("unexpected nvidia-smi GPU partitioning output")
        try:
            index = int(fields[0])
        except ValueError as error:
            raise LetsInferError("nvidia-smi reported an invalid GPU index") from error
        if index < 0 or index in indices:
            raise LetsInferError("nvidia-smi reported duplicate or invalid GPU indices")
        indices.add(index)
        modes.append(fields[1].strip("[]").lower())
    if any(mode == "enabled" for mode in modes):
        return "mig"
    if all(mode in {"disabled", "n/a"} for mode in modes):
        return "full-device"
    raise LetsInferError(
        "nvidia-smi reported an unknown GPU partitioning mode: " + ", ".join(modes)
    )


def nvidia_query(field: str, expected_count: int) -> list[str]:
    result = run(
        ["nvidia-smi", f"--query-gpu={field}", "--format=csv,noheader,nounits"],
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise LetsInferError(f"cannot inspect NVIDIA {field}: {detail}")
    rows = [line.strip().strip("[]") for line in result.stdout.splitlines() if line.strip()]
    if len(rows) != expected_count:
        raise LetsInferError(
            f"nvidia-smi reported {len(rows)} {field} row(s); expected {expected_count}"
        )
    return rows


def host_device_fingerprint() -> dict[str, Any]:
    """Probe the stable capabilities used to map this host to a runtime target."""
    count = gpu_count()
    compute = [value.lower() for value in nvidia_query("compute_cap", count)]
    architectures = {
        "sm_" + re.sub(r"[^0-9]", "", value)
        for value in compute
        if re.fullmatch(r"[0-9]+\.[0-9]+", value)
    }
    if len(architectures) != 1:
        raise LetsInferError(
            "target auto-detection requires homogeneous NVIDIA compute capability"
        )
    addressing = [value.upper() for value in nvidia_query("addressing_mode", count)]
    topology = "unified" if all(value == "ATS" for value in addressing) else "discrete"
    memory_rows = nvidia_query("memory.total", count)
    accelerator_memory: list[int] = []
    for value in memory_rows:
        if value.upper() not in {"N/A", "NOT SUPPORTED"}:
            try:
                accelerator_memory.append(int(float(value)) // 1024)
            except ValueError as error:
                raise LetsInferError("nvidia-smi reported invalid accelerator memory") from error
    meminfo = pathlib.Path("/proc/meminfo").read_text(encoding="utf-8")
    accelerator: dict[str, Any] = {
        "vendor": "nvidia",
        "architecture": next(iter(architectures)),
        "count": count,
        "partitioning": gpu_partitioning_mode(count),
        "names": nvidia_query("name", count),
    }
    if len(accelerator_memory) == count:
        accelerator["minimum_memory_gib"] = min(accelerator_memory)
    accelerator["uuids"] = nvidia_query("uuid", count)
    return {
        "platform": host_platform(),
        "accelerator": accelerator,
        "memory": {
            "topology": topology,
            "total_gib": parse_mem_total_gib(meminfo),
            "addressing_modes": addressing,
        },
    }


def refresh_local_member_facts() -> dict[str, Any]:
    """Publish a freshly signed local inventory into the coordinator store."""
    identity = read_site_identity()
    if identity.role != "coordinator":
        raise LetsInferError(
            "local fact publication for members requires the authenticated "
            "member-control channel"
        )
    try:
        link_store = LinkStore(identity)
        facts = collect_local_facts(
            identity.member_id,
            host_device_fingerprint(),
            data_path=site_data_root(),
            protection_trip_path=(
                default_watchdog_data_root() / PROTECTION_ROOT_NAME
            ),
            memory_pressure_available_bytes=active_memory_pressure_available_bytes(),
            product_version=PRODUCT_VERSION,
            links=link_store.facts(),
        )
        signature = member_proof(facts)
        with SiteStore(identity=identity) as store:
            return store.update_member_facts(
                identity.member_id,
                facts,
                signature,
                actor_type="system",
                origin_interface="local-inventory",
            )
    except (InventoryError, LinkError, SiteError) as error:
        raise LetsInferError(f"cannot publish local topology facts: {error}") from error


def host_hardware_fingerprint_sha256(
    machine_id_path: pathlib.Path = pathlib.Path("/etc/machine-id"),
) -> str:
    """Hash stable host and physical-GPU identifiers without exposing them."""
    if platform.system().lower() != "linux":
        raise LetsInferError("runtime installation identity requires a Linux host")
    try:
        machine_id = machine_id_path.read_text(encoding="ascii").strip().lower()
    except (OSError, UnicodeDecodeError) as error:
        raise LetsInferError("cannot read the host hardware identity") from error
    if not re.fullmatch(r"[0-9a-f]{32}", machine_id):
        raise LetsInferError("host hardware identity is invalid")
    count = gpu_count()
    gpu_uuids = sorted(nvidia_query("uuid", count))
    if (
        len(gpu_uuids) != count
        or len(set(gpu_uuids)) != count
        or any(
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]+", value)
            for value in gpu_uuids
        )
    ):
        raise LetsInferError("NVIDIA hardware identity is invalid")
    material = {
        "contract": "letsinfer-hardware-fingerprint-v1",
        "gpu_uuids": gpu_uuids,
        "machine_id": machine_id,
    }
    return hashlib.sha256(canonical_bytes(material)).hexdigest()


def verify_host_target(manifest: dict[str, Any]) -> dict[str, Any]:
    target = target_contract(manifest)
    actual = host_device_fingerprint()
    if not target_matches(target, actual):
        raise LetsInferError(
            f"host capabilities do not satisfy target {target['id']}: "
            f"actual={compact_json(actual)} required={compact_json(target)}"
        )
    return actual


def memory_snapshot(manifest: dict[str, Any]) -> dict[str, Any]:
    target = target_contract(manifest)
    available_gib = parse_mem_available_gib(
        pathlib.Path("/proc/meminfo").read_text(encoding="utf-8")
    )
    snapshot = {
        "memory_model": target["memory"]["topology"],
        "host_available_gib": available_gib,
    }
    if target["memory"]["topology"] == "discrete":
        rows = nvidia_query("memory.free", target["accelerator"]["count"])
        try:
            free_gib = [int(float(value)) // 1024 for value in rows]
        except ValueError as error:
            raise LetsInferError("nvidia-smi reported invalid free GPU memory") from error
        snapshot["accelerator_available_gib"] = min(free_gib)
    return snapshot


def require_memory_reserve(
    manifest: dict[str, Any], *, phase: str
) -> dict[str, Any]:
    if phase not in {"launch", "runtime"}:
        raise LetsInferError(f"unsupported memory-admission phase: {phase}")
    target_contract(manifest)
    container = manifest["container"]
    host_key = "min_available_gib" if phase == "launch" else "runtime_min_available_gib"
    host_floor = container[host_key]
    snapshot = memory_snapshot(manifest)
    if snapshot["host_available_gib"] < host_floor:
        raise LetsInferError(
            f"only {snapshot['host_available_gib']} GiB unified memory is available; "
            f"{host_floor} GiB is required during {phase}"
        )
    snapshot["required_host_available_gib"] = host_floor
    if target_contract(manifest)["memory"]["topology"] == "discrete":
        gpu_key = "min_gpu_free_gib" if phase == "launch" else "runtime_min_gpu_free_gib"
        gpu_floor = container[gpu_key]
        if snapshot["accelerator_available_gib"] < gpu_floor:
            raise LetsInferError(
                f"only {snapshot['accelerator_available_gib']} GiB accelerator memory is "
                f"available; {gpu_floor} GiB is required during {phase}"
            )
        snapshot["required_accelerator_available_gib"] = gpu_floor
    return snapshot


def run(command: Sequence[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, text=True, capture_output=True, check=check)
    except FileNotFoundError as error:
        raise LetsInferError(f"required command is unavailable: {command[0]}") from error
    except subprocess.CalledProcessError as error:
        detail = (error.stderr or error.stdout or "").strip()
        raise LetsInferError(f"command failed: {shlex.join(command)}: {detail}") from error


def atomic_json(path: pathlib.Path, value: Any) -> None:
    write_text(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def write_text(path: pathlib.Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(
        f".{path.name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
    )
    try:
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
        _fsync_path(path.parent)
    finally:
        if temporary.exists():
            temporary.unlink()


def protection_paths(config: dict[str, Any]) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
    root = expanded_path(config["protection_root"])
    return (
        root / PROTECTION_STATE_NAME,
        root / PROTECTION_ACK_NAME,
        root / PROTECTION_TRIP_NAME,
    )


def write_watchdog_public_state(
    config: dict[str, Any], manifest: dict[str, Any]
) -> pathlib.Path:
    adapter = adapter_for(manifest)
    serving = manifest["serving"]
    path = (
        expanded_path(config["watchdog_data_root"])
        / WATCHDOG_PUBLIC_STATE_DIRECTORY
        / f"{config['manifest_sha256']}.state"
    )
    values = {
        "installation_id": config["installation_id"],
        "release": config["release"],
        "model": config["model"],
        "engine": config["engine"],
        "runtime_name": config.get("runtime_name", "-"),
        "runtime_version": config.get("runtime_version", "-"),
        "manifest_sha256": config["manifest_sha256"],
        "cache_provider": cache_provider_for(manifest),
    }
    allowed = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,126}")
    for name, value in values.items():
        if not isinstance(value, str) or (
            value != "-" and allowed.fullmatch(value) is None
        ):
            raise LetsInferError(f"Watchdog public state {name} is not portable")
    ensure_private_directory(path.parent)
    write_text(
        path,
        "version=1\n"
        + "".join(f"{name}={value}\n" for name, value in values.items())
        + f"cache_persistent={str(persistent_cache_for(manifest)).lower()}\n"
        + f"inference_port={config['gateway_port']}\n"
        + f"max_connections={serving['max_connections']}\n"
        + f"max_active_requests={serving['max_active_requests']}\n"
        + f"max_context_tokens={serving['max_context_tokens']}\n",
    )
    path.chmod(0o600)
    return path


def _protection_descriptor(
    generation: str,
    phase: str,
    name: str,
    identity: dict[str, Any] | None = None,
) -> str:
    if not re.fullmatch(r"[0-9a-f]{32}", generation):
        raise LetsInferError("invalid Watchdog protection generation")
    if phase not in {"pending", "starting", "armed", "disarmed"}:
        raise LetsInferError("invalid Watchdog protection phase")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name):
        raise LetsInferError("invalid Watchdog protected container name")
    needs_identity = phase in {"starting", "armed"}
    if needs_identity and identity is None:
        raise LetsInferError("Watchdog protection requires an exact process identity")
    if not needs_identity and identity is not None:
        raise LetsInferError("Watchdog pending/disarmed state cannot bind a process identity")
    values = identity or {
        "container_id": "-",
        "pid": "-",
        "start_ticks": "-",
        "boot_id": "-",
        "cgroup": "-",
    }
    return (
        "version=1\n"
        f"generation={generation}\n"
        f"phase={phase}\n"
        f"container_name={name}\n"
        f"container_id={values['container_id']}\n"
        f"pid={values['pid']}\n"
        f"start_ticks={values['start_ticks']}\n"
        f"boot_id={values['boot_id']}\n"
        f"cgroup={values['cgroup']}\n"
    )


def _process_start_ticks(pid: int) -> int:
    try:
        payload = pathlib.Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    except OSError as error:
        raise LetsInferError(f"cannot read protected process identity: {error}") from error
    closing = payload.rfind(")")
    fields = payload[closing + 2 :].split() if closing >= 0 else []
    try:
        value = int(fields[19])
    except (IndexError, ValueError) as error:
        raise LetsInferError("cannot parse protected process start time") from error
    if value <= 0:
        raise LetsInferError("protected process start time is invalid")
    return value


def _process_cgroup(pid: int) -> str:
    try:
        lines = pathlib.Path(f"/proc/{pid}/cgroup").read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise LetsInferError(f"cannot read protected process cgroup: {error}") from error
    for line in lines:
        _, separator, relative = line.partition("::")
        if separator and relative.startswith("/") and ".." not in pathlib.PurePosixPath(relative).parts:
            return f"/sys/fs/cgroup{relative}"
    raise LetsInferError("protected process has no unified cgroup")


def _protection_identity(inspection: dict[str, Any]) -> dict[str, Any]:
    container_id = inspection.get("Id")
    state = inspection.get("State") or {}
    pid = state.get("Pid")
    labels = (inspection.get("Config") or {}).get("Labels") or {}
    if (
        not isinstance(container_id, str)
        or not re.fullmatch(r"[0-9a-f]{64}", container_id)
        or labels.get(MANAGED_LABEL) != "true"
        or state.get("Running") is not True
        or not isinstance(pid, int)
        or isinstance(pid, bool)
        or pid <= 1
    ):
        raise LetsInferError("cannot bind Watchdog to the exact managed container process")
    try:
        boot_id = pathlib.Path("/proc/sys/kernel/random/boot_id").read_text(
            encoding="ascii"
        ).strip()
    except OSError as error:
        raise LetsInferError(f"cannot read host boot identity: {error}") from error
    if not re.fullmatch(r"[0-9a-f-]{36}", boot_id):
        raise LetsInferError("host boot identity is invalid")
    return {
        "container_id": container_id,
        "pid": pid,
        "start_ticks": _process_start_ticks(pid),
        "boot_id": boot_id,
        "cgroup": _process_cgroup(pid),
    }


def _parse_protection_lines(path: pathlib.Path) -> dict[str, str]:
    if path.is_symlink():
        raise LetsInferError(f"Watchdog protection file cannot be a symlink: {path}")
    details = path.stat()
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_uid != os.getuid()
        or stat.S_IMODE(details.st_mode) & 0o077
    ):
        raise LetsInferError(f"Watchdog protection file must be private and user-owned: {path}")
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if not separator or not key or "=" in value or key in values:
            raise LetsInferError(f"invalid Watchdog protection file: {path}")
        values[key] = value
    return values


def _await_protection_ack(
    ack_path: pathlib.Path,
    generation: str,
    phase: str,
    container_id: str | None,
    *,
    timeout_seconds: float = 10.0,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    expected_id = container_id or "-"
    while time.monotonic() < deadline:
        try:
            values = _parse_protection_lines(ack_path)
            if (
                values.get("version") == "1"
                and values.get("generation") == generation
                and values.get("phase") == phase
                and values.get("container_id") == expected_id
            ):
                return
        except (OSError, LetsInferError, UnicodeError):
            pass
        time.sleep(0.1)
    raise LetsInferError(
        f"resident Watchdog did not acknowledge protection phase {phase!r}"
    )


def publish_protection_state(
    config: dict[str, Any],
    generation: str,
    phase: str,
    *,
    inspection: dict[str, Any] | None = None,
    wait_for_ack: bool = True,
) -> None:
    state_path, ack_path, trip_path = protection_paths(config)
    ensure_private_directory(state_path.parent)
    if phase == "pending" and trip_path.exists():
        raise LetsInferError(
            f"Watchdog protection trip is latched at {trip_path}; "
            "inspect it and run `letsinfer restart` to acknowledge recovery"
        )
    if phase == "pending" and ack_path.is_file():
        ack_path.unlink()
    identity = _protection_identity(inspection) if inspection is not None else None
    write_text(
        state_path,
        _protection_descriptor(generation, phase, config["name"], identity),
    )
    if wait_for_ack:
        _await_protection_ack(
            ack_path,
            generation,
            phase,
            identity["container_id"] if identity else None,
        )


def disarm_protection(config: dict[str, Any], *, wait_for_ack: bool = True) -> None:
    state_path, _, _ = protection_paths(config)
    if not state_path.is_file():
        return
    try:
        current = _parse_protection_lines(state_path)
        generation = current["generation"]
        publish_protection_state(
            config, generation, "disarmed", wait_for_ack=wait_for_ack
        )
    except (KeyError, OSError, UnicodeError) as error:
        raise LetsInferError(f"cannot disarm Watchdog protection: {error}") from error


def clear_protection_trip(config: dict[str, Any]) -> bool:
    _, _, trip_path = protection_paths(config)
    if not trip_path.exists():
        return False
    if trip_path.is_symlink() or not trip_path.is_file():
        raise LetsInferError(f"refusing to clear unsafe protection trip path: {trip_path}")
    details = trip_path.stat()
    if details.st_uid != os.getuid() or stat.S_IMODE(details.st_mode) & 0o077:
        raise LetsInferError(f"protection trip must be private and user-owned: {trip_path}")
    trip_path.unlink()
    _fsync_path(trip_path.parent)
    return True


def protection_trip_latched(config: dict[str, Any]) -> bool:
    _, _, trip_path = protection_paths(config)
    return trip_path.is_file() and not trip_path.is_symlink()


def protection_status(
    config: dict[str, Any], inspection: dict[str, Any] | None
) -> dict[str, Any]:
    state_path, ack_path, trip_path = protection_paths(config)
    payload: dict[str, Any] = {
        "armed": False,
        "phase": "absent",
        "trip_latched": trip_path.is_file() and not trip_path.is_symlink(),
        "state_path": str(state_path),
        "trip_path": str(trip_path),
    }
    try:
        state = _parse_protection_lines(state_path)
        acknowledgement = _parse_protection_lines(ack_path)
        phase = state.get("phase", "invalid")
        payload["phase"] = phase
        payload["generation"] = state.get("generation")
        payload["container_id"] = state.get("container_id")
        identity_matches = (
            inspection is not None
            and state.get("container_id") == inspection.get("Id")
        )
        payload["armed"] = (
            phase == "armed"
            and state.get("version") == "1"
            and acknowledgement.get("version") == "1"
            and acknowledgement.get("generation") == state.get("generation")
            and acknowledgement.get("phase") == phase
            and acknowledgement.get("container_id") == state.get("container_id")
            and identity_matches
            and not payload["trip_latched"]
        )
    except (OSError, LetsInferError, UnicodeError):
        pass
    return payload


def ensure_private_directory(path: pathlib.Path) -> None:
    if path.is_symlink():
        raise LetsInferError(f"private directory cannot be a symlink: {path}")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    details = path.stat()
    if not stat.S_ISDIR(details.st_mode) or details.st_uid != os.getuid():
        raise LetsInferError(f"private directory is not owned by the current user: {path}")
    path.chmod(0o700)


def ensure_runtime_home(path: pathlib.Path) -> None:
    ensure_private_directory(path)
    ensure_private_directory(path / ".cache")
    ensure_private_directory(path / ".cache/huggingface")
    ensure_private_directory(path / ".cache/huggingface/hub")
    ensure_private_directory(path / ".cache/letsinfer-prefix-store")


def _fsync_path(path: pathlib.Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _core_release(
    root: pathlib.Path,
) -> tuple[list[dict[str, Any]], dict[str, Any], str]:
    from tools.source_archive import (  # Local release tooling, loaded only here.
        SourceArchiveError,
        public_files,
        source_manifest,
    )

    try:
        records = public_files(root)
        manifest = source_manifest(records)
    except SourceArchiveError as error:
        raise LetsInferError(f"core release is invalid: {error}") from error
    identity = hashlib.sha256(canonical_bytes(manifest)).hexdigest()
    return records, manifest, identity


def _control_bundle_identity(core_identity: str, manifest_identity: str) -> str:
    return hashlib.sha256(
        canonical_bytes(
            {
                "schema_version": 1,
                "core_source_sha256": core_identity,
                "runtime_manifest_sha256": manifest_identity,
            }
        )
    ).hexdigest()


def validate_control_bundle(
    root: pathlib.Path,
    manifest_path: pathlib.Path,
    expected_manifest_sha256: str,
    *,
    require_hash_name: bool = True,
) -> tuple[pathlib.Path, dict[str, Any]]:
    if root.is_symlink() or not root.is_dir():
        raise LetsInferError(f"control bundle root is not a regular directory: {root}")
    details = root.stat()
    if details.st_uid != os.getuid() or stat.S_IMODE(details.st_mode) & 0o077:
        raise LetsInferError(f"control bundle root must be private and user-owned: {root}")
    _records, generated_core_manifest, core_identity = _core_release(root)
    core_manifest_path = _contained_regular_file(root, CORE_SOURCE_MANIFEST)
    if read_json(core_manifest_path) != generated_core_manifest:
        raise LetsInferError("control bundle core source manifest mismatch")
    bundle_identity = _control_bundle_identity(
        core_identity, expected_manifest_sha256
    )
    if require_hash_name and root.name != bundle_identity:
        raise LetsInferError("control bundle directory does not match its bundle identity")
    try:
        relative_manifest = manifest_path.resolve(strict=True).relative_to(
            root.resolve(strict=True)
        )
    except (OSError, ValueError) as error:
        raise LetsInferError("control bundle manifest escapes its root") from error
    contained_manifest = _contained_regular_file(root, str(relative_manifest))
    if sha256_file(contained_manifest) != expected_manifest_sha256:
        raise LetsInferError("control bundle manifest SHA-256 mismatch")
    manifest = read_json(contained_manifest)
    validate_manifest(manifest)
    verify_release_sources(manifest, root)
    return contained_manifest, manifest


def install_control_bundle(
    manifest_path: pathlib.Path,
    manifest: dict[str, Any],
    *,
    control_parent: pathlib.Path | None = None,
    artifact_roots: Sequence[pathlib.Path] | None = None,
    core_source_root: pathlib.Path | None = None,
) -> tuple[pathlib.Path, pathlib.Path]:
    sources = tuple(artifact_roots or (source_root(),))
    if not sources:
        raise LetsInferError("control bundle requires at least one artifact source root")
    core_records, core_manifest, core_identity = _core_release(
        core_source_root or source_root()
    )
    manifest_sha = sha256_file(manifest_path)
    bundle_identity = _control_bundle_identity(core_identity, manifest_sha)
    parent = control_parent or default_control_parent()
    ensure_private_directory(parent)
    destination = parent / bundle_identity
    destination_manifest = destination / "releases" / manifest_path.name
    if destination.exists():
        _, installed = validate_control_bundle(
            destination, destination_manifest, manifest_sha
        )
        if (
            installed["release"] != manifest["release"]
            or adapter_for(installed).name != adapter_for(manifest).name
        ):
            raise LetsInferError("existing control bundle has inconsistent release identity")
        return destination, destination_manifest

    staging = pathlib.Path(
        tempfile.mkdtemp(prefix=f".{bundle_identity}.install-", dir=parent)
    )
    staging.chmod(0o700)
    try:
        targets: list[pathlib.Path] = []
        for record in core_records:
            target = staging / record["path"]
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            descriptor = os.open(
                target,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o500 if record["mode"] & 0o111 else 0o400,
            )
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(record["content"])
                handle.flush()
                os.fsync(handle.fileno())
            targets.append(target)
        core_manifest_path = staging / CORE_SOURCE_MANIFEST
        descriptor = os.open(
            core_manifest_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o400,
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical_bytes(core_manifest))
            handle.flush()
            os.fsync(handle.fileno())
        targets.append(core_manifest_path)
        for entry in manifest.get("source_artifacts", []):
            source_path: pathlib.Path | None = None
            for source in sources:
                try:
                    candidate = _contained_regular_file(source, entry["path"])
                except (LetsInferError, FileNotFoundError):
                    continue
                if sha256_file(candidate) == entry["sha256"]:
                    source_path = candidate
                    break
            if source_path is None:
                raise LetsInferError(
                    f"no exact source is available for pinned artifact {entry['path']}"
                )
            target = staging / entry["path"]
            if target.exists():
                raise LetsInferError(
                    f"runtime artifact collides with core source: {entry['path']}"
                )
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copy2(source_path, target)
            target.chmod(0o500 if os.access(source_path, os.X_OK) else 0o400)
            targets.append(target)
        staged_manifest = staging / "releases" / manifest_path.name
        if staged_manifest in targets:
            raise LetsInferError("release manifest collides with a source artifact")
        staged_manifest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        shutil.copy2(manifest_path, staged_manifest)
        staged_manifest.chmod(0o400)
        targets.append(staged_manifest)
        for target in targets:
            _fsync_path(target)
        for directory in sorted(
            (path for path in staging.rglob("*") if path.is_dir()),
            key=lambda path: len(path.parts),
            reverse=True,
        ):
            _fsync_path(directory)
        _fsync_path(staging)
        validate_control_bundle(
            staging,
            staged_manifest,
            manifest_sha,
            require_hash_name=False,
        )
        try:
            staging.replace(destination)
        except FileExistsError:
            validate_control_bundle(
                destination, destination_manifest, manifest_sha
            )
            shutil.rmtree(staging)
        _fsync_path(parent)
    except BaseException:
        if staging.exists():
            shutil.rmtree(staging)
        raise
    return destination, destination_manifest


def purge_control_bundle(config: dict[str, Any]) -> None:
    root = pathlib.Path(config["source_root"]).expanduser()
    manifest_path = pathlib.Path(config["manifest_path"]).expanduser()
    expected_parent = default_control_parent().resolve(strict=True)
    try:
        root.resolve(strict=True).relative_to(expected_parent)
    except ValueError as error:
        raise LetsInferError(f"refusing to purge nonstandard control root: {root}")
    validate_control_bundle(root, manifest_path, config["manifest_sha256"])
    shutil.rmtree(root)
    _fsync_path(expected_parent)


def verify_watchdog_runtime(
    root: pathlib.Path, manifest_sha256: str
) -> tuple[pathlib.Path, str]:
    if root.is_symlink() or not root.is_dir() or root.name != manifest_sha256:
        raise LetsInferError(f"invalid watchdog runtime root: {root}")
    details = root.stat()
    if details.st_uid != os.getuid() or stat.S_IMODE(details.st_mode) & 0o077:
        raise LetsInferError(f"watchdog runtime must be private and user-owned: {root}")
    binary = root / "letsinfer-watchdog"
    receipt_path = root / "receipt.json"
    for path in (binary, receipt_path):
        if path.is_symlink() or not path.is_file() or path.stat().st_uid != os.getuid():
            raise LetsInferError(f"watchdog runtime file is not regular and user-owned: {path}")
    if stat.S_IMODE(binary.stat().st_mode) != 0o500:
        raise LetsInferError(f"watchdog binary mode must be 0500: {binary}")
    receipt = read_json(receipt_path)
    digest = sha256_file(binary)
    if (
        receipt.get("manifest_sha256") != manifest_sha256
        or receipt.get("binary_sha256") != digest
    ):
        raise LetsInferError("watchdog runtime receipt does not match its binary")
    return binary, digest


def install_watchdog_runtime(
    control_root: pathlib.Path,
    manifest: dict[str, Any],
    manifest_sha256: str,
    *,
    runtime_parent: pathlib.Path | None = None,
) -> tuple[pathlib.Path, str]:
    if platform.system() != "Linux":
        raise LetsInferError("the resident watchdog runtime can only be built on Linux")
    parent = runtime_parent or default_watchdog_runtime_parent()
    ensure_private_directory(parent)
    destination = parent / manifest_sha256
    if destination.exists():
        return verify_watchdog_runtime(destination, manifest_sha256)

    source = control_root / manifest["watchdog"]["build"]["source_root"]
    if source.is_symlink() or not source.is_dir():
        raise LetsInferError(f"watchdog build source is unavailable: {source}")
    staging = pathlib.Path(
        tempfile.mkdtemp(prefix=f".{manifest_sha256}.install-", dir=parent)
    )
    staging.chmod(0o700)
    build = staging / "build"
    try:
        run(
            [
                "cmake",
                "-S",
                str(source),
                "-B",
                str(build),
                "-DCMAKE_BUILD_TYPE=Release",
                "-DWATCHDOG_BUILD_TESTS=ON",
            ]
        )
        run(
            [
                "cmake",
                "--build",
                str(build),
                "--parallel",
                "--target",
                manifest["watchdog"]["build"]["target"],
                "watchdog_tests",
            ]
        )
        run(
            ["ctest", "--test-dir", str(build), "--output-on-failure"]
        )
        built = build / manifest["watchdog"]["build"]["output"]
        if built.is_symlink() or not built.is_file():
            raise LetsInferError(f"watchdog build did not produce {built}")
        binary = staging / "letsinfer-watchdog"
        shutil.copy2(built, binary)
        binary.chmod(0o500)
        digest = sha256_file(binary)
        shutil.rmtree(build)
        atomic_json(
            staging / "receipt.json",
            {
                "schema_version": 1,
                "manifest_sha256": manifest_sha256,
                "binary_sha256": digest,
            },
        )
        (staging / "receipt.json").chmod(0o600)
        _fsync_path(binary)
        _fsync_path(staging / "receipt.json")
        _fsync_path(staging)
        try:
            staging.replace(destination)
        except FileExistsError:
            shutil.rmtree(staging)
        _fsync_path(parent)
        return verify_watchdog_runtime(destination, manifest_sha256)
    except BaseException:
        if staging.exists():
            shutil.rmtree(staging)
        raise


def core_watchdog_source_identity(root: pathlib.Path | None = None) -> str:
    """Hash the exact model-neutral Watchdog source shipped with core."""
    source = (root or source_root() / "watchdog").resolve(strict=True)
    if source.is_symlink() or not source.is_dir():
        raise LetsInferError("core Watchdog source is unavailable")
    files: list[dict[str, str]] = []
    for path in sorted(source.rglob("*")):
        if path.is_symlink():
            raise LetsInferError(f"core Watchdog source cannot contain symlinks: {path}")
        if not path.is_file():
            continue
        relative = path.relative_to(source).as_posix()
        if relative.startswith("build/") or "/build/" in relative:
            raise LetsInferError("core Watchdog source contains generated build output")
        files.append({"path": relative, "sha256": sha256_file(path)})
    if not files or len(files) > 512:
        raise LetsInferError("core Watchdog source inventory is invalid")
    return hashlib.sha256(canonical_bytes({"schema_version": 1, "files": files})).hexdigest()


def install_core_watchdog_runtime(
    root: pathlib.Path | None = None,
) -> tuple[pathlib.Path, str, str]:
    source = (root or source_root() / "watchdog").resolve(strict=True)
    identity = core_watchdog_source_identity(source)
    synthetic = {
        "watchdog": {
            "build": {
                "source_root": ".",
                "target": "letsinfer_watchdog",
                "output": "letsinfer-watchdog",
            }
        }
    }
    binary, digest = install_watchdog_runtime(source, synthetic, identity)
    return binary, digest, identity


def core_watchdog_contract() -> dict[str, Any]:
    return {
        "memory_high_bytes": CONTROL_PLANE_MEMORY_HIGH_BYTES,
        "memory_max_bytes": CONTROL_PLANE_MEMORY_LIMIT_BYTES,
        "sample_interval_ms": 1000,
        "flush_interval_ms": 10000,
        "max_controllers": 4,
        "protection": {
            "warning_available_bytes": 16 << 30,
            "graceful_available_bytes": 12 << 30,
            "emergency_available_bytes": 8 << 30,
            "swap_stop_bytes": 1 << 30,
            "psi_some_us": 150000,
            "psi_full_us": 50000,
            "state_failures": 8,
            "containment_grace_ms": 3000,
        },
    }


def active_memory_pressure_available_bytes(
    config_path: pathlib.Path | None = None,
) -> int:
    """Return the active runtime's exact Watchdog warning threshold."""
    path = config_path or default_service_config_path()
    if not path.exists():
        return core_watchdog_contract()["protection"]["warning_available_bytes"]
    return read_service_config(path)["memory_pressure_available_bytes"]


def write_core_watchdog_public_state(
    installation_id: str,
    watchdog_source_sha256: str,
) -> pathlib.Path:
    if not SHA256_RE.fullmatch(installation_id) or not SHA256_RE.fullmatch(
        watchdog_source_sha256
    ):
        raise LetsInferError("core Watchdog state identity is invalid")
    path = default_watchdog_data_root() / WATCHDOG_PUBLIC_STATE_DIRECTORY / "site.state"
    ensure_private_directory(path.parent)
    write_text(
        path,
        "version=1\n"
        f"installation_id={installation_id}\n"
        f"release={PRODUCT_VERSION}\n"
        "model=site\nengine=core\nruntime_name=site\nruntime_version=1\n"
        f"manifest_sha256={watchdog_source_sha256}\n"
        "cache_provider=none\ncache_persistent=false\n"
        "inference_port=8000\nmax_connections=1\n"
        "max_active_requests=1\nmax_context_tokens=1\n",
    )
    path.chmod(0o600)
    return path


def core_watchdog_service_config(
    identity: Any, runtime_manifest: dict[str, Any] | None = None
) -> tuple[dict[str, Any], dict[str, Any]]:
    binary, binary_sha256, source_sha256 = install_core_watchdog_runtime()
    data_root = default_watchdog_data_root()
    ensure_private_directory(data_root)
    ensure_private_directory(data_root / PROTECTION_ROOT_NAME)
    public_state = write_core_watchdog_public_state(
        identity.installation_id, source_sha256
    )
    if identity.role == "coordinator":
        listen = "0.0.0.0"
        allowlist = ensure_controller_authorization(
            identity, default_watchdog_local_controller_cert_path()
        )
    elif identity.role == "member":
        listen = "127.0.0.1"
        allowlist = ensure_member_watchdog_authorization(
            identity, default_watchdog_local_controller_cert_path()
        )
    else:
        raise LetsInferError("core Watchdog requires a configured site role")
    config = {
        "watchdog_binary_path": str(binary),
        "watchdog_binary_sha256": binary_sha256,
        "watchdog_source_sha256": source_sha256,
        "watchdog_data_root": str(data_root),
        "watchdog_listen": listen,
        "watchdog_port": 9768,
        "watchdog_cert_file": str(default_watchdog_cert_path()),
        "watchdog_key_file": str(default_watchdog_key_path()),
        "watchdog_controller_ca_file": str(default_watchdog_controller_ca_path()),
        "watchdog_controller_allowlist_file": str(allowlist),
        "watchdog_public_state_file": str(public_state),
        "gateway_telemetry_file": str(default_gateway_telemetry_path()),
    }
    watchdog = (
        runtime_manifest["watchdog"]
        if runtime_manifest is not None
        else core_watchdog_contract()
    )
    return config, {"watchdog": watchdog}


def purge_watchdog_runtime(config: dict[str, Any]) -> None:
    root = expanded_path(config["watchdog_binary_path"]).parent
    expected = default_watchdog_runtime_parent() / config["watchdog_source_sha256"]
    if root != expected:
        raise LetsInferError(f"refusing to purge nonstandard watchdog runtime: {root}")
    verify_watchdog_runtime(root, config["watchdog_source_sha256"])
    shutil.rmtree(root)
    _fsync_path(expected.parent)


def _validate_private_file(path: pathlib.Path, *, minimum_bytes: int = 1) -> bytes:
    if path.is_symlink():
        raise LetsInferError(f"private file cannot be a symlink: {path}")
    try:
        details = path.stat()
        value = path.read_bytes()
    except OSError as error:
        raise LetsInferError(f"cannot read private file {path}: {error}") from error
    if not stat.S_ISREG(details.st_mode) or details.st_uid != os.getuid():
        raise LetsInferError(f"private file is not a regular user-owned file: {path}")
    if stat.S_IMODE(details.st_mode) & 0o077:
        raise LetsInferError(f"private file permissions must exclude group/other access: {path}")
    if len(value.strip()) < minimum_bytes:
        raise LetsInferError(f"private file is unexpectedly short: {path}")
    return value.strip()


def _atomic_private_text(path: pathlib.Path, value: str) -> None:
    ensure_private_directory(path.parent)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
        path.chmod(0o600)
    finally:
        if temporary.exists():
            temporary.unlink()


def ensure_api_key(path: pathlib.Path, *, rotate: bool = False) -> None:
    if path.exists() and not rotate:
        read_api_key(path)
        return
    if path.exists() and path.is_symlink():
        raise LetsInferError(f"API key cannot be a symlink: {path}")
    _atomic_private_text(path, secrets.token_urlsafe(48) + "\n")
    read_api_key(path)


def read_api_key(path: pathlib.Path) -> str:
    value = _validate_private_file(path, minimum_bytes=MIN_API_KEY_BYTES)
    try:
        decoded = value.decode("ascii")
    except UnicodeDecodeError as error:
        raise LetsInferError(f"API key must contain ASCII characters only: {path}") from error
    if any(character.isspace() for character in decoded):
        raise LetsInferError(f"API key cannot contain whitespace: {path}")
    return decoded


def read_installation_identity(path: pathlib.Path | None = None) -> dict[str, Any]:
    destination = path or default_installation_identity_path()
    if destination != site_identity_path():
        raise LetsInferError("installation identity path must be the canonical site identity")
    try:
        identity = read_site_identity(destination)
    except SiteError as error:
        raise LetsInferError(str(error)) from error
    return {
        "schema_version": 1,
        "installation_id": identity.installation_id,
        "created_at": identity.created_at_unix,
        "site_id": identity.site_id,
        "member_id": identity.member_id,
        "role": identity.role,
    }


def ensure_installation_identity(path: pathlib.Path | None = None) -> dict[str, Any]:
    destination = path or default_installation_identity_path()
    if destination != site_identity_path():
        raise LetsInferError("installation identity path must be the canonical site identity")
    return read_installation_identity(destination)


def certificate_sha256(path: pathlib.Path) -> str:
    result = run(
        ["openssl", "x509", "-in", str(path), "-noout", "-fingerprint", "-sha256"]
    )
    _, separator, raw = result.stdout.strip().partition("=")
    fingerprint = raw.replace(":", "").lower() if separator else ""
    if not SHA256_RE.fullmatch(fingerprint):
        raise LetsInferError(f"cannot read certificate fingerprint: {path}")
    return fingerprint


def _validate_controller_name(value: Any) -> str:
    if not isinstance(value, str):
        raise LetsInferError("controller name must be text")
    name = value.strip()
    if (
        not name
        or unicodedata.normalize("NFC", name) != name
        or len(name) > 64
        or len(name.encode("utf-8")) > 128
        or not all(
            character == " " or unicodedata.category(character)[0] not in {"C", "Z"}
            for character in name
        )
    ):
        raise LetsInferError("controller name is invalid")
    return name


def local_controller_id(installation_id: str) -> str:
    if not SHA256_RE.fullmatch(installation_id):
        raise LetsInferError("installation identity is invalid")
    return hashlib.sha256(
        f"letsinfer-local-controller-v1:{installation_id}".encode("ascii")
    ).hexdigest()[:32]


def write_controller_allowlist(
    store: SiteStore,
    installation_id: str,
    path: pathlib.Path | None = None,
) -> pathlib.Path:
    destination = path or default_controller_allowlist_path()
    rows = store.controllers()
    if not rows or len(rows) > CONTROLLER_MAX:
        raise LetsInferError("controller authorization set is invalid")
    allowlist = "version=1\n" + f"installation_id={installation_id}\n" + "".join(
        f"controller={row['controller_id']},{row['certificate_sha256']}\n"
        for row in rows
    )
    _atomic_private_text(destination, allowlist)
    return destination


def ensure_controller_authorization(
    identity: Any,
    local_certificate: pathlib.Path,
    allowlist_path: pathlib.Path | None = None,
) -> pathlib.Path:
    local_fingerprint = certificate_sha256(local_certificate)
    try:
        certificate_pem = _validate_private_file(
            local_certificate, minimum_bytes=256
        ).decode("ascii") + "\n"
    except UnicodeDecodeError as error:
        raise LetsInferError("local controller certificate is not ASCII PEM") from error
    controller_id = local_controller_id(identity.installation_id)
    try:
        with SiteStore(identity=identity) as store:
            existing = next(
                (
                    row
                    for row in store.controllers()
                    if row["controller_id"] == controller_id
                ),
                None,
            )
            if (
                existing is None
                or existing["certificate_sha256"] != local_fingerprint
                or existing["role"] != "administrator"
            ):
                store.upsert_controller(
                    controller_id=controller_id,
                    name="Let's Infer local controller",
                    role="administrator",
                    certificate_sha256=local_fingerprint,
                    certificate_pem=certificate_pem,
                )
            return write_controller_allowlist(
                store, identity.installation_id, allowlist_path
            )
    except SiteError as error:
        raise LetsInferError(str(error)) from error


def ensure_member_watchdog_authorization(
    identity: Any,
    local_certificate: pathlib.Path,
    allowlist_path: pathlib.Path | None = None,
) -> pathlib.Path:
    """Authorize only the node-local agent on a non-coordinator Watchdog."""
    if identity.role != "member":
        raise LetsInferError("member Watchdog authorization requires a member identity")
    fingerprint = certificate_sha256(local_certificate)
    controller_id = hashlib.sha256(
        (
            "letsinfer-member-watchdog-v1\n"
            f"{identity.installation_id}\n{identity.member_id}\n"
        ).encode("ascii")
    ).hexdigest()[:32]
    destination = allowlist_path or default_controller_allowlist_path()
    _atomic_private_text(
        destination,
        "version=1\n"
        f"installation_id={identity.installation_id}\n"
        f"controller={controller_id},{fingerprint}\n",
    )
    return destination


def _certificate_names() -> list[str]:
    names = {"localhost", socket.gethostname()}
    fqdn = socket.getfqdn()
    if fqdn:
        names.add(fqdn)
    hostname = socket.gethostname().split(".", 1)[0]
    if hostname:
        names.add(f"{hostname}.local")
    return sorted(name for name in names if re.fullmatch(r"[A-Za-z0-9.-]+", name))


def validate_tls_material(cert_path: pathlib.Path, key_path: pathlib.Path) -> None:
    _validate_private_file(key_path, minimum_bytes=256)
    if cert_path.is_symlink() or not cert_path.is_file():
        raise LetsInferError(f"TLS certificate is not a regular file: {cert_path}")
    certificate = run(
        ["openssl", "x509", "-in", str(cert_path), "-noout", "-pubkey"]
    )
    private_public = run(
        ["openssl", "pkey", "-in", str(key_path), "-pubout"]
    )
    if certificate.stdout.strip() != private_public.stdout.strip():
        raise LetsInferError("TLS certificate and private key do not match")
    expiry = run(
        ["openssl", "x509", "-in", str(cert_path), "-noout", "-checkend", "2592000"],
        check=False,
    )
    if expiry.returncode != 0:
        raise LetsInferError("TLS certificate expires within 30 days")


def validate_watchdog_tls_material(
    cert_path: pathlib.Path,
    key_path: pathlib.Path,
    controller_ca_path: pathlib.Path,
) -> None:
    validate_tls_material(cert_path, key_path)
    _validate_private_file(controller_ca_path, minimum_bytes=256)
    expiry = run(
        [
            "openssl",
            "x509",
            "-in",
            str(controller_ca_path),
            "-noout",
            "-checkend",
            "2592000",
        ],
        check=False,
    )
    if expiry.returncode != 0:
        raise LetsInferError("watchdog controller CA expires within 30 days")


def _validate_watchdog_controller_material(
    controller_ca_path: pathlib.Path,
    controller_ca_key_path: pathlib.Path,
    local_controller_cert_path: pathlib.Path,
    local_controller_key_path: pathlib.Path,
) -> None:
    _validate_private_file(controller_ca_key_path, minimum_bytes=256)
    _validate_private_file(local_controller_cert_path, minimum_bytes=256)
    _validate_private_file(local_controller_key_path, minimum_bytes=256)
    ca_public = run(
        ["openssl", "x509", "-in", str(controller_ca_path), "-noout", "-pubkey"]
    )
    ca_key_public = run(
        ["openssl", "pkey", "-in", str(controller_ca_key_path), "-pubout"]
    )
    controller_public = run(
        [
            "openssl", "x509", "-in", str(local_controller_cert_path),
            "-noout", "-pubkey",
        ]
    )
    controller_key_public = run(
        ["openssl", "pkey", "-in", str(local_controller_key_path), "-pubout"]
    )
    if ca_public.stdout.strip() != ca_key_public.stdout.strip():
        raise LetsInferError("watchdog controller CA certificate and key do not match")
    if controller_public.stdout.strip() != controller_key_public.stdout.strip():
        raise LetsInferError("watchdog local controller certificate and key do not match")
    run(
        [
            "openssl",
            "verify",
            "-CAfile",
            str(controller_ca_path),
            str(local_controller_cert_path),
        ]
    )
    controller_expiry = run(
        [
            "openssl",
            "x509",
            "-in",
            str(local_controller_cert_path),
            "-noout",
            "-checkend",
            "2592000",
        ],
        check=False,
    )
    if controller_expiry.returncode != 0:
        raise LetsInferError("watchdog local controller certificate expires within 30 days")


def ensure_watchdog_tls_material(
    cert_path: pathlib.Path,
    key_path: pathlib.Path,
    controller_ca_path: pathlib.Path,
    controller_ca_key_path: pathlib.Path,
    local_controller_cert_path: pathlib.Path,
    local_controller_key_path: pathlib.Path,
) -> None:
    server_paths = (cert_path, key_path, controller_ca_path)
    controller_paths = (
        controller_ca_key_path,
        local_controller_cert_path,
        local_controller_key_path,
    )
    server_existing = [path.exists() for path in server_paths]
    if any(server_existing):
        if not all(server_existing):
            raise LetsInferError(
                "watchdog mTLS credentials are incomplete; refusing to replace them"
            )
        if not all(path.exists() for path in controller_paths):
            raise LetsInferError(
                "watchdog controller credentials are incomplete; refusing to replace them"
            )
        validate_watchdog_tls_material(*server_paths)
        _validate_watchdog_controller_material(
            controller_ca_path,
            controller_ca_key_path,
            local_controller_cert_path,
            local_controller_key_path,
        )
        for label, certificate in (
            ("server", cert_path),
            ("controller CA", controller_ca_path),
            ("local controller", local_controller_cert_path),
        ):
            long_lived = run(
                [
                    "openssl", "x509", "-in", str(certificate), "-noout",
                    "-checkend", str(50 * 365 * 24 * 60 * 60),
                ],
                check=False,
            ).returncode == 0
            if not long_lived:
                raise LetsInferError(
                    f"watchdog {label} certificate does not meet the controller "
                    "lifetime contract; explicitly purge credentials before reinstalling"
                )
        return
    if any(path.exists() for path in controller_paths):
        raise LetsInferError(
            "watchdog controller credentials exist without server credentials"
        )
    paths = (*server_paths, *controller_paths)
    parents = {path.parent for path in paths}
    if len(parents) != 1:
        raise LetsInferError("generated watchdog mTLS credentials must share a directory")
    credential_root = parents.pop()
    ensure_private_directory(credential_root)
    staging = pathlib.Path(
        tempfile.mkdtemp(prefix=".watchdog-tls-", dir=credential_root)
    )
    staging.chmod(0o700)
    try:
        ca_cert = staging / "controller-ca.crt"
        ca_key = staging / "controller-ca.key"
        server_cert = staging / "server.crt"
        server_key = staging / "server.key"
        server_csr = staging / "server.csr"
        controller_cert = staging / "local-controller.crt"
        controller_key = staging / "local-controller.key"
        controller_csr = staging / "local-controller.csr"
        server_extensions = staging / "server.ext"
        client_extensions = staging / "client.ext"
        names = _certificate_names()
        common_name = next((name for name in names if name != "localhost"), "localhost")
        write_text(
            server_extensions,
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\n"
            + "subjectAltName="
            + ",".join([*(f"DNS:{name}" for name in names), "IP:127.0.0.1"])
            + "\n",
        )
        write_text(
            client_extensions,
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature\n"
            "extendedKeyUsage=clientAuth\n",
        )
        run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:3072", "-sha256",
                "-nodes", "-days", str(CONTROLLER_CERTIFICATE_DAYS),
                "-subj", "/CN=Let's Infer controller CA",
                "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-keyout", str(ca_key), "-out", str(ca_cert),
            ]
        )
        run(
            [
                "openssl", "req", "-new", "-newkey", "rsa:3072", "-sha256",
                "-nodes", "-subj", f"/CN={common_name}", "-keyout", str(server_key),
                "-out", str(server_csr),
            ]
        )
        run(
            [
                "openssl", "x509", "-req", "-in", str(server_csr),
                "-CA", str(ca_cert), "-CAkey", str(ca_key), "-CAcreateserial",
                "-days", str(CONTROLLER_CERTIFICATE_DAYS), "-sha256",
                "-extfile", str(server_extensions),
                "-out", str(server_cert),
            ]
        )
        run(
            [
                "openssl", "req", "-new", "-newkey", "rsa:3072", "-sha256",
                "-nodes", "-subj", "/CN=Let's Infer local controller",
                "-keyout", str(controller_key), "-out", str(controller_csr),
            ]
        )
        run(
            [
                "openssl", "x509", "-req", "-in", str(controller_csr),
                "-CA", str(ca_cert), "-CAkey", str(ca_key), "-CAcreateserial",
                "-days", str(CONTROLLER_CERTIFICATE_DAYS), "-sha256",
                "-extfile", str(client_extensions),
                "-out", str(controller_cert),
            ]
        )
        staged_paths = (
            server_cert, server_key, ca_cert, ca_key, controller_cert, controller_key
        )
        for path in staged_paths:
            path.chmod(0o600)
        validate_watchdog_tls_material(*staged_paths[:3])
        _validate_watchdog_controller_material(
            staged_paths[2], staged_paths[3], staged_paths[4], staged_paths[5]
        )
        for source, destination in zip(staged_paths, paths):
            source.replace(destination)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    validate_watchdog_tls_material(*server_paths)
    _validate_watchdog_controller_material(
        controller_ca_path,
        controller_ca_key_path,
        local_controller_cert_path,
        local_controller_key_path,
    )


def controller_pairing_challenge(
    installation_id: str,
    session_id: str,
    nonce: str,
    controller_id: str,
    name: str,
    public_key_sha256: str,
) -> bytes:
    return (
        f"{CONTROLLER_PAIRING_PROTOCOL}\n{installation_id}\n{session_id}\n{nonce}\n"
        f"{controller_id}\n{name}\n{public_key_sha256}\n"
    ).encode("utf-8")


def controller_confirmation_code(
    installation_id: str,
    session_id: str,
    nonce: str,
    controller_id: str,
    public_key_sha256: str,
) -> str:
    digest = hashlib.sha256(
        (
            f"{CONTROLLER_PAIRING_PROTOCOL}:confirmation\n{installation_id}\n"
            f"{session_id}\n{nonce}\n{controller_id}\n{public_key_sha256}\n"
        ).encode("ascii")
    ).digest()
    return f"{int.from_bytes(digest[:4], 'big') % 1_000_000:06d}"


def format_pairing_code(code: str) -> str:
    if re.fullmatch(r"[0-9]{8}", code) is None:
        raise LetsInferError("pairing code is invalid")
    return f"{code[:3]}-{code[3:5]}-{code[5:]}"


def _decode_controller_enrollment(
    payload: dict[str, Any],
    *,
    installation_id: str,
    session_id: str,
    nonce: str,
    setup_code: str,
) -> dict[str, Any]:
    if set(payload) != {
        "protocol", "setup_code", "controller_id", "name", "public_key_spki", "proof"
    } or payload.get("protocol") != CONTROLLER_PAIRING_PROTOCOL:
        raise LetsInferError("pairing request is invalid")
    supplied_code = payload.get("setup_code")
    if not isinstance(supplied_code, str) or not hmac.compare_digest(supplied_code, setup_code):
        raise LetsInferError("pairing code did not match")
    controller_id = payload.get("controller_id")
    if not isinstance(controller_id, str) or re.fullmatch(r"[0-9a-f]{32}", controller_id) is None:
        raise LetsInferError("controller identity is invalid")
    name = _validate_controller_name(payload.get("name"))
    try:
        public_key = base64.b64decode(payload.get("public_key_spki", ""), validate=True)
        proof = base64.b64decode(payload.get("proof", ""), validate=True)
    except (ValueError, TypeError) as error:
        raise LetsInferError("controller key proof is invalid") from error
    if not 64 <= len(public_key) <= 256 or not 64 <= len(proof) <= 128:
        raise LetsInferError("controller key proof is invalid")
    public_key_sha256 = hashlib.sha256(public_key).hexdigest()
    challenge = controller_pairing_challenge(
        installation_id,
        session_id,
        nonce,
        controller_id,
        name,
        public_key_sha256,
    )
    return {
        "id": controller_id,
        "name": name,
        "public_key": public_key,
        "public_key_sha256": public_key_sha256,
        "proof": proof,
        "challenge": challenge,
        "confirmation_code": controller_confirmation_code(
            installation_id,
            session_id,
            nonce,
            controller_id,
            public_key_sha256,
        ),
    }


def _verify_controller_key(candidate: dict[str, Any], directory: pathlib.Path) -> pathlib.Path:
    public_der = directory / "controller-public.der"
    public_pem = directory / "controller-public.pem"
    signature = directory / "controller-proof.der"
    challenge = directory / "controller-challenge"
    public_der.write_bytes(candidate["public_key"])
    signature.write_bytes(candidate["proof"])
    challenge.write_bytes(candidate["challenge"])
    for path in (public_der, public_pem, signature, challenge):
        if path.exists():
            path.chmod(0o600)
    run([
        "openssl", "pkey", "-pubin", "-inform", "DER", "-in", str(public_der),
        "-pubout", "-out", str(public_pem),
    ])
    description = run([
        "openssl", "pkey", "-pubin", "-in", str(public_pem), "-text", "-noout"
    ]).stdout
    if "prime256v1" not in description and "P-256" not in description:
        raise LetsInferError("controller key must be P-256")
    run([
        "openssl", "dgst", "-sha256", "-verify", str(public_pem),
        "-signature", str(signature), str(challenge),
    ])
    return public_pem


def issue_controller_certificate(
    candidate: dict[str, Any],
    controller_ca_path: pathlib.Path,
    controller_ca_key_path: pathlib.Path,
) -> tuple[str, str]:
    _validate_private_file(controller_ca_path, minimum_bytes=256)
    _validate_private_file(controller_ca_key_path, minimum_bytes=256)
    with tempfile.TemporaryDirectory(prefix="letsinfer-controller-") as directory:
        root = pathlib.Path(directory)
        root.chmod(0o700)
        public_pem = _verify_controller_key(candidate, root)
        extensions = root / "controller.ext"
        certificate = root / "controller.crt"
        write_text(
            extensions,
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature\n"
            "extendedKeyUsage=clientAuth\n"
            f"subjectAltName=URI:urn:letsinfer:controller:{candidate['id']}\n",
        )
        serial = secrets.token_hex(20)
        run([
            "openssl", "x509", "-new", "-force_pubkey", str(public_pem),
            "-subj", f"/CN=Let's Infer controller {candidate['id']}",
            "-CA", str(controller_ca_path), "-CAkey", str(controller_ca_key_path),
            "-set_serial", f"0x{serial}", "-days", str(CONTROLLER_CERTIFICATE_DAYS),
            "-sha256", "-extfile", str(extensions), "-out", str(certificate),
        ])
        run(["openssl", "verify", "-CAfile", str(controller_ca_path), str(certificate)])
        return certificate.read_text(encoding="ascii"), certificate_sha256(certificate)


def _replace_controller(
    config: dict[str, Any],
    candidate: dict[str, Any],
    certificate_pem: str,
    certificate_sha256_value: str,
    role: str,
) -> None:
    if run(
        ["systemctl", "--user", "is-active", SERVICE_NAME], check=False
    ).returncode != 0:
        raise LetsInferError("Let's Infer Watchdog is not running")
    try:
        identity = read_site_identity()
        if identity.installation_id != config["installation_id"]:
            raise LetsInferError("service installation identity does not match the site")
        with SiteStore(identity=identity) as store:
            store.upsert_controller(
                controller_id=candidate["id"],
                name=candidate["name"],
                role=role,
                certificate_sha256=certificate_sha256_value,
                certificate_pem=certificate_pem,
            )
            write_controller_allowlist(
                store,
                identity.installation_id,
                expanded_path(config["watchdog_controller_allowlist_file"]),
            )
    except SiteError as error:
        raise LetsInferError(str(error)) from error
    _reload_controller_authorization(config, require_active=True)


def _reload_controller_authorization(
    config: dict[str, Any], *, require_active: bool = False
) -> None:
    active = run(["systemctl", "--user", "is-active", SERVICE_NAME], check=False)
    if active.returncode != 0:
        if require_active:
            raise LetsInferError("Let's Infer Watchdog is not running")
        return
    run(["systemctl", "--user", "kill", "--signal=HUP", SERVICE_NAME])


class _ControllerPairingState:
    def __init__(
        self, config: dict[str, Any], setup_code: str, timeout: int, role: str
    ):
        if role not in {"viewer", "operator", "administrator"}:
            raise LetsInferError("controller role is invalid")
        self.config = config
        self.setup_code = setup_code
        self.session_id = secrets.token_hex(16)
        self.nonce = secrets.token_hex(32)
        self.deadline = time.monotonic() + timeout
        self.condition = threading.Condition()
        self.candidate: dict[str, Any] | None = None
        self.approved: bool | None = None
        self.completed = False
        self.error: str | None = None
        self.attempted = False
        self.role = role

    def hello(self) -> dict[str, Any]:
        with self.condition:
            if self.attempted or time.monotonic() >= self.deadline:
                raise LetsInferError("pairing session is unavailable")
        return {
            "protocol": CONTROLLER_PAIRING_PROTOCOL,
            "installation_id": self.config["installation_id"],
            "session_id": self.session_id,
            "nonce": self.nonce,
            "watchdog_port": self.config["watchdog_port"],
            "control_port": CONTROLLER_CONTROL_PORT,
        }

    def enroll(self, payload: dict[str, Any]) -> dict[str, Any]:
        with self.condition:
            if self.attempted:
                raise LetsInferError("pairing session has already been used")
            self.attempted = True
        candidate = _decode_controller_enrollment(
            payload,
            installation_id=self.config["installation_id"],
            session_id=self.session_id,
            nonce=self.nonce,
            setup_code=self.setup_code,
        )
        with tempfile.TemporaryDirectory(prefix="letsinfer-controller-proof-") as directory:
            _verify_controller_key(candidate, pathlib.Path(directory))
        with self.condition:
            self.candidate = candidate
            self.condition.notify_all()
            while self.approved is None and time.monotonic() < self.deadline:
                self.condition.wait(timeout=max(0.1, self.deadline - time.monotonic()))
            if self.approved is not True:
                raise LetsInferError("controller pairing was not approved")
        certificate_pem, fingerprint = issue_controller_certificate(
            candidate,
            expanded_path(self.config["watchdog_controller_ca_file"]),
            expanded_path(self.config["watchdog_controller_ca_key_file"]),
        )
        _replace_controller(
            self.config, candidate, certificate_pem, fingerprint, self.role
        )
        ca_pem = expanded_path(self.config["watchdog_controller_ca_file"]).read_text(
            encoding="ascii"
        )
        with self.condition:
            self.completed = True
            self.condition.notify_all()
        return {
            "protocol": CONTROLLER_PAIRING_PROTOCOL,
            "status": "paired",
            "installation_id": self.config["installation_id"],
            "controller_id": candidate["id"],
            "role": self.role,
            "watchdog_port": self.config["watchdog_port"],
            "control_port": CONTROLLER_CONTROL_PORT,
            "certificate_pem": certificate_pem,
            "ca_pem": ca_pem,
        }


class _ControllerPairingHandler(http.server.BaseHTTPRequestHandler):
    server_version = "LetsInferPairing/1"
    sys_version = ""

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _respond(self, status: int, value: dict[str, Any]) -> None:
        body = json.dumps(value, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path != "/pair/v1/hello":
            self._respond(404, {"error": "not found"})
            return
        try:
            state: _ControllerPairingState = self.server.pairing_state  # type: ignore[attr-defined]
            self._respond(200, state.hello())
        except LetsInferError:
            self._respond(410, {"error": "pairing session unavailable"})

    def do_POST(self) -> None:
        if self.path != "/pair/v1/enroll":
            self._respond(404, {"error": "not found"})
            return
        try:
            content_type = self.headers.get("Content-Type", "").split(";", 1)[0]
            if content_type.strip().lower() != "application/json":
                raise LetsInferError("pairing request content type is invalid")
            length = int(self.headers.get("Content-Length", "-1"))
            if length < 2 or length > 8192:
                raise LetsInferError("pairing request size is invalid")
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict):
                raise LetsInferError("pairing request is invalid")
            state: _ControllerPairingState = self.server.pairing_state  # type: ignore[attr-defined]
            self._respond(200, state.enroll(payload))
        except (LetsInferError, json.JSONDecodeError, ValueError, OSError) as error:
            state = self.server.pairing_state  # type: ignore[attr-defined]
            with state.condition:
                state.error = str(error)
                state.condition.notify_all()
            self._respond(403, {"error": "pairing failed"})


class _ControllerPairingServer(http.server.HTTPServer):
    allow_reuse_address = False
    request_queue_size = 2

    def get_request(self) -> tuple[ssl.SSLSocket, Any]:
        connection, address = super().get_request()
        connection.settimeout(15)
        try:
            secure = self.tls_context.wrap_socket(  # type: ignore[attr-defined]
                connection, server_side=True
            )
        except BaseException:
            connection.close()
            raise
        return secure, address


class _ControllerPairingServerV6(_ControllerPairingServer):
    address_family = socket.AF_INET6


def _controller_pairing_tls_context(
    certificate: str | os.PathLike[str], key: str | os.PathLike[str]
) -> ssl.SSLContext:
    if not getattr(ssl, "HAS_TLSv1_3", False):
        raise LetsInferError("controller pairing requires TLS 1.3 support")
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        tls.minimum_version = ssl.TLSVersion.TLSv1_3
        tls.maximum_version = ssl.TLSVersion.TLSv1_3
        tls.load_cert_chain(certificate, key)
    except (OSError, ssl.SSLError, ValueError) as error:
        raise LetsInferError(f"cannot load controller pairing TLS identity: {error}") from error
    return tls


def pair_controller(arguments: argparse.Namespace) -> int:
    if not CONTROLLER_PAIRING_MIN_TIMEOUT_SECONDS <= arguments.timeout <= CONTROLLER_PAIRING_TIMEOUT_SECONDS:
        raise LetsInferError(
            f"controller pairing timeout must be between "
            f"{CONTROLLER_PAIRING_MIN_TIMEOUT_SECONDS} and "
            f"{CONTROLLER_PAIRING_TIMEOUT_SECONDS} seconds"
        )
    config_path = expanded_path(arguments.config or default_service_config_path())
    config = read_service_config(config_path)
    for key in (
        "installation_id", "watchdog_controller_allowlist_file",
        "watchdog_controller_ca_key_file",
    ):
        if key not in config:
            raise LetsInferError("installed Let's Infer does not support controller pairing")
    _reload_controller_authorization(config, require_active=True)
    setup_code = f"{secrets.randbelow(100_000_000):08d}"
    state = _ControllerPairingState(
        config, setup_code, arguments.timeout, arguments.role
    )
    tls = _controller_pairing_tls_context(
        config["watchdog_cert_file"], config["watchdog_key_file"]
    )
    listen_address = config["watchdog_listen"]
    server_type = (
        _ControllerPairingServerV6 if ":" in listen_address else _ControllerPairingServer
    )
    try:
        server = server_type(
            (listen_address, CONTROLLER_PAIRING_PORT),
            _ControllerPairingHandler,
        )
    except OSError as error:
        raise LetsInferError(
            f"cannot open controller pairing on {listen_address}:"
            f"{CONTROLLER_PAIRING_PORT}: {error}"
        ) from error
    server.pairing_state = state  # type: ignore[attr-defined]
    server.tls_context = tls  # type: ignore[attr-defined]
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    print(f"PAIR CODE {format_pairing_code(setup_code)}")
    print(
        f"Listening for one controller on port {CONTROLLER_PAIRING_PORT} "
        f"for {arguments.timeout}s."
    )
    try:
        with state.condition:
            while state.candidate is None and state.error is None and time.monotonic() < state.deadline:
                state.condition.wait(timeout=max(0.1, state.deadline - time.monotonic()))
            if state.candidate is None:
                raise LetsInferError(state.error or "controller pairing timed out")
            candidate = state.candidate
        print(f"Controller: {candidate['name']}")
        print(f"VERIFY {candidate['confirmation_code'][:3]}-{candidate['confirmation_code'][3:]}")
        try:
            answer = input("Does this verification code match the Mac? [y/N] ")
        except EOFError:
            answer = ""
        with state.condition:
            state.approved = answer.strip().lower() in {"y", "yes"}
            state.condition.notify_all()
            while not state.completed and state.error is None and time.monotonic() < state.deadline:
                state.condition.wait(timeout=max(0.1, state.deadline - time.monotonic()))
            if not state.completed:
                raise LetsInferError(state.error or "controller pairing was not completed")
        print(f"PAIRED {candidate['name']} controller={candidate['id']}")
        return 0
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


def controllers(arguments: argparse.Namespace) -> int:
    config = read_service_config(expanded_path(arguments.config or default_service_config_path()))
    for key in (
        "installation_id", "watchdog_controller_allowlist_file",
    ):
        if key not in config:
            raise LetsInferError("installed Let's Infer does not support controllers")
    if arguments.operation == "forget" and (
        not isinstance(arguments.controller, str) or not arguments.controller.strip()
    ):
        raise LetsInferError("controllers forget requires a controller name or ID")
    if arguments.operation == "list" and arguments.controller is not None:
        raise LetsInferError("controllers list does not accept a controller name or ID")
    try:
        identity = read_site_identity()
        if identity.installation_id != config["installation_id"]:
            raise LetsInferError("service installation identity does not match the site")
        store = SiteStore(identity=identity)
    except SiteError as error:
        raise LetsInferError(str(error)) from error
    with store:
        rows = store.controllers()
        if arguments.operation == "forget":
            identifier = arguments.controller
            matches = [
                row for row in rows
                if row["controller_id"] == identifier
                or row["name"].casefold() == identifier.casefold()
            ]
            if len(matches) != 1:
                raise LetsInferError("controller name or ID is unknown or ambiguous")
            if matches[0]["controller_id"] == local_controller_id(
                config["installation_id"]
            ):
                raise LetsInferError(
                    "the protected local controller cannot be forgotten"
                )
            store.revoke_controller(matches[0]["controller_id"])
            write_controller_allowlist(
                store,
                config["installation_id"],
                expanded_path(config["watchdog_controller_allowlist_file"]),
            )
            _reload_controller_authorization(config)
            print(
                f"FORGOT {matches[0]['name']} "
                f"controller={matches[0]['controller_id']}"
            )
            return 0
    if arguments.json:
        print(json.dumps({"installation_id": config["installation_id"], "controllers": rows}, indent=2))
    else:
        for row in rows:
            print(
                f"{row['controller_id']}  {row['role']:<13}  {row['name']}  "
                f"paired={dt.datetime.fromtimestamp(row['created_at_unix']).astimezone().isoformat()}"
            )
    return 0


def ensure_tls_material(cert_path: pathlib.Path, key_path: pathlib.Path) -> None:
    if cert_path.exists() or key_path.exists():
        if not cert_path.exists() or not key_path.exists():
            raise LetsInferError("TLS certificate/key pair is incomplete; refusing to replace it")
        validate_tls_material(cert_path, key_path)
        return

    if cert_path.parent != key_path.parent:
        raise LetsInferError("generated TLS certificate and key must share a directory")
    ensure_private_directory(cert_path.parent)
    staging = pathlib.Path(tempfile.mkdtemp(prefix=".tls-generate-", dir=cert_path.parent))
    try:
        staged_cert = staging / "server.crt"
        staged_key = staging / "server.key"
        names = _certificate_names()
        common_name = next((name for name in names if name != "localhost"), "localhost")
        subject_alt_names = [*(f"DNS:{name}" for name in names), "IP:127.0.0.1"]
        run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:3072",
                "-sha256",
                "-nodes",
                "-days",
                "825",
                "-subj",
                f"/CN={common_name}",
                "-addext",
                f"subjectAltName={','.join(subject_alt_names)}",
                "-keyout",
                str(staged_key),
                "-out",
                str(staged_cert),
            ]
        )
        staged_key.chmod(0o600)
        staged_cert.chmod(0o644)
        validate_tls_material(staged_cert, staged_key)
        staged_key.replace(key_path)
        staged_cert.replace(cert_path)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    validate_tls_material(cert_path, key_path)


def image_id(manifest: dict[str, Any]) -> str:
    image = manifest["image"]
    inspect = run(["docker", "image", "inspect", image["reference"], "--format", "{{.Id}}"], check=False)
    if inspect.returncode != 0 and image["distribution"] == "registry-digest":
        run(["docker", "pull", image["reference"]])
        inspect = run(["docker", "image", "inspect", image["reference"], "--format", "{{.Id}}"])
    elif inspect.returncode != 0:
        raise LetsInferError(
            "pinned local image is absent; deploy/build the exact candidate image before serving"
        )
    actual = inspect.stdout.strip()
    if actual != image["immutable_id"]:
        raise LetsInferError(
            f"runtime image mismatch (expected {image['immutable_id']}, got {actual})"
        )
    image_platform = run(
        [
            "docker",
            "image",
            "inspect",
            image["reference"],
            "--format",
            "{{.Os}}/{{.Architecture}}",
        ]
    ).stdout.strip()
    expected_platform = target_contract(manifest)["platform"]
    actual_platform = normalize_platform(image_platform)
    if actual_platform != expected_platform:
        raise LetsInferError(
            f"runtime image platform is {actual_platform or 'unknown'}; "
            f"{expected_platform} is required"
        )
    return actual


def model_artifacts(manifest: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    """Return all exact dependencies with their deterministic shared-store paths."""
    return tuple(
        {**artifact, "cache_repository": artifact_cache_repository(artifact)}
        for artifact in manifest["artifacts"]
    )


def artifact_snapshot_path(
    artifact: dict[str, Any], model_cache: pathlib.Path
) -> pathlib.Path:
    return (
        model_cache
        / "hub"
        / artifact["cache_repository"]
        / "snapshots"
        / artifact["revision"]
    )


def _model_verification_receipt_path(expected: str) -> pathlib.Path:
    return site_data_root() / "model-verification/sha256" / f"{expected}.json"


def _model_file_identity(path: pathlib.Path) -> dict[str, int | str]:
    details = path.stat()
    return {
        "path": str(path),
        "device": details.st_dev,
        "inode": details.st_ino,
        "bytes": details.st_size,
        "mtime_ns": details.st_mtime_ns,
        "ctime_ns": details.st_ctime_ns,
    }


def _model_verification_is_current(path: pathlib.Path, expected: str) -> bool:
    receipt_path = _model_verification_receipt_path(expected)
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        return receipt == {
            "schema_version": 1,
            "sha256": expected,
            "file": _model_file_identity(path),
        }
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return False


def _verify_model_file(path: pathlib.Path, expected: str) -> None:
    """Hash model bytes once, then reuse an identity-bound verification receipt."""
    if _model_verification_is_current(path, expected):
        return
    actual = sha256_file(path)
    if actual != expected:
        raise LetsInferError(
            f"model artifact SHA-256 mismatch (expected {expected}, got {actual})"
        )
    receipt_path = _model_verification_receipt_path(expected)
    ensure_private_directory(receipt_path.parent.parent)
    ensure_private_directory(receipt_path.parent)
    atomic_json(
        receipt_path,
        {
            "schema_version": 1,
            "sha256": expected,
            "file": _model_file_identity(path),
        },
    )


def model_snapshot_path(manifest: dict[str, Any], model_cache: pathlib.Path) -> pathlib.Path:
    return artifact_snapshot_path(model_artifacts(manifest)[0], model_cache)


def _verify_gguf_artifact(
    artifact: dict[str, Any], snapshot: pathlib.Path, model_cache: pathlib.Path
) -> None:
    model_file = snapshot / artifact["filename"]
    if model_file.is_symlink():
        try:
            resolved = model_file.resolve(strict=True)
            resolved.relative_to((model_cache / "hub").resolve(strict=True))
        except (OSError, ValueError) as error:
            raise LetsInferError(
                f"{artifact['name']} GGUF object link escapes the model cache: {model_file}"
            ) from error
    elif not model_file.is_file():
        raise LetsInferError(f"exact {artifact['name']} GGUF file is missing: {model_file}")
    if "bytes" in artifact and model_file.stat().st_size != artifact["bytes"]:
        raise LetsInferError(
            f"{artifact['name']} GGUF size mismatch "
            f"(expected {artifact['bytes']}, got {model_file.stat().st_size})"
        )
    expected = artifact["sha256"]
    _verify_model_file(model_file.resolve(strict=True), expected)


def verify_model_snapshot(manifest: dict[str, Any], model_cache: pathlib.Path) -> pathlib.Path:
    artifacts = model_artifacts(manifest)
    for artifact in artifacts:
        snapshot = artifact_snapshot_path(artifact, model_cache)
        if not snapshot.is_dir():
            raise LetsInferError(
                f"exact {artifact['name']} snapshot is missing: {snapshot}"
            )
        broken = [
            path for path in snapshot.rglob("*")
            if path.is_symlink() and not path.exists()
        ]
        if broken:
            raise LetsInferError(
                f"{artifact['name']} snapshot contains a broken object link: {broken[0]}"
            )
        if "filename" in artifact:
            _verify_gguf_artifact(artifact, snapshot, model_cache)
    return artifact_snapshot_path(artifacts[0], model_cache)


def acquire_model_snapshot(manifest: dict[str, Any], model_cache: pathlib.Path) -> pathlib.Path:
    ensure_private_directory(model_cache)
    acquired: set[tuple[str, str, str | None]] = set()
    for artifact in model_artifacts(manifest):
        identity = (
            artifact["repository"],
            artifact["revision"],
            artifact.get("filename"),
        )
        if identity in acquired:
            continue
        acquired.add(identity)
        download_arguments = (
            f"repo_id={artifact['repository']!r}, revision={artifact['revision']!r}"
        )
        if "filename" in artifact:
            download_arguments += f", allow_patterns={[artifact['filename']]!r}"
        script = (
            "from huggingface_hub import snapshot_download; "
            f"snapshot_download({download_arguments})"
        )
        run_passthrough(
            [
                "docker",
                "run",
                "--rm",
                "--pull",
                "missing",
                "--platform",
                target_contract(manifest)["platform"],
                "--entrypoint",
                "python3",
                "--user",
                f"{os.getuid()}:{os.getgid()}",
                "--workdir",
                "/tmp",
                "-v",
                f"{model_cache}:/model-cache",
                "-e",
                "HF_HOME=/model-cache",
                "-e",
                "HOME=/tmp",
                manifest["model"]["acquisition_image"],
                "-c",
                script,
            ]
        )
    return verify_model_snapshot(manifest, model_cache)


def verify_installed_release(
    manifest: dict[str, Any],
    *,
    model_cache: pathlib.Path,
    plugin_root: pathlib.Path,
) -> str:
    verify_model_snapshot(manifest, model_cache)
    adapter = adapter_for(manifest)
    if adapter.requires_runtime_plugins:
        verify_artifacts(plugin_root, manifest["runtime_plugins"]["artifacts"])
    elif requires_core_cache_plugin(manifest):
        try:
            verify_sglang_plugin(
                plugin_root,
                source_root=source_root(),
                core_version=PRODUCT_VERSION,
            )
        except CachePluginError as error:
            raise LetsInferError(str(error)) from error
    return image_id(manifest)


def run_passthrough(command: Sequence[str]) -> None:
    ui.before_external_output()
    try:
        subprocess.run(command, text=True, check=True)
    except FileNotFoundError as error:
        raise LetsInferError(f"required command is unavailable: {command[0]}") from error
    except subprocess.CalledProcessError as error:
        raise LetsInferError(f"command failed: {shlex.join(command)}") from error


def _runtime_image_context(artifact_root: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path] | None:
    """Return the immutable runtime root and its conventional Dockerfile."""
    try:
        root = artifact_root.expanduser().resolve(strict=True)
    except OSError as error:
        raise LetsInferError(f"cannot resolve runtime artifact root: {error}") from error
    image = root / "image"
    dockerfile = image / "Dockerfile"
    if not dockerfile.exists():
        return None
    try:
        resolved_image = image.resolve(strict=True)
        resolved_dockerfile = dockerfile.resolve(strict=True)
        resolved_image.relative_to(root)
        resolved_dockerfile.relative_to(resolved_image)
    except (OSError, ValueError) as error:
        raise LetsInferError("runtime image context escapes its immutable artifact") from error
    if image.is_symlink() or dockerfile.is_symlink() or not dockerfile.is_file():
        raise LetsInferError("runtime image/Dockerfile must be a regular non-symlink file")
    for path in root.rglob("*"):
        if path.is_symlink():
            raise LetsInferError(
                f"runtime build context cannot contain symlinks: {path.relative_to(root)}"
            )
        if not path.is_file() and not path.is_dir():
            raise LetsInferError(
                f"runtime build context contains an unsupported entry: {path.relative_to(root)}"
            )
    return root, resolved_dockerfile


def _validate_runtime_dockerfile(dockerfile: pathlib.Path) -> None:
    """Require immutable external bases while leaving package choice unrestricted."""
    try:
        raw_lines = dockerfile.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise LetsInferError(f"cannot read runtime image/Dockerfile: {error}") from error
    logical_lines: list[str] = []
    pending = ""
    for raw in raw_lines:
        stripped = raw.strip()
        if not pending and (not stripped or stripped.startswith("#")):
            continue
        continued = stripped.endswith("\\")
        piece = stripped[:-1].rstrip() if continued else stripped
        pending = f"{pending} {piece}".strip()
        if not continued:
            logical_lines.append(pending)
            pending = ""
    if pending:
        raise LetsInferError("runtime image/Dockerfile ends with an incomplete continuation")

    stages: set[str] = set()
    found_from = False
    from_pattern = re.compile(
        r"^FROM(?:\s+--platform=\S+)?\s+(\S+)(?:\s+AS\s+([A-Za-z0-9._-]+))?\s*$",
        re.IGNORECASE,
    )
    for line in logical_lines:
        if not line.upper().startswith("FROM "):
            continue
        found_from = True
        match = from_pattern.fullmatch(line)
        if match is None:
            raise LetsInferError("runtime image/Dockerfile has an unsupported FROM instruction")
        reference, alias = match.groups()
        lowered = reference.lower()
        if lowered != "scratch" and lowered not in stages:
            if "$" in reference or not REGISTRY_DIGEST_RE.fullmatch(reference):
                raise LetsInferError(
                    "runtime image external FROM references must be pinned by sha256 digest"
                )
        if alias:
            stages.add(alias.lower())
    if not found_from:
        raise LetsInferError("runtime image/Dockerfile must contain a FROM instruction")


def _build_runtime_image(
    manifest: dict[str, Any], artifact_root: pathlib.Path
) -> str | None:
    resolved = _runtime_image_context(artifact_root)
    if resolved is None:
        return None
    if manifest["image"]["distribution"] != "local-image-id":
        raise LetsInferError(
            "runtime image/Dockerfile requires manifest.image.distribution=local-image-id"
        )
    context, dockerfile = resolved
    _validate_runtime_dockerfile(dockerfile)
    expected = manifest["image"]["immutable_id"]
    tag = f"letsinfer/runtime-build:{expected.removeprefix('sha256:')}"
    run_passthrough(
        [
            "docker",
            "buildx",
            "build",
            "--pull=false",
            "--provenance=false",
            "--build-arg",
            "SOURCE_DATE_EPOCH=0",
            "--build-arg",
            f"LETSINFER_EXPECTED_IMAGE_ID={expected}",
            "--output",
            "type=docker,rewrite-timestamp=true",
            "--platform",
            target_contract(manifest)["platform"],
            "-f",
            str(dockerfile),
            "-t",
            tag,
            str(context),
        ]
    )
    inspected = run(["docker", "image", "inspect", tag, "--format", "{{.Id}}"])
    actual = inspected.stdout.strip()
    if actual != expected:
        raise LetsInferError(
            "runtime-owned image identity differs from the manifest "
            f"(expected {expected}, got {actual or 'unknown'})"
        )
    return image_id(manifest)


def ensure_image(
    manifest: dict[str, Any],
    *,
    build: bool,
    pull: bool = True,
    artifact_root: pathlib.Path | None = None,
) -> str:
    try:
        return image_id(manifest)
    except LetsInferError:
        if manifest["image"]["distribution"] == "registry-digest":
            if not pull:
                raise LetsInferError(
                    "the exact runtime image is absent and dependency downloads "
                    "are disabled"
                )
            run_passthrough(
                [
                    "docker",
                    "pull",
                    "--platform",
                    target_contract(manifest)["platform"],
                    manifest["image"]["reference"],
                ]
            )
            return image_id(manifest)
        if not build:
            raise

    if artifact_root is not None:
        built = _build_runtime_image(manifest, artifact_root)
        if built is not None:
            return built

    raise LetsInferError(
        f"the exact {adapter_for(manifest).name} runtime image is absent and the "
        "installed runtime does not contain image/Dockerfile; Let's Infer does not "
        "substitute or build from core repository sources"
    )


def ensure_install_dependencies(
    manifest: dict[str, Any],
    *,
    model_cache: pathlib.Path,
    runtime_artifact_root: pathlib.Path | None,
    download: bool,
    build_image: bool,
) -> None:
    """Resolve exact model and image dependencies into their shared stores."""
    try:
        verify_model_snapshot(manifest, model_cache)
    except LetsInferError as error:
        if not download:
            required = ", ".join(
                str(artifact_snapshot_path(artifact, model_cache))
                for artifact in model_artifacts(manifest)
            )
            raise LetsInferError(
                "exact model artifacts are missing or incomplete and dependency "
                f"downloads are disabled: {required}"
            ) from error
        acquire_model_snapshot(manifest, model_cache)

    ensure_image(
        manifest,
        build=build_image,
        pull=download,
        artifact_root=runtime_artifact_root,
    )


def _verified_artifact_source(path: pathlib.Path, expected: str) -> pathlib.Path | None:
    if not path.is_symlink() and path.is_file() and sha256_file(path) == expected:
        return path
    return None


def runtime_artifact_object_path(digest: str) -> pathlib.Path:
    """Return the shared content-addressed store path for one plugin artifact."""
    if not SHA256_RE.fullmatch(digest):
        raise LetsInferError("runtime artifact digest is invalid")
    return (
        site_data_root()
        / "artifacts/sha256"
        / digest[:2]
        / digest
    )


def store_runtime_artifact(source: pathlib.Path, expected: str) -> pathlib.Path:
    """Atomically persist exact plugin bytes for reuse across runtime manifests."""
    if _verified_artifact_source(source, expected) is None:
        raise LetsInferError(f"runtime artifact source does not match sha256:{expected}")
    destination = runtime_artifact_object_path(expected)
    existing = _verified_artifact_source(destination, expected)
    if existing is not None:
        return existing
    if destination.exists() or destination.is_symlink():
        raise LetsInferError(f"runtime artifact store object is corrupt: {destination}")

    ensure_private_directory(destination.parent.parent)
    ensure_private_directory(destination.parent)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{expected}.", dir=destination.parent
    )
    temporary = pathlib.Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output, source.open("rb") as input_stream:
            shutil.copyfileobj(input_stream, output)
            output.flush()
            source_mode = stat.S_IMODE(source.stat().st_mode)
            os.fchmod(output.fileno(), 0o755 if source_mode & 0o111 else 0o644)
            os.fsync(output.fileno())
        if _verified_artifact_source(temporary, expected) is None:
            raise LetsInferError("runtime artifact changed while entering the shared store")
        try:
            os.link(temporary, destination)
        except FileExistsError:
            if _verified_artifact_source(destination, expected) is None:
                raise LetsInferError(
                    f"runtime artifact store object is corrupt: {destination}"
                )
        _fsync_path(destination.parent)
    finally:
        temporary.unlink(missing_ok=True)
    verified = _verified_artifact_source(destination, expected)
    if verified is None:
        raise LetsInferError(f"runtime artifact store commit failed: {destination}")
    return verified


def build_runtime_wheel(
    manifest: dict[str, Any],
    output_root: pathlib.Path,
    *,
    artifact_root: pathlib.Path | None = None,
) -> pathlib.Path:
    builder = manifest["runtime_plugins"]["wheel_builder"]
    crate_root = (artifact_root or source_root()) / builder["source_root"]
    if crate_root.is_symlink() or not crate_root.is_dir():
        raise LetsInferError(f"wheel source is not a regular directory: {crate_root}")
    for path in crate_root.rglob("*"):
        if path.is_symlink():
            raise LetsInferError(f"wheel source contains a symlink: {path}")

    build_source = output_root / "source"
    build_output = output_root / "output"
    shutil.copytree(
        crate_root,
        build_source,
        ignore=shutil.ignore_patterns("target", "dist", "__pycache__"),
    )
    build_output.mkdir()
    run_passthrough(
        [
            "docker",
            "run",
            "--rm",
            "--pull",
            "missing",
            "--platform",
            target_contract(manifest)["platform"],
            "-e",
            f"SOURCE_DATE_EPOCH={builder['source_date_epoch']}",
            "-e",
            "RUSTFLAGS=--remap-path-prefix=/io=letsinfer_prefix_store",
            "-e",
            "CARGO_TARGET_DIR=/tmp/target",
            "-v",
            f"{build_source}:/io",
            "-v",
            f"{build_output}:/output",
            builder["image"],
            *builder["arguments"],
        ]
    )
    wheel_entry = next(
        entry
        for entry in manifest["runtime_plugins"]["artifacts"]
        if entry["path"].endswith(".whl")
    )
    wheel = build_output / pathlib.Path(wheel_entry["path"]).name
    if _verified_artifact_source(wheel, wheel_entry["sha256"]) is None:
        actual = sha256_file(wheel) if wheel.is_file() else "missing"
        raise LetsInferError(
            f"reproducible wheel mismatch (expected {wheel_entry['sha256']}, got {actual})"
        )
    return wheel


def build_runtime_native_artifact(
    manifest: dict[str, Any],
    output_root: pathlib.Path,
    *,
    artifact_root: pathlib.Path | None = None,
) -> pathlib.Path:
    """Build the manifest-pinned Let's Infer native bridge from core source."""
    builder = manifest["runtime_plugins"]["native_builder"]
    crate_root = (artifact_root or source_root()) / builder["source_root"]
    if crate_root.is_symlink() or not crate_root.is_dir():
        raise LetsInferError(f"native source is not a regular directory: {crate_root}")
    for path in crate_root.rglob("*"):
        if path.is_symlink():
            raise LetsInferError(f"native source contains a symlink: {path}")

    build_source = output_root / "native-source"
    build_output = output_root / "native-output"
    shutil.copytree(
        crate_root,
        build_source,
        ignore=shutil.ignore_patterns("target", "__pycache__"),
    )
    build_output.mkdir()
    run_passthrough(
        [
            "docker",
            "run",
            "--rm",
            "--pull",
            "missing",
            "--platform",
            target_contract(manifest)["platform"],
            "--entrypoint",
            "sh",
            "--workdir",
            "/io",
            "-e",
            f"SOURCE_DATE_EPOCH={builder['source_date_epoch']}",
            "-e",
            "RUSTFLAGS=--remap-path-prefix=/io=letsinfer_native_bridge",
            "-e",
            "CARGO_TARGET_DIR=/output",
            "-e",
            f"LETSINFER_BUILD_ENTRYPOINT={builder['entrypoint']}",
            "-e",
            f"LETSINFER_BUILD_OUTPUT={builder['output']}",
            "-e",
            f"LETSINFER_OUTPUT_UID={os.getuid()}",
            "-e",
            f"LETSINFER_OUTPUT_GID={os.getgid()}",
            "-v",
            f"{build_source}:/io:ro",
            "-v",
            f"{build_output}:/artifact",
            builder["image"],
            "-c",
            (
                'set -eu; "$LETSINFER_BUILD_ENTRYPOINT" "$@"; '
                'install -D -m 0755 -o "$LETSINFER_OUTPUT_UID" '
                '-g "$LETSINFER_OUTPUT_GID" '
                '"/output/$LETSINFER_BUILD_OUTPUT" '
                '"/artifact/$LETSINFER_BUILD_OUTPUT"; '
                'chown -R "$LETSINFER_OUTPUT_UID:$LETSINFER_OUTPUT_GID" /artifact'
            ),
            "letsinfer-native-build",
            *builder["arguments"],
        ]
    )
    built = build_output / builder["output"]
    native_entry = next(
        entry
        for entry in manifest["runtime_plugins"]["artifacts"]
        if entry["path"] == "libletsinfer_prefix_capi.so"
    )
    if _verified_artifact_source(built, native_entry["sha256"]) is None:
        actual = sha256_file(built) if built.is_file() else "missing"
        raise LetsInferError(
            "reproducible native bridge mismatch "
            f"(expected {native_entry['sha256']}, got {actual})"
        )
    return built


def install_runtime_plugins(
    manifest: dict[str, Any],
    *,
    plugin_root: pathlib.Path,
    wheel_source: pathlib.Path | None,
    artifact_root: pathlib.Path | None = None,
) -> None:
    if requires_core_cache_plugin(manifest):
        try:
            install_sglang_plugin(
                plugin_root,
                source_root=source_root(),
                core_version=PRODUCT_VERSION,
                platform=target_contract(manifest)["platform"],
                run=run_passthrough,
                store=store_runtime_artifact,
            )
        except CachePluginError as error:
            raise LetsInferError(str(error)) from error
        return
    if not adapter_for(manifest).requires_runtime_plugins:
        return
    if plugin_root.is_symlink():
        raise LetsInferError(f"runtime plugin root cannot be a symlink: {plugin_root}")
    plugin_root.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="letsinfer-runtime-artifacts-") as build_directory:
        sources: list[tuple[dict[str, str], pathlib.Path]] = []
        built_wheel: pathlib.Path | None = None
        built_native: pathlib.Path | None = None
        for entry in manifest["runtime_plugins"]["artifacts"]:
            relative = pathlib.Path(entry["path"])
            candidates: list[pathlib.Path] = []
            if relative.suffix == ".whl" and wheel_source is not None:
                candidates.append(wheel_source)
            candidates.extend(
                [
                    (artifact_root or source_root()) / entry.get("source_path", ""),
                    runtime_artifact_object_path(entry["sha256"]),
                    plugin_root / relative,
                ]
            )
            source = next(
                (
                    candidate
                    for candidate in candidates
                    if _verified_artifact_source(candidate, entry["sha256"]) is not None
                ),
                None,
            )
            if source is None and relative.suffix == ".whl":
                built_wheel = build_runtime_wheel(
                    manifest,
                    pathlib.Path(build_directory),
                    artifact_root=artifact_root,
                )
                source = built_wheel
            if source is None and relative.suffix == ".so":
                if built_native is None:
                    built_native = build_runtime_native_artifact(
                        manifest,
                        pathlib.Path(build_directory),
                        artifact_root=artifact_root,
                    )
                source = built_native
            if source is None:
                raise LetsInferError(f"no exact source is available for runtime artifact {relative}")
            sources.append(
                (entry, store_runtime_artifact(source, entry["sha256"]))
            )

        staging = pathlib.Path(
            tempfile.mkdtemp(prefix=f".{plugin_root.name}.install-", dir=plugin_root.parent)
        )
        backup = plugin_root.with_name(f".{plugin_root.name}.previous-{os.getpid()}")
        moved_existing = False
        try:
            for entry, source in sources:
                destination = staging / entry["path"]
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
            verify_artifacts(staging, manifest["runtime_plugins"]["artifacts"])
            if backup.exists():
                raise LetsInferError(f"refusing to overwrite stale install backup: {backup}")
            if plugin_root.exists():
                plugin_root.replace(backup)
                moved_existing = True
            staging.replace(plugin_root)
            plugin_root.chmod(0o700)
            if moved_existing:
                try:
                    shutil.rmtree(backup)
                except OSError as error:
                    print(
                        f"WARNING: installed exact runtime artifacts but could not remove "
                        f"the previous tree {backup}: {error}",
                        file=sys.stderr,
                    )
        except BaseException:
            if staging.exists():
                shutil.rmtree(staging)
            if moved_existing and not plugin_root.exists() and backup.exists():
                backup.replace(plugin_root)
            raise


def container_inspect(name: str) -> dict[str, Any] | None:
    result = run(["docker", "container", "inspect", name], check=False)
    if result.returncode != 0:
        return None
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise LetsInferError(f"cannot decode Docker inspection for {name}: {error}") from error
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise LetsInferError(f"unexpected Docker inspection result for {name}")
    return value[0]


def require_matching_container(
    inspection: dict[str, Any],
    manifest: dict[str, Any],
    port: int,
    *,
    manifest_sha256: str,
    runtime_digest: str | None,
) -> None:
    labels = inspection.get("Config", {}).get("Labels") or {}
    expected = {
        MANAGED_LABEL: "true",
        MANIFEST_SHA_LABEL: manifest_sha256,
        RELEASE_LABEL: manifest["release"],
        MODEL_LABEL: manifest["model"]["alias"],
        PORT_LABEL: str(port),
        SECURITY_LABEL: SECURITY_PROFILE,
        ENGINE_LABEL: adapter_for(manifest).name,
    }
    if runtime_digest is not None:
        expected[RUNTIME_DIGEST_LABEL] = runtime_digest
    if "target" in manifest:
        target = target_contract(manifest)
        expected.update(
            {
                TARGET_ID_LABEL: target["id"],
                TARGET_PLATFORM_LABEL: target["platform"],
                ACCELERATOR_ARCHITECTURE_LABEL: target["accelerator"]["architecture"],
                MEMORY_MODEL_LABEL: target["memory"]["topology"],
                GPU_COUNT_LABEL: str(target["accelerator"]["count"]),
                GPU_PARTITIONING_LABEL: target["accelerator"]["partitioning"],
            }
        )
    mismatches = [key for key, value in expected.items() if labels.get(key) != value]
    if mismatches:
        raise LetsInferError(
            "existing container is not the requested managed release "
            f"({', '.join(mismatches)} differ); refusing to adopt it"
        )
    if inspection.get("Image") != manifest["image"]["immutable_id"]:
        raise LetsInferError("existing container image does not match the release manifest")


def require_systemd_restart_authority(inspection: Mapping[str, Any]) -> None:
    restart_policy = (
        (inspection.get("HostConfig") or {}).get("RestartPolicy") or {}
    ).get("Name")
    if restart_policy != "no":
        raise LetsInferError(
            "existing managed container has an invalid restart policy"
        )


def container_exists(name: str) -> bool:
    result = run(["docker", "container", "inspect", name], check=False)
    return result.returncode == 0


def _tls_context(cert_path: pathlib.Path) -> ssl.SSLContext:
    return ssl.create_default_context(cafile=str(cert_path))


def api_url(port: int, path: str, *, secure: bool = True) -> str:
    scheme = "https" if secure else "http"
    return f"{scheme}://127.0.0.1:{port}{path}"


def local_inference_endpoint(port: int = 8000) -> str:
    hostname = socket.gethostname().split(".", 1)[0]
    return f"http://{hostname}.local:{port}/v1"


def health_ready(port: int, cert_path: pathlib.Path) -> bool:
    try:
        with urllib.request.urlopen(
            api_url(port, "/health"), timeout=2, context=_tls_context(cert_path)
        ) as response:
            return response.status == 200
    except (OSError, ssl.SSLError, urllib.error.URLError, TimeoutError):
        return False


def api_status(
    port: int,
    path: str,
    cert_path: pathlib.Path | None,
    api_key_file: pathlib.Path | None = None,
) -> int | None:
    headers: dict[str, str] = {}
    if api_key_file is not None:
        key = read_api_key(api_key_file)
        headers["Authorization"] = f"Bearer {key}"
    request = urllib.request.Request(
        api_url(port, path, secure=cert_path is not None), headers=headers
    )
    try:
        context = _tls_context(cert_path) if cert_path is not None else None
        with urllib.request.urlopen(request, timeout=5, context=context) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code
    except (OSError, ssl.SSLError, urllib.error.URLError, TimeoutError):
        return None


def inference_auth_status(
    port: int,
    cert_path: pathlib.Path,
    api_key_file: pathlib.Path | None = None,
) -> int | None:
    """Probe inference auth with an empty request that cannot generate tokens."""
    headers = {"Content-Type": "application/json"}
    if api_key_file is not None:
        headers["Authorization"] = f"Bearer {read_api_key(api_key_file)}"
    request = urllib.request.Request(
        api_url(port, "/v1/chat/completions"),
        data=b"{}",
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(
            request, timeout=5, context=_tls_context(cert_path)
        ) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code
    except (OSError, ssl.SSLError, urllib.error.URLError, TimeoutError):
        return None


def api_json(
    port: int,
    path: str,
    cert_path: pathlib.Path | None,
    api_key_file: pathlib.Path,
) -> tuple[int | None, Any]:
    request = urllib.request.Request(
        api_url(port, path, secure=cert_path is not None),
        headers={"Authorization": f"Bearer {read_api_key(api_key_file)}"},
    )
    try:
        context = _tls_context(cert_path) if cert_path is not None else None
        with urllib.request.urlopen(request, timeout=10, context=context) as response:
            try:
                payload = json.loads(response.read().decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                return response.status, None
            return response.status, payload
    except urllib.error.HTTPError as error:
        return error.code, None
    except (OSError, ssl.SSLError, urllib.error.URLError, TimeoutError):
        return None, None


def model_identity_ready(
    manifest: dict[str, Any],
    port: int,
    cert_path: pathlib.Path | None,
    api_key_file: pathlib.Path,
) -> bool:
    return model_alias_ready(
        manifest["model"]["alias"], port, cert_path, api_key_file
    )


def model_alias_ready(
    expected: str,
    port: int,
    cert_path: pathlib.Path | None,
    api_key_file: pathlib.Path,
) -> bool:
    """Probe the served alias without requiring runtime-manifest compatibility."""
    status, payload = api_json(port, "/v1/models", cert_path, api_key_file)
    if status != 200 or not isinstance(payload, dict):
        return False
    data = payload.get("data")
    if not isinstance(data, list):
        return False
    return any(isinstance(item, dict) and item.get("id") == expected for item in data)


def container_running(name: str) -> bool:
    result = run(["docker", "inspect", "--format", "{{.State.Running}}", name], check=False)
    return result.returncode == 0 and result.stdout.strip() == "true"


def redact_secrets(value: str, secrets_to_redact: Iterable[str]) -> str:
    redacted = value
    for secret in secrets_to_redact:
        if secret:
            redacted = redacted.replace(secret, "[REDACTED]")
    return redacted


def collect_container_evidence(
    name: str, evidence: pathlib.Path, *, secrets_to_redact: Iterable[str] = ()
) -> None:
    inspect = run(["docker", "inspect", name], check=False)
    write_text(evidence / "container-inspect.json", inspect.stdout or inspect.stderr)
    logs = run(["docker", "logs", name], check=False)
    write_text(
        evidence / "server.log",
        redact_secrets(
            (logs.stdout or "") + (logs.stderr or ""), secrets_to_redact
        ),
    )


def wait_for_ready(
    name: str,
    port: int,
    timeout_seconds: int,
    cert_path: pathlib.Path,
    manifest: dict[str, Any],
) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        inspection = container_inspect(name)
        if inspection is None or not inspection.get("State", {}).get(
            "Running", False
        ):
            raise LetsInferError("container exited during startup")
        require_memory_reserve(manifest, phase="runtime")
        docker_health = (
            (inspection.get("State", {}).get("Health") or {}).get("Status")
        )
        if docker_health == "healthy" and health_ready(port, cert_path):
            return
        time.sleep(2)
    raise LetsInferError(
        "server endpoint and Docker healthcheck were not healthy before the startup timeout"
    )


def prewarm(
    manifest: dict[str, Any],
    name: str,
    port: int,
    cert_path: pathlib.Path,
    api_key_file: pathlib.Path,
) -> None:
    if not manifest["cache"]["prewarm"]:
        return
    launch = launch_for(manifest, manifest["serving"], port)
    if launch.prewarm == "openai":
        body = json.dumps(
            {
                "model": manifest["model"]["id"],
                "messages": [{"role": "user", "content": "Reply with OK."}],
                "max_tokens": 1,
                "temperature": 0,
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            api_url(port, "/v1/chat/completions"),
            data=body,
            headers={
                "Authorization": f"Bearer {read_api_key(api_key_file)}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(
                request, timeout=120, context=_tls_context(cert_path)
            ) as response:
                if response.status != 200:
                    raise LetsInferError(
                        f"{adapter_for(manifest).name} prewarm returned HTTP {response.status}"
                    )
        except (OSError, ssl.SSLError, urllib.error.URLError, TimeoutError) as error:
            raise LetsInferError(
                f"{adapter_for(manifest).name} prewarm failed: {error}"
            ) from error
        return
    run(
        [
            "docker",
            "exec",
            "-e",
            "PYTHONPATH=/tmp/letsinfer-python:/plugins",
            name,
            "python3",
            "/cache/prewarm_prefixes.py",
            "--base-url",
            f"https://127.0.0.1:{port}",
            "--api-key-file",
            "/run/secrets/letsinfer-api-key",
            "--ca-cert-file",
            "/run/secrets/letsinfer-tls.crt",
            "--model",
            manifest["model"]["id"],
            "--store-root",
            "/root/.cache/letsinfer-prefix-store",
            "--capacity-bytes",
            str(manifest["cache"]["durable_capacity_bytes"]),
            "--native-capacity-bytes",
            str(manifest["cache"]["native_capacity_bytes"]),
            "--min-tokens",
            str(manifest["cache"]["min_tokens"]),
        ]
    )


def default_evidence_dir(manifest: dict[str, Any]) -> pathlib.Path:
    stamp = dt.datetime.now().astimezone().strftime("%Y%m%dT%H%M%S%z")
    return pathlib.Path.home() / ".cache/letsinfer/results/launches" / (
        f"{manifest['release']}-{stamp}"
    )


def protection_config_for_serve(
    value: str | os.PathLike[str] | dict[str, Any] | None,
    *,
    name: str,
) -> dict[str, Any] | None:
    if value is None:
        default = default_service_config_path()
        if not default.is_file():
            return None
        value = default
    if isinstance(value, (str, os.PathLike)):
        config = dict(read_service_config(pathlib.Path(value)))
    elif isinstance(value, dict):
        config = dict(value)
    else:
        raise LetsInferError("invalid Watchdog protection configuration")
    config["name"] = name
    return config


def authorize_serving_launch(
    serving: dict[str, Any],
    *,
    qualification_mode: bool,
    evidence_dir: str | None,
) -> None:
    """Keep ordinary serving fail-closed while permitting explicit qualification."""
    if serving["qualified"]:
        return
    if not qualification_mode:
        raise LetsInferError(
            f"serving configuration is not qualified: {serving['blocked_by']}"
        )
    if not evidence_dir:
        raise LetsInferError(
            "--qualification-mode requires an explicit --evidence-dir for an "
            "unqualified serving configuration"
        )


def serve(
    arguments: argparse.Namespace,
    *,
    resolved_release: tuple[pathlib.Path, dict[str, Any]] | None = None,
    release_root: pathlib.Path | None = None,
) -> int:
    manifest_path, manifest = resolved_release or resolve_model(
        arguments.model,
        getattr(arguments, "engine", None),
        target=getattr(arguments, "target", None),
    )
    verify_release_sources(
        manifest,
        release_root or manifest_source_root(manifest_path),
    )
    serving = manifest["serving"]
    qualification_mode = bool(getattr(arguments, "qualification_mode", False))
    authorize_serving_launch(
        serving,
        qualification_mode=qualification_mode,
        evidence_dir=arguments.evidence_dir,
    )
    if qualification_mode and not serving["qualified"]:
        print(
            "WARNING: qualification launch of unqualified serving configuration: "
            f"{serving['blocked_by']}",
            file=sys.stderr,
        )

    name = arguments.name or f"letsinfer-{adapter_for(manifest).name.replace('.', '-')}"
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name):
        raise LetsInferError("container name contains unsupported characters")
    port = arguments.port
    model_cache = expanded_path(arguments.model_cache or manifest["container"]["model_cache"])
    plugin_root = (
        expanded_path(arguments.plugin_root)
        if arguments.plugin_root
        else default_plugin_root(manifest, sha256_file(manifest_path))
    )
    store_root = (
        expanded_path(arguments.store_root)
        if arguments.store_root
        else default_store_root(manifest)
    )
    runtime_cache_root = (
        expanded_path(arguments.runtime_cache_root)
        if arguments.runtime_cache_root
        else default_runtime_cache_root(manifest)
    )
    api_key_file = expanded_path(
        arguments.api_key_file or default_engine_api_key_path()
    )
    tls_cert_file = expanded_path(arguments.tls_cert_file or default_tls_cert_path())
    tls_key_file = expanded_path(arguments.tls_key_file or default_tls_key_path())
    protection_config = protection_config_for_serve(
        getattr(arguments, "protection_config", None), name=name
    )
    protection_generation = secrets.token_hex(16) if protection_config else None
    manifest_sha256 = sha256_file(manifest_path)
    supplied_runtime_root = getattr(arguments, "runtime_artifact_root", None)
    runtime_digest = getattr(arguments, "runtime_digest", None)
    if supplied_runtime_root is not None:
        runtime_artifact_root = pathlib.Path(supplied_runtime_root).expanduser()
        if runtime_digest is None:
            try:
                runtime_digest = verify_descriptor(runtime_artifact_root).digest
            except RuntimePackError as error:
                raise LetsInferError(str(error)) from error
    else:
        runtime_receipt = runtime_receipt_for_manifest(manifest_path)
        runtime_artifact_root = (
            pathlib.Path(runtime_receipt["object_root"]).expanduser()
            if runtime_receipt is not None
            else None
        )
        runtime_digest = (
            runtime_receipt["digest"] if runtime_receipt is not None else None
        )
    command = docker_command(
        manifest,
        name=name,
        manifest_sha256=manifest_sha256,
        runtime_digest=runtime_digest,
        port=port,
        model_cache=model_cache,
        plugin_root=plugin_root,
        store_root=store_root,
        runtime_cache_root=runtime_cache_root,
        api_key_file=api_key_file,
        tls_cert_file=tls_cert_file,
        tls_key_file=tls_key_file,
    )
    if arguments.dry_run:
        print(
            json.dumps(
                {
                    "manifest": str(manifest_path),
                    "release": manifest["release"],
                    "engine": adapter_for(manifest).name,
                    "status": manifest["status"],
                    "model": manifest["model"]["id"],
                    "revision": manifest["model"]["revision"],
                    "serving": serving,
                    "qualified": serving["qualified"],
                    "qualification_mode": qualification_mode,
                    "command": command,
                },
                indent=2,
            )
        )
        return 0

    host = verify_host_target(manifest)
    ensure_image(
        manifest,
        build=qualification_mode,
        artifact_root=runtime_artifact_root,
    )
    if adapter_for(manifest).requires_runtime_plugins or requires_core_cache_plugin(manifest):
        try:
            verify_installed_release(
                manifest, model_cache=model_cache, plugin_root=plugin_root
            )
        except LetsInferError:
            install_runtime_plugins(
                manifest,
                plugin_root=plugin_root,
                wheel_source=None,
                artifact_root=release_root or manifest_source_root(manifest_path),
            )
    actual_image_id = verify_installed_release(
        manifest, model_cache=model_cache, plugin_root=plugin_root
    )
    api_key = read_api_key(api_key_file)
    validate_tls_material(tls_cert_file, tls_key_file)
    inspection = container_inspect(name)
    if inspection is not None:
        if not arguments.existing_ok:
            raise LetsInferError(f"container already exists: {name}")
        require_matching_container(
            inspection,
            manifest,
            port,
            manifest_sha256=manifest_sha256,
            runtime_digest=runtime_digest,
        )
        require_systemd_restart_authority(inspection)
        try:
            if protection_config:
                publish_protection_state(
                    protection_config, protection_generation, "pending"
                )
            if not inspection.get("State", {}).get("Running", False):
                require_memory_reserve(manifest, phase="launch")
                run(["docker", "start", name])
                inspection = container_inspect(name)
                if inspection is None:
                    raise LetsInferError("managed container disappeared after start")
            if protection_config:
                publish_protection_state(
                    protection_config,
                    protection_generation,
                    "starting",
                    inspection=inspection,
                )
            wait_for_ready(
                name,
                port,
                manifest["container"]["startup_timeout_seconds"],
                tls_cert_file,
                manifest,
            )
            if not model_identity_ready(
                manifest, port, tls_cert_file, api_key_file
            ):
                raise LetsInferError(
                    "authenticated model identity does not match the release manifest"
                )
            prewarm(manifest, name, port, tls_cert_file, api_key_file)
            require_memory_reserve(manifest, phase="runtime")
            if protection_config:
                current = container_inspect(name)
                if current is None:
                    raise LetsInferError("managed container disappeared before protection armed")
                publish_protection_state(
                    protection_config,
                    protection_generation,
                    "armed",
                    inspection=current,
                )
            print(f"HEALTHY {name} existing=true")
            return 0
        except BaseException:
            if protection_config and not protection_trip_latched(protection_config):
                disarm_protection(protection_config)
            raise

    memory = require_memory_reserve(manifest, phase="launch")
    evidence = pathlib.Path(arguments.evidence_dir) if arguments.evidence_dir else default_evidence_dir(manifest)
    evidence.mkdir(parents=True, exist_ok=False)
    ensure_private_directory(store_root)
    ensure_runtime_home(runtime_cache_root)
    launch = {
        "status": "admitted",
        "timestamp": dt.datetime.now().astimezone().isoformat(),
        "manifest_path": str(manifest_path),
        "release": manifest["release"],
        "engine": adapter_for(manifest).name,
        "release_status": manifest["status"],
        "model": manifest["model"],
        "serving": serving,
        "qualification_mode": qualification_mode,
        "image_id": actual_image_id,
        "target": host,
        "memory_admission": memory,
        "store_root": str(store_root),
        "runtime_cache_root": str(runtime_cache_root),
        "security_profile": SECURITY_PROFILE,
        "command": command,
    }
    atomic_json(evidence / "release-manifest.json", manifest)
    atomic_json(evidence / "launch.json", launch)

    try:
        if protection_config:
            publish_protection_state(
                protection_config, protection_generation, "pending"
            )
        started = run(command)
        launch["container_id"] = started.stdout.strip()
        launch["status"] = "starting"
        atomic_json(evidence / "launch.json", launch)

        if protection_config:
            inspection = container_inspect(name)
            if inspection is None:
                raise LetsInferError("managed container disappeared before protection binding")
            publish_protection_state(
                protection_config,
                protection_generation,
                "starting",
                inspection=inspection,
            )

        wait_for_ready(
            name,
            port,
            manifest["container"]["startup_timeout_seconds"],
            tls_cert_file,
            manifest,
        )
        if not model_identity_ready(
            manifest, port, tls_cert_file, api_key_file
        ):
            raise LetsInferError(
                "authenticated model identity does not match the release manifest"
            )
        prewarm(manifest, name, port, tls_cert_file, api_key_file)
        launch["runtime_memory"] = require_memory_reserve(
            manifest, phase="runtime"
        )
        launch["status"] = "healthy"
        launch["healthy_timestamp"] = dt.datetime.now().astimezone().isoformat()
        if protection_config:
            inspection = container_inspect(name)
            if inspection is None:
                raise LetsInferError("managed container disappeared before protection armed")
            publish_protection_state(
                protection_config,
                protection_generation,
                "armed",
                inspection=inspection,
            )
        atomic_json(evidence / "launch.json", launch)
        collect_container_evidence(
            name, evidence, secrets_to_redact=(api_key,)
        )
    except BaseException as error:
        if protection_config and not protection_trip_latched(protection_config):
            disarm_protection(protection_config)
        launch["status"] = "failed"
        launch["error"] = str(error)
        atomic_json(evidence / "launch.json", launch)
        collect_container_evidence(
            name, evidence, secrets_to_redact=(api_key,)
        )
        inspection = container_inspect(name)
        if inspection is not None:
            labels = inspection.get("Config", {}).get("Labels") or {}
            if labels.get(MANAGED_LABEL) == "true":
                run(["docker", "update", "--restart", "no", name], check=False)
                run(["docker", "stop", "--time", "30", name], check=False)
                run(["docker", "rm", name], check=False)
        raise

    print(f"HEALTHY {name} evidence={evidence}")
    return 0


def default_service_config_path() -> pathlib.Path:
    return site_config_root() / "service.json"


def read_service_config(path: pathlib.Path) -> dict[str, Any]:
    path = absolute_user_path(path)
    if path.is_symlink():
        raise LetsInferError(f"service configuration cannot be a symlink: {path}")
    try:
        details = path.stat()
    except OSError as error:
        raise LetsInferError(f"cannot stat service configuration {path}: {error}") from error
    if details.st_uid != os.getuid() or stat.S_IMODE(details.st_mode) & 0o077:
        raise LetsInferError(f"service configuration must be private and user-owned: {path}")
    config = read_json(path)
    if (
        type(config.get("schema_version")) is not int
        or config.get("schema_version") != SERVICE_CONFIG_VERSION
    ):
        raise LetsInferError(f"unsupported service configuration: {path}")
    required = {
        "engine": str,
        "model": str,
        "release": str,
        "name": str,
        "gateway_listen": str,
        "gateway_protocol": str,
        "gateway_port": int,
        "gateway_max_connections": int,
        "gateway_queue_timeout_seconds": int,
        "gateway_telemetry_file": str,
        "engine_port": int,
        "placement_id": str,
        "placement_strategy": str,
        "placement_members": list,
        "topology_sha256": str,
        "model_cache": str,
        "plugin_root": str,
        "store_root": str,
        "runtime_cache_root": str,
        "engine_api_key_file": str,
        "gateway_api_key_file": str,
        "tls_cert_file": str,
        "tls_key_file": str,
        "source_root": str,
        "manifest_path": str,
        "manifest_sha256": str,
        "watchdog_binary_path": str,
        "watchdog_binary_sha256": str,
        "watchdog_source_sha256": str,
        "watchdog_data_root": str,
        "protection_root": str,
        "watchdog_listen": str,
        "watchdog_port": int,
        "memory_pressure_available_bytes": int,
        "watchdog_cert_file": str,
        "watchdog_key_file": str,
        "watchdog_controller_ca_file": str,
        "watchdog_controller_ca_key_file": str,
        "watchdog_local_controller_cert_file": str,
        "watchdog_local_controller_key_file": str,
        "installation_id": str,
        "watchdog_controller_allowlist_file": str,
        "watchdog_public_state_file": str,
    }
    for key, expected in required.items():
        value = config.get(key)
        if not isinstance(value, expected) or (
            expected is int and isinstance(value, bool)
        ):
            raise LetsInferError(f"service configuration {key} must be {expected.__name__}")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", config["name"]):
        raise LetsInferError("service configuration contains an invalid container name")
    if config["engine"] not in ADAPTERS:
        raise LetsInferError("service configuration contains an unsupported engine")
    if not SHA256_RE.fullmatch(config["manifest_sha256"]):
        raise LetsInferError("service configuration contains an invalid manifest hash")
    if not SHA256_RE.fullmatch(config["installation_id"]):
        raise LetsInferError("service configuration contains an invalid installation identity")
    for key in ("gateway_port", "engine_port"):
        if config[key] not in range(1, 65536):
            raise LetsInferError(f"service configuration contains an invalid {key}")
    if config["gateway_port"] == config["engine_port"]:
        raise LetsInferError("gateway and engine ports must be distinct")
    if not re.fullmatch(r"[0-9a-f]{32}", config["placement_id"]):
        raise LetsInferError("service configuration contains an invalid placement identity")
    if config["placement_strategy"] not in {"single", "replicated", "distributed"}:
        raise LetsInferError("service configuration contains an invalid placement strategy")
    if (
        not config["placement_members"]
        or not all(
            isinstance(member_id, str) and re.fullmatch(r"[0-9a-f]{32}", member_id)
            for member_id in config["placement_members"]
        )
        or len(set(config["placement_members"])) != len(config["placement_members"])
    ):
        raise LetsInferError("service configuration contains invalid placement members")
    if not SHA256_RE.fullmatch(config["topology_sha256"]):
        raise LetsInferError("service configuration contains an invalid topology identity")
    if not isinstance(config["gateway_listen"], str) or not config["gateway_listen"]:
        raise LetsInferError("service configuration contains an invalid gateway listener")
    if config["gateway_protocol"] != "http":
        raise LetsInferError("service configuration contains an invalid gateway protocol")
    if config["gateway_max_connections"] not in range(1, 257):
        raise LetsInferError("service configuration contains an invalid gateway connection limit")
    if config["gateway_queue_timeout_seconds"] not in range(1, 3601):
        raise LetsInferError("service configuration contains an invalid gateway queue timeout")
    for key in ("source_root", "manifest_path"):
        value = pathlib.Path(config[key]).expanduser()
        if not value.is_absolute():
            raise LetsInferError(f"service configuration {key} must be absolute")
    for key in ("watchdog_binary_sha256", "watchdog_source_sha256"):
        if not SHA256_RE.fullmatch(config[key]):
            raise LetsInferError(f"service configuration contains an invalid {key}")
    if config["watchdog_port"] not in range(1, 65536):
        raise LetsInferError("service configuration contains an invalid watchdog port")
    if config["memory_pressure_available_bytes"] <= 0:
        raise LetsInferError(
            "service configuration contains an invalid memory-pressure threshold"
        )
    for key in (
        "watchdog_binary_path",
        "watchdog_data_root",
        "protection_root",
        "watchdog_cert_file",
        "watchdog_key_file",
        "watchdog_controller_ca_file",
        "watchdog_controller_ca_key_file",
        "watchdog_local_controller_cert_file",
        "watchdog_local_controller_key_file",
        "watchdog_controller_allowlist_file",
        "watchdog_public_state_file",
        "gateway_telemetry_file",
    ):
        if not pathlib.Path(config[key]).expanduser().is_absolute():
            raise LetsInferError(f"service configuration {key} must be absolute")
    expected_public_state = (
        pathlib.Path(config["watchdog_data_root"]).expanduser()
        / WATCHDOG_PUBLIC_STATE_DIRECTORY
        / f"{config['manifest_sha256']}.state"
    )
    if pathlib.Path(config["watchdog_public_state_file"]).expanduser() != expected_public_state:
        raise LetsInferError("service configuration contains a non-canonical Watchdog state path")
    expected_protection_root = (
        pathlib.Path(config["watchdog_data_root"]).expanduser()
        / PROTECTION_ROOT_NAME
        / config["placement_id"]
    )
    if pathlib.Path(config["protection_root"]).expanduser() != expected_protection_root:
        raise LetsInferError("service configuration contains a non-canonical protection root")
    runtime_fields = {
        "runtime_name": str,
        "runtime_version": str,
        "runtime_digest": str,
        "runtime_policy": str,
    }
    present_runtime_fields = set(runtime_fields).intersection(config)
    if present_runtime_fields and present_runtime_fields != set(runtime_fields):
        raise LetsInferError("service configuration has an incomplete runtime receipt")
    for key, expected in runtime_fields.items():
        if key in config and not isinstance(config[key], expected):
            raise LetsInferError(f"service configuration {key} must be {expected.__name__}")
    if "runtime_digest" in config and not SHA256_RE.fullmatch(config["runtime_digest"]):
        raise LetsInferError("service configuration contains an invalid runtime digest")
    return config


def resolve_service_placement(
    manifest: dict[str, Any], manifest_sha256: str
) -> dict[str, Any]:
    """Resolve the manifest against freshly authenticated site topology."""
    identity, _graph, placement = resolve_manifest_placement(manifest)
    if placement.strategy != "single" or len(placement.member_ids) != 1:
        raise LetsInferError(
            "this target requires the engine-group installation path"
        )
    return service_placement_identity(identity, placement, manifest_sha256)


def resolve_manifest_placement(
    manifest: Mapping[str, Any],
) -> tuple[Any, TopologyGraph, Any]:
    try:
        identity, graph = _fresh_site_topology()
        placement = graph.resolve(
            target_contract(manifest), coordinator_id=identity.coordinator_id
        )
    except (SiteError, TopologyError) as error:
        raise LetsInferError(f"cannot resolve runtime placement: {error}") from error
    return identity, graph, placement


def service_placement_identity(
    identity: Any, placement: Any, manifest_sha256: str
) -> dict[str, Any]:
    identity_material = {
        "contract": "letsinfer-placement-v1",
        "site_id": identity.site_id,
        "manifest_sha256": manifest_sha256,
        "topology_sha256": placement.topology_sha256,
        "strategy": placement.strategy,
        "members": list(placement.member_ids),
    }
    return {
        "placement_id": hashlib.sha256(canonical_bytes(identity_material)).hexdigest()[:32],
        "placement_strategy": placement.strategy,
        "placement_members": list(placement.member_ids),
        "topology_sha256": placement.topology_sha256,
    }


def service_placement_document(
    config: dict[str, Any], manifest: dict[str, Any], state: str
) -> dict[str, Any]:
    identity = read_site_identity()
    if identity.member_id not in config["placement_members"]:
        raise LetsInferError("local member is not part of the configured placement")
    serving = manifest["serving"]
    adapter = adapter_for(manifest)
    endpoint = {
        "member_id": identity.member_id,
        "url": f"https://127.0.0.1:{config['engine_port']}",
        "credential_file": config["engine_api_key_file"],
        "ca_file": config["tls_cert_file"],
        "token_count_path": adapter.token_count_path,
        "token_count_protocol": adapter.token_count_protocol,
        "max_active_requests": serving["max_active_requests"],
        "max_context_tokens": serving["max_context_tokens"],
        "healthy": state == "running",
        "memory_pressure": False,
        "temperature_c": -1,
        "prefix_keys": [],
    }
    runtime_identity = (
        f"{config['runtime_name']}@{config['runtime_version']}"
        f"@sha256:{config['runtime_digest']}"
        if "runtime_name" in config
        else f"{config['release']}@sha256:{config['manifest_sha256']}"
    )
    return {
        "placement_id": config["placement_id"],
        "model": manifest["model"]["alias"],
        "runtime": runtime_identity,
        "target": target_contract(manifest)["id"],
        "strategy": config["placement_strategy"],
        "state": state,
        "topology_sha256": config["topology_sha256"],
        "members": config["placement_members"],
        "endpoints": [endpoint],
        "capacity": {
            "max_connections": serving["max_connections"],
            "max_active_requests": serving["max_active_requests"],
            "max_context_tokens": serving["max_context_tokens"],
        },
    }


def update_service_placement(
    config: dict[str, Any], manifest: dict[str, Any], state: str
) -> None:
    try:
        identity = read_site_identity()
        with SiteStore(identity=identity) as store:
            store.set_placement(service_placement_document(config, manifest, state))
    except SiteError as error:
        raise LetsInferError(f"cannot update service placement: {error}") from error


def configured_release(
    config: dict[str, Any]
) -> tuple[pathlib.Path, dict[str, Any]]:
    root = pathlib.Path(config["source_root"]).expanduser()
    path = pathlib.Path(config["manifest_path"]).expanduser()
    path, manifest = validate_control_bundle(
        root, path, config["manifest_sha256"]
    )
    if manifest["release"] != config["release"]:
        raise LetsInferError("service configuration release does not match its manifest")
    if adapter_for(manifest).name != config["engine"]:
        raise LetsInferError("service configuration engine does not match its manifest")
    if manifest["model"]["alias"] != config["model"]:
        raise LetsInferError("service configuration model alias does not match its release")
    if (
        manifest["watchdog"]["protection"]["warning_available_bytes"]
        != config["memory_pressure_available_bytes"]
    ):
        raise LetsInferError(
            "service configuration memory-pressure threshold does not match its manifest"
        )
    return path, manifest


def bind_config_to_control_bundle(config: dict[str, Any]) -> dict[str, Any]:
    manifest_sha = config["manifest_sha256"]
    source = pathlib.Path(config["source_root"]).expanduser()
    manifest_path = pathlib.Path(config["manifest_path"]).expanduser()
    manifest_path, manifest = validate_control_bundle(
        source, manifest_path, manifest_sha
    )
    candidate_root, manifest_path = install_control_bundle(
        manifest_path,
        manifest,
        artifact_roots=(source, source_root()),
    )
    if manifest["model"]["alias"] != config["model"]:
        raise LetsInferError("previous service bundle model alias is inconsistent")
    bound = dict(config)
    bound["source_root"] = str(candidate_root)
    bound["manifest_path"] = str(manifest_path)
    return bound


def retained_control_bundle_for_rollback(config: dict[str, Any]) -> bool:
    """Verify rollback bytes without accepting the old runtime schema."""
    root = pathlib.Path(config["source_root"]).expanduser()
    manifest = pathlib.Path(config["manifest_path"]).expanduser()
    manifest_sha256 = config["manifest_sha256"]
    try:
        if root.is_symlink() or not root.is_dir() or manifest.is_symlink():
            return False
        _records, _core_manifest, core_identity = _core_release(root)
        if root.name != _control_bundle_identity(core_identity, manifest_sha256):
            return False
        manifest.resolve(strict=True).relative_to(root.resolve(strict=True))
        return sha256_file(manifest) == manifest_sha256
    except (KeyError, OSError, ValueError, LetsInferError):
        return False


def serve_from_config(arguments: argparse.Namespace) -> int:
    config = read_service_config(pathlib.Path(arguments.config))
    configured_root = pathlib.Path(config["source_root"]).expanduser()
    try:
        exact_configured_root = configured_root.resolve(strict=True)
        executable_root = source_root().resolve(strict=True)
    except OSError as error:
        raise LetsInferError(
            f"cannot resolve the configured control bundle: {error}"
        ) from error
    if exact_configured_root != executable_root:
        raise LetsInferError(
            "service executable does not match the configured immutable control bundle"
        )
    resolved = configured_release(config)
    runtime_artifact_root: pathlib.Path | None = None
    if "runtime_digest" in config:
        runtime_artifact_root = default_runtime_home() / "objects" / config["runtime_digest"]
        try:
            installed_runtime = verify_descriptor(runtime_artifact_root)
        except RuntimePackError as error:
            raise LetsInferError(str(error)) from error
        manifest = resolved[1]
        if (
            installed_runtime.digest != config["runtime_digest"]
            or installed_runtime.descriptor["name"] != config["runtime_name"]
            or installed_runtime.descriptor["version"] != config["runtime_version"]
            or installed_runtime.descriptor["model"] != manifest["model"]["alias"]
            or installed_runtime.descriptor["engine"] != adapter_for(manifest).name
            or installed_runtime.descriptor["target"] != target_contract(manifest)["id"]
        ):
            raise LetsInferError(
                "service configuration does not match its immutable runtime object"
            )
    manifest = resolved[1]
    update_service_placement(config, manifest, "starting")
    try:
        result = serve(
            argparse.Namespace(
                engine=config["engine"],
                model=config["release"],
                port=config["engine_port"],
                name=config["name"],
                model_cache=config["model_cache"],
                plugin_root=config["plugin_root"],
                store_root=config["store_root"],
                runtime_cache_root=config["runtime_cache_root"],
                api_key_file=config["engine_api_key_file"],
                tls_cert_file=config["tls_cert_file"],
                tls_key_file=config["tls_key_file"],
                evidence_dir=None,
                dry_run=False,
                existing_ok=True,
                protection_config=config,
                runtime_artifact_root=runtime_artifact_root,
                runtime_digest=config.get("runtime_digest"),
            ),
            resolved_release=resolved,
            release_root=configured_root,
        )
    except BaseException:
        try:
            update_service_placement(config, manifest, "failed")
        except BaseException as placement_error:
            raise LetsInferError(
                "engine launch failed and its placement could not be marked failed"
            ) from placement_error
        raise
    update_service_placement(config, manifest, "running")
    return result


def _systemd_quote(value: pathlib.Path) -> str:
    text = str(value)
    if "\n" in text or "\0" in text:
        raise LetsInferError("systemd paths cannot contain newlines or NUL bytes")
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%") + '"'


def render_engine_service(
    config_path: pathlib.Path,
    startup_timeout_seconds: int,
    executable_root: pathlib.Path | None = None,
) -> str:
    executable = (executable_root or source_root()) / "bin/letsinfer"
    timeout = startup_timeout_seconds + 60
    return f"""[Unit]
Description=Let's Infer guarded inference engine
Requires={SERVICE_NAME}
PartOf={SERVICE_NAME}
After={SERVICE_NAME} network-online.target docker.service
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=oneshot
RemainAfterExit=yes
MemoryAccounting=yes
Environment=PYTHONDONTWRITEBYTECODE=1
UMask=0077
ExecStart={_systemd_quote(executable)} service-start --config {_systemd_quote(config_path)}
ExecStop={_systemd_quote(executable)} service-stop --config {_systemd_quote(config_path)}
TimeoutStartSec={timeout}
TimeoutStopSec=180
"""


def render_gateway_service(
    config_path: pathlib.Path,
    config: dict[str, Any],
    executable_root: pathlib.Path | None = None,
) -> str:
    executable = (executable_root or source_root()) / "bin/letsinfer"
    return f"""[Unit]
Description=Let's Infer coordinator inference gateway
Requires={SERVICE_NAME} {SITE_SERVICE_NAME}
PartOf={SITE_SERVICE_NAME}
After=network-online.target {SITE_SERVICE_NAME} {SERVICE_NAME}
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
MemoryAccounting=yes
MemoryHigh={GATEWAY_MEMORY_HIGH_BYTES}
MemoryMax={GATEWAY_MEMORY_LIMIT_BYTES}
MemorySwapMax=0
Restart=always
RestartSec=2
UMask=0077
NoNewPrivileges=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart={_systemd_quote(executable)} gateway --listen {shlex.quote(config['gateway_listen'])} --port {config['gateway_port']} --telemetry-file {_systemd_quote(pathlib.Path(config['gateway_telemetry_file']))} --queue-timeout {config['gateway_queue_timeout_seconds']} --max-connections {config['gateway_max_connections']}
TimeoutStopSec=30

[Install]
WantedBy=default.target
"""


def install_core_gateway_service(
    *,
    executable_root: pathlib.Path | None = None,
    replace_active: bool = False,
) -> dict[str, Any]:
    """Install the stable site gateway before any placement is active."""
    root = executable_root or source_root()
    config_path = site_config_root() / "gateway.json"
    config = {
        "schema_version": 2,
        "gateway_listen": "0.0.0.0",
        "gateway_protocol": "http",
        "gateway_port": 8000,
        "gateway_max_connections": 256,
        "gateway_queue_timeout_seconds": 300,
        "gateway_telemetry_file": str(default_gateway_telemetry_path()),
    }
    ensure_private_directory(config_path.parent)
    ensure_private_directory(default_gateway_telemetry_path().parent)
    if platform.system() == "Darwin":
        config_snapshot = _snapshot_user_file(config_path)
        executable = root / "bin/letsinfer"
        agent = macos_services.LaunchAgent(
            label=macos_services.GATEWAY_LABEL,
            arguments=(
                str(executable),
                "gateway",
                "--listen",
                config["gateway_listen"],
                "--port",
                str(config["gateway_port"]),
                "--telemetry-file",
                config["gateway_telemetry_file"],
                "--queue-timeout",
                str(config["gateway_queue_timeout_seconds"]),
                "--max-connections",
                str(config["gateway_max_connections"]),
            ),
            environment={"PYTHONDONTWRITEBYTECODE": "1"},
        )
        try:
            atomic_json(config_path, config)
            config_path.chmod(0o600)
            macos_services.install_launch_agent(agent)
        except (macos_services.MacOSServiceError, OSError) as failure:
            try:
                _restore_user_file(config_path, config_snapshot)
            except (LetsInferError, OSError) as rollback:
                raise LetsInferError(
                    f"macOS gateway activation failed and rollback was incomplete: {rollback}"
                ) from failure
            raise LetsInferError(
                f"macOS gateway activation failed; previous state restored: {failure}"
            ) from failure
        return config
    unit_root = pathlib.Path.home() / ".config/systemd/user"
    unit_root.mkdir(parents=True, exist_ok=True)
    unit = unit_root / GATEWAY_SERVICE_NAME
    expected = render_gateway_service(config_path, config, root)
    previous = _unit_enabled_active(GATEWAY_SERVICE_NAME)
    if previous[1] == "active" and not replace_active:
        try:
            if unit.is_symlink() or config_path.is_symlink():
                raise LetsInferError(
                    "active gateway service files cannot be symlinks"
                )
            existing_config = read_json(config_path)
            config_mode = stat.S_IMODE(config_path.stat().st_mode)
            if (
                unit.read_text(encoding="utf-8") != expected
                or existing_config != config
                or config_mode != 0o600
            ):
                raise LetsInferError(
                    "the active site gateway has a different core configuration"
                )
        except (OSError, json.JSONDecodeError) as error:
            raise LetsInferError(f"cannot verify active gateway unit: {error}") from error
        return config
    config_snapshot = _snapshot_user_file(config_path)
    snapshot = _snapshot_user_file(unit)
    loaded = False
    try:
        if previous[1] == "active":
            run_passthrough(["systemctl", "--user", "stop", GATEWAY_SERVICE_NAME])
        atomic_json(config_path, config)
        config_path.chmod(0o600)
        write_text(unit, expected)
        unit.chmod(0o644)
        run(["systemctl", "--user", "daemon-reload"])
        loaded = True
        run(["systemctl", "--user", "enable", GATEWAY_SERVICE_NAME])
        run_passthrough(["systemctl", "--user", "start", GATEWAY_SERVICE_NAME])
        enabled, active, memory_bytes = _service_state(GATEWAY_SERVICE_NAME)
        if enabled != "enabled" or active != "active":
            raise LetsInferError("site gateway did not become enabled and active")
        if memory_bytes is None or memory_bytes >= GATEWAY_MEMORY_LIMIT_BYTES:
            raise LetsInferError(
                f"site gateway memory is {memory_bytes} bytes; "
                f"the limit is below {GATEWAY_MEMORY_LIMIT_BYTES} bytes"
            )
        return config
    except BaseException as failure:
        errors: list[str] = []
        if loaded:
            run(
                ["systemctl", "--user", "stop", GATEWAY_SERVICE_NAME],
                check=False,
            )
        try:
            _restore_user_file(unit, snapshot)
            _restore_user_file(config_path, config_snapshot)
            run(["systemctl", "--user", "daemon-reload"])
            _restore_unit_enablement(GATEWAY_SERVICE_NAME, previous[0])
            if previous[1] == "active":
                run_passthrough(
                    ["systemctl", "--user", "start", GATEWAY_SERVICE_NAME]
                )
        except BaseException as error:
            errors.append(str(error))
        if errors:
            raise LetsInferError(
                "gateway activation failed and rollback was incomplete: "
                + "; ".join(errors)
            ) from failure
        raise LetsInferError(
            f"gateway activation failed; previous state restored: {failure}"
        ) from failure


def render_site_service(executable_root: pathlib.Path | None = None) -> str:
    executable = (executable_root or source_root()) / "bin/letsinfer"
    return f"""[Unit]
Description=Let's Infer private site agent
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
MemoryAccounting=yes
MemoryHigh={SITE_AGENT_MEMORY_HIGH_BYTES}
MemoryMax={SITE_AGENT_MEMORY_LIMIT_BYTES}
MemorySwapMax=0
Restart=always
RestartSec=2
UMask=0077
TasksMax={SITE_AGENT_TASK_LIMIT}
LimitNOFILE=128
NoNewPrivileges=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart={_systemd_quote(executable)} site-agent --listen 0.0.0.0 --port {SITE_CONTROL_PORT}
TimeoutStopSec=15

[Install]
WantedBy=default.target
"""


def install_site_service_only(
    *,
    no_start: bool = False,
    unit_dir: pathlib.Path | None = None,
    executable_root: pathlib.Path | None = None,
) -> None:
    if not user_lingering_enabled():
        if platform.system() == "Darwin":
            raise LetsInferError(
                "the macOS launchd user domain is unavailable; log into the target user session"
            )
        raise LetsInferError(
            "user-systemd lingering is required before installing the site service"
        )
    root = executable_root or source_root()
    executable = root / "bin/letsinfer"
    if not executable.is_file() or executable.is_symlink():
        raise LetsInferError(f"site service executable is unavailable: {executable}")
    if platform.system() == "Darwin":
        if unit_dir is not None:
            raise LetsInferError("a custom systemd unit directory is not valid on macOS")
        try:
            macos_services.install_launch_agent(
                macos_services.LaunchAgent(
                    label=macos_services.SITE_LABEL,
                    arguments=(
                        str(executable),
                        "site-agent",
                        "--listen",
                        "0.0.0.0",
                        "--port",
                        str(SITE_CONTROL_PORT),
                    ),
                    environment={"PYTHONDONTWRITEBYTECODE": "1"},
                ),
                no_start=no_start,
            )
        except macos_services.MacOSServiceError as error:
            raise LetsInferError(f"cannot install macOS site service: {error}") from error
        return
    unit_root = unit_dir or pathlib.Path.home() / ".config/systemd/user"
    unit_root.mkdir(parents=True, exist_ok=True)
    path = unit_root / SITE_SERVICE_NAME
    snapshot = _snapshot_user_file(path)
    previous = _unit_enabled_active(SITE_SERVICE_NAME)
    if previous[0] not in {"enabled", "disabled", "not-found"}:
        raise LetsInferError(
            f"refusing site-service install while enablement is {previous[0]!r}"
        )
    if previous[1] not in {"active", "inactive", "failed"}:
        raise LetsInferError(
            f"refusing site-service install while state is {previous[1]!r}"
        )
    if no_start and previous[1] == "active":
        raise LetsInferError("--no-service cannot replace an active site service")
    loaded = False
    try:
        if previous[1] == "active":
            run_passthrough(["systemctl", "--user", "stop", SITE_SERVICE_NAME])
        write_text(path, render_site_service(root))
        path.chmod(0o644)
        run(["systemctl", "--user", "daemon-reload"])
        loaded = True
        run(["systemctl", "--user", "enable", SITE_SERVICE_NAME])
        if not no_start:
            run_passthrough(["systemctl", "--user", "start", SITE_SERVICE_NAME])
            enabled, active, memory_bytes = _service_state(SITE_SERVICE_NAME)
            if enabled != "enabled" or active != "active":
                raise LetsInferError("site service did not become enabled and active")
            if memory_bytes is None or memory_bytes >= SITE_AGENT_MEMORY_LIMIT_BYTES:
                raise LetsInferError(
                    f"Let's Infer site-agent memory is {memory_bytes} bytes; "
                    f"the limit is below {SITE_AGENT_MEMORY_LIMIT_BYTES} bytes"
                )
    except BaseException as failure:
        errors: list[str] = []
        if loaded:
            result = run(
                ["systemctl", "--user", "stop", SITE_SERVICE_NAME], check=False
            )
            if result.returncode != 0:
                errors.append("could not stop replacement site service")
        try:
            _restore_user_file(path, snapshot)
            run(["systemctl", "--user", "daemon-reload"])
            _restore_unit_enablement(SITE_SERVICE_NAME, previous[0])
            if previous[1] == "active":
                run_passthrough(["systemctl", "--user", "start", SITE_SERVICE_NAME])
        except BaseException as error:
            errors.append(str(error))
        if errors:
            raise LetsInferError(
                "site-service activation failed and rollback was incomplete: "
                + "; ".join(errors)
            ) from failure
        raise LetsInferError(
            f"site-service activation failed; previous state restored: {failure}"
        ) from failure


def render_user_service(
    config: dict[str, Any], manifest: dict[str, Any]
) -> str:
    watchdog = manifest["watchdog"]
    protection = watchdog["protection"]
    executable = pathlib.Path(config["watchdog_binary_path"])
    protection_root = pathlib.Path(config["watchdog_data_root"]) / PROTECTION_ROOT_NAME
    return f"""[Unit]
Description=Let's Infer resident Watchdog
Wants={SITE_SERVICE_NAME}
After=network-online.target {SITE_SERVICE_NAME}
StartLimitIntervalSec=0

[Service]
Type=simple
MemoryAccounting=yes
MemoryHigh={watchdog['memory_high_bytes']}
MemoryMax={watchdog['memory_max_bytes']}
MemorySwapMax=0
Restart=always
RestartSec=5
UMask=0077
TasksMax=8
LimitNOFILE=64
Nice=10
CPUWeight=1
IOWeight=1
IOSchedulingClass=idle
NoNewPrivileges=yes
# A user unit must remain in the host user namespace so it can signal the
# same-UID container init through its bound pidfd. Filesystem namespace
# directives (including PrivateTmp/ProtectSystem/ProtectHome/ReadWritePaths)
# make systemd create an unprivileged user namespace and the kernel then
# rejects nonzero signals to the host-namespace process with EPERM.
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallArchitectures=native
ExecStart={_systemd_quote(executable)} --listen {_systemd_quote(config['watchdog_listen'])} --port {config['watchdog_port']} --data-dir {_systemd_quote(pathlib.Path(config['watchdog_data_root']))} --cert {_systemd_quote(pathlib.Path(config['watchdog_cert_file']))} --key {_systemd_quote(pathlib.Path(config['watchdog_key_file']))} --controller-ca {_systemd_quote(pathlib.Path(config['watchdog_controller_ca_file']))} --controllers {_systemd_quote(pathlib.Path(config['watchdog_controller_allowlist_file']))} --site-state {_systemd_quote(pathlib.Path(config['watchdog_public_state_file']))} --gateway-metrics {_systemd_quote(pathlib.Path(config['gateway_telemetry_file']))} --sample-ms {watchdog['sample_interval_ms']} --flush-ms {watchdog['flush_interval_ms']} --max-controllers {watchdog['max_controllers']} --protect-root {_systemd_quote(protection_root)} --warning-bytes {protection['warning_available_bytes']} --stop-bytes {protection['graceful_available_bytes']} --kill-bytes {protection['emergency_available_bytes']} --swap-stop-bytes {protection['swap_stop_bytes']} --psi-some-us {protection['psi_some_us']} --psi-full-us {protection['psi_full_us']} --state-failures {protection['state_failures']} --containment-grace-ms {protection['containment_grace_ms']}
TimeoutStopSec=30

[Install]
WantedBy=default.target
"""


def install_core_watchdog_service(
    identity: Any,
    *,
    replace_active: bool = False,
    runtime_manifest: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Install the one core-owned resident protector for this physical member."""
    config, manifest = core_watchdog_service_config(identity, runtime_manifest)
    unit_root = pathlib.Path.home() / ".config/systemd/user"
    unit_root.mkdir(parents=True, exist_ok=True)
    unit = unit_root / SERVICE_NAME
    expected = render_user_service(config, manifest)
    previous = _unit_enabled_active(SERVICE_NAME)
    if previous[1] == "active" and not replace_active:
        try:
            if unit.read_text(encoding="utf-8") != expected:
                raise LetsInferError(
                    "an active Watchdog has a different immutable core identity; "
                    "stop active inference before upgrading core"
                )
        except OSError as error:
            raise LetsInferError(f"cannot verify active Watchdog unit: {error}") from error
        _, _, memory_bytes = _service_state(SERVICE_NAME)
        if memory_bytes is None or memory_bytes >= CONTROL_PLANE_MEMORY_LIMIT_BYTES:
            raise LetsInferError(
                f"Let's Infer Watchdog memory is {memory_bytes} bytes; "
                f"the limit is below {CONTROL_PLANE_MEMORY_LIMIT_BYTES} bytes"
            )
        return config
    snapshot = _snapshot_user_file(unit)
    loaded = False
    try:
        if previous[1] == "active":
            run_passthrough(["systemctl", "--user", "stop", SERVICE_NAME])
        write_text(unit, expected)
        unit.chmod(0o644)
        run(["systemctl", "--user", "daemon-reload"])
        loaded = True
        run(["systemctl", "--user", "enable", SERVICE_NAME])
        run_passthrough(["systemctl", "--user", "start", SERVICE_NAME])
        enabled, active, memory_bytes = _service_state(SERVICE_NAME)
        if enabled != "enabled" or active != "active":
            raise LetsInferError("core Watchdog did not become enabled and active")
        if memory_bytes is None or memory_bytes >= CONTROL_PLANE_MEMORY_LIMIT_BYTES:
            raise LetsInferError(
                f"Let's Infer Watchdog memory is {memory_bytes} bytes; "
                f"the limit is below {CONTROL_PLANE_MEMORY_LIMIT_BYTES} bytes"
            )
        return config
    except BaseException as failure:
        errors: list[str] = []
        if loaded:
            stopped = run(
                ["systemctl", "--user", "stop", SERVICE_NAME], check=False
            )
            if stopped.returncode != 0:
                errors.append("stop replacement Watchdog")
        try:
            _restore_user_file(unit, snapshot)
            run(["systemctl", "--user", "daemon-reload"])
            _restore_unit_enablement(SERVICE_NAME, previous[0])
            if previous[1] == "active":
                run_passthrough(["systemctl", "--user", "start", SERVICE_NAME])
        except BaseException as error:
            errors.append(str(error))
        if errors:
            raise LetsInferError(
                "core Watchdog activation failed and rollback was incomplete: "
                + "; ".join(errors)
            ) from failure
        raise LetsInferError(
            f"core Watchdog activation failed; previous state restored: {failure}"
        ) from failure


def verify_active_core_watchdog() -> tuple[pathlib.Path, str]:
    source_sha256 = core_watchdog_source_identity()
    binary, digest = verify_watchdog_runtime(
        default_watchdog_runtime_parent() / source_sha256,
        source_sha256,
    )
    if run(
        ["systemctl", "--user", "is-active", SERVICE_NAME], check=False
    ).returncode != 0:
        raise LetsInferError("the resident core Watchdog is not active")
    unit = pathlib.Path.home() / ".config/systemd/user" / SERVICE_NAME
    try:
        text = unit.read_text(encoding="utf-8")
    except OSError as error:
        raise LetsInferError(f"cannot verify the resident Watchdog unit: {error}") from error
    if str(binary) not in text or "--protect-root" not in text:
        raise LetsInferError("the active Watchdog does not match this core build")
    return binary, digest


def install_core_plane_services(
    identity: Any, *, include_gateway: bool
) -> dict[str, Any]:
    """Replace core-owned services while preserving the selected runtime."""
    config_path = default_service_config_path()
    runtime_configured = config_path.is_file()
    runtime_manifest: dict[str, Any] | None = None
    runtime_error: str | None = None
    if runtime_configured:
        try:
            _, runtime_manifest = configured_release(read_service_config(config_path))
        except LetsInferError as error:
            runtime_error = str(error)

    runtime_state = {
        "configured": runtime_configured,
        "compatible": not runtime_configured or runtime_manifest is not None,
        "error": runtime_error,
    }
    if platform.system() != "Linux":
        install_site_service_only()
        if include_gateway:
            install_core_gateway_service(replace_active=True)
        return runtime_state

    preserved_units = (
        RECOVERY_TIMER_NAME,
        GATEWAY_SERVICE_NAME,
        ENGINE_SERVICE_NAME,
    )
    previous = {name: _unit_enabled_active(name) for name in preserved_units}
    safe_active_states = {"active", "inactive", "failed"}
    for name, (_enabled, active) in previous.items():
        if active not in safe_active_states:
            raise LetsInferError(
                f"refusing core-service upgrade while {name} state is {active!r}"
            )

    def stop_if_active(name: str) -> None:
        if previous[name][1] == "active":
            run_passthrough(["systemctl", "--user", "stop", name])

    def restore_if_needed(name: str, errors: list[str]) -> None:
        if previous[name][1] != "active":
            return
        if _unit_enabled_active(name)[1] == "active":
            return
        result = run(["systemctl", "--user", "start", name], check=False)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip() or "unknown systemctl error"
            errors.append(f"restore {name}: {detail}")

    try:
        # Recovery must be quiesced before inference. The existing Watchdog stays
        # active until the engine has stopped, so there is never an unprotected
        # live engine during the immutable core handoff.
        stop_if_active(RECOVERY_TIMER_NAME)
        stop_if_active(ENGINE_SERVICE_NAME)
        install_site_service_only()
        install_core_watchdog_service(
            identity,
            replace_active=True,
            runtime_manifest=runtime_manifest,
        )
        if include_gateway:
            install_core_gateway_service(replace_active=True)
        if (
            previous[ENGINE_SERVICE_NAME][1] == "active"
            and runtime_manifest is not None
        ):
            # A core update must not wait for a potentially long model load.
            # The recovery timer owns subsequent retries and refuses them while
            # Watchdog has a safety trip latched.
            run_passthrough(
                [
                    "systemctl",
                    "--user",
                    "start",
                    "--no-block",
                    ENGINE_SERVICE_NAME,
                ]
            )
        if (
            previous[RECOVERY_TIMER_NAME][1] == "active"
            and runtime_manifest is not None
        ):
            run_passthrough(["systemctl", "--user", "start", RECOVERY_TIMER_NAME])
    except BaseException as failure:
        restore_errors: list[str] = []
        # Individual installers restore their own files. Restore only the
        # runtime-facing active states that this transaction intentionally
        # quiesced or that systemd stopped through unit dependencies.
        restore_if_needed(GATEWAY_SERVICE_NAME, restore_errors)
        if _unit_enabled_active(SERVICE_NAME)[1] == "active":
            restore_if_needed(ENGINE_SERVICE_NAME, restore_errors)
            restore_if_needed(RECOVERY_TIMER_NAME, restore_errors)
        elif previous[ENGINE_SERVICE_NAME][1] == "active":
            restore_errors.append(
                f"restore {ENGINE_SERVICE_NAME}: resident Watchdog is not active"
            )
        if restore_errors:
            raise LetsInferError(
                "core-service upgrade failed and runtime restoration was incomplete: "
                + "; ".join(restore_errors)
            ) from failure
        raise LetsInferError(
            f"core-service upgrade failed; previous runtime state restored: {failure}"
        ) from failure
    return runtime_state


def render_recovery_service(
    name: str,
    protection_root: pathlib.Path,
    executable_root: pathlib.Path | None = None,
) -> str:
    executable = (executable_root or source_root()) / "bin/letsinfer-recovery"
    return f"""[Unit]
Description=Recover the Let's Infer managed engine container
After={SERVICE_NAME} {ENGINE_SERVICE_NAME}

[Service]
Type=oneshot
MemoryAccounting=yes
NoNewPrivileges=yes
PrivateTmp=yes
ExecStart={_systemd_quote(executable)} {shlex.quote(name)} {_systemd_quote(protection_root / PROTECTION_TRIP_NAME)}
TimeoutStartSec=30
"""


def render_recovery_timer() -> str:
    return f"""[Unit]
Description=Periodically recover an unhealthy Let's Infer container

[Timer]
OnActiveSec=1min
OnUnitActiveSec=1min
AccuracySec=10s
Persistent=true
Unit={RECOVERY_SERVICE_NAME}

[Install]
WantedBy=timers.target
"""


def _snapshot_user_file(path: pathlib.Path) -> tuple[str, int] | None:
    if path.is_symlink():
        raise LetsInferError(f"service file cannot be a symlink: {path}")
    if not path.exists():
        return None
    details = path.stat()
    if not stat.S_ISREG(details.st_mode) or details.st_uid != os.getuid():
        raise LetsInferError(f"service file is not regular and user-owned: {path}")
    return path.read_text(encoding="utf-8"), stat.S_IMODE(details.st_mode)


def _restore_user_file(
    path: pathlib.Path, snapshot: tuple[str, int] | None
) -> None:
    if path.is_symlink():
        raise LetsInferError(f"refusing to restore through a symlink: {path}")
    if snapshot is None:
        if path.exists():
            if not path.is_file():
                raise LetsInferError(f"refusing to remove non-file service path: {path}")
            path.unlink()
        return
    contents, mode = snapshot
    path.parent.mkdir(parents=True, exist_ok=True)
    write_text(path, contents)
    path.chmod(mode)


def _restore_unit_enablement(name: str, previous: str) -> None:
    if previous in {"not-found", "static"}:
        return
    if previous not in {"enabled", "disabled"}:
        raise LetsInferError(
            f"cannot safely restore {name} enablement state {previous!r}"
        )
    action = "enable" if previous == "enabled" else "disable"
    result = run(["systemctl", "--user", action, name], check=False)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip() or "unknown systemctl error"
        raise LetsInferError(f"could not {action} {name}: {detail}")


def install_user_service(
    config_path: pathlib.Path,
    config: dict[str, Any],
    manifest: dict[str, Any],
    *,
    no_start: bool,
    unit_dir: pathlib.Path | None = None,
) -> None:
    unit_root = unit_dir or pathlib.Path.home() / ".config/systemd/user"
    unit_root.mkdir(parents=True, exist_ok=True)
    paths = {
        SERVICE_NAME: unit_root / SERVICE_NAME,
        SITE_SERVICE_NAME: unit_root / SITE_SERVICE_NAME,
        ENGINE_SERVICE_NAME: unit_root / ENGINE_SERVICE_NAME,
        GATEWAY_SERVICE_NAME: unit_root / GATEWAY_SERVICE_NAME,
        RECOVERY_SERVICE_NAME: unit_root / RECOVERY_SERVICE_NAME,
        RECOVERY_TIMER_NAME: unit_root / RECOVERY_TIMER_NAME,
    }
    managed_paths = (config_path, *paths.values())
    snapshots = {path: _snapshot_user_file(path) for path in managed_paths}
    if snapshots[config_path] is not None:
        previous_config = read_service_config(config_path)
        if not retained_control_bundle_for_rollback(previous_config):
            bind_config_to_control_bundle(previous_config)

    state_names = (
        SERVICE_NAME,
        SITE_SERVICE_NAME,
        ENGINE_SERVICE_NAME,
        GATEWAY_SERVICE_NAME,
        RECOVERY_TIMER_NAME,
    )
    previous_states = {name: _unit_enabled_active(name) for name in state_names}
    safe_enablement_states = {"enabled", "disabled", "not-found"}
    for name in (
        SERVICE_NAME, SITE_SERVICE_NAME, GATEWAY_SERVICE_NAME, RECOVERY_TIMER_NAME
    ):
        state = previous_states[name][0]
        if state not in safe_enablement_states:
            raise LetsInferError(
                f"refusing service upgrade while {name} enablement is {state!r}"
            )
    safe_active_states = {"active", "inactive", "failed"}
    for name in state_names:
        state = previous_states[name][1]
        if state not in safe_active_states:
            raise LetsInferError(
                f"refusing service upgrade while {name} state is {state!r}"
            )
    if no_start and any(
        previous_states[name][1] == "active"
        for name in (SERVICE_NAME, SITE_SERVICE_NAME)
    ):
        raise LetsInferError(
            "--no-start cannot replace an active Let's Infer service; "
            "stop it first or allow install to perform a guarded upgrade"
        )

    replacement_loaded = False
    try:
        if previous_states[RECOVERY_TIMER_NAME][1] == "active":
            run_passthrough(["systemctl", "--user", "stop", RECOVERY_TIMER_NAME])
        if previous_states[GATEWAY_SERVICE_NAME][1] == "active":
            run_passthrough(["systemctl", "--user", "stop", GATEWAY_SERVICE_NAME])
        if previous_states[ENGINE_SERVICE_NAME][1] == "active":
            run_passthrough(["systemctl", "--user", "stop", ENGINE_SERVICE_NAME])
        if previous_states[SERVICE_NAME][1] == "active":
            run_passthrough(["systemctl", "--user", "stop", SERVICE_NAME])
        if previous_states[SITE_SERVICE_NAME][1] == "active":
            run_passthrough(["systemctl", "--user", "stop", SITE_SERVICE_NAME])
        atomic_json(config_path, config)
        config_path.chmod(0o600)
        write_text(
            paths[ENGINE_SERVICE_NAME],
            render_engine_service(
                config_path,
                manifest["container"]["startup_timeout_seconds"],
                pathlib.Path(config["source_root"]),
            ),
        )
        write_text(
            paths[GATEWAY_SERVICE_NAME],
            render_gateway_service(
                config_path, config, pathlib.Path(config["source_root"])
            ),
        )
        write_text(
            paths[SERVICE_NAME], render_user_service(config, manifest)
        )
        write_text(
            paths[SITE_SERVICE_NAME],
            render_site_service(pathlib.Path(config["source_root"])),
        )
        write_text(
            paths[RECOVERY_SERVICE_NAME],
            render_recovery_service(
                config["name"],
                pathlib.Path(config["protection_root"]),
                pathlib.Path(config["source_root"]),
            ),
        )
        write_text(paths[RECOVERY_TIMER_NAME], render_recovery_timer())
        for name in (
            SERVICE_NAME,
            SITE_SERVICE_NAME,
            ENGINE_SERVICE_NAME,
            GATEWAY_SERVICE_NAME,
            RECOVERY_SERVICE_NAME,
            RECOVERY_TIMER_NAME,
        ):
            path = paths[name]
            path.chmod(0o644)
        run(["systemctl", "--user", "daemon-reload"])
        replacement_loaded = True
        run(["systemctl", "--user", "enable", SERVICE_NAME])
        run(["systemctl", "--user", "enable", SITE_SERVICE_NAME])
        run(["systemctl", "--user", "enable", GATEWAY_SERVICE_NAME])
        run(["systemctl", "--user", "enable", RECOVERY_TIMER_NAME])
        if not no_start:
            run_passthrough(["systemctl", "--user", "start", SITE_SERVICE_NAME])
            _, _, site_memory_bytes = _service_state(SITE_SERVICE_NAME)
            if (
                site_memory_bytes is None
                or site_memory_bytes >= SITE_AGENT_MEMORY_LIMIT_BYTES
            ):
                raise LetsInferError(
                    f"Let's Infer site-agent memory is {site_memory_bytes} bytes; "
                    f"the limit is below {SITE_AGENT_MEMORY_LIMIT_BYTES} bytes"
                )
            run_passthrough(["systemctl", "--user", "start", SERVICE_NAME])
            _, _, memory_bytes = _service_state()
            if (
                memory_bytes is None
                or memory_bytes >= CONTROL_PLANE_MEMORY_LIMIT_BYTES
            ):
                raise LetsInferError(
                    f"Let's Infer control-plane memory is {memory_bytes} bytes; "
                    f"the limit is below {CONTROL_PLANE_MEMORY_LIMIT_BYTES} bytes"
                )
            run_passthrough(["systemctl", "--user", "start", ENGINE_SERVICE_NAME])
            run_passthrough(["systemctl", "--user", "start", GATEWAY_SERVICE_NAME])
            run(["systemctl", "--user", "restart", RECOVERY_TIMER_NAME])
    except BaseException as failure:
        rollback_errors: list[str] = []
        if replacement_loaded:
            for name in (
                RECOVERY_TIMER_NAME, GATEWAY_SERVICE_NAME, SITE_SERVICE_NAME,
                SERVICE_NAME, ENGINE_SERVICE_NAME
            ):
                result = run(
                    ["systemctl", "--user", "stop", name], check=False
                )
                if result.returncode != 0:
                    detail = (
                        (result.stderr or result.stdout).strip()
                        or "unknown systemctl error"
                    )
                    rollback_errors.append(f"stop replacement {name}: {detail}")
        for path in managed_paths:
            try:
                _restore_user_file(path, snapshots[path])
            except (OSError, LetsInferError) as error:
                rollback_errors.append(f"restore {path}: {error}")
        reload_result = run(
            ["systemctl", "--user", "daemon-reload"], check=False
        )
        if reload_result.returncode != 0:
            detail = (
                (reload_result.stderr or reload_result.stdout).strip()
                or "unknown systemctl error"
            )
            rollback_errors.append(f"reload previous units: {detail}")
        for name in (
            SERVICE_NAME, SITE_SERVICE_NAME, GATEWAY_SERVICE_NAME, RECOVERY_TIMER_NAME
        ):
            state = previous_states[name][0]
            try:
                _restore_unit_enablement(name, state)
            except (LetsInferError, OSError) as error:
                rollback_errors.append(f"restore {name} enablement: {error}")
        try:
            if previous_states[SITE_SERVICE_NAME][1] == "active":
                run_passthrough(["systemctl", "--user", "start", SITE_SERVICE_NAME])
            if previous_states[SERVICE_NAME][1] == "active":
                run_passthrough(["systemctl", "--user", "start", SERVICE_NAME])
            if previous_states[ENGINE_SERVICE_NAME][1] == "active":
                run_passthrough(
                    ["systemctl", "--user", "start", ENGINE_SERVICE_NAME]
                )
            if previous_states[GATEWAY_SERVICE_NAME][1] == "active":
                run_passthrough(
                    ["systemctl", "--user", "start", GATEWAY_SERVICE_NAME]
                )
            if previous_states[RECOVERY_TIMER_NAME][1] == "active":
                run(["systemctl", "--user", "start", RECOVERY_TIMER_NAME])
        except (LetsInferError, OSError) as error:
            rollback_errors.append(f"restart previous service: {error}")
        if rollback_errors:
            raise LetsInferError(
                "service activation failed and rollback was incomplete: "
                + "; ".join(rollback_errors)
            ) from failure
        raise LetsInferError(
            f"service activation failed; previous installation restored: {failure}"
        ) from failure


def _service_state(name: str = SERVICE_NAME) -> tuple[str, str, int | None]:
    if platform.system() == "Darwin":
        label = _macos_service_label(name)
        if label is None:
            return "not-found", "inactive", None
        try:
            return macos_services.service_state(label)
        except macos_services.MacOSServiceError as error:
            raise LetsInferError(f"cannot inspect macOS service: {error}") from error
    enabled = run(["systemctl", "--user", "is-enabled", name], check=False)
    active = run(["systemctl", "--user", "is-active", name], check=False)
    memory = run(
        ["systemctl", "--user", "show", name, "--property", "MemoryCurrent", "--value"],
        check=False,
    )
    memory_text = memory.stdout.strip()
    active_text = active.stdout.strip() or "inactive"
    if memory.returncode == 0 and memory_text.isdigit():
        memory_bytes = int(memory_text)
    else:
        memory_bytes = None
    return enabled.stdout.strip() or "not-found", active_text, memory_bytes


def _fresh_site_topology() -> tuple[Any, TopologyGraph]:
    """Return the coordinator identity and one fully refreshed active graph."""
    identity = read_site_identity()
    if identity.role != "coordinator":
        raise LetsInferError(
            "site topology selection is coordinator-owned; "
            f"coordinator={identity.coordinator_id}@{identity.coordinator_address}"
        )
    synchronized = _synchronize_member_facts()
    if synchronized["failed"]:
        raise LetsInferError(
            "cannot resolve placement while authenticated member facts are unavailable: "
            + ",".join(synchronized["failed"])
        )
    try:
        with SiteStore(identity=identity) as store:
            members = [row for row in store.members() if row["state"] == "active"]
        missing = [row["member_id"] for row in members if not row["facts"]]
        if missing:
            raise LetsInferError(
                "topology facts are missing for active member(s): " + ",".join(missing)
            )
        return identity, TopologyGraph(
            [row["facts"] for row in members],
            member_certificates={
                row["member_id"]: row["certificate_sha256"] for row in members
            },
        )
    except (SiteError, TopologyError) as error:
        raise LetsInferError(f"cannot build authenticated site topology: {error}") from error


def _catalog_site_release(
    catalog: dict[str, Any],
    model: str,
    engine: str | None,
    *,
    topology: tuple[Any, TopologyGraph] | None = None,
) -> tuple[tuple[str, str, str, str, str], TargetPlacement]:
    """Resolve one catalog release against the complete authenticated site."""
    model_record = catalog.get("models", {}).get(model)
    if not isinstance(model_record, dict):
        raise LetsInferError(f"model is not present in runtime catalog: {model}")
    identity, graph = topology or _fresh_site_topology()
    contracts = {
        target_id: catalog_target_contract(catalog, target_id)
        for target_id in model_record["targets"]
    }
    try:
        choice = graph.resolve_catalog_targets(
            contracts, coordinator_id=identity.coordinator_id
        )
        release = catalog_release(
            catalog, model, engine, choice.target_id, device=None
        )
    except (RuntimePackError, TopologyError) as error:
        raise LetsInferError(str(error)) from error
    return release, choice


def _runtime_source_for_install(
    model: str,
    engine: str | None,
    catalog_location: str | None,
) -> tuple[str, str, str | None, str | None, str | None] | None:
    path = pathlib.Path(model).expanduser()
    if path.exists():
        return str(path.resolve(strict=True)), "local", None, None, None
    if REGISTRY_DIGEST_RE.fullmatch(model):
        return model, "pinned", None, None, None
    location = resolved_catalog_location(catalog_location)
    if location is None:
        return None
    try:
        catalog = load_catalog(location)
        (
            selected_target,
            selected_target_sha256,
            selected_engine,
            version,
            source,
        ), _choice = _catalog_site_release(catalog, model, engine)
    except RuntimePackError as error:
        if catalog_location is None and "not present" in str(error):
            return None
        raise LetsInferError(str(error)) from error
    policy = f"engine:{selected_engine}" if engine else "recommended"
    return source, policy, version, selected_target, selected_target_sha256


def prepare_runtime_install(
    source: str,
    *,
    policy: str,
    requested_engine: str | None,
    requested_target: str | None = None,
    expected_version: str | None = None,
    expected_target_contract_sha256: str | None = None,
    artifact_roots: Sequence[pathlib.Path] = (),
) -> tuple[pathlib.Path, dict[str, Any], pathlib.Path, dict[str, Any]]:
    try:
        with materialize(source) as incoming:
            object_root = store_pack(incoming)
        pack = verify_descriptor(object_root)
    except RuntimePackError as error:
        raise LetsInferError(str(error)) from error
    manifest_path = pack.release_path
    manifest = read_json(manifest_path)
    validate_manifest(manifest)
    engine = adapter_for(manifest).name
    manifest_target = target_contract(manifest)
    target_id = manifest_target["id"]
    manifest_target_sha256 = target_contract_sha256(manifest_target)
    try:
        validate_target_binding(
            pack.descriptor.get("orchestration"), manifest_target["placement"]
        )
    except OrchestrationError as error:
        raise LetsInferError(
            f"runtime orchestration does not bind its release target: {error}"
        ) from error
    if expected_version is not None and pack.descriptor["version"] != expected_version:
        raise LetsInferError(
            "runtime catalog version does not match the immutable artifact "
            f"({expected_version!r} != {pack.descriptor['version']!r})"
        )
    if (
        pack.descriptor["model"] != manifest["model"]["alias"]
        or pack.descriptor["engine"] != engine
        or pack.descriptor["target"] != target_id
        or pack.descriptor["status"] != manifest["status"]
    ):
        raise LetsInferError("runtime descriptor and release manifest identity disagree")
    if requested_engine is not None and requested_engine != engine:
        raise LetsInferError(
            f"runtime uses engine {engine!r}, not requested engine {requested_engine!r}"
        )
    if requested_target is not None and requested_target != target_id:
        raise LetsInferError(
            f"runtime uses target {target_id!r}, not requested target {requested_target!r}"
        )
    if (
        expected_target_contract_sha256 is not None
        and expected_target_contract_sha256 != manifest_target_sha256
    ):
        raise LetsInferError(
            "runtime target contract does not match the catalog target definition"
        )
    control_root, installed_manifest_path = install_control_bundle(
        manifest_path,
        manifest,
        artifact_roots=(object_root, *artifact_roots, source_root()),
    )
    installed_manifest = read_json(installed_manifest_path)
    receipt = new_receipt(
        pack,
        object_root=object_root,
        manifest_path=installed_manifest_path,
        control_root=control_root,
        source=source,
        policy=policy,
        hardware_fingerprint_sha256=host_hardware_fingerprint_sha256(),
        target_contract_sha256=manifest_target_sha256,
        installed_at_unix_ns=time.time_ns(),
    )
    return installed_manifest_path, installed_manifest, control_root, receipt


def _control_member_host(address: str) -> str:
    endpoint = _site_control_endpoint(address)
    parsed = urllib.parse.urlsplit(endpoint)
    if not parsed.hostname:
        raise LetsInferError("member control address has no host")
    return f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname


def _engine_group_transport() -> tuple[Any, Any, Any]:
    def submit(
        member: Mapping[str, Any],
        job: Mapping[str, Any],
        credential: str | None,
    ) -> Mapping[str, Any]:
        return submit_member_group_job(
            _site_control_endpoint(str(member["address"])),
            expected_member_id=str(member["member_id"]),
            expected_certificate_sha256=str(member["certificate_sha256"]),
            job=job,
            engine_credential=credential,
        )

    def job_status(
        member: Mapping[str, Any], operation_id: str
    ) -> Mapping[str, Any]:
        return fetch_member_job_status(
            _site_control_endpoint(str(member["address"])),
            expected_member_id=str(member["member_id"]),
            expected_certificate_sha256=str(member["certificate_sha256"]),
            operation_id=operation_id,
        )

    def group_status(
        member: Mapping[str, Any], group_id: str
    ) -> Mapping[str, Any]:
        return fetch_member_group_status(
            _site_control_endpoint(str(member["address"])),
            expected_member_id=str(member["member_id"]),
            expected_certificate_sha256=str(member["certificate_sha256"]),
            group_id=group_id,
        )

    return submit, job_status, group_status


def _engine_group_member_controls(
    records: Sequence[Mapping[str, Any]],
    member_ids: Sequence[str],
    *,
    require_active: bool = True,
) -> dict[str, dict[str, str]]:
    wanted = set(member_ids)
    allowed_states = {"active"} if require_active else {"active", "offline", "draining"}
    selected = {
        str(row["member_id"]): row
        for row in records
        if row.get("state") in allowed_states and row.get("member_id") in wanted
    }
    if set(selected) != wanted:
        raise LetsInferError("engine-group placement contains an unavailable member identity")
    return {
        member_id: {
            "member_id": member_id,
            "address": str(selected[member_id]["address"]),
            "certificate_sha256": str(
                selected[member_id]["certificate_sha256"]
            ),
        }
        for member_id in member_ids
    }


def install_engine_group(
    arguments: argparse.Namespace,
    *,
    source: str,
    manifest_path: pathlib.Path,
    manifest: dict[str, Any],
    control_root: pathlib.Path,
    receipt: dict[str, Any],
) -> int:
    """Install one runtime-owned replicated or distributed engine group."""
    if not REGISTRY_DIGEST_RE.fullmatch(source):
        raise LetsInferError(
            "multi-member installation requires a digest-pinned OCI runtime"
        )
    if any(
        bool(getattr(arguments, name, False))
        for name in ("no_service", "no_start", "no_build_image")
    ):
        raise LetsInferError(
            "multi-member installation does not support disabling required lifecycle services"
        )
    identity, graph, placement = resolve_manifest_placement(manifest)
    if placement.strategy not in {"replicated", "distributed"}:
        raise LetsInferError("engine-group installation requires a multi-member target")
    runtime_root = pathlib.Path(receipt["object_root"])
    try:
        runtime = verify_descriptor(runtime_root)
        contract = validate_target_binding(
            runtime.descriptor.get("orchestration"),
            target_contract(manifest)["placement"],
        )
    except (RuntimePackError, OrchestrationError) as error:
        raise LetsInferError(f"runtime engine-group contract is invalid: {error}") from error
    if contract is None:
        raise LetsInferError("multi-member runtime has no engine-group contract")
    manifest_sha256 = sha256_file(manifest_path)
    placement_identity = service_placement_identity(
        identity, placement, manifest_sha256
    )
    placement_id = placement_identity["placement_id"]
    with _site_store() as store:
        selected_records = {
            row["member_id"]: row
            for row in store.members()
            if row["state"] == "active" and row["member_id"] in placement.member_ids
        }
        existing_groups = store.engine_groups()
    controls = _engine_group_member_controls(
        list(selected_records.values()), placement.member_ids
    )
    occupied: dict[str, list[tuple[int, int]]] = {
        member_id: [] for member_id in placement.member_ids
    }
    for existing in existing_groups:
        if existing["state"] in {"removed", "failed"}:
            continue
        for member in existing["plan"]["members"]:
            if member["member_id"] in occupied:
                occupied[member["member_id"]].append(
                    (member["port_base"], member["port_count"])
                )
    try:
        port_bases = allocate_group_ports(
            contract,
            member_ids=placement.member_ids,
            engine_coordinator_id=placement.engine_coordinator_id,
            occupied={key: tuple(value) for key, value in occupied.items()},
        )
        if placement.strategy == "distributed":
            engine_addresses = graph.engine_addresses(
                placement, target_contract(manifest)["placement"]["interconnect"]
            )
        else:
            engine_addresses = {
                member_id: _control_member_host(selected_records[member_id]["address"])
                for member_id in placement.member_ids
            }
        plan = build_group_plan(
            contract,
            member_ids=placement.member_ids,
            member_addresses=engine_addresses,
            engine_coordinator_id=placement.engine_coordinator_id,
            topology_sha256=placement.topology_sha256,
            manifest_sha256=manifest_sha256,
            runtime_digest=runtime.digest,
            member_port_bases=port_bases,
        )
    except (OrchestrationError, GroupOrchestrationError, TopologyError) as error:
        raise LetsInferError(f"cannot build engine-group plan: {error}") from error
    submit, job_status, group_status = _engine_group_transport()

    runtime_identity = (
        f"{runtime.descriptor['name']}@{runtime.descriptor['version']}"
        f"@sha256:{runtime.digest}"
    )
    placement_document = {
        "placement_id": placement_id,
        "model": manifest["model"]["alias"],
        "runtime": runtime_identity,
        "target": target_contract(manifest)["id"],
        "strategy": placement.strategy,
        "state": "starting",
        "topology_sha256": placement.topology_sha256,
        "members": list(placement.member_ids),
        "endpoints": [],
        "capacity": {
            "max_connections": manifest["serving"]["max_connections"],
            "max_active_requests": manifest["serving"]["max_active_requests"],
            "max_context_tokens": manifest["serving"]["max_context_tokens"],
            "interconnect": target_contract(manifest)["placement"]["interconnect"],
        },
    }
    receipt_path: pathlib.Path | None = None
    try:
        with _site_store() as store:
            store.set_placement(placement_document)
            orchestrator = EngineGroupOrchestrator(
                store=store,
                plan=plan,
                placement_id=placement_id,
                source=source,
                members=controls,
                submit=submit,
                status=group_status,
                job_status=job_status,
            )
            started = False
            try:
                orchestrator.stage()
                orchestrator.start()
                started = True
                credential_root = site_config_root() / "engine-groups" / plan.group_id
                ensure_private_directory(credential_root)
                credential_file = credential_root / "engine-api.key"
                _atomic_private_text(
                    credential_file, orchestrator.engine_credential + "\n"
                )
                endpoints: list[dict[str, Any]] = []
                for assignment in plan.assignments:
                    if not assignment.inference_endpoint:
                        continue
                    result = orchestrator.results.get(assignment.member_id)
                    if (
                        not isinstance(result, dict)
                        or not isinstance(result.get("endpoint"), str)
                        or not isinstance(result.get("tls_certificate_pem"), str)
                        or not SHA256_RE.fullmatch(
                            str(result.get("tls_certificate_sha256"))
                        )
                    ):
                        raise LetsInferError(
                            "engine-group member returned incomplete endpoint identity"
                        )
                    certificate_file = credential_root / f"{assignment.member_id}.crt"
                    _atomic_private_text(
                        certificate_file, result["tls_certificate_pem"]
                    )
                    if certificate_sha256(certificate_file) != result["tls_certificate_sha256"]:
                        raise LetsInferError("engine-group endpoint certificate changed")
                    endpoints.append({
                        "member_id": assignment.member_id,
                        "model": manifest["model"]["alias"],
                        "url": result["endpoint"],
                        "credential_file": str(credential_file),
                        "ca_file": str(certificate_file),
                        "max_active_requests": manifest["serving"]["max_active_requests"],
                        "max_context_tokens": manifest["serving"]["max_context_tokens"],
                        "healthy": True,
                        "memory_pressure": False,
                        "temperature_c": -1,
                        "prefix_keys": [],
                    })
                if not endpoints:
                    raise LetsInferError("engine-group has no inference endpoint")
                receipt.update(
                    {
                        "manifest_path": str(manifest_path),
                        "control_root": str(control_root),
                    }
                )
                try:
                    receipt_path = write_selection(receipt)
                except RuntimePackError as error:
                    raise LetsInferError(
                        f"engine-group runtime receipt failed: {error}"
                    ) from error
                placement_document["state"] = "running"
                placement_document["endpoints"] = endpoints
                store.set_placement(placement_document)
            except Exception as error:
                rollback_error: BaseException | None = None
                if started:
                    try:
                        orchestrator.stop()
                    except BaseException as stopped_error:
                        rollback_error = stopped_error
                placement_document["state"] = "failed"
                placement_document["endpoints"] = []
                try:
                    store.set_placement(placement_document)
                except BaseException as state_error:
                    rollback_error = rollback_error or state_error
                if rollback_error is not None:
                    raise LetsInferError(
                        "engine-group installation failed and rollback was incomplete: "
                        f"{type(rollback_error).__name__}"
                    ) from error
                raise
    except BaseException as error:
        if isinstance(error, LetsInferError):
            raise
        if isinstance(error, (SiteError, ControlError, GroupOrchestrationError)):
            raise LetsInferError(f"engine-group installation failed: {error}") from error
        raise
    if receipt_path is None:
        raise LetsInferError("engine-group runtime receipt was not persisted")
    print(
        f"INSTALLED GROUP {runtime_identity} group={plan.group_id} "
        f"placement={placement_id} members={len(plan.assignments)} "
        f"receipt={receipt_path}"
    )
    return 0


def _restore_engine_group_orchestrator(
    store: SiteStore,
    row: Mapping[str, Any],
    *,
    actor_type: str = "system",
    actor_id: str = "coordinator",
    origin_interface: str = "orchestrator",
    correlation_id: str | None = None,
) -> tuple[EngineGroupOrchestrator, dict[str, Any]]:
    """Rebuild a controller only from immutable objects and durable group state."""
    try:
        document = validate_group_document(dict(row["plan"]))
        if (
            row.get("group_id") != document["group_id"]
            or row.get("runtime_digest") != document["runtime_digest"]
            or row.get("manifest_sha256") != document["manifest_sha256"]
            or row.get("topology_sha256") != document["topology_sha256"]
            or row.get("plan_sha256")
            != hashlib.sha256(canonical_bytes(document)).hexdigest()
            or not REGISTRY_DIGEST_RE.fullmatch(str(row.get("source", "")))
        ):
            raise LetsInferError("durable engine-group identity is inconsistent")
        runtime_root = default_runtime_home() / "objects" / document["runtime_digest"]
        runtime = verify_descriptor(runtime_root)
        if runtime.digest != document["runtime_digest"]:
            raise LetsInferError("engine-group runtime object identity changed")
        control_root = default_control_parent() / document["manifest_sha256"]
        manifest_path = control_root / "releases" / runtime.release_path.name
        _, manifest = validate_control_bundle(
            control_root, manifest_path, document["manifest_sha256"]
        )
        contract = validate_target_binding(
            runtime.descriptor.get("orchestration"),
            target_contract(manifest)["placement"],
        )
        if contract is None:
            raise LetsInferError("engine-group runtime lost its orchestration contract")
        members = sorted(document["members"], key=lambda item: item["rank"])
        plan = build_group_plan(
            contract,
            member_ids=tuple(item["member_id"] for item in members),
            member_addresses={item["member_id"]: item["address"] for item in members},
            engine_coordinator_id=document["engine_coordinator_id"],
            topology_sha256=document["topology_sha256"],
            manifest_sha256=document["manifest_sha256"],
            runtime_digest=document["runtime_digest"],
            member_port_bases={item["member_id"]: item["port_base"] for item in members},
        )
        if plan.document() != document:
            raise LetsInferError("runtime contract no longer reproduces the engine-group plan")
        controls = _engine_group_member_controls(
            store.members(),
            tuple(item.member_id for item in plan.assignments),
            require_active=False,
        )
        submit, job_status, group_status = _engine_group_transport()
        orchestrator = EngineGroupOrchestrator(
            store=store,
            plan=plan,
            placement_id=str(row["placement_id"]),
            source=str(row["source"]),
            members=controls,
            submit=submit,
            status=group_status,
            job_status=job_status,
            actor_type=actor_type,
            actor_id=actor_id,
            origin_interface=origin_interface,
            correlation_id=correlation_id,
        )
        if orchestrator.engine_credential_sha256 != row.get(
            "engine_credential_sha256"
        ):
            raise LetsInferError("engine-group credential identity changed")
        member_states = row.get("members")
        if not isinstance(member_states, list) or {
            item.get("member_id") for item in member_states if isinstance(item, dict)
        } != set(orchestrator.states):
            raise LetsInferError("engine-group member journal is incomplete")
        orchestrator.states = {
            str(item["member_id"]): dict(item) for item in member_states
        }
        orchestrator.persisted_state = str(row["state"])
        return orchestrator, manifest
    except (RuntimePackError, OrchestrationError, GroupOrchestrationError) as error:
        raise LetsInferError(f"cannot restore engine-group controller: {error}") from error


def _sync_group_placement(
    store: SiteStore,
    group: Mapping[str, Any],
) -> None:
    placement = next(
        (
            row
            for row in store.placements()
            if row["placement_id"] == group["placement_id"]
        ),
        None,
    )
    if placement is None:
        raise LetsInferError("engine-group placement record disappeared")
    member_states = {
        item["member_id"]: item["state"] for item in group["member_states"]
    }
    group_running = group["state"] in {"running", "degraded"}
    updated = dict(placement)
    if group_running:
        updated["state"] = "running"
    elif group["desired_state"] in {"stopped", "removed"} and group["state"] in {
        "stopped", "removed",
    }:
        updated["state"] = "stopped"
    elif group["state"] in {"stopping", "removing"}:
        updated["state"] = "draining"
    elif group["state"] in {"staging", "staged", "starting", "recovering"}:
        updated["state"] = "starting"
    else:
        updated["state"] = "failed"
    updated["endpoints"] = [
        {
            **endpoint,
            "healthy": group_running
            and member_states.get(endpoint["member_id"]) == "running",
        }
        for endpoint in placement["endpoints"]
    ]
    if (
        updated["state"] != placement["state"]
        or updated["endpoints"] != placement["endpoints"]
    ):
        store.set_placement(updated)


def _select_engine_group(
    store: SiteStore,
    model: str | None,
    *,
    required: bool = True,
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    placements = {row["placement_id"]: row for row in store.placements()}
    candidates: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for group in store.engine_groups():
        if group["state"] == "removed" or group["desired_state"] == "removed":
            continue
        placement = placements.get(group["placement_id"])
        if placement is None:
            raise LetsInferError("engine-group placement record disappeared")
        if model is not None and placement["model"] != model:
            continue
        candidates.append((group, placement))
    if not candidates:
        if model is not None and required:
            raise LetsInferError(f"no installed engine group serves model {model!r}")
        return None
    if len(candidates) != 1:
        names = ", ".join(sorted({item[1]["model"] for item in candidates}))
        raise LetsInferError(
            "multiple engine groups are installed; specify the model (" + names + ")"
        )
    return candidates[0]


def _engine_group_lifecycle(
    model: str | None,
    action: str,
    *,
    actor_type: str = "os-principal",
    actor_id: str | None = None,
    origin_interface: str = "local-cli",
    correlation_id: str | None = None,
) -> dict[str, Any] | None:
    identity = read_site_identity()
    if identity.role != "coordinator":
        raise LetsInferError("engine-group lifecycle is coordinator-only")
    with _site_store() as store:
        selected = _select_engine_group(store, model, required=False)
        if selected is None:
            return None
        row, _placement = selected
        orchestrator, _manifest = _restore_engine_group_orchestrator(
            store,
            row,
            actor_type=actor_type,
            actor_id=actor_id or getpass.getuser(),
            origin_interface=origin_interface,
            correlation_id=correlation_id,
        )
        try:
            if action == "stop":
                result = orchestrator.stop()
            elif action == "start":
                result = orchestrator.recover(acknowledge_trips=False)
            elif action == "restart":
                stopped = orchestrator.stop()
                _sync_group_placement(store, stopped)
                result = orchestrator.recover(acknowledge_trips=False)
            elif action == "recover":
                result = orchestrator.recover(acknowledge_trips=True)
            elif action == "remove":
                if row["state"] not in {"staged", "stopped"}:
                    stopped = orchestrator.stop()
                    _sync_group_placement(store, stopped)
                result = orchestrator.remove()
            else:
                raise LetsInferError("engine-group lifecycle action is invalid")
        except GroupOrchestrationError:
            current = next(
                item
                for item in store.engine_groups()
                if item["group_id"] == row["group_id"]
            )
            failed = {
                **current["plan"],
                "placement_id": current["placement_id"],
                "desired_state": current["desired_state"],
                "state": current["state"],
                "member_states": current["members"],
            }
            _sync_group_placement(store, failed)
            raise
        _sync_group_placement(store, result)
        return result


def _remove_all_engine_groups() -> list[str]:
    identity = read_site_identity()
    if identity.role != "coordinator":
        return []
    removed: list[str] = []
    while True:
        with _site_store() as store:
            active = [
                row
                for row in store.engine_groups()
                if row["state"] != "removed" and row["desired_state"] != "removed"
            ]
            if not active:
                return removed
            row = active[0]
            placement = next(
                item
                for item in store.placements()
                if item["placement_id"] == row["placement_id"]
            )
            model = placement["model"]
        result = _engine_group_lifecycle(model, "remove")
        if result is None or result["state"] != "removed":
            raise LetsInferError(f"engine group for {model!r} was not removed")
        removed.append(result["group_id"])


def _apply_controller_site_move(prepared: PreparedMove) -> Any:
    """Commit an approved move and restart the site agent after its HTTP reply."""
    if platform.system().lower() != "linux":
        raise SiteError("persistent site moves require Linux user systemd")
    if not user_lingering_enabled():
        raise SiteError("user-systemd lingering is required before a site move")
    systemctl = shutil.which("systemctl")
    systemd_run = shutil.which("systemd-run")
    if not systemctl or not pathlib.Path(systemctl).is_absolute() or not systemd_run:
        raise SiteError("user systemd move activation tools are unavailable")
    units = (
        SERVICE_NAME,
        SITE_SERVICE_NAME,
        ENGINE_SERVICE_NAME,
        GATEWAY_SERVICE_NAME,
        RECOVERY_TIMER_NAME,
    )
    prior = {name: _unit_enabled_active(name) for name in units}
    if prior[SITE_SERVICE_NAME][1] != "active":
        raise SiteError("site move requires the private site service to be active")
    active_work = [
        name
        for name in (ENGINE_SERVICE_NAME,)
        if prior[name][1] == "active"
    ]
    if active_work:
        raise SiteError(
            "site move requires active inference services to be stopped first: "
            + ",".join(active_work)
        )
    unit_root = pathlib.Path.home() / ".config/systemd/user"
    watchdog_unit = unit_root / SERVICE_NAME
    watchdog_snapshot = _snapshot_user_file(watchdog_unit)
    restart_unit = f"letsinfer-site-move-{prepared.move_id}"
    restart_scheduled = False

    def cancel_restart() -> None:
        run(
            [
                systemctl,
                "--user",
                "stop",
                f"{restart_unit}.timer",
                f"{restart_unit}.service",
            ],
            check=False,
        )

    def before_transaction() -> None:
        nonlocal restart_scheduled
        run(
            [
                systemd_run,
                "--user",
                "--collect",
                f"--unit={restart_unit}",
                "--on-active=120s",
                systemctl,
                "--user",
                "kill",
                "--signal=TERM",
                "--kill-whom=main",
                SITE_SERVICE_NAME,
            ]
        )
        restart_scheduled = True
        for name in (RECOVERY_TIMER_NAME, GATEWAY_SERVICE_NAME, SERVICE_NAME):
            if prior[name][1] == "active":
                run_passthrough([systemctl, "--user", "stop", name])

    def before_commit(replacement: Any) -> None:
        ensure_core_watchdog_tls()
        install_core_watchdog_service(replacement)
        for name in (
            ENGINE_SERVICE_NAME,
            GATEWAY_SERVICE_NAME,
            RECOVERY_TIMER_NAME,
        ):
            run([systemctl, "--user", "disable", name], check=False)

    try:
        return apply_prepared_move(
            prepared,
            before_transaction=before_transaction,
            before_commit=before_commit,
        )
    except BaseException as failure:
        errors: list[str] = []
        if restart_scheduled:
            cancel_restart()
        try:
            run([systemctl, "--user", "stop", SERVICE_NAME], check=False)
            _restore_user_file(watchdog_unit, watchdog_snapshot)
            run([systemctl, "--user", "daemon-reload"])
            for name, (enabled, active) in prior.items():
                _restore_unit_enablement(name, enabled)
                if active == "active" and name != SITE_SERVICE_NAME:
                    run_passthrough([systemctl, "--user", "start", name])
        except BaseException as error:
            errors.append(str(error))
        if errors:
            raise SiteError(
                "site move failed and service rollback was incomplete: "
                + "; ".join(errors)
            ) from failure
        raise


def _controller_administration_completed(
    action: str, result: Mapping[str, Any]
) -> None:
    """After the commit response is on the wire, activate the new site identity."""
    if action != "site.move.commit":
        return
    move = result.get("move")
    move_id = move.get("move_id") if isinstance(move, Mapping) else None
    if not isinstance(move_id, str) or not re.fullmatch(r"[0-9a-f]{32}", move_id):
        return
    systemctl = shutil.which("systemctl")
    if systemctl is None:
        return
    restart_unit = f"letsinfer-site-move-{move_id}"
    run(
        [systemctl, "--user", "stop", f"{restart_unit}.timer"],
        check=False,
    )
    started = run(
        [
            systemctl,
            "--user",
            "start",
            "--no-block",
            f"{restart_unit}.service",
        ],
        check=False,
    )
    if started.returncode != 0:
        run(
            [systemctl, "--user", "start", f"{restart_unit}.timer"],
            check=False,
        )


def _controller_site_action(
    principal: ControllerPrincipal,
    action: str,
    payload: Mapping[str, Any],
    operation_id: str,
) -> Mapping[str, Any]:
    model_value = payload.get("model")
    model = model_value if isinstance(model_value, str) else None
    if action == "install":
        if model is None:
            raise LetsInferError("controller install action requires a model")
        engine_value = payload.get("engine")
        engine = engine_value if isinstance(engine_value, str) else None
        if engine is not None and engine not in ADAPTERS:
            raise LetsInferError(f"unknown inference engine: {engine}")
        command = ["install", model]
        if engine is not None:
            command.extend(("--engine", engine))
        try:
            arguments = parser().parse_args(command)
        except SystemExit as error:
            raise LetsInferError("controller install action is invalid") from error
        try:
            install(arguments)
            candidates = [
                receipt
                for receipt in selections()
                if receipt["model"] == model
                and (engine is None or receipt["engine"] == engine)
            ]
            if candidates:
                receipt = max(
                    candidates, key=lambda value: value["installed_at_unix_ns"]
                )
                identifier = (
                    f"{receipt['name']}@{receipt['version']}"
                    f"@sha256:{receipt['digest']}"
                )
            else:
                config = read_service_config(default_service_config_path())
                if config["model"] != model:
                    raise LetsInferError(
                        "installed runtime identity could not be resolved"
                    )
                identifier = (
                    f"{config['release']}@sha256:{config['manifest_sha256']}"
                )
        except Exception as error:
            with _site_store() as store:
                store.record_action(
                    "runtime.install",
                    model,
                    "failed",
                    type(error).__name__,
                    actor_type="controller",
                    actor_id=principal.controller_id,
                    origin_interface="controller-api",
                    correlation_id=operation_id,
                )
            raise
        with _site_store() as store:
            store.record_action(
                "runtime.install",
                identifier,
                "success",
                actor_type="controller",
                actor_id=principal.controller_id,
                origin_interface="controller-api",
                correlation_id=operation_id,
            )
        return {
            "resource": "runtime",
            "identifier": identifier,
            "state": "installed",
            "model": model,
        }

    if action == "topology-plan":
        if model is None:
            raise LetsInferError("controller topology action requires a model")
        engine_value = payload.get("engine")
        engine = engine_value if isinstance(engine_value, str) else None
        document = _topology_plan_document(
            model,
            engine,
            None,
            actor_type="controller",
            actor_id=principal.controller_id,
            origin_interface="controller-api",
            correlation_id=operation_id,
        )
        changed = bool(document["change_required"])
        return {
            "resource": "topology-plan",
            "identifier": (
                document["plan_id"]
                if changed
                else document["runtime_identity"]
            ),
            "state": "pending" if changed else "unchanged",
            "model": model,
        }

    if action == "expose":
        value = _enable_public_exposure(
            actor_type="controller",
            actor_id=principal.controller_id,
            origin_interface="controller-api",
            correlation_id=operation_id,
        )
        return {
            "resource": "exposure",
            "identifier": value["public_url"],
            "state": "enabled",
            "model": None,
        }

    if action == "unexpose":
        value = _disable_public_exposure(
            actor_type="controller",
            actor_id=principal.controller_id,
            origin_interface="controller-api",
            correlation_id=operation_id,
        )
        return {
            "resource": "exposure",
            "identifier": value["provider"],
            "state": "disabled",
            "model": None,
        }

    if model is None:
        raise LetsInferError("controller runtime action requires a model")
    group = _engine_group_lifecycle(
        model,
        action,
        actor_type="controller",
        actor_id=principal.controller_id,
        origin_interface="controller-api",
        correlation_id=operation_id,
    )
    if group is not None:
        return {
            "resource": "placement",
            "identifier": group["group_id"],
            "model": model,
            "state": "stopped" if action == "stop" else "running",
        }
    config_path = default_service_config_path()
    config = read_service_config(config_path)
    if config.get("model") != model:
        raise LetsInferError(f"no installed runtime serves model {model!r}")
    audit_action = f"runtime.{action}"
    try:
        if action == "stop":
            active = run(
                ["systemctl", "--user", "is-active", ENGINE_SERVICE_NAME],
                check=False,
            )
            if active.returncode == 0:
                run_passthrough(
                    ["systemctl", "--user", "stop", ENGINE_SERVICE_NAME]
                )
            else:
                stop_from_config(argparse.Namespace(config=str(config_path)))
            state = "stopped"
        elif action in {"start", "restart", "recover"}:
            installed = run(
                ["systemctl", "--user", "is-enabled", ENGINE_SERVICE_NAME],
                check=False,
            )
            if installed.returncode != 0 or installed.stdout.strip() not in {
                "enabled", "static",
            }:
                raise LetsInferError(f"{ENGINE_SERVICE_NAME} is not installed")
            if action == "recover":
                clear_protection_trip(config)
            elif protection_trip_latched(config):
                raise LetsInferError(
                    "runtime protection is tripped; use the recover action"
                )
            run_passthrough(
                [
                    "systemctl",
                    "--user",
                    "start" if action == "start" else "restart",
                    ENGINE_SERVICE_NAME,
                ]
            )
            run(["systemctl", "--user", "restart", RECOVERY_TIMER_NAME])
            state = "running"
        else:
            raise LetsInferError("controller runtime action is invalid")
    except Exception as error:
        with _site_store() as store:
            store.record_action(
                audit_action,
                model,
                "failed",
                type(error).__name__,
                actor_type="controller",
                actor_id=principal.controller_id,
                origin_interface="controller-api",
                correlation_id=operation_id,
            )
        raise
    with _site_store() as store:
        store.record_action(
            audit_action,
            model,
            "success",
            actor_type="controller",
            actor_id=principal.controller_id,
            origin_interface="controller-api",
            correlation_id=operation_id,
        )
    return {
        "resource": "placement",
        "identifier": config["placement_id"],
        "model": model,
        "state": state,
    }


def _engine_group_status(model: str | None) -> list[dict[str, Any]]:
    with _site_store() as store:
        placements = {row["placement_id"]: row for row in store.placements()}
        values: list[dict[str, Any]] = []
        for row in store.engine_groups():
            if row["state"] == "removed" or row["desired_state"] == "removed":
                continue
            placement = placements.get(row["placement_id"])
            if placement is None:
                raise LetsInferError("engine-group placement record disappeared")
            if model is not None and placement["model"] != model:
                continue
            values.append({
                "group_id": row["group_id"],
                "placement_id": row["placement_id"],
                "model": placement["model"],
                "runtime": placement["runtime"],
                "target": placement["target"],
                "strategy": row["strategy"],
                "desired_state": row["desired_state"],
                "state": row["state"],
                "topology_sha256": row["topology_sha256"],
                "members": row["members"],
                "endpoints": placement["endpoints"],
                "last_error": row["last_error"],
                "updated_at_unix": row["updated_at_unix"],
            })
    if model is not None and not values:
        raise LetsInferError(f"no installed engine group serves model {model!r}")
    return values


def reconcile_engine_groups_once() -> dict[str, Any]:
    """Refresh durable health without changing a group's desired lifecycle."""
    summary: dict[str, list[str]] = {"healthy": [], "degraded": [], "failed": []}
    now = int(time.time())
    with _site_store() as store:
        for row in store.engine_groups():
            if row["desired_state"] != "running" or row["state"] in {
                "staging", "starting", "recovering", "removing", "removed",
            }:
                continue
            try:
                recovery_in_cooldown = (
                    row["state"] in {"degraded", "failed"}
                    and now - int(row["updated_at_unix"]) < 300
                )
                orchestrator, _manifest = _restore_engine_group_orchestrator(store, row)
                current = orchestrator.reconcile()
                if not recovery_in_cooldown:
                    states = {
                        item["member_id"]: item["state"]
                        for item in current["member_states"]
                    }
                    if (
                        orchestrator.plan.strategy == "distributed"
                        and current["state"] == "failed"
                        and "unreachable" not in states.values()
                        and not any(orchestrator.protection_trips.values())
                    ):
                        current = orchestrator.recover(
                            acknowledge_trips=False
                        )
                    elif (
                        orchestrator.plan.strategy == "replicated"
                        and current["state"] in {"degraded", "failed"}
                        and any(
                            state not in {"running", "unreachable"}
                            and not orchestrator.protection_trips[member_id]
                            for member_id, state in states.items()
                        )
                    ):
                        current = orchestrator.recover_replicas()
                _sync_group_placement(store, current)
                bucket = "healthy" if current["state"] == "running" else current["state"]
                summary[bucket].append(row["group_id"])
            except Exception as error:
                error_code = type(error).__name__
                if row["state"] == "failed" and row["last_error"] == error_code:
                    failed = {
                        **row["plan"],
                        "placement_id": row["placement_id"],
                        "desired_state": "running",
                        "state": "failed",
                        "member_states": row["members"],
                    }
                else:
                    failed = store.set_engine_group(
                        row["plan"],
                        placement_id=row["placement_id"],
                        source=row["source"],
                        engine_credential_sha256=row["engine_credential_sha256"],
                        desired_state="running",
                        state="failed",
                        members=row["members"],
                        action="group.reconcile",
                        error=error_code,
                    )
                _sync_group_placement(store, failed)
                summary["failed"].append(row["group_id"])
    return summary


def install(arguments: argparse.Namespace) -> int:
    catalog_value = getattr(arguments, "catalog", None)
    if not isinstance(catalog_value, str):
        catalog_value = None
    runtime_source = _runtime_source_for_install(
        arguments.model,
        arguments.engine,
        catalog_value,
    )
    runtime_policy = getattr(arguments, "runtime_policy", None)
    if runtime_source is not None and isinstance(runtime_policy, str):
        runtime_source = (
            runtime_source[0],
            runtime_policy,
            runtime_source[2],
            runtime_source[3],
            runtime_source[4],
        )
    prepared_receipt: dict[str, Any] | None = None
    if runtime_source is None:
        manifest_path, manifest = resolve_model(
            arguments.model, arguments.engine
        )
        release_root = manifest_source_root(manifest_path)
    else:
        (
            source,
            policy,
            expected_version,
            selected_target,
            selected_target_sha256,
        ) = runtime_source
        manifest_path, manifest, release_root, prepared_receipt = prepare_runtime_install(
            source,
            policy=policy,
            requested_engine=arguments.engine,
            requested_target=selected_target,
            expected_version=expected_version,
            expected_target_contract_sha256=(
                selected_target_sha256
                or getattr(arguments, "expected_target_contract_sha256", None)
            ),
        )
    selected_receipt = prepared_receipt or runtime_receipt_for_manifest(manifest_path)
    verify_release_sources(manifest, release_root)
    serving = manifest["serving"]
    if not serving["qualified"]:
        if prepared_receipt is not None:
            manifest_sha = sha256_file(manifest_path)
            model_cache = expanded_path(
                getattr(arguments, "model_cache", None)
                or manifest["container"]["model_cache"]
            )
            plugin_root_value = getattr(arguments, "plugin_root", None)
            plugin_root = (
                expanded_path(plugin_root_value)
                if plugin_root_value
                else default_plugin_root(manifest, manifest_sha)
            )
            runtime_artifact_root = pathlib.Path(
                prepared_receipt["object_root"]
            ).expanduser()
            download_dependencies = bool(
                getattr(
                    arguments,
                    "download_dependencies",
                    getattr(arguments, "download", True),
                )
            )
            ensure_install_dependencies(
                manifest,
                model_cache=model_cache,
                runtime_artifact_root=runtime_artifact_root,
                download=download_dependencies,
                build_image=not getattr(arguments, "no_build_image", False),
            )
            wheel_value = getattr(arguments, "wheel", None)
            install_runtime_plugins(
                manifest,
                plugin_root=plugin_root,
                wheel_source=pathlib.Path(wheel_value) if wheel_value else None,
                artifact_root=release_root,
            )
            verify_installed_release(
                manifest,
                model_cache=model_cache,
                plugin_root=plugin_root,
            )
            store_root_value = getattr(arguments, "store_root", None)
            store_root = (
                expanded_path(store_root_value)
                if store_root_value
                else default_store_root(manifest)
            )
            runtime_cache_value = getattr(arguments, "runtime_cache_root", None)
            runtime_cache_root = (
                expanded_path(runtime_cache_value)
                if runtime_cache_value
                else default_runtime_cache_root(manifest)
            )
            api_key_value = getattr(arguments, "api_key_file", None)
            tls_cert_value = getattr(arguments, "tls_cert_file", None)
            tls_key_value = getattr(arguments, "tls_key_file", None)
            api_key_file = expanded_path(
                api_key_value or default_engine_api_key_path()
            )
            tls_cert_file = expanded_path(tls_cert_value or default_tls_cert_path())
            tls_key_file = expanded_path(tls_key_value or default_tls_key_path())
            ensure_private_directory(store_root)
            ensure_runtime_home(runtime_cache_root)
            ensure_api_key(api_key_file)
            ensure_tls_material(tls_cert_file, tls_key_file)
            try:
                receipt_path = write_selection(prepared_receipt)
            except RuntimePackError as error:
                raise LetsInferError(str(error)) from error
            print(
                f"INSTALLED RUNTIME {prepared_receipt['name']} "
                f"version={prepared_receipt['version']} digest=sha256:{prepared_receipt['digest']} "
                f"activation=blocked receipt={receipt_path}"
            )
            print(f"  blocked_by: {serving['blocked_by']}")
            return 0
        raise LetsInferError(
            f"serving configuration is not qualified: {serving['blocked_by']}"
        )
    if not arguments.no_service and not user_lingering_enabled():
        raise LetsInferError(
            "boot-persistent user service requires lingering; run "
            f"sudo loginctl enable-linger {getpass.getuser()} and retry"
        )
    placement_strategy = target_contract(manifest)["placement"]["strategy"]
    if placement_strategy != "single":
        if selected_receipt is None:
            raise LetsInferError(
                "multi-member installation requires an installed immutable runtime pack"
            )
        return install_engine_group(
            arguments,
            source=str(selected_receipt["source"]),
            manifest_path=manifest_path,
            manifest=manifest,
            control_root=release_root,
            receipt=selected_receipt,
        )
    manifest_sha = sha256_file(manifest_path)
    placement = resolve_service_placement(manifest, manifest_sha)
    control_root, installed_manifest_path = install_control_bundle(
        manifest_path,
        manifest,
        artifact_roots=(release_root, source_root()),
    )

    config_path = absolute_user_path(
        arguments.config or default_service_config_path()
    )
    previous_config: dict[str, Any] | None = None
    if config_path.is_file():
        candidate = read_service_config(config_path)
        if (
            candidate["release"] == manifest["release"]
            and candidate["engine"] == adapter_for(manifest).name
        ):
            previous_config = candidate

    model_cache = expanded_path(arguments.model_cache or manifest["container"]["model_cache"])
    plugin_root = (
        expanded_path(arguments.plugin_root)
        if arguments.plugin_root
        else default_plugin_root(manifest, manifest_sha)
    )
    store_root = (
        expanded_path(arguments.store_root)
        if arguments.store_root
        else expanded_path(previous_config["store_root"])
        if previous_config
        else default_store_root(manifest)
    )
    runtime_cache_root = (
        expanded_path(arguments.runtime_cache_root)
        if arguments.runtime_cache_root
        else default_runtime_cache_root(manifest)
    )
    api_key_file = expanded_path(
        arguments.api_key_file or default_engine_api_key_path()
    )
    gateway_api_key_file = default_api_key_path()
    try:
        gateway_token = read_api_key(gateway_api_key_file)
        with SiteStore() as store:
            if store.authenticate_key(gateway_token) is None:
                raise LetsInferError(
                    "the local inference API key is not registered; run `letsinfer setup`"
                )
    except SiteError as error:
        raise LetsInferError(str(error)) from error
    tls_cert_file = expanded_path(arguments.tls_cert_file or default_tls_cert_path())
    tls_key_file = expanded_path(arguments.tls_key_file or default_tls_key_path())
    watchdog_data_root = expanded_path(
        arguments.watchdog_data_root or default_watchdog_data_root()
    )
    watchdog_cert_file = expanded_path(
        arguments.watchdog_cert_file or default_watchdog_cert_path()
    )
    watchdog_key_file = expanded_path(
        arguments.watchdog_key_file or default_watchdog_key_path()
    )
    watchdog_controller_ca_file = expanded_path(
        arguments.watchdog_controller_ca_file or default_watchdog_controller_ca_path()
    )
    watchdog_controller_ca_key_file = expanded_path(
        arguments.watchdog_controller_ca_key_file
        or default_watchdog_controller_ca_key_path()
    )
    watchdog_local_controller_cert_file = expanded_path(
        arguments.watchdog_local_controller_cert_file
        or default_watchdog_local_controller_cert_path()
    )
    watchdog_local_controller_key_file = expanded_path(
        arguments.watchdog_local_controller_key_file
        or default_watchdog_local_controller_key_path()
    )
    runtime_artifact_root = (
        pathlib.Path(selected_receipt["object_root"]).expanduser()
        if selected_receipt is not None
        else None
    )
    download_dependencies = bool(
        getattr(
            arguments,
            "download_dependencies",
            getattr(arguments, "download", True),
        )
    )
    ensure_install_dependencies(
        manifest,
        model_cache=model_cache,
        runtime_artifact_root=runtime_artifact_root,
        download=download_dependencies,
        build_image=not arguments.no_build_image,
    )
    install_runtime_plugins(
        manifest,
        plugin_root=plugin_root,
        wheel_source=pathlib.Path(arguments.wheel) if arguments.wheel else None,
        artifact_root=control_root,
    )
    ensure_private_directory(store_root)
    ensure_runtime_home(runtime_cache_root)
    ensure_api_key(api_key_file)
    ensure_tls_material(tls_cert_file, tls_key_file)
    ensure_private_directory(watchdog_data_root)
    ensure_private_directory(watchdog_data_root / PROTECTION_ROOT_NAME)
    ensure_watchdog_tls_material(
        watchdog_cert_file,
        watchdog_key_file,
        watchdog_controller_ca_file,
        watchdog_controller_ca_key_file,
        watchdog_local_controller_cert_file,
        watchdog_local_controller_key_file,
    )
    installation_identity = ensure_installation_identity()
    site_identity = read_site_identity()
    controller_allowlist_file = ensure_controller_authorization(
        site_identity,
        watchdog_local_controller_cert_file,
    )
    (
        watchdog_binary,
        watchdog_binary_sha,
        watchdog_source_sha,
    ) = install_core_watchdog_runtime()
    verify_installed_release(manifest, model_cache=model_cache, plugin_root=plugin_root)

    ensure_private_directory(config_path.parent)
    config = {
        "schema_version": SERVICE_CONFIG_VERSION,
        "engine": adapter_for(manifest).name,
        "model": manifest["model"]["alias"],
        "release": manifest["release"],
        "manifest_sha256": manifest_sha,
        "name": arguments.name or f"letsinfer-{adapter_for(manifest).name.replace('.', '-')}",
        "gateway_listen": arguments.gateway_listen,
        "gateway_protocol": "http",
        "gateway_port": arguments.port,
        "gateway_max_connections": arguments.gateway_max_connections,
        "gateway_queue_timeout_seconds": arguments.gateway_queue_timeout,
        "gateway_telemetry_file": str(default_gateway_telemetry_path()),
        "engine_port": arguments.engine_port,
        **placement,
        "model_cache": str(model_cache),
        "plugin_root": str(plugin_root),
        "store_root": str(store_root),
        "runtime_cache_root": str(runtime_cache_root),
        "engine_api_key_file": str(api_key_file),
        "gateway_api_key_file": str(gateway_api_key_file),
        "tls_cert_file": str(tls_cert_file),
        "tls_key_file": str(tls_key_file),
        "watchdog_binary_path": str(watchdog_binary),
        "watchdog_binary_sha256": watchdog_binary_sha,
        "watchdog_source_sha256": watchdog_source_sha,
        "watchdog_data_root": str(watchdog_data_root),
        "protection_root": str(
            watchdog_data_root / PROTECTION_ROOT_NAME / placement["placement_id"]
        ),
        "watchdog_listen": arguments.watchdog_listen or manifest["watchdog"]["listen"],
        "watchdog_port": arguments.watchdog_port or manifest["watchdog"]["port"],
        "memory_pressure_available_bytes": manifest["watchdog"]["protection"][
            "warning_available_bytes"
        ],
        "watchdog_cert_file": str(watchdog_cert_file),
        "watchdog_key_file": str(watchdog_key_file),
        "watchdog_controller_ca_file": str(watchdog_controller_ca_file),
        "watchdog_controller_ca_key_file": str(watchdog_controller_ca_key_file),
        "watchdog_local_controller_cert_file": str(
            watchdog_local_controller_cert_file
        ),
        "watchdog_local_controller_key_file": str(
            watchdog_local_controller_key_file
        ),
        "installation_id": installation_identity["installation_id"],
        "watchdog_controller_allowlist_file": str(controller_allowlist_file),
        "source_root": str(control_root),
        "manifest_path": str(installed_manifest_path),
    }
    if selected_receipt is not None:
        config.update(
            {
                "runtime_name": selected_receipt["name"],
                "runtime_version": selected_receipt["version"],
                "runtime_digest": selected_receipt["digest"],
                "runtime_policy": selected_receipt["policy"],
            }
        )
    config["watchdog_public_state_file"] = str(
        write_watchdog_public_state(config, manifest)
    )
    if arguments.no_service:
        active = run(
            ["systemctl", "--user", "is-active", SERVICE_NAME], check=False
        )
        if active.returncode == 0:
            raise LetsInferError(
                "--no-service cannot replace configuration for an active service"
            )
        atomic_json(config_path, config)
        config_path.chmod(0o600)
        update_service_placement(config, manifest, "stopped")
    else:
        install_user_service(
            config_path,
            config,
            manifest,
            no_start=arguments.no_start,
        )
        if arguments.no_start:
            update_service_placement(config, manifest, "stopped")
    if prepared_receipt is not None:
        prepared_receipt["manifest_path"] = str(installed_manifest_path)
        prepared_receipt["control_root"] = str(control_root)
        try:
            write_selection(prepared_receipt)
        except RuntimePackError as error:
            raise LetsInferError(
                f"runtime activated but its selection receipt could not be written: {error}"
            ) from error
    print(
        f"INSTALLED {manifest['release']} "
        f"config={config_path} service={'disabled' if arguments.no_service else 'enabled'}"
    )
    return 0


def _stop_managed_container(
    name: str, api_key_file: pathlib.Path | None = None
) -> int:
    inspection = container_inspect(name)
    if inspection is None:
        print(f"STOPPED {name} already-absent=true")
        return 0
    labels = inspection.get("Config", {}).get("Labels") or {}
    if labels.get(MANAGED_LABEL) != "true":
        raise LetsInferError(f"container {name} is not managed by Let's Infer; refusing to remove it")

    stamp = dt.datetime.now().astimezone().strftime("%Y%m%dT%H%M%S%z")
    evidence = pathlib.Path.home() / ".cache/letsinfer/results/stops" / f"{name}-{stamp}"
    evidence.mkdir(parents=True, exist_ok=False)
    atomic_json(evidence / "container-inspect.json", inspection)
    logs = run(["docker", "logs", "--tail", "1000", name], check=False)
    known_keys: list[str] = []
    checked_paths: set[pathlib.Path] = set()
    for candidate in (api_key_file, default_api_key_path()):
        if candidate is None or candidate in checked_paths:
            continue
        checked_paths.add(candidate)
        try:
            known_keys.append(read_api_key(candidate))
        except LetsInferError:
            continue
    write_text(
        evidence / "server-tail.log",
        redact_secrets((logs.stdout or "") + (logs.stderr or ""), known_keys),
    )

    run(["docker", "update", "--restart", "no", name])
    if inspection.get("State", {}).get("Running", False):
        run(["docker", "stop", "--time", "120", name])
    run(["docker", "rm", name])
    print(f"STOPPED {name} evidence={evidence}")
    return 0


def stop_from_config(arguments: argparse.Namespace) -> int:
    config = read_service_config(pathlib.Path(arguments.config))
    _, manifest = configured_release(config)
    disarm_protection(config, wait_for_ack=False)
    result = _stop_managed_container(
        config["name"], expanded_path(config["engine_api_key_file"])
    )
    update_service_placement(config, manifest, "stopped")
    return result


def stop(arguments: argparse.Namespace) -> int:
    model_value = getattr(arguments, "model", None)
    model = model_value if isinstance(model_value, str) else None
    if model is not None and (arguments.name is not None or arguments.config is not None):
        raise LetsInferError("a model cannot be combined with --name or --config")
    if arguments.name is None and arguments.config is None:
        group = _engine_group_lifecycle(model, "stop")
        if group is not None:
            print(
                f"STOPPED group={group['group_id']} "
                f"members={len(group['member_states'])}"
            )
            return 0
    config_path = absolute_user_path(
        arguments.config or default_service_config_path()
    )
    config = read_service_config(config_path) if config_path.is_file() else None
    if model is not None and (config is None or config.get("model") != model):
        raise LetsInferError(f"no installed runtime serves model {model!r}")
    explicit_name = arguments.name is not None
    name = arguments.name
    if name is None and config is not None:
        name = config["name"]
    if name is None:
        raise LetsInferError("no service configuration exists; specify --name")

    if not arguments.container_only and not explicit_name:
        active = run(
            ["systemctl", "--user", "is-active", ENGINE_SERVICE_NAME],
            check=False,
        )
        if active.returncode == 0:
            run_passthrough(
                ["systemctl", "--user", "stop", ENGINE_SERVICE_NAME]
            )
            print(f"STOPPED {ENGINE_SERVICE_NAME}")
            return 0
    if config is not None:
        disarm_protection(config)
    key_path = expanded_path(config["engine_api_key_file"]) if config is not None else None
    return _stop_managed_container(name, key_path)


def runtime_lifecycle(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Derive one explicit runtime lifecycle from observed component state."""
    service_value = payload.get("service")
    container_value = payload.get("container")
    protection_value = payload.get("protection")
    service = service_value if isinstance(service_value, Mapping) else {}
    container = container_value if isinstance(container_value, Mapping) else {}
    protection = (
        protection_value if isinstance(protection_value, Mapping) else {}
    )
    engine_ready = (
        container.get("state") == "running"
        and container.get("healthy") is True
        and container.get("docker_health") == "healthy"
        and container.get("model_identity") is True
    )
    api_ready = (
        service.get("gateway_active") == "active"
        and service.get("gateway_health") is True
        and service.get("gateway_auth_required") is True
        and service.get("gateway_authenticated") is True
    )
    runtime_metadata_ready = service.get("runtime_metadata_ready") is not False
    route_ready = service.get("gateway_model_identity") is True
    safety_ready = (
        protection.get("armed") is True
        and protection.get("trip_latched") is False
    )
    unit_states = (
        service.get("active") == "active",
        service.get("engine_active") == "active",
        service.get("gateway_active") == "active",
        service.get("site_active") == "active",
        service.get("recovery_timer_active") == "active",
    )
    ready_units = sum(unit_states)
    details = {
        "ready": False,
        "transitional": False,
        "ready_services": ready_units,
        "total_services": len(unit_states),
    }
    if protection.get("trip_latched") is True:
        return {**details, "state": "blocked", "reason": "protection-trip"}
    engine_state = str(service.get("engine_active") or "unknown")
    container_state = str(container.get("state") or "absent")
    docker_health = str(container.get("docker_health") or "none")
    protection_phase = str(protection.get("phase") or "unknown")
    if (
        engine_state in {"activating", "reloading"}
        or container_state == "restarting"
        or docker_health == "starting"
        or protection_phase == "starting"
    ):
        return {
            **details,
            "state": "starting",
            "reason": "runtime-startup",
            "transitional": True,
        }
    if engine_state == "deactivating" or container_state == "removing":
        return {
            **details,
            "state": "stopping",
            "reason": "runtime-shutdown",
            "transitional": True,
        }
    if (
        engine_ready
        and api_ready
        and route_ready
        and runtime_metadata_ready
        and safety_ready
        and ready_units == len(unit_states)
    ):
        return {
            **details,
            "state": "ready",
            "reason": "all-components-ready",
            "ready": True,
        }
    if engine_state == "failed" or docker_health == "unhealthy" or container_state in {
        "dead",
        "paused",
    }:
        return {**details, "state": "failed", "reason": "runtime-failure"}
    if engine_state in {"inactive", "not-found"} and container_state in {
        "absent",
        "created",
        "exited",
    }:
        return {**details, "state": "stopped", "reason": "runtime-stopped"}
    if not runtime_metadata_ready:
        return {
            **details,
            "state": "degraded",
            "reason": "runtime-metadata-incompatible",
        }
    return {**details, "state": "degraded", "reason": "component-not-ready"}


def status(arguments: argparse.Namespace) -> int:
    model_value = getattr(arguments, "model", None)
    model = model_value if isinstance(model_value, str) else None
    if model is not None and (arguments.name is not None or arguments.config is not None):
        raise LetsInferError("a model cannot be combined with --name or --config")
    if arguments.name is None and arguments.config is None and site_identity_path().exists():
        identity = read_site_identity()
        if identity.role == "coordinator":
            groups = _engine_group_status(model)
            if groups:
                if arguments.json:
                    print(json.dumps({"engine_groups": groups}, sort_keys=True))
                else:
                    for group in groups:
                        print(
                            f"GROUP {group['group_id']} model={group['model']} "
                            f"strategy={group['strategy']} state={group['state']} "
                            f"desired={group['desired_state']}"
                        )
                        for member in group["members"]:
                            print(
                                f"  MEMBER {member['member_id']} role={member['role']} "
                                f"state={member['state']}"
                            )
                return 0
        elif model is not None:
            raise LetsInferError(
                "site-wide engine-group status is available from the coordinator"
            )
    config_path = absolute_user_path(
        arguments.config or default_service_config_path()
    )
    config = read_service_config(config_path) if config_path.is_file() else None
    configured_manifest: dict[str, Any] | None = None
    runtime_metadata_error: str | None = None
    if config is not None:
        try:
            _, configured_manifest = configured_release(config)
        except LetsInferError as error:
            runtime_metadata_error = str(error)
    if model is not None and (config is None or config.get("model") != model):
        raise LetsInferError(f"no installed runtime serves model {model!r}")
    name = arguments.name or (config["name"] if config else None)
    if name is None:
        if not site_identity_path().exists():
            raise LetsInferError("no service configuration exists; specify --name")
        identity = read_site_identity()
        site_enabled, site_active, site_memory_bytes = _service_state(
            SITE_SERVICE_NAME
        )
        gateway_enabled, gateway_active, gateway_memory_bytes = _service_state(
            GATEWAY_SERVICE_NAME
        )
        coordinator = identity.role == "coordinator"
        gateway_health = False
        gateway_auth_required = False
        gateway_authenticated = False
        endpoint = None
        if coordinator:
            gateway_config_path = site_config_root() / "gateway.json"
            gateway_port = 8000
            if gateway_config_path.is_file():
                gateway_config = read_json(gateway_config_path)
                value = gateway_config.get("gateway_port")
                if isinstance(value, int) and not isinstance(value, bool):
                    gateway_port = value
            gateway_health = api_status(gateway_port, "/health", None) == 200
            gateway_auth_required = (
                api_status(gateway_port, "/v1/models", None) == 401
            )
            gateway_authenticated = (
                api_status(
                    gateway_port,
                    "/v1/models",
                    None,
                    default_api_key_path(),
                )
                == 200
            )
            endpoint = local_inference_endpoint(gateway_port)
        payload = {
            "identity": identity_json(identity),
            "endpoint": endpoint,
            "services": {
                "site_enabled": site_enabled,
                "site_active": site_active,
                "site_memory_current_bytes": site_memory_bytes,
                "gateway_enabled": gateway_enabled,
                "gateway_active": gateway_active,
                "gateway_memory_current_bytes": gateway_memory_bytes,
                "gateway_health": gateway_health,
                "gateway_auth_required": gateway_auth_required,
                "gateway_authenticated": gateway_authenticated,
            },
            "runtime": None,
        }
        if arguments.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        elif ui.Terminal(sys.stdout).interactive:
            ui.site_status(payload)
        else:
            print(
                f"site={site_active} enabled={site_enabled} "
                f"role={identity.role} member={identity.member_id}"
            )
            if coordinator:
                print(
                    f"gateway={gateway_active} health={str(gateway_health).lower()} "
                    f"auth={str(gateway_auth_required and gateway_authenticated).lower()}"
                )
                print(f"endpoint={endpoint}")
            print("runtime=not-installed")
        return (
            0
            if site_active == "active"
            and (
                not coordinator
                or (
                    gateway_active == "active"
                    and gateway_health
                    and gateway_auth_required
                    and gateway_authenticated
                )
            )
            else 1
        )

    enabled, active, memory_bytes = _service_state()
    inspection = container_inspect(name)
    container_state = "absent"
    healthy = False
    labels: dict[str, str] = {}
    restart_policy = None
    docker_health = "none"
    engine_api_key_required = False
    engine_identity = False
    engine_tls = False
    if inspection is not None:
        container_state = inspection.get("State", {}).get("Status", "unknown")
        labels = inspection.get("Config", {}).get("Labels") or {}
        restart_policy = inspection.get("HostConfig", {}).get("RestartPolicy", {}).get("Name")
        port_text = labels.get(PORT_LABEL) or (
            str(config["engine_port"]) if config else "18000"
        )
        state_health = inspection.get("State", {}).get("Health") or {}
        docker_health = state_health.get("Status", "none")
        if config:
            cert_path = expanded_path(config["tls_cert_file"])
            key_path = expanded_path(config["engine_api_key_file"])
            healthy = container_state == "running" and health_ready(
                int(port_text), cert_path
            )
            engine_tls = healthy
            unauthenticated_status = inference_auth_status(
                int(port_text), cert_path
            )
            authenticated_status = inference_auth_status(
                int(port_text), cert_path, key_path
            )
            if configured_manifest is not None:
                engine_identity = model_identity_ready(
                    configured_manifest, int(port_text), cert_path, key_path
                )
            else:
                engine_identity = model_alias_ready(
                    config["model"], int(port_text), cert_path, key_path
                )
            engine_api_key_required = (
                unauthenticated_status == 401
                and authenticated_status in {400, 422}
            )

    engine_enabled, engine_active, _ = _service_state(ENGINE_SERVICE_NAME)
    site_enabled, site_active, site_memory_bytes = _service_state(SITE_SERVICE_NAME)
    gateway_enabled, gateway_active, gateway_memory_bytes = _service_state(
        GATEWAY_SERVICE_NAME
    )
    gateway_health = False
    gateway_auth_required = False
    gateway_authenticated = False
    gateway_identity = False
    if config:
        gateway_key_path = expanded_path(config["gateway_api_key_file"])
        gateway_health = api_status(config["gateway_port"], "/health", None) == 200
        gateway_auth_required = (
            api_status(config["gateway_port"], "/v1/models", None) == 401
        )
        gateway_authenticated = (
            api_status(
                config["gateway_port"], "/v1/models", None, gateway_key_path
            )
            == 200
        )
        if configured_manifest is not None:
            gateway_identity = model_identity_ready(
                configured_manifest,
                config["gateway_port"],
                None,
                gateway_key_path,
            )
        else:
            gateway_identity = model_alias_ready(
                config["model"],
                config["gateway_port"],
                None,
                gateway_key_path,
            )
    recovery_enabled, recovery_active = _unit_enabled_active(RECOVERY_TIMER_NAME)

    payload = {
        "service": {
            "name": SERVICE_NAME,
            "enabled": enabled,
            "active": active,
            "memory_current_bytes": memory_bytes,
            "memory_limit_bytes": CONTROL_PLANE_MEMORY_LIMIT_BYTES,
            "within_memory_limit": memory_bytes is not None
            and memory_bytes < CONTROL_PLANE_MEMORY_LIMIT_BYTES,
            "role": "watchdog",
            "engine_service": ENGINE_SERVICE_NAME,
            "engine_enabled": engine_enabled,
            "engine_active": engine_active,
            "site_service": SITE_SERVICE_NAME,
            "site_enabled": site_enabled,
            "site_active": site_active,
            "site_memory_current_bytes": site_memory_bytes,
            "site_memory_limit_bytes": SITE_AGENT_MEMORY_LIMIT_BYTES,
            "site_within_memory_limit": site_memory_bytes is not None
            and site_memory_bytes < SITE_AGENT_MEMORY_LIMIT_BYTES,
            "gateway_service": GATEWAY_SERVICE_NAME,
            "gateway_enabled": gateway_enabled,
            "gateway_active": gateway_active,
            "gateway_memory_current_bytes": gateway_memory_bytes,
            "gateway_health": gateway_health,
            "gateway_auth_required": gateway_auth_required,
            "gateway_authenticated": gateway_authenticated,
            "gateway_model_identity": gateway_identity,
            "runtime_metadata_ready": configured_manifest is not None,
            "runtime_metadata_error": runtime_metadata_error,
            "gateway_protocol": config.get("gateway_protocol") if config else None,
            "gateway_endpoint": (
                local_inference_endpoint(config["gateway_port"])
                if config else None
            ),
            "recovery_timer_enabled": recovery_enabled,
            "recovery_timer_active": recovery_active,
        },
        "container": {
            "name": name,
            "state": container_state,
            "healthy": healthy,
            "docker_health": docker_health,
            "tls": engine_tls,
            "api_key_required": engine_api_key_required,
            "model_identity": engine_identity,
            "managed": labels.get(MANAGED_LABEL) == "true",
            "release": labels.get(RELEASE_LABEL),
            "engine": labels.get(ENGINE_LABEL),
            "model": labels.get(MODEL_LABEL) or (config.get("model") if config else None),
            "target": labels.get(TARGET_ID_LABEL),
            "runtime_version": config.get("runtime_version") if config else None,
            "capacity": (
                {
                    key: configured_manifest["serving"][key]
                    for key in (
                        "max_connections",
                        "max_active_requests",
                        "max_context_tokens",
                    )
                }
                if configured_manifest is not None and engine_identity
                else None
            ),
            "restart_policy": restart_policy,
        },
        "protection": protection_status(config, inspection) if config else None,
        "config": str(config_path) if config else None,
    }
    payload["lifecycle"] = runtime_lifecycle(payload)
    if arguments.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    elif ui.Terminal(sys.stdout).interactive:
        ui.runtime_status(payload)
    else:
        memory = "none" if memory_bytes is None else str(memory_bytes)
        print(f"service={active} enabled={enabled} control_memory_bytes={memory}")
        print(
            f"lifecycle={payload['lifecycle']['state']} "
            f"reason={payload['lifecycle']['reason']}"
        )
        print(
            f"container={container_state} healthy={str(healthy).lower()} "
            f"docker_health={docker_health} tls={str(engine_tls).lower()} "
            f"auth={str(engine_api_key_required).lower()} restart={restart_policy or 'none'} "
            f"engine={labels.get(ENGINE_LABEL) or 'unknown'}"
        )
        print(
            f"watchdog={active} memory_bytes={memory} "
            f"engine_service={engine_active} gateway={gateway_active} "
            f"gateway_health={str(gateway_health).lower()} "
            f"recovery_timer={recovery_active}"
        )
        if config:
            protection = payload["protection"]
            print(
                f"protection={protection['phase']} "
                f"armed={str(protection['armed']).lower()} "
                f"trip_latched={str(protection['trip_latched']).lower()}"
            )
            print(f"endpoint={local_inference_endpoint(config['gateway_port'])}")
    return 0 if payload["lifecycle"]["state"] in {
        "ready",
        "starting",
        "stopping",
        "stopped",
    } else 1


def _managed_inspection(name: str) -> dict[str, Any]:
    inspection = container_inspect(name)
    if inspection is None:
        raise LetsInferError(f"managed container is absent: {name}")
    labels = inspection.get("Config", {}).get("Labels") or {}
    if labels.get(MANAGED_LABEL) != "true":
        raise LetsInferError(f"container {name} is not managed by Let's Infer")
    return inspection


def logs(arguments: argparse.Namespace) -> int:
    config_path = absolute_user_path(
        arguments.config or default_service_config_path()
    )
    config = read_service_config(config_path)
    _managed_inspection(config["name"])
    command = ["docker", "logs", "--timestamps", "--tail", str(arguments.tail)]
    if arguments.follow:
        command.append("--follow")
    command.append(config["name"])
    run_passthrough(command)
    return 0


def _run_engine_service_action(
    arguments: argparse.Namespace, action: str
) -> int:
    if action not in {"start", "restart", "recover"}:
        raise LetsInferError("engine service action is invalid")
    model_value = getattr(arguments, "model", None)
    model = model_value if isinstance(model_value, str) else None
    if model is not None and arguments.config is not None:
        raise LetsInferError("a model cannot be combined with --config")
    if arguments.config is None:
        group = _engine_group_lifecycle(model, action)
        if group is not None:
            print(
                f"{action.upper()} group={group['group_id']} "
                f"members={len(group['member_states'])} "
                f"protection_trips_acknowledged={str(action == 'recover').lower()}"
            )
            return 0
    config_path = absolute_user_path(
        arguments.config or default_service_config_path()
    )
    config = read_service_config(config_path)
    if model is not None and config.get("model") != model:
        raise LetsInferError(f"no installed runtime serves model {model!r}")
    enabled = run(
        ["systemctl", "--user", "is-enabled", ENGINE_SERVICE_NAME],
        check=False,
    )
    if enabled.returncode != 0 or enabled.stdout.strip() not in {"enabled", "static"}:
        raise LetsInferError(f"{ENGINE_SERVICE_NAME} is not installed")
    if action == "recover":
        cleared_trip = clear_protection_trip(config)
    else:
        if protection_trip_latched(config):
            raise LetsInferError(
                "runtime protection is tripped; use `letsinfer recover`"
            )
        cleared_trip = False
    systemd_action = "start" if action == "start" else "restart"
    run_passthrough(["systemctl", "--user", systemd_action, ENGINE_SERVICE_NAME])
    run(["systemctl", "--user", "restart", RECOVERY_TIMER_NAME])
    print(
        f"{action.upper()} {ENGINE_SERVICE_NAME} protection_trip_cleared="
        f"{str(cleared_trip).lower()}"
    )
    return 0


def start_service(arguments: argparse.Namespace) -> int:
    return _run_engine_service_action(arguments, "start")


def restart_service(arguments: argparse.Namespace) -> int:
    return _run_engine_service_action(arguments, "restart")


def recover_service(arguments: argparse.Namespace) -> int:
    return _run_engine_service_action(arguments, "recover")


def _unit_enabled_active(name: str) -> tuple[str, str]:
    if platform.system() == "Darwin":
        enabled, active, _memory = _service_state(name)
        return enabled, active
    enabled = run(["systemctl", "--user", "is-enabled", name], check=False)
    active = run(["systemctl", "--user", "is-active", name], check=False)
    return enabled.stdout.strip() or "not-found", active.stdout.strip() or "inactive"


def user_lingering_enabled() -> bool:
    if platform.system() == "Darwin":
        return macos_services.user_domain_available()
    linger = run(
        ["loginctl", "show-user", getpass.getuser(), "--property", "Linger", "--value"],
        check=False,
    )
    return linger.returncode == 0 and linger.stdout.strip().lower() == "yes"


def _doctor_engine_groups(
    arguments: argparse.Namespace,
    groups: Sequence[Mapping[str, Any]],
) -> int:
    checks: list[dict[str, Any]] = []

    def record(name: str, passed: bool, detail: str, *, required: bool = True) -> None:
        checks.append(
            {"name": name, "passed": passed, "required": required, "detail": detail}
        )

    identity = read_site_identity()
    record(
        "site-role", identity.role == "coordinator",
        f"role={identity.role} coordinator={identity.coordinator_id}",
    )
    record("user-lingering", user_lingering_enabled(), getpass.getuser())
    for unit, limit in (
        (SITE_SERVICE_NAME, SITE_AGENT_MEMORY_LIMIT_BYTES),
        (SERVICE_NAME, CONTROL_PLANE_MEMORY_LIMIT_BYTES),
        (GATEWAY_SERVICE_NAME, GATEWAY_MEMORY_LIMIT_BYTES),
    ):
        enabled, active, memory_bytes = _service_state(unit)
        record(
            f"service-{unit}",
            enabled == "enabled"
            and active == "active"
            and memory_bytes is not None
            and memory_bytes < limit,
            f"enabled={enabled} active={active} memory={memory_bytes} limit={limit}",
        )
    config_path = site_config_root() / "gateway.json"
    expected_gateway = {
        "schema_version": 2,
        "gateway_listen": "0.0.0.0",
        "gateway_protocol": "http",
        "gateway_port": 8000,
        "gateway_max_connections": 256,
        "gateway_queue_timeout_seconds": 300,
        "gateway_telemetry_file": str(default_gateway_telemetry_path()),
    }
    try:
        gateway_config = read_json(config_path)
        details = config_path.stat()
        gateway_config_valid = (
            gateway_config == expected_gateway
            and not config_path.is_symlink()
            and details.st_uid == os.getuid()
            and stat.S_IMODE(details.st_mode) == 0o600
        )
        record("gateway-config", gateway_config_valid, str(config_path))
    except (OSError, json.JSONDecodeError) as error:
        gateway_config = expected_gateway
        record("gateway-config", False, str(error))
    key_path = default_api_key_path()
    try:
        gateway_health = api_status(
            int(gateway_config["gateway_port"]), "/health", None
        )
        anonymous = api_status(
            int(gateway_config["gateway_port"]), "/v1/models", None
        )
        authenticated = api_status(
            int(gateway_config["gateway_port"]),
            "/v1/models",
            None,
            key_path,
        )
        record(
            "gateway-api",
            gateway_health == 200 and anonymous == 401 and authenticated == 200,
            f"health={gateway_health} anonymous={anonymous} authenticated={authenticated}",
        )
    except LetsInferError as error:
        record("gateway-api", False, str(error))
    with _site_store() as store:
        rows = {row["group_id"]: row for row in store.engine_groups()}
        for group in groups:
            row = rows.get(str(group["group_id"]))
            try:
                if row is None:
                    raise LetsInferError("engine-group journal disappeared")
                _restore_engine_group_orchestrator(store, row)
                immutable = True
                immutable_detail = row["runtime_digest"]
            except LetsInferError as error:
                immutable = False
                immutable_detail = str(error)
            record(
                f"group-{group['group_id']}-immutable",
                immutable,
                immutable_detail,
            )
            members_running = all(
                item["state"] == "running" for item in group["members"]
            )
            endpoints_healthy = bool(group["endpoints"]) and all(
                endpoint.get("healthy") is True for endpoint in group["endpoints"]
            )
            record(
                f"group-{group['group_id']}-health",
                group["state"] == "running"
                and group["desired_state"] == "running"
                and members_running
                and endpoints_healthy,
                f"state={group['state']} desired={group['desired_state']} "
                f"members_running={members_running} endpoints_healthy={endpoints_healthy}",
            )
        try:
            audit = store.verify_audit()
            record("site-audit-chain", bool(audit.get("valid")), compact_json(audit))
        except SiteError as error:
            record("site-audit-chain", False, str(error))
        exposure = store.exposure()
        if exposure is None or exposure["state"] == "disabled":
            record("public-exposure", True, "disabled")
        else:
            try:
                live = verify_tailscale(exposure["configuration_sha256"])
                passed = (
                    exposure["state"] == "enabled"
                    and live.public_url == exposure["public_url"]
                    and live.inference_target == exposure["inference_target"]
                )
                record(
                    "public-exposure",
                    passed,
                    f"provider={exposure['provider']} url={exposure['public_url']}",
                )
            except ExposureError as error:
                record("public-exposure", False, str(error))
    operational_ready = all(
        item["passed"] for item in checks if item["required"]
    )
    payload = {
        "operational_ready": operational_ready,
        "publication_ready": False,
        "engine_groups": [dict(item) for item in groups],
        "checks": checks,
    }
    if arguments.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for item in checks:
            print(
                f"{'PASS' if item['passed'] else 'FAIL'} {item['name']}: "
                f"{item['detail']}"
            )
        print(f"operational_ready={str(operational_ready).lower()}")
    return 0 if operational_ready else 1


def doctor(arguments: argparse.Namespace) -> int:
    checks: list[dict[str, Any]] = []

    def record(name: str, passed: bool, detail: str, *, required: bool = True) -> None:
        checks.append(
            {"name": name, "passed": passed, "required": required, "detail": detail}
        )

    model_value = getattr(arguments, "model", None)
    model = model_value if isinstance(model_value, str) else None
    if arguments.config is None and site_identity_path().exists():
        identity = read_site_identity()
        if identity.role == "coordinator":
            groups = _engine_group_status(model)
            if groups:
                return _doctor_engine_groups(arguments, groups)
        elif model is not None:
            raise LetsInferError(
                "site-wide engine-group doctor is available from the coordinator"
            )

    config_path = absolute_user_path(
        arguments.config or default_service_config_path()
    )
    config = read_service_config(config_path)
    _, manifest = configured_release(config)
    adapter = adapter_for(manifest)
    record(
        "engine-adapter",
        config["engine"] == adapter.name,
        f"engine={adapter.name} format={adapter.model_format} "
        f"cache={cache_provider_for(manifest)}",
    )

    target = target_contract(manifest)
    try:
        device = host_device_fingerprint()
        record(
            "runtime-target",
            target_matches(target, device),
            f"target={target['id']} actual={compact_json(device)}",
        )
    except LetsInferError as error:
        device = None
        record("runtime-target", False, str(error))

    docker_info = run(["docker", "info", "--format", "{{json .Runtimes}}"], check=False)
    record("docker", docker_info.returncode == 0, (docker_info.stderr or "server reachable").strip())
    nvidia = run(["nvidia-smi", "-L"], check=False)
    record(
        "nvidia-runtime",
        nvidia.returncode == 0 and "GPU" in nvidia.stdout,
        (nvidia.stdout or nvidia.stderr).strip(),
    )
    try:
        reserve = require_memory_reserve(manifest, phase="runtime")
        record("runtime-memory-reserve", True, compact_json(reserve))
    except LetsInferError as error:
        record("runtime-memory-reserve", False, str(error))

    try:
        verify_release_sources(
            manifest, pathlib.Path(config["source_root"]).expanduser()
        )
        record("source-identity", True, manifest["release"])
    except LetsInferError as error:
        record("source-identity", False, str(error))

    control_root = pathlib.Path(config["source_root"]).expanduser()
    _records, _core_manifest, core_identity = _core_release(control_root)
    record(
        "immutable-control-bundle",
        control_root.name
        == _control_bundle_identity(core_identity, config["manifest_sha256"]),
        f"core=sha256:{core_identity} root={control_root}",
    )
    unit_root = pathlib.Path.home() / ".config/systemd/user"
    expected_units = {
        ENGINE_SERVICE_NAME: render_engine_service(
            config_path,
            manifest["container"]["startup_timeout_seconds"],
            control_root,
        ),
        GATEWAY_SERVICE_NAME: render_gateway_service(
            config_path, config, control_root
        ),
        SERVICE_NAME: render_user_service(config, manifest),
        RECOVERY_SERVICE_NAME: render_recovery_service(
            config["name"], expanded_path(config["protection_root"]), control_root
        ),
        RECOVERY_TIMER_NAME: render_recovery_timer(),
    }
    for unit_name, expected_contents in expected_units.items():
        unit_path = unit_root / unit_name
        try:
            details = unit_path.stat()
            passed = (
                not unit_path.is_symlink()
                and stat.S_ISREG(details.st_mode)
                and details.st_uid == os.getuid()
                and stat.S_IMODE(details.st_mode) == 0o644
                and unit_path.read_text(encoding="utf-8") == expected_contents
            )
            record(f"unit-{unit_name}", passed, str(unit_path))
        except OSError as error:
            record(f"unit-{unit_name}", False, str(error))

    try:
        actual_image = verify_installed_release(
            manifest,
            model_cache=expanded_path(config["model_cache"]),
            plugin_root=expanded_path(config["plugin_root"]),
        )
        record("installed-identity", True, actual_image)
    except LetsInferError as error:
        record("installed-identity", False, str(error))

    config_mode = stat.S_IMODE(config_path.stat().st_mode)
    record("private-config", config_mode == 0o600, oct(config_mode))
    for label, key in (
        ("engine-api-key", "engine_api_key_file"),
        ("gateway-api-key", "gateway_api_key_file"),
        ("tls-key", "tls_key_file"),
    ):
        path = expanded_path(config[key])
        try:
            if key.endswith("api_key_file"):
                read_api_key(path)
            else:
                _validate_private_file(path, minimum_bytes=256)
            record(label, True, f"{path} mode=0600")
        except LetsInferError as error:
            record(label, False, str(error))
    try:
        validate_tls_material(
            expanded_path(config["tls_cert_file"]), expanded_path(config["tls_key_file"])
        )
        record("tls-certificate", True, config["tls_cert_file"])
    except LetsInferError as error:
        record("tls-certificate", False, str(error))

    try:
        binary, digest = verify_watchdog_runtime(
            expanded_path(config["watchdog_binary_path"]).parent,
            config["watchdog_source_sha256"],
        )
        record(
            "watchdog-runtime-identity",
            binary == expanded_path(config["watchdog_binary_path"])
            and digest == config["watchdog_binary_sha256"],
            f"{binary} sha256={digest}",
        )
    except LetsInferError as error:
        record("watchdog-runtime-identity", False, str(error))
    try:
        validate_watchdog_tls_material(
            *(expanded_path(config[key]) for key in (
                "watchdog_cert_file",
                "watchdog_key_file",
                "watchdog_controller_ca_file",
            ))
        )
        record("watchdog-mtls", True, config["watchdog_cert_file"])
    except LetsInferError as error:
        record("watchdog-mtls", False, str(error))
    controller_keys = (
        "watchdog_controller_ca_key_file",
        "watchdog_local_controller_cert_file",
        "watchdog_local_controller_key_file",
    )
    try:
        _validate_watchdog_controller_material(
            expanded_path(config["watchdog_controller_ca_file"]),
            *(expanded_path(config[key]) for key in controller_keys),
        )
        record(
            "watchdog-local-controller",
            True,
            config["watchdog_local_controller_cert_file"],
        )
    except LetsInferError as error:
        record("watchdog-local-controller", False, str(error))
    try:
        identity = read_installation_identity()
        installation_id = identity["installation_id"]
        if installation_id != config["installation_id"]:
            raise LetsInferError("installation identity does not match service configuration")
        identity = read_site_identity()
        with SiteStore(identity=identity) as store:
            controller_rows = store.controllers()
            expected_allowlist = (
                "version=1\n"
                f"installation_id={installation_id}\n"
                + "".join(
                    f"controller={row['controller_id']},{row['certificate_sha256']}\n"
                    for row in controller_rows
                )
            )
        actual_allowlist = _validate_private_file(
            expanded_path(config["watchdog_controller_allowlist_file"]),
            minimum_bytes=64,
        ).decode("ascii")
        if actual_allowlist != expected_allowlist.rstrip("\n"):
            raise LetsInferError("controller allowlist does not match coordinator state")
        record(
            "controller-authorization",
            True,
            f"installation={installation_id} controllers={len(controller_rows)}",
        )
    except (LetsInferError, SiteError, UnicodeDecodeError) as error:
        record("controller-authorization", False, str(error))

    for label, key in (
        ("engine-cache-permissions", "store_root"),
        ("runtime-cache-permissions", "runtime_cache_root"),
        ("watchdog-data-permissions", "watchdog_data_root"),
    ):
        path = expanded_path(config[key])
        try:
            details = path.stat()
            mode = stat.S_IMODE(details.st_mode)
            passed = (
                not path.is_symlink()
                and stat.S_ISDIR(details.st_mode)
                and details.st_uid == os.getuid()
                and mode == 0o700
            )
            record(label, passed, f"{path} mode={oct(mode)}")
        except OSError as error:
            record(label, False, str(error))

    enabled, active, memory_bytes = _service_state()
    record("service-enabled", enabled == "enabled", enabled)
    record("service-active", active == "active", active)
    record(
        "control-memory",
        memory_bytes is not None and memory_bytes < CONTROL_PLANE_MEMORY_LIMIT_BYTES,
        f"current={memory_bytes} limit<{CONTROL_PLANE_MEMORY_LIMIT_BYTES}",
    )
    engine_enabled, engine_active = _unit_enabled_active(ENGINE_SERVICE_NAME)
    record("engine-service-loaded", engine_enabled in {"static", "disabled"}, engine_enabled)
    record("engine-service-active", engine_active == "active", engine_active)
    site_enabled, site_active, site_memory_bytes = _service_state(SITE_SERVICE_NAME)
    record("site-service-enabled", site_enabled == "enabled", site_enabled)
    record("site-service-active", site_active == "active", site_active)
    record(
        "site-service-memory",
        site_memory_bytes is not None and site_memory_bytes < SITE_AGENT_MEMORY_LIMIT_BYTES,
        f"current={site_memory_bytes} limit<{SITE_AGENT_MEMORY_LIMIT_BYTES}",
    )
    gateway_enabled, gateway_active, gateway_memory_bytes = _service_state(
        GATEWAY_SERVICE_NAME
    )
    record("gateway-enabled", gateway_enabled == "enabled", gateway_enabled)
    record("gateway-active", gateway_active == "active", gateway_active)
    record(
        "gateway-memory",
        gateway_memory_bytes is not None,
        f"current={gateway_memory_bytes}",
    )
    recovery_enabled, recovery_active = _unit_enabled_active(RECOVERY_TIMER_NAME)
    record("recovery-enabled", recovery_enabled == "enabled", recovery_enabled)
    record("recovery-active", recovery_active == "active", recovery_active)
    lingering = user_lingering_enabled()
    record("user-lingering", lingering, "yes" if lingering else "no")

    inspection = container_inspect(config["name"])
    if inspection is None:
        record("managed-container", False, "absent")
    else:
        try:
            require_matching_container(
                inspection,
                manifest,
                config["engine_port"],
                manifest_sha256=config["manifest_sha256"],
                runtime_digest=config.get("runtime_digest"),
            )
            record("managed-container", True, config["name"])
        except LetsInferError as error:
            record("managed-container", False, str(error))
        state = inspection.get("State", {})
        health = (state.get("Health") or {}).get("Status", "none")
        host = inspection.get("HostConfig", {})
        record("container-running", state.get("Running") is True, state.get("Status", "unknown"))
        record("docker-health", health == "healthy", health)
        restart_policy = (host.get("RestartPolicy") or {}).get("Name")
        record("restart-policy", restart_policy == "no", str(restart_policy))
        record("read-only-root", host.get("ReadonlyRootfs") is True, str(host.get("ReadonlyRootfs")))
        cap_drop = host.get("CapDrop") or []
        record("capabilities-dropped", "ALL" in cap_drop, compact_json(cap_drop))
        security_options = host.get("SecurityOpt") or []
        no_new = any(value.startswith("no-new-privileges") for value in security_options)
        record("no-new-privileges", no_new, compact_json(security_options))
        model_destination = "/root/.cache/huggingface/hub"
        model_mount = next(
            (mount for mount in inspection.get("Mounts", []) if mount.get("Destination") == model_destination),
            None,
        )
        record(
            "read-only-model",
            model_mount is not None and model_mount.get("RW") is False,
            compact_json(model_mount or {}),
        )

    protection = protection_status(config, inspection)
    record(
        "watchdog-protection-armed",
        protection["armed"],
        f"phase={protection['phase']} container_id={protection.get('container_id')}",
    )
    record(
        "watchdog-protection-trip-clear",
        not protection["trip_latched"],
        str(protection["trip_path"]),
    )

    key_path = expanded_path(config["gateway_api_key_file"])
    health_status = api_status(config["gateway_port"], "/health", None)
    unauthenticated = api_status(config["gateway_port"], "/v1/models", None)
    authenticated = api_status(
        config["gateway_port"], "/v1/models", None, key_path
    )
    record("lan-http-health-endpoint", health_status == 200, str(health_status))
    record("anonymous-api-denied", unauthenticated == 401, str(unauthenticated))
    record("authenticated-api", authenticated == 200, str(authenticated))
    identity = model_identity_ready(
        manifest, config["gateway_port"], None, key_path
    )
    record("model-identity", identity, manifest["model"]["alias"])

    with _site_store() as store:
        exposure = store.exposure()
    if exposure is None or exposure["state"] == "disabled":
        record("public-exposure", True, "disabled")
    else:
        try:
            live = verify_tailscale(exposure["configuration_sha256"])
            record(
                "public-exposure",
                exposure["state"] == "enabled"
                and live.public_url == exposure["public_url"]
                and live.inference_target == exposure["inference_target"],
                f"provider={exposure['provider']} url={exposure['public_url']}",
            )
        except ExposureError as error:
            record("public-exposure", False, str(error))

    publication_ready = (
        manifest["status"] == "stable"
        and manifest["image"]["distribution"] == "registry-digest"
        and persistent_cache_for(manifest)
        and manifest["serving"]["qualified"]
    )
    record(
        "stable-publication",
        publication_ready,
        f"status={manifest['status']} image={manifest['image']['distribution']}",
        required=arguments.require_stable,
    )
    operational_ready = all(
        item["passed"] for item in checks if item["required"]
    )
    payload = {
        "operational_ready": operational_ready,
        "publication_ready": publication_ready,
        "release": manifest["release"],
        "engine": adapter.name,
        "checks": checks,
    }
    if arguments.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for item in checks:
            state = "PASS" if item["passed"] else ("FAIL" if item["required"] else "INFO")
            print(f"{state:4} {item['name']}: {item['detail']}")
        print(
            f"READY operational={str(operational_ready).lower()} "
            f"publication={str(publication_ready).lower()}"
        )
    return 0 if operational_ready else 1


def uninstall(arguments: argparse.Namespace) -> int:
    config_path = absolute_user_path(
        arguments.config or default_service_config_path()
    )
    config = read_service_config(config_path)
    _remove_all_engine_groups()
    active = run(["systemctl", "--user", "is-active", SERVICE_NAME], check=False)
    if active.returncode == 0:
        run_passthrough(["systemctl", "--user", "stop", SERVICE_NAME])
    else:
        inspection = container_inspect(config["name"])
        if inspection is not None:
            _stop_managed_container(
                config["name"], expanded_path(config["engine_api_key_file"])
            )

    run(
        ["systemctl", "--user", "disable", "--now", RECOVERY_TIMER_NAME],
        check=False,
    )
    run(
        ["systemctl", "--user", "disable", "--now", GATEWAY_SERVICE_NAME],
        check=False,
    )
    run(
        ["systemctl", "--user", "disable", "--now", SITE_SERVICE_NAME],
        check=False,
    )
    run(["systemctl", "--user", "disable", SERVICE_NAME], check=False)
    unit_dir = pathlib.Path.home() / ".config/systemd/user"
    for name in (
        SERVICE_NAME,
        SITE_SERVICE_NAME,
        ENGINE_SERVICE_NAME,
        GATEWAY_SERVICE_NAME,
        RECOVERY_SERVICE_NAME,
        RECOVERY_TIMER_NAME,
    ):
        path = unit_dir / name
        if path.is_symlink():
            raise LetsInferError(f"refusing to remove symlinked unit: {path}")
        if path.is_file():
            path.unlink()
    run(["systemctl", "--user", "daemon-reload"])

    if arguments.purge_runtime_plugins:
        plugin_root = expanded_path(config["plugin_root"])
        _, manifest = configured_release(config)
        if adapter_for(manifest).requires_runtime_plugins:
            verify_artifacts(plugin_root, manifest["runtime_plugins"]["artifacts"])
            shutil.rmtree(plugin_root)
        elif requires_core_cache_plugin(manifest):
            try:
                verify_sglang_plugin(
                    plugin_root,
                    source_root=source_root(),
                    core_version=PRODUCT_VERSION,
                )
            except CachePluginError as error:
                raise LetsInferError(str(error)) from error
            shutil.rmtree(plugin_root)
    if arguments.purge_credentials:
        for key in (
            "engine_api_key_file",
            "gateway_api_key_file",
            "tls_cert_file",
            "tls_key_file",
            "watchdog_cert_file",
            "watchdog_key_file",
            "watchdog_controller_ca_file",
            "watchdog_controller_ca_key_file",
            "watchdog_local_controller_cert_file",
            "watchdog_local_controller_key_file",
            "watchdog_controller_allowlist_file",
        ):
            value = config.get(key)
            if not isinstance(value, str):
                continue
            path = expanded_path(value)
            if path.is_symlink():
                raise LetsInferError(f"refusing to remove symlinked credential: {path}")
            if path.is_file():
                path.unlink()
        installation_identity = default_installation_identity_path()
        if installation_identity.is_symlink():
            raise LetsInferError(
                f"refusing to remove symlinked installation identity: "
                f"{installation_identity}"
            )
        if installation_identity.is_file():
            installation_identity.unlink()
    if arguments.purge_control_bundle:
        purge_control_bundle(config)
    if arguments.purge_watchdog_runtime:
        purge_watchdog_runtime(config)
    config_path.unlink()
    print(
        "UNINSTALLED service; model data, prefix cache, runtime cache, and evidence preserved"
    )
    return 0


def pack_runtime(arguments: argparse.Namespace) -> int:
    try:
        pack = build_archive(
            pathlib.Path(arguments.source),
            pathlib.Path(arguments.output),
        )
    except RuntimePackError as error:
        raise LetsInferError(str(error)) from error
    print(
        f"PACKED {pack.descriptor['name']} version={pack.descriptor['version']} "
        f"digest=sha256:{pack.digest} artifact={pathlib.Path(arguments.output).resolve()}"
    )
    return 0


def list_runtimes(_: argparse.Namespace) -> int:
    try:
        receipts = selections()
    except RuntimePackError as error:
        raise LetsInferError(str(error)) from error
    for receipt in sorted(receipts, key=lambda item: (item["model"], item["engine"])):
        print(
            f"{receipt['model']}\tengine={receipt['engine']}\ttarget={receipt['target']}\t"
            f"version={receipt['version']}\tdigest=sha256:{receipt['digest']}\t"
            f"policy={receipt['policy']}"
        )
    return 0


def hardware(arguments: argparse.Namespace) -> int:
    fingerprint = host_device_fingerprint()
    location = resolved_catalog_location(getattr(arguments, "catalog", None))
    matches: list[str] = []
    if location is not None:
        try:
            matches = compatible_catalog_targets(load_catalog(location), fingerprint)
        except RuntimePackError as error:
            raise LetsInferError(str(error)) from error
    selected_target = matches[0] if len(matches) == 1 else None
    payload = {
        "detected": fingerprint,
        "compatible_targets": matches,
        "selected_target": selected_target,
    }
    if arguments.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        accelerator = fingerprint["accelerator"]
        memory = fingerprint["memory"]
        target_text = selected_target or ("ambiguous" if matches else "unmatched")
        print(
            f"{fingerprint['platform']}\t{accelerator['vendor']}/"
            f"{accelerator['architecture']}\tdevices={accelerator['count']}\t"
            f"partitioning={accelerator['partitioning']}\t"
            f"memory={memory['topology']}/{memory['total_gib']}GiB\t"
            f"target={target_text}"
        )
    return 0


def derive_runtime(arguments: argparse.Namespace) -> int:
    manifest_path, parent = resolve_model(
        arguments.runtime, arguments.engine, target=getattr(arguments, "target", None)
    )
    root = manifest_source_root(manifest_path)
    verify_release_sources(parent, root)
    name = arguments.name
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name):
        raise LetsInferError("derived runtime name contains unsupported characters")
    supplied_tokens = list(arguments.engine_arguments)
    if supplied_tokens and supplied_tokens[0] == "--":
        supplied_tokens.pop(0)
    if not supplied_tokens and not arguments.without:
        raise LetsInferError("derive requires --without or native engine arguments after --")
    try:
        supplied = overlay_clauses(supplied_tokens) if supplied_tokens else []
        base_launch = launch_for(parent, parent["serving"], arguments.port)
        requested_keys = {
            *(clause_key(clause) for clause in supplied),
            *arguments.without,
        }
        protected = requested_keys.intersection(base_launch.protected_arguments)
        if protected:
            raise LetsInferError(
                "Let's Infer owns model identity, listener, authentication/TLS, "
                "safety, and cache-integration arguments; "
                f"cannot change: {', '.join(sorted(protected))}"
            )
        parent_clauses = overlay_clauses(
            base_launch.command[base_launch.engine_argument_offset :]
        )
        resolved, difference = apply_overlay(
            parent_clauses,
            supplied,
            arguments.without,
        )
    except (RuntimePackError, EngineManifestError) as error:
        raise LetsInferError(str(error)) from error
    # A derivation receives a new public alias. Engines whose core-owned
    # served identity is that alias must carry the new value in the sealed
    # resolved command; this is not a user override of a protected option.
    if adapter_for(parent).name in {"vllm", "sglang"}:
        resolved = [
            ["--served-model-name", name]
            if clause_key(clause) == "--served-model-name"
            else clause
            for clause in resolved
        ]
    resolved_arguments = flatten_clauses(resolved)
    resolved_digest = hashlib.sha256(
        json.dumps(
            list(resolved_arguments),
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()
    manifest = json.loads(json.dumps(parent))
    manifest["release"] = f"{name}-local-{resolved_digest[:12]}"
    manifest["status"] = "candidate"
    manifest["model"]["alias"] = name
    manifest["serving"]["qualified"] = False
    manifest["serving"]["blocked_by"] = "derived-runtime-qualification"
    manifest["serving"]["gate"] = {
        "measured_commit": "pending",
        "bench_block": "derived-runtime-qualification-v1",
        "evidence_directory": "pending",
        "results_sha256": "0" * 64,
    }
    manifest["derivation"] = {
        "name": name,
        "parent_release": parent["release"],
        "parent_manifest_sha256": sha256_file(manifest_path),
        "without": list(dict.fromkeys(arguments.without)),
        "supplied_engine_arguments": supplied,
        "resolved_engine_arguments": resolved,
        "resolved_arguments_sha256": resolved_digest,
        "diff": difference,
    }
    validate_manifest(manifest)
    engine = adapter_for(parent).name
    target_id = target_contract(parent)["id"]
    with tempfile.TemporaryDirectory(prefix="letsinfer-derived-runtime-") as temporary:
        source = pathlib.Path(temporary)
        runtime_config = {
            "schema_version": RUNTIME_SCHEMA_VERSION,
            "name": f"{name}/{engine}/{target_id}",
            "version": f"0.0.0+derived.{resolved_digest[:12]}",
            "model": name,
            "engine": engine,
            "target": target_id,
            "status": "candidate",
            "release_manifest": "release.json",
            "core_compatibility": {"api": 2},
            "parent": {
                "release": parent["release"],
                "manifest_sha256": sha256_file(manifest_path),
            },
        }
        (source / RUNTIME_CONFIG).write_bytes(canonical_bytes(runtime_config))
        (source / "release.json").write_bytes(canonical_bytes(manifest))
        installed_path, installed, control_root, receipt = prepare_runtime_install(
            str(source),
            policy="derived",
            requested_engine=engine,
            requested_target=target_id,
            artifact_roots=(root,),
        )
    try:
        receipt_path = write_selection(receipt)
    except RuntimePackError as error:
        raise LetsInferError(str(error)) from error
    launch = launch_for(installed, installed["serving"], arguments.port)
    print(
        f"DERIVED {receipt['name']} parent={parent['release']} "
        f"digest=sha256:{receipt['digest']} receipt={receipt_path}"
    )
    print(f"  command: {shell_command(launch)}")
    return 0


def inspect_runtime(arguments: argparse.Namespace) -> int:
    manifest_path, manifest = resolve_model(
        arguments.runtime, arguments.engine, target=getattr(arguments, "target", None)
    )
    receipt = runtime_receipt_for_manifest(manifest_path)
    launch = launch_for(manifest, manifest["serving"], arguments.port)
    derivation = manifest.get("derivation")
    if arguments.json:
        print(
            json.dumps(
                {
                    "runtime": receipt,
                    "release": manifest["release"],
                    "model": manifest["model"],
                    "engine": adapter_for(manifest).name,
                    "target": target_contract(manifest),
                    "status": manifest["status"],
                    "serving": manifest["serving"],
                    "derivation": derivation,
                    "command": list(launch.command),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if arguments.command:
        print(shell_command(launch))
    if arguments.diff:
        if derivation is None:
            print("No argument derivation; this runtime uses its packaged command.")
        else:
            print(json.dumps(derivation["diff"], indent=2, sort_keys=True))
    if not arguments.command and not arguments.diff:
        runtime_name = receipt["name"] if receipt else manifest["model"]["alias"]
        digest = f"sha256:{receipt['digest']}" if receipt else "unpacked-source"
        print(
            f"{runtime_name}\tengine={adapter_for(manifest).name}\t"
            f"release={manifest['release']}\tstatus={manifest['status']}\tdigest={digest}"
        )
    return 0


def _matching_runtime_receipt(
    name: str, engine: str | None, target: str | None = None
) -> dict[str, Any]:
    try:
        available = selections()
    except RuntimePackError as error:
        raise LetsInferError(str(error)) from error
    active_path = default_service_config_path()
    if active_path.is_file():
        try:
            active = read_service_config(active_path)
        except LetsInferError:
            active = {}
        active_digest = active.get("runtime_digest")
        for receipt in available:
            if (
                receipt["digest"] == active_digest
                and name in {receipt["name"], receipt["model"], active.get("model")}
                and (engine is None or receipt["engine"] == engine)
                and (target is None or receipt["target"] == target)
            ):
                return receipt
    matches = [
        receipt
        for receipt in available
        if name in {receipt["name"], receipt["model"]}
        and (engine is None or receipt["engine"] == engine)
        and (target is None or receipt["target"] == target)
    ]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        choices = ", ".join(
            sorted(f"{receipt['engine']}/{receipt['target']}" for receipt in matches)
        )
        raise LetsInferError(
            f"runtime is ambiguous across variants ({choices}); specify --engine and/or --target"
        )
    raise LetsInferError(f"runtime is not installed: {name}")


def _upgrade_install_arguments(
    source: str,
    policy: str,
    target_contract_sha256_value: str | None = None,
) -> argparse.Namespace:
    config_path = default_service_config_path()
    config = read_service_config(config_path) if config_path.is_file() else None
    return argparse.Namespace(
        model=source,
        engine=None,
        target=None,
        catalog=None,
        runtime_policy=policy,
        expected_target_contract_sha256=target_contract_sha256_value,
        port=config["gateway_port"] if config else 8000,
        engine_port=config["engine_port"] if config else 18000,
        gateway_listen=config["gateway_listen"] if config else "0.0.0.0",
        gateway_max_connections=(config["gateway_max_connections"] if config else 128),
        gateway_queue_timeout=(config["gateway_queue_timeout_seconds"] if config else 300),
        name=config["name"] if config else None,
        model_cache=config["model_cache"] if config else None,
        plugin_root=None,
        store_root=None,
        runtime_cache_root=None,
        api_key_file=config["gateway_api_key_file"] if config else None,
        tls_cert_file=config["tls_cert_file"] if config else None,
        tls_key_file=config["tls_key_file"] if config else None,
        watchdog_data_root=config.get("watchdog_data_root") if config else None,
        watchdog_listen=config.get("watchdog_listen") if config else None,
        watchdog_port=config.get("watchdog_port") if config else None,
        watchdog_cert_file=config.get("watchdog_cert_file") if config else None,
        watchdog_key_file=config.get("watchdog_key_file") if config else None,
        watchdog_controller_ca_file=(
            config.get("watchdog_controller_ca_file") if config else None
        ),
        watchdog_controller_ca_key_file=(
            config.get("watchdog_controller_ca_key_file") if config else None
        ),
        watchdog_local_controller_cert_file=(
            config.get("watchdog_local_controller_cert_file") if config else None
        ),
        watchdog_local_controller_key_file=(
            config.get("watchdog_local_controller_key_file") if config else None
        ),
        wheel=None,
        config=str(config_path),
        download=False,
        no_build_image=False,
        no_service=False,
        no_start=False,
    )


def _receipt_snapshot(receipt: dict[str, Any]) -> dict[str, Any]:
    return {
        key: receipt[key]
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
            "policy",
            "source",
        )
    }


def _retain_runtime_history(active_digest: str, previous: dict[str, Any]) -> None:
    try:
        updated = next(item for item in selections() if item["digest"] == active_digest)
        if not any(
            item.get("digest") == previous["digest"] for item in updated["history"]
        ):
            updated["history"] = [
                *updated["history"],
                _receipt_snapshot(previous),
            ][-20:]
            write_selection(updated)
    except (RuntimePackError, StopIteration) as error:
        raise LetsInferError(
            f"runtime changed but rollback history could not be retained: {error}"
        ) from error


def upgrade_runtime(arguments: argparse.Namespace) -> int:
    receipt = _matching_runtime_receipt(
        arguments.runtime, arguments.engine, getattr(arguments, "target", None)
    )
    expected_version: str | None = None
    expected_target_sha256: str | None = None
    if arguments.to:
        source = arguments.to
        policy = "pinned" if REGISTRY_DIGEST_RE.fullmatch(source) else "local"
    else:
        policy = receipt["policy"]
        if policy not in {"recommended", f"engine:{receipt['engine']}"}:
            raise LetsInferError(
                f"runtime policy {policy!r} is pinned; use --to with an explicit runtime source"
            )
        location = resolved_catalog_location(arguments.catalog)
        if location is None:
            raise LetsInferError("runtime upgrade requires --catalog or LETSINFER_CATALOG")
        try:
            catalog = load_catalog(location)
            selected_engine = None if policy == "recommended" else receipt["engine"]
            (
                _,
                expected_target_sha256,
                _,
                expected_version,
                source,
            ) = catalog_release(
                catalog,
                receipt["model"],
                selected_engine,
                receipt["target"],
            )
            if expected_target_sha256 != receipt["target_contract_sha256"]:
                raise LetsInferError(
                    "catalog changed an existing target contract; publish a new target ID"
                )
        except RuntimePackError as error:
            raise LetsInferError(str(error)) from error
    try:
        with materialize(source) as candidate:
            candidate_digest = candidate.digest
            candidate_name = candidate.descriptor["name"]
            candidate_version = candidate.descriptor["version"]
            candidate_model = candidate.descriptor["model"]
            candidate_engine = candidate.descriptor["engine"]
            candidate_target = candidate.descriptor["target"]
    except RuntimePackError as error:
        raise LetsInferError(str(error)) from error
    if expected_version is not None and candidate_version != expected_version:
        raise LetsInferError(
            "runtime catalog version does not match the immutable artifact "
            f"({expected_version!r} != {candidate_version!r})"
        )
    if candidate_model != receipt["model"]:
        raise LetsInferError(
            f"upgrade runtime model changed ({receipt['model']!r} -> {candidate_model!r})"
        )
    if candidate_target != receipt["target"]:
        raise LetsInferError(
            f"upgrade runtime target changed ({receipt['target']!r} -> {candidate_target!r})"
        )
    if policy.startswith("engine:") and candidate_engine != policy.split(":", 1)[1]:
        raise LetsInferError(
            f"engine-pinned runtime cannot upgrade to {candidate_engine!r}"
        )
    print(
        f"UPGRADE {receipt['name']} {receipt['version']}@sha256:{receipt['digest']} "
        f"-> {candidate_name} {candidate_version}@sha256:{candidate_digest}"
    )
    if candidate_digest == receipt["digest"]:
        print("CURRENT already-installed=true")
        return 0
    if arguments.dry_run:
        return 0
    install(_upgrade_install_arguments(source, policy, expected_target_sha256))
    _retain_runtime_history(candidate_digest, receipt)
    return 0


def rollback_runtime(arguments: argparse.Namespace) -> int:
    receipt = _matching_runtime_receipt(
        arguments.runtime, arguments.engine, getattr(arguments, "target", None)
    )
    history = receipt.get("history")
    if not isinstance(history, list) or not history:
        raise LetsInferError(f"runtime has no retained rollback receipt: {receipt['name']}")
    target = history[-1]
    object_root = pathlib.Path(target["object_root"]).expanduser()
    try:
        pack = verify_descriptor(object_root)
    except RuntimePackError as error:
        raise LetsInferError(str(error)) from error
    if pack.digest != target["digest"]:
        raise LetsInferError("rollback runtime object does not match its retained receipt")
    print(
        f"ROLLBACK {receipt['name']} {receipt['version']}@sha256:{receipt['digest']} "
        f"-> {target['name']} {target['version']}@sha256:{target['digest']}"
    )
    if arguments.dry_run:
        return 0
    install(
        _upgrade_install_arguments(
            str(object_root),
            target["policy"],
            target["target_contract_sha256"],
        )
    )
    _retain_runtime_history(target["digest"], receipt)
    return 0


def verify(arguments: argparse.Namespace) -> int:
    manifest_path, manifest = resolve_model(
        arguments.model, arguments.engine, target=getattr(arguments, "target", None)
    )
    verify_release_sources(manifest, manifest_source_root(manifest_path))
    if not arguments.source_only:
        model_cache = expanded_path(arguments.model_cache or manifest["container"]["model_cache"])
        plugin_root = (
            expanded_path(arguments.plugin_root)
            if arguments.plugin_root
            else default_plugin_root(manifest, sha256_file(manifest_path))
        )
        verify_installed_release(manifest, model_cache=model_cache, plugin_root=plugin_root)
    adapter = adapter_for(manifest)
    print(
        f"VERIFIED {manifest['release']} ({manifest['status']}) "
        f"engine={adapter.name} format={adapter.model_format}"
    )
    serving = manifest["serving"]
    state = "qualified" if serving["qualified"] else "blocked"
    detail = f", MTP K={serving['mtp_tokens']}" if adapter.name == "vllm" else ""
    print(
        f"  serving: {state}, connections<={serving['max_connections']}, "
        f"active<={serving['max_active_requests']}, "
        f"context<={serving['max_context_tokens']}{detail}"
    )
    return 0


def acquire(arguments: argparse.Namespace) -> int:
    manifest_path, manifest = resolve_model(
        arguments.model, arguments.engine, target=getattr(arguments, "target", None)
    )
    verify_release_sources(manifest, manifest_source_root(manifest_path))
    model_cache = expanded_path(
        arguments.model_cache or manifest["container"]["model_cache"]
    )
    try:
        snapshot = verify_model_snapshot(manifest, model_cache)
        existing = True
    except LetsInferError:
        snapshot = acquire_model_snapshot(manifest, model_cache)
        existing = False
    print(
        f"ACQUIRED {manifest['release']} engine={adapter_for(manifest).name} "
        f"existing={str(existing).lower()} snapshot={snapshot} "
        f"manifest_sha256={sha256_file(manifest_path)}"
    )
    return 0


class _BenchmarkCancelled(Exception):
    """An explicit benchmark stop requested graceful worker cleanup."""


def _duration(seconds: float) -> str:
    value = max(0, int(seconds))
    hours, remainder = divmod(value, 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes:02d}m {seconds:02d}s"
    if minutes:
        return f"{minutes}m {seconds:02d}s"
    return f"{seconds}s"


def _benchmark_dashboard(
    state: dict[str, Any],
    progress: dict[str, Any] | None,
    elapsed: float,
    terminal: ui.Terminal,
    frame: str,
) -> str:
    """Render one bounded live benchmark frame."""
    progress = progress if isinstance(progress, dict) else {}
    status = str(state.get("state") or "unknown").upper()
    active = state.get("state") in benchmark_jobs.ACTIVE_STATES
    color = ui.CYAN if active else (ui.GREEN if status == "COMPLETED" else ui.RED)
    mark = "●" if terminal.unicode else "*"
    brand = terminal.paint("LET'S INFER", ui.BOLD)
    lines = [
        f"{terminal.paint(terminal.mark, ui.BOLD, ui.YELLOW)}  "
        f"{brand}  /  BENCHMARK",
        "",
        f"{terminal.paint(mark, ui.BOLD, color)} "
        f"{terminal.paint(status, ui.BOLD, color)}  "
        f"{terminal.paint(str(state.get('runtime') or 'unknown runtime'), ui.BOLD)}",
    ]
    message = progress.get("message")
    if not isinstance(message, str) or not message:
        message = "Waiting for benchmark worker"
    phase = progress.get("phase")
    if not isinstance(phase, str) or not phase:
        phase = "starting"
    lines.extend(
        [
            f"  {terminal.paint(frame, ui.CYAN)} "
            f"{terminal.paint(terminal.clip(message, terminal.width - 5), ui.BOLD)}",
            f"  {terminal.paint(f'phase {phase}', ui.DIM)}",
        ]
    )

    selected = progress.get("selected_cells")
    completed = progress.get("completed_cells")
    current = progress.get("current_cell")
    selected = (
        [value for value in selected if isinstance(value, str) and value]
        if isinstance(selected, list)
        else []
    )
    completed_set = (
        {value for value in completed if isinstance(value, str)}
        if isinstance(completed, list)
        else set()
    )
    current = current if isinstance(current, str) else None
    if selected:
        done = len([cell for cell in selected if cell in completed_set])
        width = min(24, max(10, terminal.width - 28))
        filled = int(width * done / len(selected))
        bar = "█" * filled + "░" * (width - filled) if terminal.unicode else "=" * filled + "-" * (width - filled)
        lines.extend(
            [
                "",
                f"  WORKLOADS  [{bar}] {done}/{len(selected)}",
            ]
        )
        for cell in selected:
            if cell in completed_set:
                cell_mark, cell_color, detail = (
                    ("✓" if terminal.unicode else "+"),
                    ui.GREEN,
                    "complete",
                )
            elif cell == current:
                cell_mark, cell_color, detail = frame, ui.CYAN, "running"
            else:
                cell_mark, cell_color, detail = (
                    ("○" if terminal.unicode else "-"),
                    ui.DIM,
                    "waiting",
                )
            lines.append(
                f"  {terminal.paint(cell_mark, cell_color)} "
                f"{terminal.paint(cell.ljust(10), ui.BOLD if cell == current else ui.DIM)} "
                f"{terminal.paint(detail, cell_color)}"
            )

    lines.extend(["", f"  ELAPSED   {_duration(elapsed)}"])
    expected = progress.get("expected_minutes")
    if (
        isinstance(expected, list)
        and len(expected) == 2
        and all(isinstance(value, int) and not isinstance(value, bool) for value in expected)
    ):
        lines.append(f"  EXPECTED  {expected[0]}–{expected[1]} min")
    lines.extend(
        [
            f"  EVIDENCE  {terminal.clip(str(state.get('output_directory') or 'pending'), terminal.width - 12)}",
            "",
            "  Ctrl-C detaches; `letsinfer benchmark stop` cancels.",
        ]
    )
    return "\n".join(lines) + "\n"


def _benchmark_job_snapshot(*, machine: bool = False) -> int:
    try:
        state = benchmark_jobs.read_state()
        progress = benchmark_jobs.read_progress()
    except benchmark_jobs.BenchmarkJobError as error:
        raise LetsInferError(str(error)) from error
    if state is None:
        if machine:
            print(compact_json({"active": False, "state": "none"}))
        else:
            ui.Terminal(sys.stdout).status("No benchmark has been started")
        return 0
    active = state.get("state") in benchmark_jobs.ACTIVE_STATES and benchmark_jobs.is_alive(
        state
    )
    if state.get("state") in benchmark_jobs.ACTIVE_STATES and not active:
        try:
            state = benchmark_jobs.mark(
                state["job_id"],
                "failed",
                error="benchmark worker exited without recording a terminal state",
            )
        except benchmark_jobs.BenchmarkJobError as error:
            raise LetsInferError(str(error)) from error
    elapsed = (
        time.time_ns() - state.get("started_unix_ns", time.time_ns())
    ) / 1_000_000_000
    payload = {
        "active": active,
        "job": state,
        "progress": progress,
        "elapsed_seconds": elapsed,
    }
    if machine:
        print(compact_json(payload))
        return 0

    terminal = ui.Terminal(sys.stdout)
    status = str(state.get("state") or "unknown").upper()
    color = ui.CYAN if active else (ui.GREEN if status == "COMPLETED" else ui.RED)
    mark = "●" if terminal.unicode else "*"
    brand = terminal.paint("LET'S INFER", ui.BOLD)
    terminal.stream.write(
        f"{terminal.paint(terminal.mark, ui.BOLD, ui.YELLOW)}  "
        f"{brand}  /  BENCHMARK\n\n"
        f"{terminal.paint(mark, ui.BOLD, color)} "
        f"{terminal.paint(status, ui.BOLD, color)}  "
        f"{terminal.paint(str(state.get('runtime') or 'unknown runtime'), ui.BOLD)}\n"
    )
    message = (
        progress.get("message")
        if isinstance(progress, dict) and isinstance(progress.get("message"), str)
        else "Waiting for benchmark worker"
    )
    phase = (
        progress.get("phase")
        if isinstance(progress, dict) and isinstance(progress.get("phase"), str)
        else "starting"
    )
    terminal.stream.write(f"  {terminal.paint(message, ui.BOLD)}\n")
    terminal.stream.write(f"  {terminal.paint(f'phase {phase}', ui.DIM)}\n\n")
    terminal.stream.write(f"  ELAPSED   {_duration(elapsed)}\n")
    expected = progress.get("expected_minutes") if isinstance(progress, dict) else None
    if (
        isinstance(expected, list)
        and len(expected) == 2
        and all(isinstance(value, int) and not isinstance(value, bool) for value in expected)
    ):
        terminal.stream.write(f"  EXPECTED  {expected[0]}–{expected[1]} min\n")
    terminal.stream.write(
        f"  EVIDENCE  {state.get('output_directory') or 'pending'}\n"
    )
    if active:
        terminal.stream.write("\n  Ctrl-C detaches; `letsinfer benchmark stop` cancels.\n")
    elif state.get("error"):
        terminal.stream.write(
            f"\n  {terminal.paint(str(state['error']), ui.RED)}\n"
        )
    terminal.stream.flush()
    return 0


def _follow_benchmark_job(job_id: str) -> None:
    terminal = ui.Terminal(sys.stderr)
    if not terminal.interactive:
        _benchmark_job_snapshot()
        return
    frames = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")
    frame_index = 0
    detached = False
    terminal_state = False
    terminal.stream.write("\033[?1049h\033[?25l")
    terminal.stream.flush()
    try:
        while True:
            state = benchmark_jobs.read_state()
            progress = benchmark_jobs.read_progress()
            if state is None or state.get("job_id") != job_id:
                raise LetsInferError("benchmark job identity changed while attached")
            if state.get("state") in benchmark_jobs.TERMINAL_STATES:
                terminal_state = True
                break
            elapsed = (
                time.time_ns() - state.get("started_unix_ns", time.time_ns())
            ) / 1_000_000_000
            frame = frames[frame_index % len(frames)] if terminal.unicode else "*"
            terminal.stream.write(
                "\033[H\033[2J"
                + _benchmark_dashboard(state, progress, elapsed, terminal, frame)
            )
            terminal.stream.flush()
            frame_index += 1
            time.sleep(0.5)
    except KeyboardInterrupt:
        detached = True
    finally:
        terminal.stream.write("\033[?25h\033[?1049l")
        terminal.stream.flush()
    if detached:
        terminal.warning(
            "Detached; benchmark continues. Run `letsinfer benchmark` to check it."
        )
    elif terminal_state:
        _benchmark_job_snapshot()


def _benchmark_stop() -> int:
    try:
        state = benchmark_jobs.request_stop()
    except benchmark_jobs.BenchmarkJobError as error:
        raise LetsInferError(str(error)) from error
    terminal = ui.Terminal(sys.stderr)
    with ui.progress("Stopping the benchmark", stream=sys.stderr):
        stopped = benchmark_jobs.wait_for_exit(state["pid"], timeout_seconds=30)
    if not stopped:
        raise LetsInferError(
            "benchmark did not stop within 30 seconds; its worker remains isolated"
        )
    terminal.success("Benchmark stopped")
    return 0


def _benchmark_self_command(
    arguments: argparse.Namespace,
    executable: pathlib.Path,
    output: pathlib.Path,
) -> list[str]:
    command = [str(executable), "benchmark", arguments.runtime]
    values = (
        ("--base-url", arguments.base_url),
        ("--output-directory", output),
        ("--api-key-file", arguments.api_key_file),
        ("--ca-cert-file", arguments.ca_cert_file),
        ("--container", arguments.container),
        ("--store-root", arguments.store_root),
        ("--launch-directory", arguments.launch_directory),
        ("--measured-commit", arguments.measured_commit),
        ("--source-attestation", arguments.source_attestation),
        ("--watchdog-trip-file", arguments.watchdog_trip_file),
        ("--timeout", arguments.timeout),
    )
    for flag, value in values:
        if value is not None:
            command.extend([flag, str(value)])
    for selector in ("c1", "c2", "c4", "c8", "c16"):
        if getattr(arguments, selector):
            command.append(f"--{selector}")
    for context in ("32k", "64k", "128k", "256k"):
        if getattr(arguments, f"context_{context}"):
            command.append(f"--{context}")
    return command


def _mark_benchmark_job(
    job_id: str, state_name: str, *, error: str | None = None
) -> dict[str, Any]:
    try:
        return benchmark_jobs.mark(job_id, state_name, error=error)
    except benchmark_jobs.BenchmarkJobError as failure:
        raise LetsInferError(str(failure)) from failure


def benchmark_runtime(arguments: argparse.Namespace) -> int:
    """Run the generic sealed matrix for one installed runtime."""
    selectors = any(
        getattr(arguments, name)
        for name in ("c1", "c2", "c4", "c8", "c16")
    ) or any(
        getattr(arguments, f"context_{context}")
        for context in ("32k", "64k", "128k", "256k")
    )
    if arguments.runtime is None:
        if selectors or arguments.list or arguments.detach or arguments.job_worker:
            raise LetsInferError(
                "benchmark workload options require a runtime name"
            )
        if arguments.json:
            return _benchmark_job_snapshot(machine=True)
        try:
            active = benchmark_jobs.active_state()
        except benchmark_jobs.BenchmarkJobError as error:
            raise LetsInferError(str(error)) from error
        if active is not None:
            _follow_benchmark_job(active["job_id"])
            return 0
        return _benchmark_job_snapshot()
    if arguments.runtime == "stop":
        if selectors or arguments.list or arguments.detach or arguments.json:
            raise LetsInferError("benchmark stop does not accept workload options")
        return _benchmark_stop()
    if arguments.json:
        raise LetsInferError("--json is available only for benchmark status")
    if arguments.list and arguments.detach:
        raise LetsInferError("--detach cannot be combined with --list")
    manifest_path, manifest = resolve_model(arguments.runtime, None)
    root = manifest_source_root(manifest_path)
    verify_release_sources(manifest, root)
    receipt = runtime_receipt_for_manifest(manifest_path)
    if receipt is None:
        raise LetsInferError(
            "benchmark requires an installed immutable runtime pack"
        )
    runtime_config = _contained_regular_file(
        pathlib.Path(receipt["object_root"]).expanduser(), "runtime.json"
    )
    try:
        runtime_descriptor = verify_descriptor(
            pathlib.Path(receipt["object_root"]).expanduser()
        )
    except RuntimePackError as error:
        raise LetsInferError(str(error)) from error
    if runtime_descriptor.digest != receipt["digest"]:
        raise LetsInferError("installed runtime descriptor identity mismatch")
    if "benchmark" not in runtime_descriptor.descriptor:
        raise LetsInferError("installed runtime has no benchmark contract")
    runtime_config_value = read_json(runtime_config)
    if runtime_config_value.get("benchmark") != runtime_descriptor.descriptor["benchmark"]:
        raise LetsInferError(
            "installed runtime benchmark contract does not match its descriptor"
        )
    benchmark_contract_sha = hashlib.sha256(
        canonical_bytes(runtime_descriptor.descriptor["benchmark"])
    ).hexdigest()
    adapter = adapter_for(manifest)
    count_path = adapter.token_count_path
    if count_path is None and not arguments.list:
        raise LetsInferError(
            f"{adapter_for(manifest).name} does not expose exact token counting"
        )
    runner = _contained_regular_file(root, "benchmarks/runtime_matrix.py")
    letsinfer_bin = _contained_regular_file(root, "bin/letsinfer")
    command = [
        sys.executable,
        str(runner),
        "--runtime",
        arguments.runtime,
        "--letsinfer-bin",
        str(letsinfer_bin),
        "--runtime-config",
        str(runtime_config),
    ]
    if count_path is not None:
        command.extend(["--token-count-path", count_path])
        if adapter.token_count_protocol is None:
            raise LetsInferError(
                f"{adapter.name} token-count adapter has no wire protocol"
            )
        command.extend(["--token-count-protocol", adapter.token_count_protocol])

    values = (
        ("--base-url", arguments.base_url),
        ("--output-directory", arguments.output_directory),
        ("--api-key-file", arguments.api_key_file),
        ("--ca-cert-file", arguments.ca_cert_file),
        ("--container", arguments.container),
        ("--store-root", arguments.store_root),
        ("--launch-directory", arguments.launch_directory),
        ("--measured-commit", arguments.measured_commit),
        ("--source-attestation", arguments.source_attestation),
        ("--watchdog-trip-file", arguments.watchdog_trip_file),
        ("--timeout", arguments.timeout),
    )
    for flag, value in values:
        if value is not None:
            command.extend([flag, str(value)])
    for selector in ("c1", "c2", "c4", "c8", "c16"):
        if getattr(arguments, selector):
            command.append(f"--{selector}")
    for context in ("32k", "64k", "128k", "256k"):
        if getattr(arguments, f"context_{context}"):
            command.append(f"--{context}")
    if arguments.list:
        command.append("--list")
    else:
        config_path = default_service_config_path()
        if not config_path.is_file():
            raise LetsInferError(
                "benchmark requires an installed Let's Infer service for Watchdog telemetry"
            )
        config = read_service_config(config_path)
        _, watchdog_state = _unit_enabled_active(SERVICE_NAME)
        if watchdog_state != "active":
            raise LetsInferError(
                f"benchmark requires active {SERVICE_NAME} Watchdog telemetry"
            )
        installation_id = receipt.get("installation_id")
        if not isinstance(installation_id, str) or not SHA256_RE.fullmatch(
            installation_id
        ):
            raise LetsInferError("installed runtime has no valid installation identity")
        if arguments.base_url is None:
            command.extend(
                ["--base-url", f"http://127.0.0.1:{config['gateway_port']}"]
            )
        if arguments.api_key_file is None:
            command.extend(["--api-key-file", config["gateway_api_key_file"]])
        if arguments.ca_cert_file is None:
            command.extend(["--ca-cert-file", config["tls_cert_file"]])
        if arguments.watchdog_trip_file is None:
            command.extend(
                [
                    "--watchdog-trip-file",
                    str(pathlib.Path(config["protection_root"]) / PROTECTION_TRIP_NAME),
                ]
            )
        command.extend(
            [
                "--engine-port",
                str(config["engine_port"]),
                "--token-count-base-url",
                f"https://127.0.0.1:{config['engine_port']}",
                "--token-count-api-key-file",
                config["engine_api_key_file"],
                "--installation-id",
                installation_id,
                "--benchmark-timestamp-unix-ns",
                str(time.time_ns()),
                "--benchmark-contract-sha256",
                benchmark_contract_sha,
                "--watchdog-port",
                str(config["watchdog_port"]),
                "--watchdog-ca-file",
                config["watchdog_controller_ca_file"],
                "--watchdog-controller-cert-file",
                config["watchdog_local_controller_cert_file"],
                "--watchdog-controller-key-file",
                config["watchdog_local_controller_key_file"],
            ]
        )
    output: pathlib.Path | None = arguments.output_directory
    if not arguments.list and output is None:
        runtime_name = re.sub(r"[^A-Za-z0-9_.-]+", "-", arguments.runtime).strip("-")
        if not runtime_name:
            runtime_name = "runtime"
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        output = pathlib.Path.home() / ".cache/letsinfer/benchmarks" / f"{runtime_name}-{stamp}"
        command.extend(["--output-directory", str(output)])
    if arguments.job_worker:
        command.extend(["--progress-file", str(benchmark_jobs.progress_path())])

    if arguments.list:
        run_passthrough(command)
    elif arguments.job_worker:
        if not isinstance(arguments.job_id, str) or not arguments.job_id:
            raise LetsInferError("benchmark worker has no job identity")
        _mark_benchmark_job(arguments.job_id, "running")
        previous_term = signal.getsignal(signal.SIGTERM)
        previous_int = signal.getsignal(signal.SIGINT)

        def cancel_benchmark(_signal: int, _frame: Any) -> None:
            raise _BenchmarkCancelled("benchmark cancellation requested")

        signal.signal(signal.SIGTERM, cancel_benchmark)
        signal.signal(signal.SIGINT, cancel_benchmark)
        try:
            _run_benchmark_with_service_isolation(
                command,
                protection_config=config,
                cleanup_command=[
                    str(letsinfer_bin),
                    "stop",
                    "--name",
                    arguments.container or "letsinfer-benchmark",
                ],
            )
        except _BenchmarkCancelled:
            _mark_benchmark_job(arguments.job_id, "cancelled")
            return 0
        except BaseException as error:
            _mark_benchmark_job(
                arguments.job_id,
                "failed",
                error=f"{type(error).__name__}: {error}",
            )
            raise
        else:
            _mark_benchmark_job(arguments.job_id, "completed")
        finally:
            signal.signal(signal.SIGTERM, previous_term)
            signal.signal(signal.SIGINT, previous_int)
    else:
        assert output is not None
        worker_command = _benchmark_self_command(arguments, letsinfer_bin, output)
        try:
            state = benchmark_jobs.start(
                worker_command,
                runtime=arguments.runtime,
                output_directory=str(output),
            )
        except benchmark_jobs.BenchmarkJobError as error:
            raise LetsInferError(str(error)) from error
        ui.Terminal(sys.stderr).status(
            f"Benchmark started · job {state['job_id'][:8]}"
        )
        if not arguments.detach:
            _follow_benchmark_job(state["job_id"])
    return 0


def _run_benchmark_with_service_isolation(
    command: Sequence[str],
    *,
    protection_config: dict[str, Any] | None = None,
    cleanup_command: Sequence[str] | None = None,
) -> None:
    """Suspend an active engine while a benchmark owns the inference host."""
    if protection_config is not None and protection_trip_latched(protection_config):
        raise LetsInferError(
            "runtime protection is already tripped; run letsinfer recover before "
            "benchmarking"
        )
    _, engine_state = _unit_enabled_active(ENGINE_SERVICE_NAME)
    _, recovery_state = _unit_enabled_active(RECOVERY_TIMER_NAME)
    safe_states = {"active", "inactive", "failed", "not-found"}
    for name, state in (
        (ENGINE_SERVICE_NAME, engine_state),
        (RECOVERY_TIMER_NAME, recovery_state),
    ):
        if state not in safe_states:
            raise LetsInferError(
                f"refusing benchmark while {name} state is {state!r}"
            )

    benchmark_error: BaseException | None = None
    restore_errors: list[str] = []
    benchmark_trip_latched = False
    recovery_stopped = False
    engine_stopped = False
    try:
        if recovery_state == "active":
            run_passthrough(
                ["systemctl", "--user", "stop", RECOVERY_TIMER_NAME]
            )
            recovery_stopped = True
        if engine_state == "active":
            run_passthrough(
                ["systemctl", "--user", "stop", ENGINE_SERVICE_NAME]
            )
            engine_stopped = True
        run_passthrough(command)
    except BaseException as error:
        benchmark_error = error
    finally:
        benchmark_trip_latched = (
            protection_config is not None
            and protection_trip_latched(protection_config)
        )
        if cleanup_command is not None:
            cleanup = run(cleanup_command, check=False)
            if cleanup.returncode != 0:
                detail = (cleanup.stderr or cleanup.stdout).strip()
                restore_errors.append(
                    "remove temporary benchmark container: "
                    + (detail or "unknown cleanup error")
                )
        if engine_stopped and not benchmark_trip_latched:
            try:
                run_passthrough(
                    ["systemctl", "--user", "start", ENGINE_SERVICE_NAME]
                )
            except BaseException as error:
                restore_errors.append(f"restore {ENGINE_SERVICE_NAME}: {error}")
        if recovery_stopped and not benchmark_trip_latched:
            try:
                run_passthrough(
                    ["systemctl", "--user", "restart", RECOVERY_TIMER_NAME]
                )
            except BaseException as error:
                restore_errors.append(f"restore {RECOVERY_TIMER_NAME}: {error}")

    if restore_errors:
        detail = "; ".join(restore_errors)
        if benchmark_error is not None:
            raise LetsInferError(
                f"benchmark failed and service restoration was incomplete: {detail}"
            ) from benchmark_error
        raise LetsInferError(
            f"benchmark completed but service restoration was incomplete: {detail}"
        )
    if benchmark_trip_latched:
        message = (
            "benchmark triggered Watchdog protection; the engine and recovery timer "
            "remain stopped until explicit letsinfer recover"
        )
        if benchmark_error is not None:
            raise LetsInferError(f"{benchmark_error}; {message}") from benchmark_error
        raise LetsInferError(message)
    if benchmark_error is not None:
        raise benchmark_error


def list_releases(_: argparse.Namespace) -> int:
    installed = sorted(
        installed_runtime_manifests(),
        key=lambda item: (
            item[1]["model"]["alias"],
            adapter_for(item[1]).name,
            target_contract(item[1])["id"],
            item[1]["release"],
        ),
    )
    for _, manifest, _ in installed:
        serving = manifest["serving"]
        state = "qualified" if serving["qualified"] else "blocked"
        print(
            f"{adapter_for(manifest).name}\t{manifest['model']['alias']}\t"
            f"{manifest['release']}\t{manifest['status']}\t"
            f"serving={state} connections={serving['max_connections']}"
        )
    return 0


def list_engines(_: argparse.Namespace) -> int:
    for name in sorted(ADAPTERS):
        adapter = ADAPTERS[name]
        print(
            f"{adapter.name}\tformat={adapter.model_format}\t"
            f"api=openai-v1\tcache={adapter.cache_provider}\t"
            f"persistent_cache={str(adapter.persistent_cache).lower()}"
        )
    return 0


def _installed_core_layout() -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
    """Return (prefix, installer, public launcher) for an immutable install."""
    try:
        root = source_root().resolve(strict=True)
    except OSError as error:
        raise LetsInferError(f"cannot resolve the installed core: {error}") from error
    version_root = root.parent
    product_root = version_root.parent
    library_root = product_root.parent
    if product_root.name != "letsinfer" or library_root.name != "lib":
        raise LetsInferError(
            "core update must be run from an installed Let's Infer command"
        )
    prefix = library_root.parent
    installer = root / "install.sh"
    if installer.is_symlink() or not installer.is_file():
        raise LetsInferError("the installed core has no trusted release installer")
    launcher = (
        pathlib.Path("/usr/local/bin/letsinfer")
        if prefix == pathlib.Path("/opt/letsinfer")
        else prefix / "bin/letsinfer"
    )
    return prefix, installer, launcher


def update_core(arguments: argparse.Namespace) -> int:
    """Install a signed core release without changing any runtime selection."""
    try:
        active_benchmark = benchmark_jobs.active_state()
    except benchmark_jobs.BenchmarkJobError as error:
        raise LetsInferError(str(error)) from error
    if active_benchmark is not None:
        raise LetsInferError(
            "core update is unavailable while a benchmark is active; "
            "run `letsinfer benchmark stop` first"
        )
    prefix, installer, launcher = _installed_core_layout()
    command = ["/bin/sh", str(installer), "--no-setup"]
    if prefix != pathlib.Path("/opt/letsinfer"):
        command.extend(["--prefix", str(prefix)])
    if arguments.version is not None:
        command.extend(["--version", arguments.version])
    run_passthrough(command)
    if launcher.is_symlink():
        try:
            launcher.resolve(strict=True)
        except OSError as error:
            raise LetsInferError(
                f"updated core launcher is unavailable: {error}"
            ) from error
    elif not launcher.is_file():
        raise LetsInferError(f"updated core launcher is unavailable: {launcher}")
    run_passthrough([str(launcher), "core-rebind"])
    return 0


def rebind_core_services(_: argparse.Namespace) -> int:
    """Bind existing node services to this core without selecting a runtime."""
    if not site_identity_path().is_file():
        print(f"CORE {PRODUCT_VERSION} services=none runtimes=unchanged")
        return 0
    identity = read_site_identity()
    config_path = default_service_config_path()
    model = None
    if config_path.is_file():
        previous = read_service_config(config_path)
        model = previous.get("model")
    site_state = _unit_enabled_active(SITE_SERVICE_NAME)
    gateway_state = _unit_enabled_active(GATEWAY_SERVICE_NAME)
    watchdog_state = _unit_enabled_active(SERVICE_NAME)
    if all(
        enabled == "not-found" and active == "inactive"
        for enabled, active in (site_state, gateway_state, watchdog_state)
    ):
        print(f"CORE {PRODUCT_VERSION} services=none runtimes=unchanged")
        return 0
    runtime_state = install_core_plane_services(
        identity, include_gateway=identity.role == "coordinator"
    )
    runtime = f" runtime={model}" if isinstance(model, str) else ""
    if runtime_state["configured"] and not runtime_state["compatible"]:
        runtime += " runtime_state=incompatible-stopped"
    print(
        f"CORE {PRODUCT_VERSION} services=rebound{runtime} runtimes=unchanged"
    )
    return 0


def ensure_core_watchdog_tls() -> None:
    ensure_watchdog_tls_material(
        default_watchdog_cert_path(),
        default_watchdog_key_path(),
        default_watchdog_controller_ca_path(),
        default_watchdog_controller_ca_key_path(),
        default_watchdog_local_controller_cert_path(),
        default_watchdog_local_controller_key_path(),
    )


def setup_command(arguments: argparse.Namespace) -> int:
    if not arguments.no_service:
        system = platform.system().lower()
        if system not in {"linux", "darwin"}:
            raise LetsInferError("persistent Let's Infer setup requires Linux or macOS")
        if not user_lingering_enabled():
            if system == "darwin":
                raise LetsInferError(
                    "persistent Let's Infer setup requires an active macOS login session"
                )
            raise LetsInferError(
                "user-systemd lingering is required before creating a persistent site"
            )
    try:
        identity = setup_site(arguments.name, arguments.address)
    except SiteError as error:
        raise LetsInferError(str(error)) from error
    if identity.role == "member":
        if not arguments.no_service and platform.system() == "Linux":
            ensure_core_watchdog_tls()
        facts_error: LetsInferError | None = None
        try:
            refresh_local_member_facts()
        except LetsInferError as error:
            facts_error = error
        if not arguments.no_service:
            install_core_plane_services(identity, include_gateway=False)
        value = identity_json(identity)
        if arguments.json:
            print(json.dumps(value, sort_keys=True))
        else:
            print(
                f"SITE {identity.display_name} id={identity.site_id} "
                f"role={identity.role} member={identity.member_id}"
            )
        if facts_error is not None:
            print(
                "WARNING member facts will retry through the site service: "
                f"{facts_error}",
                file=sys.stderr,
            )
        return 0
    ensure_tls_material(default_tls_cert_path(), default_tls_key_path())
    if platform.system() == "Linux":
        ensure_core_watchdog_tls()
        ensure_controller_authorization(
            identity,
            default_watchdog_local_controller_cert_path(),
        )
    local_key_path = default_api_key_path()
    try:
        if local_key_path.is_symlink():
            raise LetsInferError(
                f"local inference API key cannot be a symlink: {local_key_path}"
            )
        with SiteStore(identity=identity) as store:
            active_default = next(
                (
                    row
                    for row in store.keys()
                    if row["name"] == "default" and row["revoked_at_unix"] is None
                ),
                None,
            )
            if local_key_path.is_file():
                token = read_api_key(local_key_path)
                authenticated = store.authenticate_key(token)
                if active_default is None or authenticated is None or (
                    authenticated["key_id"] != active_default["key_id"]
                ):
                    raise LetsInferError(
                        "the local inference API key does not match the site registry"
                    )
            else:
                if active_default is None:
                    _, token = store.create_key("default", application="local-client")
                else:
                    _, token = store.rotate_key("default")
                _atomic_private_text(local_key_path, token + "\n")
    except SiteError as error:
        raise LetsInferError(f"cannot provision the local inference API key: {error}") from error
    try:
        refresh_local_member_facts()
    except LetsInferError:
        if not arguments.no_service:
            raise
    if not arguments.no_service:
        install_core_plane_services(identity, include_gateway=True)
    value = identity_json(identity)
    value["api_key_file"] = str(local_key_path)
    value["inference_endpoint"] = local_inference_endpoint()
    if arguments.json:
        print(json.dumps(value, sort_keys=True))
    else:
        print(
            f"SITE {identity.display_name} id={identity.site_id} "
            f"role={identity.role} member={identity.member_id}"
        )
        print(f"API key stored privately at {local_key_path}")
        print(f"API endpoint {value['inference_endpoint']}")
    return 0


def site_status_command(arguments: argparse.Namespace) -> int:
    try:
        identity = read_site_identity()
        value = identity_json(identity)
        if identity.role == "coordinator":
            with SiteStore(identity=identity) as store:
                value["members"] = [
                    dict(row)
                    for row in store.connection.execute(
                        "SELECT member_id,display_name,role,address,state,updated_at_unix "
                        "FROM members WHERE state != 'removed' ORDER BY role,member_id"
                    )
                ]
                value["audit"] = store.verify_audit()
        else:
            value["members"] = None
            value["audit"] = None
    except SiteError as error:
        raise LetsInferError(str(error)) from error
    if arguments.json:
        print(json.dumps(value, sort_keys=True))
    else:
        print(
            f"{value['display_name']}\t{value['role']}\t"
            f"site={value['site_id']}\tmember={value['member_id']}\t"
            f"coordinator={value['coordinator_id']}@{value['coordinator_address']}"
        )
    return 0


def site_move_command(arguments: argparse.Namespace) -> int:
    identity = read_site_identity()
    with _site_store() as store:
        plan = plan_local_move(store)
    document = plan.document()
    if not arguments.apply:
        with _site_store() as store:
            store.record_action(
                "site.move", identity.site_id, "success", "plan_only"
            )
        print(json.dumps(document, sort_keys=True, indent=None if arguments.json else 2))
        return 0
    if arguments.source_site_id != identity.site_id:
        raise LetsInferError("--source-site-id must exactly confirm the current site")
    if plan.blocking_reasons:
        raise LetsInferError("site move is blocked: " + "; ".join(plan.blocking_reasons))
    required = {
        "endpoint": arguments.endpoint,
        "invite": arguments.invite,
        "coordinator certificate": arguments.coordinator_certificate_sha256,
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        raise LetsInferError("site move requires " + ", ".join(missing))
    code = arguments.code
    if code is None:
        try:
            code = getpass.getpass("Destination membership code: ")
        except (EOFError, KeyboardInterrupt) as error:
            raise LetsInferError("site move code entry was cancelled") from error
    code = re.sub(r"[- ]", "", code)
    if re.fullmatch(r"[0-9]{8}", code) is None:
        raise LetsInferError("destination membership code must contain eight digits")

    prior_units: dict[str, tuple[str, str]] = {}
    prior_unit_files: dict[str, tuple[str, int] | None] = {}
    if not arguments.no_service:
        if platform.system().lower() != "linux":
            raise LetsInferError("persistent site moves require Linux user systemd")
        if not user_lingering_enabled():
            raise LetsInferError("user-systemd lingering is required before a site move")
        for unit in (
            SERVICE_NAME,
            SITE_SERVICE_NAME,
            ENGINE_SERVICE_NAME,
            GATEWAY_SERVICE_NAME,
            RECOVERY_TIMER_NAME,
        ):
            prior_units[unit] = _unit_enabled_active(unit)
            prior_unit_files[unit] = _snapshot_user_file(
                pathlib.Path.home() / ".config/systemd/user" / unit
            )
        active_work = [
            unit
            for unit in (ENGINE_SERVICE_NAME, GATEWAY_SERVICE_NAME)
            if prior_units[unit][1] == "active"
        ]
        if active_work:
            raise LetsInferError(
                "site move requires inference and gateway services to be stopped first: "
                + ",".join(active_work)
            )

    with _site_store() as store:
        store.record_action(
            "site.move",
            str(arguments.endpoint),
            "success",
            "source_authorized_membership_replacement",
        )
    try:
        if not arguments.no_service:
            for unit in (RECOVERY_TIMER_NAME, SITE_SERVICE_NAME, SERVICE_NAME):
                if prior_units[unit][1] == "active":
                    run_passthrough(["systemctl", "--user", "stop", unit])
        with LocalMoveTransaction(identity) as transaction:
            enrollment = join_site(
                str(arguments.endpoint),
                invite_id=str(arguments.invite),
                code=code,
                coordinator_certificate_sha256=str(
                    arguments.coordinator_certificate_sha256
                ),
                member_name=arguments.name or socket.gethostname(),
                member_address=arguments.address or socket.getfqdn() or socket.gethostname(),
            )
            if not arguments.no_service:
                ensure_core_watchdog_tls()
                install_site_service_only()
                install_core_watchdog_service(enrollment.identity)
            replacement = transaction.commit()
        if not arguments.no_service:
            for unit in (
                ENGINE_SERVICE_NAME,
                GATEWAY_SERVICE_NAME,
                RECOVERY_TIMER_NAME,
            ):
                run(["systemctl", "--user", "disable", unit], check=False)
    except BaseException as failure:
        if not arguments.no_service:
            rollback_errors: list[str] = []
            unit_root = pathlib.Path.home() / ".config/systemd/user"
            for unit in prior_units:
                run(["systemctl", "--user", "stop", unit], check=False)
            try:
                for unit, snapshot in prior_unit_files.items():
                    _restore_user_file(unit_root / unit, snapshot)
                run(["systemctl", "--user", "daemon-reload"])
                for unit, (enabled, active) in prior_units.items():
                    _restore_unit_enablement(unit, enabled)
                    if active == "active":
                        run_passthrough(["systemctl", "--user", "start", unit])
            except BaseException as rollback_error:
                rollback_errors.append(str(rollback_error))
            if rollback_errors:
                raise LetsInferError(
                    "site move failed and service rollback was incomplete: "
                    + "; ".join(rollback_errors)
                ) from failure
        raise

    result = identity_json(replacement)
    result.update(
        {
            "source_site_id": identity.site_id,
            "membership_state": enrollment.state,
            "approval_expires_at_unix": enrollment.approval_expires_at_unix,
            "comparison_code": enrollment.comparison_code,
        }
    )
    if arguments.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(
            f"MOVED source={identity.site_id} destination={replacement.site_id} "
            f"member={replacement.member_id} state={enrollment.state}"
        )
        if enrollment.comparison_code is not None:
            print(f"COMPARE {enrollment.comparison_code}")
    return 0


def _site_store() -> SiteStore:
    try:
        return SiteStore()
    except SiteError as error:
        raise LetsInferError(str(error)) from error


def member_list_command(arguments: argparse.Namespace) -> int:
    identity = read_site_identity()
    if identity.role != "coordinator":
        rows = [{
            "member_id": identity.member_id,
            "display_name": socket.gethostname(),
            "role": identity.role,
            "address": identity.coordinator_address,
            "state": "active",
        }]
    else:
        with _site_store() as store:
            rows = store.members()
    if arguments.json:
        print(json.dumps(rows, sort_keys=True))
    else:
        for row in rows:
            print(
                f"{row['member_id']}\t{row['display_name']}\t{row['role']}\t"
                f"{row['state']}\t{row['address']}"
            )
    return 0


def member_prepare_command(arguments: argparse.Namespace) -> int:
    try:
        candidate = prepare_member_identity()
    except SiteError as error:
        raise LetsInferError(str(error)) from error
    print(json.dumps(candidate, sort_keys=True, indent=None if arguments.json else 2))
    return 0


def member_join_command(arguments: argparse.Namespace) -> int:
    if not arguments.no_service:
        if platform.system().lower() != "linux":
            raise LetsInferError("persistent site membership requires Linux user systemd")
        if not user_lingering_enabled():
            raise LetsInferError(
                "user-systemd lingering is required before joining a persistent site"
            )
    code = arguments.code
    if arguments.connectx:
        if code is not None:
            raise LetsInferError("ConnectX membership does not use a setup code")
    else:
        if code is None:
            try:
                code = getpass.getpass("Membership code: ")
            except (EOFError, KeyboardInterrupt) as error:
                raise LetsInferError("membership code entry was cancelled") from error
        code = re.sub(r"[- ]", "", code)
        if re.fullmatch(r"[0-9]{8}", code) is None:
            raise LetsInferError("membership code must contain eight digits")
    try:
        enrollment = join_site(
            arguments.endpoint,
            invite_id=arguments.invite,
            code=code,
            coordinator_certificate_sha256=arguments.coordinator_certificate_sha256,
            member_name=arguments.name or socket.gethostname(),
            member_address=arguments.address or socket.getfqdn() or socket.gethostname(),
        )
    except (ControlError, SiteError) as error:
        raise LetsInferError(str(error)) from error
    if not arguments.no_service:
        ensure_core_watchdog_tls()
        install_site_service_only()
        install_core_watchdog_service(enrollment.identity)
    identity = enrollment.identity
    value = identity_json(identity)
    value["membership_state"] = enrollment.state
    value["approval_expires_at_unix"] = enrollment.approval_expires_at_unix
    value["comparison_code"] = enrollment.comparison_code
    if arguments.json:
        print(json.dumps(value, sort_keys=True))
    else:
        label = "JOINED" if enrollment.state == "active" else "PENDING"
        print(
            f"{label} {identity.display_name} site={identity.site_id} "
            f"member={identity.member_id} coordinator="
            f"{identity.coordinator_id}@{identity.coordinator_address}"
        )
        if enrollment.comparison_code is not None:
            print(f"COMPARE {enrollment.comparison_code}")
    return 0


def member_invite_command(arguments: argparse.Namespace) -> int:
    direct_link = None
    if arguments.mode == "connectx":
        try:
            verified = verify_direct_connectx_interface(arguments.interface)
            if not isinstance(arguments.candidate_endpoint, str):
                raise LetsInferError(
                    "ConnectX invite requires the candidate site endpoint"
                )
            peer_address = resolve_direct_peer(
                arguments.candidate_endpoint, verified["interface"]
            )
            direct_link = verify_direct_connectx_peer(
                verified["interface"], peer_address
            )
            if not isinstance(direct_link.get("local_address"), str):
                raise LetsInferError(
                    "ConnectX route does not declare a local endpoint address"
                )
        except (InventoryError, AdoptionError) as error:
            raise LetsInferError(str(error)) from error
    elif arguments.candidate_endpoint is not None:
        raise LetsInferError("code-based invite cannot carry a candidate endpoint")
    with _site_store() as store:
        try:
            invite = store.create_invite(
                arguments.mode,
                candidate_public_key_sha256=arguments.candidate_fingerprint,
                direct_interface=arguments.interface,
                lifetime_seconds=arguments.expires_in,
            )
        except SiteError as error:
            raise LetsInferError(str(error)) from error
    if direct_link is not None:
        invite["direct_link"] = direct_link
    endpoint_address = (
        direct_link["local_address"]
        if direct_link is not None
        else read_site_identity().coordinator_address
    )
    endpoint_host = (
        f"[{endpoint_address}]" if ":" in endpoint_address else endpoint_address
    )
    invite["endpoint"] = f"https://{endpoint_host}:{SITE_CONTROL_PORT}"
    invite["coordinator_certificate_sha256"] = certificate_sha256(
        site_member_certificate_path()
    )
    if arguments.json:
        print(json.dumps(invite, sort_keys=True))
    else:
        print(
            f"INVITE {invite['invite_id']} mode={invite['mode']} "
            f"expires={invite['expires_at_unix']}"
        )
        if invite["code"] is not None:
            print(invite["code"])
    return 0


def member_approve_command(arguments: argparse.Namespace) -> int:
    comparison_code = re.sub(r"[- ]", "", arguments.comparison_code)
    with _site_store() as store:
        try:
            result = store.approve_member(arguments.member, comparison_code)
        except SiteError as error:
            raise LetsInferError(str(error)) from error
    if arguments.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(f"APPROVED {result['member_id']}")
    return 0


def _site_control_endpoint(address: str) -> str:
    if "://" in address:
        return address
    host = f"[{address}]" if ":" in address and not address.startswith("[") else address
    return f"https://{host}:{SITE_CONTROL_PORT}"


def member_sync_command(arguments: argparse.Namespace) -> int:
    result = _synchronize_member_facts()
    if arguments.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(f"SYNCED {len(result['refreshed'])} member(s)")
        for failure in result["failed"]:
            print(f"FAILED {failure}", file=sys.stderr)
    if result["failed"]:
        with _site_store() as store:
            store.record_action(
                "member.sync", "member.sync", "failed", "member_control_unavailable"
            )
        raise LetsInferError("one or more members could not publish authenticated facts")
    return 0


def _synchronize_member_facts() -> dict[str, list[str]]:
    identity = read_site_identity()
    refreshed: list[str] = []
    failures: list[str] = []
    refresh_local_member_facts()
    refreshed.append(identity.member_id)
    with _site_store() as store:
        rows = [row for row in store.members() if row["state"] != "pending"]
        for row in rows:
            member_id = row["member_id"]
            if member_id == identity.member_id:
                continue
            try:
                signed = fetch_member_facts(
                    _site_control_endpoint(row["address"]),
                    expected_member_id=member_id,
                    expected_certificate_sha256=row["certificate_sha256"],
                )
                store.update_member_facts(
                    member_id,
                    signed["facts"],
                    signed["signature"],
                    actor_type="system",
                    origin_interface="member-control",
                )
                refreshed.append(member_id)
            except (ControlError, SiteError) as error:
                failures.append(f"{member_id}:{type(error).__name__}")
    return {"refreshed": refreshed, "failed": failures}


def member_remove_command(arguments: argparse.Namespace) -> int:
    with _site_store() as store:
        try:
            result = store.remove_member(arguments.member)
        except SiteError as error:
            raise LetsInferError(str(error)) from error
    print(json.dumps(result, sort_keys=True) if arguments.json else f"REMOVED {arguments.member}")
    return 0


def member_drain_command(arguments: argparse.Namespace) -> int:
    with _site_store() as store:
        try:
            result = store.set_member_draining(arguments.member, True)
        except SiteError as error:
            raise LetsInferError(str(error)) from error
    print(json.dumps(result, sort_keys=True) if arguments.json else f"DRAINING {arguments.member}")
    return 0


def member_resume_command(arguments: argparse.Namespace) -> int:
    with _site_store() as store:
        try:
            result = store.set_member_draining(arguments.member, False)
        except SiteError as error:
            raise LetsInferError(str(error)) from error
    print(json.dumps(result, sort_keys=True) if arguments.json else f"ACTIVE {arguments.member}")
    return 0


def _engine_group_path(group_id: str) -> pathlib.Path:
    if not re.fullmatch(r"[0-9a-f]{32}", group_id):
        raise LetsInferError("engine-group identity is invalid")
    return default_engine_group_root() / group_id


def _engine_group_member_host(group: Mapping[str, Any], member_id: str) -> str:
    matches = [item for item in group["members"] if item["member_id"] == member_id]
    if len(matches) != 1:
        raise LetsInferError("engine-group member address is unavailable")
    address = matches[0]["address"]
    parsed = urllib.parse.urlsplit(
        address if "://" in address else f"https://{address}"
    )
    if parsed.scheme != "https" or not parsed.hostname:
        raise LetsInferError("engine-group member address is invalid")
    return parsed.hostname


def _ensure_engine_group_tls(
    certificate: pathlib.Path,
    private_key: pathlib.Path,
    host: str,
) -> None:
    if certificate.exists() or private_key.exists():
        if not certificate.exists() or not private_key.exists():
            raise LetsInferError("engine-group TLS material is incomplete")
        validate_tls_material(certificate, private_key)
    else:
        ensure_private_directory(certificate.parent)
        staging = pathlib.Path(
            tempfile.mkdtemp(prefix=".group-tls-", dir=certificate.parent)
        )
        try:
            staged_certificate = staging / "engine.crt"
            staged_key = staging / "engine.key"
            try:
                socket.inet_pton(socket.AF_INET, host)
                host_san = f"IP:{host}"
            except OSError:
                try:
                    socket.inet_pton(socket.AF_INET6, host)
                    host_san = f"IP:{host}"
                except OSError:
                    if (
                        len(host.encode("idna")) > 253
                        or not re.fullmatch(r"[A-Za-z0-9.-]+", host)
                    ):
                        raise LetsInferError("engine-group TLS hostname is invalid")
                    host_san = f"DNS:{host}"
            run([
                "openssl", "req", "-x509", "-newkey", "rsa:3072", "-sha256",
                "-nodes", "-days", "825", "-subj", f"/CN={host}",
                "-addext", f"subjectAltName={host_san},DNS:localhost,IP:127.0.0.1",
                "-keyout", str(staged_key), "-out", str(staged_certificate),
            ])
            staged_key.chmod(0o600)
            staged_certificate.chmod(0o644)
            validate_tls_material(staged_certificate, staged_key)
            staged_key.replace(private_key)
            staged_certificate.replace(certificate)
        finally:
            if staging.exists():
                shutil.rmtree(staging)
    check_flag = "-checkip" if re.fullmatch(r"[0-9a-fA-F:.]+", host) else "-checkhost"
    run(["openssl", "x509", "-in", str(certificate), "-noout", check_flag, host])


def _read_engine_group_config(group_id: str) -> dict[str, Any]:
    root = _engine_group_path(group_id)
    path = root / "config.json"
    try:
        payload = _validate_private_file(path, minimum_bytes=64)
        config = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LetsInferError("engine-group configuration is invalid JSON") from error
    required = {
        "schema_version", "group_id", "member_id", "plan_sha256", "source",
        "runtime_digest", "runtime_name", "runtime_version", "object_root",
        "control_root", "manifest_path", "manifest_sha256", "topology_sha256",
        "role", "group_file", "credential_file", "tls_certificate_file",
        "tls_key_file", "model_cache", "plugin_root", "store_root",
        "runtime_cache_root", "container_name", "protection_root",
    }
    if (
        not isinstance(config, dict)
        or set(config) != required
        or type(config.get("schema_version")) is not int
        or config.get("schema_version") != 1
    ):
        raise LetsInferError("engine-group configuration schema is invalid")
    if config.get("group_id") != group_id or not re.fullmatch(r"[0-9a-f]{32}", str(config.get("member_id"))):
        raise LetsInferError("engine-group configuration identity is invalid")
    for key in ("plan_sha256", "runtime_digest", "manifest_sha256", "topology_sha256"):
        if not isinstance(config.get(key), str) or not SHA256_RE.fullmatch(config[key]):
            raise LetsInferError(f"engine-group configuration {key} is invalid")
    expected_root = root.resolve(strict=True)
    for key in (
        "group_file", "credential_file", "tls_certificate_file", "tls_key_file"
    ):
        candidate = pathlib.Path(config[key]).expanduser().resolve(strict=True)
        try:
            candidate.relative_to(expected_root)
        except ValueError as error:
            raise LetsInferError(f"engine-group configuration {key} escapes its private root") from error
    runtime_root = pathlib.Path(config["object_root"]).expanduser()
    try:
        runtime = verify_descriptor(runtime_root)
    except RuntimePackError as error:
        raise LetsInferError(str(error)) from error
    if runtime.digest != config["runtime_digest"]:
        raise LetsInferError("engine-group runtime object identity changed")
    manifest_path, manifest = validate_control_bundle(
        pathlib.Path(config["control_root"]).expanduser(),
        pathlib.Path(config["manifest_path"]).expanduser(),
        config["manifest_sha256"],
    )
    if manifest_path != pathlib.Path(config["manifest_path"]).expanduser().resolve(strict=True):
        raise LetsInferError("engine-group manifest path is non-canonical")
    group_file = pathlib.Path(config["group_file"])
    try:
        group = validate_group_document(json.loads(_validate_private_file(group_file).decode("utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError, OrchestrationError) as error:
        raise LetsInferError(f"engine-group plan is invalid: {error}") from error
    if (
        group["group_id"] != group_id
        or hashlib.sha256(canonical_bytes(group)).hexdigest() != config["plan_sha256"]
        or group["runtime_digest"] != config["runtime_digest"]
        or group["manifest_sha256"] != config["manifest_sha256"]
        or group["topology_sha256"] != config["topology_sha256"]
    ):
        raise LetsInferError("engine-group configuration does not match its plan")
    credential = read_api_key(pathlib.Path(config["credential_file"]))
    _ensure_engine_group_tls(
        pathlib.Path(config["tls_certificate_file"]),
        pathlib.Path(config["tls_key_file"]),
        _engine_group_member_host(group, config["member_id"]),
    )
    config["_manifest"] = manifest
    config["_group"] = group
    config["_credential_sha256"] = group_credential_sha256(credential)
    return config


class LocalEngineGroupExecutor:
    """Install and run one runtime role without accepting arbitrary commands."""

    def __init__(self, member_id: str) -> None:
        if not re.fullmatch(r"[0-9a-f]{32}", member_id):
            raise LetsInferError("local engine-group member identity is invalid")
        self.member_id = member_id

    def __call__(
        self, job: Mapping[str, Any], engine_credential: str | None
    ) -> Mapping[str, Any]:
        action = job["action"]
        if action == "stage":
            if engine_credential is None:
                raise LetsInferError("engine-group stage credential is unavailable")
            return self.stage(job, engine_credential)
        if action == "start":
            return self.start(job)
        if action == "recover":
            return self.recover(job)
        if action == "stop":
            return self.stop(job)
        if action == "remove":
            return self.remove(job)
        raise LetsInferError("unsupported engine-group lifecycle action")

    def _assert_job_matches_config(
        self, job: Mapping[str, Any], config: Mapping[str, Any]
    ) -> None:
        if (
            job["group_id"] != config["group_id"]
            or job["member_id"] != config["member_id"]
            or job["plan_sha256"] != config["plan_sha256"]
            or job["runtime_digest"] != config["runtime_digest"]
            or job["manifest_sha256"] != config["manifest_sha256"]
            or job["topology_sha256"] != config["topology_sha256"]
            or job["engine_credential_sha256"] != config["_credential_sha256"]
            or job["role"] != config["role"]
            or job["group"] != config["_group"]
        ):
            raise LetsInferError("engine-group job differs from the staged immutable configuration")

    def _safe_result(self, config: Mapping[str, Any], state: str) -> dict[str, Any]:
        role = config["role"]
        group = config["_group"]
        host = _engine_group_member_host(group, config["member_id"])
        certificate_path = pathlib.Path(config["tls_certificate_file"])
        try:
            certificate_pem = certificate_path.read_text(encoding="ascii")
        except (OSError, UnicodeDecodeError) as error:
            raise LetsInferError("engine-group public certificate is unavailable") from error
        if (
            len(certificate_pem.encode("ascii")) > 16_384
            or not certificate_pem.startswith("-----BEGIN CERTIFICATE-----\n")
            or not certificate_pem.rstrip().endswith("-----END CERTIFICATE-----")
        ):
            raise LetsInferError("engine-group public certificate is invalid")
        result: dict[str, Any] = {
            "state": state,
            "group_id": config["group_id"],
            "member_id": config["member_id"],
            "role": role["name"],
            "runtime_digest": config["runtime_digest"],
            "manifest_sha256": config["manifest_sha256"],
            "tls_certificate_sha256": certificate_sha256(certificate_path),
            "tls_certificate_pem": certificate_pem,
        }
        if role["inference_endpoint"]:
            endpoint_host = f"[{host}]" if ":" in host else host
            result["endpoint"] = f"https://{endpoint_host}:{role['port_base']}"
        else:
            result["endpoint"] = None
        return result

    def stage(
        self, job: Mapping[str, Any], engine_credential: str
    ) -> Mapping[str, Any]:
        root = _engine_group_path(job["group_id"])
        ensure_private_directory(default_engine_group_root())
        if root.exists():
            config = _read_engine_group_config(job["group_id"])
            self._assert_job_matches_config(job, config)
            if read_api_key(pathlib.Path(config["credential_file"])) != engine_credential:
                raise LetsInferError("engine-group stage credential changed")
            return self._safe_result(config, "staged")
        ensure_private_directory(root)
        try:
            manifest_path, manifest, control_root, receipt = prepare_runtime_install(
                str(job["source"]),
                policy="site-group",
                requested_engine=None,
            )
            if (
                receipt["digest"] != job["runtime_digest"]
                or sha256_file(manifest_path) != job["manifest_sha256"]
            ):
                raise LetsInferError("engine-group runtime or manifest identity differs from its job")
            runtime_root = pathlib.Path(receipt["object_root"])
            runtime = verify_descriptor(runtime_root)
            contract = validate_target_binding(
                runtime.descriptor.get("orchestration"),
                target_contract(manifest)["placement"],
            )
            if contract is None:
                raise LetsInferError("engine-group runtime has no orchestration contract")
            role = job["role"]
            expected_role = contract["roles"].get(role["name"])
            expected_job_role = None if expected_role is None else {
                "name": role["name"],
                "rank": role["rank"],
                "role_rank": role["role_rank"],
                "port_base": role["port_base"],
                "port_count": expected_role["port_count"],
                "launcher": expected_role["launcher"],
                "command": list(expected_role.get("command", [])),
                "environment": dict(expected_role["environment"]),
                "inference_endpoint": expected_role["inference_endpoint"],
                "readiness": dict(expected_role["readiness"]),
            }
            if expected_job_role != role:
                raise LetsInferError("engine-group job role differs from the runtime contract")
            group = validate_group_document(dict(job["group"]))
            placement = target_contract(manifest)["placement"]
            if (
                group["strategy"] != placement["strategy"]
                or group["engine_strategy"] != placement["engine_strategy"]
                or len(group["members"]) != placement["member_count"]
            ):
                raise LetsInferError("engine-group plan differs from the release target")
            model_cache = expanded_path(manifest["container"]["model_cache"])
            plugin_root = default_plugin_root(manifest, job["manifest_sha256"])
            ensure_install_dependencies(
                manifest,
                model_cache=model_cache,
                runtime_artifact_root=runtime_root,
                download=True,
                build_image=True,
            )
            install_runtime_plugins(
                manifest,
                plugin_root=plugin_root,
                wheel_source=None,
                artifact_root=control_root,
            )
            verify_installed_release(
                manifest, model_cache=model_cache, plugin_root=plugin_root
            )
            credential_file = root / "engine-api.key"
            _atomic_private_text(credential_file, engine_credential + "\n")
            tls_certificate = root / "engine.crt"
            tls_key = root / "engine.key"
            _ensure_engine_group_tls(
                tls_certificate,
                tls_key,
                _engine_group_member_host(group, self.member_id),
            )
            group_file = root / "group.json"
            atomic_json(group_file, group)
            group_file.chmod(0o600)
            config = {
                "schema_version": 1,
                "group_id": job["group_id"],
                "member_id": self.member_id,
                "plan_sha256": job["plan_sha256"],
                "source": job["source"],
                "runtime_digest": job["runtime_digest"],
                "runtime_name": runtime.descriptor["name"],
                "runtime_version": runtime.descriptor["version"],
                "object_root": str(runtime_root),
                "control_root": str(control_root),
                "manifest_path": str(manifest_path),
                "manifest_sha256": job["manifest_sha256"],
                "topology_sha256": job["topology_sha256"],
                "role": dict(job["role"]),
                "group_file": str(group_file),
                "credential_file": str(credential_file),
                "tls_certificate_file": str(tls_certificate),
                "tls_key_file": str(tls_key),
                "model_cache": str(model_cache),
                "plugin_root": str(plugin_root),
                "store_root": str(default_store_root(manifest)),
                "runtime_cache_root": str(default_runtime_cache_root(manifest)),
                "container_name": f"letsinfer-group-{job['group_id']}",
                "protection_root": str(
                    default_watchdog_data_root()
                    / PROTECTION_ROOT_NAME
                    / job["group_id"]
                ),
            }
            atomic_json(root / "config.json", config)
            (root / "config.json").chmod(0o600)
            verified = _read_engine_group_config(job["group_id"])
            self._assert_job_matches_config(job, verified)
            return self._safe_result(verified, "staged")
        except BaseException:
            if root.exists():
                shutil.rmtree(root)
                _fsync_path(root.parent)
            raise

    def _wait_runtime_command(
        self, name: str, readiness: Mapping[str, Any]
    ) -> None:
        for _attempt in range(readiness["retries"]):
            inspection = container_inspect(name)
            if inspection is None or not inspection.get("State", {}).get("Running", False):
                raise LetsInferError("engine-group container exited before readiness")
            result = run(
                ["docker", "exec", name, *readiness["command"]], check=False
            )
            if result.returncode == 0:
                return
            time.sleep(readiness["interval_seconds"])
        raise LetsInferError("runtime-owned engine-group readiness timed out")

    def start(self, job: Mapping[str, Any]) -> Mapping[str, Any]:
        config = _read_engine_group_config(job["group_id"])
        self._assert_job_matches_config(job, config)
        return self._start_config(config)

    def _start_config(self, config: Mapping[str, Any]) -> Mapping[str, Any]:
        verify_active_core_watchdog()
        manifest = config["_manifest"]
        role = config["role"]
        authorize_serving_launch(
            manifest["serving"], qualification_mode=False, evidence_dir=None
        )
        verify_host_target(manifest)
        runtime_root = pathlib.Path(config["object_root"])
        ensure_image(manifest, build=False, pull=False, artifact_root=runtime_root)
        verify_installed_release(
            manifest,
            model_cache=pathlib.Path(config["model_cache"]),
            plugin_root=pathlib.Path(config["plugin_root"]),
        )
        require_memory_reserve(manifest, phase="launch")
        command = docker_command(
            manifest,
            name=config["container_name"],
            manifest_sha256=config["manifest_sha256"],
            runtime_digest=config["runtime_digest"],
            port=role["port_base"],
            model_cache=pathlib.Path(config["model_cache"]),
            plugin_root=pathlib.Path(config["plugin_root"]),
            store_root=pathlib.Path(config["store_root"]),
            runtime_cache_root=pathlib.Path(config["runtime_cache_root"]),
            api_key_file=pathlib.Path(config["credential_file"]),
            tls_cert_file=pathlib.Path(config["tls_certificate_file"]),
            tls_key_file=pathlib.Path(config["tls_key_file"]),
            group_context={
                "group_id": config["group_id"],
                "member_id": config["member_id"],
                "role": role["name"],
                **{key: value for key, value in role.items() if key != "name"},
            },
            group_config_file=pathlib.Path(config["group_file"]),
            runtime_artifact_root=runtime_root,
        )
        protection = {
            "protection_root": config["protection_root"],
            "name": config["container_name"],
        }
        generation = secrets.token_hex(16)
        inspection = container_inspect(config["container_name"])
        publish_protection_state(protection, generation, "pending")
        try:
            if inspection is None:
                run(command)
                inspection = container_inspect(config["container_name"])
            else:
                require_matching_container(
                    inspection,
                    manifest,
                    role["port_base"],
                    manifest_sha256=config["manifest_sha256"],
                    runtime_digest=config["runtime_digest"],
                )
                labels = inspection.get("Config", {}).get("Labels") or {}
                expected_labels = {
                    GROUP_ID_LABEL: config["group_id"],
                    GROUP_MEMBER_LABEL: config["member_id"],
                    GROUP_ROLE_LABEL: role["name"],
                }
                if any(labels.get(key) != value for key, value in expected_labels.items()):
                    raise LetsInferError("existing container has a different engine-group identity")
                if not inspection.get("State", {}).get("Running", False):
                    run(["docker", "start", config["container_name"]])
                    inspection = container_inspect(config["container_name"])
            if inspection is None:
                raise LetsInferError("engine-group container disappeared during start")
            publish_protection_state(
                protection, generation, "starting", inspection=inspection
            )
            if role["launcher"] == "manifest":
                wait_for_ready(
                    config["container_name"],
                    role["port_base"],
                    manifest["container"]["startup_timeout_seconds"],
                    pathlib.Path(config["tls_certificate_file"]),
                    manifest,
                )
            else:
                self._wait_runtime_command(config["container_name"], role["readiness"])
            if role["inference_endpoint"] and not model_identity_ready(
                manifest,
                role["port_base"],
                pathlib.Path(config["tls_certificate_file"]),
                pathlib.Path(config["credential_file"]),
            ):
                raise LetsInferError("engine-group model identity does not match its release")
            if role["inference_endpoint"] and role["launcher"] == "manifest":
                prewarm(
                    manifest,
                    config["container_name"],
                    role["port_base"],
                    pathlib.Path(config["tls_certificate_file"]),
                    pathlib.Path(config["credential_file"]),
                )
            require_memory_reserve(manifest, phase="runtime")
            inspection = container_inspect(config["container_name"])
            if inspection is None:
                raise LetsInferError("engine-group container disappeared before protection armed")
            publish_protection_state(
                protection, generation, "armed", inspection=inspection
            )
            return self._safe_result(config, "running")
        except BaseException:
            if not protection_trip_latched(protection):
                disarm_protection(protection, wait_for_ack=False)
            inspection = container_inspect(config["container_name"])
            if inspection is not None:
                run(["docker", "update", "--restart", "no", config["container_name"]], check=False)
                run(["docker", "stop", "--time", "30", config["container_name"]], check=False)
                run(["docker", "rm", config["container_name"]], check=False)
            raise

    def observe(self, group: Mapping[str, Any]) -> Mapping[str, Any]:
        """Report actual process/protection readiness, not only journal intent."""
        group_id = str(group.get("group_id", ""))
        config = _read_engine_group_config(group_id)
        for key in (
            "member_id", "plan_sha256", "runtime_digest", "manifest_sha256",
            "topology_sha256", "engine_credential_sha256",
        ):
            expected = (
                config["_credential_sha256"]
                if key == "engine_credential_sha256"
                else config[key]
            )
            if group.get(key) != expected:
                raise LetsInferError(
                    "engine-group observation journal differs from staged state"
                )
        if group.get("role") != config["role"]:
            raise LetsInferError(
                "engine-group observation role differs from staged state"
            )
        stored_state = str(group.get("state", ""))
        if stored_state == "removed":
            return {"state": "removed", "protection_trip_latched": False}
        inspection = container_inspect(config["container_name"])
        protection = protection_status(config, inspection)
        trip_latched = bool(protection["trip_latched"])
        if trip_latched:
            return {"state": "failed", "protection_trip_latched": True}
        running = bool(
            inspection is not None
            and inspection.get("State", {}).get("Running") is True
        )
        if not running:
            state = stored_state if stored_state in {"staged", "stopped"} else "failed"
            return {"state": state, "protection_trip_latched": False}
        if stored_state != "running" or not protection["armed"]:
            return {"state": "failed", "protection_trip_latched": False}
        role = config["role"]
        if role["launcher"] == "manifest":
            ready = health_ready(
                role["port_base"], pathlib.Path(config["tls_certificate_file"])
            )
        else:
            ready = run(
                [
                    "docker", "exec", config["container_name"],
                    *role["readiness"]["command"],
                ],
                check=False,
            ).returncode == 0
        return {
            "state": "running" if ready else "failed",
            "protection_trip_latched": False,
        }

    def recover(self, job: Mapping[str, Any]) -> Mapping[str, Any]:
        """Explicitly acknowledge this slot's durable trip and restart it."""
        config = _read_engine_group_config(job["group_id"])
        self._assert_job_matches_config(job, config)
        clear_protection_trip(config)
        return self._start_config(config)

    def stop(self, job: Mapping[str, Any]) -> Mapping[str, Any]:
        config = _read_engine_group_config(job["group_id"])
        self._assert_job_matches_config(job, config)
        protection = {
            "protection_root": config["protection_root"],
            "name": config["container_name"],
        }
        disarm_protection(protection)
        _stop_managed_container(
            config["container_name"], pathlib.Path(config["credential_file"])
        )
        return self._safe_result(config, "stopped")

    def remove(self, job: Mapping[str, Any]) -> Mapping[str, Any]:
        config = _read_engine_group_config(job["group_id"])
        self._assert_job_matches_config(job, config)
        if container_inspect(config["container_name"]) is not None:
            raise LetsInferError("engine-group container must be stopped before removal")
        result = self._safe_result(config, "removed")
        protection_root = pathlib.Path(config["protection_root"])
        expected_protection_root = (
            default_watchdog_data_root()
            / PROTECTION_ROOT_NAME
            / job["group_id"]
        )
        if protection_root.exists():
            if (
                protection_root.resolve(strict=True)
                != expected_protection_root.resolve(strict=True)
                or protection_trip_latched({"protection_root": str(protection_root)})
            ):
                raise LetsInferError("refusing to remove an unsafe engine-group protection slot")
            state_path, _, _ = protection_paths(
                {"protection_root": str(protection_root)}
            )
            if (
                state_path.is_file()
                and _parse_protection_lines(state_path).get("phase") != "disarmed"
            ):
                raise LetsInferError("engine-group protection must be disarmed before removal")
        root = _engine_group_path(job["group_id"])
        if root.resolve(strict=True) != (default_engine_group_root() / job["group_id"]).resolve(strict=True):
            raise LetsInferError("refusing to remove a non-canonical engine-group directory")
        shutil.rmtree(root)
        _fsync_path(root.parent)
        if protection_root.exists():
            shutil.rmtree(protection_root)
            _fsync_path(protection_root.parent)
        return result


def _refresh_site_links_once() -> dict[str, list[str]]:
    """Renew every configured directional link proof without changing topology."""
    identity = read_site_identity()
    if identity.role != "coordinator":
        raise LetsInferError("site link renewal is coordinator-only")
    with _site_store() as store:
        members = {
            row["member_id"]: row
            for row in store.members()
            if row["state"] == "active"
        }
    tasks: list[tuple[dict[str, Any], dict[str, Any], dict[str, Any]]] = []
    for subject_id in sorted(members):
        subject = members[subject_id]
        facts = subject.get("facts")
        if not isinstance(facts, dict):
            continue
        links = facts.get("network", {}).get("links", [])
        if not isinstance(links, list):
            raise LetsInferError(f"member {subject_id} link facts are invalid")
        for link in links:
            if not isinstance(link, dict):
                raise LetsInferError(f"member {subject_id} link facts are invalid")
            peer = members.get(link.get("peer_member_id"))
            if peer is not None:
                tasks.append((subject, peer, link))
    refreshed: list[str] = []
    failed: list[str] = []
    for subject, peer, link in tasks:
        label = f"{subject['member_id']}->{peer['member_id']}"
        if link.get("peer_certificate_sha256") != peer["certificate_sha256"]:
            failed.append(label)
            continue
        try:
            request_member_link_probe(
                _site_control_endpoint(subject["address"]),
                expected_member_id=subject["member_id"],
                expected_certificate_sha256=subject["certificate_sha256"],
                peer_endpoint=_site_control_endpoint(peer["address"]),
                peer_member_id=peer["member_id"],
                peer_certificate_sha256=peer["certificate_sha256"],
                interface=str(link.get("interface", "")),
                kind=str(link.get("kind", "")),
            )
            refreshed.append(label)
        except ControlError:
            failed.append(label)
    return {"refreshed": refreshed, "failed": failed}


def _accept_local_telemetry(
    state: SiteControlState, document: Mapping[str, Any], member_id: str
) -> None:
    try:
        state.accept_telemetry(document, requester_member_id=member_id)
    except ControlError as error:
        raise TelemetryError(str(error)) from error


def _current_controller_placements(
    placements: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Return one current placement per logical model for controller clients."""
    state_priority = {
        "failed": 0,
        "stopped": 1,
        "draining": 2,
        "starting": 3,
        "running": 4,
    }
    current: dict[str, tuple[tuple[int, int, str], dict[str, Any]]] = {}
    for placement in placements:
        model = placement.get("model")
        placement_id = placement.get("placement_id")
        updated_at = placement.get("updated_at_unix")
        state = placement.get("state")
        if (
            not isinstance(model, str)
            or not isinstance(placement_id, str)
            or not isinstance(updated_at, int)
            or isinstance(updated_at, bool)
            or state not in state_priority
        ):
            raise LetsInferError("controller placement record is invalid")
        candidate = (updated_at, state_priority[state], placement_id)
        previous = current.get(model)
        if previous is None or candidate > previous[0]:
            current[model] = (candidate, dict(placement))
    return [current[model][1] for model in sorted(current)]


def site_agent_command(arguments: argparse.Namespace) -> int:
    identity = read_site_identity()
    link_store = LinkStore(identity)
    telemetry = TelemetryAggregator() if identity.role == "coordinator" else None
    try:
        group_executor = LocalEngineGroupExecutor(identity.member_id)
        member_agent = MemberAgent(
            member_id=identity.member_id,
            handler=group_executor,
            observer=group_executor.observe,
        )
    except (MemberJobError, LetsInferError) as error:
        raise LetsInferError(f"cannot initialize member lifecycle agent: {error}") from error

    def local_facts() -> dict[str, Any]:
        try:
            return collect_local_facts(
                identity.member_id,
                host_device_fingerprint(),
                data_path=site_data_root(),
                protection_trip_path=default_watchdog_data_root() / PROTECTION_ROOT_NAME,
                memory_pressure_available_bytes=active_memory_pressure_available_bytes(),
                product_version=PRODUCT_VERSION,
                links=link_store.facts(),
            )
        except (InventoryError, LinkError, SiteError) as error:
            raise ControlError(str(error)) from error

    def adopt_fresh_member(document: Mapping[str, Any]) -> Mapping[str, Any]:
        try:
            prepared = prepare_local_move(
                endpoint=str(document["destination_endpoint"]),
                invite_id=str(document["destination_invite_id"]),
                code=None,
                coordinator_certificate_sha256=str(
                    document["destination_coordinator_certificate_sha256"]
                ),
                member_name=socket.gethostname(),
                member_address=str(document["source_member_address"]),
            )
            replacement = _apply_controller_site_move(prepared)
        except (KeyError, SiteError, LetsInferError) as error:
            raise ControlError(str(error)) from error
        return {
            "protocol": ADOPTION_PROTOCOL,
            "state": "committed",
            "source_site_id": identity.site_id,
            "destination_site_id": replacement.site_id,
            "member_id": replacement.member_id,
            "move_id": prepared.move_id,
        }

    def adoption_completed(result: Mapping[str, Any]) -> None:
        _controller_administration_completed(
            "site.move.commit", {"move": {"move_id": result.get("move_id")}}
        )

    state = SiteControlState(
        identity,
        facts_provider=local_facts,
        link_store=link_store,
        telemetry=telemetry,
        member_agent=member_agent,
        adoption_provider=(adopt_fresh_member if identity.role == "coordinator" else None),
        adoption_completed_provider=(
            adoption_completed if identity.role == "coordinator" else None
        ),
    )

    def controller_site_document() -> dict[str, Any]:
        if telemetry is None:
            raise ControllerError("site aggregation is unavailable on a member")
        with _site_store() as store:
            rows = store.members()
            placements = _current_controller_placements(store.placements())
            plans = store.topology_plans()
            exposure = store.exposure()
        telemetry.reconcile_members(
            {
                row["member_id"]
                for row in rows
                if row["state"] in {"active", "draining"}
            }
        )
        members = [
            {
                key: row[key]
                for key in (
                    "member_id", "display_name", "role", "address", "state",
                    "certificate_sha256", "facts", "facts_sha256",
                    "joined_at_unix", "updated_at_unix",
                )
            }
            for row in rows
        ]
        safe_placements = []
        for placement in placements:
            safe = dict(placement)
            safe["endpoints"] = [
                {
                    key: endpoint[key]
                    for key in (
                        "member_id", "url", "max_active_requests",
                        "max_context_tokens", "healthy", "memory_pressure",
                        "temperature_c", "prefix_keys",
                    )
                    if key in endpoint
                }
                for endpoint in placement["endpoints"]
            ]
            safe_placements.append(safe)
        active = [row for row in rows if row["state"] == "active" and row["facts"]]
        try:
            graph = TopologyGraph(
                [row["facts"] for row in active],
                member_certificates={
                    row["member_id"]: row["certificate_sha256"] for row in active
                },
            )
            topology_document: dict[str, Any] = {
                **graph.document(), "topology_sha256": graph.sha256(), "valid": True,
            }
        except TopologyError as error:
            topology_document = {"valid": False, "error": str(error)}
        return {
            "schema_version": 1,
            "identity": identity_json(identity),
            "members": members,
            "topology": topology_document,
            "placements": safe_placements,
            "pending_topology_plans": plans,
            "exposure": exposure or {
                "provider": "tailscale-funnel",
                "public_url": "",
                "state": "disabled",
                "inference_target": PUBLIC_INFERENCE_TARGET,
                "configuration_sha256": "0" * 64,
                "updated_at_unix": 0,
            },
        }

    controller_server: ControllerServer | None = None
    controller_state: ControllerState | None = None
    controller_thread: threading.Thread | None = None
    site_administration: SiteAdministration | None = None
    if identity.role == "coordinator":
        controller_paths = (
            default_watchdog_cert_path(),
            default_watchdog_key_path(),
            default_watchdog_controller_ca_path(),
        )
        existing = [path.exists() for path in controller_paths]
        if any(existing) and not all(existing):
            raise LetsInferError("private controller TLS material is incomplete")
        if all(existing):
            try:
                site_administration = SiteAdministration(
                    identity, move_apply=_apply_controller_site_move
                )
                controller_state = ControllerState(
                    identity,
                    telemetry,
                    site_provider=controller_site_document,
                    action_provider=_controller_site_action,
                    administration_provider=lambda principal, action, payload: (
                        site_administration.perform(
                            controller_id=principal.controller_id,
                            action=action,
                            payload=payload,
                        )
                    ),
                    administration_completed_provider=(
                        _controller_administration_completed
                    ),
                )
                controller_server = ControllerServer(
                    (arguments.listen, CONTROLLER_CONTROL_PORT),
                    controller_state,
                    context=controller_tls_context(*controller_paths),
                )
            except (ControllerError, OSError, ssl.SSLError) as error:
                if controller_state is not None:
                    controller_state.close()
                raise LetsInferError(
                    f"cannot start private controller listener: {error}"
                ) from error
    try:
        server = SiteControlServer((arguments.listen, arguments.port), state)
    except (ControlError, OSError, ssl.SSLError) as error:
        if controller_server is not None:
            controller_server.server_close()
        raise LetsInferError(f"cannot start private site control listener: {error}") from error
    try:
        try:
            select_direct_connectx_interface()
            direct_connectx = True
        except InventoryError:
            direct_connectx = False
        adoptable = False
        if identity.role == "coordinator" and direct_connectx:
            with _site_store() as store:
                adoptable = bool(store.adoption()["eligible"])
        publisher = DiscoveryPublisher(
            discovery_publisher_command(
                discovery_advertisement(
                    identity,
                    port=arguments.port,
                    certificate_sha256=state.certificate_sha256,
                    direct_connectx=direct_connectx,
                    adoptable=adoptable,
                )
            )
        )
        publisher.start()
    except ControlError as error:
        server.server_close()
        if controller_server is not None:
            controller_server.server_close()
        raise LetsInferError(str(error)) from error
    try:
        telemetry_publisher = TelemetryPublisher(
            identity,
            default_watchdog_data_root() / "raw.ring",
            local_accept=(
                lambda document, member_id: _accept_local_telemetry(
                    state, document, member_id
                )
            )
            if identity.role == "coordinator"
            else None,
            endpoint=(
                None
                if identity.role == "coordinator"
                else _site_control_endpoint(identity.coordinator_address)
            ),
        )
        telemetry_publisher.start()
    except TelemetryError as error:
        publisher.stop()
        server.server_close()
        if controller_server is not None:
            controller_server.server_close()
        raise LetsInferError(str(error)) from error
    try:
        facts_publisher = FactsPublisher(
            identity,
            state.facts,
            local_accept=(
                lambda document, member_id: state.accept_facts(
                    document, requester_member_id=member_id
                )
            )
            if identity.role == "coordinator"
            else None,
            endpoint=(
                None
                if identity.role == "coordinator"
                else _site_control_endpoint(identity.coordinator_address)
            ),
        )
        facts_publisher.start()
    except ControlError as error:
        telemetry_publisher.close()
        publisher.stop()
        server.server_close()
        if controller_server is not None:
            controller_server.server_close()
        raise LetsInferError(str(error)) from error
    if controller_server is not None:
        controller_thread = threading.Thread(
            target=controller_server.serve_forever,
            kwargs={"poll_interval": 0.5},
            name="letsinfer-controller-control",
            daemon=True,
        )
        controller_thread.start()
    stopped = threading.Event()
    publisher_failed: list[bool] = []
    orchestration_failed: list[str] = []
    link_monitor_failed: list[str] = []

    def monitor_site_links() -> None:
        if identity.role != "coordinator":
            return
        while not stopped.wait(10.0):
            try:
                # Per-link network failures are returned, not raised. Their
                # proofs expire naturally and distributed admission fails
                # closed while the coordinator remains usable.
                _refresh_site_links_once()
            except (ControlError, LetsInferError, LinkError, SiteError):
                continue
            except Exception as error:
                link_monitor_failed.append(type(error).__name__)
                server.shutdown()
                return

    link_thread = threading.Thread(
        target=monitor_site_links,
        name="letsinfer-link-monitor",
        daemon=True,
    )
    link_thread.start()

    def monitor_engine_groups() -> None:
        if identity.role != "coordinator":
            return
        while not stopped.wait(10.0):
            try:
                reconcile_engine_groups_once()
            except (ControlError, LetsInferError, SiteError):
                continue
            except Exception as error:
                orchestration_failed.append(type(error).__name__)
                server.shutdown()
                return

    orchestration_thread = threading.Thread(
        target=monitor_engine_groups,
        name="letsinfer-group-monitor",
        daemon=True,
    )
    orchestration_thread.start()

    def monitor_publisher() -> None:
        while not stopped.wait(1.0):
            if not publisher.alive() or (
                controller_thread is not None and not controller_thread.is_alive()
            ):
                publisher_failed.append(True)
                server.shutdown()
                return

    monitor = threading.Thread(target=monitor_publisher, daemon=True)
    monitor.start()
    print(
        f"SITE CONTROL role={identity.role} member={identity.member_id} "
        f"listen={arguments.listen}:{arguments.port}",
        flush=True,
    )
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        stopped.set()
        facts_publisher.close()
        telemetry_publisher.close()
        if controller_server is not None:
            controller_server.shutdown()
            controller_server.server_close()
        if controller_state is not None:
            controller_state.close()
        if controller_thread is not None:
            controller_thread.join(timeout=2)
        publisher.stop()
        server.server_close()
        monitor.join(timeout=2)
        link_thread.join(timeout=2)
        orchestration_thread.join(timeout=2)
        member_agent.close()
    if publisher_failed:
        raise LetsInferError("DNS-SD publisher exited while the site agent was active")
    if orchestration_failed:
        raise LetsInferError(
            "engine-group health monitor failed: " + orchestration_failed[-1]
        )
    if link_monitor_failed:
        raise LetsInferError(
            "site link monitor failed: " + link_monitor_failed[-1]
        )
    return 0


def topology_command(arguments: argparse.Namespace) -> int:
    _identity, graph = _fresh_site_topology()
    document = graph.document()
    document["topology_sha256"] = graph.sha256()
    print(json.dumps(document, sort_keys=True, indent=None if arguments.json else 2))
    return 0


def _topology_plan_document(
    model: str,
    engine: str | None,
    catalog_location: str | None,
    *,
    actor_type: str = "local-user",
    actor_id: str | None = None,
    origin_interface: str = "cli",
    correlation_id: str | None = None,
) -> dict[str, Any]:
    location = resolved_catalog_location(catalog_location)
    if location is None:
        raise LetsInferError("topology planning requires --catalog or LETSINFER_CATALOG")
    try:
        catalog = load_catalog(location)
    except RuntimePackError as error:
        raise LetsInferError(str(error)) from error
    topology = _fresh_site_topology()
    release, choice = _catalog_site_release(
        catalog, model, engine, topology=topology
    )
    target_id, target_sha256, selected_engine, version, source = release
    identity, graph = topology
    source_digest = source.rsplit("@sha256:", 1)[1]
    desired_runtime = (
        f"{model}/{selected_engine}/{target_id}@{version}"
        f"@sha256:{source_digest}"
    )
    with _site_store() as store:
        current = [
            row
            for row in store.placements()
            if row["model"] == model and row["state"] in {"starting", "running"}
        ]
    desired_members = list(choice.placement.member_ids)
    matching = [
        row
        for row in current
        if row["target"] == target_id
        and row["strategy"] == choice.placement.strategy
        and row["members"] == desired_members
        and row["runtime"] == desired_runtime
    ]
    document = {
        "schema_version": 1,
        "site_id": identity.site_id,
        "model": model,
        "engine": selected_engine,
        "runtime_version": version,
        "runtime_identity": desired_runtime,
        "runtime_source": source,
        "target": target_id,
        "target_contract_sha256": target_sha256,
        "topology_sha256": graph.sha256(),
        "placement": {
            "strategy": choice.placement.strategy,
            "members": desired_members,
            "engine_coordinator_id": choice.placement.engine_coordinator_id,
            "reason": choice.placement.reason,
        },
        "current_placement_ids": [row["placement_id"] for row in current],
        "change_required": not bool(matching),
        "automatic_restart": False,
    }
    if document["change_required"]:
        proposed = {
            key: document[key]
            for key in (
                "schema_version", "site_id", "model", "engine", "runtime_version",
                "runtime_identity", "runtime_source", "target",
                "target_contract_sha256", "topology_sha256", "placement",
                "automatic_restart",
            )
        }
        with _site_store() as store:
            plan = store.create_topology_plan(
                model,
                current=current,
                proposed=proposed,
                actor_type=actor_type,
                actor_id=actor_id,
                origin_interface=origin_interface,
                correlation_id=correlation_id,
            )
        document["plan_id"] = plan["plan_id"]
        document["plan_sha256"] = plan["proposed_sha256"]
    else:
        document["plan_id"] = None
        document["plan_sha256"] = None
    return document


def topology_plan_command(arguments: argparse.Namespace) -> int:
    document = _topology_plan_document(
        arguments.model, arguments.engine, arguments.catalog
    )
    if arguments.json:
        print(json.dumps(document, sort_keys=True))
    else:
        print(
            f"PLAN model={document['model']} engine={document['engine']} "
            f"target={document['target']} strategy={document['placement']['strategy']} "
            f"members={','.join(document['placement']['members'])} "
            f"change_required={str(document['change_required']).lower()} "
            f"plan={document['plan_id'] or 'none'} restart=manual"
        )
    return 0


def topology_probe_command(arguments: argparse.Namespace) -> int:
    if arguments.left == arguments.right:
        raise LetsInferError("topology link endpoints must be different members")
    with _site_store() as store:
        members = {
            row["member_id"]: row
            for row in store.members()
            if row["state"] == "active"
        }
    try:
        left = members[arguments.left]
        right = members[arguments.right]
    except KeyError as error:
        raise LetsInferError(f"topology link member is not active: {error.args[0]}") from error
    directions = (
        (left, right, arguments.left_interface),
        (right, left, arguments.right_interface),
    )
    links: list[dict[str, Any]] = []
    for subject, peer, interface in directions:
        try:
            links.append(
                request_member_link_probe(
                    _site_control_endpoint(subject["address"]),
                    expected_member_id=subject["member_id"],
                    expected_certificate_sha256=subject["certificate_sha256"],
                    peer_endpoint=_site_control_endpoint(peer["address"]),
                    peer_member_id=peer["member_id"],
                    peer_certificate_sha256=peer["certificate_sha256"],
                    interface=interface,
                    kind=arguments.kind,
                )
            )
        except ControlError as error:
            raise LetsInferError(str(error)) from error
    synchronized = _synchronize_member_facts()
    if synchronized["failed"]:
        raise LetsInferError(
            "link proof succeeded but authenticated fact refresh failed for: "
            + ",".join(synchronized["failed"])
        )
    result = {"links": links, "refreshed": synchronized["refreshed"]}
    print(json.dumps(result, sort_keys=True, indent=None if arguments.json else 2))
    return 0


def alias_list_command(arguments: argparse.Namespace) -> int:
    with _site_store() as store:
        aliases = store.aliases()
    if arguments.json:
        print(json.dumps(aliases, sort_keys=True))
    else:
        for alias, model in aliases.items():
            print(f"{alias}\t{model}")
    return 0


def alias_set_command(arguments: argparse.Namespace) -> int:
    with _site_store() as store:
        try:
            value = store.set_alias(arguments.alias, arguments.model)
        except SiteError as error:
            raise LetsInferError(str(error)) from error
    print(json.dumps(value, sort_keys=True) if arguments.json else f"ALIAS {value['alias']} -> {value['model']}")
    return 0


def alias_remove_command(arguments: argparse.Namespace) -> int:
    with _site_store() as store:
        try:
            value = store.remove_alias(arguments.alias)
        except SiteError as error:
            raise LetsInferError(str(error)) from error
    print(json.dumps(value, sort_keys=True) if arguments.json else f"REMOVED ALIAS {value['alias']}")
    return 0


def _require_public_gateway() -> dict[str, Any]:
    config_path = site_config_root() / "gateway.json"
    try:
        config = read_json(config_path)
    except (OSError, json.JSONDecodeError) as error:
        raise LetsInferError("the coordinator gateway is not configured") from error
    required = {
        "schema_version", "gateway_listen", "gateway_protocol", "gateway_port",
        "gateway_max_connections", "gateway_queue_timeout_seconds",
        "gateway_telemetry_file",
    }
    if (
        set(config) != required
        or type(config.get("schema_version")) is not int
        or config.get("schema_version") != 2
        or config.get("gateway_port") != 8000
        or config.get("gateway_listen") != "0.0.0.0"
        or config.get("gateway_protocol") != "http"
    ):
        raise LetsInferError("the coordinator gateway configuration is not public-edge safe")
    _, active = _unit_enabled_active(GATEWAY_SERVICE_NAME)
    if active != "active":
        raise LetsInferError("the coordinator gateway must be active before exposure")
    if api_status(8000, "/health", None) != 200:
        raise LetsInferError("the coordinator gateway health check failed")
    return config


def exposure_status_command(arguments: argparse.Namespace) -> int:
    with _site_store() as store:
        value = store.exposure()
    result = value or {
        "provider": "tailscale-funnel",
        "public_url": "",
        "state": "disabled",
        "inference_target": PUBLIC_INFERENCE_TARGET,
        "configuration_sha256": "0" * 64,
        "updated_at_unix": 0,
    }
    verified = True
    if result["state"] == "enabled":
        try:
            live = verify_tailscale(result["configuration_sha256"])
            verified = (
                live.public_url == result["public_url"]
                and live.inference_target == result["inference_target"]
            )
        except ExposureError:
            verified = False
    result = {**result, "provider_verified": verified}
    if arguments.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(
            f"EXPOSURE {result['state']} provider={result['provider']} "
            f"url={result['public_url'] or '-'}"
        )
    return 0 if verified else 1


def _enable_public_exposure(
    *,
    actor_type: str = "local-user",
    actor_id: str | None = None,
    origin_interface: str = "cli",
    correlation_id: str | None = None,
) -> dict[str, Any]:
    _require_public_gateway()
    with _site_store() as store:
        current = store.exposure()
        if current is not None and current["state"] == "enabled":
            raise LetsInferError(
                f"public inference is already exposed at {current['public_url']}"
            )
    try:
        result = enable_tailscale()
    except ExposureError as error:
        with _site_store() as store:
            store.record_action(
                "exposure.enable",
                "tailscale-funnel",
                "failed",
                type(error).__name__,
                actor_type=actor_type,
                actor_id=actor_id,
                origin_interface=origin_interface,
                correlation_id=correlation_id,
            )
        raise LetsInferError(str(error)) from error
    try:
        with _site_store() as store:
            value = store.set_exposure(
                provider=result.provider,
                public_url=result.public_url,
                state="enabled",
                inference_target=result.inference_target,
                configuration_sha256=result.configuration_sha256,
                actor_type=actor_type,
                actor_id=actor_id,
                origin_interface=origin_interface,
                correlation_id=correlation_id,
            )
    except BaseException as error:
        try:
            disable_tailscale(result.configuration_sha256)
        except ExposureError as rollback_error:
            raise LetsInferError(
                "exposure state failed and Funnel rollback was incomplete"
            ) from rollback_error
        raise LetsInferError("exposure state could not be committed") from error
    return value


def expose_command(arguments: argparse.Namespace) -> int:
    value = _enable_public_exposure()
    print(
        json.dumps(value, sort_keys=True)
        if arguments.json
        else f"EXPOSED {value['public_url']} provider={value['provider']}"
    )
    return 0


def _disable_public_exposure(
    *,
    actor_type: str = "local-user",
    actor_id: str | None = None,
    origin_interface: str = "cli",
    correlation_id: str | None = None,
) -> dict[str, Any]:
    with _site_store() as store:
        current = store.exposure()
    if current is None or current["state"] != "enabled":
        raise LetsInferError("public inference is not enabled")
    if current["provider"] != "tailscale-funnel":
        raise LetsInferError("the configured exposure provider is unsupported")
    try:
        disable_tailscale(current["configuration_sha256"])
    except ExposureError as error:
        with _site_store() as store:
            store.record_action(
                "exposure.disable",
                current["provider"],
                "failed",
                type(error).__name__,
                actor_type=actor_type,
                actor_id=actor_id,
                origin_interface=origin_interface,
                correlation_id=correlation_id,
            )
        raise LetsInferError(str(error)) from error
    try:
        with _site_store() as store:
            value = store.set_exposure(
                provider=current["provider"],
                public_url="",
                state="disabled",
                inference_target=PUBLIC_INFERENCE_TARGET,
                configuration_sha256="0" * 64,
                actor_type=actor_type,
                actor_id=actor_id,
                origin_interface=origin_interface,
                correlation_id=correlation_id,
            )
    except BaseException as error:
        try:
            restored = enable_tailscale()
            if (
                restored.public_url != current["public_url"]
                or restored.configuration_sha256
                != current["configuration_sha256"]
            ):
                raise ExposureError("restored Funnel identity changed")
        except ExposureError as rollback_error:
            raise LetsInferError(
                "exposure disable failed and Funnel rollback was incomplete"
            ) from rollback_error
        raise LetsInferError("disabled exposure state could not be committed") from error
    return value


def unexpose_command(arguments: argparse.Namespace) -> int:
    value = _disable_public_exposure()
    print(
        json.dumps(value, sort_keys=True)
        if arguments.json
        else "PUBLIC INFERENCE DISABLED"
    )
    return 0


def gateway_command(arguments: argparse.Namespace) -> int:
    from .gateway.server import run_gateway
    return run_gateway(arguments)


def key_create_command(arguments: argparse.Namespace) -> int:
    with _site_store() as store:
        try:
            metadata, token = store.create_key(
                arguments.name,
                models=arguments.model,
                expires_at_unix=arguments.expires_at,
                requests_per_minute=arguments.requests_per_minute,
                tokens_per_minute=arguments.tokens_per_minute,
                concurrency_limit=arguments.concurrency,
                context_limit=arguments.max_context,
                tenant=arguments.tenant,
                application=arguments.application,
            )
        except SiteError as error:
            raise LetsInferError(str(error)) from error
    output = {"key": metadata, "token": token, "token_shown_once": True}
    if arguments.json:
        print(json.dumps(output, sort_keys=True))
    else:
        print(f"KEY {metadata['name']} id={metadata['key_id']}")
        print(token)
        print("This token is shown once. Store it now.", file=sys.stderr)
    return 0


def key_list_command(arguments: argparse.Namespace) -> int:
    with _site_store() as store:
        rows = store.keys()
    if arguments.json:
        print(json.dumps(rows, sort_keys=True))
    else:
        for row in rows:
            state = "revoked" if row["revoked_at_unix"] is not None else "active"
            print(f"{row['key_id']}\t{row['name']}\t{state}\tmodels={','.join(row['models']) or '*'}")
    return 0


def key_show_command(arguments: argparse.Namespace) -> int:
    with _site_store() as store:
        try:
            row = store.key(arguments.key)
        except SiteError as error:
            raise LetsInferError(str(error)) from error
    print(json.dumps(row, sort_keys=True, indent=2 if not arguments.json else None))
    return 0


def key_revoke_command(arguments: argparse.Namespace) -> int:
    with _site_store() as store:
        try:
            row = store.revoke_key(arguments.key)
        except SiteError as error:
            raise LetsInferError(str(error)) from error
    print(json.dumps(row, sort_keys=True) if arguments.json else f"REVOKED {row['name']} id={row['key_id']}")
    return 0


def key_rotate_command(arguments: argparse.Namespace) -> int:
    with _site_store() as store:
        try:
            row, token = store.rotate_key(arguments.key)
        except SiteError as error:
            raise LetsInferError(str(error)) from error
    output = {"key": row, "token": token, "token_shown_once": True}
    if arguments.json:
        print(json.dumps(output, sort_keys=True))
    else:
        print(f"ROTATED {arguments.key} -> {row['name']} id={row['key_id']}")
        print(token)
        print("This token is shown once. Store it now.", file=sys.stderr)
    return 0


def key_policy_command(arguments: argparse.Namespace) -> int:
    with _site_store() as store:
        try:
            row = store.update_key_policy(
                arguments.key,
                models=arguments.model,
                expires_at_unix=arguments.expires_at,
                requests_per_minute=arguments.requests_per_minute,
                tokens_per_minute=arguments.tokens_per_minute,
                concurrency_limit=arguments.concurrency,
                context_limit=arguments.max_context,
                tenant=arguments.tenant,
                application=arguments.application,
            )
        except SiteError as error:
            raise LetsInferError(str(error)) from error
    print(json.dumps(row, sort_keys=True, indent=2 if not arguments.json else None))
    return 0


def audit_list_command(arguments: argparse.Namespace) -> int:
    with _site_store() as store:
        try:
            rows = store.audit_rows(limit=arguments.limit)
        except SiteError as error:
            raise LetsInferError(str(error)) from error
    if arguments.json:
        print(json.dumps(rows, sort_keys=True))
    else:
        for row in rows:
            timestamp = dt.datetime.fromtimestamp(
                row["timestamp_unix_ns"] / 1_000_000_000, tz=dt.timezone.utc
            ).isoformat()
            print(f"{row['sequence']}\t{timestamp}\t{row['outcome']}\t{row['action']}\t{row['target']}")
    return 0


def audit_show_command(arguments: argparse.Namespace) -> int:
    with _site_store() as store:
        rows = store.audit_rows(event_id=arguments.event)
    if not rows:
        raise LetsInferError(f"audit event is not registered: {arguments.event}")
    print(json.dumps(rows[0], sort_keys=True, indent=2 if not arguments.json else None))
    return 0


def audit_verify_command(arguments: argparse.Namespace) -> int:
    with _site_store() as store:
        try:
            result = store.verify_audit()
        except SiteError as error:
            raise LetsInferError(str(error)) from error
    print(json.dumps(result, sort_keys=True) if arguments.json else f"AUDIT OK events={result['events']} head=sha256:{result['head_sha256']}")
    return 0


def audit_export_command(arguments: argparse.Namespace) -> int:
    with _site_store() as store:
        verification = store.verify_audit()
        exported_at = time.time_ns()
        site_id = read_site_identity().site_id
        output = pathlib.Path(arguments.output).expanduser() if arguments.output else None
        temporary: pathlib.Path | None = None
        if output is None:
            handle = sys.stdout.buffer
        else:
            ensure_private_directory(output.parent)
            temporary = output.with_name(
                f".{output.name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
            )
            descriptor = os.open(
                temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
            )
            handle = os.fdopen(descriptor, "wb")
        count = 0
        try:
            try:
                handle.write(b'{"events":[')
                for row in store.iter_audit_rows():
                    if count:
                        handle.write(b",")
                    handle.write(canonical_bytes(row).rstrip(b"\n"))
                    count += 1
                suffix = {
                    "exported_at_unix_ns": exported_at,
                    "schema_version": 1,
                    "site_id": site_id,
                    "verification": verification,
                }
                encoded_suffix = canonical_bytes(suffix).rstrip(b"\n")
                handle.write(b"]," + encoded_suffix[1:] + b"\n")
                handle.flush()
                if output is not None:
                    os.fsync(handle.fileno())
            finally:
                if output is not None:
                    handle.close()
            if output is not None and temporary is not None:
                temporary.replace(output)
                output.chmod(0o600)
                _fsync_path(output.parent)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        if output is not None:
            print(f"EXPORTED {count} events to {output}")
    return 0


def _parser_action_ids(root: argparse.ArgumentParser) -> list[str]:
    found: list[str] = []
    for entry in root._actions:  # argparse has no public subparser traversal API.
        if not isinstance(entry, argparse._SubParsersAction):
            continue
        for child in entry.choices.values():
            action_id = child.get_default("action_id")
            if action_id is not None:
                if action_id not in ACTIONS:
                    raise LetsInferError(f"CLI parser uses unregistered action {action_id}")
                child.epilog = (
                    f"Execution scope: {command_action(action_id).scope.value}. "
                    f"Mutation class: {command_action(action_id).mutation.value}."
                )
                found.append(action_id)
            found.extend(_parser_action_ids(child))
    if len(found) != len(set(found)):
        raise LetsInferError("CLI parser contains duplicate action identifiers")
    return found


def _authorize_command(arguments: argparse.Namespace) -> tuple[Any, Any]:
    action_id = getattr(arguments, "action_id", None)
    if not isinstance(action_id, str):
        raise LetsInferError("CLI leaf command has no explicit execution scope")
    try:
        metadata = command_action(action_id)
    except ValueError as error:
        raise LetsInferError(str(error)) from error
    identity = None
    if metadata.requires_site or site_identity_path().exists():
        try:
            identity = read_site_identity()
        except SiteError as error:
            if metadata.requires_site:
                raise LetsInferError(
                    "this command requires a configured site; run `letsinfer setup` first"
                ) from error
    if identity is not None:
        allowed = (
            metadata.scope is CommandScope.ALL
            or metadata.scope.value == identity.role
        )
        if not allowed:
            reason = (
                f"command scope is {metadata.scope.value}; local role is {identity.role}; "
                f"coordinator={identity.coordinator_id}@{identity.coordinator_address}"
            )
            if identity.role == "coordinator":
                try:
                    with SiteStore(identity=identity) as store:
                        store.record_denied(action_id, action_id, reason)
                except SiteError:
                    pass
            raise LetsInferError(reason)
    return metadata, identity


_HANDLER_AUDITED_ACTIONS = {
    "setup": {"site.setup"},
    "site.move": {"site.move"},
    "pair": {"pair"},
    "controllers.forget": {"controllers.forget"},
    "key.create": {"key.create"},
    "key.rotate": {"key.rotate"},
    "key.revoke": {"key.revoke"},
    "key.policy": {"key.policy"},
    "member.invite": {"member.invite"},
    "member.approve": {"member.approve"},
    "member.sync": {"member.sync"},
    "member.drain": {"member.drain"},
    "member.resume": {"member.resume"},
    "member.remove": {"member.remove"},
    "expose": {"exposure.enable"},
    "unexpose": {"exposure.disable"},
}


def _audit_marker(metadata: Any, identity: Any) -> int | None:
    if (
        identity is None
        or identity.role != "coordinator"
        or metadata.audit is AuditPolicy.NONE
    ):
        return None
    try:
        with SiteStore(identity=identity) as store:
            row = store.connection.execute(
                "SELECT COALESCE(MAX(sequence),0) FROM audit_events"
            ).fetchone()
    except SiteError as error:
        raise LetsInferError(
            "mandatory site audit is unavailable before command execution"
        ) from error
    return int(row[0])


def _audit_command_result(
    metadata: Any,
    identity: Any,
    *,
    outcome: str,
    reason: str | None = None,
    after_sequence: int | None = None,
) -> None:
    if identity is None or identity.role != "coordinator":
        return
    if metadata.audit is AuditPolicy.NONE:
        return
    if metadata.audit is AuditPolicy.SUCCESS and outcome != "success":
        return
    try:
        with SiteStore(identity=identity) as store:
            handler_actions = _HANDLER_AUDITED_ACTIONS.get(metadata.name)
            if handler_actions is not None and after_sequence is not None:
                placeholders = ",".join("?" for _item in handler_actions)
                existing = store.connection.execute(
                    "SELECT 1 FROM audit_events WHERE sequence>? "
                    f"AND action IN ({placeholders}) AND outcome=? LIMIT 1",
                    (after_sequence, *sorted(handler_actions), outcome),
                ).fetchone()
                if existing is not None:
                    return
            store.record_action(metadata.name, metadata.name, outcome, reason)
    except SiteError as error:
        if outcome == "success":
            raise LetsInferError(
                "command completed but its mandatory site audit event failed"
            ) from error


def parser() -> argparse.ArgumentParser:
    root = ui.ArgumentParser(
        prog="letsinfer",
        description=__doc__,
        epilog="Run `letsinfer COMMAND --help` for command-specific options.",
    )
    subcommands = root.add_subparsers(dest="command", required=True)

    setup = subcommands.add_parser(
        "setup", help=help_label("create this machine's Let's Infer site", "setup")
    )
    setup.add_argument("--name", default="Home")
    setup.add_argument("--address")
    setup.add_argument(
        "--no-service",
        action="store_true",
        help="create a local development identity without a persistent site service",
    )
    setup.add_argument("--json", action="store_true")
    setup.set_defaults(action=setup_command, action_id="setup")

    site_command = subcommands.add_parser(
        "site", help="inspect the logical Let's Infer site"
    )
    site_operations = site_command.add_subparsers(dest="site_operation", required=True)
    site_show = site_operations.add_parser(
        "status", help=help_label("show site identity and role", "site.status")
    )
    site_show.add_argument("--json", action="store_true")
    site_show.set_defaults(action=site_status_command, action_id="site.status")
    site_move = site_operations.add_parser(
        "move", help=help_label("plan or apply a move into another site", "site.move")
    )
    site_move.add_argument("--apply", action="store_true")
    site_move.add_argument("--source-site-id")
    site_move.add_argument("--endpoint")
    site_move.add_argument("--invite")
    site_move.add_argument("--coordinator-certificate-sha256")
    site_move.add_argument("--code")
    site_move.add_argument("--name")
    site_move.add_argument("--address")
    site_move.add_argument("--no-service", action="store_true", help=argparse.SUPPRESS)
    site_move.add_argument("--json", action="store_true")
    site_move.set_defaults(action=site_move_command, action_id="site.move")

    topology_group = subcommands.add_parser("topology", help="inspect verified site topology")
    topology_operations = topology_group.add_subparsers(
        dest="topology_operation", required=True
    )
    topology_show = topology_operations.add_parser(
        "show", help=help_label("show verified site topology", "topology.show")
    )
    topology_show.add_argument("--json", action="store_true")
    topology_show.set_defaults(action=topology_command, action_id="topology.show")
    topology_probe = topology_operations.add_parser(
        "probe",
        help=help_label("prove a bidirectional physical member link", "topology.probe"),
    )
    topology_probe.add_argument("left")
    topology_probe.add_argument("right")
    topology_probe.add_argument("--left-interface", required=True)
    topology_probe.add_argument("--right-interface", required=True)
    topology_probe.add_argument(
        "--kind", choices=("connectx", "ethernet", "wifi", "other"), required=True
    )
    topology_probe.add_argument("--json", action="store_true")
    topology_probe.set_defaults(
        action=topology_probe_command, action_id="topology.probe"
    )
    topology_plan = topology_operations.add_parser(
        "plan",
        help=help_label("plan the best qualified model placement", "topology.plan"),
    )
    topology_plan.add_argument("model")
    topology_plan.add_argument("--engine", choices=sorted(ADAPTERS))
    topology_plan.add_argument("--catalog")
    topology_plan.add_argument("--json", action="store_true")
    topology_plan.set_defaults(action=topology_plan_command, action_id="topology.plan")

    member_command = subcommands.add_parser("member", help="manage site membership")
    member_operations = member_command.add_subparsers(dest="member_operation", required=True)
    member_list = member_operations.add_parser(
        "list", help=help_label("list active site members", "member.list")
    )
    member_list.add_argument("--json", action="store_true")
    member_list.set_defaults(action=member_list_command, action_id="member.list")
    member_prepare = member_operations.add_parser(
        "prepare", help=help_label("create this machine's pending member identity", "member.prepare")
    )
    member_prepare.add_argument("--json", action="store_true")
    member_prepare.set_defaults(action=member_prepare_command, action_id="member.prepare")
    member_join = member_operations.add_parser(
        "join", help=help_label("join an authorized Let's Infer site", "member.join")
    )
    member_join.add_argument("endpoint")
    member_join.add_argument("--invite", required=True)
    member_join.add_argument("--coordinator-certificate-sha256", required=True)
    member_join.add_argument("--code")
    member_join.add_argument("--connectx", action="store_true")
    member_join.add_argument("--name")
    member_join.add_argument("--address")
    member_join.add_argument(
        "--no-service",
        action="store_true",
        help="join for local protocol development without installing the site service",
    )
    member_join.add_argument("--json", action="store_true")
    member_join.set_defaults(action=member_join_command, action_id="member.join")
    member_invite = member_operations.add_parser(
        "invite", help=help_label("authorize one bounded membership attempt", "member.invite")
    )
    member_invite.add_argument("--mode", choices=("lan", "remote", "connectx"), required=True)
    member_invite.add_argument("--candidate-fingerprint")
    member_invite.add_argument("--candidate-endpoint")
    member_invite.add_argument("--interface")
    member_invite.add_argument("--expires-in", type=int, default=180)
    member_invite.add_argument("--json", action="store_true")
    member_invite.set_defaults(action=member_invite_command, action_id="member.invite")
    member_approve = member_operations.add_parser(
        "approve", help=help_label("approve a matching member comparison code", "member.approve")
    )
    member_approve.add_argument("member")
    member_approve.add_argument("comparison_code")
    member_approve.add_argument("--json", action="store_true")
    member_approve.set_defaults(action=member_approve_command, action_id="member.approve")
    member_sync = member_operations.add_parser(
        "sync", help=help_label("refresh authenticated member facts", "member.sync")
    )
    member_sync.add_argument("--json", action="store_true")
    member_sync.set_defaults(action=member_sync_command, action_id="member.sync")
    member_drain = member_operations.add_parser(
        "drain", help=help_label("stop assigning new requests to a member", "member.drain")
    )
    member_drain.add_argument("member")
    member_drain.add_argument("--json", action="store_true")
    member_drain.set_defaults(action=member_drain_command, action_id="member.drain")
    member_resume = member_operations.add_parser(
        "resume", help=help_label("resume assigning requests to a drained member", "member.resume")
    )
    member_resume.add_argument("member")
    member_resume.add_argument("--json", action="store_true")
    member_resume.set_defaults(action=member_resume_command, action_id="member.resume")
    member_remove = member_operations.add_parser(
        "remove", help=help_label("remove an inactive site member", "member.remove")
    )
    member_remove.add_argument("member")
    member_remove.add_argument("--json", action="store_true")
    member_remove.set_defaults(action=member_remove_command, action_id="member.remove")

    alias_command = subcommands.add_parser("alias", help="manage stable model aliases")
    alias_operations = alias_command.add_subparsers(dest="alias_operation", required=True)
    alias_list = alias_operations.add_parser(
        "list", help=help_label("list model aliases", "alias.list")
    )
    alias_list.add_argument("--json", action="store_true")
    alias_list.set_defaults(action=alias_list_command, action_id="alias.list")
    alias_set = alias_operations.add_parser(
        "set", help=help_label("create or replace a model alias", "alias.set")
    )
    alias_set.add_argument("alias")
    alias_set.add_argument("model")
    alias_set.add_argument("--json", action="store_true")
    alias_set.set_defaults(action=alias_set_command, action_id="alias.set")
    alias_remove = alias_operations.add_parser(
        "remove", help=help_label("remove a model alias", "alias.remove")
    )
    alias_remove.add_argument("alias")
    alias_remove.add_argument("--json", action="store_true")
    alias_remove.set_defaults(action=alias_remove_command, action_id="alias.remove")

    listing = subcommands.add_parser("releases", help="list installed release manifests")
    listing.set_defaults(action=list_releases, action_id="releases")

    engines = subcommands.add_parser("engines", help="list registered inference engines")
    engines.set_defaults(action=list_engines, action_id="engines")

    hardware_probe = subcommands.add_parser(
        "hardware", help="show the capabilities used for runtime target selection"
    )
    hardware_probe.add_argument("--json", action="store_true")
    hardware_probe.add_argument("--catalog")
    hardware_probe.set_defaults(action=hardware, action_id="hardware")

    updating = subcommands.add_parser(
        "update", help="update Let's Infer core without changing runtimes"
    )
    updating.add_argument(
        "--version", help="install this exact stable or release-candidate version"
    )
    updating.set_defaults(action=update_core, action_id="update")

    runtime_listing = subcommands.add_parser(
        "runtimes", help="list installed immutable runtime packs"
    )
    runtime_listing.set_defaults(action=list_runtimes, action_id="runtimes")

    packing = subcommands.add_parser(
        "pack", help="build a deterministic runtime-pack artifact"
    )
    packing.add_argument("source")
    packing.add_argument("--output", required=True)
    packing.set_defaults(action=pack_runtime, action_id="pack")

    deriving = subcommands.add_parser(
        "derive", help="derive a local candidate with native engine argument changes"
    )
    deriving.add_argument("runtime")
    deriving.add_argument("--name", required=True)
    deriving.add_argument("--engine", choices=sorted(ADAPTERS))
    deriving.add_argument("--target")
    deriving.add_argument("--without", action="append", default=[])
    deriving.add_argument("--port", type=int, default=8000)
    deriving.set_defaults(action=derive_runtime, action_id="derive", engine_arguments=[])

    inspecting = subcommands.add_parser(
        "inspect", help="inspect a runtime's resolved command or derivation"
    )
    inspecting.add_argument("runtime")
    inspecting.add_argument("--engine", choices=sorted(ADAPTERS))
    inspecting.add_argument("--target")
    inspecting.add_argument("--port", type=int, default=8000)
    inspecting.add_argument("--command", action="store_true")
    inspecting.add_argument("--diff", action="store_true")
    inspecting.add_argument("--json", action="store_true")
    inspecting.set_defaults(action=inspect_runtime, action_id="inspect")

    upgrading = subcommands.add_parser(
        "upgrade", help="upgrade an installed runtime according to its selection policy"
    )
    upgrading.add_argument("runtime")
    upgrading.add_argument("--engine", choices=sorted(ADAPTERS))
    upgrading.add_argument("--target")
    upgrading.add_argument("--catalog")
    upgrading.add_argument("--to")
    upgrading.add_argument("--dry-run", action="store_true")
    upgrading.set_defaults(action=upgrade_runtime, action_id="upgrade")

    rolling_back = subcommands.add_parser(
        "rollback", help="reinstall the previous retained runtime"
    )
    rolling_back.add_argument("runtime")
    rolling_back.add_argument("--engine", choices=sorted(ADAPTERS))
    rolling_back.add_argument("--target")
    rolling_back.add_argument("--dry-run", action="store_true")
    rolling_back.set_defaults(action=rollback_runtime, action_id="rollback")

    checking = subcommands.add_parser(
        "verify", help="verify a release and its installed runtime artifacts"
    )
    checking.add_argument("model")
    checking.add_argument("--engine", choices=sorted(ADAPTERS))
    checking.add_argument("--target")
    checking.add_argument("--model-cache")
    checking.add_argument("--plugin-root")
    checking.add_argument(
        "--source-only", action="store_true", help="skip target model, plugin, and image checks"
    )
    checking.set_defaults(action=verify, action_id="verify")

    acquiring = subcommands.add_parser(
        "acquire", help="acquire and verify an exact model artifact"
    )
    acquiring.add_argument("model")
    acquiring.add_argument("--engine", choices=sorted(ADAPTERS))
    acquiring.add_argument("--target")
    acquiring.add_argument("--model-cache")
    acquiring.set_defaults(action=acquire, action_id="acquire")

    benchmarking = subcommands.add_parser(
        "benchmark", help="start, inspect, or stop a durable runtime benchmark"
    )
    benchmarking.add_argument(
        "runtime",
        nargs="?",
        help="installed runtime, or `stop` to cancel the active benchmark",
    )
    benchmarking.add_argument("--base-url")
    benchmarking.add_argument("--output-directory", type=pathlib.Path)
    benchmarking.add_argument("--api-key-file", type=pathlib.Path)
    benchmarking.add_argument("--ca-cert-file", type=pathlib.Path)
    benchmarking.add_argument("--container")
    benchmarking.add_argument("--store-root", type=pathlib.Path)
    benchmarking.add_argument("--launch-directory", type=pathlib.Path)
    benchmarking.add_argument("--measured-commit")
    benchmarking.add_argument("--source-attestation", type=pathlib.Path)
    benchmarking.add_argument("--watchdog-trip-file", type=pathlib.Path)
    benchmarking.add_argument("--timeout", type=int)
    for concurrency in (1, 2, 4, 8, 16):
        benchmarking.add_argument(f"--c{concurrency}", action="store_true")
    for context in ("32k", "64k", "128k", "256k"):
        benchmarking.add_argument(
            f"--{context}", action="store_true", dest=f"context_{context}"
        )
    benchmarking.add_argument(
        "--list", action="store_true", help="validate and print cells without inference"
    )
    benchmarking.add_argument(
        "--detach",
        action="store_true",
        help="start the benchmark without attaching to its live progress",
    )
    benchmarking.add_argument(
        "--json", action="store_true", help="emit machine-readable benchmark status"
    )
    benchmarking.add_argument("--job-worker", action="store_true", help=argparse.SUPPRESS)
    benchmarking.add_argument("--job-id", help=argparse.SUPPRESS)
    benchmarking.set_defaults(action=benchmark_runtime, action_id="benchmark")

    installing = subcommands.add_parser(
        "install", help="install a model or immutable runtime pack"
    )
    installing.add_argument("model")
    installing.add_argument("--engine", choices=sorted(ADAPTERS))
    installing.add_argument("--catalog")
    installing.add_argument("--port", type=int, default=8000)
    installing.add_argument("--engine-port", type=int, default=18000, help=argparse.SUPPRESS)
    installing.add_argument("--gateway-listen", default="0.0.0.0")
    installing.add_argument("--gateway-max-connections", type=int, default=128)
    installing.add_argument("--gateway-queue-timeout", type=int, default=300)
    installing.add_argument("--name")
    installing.add_argument("--model-cache")
    installing.add_argument("--plugin-root")
    installing.add_argument("--store-root")
    installing.add_argument("--runtime-cache-root")
    installing.add_argument("--engine-api-key-file", dest="api_key_file")
    installing.add_argument("--tls-cert-file")
    installing.add_argument("--tls-key-file")
    installing.add_argument("--watchdog-data-root")
    installing.add_argument("--watchdog-listen")
    installing.add_argument("--watchdog-port", type=int)
    installing.add_argument("--watchdog-cert-file")
    installing.add_argument("--watchdog-key-file")
    installing.add_argument("--watchdog-controller-ca-file")
    installing.add_argument("--watchdog-controller-ca-key-file")
    installing.add_argument("--watchdog-local-controller-cert-file")
    installing.add_argument("--watchdog-local-controller-key-file")
    installing.add_argument("--wheel")
    installing.add_argument("--config")
    installing.add_argument(
        "--download",
        dest="download_dependencies",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    installing.add_argument(
        "--no-download",
        dest="download_dependencies",
        action="store_false",
        help="require exact model artifacts and registry image layers to exist already",
    )
    installing.add_argument(
        "--no-build-image", action="store_true", help="require the exact image to exist already"
    )
    installing.add_argument(
        "--no-service", action="store_true", help="do not install a user systemd service"
    )
    installing.add_argument(
        "--no-start", action="store_true", help="install and enable the service without starting it"
    )
    installing.set_defaults(action=install, action_id="install", download_dependencies=True)

    serving = subcommands.add_parser("serve", help="start a release's qualified serving configuration")
    serving.add_argument("model")
    serving.add_argument("--engine", choices=sorted(ADAPTERS))
    serving.add_argument("--target")
    serving.add_argument("--port", type=int, default=8000)
    serving.add_argument("--name")
    serving.add_argument("--model-cache")
    serving.add_argument("--plugin-root")
    serving.add_argument("--store-root")
    serving.add_argument("--runtime-cache-root")
    serving.add_argument("--engine-api-key-file", dest="api_key_file")
    serving.add_argument("--tls-cert-file")
    serving.add_argument("--tls-key-file")
    serving.add_argument("--evidence-dir")
    serving.add_argument(
        "--qualification-mode",
        action="store_true",
        help=(
            "permit an explicitly unqualified serving configuration only with an explicit "
            "evidence directory; normal serving and installation remain gated"
        ),
    )
    serving.add_argument("--dry-run", action="store_true")
    serving.add_argument("--existing-ok", action="store_true", help=argparse.SUPPRESS)
    serving.add_argument("--protection-config", help=argparse.SUPPRESS)
    serving.set_defaults(action=serve, action_id="serve")

    showing = subcommands.add_parser("status", help="show site runtime or managed-container status")
    showing.add_argument("model", nargs="?")
    showing.add_argument("--name")
    showing.add_argument("--config")
    showing.add_argument("--json", action="store_true")
    showing.set_defaults(action=status, action_id="status")

    diagnosing = subcommands.add_parser(
        "doctor", help="audit operational and publication readiness"
    )
    diagnosing.add_argument("model", nargs="?")
    diagnosing.add_argument("--config")
    diagnosing.add_argument("--json", action="store_true")
    diagnosing.add_argument(
        "--require-stable",
        action="store_true",
        help="treat candidate/publication status as a failing readiness check",
    )
    diagnosing.set_defaults(action=doctor, action_id="doctor")

    logging = subcommands.add_parser("logs", help="show managed server logs")
    logging.add_argument("--config")
    logging.add_argument("--tail", type=int, default=200)
    logging.add_argument("--follow", action="store_true")
    logging.set_defaults(action=logs, action_id="logs")

    starting = subcommands.add_parser(
        "start", help=help_label("start a stopped site runtime", "start")
    )
    starting.add_argument("model", nargs="?")
    starting.add_argument("--config")
    starting.set_defaults(action=start_service, action_id="start")

    restarting = subcommands.add_parser(
        "restart", help=help_label("restart a site runtime", "restart")
    )
    restarting.add_argument("model", nargs="?")
    restarting.add_argument("--config")
    restarting.set_defaults(action=restart_service, action_id="restart")

    recovering = subcommands.add_parser(
        "recover",
        help=help_label(
            "acknowledge protection trips and recover a site runtime", "recover"
        ),
    )
    recovering.add_argument("model", nargs="?")
    recovering.add_argument("--config")
    recovering.set_defaults(action=recover_service, action_id="recover")

    exposure = subcommands.add_parser(
        "exposure", help="inspect public inference exposure"
    )
    exposure.add_argument("--json", action="store_true")
    exposure.set_defaults(
        action=exposure_status_command, action_id="exposure.status"
    )

    exposing = subcommands.add_parser(
        "expose",
        help=help_label(
            "publish only the inference gateway through Tailscale Funnel",
            "expose",
        ),
    )
    exposing.add_argument("--json", action="store_true")
    exposing.set_defaults(action=expose_command, action_id="expose")

    unexposing = subcommands.add_parser(
        "unexpose",
        help=help_label("disable public inference exposure", "unexpose"),
    )
    unexposing.add_argument("--json", action="store_true")
    unexposing.set_defaults(action=unexpose_command, action_id="unexpose")

    pairing = subcommands.add_parser(
        "pair", help=help_label(
            "pair one controller with a short, human-verified code", "pair"
        )
    )
    pairing.add_argument("--config")
    pairing.add_argument(
        "--timeout", type=int, default=CONTROLLER_PAIRING_TIMEOUT_SECONDS
    )
    pairing.add_argument(
        "--role",
        choices=("viewer", "operator", "administrator"),
        default="administrator",
    )
    pairing.set_defaults(action=pair_controller, action_id="pair")

    controller_command = subcommands.add_parser(
        "controllers", help="manage paired Let's Infer controllers"
    )
    controller_operations = controller_command.add_subparsers(
        dest="operation", required=True
    )
    controller_list = controller_operations.add_parser(
        "list", help=help_label("list paired controllers", "controllers.list")
    )
    controller_list.add_argument("--config")
    controller_list.add_argument("--json", action="store_true")
    controller_list.set_defaults(
        action=controllers, action_id="controllers.list", controller=None
    )
    controller_forget = controller_operations.add_parser(
        "forget", help=help_label("revoke a paired controller", "controllers.forget")
    )
    controller_forget.add_argument("controller")
    controller_forget.add_argument("--config")
    controller_forget.add_argument("--json", action="store_true")
    controller_forget.set_defaults(action=controllers, action_id="controllers.forget")

    key_command = subcommands.add_parser("key", help="manage inference API keys")
    key_operations = key_command.add_subparsers(dest="key_operation", required=True)
    key_create = key_operations.add_parser(
        "create", help=help_label("create a scoped inference API key", "key.create")
    )
    key_create.add_argument("name")
    key_create.add_argument("--model", action="append", default=[])
    key_create.add_argument("--expires-at", type=int)
    key_create.add_argument("--requests-per-minute", type=int)
    key_create.add_argument("--tokens-per-minute", type=int)
    key_create.add_argument("--concurrency", type=int)
    key_create.add_argument("--max-context", type=int)
    key_create.add_argument("--tenant")
    key_create.add_argument("--application")
    key_create.add_argument("--json", action="store_true")
    key_create.set_defaults(action=key_create_command, action_id="key.create")
    key_list = key_operations.add_parser(
        "list", help=help_label("list API-key metadata", "key.list")
    )
    key_list.add_argument("--json", action="store_true")
    key_list.set_defaults(action=key_list_command, action_id="key.list")
    key_show = key_operations.add_parser(
        "show", help=help_label("inspect one API-key policy", "key.show")
    )
    key_show.add_argument("key")
    key_show.add_argument("--json", action="store_true")
    key_show.set_defaults(action=key_show_command, action_id="key.show")
    key_rotate = key_operations.add_parser(
        "rotate", help=help_label("replace and revoke an API key", "key.rotate")
    )
    key_rotate.add_argument("key")
    key_rotate.add_argument("--json", action="store_true")
    key_rotate.set_defaults(action=key_rotate_command, action_id="key.rotate")
    key_revoke = key_operations.add_parser(
        "revoke", help=help_label("revoke an API key", "key.revoke")
    )
    key_revoke.add_argument("key")
    key_revoke.add_argument("--json", action="store_true")
    key_revoke.set_defaults(action=key_revoke_command, action_id="key.revoke")
    key_policy = key_operations.add_parser(
        "policy", help=help_label("replace an API-key policy", "key.policy")
    )
    key_policy.add_argument("key")
    key_policy.add_argument("--model", action="append")
    key_policy.add_argument("--expires-at", type=int)
    key_policy.add_argument("--requests-per-minute", type=int)
    key_policy.add_argument("--tokens-per-minute", type=int)
    key_policy.add_argument("--concurrency", type=int)
    key_policy.add_argument("--max-context", type=int)
    key_policy.add_argument("--tenant")
    key_policy.add_argument("--application")
    key_policy.add_argument("--json", action="store_true")
    key_policy.set_defaults(action=key_policy_command, action_id="key.policy")

    audit_command = subcommands.add_parser("audit", help="inspect the site audit chain")
    audit_operations = audit_command.add_subparsers(dest="audit_operation", required=True)
    audit_list = audit_operations.add_parser(
        "list", help=help_label("list audit events", "audit.list")
    )
    audit_list.add_argument("--limit", type=int, default=100)
    audit_list.add_argument("--json", action="store_true")
    audit_list.set_defaults(action=audit_list_command, action_id="audit.list")
    audit_show = audit_operations.add_parser(
        "show", help=help_label("show one audit event", "audit.show")
    )
    audit_show.add_argument("event")
    audit_show.add_argument("--json", action="store_true")
    audit_show.set_defaults(action=audit_show_command, action_id="audit.show")
    audit_verify = audit_operations.add_parser(
        "verify", help=help_label("verify hashes and signed checkpoints", "audit.verify")
    )
    audit_verify.add_argument("--json", action="store_true")
    audit_verify.set_defaults(action=audit_verify_command, action_id="audit.verify")
    audit_export = audit_operations.add_parser(
        "export", help=help_label("export verified audit events", "audit.export")
    )
    audit_export.add_argument("--output")
    audit_export.set_defaults(action=audit_export_command, action_id="audit.export")

    stopping = subcommands.add_parser(
        "stop", help=help_label("stop a site runtime", "stop")
    )
    stopping.add_argument("model", nargs="?")
    stopping.add_argument(
        "--name",
        help="remove only this managed container without stopping the resident service",
    )
    stopping.add_argument("--config")
    stopping.add_argument("--container-only", action="store_true", help=argparse.SUPPRESS)
    stopping.set_defaults(action=stop, action_id="stop")

    uninstalling = subcommands.add_parser(
        "uninstall", help="remove the service while preserving model and cache data"
    )
    uninstalling.add_argument("--config")
    uninstalling.add_argument("--purge-runtime-plugins", action="store_true")
    uninstalling.add_argument("--purge-credentials", action="store_true")
    uninstalling.add_argument("--purge-control-bundle", action="store_true")
    uninstalling.add_argument("--purge-watchdog-runtime", action="store_true")
    uninstalling.set_defaults(action=uninstall, action_id="uninstall")

    service_start = subcommands.add_parser(
        "service-start", help="start from service configuration (systemd internal)"
    )
    service_start.add_argument("--config", required=True)
    service_start.set_defaults(action=serve_from_config, action_id="service-start")

    service_stop = subcommands.add_parser(
        "service-stop", help="stop from service configuration (systemd internal)"
    )
    service_stop.add_argument("--config", required=True)
    service_stop.set_defaults(action=stop_from_config, action_id="service-stop")
    gateway = subcommands.add_parser("gateway", help=argparse.SUPPRESS)
    gateway.add_argument("--listen", default="127.0.0.1")
    gateway.add_argument("--port", type=int, default=8000)
    gateway.add_argument("--telemetry-file", required=True)
    gateway.add_argument("--queue-timeout", type=int, default=300)
    gateway.add_argument("--max-connections", type=int, default=128)
    gateway.set_defaults(action=gateway_command, action_id="gateway")
    site_agent = subcommands.add_parser("site-agent", help=argparse.SUPPRESS)
    site_agent.add_argument("--listen", default="0.0.0.0")
    site_agent.add_argument("--port", type=int, default=SITE_CONTROL_PORT)
    site_agent.set_defaults(action=site_agent_command, action_id="site-agent")
    core_rebind = subcommands.add_parser("core-rebind", help=argparse.SUPPRESS)
    core_rebind.set_defaults(action=rebind_core_services, action_id="core-rebind")
    internal_commands = {
        "service-start",
        "service-stop",
        "gateway",
        "site-agent",
        "core-rebind",
    }
    subcommands._choices_actions[:] = [
        choice
        for choice in subcommands._choices_actions
        if choice.dest not in internal_commands
    ]
    subcommands.metavar = "COMMAND"
    try:
        validate_registry(_parser_action_ids(root))
    except ValueError as error:
        raise LetsInferError(str(error)) from error
    return root


def main(argv: Sequence[str] | None = None) -> int:
    metadata = None
    identity = None
    audit_sequence = None
    try:
        raw_arguments = list(argv) if argv is not None else sys.argv[1:]
        command_parser = parser()
        if not raw_arguments:
            command_parser.print_help()
            return 0
        engine_arguments: list[str] = []
        if raw_arguments[:1] == ["derive"] and "--" in raw_arguments:
            separator = raw_arguments.index("--")
            engine_arguments = raw_arguments[separator:]
            raw_arguments = raw_arguments[:separator]
        arguments = command_parser.parse_args(raw_arguments)
        metadata, identity = _authorize_command(arguments)
        audit_sequence = _audit_marker(metadata, identity)
        if arguments.command == "derive":
            arguments.engine_arguments = engine_arguments
        if getattr(arguments, "port", 1) not in range(1, 65536):
            raise LetsInferError("port must be between 1 and 65535")
        engine_port = getattr(arguments, "engine_port", None)
        if engine_port is not None and engine_port not in range(1, 65536):
            raise LetsInferError("engine port must be between 1 and 65535")
        if engine_port is not None and engine_port == arguments.port:
            raise LetsInferError("gateway and engine ports must be distinct")
        max_connections = getattr(arguments, "gateway_max_connections", None)
        if max_connections is not None and max_connections not in range(1, 257):
            raise LetsInferError("gateway max connections must be between 1 and 256")
        queue_timeout = getattr(arguments, "gateway_queue_timeout", None)
        if queue_timeout is not None and queue_timeout not in range(1, 3601):
            raise LetsInferError("gateway queue timeout must be between 1 and 3600 seconds")
        watchdog_port = getattr(arguments, "watchdog_port", None)
        if watchdog_port is not None and watchdog_port not in range(1, 65536):
            raise LetsInferError("watchdog port must be between 1 and 65535")
        if getattr(arguments, "tail", 0) < 0:
            raise LetsInferError("log tail must be non-negative")
        progress_message = ACTION_PROGRESS.get(metadata.name)
        machine_output = bool(getattr(arguments, "json", False))
        lightweight = bool(
            getattr(arguments, "dry_run", False)
            or getattr(arguments, "list", False)
            or getattr(arguments, "source_only", False)
        )
        if progress_message is None:
            result = arguments.action(arguments)
        else:
            activity = ui.progress(
                progress_message[0],
                done=progress_message[1],
                enabled=not machine_output and not lightweight,
            )
            with activity, ui.protect_stdout(activity):
                result = arguments.action(arguments)
        _audit_command_result(
            metadata,
            identity,
            outcome="success",
            after_sequence=audit_sequence,
        )
        return result
    except (LetsInferError, RuntimePackError, SiteError) as error:
        if metadata is not None:
            _audit_command_result(
                metadata,
                identity,
                outcome="failed",
                reason=type(error).__name__,
                after_sequence=audit_sequence,
            )
        ui.fatal(str(error))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
