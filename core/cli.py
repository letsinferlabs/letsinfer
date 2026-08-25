#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Install and serve immutable, independently qualified Let's Infer runtimes."""

from __future__ import annotations

import argparse
import base64
import contextlib
import datetime as dt
import functools
import getpass
import hashlib
import hmac
import http.server
import io
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

from benchmarks import benchmark_record as benchmark_record_contract

# A hash-addressed control bundle must not mutate itself when Python imports
# the adjacent engine registry. Runtime caches belong outside the bundle.
sys.dont_write_bytecode = True

from . import PRODUCT_VERSION
from .paths import (
    PathContractError,
    benchmarks_root,
    cache_root,
    ensure_home as ensure_letsinfer_home,
    evidence_root,
    home_root as letsinfer_home_root,
    managed_roots,
    models_root,
    oci_root,
    secrets_root,
)
from .actions import (
    ACTIONS,
    AuditPolicy,
    CommandScope,
    action as command_action,
    help_label,
    validate_registry,
)
from .engine_protocol import (
    ENGINE_ADAPTER,
    ENGINE_PROGRESS_PATH,
    ENGINE_PROTOCOL_VERSION,
    EngineManifestError,
    SAFE_NAME_RE,
    adapter_for,
    artifact_storage_slug,
    cache_provider_for,
    evidence_contract_for,
    launch_for,
    persistent_cache_for,
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
    build_single_group_plan,
    MemberAgent,
    MemberJobError,
    MemberJobStore,
    OrchestrationError,
    credential_sha256 as group_credential_sha256,
    orchestration_contract_sha256,
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
    build_archive,
    canonical_bytes,
    catalog_release,
    catalog_release_record,
    catalog_target_contract,
    compatible_catalog_targets,
    default_runtime_home,
    describe_source,
    materialize,
    new_receipt,
    resolved_catalog_location,
    restore_selection,
    selections,
    store_pack,
    target_matches,
    target_contract_sha256,
    validate_runtime_config,
    validate_target_contract,
    verify_descriptor,
    write_selection,
)
from .updates import (
    Component,
    UpdateManager,
    UpdatePoller,
    request_background_refresh,
)
from .updates.manager import UpdateError, compare_versions
from .catalog import CatalogError, CatalogManager
from . import benchmark_jobs, benchmark_verification, command_ui, ui
from .ui_contracts import OutputContract, ProgressKind, SurfaceKind, contract as ui_contract
from .state_plane import runtime_lifecycle as derive_runtime_lifecycle
from .platform import macos as macos_services
from .site.state import (
    SiteError,
    SiteStore,
    config_root as site_config_root,
    data_root as site_data_root,
    identity_json,
    identity_path as site_identity_path,
    has_active_engine_groups_for_cleanup,
    member_certificate_path as site_member_certificate_path,
    member_proof,
    prepare_member_identity,
    read_exposure_for_cleanup,
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
    Placement,
    TargetPlacement,
    TopologyError,
    TopologyGraph,
    validate_member_facts,
)
from .site.telemetry import (
    TelemetryAggregator,
    TelemetryError,
    TelemetryPublisher,
)
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
WATCHDOG_CONTROLLER_STREAM_FLOOR = 16
WATCHDOG_CONTROLLER_STREAM_LIMIT = 16
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
GROUP_NODE_LABEL = "io.letsinfer.group-node"
GROUP_TASK_LABEL = "io.letsinfer.group-task"
SECURITY_PROFILE = "tls-api-key-v1"
SERVICE_CONFIG_VERSION = 4
CORE_SOURCE_MANIFEST = "SOURCE-MANIFEST.json"
SERVICE_NAME = "letsinfer.service"
ENGINE_SERVICE_NAME = "letsinfer-engine.service"
GATEWAY_SERVICE_NAME = "letsinfer-gateway.service"
NODE_SERVICE_NAME = "letsinfer-node.service"
RECOVERY_SERVICE_NAME = "letsinfer-recovery.service"
RECOVERY_TIMER_NAME = "letsinfer-recovery.timer"


def _macos_service_label(name: str) -> str | None:
    return {
        NODE_SERVICE_NAME: macos_services.NODE_LABEL,
        GATEWAY_SERVICE_NAME: macos_services.GATEWAY_LABEL,
    }.get(name)
CONTROL_PLANE_MEMORY_HIGH_BYTES = 24 * 1024 * 1024
CONTROL_PLANE_MEMORY_LIMIT_BYTES = 30 * 1024 * 1024
NODE_AGENT_MEMORY_HIGH_BYTES = 128 * 1024 * 1024
NODE_AGENT_MEMORY_LIMIT_BYTES = 192 * 1024 * 1024
NODE_AGENT_TASK_LIMIT = 32
GATEWAY_MEMORY_HIGH_BYTES = 64 * 1024 * 1024
GATEWAY_MEMORY_LIMIT_BYTES = 96 * 1024 * 1024
PROTECTION_STATE_NAME = "protected-engine.state"
PROTECTION_ACK_NAME = "protected-engine.ack"
PROTECTION_TRIP_NAME = "protection-trip.json"
PROTECTION_ROOT_NAME = "protected-engines"
WATCHDOG_PUBLIC_STATE_DIRECTORY = "service-state"
CONTROLLER_PAIRING_PROTOCOL = "letsinfer-controller-pair-v1"
CONTROLLER_PAIRING_PORT = 9769
WATCHDOG_TELEMETRY_PORT = 9768
CONTROLLER_PAIRING_TIMEOUT_SECONDS = 180
CONTROLLER_PAIRING_MIN_TIMEOUT_SECONDS = 30
CONTROLLER_CERTIFICATE_DAYS = 36500
CONTROLLER_MAX = 64
MIN_API_KEY_BYTES = 32

# Every public human command opens with the same lockup and palette as status.
# Long work adds a delayed activity indicator, while JSON, redirected output,
# internal service commands, raw logs/exports, and one-time secrets retain
# stable byte contracts. Status and benchmark own their complete live surfaces.
ACTION_PROGRESS: Mapping[str, tuple[str, str]] = {
    "setup": ("Creating the node", "Node ready"),
    "update": ("Updating Let's Infer core", "Core updated"),
    "node.move": ("Preparing the node move", "Node move ready"),
    "topology.probe": ("Probing the child link", "Child link verified"),
    "topology.plan": ("Planning model placement", "Placement plan ready"),
    "child.prepare": ("Preparing the child identity", "Child identity ready"),
    "child.join": ("Joining the main node", "Child joined"),
    "child.invite": ("Creating the child invitation", "Child invitation ready"),
    "child.approve": ("Approving the child", "Child approved"),
    "child.sync": ("Refreshing child facts", "Child facts refreshed"),
    "child.drain": ("Draining the child", "Child drained"),
    "child.resume": ("Resuming the child", "Child active"),
    "child.remove": ("Removing the child", "Child removed"),
    "alias.set": ("Saving the model alias", "Model alias saved"),
    "alias.remove": ("Removing the model alias", "Model alias removed"),
    "pack": ("Building the runtime pack", "Runtime pack built"),
    "upgrade": ("Resolving the runtime upgrade", "Runtime upgraded"),
    "rollback": ("Restoring the previous runtime", "Runtime restored"),
    "verify": ("Verifying the runtime", "Runtime verified"),
    "acquire": ("Acquiring the model", "Model acquired"),
    "install": ("Installing the runtime", "Runtime installed"),
    "scale": ("Scaling the replica pool", "Replica pool scaled"),
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

READ_PROGRESS: Mapping[str, tuple[str, str]] = {
    "node.status": ("Reading the node identity", "Node identity loaded"),
    "hardware": ("Inspecting local hardware", "Hardware inspected"),
    "update.check": ("Checking for updates", "Update check complete"),
    "topology.show": ("Reading the verified topology", "Topology loaded"),
    "child.list": ("Reading node membership", "Node membership loaded"),
    "alias.list": ("Reading model aliases", "Model aliases loaded"),
    "list": ("Loading available runtimes", "Available runtimes loaded"),
    "runtimes": ("Loading installed runtimes", "Installed runtimes loaded"),
    "inspect": ("Inspecting the runtime", "Runtime inspected"),
    "doctor": ("Checking node readiness", "Readiness check complete"),
    "exposure.status": ("Checking public exposure", "Exposure checked"),
    "controllers.list": ("Reading paired controllers", "Controllers loaded"),
    "key.list": ("Reading API keys", "API keys loaded"),
    "key.show": ("Reading the API key policy", "API key policy loaded"),
    "audit.list": ("Reading the audit chain", "Audit events loaded"),
    "audit.show": ("Reading the audit event", "Audit event loaded"),
    "audit.verify": ("Verifying the audit chain", "Audit chain verified"),
    "audit.export": ("Exporting the audit chain", "Audit chain exported"),
}

# Named progress is handler-owned only when the handler can advance every
# declared boundary at the point where it actually completes. ``update`` owns
# its established StepProgress directly; these handlers use
# ``_command_step_progress`` below. Everything else uses one truthful spinner.
HANDLER_STEP_PROGRESS = frozenset({"topology.probe"})
POST_PROMPT_PROGRESS = frozenset(
    {"node.move", "child.join", "install", "upgrade", "rollback", "pair", "uninstall"}
)


def _human_presenter(
    stream: Any = None,
) -> command_ui.CommandUI | None:
    """Return the shared presenter only when the complete human surface is a TTY."""

    target = sys.stdout if stream is None else stream
    if not (
        ui.Terminal(sys.stdout).interactive
        and ui.Terminal(sys.stderr).interactive
        and ui.Terminal(target).interactive
    ):
        return None
    return command_ui.CommandUI(target)


def _raw_ui_variant(presentation: Any, arguments: argparse.Namespace) -> bool:
    """Resolve an explicitly declared raw selector without inference."""

    for selector in presentation.raw_variants:
        name, separator, expected = selector.partition("=")
        if not separator:
            raise LetsInferError(
                f"invalid raw UI selector for {presentation.action_id}: {selector}"
            )
        actual = getattr(arguments, name, None)
        wanted: object
        if expected == "true":
            wanted = True
        elif expected == "false":
            wanted = False
        elif expected == "none":
            wanted = None
        else:
            wanted = expected
        if actual == wanted:
            return True
    return False


def _command_step_progress(arguments: argparse.Namespace) -> ui.StepProgress:
    """Build a handler-owned step surface without touching machine output."""

    presentation = ui_contract(arguments.action_id)
    if presentation.progress is not ProgressKind.STEPS:
        raise RuntimeError(
            f"{arguments.action_id} does not declare handler-owned step progress"
        )
    terminal = ui.Terminal(sys.stderr)
    human = (
        not bool(getattr(arguments, "json", False))
        and not _raw_ui_variant(presentation, arguments)
        and _human_presenter() is not None
    )
    if not human:
        terminal.interactive = False
        terminal.color = False
        terminal.unicode = False
    return ui.StepProgress(
        terminal,
        presentation.steps,
        section=presentation.action_id,
        show_header=False,
    )


def _command_activity(
    arguments: argparse.Namespace,
    message: str | None = None,
    *,
    action_id: str | None = None,
) -> ui.Spinner:
    """Return a handler-owned spinner which never contaminates machine output."""

    resolved_action_id = action_id or getattr(arguments, "action_id", None)
    if not isinstance(resolved_action_id, str):
        raise RuntimeError("handler-owned activity requires an action identifier")
    presentation = ui_contract(resolved_action_id)
    progress_message = ACTION_PROGRESS.get(resolved_action_id) or READ_PROGRESS.get(
        resolved_action_id
    )
    if message is None:
        if progress_message is None:
            raise RuntimeError(
                f"{resolved_action_id} has no declared activity language"
            )
        message = progress_message[0]
    enabled = (
        not bool(getattr(arguments, "json", False))
        and not _raw_ui_variant(presentation, arguments)
        and _human_presenter() is not None
    )
    return ui.progress(message, stream=sys.stderr, enabled=enabled)


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


@functools.lru_cache(maxsize=1)
def _core_update_identity() -> str:
    """Bind cached advice to the exact immutable core directory in use."""
    root = source_root().resolve(strict=False)
    manifest = root / CORE_SOURCE_MANIFEST
    try:
        document = (
            json.loads(manifest.read_text(encoding="utf-8"))
            if not manifest.is_symlink() and manifest.is_file()
            else None
        )
        if isinstance(document, dict):
            records = {
                row["path"]: row["sha256"]
                for row in document.get("files", [])
                if isinstance(row, dict)
                and isinstance(row.get("path"), str)
                and isinstance(row.get("sha256"), str)
            }
            bound_paths = ("core/cli.py", "core/updates/manager.py")
            if all(
                records.get(relative) == sha256_file(root / relative)
                for relative in bound_paths
            ):
                return sha256_file(manifest)
    except (OSError, KeyError, TypeError, json.JSONDecodeError):
        pass
    # Development trees do not necessarily have a freshly materialized source
    # manifest. Bind their cache to the update-facing implementation bytes;
    # every installed release takes the exact manifest-bound branch above.
    digest = hashlib.sha256(str(root).encode("utf-8"))
    for relative in ("core/__init__.py", "core/cli.py", "core/updates/manager.py"):
        path = root / relative
        digest.update(relative.encode("utf-8"))
        try:
            digest.update(bytes.fromhex(sha256_file(path)))
        except OSError:
            digest.update(b"missing")
    return digest.hexdigest()


def _update_components() -> tuple[Component, ...]:
    """Return core plus the one selected resident or qualification runtime."""
    components = [
        Component("core", "core", PRODUCT_VERSION, _core_update_identity())
    ]
    config_path = (
        qualification_service_config_path()
        if qualification_service_config_path().is_file()
        else default_service_config_path()
    )
    if not config_path.is_file():
        return tuple(components)
    try:
        config = read_service_config(config_path)
        runtime_digest = config.get("runtime_digest")
        receipt = next(
            item for item in selections() if item["digest"] == runtime_digest
        )
        components.append(
            Component(
                "runtime",
                receipt["logical_model"],
                receipt["version"],
                receipt["digest"],
                policy=receipt["policy"],
                model=receipt["logical_model"],
                runtime=receipt["candidate_id"],
                engine=receipt["engine"],
                target=receipt["target"],
                target_contract_sha256=receipt["target_contract_sha256"],
                installed_source=receipt["source"],
            )
        )
    except (LetsInferError, RuntimePackError, UpdateError, StopIteration):
        # Core advice remains available while a partially removed runtime is
        # repaired. Never let advisory state break another CLI command.
        pass
    return tuple(components)


def _update_manager(catalog: str | None = None) -> UpdateManager:
    return UpdateManager(
        _update_components,
        catalog_location=lambda: resolved_catalog_location(catalog),
        catalog_loader=lambda location: CatalogManager(location).load(
            refresh=True
        ).document,
    )


def expanded_path(value: str | os.PathLike[str]) -> pathlib.Path:
    return pathlib.Path(value).expanduser().resolve(strict=False)


def absolute_user_path(value: str | os.PathLike[str]) -> pathlib.Path:
    return pathlib.Path(os.path.abspath(pathlib.Path(value).expanduser()))


def default_store_root(manifest: dict[str, Any]) -> pathlib.Path:
    return cache_root() / "prefix-store" / manifest["release"]


def default_runtime_cache_root(manifest: dict[str, Any]) -> pathlib.Path:
    image_id = manifest["image"]["immutable_id"].removeprefix("sha256:")
    return cache_root() / "runtime" / image_id


def default_model_cache_root() -> pathlib.Path:
    return models_root()


def requested_model_cache(
    explicit: str | os.PathLike[str] | None,
) -> pathlib.Path:
    return expanded_path(explicit) if explicit else default_model_cache_root()


def default_api_key_path() -> pathlib.Path:
    return secrets_root() / "api-key"


def default_engine_api_key_path() -> pathlib.Path:
    return secrets_root() / "engine/api-key"


def default_tls_cert_path() -> pathlib.Path:
    return site_config_root() / "tls/server.crt"


def default_tls_key_path() -> pathlib.Path:
    return secrets_root() / "tls/server.key"


def default_control_parent() -> pathlib.Path:
    return letsinfer_home_root() / "core" / "control"


def default_watchdog_runtime_parent() -> pathlib.Path:
    return site_data_root() / "watchdog/runtime"


def default_watchdog_data_root() -> pathlib.Path:
    return site_data_root() / "watchdog/data-v1"


def default_gateway_telemetry_path() -> pathlib.Path:
    return site_data_root() / "gateway/telemetry.state"


def default_gateway_group_telemetry_path() -> pathlib.Path:
    path = default_gateway_telemetry_path()
    return path.with_name(path.name + ".groups.json")


def default_engine_group_root() -> pathlib.Path:
    return site_data_root() / "engine-groups"


def default_watchdog_cert_path() -> pathlib.Path:
    return site_config_root() / "watchdog/server.crt"


def default_watchdog_key_path() -> pathlib.Path:
    return secrets_root() / "watchdog/server.key"


def default_watchdog_controller_ca_path() -> pathlib.Path:
    return site_config_root() / "watchdog/controller-ca.crt"


def default_watchdog_controller_ca_key_path() -> pathlib.Path:
    return secrets_root() / "watchdog/controller-ca.key"


def default_watchdog_local_controller_cert_path() -> pathlib.Path:
    return site_config_root() / "watchdog/local-controller.crt"


def default_watchdog_local_controller_key_path() -> pathlib.Path:
    return secrets_root() / "watchdog/local-controller.key"


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


def runtime_execution_manifest(
    runtime: dict[str, Any],
    *,
    qualified: bool,
    blocked_by: str = "runtime-unqualified",
    image_override: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Derive the private core execution view from authoritative runtime.json.

    Runtime packs expose only schema-v5 runtime.json. The control plane keeps a
    deterministic, hash-bound execution view so existing lifecycle code never
    needs to reinterpret source metadata. Qualification is authorization from a
    signed catalog, never an author-controlled property of executable bytes.
    """

    try:
        runtime = validate_runtime_config(runtime)
    except RuntimePackError as error:
        raise LetsInferError(str(error)) from error
    engine = runtime["engine"]
    model = runtime["model"]
    artifacts = []
    for source in runtime["artifacts"]:
        artifact = dict(source)
        uri = artifact.pop("uri")
        if not uri.startswith("hf://"):
            raise LetsInferError("runtime artifact URI must use hf://")
        artifact["repository"] = uri.removeprefix("hf://")
        artifacts.append(artifact)
    execution_engine = {
        "name": engine["id"],
        "model_format": engine["model_format"],
        "api_protocol": "openai-v1",
        "cache_provider": engine["cache_provider"],
        "arguments": list(engine["arguments"]),
        "environment": dict(engine["environment"]),
    }
    execution = {
        "schema_version": 1,
        "release": f"{runtime['id']}@{runtime['version']}",
        "status": "stable" if qualified else "candidate",
        "target": runtime["target"],
        "engine": execution_engine,
        "model": {
            "alias": runtime["logical_model"],
            "id": model["uri"].removeprefix("hf://"),
            "artifact": model["artifact"],
            "acquisition_image": model["acquisition"]["image"],
        },
        "artifacts": artifacts,
        "image": (
            {"distribution": "registry-digest", **engine["oci"]}
            if image_override is None
            else dict(image_override)
        ),
        "container": {**runtime["container"], "model_cache": "/models"},
        "watchdog": {
            "listen": "0.0.0.0",
            "protocol_version": WATCHDOG_PROTOCOL_VERSION,
            "port": 9768,
            **core_watchdog_contract(),
            "build": {
                "source_root": "watchdog",
                "target": "letsinfer_watchdog",
                "output": "letsinfer-watchdog",
            },
        },
        "cache": runtime["cache"],
        "serving": {
            **runtime["serving"],
            "qualified": qualified,
            **({} if qualified else {"blocked_by": blocked_by}),
        },
    }
    for optional in ("orchestration",):
        if optional in runtime:
            execution[optional] = runtime[optional]
    validate_manifest(execution)
    return execution


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
    """Validate the private execution view derived from schema-v3 runtime.json.

    This is deliberately engine agnostic. Engine-specific arguments and cache
    configuration are opaque to core and are interpreted by the digest-pinned
    Engine OCI adapter.
    """

    if not isinstance(manifest, dict):
        raise LetsInferError("manifest must be an object")
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
            "container",
            "watchdog",
            "cache",
            "serving",
            "orchestration",
        },
        "manifest",
    )
    if manifest.get("schema_version") != 1 or isinstance(
        manifest.get("schema_version"), bool
    ):
        raise LetsInferError("unsupported execution manifest schema_version")
    release = _require(manifest, "release", str, "manifest")
    if not release or any(character.isspace() for character in release):
        raise LetsInferError("manifest.release must be a machine identifier")
    status = _require(manifest, "status", str, "manifest")
    if status not in {"candidate", "stable"}:
        raise LetsInferError("manifest.status must be candidate or stable")

    target = target_contract(manifest)
    model = _require(manifest, "model", dict, "manifest")
    _reject_unknown_fields(
        model,
        {"alias", "id", "artifact", "acquisition_image"},
        "manifest.model",
    )
    for key in ("alias", "id", "artifact"):
        value = _require(model, key, str, "manifest.model")
        if not value or any(character.isspace() for character in value):
            raise LetsInferError(f"manifest.model.{key} must be a machine identifier")
    acquisition_image = _require(
        model, "acquisition_image", str, "manifest.model"
    )
    if not REGISTRY_DIGEST_RE.fullmatch(acquisition_image):
        raise LetsInferError("manifest.model.acquisition_image must be digest-pinned")

    image = _require(manifest, "image", dict, "manifest")
    if set(image) not in (
        {"distribution", "reference", "immutable_id"},
        {"distribution", "reference", "immutable_id", "base"},
    ):
        raise LetsInferError("manifest.image has invalid fields")
    distribution = _require(image, "distribution", str, "manifest.image")
    reference = _require(image, "reference", str, "manifest.image")
    immutable_id = _require(image, "immutable_id", str, "manifest.image")
    if distribution not in {"local-image-id", "registry-digest"}:
        raise LetsInferError("manifest.image.distribution is invalid")
    if not IMAGE_ID_RE.fullmatch(immutable_id):
        raise LetsInferError("manifest.image.immutable_id must be an exact image ID")
    if distribution == "registry-digest" and not REGISTRY_DIGEST_RE.fullmatch(
        reference
    ):
        raise LetsInferError("registry image reference must be digest-pinned")
    if distribution == "local-image-id" and reference != immutable_id:
        raise LetsInferError("local image reference must equal its immutable image ID")
    if "base" in image and not REGISTRY_DIGEST_RE.fullmatch(image["base"]):
        raise LetsInferError("manifest.image.base must be digest-pinned")

    container = _require(manifest, "container", dict, "manifest")
    allowed_container = {
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
    _reject_unknown_fields(container, allowed_container, "manifest.container")
    for key in (
        "memory_bytes",
        "shm_bytes",
        "min_available_gib",
        "runtime_min_available_gib",
        "startup_timeout_seconds",
    ):
        value = container.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise LetsInferError(f"manifest.container.{key} must be positive")
    if container["runtime_min_available_gib"] >= container["min_available_gib"]:
        raise LetsInferError(
            "manifest.container.runtime_min_available_gib must be below the launch floor"
        )
    if container.get("model_cache") != "/models":
        raise LetsInferError("manifest.container.model_cache must be /models")
    cpuset = container.get("cpuset_cpus")
    if cpuset is not None and (
        not isinstance(cpuset, str)
        or re.fullmatch(
            r"(?:0|[1-9][0-9]*)(?:-(?:0|[1-9][0-9]*))?"
            r"(?:,(?:0|[1-9][0-9]*)(?:-(?:0|[1-9][0-9]*))?)*",
            cpuset,
        )
        is None
    ):
        raise LetsInferError(
            "manifest.container.cpuset_cpus must be a canonical Docker CPU set"
        )
    gpu_floor_keys = {"min_gpu_free_gib", "runtime_min_gpu_free_gib"}
    present_gpu_floors = gpu_floor_keys.intersection(container)
    if target["memory"]["topology"] == "unified" and present_gpu_floors:
        raise LetsInferError(
            "unified-memory targets cannot declare separate GPU-memory floors"
        )
    if target["memory"]["topology"] == "discrete":
        if present_gpu_floors != gpu_floor_keys:
            raise LetsInferError(
                "discrete-memory targets require launch and runtime GPU floors"
            )
        for key in gpu_floor_keys:
            value = container[key]
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise LetsInferError(f"manifest.container.{key} must be positive")
        if container["runtime_min_gpu_free_gib"] >= container["min_gpu_free_gib"]:
            raise LetsInferError(
                "manifest.container.runtime_min_gpu_free_gib must be below the launch floor"
            )

    expected_watchdog = {
        "listen": "0.0.0.0",
        "protocol_version": WATCHDOG_PROTOCOL_VERSION,
        "port": 9768,
        **core_watchdog_contract(),
        "build": {
            "source_root": "watchdog",
            "target": "letsinfer_watchdog",
            "output": "letsinfer-watchdog",
        },
    }
    if manifest.get("watchdog") != expected_watchdog:
        raise LetsInferError("manifest.watchdog must equal the core Watchdog contract")

    serving = _require(manifest, "serving", dict, "manifest")
    allowed_serving = {
        "qualified",
        "max_connections",
        "max_active_requests",
        "max_context_tokens",
        "gate",
        "blocked_by",
    }
    _reject_unknown_fields(serving, allowed_serving, "manifest.serving")
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
    if status == "stable" and not serving["qualified"]:
        raise LetsInferError("stable execution manifest must be qualified")
    if status == "candidate":
        blocked_by = serving.get("blocked_by")
        if not isinstance(blocked_by, str) or not MANIFEST_CODE_RE.fullmatch(
            blocked_by
        ):
            raise LetsInferError(
                "candidate execution manifest requires a machine-identifier blocked_by"
            )

    try:
        validate_engine_manifest(manifest)
        launch_for(manifest, serving, 8000)
    except EngineManifestError as error:
        raise LetsInferError(str(error)) from error
    if "orchestration" in manifest:
        try:
            validate_orchestration_contract(manifest["orchestration"])
        except OrchestrationError as error:
            raise LetsInferError(str(error)) from error


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


def verify_runtime_sources(manifest: dict[str, Any], root: pathlib.Path) -> None:
    """Verify runtime bytes without interpreting engine-owned source code."""

    validate_manifest(manifest)
    descriptor = root / "letsinfer-runtime.json"
    if descriptor.is_file() and not descriptor.is_symlink():
        try:
            pack = verify_descriptor(root)
        except RuntimePackError as error:
            raise LetsInferError(str(error)) from error
        if runtime_execution_manifest(
            pack.runtime,
            qualified=manifest["serving"]["qualified"],
            blocked_by=manifest["serving"].get("blocked_by", "runtime-unqualified"),
        ) != manifest:
            raise LetsInferError(
                "runtime descriptor and private execution manifest disagree"
            )
        return
    if "source_artifacts" in manifest or "runtime_plugins" in manifest:
        raise LetsInferError(
            "Engine OCI source and plugins cannot be supplied by core manifests"
        )


def runtime_source_root(manifest_path: pathlib.Path) -> pathlib.Path:
    """Return the private immutable control root for a runtime execution view."""
    if manifest_path.name != "runtime-execution.json":
        raise LetsInferError("installed runtime manifest must be runtime-execution.json")
    return manifest_path.parent


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
                f"installed runtime receipt digest mismatch: {receipt['candidate_id']}"
            )
        control_root = pathlib.Path(receipt["control_root"]).expanduser()
        manifest_path = pathlib.Path(receipt["manifest_path"]).expanduser()
        _, manifest = validate_control_bundle(
            control_root,
            manifest_path,
            sha256_file(manifest_path),
        )
        if (
            pack.runtime["id"] != receipt["candidate_id"]
            or pack.runtime["logical_model"] != receipt["logical_model"]
            or pack.runtime["engine"]["id"] != receipt["engine"]
            or pack.runtime["target"]["id"] != receipt["target"]
            or manifest["model"]["alias"] != receipt["logical_model"]
            or adapter_for(manifest).name != receipt["engine"]
            or target_contract(manifest)["id"] != receipt["target"]
            or target_contract_sha256(target_contract(manifest))
            != receipt["target_contract_sha256"]
        ):
            raise LetsInferError(
                f"installed runtime receipt identity mismatch: {receipt['candidate_id']}"
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
    target: str | None = None,
) -> tuple[pathlib.Path, dict[str, Any]]:
    available: list[tuple[pathlib.Path, dict[str, Any]]] = []
    runtime_names: dict[tuple[str, str, str], str] = {}
    selected_runtimes: dict[
        tuple[str, str, str],
        tuple[pathlib.Path, dict[str, Any], dict[str, Any]],
    ] = {}
    for path, manifest, receipt in installed_runtime_manifests():
        target_id = target_contract(manifest)["id"]
        key = (manifest["model"]["alias"], adapter_for(manifest).name, target_id)
        candidate_rank = receipt["installed_at"]
        current = selected_runtimes.get(key)
        if current is not None and candidate_rank <= current[2]["installed_at"]:
            continue
        selected_runtimes[key] = (path, manifest, receipt)
    for key in sorted(selected_runtimes):
        path, manifest, receipt = selected_runtimes[key]
        target_id = key[2]
        available.append((path, manifest))
        runtime_names[(manifest["release"], adapter_for(manifest).name, target_id)] = receipt[
            "candidate_id"
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
        if target is None or target_id == target:
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
            "specify an exact runtime candidate or target"
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
    if runtime_artifact_root is None:
        raise LetsInferError("engine launch requires an immutable runtime artifact")
    runtime_path = runtime_artifact_root.expanduser().resolve(strict=True)
    try:
        runtime_path.relative_to(default_runtime_home().expanduser().resolve(strict=True))
    except (OSError, ValueError) as error:
        raise LetsInferError(
            "engine launch runtime artifact must be installed under LETSINFER_HOME"
        ) from error
    runtime_command: tuple[str, ...] | None = None
    if group_context is not None:
        required_group = {
            "group_id", "member_id", "task_id", "launcher",
            "command", "environment", "port_base", "port_count",
            "endpoint_owner", "readiness", "device_uuids",
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
            or not isinstance(group_context["endpoint_owner"], bool)
            or not isinstance(group_context["device_uuids"], list)
            or not group_context["device_uuids"]
            or len(group_context["device_uuids"])
            != len(set(group_context["device_uuids"]))
            or any(
                not isinstance(device_uuid, str) or not device_uuid
                for device_uuid in group_context["device_uuids"]
            )
            or group_config_file is None
        ):
            raise LetsInferError("engine-group container identity is invalid")
        if group_context["launcher"] == "runtime-command":
            raw_command = group_context["command"]
            if not isinstance(raw_command, list) or not raw_command:
                raise LetsInferError("runtime-owned engine-group command is invalid")
            runtime_command = tuple(raw_command)
        elif group_context["launcher"] != "manifest" or group_context["command"] != []:
            raise LetsInferError("engine-group launcher is invalid")
    elif group_config_file is not None:
        raise LetsInferError("engine-group configuration requires a group context")
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
                "--label", f"{GROUP_NODE_LABEL}={group_context['member_id']}",
                "--label", f"{GROUP_TASK_LABEL}={group_context['task_id']}",
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
        runtime_command[0] if runtime_command is not None else launch.command[0],
        "--network",
        "host",
        "--ipc",
        "host",
        "--gpus",
        (
            "all"
            if group_context is None
            else "device=" + ",".join(group_context["device_uuids"])
        ),
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
        f"{model_cache}:/models:ro",
        "-v",
        f"{runtime_path}:/opt/letsinfer/runtime-pack:ro",
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
        command.extend([
            "-v", f"{group_path}:/run/letsinfer/group.json:ro",
            "-e", "LETSINFER_GROUP_CONFIG=/run/letsinfer/group.json",
            "-e", f"LETSINFER_GROUP_ID={group_context['group_id']}",
            "-e", f"LETSINFER_NODE_ID={group_context['member_id']}",
            "-e", f"LETSINFER_TASK_ID={group_context['task_id']}",
            "-e", f"LETSINFER_PORT_BASE={group_context['port_base']}",
            "-e", f"LETSINFER_PORT_COUNT={group_context['port_count']}",
            "-e", f"LETSINFER_ENGINE_PORT={group_context['port_base'] if group_context['endpoint_owner'] else -1}",
            "-e", "LETSINFER_ENGINE_CREDENTIAL_FILE=/run/secrets/letsinfer-api-key",
            "-e", "LETSINFER_TLS_CERT_FILE=/run/secrets/letsinfer-tls.crt",
            "-e", "LETSINFER_TLS_KEY_FILE=/run/secrets/letsinfer-tls.key",
        ])
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
        command.extend(launch.command[1:])
    return command


def parse_mem_available_gib(text: str) -> int:
    return parse_mem_available_bytes(text) // (1024**3)


def parse_mem_available_bytes(text: str) -> int:
    for line in text.splitlines():
        fields = line.split()
        if fields and fields[0] == "MemAvailable:" and len(fields) >= 2:
            return int(fields[1]) * 1024
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
    if identity.role != "main":
        raise LetsInferError(
            "local fact publication for members requires the authenticated "
            "child-control channel"
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


_SENSITIVE_ARGUMENT_NAMES = frozenset(
    {
        "authorization",
        "code",
        "cookie",
        "credential",
        "password",
        "secret",
        "token",
    }
)
_LABELED_SECRET_RE = re.compile(
    r"(?i)\b(api[_-]?key|authorization|cookie|credential|password|secret|token)"
    r"(\s*[:=]\s*)(?:bearer\s+)?([^\s,;]+)"
)


def _safe_diagnostic(value: str, *, max_lines: int = 24, max_chars: int = 4096) -> str:
    """Bound and neutralize untrusted child output before terminal display."""

    # Strip complete ANSI control sequences before scanning for labeled
    # credentials.  Replacing ESC alone can leave a trailing ``m`` adjacent to
    # ``Authorization`` and defeat the word-boundary match.
    value = ui.ANSI.sub("", value)
    redacted = _LABELED_SECRET_RE.sub(
        lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]",
        value,
    )
    neutral = "".join(
        character
        if character in {"\n", "\t"}
        or unicodedata.category(character) not in {"Cc", "Cf"}
        else "?"
        for character in redacted
    )
    lines = neutral.splitlines()[-max_lines:]
    bounded = []
    for line in lines:
        if len(line) > 512:
            line = line[:248] + " … " + line[-248:]
        bounded.append(line)
    result = "\n".join(bounded).strip()
    if len(result) > max_chars:
        result = "[diagnostic truncated]\n" + result[-(max_chars - 23) :]
    return result


def _display_command(command: Sequence[str]) -> str:
    """Return a bounded command description with credential values removed."""

    rendered: list[str] = []
    redact_next = False
    for raw in command:
        value = str(raw)
        if redact_next:
            rendered.append("[REDACTED]")
            redact_next = False
            continue
        if value.startswith("--"):
            name, separator, inline = value[2:].partition("=")
            normalized = name.lower().replace("_", "-")
            words = set(normalized.split("-"))
            sensitive = bool(words & _SENSITIVE_ARGUMENT_NAMES) or "api-key" in normalized
            location_only = normalized.endswith(
                ("-file", "-path", "-dir", "-directory")
            )
            if sensitive and not location_only:
                if separator:
                    rendered.append(f"--{name}=[REDACTED]")
                else:
                    rendered.append(value)
                    redact_next = True
                continue
        safe = _safe_diagnostic(value, max_lines=1, max_chars=512)
        rendered.append(safe or "?")
    return shlex.join(rendered)


def run(command: Sequence[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, text=True, capture_output=True, check=check)
    except FileNotFoundError as error:
        raise LetsInferError(
            f"required command is unavailable: {_display_command(command[:1])}"
        ) from error
    except subprocess.CalledProcessError as error:
        detail = _safe_diagnostic(error.stderr or error.stdout or "")
        suffix = f": {detail}" if detail else ""
        raise LetsInferError(
            f"command failed: {_display_command(command)}{suffix}"
        ) from error


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
    descriptor = (
        "version=1\n"
        + "".join(f"{name}={value}\n" for name, value in values.items())
        + f"cache_persistent={str(persistent_cache_for(manifest)).lower()}\n"
        + f"inference_port={config['gateway_port']}\n"
        + f"max_connections={serving['max_connections']}\n"
        + f"max_active_requests={serving['max_active_requests']}\n"
        + f"max_context_tokens={serving['max_context_tokens']}\n"
    )
    write_text(path, descriptor)
    path.chmod(0o600)
    # The manifest-addressed descriptor remains durable evidence. The resident
    # Watchdog follows this stable, atomically replaced projection so a runtime
    # switch does not require restarting the protector or its telemetry stream.
    active = path.parent / "site.state"
    write_text(active, descriptor)
    active.chmod(0o600)
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
        # The descriptor may have been lost while Watchdog still retains the
        # already-bound pidfd in memory. Recreate an explicit disarmed
        # generation and require its acknowledgement; treating a missing file
        # as unprotected would let a planned stop look like a crash.
        publish_protection_state(
            config,
            secrets.token_hex(16),
            "disarmed",
            wait_for_ack=wait_for_ack,
        )
        return
    try:
        current = _parse_protection_lines(state_path)
        generation = current["generation"]
        publish_protection_state(
            config, generation, "disarmed", wait_for_ack=wait_for_ack
        )
    except (KeyError, OSError, UnicodeError) as error:
        raise LetsInferError(f"cannot disarm Watchdog protection: {error}") from error


def disarm_before_planned_stop(config: dict[str, Any]) -> None:
    """Acknowledge disarm before any deliberate managed-process exit."""
    disarm_protection(config)


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


def retire_qualification_protection_slot(config: dict[str, Any]) -> None:
    """Remove one safely retired qualification target from Watchdog's slot table."""
    root = expanded_path(config["protection_root"])
    if not root.exists():
        return
    if root.is_symlink():
        raise LetsInferError("qualification protection root cannot be a symlink")
    try:
        expected = (
            expanded_path(config["watchdog_data_root"])
            / PROTECTION_ROOT_NAME
            / config["placement_id"]
        )
    except (KeyError, TypeError) as error:
        raise LetsInferError(
            "qualification protection slot has an incomplete identity"
        ) from error
    try:
        if root.resolve(strict=True) != expected.resolve(strict=True):
            raise LetsInferError(
                "refusing to retire a non-canonical qualification protection slot"
            )
    except OSError as error:
        raise LetsInferError(
            f"cannot resolve qualification protection slot: {error}"
        ) from error
    details = root.stat()
    if (
        not stat.S_ISDIR(details.st_mode)
        or details.st_uid != os.getuid()
        or stat.S_IMODE(details.st_mode) & 0o077
    ):
        raise LetsInferError(
            "qualification protection root must be private and user-owned"
        )
    if protection_trip_latched(config):
        raise LetsInferError(
            "refusing to retire a qualification protection slot with a latched trip"
        )

    state_path, _, _ = protection_paths(config)
    if state_path.is_file():
        phase = _parse_protection_lines(state_path).get("phase")
        if phase in {"starting", "armed"}:
            # Watchdog intentionally retains a missing live target. Publish and
            # await an explicit disarmed generation before removing the
            # directory so its bounded in-memory slot can be released safely.
            disarm_protection(config)
            phase = _parse_protection_lines(state_path).get("phase")
        if phase not in {"pending", "disarmed"}:
            raise LetsInferError(
                f"qualification protection slot is not safely retired: {phase or 'invalid'}"
            )

    shutil.rmtree(root)
    _fsync_path(root.parent)


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
    verify_runtime_sources(manifest, root)
    return contained_manifest, manifest


def install_control_bundle(
    manifest_path: pathlib.Path,
    manifest: dict[str, Any],
    *,
    control_parent: pathlib.Path | None = None,
    core_source_root: pathlib.Path | None = None,
) -> tuple[pathlib.Path, pathlib.Path]:
    core_records, core_manifest, core_identity = _core_release(
        core_source_root or source_root()
    )
    manifest_data = canonical_bytes(manifest)
    manifest_sha = hashlib.sha256(manifest_data).hexdigest()
    bundle_identity = _control_bundle_identity(core_identity, manifest_sha)
    parent = control_parent or default_control_parent()
    ensure_private_directory(parent)
    destination = parent / bundle_identity
    destination_manifest = destination / "runtime-execution.json"
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
        staged_manifest = staging / "runtime-execution.json"
        if staged_manifest in targets:
            raise LetsInferError("release manifest collides with a source artifact")
        descriptor = os.open(
            staged_manifest,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o400,
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(manifest_data)
            handle.flush()
            os.fsync(handle.fileno())
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
        "max_controllers": WATCHDOG_CONTROLLER_STREAM_FLOOR,
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
    path = config_path or active_service_config_path()
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
    public_state = None
    if runtime_manifest is not None:
        active_config_path = active_service_config_path()
        if active_config_path.is_file():
            active_config = read_service_config(active_config_path)
            public_state = write_watchdog_public_state(
                active_config, runtime_manifest
            ).parent / "site.state"
    if public_state is None:
        public_state = write_core_watchdog_public_state(
            identity.installation_id, source_sha256
        )
    if identity.role == "main":
        listen = "0.0.0.0"
        allowlist = ensure_controller_authorization(
            identity, default_watchdog_local_controller_cert_path()
        )
    elif identity.role == "child":
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
    return config, {"watchdog": core_watchdog_contract()}


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
    if identity.role != "child":
        raise LetsInferError("child Watchdog authorization requires a child identity")
    fingerprint = certificate_sha256(local_certificate)
    controller_id = hashlib.sha256(
        (
            "letsinfer-child-watchdog-v1\n"
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
    for parent in {path.parent for path in paths}:
        ensure_private_directory(parent)
    staging = pathlib.Path(
        tempfile.mkdtemp(prefix=".watchdog-tls-", dir=key_path.parent)
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
    presenter = _human_presenter()
    pairing_code = format_pairing_code(setup_code)
    if presenter is not None:
        presenter.result(
            "Pairing is ready",
            semantic=command_ui.Semantic.INFO,
            detail=(
                f"Listening for one controller on port {CONTROLLER_PAIRING_PORT} "
                f"for {arguments.timeout} seconds"
            ),
        )
        presenter.verbatim(pairing_code, label="Pair code", copyable=True)
    else:
        print(f"PAIR CODE {pairing_code}")
        print(
            f"Listening for one controller on port {CONTROLLER_PAIRING_PORT} "
            f"for {arguments.timeout}s."
        )
    try:
        waiting = _command_activity(
            arguments, "Waiting for a controller", action_id="pair"
        )
        with waiting, ui.protect_stdout(waiting):
            with state.condition:
                while (
                    state.candidate is None
                    and state.error is None
                    and time.monotonic() < state.deadline
                ):
                    state.condition.wait(
                        timeout=max(0.1, state.deadline - time.monotonic())
                    )
                if state.candidate is None:
                    raise LetsInferError(state.error or "controller pairing timed out")
                candidate = state.candidate
        verification_code = (
            f"{candidate['confirmation_code'][:3]}-"
            f"{candidate['confirmation_code'][3:]}"
        )
        if presenter is not None:
            presenter.records(
                (
                    command_ui.RecordRow("Controller", candidate["name"]),
                    command_ui.RecordRow(
                        "Verify",
                        verification_code,
                        semantic=command_ui.Semantic.WARNING,
                    ),
                )
            )
        else:
            print(f"Controller: {candidate['name']}")
            print(f"VERIFY {verification_code}")
        with state.condition:
            state.approved = ui.confirm(
                "Does this verification code match the Mac?"
            )
            state.condition.notify_all()
            completing = _command_activity(
                arguments, "Completing controller pairing", action_id="pair"
            )
            with completing, ui.protect_stdout(completing):
                while (
                    not state.completed
                    and state.error is None
                    and time.monotonic() < state.deadline
                ):
                    state.condition.wait(
                        timeout=max(0.1, state.deadline - time.monotonic())
                    )
                if not state.completed:
                    raise LetsInferError(
                        state.error or "controller pairing was not completed"
                    )
        if presenter is not None:
            presenter.result(
                f"Paired {candidate['name']}",
                semantic=command_ui.Semantic.SUCCESS,
                detail=candidate["id"],
            )
        else:
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
            result = {
                "controller_id": matches[0]["controller_id"],
                "name": matches[0]["name"],
                "revoked": True,
            }
            if arguments.json:
                print(json.dumps(result, sort_keys=True))
                return 0
            presenter = _human_presenter()
            if presenter is not None:
                presenter.result(
                    f"Controller {matches[0]['name']} revoked",
                    semantic=command_ui.Semantic.SUCCESS,
                    detail=matches[0]["controller_id"],
                )
            else:
                print(
                    f"FORGOT {matches[0]['name']} "
                    f"controller={matches[0]['controller_id']}"
                )
            return 0
    if arguments.json:
        print(json.dumps({"installation_id": config["installation_id"], "controllers": rows}, indent=2))
    else:
        presenter = _human_presenter()
        if presenter is not None:
            presenter.table(
                (
                    command_ui.TableColumn("name", "NAME", min_width=8),
                    command_ui.TableColumn("role", "ROLE", min_width=6),
                    command_ui.TableColumn("controller_id", "CONTROLLER", min_width=12),
                    command_ui.TableColumn(
                        "created_at_unix",
                        "PAIRED",
                        min_width=10,
                        formatter=lambda value, _row: dt.datetime.fromtimestamp(
                            int(value)
                        ).astimezone().isoformat(),
                    ),
                ),
                rows,
                empty_message="No controllers are paired",
            )
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

    ensure_private_directory(key_path.parent)
    ensure_private_directory(cert_path.parent)
    staging = pathlib.Path(tempfile.mkdtemp(prefix=".tls-generate-", dir=key_path.parent))
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
    digest = actual.removeprefix("sha256:")
    receipt = oci_root() / "engines" / f"{digest}.json"
    ensure_private_directory(receipt.parent.parent)
    ensure_private_directory(receipt.parent)
    atomic_json(
        receipt,
        {
            "schema_version": 1,
            "kind": "engine-oci",
            "engine": adapter_for(manifest).name,
            "reference": image["reference"],
            "immutable_id": actual,
            "platform": actual_platform,
            "verified_at_unix_ns": time.time_ns(),
        },
    )
    return actual


def model_artifacts(manifest: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    """Return all exact dependencies with their deterministic shared-store paths."""
    return tuple(
        {**artifact, "storage_slug": artifact_storage_slug(artifact)}
        for artifact in manifest["artifacts"]
    )


def artifact_snapshot_path(
    artifact: dict[str, Any], model_cache: pathlib.Path
) -> pathlib.Path:
    return (
        model_cache / artifact["storage_slug"] / artifact["revision"]
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
    if model_file.is_symlink() or not model_file.is_file():
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
        destination = artifact_snapshot_path(artifact, model_cache)
        if destination.is_dir():
            continue
        parent = destination.parent
        ensure_private_directory(parent)
        staging = parent / f".{artifact['revision']}.incoming-{secrets.token_hex(8)}"
        staging.mkdir(mode=0o700)
        container_destination = (
            f"/model-store/{artifact['storage_slug']}/{staging.name}"
        )
        download_arguments = (
            f"repo_id={artifact['repository']!r}, revision={artifact['revision']!r}, "
            f"local_dir={container_destination!r}"
        )
        if "filename" in artifact:
            download_arguments += f", allow_patterns={[artifact['filename']]!r}"
        script = (
            "from huggingface_hub import snapshot_download; "
            f"snapshot_download({download_arguments})"
        )
        try:
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
                    f"{model_cache}:/model-store",
                    "-e",
                    "HF_HOME=/tmp/huggingface",
                    "-e",
                    "HOME=/tmp",
                    manifest["model"]["acquisition_image"],
                    "-c",
                    script,
                ]
            )
            metadata = staging / ".cache"
            if metadata.exists():
                shutil.rmtree(metadata)
            invalid = [
                path
                for path in staging.rglob("*")
                if path.is_symlink() or (not path.is_file() and not path.is_dir())
            ]
            if invalid:
                raise LetsInferError(
                    f"downloaded model contains an unsafe entry: {invalid[0]}"
                )
            if "filename" in artifact:
                _verify_gguf_artifact(artifact, staging, model_cache)
            try:
                staging.replace(destination)
            except FileExistsError:
                shutil.rmtree(staging)
            _fsync_path(parent)
        except BaseException:
            if staging.exists():
                shutil.rmtree(staging)
            raise
    return verify_model_snapshot(manifest, model_cache)


def verify_installed_runtime(
    manifest: dict[str, Any],
    *,
    model_cache: pathlib.Path,
) -> str:
    """Verify exact model bytes and the adapter baked into the Engine OCI."""

    verify_model_snapshot(manifest, model_cache)
    actual_image_id = image_id(manifest)
    result = run(
        [
            "docker",
            "run",
            "--rm",
            "--pull",
            "never",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges=true",
            "--entrypoint",
            ENGINE_ADAPTER,
            manifest["image"]["reference"],
            "verify",
            "--protocol",
            str(ENGINE_PROTOCOL_VERSION),
        ],
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip() or "no adapter output"
        raise LetsInferError(f"Engine OCI protocol verification failed: {detail}")
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise LetsInferError("Engine OCI adapter verification returned invalid JSON") from error
    if report != {
        "engine_protocol": ENGINE_PROTOCOL_VERSION,
        "status": "ok",
    }:
        raise LetsInferError("Engine OCI adapter verification returned the wrong contract")
    return actual_image_id


def run_passthrough(
    command: Sequence[str],
    *,
    visible: bool = False,
    failure_label: str | None = None,
) -> None:
    """Run a child without letting routine build output take over the TTY.

    Human commands keep their progress owner active and receive a concise tail
    only when the child fails. Raw commands and authentication prompts opt into
    direct terminal ownership. Redirected/noninteractive execution retains the
    original byte-for-byte passthrough behavior.
    """

    interactive = _human_presenter() is not None
    direct = (
        visible
        or (not interactive and failure_label is None)
        or pathlib.Path(command[0]).name == "sudo"
    )
    if direct:
        ui.before_external_output()
        try:
            subprocess.run(command, text=True, check=True)
        except FileNotFoundError as error:
            raise LetsInferError(
                f"required command is unavailable: {_display_command(command[:1])}"
            ) from error
        except subprocess.CalledProcessError as error:
            raise LetsInferError(
                f"command failed: {_display_command(command)}"
            ) from error
        return

    try:
        with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as output:
            result = subprocess.run(
                command,
                text=True,
                stdout=output,
                stderr=subprocess.STDOUT,
                check=False,
            )
            if result.returncode == 0:
                return
            output.seek(0)
            lines = output.read().splitlines()
    except FileNotFoundError as error:
        raise LetsInferError(
            f"required command is unavailable: {_display_command(command[:1])}"
        ) from error
    tail = _safe_diagnostic("\n".join(lines))
    detail = f"\n{tail}" if tail else ""
    if failure_label is not None:
        for line in reversed(lines):
            candidate = line.strip()
            if candidate.startswith("ERROR:"):
                concise = _safe_diagnostic(candidate.removeprefix("ERROR:").strip())
                detail = f": {concise}" if concise else ""
                break
        raise LetsInferError(
            f"{failure_label} failed ({result.returncode}){detail}"
        )
    raise LetsInferError(
        f"command failed ({result.returncode}): {_display_command(command)}{detail}"
    )


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
            state = inspection.get("State", {}) if inspection is not None else {}
            if state.get("OOMKilled") is True:
                raise LetsInferError(
                    "Engine container was OOM-killed during startup; "
                    "the launch evidence contains its inspect state and server log"
                )
            exit_code = state.get("ExitCode")
            runtime_error = str(state.get("Error") or "").strip()
            details: list[str] = []
            if isinstance(exit_code, int) and not isinstance(exit_code, bool):
                details.append(f"exit code {exit_code}")
            if runtime_error:
                details.append(_safe_diagnostic(runtime_error))
            suffix = f" ({'; '.join(details)})" if details else ""
            raise LetsInferError(f"Engine container exited during startup{suffix}")
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
    return evidence_root() / "launches" / (
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


def prepare_new_launch(
    manifest: dict[str, Any],
    *,
    qualification_config: dict[str, Any] | None,
    qualification_existing: bool,
    name: str,
    api_key_file: pathlib.Path,
) -> tuple[dict[str, Any], dict[str, tuple[str, str]] | None]:
    """Admit one launch, transactionally replacing a resident for qualification."""
    resident_handoff: dict[str, tuple[str, str]] | None = None
    if qualification_config is not None:
        resident_handoff = _quiesce_resident_runtime_for_qualification()
    try:
        # A qualification candidate replaces the resident model in the single
        # local inference slot. Measure launch headroom only after that exact
        # resident has been quiesced; otherwise unified-memory hosts reject a
        # safe replacement because both models appear resident at once.
        memory = require_memory_reserve(manifest, phase="launch")
        if qualification_config is not None:
            if qualification_existing:
                # Even when the candidate descriptor was lost, the resident
                # Watchdog may still be bound to this exact single-slot
                # container. Recreate the slot's disarmed generation and wait
                # for acknowledgement before the orphaned process can exit.
                disarm_protection(qualification_config)
                _stop_managed_container(name, api_key_file)
            _activate_qualification_candidate(qualification_config, manifest)
    except BaseException:
        if resident_handoff is not None:
            _restore_resident_runtime_after_qualification(resident_handoff)
        raise
    return memory, resident_handoff


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
    presenter = None if arguments.dry_run else _human_presenter()
    manifest_path, manifest = resolved_release or resolve_model(
        arguments.model,
        target=getattr(arguments, "target", None),
    )
    verify_runtime_sources(
        manifest,
        release_root or runtime_source_root(manifest_path),
    )
    serving = manifest["serving"]
    qualification_mode = bool(getattr(arguments, "qualification_mode", False))
    authorize_serving_launch(
        serving,
        qualification_mode=qualification_mode,
        evidence_dir=arguments.evidence_dir,
    )
    if qualification_mode and not serving["qualified"]:
        if presenter is not None:
            presenter.result(
                "Unqualified runtime",
                semantic=command_ui.Semantic.WARNING,
                detail=f"Qualification mode: {serving['blocked_by']}",
            )
        else:
            print(
                "WARNING: qualification launch of unqualified serving configuration: "
                f"{serving['blocked_by']}",
                file=sys.stderr,
            )
    resume_progress = (
        qualification_mode and not serving["qualified"] and presenter is not None
    )

    name = arguments.name or f"letsinfer-{adapter_for(manifest).name.replace('.', '-')}"
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name):
        raise LetsInferError("container name contains unsupported characters")
    requested_port = getattr(arguments, "port", None)
    if requested_port is None:
        if qualification_mode:
            resident_path = default_service_config_path()
            if not resident_path.is_file():
                raise LetsInferError(
                    "qualification requires an installed Let's Infer service for "
                    "its internal engine port"
                )
            port = read_service_config(resident_path)["engine_port"]
        else:
            port = 8000
    else:
        port = requested_port
    model_cache = requested_model_cache(arguments.model_cache)
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
    manifest_sha256 = sha256_file(manifest_path)
    supplied_runtime_root = getattr(arguments, "runtime_artifact_root", None)
    runtime_digest = getattr(arguments, "runtime_digest", None)
    runtime_receipt = runtime_receipt_for_manifest(manifest_path)
    if supplied_runtime_root is not None:
        runtime_artifact_root = pathlib.Path(supplied_runtime_root).expanduser()
        if runtime_digest is None:
            try:
                runtime_digest = verify_descriptor(runtime_artifact_root).digest
            except RuntimePackError as error:
                raise LetsInferError(str(error)) from error
    else:
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
        store_root=store_root,
        runtime_cache_root=runtime_cache_root,
        api_key_file=api_key_file,
        tls_cert_file=tls_cert_file,
        tls_key_file=tls_key_file,
        runtime_artifact_root=runtime_artifact_root,
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

    def prepare_launch() -> tuple[dict[str, Any], str]:
        host_value = verify_host_target(manifest)
        ensure_image(
            manifest,
            build=qualification_mode,
            artifact_root=runtime_artifact_root,
        )
        return host_value, verify_installed_runtime(
            manifest, model_cache=model_cache
        )

    if resume_progress:
        preparing = _command_activity(
            arguments,
            "Preparing the qualification runtime",
            action_id="serve",
        )
        with preparing, ui.protect_stdout(preparing):
            host, actual_image_id = prepare_launch()
    else:
        host, actual_image_id = prepare_launch()

    def await_runtime() -> None:
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

    def wait_for_runtime() -> None:
        if not resume_progress:
            await_runtime()
            return
        waiting = _command_activity(
            arguments, "Waiting for inference readiness", action_id="serve"
        )
        with waiting, ui.protect_stdout(waiting):
            await_runtime()
    api_key = read_api_key(api_key_file)
    validate_tls_material(tls_cert_file, tls_key_file)
    evidence = expanded_path(
        arguments.evidence_dir or default_evidence_dir(manifest)
    )
    qualification_config: dict[str, Any] | None = None
    qualification_existing = False
    resident_handoff: dict[str, tuple[str, str]] | None = None
    if qualification_mode:
        if evidence.exists():
            raise LetsInferError(f"refusing existing evidence directory: {evidence}")
        # Retire the previous candidate before refreshing topology. Its exact
        # protection slot may contain a candidate-only trip; retaining that
        # orphan in the node-wide inventory would incorrectly make otherwise
        # compatible hardware unavailable for the replacement.
        _retire_qualification_candidate(remove_container=True)
        qualification_config = _qualification_config(
            manifest_path=manifest_path,
            manifest=manifest,
            release_root=release_root or runtime_source_root(manifest_path),
            manifest_sha256=manifest_sha256,
            name=name,
            port=port,
            model_cache=model_cache,
            store_root=store_root,
            runtime_cache_root=runtime_cache_root,
            api_key_file=api_key_file,
            tls_cert_file=tls_cert_file,
            tls_key_file=tls_key_file,
            evidence_dir=evidence,
            runtime_receipt=runtime_receipt,
        )
        protection_config = qualification_config
    else:
        protection_config = protection_config_for_serve(
            getattr(arguments, "protection_config", None), name=name
        )
    protection_generation = secrets.token_hex(16) if protection_config else None
    inspection = container_inspect(name)
    if inspection is not None and qualification_config is not None:
        labels = inspection.get("Config", {}).get("Labels") or {}
        if labels.get(MANAGED_LABEL) != "true":
            raise LetsInferError(
                f"container {name} is not managed by Let's Infer; refusing to replace it"
            )
        qualification_existing = True
        inspection = None
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
            wait_for_runtime()
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
            if presenter is not None:
                presenter.records(
                    (
                        command_ui.RecordRow(
                            "Runtime",
                            manifest["model"]["alias"],
                            semantic=command_ui.Semantic.SUCCESS,
                        ),
                        command_ui.RecordRow("Container", name, "Existing"),
                        command_ui.RecordRow("Port", port),
                        command_ui.RecordRow(
                            "Guard",
                            "Armed" if protection_config else "Not configured",
                        ),
                    )
                )
            else:
                print(f"HEALTHY {name} existing=true")
            return 0
        except BaseException:
            if protection_config and not protection_trip_latched(protection_config):
                disarm_before_planned_stop(protection_config)
            raise

    evidence.mkdir(parents=True, exist_ok=False)
    ensure_private_directory(store_root)
    ensure_runtime_home(runtime_cache_root)
    memory, resident_handoff = prepare_new_launch(
        manifest,
        qualification_config=qualification_config,
        qualification_existing=qualification_existing,
        name=name,
        api_key_file=api_key_file,
    )
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

        wait_for_runtime()
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
        if qualification_config is not None:
            update_service_placement(qualification_config, manifest, "running")
        atomic_json(evidence / "launch.json", launch)
        collect_container_evidence(
            name, evidence, secrets_to_redact=(api_key,)
        )
    except BaseException as error:
        if protection_config and not protection_trip_latched(protection_config):
            disarm_before_planned_stop(protection_config)
        if qualification_config is not None:
            update_service_placement(qualification_config, manifest, "failed")
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
        if qualification_config is not None:
            try:
                _retire_qualification_candidate(remove_container=True)
            finally:
                if resident_handoff is not None:
                    _restore_resident_runtime_after_qualification(resident_handoff)
        raise

    if presenter is not None:
        presenter.records(
            (
                command_ui.RecordRow(
                    "Runtime",
                    manifest["model"]["alias"],
                    semantic=command_ui.Semantic.SUCCESS,
                ),
                command_ui.RecordRow("Container", name, "Healthy"),
                command_ui.RecordRow("Port", port),
                command_ui.RecordRow(
                    "Guard", "Armed" if protection_config else "Not configured"
                ),
            )
        )
        presenter.verbatim(evidence, label="Evidence", copyable=True)
    else:
        print(f"HEALTHY {name} evidence={evidence}")
    return 0


def default_service_config_path() -> pathlib.Path:
    return site_config_root() / "service.json"


def qualification_service_config_path() -> pathlib.Path:
    """Return the single local qualification-slot descriptor."""
    return site_config_root() / "qualification.json"


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
    if not SAFE_NAME_RE.fullmatch(config["engine"]):
        raise LetsInferError("service configuration contains an invalid engine identity")
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
    if config["gateway_queue_timeout_seconds"] not in range(0, 3601):
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
    qualification_mode = config.get("qualification_mode")
    if qualification_mode is not None and not isinstance(qualification_mode, bool):
        raise LetsInferError("service configuration qualification_mode must be bool")
    if qualification_mode is True:
        evidence = config.get("qualification_evidence_dir")
        if not isinstance(evidence, str) or not pathlib.Path(evidence).is_absolute():
            raise LetsInferError(
                "qualification service configuration requires an absolute evidence directory"
            )
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
        "device_uuids": {
            member_id: list(placement.device_uuids[member_id])
            for member_id in placement.member_ids
        },
    }
    return {
        "placement_id": hashlib.sha256(canonical_bytes(identity_material)).hexdigest()[:32],
        "placement_strategy": placement.strategy,
        "placement_members": list(placement.member_ids),
        "topology_sha256": placement.topology_sha256,
    }


def logical_service_id(node_id: str, model: str) -> str:
    """Return the stable public service identity for one logical model."""
    return hashlib.sha256(
        canonical_bytes(
            {
                "contract": "letsinfer-model-service-v1",
                "node_id": node_id,
                "model": model,
            }
        )
    ).hexdigest()[:32]


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
    runtime_version = config.get("runtime_version", config["release"])
    runtime_digest = config.get("runtime_digest", config["manifest_sha256"])
    runtime_identity = (
        f"{manifest['model']['alias']}/{adapter.name}/"
        f"{target_contract(manifest)['id']}@{runtime_version}"
        f"@sha256:{runtime_digest}"
    )
    return {
        "placement_id": config["placement_id"],
        "service_id": logical_service_id(identity.site_id, manifest["model"]["alias"]),
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
            store.ensure_model_service(manifest["model"]["alias"])
            store.set_placement(service_placement_document(config, manifest, state))
    except SiteError as error:
        raise LetsInferError(f"cannot update service placement: {error}") from error


def _qualification_config(
    *,
    manifest_path: pathlib.Path,
    manifest: dict[str, Any],
    release_root: pathlib.Path,
    manifest_sha256: str,
    name: str,
    port: int,
    model_cache: pathlib.Path,
    store_root: pathlib.Path,
    runtime_cache_root: pathlib.Path,
    api_key_file: pathlib.Path,
    tls_cert_file: pathlib.Path,
    tls_key_file: pathlib.Path,
    evidence_dir: pathlib.Path,
    runtime_receipt: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Bind an explicit qualification launch to the site's one candidate slot."""
    resident_path = default_service_config_path()
    resident = (
        read_service_config(resident_path)
        if resident_path.is_file()
        else _qualification_core_plane_config()
    )
    control_root, installed_manifest_path = install_control_bundle(
        manifest_path,
        manifest,
    )
    placement = resolve_service_placement(manifest, manifest_sha256)
    candidate = dict(resident)
    for key in ("runtime_name", "runtime_version", "runtime_digest", "runtime_policy"):
        candidate.pop(key, None)
    candidate.update(
        {
            "schema_version": SERVICE_CONFIG_VERSION,
            "engine": adapter_for(manifest).name,
            "model": manifest["model"]["alias"],
            "release": manifest["release"],
            "manifest_sha256": manifest_sha256,
            "name": name,
            "engine_port": port,
            **placement,
            "model_cache": str(model_cache),
            "store_root": str(store_root),
            "runtime_cache_root": str(runtime_cache_root),
            "engine_api_key_file": str(api_key_file),
            "tls_cert_file": str(tls_cert_file),
            "tls_key_file": str(tls_key_file),
            "source_root": str(control_root),
            "manifest_path": str(installed_manifest_path),
            "memory_pressure_available_bytes": manifest["watchdog"]["protection"][
                "warning_available_bytes"
            ],
            "protection_root": str(
                expanded_path(resident["watchdog_data_root"])
                / PROTECTION_ROOT_NAME
                / placement["placement_id"]
            ),
            "qualification_mode": True,
            "qualification_evidence_dir": str(evidence_dir),
        }
    )
    if runtime_receipt is not None:
        required = ("candidate_id", "version", "digest", "policy")
        if not all(isinstance(runtime_receipt.get(key), str) for key in required):
            raise LetsInferError("qualification runtime receipt is incomplete")
        candidate.update(
            {
                "runtime_name": runtime_receipt["candidate_id"],
                "runtime_version": runtime_receipt["version"],
                "runtime_digest": runtime_receipt["digest"],
                "runtime_policy": runtime_receipt["policy"],
            }
        )
    candidate["watchdog_public_state_file"] = str(
        expanded_path(candidate["watchdog_data_root"])
        / WATCHDOG_PUBLIC_STATE_DIRECTORY
        / f"{manifest_sha256}.state"
    )
    return candidate


def _qualification_core_plane_config() -> dict[str, Any]:
    """Describe setup-owned services when no qualified runtime is resident yet."""
    watchdog_binary, watchdog_binary_sha256 = verify_active_core_watchdog()
    gateway = core_gateway_config()
    identity = ensure_installation_identity()
    return {
        **gateway,
        "gateway_api_key_file": str(default_api_key_path()),
        "engine_api_key_file": str(default_engine_api_key_path()),
        "tls_cert_file": str(default_tls_cert_path()),
        "tls_key_file": str(default_tls_key_path()),
        "watchdog_binary_path": str(watchdog_binary),
        "watchdog_binary_sha256": watchdog_binary_sha256,
        "watchdog_source_sha256": core_watchdog_source_identity(),
        "watchdog_data_root": str(default_watchdog_data_root()),
        "watchdog_listen": "0.0.0.0",
        "watchdog_port": 9768,
        "watchdog_cert_file": str(default_watchdog_cert_path()),
        "watchdog_key_file": str(default_watchdog_key_path()),
        "watchdog_controller_ca_file": str(default_watchdog_controller_ca_path()),
        "watchdog_controller_ca_key_file": str(
            default_watchdog_controller_ca_key_path()
        ),
        "watchdog_local_controller_cert_file": str(
            default_watchdog_local_controller_cert_path()
        ),
        "watchdog_local_controller_key_file": str(
            default_watchdog_local_controller_key_path()
        ),
        "installation_id": identity["installation_id"],
        "watchdog_controller_allowlist_file": str(
            default_controller_allowlist_path()
        ),
        "watchdog_public_state_file": str(
            default_watchdog_data_root()
            / WATCHDOG_PUBLIC_STATE_DIRECTORY
            / "site.state"
        ),
    }


def _restore_resident_watchdog_projection() -> None:
    resident_path = default_service_config_path()
    if not resident_path.is_file():
        return
    resident = read_service_config(resident_path)
    _, manifest = configured_release(resident)
    write_watchdog_public_state(resident, manifest)


def _quiesce_resident_placement() -> None:
    """Remove the boot selection from routing while its unit is stopped."""
    resident_path = default_service_config_path()
    if not resident_path.is_file():
        return
    resident = read_service_config(resident_path)
    _, manifest = configured_release(resident)
    update_service_placement(resident, manifest, "stopped")


def _quiesce_resident_runtime_for_qualification() -> dict[str, tuple[str, str]]:
    """Stop boot-owned inference while preserving its exact prior unit state."""
    units = (RECOVERY_TIMER_NAME, ENGINE_SERVICE_NAME)
    previous = {name: _unit_enabled_active(name) for name in units}
    safe_states = {"active", "inactive", "failed", "not-found"}
    for name, (_enabled, active) in previous.items():
        if active not in safe_states:
            raise LetsInferError(
                f"refusing qualification while {name} state is {active!r}"
            )
    if previous[RECOVERY_TIMER_NAME][1] == "active":
        run_passthrough(["systemctl", "--user", "stop", RECOVERY_TIMER_NAME])
    if previous[ENGINE_SERVICE_NAME][1] == "active":
        resident_path = default_service_config_path()
        if not resident_path.is_file():
            raise LetsInferError(
                "resident engine service is active without a service configuration"
            )
        disarm_before_planned_stop(read_service_config(resident_path))
        run_passthrough(["systemctl", "--user", "stop", ENGINE_SERVICE_NAME])
    for name, (_enabled, active) in previous.items():
        if active == "failed":
            run(["systemctl", "--user", "reset-failed", name])
    return previous


def _restore_resident_runtime_after_qualification(
    previous: Mapping[str, tuple[str, str]],
) -> None:
    """Roll back a failed candidate handoff to the prior boot-owned runtime."""
    _restore_resident_watchdog_projection()
    if previous.get(ENGINE_SERVICE_NAME, ("", ""))[1] == "active":
        if _unit_enabled_active(ENGINE_SERVICE_NAME)[1] != "active":
            run_passthrough(
                [
                    "systemctl",
                    "--user",
                    "start",
                    "--no-block",
                    ENGINE_SERVICE_NAME,
                ]
            )
    if previous.get(RECOVERY_TIMER_NAME, ("", ""))[1] == "active":
        if _unit_enabled_active(RECOVERY_TIMER_NAME)[1] != "active":
            run_passthrough(["systemctl", "--user", "start", RECOVERY_TIMER_NAME])


def _retire_qualification_candidate(*, remove_container: bool) -> None:
    """Retire the one candidate slot before replacement or resident recovery."""
    state_path = qualification_service_config_path()
    if not state_path.is_file():
        return
    config = read_service_config(state_path)
    if config.get("qualification_mode") is not True:
        raise LetsInferError("qualification slot has an invalid lifecycle mode")
    _, manifest = configured_release(config)
    inspection = container_inspect(config["name"])
    # A running candidate can be stopped only after the resident Watchdog has
    # observed the disarmed generation. An absent or already-stopped container
    # has no live process to protect; requiring a new acknowledgement there is
    # both unnecessary and can deadlock retirement after the Watchdog has
    # already restored its resident projection.
    if inspection is not None and inspection.get("State", {}).get("Running") is True:
        disarm_before_planned_stop(config)
    if remove_container and inspection is not None:
        _stop_managed_container(
            config["name"], expanded_path(config["engine_api_key_file"])
        )
    update_service_placement(config, manifest, "stopped")
    if protection_trip_latched(config):
        # Retirement is the explicit acknowledgement boundary for this
        # candidate only. Preserve its trip beside the launch evidence before
        # removing the latch so it cannot poison future hardware placement.
        evidence = expanded_path(config["qualification_evidence_dir"])
        ensure_private_directory(evidence)
        _, _, trip_path = protection_paths(config)
        archived_trip = evidence / "retired-protection-trip.json"
        write_text(archived_trip, trip_path.read_text(encoding="utf-8"))
        archived_trip.chmod(0o600)
        clear_protection_trip(config)
    retire_qualification_protection_slot(config)
    state_path.unlink()
    _fsync_path(state_path.parent)
    _restore_resident_watchdog_projection()


def _qualification_candidate_lifecycle(
    config: dict[str, Any], action: str
) -> int:
    """Apply one lifecycle action to the candidate that owns the inference slot."""
    if config.get("qualification_mode") is not True:
        raise LetsInferError("qualification slot has an invalid lifecycle mode")
    if action not in {"start", "stop", "restart", "recover"}:
        raise LetsInferError("qualification lifecycle action is invalid")
    _, manifest = configured_release(config)
    inspection = container_inspect(config["name"])
    if inspection is None:
        raise LetsInferError(
            "qualification candidate container is absent; relaunch the runtime candidate"
        )
    require_matching_container(
        inspection,
        manifest,
        config["engine_port"],
        manifest_sha256=config["manifest_sha256"],
        runtime_digest=config.get("runtime_digest"),
    )
    require_systemd_restart_authority(inspection)

    if action == "stop":
        disarm_protection(config)
        run(["docker", "update", "--restart", "no", config["name"]])
        if inspection.get("State", {}).get("Running", False):
            run(["docker", "stop", "--time", "120", config["name"]])
        update_service_placement(config, manifest, "stopped")
        presenter = _human_presenter()
        if presenter is not None:
            presenter.records(
                (
                    command_ui.RecordRow(
                        "Runtime",
                        config.get("model", manifest["model"]["alias"]),
                        semantic=command_ui.Semantic.SUCCESS,
                    ),
                    command_ui.RecordRow("Container", config["name"], "Stopped"),
                    command_ui.RecordRow("Candidate", "Preserved"),
                )
            )
        else:
            print(f"STOPPED {config['name']} candidate=preserved")
        return 0

    if action == "recover":
        cleared_trip = clear_protection_trip(config)
    else:
        if protection_trip_latched(config):
            raise LetsInferError(
                "runtime protection is tripped; use `letsinfer recover`"
            )
        cleared_trip = False

    try:
        if action in {"restart", "recover"} and inspection.get("State", {}).get(
            "Running", False
        ):
            disarm_protection(config)
            run(["docker", "update", "--restart", "no", config["name"]])
            run(["docker", "stop", "--time", "120", config["name"]])
            inspection = container_inspect(config["name"])
            if inspection is None:
                raise LetsInferError(
                    "qualification candidate disappeared during restart"
                )

        write_watchdog_public_state(config, manifest)
        update_service_placement(config, manifest, "starting")
        generation = secrets.token_hex(16)
        publish_protection_state(config, generation, "pending")
        if not inspection.get("State", {}).get("Running", False):
            require_memory_reserve(manifest, phase="launch")
            run(["docker", "start", config["name"]])
            inspection = container_inspect(config["name"])
            if inspection is None:
                raise LetsInferError(
                    "qualification candidate disappeared after start"
                )
        publish_protection_state(
            config, generation, "starting", inspection=inspection
        )
        certificate = expanded_path(config["tls_cert_file"])
        api_key = expanded_path(config["engine_api_key_file"])
        wait_for_ready(
            config["name"],
            config["engine_port"],
            manifest["container"]["startup_timeout_seconds"],
            certificate,
            manifest,
        )
        if not model_identity_ready(
            manifest, config["engine_port"], certificate, api_key
        ):
            raise LetsInferError(
                "authenticated model identity does not match the release manifest"
            )
        prewarm(
            manifest,
            config["name"],
            config["engine_port"],
            certificate,
            api_key,
        )
        require_memory_reserve(manifest, phase="runtime")
        current = container_inspect(config["name"])
        if current is None:
            raise LetsInferError(
                "qualification candidate disappeared before protection armed"
            )
        publish_protection_state(
            config, generation, "armed", inspection=current
        )
        update_service_placement(config, manifest, "running")
    except BaseException:
        if not protection_trip_latched(config):
            try:
                disarm_before_planned_stop(config)
            except BaseException:
                pass
        try:
            update_service_placement(config, manifest, "failed")
        except BaseException:
            pass
        raise
    presenter = _human_presenter()
    if presenter is not None:
        presenter.records(
            (
                command_ui.RecordRow(
                    "Runtime",
                    config.get("model", manifest["model"]["alias"]),
                    semantic=command_ui.Semantic.SUCCESS,
                ),
                command_ui.RecordRow("Container", config["name"], "Active"),
                command_ui.RecordRow("Action", action.title()),
                command_ui.RecordRow(
                    "Guard",
                    "Recovered" if cleared_trip else "Armed",
                    "Protection trip cleared" if cleared_trip else "",
                ),
            )
        )
    else:
        print(
            f"{action.upper()} {config['name']} candidate=active "
            f"protection_trip_cleared={str(cleared_trip).lower()}"
        )
    return 0


def _activate_qualification_candidate(
    config: dict[str, Any], manifest: dict[str, Any]
) -> pathlib.Path:
    """Atomically replace the local qualification slot and publish its route."""
    _, engine_state = _unit_enabled_active(ENGINE_SERVICE_NAME)
    if engine_state not in {"inactive", "failed", "not-found"}:
        raise LetsInferError(
            "qualification requires the resident engine service to be stopped"
        )
    _retire_qualification_candidate(remove_container=True)
    _quiesce_resident_placement()
    state_path = qualification_service_config_path()
    ensure_private_directory(state_path.parent)
    atomic_json(state_path, config)
    state_path.chmod(0o600)
    write_watchdog_public_state(config, manifest)
    update_service_placement(config, manifest, "starting")
    return state_path


def active_service_config_path() -> pathlib.Path:
    """Prefer the explicit candidate slot over the boot-persistent selection."""
    candidate = qualification_service_config_path()
    if candidate.is_file():
        config = read_service_config(candidate)
        if config.get("qualification_mode") is not True:
            raise LetsInferError("qualification slot has an invalid lifecycle mode")
        return candidate
    return default_service_config_path()


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
    candidate_root, manifest_path = _bind_runtime_release_to_current_core(
        manifest_path, manifest
    )
    if manifest["model"]["alias"] != config["model"]:
        raise LetsInferError("previous service bundle model alias is inconsistent")
    bound = dict(config)
    bound["source_root"] = str(candidate_root)
    bound["manifest_path"] = str(manifest_path)
    return bound


def _bind_runtime_release_to_current_core(
    manifest_path: pathlib.Path,
    manifest: dict[str, Any],
) -> tuple[pathlib.Path, pathlib.Path]:
    """Bind immutable runtime metadata to exactly the executing core."""

    return install_control_bundle(
        manifest_path,
        manifest,
    )


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
    if config.get("qualification_mode") is True:
        raise LetsInferError("qualification candidates cannot become boot services")
    _retire_qualification_candidate(remove_container=True)
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
        try:
            runtime_receipt = next(
                item for item in selections() if item["digest"] == config["runtime_digest"]
            )
        except (RuntimePackError, StopIteration) as error:
            raise LetsInferError("service runtime selection is unavailable") from error
        runtime_artifact_root = pathlib.Path(runtime_receipt["object_root"]).expanduser()
        try:
            installed_runtime = verify_descriptor(runtime_artifact_root)
        except RuntimePackError as error:
            raise LetsInferError(str(error)) from error
        manifest = resolved[1]
        if (
            installed_runtime.digest != config["runtime_digest"]
            or installed_runtime.runtime["id"] != config["runtime_name"]
            or installed_runtime.runtime["version"] != config["runtime_version"]
            or installed_runtime.runtime["logical_model"] != manifest["model"]["alias"]
            or installed_runtime.runtime["engine"]["id"] != adapter_for(manifest).name
            or installed_runtime.runtime["target"]["id"] != target_contract(manifest)["id"]
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
Requires={SERVICE_NAME} {NODE_SERVICE_NAME}
PartOf={NODE_SERVICE_NAME}
After=network-online.target {NODE_SERVICE_NAME} {SERVICE_NAME}
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


def core_gateway_config() -> dict[str, Any]:
    return {
        "schema_version": 2,
        "gateway_listen": "0.0.0.0",
        "gateway_protocol": "http",
        "gateway_port": 8000,
        "gateway_max_connections": 256,
        "gateway_queue_timeout_seconds": 0,
        "gateway_telemetry_file": str(default_gateway_telemetry_path()),
    }


def verify_active_core_gateway() -> pathlib.Path:
    config_path = site_config_root() / "gateway.json"
    expected_config = core_gateway_config()
    unit = pathlib.Path.home() / ".config/systemd/user" / GATEWAY_SERVICE_NAME
    try:
        details = unit.stat()
        actual_config = read_json(config_path)
        valid = (
            not unit.is_symlink()
            and stat.S_ISREG(details.st_mode)
            and details.st_uid == os.getuid()
            and stat.S_IMODE(details.st_mode) == 0o644
            and actual_config == expected_config
            and unit.read_text(encoding="utf-8")
            == render_gateway_service(config_path, expected_config, source_root())
        )
    except (OSError, json.JSONDecodeError) as error:
        raise LetsInferError(f"cannot verify the active core gateway: {error}") from error
    if not valid:
        raise LetsInferError("the active gateway does not match this core build")
    if _unit_enabled_active(GATEWAY_SERVICE_NAME)[1] != "active":
        raise LetsInferError("the resident core gateway is not active")
    return unit


def install_core_gateway_service(
    *,
    executable_root: pathlib.Path | None = None,
    replace_active: bool = False,
) -> dict[str, Any]:
    """Install the stable site gateway before any placement is active."""
    root = executable_root or source_root()
    config_path = site_config_root() / "gateway.json"
    config = core_gateway_config()
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


def render_node_service(executable_root: pathlib.Path | None = None) -> str:
    executable = (executable_root or source_root()) / "bin/letsinfer"
    return f"""[Unit]
Description=Let's Infer private node agent
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
MemoryAccounting=yes
MemoryHigh={NODE_AGENT_MEMORY_HIGH_BYTES}
MemoryMax={NODE_AGENT_MEMORY_LIMIT_BYTES}
MemorySwapMax=0
Restart=always
RestartSec=2
UMask=0077
TasksMax={NODE_AGENT_TASK_LIMIT}
LimitNOFILE=128
NoNewPrivileges=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart={_systemd_quote(executable)} node-agent --listen 0.0.0.0 --port {SITE_CONTROL_PORT}
TimeoutStopSec=15

[Install]
WantedBy=default.target
"""


def install_node_service_only(
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
            "user-systemd lingering is required before installing the node service"
        )
    root = executable_root or source_root()
    executable = root / "bin/letsinfer"
    if not executable.is_file() or executable.is_symlink():
        raise LetsInferError(f"node service executable is unavailable: {executable}")
    if platform.system() == "Darwin":
        if unit_dir is not None:
            raise LetsInferError("a custom systemd unit directory is not valid on macOS")
        try:
            macos_services.install_launch_agent(
                macos_services.LaunchAgent(
                    label=macos_services.NODE_LABEL,
                    arguments=(
                        str(executable),
                        "node-agent",
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
            raise LetsInferError(f"cannot install macOS node service: {error}") from error
        return
    unit_root = unit_dir or pathlib.Path.home() / ".config/systemd/user"
    unit_root.mkdir(parents=True, exist_ok=True)
    path = unit_root / NODE_SERVICE_NAME
    snapshot = _snapshot_user_file(path)
    previous = _unit_enabled_active(NODE_SERVICE_NAME)
    if previous[0] not in {"enabled", "disabled", "not-found"}:
        raise LetsInferError(
            f"refusing node-service install while enablement is {previous[0]!r}"
        )
    if previous[1] not in {"active", "inactive", "failed"}:
        raise LetsInferError(
            f"refusing node-service install while state is {previous[1]!r}"
        )
    if no_start and previous[1] == "active":
        raise LetsInferError("--no-service cannot replace an active node service")
    loaded = False
    try:
        if previous[1] == "active":
            run_passthrough(["systemctl", "--user", "stop", NODE_SERVICE_NAME])
        write_text(path, render_node_service(root))
        path.chmod(0o644)
        run(["systemctl", "--user", "daemon-reload"])
        loaded = True
        run(["systemctl", "--user", "enable", NODE_SERVICE_NAME])
        if not no_start:
            run_passthrough(["systemctl", "--user", "start", NODE_SERVICE_NAME])
            enabled, active, memory_bytes = _service_state(NODE_SERVICE_NAME)
            if enabled != "enabled" or active != "active":
                raise LetsInferError("node service did not become enabled and active")
            if memory_bytes is None or memory_bytes >= NODE_AGENT_MEMORY_LIMIT_BYTES:
                raise LetsInferError(
                    f"Let's Infer node-agent memory is {memory_bytes} bytes; "
                    f"the limit is below {NODE_AGENT_MEMORY_LIMIT_BYTES} bytes"
                )
    except BaseException as failure:
        errors: list[str] = []
        if loaded:
            result = run(
                ["systemctl", "--user", "stop", NODE_SERVICE_NAME], check=False
            )
            if result.returncode != 0:
                errors.append("could not stop replacement node service")
        try:
            _restore_user_file(path, snapshot)
            run(["systemctl", "--user", "daemon-reload"])
            _restore_unit_enablement(NODE_SERVICE_NAME, previous[0])
            if previous[1] == "active":
                run_passthrough(["systemctl", "--user", "start", NODE_SERVICE_NAME])
        except BaseException as error:
            errors.append(str(error))
        if errors:
            raise LetsInferError(
                "node-service activation failed and rollback was incomplete: "
                + "; ".join(errors)
            ) from failure
        raise LetsInferError(
            f"node-service activation failed; previous state restored: {failure}"
        ) from failure


def render_user_service(
    config: dict[str, Any], manifest: dict[str, Any]
) -> str:
    watchdog = manifest["watchdog"]
    max_controllers = max(
        WATCHDOG_CONTROLLER_STREAM_FLOOR, watchdog["max_controllers"]
    )
    protection = watchdog["protection"]
    executable = pathlib.Path(config["watchdog_binary_path"])
    protection_root = pathlib.Path(config["watchdog_data_root"]) / PROTECTION_ROOT_NAME
    return f"""[Unit]
Description=Let's Infer resident Watchdog
Wants={NODE_SERVICE_NAME}
After=network-online.target {NODE_SERVICE_NAME}
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
ExecStart={_systemd_quote(executable)} --listen {_systemd_quote(config['watchdog_listen'])} --port {config['watchdog_port']} --data-dir {_systemd_quote(pathlib.Path(config['watchdog_data_root']))} --cert {_systemd_quote(pathlib.Path(config['watchdog_cert_file']))} --key {_systemd_quote(pathlib.Path(config['watchdog_key_file']))} --controller-ca {_systemd_quote(pathlib.Path(config['watchdog_controller_ca_file']))} --controllers {_systemd_quote(pathlib.Path(config['watchdog_controller_allowlist_file']))} --site-state {_systemd_quote(pathlib.Path(config['watchdog_public_state_file']))} --gateway-metrics {_systemd_quote(pathlib.Path(config['gateway_telemetry_file']))} --sample-ms {watchdog['sample_interval_ms']} --flush-ms {watchdog['flush_interval_ms']} --max-controllers {max_controllers} --protect-root {_systemd_quote(protection_root)} --warning-bytes {protection['warning_available_bytes']} --stop-bytes {protection['graceful_available_bytes']} --kill-bytes {protection['emergency_available_bytes']} --swap-stop-bytes {protection['swap_stop_bytes']} --psi-some-us {protection['psi_some_us']} --psi-full-us {protection['psi_full_us']} --state-failures {protection['state_failures']} --containment-grace-ms {protection['containment_grace_ms']}
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
    resident_path = default_service_config_path()
    candidate_path = qualification_service_config_path()
    config_path = candidate_path if candidate_path.is_file() else resident_path
    runtime_configured = config_path.is_file()
    qualification_active = config_path == candidate_path and runtime_configured
    runtime_config: dict[str, Any] | None = None
    bound_runtime_config: dict[str, Any] | None = None
    runtime_manifest: dict[str, Any] | None = None
    runtime_error: str | None = None
    if runtime_configured:
        try:
            runtime_config = read_service_config(config_path)
            configured_release(runtime_config)
            bound_runtime_config = bind_config_to_control_bundle(runtime_config)
            _, runtime_manifest = configured_release(bound_runtime_config)
        except LetsInferError as error:
            runtime_error = str(error)

    runtime_state = {
        "configured": runtime_configured,
        "compatible": not runtime_configured or runtime_manifest is not None,
        "error": runtime_error,
        "qualification_active": qualification_active,
    }
    if platform.system() != "Linux":
        install_node_service_only()
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

    runtime_binding_snapshots: dict[
        pathlib.Path, tuple[str, int] | None
    ] | None = None
    try:
        # Recovery must be quiesced before inference. The existing Watchdog stays
        # active until the engine has stopped, so there is never an unprotected
        # live engine during the immutable core handoff.
        stop_if_active(RECOVERY_TIMER_NAME)
        if previous[ENGINE_SERVICE_NAME][1] == "active":
            if not resident_path.is_file():
                raise LetsInferError(
                    "engine service is active without a resident service configuration"
                )
            disarm_before_planned_stop(read_service_config(resident_path))
        stop_if_active(ENGINE_SERVICE_NAME)
        install_node_service_only()
        install_core_watchdog_service(
            identity,
            replace_active=True,
            runtime_manifest=runtime_manifest,
        )
        if include_gateway:
            install_core_gateway_service(replace_active=True)
        if bound_runtime_config is not None and runtime_manifest is not None:
            runtime_binding_snapshots = _install_runtime_control_binding(
                config_path,
                bound_runtime_config,
                runtime_manifest,
            )
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
        if runtime_binding_snapshots is not None:
            try:
                _restore_runtime_control_binding(runtime_binding_snapshots)
            except BaseException as error:
                restore_errors.append(f"restore runtime control binding: {error}")
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


def wait_for_core_plane_ready(
    *,
    include_gateway: bool,
    timeout_seconds: float = 90.0,
    poll_seconds: float = 0.5,
    stable_polls: int = 5,
) -> None:
    """Wait until a rebound Linux control plane is stable, not merely started.

    systemd considers a simple service active as soon as its process is spawned.
    A listener can still fail immediately afterwards, notably while migrating
    from an older core whose sockets were not reusable. Keep the update's
    rebind step active through that bounded migration window and require the
    public gateway health endpoint plus several consecutive healthy samples.
    """
    if platform.system() != "Linux":
        return
    if timeout_seconds <= 0 or poll_seconds <= 0 or stable_polls <= 0:
        raise LetsInferError("invalid core-plane readiness bounds")
    expected = [NODE_SERVICE_NAME, SERVICE_NAME]
    if include_gateway:
        expected.append(GATEWAY_SERVICE_NAME)
    deadline = time.monotonic() + timeout_seconds
    consecutive = 0
    last_states: dict[str, str] = {}
    gateway_ready = not include_gateway
    while time.monotonic() < deadline:
        last_states = {
            name: _unit_enabled_active(name)[1]
            for name in expected
        }
        gateway_ready = not include_gateway or api_status(
            8000, "/health", None
        ) == 200
        if all(state == "active" for state in last_states.values()) and gateway_ready:
            consecutive += 1
            if consecutive >= stable_polls:
                return
        else:
            consecutive = 0
        time.sleep(poll_seconds)
    detail = ", ".join(
        f"{name}={state}" for name, state in last_states.items()
    )
    if include_gateway:
        detail += f", gateway_health={'ready' if gateway_ready else 'unavailable'}"
    raise LetsInferError(
        f"rebound core services did not become stable within {timeout_seconds:g}s: "
        f"{detail}"
    )


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


def _runtime_control_binding_paths(
    config_path: pathlib.Path, config: dict[str, Any]
) -> tuple[pathlib.Path, ...]:
    if config.get("qualification_mode") is True:
        return (config_path,)
    unit_root = pathlib.Path.home() / ".config/systemd/user"
    return (
        config_path,
        unit_root / ENGINE_SERVICE_NAME,
        unit_root / RECOVERY_SERVICE_NAME,
    )


def _restore_runtime_control_binding(
    snapshots: dict[pathlib.Path, tuple[str, int] | None]
) -> None:
    reload_units = any(path.name.endswith(".service") for path in snapshots)
    for path, snapshot in snapshots.items():
        _restore_user_file(path, snapshot)
    if reload_units:
        run(["systemctl", "--user", "daemon-reload"])


def _install_runtime_control_binding(
    config_path: pathlib.Path,
    config: dict[str, Any],
    manifest: dict[str, Any],
) -> dict[pathlib.Path, tuple[str, int] | None]:
    """Atomically move a selected runtime onto this core's control bundle."""
    paths = _runtime_control_binding_paths(config_path, config)
    snapshots = {path: _snapshot_user_file(path) for path in paths}
    try:
        atomic_json(config_path, config)
        config_path.chmod(0o600)
        if config.get("qualification_mode") is not True:
            unit_root = pathlib.Path.home() / ".config/systemd/user"
            engine_unit = unit_root / ENGINE_SERVICE_NAME
            recovery_unit = unit_root / RECOVERY_SERVICE_NAME
            write_text(
                engine_unit,
                render_engine_service(
                    config_path,
                    manifest["container"]["startup_timeout_seconds"],
                    pathlib.Path(config["source_root"]),
                ),
            )
            write_text(
                recovery_unit,
                render_recovery_service(
                    config["name"],
                    pathlib.Path(config["protection_root"]),
                    pathlib.Path(config["source_root"]),
                ),
            )
            engine_unit.chmod(0o644)
            recovery_unit.chmod(0o644)
            run(["systemctl", "--user", "daemon-reload"])
    except BaseException as failure:
        try:
            _restore_runtime_control_binding(snapshots)
        except BaseException as rollback_error:
            raise LetsInferError(
                "runtime control rebind failed and rollback was incomplete: "
                f"{rollback_error}"
            ) from failure
        raise LetsInferError(
            f"runtime control rebind failed; previous binding restored: {failure}"
        ) from failure
    return snapshots


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
    runtime_receipt: dict[str, Any] | None = None,
    unit_dir: pathlib.Path | None = None,
) -> None:
    unit_root = unit_dir or pathlib.Path.home() / ".config/systemd/user"
    unit_root.mkdir(parents=True, exist_ok=True)
    paths = {
        SERVICE_NAME: unit_root / SERVICE_NAME,
        NODE_SERVICE_NAME: unit_root / NODE_SERVICE_NAME,
        ENGINE_SERVICE_NAME: unit_root / ENGINE_SERVICE_NAME,
        GATEWAY_SERVICE_NAME: unit_root / GATEWAY_SERVICE_NAME,
        RECOVERY_SERVICE_NAME: unit_root / RECOVERY_SERVICE_NAME,
        RECOVERY_TIMER_NAME: unit_root / RECOVERY_TIMER_NAME,
    }
    managed_paths = (config_path, *paths.values())
    snapshots = {path: _snapshot_user_file(path) for path in managed_paths}
    previous_config: dict[str, Any] | None = None
    if snapshots[config_path] is not None:
        previous_config = read_service_config(config_path)
        if not retained_control_bundle_for_rollback(previous_config):
            bind_config_to_control_bundle(previous_config)

    state_names = (
        SERVICE_NAME,
        NODE_SERVICE_NAME,
        ENGINE_SERVICE_NAME,
        GATEWAY_SERVICE_NAME,
        RECOVERY_TIMER_NAME,
    )
    previous_states = {name: _unit_enabled_active(name) for name in state_names}
    previous_runtime_receipt: dict[str, Any] | None = None
    if runtime_receipt is not None:
        try:
            previous_runtime_receipt = next(
                (
                    receipt
                    for receipt in selections()
                    if receipt["logical_model"] == runtime_receipt["logical_model"]
                ),
                None,
            )
        except RuntimePackError as error:
            raise LetsInferError(str(error)) from error
    safe_enablement_states = {"enabled", "disabled", "not-found"}
    for name in (
        SERVICE_NAME, NODE_SERVICE_NAME, GATEWAY_SERVICE_NAME, RECOVERY_TIMER_NAME
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
        for name in (SERVICE_NAME, NODE_SERVICE_NAME)
    ):
        raise LetsInferError(
            "--no-start cannot replace an active Let's Infer service; "
            "stop it first or allow install to perform a guarded upgrade"
        )

    replacement_loaded = False
    selection_attempted = False
    try:
        if previous_states[RECOVERY_TIMER_NAME][1] == "active":
            run_passthrough(["systemctl", "--user", "stop", RECOVERY_TIMER_NAME])
        if previous_states[GATEWAY_SERVICE_NAME][1] == "active":
            run_passthrough(["systemctl", "--user", "stop", GATEWAY_SERVICE_NAME])
        if previous_states[ENGINE_SERVICE_NAME][1] == "active":
            if previous_config is None:
                raise LetsInferError(
                    "engine service is active without a previous service configuration"
                )
            disarm_before_planned_stop(previous_config)
            run_passthrough(["systemctl", "--user", "stop", ENGINE_SERVICE_NAME])
        if previous_states[SERVICE_NAME][1] == "active":
            run_passthrough(["systemctl", "--user", "stop", SERVICE_NAME])
        if previous_states[NODE_SERVICE_NAME][1] == "active":
            run_passthrough(["systemctl", "--user", "stop", NODE_SERVICE_NAME])
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
            paths[NODE_SERVICE_NAME],
            render_node_service(pathlib.Path(config["source_root"])),
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
            NODE_SERVICE_NAME,
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
        run(["systemctl", "--user", "enable", NODE_SERVICE_NAME])
        run(["systemctl", "--user", "enable", GATEWAY_SERVICE_NAME])
        run(["systemctl", "--user", "enable", RECOVERY_TIMER_NAME])
        if runtime_receipt is not None:
            selection_attempted = True
            try:
                write_selection(runtime_receipt)
            except RuntimePackError as error:
                raise LetsInferError(str(error)) from error
        if not no_start:
            run_passthrough(["systemctl", "--user", "start", NODE_SERVICE_NAME])
            _, _, node_memory_bytes = _service_state(NODE_SERVICE_NAME)
            if (
                node_memory_bytes is None
                or node_memory_bytes >= NODE_AGENT_MEMORY_LIMIT_BYTES
            ):
                raise LetsInferError(
                    f"Let's Infer node-agent memory is {node_memory_bytes} bytes; "
                    f"the limit is below {NODE_AGENT_MEMORY_LIMIT_BYTES} bytes"
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
            wait_for_core_plane_ready(include_gateway=True)
            run(["systemctl", "--user", "restart", RECOVERY_TIMER_NAME])
    except BaseException as failure:
        rollback_errors: list[str] = []
        rollback_safe = True
        if replacement_loaded:
            inspection = container_inspect(config["name"])
            if (
                inspection is not None
                and inspection.get("State", {}).get("Running") is True
            ):
                try:
                    disarm_before_planned_stop(config)
                except BaseException as error:
                    rollback_safe = False
                    rollback_errors.append(
                        f"disarm replacement runtime before rollback: {error}"
                    )
        if replacement_loaded and rollback_safe:
            for name in (
                RECOVERY_TIMER_NAME,
                GATEWAY_SERVICE_NAME,
                ENGINE_SERVICE_NAME,
                SERVICE_NAME,
                NODE_SERVICE_NAME,
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
        if not rollback_safe:
            raise LetsInferError(
                "service activation failed and rollback could not safely stop "
                "the replacement runtime: " + "; ".join(rollback_errors)
            ) from failure
        if selection_attempted and runtime_receipt is not None:
            try:
                restore_selection(runtime_receipt, previous_runtime_receipt)
            except RuntimePackError as error:
                rollback_errors.append(f"restore runtime selection: {error}")
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
            SERVICE_NAME, NODE_SERVICE_NAME, GATEWAY_SERVICE_NAME, RECOVERY_TIMER_NAME
        ):
            state = previous_states[name][0]
            try:
                _restore_unit_enablement(name, state)
            except (LetsInferError, OSError) as error:
                rollback_errors.append(f"restore {name} enablement: {error}")
        try:
            if previous_states[NODE_SERVICE_NAME][1] == "active":
                run_passthrough(["systemctl", "--user", "start", NODE_SERVICE_NAME])
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
    """Return the main identity and one fully refreshed active graph."""
    identity = read_site_identity()
    if identity.role != "main":
        raise LetsInferError(
            "node topology selection is main-node-owned; "
            f"main={identity.coordinator_id}@{identity.coordinator_address}"
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
            allocations = store.device_allocations(active_only=True)
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
            allocated_devices={
                member_id: [
                    row["device_uuid"]
                    for row in allocations
                    if row["member_id"] == member_id
                ]
                for member_id in (row["member_id"] for row in members)
            },
        )
    except (SiteError, TopologyError) as error:
        raise LetsInferError(f"cannot build authenticated site topology: {error}") from error


def _catalog_site_release(
    catalog: dict[str, Any],
    model: str,
    runtime: str | None,
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
            catalog, model, runtime, choice.target_id, device=None
        )
    except (RuntimePackError, TopologyError) as error:
        raise LetsInferError(str(error)) from error
    return release, choice


def _runtime_source_for_install(
    model: str,
    runtime: str | None,
    catalog_location: str | None,
) -> tuple[str, str, str | None, str | None, str | None, bool]:
    path = pathlib.Path(model).expanduser()
    if path.exists():
        return str(path.resolve(strict=True)), "local", None, None, None, False
    if REGISTRY_DIGEST_RE.fullmatch(model):
        return model, "pinned", None, None, None, False
    location = resolved_catalog_location(catalog_location)
    if location is None:
        raise LetsInferError(
            "runtime installation requires a signed catalog or an explicit local/OCI runtime source"
        )
    try:
        catalog = CatalogManager(location).load().document
        (
            selected_target,
            selected_target_sha256,
            selected_runtime,
            version,
            source,
        ), _choice = _catalog_site_release(catalog, model, runtime)
    except (CatalogError, RuntimePackError) as error:
        raise LetsInferError(str(error)) from error
    policy = f"runtime:{selected_runtime}" if runtime else "recommended"
    return source, policy, version, selected_target, selected_target_sha256, True


def prepare_runtime_install(
    source: str,
    *,
    policy: str,
    qualified: bool,
    requested_runtime: str | None,
    requested_target: str | None = None,
    expected_version: str | None = None,
    expected_target_contract_sha256: str | None = None,
    image_override: Mapping[str, str] | None = None,
) -> tuple[pathlib.Path, dict[str, Any], pathlib.Path, dict[str, Any]]:
    try:
        with materialize(source) as incoming:
            object_root = store_pack(incoming)
        pack = verify_descriptor(object_root)
    except RuntimePackError as error:
        raise LetsInferError(str(error)) from error
    manifest_path = pack.runtime_path
    manifest = runtime_execution_manifest(
        pack.runtime, qualified=qualified, image_override=image_override
    )
    engine = adapter_for(manifest).name
    manifest_target = target_contract(manifest)
    target_id = manifest_target["id"]
    manifest_target_sha256 = target_contract_sha256(manifest_target)
    try:
        validate_target_binding(
            pack.runtime.get("orchestration"), manifest_target["placement"]
        )
    except OrchestrationError as error:
        raise LetsInferError(
            f"runtime orchestration does not bind its release target: {error}"
        ) from error
    if expected_version is not None and pack.runtime["version"] != expected_version:
        raise LetsInferError(
            "runtime catalog version does not match the immutable artifact "
            f"({expected_version!r} != {pack.runtime['version']!r})"
        )
    if (
        pack.runtime["logical_model"] != manifest["model"]["alias"]
        or pack.runtime["engine"]["id"] != engine
        or pack.runtime["target"]["id"] != target_id
    ):
        raise LetsInferError("runtime descriptor and runtime.json identity disagree")
    if requested_runtime is not None and requested_runtime != pack.runtime["id"]:
        raise LetsInferError(
            f"runtime candidate is {pack.runtime['id']!r}, not requested {requested_runtime!r}"
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
        pack.runtime_path,
        manifest,
    )
    installed_manifest = read_json(installed_manifest_path)
    receipt = new_receipt(
        pack,
        object_root=object_root,
        manifest_path=installed_manifest_path,
        control_root=control_root,
        source=source,
        policy=policy,
        qualified=qualified,
        hardware_fingerprint_sha256=host_hardware_fingerprint_sha256(),
        target_contract_sha256=manifest_target_sha256,
        installed_at_unix_ns=time.time_ns(),
    )
    return installed_manifest_path, installed_manifest, control_root, receipt


def _control_member_host(address: str) -> str:
    endpoint = _site_control_endpoint(address)
    parsed = urllib.parse.urlsplit(endpoint)
    if not parsed.hostname:
        raise LetsInferError("child control address has no host")
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


def _group_release_identity(
    *,
    catalog_release_value: Mapping[str, Any],
    candidate_id: str,
    version: str,
    source: str,
    target_id: str,
    target_sha256: str,
    runtime: RuntimePack,
    manifest_sha256: str,
) -> dict[str, Any]:
    """Bind one installed group to the exact signed-catalog release."""
    release = dict(catalog_release_value)
    benchmark = release.get("benchmark")
    runtime_benchmark = runtime.runtime.get("benchmark")
    record = (
        runtime_benchmark.get("record")
        if isinstance(runtime_benchmark, Mapping)
        else None
    )
    authors = release.get("authors")
    if (
        release.get("source") != source
        or release.get("engine") != runtime.runtime["engine"]["id"]
        or release.get("engine_oci") != runtime.runtime["engine"]["oci"]["reference"]
        or release.get("model_uri") != runtime.runtime["model"]["uri"]
        or (
            benchmark is not None
            and (
                not isinstance(benchmark, Mapping)
                or not isinstance(benchmark.get("id"), str)
                or not SHA256_RE.fullmatch(benchmark["id"])
            )
        )
        or not isinstance(runtime_benchmark, Mapping)
        or (benchmark is None and record is not None)
        or (
            benchmark is not None
            and record is not None
            and (
                not isinstance(record, Mapping)
                or benchmark.get("id") != record.get("id")
            )
        )
        or not isinstance(authors, list)
        or not authors
        or any(
            not isinstance(author, Mapping)
            or not isinstance(author.get("github_login"), str)
            or not author["github_login"]
            for author in authors
        )
    ):
        raise LetsInferError(
            "signed catalog release does not match the installed runtime bytes"
        )
    artifacts = [
        {
            "name": artifact["name"],
            "uri": artifact["uri"],
            "revision": artifact["revision"],
            "sha256": artifact.get("sha256"),
        }
        for artifact in runtime.runtime["artifacts"]
    ]
    return {
        "logical_model": runtime.runtime["logical_model"],
        "candidate_id": candidate_id,
        "version": version,
        "source": source,
        "runtime_digest": runtime.digest,
        "manifest_sha256": manifest_sha256,
        "engine_oci": release["engine_oci"],
        "model_uri": release["model_uri"],
        "artifacts": artifacts,
        "target_id": target_id,
        "target_contract_sha256": target_sha256,
        "qualification": "qualified",
        "benchmark": (
            None
            if benchmark is None
            else {
                "id": benchmark["id"],
                "evidence": benchmark.get("evidence"),
            }
        ),
        "authors": [author["github_login"] for author in authors],
        "license": release["license"],
    }


def install_engine_group(
    arguments: argparse.Namespace,
    *,
    source: str,
    manifest_path: pathlib.Path,
    manifest: dict[str, Any],
    control_root: pathlib.Path,
    receipt: dict[str, Any],
    release_identity: Mapping[str, Any],
    resolved_topology: tuple[Any, TopologyGraph, Any] | None = None,
) -> int:
    """Install one exact engine group under a logical model service."""
    if not REGISTRY_DIGEST_RE.fullmatch(source):
        raise LetsInferError(
            "engine-group installation requires a digest-pinned OCI runtime"
        )
    if any(
        bool(getattr(arguments, name, False))
        for name in ("no_service", "no_start", "no_build_image")
    ):
        raise LetsInferError(
            "engine-group installation does not support disabling required lifecycle services"
        )
    identity, graph, placement = (
        resolved_topology or resolve_manifest_placement(manifest)
    )
    if placement.strategy not in {"single", "parallel"}:
        raise LetsInferError("engine-group installation has an invalid target strategy")
    runtime_root = pathlib.Path(receipt["object_root"])
    try:
        runtime = verify_descriptor(runtime_root)
        if (
            release_identity.get("source") != source
            or release_identity.get("logical_model") != manifest["model"]["alias"]
            or release_identity.get("target_id") != target_contract(manifest)["id"]
        ):
            raise OrchestrationError(
                "signed release identity does not match the requested model, target, and source"
            )
        contract = validate_target_binding(
            runtime.runtime.get("orchestration"),
            target_contract(manifest)["placement"],
        )
    except (RuntimePackError, OrchestrationError) as error:
        raise LetsInferError(f"runtime engine-group contract is invalid: {error}") from error
    if placement.strategy == "parallel" and contract is None:
        raise LetsInferError("parallel runtime has no engine-group contract")
    if placement.strategy == "single" and contract is not None:
        raise LetsInferError("single runtime cannot carry a parallel group contract")
    manifest_sha256 = sha256_file(manifest_path)
    service_id = logical_service_id(identity.site_id, manifest["model"]["alias"])
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
        for resource in existing["plan"]["resources"]:
            if resource["node_id"] in occupied:
                occupied[resource["node_id"]].append(
                    (resource["port_base"], resource["port_count"])
                )
    try:
        if contract is None:
            member_id = placement.member_ids[0]
            port_base = next(
                (
                    candidate
                    for candidate in range(18000, 60000)
                    if all(
                        candidate + 1 <= used or used + length <= candidate
                        for used, length in occupied[member_id]
                    )
                ),
                None,
            )
            if port_base is None:
                raise GroupOrchestrationError(
                    f"no engine port remains on node {member_id}"
                )
            plan = build_single_group_plan(
                member_id=member_id,
                member_address=_control_member_host(
                    selected_records[member_id]["address"]
                ),
                device_uuids=placement.device_uuids[member_id],
                topology_sha256=placement.topology_sha256,
                manifest_sha256=manifest_sha256,
                runtime_digest=runtime.digest,
                service_id=service_id,
                release=release_identity,
                port_base=port_base,
            )
        else:
            port_bases = allocate_group_ports(
                contract,
                member_ids=placement.member_ids,
                occupied={key: tuple(value) for key, value in occupied.items()},
            )
        if placement.strategy == "parallel" and len(placement.member_ids) > 1:
            engine_addresses = graph.engine_addresses(
                placement, target_contract(manifest)["placement"]["interconnect"]
            )
        else:
            engine_addresses = {
                member_id: _control_member_host(selected_records[member_id]["address"])
                for member_id in placement.member_ids
            }
        if contract is not None:
            plan = build_group_plan(
                contract,
                member_ids=placement.member_ids,
                member_addresses=engine_addresses,
                topology_sha256=placement.topology_sha256,
                manifest_sha256=manifest_sha256,
                runtime_digest=runtime.digest,
                service_id=service_id,
                release=release_identity,
                member_port_bases=port_bases,
                member_device_uuids=placement.device_uuids,
                connections=graph.placement_connections(placement),
            )
    except (OrchestrationError, GroupOrchestrationError, TopologyError) as error:
        raise LetsInferError(f"cannot build engine-group plan: {error}") from error
    submit, job_status, group_status = _engine_group_transport()

    runtime_identity = (
        f"{manifest['model']['alias']}/{adapter_for(manifest).name}/"
        f"{target_contract(manifest)['id']}@{runtime.runtime['version']}"
        f"@sha256:{runtime.digest}"
    )
    placement_id = plan.group_id
    placement_document = {
        "placement_id": placement_id,
        "service_id": service_id,
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
            service = store.ensure_model_service(manifest["model"]["alias"])
            if service["service_id"] != service_id:
                raise LetsInferError("logical model service identity is inconsistent")
            store.reserve_group_devices(
                plan.group_id,
                [
                    {
                        "member_id": assignment.member_id,
                        "device_uuids": list(assignment.device_uuids),
                    }
                    for assignment in plan.assignments
                ],
            )
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
                credential_root = secrets_root() / "engine-groups" / plan.group_id
                ensure_private_directory(credential_root)
                credential_file = credential_root / "engine-api.key"
                _atomic_private_text(
                    credential_file, orchestrator.engine_credential + "\n"
                )
                endpoints: list[dict[str, Any]] = []
                for assignment in plan.assignments:
                    if not assignment.endpoint_owner:
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
                try:
                    store.set_group_allocation_state(plan.group_id, "released")
                except BaseException as allocation_error:
                    rollback_error = rollback_error or allocation_error
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
    presenter = _human_presenter()
    if presenter is not None:
        presenter.records(
            (
                command_ui.RecordRow(
                    "Runtime",
                    runtime_identity,
                    semantic=command_ui.Semantic.SUCCESS,
                ),
                command_ui.RecordRow("Group", plan.group_id),
                command_ui.RecordRow("Placement", placement_id),
                command_ui.RecordRow("Members", len(plan.assignments)),
            )
        )
        presenter.verbatim(receipt_path, label="Receipt", copyable=True)
    else:
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
    actor_id: str = "main",
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
            or row.get("source") != document["release"]["source"]
        ):
            raise LetsInferError("durable engine-group identity is inconsistent")
        runtime_root = default_runtime_home() / ".objects" / document["runtime_digest"]
        runtime = verify_descriptor(runtime_root)
        if runtime.digest != document["runtime_digest"]:
            raise LetsInferError("engine-group runtime object identity changed")
        regenerated_manifest = runtime_execution_manifest(
            runtime.runtime,
            qualified=document["release"]["qualification"] == "qualified",
        )
        if (
            hashlib.sha256(canonical_bytes(regenerated_manifest)).hexdigest()
            != document["manifest_sha256"]
        ):
            raise LetsInferError(
                "engine-group runtime no longer reproduces its execution manifest"
            )
        control_root, manifest_path = install_control_bundle(
            runtime.runtime_path, regenerated_manifest
        )
        _, manifest = validate_control_bundle(
            control_root, manifest_path, document["manifest_sha256"]
        )
        contract = validate_target_binding(
            runtime.runtime.get("orchestration"),
            target_contract(manifest)["placement"],
        )
        resources = list(document["resources"])
        if contract is None:
            if document["strategy"] != "single" or len(resources) != 1:
                raise LetsInferError("engine-group runtime lost its parallel contract")
            resource = resources[0]
            plan = build_single_group_plan(
                member_id=resource["node_id"],
                member_address=resource["address"],
                device_uuids=resource["device_uuids"],
                topology_sha256=document["topology_sha256"],
                manifest_sha256=document["manifest_sha256"],
                runtime_digest=document["runtime_digest"],
                service_id=document["service_id"],
                release=document["release"],
                port_base=resource["port_base"],
            )
        else:
            plan = build_group_plan(
                contract,
                member_ids=tuple(item["node_id"] for item in resources),
                member_addresses={item["node_id"]: item["address"] for item in resources},
                topology_sha256=document["topology_sha256"],
                manifest_sha256=document["manifest_sha256"],
                runtime_digest=document["runtime_digest"],
                service_id=document["service_id"],
                release=document["release"],
                member_port_bases={item["node_id"]: item["port_base"] for item in resources},
                member_device_uuids={
                    item["node_id"]: item["device_uuids"] for item in resources
                },
                connections=document["connections"],
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
    group_running = group["state"] == "running"
    updated = {
        key: placement[key]
        for key in (
            "placement_id",
            "service_id",
            "model",
            "runtime",
            "target",
            "strategy",
            "state",
            "topology_sha256",
            "members",
            "endpoints",
            "capacity",
        )
    }
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
    if identity.role != "main":
        raise LetsInferError("engine-group lifecycle is main-node-only")
    with _site_store() as store:
        placements = {row["placement_id"]: row for row in store.placements()}
        selected = [
            (row, placements[row["placement_id"]])
            for row in store.engine_groups()
            if row["state"] != "removed"
            and (action == "remove" or row["desired_state"] != "removed")
            and row["placement_id"] in placements
            and (model is None or placements[row["placement_id"]]["model"] == model)
        ]
        if not selected:
            return None
        results: list[dict[str, Any]] = []
        for row, _placement in selected:
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
                    if (
                        row["desired_state"] != "removed"
                        and row["state"] not in {"staged", "stopped"}
                    ):
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
            results.append(result)
        if len(results) == 1:
            return results[0]
        aggregate_id = hashlib.sha256(
            canonical_bytes(
                {
                    "contract": "letsinfer-replica-lifecycle-v1",
                    "model": model,
                    "groups": sorted(result["group_id"] for result in results),
                }
            )
        ).hexdigest()[:32]
        return {
            "group_id": aggregate_id,
            "group_ids": [result["group_id"] for result in results],
            "state": results[0]["state"],
            "groups": results,
        }


def _remove_all_engine_groups() -> list[str]:
    identity = read_site_identity()
    if identity.role != "main":
        return []
    removed: list[str] = []
    while True:
        with _site_store() as store:
            active = [
                row
                for row in store.engine_groups()
                if row["state"] != "removed"
                or row["desired_state"] != "removed"
            ]
            if not active:
                return removed
            row = active[0]
            if row["state"] == "removed":
                raise LetsInferError(
                    "engine-group removal is incomplete; restore member connectivity "
                    "and retry removal before uninstalling"
                )
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
    """Commit an approved move and restart the node agent after its HTTP reply."""
    if platform.system().lower() != "linux":
        raise SiteError("persistent node moves require Linux user systemd")
    if not user_lingering_enabled():
        raise SiteError("user-systemd lingering is required before a node move")
    systemctl = shutil.which("systemctl")
    systemd_run = shutil.which("systemd-run")
    if not systemctl or not pathlib.Path(systemctl).is_absolute() or not systemd_run:
        raise SiteError("user systemd move activation tools are unavailable")
    units = (
        SERVICE_NAME,
        NODE_SERVICE_NAME,
        ENGINE_SERVICE_NAME,
        GATEWAY_SERVICE_NAME,
        RECOVERY_TIMER_NAME,
    )
    prior = {name: _unit_enabled_active(name) for name in units}
    if prior[NODE_SERVICE_NAME][1] != "active":
        raise SiteError("node move requires the private node service to be active")
    active_work = [
        name
        for name in (ENGINE_SERVICE_NAME,)
        if prior[name][1] == "active"
    ]
    if active_work:
        raise SiteError(
            "node move requires active inference services to be stopped first: "
            + ",".join(active_work)
        )
    unit_root = pathlib.Path.home() / ".config/systemd/user"
    watchdog_unit = unit_root / SERVICE_NAME
    watchdog_snapshot = _snapshot_user_file(watchdog_unit)
    restart_unit = f"letsinfer-node-move-{prepared.move_id}"
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
                NODE_SERVICE_NAME,
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
                if active == "active" and name != NODE_SERVICE_NAME:
                    run_passthrough([systemctl, "--user", "start", name])
        except BaseException as error:
            errors.append(str(error))
        if errors:
            raise SiteError(
                "node move failed and service rollback was incomplete: "
                + "; ".join(errors)
            ) from failure
        raise


def _controller_administration_completed(
    action: str, result: Mapping[str, Any]
) -> None:
    """After the commit response is on the wire, activate the new site identity."""
    if action != "node.move.commit":
        return
    move = result.get("move")
    move_id = move.get("move_id") if isinstance(move, Mapping) else None
    if not isinstance(move_id, str) or not re.fullmatch(r"[0-9a-f]{32}", move_id):
        return
    systemctl = shutil.which("systemctl")
    if systemctl is None:
        return
    restart_unit = f"letsinfer-node-move-{move_id}"
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
        runtime_value = payload.get("runtime")
        runtime = runtime_value if isinstance(runtime_value, str) else None
        command = ["install", model]
        if runtime is not None:
            command.extend(("--runtime", runtime))
        try:
            arguments = parser().parse_args(command)
        except SystemExit as error:
            raise LetsInferError("controller install action is invalid") from error
        try:
            install(arguments)
            candidates = [
                receipt
                for receipt in selections()
                if receipt["logical_model"] == model
                and (runtime is None or receipt["candidate_id"] == runtime)
            ]
            if candidates:
                receipt = max(
                    candidates, key=lambda value: value["installed_at_unix_ns"]
                )
                identifier = (
                    f"{receipt['candidate_id']}@{receipt['version']}"
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
        runtime_value = payload.get("runtime")
        runtime = runtime_value if isinstance(runtime_value, str) else None
        document = _topology_plan_document(
            model,
            runtime,
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
                disarm_before_planned_stop(config)
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
            if action in {"restart", "recover"}:
                disarm_before_planned_stop(config)
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
                        current["state"] == "failed"
                        and "unreachable" not in states.values()
                        and not any(orchestrator.protection_trips.values())
                    ):
                        current = orchestrator.recover(
                            acknowledge_trips=False
                        )
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


def _catalog_release_for_node(
    catalog: Mapping[str, Any],
    model: str,
    runtime: str | None,
    *,
    identity: Any,
    graph: TopologyGraph,
    member_id: str,
    ignore_allocations: bool = False,
) -> tuple[tuple[str, str, str, str, str], TargetPlacement, TopologyGraph]:
    """Resolve one exact target-specific release for one physical node."""
    if member_id not in graph.members:
        raise LetsInferError(f"node is not active in this topology: {member_id}")
    model_record = catalog.get("models", {}).get(model)
    if not isinstance(model_record, Mapping):
        raise LetsInferError(f"model is not present in runtime catalog: {model}")
    contracts = {
        target_id: catalog_target_contract(dict(catalog), target_id)
        for target_id in model_record["targets"]
    }
    node_graph = TopologyGraph(
        [graph.members[member_id]],
        allocated_devices={
            member_id: ()
            if ignore_allocations
            else tuple(graph.allocated_devices.get(member_id, ()))
        },
    )
    try:
        choice = node_graph.resolve_catalog_targets(
            contracts, coordinator_id=member_id
        )
        release = catalog_release(
            dict(catalog), model, runtime, choice.target_id, device=None
        )
    except (RuntimePackError, TopologyError) as error:
        raise LetsInferError(str(error)) from error
    return release, choice, node_graph


def _selected_install_node_ids(
    arguments: argparse.Namespace,
    identity: Any,
    members: Sequence[Mapping[str, Any]],
) -> tuple[str, ...]:
    active = [dict(row) for row in members if row.get("state") == "active"]
    by_id = {str(row["member_id"]): row for row in active}
    by_name: dict[str, list[str]] = {}
    for row in active:
        by_name.setdefault(str(row["display_name"]), []).append(str(row["member_id"]))
    requested = list(getattr(arguments, "node", None) or [])
    if getattr(arguments, "all_nodes", False) and requested:
        raise LetsInferError("--node and --all-nodes cannot be combined")
    if getattr(arguments, "all_nodes", False):
        return tuple(sorted(by_id))
    if requested:
        selected: list[str] = []
        for value in requested:
            if value in by_id:
                member_id = value
            else:
                matches = by_name.get(value, [])
                if not matches:
                    raise LetsInferError(f"unknown active node: {value}")
                if len(matches) != 1:
                    raise LetsInferError(
                        f"node name is ambiguous; use its identity: {value}"
                    )
                member_id = matches[0]
            if member_id not in selected:
                selected.append(member_id)
        return tuple(selected)
    if len(active) > 1 and sys.stdin.isatty():
        if ui.confirm(
            f"Replicate this model across all {len(active)} compatible nodes?"
        ):
            return tuple(sorted(by_id))
    return (identity.member_id,)


def _remove_engine_groups_by_id(group_ids: Sequence[str]) -> None:
    """Drain and remove exact groups before an explicitly approved replacement."""
    wanted = tuple(dict.fromkeys(group_ids))
    if not wanted:
        return
    with _site_store() as store:
        rows = {row["group_id"]: row for row in store.engine_groups()}
        allocations_by_group: dict[str, list[dict[str, Any]]] = {}
        for allocation in store.device_allocations():
            allocations_by_group.setdefault(
                str(allocation["group_id"]), []
            ).append(dict(allocation))
        missing = [group_id for group_id in wanted if group_id not in rows]
        if missing:
            raise LetsInferError(
                "replacement group state disappeared: " + ",".join(missing)
            )
        for group_id in wanted:
            row = rows[group_id]
            if row["state"] == "removed" or row["desired_state"] == "removed":
                continue
            orchestrator, _manifest = _restore_engine_group_orchestrator(store, row)
            allocations = allocations_by_group.get(group_id, [])
            allocations_released = bool(allocations) and all(
                allocation["state"] == "released" for allocation in allocations
            )
            if (
                row["state"] not in {"staged", "stopped"}
                and not allocations_released
            ):
                stopped = orchestrator.stop()
                _sync_group_placement(store, stopped)
            removed = orchestrator.remove()
            _sync_group_placement(store, removed)


def _install_catalog_nodes(
    arguments: argparse.Namespace,
) -> int | None:
    """Plan and install one independent target-specific group per selected node."""
    model_path = pathlib.Path(arguments.model).expanduser()
    if model_path.exists() or REGISTRY_DIGEST_RE.fullmatch(arguments.model):
        return None
    location = resolved_catalog_location(getattr(arguments, "catalog", None))
    if location is None:
        return None
    try:
        catalog = CatalogManager(location).load().document
    except (CatalogError, RuntimePackError) as error:
        raise LetsInferError(str(error)) from error
    identity, graph = _fresh_site_topology()
    with _site_store() as store:
        members = store.members()
        placements = {
            row["placement_id"]: row
            for row in store.placements()
            if row["state"] in {"starting", "running", "draining"}
        }
        groups = [
            row
            for row in store.engine_groups()
            if row["state"] != "removed" and row["desired_state"] != "removed"
        ]
    selected = _selected_install_node_ids(arguments, identity, members)
    member_rows = {str(row["member_id"]): dict(row) for row in members}
    groups_by_node: dict[str, list[dict[str, Any]]] = {
        member_id: [] for member_id in selected
    }
    for group in groups:
        for resource in group["plan"]["resources"]:
            if resource["node_id"] in groups_by_node:
                groups_by_node[resource["node_id"]].append(group)
    install_nodes: list[str] = []
    replacements: dict[str, list[str]] = {}
    planned: dict[str, tuple[tuple[str, str, str, str, str], TargetPlacement]] = {}
    presenter = _human_presenter()
    plan_rows: list[dict[str, Any]] = []
    for member_id in selected:
        display_name = member_rows[member_id]["display_name"]
        resident = groups_by_node[member_id]
        resident_models = {
            placements[row["placement_id"]]["model"]
            for row in resident
            if row["placement_id"] in placements
        }
        try:
            release, choice, _node_graph = _catalog_release_for_node(
                catalog,
                arguments.model,
                getattr(arguments, "runtime", None),
                identity=identity,
                graph=graph,
                member_id=member_id,
                ignore_allocations=bool(resident),
            )
        except LetsInferError as error:
            if presenter is not None:
                plan_rows.append(
                    {
                        "node": display_name,
                        "state": "Unsupported",
                        "detail": str(error),
                        "_semantic": command_ui.Semantic.ERROR,
                    }
                )
            else:
                print(f"ERROR {display_name}  {error}")
            continue
        planned[member_id] = (release, choice)
        install_nodes.append(member_id)
        if resident:
            replacements[member_id] = [row["group_id"] for row in resident]
            names = ", ".join(sorted(resident_models)) or "an installed runtime"
            if presenter is not None:
                plan_rows.append(
                    {
                        "node": display_name,
                        "state": "Replace",
                        "detail": f"{release[2]}@{release[3]} replaces {names}",
                        "_semantic": command_ui.Semantic.WARNING,
                    }
                )
            else:
                print(f"WARNING {display_name}  supported; replaces {names}")
        else:
            if presenter is not None:
                plan_rows.append(
                    {
                        "node": display_name,
                        "state": "Ready",
                        "detail": f"{release[2]}@{release[3]}",
                        "_semantic": command_ui.Semantic.SUCCESS,
                    }
                )
            else:
                print(f"OK {display_name}  supported; {release[2]}@{release[3]}")
    if presenter is not None:
        presenter.table(
            (
                command_ui.TableColumn("node", "NODE", min_width=6),
                command_ui.TableColumn("state", "STATE", min_width=7),
                command_ui.TableColumn("detail", "RUNTIME", min_width=10),
            ),
            plan_rows,
            empty_message="No compatible nodes were selected",
        )
    if not install_nodes:
        if any(
            placements[row["placement_id"]]["model"] == arguments.model
            for rows in groups_by_node.values()
            for row in rows
            if row["placement_id"] in placements
        ):
            return 0
        raise LetsInferError("no selected node has a qualified runtime for this model")
    if replacements and not getattr(arguments, "replace_existing", False):
        if not sys.stdin.isatty():
            raise LetsInferError(
                "installation would replace installed runtime groups; retry with "
                "--replace-existing"
            )
        if not ui.confirm(
            "An existing runtime must be removed first. Replace it now?"
        ):
            raise LetsInferError("installation cancelled before replacement")
    activity = _command_activity(arguments, action_id="install")
    with activity, ui.protect_stdout(activity):
        if replacements:
            _remove_engine_groups_by_id(
                [group_id for values in replacements.values() for group_id in values]
            )
        completed = 0
        for member_id in install_nodes:
            # Refresh after every launch so the next plan observes the newly sealed
            # GPU allocation and cannot overlap it.
            identity, graph = _fresh_site_topology()
            release, choice, node_graph = _catalog_release_for_node(
                catalog,
                arguments.model,
                getattr(arguments, "runtime", None),
                identity=identity,
                graph=graph,
                member_id=member_id,
            )
            target_id, target_sha256, candidate, version, source = release
            manifest_path, manifest, control_root, receipt = prepare_runtime_install(
                source,
                policy=(
                    f"runtime:{candidate}"
                    if getattr(arguments, "runtime", None)
                    else "recommended"
                ),
                qualified=True,
                requested_runtime=getattr(arguments, "runtime", None),
                requested_target=target_id,
                expected_version=version,
                expected_target_contract_sha256=target_sha256,
            )
            runtime = verify_descriptor(pathlib.Path(receipt["object_root"]))
            release_record = catalog_release_record(
                dict(catalog), arguments.model, target_id, candidate, version
            )
            release_identity = _group_release_identity(
                catalog_release_value=release_record,
                candidate_id=candidate,
                version=version,
                source=source,
                target_id=target_id,
                target_sha256=target_sha256,
                runtime=runtime,
                manifest_sha256=sha256_file(manifest_path),
            )
            install_engine_group(
                arguments,
                source=source,
                manifest_path=manifest_path,
                manifest=manifest,
                control_root=control_root,
                receipt=receipt,
                release_identity=release_identity,
                resolved_topology=(identity, node_graph, choice.placement),
            )
            completed += 1
    if presenter is not None:
        presenter.records(
            (
                command_ui.RecordRow(
                    "Runtime", arguments.model, semantic=command_ui.Semantic.SUCCESS
                ),
                command_ui.RecordRow("Groups", completed),
                command_ui.RecordRow(
                    "Nodes",
                    ", ".join(
                        member_rows[member_id]["display_name"]
                        for member_id in install_nodes
                    ),
                ),
            )
        )
    else:
        print(
            f"REPLICA POOL {arguments.model} groups={completed} "
            f"nodes={','.join(install_nodes)}"
        )
    return 0


def scale_command(arguments: argparse.Namespace) -> int:
    """Converge one logical model service to an exact number of groups."""
    replicas = arguments.replicas
    if not isinstance(replicas, int) or isinstance(replicas, bool) or replicas not in range(1, 129):
        raise LetsInferError("--replicas must be from 1 through 128")
    location = resolved_catalog_location(arguments.catalog)
    if location is None:
        raise LetsInferError(
            "replica scaling requires --catalog or LETSINFER_CATALOG"
        )
    try:
        catalog = CatalogManager(location).load().document
    except (CatalogError, RuntimePackError) as error:
        raise LetsInferError(str(error)) from error

    with _site_store() as store:
        placements = {row["placement_id"]: row for row in store.placements()}
        current = [
            row
            for row in store.engine_groups()
            if row["state"] != "removed"
            and row["desired_state"] != "removed"
            and row["placement_id"] in placements
            and placements[row["placement_id"]]["model"] == arguments.model
        ]
    if len(current) > replicas:
        removable = sorted(
            current,
            key=lambda row: (
                row["state"] == "running",
                row["updated_at_unix"],
                row["group_id"],
            ),
        )[: len(current) - replicas]
        _remove_engine_groups_by_id([row["group_id"] for row in removable])
        current = [row for row in current if row not in removable]

    while len(current) < replicas:
        identity, graph = _fresh_site_topology()
        try:
            release, choice = _catalog_site_release(
                dict(catalog),
                arguments.model,
                arguments.runtime,
                topology=(identity, graph),
            )
        except LetsInferError as error:
            raise LetsInferError(
                f"replica pool reached {len(current)}/{replicas}; "
                f"no unallocated qualified target remains: {error}"
            ) from error
        target_id, target_sha256, candidate, version, source = release
        manifest_path, manifest, control_root, receipt = prepare_runtime_install(
            source,
            policy=f"runtime:{candidate}" if arguments.runtime else "recommended",
            qualified=True,
            requested_runtime=arguments.runtime,
            requested_target=target_id,
            expected_version=version,
            expected_target_contract_sha256=target_sha256,
        )
        runtime = verify_descriptor(pathlib.Path(receipt["object_root"]))
        release_identity = _group_release_identity(
            catalog_release_value=catalog_release_record(
                dict(catalog), arguments.model, target_id, candidate, version
            ),
            candidate_id=candidate,
            version=version,
            source=source,
            target_id=target_id,
            target_sha256=target_sha256,
            runtime=runtime,
            manifest_sha256=sha256_file(manifest_path),
        )
        install_engine_group(
            arguments,
            source=source,
            manifest_path=manifest_path,
            manifest=manifest,
            control_root=control_root,
            receipt=receipt,
            release_identity=release_identity,
            resolved_topology=(identity, graph, choice.placement),
        )
        with _site_store() as store:
            placements = {row["placement_id"]: row for row in store.placements()}
            current = [
                row
                for row in store.engine_groups()
                if row["state"] != "removed"
                and row["desired_state"] != "removed"
                and row["placement_id"] in placements
                and placements[row["placement_id"]]["model"] == arguments.model
            ]
    presenter = _human_presenter()
    if presenter is not None:
        presenter.records(
            (
                command_ui.RecordRow(
                    "Runtime", arguments.model, semantic=command_ui.Semantic.SUCCESS
                ),
                command_ui.RecordRow("Groups", len(current)),
                command_ui.RecordRow("Desired", replicas),
            )
        )
    else:
        print(f"REPLICA POOL {arguments.model} groups={len(current)} desired={replicas}")
    return 0


def install(arguments: argparse.Namespace) -> int:
    catalog_install = _install_catalog_nodes(arguments)
    if catalog_install is not None:
        return catalog_install
    catalog_value = getattr(arguments, "catalog", None)
    if not isinstance(catalog_value, str):
        catalog_value = None
    runtime_source = _runtime_source_for_install(
        arguments.model,
        getattr(arguments, "runtime", None),
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
            runtime_source[5],
        )
    (
        source,
        policy,
        expected_version,
        selected_target,
        selected_target_sha256,
        catalog_qualified,
    ) = runtime_source
    manifest_path, manifest, release_root, prepared_receipt = prepare_runtime_install(
        source,
        policy=policy,
        qualified=catalog_qualified,
        requested_runtime=getattr(arguments, "runtime", None),
        requested_target=selected_target,
        expected_version=expected_version,
        expected_target_contract_sha256=(
            selected_target_sha256
            or getattr(arguments, "expected_target_contract_sha256", None)
        ),
    )
    selected_receipt = prepared_receipt
    verify_runtime_sources(manifest, release_root)
    serving = manifest["serving"]
    if not serving["qualified"]:
        model_cache = requested_model_cache(getattr(arguments, "model_cache", None))
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
        verify_installed_runtime(manifest, model_cache=model_cache)
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
        api_key_file = expanded_path(api_key_value or default_engine_api_key_path())
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
        presenter = _human_presenter()
        if presenter is not None:
            presenter.records(
                (
                    command_ui.RecordRow(
                        "Runtime",
                        prepared_receipt["candidate_id"],
                        prepared_receipt["version"],
                        command_ui.Semantic.WARNING,
                    ),
                    command_ui.RecordRow(
                        "Activation", "Blocked", serving["blocked_by"]
                    ),
                )
            )
            presenter.verbatim(
                f"sha256:{prepared_receipt['digest']}",
                label="Digest",
                copyable=True,
            )
            presenter.verbatim(receipt_path, label="Receipt", copyable=True)
        else:
            print(
                f"INSTALLED RUNTIME {prepared_receipt['candidate_id']} "
                f"version={prepared_receipt['version']} digest=sha256:{prepared_receipt['digest']} "
                f"activation=blocked receipt={receipt_path}"
            )
            print(f"  blocked_by: {serving['blocked_by']}")
        return 0
    if not arguments.no_service and not user_lingering_enabled():
        raise LetsInferError(
            "boot-persistent user service requires lingering; run "
            f"sudo loginctl enable-linger {getpass.getuser()} and retry"
        )
    raise LetsInferError(
        "qualified runtime activation requires its signed catalog release; "
        "install by logical model name instead of a local or bare OCI source"
    )
    # Unqualified development runs retain the isolated candidate path above.
    # Every qualified runtime below this boundary is represented by a durable
    # engine group, including an ordinary one-device runtime.
    manifest_sha = sha256_file(manifest_path)
    placement = resolve_service_placement(manifest, manifest_sha)
    control_root, installed_manifest_path = install_control_bundle(
        manifest_path,
        manifest,
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

    model_cache = requested_model_cache(arguments.model_cache)
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
    runtime_artifact_root = pathlib.Path(selected_receipt["object_root"]).expanduser()
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
    verify_installed_runtime(manifest, model_cache=model_cache)

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
    config.update(
        {
            "runtime_name": selected_receipt["candidate_id"],
            "runtime_version": selected_receipt["version"],
            "runtime_digest": selected_receipt["digest"],
            "runtime_policy": selected_receipt["policy"],
        }
    )
    config["watchdog_public_state_file"] = str(
        write_watchdog_public_state(config, manifest)
    )
    if prepared_receipt is not None:
        prepared_receipt["manifest_path"] = str(installed_manifest_path)
        prepared_receipt["control_root"] = str(control_root)
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
            runtime_receipt=prepared_receipt,
        )
        if arguments.no_start:
            update_service_placement(config, manifest, "stopped")
    if prepared_receipt is not None and arguments.no_service:
        try:
            write_selection(prepared_receipt)
        except RuntimePackError as error:
            raise LetsInferError(
                f"runtime activated but its selection receipt could not be written: {error}"
            ) from error
    presenter = _human_presenter()
    if presenter is not None:
        service_state = "Disabled" if arguments.no_service else "Enabled"
        if not arguments.no_service and arguments.no_start:
            service_state = "Installed, not started"
        presenter.records(
            (
                command_ui.RecordRow(
                    "Runtime",
                    manifest["release"],
                    semantic=command_ui.Semantic.SUCCESS,
                ),
                command_ui.RecordRow("Service", service_state),
            )
        )
        presenter.verbatim(config_path, label="Configuration", copyable=True)
    else:
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
        presenter = _human_presenter()
        if presenter is not None:
            presenter.result(
                "Runtime already stopped",
                semantic=command_ui.Semantic.INFO,
                detail=name,
            )
        else:
            print(f"STOPPED {name} already-absent=true")
        return 0
    labels = inspection.get("Config", {}).get("Labels") or {}
    if labels.get(MANAGED_LABEL) != "true":
        raise LetsInferError(f"container {name} is not managed by Let's Infer; refusing to remove it")

    stamp = dt.datetime.now().astimezone().strftime("%Y%m%dT%H%M%S%z")
    evidence = evidence_root() / "stops" / f"{name}-{stamp}"
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
    presenter = _human_presenter()
    if presenter is not None:
        presenter.records(
            (
                command_ui.RecordRow(
                    "Container", name, "Stopped", command_ui.Semantic.SUCCESS
                ),
            )
        )
        presenter.verbatim(evidence, label="Evidence", copyable=True)
    else:
        print(f"STOPPED {name} evidence={evidence}")
    return 0


def stop_from_config(arguments: argparse.Namespace) -> int:
    config = read_service_config(pathlib.Path(arguments.config))
    _, manifest = configured_release(config)
    disarm_before_planned_stop(config)
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
        qualification_path = qualification_service_config_path()
        if qualification_path.is_file():
            qualification = read_service_config(qualification_path)
            if qualification.get("qualification_mode") is not True:
                raise LetsInferError("qualification slot has an invalid lifecycle mode")
            if model is not None and qualification.get("model") != model:
                raise LetsInferError(f"no installed runtime serves model {model!r}")
            return _qualification_candidate_lifecycle(qualification, "stop")
    if arguments.name is None and arguments.config is None:
        group = _engine_group_lifecycle(model, "stop")
        if group is not None:
            groups = group.get("groups")
            members = (
                sum(len(item["member_states"]) for item in groups)
                if isinstance(groups, list)
                else len(group["member_states"])
            )
            presenter = _human_presenter()
            if presenter is not None:
                presenter.records(
                    (
                        command_ui.RecordRow(
                            "Runtime",
                            model or "All installed runtimes",
                            semantic=command_ui.Semantic.SUCCESS,
                        ),
                        command_ui.RecordRow("Group", group["group_id"]),
                        command_ui.RecordRow("Members", members),
                        command_ui.RecordRow("State", "Stopped"),
                    )
                )
            else:
                print(
                    f"STOPPED group={group['group_id']} "
                    f"members={members}"
                )
            return 0
    if arguments.name is not None:
        qualification_path = qualification_service_config_path()
        if qualification_path.is_file():
            qualification = read_service_config(qualification_path)
            if qualification.get("qualification_mode") is True and qualification[
                "name"
            ] == arguments.name:
                return _qualification_candidate_lifecycle(qualification, "stop")
    config_path = absolute_user_path(
        arguments.config or default_service_config_path()
    )
    config = read_service_config(config_path) if config_path.is_file() else None
    if config is not None and config.get("qualification_mode") is True:
        if model is not None and config.get("model") != model:
            raise LetsInferError(f"no installed runtime serves model {model!r}")
        return _qualification_candidate_lifecycle(config, "stop")
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
            assert config is not None
            disarm_before_planned_stop(config)
            run_passthrough(
                ["systemctl", "--user", "stop", ENGINE_SERVICE_NAME]
            )
            presenter = _human_presenter()
            if presenter is not None:
                presenter.records(
                    (
                        command_ui.RecordRow(
                            "Service",
                            ENGINE_SERVICE_NAME,
                            "Stopped",
                            command_ui.Semantic.SUCCESS,
                        ),
                    )
                )
            else:
                print(f"STOPPED {ENGINE_SERVICE_NAME}")
            return 0
    if config is not None:
        disarm_before_planned_stop(config)
    key_path = expanded_path(config["engine_api_key_file"]) if config is not None else None
    return _stop_managed_container(name, key_path)


def runtime_lifecycle(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Compatibility entry point for the shared operational state plane."""

    return derive_runtime_lifecycle(payload)


def _local_controller_telemetry(
    config: Mapping[str, Any] | None = None,
    *,
    preferred_member_id: str | None = None,
) -> dict[str, Any] | None:
    """Read the node agent's live aggregate without consuming a Watchdog slot."""

    controller_ca = expanded_path(
        str(config.get("watchdog_controller_ca_file"))
        if config and config.get("watchdog_controller_ca_file")
        else default_watchdog_controller_ca_path()
    )
    client_certificate = expanded_path(
        str(config.get("watchdog_local_controller_cert_file"))
        if config and config.get("watchdog_local_controller_cert_file")
        else default_watchdog_local_controller_cert_path()
    )
    client_key = expanded_path(
        str(config.get("watchdog_local_controller_key_file"))
        if config and config.get("watchdog_local_controller_key_file")
        else default_watchdog_local_controller_key_path()
    )
    if not all(path.is_file() for path in (
        controller_ca, client_certificate, client_key
    )):
        return None
    connection: http.client.HTTPSConnection | None = None
    try:
        context = ssl.create_default_context(cafile=str(controller_ca))
        context.check_hostname = False
        context.load_cert_chain(str(client_certificate), str(client_key))
        connection = http.client.HTTPSConnection(
            "127.0.0.1", CONTROLLER_CONTROL_PORT, timeout=1, context=context
        )
        connection.request("GET", "/control/v1/telemetry?history=0")
        response = connection.getresponse()
        body = response.read(1024 * 1024 + 1)
        if response.status != 200 or len(body) > 1024 * 1024:
            return None
        value = json.loads(body)
        if not isinstance(value, dict):
            return None
        telemetry = value.get("telemetry")
        aggregate = telemetry.get("aggregate") if isinstance(telemetry, dict) else None
        if not isinstance(aggregate, dict):
            return None
        result = dict(aggregate)
        result["updated_unix_ms"] = telemetry.get("unix_ms")
        result["fresh"] = False
        members = telemetry.get("members")
        if isinstance(members, list):
            fresh_rows = [
                row
                for row in members
                if isinstance(row, dict)
                and row.get("stale") is False
                and isinstance(row.get("sample"), dict)
            ]
            fresh = (
                next(
                    (
                        row
                        for row in fresh_rows
                        if row["sample"].get("member_id") == preferred_member_id
                    ),
                    None,
                )
                if preferred_member_id is not None
                else next(iter(fresh_rows), None)
            )
            if fresh is not None:
                sample = fresh["sample"]
                result["fresh"] = True
                result["sample_member_id"] = sample.get("member_id")
                result["sample_sequence"] = sample.get("sequence")
                result["sample_unix_ms"] = sample.get("unix_ms")
                result["system"] = sample.get("system")
                result["workload"] = sample.get("workload")
        return result
    except (
        OSError,
        UnicodeDecodeError,
        ssl.SSLError,
        http.client.HTTPException,
        json.JSONDecodeError,
    ):
        return None
    finally:
        if connection is not None:
            connection.close()


def _local_status_node(identity: Any) -> dict[str, Any]:
    """Return the cached local identity and inventory used by live status."""

    summary: dict[str, Any] = {
        **identity_json(identity),
        "hostname": socket.gethostname(),
    }
    if identity.role != "main":
        return summary
    try:
        with SiteStore(identity=identity) as store:
            member = next(
                (
                    row
                    for row in store.members()
                    if row.get("member_id") == identity.member_id
                ),
                None,
            )
    except (OSError, SiteError):
        return summary
    facts = member.get("facts") if isinstance(member, dict) else None
    inventory = facts.get("inventory") if isinstance(facts, dict) else None
    if isinstance(inventory, dict):
        summary["hardware_name"] = (
            inventory.get("dgx_name")
            or inventory.get("product_name")
            or inventory.get("board_name")
        )
        summary["uptime_seconds"] = inventory.get("uptime_seconds")
    return summary


def status(arguments: argparse.Namespace) -> int:
    if (
        not arguments.json
        and ui.Terminal(sys.stdout).interactive
        and not getattr(arguments, "_single_snapshot", False)
    ):
        def snapshot() -> dict[str, Any]:
            values = vars(arguments).copy()
            values.update(
                {
                    "json": True,
                    "_single_snapshot": True,
                    "_live_snapshot": True,
                }
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = status(argparse.Namespace(**values))
            value = json.loads(output.getvalue())
            if not isinstance(value, dict):
                raise LetsInferError("status snapshot is invalid")
            value["exit_code"] = code
            value["updates"] = [
                {
                    "kind": record.kind,
                    "subject": record.subject,
                    "version": record.available_version,
                }
                for record in _update_manager().cached().available
            ]
            return value

        return ui.live_runtime_status(snapshot)
    model_value = getattr(arguments, "model", None)
    model = model_value if isinstance(model_value, str) else None
    live_groups: list[dict[str, Any]] = []
    if model is not None and (arguments.name is not None or arguments.config is not None):
        raise LetsInferError("a model cannot be combined with --name or --config")
    if arguments.name is None and arguments.config is None and site_identity_path().exists():
        identity = read_site_identity()
        if identity.role == "main":
            groups = _engine_group_status(model)
            if groups:
                if getattr(arguments, "_live_snapshot", False):
                    live_groups = groups
                else:
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
                                    f"  MEMBER {member['member_id']} "
                                    f"task={member['task_id']} "
                                    f"state={member['state']}"
                                )
                    return 0
        elif model is not None:
            raise LetsInferError(
                "node-wide engine-group status is available from the main node"
            )
    config_path = absolute_user_path(
        arguments.config or active_service_config_path()
    )
    config = read_service_config(config_path) if config_path.is_file() else None
    qualification_mode = bool(
        config is not None and config.get("qualification_mode") is True
    )
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
        watchdog_enabled, watchdog_active, watchdog_memory_bytes = _service_state()
        node_enabled, node_active, node_memory_bytes = _service_state(
            NODE_SERVICE_NAME
        )
        gateway_enabled, gateway_active, gateway_memory_bytes = _service_state(
            GATEWAY_SERVICE_NAME
        )
        is_main = identity.role == "main"
        gateway_health = False
        gateway_auth_required = False
        gateway_authenticated = False
        endpoint = None
        if is_main:
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
        service = {
            "active": watchdog_active,
            "enabled": watchdog_enabled,
            "watchdog_expected": platform.system() == "Linux",
            "memory_current_bytes": watchdog_memory_bytes,
            "memory_limit_bytes": CONTROL_PLANE_MEMORY_LIMIT_BYTES,
            "runtime_installed": False,
            "gateway_expected": is_main,
            "node_enabled": node_enabled,
            "node_active": node_active,
            "node_memory_current_bytes": node_memory_bytes,
            "gateway_enabled": gateway_enabled,
            "gateway_active": gateway_active,
            "gateway_health": gateway_health,
            "gateway_auth_required": gateway_auth_required,
            "gateway_authenticated": gateway_authenticated,
            "gateway_model_identity": False,
            "gateway_endpoint": endpoint,
        }
        payload = {
            "identity": identity_json(identity),
            "endpoint": endpoint,
            "services": {
                "watchdog_enabled": watchdog_enabled,
                "watchdog_active": watchdog_active,
                "watchdog_memory_current_bytes": watchdog_memory_bytes,
                "node_enabled": node_enabled,
                "node_active": node_active,
                "node_memory_current_bytes": node_memory_bytes,
                "gateway_enabled": gateway_enabled,
                "gateway_active": gateway_active,
                "gateway_memory_current_bytes": gateway_memory_bytes,
                "gateway_health": gateway_health,
                "gateway_auth_required": gateway_auth_required,
                "gateway_authenticated": gateway_authenticated,
            },
            "service": service,
            "container": {},
            "protection": None,
            "runtime": None,
            "node": _local_status_node(identity),
            "telemetry": (
                _local_controller_telemetry(
                    preferred_member_id=identity.member_id,
                )
                if identity.role == "main" and node_active == "active"
                else None
            ),
        }
        if live_groups:
            payload["engine_groups"] = live_groups
        payload["lifecycle"] = runtime_lifecycle(payload)
        if arguments.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        elif ui.Terminal(sys.stdout).interactive:
            ui.node_status(payload)
        else:
            print(
                f"node={node_active} enabled={node_enabled} "
                f"role={identity.role} node_id={identity.member_id}"
            )
            if is_main:
                print(
                    f"gateway={gateway_active} health={str(gateway_health).lower()} "
                    f"auth={str(gateway_auth_required and gateway_authenticated).lower()}"
                )
                print(f"endpoint={endpoint}")
            print("runtime=not-installed")
        return 0 if payload["lifecycle"]["state"] == "ready" else 1

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
    node_enabled, node_active, node_memory_bytes = _service_state(NODE_SERVICE_NAME)
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
    memory_available_bytes: int | None = None
    try:
        memory_available_bytes = parse_mem_available_bytes(
            pathlib.Path("/proc/meminfo").read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, ValueError, LetsInferError):
        pass
    memory_pressure_floor_bytes = (
        config.get("memory_pressure_available_bytes") if config else None
    )
    memory_pressure = (
        memory_available_bytes is not None
        and memory_pressure_floor_bytes is not None
        and memory_available_bytes <= memory_pressure_floor_bytes
    )

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
            "node_service": NODE_SERVICE_NAME,
            "node_enabled": node_enabled,
            "node_active": node_active,
            "node_memory_current_bytes": node_memory_bytes,
            "node_memory_limit_bytes": NODE_AGENT_MEMORY_LIMIT_BYTES,
            "site_within_memory_limit": node_memory_bytes is not None
            and node_memory_bytes < NODE_AGENT_MEMORY_LIMIT_BYTES,
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
            "runtime_mode": "qualification" if qualification_mode else "resident",
            "memory_pressure": memory_pressure,
            "memory_available_bytes": memory_available_bytes,
            "memory_pressure_floor_bytes": memory_pressure_floor_bytes,
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
            "qualification_mode": qualification_mode,
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
    local_member_id: str | None = None
    try:
        identity = read_site_identity()
        local_member_id = identity.member_id
        payload["node"] = _local_status_node(identity)
    except (OSError, SiteError, StopIteration):
        payload["node"] = None
    payload["lifecycle"] = runtime_lifecycle(payload)
    payload["telemetry"] = _local_controller_telemetry(
        config,
        preferred_member_id=local_member_id,
    )
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
    run_passthrough(command, visible=True)
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
        candidate_path = qualification_service_config_path()
        if candidate_path.is_file():
            candidate = read_service_config(candidate_path)
            if candidate.get("qualification_mode") is not True:
                raise LetsInferError("qualification slot has an invalid lifecycle mode")
            if model is not None and candidate.get("model") != model:
                raise LetsInferError(f"no installed runtime serves model {model!r}")
            return _qualification_candidate_lifecycle(candidate, action)
    if arguments.config is None:
        group = _engine_group_lifecycle(model, action)
        if group is not None:
            groups = group.get("groups")
            members = (
                sum(len(item["member_states"]) for item in groups)
                if isinstance(groups, list)
                else len(group["member_states"])
            )
            presenter = _human_presenter()
            if presenter is not None:
                presenter.records(
                    (
                        command_ui.RecordRow(
                            "Runtime",
                            model or "All installed runtimes",
                            semantic=command_ui.Semantic.SUCCESS,
                        ),
                        command_ui.RecordRow("Group", group["group_id"]),
                        command_ui.RecordRow("Members", members),
                        command_ui.RecordRow("Action", action.title()),
                        command_ui.RecordRow(
                            "Guard",
                            "Recovered" if action == "recover" else "Armed",
                            (
                                "Protection trips acknowledged"
                                if action == "recover"
                                else ""
                            ),
                        ),
                    )
                )
            else:
                print(
                    f"{action.upper()} group={group['group_id']} "
                    f"members={members} "
                    f"protection_trips_acknowledged={str(action == 'recover').lower()}"
                )
            return 0
    config_path = absolute_user_path(
        arguments.config or default_service_config_path()
    )
    config = read_service_config(config_path)
    if config.get("qualification_mode") is True:
        if model is not None and config.get("model") != model:
            raise LetsInferError(f"no installed runtime serves model {model!r}")
        return _qualification_candidate_lifecycle(config, action)
    if model is not None and config.get("model") != model:
        raise LetsInferError(f"no installed runtime serves model {model!r}")
    enabled = run(
        ["systemctl", "--user", "is-enabled", ENGINE_SERVICE_NAME],
        check=False,
    )
    if enabled.returncode != 0 or enabled.stdout.strip() not in {"enabled", "static"}:
        raise LetsInferError(f"{ENGINE_SERVICE_NAME} is not installed")
    if action in {"restart", "recover"}:
        disarm_before_planned_stop(config)
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
    presenter = _human_presenter()
    if presenter is not None:
        presenter.records(
            (
                command_ui.RecordRow(
                    "Runtime",
                    config["model"],
                    semantic=command_ui.Semantic.SUCCESS,
                ),
                command_ui.RecordRow("Service", ENGINE_SERVICE_NAME, "Active"),
                command_ui.RecordRow("Action", action.title()),
                command_ui.RecordRow(
                    "Guard",
                    "Recovered" if cleared_trip else "Armed",
                    "Protection trip cleared" if cleared_trip else "",
                ),
            )
        )
    else:
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
        "site-role", identity.role == "main",
        f"role={identity.role} coordinator={identity.coordinator_id}",
    )
    record("user-lingering", user_lingering_enabled(), getpass.getuser())
    for unit, limit in (
        (NODE_SERVICE_NAME, NODE_AGENT_MEMORY_LIMIT_BYTES),
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
        "gateway_queue_timeout_seconds": 0,
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
        presenter = _human_presenter()
        if presenter is not None:
            rendered = [
                {
                    **item,
                    "result": "PASS" if item["passed"] else "FAIL",
                    "_semantic": (
                        command_ui.Semantic.SUCCESS
                        if item["passed"]
                        else command_ui.Semantic.ERROR
                    ),
                }
                for item in checks
            ]
            presenter.table(
                (
                    command_ui.TableColumn("result", "RESULT", min_width=6),
                    command_ui.TableColumn("name", "CHECK", min_width=12),
                    command_ui.TableColumn("detail", "DETAIL", min_width=18),
                ),
                rendered,
            )
            presenter.result(
                "Node is operational" if operational_ready else "Node needs attention",
                semantic=(
                    command_ui.Semantic.SUCCESS
                    if operational_ready
                    else command_ui.Semantic.ERROR
                ),
            )
        else:
            for item in checks:
                print(
                    f"{'PASS' if item['passed'] else 'FAIL'} {item['name']}: "
                    f"{item['detail']}"
                )
            print(f"operational_ready={str(operational_ready).lower()}")
    return 0 if operational_ready else 1


def _doctor_runtime_unit_checks(
    *,
    qualification_mode: bool,
    engine_enabled: str,
    engine_active: str,
    recovery_enabled: str,
    recovery_active: str,
) -> tuple[tuple[str, bool, str], ...]:
    if qualification_mode:
        return (
            (
                "resident-engine-quiesced",
                engine_active in {"inactive", "failed", "not-found"},
                engine_active,
            ),
            (
                "resident-recovery-quiesced",
                recovery_active in {"inactive", "failed", "not-found"},
                recovery_active,
            ),
        )
    return (
        (
            "engine-service-loaded",
            engine_enabled in {"static", "disabled"},
            engine_enabled,
        ),
        ("engine-service-active", engine_active == "active", engine_active),
        ("recovery-enabled", recovery_enabled == "enabled", recovery_enabled),
        ("recovery-active", recovery_active == "active", recovery_active),
    )


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
        if identity.role == "main":
            groups = _engine_group_status(model)
            if groups:
                return _doctor_engine_groups(arguments, groups)
        elif model is not None:
            raise LetsInferError(
                "node-wide engine-group doctor is available from the main node"
            )

    config_path = absolute_user_path(
        arguments.config or active_service_config_path()
    )
    config = read_service_config(config_path)
    qualification_mode = config.get("qualification_mode") is True
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
        verify_runtime_sources(
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
    expected_units = (
        {}
        if qualification_mode
        else {
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
                config["name"],
                expanded_path(config["protection_root"]),
                control_root,
            ),
            RECOVERY_TIMER_NAME: render_recovery_timer(),
        }
    )
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
    if qualification_mode:
        try:
            gateway_unit = verify_active_core_gateway()
            record(f"unit-{GATEWAY_SERVICE_NAME}", True, str(gateway_unit))
        except LetsInferError as error:
            record(f"unit-{GATEWAY_SERVICE_NAME}", False, str(error))
        try:
            verify_active_core_watchdog()
            watchdog_unit = pathlib.Path.home() / ".config/systemd/user" / SERVICE_NAME
            record(f"unit-{SERVICE_NAME}", True, str(watchdog_unit))
        except LetsInferError as error:
            record(f"unit-{SERVICE_NAME}", False, str(error))

    try:
        actual_image = verify_installed_runtime(
            manifest,
            model_cache=expanded_path(config["model_cache"]),
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
        if qualification_mode:
            binary, digest = verify_active_core_watchdog()
            watchdog_identity = binary.is_file() and SHA256_RE.fullmatch(digest) is not None
        else:
            binary, digest = verify_watchdog_runtime(
                expanded_path(config["watchdog_binary_path"]).parent,
                config["watchdog_source_sha256"],
            )
            watchdog_identity = (
                binary == expanded_path(config["watchdog_binary_path"])
                and digest == config["watchdog_binary_sha256"]
            )
        record(
            "watchdog-runtime-identity",
            watchdog_identity,
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
    node_enabled, node_active, node_memory_bytes = _service_state(NODE_SERVICE_NAME)
    record("node-service-enabled", node_enabled == "enabled", node_enabled)
    record("node-service-active", node_active == "active", node_active)
    record(
        "node-service-memory",
        node_memory_bytes is not None and node_memory_bytes < NODE_AGENT_MEMORY_LIMIT_BYTES,
        f"current={node_memory_bytes} limit<{NODE_AGENT_MEMORY_LIMIT_BYTES}",
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
    for name, passed, detail in _doctor_runtime_unit_checks(
        qualification_mode=qualification_mode,
        engine_enabled=engine_enabled,
        engine_active=engine_active,
        recovery_enabled=recovery_enabled,
        recovery_active=recovery_active,
    ):
        record(name, passed, detail)
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
        "runtime_mode": "qualification" if qualification_mode else "production",
        "release": manifest["release"],
        "engine": adapter.name,
        "checks": checks,
    }
    if arguments.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        presenter = _human_presenter()
        if presenter is not None:
            rendered = []
            for item in checks:
                state = (
                    "PASS"
                    if item["passed"]
                    else "FAIL"
                    if item["required"]
                    else "INFO"
                )
                rendered.append(
                    {
                        **item,
                        "result": state,
                        "_semantic": (
                            command_ui.Semantic.SUCCESS
                            if state == "PASS"
                            else command_ui.Semantic.ERROR
                            if state == "FAIL"
                            else command_ui.Semantic.INFO
                        ),
                    }
                )
            presenter.table(
                (
                    command_ui.TableColumn("result", "RESULT", min_width=6),
                    command_ui.TableColumn("name", "CHECK", min_width=12),
                    command_ui.TableColumn("detail", "DETAIL", min_width=18),
                ),
                rendered,
            )
            presenter.records(
                (
                    command_ui.RecordRow(
                        "Operational",
                        "Ready" if operational_ready else "Attention",
                        semantic=(
                            command_ui.Semantic.SUCCESS
                            if operational_ready
                            else command_ui.Semantic.ERROR
                        ),
                    ),
                    command_ui.RecordRow(
                        "Publication",
                        "Ready" if publication_ready else "Not ready",
                        semantic=(
                            command_ui.Semantic.SUCCESS
                            if publication_ready
                            else command_ui.Semantic.WARNING
                        ),
                    ),
                )
            )
        else:
            for item in checks:
                state = "PASS" if item["passed"] else ("FAIL" if item["required"] else "INFO")
                print(f"{state:4} {item['name']}: {item['detail']}")
            print(
                f"READY operational={str(operational_ready).lower()} "
                f"publication={str(publication_ready).lower()}"
            )
    return 0 if operational_ready else 1


def _uninstall_service_config(explicit: str | None) -> tuple[pathlib.Path | None, dict[str, Any] | None]:
    if explicit is not None:
        path = absolute_user_path(explicit)
        if not path.is_file() or path.is_symlink():
            raise LetsInferError(f"service configuration is unavailable: {path}")
        return path, read_service_config(path)
    candidates = (
        default_service_config_path(),
    )
    for path in candidates:
        if path.is_symlink():
            raise LetsInferError(f"service configuration cannot be a symlink: {path}")
        if path.is_file():
            return path, read_service_config(path)
    return None, None


def _installed_runtime_image_references() -> set[str]:
    objects = default_runtime_home() / ".objects"
    if not objects.exists():
        return set()
    if objects.is_symlink() or not objects.is_dir():
        raise LetsInferError(f"runtime object storage is unsafe: {objects}")
    references: set[str] = set()
    for descriptor_path in sorted(objects.glob(f"*/{RUNTIME_CONFIG}")):
        if descriptor_path.is_symlink() or not descriptor_path.is_file():
            continue
        try:
            runtime = json.loads(descriptor_path.read_text(encoding="utf-8"))
            manifest = runtime_execution_manifest(runtime, qualified=False)
        except (KeyError, OSError, UnicodeDecodeError, json.JSONDecodeError, LetsInferError):
            # Corrupt local metadata is deleted with the runtime object, but must
            # never be trusted to select a Docker image for removal.
            continue
        image = manifest["image"]
        references.update((image["reference"], image["immutable_id"]))
        if "base" in image:
            references.add(image["base"])
        references.add(manifest["model"]["acquisition_image"])
    return references


def _remove_managed_containers(
    runtime_images: Iterable[str] = (),
) -> tuple[int, int]:
    if shutil.which("docker") is None:
        return 0, 0
    listing = run(
        ["docker", "ps", "-aq", "--filter", f"label={MANAGED_LABEL}=true"],
        check=False,
    )
    if listing.returncode != 0:
        return 0, 0
    images = set(runtime_images)
    containers = 0
    for identifier in listing.stdout.split():
        inspection = container_inspect(identifier)
        if inspection is None:
            continue
        labels = inspection.get("Config", {}).get("Labels") or {}
        if labels.get(MANAGED_LABEL) != "true":
            raise LetsInferError(
                f"container {identifier} lost its Let's Infer ownership label"
            )
        image = inspection.get("Config", {}).get("Image")
        if isinstance(image, str) and image:
            images.add(image)
        run(["docker", "rm", "-f", identifier])
        containers += 1
    # Remove runtime references before immutable IDs and shared dependency
    # digests. Docker itself refuses removal while another container needs an
    # image, so uninstall cannot invalidate an unrelated running workload.
    ordered_images = sorted(images, key=lambda image: image.startswith("sha256:"))
    removed_images = sum(
        run(["docker", "image", "rm", image], check=False).returncode == 0
        for image in ordered_images
    )
    return containers, removed_images


def _remove_linux_services(config: dict[str, Any] | None) -> None:
    if config is not None:
        active = run(
            ["systemctl", "--user", "is-active", SERVICE_NAME], check=False
        )
        inspection = container_inspect(config["name"])
        if active.returncode == 0 and inspection is not None:
            disarm_before_planned_stop(config)
        if inspection is not None:
            _stop_managed_container(
                config["name"], expanded_path(config["engine_api_key_file"])
            )
    for name in (
        RECOVERY_TIMER_NAME,
        ENGINE_SERVICE_NAME,
        GATEWAY_SERVICE_NAME,
        NODE_SERVICE_NAME,
        SERVICE_NAME,
    ):
        run(["systemctl", "--user", "disable", "--now", name], check=False)
    unit_dir = pathlib.Path.home() / ".config/systemd/user"
    for name in (
        SERVICE_NAME,
        NODE_SERVICE_NAME,
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
    run(["systemctl", "--user", "daemon-reload"], check=False)
    timer_stamp = (
        pathlib.Path.home()
        / ".local/share/systemd/timers"
        / f"stamp-{RECOVERY_TIMER_NAME}"
    )
    if timer_stamp.is_symlink():
        raise LetsInferError(f"refusing to remove symlinked timer stamp: {timer_stamp}")
    timer_stamp.unlink(missing_ok=True)


def _remove_macos_services() -> None:
    for label in (macos_services.GATEWAY_LABEL, macos_services.NODE_LABEL):
        try:
            macos_services.remove_launch_agent(label)
        except macos_services.MacOSServiceError as error:
            raise LetsInferError(f"cannot remove macOS service: {error}") from error


def _remove_public_exposure() -> None:
    try:
        identity = read_site_identity()
        with SiteStore(identity=identity) as store:
            exposure = store.exposure()
    except SiteError:
        exposure = read_exposure_for_cleanup()
    if exposure is None or exposure["state"] != "enabled":
        return
    if exposure["provider"] != "tailscale-funnel":
        raise LetsInferError(
            f"cannot remove unsupported public exposure: {exposure['provider']}"
        )
    try:
        disable_tailscale(exposure["configuration_sha256"])
    except ExposureError as error:
        raise LetsInferError(
            "public inference exposure could not be disabled; uninstall aborted"
        ) from error


def _remove_managed_home(
    *,
    keep_models: bool,
    configured_model_cache: pathlib.Path | None,
) -> None:
    home = letsinfer_home_root()
    model_roots = {models_root()}
    if configured_model_cache is not None:
        model_roots.add(configured_model_cache)
    external = {*managed_roots(), *model_roots}
    for path in sorted(external, key=lambda item: len(item.parts), reverse=True):
        if path == home or path.is_relative_to(home):
            continue
        if keep_models and path in model_roots:
            continue
        _remove_user_tree(path, label="Let's Infer data")
    if not home.exists() and not home.is_symlink():
        return
    if home.is_symlink() or not home.is_dir():
        raise LetsInferError(f"refusing to remove unsafe LETSINFER_HOME: {home}")
    if not keep_models:
        _remove_user_tree(home, label="LETSINFER_HOME")
        return
    preserved = models_root()
    if not preserved.is_relative_to(home):
        _remove_user_tree(home, label="LETSINFER_HOME")
        return
    first = preserved.relative_to(home).parts[0]
    for child in home.iterdir():
        if child.name == first:
            continue
        if child.is_symlink() or child.is_file():
            child.unlink()
        else:
            _remove_user_tree(child, label="Let's Infer data")


def _remove_installed_core() -> bool:
    root = source_root().resolve(strict=True)
    if not (root / CORE_SOURCE_MANIFEST).is_file():
        return False
    helper = root / "bin/letsinfer-uninstall-core"
    if not helper.is_file() or helper.is_symlink():
        raise LetsInferError("installed core uninstaller is unavailable")
    launcher_directory = pathlib.Path(
        os.environ.get("LETSINFER_LAUNCHER_DIR", str(root / "bin"))
    )
    command = [
        str(helper),
        "--source",
        str(root),
        "--launcher-directory",
        str(launcher_directory),
        "--letsinfer-home",
        str(letsinfer_home_root()),
        "--quiet",
    ]
    if launcher_directory == pathlib.Path("/usr/local/bin"):
        command.insert(0, "sudo")
    run_passthrough(command)
    return True


def uninstall(arguments: argparse.Namespace) -> int:
    config_path, config = _uninstall_service_config(arguments.config)
    models = (
        expanded_path(config["model_cache"])
        if config is not None and isinstance(config.get("model_cache"), str)
        else None
    )
    description = (
        "Remove Let's Infer, its runtimes, credentials, caches, and benchmark data"
        + (", while keeping downloaded models?" if arguments.keep_models else ", including downloaded models?")
    )
    if not _confirmed(
        description,
        assume_yes=False,
        noninteractive_flag=None,
    ):
        presenter = _human_presenter()
        if presenter is not None:
            presenter.result(
                "Uninstall cancelled",
                semantic=command_ui.Semantic.INFO,
                detail="No managed data was removed",
            )
        else:
            print("Uninstall cancelled")
        arguments.suppress_completion = True
        return 0

    cleanup = ui.progress(
        "Stopping services and removing runtime data",
        stream=sys.stderr,
        enabled=_human_presenter() is not None,
    )
    with cleanup, ui.protect_stdout(cleanup):
        site_identity_valid = False
        if site_identity_path().is_file():
            try:
                read_site_identity()
            except SiteError:
                pass
            else:
                site_identity_valid = True
        runtime_images = _installed_runtime_image_references()
        try:
            active_benchmark = benchmark_jobs.active_state()
        except benchmark_jobs.BenchmarkJobError as error:
            raise LetsInferError(str(error)) from error
        if active_benchmark is not None:
            state = benchmark_jobs.request_stop()
            if not benchmark_jobs.wait_for_exit(
                state["pid"],
                timeout_seconds=_benchmark_stop_timeout_seconds(),
            ):
                raise LetsInferError("active benchmark did not stop; uninstall aborted")

        _remove_public_exposure()
        if site_identity_valid:
            _remove_all_engine_groups()
        elif has_active_engine_groups_for_cleanup():
            raise LetsInferError(
                "cannot safely uninstall while an unreadable node identity owns active "
                "engine groups; restore the node identity and stop those groups first"
            )
        _retire_qualification_candidate(remove_container=True)
        system = platform.system()
        if system == "Linux":
            _remove_linux_services(config)
        elif system == "Darwin":
            _remove_macos_services()
        else:
            raise LetsInferError(f"unsupported uninstall platform: {system}")
        containers, images = _remove_managed_containers(runtime_images)

    def finalize() -> int:
        removal = ui.progress(
            "Removing the core and managed data",
            stream=sys.stderr,
            enabled=_human_presenter() is not None,
        )
        with removal, ui.protect_stdout(removal):
            core_removed = _remove_installed_core()
            _remove_managed_home(
                keep_models=arguments.keep_models,
                configured_model_cache=models,
            )
        presenter = _human_presenter()
        if presenter is not None:
            presenter.records(
                (
                    command_ui.RecordRow(
                        "Let's Infer",
                        "Removed",
                        semantic=command_ui.Semantic.SUCCESS,
                    ),
                    command_ui.RecordRow(
                        "Core", "Removed" if core_removed else "Not installed"
                    ),
                    command_ui.RecordRow("Containers", containers),
                    command_ui.RecordRow("Images", images),
                    command_ui.RecordRow(
                        "Models",
                        "Preserved" if arguments.keep_models else "Removed",
                    ),
                )
            )
        else:
            print(
                "UNINSTALLED Let's Infer "
                f"core_removed={str(core_removed).lower()} "
                f"containers={containers} images={images} "
                f"models={'preserved' if arguments.keep_models else 'removed'}"
            )
        return 0

    arguments.after_audit = finalize
    return 0


def pack_runtime(arguments: argparse.Namespace) -> int:
    try:
        pack = build_archive(
            pathlib.Path(arguments.source),
            pathlib.Path(arguments.output),
        )
    except RuntimePackError as error:
        raise LetsInferError(str(error)) from error
    artifact = pathlib.Path(arguments.output).resolve()
    presenter = _human_presenter()
    if presenter is not None:
        presenter.records(
            (
                command_ui.RecordRow("Runtime", pack.runtime["id"]),
                command_ui.RecordRow("Version", pack.runtime["version"]),
            )
        )
        presenter.verbatim(f"sha256:{pack.digest}", label="Digest", copyable=True)
        presenter.verbatim(artifact, label="Artifact", copyable=True)
    else:
        print(
            f"PACKED {pack.runtime['id']} version={pack.runtime['version']} "
            f"digest=sha256:{pack.digest} artifact={artifact}"
        )
    return 0


def list_runtimes(_: argparse.Namespace) -> int:
    try:
        receipts = selections()
    except RuntimePackError as error:
        raise LetsInferError(str(error)) from error
    ordered = sorted(receipts, key=lambda item: item["logical_model"])
    presenter = _human_presenter()
    if presenter is not None:
        presenter.table(
            (
                command_ui.TableColumn("logical_model", "MODEL", min_width=8),
                command_ui.TableColumn("candidate_id", "RUNTIME", min_width=8),
                command_ui.TableColumn("engine", "ENGINE", min_width=6),
                command_ui.TableColumn("target", "TARGET", min_width=6),
                command_ui.TableColumn("version", "VERSION", min_width=7),
            ),
            ordered,
            empty_message="No runtimes are installed",
        )
    else:
        for receipt in ordered:
            print(
                f"{receipt['logical_model']}\truntime={receipt['candidate_id']}\tengine={receipt['engine']}\ttarget={receipt['target']}\t"
                f"version={receipt['version']}\tdigest=sha256:{receipt['digest']}\t"
                f"policy={receipt['policy']}"
            )
    return 0


def list_available_runtimes(arguments: argparse.Namespace) -> int:
    """List qualified catalog releases that can run on this hardware."""

    try:
        snapshot = CatalogManager(arguments.catalog).load(
            refresh=arguments.refresh,
            allow_stale=not arguments.refresh,
        )
        receipts = selections()
        catalog = snapshot.document
        if arguments.all_targets:
            target_ids = sorted(catalog["targets"])
        else:
            target_ids = compatible_catalog_targets(
                catalog, host_device_fingerprint()
            )
    except (CatalogError, RuntimePackError) as error:
        raise LetsInferError(str(error)) from error

    installed = {
        (
            receipt["logical_model"],
            receipt["target"],
            receipt["candidate_id"],
            receipt["version"],
        )
        for receipt in receipts
    }
    rows: list[dict[str, Any]] = []
    model_filter = arguments.model
    if model_filter is not None and model_filter not in catalog["models"]:
        raise LetsInferError(f"model is not present in runtime catalog: {model_filter}")

    for model, model_record in sorted(catalog["models"].items()):
        if model_filter is not None and model != model_filter:
            continue
        for target, target_record in sorted(model_record["targets"].items()):
            if target not in target_ids:
                continue
            recommendation = target_record["recommended"]
            for candidate, candidate_record in sorted(
                target_record["candidates"].items()
            ):
                available = [
                    (version, release)
                    for version, release in candidate_record["releases"].items()
                ]
                available.sort(
                    key=functools.cmp_to_key(
                        lambda left, right: compare_versions(left[0], right[0])
                    ),
                    reverse=True,
                )
                if not arguments.versions:
                    available = available[:1]
                for version, release in available:
                    benchmark = release["benchmark"]
                    recommended = recommendation == {
                        "candidate": candidate,
                        "version": version,
                    }
                    rows.append(
                        {
                            "model": model,
                            "runtime": candidate,
                            "version": version,
                            "authors": release["authors"],
                            "license": release["license"],
                            "engine": release["engine"],
                            "target": target,
                            "model_uri": release["model_uri"],
                            "benchmark_id": (
                                benchmark["id"] if benchmark is not None else None
                            ),
                            "benchmark_score": (
                                benchmark["score"] if benchmark is not None else None
                            ),
                            "verification": release["verification"],
                            "provenance": release["provenance"],
                            "recommended": recommended,
                            "installed": (model, target, candidate, version)
                            in installed,
                        }
                    )

    rows.sort(
        key=lambda item: (
            item["model"],
            item["target"],
            not item["recommended"],
            item["runtime"],
        )
    )
    if arguments.json:
        print(
            json.dumps(
                {
                    "catalog": {
                        "source": snapshot.source,
                        "sha256": snapshot.catalog_sha256,
                        "stale": snapshot.stale,
                        "age_seconds": snapshot.age_seconds,
                    },
                    "compatible_targets": target_ids,
                    "runtimes": rows,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    presenter = _human_presenter()
    if not rows:
        suffix = "" if arguments.all_targets else " for this hardware"
        if presenter is not None:
            presenter.empty(
                "No qualified runtimes are available",
                detail=suffix.removeprefix(" for ") or None,
            )
        else:
            print(f"No qualified runtimes are available{suffix}.")
        return 0

    headings = (
        "MODEL", "AUTHOR", "VERSION", "ENGINE", "TARGET", "VERIFIED", "STATUS"
    )
    rendered = [
        (
            row["model"],
            ", ".join(author["github_login"] for author in row["authors"]),
            row["version"],
            row["engine"],
            row["target"],
            (
                str(len(row["verification"]["verifiers"]))
                if "consensus_path" in row["verification"]
                else "legacy"
            ),
            " · ".join(
                label
                for enabled, label in (
                    (row["recommended"], "recommended"),
                    (row["installed"], "installed"),
                    (row["benchmark_score"] is None, "unscored"),
                )
                if enabled
            )
            or "qualified",
        )
        for row in rows
    ]
    if presenter is not None:
        if presenter.terminal.width < 100:
            for index, row in enumerate(rendered):
                model, authors, version, engine, target, verified, status = row
                presenter.result(
                    f"{model}  {version}",
                    semantic=(
                        command_ui.Semantic.SUCCESS
                        if "installed" in status
                        else command_ui.Semantic.INFO
                    ),
                    detail=(
                        f"{engine} · {target} · {status}\n"
                        f"By {authors} · {verified} verification"
                    ),
                )
                if index + 1 < len(rendered):
                    presenter.wrapped("")
        else:
            presenter.table(
                tuple(
                    command_ui.TableColumn(
                        str(index), heading, min_width=5 if index else 8
                    )
                    for index, heading in enumerate(headings)
                ),
                rendered,
                empty_message="No qualified runtimes are available",
            )
        if snapshot.stale:
            presenter.result(
                "Using the last verified catalog",
                semantic=command_ui.Semantic.WARNING,
                detail="refresh is temporarily unavailable",
            )
    else:
        widths = [
            max(len(headings[index]), *(len(row[index]) for row in rendered))
            for index in range(len(headings))
        ]
        print(
            "  ".join(
                value.ljust(widths[index]) for index, value in enumerate(headings)
            )
        )
        for row in rendered:
            print(
                "  ".join(
                    value.ljust(widths[index]) for index, value in enumerate(row)
                )
            )
        if snapshot.stale:
            print("\nUsing the last verified catalog; refresh is temporarily unavailable.")
    return 0


def hardware(arguments: argparse.Namespace) -> int:
    fingerprint = host_device_fingerprint()
    location = resolved_catalog_location(getattr(arguments, "catalog", None))
    matches: list[str] = []
    if location is not None:
        try:
            matches = compatible_catalog_targets(
                CatalogManager(location).load().document, fingerprint
            )
        except (CatalogError, RuntimePackError) as error:
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
        presenter = _human_presenter()
        if presenter is not None:
            target_semantic = (
                command_ui.Semantic.SUCCESS
                if selected_target is not None
                else command_ui.Semantic.WARNING
            )
            presenter.records(
                (
                    command_ui.RecordRow("Platform", fingerprint["platform"]),
                    command_ui.RecordRow(
                        "Accelerator",
                        f"{accelerator['vendor']}/{accelerator['architecture']}",
                        f"{accelerator['count']} device(s) · {accelerator['partitioning']}",
                    ),
                    command_ui.RecordRow(
                        "Memory",
                        f"{memory['total_gib']} GiB",
                        memory["topology"],
                    ),
                    command_ui.RecordRow(
                        "Target", target_text, semantic=target_semantic
                    ),
                )
            )
        else:
            print(
                f"{fingerprint['platform']}\t{accelerator['vendor']}/"
                f"{accelerator['architecture']}\tdevices={accelerator['count']}\t"
                f"partitioning={accelerator['partitioning']}\t"
                f"memory={memory['topology']}/{memory['total_gib']}GiB\t"
                f"target={target_text}"
            )
    return 0


def inspect_runtime(arguments: argparse.Namespace) -> int:
    manifest_path, manifest = resolve_model(
        arguments.runtime, target=getattr(arguments, "target", None)
    )
    receipt = runtime_receipt_for_manifest(manifest_path)
    launch = launch_for(manifest, manifest["serving"], arguments.port)
    publication: dict[str, Any] | None = None
    publication_error: str | None = None
    if receipt is not None:
        try:
            catalog = CatalogManager(arguments.catalog).load(
                refresh=False, allow_stale=True
            ).document
            publication = (
                catalog.get("models", {})
                .get(receipt["logical_model"], {})
                .get("targets", {})
                .get(receipt["target"], {})
                .get("candidates", {})
                .get(receipt["candidate_id"], {})
                .get("releases", {})
                .get(receipt["version"])
            )
        except CatalogError as error:
            publication_error = str(error)
    if arguments.json:
        print(
            json.dumps(
                {
                    "runtime": receipt,
                    "model": manifest["model"],
                    "engine": adapter_for(manifest).name,
                    "target": target_contract(manifest),
                    "status": manifest["status"],
                    "serving": manifest["serving"],
                    "command": list(launch.command),
                    "publication": publication,
                    "publication_error": publication_error,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if arguments.command:
        print(shell_command(launch))
    if not arguments.command:
        runtime_name = receipt["candidate_id"] if receipt else manifest["model"]["alias"]
        digest = f"sha256:{receipt['digest']}" if receipt else "unpacked-source"
        version = receipt["version"] if receipt else manifest["release"].rsplit("@", 1)[-1]
        presenter = _human_presenter()
        if presenter is not None:
            presenter.records(
                (
                    command_ui.RecordRow("Runtime", runtime_name),
                    command_ui.RecordRow("Engine", adapter_for(manifest).name),
                    command_ui.RecordRow("Version", version),
                    command_ui.RecordRow("Status", manifest["status"]),
                ),
                value_width=20,
            )
            presenter.verbatim(digest, label="Digest", copyable=True)
        else:
            print(
                f"{runtime_name}\tengine={adapter_for(manifest).name}\t"
                f"version={version}\tstatus={manifest['status']}\tdigest={digest}"
            )
        if publication is not None:
            verification = publication["verification"]
            benchmark = publication["benchmark"]
            provenance = publication["provenance"]
            verifiers = ", ".join(
                f"@{item['github_login']}" for item in verification["verifiers"]
            ) or (
                "maintainer override"
                if verification["method"] == "allowlisted-maintainer-bypass-v1"
                else "maintainer migration"
            )
            if presenter is not None:
                presenter.records(
                    (
                        command_ui.RecordRow(
                            "Verification", verification["method"], verifiers
                        ),
                        command_ui.RecordRow(
                            "Score",
                            benchmark["score"] if benchmark is not None else "unscored",
                        ),
                    ),
                    value_width=24,
                )
            else:
                print(
                    f"verification={verification['method']}\t"
                    f"verifiers={verifiers}\t"
                    f"score={benchmark['score'] if benchmark is not None else 'unscored'}"
                )
            if "consensus_path" in verification:
                if presenter is not None:
                    presenter.records(
                        (
                            command_ui.RecordRow(
                                "Consensus", verification["consensus_path"]
                            ),
                        ),
                        value_width=28,
                    )
                    presenter.verbatim(
                        provenance["execution_sha256"],
                        label="Subject",
                        copyable=True,
                    )
                    presenter.verbatim(
                        verification["consensus_sha256"],
                        label="Consensus SHA",
                        copyable=True,
                    )
                else:
                    print(
                        f"subject={provenance['execution_sha256']}\t"
                        f"consensus={verification['consensus_path']}\t"
                        f"consensus_sha256={verification['consensus_sha256']}"
                    )
        elif publication_error is not None:
            if presenter is not None:
                presenter.result(
                    "Verification unavailable",
                    semantic=command_ui.Semantic.WARNING,
                    detail=publication_error,
                )
            else:
                print(f"verification=unavailable\treason={publication_error}")
    return 0


def _matching_runtime_receipt(
    name: str, target: str | None = None
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
                and name in {receipt["candidate_id"], receipt["logical_model"], active.get("model")}
                and (target is None or receipt["target"] == target)
            ):
                return receipt
    matches = [
        receipt
        for receipt in available
        if name in {receipt["candidate_id"], receipt["logical_model"]}
        and (target is None or receipt["target"] == target)
    ]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        choices = ", ".join(
            sorted(f"{receipt['engine']}/{receipt['target']}" for receipt in matches)
        )
        raise LetsInferError(
            f"runtime is ambiguous across candidates ({choices}); specify the exact candidate ID"
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
        runtime=None,
        target=None,
        catalog=None,
        runtime_policy=policy,
        expected_target_contract_sha256=target_contract_sha256_value,
        port=config["gateway_port"] if config else 8000,
        engine_port=config["engine_port"] if config else 18000,
        gateway_listen=config["gateway_listen"] if config else "0.0.0.0",
        gateway_max_connections=(config["gateway_max_connections"] if config else 128),
        gateway_queue_timeout=(config["gateway_queue_timeout_seconds"] if config else 0),
        name=config["name"] if config else None,
        model_cache=config["model_cache"] if config else None,
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


def _group_upgrade_placement(
    identity: Any,
    graph: TopologyGraph,
    *,
    member_ids: Sequence[str],
    target: Mapping[str, Any],
) -> tuple[TopologyGraph, Placement]:
    """Resolve an updated target only on the group's existing machines."""
    wanted = tuple(member_ids)
    if not wanted or len(wanted) != len(set(wanted)) or set(wanted) - set(graph.members):
        raise LetsInferError("engine-group update has invalid node identities")
    try:
        constrained = TopologyGraph(
            [graph.members[member_id] for member_id in wanted],
            allocated_devices={
                member_id: tuple(graph.allocated_devices.get(member_id, ()))
                for member_id in wanted
            },
        )
        placement = constrained.resolve(
            target,
            coordinator_id=identity.coordinator_id,
        )
    except TopologyError as error:
        raise LetsInferError(
            "updated runtime no longer fits the engine group's existing nodes: "
            f"{error}"
        ) from error
    if set(placement.member_ids) != set(wanted):
        raise LetsInferError(
            "updated runtime changes the engine-group node count; install it as a new group"
        )
    return constrained, placement


def _group_member_ids(group: Mapping[str, Any]) -> tuple[str, ...]:
    resources = group.get("plan", {}).get("resources")
    if (
        not isinstance(resources, list)
        or not resources
        or any(not isinstance(item, Mapping) for item in resources)
    ):
        raise LetsInferError("engine group has an incomplete immutable node plan")
    values = tuple(str(item.get("node_id", "")) for item in resources)
    if any(not re.fullmatch(r"[0-9a-f]{32}", value) for value in values):
        raise LetsInferError("engine group has an invalid immutable node plan")
    return values


def _cleanup_failed_group_release(
    source: str,
    member_ids: Sequence[str],
) -> None:
    """Remove a partially installed replacement before restoring its predecessor."""
    wanted = set(member_ids)
    with _site_store() as store:
        candidates = [
            row["group_id"]
            for row in store.engine_groups()
            if row["source"] == source
            and row["state"] != "removed"
            and row["desired_state"] != "removed"
            and set(_group_member_ids(row)) == wanted
        ]
    if candidates:
        _remove_engine_groups_by_id(candidates)


def _stop_engine_group_by_id(group_id: str) -> None:
    """Stop one exact group without affecting its replica siblings."""
    with _site_store() as store:
        row = next(
            (item for item in store.engine_groups() if item["group_id"] == group_id),
            None,
        )
        if row is None or row["state"] == "removed":
            raise LetsInferError("engine group disappeared before it could be stopped")
        if row["state"] == "stopped" and row["desired_state"] == "stopped":
            return
        orchestrator, _manifest = _restore_engine_group_orchestrator(store, row)
        stopped = orchestrator.stop()
        _sync_group_placement(store, stopped)


def _active_group_id_for_release(
    source: str,
    member_ids: Sequence[str],
) -> str:
    wanted = set(member_ids)
    with _site_store() as store:
        matches = [
            row
            for row in store.engine_groups()
            if row["source"] == source
            and row["state"] != "removed"
            and row["desired_state"] != "removed"
            and set(_group_member_ids(row)) == wanted
        ]
    if len(matches) != 1:
        raise LetsInferError("restored engine-group identity is ambiguous")
    return str(matches[0]["group_id"])


def _install_retained_group_release(
    arguments: argparse.Namespace,
    *,
    release: Mapping[str, Any],
    member_ids: Sequence[str],
) -> str:
    """Recreate one exact historical group on the same physical nodes."""
    try:
        manifest_path, manifest, control_root, receipt = prepare_runtime_install(
            str(release["source"]),
            policy=f"runtime:{release['candidate_id']}",
            qualified=True,
            requested_runtime=str(release["candidate_id"]),
            requested_target=str(release["target_id"]),
            expected_version=str(release["version"]),
            expected_target_contract_sha256=str(
                release["target_contract_sha256"]
            ),
        )
        runtime = verify_descriptor(pathlib.Path(receipt["object_root"]))
        if (
            runtime.digest != release["runtime_digest"]
            or sha256_file(manifest_path) != release["manifest_sha256"]
        ):
            raise LetsInferError("retained engine-group release bytes changed")
        identity, graph = _fresh_site_topology()
        constrained, placement = _group_upgrade_placement(
            identity,
            graph,
            member_ids=member_ids,
            target=target_contract(manifest),
        )
        install_engine_group(
            arguments,
            source=str(release["source"]),
            manifest_path=manifest_path,
            manifest=manifest,
            control_root=control_root,
            receipt=receipt,
            release_identity=dict(release),
            resolved_topology=(identity, constrained, placement),
        )
    except (KeyError, RuntimePackError) as error:
        raise LetsInferError(f"retained engine-group release is invalid: {error}") from error
    return _active_group_id_for_release(str(release["source"]), member_ids)


def upgrade_runtime(arguments: argparse.Namespace) -> int:
    """Roll each replica group to its candidate's latest signed release."""
    model = arguments.runtime
    if arguments.to:
        raise LetsInferError(
            "qualified engine groups update only from the signed catalog; --to is unsupported"
        )
    location = resolved_catalog_location(arguments.catalog)
    if location is None:
        raise LetsInferError("runtime upgrade requires --catalog or LETSINFER_CATALOG")
    try:
        catalog = CatalogManager(location).load().document
    except (CatalogError, RuntimePackError) as error:
        raise LetsInferError(str(error)) from error
    with _site_store() as store:
        placements = {row["placement_id"]: row for row in store.placements()}
        groups = sorted(
            (
                row
                for row in store.engine_groups()
                if row["state"] != "removed"
                and row["desired_state"] != "removed"
                and row["placement_id"] in placements
                and placements[row["placement_id"]]["model"] == model
            ),
            key=lambda row: row["group_id"],
        )
    if not groups:
        raise LetsInferError(f"no installed engine group serves model {model!r}")

    presenter = _human_presenter()
    planned: list[dict[str, Any]] = []
    plan_rows: list[dict[str, Any]] = []
    for group in groups:
        release = group["plan"].get("release")
        if not isinstance(release, Mapping):
            raise LetsInferError(
                f"engine group {group['group_id']} has no immutable release identity"
            )
        candidate_id = str(release.get("candidate_id", ""))
        target_id = str(release.get("target_id", ""))
        try:
            (
                selected_target,
                target_sha256,
                selected_candidate,
                version,
                source,
            ) = catalog_release(
                dict(catalog), model, candidate_id, target_id, device=None
            )
            record = catalog_release_record(
                dict(catalog), model, selected_target, selected_candidate, version
            )
            target = catalog_target_contract(dict(catalog), selected_target)
        except RuntimePackError as error:
            raise LetsInferError(str(error)) from error
        if (
            selected_target != target_id
            or selected_candidate != candidate_id
            or target_sha256 != release.get("target_contract_sha256")
        ):
            raise LetsInferError(
                f"catalog changed immutable target identity for group {group['group_id']}"
            )
        planned.append(
            {
                "group": group,
                "current": dict(release),
                "target": target,
                "target_sha256": target_sha256,
                "record": record,
                "candidate_id": candidate_id,
                "version": version,
                "source": source,
            }
        )
        state = "current" if source == release.get("source") else "update"
        if presenter is not None:
            plan_rows.append(
                {
                    "group": group["group_id"],
                    "state": state.title(),
                    "runtime": candidate_id,
                    "version": (
                        f"{release.get('version')} "
                        f"{'→' if presenter.terminal.unicode else '->'} {version}"
                    ),
                    "_semantic": (
                        command_ui.Semantic.INFO
                        if state == "current"
                        else command_ui.Semantic.WARNING
                    ),
                }
            )
        else:
            print(
                f"{state.upper()} group={group['group_id']} candidate={candidate_id} "
                f"{release.get('version')} -> {version}"
            )
    if presenter is not None:
        presenter.table(
            (
                command_ui.TableColumn("group", "GROUP", min_width=8),
                command_ui.TableColumn("state", "STATE", min_width=7),
                command_ui.TableColumn("runtime", "RUNTIME", min_width=8),
                command_ui.TableColumn("version", "VERSION", min_width=9),
            ),
            plan_rows,
        )
    changes = [item for item in planned if item["source"] != item["current"]["source"]]
    if not changes:
        if presenter is not None:
            presenter.result(
                "Runtime is current",
                semantic=command_ui.Semantic.SUCCESS,
                detail=f"{model} · {len(groups)} group(s)",
            )
        else:
            print(f"CURRENT model={model} groups={len(groups)}")
        return 0
    if arguments.dry_run:
        if presenter is not None:
            presenter.result(
                "Dry run complete",
                semantic=command_ui.Semantic.INFO,
                detail=f"{model} · {len(changes)} group(s) would be upgraded",
            )
        else:
            print(f"DRY RUN model={model} groups={len(changes)}")
        return 0

    completed = 0
    for item in changes:
        old_group = item["group"]
        old_release = item["current"]
        member_ids = tuple(
            resource["node_id"] for resource in old_group["plan"]["resources"]
        )
        resolving = _command_activity(
            arguments,
            f"Preparing upgrade {completed + 1} of {len(changes)}",
            action_id="upgrade",
        )
        with resolving, ui.protect_stdout(resolving):
            manifest_path, manifest, control_root, receipt = prepare_runtime_install(
                item["source"],
                policy=f"runtime:{item['candidate_id']}",
                qualified=True,
                requested_runtime=item["candidate_id"],
                requested_target=old_release["target_id"],
                expected_version=item["version"],
                expected_target_contract_sha256=item["target_sha256"],
            )
        runtime = verify_descriptor(pathlib.Path(receipt["object_root"]))
        release_identity = _group_release_identity(
            catalog_release_value=item["record"],
            candidate_id=item["candidate_id"],
            version=item["version"],
            source=item["source"],
            target_id=old_release["target_id"],
            target_sha256=item["target_sha256"],
            runtime=runtime,
            manifest_sha256=sha256_file(manifest_path),
        )
        _remove_engine_groups_by_id([old_group["group_id"]])
        try:
            identity, graph = _fresh_site_topology()
            constrained, placement = _group_upgrade_placement(
                identity,
                graph,
                member_ids=member_ids,
                target=item["target"],
            )
            applying = _command_activity(
                arguments,
                f"Applying upgrade {completed + 1} of {len(changes)}",
                action_id="upgrade",
            )
            with applying, ui.protect_stdout(applying):
                install_engine_group(
                    arguments,
                    source=item["source"],
                    manifest_path=manifest_path,
                    manifest=manifest,
                    control_root=control_root,
                    receipt=receipt,
                    release_identity=release_identity,
                    resolved_topology=(identity, constrained, placement),
                )
            updated_group_id = _active_group_id_for_release(
                item["source"], member_ids
            )
            if old_group["desired_state"] == "stopped":
                _stop_engine_group_by_id(updated_group_id)
        except BaseException as update_error:
            try:
                _cleanup_failed_group_release(item["source"], member_ids)
                restored_group_id = _install_retained_group_release(
                    arguments,
                    release=old_release,
                    member_ids=member_ids,
                )
                if old_group["desired_state"] == "stopped":
                    _stop_engine_group_by_id(restored_group_id)
            except BaseException as rollback_error:
                raise LetsInferError(
                    f"group {old_group['group_id']} update failed and rollback failed: "
                    f"{type(rollback_error).__name__}"
                ) from update_error
            raise LetsInferError(
                f"group {old_group['group_id']} update failed; previous release restored"
            ) from update_error
        completed += 1
        if presenter is not None:
            presenter.result(
                f"Upgraded group {completed} of {len(changes)}",
                semantic=command_ui.Semantic.SUCCESS,
                detail=f"{item['candidate_id']} · {item['version']}",
            )
        else:
            print(
                f"UPDATED {completed}/{len(changes)} candidate={item['candidate_id']} "
                f"version={item['version']}"
            )
    if presenter is not None:
        presenter.records(
            (
                command_ui.RecordRow(
                    "Runtime", model, semantic=command_ui.Semantic.SUCCESS
                ),
                command_ui.RecordRow("Groups", completed, "Upgraded"),
            )
        )
    else:
        print(f"UPDATED model={model} groups={completed}")
    return 0


def rollback_runtime(arguments: argparse.Namespace) -> int:
    """Roll every current replica back to its most recently removed release."""
    model = arguments.runtime
    with _site_store() as store:
        placements = {row["placement_id"]: row for row in store.placements()}
        all_groups = store.engine_groups()
    current = [
        row
        for row in all_groups
        if row["state"] != "removed"
        and row["desired_state"] != "removed"
        and row["placement_id"] in placements
        and placements[row["placement_id"]]["model"] == model
        and (
            getattr(arguments, "target", None) is None
            or placements[row["placement_id"]]["target"] == arguments.target
        )
    ]
    if not current:
        raise LetsInferError(f"no installed engine group serves model {model!r}")
    presenter = _human_presenter()
    planned: list[tuple[dict[str, Any], dict[str, Any]]] = []
    plan_rows: list[dict[str, Any]] = []
    for group in sorted(current, key=lambda row: row["group_id"]):
        release = group["plan"].get("release")
        if not isinstance(release, Mapping):
            raise LetsInferError("current engine group has no immutable release")
        member_ids = set(_group_member_ids(group))
        candidates = [
            row
            for row in all_groups
            if row["state"] == "removed"
            and row["desired_state"] == "removed"
            and row["source"] != group["source"]
            and set(_group_member_ids(row)) == member_ids
            and isinstance(row["plan"].get("release"), Mapping)
            and row["plan"]["release"].get("candidate_id")
            == release.get("candidate_id")
            and row["plan"]["release"].get("target_id")
            == release.get("target_id")
        ]
        if not candidates:
            raise LetsInferError(
                f"engine group {group['group_id']} has no retained previous release"
            )
        previous = max(
            candidates,
            key=lambda row: (int(row["updated_at_unix"]), str(row["group_id"])),
        )
        planned.append((group, previous))
        old = previous["plan"]["release"]
        if presenter is not None:
            plan_rows.append(
                {
                    "group": group["group_id"],
                    "version": (
                        f"{release['version']} "
                        f"{'→' if presenter.terminal.unicode else '->'} "
                        f"{old['version']}"
                    ),
                    "nodes": len(member_ids),
                    "_semantic": command_ui.Semantic.WARNING,
                }
            )
        else:
            print(
                f"ROLLBACK group={group['group_id']} {release['version']} -> "
                f"{old['version']} nodes={len(member_ids)}"
            )
    if presenter is not None:
        presenter.table(
            (
                command_ui.TableColumn("group", "GROUP", min_width=8),
                command_ui.TableColumn("version", "VERSION", min_width=9),
                command_ui.TableColumn(
                    "nodes", "NODES", min_width=5, align="right"
                ),
            ),
            plan_rows,
        )
    if arguments.dry_run:
        if presenter is not None:
            presenter.result(
                "Dry run complete",
                semantic=command_ui.Semantic.INFO,
                detail=f"{model} · {len(planned)} group(s) would be rolled back",
            )
        return 0
    completed = 0
    for group, previous in planned:
        current_release = dict(group["plan"]["release"])
        previous_release = dict(previous["plan"]["release"])
        member_ids = _group_member_ids(group)
        _remove_engine_groups_by_id([group["group_id"]])
        try:
            applying = _command_activity(
                arguments,
                f"Rolling back group {completed + 1} of {len(planned)}",
                action_id="rollback",
            )
            with applying, ui.protect_stdout(applying):
                restored_group_id = _install_retained_group_release(
                    arguments,
                    release=previous_release,
                    member_ids=member_ids,
                )
            if group["desired_state"] == "stopped":
                _stop_engine_group_by_id(restored_group_id)
        except BaseException as rollback_error:
            try:
                _cleanup_failed_group_release(previous_release["source"], member_ids)
                current_group_id = _install_retained_group_release(
                    arguments,
                    release=current_release,
                    member_ids=member_ids,
                )
                if group["desired_state"] == "stopped":
                    _stop_engine_group_by_id(current_group_id)
            except BaseException as restore_error:
                raise LetsInferError(
                    f"group {group['group_id']} rollback failed and current release "
                    f"could not be restored: {type(restore_error).__name__}"
                ) from rollback_error
            raise LetsInferError(
                f"group {group['group_id']} rollback failed; current release restored"
            ) from rollback_error
        completed += 1
        if presenter is not None:
            presenter.result(
                f"Rolled back group {completed} of {len(planned)}",
                semantic=command_ui.Semantic.SUCCESS,
                detail=str(previous_release["version"]),
            )
    if presenter is not None:
        presenter.records(
            (
                command_ui.RecordRow(
                    "Runtime", model, semantic=command_ui.Semantic.SUCCESS
                ),
                command_ui.RecordRow("Groups", completed, "Rolled back"),
            )
        )
    else:
        print(f"ROLLED BACK model={model} groups={completed}")
    return 0


def verify(arguments: argparse.Namespace) -> int:
    manifest_path, manifest = resolve_model(
        arguments.model, target=getattr(arguments, "target", None)
    )
    verify_runtime_sources(manifest, runtime_source_root(manifest_path))
    if not arguments.source_only:
        model_cache = requested_model_cache(arguments.model_cache)
        verify_installed_runtime(manifest, model_cache=model_cache)
    adapter = adapter_for(manifest)
    serving = manifest["serving"]
    state = "qualified" if serving["qualified"] else "blocked"
    presenter = _human_presenter()
    if presenter is not None:
        presenter.records(
            (
                command_ui.RecordRow("Release", manifest["release"]),
                command_ui.RecordRow("Status", manifest["status"]),
                command_ui.RecordRow("Engine", adapter.name, adapter.model_format),
                command_ui.RecordRow(
                    "Serving",
                    state.title(),
                    (
                        f"{serving['max_connections']} connections · "
                        f"{serving['max_active_requests']} active · "
                        f"{serving['max_context_tokens']} context"
                    ),
                    (
                        command_ui.Semantic.SUCCESS
                        if serving["qualified"]
                        else command_ui.Semantic.WARNING
                    ),
                ),
            )
        )
    else:
        print(
            f"VERIFIED {manifest['release']} ({manifest['status']}) "
            f"engine={adapter.name} format={adapter.model_format}"
        )
        print(
            f"  serving: {state}, connections<={serving['max_connections']}, "
            f"active<={serving['max_active_requests']}, "
            f"context<={serving['max_context_tokens']}"
        )
    return 0


def acquire(arguments: argparse.Namespace) -> int:
    manifest_path, manifest = resolve_model(
        arguments.model, target=getattr(arguments, "target", None)
    )
    verify_runtime_sources(manifest, runtime_source_root(manifest_path))
    model_cache = requested_model_cache(arguments.model_cache)
    try:
        snapshot = verify_model_snapshot(manifest, model_cache)
        existing = True
    except LetsInferError:
        snapshot = acquire_model_snapshot(manifest, model_cache)
        existing = False
    manifest_digest = sha256_file(manifest_path)
    presenter = _human_presenter()
    if presenter is not None:
        presenter.records(
            (
                command_ui.RecordRow("Release", manifest["release"]),
                command_ui.RecordRow("Engine", adapter_for(manifest).name),
                command_ui.RecordRow(
                    "Snapshot", "Already present" if existing else "Downloaded"
                ),
            )
        )
        presenter.verbatim(snapshot, label="Model snapshot", copyable=True)
        presenter.verbatim(
            manifest_digest,
            label="Manifest SHA-256",
            copyable=True,
        )
    else:
        print(
            f"ACQUIRED {manifest['release']} engine={adapter_for(manifest).name} "
            f"existing={str(existing).lower()} snapshot={snapshot} "
            f"manifest_sha256={manifest_digest}"
        )
    return 0


class _BenchmarkCancelled(Exception):
    """An explicit benchmark stop requested graceful worker cleanup."""


def _benchmark_presenter() -> command_ui.CommandUI | None:
    """Open one non-dashboard benchmark surface with cached update context."""

    presenter = _human_presenter()
    if presenter is not None:
        presenter.header("Benchmark")
        ui.update_notice(_update_manager().cached().available)
    return presenter


def _duration(seconds: float) -> str:
    value = max(0, int(seconds))
    hours, remainder = divmod(value, 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes:02d}m {seconds:02d}s"
    if minutes:
        return f"{minutes}m {seconds:02d}s"
    return f"{seconds}s"


def _live_number(value: object) -> int | float | None:
    if (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and float(value) >= 0
    ):
        return value
    return None


def _engine_preparation_snapshot(
    config: Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    """Read optional authenticated Engine preparation progress without failing a job."""

    if not isinstance(config, Mapping):
        return None
    try:
        port = int(config["engine_port"])
        certificate = expanded_path(str(config["tls_cert_file"]))
        key_file = expanded_path(str(config["engine_api_key_file"]))
        request = urllib.request.Request(
            f"https://127.0.0.1:{port}{ENGINE_PROGRESS_PATH}",
            headers={"Authorization": f"Bearer {read_api_key(key_file)}"},
        )
        with urllib.request.urlopen(
            request,
            timeout=0.5,
            context=_tls_context(certificate),
        ) as response:
            body = response.read(4097)
        if response.status != 200 or len(body) > 4096:
            return None
        value = json.loads(body)
    except (
        KeyError,
        OSError,
        ValueError,
        UnicodeError,
        urllib.error.URLError,
        json.JSONDecodeError,
    ):
        return None
    now_ms = int(time.time() * 1000)
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "state", "detail", "updated_unix_ms"}
        or value.get("schema_version") != 1
        or value.get("state") not in benchmark_jobs.PREPARATION_STATES
        or not isinstance(value.get("detail"), str)
        or not value["detail"]
        or len(value["detail"]) > 160
        or not isinstance(value.get("updated_unix_ms"), int)
        or isinstance(value.get("updated_unix_ms"), bool)
        or not 0 <= now_ms - value["updated_unix_ms"] <= 30_000
        or any(ord(character) < 32 and character not in "\t" for character in value["detail"])
    ):
        return None
    return value


def _benchmark_live_metrics(
    progress: Mapping[str, Any],
    config: Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    preferred_member_id: str | None = None
    try:
        preferred_member_id = read_site_identity().member_id
    except (OSError, SiteError):
        pass
    telemetry = _local_controller_telemetry(
        config,
        preferred_member_id=preferred_member_id,
    )
    if not isinstance(telemetry, dict):
        return None
    updated_ms = telemetry.get("updated_unix_ms")
    sample_ms = telemetry.get("sample_unix_ms")
    if (
        not isinstance(updated_ms, int)
        or isinstance(updated_ms, bool)
        or updated_ms <= 0
    ):
        return None
    now_ms = int(time.time() * 1000)
    fresh = 0 <= now_ms - updated_ms <= 5_000
    current_cell = progress.get("current_cell")
    phase = progress.get("phase")
    phase_updated_ns = progress.get("updated_unix_ns")
    performance_fresh = (
        fresh
        and isinstance(current_cell, str)
        and current_cell
        and isinstance(phase, str)
        and phase.endswith(":measuring")
        and isinstance(phase_updated_ns, int)
        and not isinstance(phase_updated_ns, bool)
        and updated_ms * 1_000_000 >= phase_updated_ns
    )
    raw_rates = telemetry.get("rates")
    rates = raw_rates if isinstance(raw_rates, Mapping) else {}
    raw_system = telemetry.get("system")
    system = raw_system if isinstance(raw_system, Mapping) else {}
    return {
        "schema_version": 1,
        "sample_unix_ms": max(updated_ms, sample_ms if isinstance(sample_ms, int) else 0),
        "fresh": fresh,
        "performance_cell": current_cell if performance_fresh else None,
        "active_requests": _live_number(telemetry.get("active_requests")) if performance_fresh else None,
        "queued_requests": _live_number(telemetry.get("queued_requests")) if performance_fresh else None,
        "rates": {
            field: _live_number(rates.get(field)) if performance_fresh else None
            for field in benchmark_jobs.LIVE_RATE_FIELDS
        },
        "temperatures": {
            field: _live_number(system.get(field)) if fresh else None
            for field in benchmark_jobs.LIVE_TEMPERATURE_FIELDS
        },
        "system": {
            field: _live_number(system.get(field)) if fresh else None
            for field in benchmark_jobs.LIVE_SYSTEM_FIELDS
        },
    }


class _BenchmarkLiveProgress:
    """Mirror trusted bounded telemetry into one durable benchmark progress file."""

    def __init__(
        self,
        job_id: str,
        config: Mapping[str, Any] | None,
        *,
        interval: float = 0.5,
    ) -> None:
        self.job_id = job_id
        self.config = config
        self.interval = max(0.1, interval)
        self.stop_event = threading.Event()
        self.thread = threading.Thread(
            target=self._run,
            name="letsinfer-benchmark-live-progress",
            daemon=True,
        )

    def __enter__(self) -> _BenchmarkLiveProgress:
        self.thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop_event.set()
        self.thread.join(timeout=2)

    def _run(self) -> None:
        while not self.stop_event.is_set():
            try:
                progress = benchmark_jobs.read_progress() or {}
                changes: dict[str, Any] = {}
                metrics = _benchmark_live_metrics(progress, self.config)
                if metrics is not None:
                    changes["live_metrics"] = metrics
                preparation = _engine_preparation_snapshot(self.config)
                if preparation is not None:
                    changes["preparation"] = preparation
                if changes:
                    benchmark_jobs.merge_progress(self.job_id, changes)
            except (
                benchmark_jobs.BenchmarkJobError,
                LetsInferError,
                OSError,
                ValueError,
            ):
                # Live presentation is best-effort and never owns benchmark safety.
                pass
            if self.stop_event.wait(self.interval):
                return


def _benchmark_dashboard(
    state: dict[str, Any],
    progress: dict[str, Any] | None,
    elapsed: float,
    terminal: ui.Terminal,
    frame: str,
    updates: Iterable[object] = (),
) -> str:
    """Render one bounded live benchmark frame."""
    from . import status_ui

    def mapping(value: object) -> Mapping[str, Any]:
        return value if isinstance(value, Mapping) else {}

    progress = progress if isinstance(progress, dict) else {}
    status = str(state.get("state") or "unknown").upper()
    active = state.get("state") in benchmark_jobs.ACTIVE_STATES
    color = ui.GREEN if active or status == "COMPLETED" else ui.RED
    mark = "●" if terminal.unicode else "*"
    lines = [
        terminal.logo("benchmark"),
        "",
        f"{terminal.paint(mark, ui.BOLD, color)} "
        f"{terminal.paint(status, ui.BOLD, color)}  "
        f"{terminal.paint(str(state.get('runtime') or 'unknown runtime'), ui.BOLD)}",
    ]
    update_labels = ui.update_labels(updates)
    if update_labels:
        update_text = " · ".join(update_labels)
        wrapped_updates = terminal.wrap(
            update_text,
            max(1, terminal.width - 22),
        )
        lines.extend(
            [
                f"  {terminal.paint('↑ UPDATE AVAILABLE', ui.BOLD, ui.YELLOW)}  "
                f"{terminal.paint(wrapped_updates[0], ui.DIM)}",
                *(
                    f"                      {terminal.paint(part, ui.DIM)}"
                    for part in wrapped_updates[1:]
                ),
            ]
        )
    message = progress.get("message")
    if not isinstance(message, str) or not message:
        message = "Waiting for benchmark worker"
    phase = progress.get("phase")
    if not isinstance(phase, str) or not phase:
        phase = "starting"
    preparation = mapping(progress.get("preparation"))
    preparation_state = str(preparation.get("state") or phase)
    preparation_detail = str(preparation.get("detail") or "")
    lines.extend(
        [
            f"  {terminal.paint(frame, ui.GREEN if active else color)} "
            f"{terminal.paint(terminal.clip(message, terminal.width - 5), ui.BOLD)}",
            f"  {terminal.paint(f'state {preparation_state}', ui.DIM)}"
            + (
                terminal.paint(
                    " · " + terminal.clip(
                        preparation_detail,
                        max(1, terminal.width - len(preparation_state) - 12),
                    ),
                    ui.DIM,
                )
                if preparation_detail and preparation_detail != message
                else ""
            ),
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
        metrics = mapping(progress.get("live_metrics"))
        metric_rates = mapping(metrics.get("rates"))
        temperatures = mapping(metrics.get("temperatures"))
        system = mapping(metrics.get("system"))
        metric_cell = metrics.get("performance_cell")
        metric_fresh = metrics.get("fresh") is True
        performance_current = (
            metric_fresh
            and isinstance(current, str)
            and current
            and metric_cell == current
        )
        aggregate = (
            metric_rates.get("aggregate_tokens_per_second")
            if performance_current
            else None
        )
        decode = (
            metric_rates.get("decode_tokens_per_second")
            if performance_current
            else None
        )
        prefill = (
            metric_rates.get("prefill_tokens_per_second")
            if performance_current
            else None
        )
        ttft = (
            metric_rates.get("average_ttft_milliseconds")
            if performance_current
            else None
        )
        active_requests = metrics.get("active_requests") if performance_current else None
        queued_requests = metrics.get("queued_requests") if performance_current else None

        def live_rate(value: object) -> str:
            return status_ui._rate(value)

        def temperature(value: object) -> str:
            return status_ui._temperature(value)

        def metric_lines(label: str, value: str) -> list[str]:
            prefix = f"  {label.ljust(13)}"
            continuation = " " * len(prefix)
            wrapped = terminal.wrap(value, max(1, terminal.width - len(prefix)))
            return [prefix + wrapped[0], *(continuation + part for part in wrapped[1:])]

        performance_rows = (
            (
                "Tokens",
                f"{live_rate(aggregate)} tok/s   "
                f"{live_rate(decode)} decode · {live_rate(prefill)} prefill",
            ),
            (
                "TTFT",
                "—"
                if not isinstance(ttft, (int, float)) or isinstance(ttft, bool)
                else f"{status_ui._compact(float(ttft) / 1000, decimals=2)} s",
            ),
            (
                "Requests",
                "—"
                if not isinstance(active_requests, (int, float))
                or isinstance(active_requests, bool)
                or not isinstance(queued_requests, (int, float))
                or isinstance(queued_requests, bool)
                else f"{int(active_requests)} active · {int(queued_requests)} queued",
            ),
            (
                "Utilization",
                f"GPU {status_ui._percent(system.get('gpu_percent'))} · "
                f"CPU {status_ui._percent(system.get('cpu_percent'))} · "
                f"NVMe {status_ui._percent(system.get('disk_percent'))}",
            ),
            (
                "Memory",
                f"{status_ui._percent(system.get('memory_percent'))} · "
                f"{status_ui._mib_size(system.get('memory_used_mib'))} / "
                f"{status_ui._mib_size(system.get('memory_total_mib'))}",
            ),
            (
                "NVMe I/O",
                f"↑{status_ui._binary_rate_kib(system.get('disk_read_kib_s'))} "
                f"↓{status_ui._binary_rate_kib(system.get('disk_write_kib_s'))}",
            ),
            (
                "Power",
                "—"
                if not isinstance(system.get("power_deci_w"), (int, float))
                or isinstance(system.get("power_deci_w"), bool)
                else f"{status_ui._compact(float(system['power_deci_w']) / 10, decimals=1)} W",
            ),
            (
                "Temperature",
                f"GPU {temperature(temperatures.get('gpu_temp_deci_c'))} · "
                f"CPU {temperature(temperatures.get('system_temp_deci_c'))} · "
                f"NVMe {temperature(temperatures.get('nvme_temp_deci_c'))}",
            ),
        )
        lines.extend(("", "  PERFORMANCE"))
        for metric_label, metric_value in performance_rows:
            lines.extend(metric_lines(metric_label, metric_value))
        lines.append("")
        for cell in selected:
            if cell in completed_set:
                cell_mark, cell_color, detail = (
                    ("✓" if terminal.unicode else "+"),
                    ui.GREEN,
                    "complete",
                )
            elif cell == current:
                cell_mark, cell_color, detail = frame, ui.GREEN, "running"
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
    if active:
        lines.extend(
            [
                "",
                terminal.paint(
                    "  Ctrl-C detaches; `letsinfer benchmark stop` cancels.",
                    ui.DIM,
                ),
            ]
        )
    elif state.get("error"):
        lines.extend(["", f"  {terminal.paint(str(state['error']), ui.RED)}"])
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
            presenter = _benchmark_presenter()
            if presenter is not None:
                presenter.result(
                    "No benchmark has been started",
                    semantic=command_ui.Semantic.MUTED,
                    detail="Run `letsinfer benchmark <runtime>` to start one",
                )
            else:
                ui.Terminal(sys.stdout).status("No benchmark has been started")
        return 0
    active = state.get("state") in benchmark_jobs.ACTIVE_STATES and benchmark_jobs.is_alive(
        state
    )
    if state.get("state") in benchmark_jobs.ACTIVE_STATES and not active:
        if state.get("kind") == "verification":
            _recover_interrupted_verification(state)
            state = benchmark_jobs.read_state() or state
        try:
            if state.get("state") in benchmark_jobs.ACTIVE_STATES:
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
    frame = (
        "⠋" if active and terminal.unicode
        else "✓" if state.get("state") == "completed" and terminal.unicode
        else "*"
    )
    terminal.stream.write(
        _benchmark_dashboard(
            state,
            progress,
            elapsed,
            terminal,
            frame,
            _update_manager().cached().available,
        )
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
    updates: tuple[object, ...] = ()
    next_update_read = 0.0
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
            now = time.monotonic()
            if now >= next_update_read:
                updates = tuple(_update_manager().cached().available)
                next_update_read = now + 5.0
            frame = frames[frame_index % len(frames)] if terminal.unicode else "*"
            terminal.stream.write(
                "\033[H\033[2J"
                + _benchmark_dashboard(
                    state,
                    progress,
                    elapsed,
                    terminal,
                    frame,
                    updates,
                )
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
    presenter = _benchmark_presenter()
    try:
        state = benchmark_jobs.request_stop()
    except benchmark_jobs.BenchmarkJobError as error:
        raise LetsInferError(str(error)) from error
    terminal = ui.Terminal(sys.stderr)
    timeout_seconds = _benchmark_stop_timeout_seconds()
    with ui.progress(
        "Stopping the benchmark and restoring inference", stream=sys.stderr
    ):
        stopped = benchmark_jobs.wait_for_exit(
            state["pid"], timeout_seconds=timeout_seconds
        )
    if not stopped:
        raise LetsInferError(
            f"benchmark did not stop within {timeout_seconds} seconds; "
            "its worker remains isolated"
        )
    if presenter is not None:
        presenter.result(
            "Benchmark stopped",
            semantic=command_ui.Semantic.SUCCESS,
        )
    else:
        terminal.success("Benchmark stopped")
    return 0


def _confirmed(
    message: str,
    *,
    assume_yes: bool,
    noninteractive_flag: str | None = "--yes",
) -> bool:
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        suffix = (
            f"; rerun with {noninteractive_flag}"
            if noninteractive_flag is not None
            else ""
        )
        raise LetsInferError(f"interactive confirmation is required{suffix}")
    return ui.confirm(message)


def _remove_user_tree(path: pathlib.Path, *, label: str) -> bool:
    if not path.exists() and not path.is_symlink():
        return False
    if path.resolve(strict=False) in {
        pathlib.Path("/"),
        pathlib.Path.home().resolve(strict=False),
    }:
        raise LetsInferError(f"refusing to remove overly broad {label}: {path}")
    if path.is_symlink() or not path.is_dir():
        raise LetsInferError(f"refusing to remove unsafe {label}: {path}")
    details = path.stat()
    if details.st_uid != os.getuid():
        raise LetsInferError(f"refusing to remove {label} not owned by this user: {path}")
    shutil.rmtree(path)
    return True


def _benchmark_clean(*, assume_yes: bool) -> int:
    presenter = _benchmark_presenter()
    try:
        active = benchmark_jobs.active_state()
    except benchmark_jobs.BenchmarkJobError as error:
        raise LetsInferError(str(error)) from error
    if active is not None:
        raise LetsInferError(
            f"benchmark {active['job_id']} is active; run `letsinfer benchmark stop` first"
        )
    if not _confirmed(
        "Delete all locally generated benchmark results and job logs?",
        assume_yes=assume_yes,
    ):
        if presenter is not None:
            presenter.result(
                "Benchmark cleanup cancelled",
                semantic=command_ui.Semantic.INFO,
                detail="No benchmark data was removed",
            )
        else:
            print("Benchmark cleanup cancelled")
        return 0
    removed = int(_remove_user_tree(benchmarks_root(), label="benchmark evidence"))
    removed += int(_remove_user_tree(benchmark_jobs.root(), label="benchmark job state"))
    if presenter is not None:
        presenter.records(
            (
                command_ui.RecordRow(
                    "Benchmark data",
                    "Removed",
                    semantic=command_ui.Semantic.SUCCESS,
                ),
                command_ui.RecordRow("Data roots", removed),
                command_ui.RecordRow("Sealed results", "Preserved"),
            )
        )
    else:
        print(
            f"CLEANED local benchmark data roots={removed}; "
            "sealed runtime results preserved"
        )
    return 0


def _benchmark_stop_timeout_seconds() -> int:
    """Allow a cancelled benchmark to reload the runtime it displaced."""

    path = qualification_service_config_path()
    if not path.is_file():
        return 30
    try:
        config = read_service_config(path)
        _manifest_path, manifest = configured_release(config)
        startup = manifest["container"]["startup_timeout_seconds"]
    except (KeyError, LetsInferError, OSError, TypeError):
        return 30
    if not isinstance(startup, int) or isinstance(startup, bool) or startup <= 0:
        return 30
    return min(3_600, max(30, startup + 60))


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


def _verification_progress(job_id: str, phase: str, message: str) -> None:
    try:
        benchmark_jobs.update_progress(
            job_id,
            {
                "phase": phase,
                "message": message,
                "verification": True,
            },
        )
    except benchmark_jobs.BenchmarkJobError as error:
        raise LetsInferError(str(error)) from error


def _gateway_is_idle() -> None:
    """Fail before downloads or runtime replacement when clients are active."""

    path = default_gateway_telemetry_path()
    if not path.exists():
        return
    if path.is_symlink() or not path.is_file():
        raise LetsInferError(f"gateway telemetry is unsafe: {path}")
    values: dict[str, int] = {}
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            key, separator, raw = line.partition("=")
            if separator and key in {"active_requests", "queued_requests"}:
                values[key] = int(raw)
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise LetsInferError(f"gateway telemetry is unreadable: {error}") from error
    active = values.get("active_requests", 0)
    queued = values.get("queued_requests", 0)
    if active or queued:
        raise LetsInferError(
            f"verification requires an idle gateway; active={active} queued={queued}"
        )


def _interactive_github_identity() -> benchmark_verification.GitHubIdentity:
    interactive = sys.stdin.isatty() and sys.stderr.isatty()
    presenter = (
        _benchmark_presenter()
        if interactive
        else command_ui.CommandUI(sys.stderr)
    )
    # The dashboard presenter requires stdout, stderr, and stdin to share a
    # human terminal. GitHub authentication still has a valid interactive
    # control channel when stdout is redirected, so retain a stderr-owned
    # prompt surface without contaminating captured stdout.
    if presenter is None:
        presenter = command_ui.CommandUI(sys.stderr)
    if benchmark_verification.gh_version() is None:
        command = benchmark_verification.gh_install_command()
        instruction = (
            " ".join(command)
            if command is not None
            else "install GitHub CLI from https://cli.github.com/"
        )
        if not interactive or command is None:
            raise LetsInferError(
                f"GitHub CLI is required; run `{instruction}` and retry"
            )
        presenter.result(
            "GitHub CLI is required",
            semantic=command_ui.Semantic.WARNING,
            detail=f"Installer: {instruction}",
        )
        try:
            if not presenter.prompt.confirm(
                "Install GitHub CLI now?",
                default=True,
                require_tty=True,
            ):
                raise LetsInferError("GitHub CLI installation was cancelled")
            benchmark_verification.ensure_gh(interactive=True, install=True)
        except (command_ui.PromptUnavailable, KeyboardInterrupt) as error:
            raise LetsInferError("GitHub CLI installation was cancelled") from error
        except benchmark_verification.VerificationError as error:
            raise LetsInferError(str(error)) from error
    try:
        return benchmark_verification.github_identity(interactive=False)
    except benchmark_verification.VerificationError as error:
        if "not authenticated" not in str(error) or not interactive:
            raise LetsInferError(str(error)) from error
    presenter.result(
        "GitHub authentication is required",
        semantic=command_ui.Semantic.WARNING,
        detail="GitHub CLI will show the browser or device-code URL",
    )
    try:
        if not presenter.prompt.confirm(
            "Authenticate with GitHub now?",
            default=True,
            require_tty=True,
        ):
            raise LetsInferError("GitHub authentication was cancelled")
        identity = benchmark_verification.github_identity(
            interactive=True, authenticate=True
        )
    except (command_ui.PromptUnavailable, KeyboardInterrupt) as error:
        raise LetsInferError("GitHub authentication was cancelled") from error
    except benchmark_verification.VerificationError as error:
        raise LetsInferError(str(error)) from error
    presenter.records(
        (
            command_ui.RecordRow(
                "GitHub",
                f"@{identity.login}",
                str(identity.numeric_id),
                command_ui.Semantic.SUCCESS,
            ),
        )
    )
    return identity


def _verification_self_command(
    arguments: argparse.Namespace, executable: pathlib.Path
) -> list[str]:
    command = [
        str(executable),
        "benchmark",
        "verify",
        arguments.verification_target,
    ]
    if arguments.candidate is not None:
        command.extend(["--candidate", arguments.candidate])
    return command


def _verification_job_snapshot(*, machine: bool = False) -> int:
    state = benchmark_jobs.read_state()
    if state is None or state.get("kind") != "verification":
        if machine:
            print(compact_json({"active": False, "state": "none", "kind": "verification"}))
        else:
            presenter = _benchmark_presenter()
            if presenter is not None:
                presenter.result(
                    "No runtime verification has been started",
                    semantic=command_ui.Semantic.MUTED,
                    detail=(
                        "Run `letsinfer benchmark verify <pull-request-url>` "
                        "to start one"
                    ),
                )
            else:
                ui.Terminal(sys.stdout).status(
                    "No runtime verification has been started"
                )
        return 0
    active = (
        state.get("state") in benchmark_jobs.ACTIVE_STATES
        and benchmark_jobs.is_alive(state)
    )
    if state.get("state") in benchmark_jobs.ACTIVE_STATES and not active:
        _recover_interrupted_verification(state)
    if machine:
        return _benchmark_job_snapshot(machine=True)
    if active:
        _follow_benchmark_job(state["job_id"])
        return 0
    return _benchmark_job_snapshot()


def _verification_stop() -> int:
    state = benchmark_jobs.active_state()
    if state is None or state.get("kind") != "verification":
        raise LetsInferError("no runtime verification is active")
    return _benchmark_stop()


def _selected_receipt(logical_model: str) -> dict[str, Any] | None:
    try:
        return next(
            (
                receipt
                for receipt in selections()
                if receipt["logical_model"] == logical_model
            ),
            None,
        )
    except RuntimePackError as error:
        raise LetsInferError(str(error)) from error


def _prepare_verification_runtime(
    source: str,
    *,
    policy: str,
    requested_runtime: str | None = None,
    expected_version: str | None = None,
    requested_target: str | None = None,
    expected_target_contract_sha256: str | None = None,
    image_override: Mapping[str, str] | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any] | None]:
    """Resolve and validate all candidate bytes without changing selection."""

    manifest_path, manifest, release_root, prepared = prepare_runtime_install(
        source,
        policy=policy,
        qualified=False,
        requested_runtime=requested_runtime,
        requested_target=requested_target,
        expected_version=expected_version,
        expected_target_contract_sha256=expected_target_contract_sha256,
        image_override=image_override,
    )
    verify_runtime_sources(manifest, release_root)
    verify_host_target(manifest)
    runtime_root = pathlib.Path(prepared["object_root"]).expanduser()
    model_cache = requested_model_cache(None)
    ensure_install_dependencies(
        manifest,
        model_cache=model_cache,
        runtime_artifact_root=runtime_root,
        download=True,
        build_image=True,
    )
    verify_installed_runtime(manifest, model_cache=model_cache)
    previous = _selected_receipt(prepared["logical_model"])
    return manifest, prepared, previous


def _publish_verification_runtime(
    prepared: dict[str, Any], previous: dict[str, Any] | None
) -> dict[str, Any]:
    """Atomically select a fully prepared candidate with exact rollback state."""

    published = False
    try:
        write_selection(prepared)
        published = True
        current = _selected_receipt(prepared["logical_model"])
        if current is None or current["digest"] != prepared["digest"]:
            raise LetsInferError("verification runtime selection was not published")
    except BaseException:
        if published:
            selected = _selected_receipt(prepared["logical_model"])
            if selected is not None and selected.get("digest") == prepared["digest"]:
                _restore_verification_selection(selected, previous)
        raise
    return current


def _restore_verification_selection(
    replacement: dict[str, Any], previous: dict[str, Any] | None
) -> None:
    try:
        restore_selection(replacement, previous)
    except RuntimePackError as error:
        raise LetsInferError(str(error)) from error


def _restoration_receipt_path(state: Mapping[str, Any]) -> pathlib.Path:
    return pathlib.Path(str(state["output_directory"])) / "restoration-receipt.json"


def _write_restoration_receipt(
    state: Mapping[str, Any],
    *,
    logical_model: str,
    original: dict[str, Any],
    replacement: dict[str, Any] | None,
    restored: bool,
) -> None:
    path = _restoration_receipt_path(state)
    atomic_json(
        path,
        {
            "schema_version": 1,
            "job_id": state["job_id"],
            "logical_model": logical_model,
            "original_selection": original,
            "replacement_digest": (
                None if replacement is None else replacement["digest"]
            ),
            "restored": restored,
            "updated_unix_ns": time.time_ns(),
        },
    )
    path.chmod(0o600)


def _recover_interrupted_verification(state: Mapping[str, Any]) -> None:
    """Use the persisted receipt after worker death or a machine reboot."""

    path = _restoration_receipt_path(state)
    if not path.is_file() or path.is_symlink():
        try:
            benchmark_verification.cleanup_local_engine(
                pathlib.Path(str(state["output_directory"]))
            )
        except benchmark_verification.VerificationError as error:
            raise LetsInferError(
                f"cannot clean interrupted verifier Engine: {error}"
            ) from error
        benchmark_jobs.mark(
            str(state["job_id"]),
            "failed",
            error="verification worker exited before publishing a restoration receipt",
        )
        return
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LetsInferError(f"verification restoration receipt is invalid: {error}") from error
    if (
        not isinstance(receipt, dict)
        or receipt.get("schema_version") != 1
        or receipt.get("job_id") != state.get("job_id")
        or not isinstance(receipt.get("logical_model"), str)
        or not isinstance(receipt.get("original_selection"), dict)
        or type(receipt.get("restored")) is not bool
    ):
        raise LetsInferError("verification restoration receipt has an invalid schema")
    if not receipt["restored"]:
        current = _selected_receipt(receipt["logical_model"])
        original = receipt["original_selection"]
        replacement_digest = receipt.get("replacement_digest")
        if current is None:
            raise LetsInferError("verification runtime selection disappeared before recovery")
        if current["digest"] == original.get("digest"):
            pass
        elif current["digest"] == replacement_digest:
            _restore_verification_selection(current, original)
        else:
            raise LetsInferError(
                "runtime selection changed outside the interrupted verification; "
                "automatic restoration refused"
            )
        if qualification_service_config_path().is_file():
            _retire_qualification_candidate(remove_container=True)
        _write_restoration_receipt(
            state,
            logical_model=receipt["logical_model"],
            original=original,
            replacement=None,
            restored=True,
        )
    try:
        benchmark_verification.cleanup_local_engine(
            pathlib.Path(str(state["output_directory"]))
        )
    except benchmark_verification.VerificationError as error:
        raise LetsInferError(f"cannot clean interrupted verifier Engine: {error}") from error
    benchmark_jobs.mark(
        str(state["job_id"]),
        "failed",
        error="verification worker exited; exact resident selection was restored",
    )


def _nested_benchmark_arguments(
    runtime: str, output: pathlib.Path, job_id: str
) -> argparse.Namespace:
    arguments = parser().parse_args(
        [
            "benchmark",
            runtime,
            "--output-directory",
            str(output),
            "--job-worker",
            "--job-id",
            job_id,
        ]
    )
    arguments.nested_verification = True
    return arguments


def _run_verification_benchmark(
    runtime: str, output: pathlib.Path, job_id: str, label: str
) -> dict[str, Any]:
    _verification_progress(job_id, f"benchmark:{label}", f"Benchmarking {label}")
    benchmark_runtime(_nested_benchmark_arguments(runtime, output, job_id))
    path = output / "benchmark.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LetsInferError(f"{label} benchmark evidence is unavailable: {error}") from error
    try:
        benchmark_record_contract.validate_record(value)
    except benchmark_record_contract.BenchmarkRecordError as error:
        raise LetsInferError(f"{label} benchmark evidence is invalid: {error}") from error
    return value


def _verification_failure(error: BaseException, phase: str) -> dict[str, str]:
    """Map an execution failure to the bounded public verification taxonomy."""

    message = " ".join(str(error).split())[:500] or type(error).__name__
    lowered = message.lower()
    if "out of memory" in lowered or "oom" in lowered or "memory exhausted" in lowered:
        category = "out_of_memory"
    elif "protection" in lowered or "safety trip" in lowered:
        category = "protection_trip"
    elif "restor" in lowered:
        category = "restoration"
    elif "output" in lowered and ("invalid" in lowered or "validation" in lowered):
        category = "output_validation"
    elif "incomplete" in lowered or "workload" in lowered:
        category = "incomplete_workload"
    else:
        category = "crash"
    return {"category": category, "phase": phase[:128], "message": message}


def _run_verification_worker(arguments: argparse.Namespace) -> int:
    job_id = arguments.job_id
    if not isinstance(job_id, str) or not job_id:
        raise LetsInferError("verification worker has no job identity")
    state = _mark_benchmark_job(job_id, "running")
    metadata = state.get("metadata")
    if not isinstance(metadata, dict):
        raise LetsInferError("verification job metadata is unavailable")
    output = pathlib.Path(state["output_directory"])
    ensure_private_directory(output)
    previous_term = signal.getsignal(signal.SIGTERM)
    previous_int = signal.getsignal(signal.SIGINT)
    baseline_current: dict[str, Any] | None = None
    candidate_current: dict[str, Any] | None = None
    candidate_previous: dict[str, Any] | None = None
    logical_model: str | None = None
    restoration: dict[str, Any] = {"passed": False}
    gh: str | None = None
    pr: benchmark_verification.PullRequest | None = None
    identity: benchmark_verification.GitHubIdentity | None = None
    subject: dict[str, Any] | None = None
    baseline: dict[str, Any] | None = None
    candidate_record: dict[str, Any] | None = None
    candidate_execution_started = False
    failure_phase = "preflight"
    runtime_author_ids: set[int] = set()
    verifier_bundle: benchmark_verification.VerifierBundle | None = None

    def cancel(_signal: int, _frame: Any) -> None:
        raise _BenchmarkCancelled("verification cancellation requested")

    signal.signal(signal.SIGTERM, cancel)
    signal.signal(signal.SIGINT, cancel)
    error: BaseException | None = None
    cancelled = False
    try:
        _verification_progress(job_id, "github", "Confirming pull-request identity")
        failure_phase = "github"
        gh = benchmark_verification.ensure_gh(interactive=False)
        pr = benchmark_verification.pull_request(arguments.verification_target, gh=gh)
        if pr.head_sha != metadata.get("observed_head_sha"):
            raise LetsInferError("pull-request head changed after verification started")
        if "benchmark-ready" not in pr.labels:
            raise LetsInferError("runtime PR is no longer benchmark-ready")
        identity = benchmark_verification.github_identity(interactive=False)
        if identity.document() != metadata.get("verifier"):
            raise LetsInferError("authenticated GitHub identity changed during verification")
        candidate = benchmark_verification.select_candidate(pr, arguments.candidate)
        if candidate != metadata.get("candidate"):
            raise LetsInferError("pull-request candidate changed during verification")

        _verification_progress(job_id, "artifact", "Downloading the exact verifier bundle")
        failure_phase = "artifact"
        verifier_bundle = benchmark_verification.download_verifier_bundle(
            pr, candidate, output / "verifier-artifact", gh=gh
        )
        pack_path = verifier_bundle.runtime_pack
        try:
            with materialize(pack_path) as bundled_pack:
                runtime = dict(bundled_pack.runtime)
        except RuntimePackError as pack_error:
            raise LetsInferError(str(pack_error)) from pack_error
        authors = verifier_bundle.document["runtime_authors"]
        for author in authors:
            author_id = author.get("github_id") if isinstance(author, dict) else None
            if (
                not isinstance(author_id, int)
                or isinstance(author_id, bool)
                or author_id <= 0
            ):
                raise LetsInferError("pull-request runtime author identity is invalid")
            runtime_author_ids.add(author_id)
        logical_model = runtime.get("logical_model")
        if not isinstance(logical_model, str):
            raise LetsInferError("pull-request candidate logical model is invalid")
        if {"qualified", "blocked_by"}.intersection(runtime.get("serving", {})):
            raise LetsInferError(
                "a pull-request runtime cannot grant its own qualification"
            )
        subject = verifier_bundle.subject
        try:
            benchmark_verification.load_local_engine(verifier_bundle, output)
        except benchmark_verification.VerificationError as bundle_error:
            raise LetsInferError(str(bundle_error)) from bundle_error
        image_override = (
            None
            if verifier_bundle.engine_config_digest is None
            else {
                "distribution": "local-image-id",
                "reference": verifier_bundle.engine_config_digest,
                "immutable_id": verifier_bundle.engine_config_digest,
            }
        )
        _verification_progress(job_id, "preflight", "Resolving baseline and dependencies")
        failure_phase = "preflight"
        source, policy, expected_version, selected_target, selected_target_sha, _qualified = (
            _runtime_source_for_install(logical_model, None, None)
        )
        baseline_current = _selected_receipt(logical_model)
        if (
            baseline_current is None
            or baseline_current.get("source") != source
            or baseline_current.get("version") != expected_version
            or baseline_current.get("target") != selected_target
            or baseline_current.get("target_contract_sha256")
            != selected_target_sha
        ):
            raise LetsInferError(
                "community verification requires the current catalog recommendation "
                f"as its exact baseline; run `letsinfer install {logical_model}` "
                "before retrying"
            )
        candidate_manifest, candidate_prepared, candidate_previous = (
            _prepare_verification_runtime(
                str(pack_path),
                policy="community-verification",
                requested_runtime=candidate,
                image_override=image_override,
            )
        )
        if candidate_manifest["model"]["alias"] != logical_model:
            raise LetsInferError("candidate logical model changed while preparing")
        if (
            candidate_previous is None
            or candidate_previous.get("digest") != baseline_current.get("digest")
        ):
            raise LetsInferError("candidate preparation did not bind the exact baseline")
        _write_restoration_receipt(
            state,
            logical_model=logical_model,
            original=baseline_current,
            replacement=None,
            restored=False,
        )
        failure_phase = "benchmark:baseline"
        baseline = _run_verification_benchmark(
            baseline_current["candidate_id"], output / "baseline", job_id, "baseline"
        )

        candidate_current = _publish_verification_runtime(
            candidate_prepared, candidate_previous
        )
        candidate_execution_started = True
        _write_restoration_receipt(
            state,
            logical_model=logical_model,
            original=baseline_current,
            replacement=candidate_current,
            restored=False,
        )
        failure_phase = "benchmark:candidate"
        candidate_record = _run_verification_benchmark(
            candidate, output / "candidate", job_id, "candidate"
        )

        _verification_progress(job_id, "restore", "Restoring the resident runtime")
        failure_phase = "restore"
        _restore_verification_selection(candidate_current, candidate_previous)
        candidate_current = None
        resident_digest = baseline_current.get("digest")
        restoration = {
            "passed": True,
            "resident_runtime_digest": resident_digest,
            "qualification_slot_retired": not qualification_service_config_path().exists(),
        }
        if not restoration["qualification_slot_retired"]:
            _retire_qualification_candidate(remove_container=True)
            restoration["qualification_slot_retired"] = True
        _write_restoration_receipt(
            state,
            logical_model=logical_model,
            original=baseline_current,
            replacement=None,
            restored=True,
        )

        device = benchmark_verification.device_identity()
        record = benchmark_verification.verification_record(
            pr=pr,
            verifier=identity,
            device=device,
            subject=subject,
            candidate_benchmark=candidate_record,
            baseline_benchmark=baseline,
            restoration=restoration,
            runtime_author_ids=runtime_author_ids,
        )
        evidence_path = output / "verification-benchmark.json"
        atomic_json(evidence_path, record)
        evidence_path.chmod(0o600)
        body = benchmark_verification.build_comment(record, device)
        comment_path = output / "github-comment.md"
        _atomic_private_text(comment_path, body)
        _verification_progress(job_id, "submit", "Posting signed verification evidence")
        comment_url = benchmark_verification.post_comment(pr, body, gh=gh)
        receipt = {
            "schema_version": 1,
            "verification_id": record["verification_id"],
            "comment_url": comment_url,
            "evidence_sha256": sha256_file(evidence_path),
            "restoration": restoration,
        }
        atomic_json(output / "submission.json", receipt)
        _mark_benchmark_job(job_id, "completed")
    except _BenchmarkCancelled as caught:
        error = caught
        cancelled = True
    except BaseException as caught:
        error = caught
    finally:
        restore_errors: list[str] = []
        if candidate_current is not None:
            try:
                _restore_verification_selection(candidate_current, candidate_previous)
            except BaseException as restore_error:
                restore_errors.append(f"candidate selection: {restore_error}")
        if qualification_service_config_path().is_file():
            try:
                _retire_qualification_candidate(remove_container=True)
            except BaseException as restore_error:
                restore_errors.append(f"qualification slot: {restore_error}")
        try:
            benchmark_verification.cleanup_local_engine(output)
        except BaseException as restore_error:
            restore_errors.append(f"verifier Engine image: {restore_error}")
        if (
            not restore_errors
            and logical_model is not None
            and baseline_current is not None
            and _restoration_receipt_path(state).is_file()
        ):
            try:
                _write_restoration_receipt(
                    state,
                    logical_model=logical_model,
                    original=baseline_current,
                    replacement=None,
                    restored=True,
                )
            except BaseException as restore_error:
                restore_errors.append(f"restoration receipt: {restore_error}")
        signal.signal(signal.SIGTERM, previous_term)
        signal.signal(signal.SIGINT, previous_int)
        if restore_errors:
            error = LetsInferError(
                "verification restoration was incomplete: " + "; ".join(restore_errors)
            )
            cancelled = False
            restoration = {
                "passed": False,
                "errors": restore_errors,
                "qualification_slot_retired": not qualification_service_config_path().exists(),
            }
        elif logical_model is not None and baseline_current is not None:
            restoration = {
                "passed": True,
                "resident_runtime_digest": baseline_current.get("digest"),
                "qualification_slot_retired": not qualification_service_config_path().exists(),
            }
    if error is None:
        return 0
    if cancelled:
        _mark_benchmark_job(job_id, "cancelled")
        return 0
    assert error is not None
    if (
        candidate_execution_started
        and pr is not None
        and identity is not None
        and subject is not None
        and gh is not None
    ):
        try:
            failure = _verification_failure(error, failure_phase)
            if failure["category"] == "restoration":
                restoration = {**restoration, "passed": False}
            device = benchmark_verification.device_identity()
            record = benchmark_verification.verification_record(
                pr=pr,
                verifier=identity,
                device=device,
                subject=subject,
                candidate_benchmark=candidate_record,
                baseline_benchmark=baseline,
                restoration=restoration,
                failure=failure,
                runtime_author_ids=runtime_author_ids,
            )
            evidence_path = output / "verification-benchmark.json"
            atomic_json(evidence_path, record)
            evidence_path.chmod(0o600)
            body = benchmark_verification.build_comment(record, device)
            _atomic_private_text(output / "github-comment.md", body)
            benchmark_verification.post_comment(pr, body, gh=gh)
        except BaseException as submission_error:
            error = LetsInferError(
                f"{error}; blocking evidence could not be posted: {submission_error}"
            )
    _mark_benchmark_job(
        job_id, "failed", error=f"{type(error).__name__}: {error}"
    )
    raise error


def _benchmark_verify(arguments: argparse.Namespace) -> int:
    target = arguments.verification_target
    selectors = any(
        getattr(arguments, name)
        for name in ("c1", "c2", "c4", "c8", "c16")
    ) or any(
        getattr(arguments, f"context_{context}")
        for context in ("32k", "64k", "128k", "256k")
    )
    if selectors or arguments.list or arguments.detach:
        raise LetsInferError(
            "runtime verification uses the complete standardized benchmark contract"
        )
    if arguments.yes:
        raise LetsInferError("--yes cannot authorize GitHub authentication")
    if target is None or target == "status":
        return _verification_job_snapshot(machine=arguments.json)
    if target == "stop":
        if arguments.json:
            raise LetsInferError("benchmark verify stop does not accept --json")
        return _verification_stop()
    if arguments.json:
        raise LetsInferError("--json is available only for benchmark verify status")
    if arguments.job_worker:
        return _run_verification_worker(arguments)

    _gateway_is_idle()
    identity = _interactive_github_identity()
    try:
        gh = benchmark_verification.ensure_gh(interactive=False)
        pr = benchmark_verification.pull_request(target, gh=gh)
        candidate = benchmark_verification.select_candidate(pr, arguments.candidate)
        if "benchmark-ready" not in pr.labels:
            raise benchmark_verification.VerificationError(
                "runtime PR is not benchmark-ready; wait for source and supply-chain review"
            )
    except benchmark_verification.VerificationError as error:
        raise LetsInferError(str(error)) from error
    active = benchmark_jobs.active_state()
    if active is not None:
        raise LetsInferError(
            f"benchmark {active['job_id']} is already active; stop it first"
        )
    executable = _contained_regular_file(source_root(), "bin/letsinfer")
    output = (
        benchmarks_root()
        / "verifications"
        / f"pr-{pr.number}-{candidate}-{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    )
    worker = _verification_self_command(arguments, executable)
    try:
        state = benchmark_jobs.start(
            worker,
            runtime=candidate,
            output_directory=str(output),
            kind="verification",
            metadata={
                "pull_request": pr.number,
                "pull_request_url": pr.url,
                "observed_head_sha": pr.head_sha,
                "candidate": candidate,
                "verifier": identity.document(),
                "pull_request_author": pr.author.document(),
            },
        )
    except benchmark_jobs.BenchmarkJobError as error:
        raise LetsInferError(str(error)) from error
    # The attached live dashboard owns this surface and immediately renders
    # the job identity, verifier, elapsed time, and current phase.  Avoid a
    # transient one-line status immediately before that continuously refreshed
    # view takes over the terminal.
    _follow_benchmark_job(state["job_id"])
    return 0


def benchmark_runtime(arguments: argparse.Namespace) -> int:
    """Run the generic sealed matrix for one installed runtime."""
    try:
        prior_job = benchmark_jobs.read_state()
    except benchmark_jobs.BenchmarkJobError as error:
        raise LetsInferError(str(error)) from error
    if (
        prior_job is not None
        and prior_job.get("kind") == "verification"
        and prior_job.get("state") in benchmark_jobs.ACTIVE_STATES
        and not benchmark_jobs.is_alive(prior_job)
    ):
        _recover_interrupted_verification(prior_job)
    selectors = any(
        getattr(arguments, name)
        for name in ("c1", "c2", "c4", "c8", "c16")
    ) or any(
        getattr(arguments, f"context_{context}")
        for context in ("32k", "64k", "128k", "256k")
    )
    if arguments.runtime == "verify":
        return _benchmark_verify(arguments)
    if (
        getattr(arguments, "verification_target", None) is not None
        or getattr(arguments, "candidate", None) is not None
    ):
        raise LetsInferError(
            "the second benchmark argument is available only after `benchmark verify`"
        )
    if arguments.runtime is None:
        if (
            selectors
            or arguments.list
            or arguments.detach
            or arguments.job_worker
            or arguments.yes
        ):
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
        if selectors or arguments.list or arguments.detach or arguments.json or arguments.yes:
            raise LetsInferError("benchmark stop does not accept workload options")
        return _benchmark_stop()
    if arguments.runtime == "clean":
        if selectors or arguments.list or arguments.detach or arguments.json:
            raise LetsInferError("benchmark clean does not accept workload options")
        return _benchmark_clean(assume_yes=arguments.yes)
    if arguments.yes:
        raise LetsInferError("--yes is available only for benchmark clean")
    if arguments.json:
        raise LetsInferError("--json is available only for benchmark status")
    if arguments.list and arguments.detach:
        raise LetsInferError("--detach cannot be combined with --list")
    manifest_path, manifest = resolve_model(arguments.runtime)
    root = runtime_source_root(manifest_path)
    verify_runtime_sources(manifest, root)
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
    benchmark_contract = runtime_descriptor.runtime["benchmark"]["contract"]
    # Runtime receipts retain the immutable control bundle that was current at
    # install time.  Benchmarking must not execute that historical core after a
    # core-only update.  Recompose the unchanged runtime artifacts with this
    # executable's core and dispatch the worker from that immutable bundle.
    root, manifest_path = _bind_runtime_release_to_current_core(
        manifest_path, manifest
    )
    verify_runtime_sources(manifest, root)
    runtime_config_value = read_json(runtime_config)
    if runtime_config_value.get("benchmark", {}).get("contract") != benchmark_contract:
        raise LetsInferError(
            "installed runtime benchmark contract does not match its descriptor"
        )
    benchmark_contract_sha = hashlib.sha256(
        canonical_bytes(benchmark_contract)
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
        str(manifest_path),
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
        if config_path.is_file():
            config = read_service_config(config_path)
        else:
            config = _qualification_core_plane_config()
            placement = resolve_service_placement(manifest, sha256_file(manifest_path))
            config.update(
                {
                    "engine_port": 18000,
                    "protection_root": str(
                        default_watchdog_data_root()
                        / PROTECTION_ROOT_NAME
                        / placement["placement_id"]
                    ),
                }
            )
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
        output = benchmarks_root() / f"{runtime_name}-{stamp}"
        command.extend(["--output-directory", str(output)])
    if arguments.job_worker:
        command.extend(["--progress-file", str(benchmark_jobs.progress_path())])

    if arguments.list:
        # ``--list`` is an explicit raw-output contract: the materializer's
        # validated workload list belongs to the caller even on a TTY.
        run_passthrough(command, visible=True)
    elif arguments.job_worker:
        if not isinstance(arguments.job_id, str) or not arguments.job_id:
            raise LetsInferError("benchmark worker has no job identity")
        nested_verification = bool(
            getattr(arguments, "nested_verification", False)
        )
        if not nested_verification:
            _mark_benchmark_job(arguments.job_id, "running")
        previous_term = signal.getsignal(signal.SIGTERM)
        previous_int = signal.getsignal(signal.SIGINT)

        def cancel_benchmark(_signal: int, _frame: Any) -> None:
            raise _BenchmarkCancelled("benchmark cancellation requested")

        if not nested_verification:
            signal.signal(signal.SIGTERM, cancel_benchmark)
            signal.signal(signal.SIGINT, cancel_benchmark)
        try:
            with _BenchmarkLiveProgress(arguments.job_id, config):
                _run_benchmark_with_service_isolation(
                    command,
                    protection_config=config,
                    cleanup_command=[
                        str(letsinfer_bin),
                        "stop",
                        "--name",
                        arguments.container or "letsinfer-benchmark",
                    ],
                    progress_job_id=arguments.job_id,
                )
        except _BenchmarkCancelled:
            if not nested_verification:
                _mark_benchmark_job(arguments.job_id, "cancelled")
            return 0
        except BaseException as error:
            if not nested_verification:
                _mark_benchmark_job(
                    arguments.job_id,
                    "failed",
                    error=f"{type(error).__name__}: {error}",
                )
            raise
        else:
            if not nested_verification:
                _mark_benchmark_job(arguments.job_id, "completed")
        finally:
            if not nested_verification:
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
        if arguments.detach:
            presenter = _benchmark_presenter()
            if presenter is not None:
                presenter.records(
                    (
                        command_ui.RecordRow(
                            "Benchmark",
                            "Running",
                            semantic=command_ui.Semantic.WORKING,
                        ),
                        command_ui.RecordRow("Runtime", arguments.runtime),
                        command_ui.RecordRow("Job", state["job_id"][:8]),
                    )
                )
            else:
                ui.Terminal(sys.stderr).status(
                    f"Benchmark started · job {state['job_id'][:8]}"
                )
        else:
            # The attached dashboard is the progress surface; it includes the
            # job identifier from its first frame and then refreshes in place.
            _follow_benchmark_job(state["job_id"])
    return 0


def _run_benchmark_with_service_isolation(
    command: Sequence[str],
    *,
    protection_config: dict[str, Any] | None = None,
    cleanup_command: Sequence[str] | None = None,
    progress_job_id: str | None = None,
) -> None:
    """Suspend an active engine while a benchmark owns the inference host."""
    if protection_config is not None and protection_trip_latched(protection_config):
        raise LetsInferError(
            "runtime protection is already tripped; run letsinfer recover before "
            "benchmarking"
        )
    # Preserve the inference-slot intent before the matrix begins.  Each cell
    # deliberately replaces the candidate container and store, so restoration
    # means rearming the final candidate when the slot was serving beforehand.
    # The runtime matrix delegates replacement to ``serve``; duplicating that
    # transaction here creates a cancellation window with no candidate to
    # restore.
    candidate_was_running = False
    candidate_path = qualification_service_config_path()
    if candidate_path.is_file():
        candidate = read_service_config(candidate_path)
        if candidate.get("qualification_mode") is not True:
            raise LetsInferError("qualification slot has an invalid lifecycle mode")
        if protection_trip_latched(candidate):
            raise LetsInferError(
                "runtime protection is already tripped; run letsinfer recover "
                "before benchmarking"
            )
        candidate_inspection = container_inspect(candidate["name"])
        candidate_was_running = bool(
            candidate_inspection is not None
            and candidate_inspection.get("State", {}).get("Running") is True
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
        if progress_job_id is not None:
            benchmark_jobs.merge_progress(
                progress_job_id,
                {
                    "preparation": {
                        "schema_version": 1,
                        "state": "acquiring-inputs",
                        "detail": "Acquiring and verifying runtime inputs",
                        "updated_unix_ms": int(time.time() * 1000),
                    }
                },
            )
        if recovery_state == "active":
            run_passthrough(
                ["systemctl", "--user", "stop", RECOVERY_TIMER_NAME]
            )
            recovery_stopped = True
        if engine_state == "active":
            if protection_config is None:
                raise LetsInferError(
                    "active engine has no protection configuration for benchmark isolation"
                )
            disarm_before_planned_stop(protection_config)
            run_passthrough(
                ["systemctl", "--user", "stop", ENGINE_SERVICE_NAME]
            )
            engine_stopped = True
        run_passthrough(command, failure_label="benchmark runner")
    except BaseException as error:
        benchmark_error = error
    finally:
        if progress_job_id is not None:
            try:
                benchmark_jobs.merge_progress(
                    progress_job_id,
                    {
                        "preparation": {
                            "schema_version": 1,
                            "state": "restoring-service",
                            "detail": "Stopping benchmark resources and restoring the prior service",
                            "updated_unix_ms": int(time.time() * 1000),
                        }
                    },
                )
            except benchmark_jobs.BenchmarkJobError:
                pass
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
        if not benchmark_trip_latched:
            final_candidate_path = qualification_service_config_path()
            if candidate_was_running:
                if not final_candidate_path.is_file():
                    restore_errors.append(
                        "restore qualification candidate: candidate slot is absent"
                    )
                else:
                    try:
                        final_candidate = read_service_config(final_candidate_path)
                        _qualification_candidate_lifecycle(final_candidate, "start")
                    except BaseException as error:
                        restore_errors.append(
                            f"restore qualification candidate: {error}"
                        )
            elif final_candidate_path.is_file():
                try:
                    _retire_qualification_candidate(remove_container=True)
                except BaseException as error:
                    restore_errors.append(
                        f"retire temporary qualification candidate: {error}"
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


def _installed_core_layout() -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
    """Return (home, installer, public launcher) for an immutable install."""
    try:
        root = source_root().resolve(strict=True)
    except OSError as error:
        raise LetsInferError(f"cannot resolve the installed core: {error}") from error
    version_root = root.parent
    versions_root = version_root.parent
    core = versions_root.parent
    if versions_root.name != "versions" or core.name != "core":
        raise LetsInferError(
            "core update must be run from an installed Let's Infer command"
        )
    home = core.parent
    if home != letsinfer_home_root().resolve(strict=True):
        raise LetsInferError("installed core is outside LETSINFER_HOME")
    current = core / "current"
    if not current.is_symlink() or current.resolve(strict=True) != root:
        raise LetsInferError("installed core is not the active LETSINFER_HOME core")
    installer = root / "install.sh"
    if installer.is_symlink() or not installer.is_file():
        raise LetsInferError("the installed core has no trusted release installer")
    launcher_root = os.environ.get("LETSINFER_LAUNCHER_DIR")
    launcher = (
        pathlib.Path(launcher_root) / "letsinfer"
        if launcher_root
        else current / "bin/letsinfer"
    )
    return home, installer, launcher


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
    _, installer, launcher = _installed_core_layout()
    command = ["/bin/sh", str(installer), "--no-setup", "--no-progress"]
    if launcher.parent != pathlib.Path("/usr/local/bin"):
        if launcher.parent.name != "bin":
            raise LetsInferError("installed launcher is outside a supported bin directory")
        command.extend(["--prefix", str(launcher.parent.parent)])
    if arguments.version is not None:
        command.extend(["--version", arguments.version])
    terminal = ui.Terminal(sys.stderr)
    if not terminal.interactive:
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
        run([str(launcher), "--help"])
        run_passthrough([str(launcher), "core-prune", "--quiet"])
        return 0

    # Authenticate before the progress owner starts. This keeps sudo's prompt
    # completely separate from animated output and avoids leaking spinner
    # frames into sudo's controlling terminal.
    if launcher.parent == pathlib.Path("/usr/local/bin"):
        run_passthrough(["sudo", "-v"])
    with ui.StepProgress(
        terminal,
        (
            "Resolve and install core",
            "Rebind services and runtime",
            "Verify update",
        ),
        section="update",
        show_header=False,
    ) as progress:
        run(command)
        progress.advance()
        if launcher.is_symlink():
            try:
                launcher.resolve(strict=True)
            except OSError as error:
                raise LetsInferError(
                    f"updated core launcher is unavailable: {error}"
                ) from error
        elif not launcher.is_file():
            raise LetsInferError(f"updated core launcher is unavailable: {launcher}")
        run([str(launcher), "core-rebind"])
        progress.advance()
        run([str(launcher), "--help"])
        run([str(launcher), "core-prune", "--quiet"])
        progress.advance()
    return 0


def check_updates(arguments: argparse.Namespace) -> int:
    """Synchronously refresh core and selected-runtime availability."""
    manager = _update_manager(arguments.catalog)
    try:
        snapshot = manager.refresh()
    except (UpdateError, RuntimePackError, OSError) as error:
        raise LetsInferError(f"update check failed: {error}") from error
    if arguments.json:
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "busy": snapshot.busy,
                    "updates_available": bool(snapshot.available),
                    "components": [
                        {
                            "kind": record.kind,
                            "subject": record.subject,
                            "installed_version": record.installed_version,
                            "available_version": record.available_version,
                            "available_identity": record.available_identity,
                            "available_source": record.available_source,
                            "status": record.status,
                            "checked_at_unix": record.checked_at_unix,
                            "verified_at_unix": record.verified_at_unix,
                            "error_code": record.error_code,
                        }
                        for record in snapshot.records
                    ],
                },
                sort_keys=True,
            )
        )
    else:
        presenter = _human_presenter()
        rendered = []
        for record in snapshot.records:
            label = "Core" if record.kind == "core" else record.subject
            if record.available:
                state = "Available"
                semantic = command_ui.Semantic.WARNING
                detail = (
                    f"{record.installed_version} → {record.available_version}"
                )
            elif record.status == "current":
                state = "Current"
                semantic = command_ui.Semantic.SUCCESS
                detail = record.installed_version
            elif record.status == "pinned":
                state = "Pinned"
                semantic = command_ui.Semantic.INFO
                detail = record.installed_version
            else:
                state = "Unavailable"
                semantic = command_ui.Semantic.ERROR
                detail = record.error_code or record.status
            rendered.append(
                {
                    "component": label,
                    "state": state,
                    "detail": detail,
                    "_semantic": semantic,
                }
            )
        if presenter is not None:
            if snapshot.busy:
                presenter.result(
                    "Another update check is running",
                    semantic=command_ui.Semantic.INFO,
                    detail="Showing the latest verified state",
                )
            presenter.table(
                (
                    command_ui.TableColumn("component", "COMPONENT", min_width=8),
                    command_ui.TableColumn("state", "STATE", min_width=7),
                    command_ui.TableColumn("detail", "VERSION", min_width=8),
                ),
                rendered,
                empty_message="No installed components were found",
            )
            for record in snapshot.available:
                command = (
                    f"letsinfer update --version {record.available_version}"
                    if record.kind == "core"
                    else f"letsinfer upgrade {record.subject}"
                )
                presenter.verbatim(command, label="Apply", copyable=True)
        else:
            terminal = ui.Terminal(sys.stdout)
            if snapshot.busy:
                terminal.status("Another update check is already running; showing verified state")
            for record in snapshot.records:
                label = "Core" if record.kind == "core" else record.subject
                if record.available:
                    terminal.warning(
                        f"{label} {record.available_version} available "
                        f"(installed {record.installed_version})"
                    )
                elif record.status == "current":
                    terminal.success(f"{label} {record.installed_version} is current")
                elif record.status == "pinned":
                    terminal.status(f"{label} {record.installed_version} is pinned")
                else:
                    terminal.error(
                        f"{label} could not be checked ({record.error_code or record.status})"
                    )
            if snapshot.available:
                for record in snapshot.available:
                    if record.kind == "core":
                        terminal.status(
                            f"Apply with `letsinfer update --version {record.available_version}`"
                        )
                    else:
                        terminal.status(f"Apply with `letsinfer upgrade {record.subject}`")
    return int(
        (snapshot.busy and not snapshot.records)
        or any(
            record.status in {"unknown", "integrity_error"}
            for record in snapshot.records
        )
    )


def rebind_core_services(_: argparse.Namespace) -> int:
    """Bind existing node services to this core without selecting a runtime."""
    if not site_identity_path().is_file():
        print(f"CORE {PRODUCT_VERSION} services=none runtimes=unchanged")
        return 0
    identity = read_site_identity()
    resident_path = default_service_config_path()
    candidate_path = qualification_service_config_path()
    config_path = candidate_path if candidate_path.is_file() else resident_path
    model = None
    if config_path.is_file():
        previous = read_service_config(config_path)
        model = previous.get("model")
    site_state = _unit_enabled_active(NODE_SERVICE_NAME)
    gateway_state = _unit_enabled_active(GATEWAY_SERVICE_NAME)
    watchdog_state = _unit_enabled_active(SERVICE_NAME)
    if all(
        enabled == "not-found" and active == "inactive"
        for enabled, active in (site_state, gateway_state, watchdog_state)
    ):
        print(f"CORE {PRODUCT_VERSION} services=none runtimes=unchanged")
        return 0
    include_gateway = identity.role == "main"
    runtime_state = install_core_plane_services(
        identity, include_gateway=include_gateway
    )
    wait_for_core_plane_ready(include_gateway=include_gateway)
    runtime = f" runtime={model}" if isinstance(model, str) else ""
    if runtime_state["configured"] and not runtime_state["compatible"]:
        runtime += " runtime_state=incompatible-stopped"
    print(
        f"CORE {PRODUCT_VERSION} services=rebound{runtime} runtimes=unchanged"
    )
    return 0


def _core_artifact_references() -> tuple[set[pathlib.Path], set[str]]:
    control_parent = default_control_parent().resolve(strict=False)
    control_roots: set[pathlib.Path] = set()
    watchdog_identities = {core_watchdog_source_identity()}
    config_paths = [
        default_service_config_path(),
        qualification_service_config_path(),
    ]
    group_root = default_engine_group_root()
    if group_root.is_dir() and not group_root.is_symlink():
        config_paths.extend(sorted(group_root.glob("*/config.json")))
    for path in config_paths:
        if path.is_symlink() or not path.is_file():
            continue
        config = read_json(path)
        source_value = config.get("source_root") or config.get("control_root")
        if isinstance(source_value, str):
            source = pathlib.Path(source_value).expanduser().resolve(strict=False)
            try:
                source.relative_to(control_parent)
            except ValueError:
                pass
            else:
                control_roots.add(source)
    try:
        runtime_receipts = selections()
    except RuntimePackError as error:
        raise LetsInferError(str(error)) from error
    for receipt in runtime_receipts:
        retained = [receipt, *receipt.get("history", [])]
        for record in retained:
            if not isinstance(record, dict):
                continue
            source_value = record.get("control_root")
            if not isinstance(source_value, str):
                continue
            source = pathlib.Path(source_value).expanduser().resolve(strict=False)
            try:
                source.relative_to(control_parent)
            except ValueError:
                continue
            control_roots.add(source)
    return control_roots, watchdog_identities


def _core_user_artifact_prune_plan() -> dict[str, list[pathlib.Path]]:
    active_controls, active_manifests = _core_artifact_references()
    stale_controls: list[pathlib.Path] = []
    control_parent = default_control_parent()
    if control_parent.exists():
        if control_parent.is_symlink() or not control_parent.is_dir():
            raise LetsInferError(f"control bundle storage is unsafe: {control_parent}")
        for candidate in sorted(control_parent.iterdir()):
            resolved_candidate = candidate.resolve(strict=False)
            if resolved_candidate in active_controls or candidate.name.startswith("."):
                continue
            if candidate.is_symlink() or not candidate.is_dir():
                raise LetsInferError(f"control bundle entry is unsafe: {candidate}")
            if not SHA256_RE.fullmatch(candidate.name):
                continue
            runtime_manifest = candidate / "runtime-execution.json"
            if runtime_manifest.is_symlink() or not runtime_manifest.is_file():
                raise LetsInferError(
                    f"stale control bundle has no trusted runtime manifest: {candidate}"
                )
            manifest_sha = sha256_file(runtime_manifest)
            validate_control_bundle(candidate, runtime_manifest, manifest_sha)
            stale_controls.append(candidate)

    stale_watchdogs: list[pathlib.Path] = []
    watchdog_parent = default_watchdog_runtime_parent()
    if watchdog_parent.exists():
        if watchdog_parent.is_symlink() or not watchdog_parent.is_dir():
            raise LetsInferError(f"Watchdog runtime storage is unsafe: {watchdog_parent}")
        for candidate in sorted(watchdog_parent.iterdir()):
            if candidate.name in active_manifests or candidate.name.startswith("."):
                continue
            if candidate.is_symlink() or not candidate.is_dir():
                raise LetsInferError(f"Watchdog runtime entry is unsafe: {candidate}")
            if not SHA256_RE.fullmatch(candidate.name):
                continue
            verify_watchdog_runtime(candidate, candidate.name)
            stale_watchdogs.append(candidate)
    return {
        "control_bundles": stale_controls,
        "watchdog_runtimes": stale_watchdogs,
    }


def _prune_core_user_artifacts(*, dry_run: bool) -> dict[str, list[str]]:
    plan = _core_user_artifact_prune_plan()
    if not dry_run:
        for paths in plan.values():
            for path in paths:
                shutil.rmtree(path)
    return {
        name: [str(path) for path in paths]
        for name, paths in plan.items()
    }


def prune_core_command(arguments: argparse.Namespace) -> int:
    """Remove only superseded, fully validated core identities and bundles."""

    root = source_root().resolve(strict=True)
    if not (root / CORE_SOURCE_MANIFEST).is_file():
        raise LetsInferError("core pruning must run from an immutable installation")
    helper = root / "bin/letsinfer-prune-core"
    if helper.is_symlink() or not helper.is_file():
        raise LetsInferError("installed core pruning helper is unavailable")
    base_command = [
        str(helper),
        "--active-source",
        str(root),
        "--letsinfer-home",
        str(letsinfer_home_root()),
    ]
    plan_command = [*base_command, "--dry-run"]
    planned = run(plan_command)
    try:
        core_plan = json.loads(planned.stdout)
    except json.JSONDecodeError as error:
        raise LetsInferError("core pruning helper returned invalid data") from error
    user_plan = _prune_core_user_artifacts(dry_run=True)
    if not arguments.dry_run:
        _prune_core_user_artifacts(dry_run=False)
        run_passthrough([*base_command, "--quiet"])
    payload = {
        "schema_version": 1,
        "dry_run": arguments.dry_run,
        "active_source": str(root),
        "core_identities": core_plan["remove"],
        **user_plan,
    }
    if not arguments.quiet:
        if arguments.json:
            print(json.dumps(payload, sort_keys=True))
        else:
            total = sum(
                len(payload[name])
                for name in (
                    "core_identities",
                    "control_bundles",
                    "watchdog_runtimes",
                )
            )
            action = "WOULD PRUNE" if arguments.dry_run else "PRUNED"
            print(f"{action} superseded core artifacts={total}")
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
    try:
        ensure_letsinfer_home()
    except PathContractError as error:
        raise LetsInferError(str(error)) from error
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
    if identity.role == "child":
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
        presenter = None
        if arguments.json:
            print(json.dumps(value, sort_keys=True))
        else:
            presenter = _human_presenter()
            if presenter is not None:
                presenter.records(
                    (
                        command_ui.RecordRow(
                            "Node",
                            identity.display_name,
                            identity.site_id,
                            command_ui.Semantic.SUCCESS,
                        ),
                        command_ui.RecordRow("Role", identity.role),
                        command_ui.RecordRow("Machine", identity.member_id),
                    )
                )
            else:
                print(
                    f"NODE {identity.display_name} id={identity.site_id} "
                    f"role={identity.role} machine={identity.member_id}"
                )
        if facts_error is not None:
            if presenter is not None:
                presenter.result(
                    "Node facts will retry through the node service",
                    semantic=command_ui.Semantic.WARNING,
                    detail=str(facts_error),
                )
            else:
                print(
                    "WARNING child facts will retry through the node service: "
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
        presenter = _human_presenter()
        if presenter is not None:
            presenter.records(
                (
                    command_ui.RecordRow(
                        "Node",
                        identity.display_name,
                        identity.site_id,
                        command_ui.Semantic.SUCCESS,
                    ),
                    command_ui.RecordRow("Role", identity.role),
                    command_ui.RecordRow("Machine", identity.member_id),
                    command_ui.RecordRow("API", value["inference_endpoint"]),
                )
            )
            presenter.verbatim(
                local_key_path,
                label="Private API key",
                copyable=True,
            )
        else:
            print(
                f"NODE {identity.display_name} id={identity.site_id} "
                f"role={identity.role} machine={identity.member_id}"
            )
            print(f"API key stored privately at {local_key_path}")
            print(f"API endpoint {value['inference_endpoint']}")
    return 0


def site_status_command(arguments: argparse.Namespace) -> int:
    try:
        identity = read_site_identity()
        value = identity_json(identity)
        if identity.role == "main":
            with SiteStore(identity=identity) as store:
                value["machines"] = [
                    dict(row)
                    for row in store.connection.execute(
                        "SELECT member_id,display_name,role,address,state,updated_at_unix "
                        "FROM members WHERE state != 'removed' ORDER BY role,member_id"
                    )
                ]
                value["audit"] = store.verify_audit()
        else:
            value["machines"] = None
            value["audit"] = None
    except SiteError as error:
        raise LetsInferError(str(error)) from error
    if arguments.json:
        print(json.dumps(value, sort_keys=True))
    else:
        presenter = _human_presenter()
        if presenter is not None:
            presenter.records(
                (
                    command_ui.RecordRow(
                        "Node",
                        value["display_name"],
                        value["role"],
                        command_ui.Semantic.SUCCESS,
                    ),
                    command_ui.RecordRow("Node ID", value["node_id"]),
                    command_ui.RecordRow("Machine", value["machine_id"]),
                    command_ui.RecordRow(
                        "Main", value["main_id"], value["main_address"]
                    ),
                )
            )
        else:
            print(
                f"{value['display_name']}\t{value['role']}\t"
                f"node={value['node_id']}\tmachine={value['machine_id']}\t"
                f"main={value['main_id']}@{value['main_address']}"
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
                "node.move", identity.site_id, "success", "plan_only"
            )
        if arguments.json:
            print(json.dumps(document, sort_keys=True))
        else:
            presenter = _human_presenter()
            if presenter is not None:
                presenter.object(document, title="Node move plan")
            else:
                print(json.dumps(document, sort_keys=True, indent=2))
        return 0
    if arguments.source_site_id != identity.site_id:
        raise LetsInferError("--source-node-id must exactly confirm the current node")
    if plan.blocking_reasons:
        raise LetsInferError("node move is blocked: " + "; ".join(plan.blocking_reasons))
    required = {
        "endpoint": arguments.endpoint,
        "invite": arguments.invite,
        "main certificate": arguments.coordinator_certificate_sha256,
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        raise LetsInferError("node move requires " + ", ".join(missing))
    code = arguments.code
    if code is None:
        try:
            code = command_ui.CommandUI(sys.stderr).prompt.secret(
                "Destination membership code",
                require_tty=True,
            )
        except (command_ui.PromptUnavailable, KeyboardInterrupt) as error:
            raise LetsInferError("node move code entry was cancelled") from error
    code = re.sub(r"[- ]", "", code)
    if re.fullmatch(r"[0-9]{8}", code) is None:
        raise LetsInferError("destination membership code must contain eight digits")

    prior_units: dict[str, tuple[str, str]] = {}
    prior_unit_files: dict[str, tuple[str, int] | None] = {}
    if not arguments.no_service:
        if platform.system().lower() != "linux":
            raise LetsInferError("persistent node moves require Linux user systemd")
        if not user_lingering_enabled():
            raise LetsInferError("user-systemd lingering is required before a node move")
        for unit in (
            SERVICE_NAME,
            NODE_SERVICE_NAME,
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
                "node move requires inference and gateway services to be stopped first: "
                + ",".join(active_work)
            )

    with _site_store() as store:
        store.record_action(
            "node.move",
            str(arguments.endpoint),
            "success",
            "source_authorized_membership_replacement",
        )
    try:
        if not arguments.no_service:
            for unit in (RECOVERY_TIMER_NAME, NODE_SERVICE_NAME, SERVICE_NAME):
                if prior_units[unit][1] == "active":
                    run_passthrough(["systemctl", "--user", "stop", unit])
        moving = _command_activity(
            arguments, "Joining the destination node", action_id="node.move"
        )
        with moving, ui.protect_stdout(moving):
            with LocalMoveTransaction(identity) as transaction:
                enrollment = join_site(
                    str(arguments.endpoint),
                    invite_id=str(arguments.invite),
                    code=code,
                    coordinator_certificate_sha256=str(
                        arguments.coordinator_certificate_sha256
                    ),
                    member_name=arguments.name or socket.gethostname(),
                    member_address=(
                        arguments.address
                        or socket.getfqdn()
                        or socket.gethostname()
                    ),
                )
                if not arguments.no_service:
                    ensure_core_watchdog_tls()
                    install_node_service_only()
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
                    "node move failed and service rollback was incomplete: "
                    + "; ".join(rollback_errors)
                ) from failure
        raise

    result = identity_json(replacement)
    result.update(
        {
            "source_node_id": identity.site_id,
            "child_state": enrollment.state,
            "approval_expires_at_unix": enrollment.approval_expires_at_unix,
            "comparison_code": enrollment.comparison_code,
        }
    )
    if arguments.json:
        print(json.dumps(result, sort_keys=True))
    else:
        presenter = _human_presenter()
        if presenter is not None:
            presenter.records(
                (
                    command_ui.RecordRow(
                        "Node move",
                        "Complete",
                        semantic=command_ui.Semantic.SUCCESS,
                    ),
                    command_ui.RecordRow("Source", identity.site_id),
                    command_ui.RecordRow("Destination", replacement.site_id),
                    command_ui.RecordRow("Child", replacement.member_id),
                    command_ui.RecordRow("State", enrollment.state),
                )
            )
            if enrollment.comparison_code is not None:
                presenter.verbatim(
                    enrollment.comparison_code,
                    label="Comparison code",
                    copyable=True,
                )
        else:
            print(
                f"MOVED source={identity.site_id} destination={replacement.site_id} "
                f"child={replacement.member_id} state={enrollment.state}"
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
    if identity.role != "main":
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
        presenter = _human_presenter()
        if presenter is not None:
            rendered = [
                {
                    **row,
                    "_semantic": (
                        command_ui.Semantic.SUCCESS
                        if row["state"] == "active"
                        else command_ui.Semantic.WARNING
                    ),
                }
                for row in rows
            ]
            presenter.table(
                (
                    command_ui.TableColumn("display_name", "NAME", min_width=8),
                    command_ui.TableColumn("role", "ROLE", min_width=5),
                    command_ui.TableColumn("state", "STATE", min_width=7),
                    command_ui.TableColumn("address", "ADDRESS", min_width=10),
                    command_ui.TableColumn("member_id", "MEMBER", min_width=10),
                ),
                rendered,
                empty_message="No nodes are connected",
            )
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
    if arguments.json:
        print(json.dumps(candidate, sort_keys=True))
    else:
        presenter = _human_presenter()
        if presenter is not None:
            presenter.object(candidate, title="Prepared node identity")
        else:
            print(json.dumps(candidate, sort_keys=True, indent=2))
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
                code = command_ui.CommandUI(sys.stderr).prompt.secret(
                    "Membership code",
                    require_tty=True,
                )
            except (command_ui.PromptUnavailable, KeyboardInterrupt) as error:
                raise LetsInferError("membership code entry was cancelled") from error
        code = re.sub(r"[- ]", "", code)
        if re.fullmatch(r"[0-9]{8}", code) is None:
            raise LetsInferError("membership code must contain eight digits")
    joining = _command_activity(arguments, action_id="child.join")
    with joining, ui.protect_stdout(joining):
        try:
            enrollment = join_site(
                arguments.endpoint,
                invite_id=arguments.invite,
                code=code,
                coordinator_certificate_sha256=(
                    arguments.coordinator_certificate_sha256
                ),
                member_name=arguments.name or socket.gethostname(),
                member_address=(
                    arguments.address or socket.getfqdn() or socket.gethostname()
                ),
            )
        except (ControlError, SiteError) as error:
            raise LetsInferError(str(error)) from error
        if not arguments.no_service:
            ensure_core_watchdog_tls()
            install_node_service_only()
            install_core_watchdog_service(enrollment.identity)
    identity = enrollment.identity
    value = identity_json(identity)
    value["child_state"] = enrollment.state
    value["approval_expires_at_unix"] = enrollment.approval_expires_at_unix
    value["comparison_code"] = enrollment.comparison_code
    if arguments.json:
        print(json.dumps(value, sort_keys=True))
    else:
        label = "JOINED" if enrollment.state == "active" else "PENDING"
        presenter = _human_presenter()
        if presenter is not None:
            presenter.records(
                (
                    command_ui.RecordRow(
                        "State",
                        label.title(),
                        semantic=(
                            command_ui.Semantic.SUCCESS
                            if enrollment.state == "active"
                            else command_ui.Semantic.WARNING
                        ),
                    ),
                    command_ui.RecordRow("Node", identity.display_name, identity.site_id),
                    command_ui.RecordRow("Member", identity.member_id),
                    command_ui.RecordRow(
                        "Main",
                        identity.coordinator_id,
                        identity.coordinator_address,
                    ),
                )
            )
        else:
            print(
                f"{label} {identity.display_name} node={identity.site_id} "
                f"child={identity.member_id} main="
                f"{identity.coordinator_id}@{identity.coordinator_address}"
            )
        if enrollment.comparison_code is not None:
            if presenter is not None:
                presenter.result(
                    "Compare this code on both devices",
                    semantic=command_ui.Semantic.WARNING,
                    detail=enrollment.comparison_code,
                )
            else:
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
    invite["main_certificate_sha256"] = certificate_sha256(
        site_member_certificate_path()
    )
    if arguments.json:
        print(json.dumps(invite, sort_keys=True))
    else:
        presenter = _human_presenter()
        if presenter is not None:
            presenter.records(
                (
                    command_ui.RecordRow("Invite", invite["invite_id"]),
                    command_ui.RecordRow("Mode", invite["mode"]),
                    command_ui.RecordRow("Expires", invite["expires_at_unix"]),
                    command_ui.RecordRow("Endpoint", invite["endpoint"]),
                )
            )
        else:
            print(
                f"INVITE {invite['invite_id']} mode={invite['mode']} "
                f"expires={invite['expires_at_unix']}"
            )
        if invite["code"] is not None:
            if presenter is not None:
                presenter.verbatim(
                    invite["code"],
                    label="Membership code",
                    copyable=True,
                )
            else:
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
        presenter = _human_presenter()
        if presenter is not None:
            presenter.result(
                "Node approved",
                semantic=command_ui.Semantic.SUCCESS,
                detail=result["member_id"],
            )
        else:
            print(f"APPROVED {result['member_id']}")
    return 0


def _site_control_endpoint(address: str) -> str:
    if "://" in address:
        return address
    if address.startswith("["):
        parsed = urllib.parse.urlsplit(f"https://{address}")
        return (
            f"https://{address}"
            if parsed.port is not None
            else f"https://{address}:{SITE_CONTROL_PORT}"
        )
    if address.count(":") == 1:
        _host, separator, port = address.rpartition(":")
        if separator and port.isdecimal():
            return f"https://{address}"
    host = f"[{address}]" if ":" in address else address
    return f"https://{host}:{SITE_CONTROL_PORT}"


def member_sync_command(arguments: argparse.Namespace) -> int:
    result = _synchronize_member_facts()
    if arguments.json:
        print(json.dumps(result, sort_keys=True))
    if result["failed"]:
        with _site_store() as store:
            store.record_action(
                "child.sync", "child.sync", "failed", "child_control_unavailable"
            )
        raise LetsInferError(
            "one or more child nodes could not publish authenticated facts: "
            + ", ".join(result["failed"])
        )
    if not arguments.json:
        presenter = _human_presenter()
        if presenter is not None:
            presenter.result(
                f"Refreshed {len(result['refreshed'])} node(s)",
                semantic=command_ui.Semantic.SUCCESS,
            )
        else:
            print(f"SYNCED {len(result['refreshed'])} machine(s)")
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
                    origin_interface="child-control",
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
    if arguments.json:
        print(json.dumps(result, sort_keys=True))
    else:
        presenter = _human_presenter()
        if presenter is not None:
            presenter.result(
                "Node removed",
                semantic=command_ui.Semantic.SUCCESS,
                detail=arguments.member,
            )
        else:
            print(f"REMOVED {arguments.member}")
    return 0


def member_drain_command(arguments: argparse.Namespace) -> int:
    with _site_store() as store:
        try:
            result = store.set_member_draining(arguments.member, True)
        except SiteError as error:
            raise LetsInferError(str(error)) from error
    if arguments.json:
        print(json.dumps(result, sort_keys=True))
    else:
        presenter = _human_presenter()
        if presenter is not None:
            presenter.result(
                "Node is draining",
                semantic=command_ui.Semantic.WARNING,
                detail=arguments.member,
            )
        else:
            print(f"DRAINING {arguments.member}")
    return 0


def member_resume_command(arguments: argparse.Namespace) -> int:
    with _site_store() as store:
        try:
            result = store.set_member_draining(arguments.member, False)
        except SiteError as error:
            raise LetsInferError(str(error)) from error
    if arguments.json:
        print(json.dumps(result, sort_keys=True))
    else:
        presenter = _human_presenter()
        if presenter is not None:
            presenter.result(
                "Node is active",
                semantic=command_ui.Semantic.SUCCESS,
                detail=arguments.member,
            )
        else:
            print(f"ACTIVE {arguments.member}")
    return 0


def _engine_group_path(group_id: str) -> pathlib.Path:
    if not re.fullmatch(r"[0-9a-f]{32}", group_id):
        raise LetsInferError("engine-group identity is invalid")
    return default_engine_group_root() / group_id


def _engine_group_member_host(group: Mapping[str, Any], member_id: str) -> str:
    matches = [item for item in group["resources"] if item["node_id"] == member_id]
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
        "task", "group_file", "credential_file", "tls_certificate_file",
        "tls_key_file", "model_cache", "store_root",
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
    """Install and run one bounded runtime task without arbitrary commands."""

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
            or job["task"] != config["task"]
            or job["group"] != config["_group"]
        ):
            raise LetsInferError("engine-group job differs from the staged immutable configuration")

    def _safe_result(self, config: Mapping[str, Any], state: str) -> dict[str, Any]:
        task = config["task"]
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
            "task_id": task["task_id"],
            "runtime_digest": config["runtime_digest"],
            "manifest_sha256": config["manifest_sha256"],
            "tls_certificate_sha256": certificate_sha256(certificate_path),
            "tls_certificate_pem": certificate_pem,
        }
        if task["endpoint_owner"]:
            endpoint_host = f"[{host}]" if ":" in host else host
            result["endpoint"] = f"https://{endpoint_host}:{task['port_base']}"
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
                qualified=True,
                requested_runtime=None,
            )
            if (
                receipt["digest"] != job["runtime_digest"]
                or sha256_file(manifest_path) != job["manifest_sha256"]
            ):
                raise LetsInferError("engine-group runtime or manifest identity differs from its job")
            runtime_root = pathlib.Path(receipt["object_root"])
            runtime = verify_descriptor(runtime_root)
            contract = validate_target_binding(
                runtime.runtime.get("orchestration"),
                target_contract(manifest)["placement"],
            )
            task = job["task"]
            expected_task = (
                {
                    "task_id": "task-0",
                    "port_count": 1,
                    "launcher": "manifest",
                    "environment": {},
                    "readiness": {"kind": "manifest"},
                }
                if contract is None and task.get("task_id") == "task-0"
                else None
                if contract is None
                else next(
                    (item for item in contract["tasks"] if item["task_id"] == task.get("task_id")),
                    None,
                )
            )
            expected_job_task = None if expected_task is None else {
                "task_id": task["task_id"],
                "port_base": task["port_base"],
                "port_count": expected_task["port_count"],
                "launcher": expected_task["launcher"],
                "command": list(expected_task.get("command", [])),
                "environment": dict(expected_task["environment"]),
                "endpoint_owner": task["task_id"] == (
                    "task-0" if contract is None else contract["endpoint_owner"]
                ),
                "readiness": dict(expected_task["readiness"]),
                "device_uuids": list(task["device_uuids"]),
            }
            if expected_job_task != task:
                raise LetsInferError("engine-group job task differs from the runtime contract")
            group = validate_group_document(dict(job["group"]))
            placement = target_contract(manifest)["placement"]
            if (
                group["strategy"] != placement["strategy"]
                or len(group["resources"]) != placement["node_count"]
                or group["runtime_execution_contract_sha256"]
                != orchestration_contract_sha256(contract)
                or len(task["device_uuids"])
                != target_contract(manifest)["accelerator"]["count"]
            ):
                raise LetsInferError("engine-group plan differs from the release target")
            model_cache = default_model_cache_root()
            ensure_install_dependencies(
                manifest,
                model_cache=model_cache,
                runtime_artifact_root=runtime_root,
                download=True,
                build_image=True,
            )
            verify_installed_runtime(
                manifest, model_cache=model_cache
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
                "runtime_name": runtime.runtime["id"],
                "runtime_version": runtime.runtime["version"],
                "object_root": str(runtime_root),
                "control_root": str(control_root),
                "manifest_path": str(manifest_path),
                "manifest_sha256": job["manifest_sha256"],
                "topology_sha256": job["topology_sha256"],
                "task": dict(job["task"]),
                "group_file": str(group_file),
                "credential_file": str(credential_file),
                "tls_certificate_file": str(tls_certificate),
                "tls_key_file": str(tls_key),
                "model_cache": str(model_cache),
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
        task = config["task"]
        authorize_serving_launch(
            manifest["serving"], qualification_mode=False, evidence_dir=None
        )
        verify_host_target(manifest)
        runtime_root = pathlib.Path(config["object_root"])
        ensure_image(manifest, build=False, pull=False, artifact_root=runtime_root)
        verify_installed_runtime(
            manifest,
            model_cache=pathlib.Path(config["model_cache"]),
        )
        require_memory_reserve(manifest, phase="launch")
        command = docker_command(
            manifest,
            name=config["container_name"],
            manifest_sha256=config["manifest_sha256"],
            runtime_digest=config["runtime_digest"],
            port=task["port_base"],
            model_cache=pathlib.Path(config["model_cache"]),
            store_root=pathlib.Path(config["store_root"]),
            runtime_cache_root=pathlib.Path(config["runtime_cache_root"]),
            api_key_file=pathlib.Path(config["credential_file"]),
            tls_cert_file=pathlib.Path(config["tls_certificate_file"]),
            tls_key_file=pathlib.Path(config["tls_key_file"]),
            group_context={
                "group_id": config["group_id"],
                "member_id": config["member_id"],
                **dict(task),
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
                    task["port_base"],
                    manifest_sha256=config["manifest_sha256"],
                    runtime_digest=config["runtime_digest"],
                )
                labels = inspection.get("Config", {}).get("Labels") or {}
                expected_labels = {
                    GROUP_ID_LABEL: config["group_id"],
                    GROUP_NODE_LABEL: config["member_id"],
                    GROUP_TASK_LABEL: task["task_id"],
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
            if task["launcher"] == "manifest":
                wait_for_ready(
                    config["container_name"],
                    task["port_base"],
                    manifest["container"]["startup_timeout_seconds"],
                    pathlib.Path(config["tls_certificate_file"]),
                    manifest,
                )
            else:
                self._wait_runtime_command(config["container_name"], task["readiness"])
            if task["endpoint_owner"] and not model_identity_ready(
                manifest,
                task["port_base"],
                pathlib.Path(config["tls_certificate_file"]),
                pathlib.Path(config["credential_file"]),
            ):
                raise LetsInferError("engine-group model identity does not match its release")
            if task["endpoint_owner"] and task["launcher"] == "manifest":
                prewarm(
                    manifest,
                    config["container_name"],
                    task["port_base"],
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
                disarm_before_planned_stop(protection)
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
        if group.get("task") != config["task"]:
            raise LetsInferError(
                "engine-group observation task differs from staged state"
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
        task = config["task"]
        if task["launcher"] == "manifest":
            ready = health_ready(
                task["port_base"], pathlib.Path(config["tls_certificate_file"])
            )
        else:
            ready = run(
                [
                    "docker", "exec", config["container_name"],
                    *task["readiness"]["command"],
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
        disarm_before_planned_stop(protection)
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
    if identity.role != "main":
        raise LetsInferError("node link renewal runs on the main node")
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
            raise LetsInferError(f"child {subject_id} link facts are invalid")
        for link in links:
            if not isinstance(link, dict):
                raise LetsInferError(f"child {subject_id} link facts are invalid")
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
    state: SiteControlState, sample: Mapping[str, Any], member_id: str
) -> None:
    try:
        state.accept_local_telemetry(sample, requester_member_id=member_id)
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


def _gateway_group_activity() -> dict[str, Any] | None:
    """Read the gateway's atomic dynamic group snapshot without trusting links."""
    path = default_gateway_group_telemetry_path()
    try:
        details = path.lstat()
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != os.getuid()
            or details.st_mode & 0o022
            or details.st_size < 2
            or details.st_size > 1024 * 1024
        ):
            return None
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            raw = os.read(descriptor, 1024 * 1024 + 1)
        finally:
            os.close(descriptor)
        value = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "unix_ms", "models", "groups"}
        or value.get("schema_version") != 1
        or not isinstance(value.get("unix_ms"), int)
        or isinstance(value.get("unix_ms"), bool)
        or not isinstance(value.get("models"), dict)
        or not isinstance(value.get("groups"), dict)
        or not 0 <= int(time.time() * 1000) - value["unix_ms"] <= 5_000
    ):
        return None
    for placement_id, row in value["groups"].items():
        if (
            not isinstance(placement_id, str)
            or not ID_RE.fullmatch(placement_id)
            or not isinstance(row, dict)
            or not isinstance(row.get("active_requests"), int)
            or isinstance(row.get("active_requests"), bool)
            or row["active_requests"] < 0
        ):
            return None
    for model, row in value["models"].items():
        if (
            not isinstance(model, str)
            or not model
            or not isinstance(row, dict)
            or not isinstance(row.get("queued_requests"), int)
            or isinstance(row.get("queued_requests"), bool)
            or row["queued_requests"] < 0
        ):
            return None
    return value


def node_agent_command(arguments: argparse.Namespace) -> int:
    identity = read_site_identity()
    link_store = LinkStore(identity)
    telemetry = TelemetryAggregator() if identity.role == "main" else None
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
            "node.move.commit", {"move": {"move_id": result.get("move_id")}}
        )

    state = SiteControlState(
        identity,
        facts_provider=local_facts,
        link_store=link_store,
        telemetry=telemetry,
        member_agent=member_agent,
        adoption_provider=(adopt_fresh_member if identity.role == "main" else None),
        adoption_completed_provider=(
            adoption_completed if identity.role == "main" else None
        ),
    )

    def controller_site_document() -> dict[str, Any]:
        if telemetry is None:
            raise ControllerError("node aggregation is available only on the main node")
        with _site_store() as store:
            rows = store.members()
            placements = store.placements()
            model_services = store.model_services()
            engine_groups = store.engine_groups()
            allocations = store.device_allocations(active_only=True)
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
        safe_placements: list[dict[str, Any]] = []
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
        placements_by_id = {
            placement["placement_id"]: placement for placement in safe_placements
        }
        allocations_by_group: dict[str, list[dict[str, Any]]] = {}
        for allocation in allocations:
            allocations_by_group.setdefault(allocation["group_id"], []).append(
                {
                    "machine_id": allocation["member_id"],
                    "device_uuid": allocation["device_uuid"],
                    "state": allocation["state"],
                }
            )
        activity = _gateway_group_activity()
        group_activity = activity["groups"] if activity is not None else {}
        model_activity = activity["models"] if activity is not None else {}
        groups_by_service: dict[str, list[dict[str, Any]]] = {}
        for group in engine_groups:
            placement = placements_by_id.get(group["placement_id"])
            if placement is None or group["state"] == "removed":
                continue
            release = group["plan"].get("release")
            service_id = group["plan"].get("service_id")
            if not isinstance(service_id, str) or not isinstance(release, dict):
                raise ControllerError("engine-group service identity is incomplete")
            groups_by_service.setdefault(service_id, []).append(
                {
                    **placement,
                    "group_id": group["group_id"],
                    "release": release,
                    "failure_policy": group["failure_policy"],
                    "endpoint_owner": group["plan"]["endpoint_owner"],
                    "runtime_execution_contract_sha256": group[
                        "runtime_execution_contract_sha256"
                    ],
                    "resource_assignments": group["plan"]["resources"],
                    "connections": group["plan"]["connections"],
                    "task_states": [
                        {
                            "node_id": task["member_id"],
                            "task_id": task["task_id"],
                            "state": task["state"],
                            "error": task["error"],
                        }
                        for task in group["members"]
                    ],
                    "device_allocations": allocations_by_group.get(
                        group["group_id"], []
                    ),
                    "desired_state": group["desired_state"],
                    "last_error": group["last_error"],
                    "telemetry": group_activity.get(group["placement_id"]),
                }
            )
        services = [
            {
                **service,
                "groups": sorted(
                    groups_by_service.get(service["service_id"], []),
                    key=lambda group: group["group_id"],
                ),
                "telemetry": {
                    "active_requests": sum(
                        int(
                            (group_activity.get(group["placement_id"]) or {}).get(
                                "active_requests", 0
                            )
                        )
                        for group in groups_by_service.get(service["service_id"], [])
                    ),
                    "queued_requests": int(
                        (model_activity.get(service["model"]) or {}).get(
                            "queued_requests", 0
                        )
                    ),
                    "available": activity is not None,
                },
            }
            for service in model_services
            if service["desired_state"] != "removed"
        ]
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
            "schema_version": 2,
            "identity": identity_json(identity),
            "machines": members,
            "topology": topology_document,
            "services": services,
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
    if identity.role == "main":
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
        if identity.role == "main" and direct_connectx:
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
            watchdog_port=WATCHDOG_TELEMETRY_PORT,
            watchdog_ca_file=default_watchdog_controller_ca_path(),
            watchdog_controller_cert_file=default_watchdog_local_controller_cert_path(),
            watchdog_controller_key_file=default_watchdog_local_controller_key_path(),
            local_accept=(
                lambda sample, member_id: _accept_local_telemetry(
                    state, sample, member_id
                )
            )
            if identity.role == "main"
            else None,
            endpoint=(
                None
                if identity.role == "main"
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
            if identity.role == "main"
            else None,
            endpoint=(
                None
                if identity.role == "main"
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
    telemetry_failed: list[str] = []
    orchestration_failed: list[str] = []
    link_monitor_failed: list[str] = []
    update_poller = UpdatePoller(_update_manager(), stop=stopped)
    update_poller.start()

    def monitor_site_links() -> None:
        if identity.role != "main":
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
        if identity.role != "main":
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
            if not telemetry_publisher.alive():
                telemetry_failed.append(
                    telemetry_publisher.last_error
                    or "telemetry publisher exited unexpectedly"
                )
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
        update_poller.join(timeout=2)
        member_agent.close()
    if publisher_failed:
        raise LetsInferError("DNS-SD publisher exited while the node agent was active")
    if telemetry_failed:
        raise LetsInferError(
            "Watchdog telemetry publisher exited while the node agent was active: "
            + telemetry_failed[-1]
        )
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
    if arguments.json:
        print(json.dumps(document, sort_keys=True))
    else:
        presenter = _human_presenter()
        if presenter is not None:
            presenter.object(document, title="Verified topology")
        else:
            print(json.dumps(document, sort_keys=True, indent=2))
    return 0


def _topology_plan_document(
    model: str,
    runtime: str | None,
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
        catalog = CatalogManager(location).load().document
    except (CatalogError, RuntimePackError) as error:
        raise LetsInferError(str(error)) from error
    topology = _fresh_site_topology()
    release, choice = _catalog_site_release(
        catalog, model, runtime, topology=topology
    )
    target_id, target_sha256, selected_runtime, version, source = release
    selected_engine = catalog_release_record(
        catalog, model, target_id, selected_runtime, version
    )["engine"]
    identity, graph = topology
    source_digest = source.rsplit("@sha256:", 1)[1]
    desired_runtime = (
        f"{selected_runtime}@{version}"
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
        "runtime_candidate": selected_runtime,
        "runtime_version": version,
        "runtime_identity": desired_runtime,
        "runtime_source": source,
        "target": target_id,
        "target_contract_sha256": target_sha256,
        "topology_sha256": graph.sha256(),
        "placement": {
            "strategy": choice.placement.strategy,
            "members": desired_members,
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
                "schema_version", "site_id", "model", "engine", "runtime_candidate", "runtime_version",
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
        arguments.model, arguments.runtime, arguments.catalog
    )
    if arguments.json:
        print(json.dumps(document, sort_keys=True))
    else:
        presenter = _human_presenter()
        if presenter is not None:
            presenter.records(
                (
                    command_ui.RecordRow("Model", document["model"]),
                    command_ui.RecordRow("Engine", document["engine"]),
                    command_ui.RecordRow("Target", document["target"]),
                    command_ui.RecordRow(
                        "Placement",
                        document["placement"]["strategy"],
                        ", ".join(document["placement"]["members"]),
                    ),
                    command_ui.RecordRow(
                        "Change",
                        "Required" if document["change_required"] else "None",
                        semantic=(
                            command_ui.Semantic.WARNING
                            if document["change_required"]
                            else command_ui.Semantic.SUCCESS
                        ),
                    ),
                    command_ui.RecordRow("Plan", document["plan_id"] or "None"),
                )
            )
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
    with _command_step_progress(arguments) as progress:
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
            raise LetsInferError(
                f"topology link member is not active: {error.args[0]}"
            ) from error
        progress.advance()

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
        progress.advance()

        synchronized = _synchronize_member_facts()
        if synchronized["failed"]:
            raise LetsInferError(
                "link proof succeeded but authenticated fact refresh failed for: "
                + ",".join(synchronized["failed"])
            )
        progress.advance()
    result = {"links": links, "refreshed": synchronized["refreshed"]}
    if arguments.json:
        print(json.dumps(result, sort_keys=True))
    else:
        presenter = _human_presenter()
        if presenter is not None:
            presenter.object(result, title="Verified links")
        else:
            print(json.dumps(result, sort_keys=True, indent=2))
    return 0


def alias_list_command(arguments: argparse.Namespace) -> int:
    with _site_store() as store:
        aliases = store.aliases()
    if arguments.json:
        print(json.dumps(aliases, sort_keys=True))
    else:
        presenter = _human_presenter()
        if presenter is not None:
            presenter.table(
                (
                    command_ui.TableColumn("alias", "ALIAS", min_width=8),
                    command_ui.TableColumn("model", "MODEL", min_width=12),
                ),
                [
                    {"alias": alias, "model": model}
                    for alias, model in sorted(aliases.items())
                ],
                empty_message="No model aliases are configured",
            )
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
    if arguments.json:
        print(json.dumps(value, sort_keys=True))
    else:
        presenter = _human_presenter()
        if presenter is not None:
            presenter.result(
                f"Alias {value['alias']} saved",
                semantic=command_ui.Semantic.SUCCESS,
                detail=value["model"],
            )
        else:
            print(f"ALIAS {value['alias']} -> {value['model']}")
    return 0


def alias_remove_command(arguments: argparse.Namespace) -> int:
    with _site_store() as store:
        try:
            value = store.remove_alias(arguments.alias)
        except SiteError as error:
            raise LetsInferError(str(error)) from error
    if arguments.json:
        print(json.dumps(value, sort_keys=True))
    else:
        presenter = _human_presenter()
        if presenter is not None:
            presenter.result(
                f"Alias {value['alias']} removed",
                semantic=command_ui.Semantic.SUCCESS,
            )
        else:
            print(f"REMOVED ALIAS {value['alias']}")
    return 0


def _require_public_gateway() -> dict[str, Any]:
    config_path = site_config_root() / "gateway.json"
    try:
        config = read_json(config_path)
    except (OSError, json.JSONDecodeError) as error:
        raise LetsInferError("the main-node gateway is not configured") from error
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
        raise LetsInferError("the main-node gateway configuration is not public-edge safe")
    _, active = _unit_enabled_active(GATEWAY_SERVICE_NAME)
    if active != "active":
        raise LetsInferError("the main-node gateway must be active before exposure")
    if api_status(8000, "/health", None) != 200:
        raise LetsInferError("the main-node gateway health check failed")
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
        presenter = _human_presenter()
        if presenter is not None:
            presenter.records(
                (
                    command_ui.RecordRow(
                        "State",
                        result["state"].title(),
                        semantic=(
                            command_ui.Semantic.SUCCESS
                            if result["state"] == "enabled" and verified
                            else command_ui.Semantic.WARNING
                        ),
                    ),
                    command_ui.RecordRow("Provider", result["provider"]),
                    command_ui.RecordRow("URL", result["public_url"] or "—"),
                    command_ui.RecordRow(
                        "Verified",
                        "Yes" if verified else "No",
                        semantic=(
                            command_ui.Semantic.SUCCESS
                            if verified
                            else command_ui.Semantic.ERROR
                        ),
                    ),
                )
            )
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
    if arguments.json:
        print(json.dumps(value, sort_keys=True))
    else:
        presenter = _human_presenter()
        if presenter is not None:
            presenter.result(
                "Public inference enabled",
                semantic=command_ui.Semantic.SUCCESS,
                detail=f"{value['public_url']} · {value['provider']}",
            )
        else:
            print(f"EXPOSED {value['public_url']} provider={value['provider']}")
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
    if arguments.json:
        print(json.dumps(value, sort_keys=True))
    else:
        presenter = _human_presenter()
        if presenter is not None:
            presenter.result(
                "Public inference disabled",
                semantic=command_ui.Semantic.SUCCESS,
            )
        else:
            print("PUBLIC INFERENCE DISABLED")
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
        presenter = _human_presenter(sys.stderr)
        if presenter is not None:
            presenter.records(
                (
                    command_ui.RecordRow("Key", metadata["name"]),
                    command_ui.RecordRow("Key ID", metadata["key_id"]),
                )
            )
            presenter.result(
                "This token is shown once",
                semantic=command_ui.Semantic.WARNING,
                detail="Store it securely now",
            )
        else:
            print(
                f"KEY {metadata['name']} id={metadata['key_id']}",
                file=sys.stderr,
            )
            print("This token is shown once. Store it now.", file=sys.stderr)
        # A one-time token is deliberately the only unstyled line.  This keeps
        # it copyable and preserves the redirected stdout contract.
        print(token)
    return 0


def key_list_command(arguments: argparse.Namespace) -> int:
    with _site_store() as store:
        rows = store.keys()
    if arguments.json:
        print(json.dumps(rows, sort_keys=True))
    else:
        rendered = [
            {
                **row,
                "state": "revoked" if row["revoked_at_unix"] is not None else "active",
                "model_text": ",".join(row["models"]) or "*",
                "_semantic": (
                    command_ui.Semantic.WARNING
                    if row["revoked_at_unix"] is not None
                    else command_ui.Semantic.SUCCESS
                ),
            }
            for row in rows
        ]
        presenter = _human_presenter()
        if presenter is not None:
            presenter.table(
                (
                    command_ui.TableColumn("name", "NAME", min_width=8),
                    command_ui.TableColumn("state", "STATE", min_width=7),
                    command_ui.TableColumn("model_text", "MODELS", min_width=8),
                    command_ui.TableColumn("key_id", "KEY ID", min_width=10),
                ),
                rendered,
                empty_message="No API keys are registered",
            )
        else:
            for row in rendered:
                print(
                    f"{row['key_id']}\t{row['name']}\t{row['state']}\t"
                    f"models={row['model_text']}"
                )
    return 0


def key_show_command(arguments: argparse.Namespace) -> int:
    with _site_store() as store:
        try:
            row = store.key(arguments.key)
        except SiteError as error:
            raise LetsInferError(str(error)) from error
    if arguments.json:
        print(json.dumps(row, sort_keys=True))
    else:
        presenter = _human_presenter()
        if presenter is not None:
            presenter.object(row, title="API key policy")
        else:
            print(json.dumps(row, sort_keys=True, indent=2))
    return 0


def key_revoke_command(arguments: argparse.Namespace) -> int:
    with _site_store() as store:
        try:
            row = store.revoke_key(arguments.key)
        except SiteError as error:
            raise LetsInferError(str(error)) from error
    if arguments.json:
        print(json.dumps(row, sort_keys=True))
    else:
        presenter = _human_presenter()
        if presenter is not None:
            presenter.result(
                f"Revoked {row['name']}",
                semantic=command_ui.Semantic.SUCCESS,
                detail=row["key_id"],
            )
        else:
            print(f"REVOKED {row['name']} id={row['key_id']}")
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
        presenter = _human_presenter(sys.stderr)
        if presenter is not None:
            presenter.records(
                (
                    command_ui.RecordRow("Key", row["name"]),
                    command_ui.RecordRow("Key ID", row["key_id"]),
                    command_ui.RecordRow("Replaced", arguments.key),
                )
            )
            presenter.result(
                "This token is shown once",
                semantic=command_ui.Semantic.WARNING,
                detail="Store it securely now",
            )
        else:
            print(
                f"ROTATED {arguments.key} -> {row['name']} id={row['key_id']}",
                file=sys.stderr,
            )
            print("This token is shown once. Store it now.", file=sys.stderr)
        print(token)
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
    if arguments.json:
        print(json.dumps(row, sort_keys=True))
    else:
        presenter = _human_presenter()
        if presenter is not None:
            presenter.object(row, title="Updated API key policy")
        else:
            print(json.dumps(row, sort_keys=True, indent=2))
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
        rendered = [
            {
                **row,
                "timestamp": dt.datetime.fromtimestamp(
                    row["timestamp_unix_ns"] / 1_000_000_000,
                    tz=dt.timezone.utc,
                ).isoformat(),
                "_semantic": (
                    command_ui.Semantic.SUCCESS
                    if row["outcome"] == "success"
                    else command_ui.Semantic.ERROR
                ),
            }
            for row in rows
        ]
        presenter = _human_presenter()
        if presenter is not None:
            presenter.table(
                (
                    command_ui.TableColumn("sequence", "SEQ", min_width=3, align="right"),
                    command_ui.TableColumn("outcome", "RESULT", min_width=7),
                    command_ui.TableColumn("action", "ACTION", min_width=8),
                    command_ui.TableColumn("target", "TARGET", min_width=8),
                    command_ui.TableColumn("timestamp", "TIME", min_width=10),
                ),
                rendered,
                empty_message="The audit chain is empty",
            )
        else:
            for row in rendered:
                print(
                    f"{row['sequence']}\t{row['timestamp']}\t{row['outcome']}\t"
                    f"{row['action']}\t{row['target']}"
                )
    return 0


def audit_show_command(arguments: argparse.Namespace) -> int:
    with _site_store() as store:
        rows = store.audit_rows(event_id=arguments.event)
    if not rows:
        raise LetsInferError(f"audit event is not registered: {arguments.event}")
    if arguments.json:
        print(json.dumps(rows[0], sort_keys=True))
    else:
        presenter = _human_presenter()
        if presenter is not None:
            presenter.object(rows[0], title="Audit event")
        else:
            print(json.dumps(rows[0], sort_keys=True, indent=2))
    return 0


def audit_verify_command(arguments: argparse.Namespace) -> int:
    with _site_store() as store:
        try:
            result = store.verify_audit()
        except SiteError as error:
            raise LetsInferError(str(error)) from error
    if arguments.json:
        print(json.dumps(result, sort_keys=True))
    else:
        presenter = _human_presenter()
        if presenter is not None:
            presenter.records(
                (
                    command_ui.RecordRow(
                        "Audit", "Verified", semantic=command_ui.Semantic.SUCCESS
                    ),
                    command_ui.RecordRow("Events", result["events"]),
                ),
                value_width=22,
            )
            presenter.verbatim(
                f"sha256:{result['head_sha256']}",
                label="Head",
                copyable=True,
            )
        else:
            print(
                f"AUDIT OK events={result['events']} head=sha256:{result['head_sha256']}"
            )
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
            presenter = _human_presenter()
            if presenter is not None:
                presenter.records(
                    (
                        command_ui.RecordRow(
                            "Audit export",
                            "Complete",
                            semantic=command_ui.Semantic.SUCCESS,
                        ),
                        command_ui.RecordRow("Events", count),
                    )
                )
                presenter.verbatim(output, label="Artifact", copyable=True)
            else:
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
                    "this command requires a configured node; run `letsinfer setup` first"
                ) from error
    if identity is not None:
        allowed = (
            metadata.scope is CommandScope.ALL
            or metadata.scope.value == identity.role
        )
        if not allowed:
            reason = (
                f"command scope is {metadata.scope.value}; local role is {identity.role}; "
                f"main={identity.coordinator_id}@{identity.coordinator_address}"
            )
            if identity.role == "main":
                try:
                    with SiteStore(identity=identity) as store:
                        store.record_denied(action_id, action_id, reason)
                except SiteError:
                    pass
            raise LetsInferError(reason)
    return metadata, identity


_HANDLER_AUDITED_ACTIONS = {
    "setup": {"node.setup"},
    "node.move": {"node.move"},
    "pair": {"pair"},
    "controllers.forget": {"controllers.forget"},
    "key.create": {"key.create"},
    "key.rotate": {"key.rotate"},
    "key.revoke": {"key.revoke"},
    "key.policy": {"key.policy"},
    "child.invite": {"child.invite"},
    "child.approve": {"child.approve"},
    "child.sync": {"child.sync"},
    "child.drain": {"child.drain"},
    "child.resume": {"child.resume"},
    "child.remove": {"child.remove"},
    "expose": {"exposure.enable"},
    "unexpose": {"exposure.disable"},
}


def _audit_marker(metadata: Any, identity: Any) -> int | None:
    if (
        identity is None
        or identity.role != "main"
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
            "mandatory node audit is unavailable before command execution"
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
    if identity is None or identity.role != "main":
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
                "command completed but its mandatory node audit event failed"
            ) from error


def parser() -> argparse.ArgumentParser:
    root = ui.ArgumentParser(
        prog="letsinfer",
        description=__doc__,
        epilog="Run `letsinfer COMMAND --help` for command-specific options.",
    )
    subcommands = root.add_subparsers(dest="command", required=True)

    setup = subcommands.add_parser(
        "setup", help=help_label("create this machine's Let's Infer node", "setup")
    )
    setup.add_argument("--name", default="Home")
    setup.add_argument("--address")
    setup.add_argument(
        "--no-service",
        action="store_true",
        help="create a local development identity without a persistent node service",
    )
    setup.add_argument("--json", action="store_true")
    setup.set_defaults(action=setup_command, action_id="setup")

    site_command = subcommands.add_parser(
        "node", help="inspect this Let's Infer node"
    )
    site_operations = site_command.add_subparsers(dest="site_operation", required=True)
    site_show = site_operations.add_parser(
        "status", help=help_label("show node identity and role", "node.status")
    )
    site_show.add_argument("--json", action="store_true")
    site_show.set_defaults(action=site_status_command, action_id="node.status")
    site_move = site_operations.add_parser(
        "move", help=help_label("plan or apply a move into another node", "node.move")
    )
    site_move.add_argument("--apply", action="store_true")
    site_move.add_argument("--source-node-id", dest="source_site_id")
    site_move.add_argument("--endpoint")
    site_move.add_argument("--invite")
    site_move.add_argument(
        "--main-certificate-sha256", dest="coordinator_certificate_sha256"
    )
    site_move.add_argument("--code")
    site_move.add_argument("--name")
    site_move.add_argument("--address")
    site_move.add_argument("--no-service", action="store_true", help=argparse.SUPPRESS)
    site_move.add_argument("--json", action="store_true")
    site_move.set_defaults(action=site_move_command, action_id="node.move")

    topology_group = subcommands.add_parser("topology", help="inspect verified node topology")
    topology_operations = topology_group.add_subparsers(
        dest="topology_operation", required=True
    )
    topology_show = topology_operations.add_parser(
        "show", help=help_label("show verified node topology", "topology.show")
    )
    topology_show.add_argument("--json", action="store_true")
    topology_show.set_defaults(action=topology_command, action_id="topology.show")
    topology_probe = topology_operations.add_parser(
        "probe",
        help=help_label("prove a bidirectional child-node link", "topology.probe"),
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
    topology_plan.add_argument("--runtime", help="select an exact runtime candidate ID")
    topology_plan.add_argument("--catalog")
    topology_plan.add_argument("--json", action="store_true")
    topology_plan.set_defaults(action=topology_plan_command, action_id="topology.plan")

    member_command = subcommands.add_parser("child", help="manage child nodes")
    member_operations = member_command.add_subparsers(dest="member_operation", required=True)
    member_list = member_operations.add_parser(
        "list", help=help_label("list the main and child nodes", "child.list")
    )
    member_list.add_argument("--json", action="store_true")
    member_list.set_defaults(action=member_list_command, action_id="child.list")
    member_prepare = member_operations.add_parser(
        "prepare", help=help_label("create this machine's pending child identity", "child.prepare")
    )
    member_prepare.add_argument("--json", action="store_true")
    member_prepare.set_defaults(action=member_prepare_command, action_id="child.prepare")
    member_join = member_operations.add_parser(
        "join", help=help_label("join an authorized main node as a child", "child.join")
    )
    member_join.add_argument("endpoint")
    member_join.add_argument("--invite", required=True)
    member_join.add_argument(
        "--main-certificate-sha256",
        dest="coordinator_certificate_sha256",
        required=True,
    )
    member_join.add_argument("--code")
    member_join.add_argument("--connectx", action="store_true")
    member_join.add_argument("--name")
    member_join.add_argument("--address")
    member_join.add_argument(
        "--no-service",
        action="store_true",
        help="join for local protocol development without installing the node service",
    )
    member_join.add_argument("--json", action="store_true")
    member_join.set_defaults(action=member_join_command, action_id="child.join")
    member_invite = member_operations.add_parser(
        "invite", help=help_label("authorize one bounded child join", "child.invite")
    )
    member_invite.add_argument("--mode", choices=("lan", "remote", "connectx"), required=True)
    member_invite.add_argument("--candidate-fingerprint")
    member_invite.add_argument("--candidate-endpoint")
    member_invite.add_argument("--interface")
    member_invite.add_argument("--expires-in", type=int, default=180)
    member_invite.add_argument("--json", action="store_true")
    member_invite.set_defaults(action=member_invite_command, action_id="child.invite")
    member_approve = member_operations.add_parser(
        "approve", help=help_label("approve a matching child comparison code", "child.approve")
    )
    member_approve.add_argument("member")
    member_approve.add_argument("comparison_code")
    member_approve.add_argument("--json", action="store_true")
    member_approve.set_defaults(action=member_approve_command, action_id="child.approve")
    member_sync = member_operations.add_parser(
        "sync", help=help_label("refresh authenticated child facts", "child.sync")
    )
    member_sync.add_argument("--json", action="store_true")
    member_sync.set_defaults(action=member_sync_command, action_id="child.sync")
    member_drain = member_operations.add_parser(
        "drain", help=help_label("stop assigning new work to a child", "child.drain")
    )
    member_drain.add_argument("member")
    member_drain.add_argument("--json", action="store_true")
    member_drain.set_defaults(action=member_drain_command, action_id="child.drain")
    member_resume = member_operations.add_parser(
        "resume", help=help_label("resume assigning work to a drained child", "child.resume")
    )
    member_resume.add_argument("member")
    member_resume.add_argument("--json", action="store_true")
    member_resume.set_defaults(action=member_resume_command, action_id="child.resume")
    member_remove = member_operations.add_parser(
        "remove", help=help_label("remove an inactive child", "child.remove")
    )
    member_remove.add_argument("member")
    member_remove.add_argument("--json", action="store_true")
    member_remove.set_defaults(action=member_remove_command, action_id="child.remove")

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
    update_operations = updating.add_subparsers(dest="update_operation")
    update_check = update_operations.add_parser(
        "check", help=help_label("check core and selected runtime", "update.check")
    )
    update_check.add_argument("--catalog")
    update_check.add_argument("--json", action="store_true")
    update_check.set_defaults(action=check_updates, action_id="update.check")

    runtime_listing = subcommands.add_parser(
        "runtimes", help="list installed immutable runtime packs"
    )
    runtime_listing.set_defaults(action=list_runtimes, action_id="runtimes")

    available_listing = subcommands.add_parser(
        "list", help="list qualified runtimes available for this hardware"
    )
    available_listing.add_argument("model", nargs="?")
    available_listing.add_argument(
        "--versions", action="store_true", help="include every retained release"
    )
    available_listing.add_argument(
        "--all-targets",
        action="store_true",
        help="include runtimes for hardware targets other than this device",
    )
    available_listing.add_argument(
        "--refresh", action="store_true", help="require a fresh signed catalog"
    )
    available_listing.add_argument("--catalog")
    available_listing.add_argument("--json", action="store_true")
    available_listing.set_defaults(action=list_available_runtimes, action_id="list")

    packing = subcommands.add_parser(
        "pack", help="build a deterministic runtime-pack artifact"
    )
    packing.add_argument("source")
    packing.add_argument("--output", required=True)
    packing.set_defaults(action=pack_runtime, action_id="pack")

    inspecting = subcommands.add_parser(
        "inspect", help="inspect an installed runtime and its resolved command"
    )
    inspecting.add_argument("runtime")
    inspecting.add_argument("--target")
    inspecting.add_argument("--catalog")
    inspecting.add_argument("--port", type=int, default=8000)
    inspecting.add_argument("--command", action="store_true")
    inspecting.add_argument("--json", action="store_true")
    inspecting.set_defaults(action=inspect_runtime, action_id="inspect")

    upgrading = subcommands.add_parser(
        "upgrade", help="upgrade an installed runtime according to its selection policy"
    )
    upgrading.add_argument("runtime")
    upgrading.add_argument("--target")
    upgrading.add_argument("--catalog")
    upgrading.add_argument("--to")
    upgrading.add_argument("--dry-run", action="store_true")
    upgrading.set_defaults(action=upgrade_runtime, action_id="upgrade")

    rolling_back = subcommands.add_parser(
        "rollback", help="reinstall the previous retained runtime"
    )
    rolling_back.add_argument("runtime")
    rolling_back.add_argument("--target")
    rolling_back.add_argument("--dry-run", action="store_true")
    rolling_back.set_defaults(action=rollback_runtime, action_id="rollback")

    checking = subcommands.add_parser(
        "verify", help="verify an installed runtime and its exact artifacts"
    )
    checking.add_argument("model")
    checking.add_argument("--target")
    checking.add_argument("--model-cache")
    checking.add_argument(
        "--source-only", action="store_true", help="verify only the immutable runtime pack"
    )
    checking.set_defaults(action=verify, action_id="verify")

    acquiring = subcommands.add_parser(
        "acquire", help="acquire and verify an exact model artifact"
    )
    acquiring.add_argument("model")
    acquiring.add_argument("--target")
    acquiring.add_argument("--model-cache")
    acquiring.set_defaults(action=acquire, action_id="acquire")

    benchmarking = subcommands.add_parser(
        "benchmark", help="start, inspect, or stop a durable runtime benchmark"
    )
    benchmarking.add_argument(
        "runtime",
        nargs="?",
        help=(
            "installed runtime, `stop` to cancel the active benchmark, or "
            "`clean` to remove local benchmark data; use `verify PR_URL` for "
            "community qualification"
        ),
    )
    benchmarking.add_argument(
        "verification_target",
        nargs="?",
        help="pull-request URL, `status`, or `stop` after `benchmark verify`",
    )
    benchmarking.add_argument(
        "--candidate",
        help="select one exact changed candidate when a verification PR is ambiguous",
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
    benchmarking.add_argument(
        "--yes", action="store_true", help="confirm deletion for benchmark clean"
    )
    benchmarking.add_argument("--job-worker", action="store_true", help=argparse.SUPPRESS)
    benchmarking.add_argument("--job-id", help=argparse.SUPPRESS)
    benchmarking.set_defaults(action=benchmark_runtime, action_id="benchmark")

    installing = subcommands.add_parser(
        "install", help="install a model or immutable runtime pack"
    )
    installing.add_argument("model")
    installing.add_argument("--runtime", help="select an exact runtime candidate ID")
    installing.add_argument("--catalog")
    installing.add_argument(
        "--node",
        action="append",
        help="install on this child or main node; repeat to create replicas",
    )
    installing.add_argument(
        "--all-nodes",
        action="store_true",
        help="install one compatible target-specific replica on every active node",
    )
    installing.add_argument(
        "--replace-existing",
        action="store_true",
        help="confirm replacement of model groups occupying selected devices",
    )
    installing.add_argument("--port", type=int, default=8000)
    installing.add_argument("--engine-port", type=int, default=18000, help=argparse.SUPPRESS)
    installing.add_argument("--gateway-listen", default="0.0.0.0")
    installing.add_argument("--gateway-max-connections", type=int, default=128)
    installing.add_argument(
        "--gateway-queue-timeout",
        type=int,
        default=0,
        help="seconds to wait for admission; 0 waits until the client disconnects",
    )
    installing.add_argument("--name")
    installing.add_argument("--model-cache")
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

    scaling = subcommands.add_parser(
        "scale", help="set the number of independent engine groups for one model"
    )
    scaling.add_argument("model")
    scaling.add_argument("--replicas", type=int, required=True)
    scaling.add_argument("--runtime", help="select an exact runtime candidate ID")
    scaling.add_argument("--catalog")
    scaling.set_defaults(action=scale_command, action_id="scale")

    serving = subcommands.add_parser("serve", help="start an installed runtime")
    serving.add_argument("model")
    serving.add_argument("--target")
    serving.add_argument(
        "--port",
        type=int,
        default=None,
        help="internal engine port (defaults to the installed engine port)",
    )
    serving.add_argument("--name")
    serving.add_argument("--model-cache")
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

    showing = subcommands.add_parser("status", help="show node runtime or managed-container status")
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
        "start", help=help_label("start a stopped node runtime", "start")
    )
    starting.add_argument("model", nargs="?")
    starting.add_argument("--config")
    starting.set_defaults(action=start_service, action_id="start")

    restarting = subcommands.add_parser(
        "restart", help=help_label("restart a node runtime", "restart")
    )
    restarting.add_argument("model", nargs="?")
    restarting.add_argument("--config")
    restarting.set_defaults(action=restart_service, action_id="restart")

    recovering = subcommands.add_parser(
        "recover",
        help=help_label(
            "acknowledge protection trips and recover a node runtime", "recover"
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

    audit_command = subcommands.add_parser("audit", help="inspect the node audit chain")
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
        "stop", help=help_label("stop a node runtime", "stop")
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
        "uninstall", help="remove Let's Infer and all locally managed data"
    )
    uninstalling.add_argument("--config")
    uninstalling.add_argument(
        "--keep-models",
        action="store_true",
        help="preserve the models directory while removing everything else",
    )
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
    gateway.add_argument("--queue-timeout", type=int, default=0)
    gateway.add_argument("--max-connections", type=int, default=128)
    gateway.set_defaults(action=gateway_command, action_id="gateway")
    node_agent = subcommands.add_parser("node-agent", help=argparse.SUPPRESS)
    node_agent.add_argument("--listen", default="0.0.0.0")
    node_agent.add_argument("--port", type=int, default=SITE_CONTROL_PORT)
    node_agent.set_defaults(action=node_agent_command, action_id="node-agent")
    core_rebind = subcommands.add_parser("core-rebind", help=argparse.SUPPRESS)
    core_rebind.set_defaults(action=rebind_core_services, action_id="core-rebind")

    core_prune = subcommands.add_parser("core-prune", help=argparse.SUPPRESS)
    core_prune.add_argument("--dry-run", action="store_true")
    core_prune.add_argument("--json", action="store_true")
    core_prune.add_argument("--quiet", action="store_true")
    core_prune.set_defaults(action=prune_core_command, action_id="core-prune")
    internal_commands = {
        "service-start",
        "service-stop",
        "gateway",
        "node-agent",
        "core-rebind",
        "core-prune",
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
    audit_recorded = False
    machine_output = False
    raw_output = False
    presentation = None
    header_shown = False
    update_manager = None
    initial_updates: tuple[tuple[str, str, str | None, str | None], ...] = ()
    try:
        raw_arguments = list(argv) if argv is not None else sys.argv[1:]
        command_parser = parser()
        if not raw_arguments:
            if ui.Terminal(sys.stdout).interactive:
                ui.home()
            else:
                command_parser.print_help()
            return 0
        arguments = command_parser.parse_args(raw_arguments)
        presentation = ui_contract(arguments.action_id)
        machine_output = bool(getattr(arguments, "json", False))
        raw_output = _raw_ui_variant(presentation, arguments)
        human_interactive = (
            not machine_output
            and not raw_output
            and presentation.branded
            and ui.Terminal(sys.stdout).interactive
            and ui.Terminal(sys.stderr).interactive
        )
        owns_surface = presentation.output in {
            OutputContract.FROZEN_STATUS,
            OutputContract.LIVE_DASHBOARD,
        }
        public_command = presentation.surface is not SurfaceKind.INTERNAL
        worker_context = bool(getattr(arguments, "job_worker", False))
        source_manifest = source_root() / CORE_SOURCE_MANIFEST
        installed_release = (
            not source_manifest.is_symlink()
            and source_manifest.is_file()
        )
        if public_command and installed_release and not worker_context:
            update_manager = _update_manager()
            update_snapshot = update_manager.cached()
            initial_updates = tuple(
                (
                    record.kind,
                    record.subject,
                    record.available_version,
                    record.available_identity,
                )
                for record in update_snapshot.available
            )
        else:
            update_snapshot = None
        if human_interactive and not owns_surface:
            command_ui.CommandUI(sys.stderr).header(presentation.title)
            header_shown = True
        if (
            human_interactive
            and presentation.show_cached_updates
            and not owns_surface
            and update_snapshot is not None
        ):
            ui.update_notice(update_snapshot.available)
        if update_manager is not None:
            request_background_refresh(
                update_manager,
                snapshot=update_snapshot,
                installed=installed_release,
                public_command=public_command,
                explicit_check=arguments.action_id in {
                    "update",
                    "update.check",
                    "uninstall",
                },
                worker_context=worker_context,
            )
        metadata, identity = _authorize_command(arguments)
        audit_sequence = _audit_marker(metadata, identity)
        port = getattr(arguments, "port", 1)
        if port is not None and port not in range(1, 65536):
            raise LetsInferError("port must be between 1 and 65535")
        engine_port = getattr(arguments, "engine_port", None)
        if engine_port is not None and engine_port not in range(1, 65536):
            raise LetsInferError("engine port must be between 1 and 65535")
        if engine_port is not None and port is not None and engine_port == port:
            raise LetsInferError("gateway and engine ports must be distinct")
        max_connections = getattr(arguments, "gateway_max_connections", None)
        if max_connections is not None and max_connections not in range(1, 257):
            raise LetsInferError("gateway max connections must be between 1 and 256")
        queue_timeout = getattr(arguments, "gateway_queue_timeout", None)
        if queue_timeout is not None and queue_timeout not in range(0, 3601):
            raise LetsInferError(
                "gateway queue timeout must be 0 (unlimited) or between 1 and 3600 seconds"
            )
        watchdog_port = getattr(arguments, "watchdog_port", None)
        if watchdog_port is not None and watchdog_port not in range(1, 65536):
            raise LetsInferError("watchdog port must be between 1 and 65535")
        if getattr(arguments, "tail", 0) < 0:
            raise LetsInferError("log tail must be non-negative")
        progress_message = ACTION_PROGRESS.get(metadata.name) or READ_PROGRESS.get(
            metadata.name
        )
        lightweight = bool(
            getattr(arguments, "dry_run", False)
            or getattr(arguments, "list", False)
            or getattr(arguments, "source_only", False)
        )
        has_bounded_progress = (
            progress_message is not None
            and presentation.progress in {ProgressKind.SPINNER, ProgressKind.STEPS}
        )
        generic_progress = (
            has_bounded_progress
            and metadata.name not in {"update", "uninstall"}
            and metadata.name not in HANDLER_STEP_PROGRESS
        )

        def execute() -> int:
            nonlocal audit_recorded
            result = arguments.action(arguments)
            succeeded = result in (None, 0)
            _audit_command_result(
                metadata,
                identity,
                outcome="success" if succeeded else "failed",
                reason=None if succeeded else f"exit_{result}",
                after_sequence=audit_sequence,
            )
            audit_recorded = True
            after_audit = getattr(arguments, "after_audit", None)
            if succeeded and after_audit is not None:
                result = after_audit()
            return result

        if generic_progress:
            activity = ui.progress(
                progress_message[0],
                done=progress_message[1],
                # The signed installer owns its one progress line and may prompt
                # for sudo. A second animated writer can leak a spinner frame into
                # that interactive stdin stream (observed as `-: command not found`).
                enabled=(
                    human_interactive
                    and not lightweight
                ),
            )
            with activity, ui.protect_stdout(activity):
                result = execute()
                if result not in (None, 0) or getattr(
                    arguments, "suppress_completion", False
                ):
                    activity.done = None
        else:
            result = execute()
            if (
                human_interactive
                and has_bounded_progress
                and result in (None, 0)
                and not getattr(arguments, "suppress_completion", False)
            ):
                ui.Terminal(sys.stderr).success(progress_message[1])
        if (
            result in (None, 0)
            and human_interactive
            and presentation.show_cached_updates
            and not owns_surface
            and update_manager is not None
            and arguments.action_id not in {"update", "update.check", "uninstall"}
        ):
            refreshed_snapshot = update_manager.cached()
            refreshed = refreshed_snapshot.available
            refreshed_identity = tuple(
                (
                    record.kind,
                    record.subject,
                    record.available_version,
                    record.available_identity,
                )
                for record in refreshed
            )
            if refreshed_identity != initial_updates:
                verified_current = bool(refreshed_snapshot.records) and all(
                    record.status in {"current", "pinned"}
                    for record in refreshed_snapshot.records
                )
                ui.update_notice(
                    refreshed,
                    cleared=bool(initial_updates) and verified_current,
                    attention=(
                        bool(initial_updates)
                        and not refreshed
                        and not verified_current
                    ),
                )
        return result
    except (LetsInferError, PathContractError, RuntimePackError, SiteError) as error:
        if metadata is not None and not audit_recorded:
            _audit_command_result(
                metadata,
                identity,
                outcome="failed",
                reason=type(error).__name__,
                after_sequence=audit_sequence,
            )
        internal = bool(
            presentation is not None
            and presentation.surface is SurfaceKind.INTERNAL
        )
        if machine_output or raw_output or internal:
            sys.stderr.write(f"FATAL: {error}\n")
            sys.stderr.flush()
        else:
            section = (
                None
                if header_shown
                or presentation is None
                or presentation.output
                in {OutputContract.FROZEN_STATUS, OutputContract.LIVE_DASHBOARD}
                else presentation.action_id
            )
            ui.fatal(str(error), section=section)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
