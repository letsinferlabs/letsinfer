#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Strict, engine-neutral contracts for one immutable runtime group.

Core assigns authenticated members and owns lifecycle ordering. Runtime packs
own every engine-specific executable and argument. No shell expansion or
engine option knowledge crosses that boundary.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

from core.engine_distribution import (
    EngineDistributionError,
    validate_engine_distribution,
)
from core.runtime_sources import is_immutable_runtime_source, local_runtime_digest


PLACEMENT_GROUP_SCHEMA_VERSION = 1
RUNTIME_ORCHESTRATION_SCHEMA_VERSION = 3
ID_RE = re.compile(r"^[0-9a-f]{32}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")
INTERFACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,31}$")
CANDIDATE_ID_RE = re.compile(
    r"^[a-z0-9][a-z0-9._-]*--[a-z0-9][a-z0-9._-]*--"
    r"[a-z0-9][a-z0-9._-]*--[a-z0-9][a-z0-9._-]*$"
)
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
OCI_DIGEST_RE = re.compile(
    r"^[a-z0-9][a-z0-9.-]*(?::[0-9]+)?/"
    r"[a-z0-9][a-z0-9._/-]*(?::[a-zA-Z0-9._-]+)?@sha256:[0-9a-f]{64}$"
)
ENVIRONMENT_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
MAX_ARGUMENTS = 128
MAX_ARGUMENT_BYTES = 16 * 1024
MAX_ENVIRONMENT = 64
MAX_ENVIRONMENT_BYTES = 16 * 1024
PROTECTED_ENVIRONMENT_PREFIX = "LETSINFER_"
FORBIDDEN_EXECUTABLES = {
    "/bin/bash",
    "/bin/dash",
    "/bin/sh",
    "/usr/bin/bash",
    "/usr/bin/dash",
    "/usr/bin/env",
    "/usr/bin/sh",
}


class OrchestrationError(ValueError):
    """A runtime topology or placement-group plan is incomplete or unsafe."""


@dataclasses.dataclass(frozen=True)
class Placement:
    placement_id: str
    node_id: str
    address: str
    task_id: str
    port_base: int
    port_count: int
    launcher: str
    command: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    endpoint_owner: bool
    readiness: Mapping[str, Any]
    device_uuids: tuple[str, ...]
    rdma_interface: str | None = None

    def document(self) -> dict[str, Any]:
        return {
            "placement_id": self.placement_id,
            "node_id": self.node_id,
            "address": self.address,
            "task_id": self.task_id,
            "port_base": self.port_base,
            "port_count": self.port_count,
            "device_uuids": list(self.device_uuids),
            **(
                {"rdma_interface": self.rdma_interface}
                if self.rdma_interface is not None
                else {}
            ),
        }


@dataclasses.dataclass(frozen=True)
class PlacementGroupPlan:
    placement_group_id: str
    service_id: str
    release: Mapping[str, Any]
    topology_sha256: str
    manifest_sha256: str
    runtime_digest: str
    runtime_execution_contract_sha256: str
    endpoint_placement_id: str
    startup_order: tuple[tuple[str, ...], ...]
    connections: tuple[Mapping[str, Any], ...]
    placements: tuple[Placement, ...]

    def document(self) -> dict[str, Any]:
        """Return the immutable placement-group document."""
        return {
            "schema_version": PLACEMENT_GROUP_SCHEMA_VERSION,
            "placement_group_id": self.placement_group_id,
            "service_id": self.service_id,
            "release": json.loads(json.dumps(self.release)),
            "topology_sha256": self.topology_sha256,
            "manifest_sha256": self.manifest_sha256,
            "runtime_digest": self.runtime_digest,
            "runtime_execution_contract_sha256": self.runtime_execution_contract_sha256,
            "endpoint_placement_id": self.endpoint_placement_id,
            "startup_order": [list(phase) for phase in self.startup_order],
            "connections": [dict(item) for item in self.connections],
            "placements": [placement.document() for placement in self.placements],
        }


def _canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def validate_release_identity(value: Any) -> dict[str, Any]:
    """Validate the immutable signed-catalog release bound to a placement group."""
    required = {
        "logical_model", "candidate_id", "version", "source",
        "runtime_digest", "manifest_sha256", "engine_distribution", "model_uri",
        "artifacts", "target_id", "target_contract_sha256", "qualification",
        "benchmark", "authors", "license", "native_execution",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise OrchestrationError("placement-group release identity is incomplete")
    for key in ("logical_model", "target_id"):
        if not isinstance(value.get(key), str) or not SAFE_NAME_RE.fullmatch(value[key]):
            raise OrchestrationError(f"placement-group release {key} is invalid")
    candidate_id = value.get("candidate_id")
    if (
        not isinstance(candidate_id, str)
        or len(candidate_id.encode("utf-8")) > 512
        or CANDIDATE_ID_RE.fullmatch(candidate_id) is None
    ):
        raise OrchestrationError("placement-group release candidate_id is invalid")
    if not isinstance(value.get("version"), str) or not VERSION_RE.fullmatch(value["version"]):
        raise OrchestrationError("placement-group release version is invalid")
    if not is_immutable_runtime_source(value.get("source")):
        raise OrchestrationError("placement-group release source is not immutable")
    try:
        distribution = validate_engine_distribution(value.get("engine_distribution"))
    except EngineDistributionError as error:
        raise OrchestrationError(str(error)) from error
    native_execution = value.get("native_execution")
    if distribution["kind"] == "oci-container":
        if native_execution is not None:
            raise OrchestrationError("OCI placement-group release cannot carry native execution")
    elif (
        not isinstance(native_execution, dict)
        or set(native_execution) != {"engine", "model", "artifacts", "cache", "serving"}
        or not isinstance(native_execution.get("engine"), dict)
        or not isinstance(native_execution.get("model"), dict)
        or not isinstance(native_execution.get("artifacts"), list)
        or not native_execution["artifacts"]
        or not isinstance(native_execution.get("cache"), dict)
        or not isinstance(native_execution.get("serving"), dict)
        or len(_canonical_bytes(native_execution)) > 12 * 1024
    ):
        raise OrchestrationError("native placement-group execution projection is invalid")
    for key in ("runtime_digest", "manifest_sha256", "target_contract_sha256"):
        if not isinstance(value.get(key), str) or not SHA256_RE.fullmatch(value[key]):
            raise OrchestrationError(f"placement-group release {key} is invalid")
    source_digest = local_runtime_digest(value["source"])
    if source_digest is not None and source_digest != value["runtime_digest"]:
        raise OrchestrationError(
            "placement-group local source differs from its runtime digest"
        )
    model_uri = value.get("model_uri")
    if (
        not isinstance(model_uri, str)
        or not model_uri.startswith("hf://")
        or len(model_uri.encode("utf-8")) > 512
    ):
        raise OrchestrationError("placement-group release model URI is invalid")
    artifacts = value.get("artifacts")
    artifact_fields = {"name", "uri", "revision", "sha256"}
    if (
        not isinstance(artifacts, list)
        or not artifacts
        or len(artifacts) > 64
        or any(not isinstance(item, dict) or set(item) != artifact_fields for item in artifacts)
    ):
        raise OrchestrationError("placement-group release artifacts are invalid")
    artifact_names: set[str] = set()
    for artifact in artifacts:
        if (
            not isinstance(artifact["name"], str)
            or not SAFE_NAME_RE.fullmatch(artifact["name"])
            or artifact["name"] in artifact_names
            or not isinstance(artifact["uri"], str)
            or not artifact["uri"].startswith("hf://")
            or len(artifact["uri"].encode("utf-8")) > 512
            or not isinstance(artifact["revision"], str)
            or re.fullmatch(r"[0-9a-f]{40}", artifact["revision"]) is None
            or (
                artifact["sha256"] is not None
                and (
                    not isinstance(artifact["sha256"], str)
                    or not SHA256_RE.fullmatch(artifact["sha256"])
                )
            )
        ):
            raise OrchestrationError("placement-group release artifact identity is invalid")
        artifact_names.add(artifact["name"])
    if value.get("qualification") not in {"qualified", "unqualified"}:
        raise OrchestrationError("placement-group release qualification is invalid")
    if value["qualification"] == "qualified" and source_digest is not None:
        raise OrchestrationError(
            "qualified placement-group release requires a published OCI source"
        )
    benchmark = value.get("benchmark")
    if (
        benchmark is not None
        and (
            not isinstance(benchmark, dict)
            or set(benchmark) != {"id", "evidence"}
            or not isinstance(benchmark.get("id"), str)
            or not SHA256_RE.fullmatch(benchmark["id"])
            or (
                benchmark.get("evidence") is not None
                and (
                    not isinstance(benchmark["evidence"], str)
                    or not OCI_DIGEST_RE.fullmatch(benchmark["evidence"])
                )
            )
        )
    ):
        raise OrchestrationError("placement-group release benchmark identity is invalid")
    authors = value.get("authors")
    qualified = value["qualification"] == "qualified"
    if (
        not isinstance(authors, list)
        or (qualified and not authors)
        or len(authors) > 32
        or len(authors) != len(set(authors))
        or any(
            not isinstance(author, str)
            or not author.strip()
            or len(author.encode("utf-8")) > 128
            for author in authors
        )
    ):
        raise OrchestrationError("placement-group release authors are invalid")
    license_value = value.get("license")
    if qualified and (
        not isinstance(license_value, str)
        or not license_value
        or len(license_value.encode("utf-8")) > 128
    ):
        raise OrchestrationError("placement-group release license is invalid")
    if not qualified and license_value is not None and (
        not isinstance(license_value, str)
        or not license_value
        or len(license_value.encode("utf-8")) > 128
    ):
        raise OrchestrationError("placement-group release license is invalid")
    return value


def _placement_id(
    placement: Mapping[str, Any],
    *,
    service_id: str,
    runtime_digest: str,
    manifest_sha256: str,
    topology_sha256: str,
) -> str:
    identity = {
        "contract": "letsinfer-placement-v1",
        "service_id": service_id,
        "runtime_digest": runtime_digest,
        "manifest_sha256": manifest_sha256,
        "topology_sha256": topology_sha256,
        **{key: placement[key] for key in placement if key != "placement_id"},
    }
    return hashlib.sha256(_canonical_bytes(identity)).hexdigest()[:32]


def validate_placement_group_document(value: Any) -> dict[str, Any]:
    """Validate one immutable atomic endpoint and its exact placements."""

    required = {
        "schema_version",
        "placement_group_id",
        "service_id",
        "release",
        "topology_sha256",
        "manifest_sha256",
        "runtime_digest",
        "runtime_execution_contract_sha256",
        "endpoint_placement_id",
        "startup_order",
        "connections",
        "placements",
    }
    if (
        not isinstance(value, dict)
        or set(value) != required
        or type(value.get("schema_version")) is not int
        or value.get("schema_version") != PLACEMENT_GROUP_SCHEMA_VERSION
    ):
        raise OrchestrationError("placement-group document schema is invalid")
    for key, label in (
        ("placement_group_id", "identity"),
        ("service_id", "service identity"),
    ):
        if not isinstance(value.get(key), str) or not ID_RE.fullmatch(value[key]):
            raise OrchestrationError(f"placement-group document {label} is invalid")
    release = validate_release_identity(value.get("release"))
    for key in (
        "topology_sha256",
        "manifest_sha256",
        "runtime_digest",
        "runtime_execution_contract_sha256",
    ):
        if not isinstance(value.get(key), str) or not SHA256_RE.fullmatch(value[key]):
            raise OrchestrationError(f"placement-group document {key} is invalid")
    if (
        release["runtime_digest"] != value["runtime_digest"]
        or release["manifest_sha256"] != value["manifest_sha256"]
    ):
        raise OrchestrationError("placement-group release does not match its sealed bytes")

    placements = value.get("placements")
    placement_fields = {
        "placement_id",
        "node_id",
        "address",
        "task_id",
        "port_base",
        "port_count",
        "device_uuids",
    }
    if (
        not isinstance(placements, list)
        or len(placements) not in range(1, 65)
        or any(
            not isinstance(item, dict)
            or set(item) not in (
                placement_fields,
                placement_fields | {"rdma_interface"},
            )
            for item in placements
        )
    ):
        raise OrchestrationError("placement-group placements are invalid")

    placement_ids: list[str] = []
    node_ids: list[str] = []
    task_ids: list[str] = []
    all_devices: list[str] = []
    rdma_nodes: list[str] = []
    for placement in placements:
        placement_id = placement.get("placement_id")
        node_id = placement.get("node_id")
        task_id = placement.get("task_id")
        address = placement.get("address")
        port_base = placement.get("port_base")
        port_count = placement.get("port_count")
        devices = placement.get("device_uuids")
        rdma_interface = placement.get("rdma_interface")
        if not isinstance(placement_id, str) or not ID_RE.fullmatch(placement_id):
            raise OrchestrationError("placement identity is invalid")
        if not isinstance(node_id, str) or not ID_RE.fullmatch(node_id):
            raise OrchestrationError("placement node identity is invalid")
        if (
            not isinstance(task_id, str)
            or re.fullmatch(r"task-(?:0|[1-9][0-9]*)", task_id) is None
        ):
            raise OrchestrationError("placement task identity is invalid")
        if not isinstance(address, str) or not address or len(address.encode("utf-8")) > 255:
            raise OrchestrationError("placement address is invalid")
        if (
            not isinstance(port_base, int)
            or isinstance(port_base, bool)
            or port_base not in range(1024, 65536)
            or not isinstance(port_count, int)
            or isinstance(port_count, bool)
            or port_count not in range(1, 33)
            or port_base + port_count > 65536
        ):
            raise OrchestrationError("placement port range is invalid")
        if (
            not isinstance(devices, list)
            or not devices
            or len(devices) != len(set(devices))
            or any(
                not isinstance(device, str)
                or not device
                or len(device.encode("utf-8")) > 255
                for device in devices
            )
        ):
            raise OrchestrationError("placement device allocation is invalid")
        if rdma_interface is not None and (
            not isinstance(rdma_interface, str)
            or not INTERFACE_RE.fullmatch(rdma_interface)
        ):
            raise OrchestrationError("placement RDMA interface is invalid")
        if placement_id != _placement_id(
            placement,
            service_id=value["service_id"],
            runtime_digest=value["runtime_digest"],
            manifest_sha256=value["manifest_sha256"],
            topology_sha256=value["topology_sha256"],
        ):
            raise OrchestrationError("placement identity does not match its contents")
        placement_ids.append(placement_id)
        node_ids.append(node_id)
        task_ids.append(task_id)
        all_devices.extend(devices)
        if rdma_interface is not None:
            rdma_nodes.append(node_id)
    expected_tasks = [f"task-{index}" for index in range(len(placements))]
    if (
        len(placement_ids) != len(set(placement_ids))
        or len(node_ids) != len(set(node_ids))
        or task_ids != expected_tasks
        or len(all_devices) != len(set(all_devices))
    ):
        raise OrchestrationError(
            "placement-group placements overlap or have unstable identities"
        )

    connections = value.get("connections")
    connection_fields = {"nodes", "kind", "speed_mbps", "mtu", "rdma"}
    if not isinstance(connections, list) or any(
        not isinstance(item, dict) or set(item) != connection_fields
        for item in connections
    ):
        raise OrchestrationError("placement-group connections are invalid")
    pairs: list[tuple[str, str]] = []
    for connection in connections:
        nodes = connection["nodes"]
        if (
            not isinstance(nodes, list)
            or len(nodes) != 2
            or nodes != sorted(nodes)
            or nodes[0] == nodes[1]
            or any(node not in node_ids for node in nodes)
            or connection["kind"] not in {"connectx", "ethernet", "wifi", "other"}
            or not isinstance(connection["rdma"], bool)
            or not isinstance(connection["speed_mbps"], int)
            or isinstance(connection["speed_mbps"], bool)
            or connection["speed_mbps"] < 0
            or not isinstance(connection["mtu"], int)
            or isinstance(connection["mtu"], bool)
            or connection["mtu"] <= 0
        ):
            raise OrchestrationError("placement-group connection fact is invalid")
        pairs.append((nodes[0], nodes[1]))
    if pairs != sorted(set(pairs)):
        raise OrchestrationError("placement-group connections must be unique and ordered")
    if len(node_ids) == 1 and connections:
        raise OrchestrationError("one-placement groups cannot contain connections")
    if len(node_ids) > 1:
        reached = {node_ids[0]}
        while True:
            expanded = reached | {
                right if left in reached else left
                for left, right in pairs
                if left in reached or right in reached
            }
            if expanded == reached:
                break
            reached = expanded
        if reached != set(node_ids):
            raise OrchestrationError("placement-group connections do not join every node")
    if rdma_nodes:
        if sorted(rdma_nodes) != sorted(node_ids):
            raise OrchestrationError(
                "placement-group RDMA interfaces must bind every placement"
            )
        rdma_pairs = [
            (connection["nodes"][0], connection["nodes"][1])
            for connection in connections
            if connection["rdma"] is True
        ]
        reached = {node_ids[0]}
        while True:
            expanded = reached | {
                right if left in reached else left
                for left, right in rdma_pairs
                if left in reached or right in reached
            }
            if expanded == reached:
                break
            reached = expanded
        if reached != set(node_ids):
            raise OrchestrationError(
                "placement-group RDMA connections do not join every placement"
            )

    endpoint_placement_id = value.get("endpoint_placement_id")
    if endpoint_placement_id not in placement_ids:
        raise OrchestrationError(
            "placement-group endpoint owner is not an assigned placement"
        )
    startup_order = value.get("startup_order")
    flattened = (
        [placement_id for phase in startup_order for placement_id in phase]
        if isinstance(startup_order, list)
        and all(isinstance(phase, list) and phase for phase in startup_order)
        else []
    )
    if (
        not flattened
        or sorted(flattened) != sorted(placement_ids)
        or len(flattened) != len(set(flattened))
    ):
        raise OrchestrationError(
            "placement-group startup order must contain every placement exactly once"
        )
    if len(placements) == 1 and (
        endpoint_placement_id != placement_ids[0]
        or startup_order != [[placement_ids[0]]]
    ):
        raise OrchestrationError("one-placement group document is inconsistent")

    identity = {
        "contract": "letsinfer-placement-group-v1",
        **{
            key: value[key]
            for key in required - {"schema_version", "placement_group_id"}
        },
    }
    if (
        hashlib.sha256(_canonical_bytes(identity)).hexdigest()[:32]
        != value["placement_group_id"]
    ):
        raise OrchestrationError(
            "placement-group document identity does not match its contents"
        )
    return value


def _argv(value: Any, where: str) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or not value
        or len(value) > MAX_ARGUMENTS
        or any(
            not isinstance(item, str)
            or not item
            or "\0" in item
            or len(item.encode("utf-8")) > 4096
            for item in value
        )
        or sum(len(item.encode("utf-8")) for item in value) > MAX_ARGUMENT_BYTES
    ):
        raise OrchestrationError(f"{where} must be a bounded non-empty argv")
    executable = value[0]
    if not executable.startswith("/") or "/../" in executable or executable.endswith("/.."):
        raise OrchestrationError(f"{where}[0] must be an absolute contained executable")
    if executable in FORBIDDEN_EXECUTABLES:
        raise OrchestrationError(f"{where} cannot invoke a shell or environment dispatcher")
    return tuple(value)


def _environment(value: Any, where: str) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, dict) or len(value) > MAX_ENVIRONMENT:
        raise OrchestrationError(f"{where} must be a bounded object")
    total = 0
    result: list[tuple[str, str]] = []
    for key in sorted(value):
        item = value[key]
        if not isinstance(key, str) or not ENVIRONMENT_RE.fullmatch(key):
            raise OrchestrationError(f"{where} contains an invalid variable name")
        if key.startswith(PROTECTED_ENVIRONMENT_PREFIX):
            raise OrchestrationError(f"{where}.{key} is reserved for core")
        if not isinstance(item, str) or "\0" in item:
            raise OrchestrationError(f"{where}.{key} must be a string without NUL")
        total += len(key.encode("utf-8")) + len(item.encode("utf-8"))
        if total > MAX_ENVIRONMENT_BYTES:
            raise OrchestrationError(f"{where} exceeds its byte limit")
        result.append((key, item))
    return tuple(result)


def _readiness(value: Any, launcher: str, where: str) -> dict[str, Any]:
    if launcher == "manifest":
        if value != {"kind": "manifest"}:
            raise OrchestrationError(
                f"{where} must use the sealed manifest readiness contract"
            )
        return {"kind": "manifest"}
    required = {"kind", "command", "interval_seconds", "timeout_seconds", "retries"}
    if not isinstance(value, dict) or set(value) != required or value.get("kind") != "exec":
        raise OrchestrationError(f"{where} must be an exact exec readiness contract")
    command = _argv(value.get("command"), f"{where}.command")
    for key, lower, upper in (
        ("interval_seconds", 1, 60),
        ("timeout_seconds", 1, 30),
        ("retries", 1, 600),
    ):
        item = value.get(key)
        if not isinstance(item, int) or isinstance(item, bool) or item not in range(lower, upper + 1):
            raise OrchestrationError(f"{where}.{key} must be from {lower} through {upper}")
    return {
        "kind": "exec",
        "command": list(command),
        "interval_seconds": value["interval_seconds"],
        "timeout_seconds": value["timeout_seconds"],
        "retries": value["retries"],
    }


def validate_orchestration_contract(value: Any) -> dict[str, Any]:
    """Validate one bounded runtime-owned task contract without interpreting it."""
    required = {
        "schema_version", "failure_policy", "endpoint_owner", "startup_order", "tasks",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise OrchestrationError(
            "runtime.orchestration must contain exactly schema_version, failure_policy, "
            "endpoint_owner, startup_order, and tasks"
        )
    if (
        type(value.get("schema_version")) is not int
        or value.get("schema_version") != RUNTIME_ORCHESTRATION_SCHEMA_VERSION
    ):
        raise OrchestrationError("unsupported runtime.orchestration schema_version")
    if value.get("failure_policy") != "whole-group":
        raise OrchestrationError("parallel orchestration requires whole-group failure policy")
    tasks = value.get("tasks")
    if not isinstance(tasks, list) or len(tasks) not in range(1, 65):
        raise OrchestrationError("runtime.orchestration.tasks must contain 1 through 64 tasks")
    task_ids: list[str] = []
    for index, task in enumerate(tasks):
        where = f"runtime.orchestration.tasks[{index}]"
        task_id = task.get("task_id") if isinstance(task, dict) else None
        if task_id != f"task-{index}":
            raise OrchestrationError(f"{where}.task_id must be task-{index}")
        common = {
            "task_id", "launcher", "environment", "port_count", "readiness",
        }
        if not isinstance(task, dict) or not common.issubset(task):
            raise OrchestrationError(f"{where} is incomplete")
        launcher = task.get("launcher")
        expected_fields = common if launcher == "manifest" else common | {"command"}
        if launcher not in {"manifest", "runtime-command"} or set(task) != expected_fields:
            raise OrchestrationError(f"{where} has invalid fields")
        port_count = task.get("port_count")
        if (
            not isinstance(port_count, int)
            or isinstance(port_count, bool)
            or port_count not in range(1, 33)
        ):
            raise OrchestrationError(f"{where}.port_count must be from 1 through 32")
        _environment(task.get("environment"), f"{where}.environment")
        if launcher == "runtime-command":
            _argv(task.get("command"), f"{where}.command")
        _readiness(task.get("readiness"), launcher, f"{where}.readiness")
        task_ids.append(task_id)
    if value.get("endpoint_owner") not in task_ids:
        raise OrchestrationError("runtime.orchestration.endpoint_owner is not a task")
    phases = value.get("startup_order")
    if (
        not isinstance(phases, list) or not phases
        or any(not isinstance(phase, list) or not phase for phase in phases)
    ):
        raise OrchestrationError("runtime.orchestration.startup_order must contain task phases")
    flattened = [task_id for phase in phases for task_id in phase]
    if len(flattened) != len(set(flattened)) or sorted(flattened) != sorted(task_ids):
        raise OrchestrationError(
            "runtime.orchestration.startup_order must contain every task exactly once"
        )
    if len(_canonical_bytes(value)) > 64 * 1024:
        raise OrchestrationError("runtime.orchestration exceeds 65536 bytes")
    return value


def validate_target_binding(value: Any, placement: Mapping[str, Any]) -> dict[str, Any] | None:
    """Require the runtime group contract to exactly bind its target placement."""
    strategy = placement.get("strategy")
    if strategy == "single":
        if value is not None:
            raise OrchestrationError("single-node targets cannot declare runtime orchestration")
        return None
    contract = validate_orchestration_contract(value)
    if len(contract["tasks"]) != placement.get("node_count"):
        raise OrchestrationError(
            "runtime.orchestration.tasks does not match target.placement.node_count"
        )
    return contract


def bind_endpoint_node(
    value: Any,
    member_ids: Sequence[str],
    endpoint_member_id: str,
) -> tuple[str, ...]:
    """Map the opaque endpoint-owner task to the main node deterministically."""
    contract = validate_orchestration_contract(value)
    members = tuple(member_ids)
    if (
        len(members) != len(contract["tasks"])
        or len(set(members)) != len(members)
        or any(not isinstance(item, str) or not ID_RE.fullmatch(item) for item in members)
        or not isinstance(endpoint_member_id, str)
        or endpoint_member_id not in members
    ):
        raise OrchestrationError(
            "placement-group endpoint owner requires the selected main node"
        )
    endpoint_index = next(
        index
        for index, task in enumerate(contract["tasks"])
        if task["task_id"] == contract["endpoint_owner"]
    )
    current_index = members.index(endpoint_member_id)
    ordered = list(members)
    ordered[endpoint_index], ordered[current_index] = (
        ordered[current_index],
        ordered[endpoint_index],
    )
    return tuple(ordered)


def validate_placement_group_target_interconnect(
    value: Any,
    placement: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind generated group resources to the runtime target's link contract."""
    group = validate_placement_group_document(value)
    if not isinstance(placement, Mapping) or set(placement) != {
        "strategy", "node_count", "interconnect"
    }:
        raise OrchestrationError("runtime target placement is invalid")
    if len(group["placements"]) != placement["node_count"]:
        raise OrchestrationError("placement-group plan differs from the release target")
    interconnect = placement["interconnect"]
    if not isinstance(interconnect, Mapping) or set(interconnect) != {
        "kind", "rdma_required", "minimum_speed_mbps", "minimum_mtu"
    }:
        raise OrchestrationError("runtime target interconnect is invalid")
    if (
        interconnect["kind"] not in {"any", "connectx", "ethernet", "wifi", "other"}
        or not isinstance(interconnect["rdma_required"], bool)
        or not isinstance(interconnect["minimum_speed_mbps"], int)
        or isinstance(interconnect["minimum_speed_mbps"], bool)
        or interconnect["minimum_speed_mbps"] < 0
        or not isinstance(interconnect["minimum_mtu"], int)
        or isinstance(interconnect["minimum_mtu"], bool)
        or interconnect["minimum_mtu"] < 0
    ):
        raise OrchestrationError("runtime target interconnect is invalid")
    matching_pairs: list[tuple[str, str]] = []
    for connection in group["connections"]:
        if (
            (interconnect["kind"] == "any" or connection["kind"] == interconnect["kind"])
            and (
                not interconnect["rdma_required"]
                or connection["rdma"] is True
            )
            and connection["speed_mbps"] >= interconnect["minimum_speed_mbps"]
            and connection["mtu"] >= interconnect["minimum_mtu"]
        ):
            matching_pairs.append(tuple(connection["nodes"]))
    node_ids = [item["node_id"] for item in group["placements"]]
    if len(node_ids) > 1:
        reached = {node_ids[0]}
        while True:
            expanded = reached | {
                right if left in reached else left
                for left, right in matching_pairs
                if left in reached or right in reached
            }
            if expanded == reached:
                break
            reached = expanded
        if reached != set(node_ids):
            raise OrchestrationError(
                "placement-group connections do not satisfy the release target"
            )
    bound_nodes = {
        item["node_id"]
        for item in group["placements"]
        if "rdma_interface" in item
    }
    if interconnect["rdma_required"]:
        if bound_nodes != set(node_ids):
            raise OrchestrationError(
                "RDMA target requires one sealed interface on every node"
            )
    elif bound_nodes:
        raise OrchestrationError(
            "non-RDMA target cannot receive RDMA device resources"
        )
    return group


def orchestration_contract_sha256(value: Mapping[str, Any] | None) -> str:
    """Bind the runtime-owned execution bytes without assigning them semantics."""
    document: Any = {"contract": "letsinfer-single-task-v1"}
    if value is not None:
        document = validate_orchestration_contract(dict(value))
    return hashlib.sha256(_canonical_bytes(document)).hexdigest()


def _bound_placement(
    *,
    service_id: str,
    runtime_digest: str,
    manifest_sha256: str,
    topology_sha256: str,
    node_id: str,
    address: str,
    task: Mapping[str, Any],
    port_base: int,
    device_uuids: Sequence[str],
    endpoint_owner: bool,
    rdma_interface: str | None = None,
) -> Placement:
    placement_document = {
        "node_id": node_id,
        "address": address,
        "task_id": task["task_id"],
        "port_base": port_base,
        "port_count": task["port_count"],
        "device_uuids": list(device_uuids),
        **(
            {"rdma_interface": rdma_interface}
            if rdma_interface is not None
            else {}
        ),
    }
    return Placement(
        placement_id=_placement_id(
            placement_document,
            service_id=service_id,
            runtime_digest=runtime_digest,
            manifest_sha256=manifest_sha256,
            topology_sha256=topology_sha256,
        ),
        node_id=node_id,
        address=address,
        task_id=task["task_id"],
        port_base=port_base,
        port_count=task["port_count"],
        launcher=task["launcher"],
        command=tuple(task.get("command", ())),
        environment=_environment(
            task["environment"],
            f"runtime.orchestration.tasks[{task['task_id']}].environment",
        ),
        endpoint_owner=endpoint_owner,
        readiness=_readiness(
            task["readiness"],
            task["launcher"],
            f"runtime.orchestration.tasks[{task['task_id']}].readiness",
        ),
        device_uuids=tuple(device_uuids),
        rdma_interface=rdma_interface,
    )


def _placement_group_plan(
    *,
    service_id: str,
    release: Mapping[str, Any],
    topology_sha256: str,
    manifest_sha256: str,
    runtime_digest: str,
    runtime_execution_contract_sha256: str,
    endpoint_placement_id: str,
    startup_order: Sequence[Sequence[str]],
    connections: Sequence[Mapping[str, Any]],
    placements: Sequence[Placement],
) -> PlacementGroupPlan:
    identity = {
        "contract": "letsinfer-placement-group-v1",
        "service_id": service_id,
        "release": dict(release),
        "topology_sha256": topology_sha256,
        "manifest_sha256": manifest_sha256,
        "runtime_digest": runtime_digest,
        "runtime_execution_contract_sha256": runtime_execution_contract_sha256,
        "endpoint_placement_id": endpoint_placement_id,
        "startup_order": [list(phase) for phase in startup_order],
        "connections": [dict(connection) for connection in connections],
        "placements": [placement.document() for placement in placements],
    }
    plan = PlacementGroupPlan(
        placement_group_id=hashlib.sha256(_canonical_bytes(identity)).hexdigest()[:32],
        service_id=service_id,
        release=dict(release),
        topology_sha256=topology_sha256,
        manifest_sha256=manifest_sha256,
        runtime_digest=runtime_digest,
        runtime_execution_contract_sha256=runtime_execution_contract_sha256,
        endpoint_placement_id=endpoint_placement_id,
        startup_order=tuple(tuple(phase) for phase in startup_order),
        connections=tuple(dict(connection) for connection in connections),
        placements=tuple(placements),
    )
    validate_placement_group_document(plan.document())
    return plan


def build_placement_group_plan(
    value: Any,
    *,
    member_ids: Sequence[str],
    member_addresses: Mapping[str, str],
    topology_sha256: str,
    manifest_sha256: str,
    runtime_digest: str,
    service_id: str,
    release: Mapping[str, Any],
    member_port_bases: Mapping[str, int],
    member_device_uuids: Mapping[str, Sequence[str]],
    connections: Sequence[Mapping[str, Any]],
    member_rdma_interfaces: Mapping[str, str] | None = None,
    endpoint_member_id: str | None = None,
) -> PlacementGroupPlan:
    """Bind runtime-owned tasks to exact Core placements and one endpoint."""

    contract = validate_orchestration_contract(value)
    safe_release = validate_release_identity(dict(release))
    members = tuple(member_ids)
    if (
        not isinstance(service_id, str)
        or not ID_RE.fullmatch(service_id)
        or len(members) != len(contract["tasks"])
        or len(set(members)) != len(members)
        or any(not isinstance(node, str) or not ID_RE.fullmatch(node) for node in members)
    ):
        raise OrchestrationError("placement-group node assignments are invalid")
    if set(member_addresses) != set(members):
        raise OrchestrationError("placement-group node addresses are incomplete")
    if set(member_port_bases) != set(members):
        raise OrchestrationError("placement-group port assignments are incomplete")
    if set(member_device_uuids) != set(members):
        raise OrchestrationError("placement-group device assignments are incomplete")
    if (
        safe_release["runtime_digest"] != runtime_digest
        or safe_release["manifest_sha256"] != manifest_sha256
    ):
        raise OrchestrationError("placement-group release identity changed")
    for digest, label in (
        (topology_sha256, "topology"),
        (manifest_sha256, "manifest"),
        (runtime_digest, "runtime"),
    ):
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise OrchestrationError(
                f"placement-group {label} identity must be a SHA-256"
            )
    rdma_interfaces = dict(member_rdma_interfaces or {})
    if rdma_interfaces and set(rdma_interfaces) != set(members):
        raise OrchestrationError("placement-group RDMA assignments are incomplete")

    placements = tuple(
        _bound_placement(
            service_id=service_id,
            runtime_digest=runtime_digest,
            manifest_sha256=manifest_sha256,
            topology_sha256=topology_sha256,
            node_id=node_id,
            address=member_addresses[node_id],
            task=contract["tasks"][index],
            port_base=member_port_bases[node_id],
            device_uuids=member_device_uuids[node_id],
            endpoint_owner=(
                contract["tasks"][index]["task_id"] == contract["endpoint_owner"]
            ),
            rdma_interface=rdma_interfaces.get(node_id),
        )
        for index, node_id in enumerate(members)
    )
    endpoint_placements = [
        placement for placement in placements if placement.endpoint_owner
    ]
    if len(endpoint_placements) != 1 or (
        endpoint_member_id is not None
        and endpoint_placements[0].node_id != endpoint_member_id
    ):
        raise OrchestrationError(
            "placement-group endpoint is not assigned to the selected main node"
        )
    by_task = {placement.task_id: placement.placement_id for placement in placements}
    startup_order = [
        [by_task[task_id] for task_id in phase]
        for phase in contract["startup_order"]
    ]
    return _placement_group_plan(
        service_id=service_id,
        release=safe_release,
        topology_sha256=topology_sha256,
        manifest_sha256=manifest_sha256,
        runtime_digest=runtime_digest,
        runtime_execution_contract_sha256=orchestration_contract_sha256(contract),
        endpoint_placement_id=endpoint_placements[0].placement_id,
        startup_order=startup_order,
        connections=connections,
        placements=placements,
    )


def build_single_placement_group_plan(
    *,
    member_id: str,
    member_address: str,
    device_uuids: Sequence[str],
    topology_sha256: str,
    manifest_sha256: str,
    runtime_digest: str,
    service_id: str,
    release: Mapping[str, Any],
    port_base: int,
    port_count: int = 1,
) -> PlacementGroupPlan:
    """Build one placement and its atomic placement group."""

    safe_release = validate_release_identity(dict(release))
    task = {
        "task_id": "task-0",
        "launcher": "manifest",
        "command": [],
        "environment": {},
        "port_count": port_count,
        "readiness": {"kind": "manifest"},
    }
    placement = _bound_placement(
        service_id=service_id,
        runtime_digest=runtime_digest,
        manifest_sha256=manifest_sha256,
        topology_sha256=topology_sha256,
        node_id=member_id,
        address=member_address,
        task=task,
        port_base=port_base,
        device_uuids=device_uuids,
        endpoint_owner=True,
    )
    return _placement_group_plan(
        service_id=service_id,
        release=safe_release,
        topology_sha256=topology_sha256,
        manifest_sha256=manifest_sha256,
        runtime_digest=runtime_digest,
        runtime_execution_contract_sha256=orchestration_contract_sha256(None),
        endpoint_placement_id=placement.placement_id,
        startup_order=((placement.placement_id,),),
        connections=(),
        placements=(placement,),
    )
