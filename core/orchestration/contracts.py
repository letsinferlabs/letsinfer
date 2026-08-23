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


SCHEMA_VERSION = 3
ID_RE = re.compile(r"^[0-9a-f]{32}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
OCI_DIGEST_RE = re.compile(
    r"^[a-z0-9][a-z0-9._/-]*(?::[a-zA-Z0-9._-]+)?@sha256:[0-9a-f]{64}$"
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
    """A runtime topology or group plan is incomplete or unsafe."""


@dataclasses.dataclass(frozen=True)
class TaskAssignment:
    member_id: str
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


@dataclasses.dataclass(frozen=True)
class GroupPlan:
    group_id: str
    service_id: str
    release: Mapping[str, Any]
    strategy: str
    failure_policy: str
    topology_sha256: str
    manifest_sha256: str
    runtime_digest: str
    runtime_execution_contract_sha256: str
    endpoint_owner: str
    startup_order: tuple[tuple[str, ...], ...]
    connections: tuple[Mapping[str, Any], ...]
    assignments: tuple[TaskAssignment, ...]

    def document(self) -> dict[str, Any]:
        """Return the immutable, engine-consumable group document."""
        return {
            "schema_version": SCHEMA_VERSION,
            "group_id": self.group_id,
            "service_id": self.service_id,
            "release": json.loads(json.dumps(self.release)),
            "strategy": self.strategy,
            "failure_policy": self.failure_policy,
            "topology_sha256": self.topology_sha256,
            "manifest_sha256": self.manifest_sha256,
            "runtime_digest": self.runtime_digest,
            "runtime_execution_contract_sha256": self.runtime_execution_contract_sha256,
            "endpoint_owner": self.endpoint_owner,
            "startup_order": [list(phase) for phase in self.startup_order],
            "connections": [dict(item) for item in self.connections],
            "resources": [
                {
                    "node_id": assignment.member_id,
                    "address": assignment.address,
                    "task_id": assignment.task_id,
                    "port_base": assignment.port_base,
                    "port_count": assignment.port_count,
                    "device_uuids": list(assignment.device_uuids),
                }
                for assignment in self.assignments
            ],
        }


def _canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def validate_release_identity(value: Any) -> dict[str, Any]:
    """Validate the immutable signed-catalog release bound to one group."""
    required = {
        "logical_model", "candidate_id", "version", "source",
        "runtime_digest", "manifest_sha256", "engine_oci", "model_uri",
        "artifacts", "target_id", "target_contract_sha256", "qualification",
        "benchmark", "authors", "license",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise OrchestrationError("engine-group release identity is incomplete")
    for key in ("logical_model", "candidate_id", "target_id"):
        if not isinstance(value.get(key), str) or not SAFE_NAME_RE.fullmatch(value[key]):
            raise OrchestrationError(f"engine-group release {key} is invalid")
    if not isinstance(value.get("version"), str) or not VERSION_RE.fullmatch(value["version"]):
        raise OrchestrationError("engine-group release version is invalid")
    for key in ("source", "engine_oci"):
        if not isinstance(value.get(key), str) or not OCI_DIGEST_RE.fullmatch(value[key]):
            raise OrchestrationError(f"engine-group release {key} is not digest-pinned OCI")
    for key in ("runtime_digest", "manifest_sha256", "target_contract_sha256"):
        if not isinstance(value.get(key), str) or not SHA256_RE.fullmatch(value[key]):
            raise OrchestrationError(f"engine-group release {key} is invalid")
    model_uri = value.get("model_uri")
    if (
        not isinstance(model_uri, str)
        or not model_uri.startswith("hf://")
        or len(model_uri.encode("utf-8")) > 512
    ):
        raise OrchestrationError("engine-group release model URI is invalid")
    artifacts = value.get("artifacts")
    artifact_fields = {"name", "uri", "revision", "sha256"}
    if (
        not isinstance(artifacts, list)
        or not artifacts
        or len(artifacts) > 64
        or any(not isinstance(item, dict) or set(item) != artifact_fields for item in artifacts)
    ):
        raise OrchestrationError("engine-group release artifacts are invalid")
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
            raise OrchestrationError("engine-group release artifact identity is invalid")
        artifact_names.add(artifact["name"])
    if value.get("qualification") not in {"qualified", "unqualified"}:
        raise OrchestrationError("engine-group release qualification is invalid")
    benchmark = value.get("benchmark")
    if (
        not isinstance(benchmark, dict)
        or set(benchmark) != {"id", "evidence"}
        or not isinstance(benchmark.get("id"), str)
        or not SHA256_RE.fullmatch(benchmark["id"])
        or not isinstance(benchmark.get("evidence"), str)
        or not OCI_DIGEST_RE.fullmatch(benchmark["evidence"])
    ):
        raise OrchestrationError("engine-group release benchmark identity is invalid")
    authors = value.get("authors")
    if (
        not isinstance(authors, list)
        or not authors
        or len(authors) > 32
        or len(authors) != len(set(authors))
        or any(
            not isinstance(author, str)
            or not author.strip()
            or len(author.encode("utf-8")) > 128
            for author in authors
        )
    ):
        raise OrchestrationError("engine-group release authors are invalid")
    license_value = value.get("license")
    if (
        not isinstance(license_value, str)
        or not license_value
        or len(license_value.encode("utf-8")) > 128
    ):
        raise OrchestrationError("engine-group release license is invalid")
    return value


def validate_group_document(value: Any) -> dict[str, Any]:
    """Validate the immutable, engine-neutral resource plan for one group."""
    required = {
        "schema_version", "group_id", "service_id", "release", "strategy",
        "failure_policy", "topology_sha256", "manifest_sha256", "runtime_digest",
        "runtime_execution_contract_sha256", "endpoint_owner", "startup_order",
        "connections", "resources",
    }
    if (
        not isinstance(value, dict)
        or set(value) != required
        or type(value.get("schema_version")) is not int
        or value.get("schema_version") != SCHEMA_VERSION
    ):
        raise OrchestrationError("engine-group document schema is invalid")
    for key, label in (("group_id", "identity"), ("service_id", "service identity")):
        if not isinstance(value.get(key), str) or not ID_RE.fullmatch(value[key]):
            raise OrchestrationError(f"engine-group document {label} is invalid")
    release = validate_release_identity(value.get("release"))
    strategy = value.get("strategy")
    if strategy not in {"single", "parallel"}:
        raise OrchestrationError("engine-group document strategy is invalid")
    for key in (
        "topology_sha256", "manifest_sha256", "runtime_digest",
        "runtime_execution_contract_sha256",
    ):
        if not isinstance(value.get(key), str) or not SHA256_RE.fullmatch(value[key]):
            raise OrchestrationError(f"engine-group document {key} is invalid")
    if (
        release["runtime_digest"] != value["runtime_digest"]
        or release["manifest_sha256"] != value["manifest_sha256"]
    ):
        raise OrchestrationError("engine-group release does not match its sealed bytes")
    resources = value.get("resources")
    resource_fields = {
        "node_id", "address", "task_id", "port_base", "port_count", "device_uuids",
    }
    if (
        not isinstance(resources, list)
        or len(resources) not in range(1, 65)
        or any(not isinstance(item, dict) or set(item) != resource_fields for item in resources)
    ):
        raise OrchestrationError("engine-group resources are invalid")
    node_ids: list[str] = []
    task_ids: list[str] = []
    all_devices: list[str] = []
    for item in resources:
        node_id = item.get("node_id")
        task_id = item.get("task_id")
        address = item.get("address")
        port_base = item.get("port_base")
        port_count = item.get("port_count")
        devices = item.get("device_uuids")
        if not isinstance(node_id, str) or not ID_RE.fullmatch(node_id):
            raise OrchestrationError("engine-group resource node identity is invalid")
        if not isinstance(task_id, str) or re.fullmatch(r"task-(?:0|[1-9][0-9]*)", task_id) is None:
            raise OrchestrationError("engine-group resource task identity is invalid")
        if not isinstance(address, str) or not address or len(address.encode("utf-8")) > 255:
            raise OrchestrationError("engine-group resource address is invalid")
        if (
            not isinstance(port_base, int) or isinstance(port_base, bool)
            or port_base not in range(1024, 65536)
            or not isinstance(port_count, int) or isinstance(port_count, bool)
            or port_count not in range(1, 33) or port_base + port_count > 65536
        ):
            raise OrchestrationError("engine-group resource port range is invalid")
        if (
            not isinstance(devices, list) or not devices
            or len(devices) != len(set(devices))
            or any(
                not isinstance(device, str) or not device
                or len(device.encode("utf-8")) > 255 for device in devices
            )
        ):
            raise OrchestrationError("engine-group resource device allocation is invalid")
        node_ids.append(node_id)
        task_ids.append(task_id)
        all_devices.extend(devices)
    expected_tasks = [f"task-{index}" for index in range(len(resources))]
    if (
        len(node_ids) != len(set(node_ids))
        or task_ids != expected_tasks
        or len(all_devices) != len(set(all_devices))
    ):
        raise OrchestrationError("engine-group resources overlap or have unstable task identities")
    connections = value.get("connections")
    connection_fields = {"nodes", "kind", "speed_mbps", "mtu", "rdma"}
    if not isinstance(connections, list) or any(
        not isinstance(item, dict) or set(item) != connection_fields
        for item in connections
    ):
        raise OrchestrationError("engine-group connections are invalid")
    pairs: list[tuple[str, str]] = []
    for item in connections:
        nodes = item["nodes"]
        if (
            not isinstance(nodes, list)
            or len(nodes) != 2
            or nodes != sorted(nodes)
            or nodes[0] == nodes[1]
            or any(node not in node_ids for node in nodes)
            or item["kind"] not in {"connectx", "ethernet", "wifi", "other"}
            or not isinstance(item["rdma"], bool)
            or not isinstance(item["speed_mbps"], int)
            or isinstance(item["speed_mbps"], bool)
            or item["speed_mbps"] < 0
            or not isinstance(item["mtu"], int)
            or isinstance(item["mtu"], bool)
            or item["mtu"] <= 0
        ):
            raise OrchestrationError("engine-group connection fact is invalid")
        pairs.append((nodes[0], nodes[1]))
    if pairs != sorted(set(pairs)):
        raise OrchestrationError("engine-group connections must be unique and ordered")
    if len(node_ids) == 1 and connections:
        raise OrchestrationError("single-node engine groups cannot contain connections")
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
            raise OrchestrationError("engine-group connections do not join every node")
    endpoint_owner = value.get("endpoint_owner")
    if endpoint_owner not in task_ids:
        raise OrchestrationError("engine-group endpoint owner is not an assigned task")
    startup_order = value.get("startup_order")
    if (
        not isinstance(startup_order, list) or not startup_order
        or any(not isinstance(phase, list) or not phase for phase in startup_order)
        or sorted(task for phase in startup_order for task in phase) != sorted(task_ids)
        or len([task for phase in startup_order for task in phase]) != len(task_ids)
    ):
        raise OrchestrationError("engine-group startup order must contain every task exactly once")
    if strategy == "single":
        if (
            len(resources) != 1
            or value.get("failure_policy") != "independent"
            or endpoint_owner != "task-0"
            or startup_order != [["task-0"]]
        ):
            raise OrchestrationError("single engine-group document is inconsistent")
    elif value.get("failure_policy") != "whole-group":
        raise OrchestrationError("parallel engine-group document must be atomic")
    identity = {
        "contract": "letsinfer-execution-group-v3",
        **{key: value[key] for key in required - {"schema_version", "group_id"}},
    }
    if hashlib.sha256(_canonical_bytes(identity)).hexdigest()[:32] != value["group_id"]:
        raise OrchestrationError("engine-group document identity does not match its contents")
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
        or value.get("schema_version") != SCHEMA_VERSION
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


def orchestration_contract_sha256(value: Mapping[str, Any] | None) -> str:
    """Bind the runtime-owned execution bytes without assigning them semantics."""
    document: Any = {"contract": "letsinfer-single-task-v1"}
    if value is not None:
        document = validate_orchestration_contract(dict(value))
    return hashlib.sha256(_canonical_bytes(document)).hexdigest()


def build_group_plan(
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
) -> GroupPlan:
    """Expand one validated runtime contract across an authenticated placement."""
    contract = validate_orchestration_contract(value)
    safe_release = validate_release_identity(dict(release))
    if not isinstance(service_id, str) or not ID_RE.fullmatch(service_id):
        raise OrchestrationError("group service identity is invalid")
    if (
        safe_release["runtime_digest"] != runtime_digest
        or safe_release["manifest_sha256"] != manifest_sha256
    ):
        raise OrchestrationError("group release identity does not match runtime bytes")
    members = tuple(member_ids)
    if (
        len(members) != len(contract["tasks"])
        or len(set(members)) != len(members)
        or any(not isinstance(item, str) or not ID_RE.fullmatch(item) for item in members)
    ):
        raise OrchestrationError("group members do not match the runtime member count")
    for value_hash, label in (
        (topology_sha256, "topology"),
        (manifest_sha256, "manifest"),
        (runtime_digest, "runtime"),
    ):
        if not isinstance(value_hash, str) or not SHA256_RE.fullmatch(value_hash):
            raise OrchestrationError(f"group {label} identity must be a SHA-256")
    if set(member_addresses) != set(members) or any(
        not isinstance(member_addresses[item], str)
        or not member_addresses[item]
        or len(member_addresses[item].encode("utf-8")) > 255
        for item in members
    ):
        raise OrchestrationError("group member addresses are incomplete or invalid")
    if set(member_port_bases) != set(members):
        raise OrchestrationError("group member port assignments are incomplete")
    if set(member_device_uuids) != set(members):
        raise OrchestrationError("group member device assignments are incomplete")
    if any(
        not isinstance(member_device_uuids[item], Sequence)
        or isinstance(member_device_uuids[item], (str, bytes))
        or not member_device_uuids[item]
        or len(member_device_uuids[item]) != len(set(member_device_uuids[item]))
        or any(
            not isinstance(device_uuid, str)
            or not device_uuid
            or len(device_uuid.encode("utf-8")) > 255
            for device_uuid in member_device_uuids[item]
        )
        for item in members
    ):
        raise OrchestrationError("group member device assignments are invalid")

    assignments: list[TaskAssignment] = []
    for index, member_id in enumerate(members):
        task = contract["tasks"][index]
        port_base = member_port_bases[member_id]
        port_count = task["port_count"]
        if (
            not isinstance(port_base, int)
            or isinstance(port_base, bool)
            or port_base not in range(1024, 65536)
            or port_base + port_count > 65536
        ):
            raise OrchestrationError("group member port range is invalid")
        assignments.append(
            TaskAssignment(
                member_id=member_id,
                address=member_addresses[member_id],
                task_id=task["task_id"],
                port_base=port_base,
                port_count=port_count,
                launcher=task["launcher"],
                command=tuple(task.get("command", ())),
                environment=_environment(
                    task["environment"],
                    f"runtime.orchestration.tasks[{index}].environment",
                ),
                endpoint_owner=task["task_id"] == contract["endpoint_owner"],
                readiness=_readiness(
                    task["readiness"],
                    task["launcher"],
                    f"runtime.orchestration.tasks[{index}].readiness",
                ),
                device_uuids=tuple(member_device_uuids[member_id]),
            )
        )
    safe_connections = [dict(item) for item in connections]
    identity = {
        "contract": "letsinfer-execution-group-v3",
        "service_id": service_id,
        "release": safe_release,
        "strategy": "parallel",
        "failure_policy": contract["failure_policy"],
        "topology_sha256": topology_sha256,
        "manifest_sha256": manifest_sha256,
        "runtime_digest": runtime_digest,
        "runtime_execution_contract_sha256": orchestration_contract_sha256(contract),
        "endpoint_owner": contract["endpoint_owner"],
        "startup_order": contract["startup_order"],
        "connections": safe_connections,
        "resources": [
            {
                "node_id": item.member_id, "address": item.address,
                "task_id": item.task_id, "port_base": item.port_base,
                "port_count": item.port_count,
                "device_uuids": list(item.device_uuids),
            }
            for item in assignments
        ],
    }
    plan = GroupPlan(
        group_id=hashlib.sha256(_canonical_bytes(identity)).hexdigest()[:32],
        service_id=service_id,
        release=safe_release,
        strategy="parallel",
        failure_policy=contract["failure_policy"],
        topology_sha256=topology_sha256,
        manifest_sha256=manifest_sha256,
        runtime_digest=runtime_digest,
        runtime_execution_contract_sha256=orchestration_contract_sha256(contract),
        endpoint_owner=contract["endpoint_owner"],
        startup_order=tuple(tuple(phase) for phase in contract["startup_order"]),
        connections=tuple(safe_connections),
        assignments=tuple(assignments),
    )
    validate_group_document(plan.document())
    return plan


def build_single_group_plan(
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
) -> GroupPlan:
    """Build one ordinary engine as a one-endpoint, one-member group."""
    safe_release = validate_release_identity(dict(release))
    if not isinstance(service_id, str) or not ID_RE.fullmatch(service_id):
        raise OrchestrationError("single group service identity is invalid")
    if (
        safe_release["runtime_digest"] != runtime_digest
        or safe_release["manifest_sha256"] != manifest_sha256
    ):
        raise OrchestrationError("single group release identity does not match runtime bytes")
    if not isinstance(member_id, str) or not ID_RE.fullmatch(member_id):
        raise OrchestrationError("single group member identity is invalid")
    if (
        not isinstance(member_address, str)
        or not member_address
        or len(member_address.encode("utf-8")) > 255
    ):
        raise OrchestrationError("single group member address is invalid")
    if (
        not isinstance(device_uuids, Sequence)
        or isinstance(device_uuids, (str, bytes))
        or not device_uuids
        or len(device_uuids) != len(set(device_uuids))
        or any(
            not isinstance(device_uuid, str)
            or not device_uuid
            or len(device_uuid.encode("utf-8")) > 255
            for device_uuid in device_uuids
        )
    ):
        raise OrchestrationError("single group device assignment is invalid")
    for value_hash, label in (
        (topology_sha256, "topology"),
        (manifest_sha256, "manifest"),
        (runtime_digest, "runtime"),
    ):
        if not isinstance(value_hash, str) or not SHA256_RE.fullmatch(value_hash):
            raise OrchestrationError(f"single group {label} identity must be a SHA-256")
    if (
        not isinstance(port_base, int)
        or isinstance(port_base, bool)
        or port_base not in range(1024, 65536)
    ):
        raise OrchestrationError("single group port is invalid")
    assignment = TaskAssignment(
        member_id=member_id,
        address=member_address,
        task_id="task-0",
        port_base=port_base,
        port_count=1,
        launcher="manifest",
        command=(),
        environment=(),
        endpoint_owner=True,
        readiness={"kind": "manifest"},
        device_uuids=tuple(device_uuids),
    )
    identity = {
        "contract": "letsinfer-execution-group-v3",
        "service_id": service_id,
        "release": safe_release,
        "strategy": "single",
        "failure_policy": "independent",
        "topology_sha256": topology_sha256,
        "manifest_sha256": manifest_sha256,
        "runtime_digest": runtime_digest,
        "runtime_execution_contract_sha256": orchestration_contract_sha256(None),
        "endpoint_owner": "task-0",
        "startup_order": [["task-0"]],
        "connections": [],
        "resources": [
            {
                "node_id": member_id,
                "address": member_address,
                "task_id": "task-0",
                "port_base": port_base,
                "port_count": 1,
                "device_uuids": list(device_uuids),
            }
        ],
    }
    plan = GroupPlan(
        group_id=hashlib.sha256(_canonical_bytes(identity)).hexdigest()[:32],
        service_id=service_id,
        release=safe_release,
        strategy="single",
        failure_policy="independent",
        topology_sha256=topology_sha256,
        manifest_sha256=manifest_sha256,
        runtime_digest=runtime_digest,
        runtime_execution_contract_sha256=orchestration_contract_sha256(None),
        endpoint_owner="task-0",
        startup_order=(("task-0",),),
        connections=(),
        assignments=(assignment,),
    )
    validate_group_document(plan.document())
    return plan
