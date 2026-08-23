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


SCHEMA_VERSION = 2
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
class RoleAssignment:
    member_id: str
    address: str
    rank: int
    role_rank: int
    role: str
    port_base: int
    port_count: int
    launcher: str
    command: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    inference_endpoint: bool
    readiness: Mapping[str, Any]
    device_uuids: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class GroupPlan:
    group_id: str
    service_id: str
    release: Mapping[str, Any]
    strategy: str
    engine_strategy: str
    failure_policy: str
    minimum_healthy_members: int
    topology_sha256: str
    manifest_sha256: str
    runtime_digest: str
    engine_coordinator_id: str
    startup_order: tuple[str, ...]
    assignments: tuple[RoleAssignment, ...]

    def document(self) -> dict[str, Any]:
        """Return the immutable, engine-consumable group document."""
        return {
            "schema_version": SCHEMA_VERSION,
            "group_id": self.group_id,
            "service_id": self.service_id,
            "release": json.loads(json.dumps(self.release)),
            "strategy": self.strategy,
            "engine_strategy": self.engine_strategy,
            "failure_policy": self.failure_policy,
            "minimum_healthy_members": self.minimum_healthy_members,
            "topology_sha256": self.topology_sha256,
            "manifest_sha256": self.manifest_sha256,
            "runtime_digest": self.runtime_digest,
            "engine_coordinator_id": self.engine_coordinator_id,
            "startup_order": list(self.startup_order),
            "members": [
                {
                    "member_id": assignment.member_id,
                    "address": assignment.address,
                    "rank": assignment.rank,
                    "role_rank": assignment.role_rank,
                    "role": assignment.role,
                    "port_base": assignment.port_base,
                    "port_count": assignment.port_count,
                    "inference_endpoint": assignment.inference_endpoint,
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
    """Validate the exact immutable group document sent to every member."""
    required = {
        "schema_version", "group_id", "service_id", "release", "strategy", "engine_strategy",
        "failure_policy", "minimum_healthy_members", "topology_sha256",
        "manifest_sha256", "runtime_digest", "engine_coordinator_id",
        "startup_order", "members",
    }
    if (
        not isinstance(value, dict)
        or set(value) != required
        or type(value.get("schema_version")) is not int
        or value.get("schema_version") != SCHEMA_VERSION
    ):
        raise OrchestrationError("engine-group document schema is invalid")
    if not isinstance(value.get("group_id"), str) or not ID_RE.fullmatch(value["group_id"]):
        raise OrchestrationError("engine-group document identity is invalid")
    if not isinstance(value.get("service_id"), str) or not ID_RE.fullmatch(value["service_id"]):
        raise OrchestrationError("engine-group document service identity is invalid")
    release = validate_release_identity(value.get("release"))
    if value.get("strategy") not in {"single", "parallel"}:
        raise OrchestrationError("engine-group document strategy is invalid")
    if not isinstance(value.get("engine_strategy"), str) or not SAFE_NAME_RE.fullmatch(value["engine_strategy"]):
        raise OrchestrationError("engine-group document engine strategy is invalid")
    for key in ("topology_sha256", "manifest_sha256", "runtime_digest"):
        if not isinstance(value.get(key), str) or not SHA256_RE.fullmatch(value[key]):
            raise OrchestrationError(f"engine-group document {key} is invalid")
    if (
        release["runtime_digest"] != value["runtime_digest"]
        or release["manifest_sha256"] != value["manifest_sha256"]
    ):
        raise OrchestrationError("engine-group release does not match its sealed bytes")
    coordinator = value.get("engine_coordinator_id")
    if not isinstance(coordinator, str) or not ID_RE.fullmatch(coordinator):
        raise OrchestrationError("engine-group document coordinator is invalid")
    members = value.get("members")
    member_fields = {
        "member_id", "address", "rank", "role_rank", "role", "port_base",
        "port_count", "inference_endpoint", "device_uuids",
    }
    if (
        not isinstance(members, list)
        or len(members) not in range(1, 65)
        or any(not isinstance(item, dict) or set(item) != member_fields for item in members)
    ):
        raise OrchestrationError("engine-group document members are invalid")
    ids: list[str] = []
    ranks: list[int] = []
    role_ranks: dict[str, list[int]] = {}
    for item in members:
        member_id = item.get("member_id")
        address = item.get("address")
        rank = item.get("rank")
        role_rank = item.get("role_rank")
        role = item.get("role")
        port_base = item.get("port_base")
        port_count = item.get("port_count")
        if not isinstance(member_id, str) or not ID_RE.fullmatch(member_id):
            raise OrchestrationError("engine-group document member identity is invalid")
        if not isinstance(address, str) or not address or len(address.encode("utf-8")) > 255:
            raise OrchestrationError("engine-group document member address is invalid")
        if not isinstance(rank, int) or isinstance(rank, bool) or rank < 0:
            raise OrchestrationError("engine-group document member rank is invalid")
        if not isinstance(role_rank, int) or isinstance(role_rank, bool) or role_rank < 0:
            raise OrchestrationError("engine-group document role rank is invalid")
        if role not in {"engine", "engine-member", "engine-coordinator"}:
            raise OrchestrationError("engine-group document role is invalid")
        if (
            not isinstance(port_base, int)
            or isinstance(port_base, bool)
            or port_base not in range(1024, 65536)
            or not isinstance(port_count, int)
            or isinstance(port_count, bool)
            or port_count not in range(1, 33)
            or port_base + port_count > 65536
        ):
            raise OrchestrationError("engine-group document port range is invalid")
        if not isinstance(item.get("inference_endpoint"), bool):
            raise OrchestrationError("engine-group document endpoint flag is invalid")
        device_uuids = item.get("device_uuids")
        if (
            not isinstance(device_uuids, list)
            or not device_uuids
            or len(device_uuids) != len(set(device_uuids))
            or any(
                not isinstance(device_uuid, str)
                or not device_uuid
                or len(device_uuid.encode("utf-8")) > 255
                for device_uuid in device_uuids
            )
        ):
            raise OrchestrationError("engine-group document device allocation is invalid")
        ids.append(member_id)
        ranks.append(rank)
        role_ranks.setdefault(role, []).append(role_rank)
    if len(set(ids)) != len(ids) or sorted(ranks) != list(range(len(members))):
        raise OrchestrationError("engine-group document members are duplicated or misranked")
    if coordinator not in ids or members[0]["member_id"] != coordinator or members[0]["rank"] != 0:
        raise OrchestrationError("engine-group document coordinator must have rank zero")
    if any(sorted(values) != list(range(len(values))) for values in role_ranks.values()):
        raise OrchestrationError("engine-group document role ranks are not contiguous")
    strategy = value["strategy"]
    if strategy == "single":
        if (
            len(members) != 1
            or value.get("failure_policy") != "independent"
            or value.get("startup_order") != ["engine"]
            or set(role_ranks) != {"engine"}
            or not members[0]["inference_endpoint"]
            or value.get("minimum_healthy_members") != 1
        ):
            raise OrchestrationError("single engine-group document is inconsistent")
    else:
        if (
            value.get("failure_policy") != "whole-group"
            or value.get("minimum_healthy_members") != len(members)
            or value.get("startup_order") != ["engine-member", "engine-coordinator"]
            or set(role_ranks) != {"engine-member", "engine-coordinator"}
            or len(role_ranks["engine-coordinator"]) != 1
        ):
            raise OrchestrationError("parallel engine-group document is inconsistent")
        for item in members:
            expected_endpoint = item["role"] == "engine-coordinator"
            if item["inference_endpoint"] is not expected_endpoint:
                raise OrchestrationError("parallel engine-group endpoint assignment is invalid")
    identity = {
        "contract": "letsinfer-engine-group-v2",
        "service_id": value["service_id"],
        "release": release,
        "strategy": strategy,
        "engine_strategy": value["engine_strategy"],
        "topology_sha256": value["topology_sha256"],
        "manifest_sha256": value["manifest_sha256"],
        "runtime_digest": value["runtime_digest"],
        "engine_coordinator_id": coordinator,
        "members": [
            {
                "member_id": item["member_id"], "address": item["address"],
                "role": item["role"], "port_base": item["port_base"],
                "port_count": item["port_count"],
                "device_uuids": item["device_uuids"],
            }
            for item in members
        ],
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
    """Validate one runtime-owned, engine-specific group contract."""
    required = {
        "schema_version",
        "strategy",
        "member_count",
        "engine_strategy",
        "failure_policy",
        "minimum_healthy_members",
        "startup_order",
        "roles",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise OrchestrationError(
            "runtime.orchestration must contain exactly schema_version, strategy, "
            "member_count, engine_strategy, failure_policy, minimum_healthy_members, "
            "startup_order, and roles"
        )
    if (
        type(value.get("schema_version")) is not int
        or value.get("schema_version") != SCHEMA_VERSION
    ):
        raise OrchestrationError("unsupported runtime.orchestration schema_version")
    strategy = value.get("strategy")
    if strategy != "parallel":
        raise OrchestrationError("runtime.orchestration.strategy must be parallel")
    member_count = value.get("member_count")
    if (
        not isinstance(member_count, int)
        or isinstance(member_count, bool)
        or member_count not in range(1, 65)
    ):
        raise OrchestrationError("runtime.orchestration.member_count must be from 2 through 64")
    engine_strategy = value.get("engine_strategy")
    if not isinstance(engine_strategy, str) or not SAFE_NAME_RE.fullmatch(engine_strategy):
        raise OrchestrationError("runtime.orchestration.engine_strategy is invalid")

    if value.get("failure_policy") != "whole-group":
        raise OrchestrationError("parallel orchestration requires whole-group failure policy")
    expected_roles: dict[str, tuple[str, bool]] = {
        "engine-member": ("members", False),
        "engine-coordinator": ("engine-coordinator", True),
    }
    if value.get("minimum_healthy_members") != member_count:
        raise OrchestrationError(
            "parallel orchestration requires every member to remain healthy"
        )
    roles = value.get("roles")
    if not isinstance(roles, dict) or set(roles) != set(expected_roles):
        raise OrchestrationError(
            f"{strategy} orchestration roles must be exactly {', '.join(sorted(expected_roles))}"
        )
    expected_order = ["engine-member", "engine-coordinator"]
    if value.get("startup_order") != expected_order:
        raise OrchestrationError(
            f"runtime.orchestration.startup_order must be {expected_order!r}"
        )

    for name, (assignment, inference_endpoint) in expected_roles.items():
        role = roles[name]
        common = {
            "assignment", "launcher", "environment", "port_count",
            "inference_endpoint", "readiness",
        }
        if not isinstance(role, dict) or not common.issubset(role):
            raise OrchestrationError(f"runtime.orchestration.roles.{name} is incomplete")
        launcher = role.get("launcher")
        expected_fields = common if launcher == "manifest" else common | {"command"}
        if launcher not in {"manifest", "runtime-command"} or set(role) != expected_fields:
            raise OrchestrationError(f"runtime.orchestration.roles.{name} has invalid fields")
        if role.get("assignment") != assignment:
            raise OrchestrationError(
                f"runtime.orchestration.roles.{name}.assignment must be {assignment}"
            )
        if role.get("inference_endpoint") is not inference_endpoint:
            raise OrchestrationError(
                f"runtime.orchestration.roles.{name}.inference_endpoint is invalid"
            )
        port_count = role.get("port_count")
        if (
            not isinstance(port_count, int)
            or isinstance(port_count, bool)
            or port_count not in range(1, 33)
        ):
            raise OrchestrationError(
                f"runtime.orchestration.roles.{name}.port_count must be from 1 through 32"
            )
        _environment(role.get("environment"), f"runtime.orchestration.roles.{name}.environment")
        if launcher == "runtime-command":
            _argv(role.get("command"), f"runtime.orchestration.roles.{name}.command")
        _readiness(role.get("readiness"), launcher, f"runtime.orchestration.roles.{name}.readiness")
    return value


def validate_target_binding(value: Any, placement: Mapping[str, Any]) -> dict[str, Any] | None:
    """Require the runtime group contract to exactly bind its target placement."""
    strategy = placement.get("strategy")
    if strategy == "single":
        if value is not None:
            raise OrchestrationError("single-member targets cannot declare runtime orchestration")
        return None
    contract = validate_orchestration_contract(value)
    for key in ("strategy", "member_count", "engine_strategy"):
        if contract[key] != placement.get(key):
            raise OrchestrationError(
                f"runtime.orchestration.{key} does not match target.placement.{key}"
            )
    return contract


def build_group_plan(
    value: Any,
    *,
    member_ids: Sequence[str],
    member_addresses: Mapping[str, str],
    engine_coordinator_id: str,
    topology_sha256: str,
    manifest_sha256: str,
    runtime_digest: str,
    service_id: str,
    release: Mapping[str, Any],
    member_port_bases: Mapping[str, int],
    member_device_uuids: Mapping[str, Sequence[str]],
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
        len(members) != contract["member_count"]
        or len(set(members)) != len(members)
        or any(not isinstance(item, str) or not ID_RE.fullmatch(item) for item in members)
    ):
        raise OrchestrationError("group members do not match the runtime member count")
    if engine_coordinator_id not in members:
        raise OrchestrationError("engine coordinator is not a group member")
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

    ordered = (engine_coordinator_id,) + tuple(
        member for member in members if member != engine_coordinator_id
    )
    assignments: list[RoleAssignment] = []
    role_ranks: dict[str, int] = {}
    for rank, member_id in enumerate(ordered):
        role_name = (
            "engine-coordinator"
            if member_id == engine_coordinator_id
            else "engine-member"
        )
        role = contract["roles"][role_name]
        port_base = member_port_bases[member_id]
        port_count = role["port_count"]
        if (
            not isinstance(port_base, int)
            or isinstance(port_base, bool)
            or port_base not in range(1024, 65536)
            or port_base + port_count > 65536
        ):
            raise OrchestrationError("group member port range is invalid")
        role_rank = role_ranks.get(role_name, 0)
        role_ranks[role_name] = role_rank + 1
        assignments.append(
            RoleAssignment(
                member_id=member_id,
                address=member_addresses[member_id],
                rank=rank,
                role_rank=role_rank,
                role=role_name,
                port_base=port_base,
                port_count=port_count,
                launcher=role["launcher"],
                command=tuple(role.get("command", ())),
                environment=_environment(
                    role["environment"],
                    f"runtime.orchestration.roles.{role_name}.environment",
                ),
                inference_endpoint=role["inference_endpoint"],
                readiness=_readiness(
                    role["readiness"],
                    role["launcher"],
                    f"runtime.orchestration.roles.{role_name}.readiness",
                ),
                device_uuids=tuple(member_device_uuids[member_id]),
            )
        )
    identity = {
        "contract": "letsinfer-engine-group-v2",
        "service_id": service_id,
        "release": safe_release,
        "strategy": contract["strategy"],
        "engine_strategy": contract["engine_strategy"],
        "topology_sha256": topology_sha256,
        "manifest_sha256": manifest_sha256,
        "runtime_digest": runtime_digest,
        "engine_coordinator_id": engine_coordinator_id,
        "members": [
            {
                "member_id": item.member_id, "address": item.address,
                "role": item.role, "port_base": item.port_base,
                "port_count": item.port_count,
                "device_uuids": list(item.device_uuids),
            }
            for item in assignments
        ],
    }
    return GroupPlan(
        group_id=hashlib.sha256(_canonical_bytes(identity)).hexdigest()[:32],
        service_id=service_id,
        release=safe_release,
        strategy=contract["strategy"],
        engine_strategy=contract["engine_strategy"],
        failure_policy=contract["failure_policy"],
        minimum_healthy_members=contract["minimum_healthy_members"],
        topology_sha256=topology_sha256,
        manifest_sha256=manifest_sha256,
        runtime_digest=runtime_digest,
        engine_coordinator_id=engine_coordinator_id,
        startup_order=tuple(contract["startup_order"]),
        assignments=tuple(assignments),
    )


def build_single_group_plan(
    *,
    member_id: str,
    member_address: str,
    device_uuids: Sequence[str],
    engine_strategy: str,
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
    if not isinstance(engine_strategy, str) or not SAFE_NAME_RE.fullmatch(engine_strategy):
        raise OrchestrationError("single group engine strategy is invalid")
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
    assignment = RoleAssignment(
        member_id=member_id,
        address=member_address,
        rank=0,
        role_rank=0,
        role="engine",
        port_base=port_base,
        port_count=1,
        launcher="manifest",
        command=(),
        environment=(),
        inference_endpoint=True,
        readiness={"kind": "manifest"},
        device_uuids=tuple(device_uuids),
    )
    identity = {
        "contract": "letsinfer-engine-group-v2",
        "service_id": service_id,
        "release": safe_release,
        "strategy": "single",
        "engine_strategy": engine_strategy,
        "topology_sha256": topology_sha256,
        "manifest_sha256": manifest_sha256,
        "runtime_digest": runtime_digest,
        "engine_coordinator_id": member_id,
        "members": [
            {
                "member_id": member_id,
                "address": member_address,
                "role": "engine",
                "port_base": port_base,
                "port_count": 1,
                "device_uuids": list(device_uuids),
            }
        ],
    }
    return GroupPlan(
        group_id=hashlib.sha256(_canonical_bytes(identity)).hexdigest()[:32],
        service_id=service_id,
        release=safe_release,
        strategy="single",
        engine_strategy=engine_strategy,
        failure_policy="independent",
        minimum_healthy_members=1,
        topology_sha256=topology_sha256,
        manifest_sha256=manifest_sha256,
        runtime_digest=runtime_digest,
        engine_coordinator_id=member_id,
        startup_order=("engine",),
        assignments=(assignment,),
    )
