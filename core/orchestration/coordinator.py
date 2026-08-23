#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Coordinator-owned, fail-closed lifecycle for immutable engine groups."""

from __future__ import annotations

import hashlib
import re
import time
import uuid
from collections.abc import Callable, Mapping
from typing import Any, Optional

from core.site.state import SiteError, SiteStore

from .contracts import (
    GroupPlan,
    RoleAssignment,
    validate_group_document,
    validate_orchestration_contract,
)
from .credentials import (
    GroupCredentialError,
    credential_sha256,
    derive_group_credential,
)
from .member import PROTOCOL, canonical_bytes


OCI_RE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
ID_RE = re.compile(r"^[0-9a-f]{32}$")
JOB_LIFETIME_SECONDS = 120
GROUP_PORT_MIN = 18000
GROUP_PORT_MAX = 60000


class GroupOrchestrationError(RuntimeError):
    """A member group could not reach or retain its qualified topology."""


SubmitJob = Callable[[Mapping[str, Any], Mapping[str, Any], Optional[str]], Mapping[str, Any]]
FetchStatus = Callable[[Mapping[str, Any], str], Mapping[str, Any]]
FetchJob = Callable[[Mapping[str, Any], str], Mapping[str, Any]]
JOB_TIMEOUT_SECONDS = {
    "stage": 24 * 60 * 60,
    "start": 12 * 60 * 60,
    "recover": 12 * 60 * 60,
    "stop": 10 * 60,
    "remove": 10 * 60,
}


def allocate_group_ports(
    contract: Mapping[str, Any],
    *,
    member_ids: tuple[str, ...],
    engine_coordinator_id: str,
    occupied: Mapping[str, tuple[tuple[int, int], ...]],
) -> dict[str, int]:
    """Allocate deterministic non-overlapping member-local port ranges."""
    validated = validate_orchestration_contract(dict(contract))
    if (
        len(member_ids) != validated["member_count"]
        or len(set(member_ids)) != len(member_ids)
        or engine_coordinator_id not in member_ids
        or any(not ID_RE.fullmatch(item) for item in member_ids)
    ):
        raise GroupOrchestrationError("port allocation members are invalid")
    if set(occupied) - set(member_ids):
        raise GroupOrchestrationError("port allocation contains an unrelated member")
    result: dict[str, int] = {}
    for member_id in member_ids:
        role = (
            "engine-coordinator"
            if member_id == engine_coordinator_id
            else "engine-member"
        )
        count = validated["roles"][role]["port_count"]
        ranges = list(occupied.get(member_id, ()))
        for base, length in ranges:
            if (
                not isinstance(base, int)
                or isinstance(base, bool)
                or not isinstance(length, int)
                or isinstance(length, bool)
                or length <= 0
                or base < 1
                or base + length > 65536
            ):
                raise GroupOrchestrationError("occupied member port range is invalid")
        selected: int | None = None
        for base in range(GROUP_PORT_MIN, GROUP_PORT_MAX - count + 1):
            if all(base + count <= used or used + length <= base for used, length in ranges):
                selected = base
                break
        if selected is None:
            raise GroupOrchestrationError(f"no contiguous engine ports remain on member {member_id}")
        result[member_id] = selected
    return result


def group_job(
    plan: GroupPlan,
    assignment: RoleAssignment,
    *,
    action: str,
    source: str | None,
    engine_credential_sha256: str,
    operation_id: str | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    """Create one exact, short-lived member operation from a sealed plan."""
    if action not in {"stage", "start", "recover", "stop", "remove"}:
        raise GroupOrchestrationError("engine-group action is invalid")
    if action == "stage":
        if not isinstance(source, str) or not OCI_RE.fullmatch(source):
            raise GroupOrchestrationError("stage requires a digest-pinned OCI runtime source")
    elif source is not None:
        raise GroupOrchestrationError("only stage may carry a runtime source")
    identifier = operation_id or uuid.uuid4().hex
    if not ID_RE.fullmatch(identifier):
        raise GroupOrchestrationError("engine-group operation identity is invalid")
    group = validate_group_document(plan.document())
    return {
        "protocol": PROTOCOL,
        "operation_id": identifier,
        "group_id": plan.group_id,
        "action": action,
        "member_id": assignment.member_id,
        "plan_sha256": hashlib.sha256(canonical_bytes(group)).hexdigest(),
        "runtime_digest": plan.runtime_digest,
        "manifest_sha256": plan.manifest_sha256,
        "topology_sha256": plan.topology_sha256,
        "engine_credential_sha256": engine_credential_sha256,
        "expires_at_unix": (int(time.time()) if now is None else now) + JOB_LIFETIME_SECONDS,
        "source": source,
        "role": {
            "name": assignment.role,
            "rank": assignment.rank,
            "role_rank": assignment.role_rank,
            "port_base": assignment.port_base,
            "port_count": assignment.port_count,
            "launcher": assignment.launcher,
            "command": list(assignment.command),
            "environment": dict(assignment.environment),
            "inference_endpoint": assignment.inference_endpoint,
            "readiness": dict(assignment.readiness),
            "device_uuids": list(assignment.device_uuids),
        },
        "group": group,
    }


class EngineGroupOrchestrator:
    """Execute ordered lifecycle transitions and durably audit every step."""

    def __init__(
        self,
        *,
        store: SiteStore,
        plan: GroupPlan,
        placement_id: str,
        source: str,
        members: Mapping[str, Mapping[str, Any]],
        submit: SubmitJob,
        status: FetchStatus,
        job_status: FetchJob,
        actor_type: str = "system",
        actor_id: str = "main",
        origin_interface: str = "orchestrator",
        correlation_id: str | None = None,
        engine_credential: str | None = None,
    ) -> None:
        validate_group_document(plan.document())
        if not ID_RE.fullmatch(placement_id):
            raise GroupOrchestrationError("engine-group placement identity is invalid")
        if not OCI_RE.fullmatch(source):
            raise GroupOrchestrationError("engine-group source must be digest-pinned OCI")
        if set(members) != {item.member_id for item in plan.assignments}:
            raise GroupOrchestrationError("engine-group member controls are incomplete")
        for member_id, member in members.items():
            if (
                member.get("member_id") != member_id
                or not isinstance(member.get("address"), str)
                or not member["address"]
                or not isinstance(member.get("certificate_sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", member["certificate_sha256"])
            ):
                raise GroupOrchestrationError("engine-group member control identity is invalid")
        self.store = store
        self.plan = plan
        self.placement_id = placement_id
        self.source = source
        self.members = {key: dict(value) for key, value in members.items()}
        self.submit = submit
        self.fetch_status = status
        self.fetch_job_status = job_status
        self.actor_type = actor_type
        self.actor_id = actor_id
        self.origin_interface = origin_interface
        self.correlation_id = correlation_id or uuid.uuid4().hex
        try:
            self.engine_credential = (
                derive_group_credential(plan.group_id)
                if engine_credential is None
                else engine_credential
            )
            self.engine_credential_sha256 = credential_sha256(self.engine_credential)
        except GroupCredentialError as error:
            raise GroupOrchestrationError(str(error)) from error
        self.states = {
            item.member_id: {
                "member_id": item.member_id,
                "role": item.role,
                "rank": item.rank,
                "state": "pending",
                "operation_id": None,
                "error": None,
            }
            for item in plan.assignments
        }
        self.results: dict[str, dict[str, Any]] = {}
        self.protection_trips: dict[str, bool] = {
            item.member_id: False for item in plan.assignments
        }
        self.persisted_state: str | None = None

    def _persist(
        self,
        *,
        action: str,
        desired_state: str,
        state: str,
        error: str | None = None,
    ) -> dict[str, Any]:
        try:
            result = self.store.set_engine_group(
                self.plan.document(),
                placement_id=self.placement_id,
                source=self.source,
                engine_credential_sha256=self.engine_credential_sha256,
                desired_state=desired_state,
                state=state,
                members=[self.states[item.member_id] for item in self.plan.assignments],
                action=action,
                error=error,
                actor_type=self.actor_type,
                actor_id=self.actor_id,
                origin_interface=self.origin_interface,
                correlation_id=self.correlation_id,
            )
            self.persisted_state = state
            return result
        except SiteError as persistence_error:
            raise GroupOrchestrationError(str(persistence_error)) from persistence_error

    def _invoke(self, assignment: RoleAssignment, action: str) -> Mapping[str, Any]:
        operation_id = uuid.uuid4().hex
        state = self.states[assignment.member_id]
        state["operation_id"] = operation_id
        state["state"] = {
            "stage": "staging", "start": "starting", "recover": "starting",
            "stop": "stopping", "remove": "removing",
        }[action]
        state["error"] = None
        job = group_job(
            self.plan,
            assignment,
            action=action,
            source=self.source if action == "stage" else None,
            engine_credential_sha256=self.engine_credential_sha256,
            operation_id=operation_id,
        )
        response = self.submit(
            self.members[assignment.member_id],
            job,
            self.engine_credential if action == "stage" else None,
        )
        if (
            not isinstance(response, Mapping)
            or response.get("protocol") != PROTOCOL
            or response.get("operation_id") != operation_id
            or response.get("state") not in {"running", "succeeded"}
        ):
            raise GroupOrchestrationError("member returned an invalid engine-group response")
        if response["state"] == "running":
            deadline = time.monotonic() + JOB_TIMEOUT_SECONDS[action]
            while time.monotonic() < deadline:
                status = self.fetch_job_status(
                    self.members[assignment.member_id], operation_id
                )
                if (
                    not isinstance(status, Mapping)
                    or status.get("protocol") != PROTOCOL
                    or not isinstance(status.get("job"), Mapping)
                    or status["job"].get("operation_id") != operation_id
                ):
                    raise GroupOrchestrationError(
                        "member returned an invalid engine-group job status"
                    )
                member_job = status["job"]
                if member_job.get("state") == "succeeded":
                    response = {
                        "protocol": PROTOCOL,
                        "operation_id": operation_id,
                        "state": "succeeded",
                        "result": member_job.get("result"),
                    }
                    break
                if member_job.get("state") == "failed":
                    raise GroupOrchestrationError(
                        f"member engine-group {action} failed: "
                        f"{member_job.get('error') or 'unknown'}"
                    )
                if member_job.get("state") != "running":
                    raise GroupOrchestrationError(
                        "member engine-group job entered an invalid state"
                    )
                time.sleep(1.0)
            else:
                raise GroupOrchestrationError(
                    f"member engine-group {action} timed out"
                )
        if not isinstance(response.get("result"), Mapping):
            raise GroupOrchestrationError("member engine-group result is invalid")
        self.results[assignment.member_id] = dict(response["result"])
        state["state"] = {
            "stage": "staged", "start": "running", "recover": "running",
            "stop": "stopped", "remove": "removed",
        }[action]
        return response

    def stage(self) -> dict[str, Any]:
        self._persist(action="group.stage", desired_state="running", state="staging")
        completed: list[RoleAssignment] = []
        try:
            for assignment in self.plan.assignments:
                self._invoke(assignment, "stage")
                completed.append(assignment)
                self._persist(action="group.stage", desired_state="running", state="staging")
        except BaseException as error:
            failing = next(
                (item for item in self.plan.assignments if self.states[item.member_id]["state"] == "staging"),
                None,
            )
            if failing is not None:
                self.states[failing.member_id]["state"] = "failed"
                self.states[failing.member_id]["error"] = type(error).__name__
            for assignment in reversed(completed):
                try:
                    self._invoke(assignment, "remove")
                except BaseException:
                    self.states[assignment.member_id]["state"] = "failed"
                    self.states[assignment.member_id]["error"] = "rollback_failed"
            self._persist(
                action="group.stage", desired_state="stopped", state="failed",
                error=type(error).__name__,
            )
            if isinstance(error, GroupOrchestrationError):
                raise
            raise GroupOrchestrationError(f"engine-group staging failed: {type(error).__name__}") from error
        return self._persist(action="group.stage", desired_state="running", state="staged")

    def _role_order(self, *, reverse: bool = False) -> list[RoleAssignment]:
        role_order = list(self.plan.startup_order)
        if reverse:
            role_order.reverse()
        assignments: list[RoleAssignment] = []
        for role in role_order:
            same_role = [item for item in self.plan.assignments if item.role == role]
            same_role.sort(key=lambda item: item.role_rank, reverse=reverse)
            assignments.extend(same_role)
        return assignments

    def start(self) -> dict[str, Any]:
        self._persist(action="group.start", desired_state="running", state="starting")
        started: list[RoleAssignment] = []
        try:
            for assignment in self._role_order():
                self._invoke(assignment, "start")
                started.append(assignment)
                self._persist(action="group.start", desired_state="running", state="starting")
        except BaseException as error:
            failing = next(
                (item for item in self.plan.assignments if self.states[item.member_id]["state"] == "starting"),
                None,
            )
            if failing is not None:
                self.states[failing.member_id]["state"] = "failed"
                self.states[failing.member_id]["error"] = type(error).__name__
            for assignment in reversed(started):
                try:
                    self._invoke(assignment, "stop")
                except BaseException:
                    self.states[assignment.member_id]["state"] = "failed"
                    self.states[assignment.member_id]["error"] = "rollback_failed"
            self._persist(
                action="group.start", desired_state="stopped", state="failed",
                error=type(error).__name__,
            )
            if isinstance(error, GroupOrchestrationError):
                raise
            raise GroupOrchestrationError(f"engine-group start failed: {type(error).__name__}") from error
        result = self._persist(action="group.start", desired_state="running", state="running")
        self.store.set_group_allocation_state(
            self.plan.group_id,
            "active",
            actor_type=self.actor_type,
            actor_id=self.actor_id,
            origin_interface=self.origin_interface,
            correlation_id=self.correlation_id,
        )
        return result

    def stop(self) -> dict[str, Any]:
        self.store.set_group_allocation_state(
            self.plan.group_id,
            "draining",
            actor_type=self.actor_type,
            actor_id=self.actor_id,
            origin_interface=self.origin_interface,
            correlation_id=self.correlation_id,
        )
        self._persist(action="group.stop", desired_state="stopped", state="stopping")
        failures: list[str] = []
        for assignment in self._role_order(reverse=True):
            try:
                self._invoke(assignment, "stop")
            except BaseException as error:
                self.states[assignment.member_id]["state"] = "failed"
                self.states[assignment.member_id]["error"] = type(error).__name__
                failures.append(assignment.member_id)
            self._persist(action="group.stop", desired_state="stopped", state="stopping")
        if failures:
            self._persist(
                action="group.stop", desired_state="stopped", state="failed",
                error="member_stop_failed",
            )
            raise GroupOrchestrationError(
                "engine-group stop failed on member(s): " + ",".join(failures)
            )
        result = self._persist(action="group.stop", desired_state="stopped", state="stopped")
        self.store.set_group_allocation_state(
            self.plan.group_id,
            "reserved",
            actor_type=self.actor_type,
            actor_id=self.actor_id,
            origin_interface=self.origin_interface,
            correlation_id=self.correlation_id,
        )
        return result

    def remove(self) -> dict[str, Any]:
        self._persist(action="group.remove", desired_state="removed", state="removing")
        failures: list[str] = []
        for assignment in self._role_order(reverse=True):
            try:
                self._invoke(assignment, "remove")
            except BaseException as error:
                self.states[assignment.member_id]["state"] = "failed"
                self.states[assignment.member_id]["error"] = type(error).__name__
                failures.append(assignment.member_id)
            self._persist(action="group.remove", desired_state="removed", state="removing")
        if failures:
            self._persist(
                action="group.remove", desired_state="removed", state="failed",
                error="member_remove_failed",
            )
            raise GroupOrchestrationError(
                "engine-group removal failed on member(s): " + ",".join(failures)
            )
        result = self._persist(action="group.remove", desired_state="removed", state="removed")
        self.store.set_group_allocation_state(
            self.plan.group_id,
            "released",
            actor_type=self.actor_type,
            actor_id=self.actor_id,
            origin_interface=self.origin_interface,
            correlation_id=self.correlation_id,
        )
        return result

    def reconcile(self) -> dict[str, Any]:
        previous_states = {
            member_id: dict(value) for member_id, value in self.states.items()
        }
        running = 0
        for assignment in self.plan.assignments:
            state = self.states[assignment.member_id]
            try:
                response = self.fetch_status(self.members[assignment.member_id], self.plan.group_id)
                group = response.get("group")
                trip = response.get("protection_trip_latched")
                if (
                    not isinstance(group, Mapping)
                    or group.get("group_id") != self.plan.group_id
                    or not isinstance(trip, bool)
                ):
                    raise GroupOrchestrationError("member group status is invalid")
                self.protection_trips[assignment.member_id] = trip
                observed = group.get("state")
                if observed not in {"staged", "running", "stopped", "failed", "removed"}:
                    raise GroupOrchestrationError("member group state is invalid")
                state["state"] = observed
                state["error"] = None
                if observed == "running":
                    running += 1
            except BaseException:
                state["state"] = "unreachable"
                state["error"] = "member_unreachable"
                self.protection_trips[assignment.member_id] = False
        if running == len(self.plan.assignments):
            group_state = "running"
        else:
            group_state = "failed"
        if self.persisted_state == group_state and previous_states == self.states:
            return {
                **self.plan.document(),
                "placement_id": self.placement_id,
                "source": self.source,
                "engine_credential_sha256": self.engine_credential_sha256,
                "desired_state": "running",
                "state": group_state,
                "member_states": [
                    dict(self.states[item.member_id])
                    for item in self.plan.assignments
                ],
                "last_error": None,
            }
        return self._persist(
            action="group.reconcile",
            desired_state="running",
            state=group_state,
            error=None if group_state in {"running", "degraded"} else "insufficient_healthy_members",
        )

    def recover(self, *, acknowledge_trips: bool = False) -> dict[str, Any]:
        """Restart the complete group, clearing trips only for an explicit action."""
        self._persist(action="group.recover", desired_state="running", state="recovering")
        self.stop()
        self._persist(action="group.recover", desired_state="running", state="recovering")
        started: list[RoleAssignment] = []
        action = "recover" if acknowledge_trips else "start"
        try:
            for assignment in self._role_order():
                self._invoke(assignment, action)
                started.append(assignment)
                self._persist(
                    action="group.recover",
                    desired_state="running",
                    state="recovering",
                )
        except BaseException as error:
            failing = next(
                (
                    item
                    for item in self.plan.assignments
                    if self.states[item.member_id]["state"] == "starting"
                ),
                None,
            )
            if failing is not None:
                self.states[failing.member_id]["state"] = "failed"
                self.states[failing.member_id]["error"] = type(error).__name__
            for assignment in reversed(started):
                try:
                    self._invoke(assignment, "stop")
                except BaseException:
                    self.states[assignment.member_id]["state"] = "failed"
                    self.states[assignment.member_id]["error"] = "rollback_failed"
            self._persist(
                action="group.recover",
                desired_state="running",
                state="failed",
                error=type(error).__name__,
            )
            if isinstance(error, GroupOrchestrationError):
                raise
            raise GroupOrchestrationError(
                f"engine-group recovery failed: {type(error).__name__}"
            ) from error
        result = self._persist(
            action="group.recover", desired_state="running", state="running"
        )
        self.store.set_group_allocation_state(
            self.plan.group_id,
            "active",
            actor_type=self.actor_type,
            actor_id=self.actor_id,
            origin_interface=self.origin_interface,
            correlation_id=self.correlation_id,
        )
        return result
