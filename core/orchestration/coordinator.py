#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Coordinator-owned, fail-closed lifecycle for immutable placement groups."""

from __future__ import annotations

import hashlib
import re
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections.abc import Callable, Mapping
from typing import Any, Optional

from core.site.state import SiteError, SiteStore
from core.runtime_sources import is_immutable_runtime_source

from .contracts import (
    PlacementGroupPlan,
    Placement,
    validate_placement_group_document,
    validate_orchestration_contract,
)
from .credentials import (
    PlacementGroupCredentialError,
    credential_sha256,
    derive_placement_group_credential,
)
from .member import PROTOCOL, canonical_bytes


ID_RE = re.compile(r"^[0-9a-f]{32}$")
JOB_LIFETIME_SECONDS = 120
PLACEMENT_PORT_MIN = 18000
PLACEMENT_PORT_MAX = 60000


class PlacementGroupOrchestrationError(RuntimeError):
    """A placement group could not reach or retain its qualified topology."""


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


def allocate_placement_ports(
    contract: Mapping[str, Any],
    *,
    member_ids: tuple[str, ...],
    occupied: Mapping[str, tuple[tuple[int, int], ...]],
) -> dict[str, int]:
    """Allocate deterministic non-overlapping member-local port ranges."""
    validated = validate_orchestration_contract(dict(contract))
    if (
        len(member_ids) != len(validated["tasks"])
        or len(set(member_ids)) != len(member_ids)
        or any(not ID_RE.fullmatch(item) for item in member_ids)
    ):
        raise PlacementGroupOrchestrationError("port allocation members are invalid")
    if set(occupied) - set(member_ids):
        raise PlacementGroupOrchestrationError("port allocation contains an unrelated member")
    result: dict[str, int] = {}
    for index, member_id in enumerate(member_ids):
        count = validated["tasks"][index]["port_count"]
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
                raise PlacementGroupOrchestrationError("occupied member port range is invalid")
        selected: int | None = None
        for base in range(PLACEMENT_PORT_MIN, PLACEMENT_PORT_MAX - count + 1):
            if all(base + count <= used or used + length <= base for used, length in ranges):
                selected = base
                break
        if selected is None:
            raise PlacementGroupOrchestrationError(f"no contiguous engine ports remain on member {member_id}")
        result[member_id] = selected
    return result


def placement_job(
    plan: PlacementGroupPlan,
    placement: Placement,
    *,
    action: str,
    source: str | None,
    engine_credential_sha256: str,
    operation_id: str | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    """Create one exact, short-lived member operation from a sealed plan."""
    if action not in {"stage", "start", "recover", "stop", "remove"}:
        raise PlacementGroupOrchestrationError("placement-group action is invalid")
    if action == "stage":
        if not is_immutable_runtime_source(source):
            raise PlacementGroupOrchestrationError("stage requires an immutable runtime source")
    elif source is not None:
        raise PlacementGroupOrchestrationError("only stage may carry a runtime source")
    identifier = operation_id or uuid.uuid4().hex
    if not ID_RE.fullmatch(identifier):
        raise PlacementGroupOrchestrationError("placement-group operation identity is invalid")
    placement_group = validate_placement_group_document(plan.document())
    return {
        "protocol": PROTOCOL,
        "operation_id": identifier,
        "placement_group_id": plan.placement_group_id,
        "placement_id": placement.placement_id,
        "action": action,
        "node_id": placement.node_id,
        "plan_sha256": hashlib.sha256(canonical_bytes(placement_group)).hexdigest(),
        "runtime_digest": plan.runtime_digest,
        "manifest_sha256": plan.manifest_sha256,
        "topology_sha256": plan.topology_sha256,
        "engine_credential_sha256": engine_credential_sha256,
        "expires_at_unix": (int(time.time()) if now is None else now) + JOB_LIFETIME_SECONDS,
        "source": source,
        "placement": {
            "placement_id": placement.placement_id,
            "node_id": placement.node_id,
            "task_id": placement.task_id,
            "port_base": placement.port_base,
            "port_count": placement.port_count,
            "launcher": placement.launcher,
            "command": list(placement.command),
            "environment": dict(placement.environment),
            "endpoint_owner": placement.endpoint_owner,
            "readiness": dict(placement.readiness),
            "device_uuids": list(placement.device_uuids),
        },
        "placement_group": placement_group,
    }


class PlacementGroupOrchestrator:
    """Execute ordered lifecycle transitions and durably audit every step."""

    def __init__(
        self,
        *,
        store: SiteStore,
        plan: PlacementGroupPlan,
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
        validate_placement_group_document(plan.document())
        if not is_immutable_runtime_source(source):
            raise PlacementGroupOrchestrationError("placement-group source must be immutable")
        if set(members) != {item.node_id for item in plan.placements}:
            raise PlacementGroupOrchestrationError(
                "placement-group node controls are incomplete"
            )
        for member_id, member in members.items():
            if (
                member.get("member_id") != member_id
                or not isinstance(member.get("address"), str)
                or not member["address"]
                or not isinstance(member.get("certificate_sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", member["certificate_sha256"])
            ):
                raise PlacementGroupOrchestrationError(
                    "placement-group node control identity is invalid"
                )
        self.store = store
        self.plan = plan
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
                derive_placement_group_credential(plan.placement_group_id)
                if engine_credential is None
                else engine_credential
            )
            self.engine_credential_sha256 = credential_sha256(self.engine_credential)
        except PlacementGroupCredentialError as error:
            raise PlacementGroupOrchestrationError(str(error)) from error
        self.states = {
            item.placement_id: {
                "placement_id": item.placement_id,
                "node_id": item.node_id,
                "task_id": item.task_id,
                "state": "pending",
                "operation_id": None,
                "error": None,
            }
            for item in plan.placements
        }
        self.results: dict[str, dict[str, Any]] = {}
        self.protection_trips: dict[str, bool] = {
            item.placement_id: False for item in plan.placements
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
            result = self.store.set_placement_group(
                self.plan.document(),
                source=self.source,
                engine_credential_sha256=self.engine_credential_sha256,
                desired_state=desired_state,
                state=state,
                placements=[
                    self.states[item.placement_id] for item in self.plan.placements
                ],
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
            raise PlacementGroupOrchestrationError(str(persistence_error)) from persistence_error

    def _invoke(self, placement: Placement, action: str) -> Mapping[str, Any]:
        operation_id = uuid.uuid4().hex
        state = self.states[placement.placement_id]
        state["operation_id"] = operation_id
        state["state"] = {
            "stage": "staging", "start": "starting", "recover": "starting",
            "stop": "stopping", "remove": "removing",
        }[action]
        state["error"] = None
        if action in {"stop", "remove"}:
            status = self.fetch_status(
                self.members[placement.node_id], self.plan.placement_group_id
            )
            observed_placement = (
                status.get("placement") if isinstance(status, Mapping) else None
            )
            placement_state = (
                observed_placement.get("state")
                if isinstance(observed_placement, Mapping)
                else None
            )
            trip = (
                status.get("protection_trip_latched")
                if isinstance(status, Mapping)
                else None
            )
            if (
                not isinstance(status, Mapping)
                or status.get("protocol") != PROTOCOL
                or not isinstance(trip, bool)
                or (
                    observed_placement is not None
                    and (
                        not isinstance(observed_placement, Mapping)
                        or observed_placement.get("placement_group_id")
                        != self.plan.placement_group_id
                        or observed_placement.get("placement_id")
                        != placement.placement_id
                        or placement_state
                        not in {"staged", "running", "stopped", "failed", "removed"}
                    )
                )
            ):
                raise PlacementGroupOrchestrationError(
                    "node placement status is invalid"
                )
            self.protection_trips[placement.placement_id] = trip
            if (observed_placement is None or placement_state == "removed") and trip:
                raise PlacementGroupOrchestrationError(
                    "refusing to finalize an absent member with a protection trip"
                )
            if observed_placement is None or placement_state == "removed":
                terminal_state = "stopped" if action == "stop" else "removed"
                response = {
                    "protocol": PROTOCOL,
                    "operation_id": operation_id,
                    "state": "succeeded",
                    "result": {"state": terminal_state},
                }
                self.results[placement.placement_id] = dict(response["result"])
                state["state"] = terminal_state
                return response
        job = placement_job(
            self.plan,
            placement,
            action=action,
            source=self.source if action == "stage" else None,
            engine_credential_sha256=self.engine_credential_sha256,
            operation_id=operation_id,
        )
        response = self.submit(
            self.members[placement.node_id],
            job,
            self.engine_credential if action == "stage" else None,
        )
        if (
            not isinstance(response, Mapping)
            or response.get("protocol") != PROTOCOL
            or response.get("operation_id") != operation_id
            or response.get("state") not in {"running", "succeeded"}
        ):
            raise PlacementGroupOrchestrationError("member returned an invalid placement-group response")
        if response["state"] == "running":
            deadline = time.monotonic() + JOB_TIMEOUT_SECONDS[action]
            while time.monotonic() < deadline:
                status = self.fetch_job_status(
                    self.members[placement.node_id], operation_id
                )
                if (
                    not isinstance(status, Mapping)
                    or status.get("protocol") != PROTOCOL
                    or not isinstance(status.get("job"), Mapping)
                    or status["job"].get("operation_id") != operation_id
                ):
                    raise PlacementGroupOrchestrationError(
                        "member returned an invalid placement-group job status"
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
                    raise PlacementGroupOrchestrationError(
                        f"member placement-group {action} failed: "
                        f"{member_job.get('error') or 'unknown'}"
                    )
                if member_job.get("state") != "running":
                    raise PlacementGroupOrchestrationError(
                        "member placement-group job entered an invalid state"
                    )
                time.sleep(1.0)
            else:
                raise PlacementGroupOrchestrationError(
                    f"member placement-group {action} timed out"
                )
        if not isinstance(response.get("result"), Mapping):
            raise PlacementGroupOrchestrationError("member placement-group result is invalid")
        self.results[placement.placement_id] = dict(response["result"])
        state["state"] = {
            "stage": "staged", "start": "running", "recover": "running",
            "stop": "stopped", "remove": "removed",
        }[action]
        return response

    def stage(self) -> dict[str, Any]:
        self._persist(action="placement_group.stage", desired_state="running", state="staging")
        completed: list[Placement] = []
        try:
            for placement in self.plan.placements:
                self._invoke(placement, "stage")
                completed.append(placement)
                self._persist(action="placement_group.stage", desired_state="running", state="staging")
        except BaseException as error:
            failing = next(
                (item for item in self.plan.placements if self.states[item.placement_id]["state"] == "staging"),
                None,
            )
            if failing is not None:
                self.states[failing.placement_id]["state"] = "failed"
                self.states[failing.placement_id]["error"] = type(error).__name__
            for placement in reversed(completed):
                try:
                    self._invoke(placement, "remove")
                except BaseException:
                    self.states[placement.placement_id]["state"] = "failed"
                    self.states[placement.placement_id]["error"] = "rollback_failed"
            self._persist(
                action="placement_group.stage", desired_state="stopped", state="failed",
                error=type(error).__name__,
            )
            if isinstance(error, PlacementGroupOrchestrationError):
                raise
            raise PlacementGroupOrchestrationError(f"placement-group staging failed: {type(error).__name__}") from error
        return self._persist(action="placement_group.stage", desired_state="running", state="staged")

    def _task_order(self, *, reverse: bool = False) -> list[Placement]:
        return [item for phase in self._task_phases(reverse=reverse) for item in phase]

    def _task_phases(self, *, reverse: bool = False) -> list[list[Placement]]:
        phases = list(self.plan.startup_order)
        if reverse:
            phases.reverse()
        by_placement = {
            item.placement_id: item for item in self.plan.placements
        }
        result: list[list[Placement]] = []
        for phase in phases:
            placement_ids = tuple(reversed(phase)) if reverse else phase
            result.append(
                [by_placement[placement_id] for placement_id in placement_ids]
            )
        return result

    def _invoke_phase(
        self,
        placements: list[Placement],
        action: str,
    ) -> tuple[list[Placement], list[tuple[Placement, BaseException]]]:
        """Invoke one runtime-declared phase concurrently and await every task."""
        completed = [
            placement
            for placement in placements
            if action == "remove"
            and self.states[placement.placement_id]["state"] == "removed"
        ]
        pending = [placement for placement in placements if placement not in completed]
        failures: list[tuple[Placement, BaseException]] = []
        preempted: set[str] = set()
        preemption_started = False
        if not pending:
            return completed, failures
        with ThreadPoolExecutor(
            max_workers=len(pending),
            thread_name_prefix=f"letsinfer-placement-{action}",
        ) as executor:
            futures = {
                executor.submit(self._invoke, placement, action): placement
                for placement in pending
            }
            for future in as_completed(futures):
                placement = futures[future]
                try:
                    future.result()
                    completed.append(placement)
                except BaseException as error:
                    member_state = self.states[placement.placement_id]
                    if placement.placement_id not in preempted:
                        member_state["state"] = "failed"
                        member_state["error"] = type(error).__name__
                    failures.append((placement, error))
                    if action in {"start", "recover"} and not preemption_started:
                        preemption_started = True
                        stopped, stop_failures = self._invoke_phase(
                            placements, "stop"
                        )
                        preempted.update(
                            item.placement_id for item in stopped
                        )
                        failures.extend(stop_failures)
        completed.sort(key=lambda item: item.task_id)
        failures.sort(key=lambda item: item[0].task_id)
        return completed, failures

    def _rollback_start_failure(
        self,
        *,
        audit_action: str,
    ) -> list[tuple[Placement, BaseException]]:
        """Preempt every placement and retain allocations until stop is proven."""
        self.store.set_placement_group_allocation_state(
            self.plan.placement_group_id,
            "draining",
            actor_type=self.actor_type,
            actor_id=self.actor_id,
            origin_interface=self.origin_interface,
            correlation_id=self.correlation_id,
        )
        _stopped, failures = self._run_phases(
            "stop",
            reverse=True,
            audit_action=audit_action,
            desired_state="stopped",
            state="stopping",
            stop_on_failure=False,
        )
        if not failures:
            self.store.set_placement_group_allocation_state(
                self.plan.placement_group_id,
                "reserved",
                actor_type=self.actor_type,
                actor_id=self.actor_id,
                origin_interface=self.origin_interface,
                correlation_id=self.correlation_id,
            )
        return failures

    def _run_phases(
        self,
        action: str,
        *,
        reverse: bool = False,
        audit_action: str,
        desired_state: str,
        state: str,
        stop_on_failure: bool = True,
    ) -> tuple[list[Placement], list[tuple[Placement, BaseException]]]:
        completed: list[Placement] = []
        failures: list[tuple[Placement, BaseException]] = []
        for phase in self._task_phases(reverse=reverse):
            phase_completed, phase_failures = self._invoke_phase(phase, action)
            completed.extend(phase_completed)
            failures.extend(phase_failures)
            self._persist(
                action=audit_action,
                desired_state=desired_state,
                state=state,
            )
            if phase_failures and stop_on_failure:
                break
        return completed, failures

    def start(self) -> dict[str, Any]:
        self._persist(action="placement_group.start", desired_state="running", state="starting")
        try:
            _started, failures = self._run_phases(
                "start",
                audit_action="placement_group.start",
                desired_state="running",
                state="starting",
            )
            if failures:
                failed_tasks = sorted({item.task_id for item, _error in failures})
                raise PlacementGroupOrchestrationError(
                    "placement-group start failed on task(s): "
                    + ",".join(failed_tasks)
                )
        except BaseException as error:
            rollback_failures = self._rollback_start_failure(
                audit_action="placement_group.start"
            )
            self._persist(
                action="placement_group.start", desired_state="stopped", state="failed",
                error=(
                    "start_rollback_failed"
                    if rollback_failures
                    else type(error).__name__
                ),
            )
            if rollback_failures:
                failed_tasks = sorted(
                    {item.task_id for item, _failure in rollback_failures}
                )
                raise PlacementGroupOrchestrationError(
                    "placement-group start failed and rollback failed on task(s): "
                    + ",".join(failed_tasks)
                ) from error
            if isinstance(error, PlacementGroupOrchestrationError):
                raise
            raise PlacementGroupOrchestrationError(f"placement-group start failed: {type(error).__name__}") from error
        result = self._persist(action="placement_group.start", desired_state="running", state="running")
        self.store.set_placement_group_allocation_state(
            self.plan.placement_group_id,
            "active",
            actor_type=self.actor_type,
            actor_id=self.actor_id,
            origin_interface=self.origin_interface,
            correlation_id=self.correlation_id,
        )
        return result

    def stop(self) -> dict[str, Any]:
        self.store.set_placement_group_allocation_state(
            self.plan.placement_group_id,
            "draining",
            actor_type=self.actor_type,
            actor_id=self.actor_id,
            origin_interface=self.origin_interface,
            correlation_id=self.correlation_id,
        )
        self._persist(action="placement_group.stop", desired_state="stopped", state="stopping")
        _completed, failures = self._run_phases(
            "stop",
            reverse=True,
            audit_action="placement_group.stop",
            desired_state="stopped",
            state="stopping",
            stop_on_failure=False,
        )
        if failures:
            self._persist(
                action="placement_group.stop", desired_state="stopped", state="failed",
                error="placement_stop_failed",
            )
            raise PlacementGroupOrchestrationError(
                "placement-group stop failed on task(s): "
                + ",".join(item.task_id for item, _error in failures)
            )
        result = self._persist(action="placement_group.stop", desired_state="stopped", state="stopped")
        self.store.set_placement_group_allocation_state(
            self.plan.placement_group_id,
            "reserved",
            actor_type=self.actor_type,
            actor_id=self.actor_id,
            origin_interface=self.origin_interface,
            correlation_id=self.correlation_id,
        )
        return result

    def remove(self) -> dict[str, Any]:
        self._persist(action="placement_group.remove", desired_state="removed", state="removing")
        _completed, failures = self._run_phases(
            "remove",
            reverse=True,
            audit_action="placement_group.remove",
            desired_state="removed",
            state="removing",
            stop_on_failure=False,
        )
        if failures:
            self._persist(
                action="placement_group.remove", desired_state="removed", state="failed",
                error="placement_remove_failed",
            )
            raise PlacementGroupOrchestrationError(
                "placement-group removal failed on task(s): "
                + ",".join(item.task_id for item, _error in failures)
            )
        result = self._persist(action="placement_group.remove", desired_state="removed", state="removed")
        self.store.set_placement_group_allocation_state(
            self.plan.placement_group_id,
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
        for placement in self.plan.placements:
            state = self.states[placement.placement_id]
            try:
                response = self.fetch_status(self.members[placement.node_id], self.plan.placement_group_id)
                observed_placement = response.get("placement")
                trip = response.get("protection_trip_latched")
                if (
                    not isinstance(observed_placement, Mapping)
                    or observed_placement.get("placement_group_id")
                    != self.plan.placement_group_id
                    or observed_placement.get("placement_id")
                    != placement.placement_id
                    or not isinstance(trip, bool)
                ):
                    raise PlacementGroupOrchestrationError(
                        "node placement status is invalid"
                    )
                self.protection_trips[placement.placement_id] = trip
                observed = observed_placement.get("state")
                if observed not in {"staged", "running", "stopped", "failed", "removed"}:
                    raise PlacementGroupOrchestrationError(
                        "node placement state is invalid"
                    )
                state["state"] = observed
                state["error"] = None
                if observed == "running":
                    running += 1
            except BaseException:
                state["state"] = "unreachable"
                state["error"] = "node_unreachable"
                self.protection_trips[placement.placement_id] = False
        if running == len(self.plan.placements):
            group_state = "running"
        else:
            group_state = "failed"
        if self.persisted_state == group_state and previous_states == self.states:
            return {
                **self.plan.document(),
                "source": self.source,
                "engine_credential_sha256": self.engine_credential_sha256,
                "desired_state": "running",
                "state": group_state,
                "placement_states": [
                    dict(self.states[item.placement_id])
                    for item in self.plan.placements
                ],
                "last_error": None,
            }
        return self._persist(
            action="placement_group.reconcile",
            desired_state="running",
            state=group_state,
            error=(
                None
                if group_state in {"running", "degraded"}
                else "insufficient_healthy_placements"
            ),
        )

    def recover(self, *, acknowledge_trips: bool = False) -> dict[str, Any]:
        """Restart the complete group, clearing trips only for an explicit action."""
        self._persist(action="placement_group.recover", desired_state="running", state="recovering")
        self.stop()
        self._persist(action="placement_group.recover", desired_state="running", state="recovering")
        action = "recover" if acknowledge_trips else "start"
        try:
            _started, failures = self._run_phases(
                action,
                audit_action="placement_group.recover",
                desired_state="running",
                state="recovering",
            )
            if failures:
                failed_tasks = sorted({item.task_id for item, _error in failures})
                raise PlacementGroupOrchestrationError(
                    "placement-group recovery failed on task(s): "
                    + ",".join(failed_tasks)
                )
        except BaseException as error:
            rollback_failures = self._rollback_start_failure(
                audit_action="placement_group.recover"
            )
            self._persist(
                action="placement_group.recover",
                desired_state="running",
                state="failed",
                error=(
                    "recovery_rollback_failed"
                    if rollback_failures
                    else type(error).__name__
                ),
            )
            if rollback_failures:
                failed_tasks = sorted(
                    {item.task_id for item, _failure in rollback_failures}
                )
                raise PlacementGroupOrchestrationError(
                    "placement-group recovery failed and rollback failed on task(s): "
                    + ",".join(failed_tasks)
                ) from error
            if isinstance(error, PlacementGroupOrchestrationError):
                raise
            raise PlacementGroupOrchestrationError(
                f"placement-group recovery failed: {type(error).__name__}"
            ) from error
        result = self._persist(
            action="placement_group.recover", desired_state="running", state="running"
        )
        self.store.set_placement_group_allocation_state(
            self.plan.placement_group_id,
            "active",
            actor_type=self.actor_type,
            actor_id=self.actor_id,
            origin_interface=self.origin_interface,
            correlation_id=self.correlation_id,
        )
        return result
