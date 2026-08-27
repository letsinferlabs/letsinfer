#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""The Let's Infer coordinator's engine-neutral OpenAI-compatible gateway."""

from __future__ import annotations

import argparse
import collections
import dataclasses
import http.client
import http.server
import json
import os
import pathlib
import queue
import re
import secrets
import select
import signal
import socket
import ssl
import stat
import threading
import time
import urllib.parse
import uuid
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from ..state_plane import backend_available as backend_is_operational
from ..state_plane import engine_has_capacity
from ..site.state import SiteError, SiteIdentity, SiteStore, read_identity
from ..site.topology import (
    MAX_FACT_AGE_SECONDS,
    TopologyError,
    TopologyGraph,
    facts_sha256,
    validate_member_facts,
)
from ..exact_tokens import (
    TOKEN_COUNT_PROTOCOLS,
    TokenCountError,
    parse_token_count_response,
    prepare_token_count_request,
)


MAX_REQUEST_BYTES = 32 * 1024 * 1024
MAX_USAGE_TAIL_BYTES = 128 * 1024
PUBLIC_INFERENCE_POST_PATHS = frozenset({"/v1/chat/completions"})
PUBLIC_INFERENCE_GET_PATHS = frozenset({"/health", "/v1/models"})
PUBLIC_INFERENCE_PATHS = PUBLIC_INFERENCE_GET_PATHS | PUBLIC_INFERENCE_POST_PATHS
CORS_REQUEST_HEADERS_MAX_BYTES = 2048
CORS_HEADER_TOKEN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
MAX_CONNECTIONS = 256
DEFAULT_QUEUE_TIMEOUT_SECONDS = 0
BACKEND_RESPONSE_TIMEOUT_SECONDS = 3600
BACKEND_MAX_COOLDOWN_SECONDS = 30
PREFIX_AFFINITY_MAX_ENTRIES = 4096
PREFIX_AFFINITY_TTL_SECONDS = 60 * 60
REQUEST_SUMMARY_RETENTION_SECONDS = 7 * 24 * 60 * 60
REQUEST_SUMMARY_MAX_ROWS = 100_000
MINUTE_ROLLUP_RETENTION_SECONDS = 30 * 24 * 60 * 60
HOUR_ROLLUP_RETENTION_SECONDS = 400 * 24 * 60 * 60
HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host", "authorization",
}


class GatewayError(RuntimeError):
    """A bounded gateway request or configuration error."""


class AdmissionError(GatewayError):
    """A client-visible admission failure with an explicit HTTP status."""

    def __init__(self, message: str, *, status: int = 400, code: str = "admission_rejected") -> None:
        super().__init__(message)
        self.status = status
        self.code = code


class PlacementContextMismatch(GatewayError):
    """The request can be retried only on a larger qualified placement."""


class ClientDisconnected(Exception):
    """The waiting inference client closed its HTTP connection."""


@dataclasses.dataclass
class Backend:
    placement_group_id: str
    placement_id: str
    node_id: str
    model: str
    url: str
    credential_file: str
    ca_file: str | None
    token_count_path: str | None
    token_count_protocol: str | None
    max_active_requests: int
    max_context_tokens: int
    healthy: bool
    memory_pressure: bool
    temperature_c: float
    prefix_keys: set[str]
    engine: str = ""

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.placement_group_id, self.placement_id, self.url)


@dataclasses.dataclass
class RequestUsage:
    input_tokens: int | None = None
    output_tokens: int | None = None
    cached_tokens: int | None = None
    exact: bool = False


@dataclasses.dataclass(frozen=True)
class StreamingUsageEvent:
    """One exact cumulative usage observation from an OpenAI SSE event."""

    usage: RequestUsage
    choice_index: int | None


class StreamingUsageTracker:
    """Bounded parser and monotonic reconciler for cumulative SSE usage."""

    def __init__(self, *, max_pending_bytes: int = MAX_USAGE_TAIL_BYTES) -> None:
        self.max_pending_bytes = max_pending_bytes
        self.pending = bytearray()
        self.discard_line = False
        self.input_tokens = 0
        self.cached_tokens = 0
        self.aggregate_output_tokens = 0
        self.choice_output_tokens: dict[int, int] = {}
        self.accounted_input_tokens = 0
        self.accounted_output_tokens = 0
        self.accounted_cached_tokens = 0
        self.saw_exact = False

    def _observe(self, event: StreamingUsageEvent) -> dict[str, int]:
        usage = event.usage
        assert usage.input_tokens is not None
        assert usage.output_tokens is not None
        assert usage.cached_tokens is not None
        self.saw_exact = True
        self.input_tokens = max(self.input_tokens, usage.input_tokens)
        self.cached_tokens = max(self.cached_tokens, usage.cached_tokens)
        if event.choice_index is None:
            self.aggregate_output_tokens = max(
                self.aggregate_output_tokens, usage.output_tokens
            )
        else:
            self.choice_output_tokens[event.choice_index] = max(
                self.choice_output_tokens.get(event.choice_index, 0),
                usage.output_tokens,
            )
        output_tokens = max(
            self.aggregate_output_tokens,
            sum(self.choice_output_tokens.values()),
        )
        changes = {
            "input_tokens": self.input_tokens - self.accounted_input_tokens,
            "output_tokens": output_tokens - self.accounted_output_tokens,
            "cached_tokens": self.cached_tokens - self.accounted_cached_tokens,
        }
        self.accounted_input_tokens = self.input_tokens
        self.accounted_output_tokens = output_tokens
        self.accounted_cached_tokens = self.cached_tokens
        return changes

    def _line(self, line: bytes) -> dict[str, int]:
        candidate = line.strip()
        if not candidate.startswith(b"data:"):
            return {}
        candidate = candidate[5:].strip()
        if not candidate.startswith(b"{"):
            return {}
        try:
            value = json.loads(candidate)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {}
        event = _streaming_usage_event(value)
        return self._observe(event) if event is not None else {}

    def feed(self, chunk: bytes) -> dict[str, int]:
        """Consume arbitrarily fragmented SSE bytes and return metric deltas."""

        changes = {"input_tokens": 0, "output_tokens": 0, "cached_tokens": 0}
        for value in chunk:
            if value == ord("\n"):
                if not self.discard_line:
                    for key, delta in self._line(bytes(self.pending)).items():
                        changes[key] += delta
                self.pending.clear()
                self.discard_line = False
                continue
            if self.discard_line:
                continue
            self.pending.append(value)
            if len(self.pending) > self.max_pending_bytes:
                self.pending.clear()
                self.discard_line = True
        return changes

    def reconcile(
        self,
        final_usage: RequestUsage,
        *,
        exact_prompt_tokens: int | None,
    ) -> tuple[RequestUsage, dict[str, int]]:
        """Reconcile a final response without double-counting live deltas."""

        input_tokens = (
            final_usage.input_tokens
            if final_usage.input_tokens is not None
            else exact_prompt_tokens
        )
        if input_tokens is None and self.saw_exact:
            input_tokens = self.input_tokens
        output_tokens = final_usage.output_tokens
        if output_tokens is None and self.saw_exact:
            output_tokens = self.accounted_output_tokens
        cached_tokens = final_usage.cached_tokens
        if cached_tokens is None and self.saw_exact:
            cached_tokens = self.cached_tokens

        # Exact cumulative engine observations cannot legitimately exceed the
        # final usage. Keep telemetry counters monotonic if an interrupted or
        # malformed tail omits or regresses that final summary.
        accounted_input = max(self.accounted_input_tokens, input_tokens or 0)
        accounted_output = max(self.accounted_output_tokens, output_tokens or 0)
        accounted_cached = max(self.accounted_cached_tokens, cached_tokens or 0)
        changes = {
            "input_tokens": accounted_input - self.accounted_input_tokens,
            "output_tokens": accounted_output - self.accounted_output_tokens,
            "cached_tokens": accounted_cached - self.accounted_cached_tokens,
        }
        self.accounted_input_tokens = accounted_input
        self.accounted_output_tokens = accounted_output
        self.accounted_cached_tokens = accounted_cached
        return RequestUsage(
            input_tokens,
            output_tokens,
            cached_tokens,
            final_usage.exact or self.saw_exact or exact_prompt_tokens is not None,
        ), changes


@dataclasses.dataclass
class GatewayMetrics:
    requests_received: int = 0
    requests_admitted: int = 0
    requests_completed: int = 0
    requests_failed: int = 0
    requests_cancelled: int = 0
    requests_retried: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cached_tokens: int = 0
    active_requests: int = 0
    connected_clients: int = 0
    queued_requests: int = 0
    queue_milliseconds: int = 0
    ttft_milliseconds: int = 0
    decode_milliseconds: int = 0
    exact_token_requests: int = 0
    prefix_cache_hits: int = 0
    usage_records_dropped: int = 0
    usage_write_errors: int = 0


class PolicySnapshot:
    """Small reloadable copies of coordinator policy; no request bodies."""

    def __init__(self, identity: SiteIdentity) -> None:
        self.identity = identity
        self.lock = threading.RLock()
        self.aliases: dict[str, str] = {}
        self.backends: list[Backend] = []
        self.active: collections.Counter[tuple[str, str, str]] = collections.Counter()
        self.queued_by_model: collections.Counter[str] = collections.Counter()
        self.placement_group_counters: dict[str, collections.Counter[str]] = {}
        self.placement_group_windows: collections.deque[
            tuple[float, str, dict[str, int]]
        ] = collections.deque(maxlen=16_384)
        self.failure_counts: collections.Counter[tuple[str, str, str]] = collections.Counter()
        self.unavailable_until: dict[tuple[str, str, str], float] = {}
        self.prefix_affinity: collections.OrderedDict[
            tuple[str, str], tuple[tuple[str, str, str], float]
        ] = collections.OrderedDict()
        self.condition = threading.Condition(self.lock)
        self.last_reload = 0.0
        self.database_mtime_ns = -1

    def reload(self, *, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self.last_reload < 1.0:
            return
        self.last_reload = now
        try:
            database = SiteStore(identity=self.identity)
        except SiteError as error:
            raise GatewayError(str(error)) from error
        try:
            aliases = dict(database.connection.execute("SELECT alias,model FROM model_aliases"))
            member_rows = database.connection.execute(
                "SELECT member_id,state,certificate_sha256,facts_json,facts_sha256 FROM members "
                "WHERE state!='removed'"
            ).fetchall()
            placement_groups = [
                placement_group
                for placement_group in database.placement_groups()
                if placement_group["state"] == "running"
                and placement_group["desired_state"] == "running"
            ]
        finally:
            database.close()
        member_states: dict[str, str] = {}
        member_health: dict[str, dict[str, Any] | None] = {}
        member_facts: dict[str, dict[str, Any]] = {}
        member_certificates: dict[str, str] = {}
        now_unix = int(time.time())
        for member_value in member_rows:
            member = dict(member_value)
            member_id = str(member["member_id"])
            member_states[member_id] = str(member["state"])
            member_health[member_id] = None
            if member["state"] != "active":
                continue
            try:
                facts = json.loads(member["facts_json"])
                if facts == {}:
                    continue
                if not isinstance(facts, dict):
                    raise TopologyError("member facts must be an object")
                validate_member_facts(facts)
                if (
                    facts.get("member_id") != member_id
                    or member.get("facts_sha256") != facts_sha256(facts)
                ):
                    raise TopologyError("member facts identity changed")
            except (TypeError, json.JSONDecodeError, TopologyError) as error:
                raise GatewayError(f"member {member_id} routing facts are invalid") from error
            observed = int(facts["observed_at_unix"])
            if now_unix - observed > MAX_FACT_AGE_SECONDS or observed > now_unix + 5:
                continue
            member_facts[member_id] = facts
            member_certificates[member_id] = str(member["certificate_sha256"])
            member_health[member_id] = dict(facts["health"])
        routing_graph: TopologyGraph | None = None
        if member_facts:
            try:
                routing_graph = TopologyGraph(
                    list(member_facts.values()),
                    now_unix=now_unix,
                    member_certificates=member_certificates,
                )
            except TopologyError as error:
                raise GatewayError("current node topology is invalid") from error
        backends: list[Backend] = []
        for placement_group in placement_groups:
            placement_group_id = str(placement_group["placement_group_id"])
            placements = placement_group.get("placements")
            endpoint = placement_group.get("endpoint")
            capacity = placement_group.get("capacity")
            if (
                not isinstance(placements, list)
                or not placements
                or any(not isinstance(placement, dict) for placement in placements)
                or not isinstance(endpoint, dict)
                or not isinstance(capacity, dict)
            ):
                raise GatewayError(
                    f"placement group {placement_group_id} metadata is invalid"
                )
            placement_ids = [str(placement.get("placement_id", "")) for placement in placements]
            node_ids = [str(placement.get("node_id", "")) for placement in placements]
            if (
                len(placement_ids) != len(set(placement_ids))
                or len(node_ids) != len(set(node_ids))
                or any(placement.get("state") != "running" for placement in placements)
            ):
                continue
            endpoint_placement = next(
                (
                    placement
                    for placement in placements
                    if placement.get("placement_id") == endpoint.get("placement_id")
                ),
                None,
            )
            if (
                endpoint_placement is None
                or endpoint_placement.get("endpoint_owner") is not True
                or endpoint.get("node_id") != endpoint_placement.get("node_id")
            ):
                raise GatewayError(
                    f"placement group {placement_group_id} endpoint owner is invalid"
                )
            runtime_parts = str(placement_group.get("runtime", "")).split("/", 2)
            if (
                len(runtime_parts) != 3
                or not runtime_parts[1]
            ):
                raise GatewayError(
                    f"placement group {placement_group_id} runtime identity is invalid"
                )
            engine = runtime_parts[1]
            # A placement group is atomic. Losing any required placement removes
            # its endpoint; sibling placement groups remain available replicas.
            if any(member_states.get(node_id) != "active" for node_id in node_ids):
                continue
            if any(member_health.get(node_id) is None for node_id in node_ids):
                continue
            if len(node_ids) > 1:
                try:
                    if routing_graph is None or not routing_graph.placement_group_available(
                        node_ids,
                        interconnect=capacity.get("interconnect"),
                    ):
                        continue
                except TopologyError as error:
                    raise GatewayError(
                        f"placement group {placement_group_id} topology contract is invalid"
                    ) from error
            endpoint_node_id = str(endpoint["node_id"])
            live_health = member_health[endpoint_node_id]
            assert live_health is not None
            prefix_keys = endpoint.get("prefix_keys", [])
            token_count_path = endpoint.get("token_count_path")
            token_count_protocol = endpoint.get("token_count_protocol")
            max_active_requests = endpoint.get("max_active_requests")
            max_context_tokens = endpoint.get("max_context_tokens")
            if (
                not isinstance(max_active_requests, int)
                or isinstance(max_active_requests, bool)
                or max_active_requests <= 0
                or not isinstance(max_context_tokens, int)
                or isinstance(max_context_tokens, bool)
                or max_context_tokens <= 0
            ):
                raise GatewayError(
                    f"placement group {placement_group_id} capacity is invalid"
                )
            if (
                not isinstance(prefix_keys, list)
                or any(not isinstance(prefix, str) for prefix in prefix_keys)
            ):
                raise GatewayError(
                    f"placement group {placement_group_id} prefix identity is invalid"
                )
            if token_count_path is not None and (
                not isinstance(token_count_path, str)
                or not token_count_path.startswith("/")
                or "://" in token_count_path
            ):
                raise GatewayError(
                    f"placement group {placement_group_id} token-count path is invalid"
                )
            if (token_count_path is None) != (token_count_protocol is None) or (
                token_count_protocol is not None
                and token_count_protocol not in TOKEN_COUNT_PROTOCOLS
            ):
                raise GatewayError(
                    f"placement group {placement_group_id} token-count protocol is invalid"
                )
            endpoint_temperature = endpoint.get("temperature_c", -1)
            if not isinstance(endpoint_temperature, (int, float)) or isinstance(
                endpoint_temperature, bool
            ):
                raise GatewayError(
                    f"placement group {placement_group_id} endpoint temperature is invalid"
                )
            temperatures = [
                float(value)
                for value in (
                    endpoint_temperature,
                    *(
                        member_health[node_id]["max_temperature_c"]
                        for node_id in node_ids
                        if member_health[node_id] is not None
                    ),
                )
                if float(value) >= 0
            ]
            backends.append(
                Backend(
                    placement_group_id=placement_group_id,
                    placement_id=str(endpoint["placement_id"]),
                    node_id=endpoint_node_id,
                    model=str(placement_group["model"]),
                    url=str(endpoint["url"]),
                    credential_file=str(endpoint["credential_file"]),
                    ca_file=str(endpoint["ca_file"]) if endpoint.get("ca_file") else None,
                    token_count_path=token_count_path,
                    token_count_protocol=token_count_protocol,
                    max_active_requests=max_active_requests,
                    max_context_tokens=max_context_tokens,
                    healthy=backend_is_operational(endpoint, live_health),
                    memory_pressure=(
                        endpoint.get("memory_pressure", False) is True
                        or any(
                            bool(member_health[node_id]["memory_pressure"])
                            for node_id in node_ids
                            if member_health[node_id] is not None
                        )
                    ),
                    temperature_c=max(temperatures) if temperatures else -1,
                    prefix_keys=set(prefix_keys),
                    engine=engine,
                )
            )
        with self.condition:
            self.aliases = aliases
            self.backends = backends
            valid = {backend.key for backend in backends}
            # Keep counters for in-flight requests whose member was drained.
            # A later resume must not over-admit while those requests finish.
            self.active = collections.Counter(
                {key: amount for key, amount in self.active.items() if amount > 0}
            )
            self.failure_counts = collections.Counter(
                {
                    key: amount
                    for key, amount in self.failure_counts.items()
                    if key in valid and amount > 0
                }
            )
            self.unavailable_until = {
                key: deadline
                for key, deadline in self.unavailable_until.items()
                if key in valid
            }
            self._prune_prefix_affinity(time.monotonic())
            self.condition.notify_all()

    def _prune_prefix_affinity(self, now: float) -> None:
        expired = [
            key
            for key, (_backend, deadline) in self.prefix_affinity.items()
            if deadline <= now
        ]
        for key in expired:
            self.prefix_affinity.pop(key, None)

    def record_prefix_affinity(self, backend: Backend, prefix_key: str) -> None:
        with self.condition:
            key = (backend.model, prefix_key)
            self.prefix_affinity.pop(key, None)
            self.prefix_affinity[key] = (
                backend.key,
                time.monotonic() + PREFIX_AFFINITY_TTL_SECONDS,
            )
            while len(self.prefix_affinity) > PREFIX_AFFINITY_MAX_ENTRIES:
                self.prefix_affinity.popitem(last=False)

    def backend_available(self, backend: Backend, *, now: float | None = None) -> bool:
        deadline = self.unavailable_until.get(backend.key, 0.0)
        return deadline <= (time.monotonic() if now is None else now)

    def mark_backend_failure(self, backend: Backend) -> None:
        with self.condition:
            failures = min(self.failure_counts[backend.key] + 1, 16)
            self.failure_counts[backend.key] = failures
            cooldown = min(BACKEND_MAX_COOLDOWN_SECONDS, 2 ** (failures - 1))
            self.unavailable_until[backend.key] = time.monotonic() + cooldown
            self.condition.notify_all()

    def mark_backend_success(self, backend: Backend) -> None:
        with self.condition:
            self.failure_counts.pop(backend.key, None)
            self.unavailable_until.pop(backend.key, None)
            self.condition.notify_all()

    def authenticate(self, token: str) -> dict[str, Any] | None:
        try:
            return SiteStore.authenticate_key_from_authority(
                token, identity=self.identity
            )
        except SiteError as error:
            raise GatewayError(str(error)) from error

    def resolve_model(self, requested: str) -> str:
        self.reload()
        with self.lock:
            return self.aliases.get(requested, requested)

    def context_backends(self, model: str) -> tuple[Backend, ...]:
        """Return healthy endpoints suitable for read-only admission inspection.

        Exact token counting stays available before capacity admission so the
        gateway can reject an impossible context instead of queueing forever.
        """
        self.reload()
        with self.lock:
            candidates = [
                backend
                for backend in self.backends
                if backend.model == model
                and backend.healthy
                and self.backend_available(backend)
            ]
        candidates.sort(
            key=lambda backend: (
                backend.token_count_path is None,
                -backend.max_context_tokens,
                backend.node_id,
            )
        )
        return tuple(candidates)

    def acquire_backend(
        self,
        model: str,
        *,
        prefix_key: str | None,
        timeout: float,
        excluded: set[tuple[str, str, str]] | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> tuple[Backend, float]:
        started = time.monotonic()
        deadline = None if timeout <= 0 else started + timeout
        while True:
            if cancelled is not None and cancelled():
                raise ClientDisconnected()
            self.reload()
            excluded_keys = excluded or set()
            with self.condition:
                self._prune_prefix_affinity(time.monotonic())
                affinity = (
                    self.prefix_affinity.get((model, prefix_key), (None, 0.0))[0]
                    if prefix_key
                    else None
                )
                available_for_model = [
                    backend
                    for backend in self.backends
                    if backend.model == model
                    and backend.healthy
                    and self.backend_available(backend)
                ]
                if available_for_model and all(
                    backend.key in excluded_keys for backend in available_for_model
                ):
                    raise GatewayError("all available placements failed before output began")
                candidates = [
                    backend
                    for backend in self.backends
                    if backend.model == model
                    and backend.healthy
                    and self.backend_available(backend)
                    and backend.key not in excluded_keys
                    and engine_has_capacity(
                        active_requests=self.active[backend.key],
                        max_active_requests=backend.max_active_requests,
                    )
                ]
                if candidates:
                    candidates.sort(
                        key=lambda backend: (
                            not (
                                prefix_key
                                and (
                                    backend.key == affinity
                                    or prefix_key in backend.prefix_keys
                                )
                            ),
                            self.active[backend.key] / backend.max_active_requests,
                            backend.temperature_c if backend.temperature_c >= 0 else 10_000,
                            backend.node_id,
                        )
                    )
                    selected = candidates[0]
                    self.active[selected.key] += 1
                    return selected, time.monotonic() - started
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                raise GatewayError("no qualified placement became available before queue timeout")
            with self.condition:
                self.condition.wait(
                    timeout=0.25 if remaining is None else min(0.25, remaining)
                )

    def release_backend(self, backend: Backend) -> None:
        with self.condition:
            if self.active[backend.key] > 1:
                self.active[backend.key] -= 1
            else:
                self.active.pop(backend.key, None)
            self.condition.notify_all()

    def begin_wait(self, model: str) -> None:
        with self.condition:
            self.queued_by_model[model] += 1

    def end_wait(self, model: str) -> None:
        with self.condition:
            if self.queued_by_model[model] > 1:
                self.queued_by_model[model] -= 1
            else:
                self.queued_by_model.pop(model, None)

    def record_placement_group_metrics(
        self, placement_group_id: str | None, **changes: int
    ) -> None:
        if placement_group_id is None or not changes:
            return
        bounded = {
            key: max(0, int(value))
            for key, value in changes.items()
            if int(value) != 0
        }
        if not bounded:
            return
        with self.condition:
            counters = self.placement_group_counters.setdefault(
                placement_group_id, collections.Counter()
            )
            counters.update(bounded)
            self.placement_group_windows.append(
                (time.monotonic(), placement_group_id, bounded)
            )

    def activity_snapshot(self) -> dict[str, Any]:
        now = time.monotonic()
        cutoff = now - 5.0
        with self.condition:
            while (
                self.placement_group_windows
                and self.placement_group_windows[0][0] < cutoff
            ):
                self.placement_group_windows.popleft()
            recent: dict[str, collections.Counter[str]] = {}
            first: dict[str, float] = {}
            for observed, placement_group_id, changes in self.placement_group_windows:
                recent.setdefault(
                    placement_group_id, collections.Counter()
                ).update(changes)
                first.setdefault(placement_group_id, observed)
            placement_groups: dict[str, dict[str, Any]] = {}
            for backend in self.backends:
                row = placement_groups.setdefault(
                    backend.placement_group_id,
                    {
                        "model": backend.model,
                        "endpoint_placement_id": backend.placement_id,
                        "endpoint_node_id": backend.node_id,
                        "active_requests": 0,
                        "max_active_requests": 0,
                        "counters": dict(
                            self.placement_group_counters.get(
                                backend.placement_group_id, {}
                            )
                        ),
                        "rates": {},
                    },
                )
                row["active_requests"] += self.active[backend.key]
                row["max_active_requests"] += backend.max_active_requests
            for placement_group_id, counters in recent.items():
                if placement_group_id not in placement_groups:
                    continue
                elapsed = max(1.0, now - first[placement_group_id])
                placement_groups[placement_group_id]["rates"] = {
                    "input_tokens_per_second": counters["input_tokens"] / elapsed,
                    "output_tokens_per_second": counters["output_tokens"] / elapsed,
                    "cached_tokens_per_second": counters["cached_tokens"] / elapsed,
                }
            return {
                "schema_version": 2,
                "unix_ms": int(time.time() * 1000),
                "models": {
                    model: {"queued_requests": amount}
                    for model, amount in sorted(self.queued_by_model.items())
                },
                "placement_groups": placement_groups,
            }


class QuotaState:
    def __init__(self, identity: SiteIdentity) -> None:
        self.lock = threading.Lock()
        self.requests: dict[str, collections.deque[float]] = {}
        self.tokens: dict[str, collections.deque[tuple[float, int]]] = {}
        self.active: collections.Counter[str] = collections.Counter()
        self.reserved: collections.Counter[str] = collections.Counter()
        cutoff_ms = int((time.time() - 60) * 1000)
        with SiteStore(identity=identity) as store:
            rows = store.connection.execute(
                """SELECT key_id,received_unix_ms,completed_unix_ms,input_tokens,output_tokens
                   FROM request_summaries
                   WHERE key_id IS NOT NULL AND received_unix_ms>=?""",
                (cutoff_ms,),
            ).fetchall()
        for row in rows:
            key_id = str(row["key_id"])
            received = float(row["received_unix_ms"]) / 1000.0
            self.requests.setdefault(key_id, collections.deque()).append(received)
            tokens = int(row["input_tokens"] or 0) + int(row["output_tokens"] or 0)
            if row["completed_unix_ms"] is not None and tokens > 0:
                completed = float(row["completed_unix_ms"]) / 1000.0
                self.tokens.setdefault(key_id, collections.deque()).append((completed, tokens))

    def admit(self, policy: Mapping[str, Any]) -> None:
        key_id = str(policy["key_id"])
        now = time.time()
        with self.lock:
            requests = self.requests.setdefault(key_id, collections.deque())
            while requests and requests[0] <= now - 60:
                requests.popleft()
            token_rows = self.tokens.setdefault(key_id, collections.deque())
            while token_rows and token_rows[0][0] <= now - 60:
                token_rows.popleft()
            rpm = policy.get("requests_per_minute")
            tpm = policy.get("tokens_per_minute")
            concurrency = policy.get("concurrency_limit")
            if rpm is not None and len(requests) >= rpm:
                raise AdmissionError("API key request-rate limit reached", status=429, code="rate_limit")
            if tpm is not None and sum(item[1] for item in token_rows) >= tpm:
                raise AdmissionError("API key token-rate limit reached", status=429, code="rate_limit")
            if concurrency is not None and self.active[key_id] >= concurrency:
                raise AdmissionError("API key concurrency limit reached", status=429, code="concurrency_limit")
            requests.append(now)
            self.active[key_id] += 1

    def reserve_tokens(self, policy: Mapping[str, Any], tokens: int) -> int:
        key_id = str(policy["key_id"])
        limit = policy.get("tokens_per_minute")
        if limit is None:
            return 0
        if not isinstance(tokens, int) or isinstance(tokens, bool) or tokens <= 0:
            raise AdmissionError(
                "exact positive token demand is required for this API key",
                status=400,
                code="token_budget_required",
            )
        now = time.time()
        with self.lock:
            token_rows = self.tokens.setdefault(key_id, collections.deque())
            while token_rows and token_rows[0][0] <= now - 60:
                token_rows.popleft()
            used = sum(item[1] for item in token_rows)
            if used + self.reserved[key_id] + tokens > limit:
                raise AdmissionError(
                    "API key token-rate limit reached",
                    status=429,
                    code="rate_limit",
                )
            self.reserved[key_id] += tokens
        return tokens

    def complete(self, key_id: str, tokens: int, *, reserved_tokens: int = 0) -> None:
        with self.lock:
            self.active[key_id] = max(0, self.active[key_id] - 1)
            if reserved_tokens:
                self.reserved[key_id] = max(
                    0, self.reserved[key_id] - reserved_tokens
                )
            if tokens > 0:
                self.tokens.setdefault(key_id, collections.deque()).append((time.time(), tokens))


class MetricsPublisher:
    FIELDS = tuple(field.name for field in dataclasses.fields(GatewayMetrics))
    MAX_STALE_SECONDS = 3.5

    def __init__(
        self,
        path: pathlib.Path,
        *,
        details_provider: Callable[[], Mapping[str, Any]] | None = None,
    ) -> None:
        self.path = path
        self.details_path = path.with_name(path.name + ".placement-groups.json")
        self.details_provider = details_provider
        self.lock = threading.Lock()
        self.metrics = GatewayMetrics()
        self.last_success_monotonic = 0.0
        self.last_error: str | None = None
        self.stop_event = threading.Event()
        # Validate the telemetry destination and publish the initial state before
        # the gateway can report healthy or accept inference.
        self._write()
        self.thread = threading.Thread(target=self._run, name="letsinfer-gateway-metrics", daemon=True)
        self.thread.start()

    def update(self, **changes: int) -> None:
        with self.lock:
            for key, delta in changes.items():
                if key not in self.FIELDS:
                    raise GatewayError(f"unknown gateway metric {key}")
                setattr(self.metrics, key, max(0, getattr(self.metrics, key) + int(delta)))

    def snapshot(self) -> dict[str, int]:
        with self.lock:
            return dataclasses.asdict(self.metrics)

    def _write(self) -> None:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.path.parent.is_symlink():
            raise GatewayError("gateway telemetry directory cannot be a symlink")
        body = "version=2\n" + "".join(
            f"{key}={value}\n" for key, value in sorted(self.snapshot().items())
        )
        temporary = self.path.with_name(f".{self.path.name}.{os.getpid()}.{secrets.token_hex(4)}")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "w", encoding="ascii") as handle:
                handle.write(body)
                handle.flush()
                os.fsync(handle.fileno())
            temporary.replace(self.path)
            if self.details_provider is not None:
                details = self.details_provider()
                details_body = (
                    json.dumps(details, sort_keys=True, separators=(",", ":")) + "\n"
                ).encode("utf-8")
                if len(details_body) > 1024 * 1024:
                    raise GatewayError(
                        "gateway placement-group telemetry exceeds its size limit"
                    )
                details_temporary = self.details_path.with_name(
                    f".{self.details_path.name}.{os.getpid()}.{secrets.token_hex(4)}"
                )
                details_descriptor = os.open(
                    details_temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
                )
                try:
                    with os.fdopen(details_descriptor, "wb") as details_handle:
                        details_handle.write(details_body)
                        details_handle.flush()
                        os.fsync(details_handle.fileno())
                    details_temporary.replace(self.details_path)
                finally:
                    if details_temporary.exists():
                        details_temporary.unlink()
            with self.lock:
                self.last_success_monotonic = time.monotonic()
                self.last_error = None
        finally:
            if temporary.exists():
                temporary.unlink()

    def _record_failure(self, error: BaseException) -> None:
        with self.lock:
            self.last_error = type(error).__name__

    def healthy(self) -> bool:
        with self.lock:
            recent = (
                self.last_success_monotonic > 0
                and time.monotonic() - self.last_success_monotonic
                <= self.MAX_STALE_SECONDS
            )
        return recent and self.thread.is_alive() and not self.stop_event.is_set()

    def _run(self) -> None:
        while not self.stop_event.wait(1.0):
            try:
                self._write()
            except (OSError, GatewayError) as error:
                self._record_failure(error)
                continue
        try:
            self._write()
        except (OSError, GatewayError) as error:
            self._record_failure(error)

    def close(self) -> None:
        self.stop_event.set()
        self.thread.join(timeout=2)


class UsageWriter:
    def __init__(self, identity: SiteIdentity, metrics: MetricsPublisher) -> None:
        self.identity = identity
        self.metrics = metrics
        self.items: queue.Queue[dict[str, Any] | None] = queue.Queue(maxsize=4096)
        self.completed_writes = 0
        self.thread = threading.Thread(target=self._run, name="letsinfer-usage-writer", daemon=True)
        self.thread.start()

    def submit(self, row: dict[str, Any]) -> bool:
        try:
            self.items.put_nowait(row)
        except queue.Full:
            self.metrics.update(usage_records_dropped=1)
            return False
        return True

    def _run(self) -> None:
        with SiteStore(identity=self.identity) as store:
            while True:
                row = self.items.get()
                if row is None:
                    break
                try:
                    with store.transaction():
                        store.connection.execute(
                            """INSERT INTO request_summaries
                               (request_id,key_id,model,placement_group_id,placement_id,
                                node_id,received_unix_ms,
                                completed_unix_ms,status,input_tokens,output_tokens,cached_tokens,
                                queue_ms,ttft_ms,decode_ms,retries,exact_tokens)
                               VALUES(:request_id,:key_id,:model,:placement_group_id,
                                      :placement_id,:node_id,:received_unix_ms,
                                      :completed_unix_ms,:status,:input_tokens,:output_tokens,:cached_tokens,
                                      :queue_ms,:ttft_ms,:decode_ms,:retries,:exact_tokens)""",
                            row,
                        )
                        if row["completed_unix_ms"] is not None:
                            for resolution, seconds in (("minute", 60), ("hour", 3600)):
                                bucket = (row["completed_unix_ms"] // 1000 // seconds) * seconds
                                store.connection.execute(
                                    """INSERT INTO usage_rollups
                                       (bucket_unix,resolution,key_id,model,requests,errors,input_tokens,output_tokens,cached_tokens)
                                       VALUES(?,?,?,?,1,?,?,?,?)
                                       ON CONFLICT(bucket_unix,resolution,key_id,model) DO UPDATE SET
                                         requests=requests+1,errors=errors+excluded.errors,
                                         input_tokens=input_tokens+excluded.input_tokens,
                                         output_tokens=output_tokens+excluded.output_tokens,
                                         cached_tokens=cached_tokens+excluded.cached_tokens""",
                                    (
                                        bucket, resolution, row["key_id"] or "anonymous", row["model"],
                                        0 if row["status"] == "completed" else 1,
                                        row["input_tokens"] or 0, row["output_tokens"] or 0,
                                        row["cached_tokens"] or 0,
                                    ),
                                )
                        self.completed_writes += 1
                        if self.completed_writes % 256 == 0:
                            now = int(time.time())
                            store.connection.execute(
                                "DELETE FROM request_summaries WHERE received_unix_ms<?",
                                ((now - REQUEST_SUMMARY_RETENTION_SECONDS) * 1000,),
                            )
                            store.connection.execute(
                                """DELETE FROM request_summaries
                                   WHERE request_id IN (
                                     SELECT request_id FROM request_summaries
                                     ORDER BY received_unix_ms DESC
                                     LIMIT -1 OFFSET ?
                                   )""",
                                (REQUEST_SUMMARY_MAX_ROWS,),
                            )
                            store.connection.execute(
                                "DELETE FROM usage_rollups WHERE resolution='minute' AND bucket_unix<?",
                                (now - MINUTE_ROLLUP_RETENTION_SECONDS,),
                            )
                            store.connection.execute(
                                "DELETE FROM usage_rollups WHERE resolution='hour' AND bucket_unix<?",
                                (now - HOUR_ROLLUP_RETENTION_SECONDS,),
                            )
                except Exception:
                    self.metrics.update(usage_write_errors=1)
                    continue

    def close(self) -> None:
        try:
            self.items.put(None, timeout=2)
        except queue.Full:
            self.metrics.update(usage_records_dropped=1)
        self.thread.join(timeout=5)


class GatewayServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    # systemd is the sole process owner and may immediately replace this exact
    # listener during a verified core update. Reuse only the local address;
    # the old socket is already closed before the new unit starts.
    allow_reuse_address = True
    request_queue_size = 128

    def __init__(
        self,
        address: tuple[str, int],
        *,
        identity: SiteIdentity,
        telemetry_file: pathlib.Path,
        queue_timeout_seconds: int,
        max_connections: int,
    ) -> None:
        self.identity = identity
        self.policy = PolicySnapshot(identity)
        self.policy.reload(force=True)
        self.quotas = QuotaState(identity)
        self.metrics = MetricsPublisher(
            telemetry_file,
            details_provider=self.policy.activity_snapshot,
        )
        self.usage = UsageWriter(identity, self.metrics)
        self.queue_timeout_seconds = queue_timeout_seconds
        self.connection_slots = threading.BoundedSemaphore(max_connections)
        super().__init__(address, GatewayHandler)

    def get_request(self) -> tuple[socket.socket, Any]:
        connection, address = super().get_request()
        connection.settimeout(30)
        return connection, address

    def process_request(self, request: socket.socket, client_address: Any) -> None:
        if not self.connection_slots.acquire(blocking=False):
            request.close()
            return
        self.metrics.update(connected_clients=1)
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.metrics.update(connected_clients=-1)
            self.connection_slots.release()
            raise

    def process_request_thread(self, request: socket.socket, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.metrics.update(connected_clients=-1)
            self.connection_slots.release()

    def server_close(self) -> None:
        super().server_close()
        self.metrics.close()
        self.usage.close()


def _read_backend_token(path_value: str) -> str:
    path = pathlib.Path(path_value)
    if path.is_symlink():
        raise GatewayError("backend credential cannot be a symlink")
    details = path.stat()
    if not stat.S_ISREG(details.st_mode) or details.st_uid != os.getuid() or stat.S_IMODE(details.st_mode) & 0o077:
        raise GatewayError("backend credential must be a private user-owned file")
    value = path.read_text(encoding="ascii").strip()
    if len(value) < 32 or any(character.isspace() for character in value):
        raise GatewayError("backend credential is invalid")
    return value


def _usage_from_json(value: Any) -> RequestUsage:
    if not isinstance(value, dict) or not isinstance(value.get("usage"), dict):
        return RequestUsage()
    usage = value["usage"]
    input_tokens = usage.get("prompt_tokens", usage.get("input_tokens"))
    output_tokens = usage.get("completion_tokens", usage.get("output_tokens"))
    details = usage.get("prompt_tokens_details")
    if details is None:
        cached: Any = 0
    elif isinstance(details, dict):
        cached = details.get("cached_tokens", 0)
    else:
        cached = None
    if (
        isinstance(input_tokens, int) and not isinstance(input_tokens, bool) and input_tokens >= 0
        and isinstance(output_tokens, int) and not isinstance(output_tokens, bool) and output_tokens >= 0
        and isinstance(cached, int) and not isinstance(cached, bool) and cached >= 0
    ):
        return RequestUsage(input_tokens, output_tokens, cached, True)
    return RequestUsage()


def _streaming_usage_event(value: Any) -> StreamingUsageEvent | None:
    usage = _usage_from_json(value)
    if not usage.exact:
        return None
    choices = value.get("choices") if isinstance(value, dict) else None
    choice_index: int | None = None
    if isinstance(choices, list) and len(choices) == 1:
        choice = choices[0]
        index = choice.get("index") if isinstance(choice, dict) else None
        if isinstance(index, int) and not isinstance(index, bool) and index >= 0:
            choice_index = index
    return StreamingUsageEvent(usage, choice_index)


def _instrument_stream_usage(backend: Backend, body: bytes) -> bytes:
    """Request the protocol-required exact streaming usage observation."""

    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return body
    if not isinstance(value, dict) or value.get("stream") is not True:
        return body
    options = value.get("stream_options")
    if options is None:
        options = {}
    if not isinstance(options, dict):
        # Preserve the engine's validation behavior for malformed requests.
        return body
    options = {**options, "include_usage": True}
    value["stream_options"] = options
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _usage_from_tail(tail: bytes) -> RequestUsage:
    best = RequestUsage()
    for line in tail.splitlines():
        candidate = line.strip()
        if candidate.startswith(b"data:"):
            candidate = candidate[5:].strip()
        if not candidate.startswith(b"{"):
            continue
        try:
            parsed = json.loads(candidate)
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        usage = _usage_from_json(parsed)
        if usage.exact:
            best = usage
    if best.exact:
        return best
    try:
        return _usage_from_json(json.loads(tail))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return RequestUsage()


class GatewayHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "letsinfer"
    sys_version = ""

    @property
    def gateway(self) -> GatewayServer:
        return self.server  # type: ignore[return-value]

    def log_message(self, _format: str, *_arguments: Any) -> None:
        return

    def _client_disconnected(self) -> bool:
        """Detect an abandoned request while it is waiting for admission."""
        try:
            readable, _, _ = select.select([self.connection], [], [], 0)
            if not readable:
                return False
            return self.connection.recv(
                1, socket.MSG_PEEK | getattr(socket, "MSG_DONTWAIT", 0)
            ) == b""
        except (BlockingIOError, InterruptedError):
            return False
        except (OSError, ValueError):
            return True

    def end_headers(self) -> None:
        # The LAN endpoint authenticates with bearer keys, never browser
        # cookies. Allow local browser clients to use the same OpenAI surface
        # without weakening API-key authentication or exposing control routes.
        if self.headers.get("Origin"):
            self.send_header("Access-Control-Allow-Origin", "*")
        super().end_headers()

    def _cors_requested_headers(self) -> str:
        raw = self.headers.get("Access-Control-Request-Headers", "")
        if len(raw.encode("utf-8")) > CORS_REQUEST_HEADERS_MAX_BYTES:
            raise GatewayError("CORS request headers exceed the 2 KiB limit")
        values = [value.strip() for value in raw.split(",") if value.strip()]
        if any(CORS_HEADER_TOKEN.fullmatch(value) is None for value in values):
            raise GatewayError("CORS request headers are invalid")
        return ", ".join(values) if values else "Authorization, Content-Type"

    def _json(self, status: int, message: str, *, code: str) -> None:
        body = json.dumps({"error": {"message": message, "type": code}}, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def _token(self) -> str:
        authorization = self.headers.get("Authorization", "")
        scheme, separator, value = authorization.partition(" ")
        return value if separator and scheme.lower() == "bearer" else ""

    def _body(self) -> bytes:
        if self.headers.get("Transfer-Encoding"):
            raise GatewayError("chunked request bodies are unsupported")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as error:
            raise GatewayError("invalid content length") from error
        if length < 0 or length > MAX_REQUEST_BYTES:
            raise GatewayError("request body exceeds the 32 MiB limit")
        return self.rfile.read(length)

    def _request_model(
        self, body: bytes
    ) -> tuple[str, str, str | None, int | None, bytes]:
        try:
            value = json.loads(body) if body else {}
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise GatewayError("request body is not valid JSON") from error
        if not isinstance(value, dict) or not isinstance(value.get("model"), str):
            raise GatewayError("request must contain a model")
        requested_model = value["model"]
        model = self.gateway.policy.resolve_model(requested_model)
        prefix_material = value.get("prompt_cache_key")
        prefix_key = str(prefix_material) if isinstance(prefix_material, str) and len(prefix_material) <= 256 else None
        max_tokens = value.get("max_tokens", value.get("max_completion_tokens"))
        if max_tokens is not None and (
            not isinstance(max_tokens, int)
            or isinstance(max_tokens, bool)
            or max_tokens <= 0
        ):
            raise AdmissionError("max_tokens must be positive")
        value["model"] = model
        return requested_model, model, prefix_key, max_tokens, json.dumps(
            value, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    def _connect(self, backend: Backend) -> tuple[http.client.HTTPConnection, str]:
        parsed = urllib.parse.urlsplit(backend.url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.path not in {"", "/"}:
            raise GatewayError("backend URL is invalid")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if parsed.scheme == "https":
            if not backend.ca_file:
                raise GatewayError("HTTPS backend has no pinned CA file")
            context = ssl.create_default_context(cafile=backend.ca_file)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            connection: http.client.HTTPConnection = http.client.HTTPSConnection(
                parsed.hostname,
                port,
                context=context,
                timeout=BACKEND_RESPONSE_TIMEOUT_SECONDS,
            )
        else:
            if parsed.hostname not in {"127.0.0.1", "::1", "localhost"}:
                raise GatewayError("plaintext backend must be loopback-local")
            connection = http.client.HTTPConnection(
                parsed.hostname,
                port,
                timeout=BACKEND_RESPONSE_TIMEOUT_SECONDS,
            )
        return connection, f"{parsed.hostname}:{port}"

    def _count_tokens(self, backend: Backend, body: bytes) -> int:
        if backend.token_count_path is None or backend.token_count_protocol is None:
            raise AdmissionError(
                "this runtime cannot enforce an exact API-key context limit",
                status=503,
                code="exact_context_unavailable",
            )
        connection: http.client.HTTPConnection | None = None
        try:
            connection, host = self._connect(backend)
            token = _read_backend_token(backend.credential_file)
            count_body = prepare_token_count_request(
                backend.token_count_protocol, backend.model, body
            )
            count_path = backend.token_count_path
            connection.request(
                "POST",
                count_path,
                body=count_body,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Host": host,
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "Content-Length": str(len(count_body)),
                    "Connection": "close",
                },
            )
            response = connection.getresponse()
            payload = response.read(MAX_USAGE_TAIL_BYTES + 1)
            if response.status != 200 or len(payload) > MAX_USAGE_TAIL_BYTES:
                raise AdmissionError(
                    "runtime exact token counting failed",
                    status=503,
                    code="exact_context_unavailable",
                )
            return parse_token_count_response(
                backend.token_count_protocol, backend.model, payload
            )
        except AdmissionError:
            raise
        except (OSError, ssl.SSLError, http.client.HTTPException, TokenCountError) as error:
            raise AdmissionError(
                "runtime exact token counting failed",
                status=503,
                code="exact_context_unavailable",
            ) from error
        finally:
            if connection is not None:
                connection.close()

    def _models(self) -> None:
        try:
            policy = self.gateway.policy.authenticate(self._token())
        except GatewayError as error:
            self._json(503, str(error), code="key_authority_unavailable")
            return
        if policy is None:
            self._json(401, "invalid or expired API key", code="unauthorized")
            return
        self.gateway.policy.reload()
        with self.gateway.policy.lock:
            models = {
                backend.model
                for backend in self.gateway.policy.backends
                if backend.healthy
                and self.gateway.policy.backend_available(backend)
            }
            alias_map = dict(self.gateway.policy.aliases)
            aliases = {alias for alias, model in alias_map.items() if model in models}
        allowed = set(policy["models"])
        if allowed:
            models = {model for model in models if model in allowed}
            aliases = {
                alias for alias in aliases
                if alias in allowed or alias_map[alias] in allowed
            }
        now = int(time.time())
        body = json.dumps(
            {
                "object": "list",
                "data": [
                    {"id": name, "object": "model", "created": now, "owned_by": "letsinfer"}
                    for name in sorted(models | aliases)
                ],
            },
            separators=(",", ":"),
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def _proxy(self) -> None:
        received_unix_ms = int(time.time() * 1000)
        request_id = uuid.uuid4().hex
        self.gateway.metrics.update(requests_received=1)
        if self.path not in PUBLIC_INFERENCE_POST_PATHS:
            self._json(
                404,
                "only the supported OpenAI-compatible inference surface is available",
                code="not_found",
            )
            return
        try:
            policy = self.gateway.policy.authenticate(self._token())
        except GatewayError as error:
            self.gateway.metrics.update(requests_failed=1)
            self._json(503, str(error), code="key_authority_unavailable")
            return
        if policy is None:
            self.gateway.metrics.update(requests_failed=1)
            self._json(401, "invalid or expired API key", code="unauthorized")
            return
        exact_prompt_tokens: int | None = None
        try:
            requested_model, model, prefix_key, max_tokens, body = self._request_model(self._body())
            if policy["models"] and not {requested_model, model}.intersection(policy["models"]):
                raise AdmissionError(
                    "API key is not authorized for this model", status=403, code="model_forbidden"
                )
            if (
                policy["context_limit"] is not None
                and max_tokens is not None
                and max_tokens > policy["context_limit"]
            ):
                raise AdmissionError("request exceeds the API key context limit")
            if (
                policy["context_limit"] is not None
                or policy["tokens_per_minute"] is not None
            ) and max_tokens is None:
                raise AdmissionError(
                    "max_tokens is required for bounded context or token-rate policy",
                    status=400,
                    code="token_budget_required",
                )
            context_backends = self.gateway.policy.context_backends(model)
            maximum_context = max(
                (backend.max_context_tokens for backend in context_backends),
                default=None,
            )
            if (
                maximum_context is not None
                and max_tokens is not None
                and max_tokens > maximum_context
            ):
                raise AdmissionError(
                    "request exceeds every qualified placement's context capacity",
                    status=400,
                    code="context_length_exceeded",
                )
            count_backends = [
                backend
                for backend in context_backends
                if backend.token_count_path is not None
                and backend.token_count_protocol is not None
            ]
            count_error: AdmissionError | None = None
            for count_backend in count_backends:
                try:
                    exact_prompt_tokens = self._count_tokens(count_backend, body)
                    break
                except AdmissionError as error:
                    count_error = error
            exact_required = (
                policy["context_limit"] is not None
                or policy["tokens_per_minute"] is not None
            )
            if exact_prompt_tokens is None and (count_backends or exact_required):
                raise count_error or AdmissionError(
                    "this runtime cannot enforce an exact API-key context limit",
                    status=503,
                    code="exact_context_unavailable",
                )
            if exact_prompt_tokens is not None:
                total_requested = exact_prompt_tokens + (max_tokens or 0)
                if (
                    policy["context_limit"] is not None
                    and total_requested > policy["context_limit"]
                ):
                    raise AdmissionError(
                        "request exceeds the API key context limit",
                        status=400,
                        code="context_length_exceeded",
                    )
                if maximum_context is not None and total_requested > maximum_context:
                    raise AdmissionError(
                        "request exceeds every qualified placement's context capacity",
                        status=400,
                        code="context_length_exceeded",
                    )
            self.gateway.quotas.admit(policy)
        except AdmissionError as error:
            self.gateway.metrics.update(requests_failed=1)
            self._json(error.status, str(error), code=error.code)
            return
        except GatewayError as error:
            self.gateway.metrics.update(requests_failed=1)
            self._json(400, str(error), code="invalid_request")
            return

        key_id = str(policy["key_id"])
        backend: Backend | None = None
        selected_placement_group_id: str | None = None
        selected_placement_id: str | None = None
        selected_node_id: str | None = None
        usage = RequestUsage()
        streaming_usage = StreamingUsageTracker()
        queue_seconds = 0.0
        first_byte_at: float | None = None
        dispatch_at: float | None = None
        completed_at: float | None = None
        retries = 0
        status = "failed"
        headers_sent = False
        queued_metric = True
        active_metric = False
        quota_admitted = True
        quota_reserved_tokens = 0
        request_admitted = False
        engine_dispatched = False
        failure_metric_recorded = False
        self.gateway.metrics.update(queued_requests=1)
        try:
            attempted: set[tuple[str, str, str]] = set()
            while True:
                self.gateway.policy.begin_wait(model)
                try:
                    backend, waited = self.gateway.policy.acquire_backend(
                        model,
                        prefix_key=prefix_key,
                        timeout=self.gateway.queue_timeout_seconds,
                        excluded=attempted,
                        cancelled=self._client_disconnected,
                    )
                finally:
                    self.gateway.policy.end_wait(model)
                queue_seconds += waited
                if queued_metric:
                    self.gateway.metrics.update(queued_requests=-1)
                    queued_metric = False
                self.gateway.metrics.update(active_requests=1)
                active_metric = True
                attempted.add(backend.key)
                selected_placement_group_id = backend.placement_group_id
                selected_placement_id = backend.placement_id
                selected_node_id = backend.node_id
                connection: http.client.HTTPConnection | None = None
                try:
                    if (
                        policy["context_limit"] is not None
                        or policy["tokens_per_minute"] is not None
                        or backend.token_count_path is not None
                    ):
                        if exact_prompt_tokens is None:
                            exact_prompt_tokens = self._count_tokens(backend, body)
                        total_requested = exact_prompt_tokens + (max_tokens or 0)
                        if policy["context_limit"] is not None and total_requested > policy["context_limit"]:
                            raise AdmissionError("request exceeds the API key context limit")
                        if total_requested > backend.max_context_tokens:
                            raise PlacementContextMismatch(
                                "request exceeds this placement's qualified context capacity"
                            )
                        if (
                            policy["tokens_per_minute"] is not None
                            and quota_reserved_tokens == 0
                        ):
                            quota_reserved_tokens = self.gateway.quotas.reserve_tokens(
                                policy, total_requested
                            )
                    connection, host = self._connect(backend)
                    token = _read_backend_token(backend.credential_file)
                    headers = {
                        key: value
                        for key, value in self.headers.items()
                        if key.lower() not in HOP_HEADERS | {"content-length"}
                    }
                    headers["Authorization"] = f"Bearer {token}"
                    headers["Host"] = host
                    headers["Connection"] = "close"
                    headers["Content-Length"] = str(len(body))
                    if not request_admitted:
                        self.gateway.metrics.update(requests_admitted=1)
                        self.gateway.policy.record_placement_group_metrics(
                            selected_placement_group_id, requests_admitted=1
                        )
                        request_admitted = True
                    dispatch_at = time.monotonic()
                    engine_dispatched = True
                    dispatch_body = _instrument_stream_usage(backend, body)
                    headers["Content-Length"] = str(len(dispatch_body))
                    connection.request(
                        self.command,
                        self.path,
                        body=dispatch_body,
                        headers=headers,
                    )
                    response = connection.getresponse()
                    if response.status >= 500 and not headers_sent:
                        response.read(MAX_USAGE_TAIL_BYTES)
                        raise OSError(f"backend returned {response.status}")
                    self.send_response(response.status, response.reason)
                    for key, value in response.getheaders():
                        if (
                            key.lower() in HOP_HEADERS | {"date", "server", "content-length"}
                            or key.lower().startswith("access-control-")
                        ):
                            continue
                        self.send_header(key, value)
                    self.send_header("Connection", "close")
                    self.end_headers()
                    headers_sent = True
                    tail = bytearray()
                    while True:
                        chunk = response.read1(64 * 1024)
                        if not chunk:
                            break
                        if first_byte_at is None:
                            first_byte_at = time.monotonic()
                        live_changes = streaming_usage.feed(chunk)
                        if any(live_changes.values()):
                            self.gateway.metrics.update(**live_changes)
                            self.gateway.policy.record_placement_group_metrics(
                                selected_placement_group_id, **live_changes
                            )
                        self.wfile.write(chunk)
                        self.wfile.flush()
                        tail.extend(chunk)
                        if len(tail) > MAX_USAGE_TAIL_BYTES:
                            del tail[:-MAX_USAGE_TAIL_BYTES]
                    if response.length not in {None, 0}:
                        raise http.client.IncompleteRead(bytes(tail), response.length)
                    completed_at = time.monotonic()
                    usage = _usage_from_tail(bytes(tail))
                    status = "completed" if 200 <= response.status < 400 else "failed"
                    self.gateway.policy.mark_backend_success(backend)
                    if status == "completed" and prefix_key is not None:
                        self.gateway.policy.record_prefix_affinity(backend, prefix_key)
                    break
                except AdmissionError as error:
                    if error.code != "exact_context_unavailable" or backend is None:
                        raise
                    self.gateway.policy.mark_backend_failure(backend)
                    with self.gateway.policy.lock:
                        alternatives = [
                            candidate
                            for candidate in self.gateway.policy.backends
                            if candidate.model == model
                            and candidate.key not in attempted
                            and candidate.healthy
                            and self.gateway.policy.backend_available(candidate)
                            and candidate.token_count_path is not None
                        ]
                    if not alternatives:
                        raise
                    if not queued_metric:
                        self.gateway.metrics.update(queued_requests=1)
                        queued_metric = True
                    retries += 1
                    self.gateway.metrics.update(requests_retried=1)
                    continue
                except PlacementContextMismatch:
                    with self.gateway.policy.lock:
                        larger = [
                            candidate
                            for candidate in self.gateway.policy.backends
                            if candidate.model == model
                            and candidate.key not in attempted
                            and candidate.healthy
                            and self.gateway.policy.backend_available(candidate)
                            and candidate.max_context_tokens >= total_requested
                        ]
                    if not larger:
                        raise AdmissionError(
                            "request exceeds every qualified placement's context capacity",
                            status=400,
                            code="context_length_exceeded",
                        )
                    if not queued_metric:
                        self.gateway.metrics.update(queued_requests=1)
                        queued_metric = True
                    continue
                except (OSError, ssl.SSLError, http.client.HTTPException, GatewayError):
                    if backend is not None:
                        self.gateway.policy.mark_backend_failure(backend)
                    if headers_sent:
                        raise
                    with self.gateway.policy.lock:
                        alternatives = [
                            candidate for candidate in self.gateway.policy.backends
                            if candidate.model == model
                            and candidate.key not in attempted
                            and candidate.healthy
                            and self.gateway.policy.backend_available(candidate)
                        ]
                    if not alternatives:
                        raise
                    if not queued_metric:
                        self.gateway.metrics.update(queued_requests=1)
                        queued_metric = True
                    retries += 1
                    self.gateway.metrics.update(requests_retried=1)
                finally:
                    if connection is not None:
                        connection.close()
                    if backend is not None:
                        self.gateway.policy.release_backend(backend)
                        if active_metric:
                            self.gateway.metrics.update(active_requests=-1)
                            active_metric = False
                        backend = None
            self.close_connection = True
        except (ClientDisconnected, BrokenPipeError, ConnectionResetError):
            status = "cancelled"
            self.gateway.metrics.update(requests_cancelled=1)
            self.close_connection = True
        except AdmissionError as error:
            self.gateway.metrics.update(requests_failed=1)
            failure_metric_recorded = True
            if not headers_sent:
                self._json(error.status, str(error), code=error.code)
            else:
                self.close_connection = True
        except (OSError, ssl.SSLError, http.client.HTTPException, GatewayError) as error:
            self.gateway.metrics.update(requests_failed=1)
            failure_metric_recorded = True
            if not headers_sent:
                try:
                    self._json(503, str(error), code="placement_unavailable")
                except (BrokenPipeError, ConnectionResetError):
                    status = "cancelled"
                    self.gateway.metrics.update(requests_cancelled=1)
                    self.close_connection = True
            else:
                self.close_connection = True
        finally:
            if queued_metric:
                self.gateway.metrics.update(queued_requests=-1)
            if active_metric:
                self.gateway.metrics.update(active_requests=-1)
            usage, usage_changes = streaming_usage.reconcile(
                usage,
                exact_prompt_tokens=exact_prompt_tokens if engine_dispatched else None,
            )
            total_tokens = 0
            if engine_dispatched:
                total_tokens = (
                    usage.input_tokens
                    if usage.input_tokens is not None
                    else (exact_prompt_tokens or 0)
                ) + (usage.output_tokens or 0)
            if quota_admitted:
                self.gateway.quotas.complete(
                    key_id,
                    total_tokens,
                    reserved_tokens=quota_reserved_tokens,
                )
            completed_unix_ms = int(time.time() * 1000)
            queue_ms = int(queue_seconds * 1000)
            ttft_ms = int((first_byte_at - dispatch_at) * 1000) if first_byte_at is not None and dispatch_at is not None else None
            decode_ms = int((completed_at - first_byte_at) * 1000) if completed_at is not None and first_byte_at is not None else None
            if status == "completed":
                self.gateway.metrics.update(requests_completed=1)
            elif status == "failed" and not failure_metric_recorded:
                self.gateway.metrics.update(requests_failed=1)
            self.gateway.metrics.update(
                **usage_changes,
                queue_milliseconds=queue_ms,
                ttft_milliseconds=ttft_ms or 0,
                decode_milliseconds=decode_ms or 0,
                exact_token_requests=1
                if usage.exact or exact_prompt_tokens is not None
                else 0,
                prefix_cache_hits=1 if (usage.cached_tokens or 0) > 0 else 0,
            )
            self.gateway.policy.record_placement_group_metrics(
                selected_placement_group_id,
                **usage_changes,
                requests_completed=1 if status == "completed" else 0,
                requests_failed=1 if status == "failed" else 0,
                requests_cancelled=1 if status == "cancelled" else 0,
            )
            self.gateway.usage.submit({
                "request_id": request_id,
                "key_id": key_id,
                "model": model,
                "placement_group_id": selected_placement_group_id,
                "placement_id": selected_placement_id,
                "node_id": selected_node_id,
                "received_unix_ms": received_unix_ms,
                "completed_unix_ms": completed_unix_ms,
                "status": status,
                "input_tokens": usage.input_tokens if usage.input_tokens is not None else exact_prompt_tokens,
                "output_tokens": usage.output_tokens,
                "cached_tokens": usage.cached_tokens,
                "queue_ms": queue_ms,
                "ttft_ms": ttft_ms,
                "decode_ms": decode_ms,
                "retries": retries,
                "exact_tokens": 1
                if usage.exact or exact_prompt_tokens is not None
                else 0,
            })

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            healthy = self.gateway.metrics.healthy()
            body = b'{"status":"ok"}' if healthy else b'{"status":"degraded"}'
            self.send_response(200 if healthy else 503)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True
            return
        if self.path == "/v1/models":
            self._models()
            return
        self._json(405, "GET is only supported for /health and /v1/models", code="method_not_allowed")

    def do_OPTIONS(self) -> None:  # noqa: N802
        path = urllib.parse.urlsplit(self.path).path
        if path not in PUBLIC_INFERENCE_PATHS:
            self._json(
                404,
                "only the supported OpenAI-compatible inference surface is available",
                code="not_found",
            )
            return
        requested_method = self.headers.get("Access-Control-Request-Method", "").upper()
        allowed_for_path = "GET" if path in PUBLIC_INFERENCE_GET_PATHS else "POST"
        if requested_method and requested_method != allowed_for_path:
            self._json(405, "requested CORS method is not supported", code="method_not_allowed")
            return
        try:
            requested_headers = self._cors_requested_headers()
        except GatewayError as error:
            self._json(400, str(error), code="invalid_request")
            return
        self.send_response(204)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", requested_headers)
        self.send_header("Access-Control-Max-Age", "600")
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

    def do_POST(self) -> None:  # noqa: N802
        self._proxy()

    def do_DELETE(self) -> None:  # noqa: N802
        self._json(405, "method is not supported", code="method_not_allowed")

    def do_PUT(self) -> None:  # noqa: N802
        self._json(405, "method is not supported", code="method_not_allowed")


def run_gateway(arguments: argparse.Namespace) -> int:
    identity = read_identity()
    if identity.role != "main":
        raise GatewayError(
            f"the inference gateway runs on the main node; main="
            f"{identity.coordinator_id}@{identity.coordinator_address}"
        )
    if arguments.port < 1 or arguments.port > 65535:
        raise GatewayError("gateway port must be between 1 and 65535")
    if arguments.max_connections < 1 or arguments.max_connections > MAX_CONNECTIONS:
        raise GatewayError(f"max connections must be between 1 and {MAX_CONNECTIONS}")
    if arguments.queue_timeout < 0 or arguments.queue_timeout > 3600:
        raise GatewayError(
            "queue timeout must be 0 (unlimited) or between 1 and 3600 seconds"
        )
    server = GatewayServer(
        (arguments.listen, arguments.port), identity=identity,
        telemetry_file=pathlib.Path(arguments.telemetry_file).expanduser(),
        queue_timeout_seconds=arguments.queue_timeout,
        max_connections=arguments.max_connections,
    )
    stop = threading.Event()

    def shutdown(_signal: int, _frame: Any) -> None:
        stop.set()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        server.server_close()
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="letsinfer-gateway")
    root.add_argument("--listen", default="127.0.0.1")
    root.add_argument("--port", type=int, default=8000)
    root.add_argument("--telemetry-file", required=True)
    root.add_argument("--queue-timeout", type=int, default=DEFAULT_QUEUE_TIMEOUT_SECONDS)
    root.add_argument("--max-connections", type=int, default=128)
    return root


def main(argv: Sequence[str] | None = None) -> int:
    try:
        return run_gateway(parser().parse_args(argv))
    except (GatewayError, SiteError, OSError, ssl.SSLError) as error:
        print(f"FATAL: {error}", file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
