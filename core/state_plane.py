#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""One engine-neutral operational state plane for Let's Infer.

Collectors publish observations.  This module alone turns those observations
into availability, admission, and lifecycle signals.  In particular, host
memory headroom is telemetry: loaded engines commonly reserve weights, KV
cache, and graph workspaces before serving requests, so it is not an admission
or health signal by itself.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def member_health_state(*, protection_tripped: bool) -> str:
    """Return the member state derived from the Guard fault signal."""

    return "degraded" if protection_tripped else "healthy"


def member_available(health: Mapping[str, Any]) -> bool:
    """Return whether a member may host or continue a placement."""

    return (
        health.get("state") == "healthy"
        and health.get("protection_trip") is False
    )


def backend_available(
    endpoint: Mapping[str, Any], member_health: Mapping[str, Any]
) -> bool:
    """Return whether one engine endpoint is operational.

    This contract is deliberately independent of engine name and host-memory
    headroom.  Guard faults and explicit endpoint/member health are hard
    signals; each engine's declared capacity controls admission separately.
    """

    return endpoint.get("healthy", True) is True and member_available(member_health)


def engine_has_capacity(*, active_requests: int, max_active_requests: int) -> bool:
    """Apply the capacity declared by any engine adapter."""

    return active_requests < max_active_requests


def runtime_lifecycle(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Derive one explicit runtime lifecycle from all observed components."""

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
    qualification_mode = service.get("runtime_mode") == "qualification"
    if qualification_mode:
        # The candidate owns the inference slot directly. The resident engine
        # unit and recovery timer are intentionally quiesced.
        unit_states = (
            service.get("active") == "active",
            service.get("gateway_active") == "active",
            service.get("site_active") == "active",
        )
    else:
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
    if (
        (qualification_mode or engine_state in {"inactive", "not-found"})
        and container_state in {"absent", "created", "exited"}
        and protection.get("armed") is False
        and protection.get("trip_latched") is False
    ):
        return {**details, "state": "stopped", "reason": "runtime-stopped"}
    if engine_state == "failed" or docker_health == "unhealthy" or container_state in {
        "dead",
        "paused",
    }:
        return {**details, "state": "failed", "reason": "runtime-failure"}
    if not runtime_metadata_ready:
        return {
            **details,
            "state": "degraded",
            "reason": "runtime-metadata-incompatible",
        }
    return {**details, "state": "degraded", "reason": "component-not-ready"}
