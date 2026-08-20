#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Dependency-free live status dashboard rendering."""

from __future__ import annotations

import re
from typing import Any, Iterable, Mapping

from . import ui


ANSI = re.compile(r"\033\[[0-9;]*m")


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _number(value: object, default: float = -1.0) -> float:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    return default


def _integer(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _format_uptime(value: object) -> str:
    seconds = _integer(value)
    if seconds is None or seconds < 0:
        return "Uptime —"
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes = remainder // 60
    if days:
        return f"Uptime {days}d {hours}h"
    if hours:
        return f"Uptime {hours}h {minutes}m"
    return f"Uptime {minutes}m"


def _context(value: object) -> str:
    tokens = _integer(value)
    if tokens is None or tokens <= 0:
        return "unknown context"
    if tokens >= 1_000_000:
        return f"{tokens / 1_000_000:.1f}M context"
    if tokens >= 1_000:
        return f"{tokens / 1_000:.0f}K context"
    return f"{tokens} context"


def _bytes_gib(value: object) -> str:
    amount = _number(value)
    return "—" if amount < 0 else f"{amount / 1024**3:.1f} GiB"


def _mib(value: object) -> str:
    amount = _number(value)
    return "—" if amount < 0 else f"{amount / 1024**2:.1f} MiB"


def _rate(value: object) -> str:
    amount = _number(value)
    return "—" if amount < 0 else f"{amount:.1f}"


def _percent(value: object) -> str:
    amount = _number(value)
    return "—" if amount < 0 else f"{amount:.0f}%"


def _temperature(value: object) -> str:
    amount = _number(value)
    return "—" if amount < 0 else f"{amount / 10:.0f}°C"


def _clock(value: object) -> str:
    amount = _number(value)
    return "—" if amount < 0 else f"{amount / 1000:.2f} GHz"


def _meter(terminal: ui.Terminal, value: float, *, width: int = 16) -> str:
    bounded = max(0.0, min(100.0, value))
    filled = round(bounded / 100.0 * width)
    if bounded > 0 and filled == 0:
        filled = 1
    return terminal.paint(" " * filled, "\033[48;2;247;247;247m") + terminal.paint(
        ("· " * width)[: width - filled], ui.DIM
    )


def _sparkline(
    terminal: ui.Terminal, values: Iterable[float], *, width: int = 24
) -> str:
    raw = list(values)
    if not raw:
        return terminal.paint("·" * width, ui.DIM)
    points: list[float] = []
    for index in range(width):
        position = index * (len(raw) - 1) / max(1, width - 1)
        left = int(position)
        right = min(len(raw) - 1, left + 1)
        fraction = position - left
        points.append(raw[left] + (raw[right] - raw[left]) * fraction)
    blocks = "▁▂▃▄▅▆▇█"
    maximum = max(max(points), 1.0)
    return "".join(
        blocks[min(7, max(0, round(max(0.0, value) / maximum * 7)))]
        for value in points
    )


def _row(
    terminal: ui.Terminal,
    label: str,
    value: str,
    detail: str = "",
    *,
    color: str | None = None,
    width: int,
) -> str:
    label_text = terminal.paint(label.ljust(13), ui.DIM)
    value_text = terminal.paint(value.ljust(14), *(filter(None, (ui.BOLD, color))))
    detail_text = terminal.paint(
        terminal.clip(detail, max(1, width - 29)), ui.DIM
    )
    return f"{label_text}{value_text}{detail_text}".rstrip()


def _panel(terminal: ui.Terminal, values: Iterable[str]) -> list[str]:
    outer_width = max(48, min(terminal.width, 76))
    inner_width = outer_width - 6
    border = "─" * (outer_width - 2)
    lines = [terminal.paint(f"┌{border}┐", ui.DIM)]
    for value in values:
        plain = ANSI.sub("", value)
        rendered = value if len(plain) <= inner_width else terminal.clip(value, inner_width)
        plain = ANSI.sub("", rendered)
        padding = " " * max(0, inner_width - len(plain))
        lines.append(
            f"{terminal.paint('│', ui.DIM)}  {rendered}{padding}  "
            f"{terminal.paint('│', ui.DIM)}"
        )
    lines.append(terminal.paint(f"└{border}┘", ui.DIM))
    return lines


def dashboard_lines(
    payload: Mapping[str, Any],
    terminal: ui.Terminal,
    *,
    session_history: Mapping[str, list[float]] | None = None,
) -> list[str]:
    service = _mapping(payload.get("service"))
    container = _mapping(payload.get("container"))
    protection = _mapping(payload.get("protection"))
    lifecycle = _mapping(payload.get("lifecycle"))
    capacity = _mapping(container.get("capacity"))
    telemetry = _mapping(payload.get("telemetry"))
    rates = _mapping(telemetry.get("rates"))
    system = _mapping(telemetry.get("system"))
    site = _mapping(payload.get("site"))
    history = session_history or {}
    width = max(42, min(terminal.width, 76) - 6)

    pressure = service.get("memory_pressure") is True
    derived_ready = (
        container.get("state") == "running"
        and container.get("healthy") is True
        and container.get("docker_health") == "healthy"
        and container.get("model_identity") is True
        and service.get("gateway_active") == "active"
        and service.get("gateway_health") is True
        and service.get("gateway_authenticated") is True
        and service.get("gateway_model_identity") is True
        and protection.get("armed") is True
        and protection.get("trip_latched") is False
    )
    lifecycle_state = str(
        lifecycle.get("state") or ("ready" if derived_ready else "degraded")
    )
    serving = lifecycle_state == "ready"
    state = (
        "PRESSURE"
        if pressure
        else "SERVING"
        if serving
        else "STARTING"
        if lifecycle_state == "starting"
        else "STOPPED"
        if lifecycle_state == "stopped"
        else "FAILED"
        if lifecycle_state in {"failed", "blocked"}
        else "ATTENTION"
    )
    state_color = (
        ui.ORANGE
        if pressure
        else ui.GREEN
        if serving
        else ui.CYAN
        if lifecycle_state == "starting"
        else ui.RED
        if lifecycle_state in {"failed", "blocked"}
        else ui.YELLOW
    )
    site_state = "Ready" if serving and not pressure else "Pressure" if pressure else "Attention"
    site_color = ui.GREEN if serving and not pressure else ui.ORANGE if pressure else ui.YELLOW
    endpoint = str(service.get("gateway_endpoint") or "LAN HTTP · API key").removeprefix(
        "http://"
    )
    model = str(container.get("model") or "No model")
    engine = {
        "dwarfstar": "DwarfStar",
        "llama.cpp": "llama.cpp",
        "sglang": "SGLang",
        "vllm": "vLLM",
    }.get(str(container.get("engine") or "unknown"), str(container.get("engine") or "unknown"))
    target = str(container.get("target") or "unknown target")
    version = str(container.get("runtime_version") or "unknown version")
    active = _integer(telemetry.get("active_requests"))
    queued = _integer(telemetry.get("queued_requests"))
    maximum = _integer(capacity.get("max_connections")) or _integer(
        capacity.get("max_active_requests")
    )
    allocated = _integer(capacity.get("max_active_requests"))
    services_total = _integer(lifecycle.get("total_services"))
    services_ready = _integer(lifecycle.get("ready_services"))
    if services_total is None or services_ready is None:
        service_states = (
            service.get("active") == "active",
            service.get("engine_active") == "active",
            service.get("gateway_active") == "active",
            service.get("site_active") == "active",
            service.get("recovery_timer_active") == "active",
        )
        services_total = len(service_states)
        services_ready = sum(service_states)
    api_process_ready = (
        service.get("gateway_active") == "active"
        and service.get("gateway_health") is True
        and service.get("gateway_auth_required") is True
        and service.get("gateway_authenticated") is True
    )
    route_ready = service.get("gateway_model_identity") is True

    lines = [terminal.logo(), ""]
    display_name = str(site.get("display_name") or "Home")
    lines.append(
        f"{terminal.paint(display_name, ui.BOLD)}  "
        f"{terminal.paint(site_state, ui.BOLD, site_color)}  "
        f"{terminal.paint(_format_uptime(site.get('uptime_seconds')), ui.DIM)}"
    )
    hardware = str(site.get("hardware_name") or "Local inference node")
    hostname = str(site.get("hostname") or "local")
    role = str(site.get("role") or "node")
    lines.extend((terminal.paint(f"{hardware} · {hostname} · {role}", ui.DIM), ""))
    lines.append(
        _row(
            terminal,
            "State",
            state,
            terminal.paint("LIVE", ui.BOLD, ui.GREEN) + terminal.paint(" · 1 sec", ui.DIM),
            color=state_color,
            width=width,
        )
    )
    lines.append(_row(terminal, "Model", model, _context(capacity.get("max_context_tokens")), width=width))
    lines.append(_row(terminal, "Engine", engine, target, width=width))
    runtime_metadata_ready = service.get("runtime_metadata_ready") is not False
    lines.append(
        _row(
            terminal,
            "Version",
            version,
            "runtime pack" if runtime_metadata_ready else "runtime metadata incompatible",
            color=None if runtime_metadata_ready else ui.RED,
            width=width,
        )
    )
    api_state = "Paused" if pressure else "Ready" if api_process_ready and route_ready else "Starting" if lifecycle_state == "starting" else "Unavailable"
    api_color = ui.ORANGE if pressure else ui.GREEN if api_state == "Ready" else ui.CYAN if api_state == "Starting" else ui.RED
    api_detail = (
        f"memory pressure · {_bytes_gib(service.get('memory_available_bytes'))} available"
        if pressure
        else endpoint
    )
    lines.append(_row(terminal, "API", api_state, api_detail, color=api_color, width=width))
    lines.append(
        _row(
            terminal,
            "Services",
            f"{services_ready} / {services_total} active",
            "candidate control plane active" if service.get("runtime_mode") == "qualification" else "gateway · engine · watchdog · recovery · telemetry",
            width=width,
        )
    )
    safety = "Pressure" if pressure else "Armed" if protection.get("armed") is True else "Arming" if lifecycle_state == "starting" else "Blocked"
    safety_color = ui.ORANGE if pressure else ui.GREEN if safety == "Armed" else ui.CYAN if safety == "Arming" else ui.RED
    safety_detail = (
        f"admission paused · {_bytes_gib(service.get('memory_pressure_floor_bytes'))} floor"
        if pressure
        else "no trip · candidate guarded"
        if service.get("runtime_mode") == "qualification"
        else "no trip · recovery ready"
    )
    lines.append(_row(terminal, "Safety", safety, safety_detail, color=safety_color, width=width))
    lines.append(
        _row(
            terminal,
            "Watchdog",
            _mib(service.get("memory_current_bytes")),
            f"{_mib(service.get('memory_limit_bytes'))} limit",
            width=width,
        )
    )

    def route(name: str, status: str, detail: str, color: str) -> str:
        return (
            f"{terminal.paint('●', ui.BOLD, color)}  {terminal.paint(name.ljust(10), ui.BOLD)}"
            f"{terminal.paint(status.ljust(11), ui.BOLD, color)}{terminal.paint(detail, ui.DIM)}"
        ).rstrip()

    lines.extend(("", "Request path", terminal.paint("○  CLIENT", ui.DIM), terminal.paint("│", ui.DIM)))
    gateway_state = "PRESSURE" if pressure else "API Ready" if api_process_ready and route_ready else "UNAVAILABLE"
    gateway_color = ui.ORANGE if pressure else ui.GREEN if gateway_state == "API Ready" else ui.RED
    lines.append(route("GATEWAY", gateway_state, endpoint, gateway_color))
    lines.extend((terminal.paint("│", ui.DIM), route("RUNTIME", "SERVING" if container.get("healthy") is True else "STOPPED", f"{model} · {engine}", ui.GREEN if container.get("healthy") is True else ui.RED), terminal.paint("│", ui.DIM), route("TARGET", "READY" if container.get("healthy") is True else "WAITING", target, ui.GREEN if container.get("healthy") is True else ui.YELLOW)))

    scheduler_capacity = str(maximum) if maximum is not None else "—"
    lines.extend(
        (
            "",
            f"Scheduler  {terminal.paint(f'{scheduler_capacity} max · dynamic admission', ui.DIM)}",
        )
    )
    meter_width = 22 if width >= 64 else 16
    active_value = active or 0
    queued_value = queued or 0
    denominator = max(maximum or 1, 1)
    lines.append(_row(terminal, "Active", f"{active_value} requests", _meter(terminal, active_value / denominator * 100, width=meter_width), width=width))
    lines.append(_row(terminal, "Queue", f"{queued_value} waiting", _meter(terminal, queued_value / denominator * 100, width=meter_width), width=width))
    lines.append(_row(terminal, "Allocated", f"{allocated or 0} / {maximum or '—'}", _meter(terminal, (allocated or 0) / denominator * 100, width=meter_width), width=width))

    aggregate_rate = (
        rates.get("aggregate_tokens_per_second")
        if rates.get("aggregate_tokens_per_second") is not None
        else rates.get("output_tokens_per_second")
    )
    decode_rate = rates.get("decode_tokens_per_second")
    prefill_rate = rates.get("prefill_tokens_per_second")
    ttft = _number(rates.get("average_ttft_milliseconds"))
    prefix = _number(rates.get("prefix_cache_hit_ratio"))
    lines.extend(("", "Performance"))
    lines.append(_row(terminal, "Tokens", f"{_rate(aggregate_rate)} tok/s", f"{_rate(decode_rate)} decode · {_rate(prefill_rate)} prefill", width=width))
    lines.append(_row(terminal, "Latency", "—" if ttft < 0 else f"{ttft / 1000:.2f}s TTFT", "— prefix hit" if prefix < 0 else f"{prefix * 100:.0f}% prefix hit", width=width))
    lines.append(_row(terminal, "Context", f"— / {_context(capacity.get('max_context_tokens')).removesuffix(' context')}", "live usage unavailable", width=width))

    historical = telemetry.get("history")
    historical_rows = historical if isinstance(historical, list) else []
    token_history = [
        _number(
            _mapping(
                _mapping(_mapping(row).get("aggregate")).get("rates")
            ).get("aggregate_tokens_per_second"),
            0,
        )
        for row in historical_rows
    ]
    request_history = [
        _number(_mapping(row).get("aggregate", {}).get("active_requests"), 0)
        for row in historical_rows
    ]
    chart_width = 24 if width >= 64 else 16
    lines.extend(("", f"History  {terminal.paint('last 5 min · 1 sec', ui.DIM)}"))
    lines.append(_row(terminal, "Tokens", f"{_rate(aggregate_rate)}/s", _sparkline(terminal, token_history, width=chart_width), width=width))
    lines.append(_row(terminal, "Requests", f"{active_value} active", _sparkline(terminal, request_history, width=chart_width), width=width))
    for label, key in (("GPU", "gpu"), ("Memory", "memory"), ("CPU", "cpu"), ("NVMe", "nvme")):
        values = history.get(key, [])
        lines.append(_row(terminal, label, _percent(system.get({"gpu": "gpu_percent", "memory": "memory_percent", "cpu": "cpu_percent", "nvme": "disk_percent"}[key])), _sparkline(terminal, values, width=chart_width), width=width))

    lines.extend(("", "System"))
    lines.append(_row(terminal, "GPU", _percent(system.get("gpu_percent")), f"{_temperature(system.get('gpu_temp_deci_c'))} · {_clock(system.get('gpu_clock_mhz'))}", width=width))
    memory_used = _number(system.get("memory_used_mib"))
    memory_total = _number(system.get("memory_total_mib"))
    memory_detail = "—" if min(memory_used, memory_total) < 0 else f"{memory_used / 1024:.1f} / {memory_total / 1024:.1f} GB"
    lines.append(_row(terminal, "Unified mem", _percent(system.get("memory_percent")), memory_detail, width=width))
    lines.append(_row(terminal, "CPU", _percent(system.get("cpu_percent")), f"{_temperature(system.get('system_temp_deci_c'))} · {_clock(system.get('cpu_clock_mhz'))}", width=width))
    lines.append(_row(terminal, "NVMe", _percent(system.get("disk_percent")), f"{_temperature(system.get('nvme_temp_deci_c'))} · R/W {_number(system.get('disk_read_kib_s'), 0):.0f}/{_number(system.get('disk_write_kib_s'), 0):.0f} KiB/s", width=width))
    lines.append(_row(terminal, "Power", "—" if _number(system.get("power_deci_w")) < 0 else f"{_number(system.get('power_deci_w')) / 10:.0f} W", "total draw", width=width))
    rx = _number(system.get("network_rx_kib_s"), 0)
    tx = _number(system.get("network_tx_kib_s"), 0)
    lines.append(_row(terminal, "Network", f"{rx + tx:.0f} KiB/s", f"down {rx:.0f} · up {tx:.0f}", width=width))
    return _panel(terminal, lines)
