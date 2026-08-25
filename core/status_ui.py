#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Dependency-free live status dashboard rendering."""

from __future__ import annotations

import re
from typing import Any, Iterable, Mapping

from . import ui
from .state_plane import runtime_lifecycle


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


def _temperature_detail(
    terminal: ui.Terminal, temperature: object, remainder: str
) -> str:
    return terminal.paint(_temperature(temperature), ui.BOLD) + terminal.paint(
        f" · {remainder}", ui.DIM
    )


def _sparkline(
    terminal: ui.Terminal,
    values: Iterable[float],
    *,
    width: int = 24,
    color: str | None = None,
    scale_maximum: float | None = None,
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
    maximum = (
        max(scale_maximum, 1.0)
        if scale_maximum is not None
        else max(max(points), 1.0)
    )
    rendered = "".join(
        blocks[min(7, max(0, round(max(0.0, value) / maximum * 7)))]
        for value in points
    )
    return terminal.paint(rendered, color) if color is not None else rendered


def _row(
    terminal: ui.Terminal,
    label: str,
    value: str,
    detail: str = "",
    *,
    color: str | None = None,
    dim_detail: bool = True,
    width: int,
) -> str:
    label_text = terminal.paint(label.ljust(13), ui.DIM)
    value_text = terminal.paint(value.ljust(14), *(filter(None, (ui.BOLD, color))))
    clipped_detail = terminal.clip(detail, max(1, width - 29))
    detail_text = (
        terminal.paint(clipped_detail, ui.DIM) if dim_detail else clipped_detail
    )
    return f"{label_text}{value_text}{detail_text}".rstrip()


def _health_row(
    terminal: ui.Terminal,
    label: str,
    symbol: str,
    text: str,
    *,
    color: str,
    width: int,
) -> str:
    """Render one compact health fact without a synthetic detail column."""
    label_text = terminal.paint(label.ljust(13), ui.DIM)
    symbol_text = terminal.paint(symbol, ui.BOLD, color)
    detail = terminal.paint(
        terminal.clip(text, max(1, width - 16)),
        ui.DIM,
    )
    return f"{label_text}{symbol_text}  {detail}".rstrip()


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
    lifecycle = _mapping(payload.get("lifecycle") or runtime_lifecycle(payload))
    capacity = _mapping(container.get("capacity"))
    telemetry = _mapping(payload.get("telemetry"))
    rates = _mapping(telemetry.get("rates"))
    system = _mapping(telemetry.get("system"))
    site = _mapping(payload.get("node"))
    history = session_history or {}
    width = max(42, min(terminal.width, 76) - 6)

    runtime_installed = service.get("runtime_installed") is not False
    gateway_expected = service.get("gateway_expected") is not False
    watchdog_expected = service.get("watchdog_expected") is not False
    lifecycle_state = str(lifecycle.get("state") or "degraded")
    control_ready = lifecycle_state == "ready"
    serving = control_ready and runtime_installed
    runtime_ready = lifecycle.get("runtime_ready") is True
    state = (
        "SERVING"
        if serving
        else "READY"
        if control_ready
        else "STARTING"
        if lifecycle_state == "starting"
        else "STOPPED"
        if lifecycle_state == "stopped"
        else "FAILED"
        if lifecycle_state in {"failed", "blocked"}
        else "ATTENTION"
    )
    state_color = (
        ui.GREEN
        if control_ready
        else ui.CYAN
        if lifecycle_state == "starting"
        else ui.RED
        if lifecycle_state in {"failed", "blocked"}
        else ui.YELLOW
    )
    site_color = ui.GREEN if control_ready else ui.YELLOW
    endpoint = str(service.get("gateway_endpoint") or "LAN HTTP · API key").removeprefix(
        "http://"
    )
    model = str(
        container.get("model")
        or ("No model" if runtime_installed else "Not installed")
    )
    engine = str(container.get("engine") or "unknown")
    target = str(container.get("target") or "unknown target")
    version = str(container.get("runtime_version") or "unknown version")
    active = _integer(telemetry.get("active_requests"))
    queued = _integer(telemetry.get("queued_requests"))
    maximum = _integer(capacity.get("max_connections")) or _integer(
        capacity.get("max_active_requests")
    )
    allocated = _integer(capacity.get("max_active_requests"))
    api_process_ready = (
        service.get("gateway_active") == "active"
        and service.get("gateway_health") is True
        and service.get("gateway_auth_required") is True
        and service.get("gateway_authenticated") is True
    )
    route_ready = (
        service.get("gateway_model_identity") is True
        if runtime_installed
        else api_process_ready
    )

    display_name = str(site.get("display_name") or "Home")
    uptime = _format_uptime(site.get("uptime_seconds"))
    site_mark = (
        "✓" if terminal.unicode and control_ready
        else "!" if not control_ready
        else "OK"
    )
    brand = terminal.logo()
    display_budget = max(
        1,
        width
        - len(site_mark)
        - len(uptime)
        - len(ANSI.sub("", brand))
        - 6,
    )
    display_name = terminal.clip(display_name, display_budget)
    identity = (
        f"{terminal.paint(display_name, ui.BOLD)}  "
        f"{terminal.paint(site_mark, ui.BOLD, site_color)}  "
        f"{terminal.paint(uptime, ui.DIM)}"
    )
    identity_gap = " " * max(
        2,
        width - len(ANSI.sub("", identity)) - len(ANSI.sub("", brand)),
    )
    lines = [f"{identity}{identity_gap}{brand}"]
    hardware = str(site.get("hardware_name") or "Local inference node")
    hostname = str(site.get("hostname") or "local")
    role = str(site.get("role") or "node")
    lines.append(terminal.paint(f"{hardware} · {hostname} · {role}", ui.DIM))
    updates = payload.get("updates")
    if isinstance(updates, list) and updates:
        labels = ui.update_labels(updates)
        if labels:
            lines.append(
                terminal.paint("↑  UPDATE AVAILABLE", ui.BOLD, ui.YELLOW)
                + terminal.paint(" · " + " · ".join(labels), ui.DIM)
            )
    lines.append("")
    state_symbol = (
        "✓" if terminal.unicode and control_ready
        else "•" if terminal.unicode and lifecycle_state == "starting"
        else "○" if terminal.unicode and lifecycle_state == "stopped"
        else "✗" if terminal.unicode and lifecycle_state in {"failed", "blocked"}
        else "!" if terminal.unicode
        else "OK" if control_ready
        else "!"
    )
    lines.append(
        _health_row(
            terminal,
            "State",
            state_symbol,
            state,
            color=state_color,
            width=width,
        )
    )
    if runtime_installed:
        lines.append(_row(terminal, "Model", model, _context(capacity.get("max_context_tokens")), width=width))
        lines.append(_row(terminal, "Engine", engine, width=width))
        runtime_metadata_ready = service.get("runtime_metadata_ready") is not False
        lines.append(
            _row(
                terminal,
                "Version",
                version,
                "" if runtime_metadata_ready else "runtime metadata incompatible",
                color=None if runtime_metadata_ready else ui.RED,
                width=width,
            )
        )
    else:
        lines.append(
            _row(
                terminal,
                "Runtime",
                "Not installed",
                "letsinfer install <model>",
                width=width,
            )
        )
    api_state = "Ready" if api_process_ready and route_ready else "Starting" if lifecycle_state == "starting" else "Unavailable"
    api_color = ui.GREEN if api_state == "Ready" else ui.CYAN if api_state == "Starting" else ui.RED
    api_detail = endpoint
    api_symbol = (
        "✓" if terminal.unicode and api_state == "Ready"
        else "•" if terminal.unicode and api_state == "Starting"
        else "✗" if terminal.unicode and api_state == "Unavailable"
        else "!" if terminal.unicode
        else "OK" if api_state == "Ready"
        else "!"
    )
    api_text = (
        api_detail
        if api_state == "Ready"
        else f"{api_state} · {api_detail}"
    )
    if gateway_expected:
        lines.append(
            _health_row(
                terminal,
                "API",
                api_symbol,
                api_text,
                color=api_color,
                width=width,
            )
        )
    safety = (
        "Monitoring"
        if not runtime_installed and service.get("active") == "active"
        else "Unavailable"
        if not runtime_installed
        else "Armed"
        if protection.get("armed") is True
        else "Arming"
        if lifecycle_state == "starting"
        else "Disarmed"
        if lifecycle_state == "stopped"
        else "Blocked"
    )
    safety_color = (
        ui.GREEN
        if safety in {"Armed", "Monitoring"}
        else ui.CYAN
        if safety == "Arming"
        else ui.YELLOW
        if safety == "Disarmed"
        else ui.RED
    )
    safety_detail = (
        "intentional stop · no trip"
        if lifecycle_state == "stopped"
        else str(_mapping(protection.get("incident")).get("reason") or "")
        if protection.get("trip_latched") is True
        else ""
    )
    guard_symbol = (
        "✓" if terminal.unicode and safety in {"Armed", "Monitoring"}
        else "•" if terminal.unicode and safety == "Arming"
        else "○" if terminal.unicode and safety == "Disarmed"
        else "✗" if terminal.unicode and safety == "Blocked"
        else "!" if terminal.unicode
        else "OK" if safety in {"Armed", "Monitoring"}
        else "!"
    )
    guard_text = (
        ""
        if safety in {"Armed", "Monitoring"}
        else safety
        if not safety_detail
        else f"{safety} · {safety_detail}"
    )
    if runtime_installed or watchdog_expected:
        lines.append(
            _health_row(
                terminal,
                "Guard",
                guard_symbol,
                guard_text,
                color=safety_color,
                width=width,
            )
        )

    def route(name: str, status: str, detail: str, color: str) -> str:
        status_width = 15 if not runtime_installed else 11
        return (
            f"{terminal.paint('●', ui.BOLD, color)}  {terminal.paint(name.ljust(10), ui.BOLD)}"
            f"{terminal.paint(status.ljust(status_width), ui.BOLD, color)}{terminal.paint(detail, ui.DIM)}"
        ).rstrip()

    if gateway_expected:
        lines.extend(("", "Request path", terminal.paint("○  CLIENT", ui.DIM), terminal.paint("│", ui.DIM)))
        gateway_state = (
            "API Ready"
            if api_process_ready and route_ready
            else "STARTING"
            if lifecycle_state == "starting"
            else "UNAVAILABLE"
        )
        gateway_color = (
            ui.GREEN
            if gateway_state == "API Ready"
            else ui.CYAN
            if gateway_state == "STARTING"
            else ui.RED
        )
        lines.append(route("GATEWAY", gateway_state, endpoint, gateway_color))
        lines.extend(
            (
                terminal.paint("│", ui.DIM),
                route(
                    "RUNTIME",
                    "SERVING"
                    if runtime_ready
                    else "STARTING"
                    if lifecycle_state == "starting"
                    else "NOT INSTALLED"
                    if not runtime_installed
                    else "STOPPED",
                    "letsinfer install <model>"
                    if not runtime_installed
                    else f"{model} · {engine}",
                    ui.GREEN
                    if runtime_ready
                    else ui.CYAN
                    if lifecycle_state == "starting"
                    else ui.YELLOW
                    if not runtime_installed
                    else ui.RED,
                ),
                terminal.paint("│", ui.DIM),
                route(
                    "DEVICE" if not runtime_installed else "TARGET",
                    "READY" if control_ready else "WAITING",
                    hardware if not runtime_installed else target,
                    ui.GREEN if control_ready else ui.YELLOW,
                ),
            )
        )

    active_value = active if active is not None else None
    queued_value = queued if queued is not None else None
    scheduler_capacity = str(maximum) if maximum is not None else "—"
    if runtime_installed:
        lines.extend(
            (
                "",
                f"Scheduler  {terminal.paint(f'{scheduler_capacity} max · dynamic admission', ui.DIM)}",
            )
        )
        lines.append(
            _row(
                terminal,
                "Active",
                "—" if active_value is None else f"{active_value} requests",
                width=width,
            )
        )
        lines.append(
            _row(
                terminal,
                "Queue",
                "—" if queued_value is None else f"{queued_value} waiting",
                width=width,
            )
        )
        lines.append(
            _row(
                terminal,
                "Allocated",
                f"{allocated or 0} / {maximum or '—'}",
                width=width,
            )
        )

    aggregate_rate = (
        rates.get("aggregate_tokens_per_second")
        if rates.get("aggregate_tokens_per_second") is not None
        else rates.get("output_tokens_per_second")
    )
    decode_rate = rates.get("decode_tokens_per_second")
    prefill_rate = rates.get("prefill_tokens_per_second")
    ttft = _number(rates.get("average_ttft_milliseconds"))
    prefix = _number(rates.get("prefix_cache_hit_ratio"))
    chart_width = 24 if width >= 64 else 16
    watchdog_current = _number(service.get("memory_current_bytes"))
    watchdog_limit = _number(service.get("memory_limit_bytes"))
    watchdog_usage = (
        "—"
        if min(watchdog_current, watchdog_limit) < 0
        else f"{watchdog_current / 1024**2:.1f} / {watchdog_limit / 1024**2:.0f} MiB"
    )
    telemetry_display_state = str(telemetry.get("display_state") or "live")
    telemetry_detail = (
        f"reconnecting · last good {_number(telemetry.get('display_age_seconds'), 0):.0f}s ago"
        if telemetry_display_state == "reconnecting"
        else "telemetry unavailable"
        if telemetry_display_state == "unavailable"
        else ""
    )
    lines.extend(("", "Performance" if runtime_installed else "Monitoring"))
    if runtime_installed:
        lines.append(_row(terminal, "Tokens", f"{_rate(aggregate_rate)} tok/s", f"{_rate(decode_rate)} decode · {_rate(prefill_rate)} prefill", width=width))
        lines.append(_row(terminal, "Latency", "—" if ttft < 0 else f"{ttft / 1000:.2f}s TTFT", "— prefix hit" if prefix < 0 else f"{prefix * 100:.0f}% prefix hit", width=width))
        lines.append(_row(terminal, "Context", f"— / {_context(capacity.get('max_context_tokens')).removesuffix(' context')}", "live usage unavailable", width=width))
        lines.append(
            _row(
                terminal,
                "Requests",
                (
                    "—"
                    if active_value is None or queued_value is None
                    else f"{active_value} active · {queued_value} queued"
                ),
                width=width,
            )
        )
    if runtime_installed or watchdog_expected:
        lines.append(
            _row(
                terminal,
                "Watchdog",
                watchdog_usage,
                telemetry_detail,
                color=(ui.YELLOW if telemetry_display_state == "reconnecting" else None),
                width=width,
            )
        )

    memory_used = _number(system.get("memory_used_mib"))
    memory_total = _number(system.get("memory_total_mib"))
    memory_value = _percent(system.get("memory_percent"))
    if min(memory_used, memory_total) >= 0:
        memory_value += f" {memory_used / 1024:.0f}/{memory_total / 1024:.0f}G"
    gpu_value = _percent(system.get("gpu_percent"))
    gpu_clock = _number(system.get("gpu_clock_mhz"))
    if gpu_clock >= 0:
        gpu_value += f" {gpu_clock / 1000:.2f}G"
    cpu_value = _percent(system.get("cpu_percent"))
    cpu_clock = _number(system.get("cpu_clock_mhz"))
    if cpu_clock >= 0:
        cpu_value += f" {cpu_clock / 1000:.2f}G"
    nvme_value = _percent(system.get("disk_percent"))
    disk_read = _number(system.get("disk_read_kib_s"))
    disk_write = _number(system.get("disk_write_kib_s"))
    if min(disk_read, disk_write) >= 0:
        nvme_value += f" R{disk_read:.0f}/W{disk_write:.0f}"
    power_watts = _number(system.get("power_deci_w"))
    power_value = "—" if power_watts < 0 else f"{power_watts / 10:.0f} W"
    rx = _number(system.get("network_rx_kib_s"))
    tx = _number(system.get("network_tx_kib_s"))
    network_value = (
        "—"
        if min(rx, tx) < 0
        else f"{rx + tx:.0f}K/s ↓{rx:.0f} ↑{tx:.0f}"
    )

    system_rows = (
        ("GPU", "gpu", gpu_value, 100.0),
        ("Unified mem", "memory", memory_value, 100.0),
        ("CPU", "cpu", cpu_value, 100.0),
        ("NVMe", "nvme", nvme_value, 100.0),
        ("Power", "power", power_value, None),
        ("Network", "network", network_value, None),
    )
    lines.extend(("", f"System  {terminal.paint('last 5 min · 1 sec', ui.DIM)}"))
    for index, (label, key, value, scale_maximum) in enumerate(system_rows):
        values = history.get(key, [])
        lines.append(
            _row(
                terminal,
                label,
                value,
                _sparkline(
                    terminal,
                    values,
                    width=chart_width,
                    color=ui.HISTORY_CHART_COLORS[index],
                    scale_maximum=scale_maximum,
                ),
                dim_detail=False,
                width=width,
            )
        )

    temperature_rows = (
        ("GPU", "gpu_temp", system.get("gpu_temp_deci_c"), ui.YELLOW),
        ("CPU", "cpu_temp", system.get("system_temp_deci_c"), ui.ORANGE),
        ("NVMe", "nvme_temp", system.get("nvme_temp_deci_c"), ui.RED),
    )
    lines.extend(("", f"Temperature  {terminal.paint('last 5 min · 1 sec', ui.DIM)}"))
    for label, key, value, color in temperature_rows:
        lines.append(
            _row(
                terminal,
                label,
                _temperature(value),
                _sparkline(
                    terminal,
                    history.get(key, []),
                    width=chart_width,
                    color=color,
                    scale_maximum=120.0,
                ),
                dim_detail=False,
                width=width,
            )
        )
    return _panel(terminal, lines)
