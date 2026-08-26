#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Live, read-only rendering for verified node topology."""

from __future__ import annotations

import re
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from . import status_ui, ui


ANSI = re.compile(r"\033\[[0-9;]*m")
SPINNER = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")
REFRESH_SECONDS = 0.12
SNAPSHOT_SECONDS = 1.0


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _number(value: object) -> float:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else -1.0


def _plain(value: str) -> str:
    return ANSI.sub("", value)


def _panel(terminal: ui.Terminal, values: Sequence[str]) -> list[str]:
    outer_width = max(48, min(terminal.width, 76))
    inner_width = outer_width - 6
    border = "─" * (outer_width - 2)
    lines = [terminal.paint(f"┌{border}┐", ui.DIM)]
    for value in values:
        rendered = value if len(_plain(value)) <= inner_width else terminal.clip(value, inner_width)
        padding = " " * max(0, inner_width - len(_plain(rendered)))
        lines.append(
            f"{terminal.paint('│', ui.DIM)}  {rendered}{padding}  "
            f"{terminal.paint('│', ui.DIM)}"
        )
    lines.append(terminal.paint(f"└{border}┘", ui.DIM))
    return lines


def _traffic(node: Mapping[str, Any], direction: str) -> tuple[str, bool]:
    traffic = _mapping(node.get("traffic"))
    value = _number(traffic.get(f"{direction}_kib_s"))
    return status_ui._binary_rate_kib(value), bool(traffic.get("fresh")) and value > 0


def _flow(
    terminal: ui.Terminal,
    width: int,
    frame: int,
    *,
    forward: bool,
    active: bool,
) -> str:
    width = max(8, width)
    if not terminal.unicode:
        body = ["-"] * width
        body[-1 if forward else 0] = ">" if forward else "<"
        if active:
            position = frame % (width - 2) + 1
            body[position if forward else width - position - 1] = "*"
        return terminal.paint("".join(body), ui.CYAN if active else ui.DIM)
    body = ["─"] * width
    body[-1 if forward else 0] = "▶" if forward else "◀"
    if active:
        position = frame % (width - 2) + 1
        body[position if forward else width - position - 1] = "◆"
    return terminal.paint("".join(body), ui.CYAN if active else ui.DIM)


def _tree_pulse(
    terminal: ui.Terminal,
    value: str,
    *,
    frame: int,
    segment: int,
    segments: int = 4,
) -> str:
    """Move one neutral white pulse down a logical membership connector."""

    distance = (segment - frame) % segments
    if distance == 0:
        return terminal.paint(value, ui.BOLD, ui.LIGHT)
    if distance == 1:
        return terminal.paint(value, ui.LIGHT)
    return terminal.paint(value, ui.DIM)


def _node_header(
    terminal: ui.Terminal,
    node: Mapping[str, Any],
    spinner: str,
    width: int,
) -> str:
    health = str(node.get("health") or "unknown")
    online = node.get("online") is not False and node.get("state") != "offline"
    paused = node.get("state") == "paused"
    color = (
        ui.GREEN
        if online and health == "healthy" and not paused
        else ui.YELLOW
        if online and (health == "degraded" or paused)
        else ui.RED
    )
    name = str(node.get("name") or str(node.get("member_id") or "unknown")[:8])
    role = str(node.get("role") or "node").upper()
    role_suffix = f" · {role}" if role == "MAIN" else ""
    state_suffix = (
        " · ONLINE · PAUSED"
        if online and paused
        else " · ONLINE"
        if online
        else " · OFFLINE"
    )
    mark = spinner if online else "○" if terminal.unicode else "!"
    return terminal.paint(
        terminal.clip(f"{mark} {name}{role_suffix}{state_suffix}", width),
        ui.BOLD,
        color,
    )


def _node_detail(terminal: ui.Terminal, node: Mapping[str, Any], width: int) -> str:
    accelerator = str(node.get("accelerator") or "accelerator unknown")
    memory = node.get("memory_total_gib")
    memory_text = (
        f"{memory} G"
        if isinstance(memory, int) and not isinstance(memory, bool)
        else "memory —"
    )
    return terminal.paint(terminal.clip(f"{accelerator} · {memory_text}", width), ui.DIM)


def _node_models(terminal: ui.Terminal, node: Mapping[str, Any], width: int) -> str:
    models = node.get("models")
    values = (
        [str(row.get("model")) for row in models if isinstance(row, Mapping)]
        if isinstance(models, list)
        else []
    )
    text = ", ".join(value for value in values if value) or "No model placement"
    return terminal.paint(terminal.clip(text, width), ui.DIM)


def _two_columns(
    terminal: ui.Terminal,
    left: str,
    right: str,
    *,
    width: int,
) -> str:
    gap = 4
    column = max(8, (width - gap) // 2)
    left_plain = _plain(left)
    left_padding = " " * max(0, column - len(left_plain))
    return left + left_padding + " " * gap + right


def _link_lines(
    terminal: ui.Terminal,
    link: Mapping[str, Any],
    nodes: Mapping[str, Mapping[str, Any]],
    *,
    frame: int,
    width: int,
) -> list[str]:
    members = link.get("members")
    if not isinstance(members, list) or len(members) != 2:
        return []
    left = nodes.get(str(members[0]))
    right = nodes.get(str(members[1]))
    if left is None or right is None:
        return []
    spinner = SPINNER[frame % len(SPINNER)] if terminal.unicode else "*"
    column = max(8, (width - 4) // 2)
    left_tx, left_tx_live = _traffic(left, "tx")
    left_rx, left_rx_live = _traffic(left, "rx")
    right_tx, right_tx_live = _traffic(right, "tx")
    right_rx, right_rx_live = _traffic(right, "rx")
    left_forward = f"TX {left_tx}"
    right_forward = f"RX {right_rx}"
    left_reverse = f"RX {left_rx}"
    right_reverse = f"TX {right_tx}"
    rate_width = max(len(left_forward), len(left_reverse), 8)
    opposite_width = max(len(right_forward), len(right_reverse), 8)
    flow_width = max(8, width - rate_width - opposite_width - 2)
    speed = _number(link.get("speed_mbps"))
    speed_text = (
        f"{speed / 1000:g} Gbit/s"
        if speed >= 1000
        else f"{speed:g} Mbit/s"
        if speed >= 0
        else "speed —"
    )
    verified_age = link.get("age_seconds")
    age_text = (
        "verified now"
        if isinstance(verified_age, int) and verified_age <= 1
        else f"verified {verified_age}s ago"
        if isinstance(verified_age, int)
        else "verified"
    )
    capability = " · ".join(
        part
        for part in (
            str(link.get("kind") or "link").upper(),
            speed_text,
            "RDMA" if link.get("rdma") is True else None,
            f"MTU {link.get('mtu')}" if isinstance(link.get("mtu"), int) else None,
            age_text,
        )
        if part is not None
    )
    return [
        _two_columns(
            terminal,
            _node_header(terminal, left, spinner, column),
            _node_header(terminal, right, spinner, column),
            width=width,
        ),
        _two_columns(
            terminal,
            _node_detail(terminal, left, column),
            _node_detail(terminal, right, column),
            width=width,
        ),
        _two_columns(
            terminal,
            _node_models(terminal, left, column),
            _node_models(terminal, right, column),
            width=width,
        ),
        "",
        terminal.paint(left_forward.ljust(rate_width), ui.BOLD)
        + " "
        + _flow(
            terminal,
            flow_width,
            frame,
            forward=True,
            active=left_tx_live or right_rx_live,
        )
        + " "
        + terminal.paint(right_forward.rjust(opposite_width), ui.BOLD),
        terminal.paint(left_reverse.ljust(rate_width), ui.BOLD)
        + " "
        + _flow(
            terminal,
            flow_width,
            frame,
            forward=False,
            active=left_rx_live or right_tx_live,
        )
        + " "
        + terminal.paint(right_reverse.rjust(opposite_width), ui.BOLD),
        terminal.paint(terminal.clip(capability, width), ui.BOLD, ui.GREEN),
        terminal.paint("Node traffic · authenticated host-wide RX/TX", ui.DIM),
    ]


def _unlinked_node_lines(
    terminal: ui.Terminal,
    node: Mapping[str, Any],
    *,
    frame: int,
    width: int,
    peer_count: int,
) -> list[str]:
    spinner = SPINNER[frame % len(SPINNER)] if terminal.unicode else "*"
    return [
        _node_header(terminal, node, spinner, width),
        _node_detail(terminal, node, width),
        _node_models(terminal, node, width),
        terminal.paint(
            "No verified direct node link"
            if peer_count
            else "No other nodes connected",
            ui.DIM,
        ),
    ]


def _node_link_text(
    terminal: ui.Terminal,
    member_id: str,
    links: Sequence[Mapping[str, Any]],
    width: int,
) -> str:
    matches = [
        link
        for link in links
        if isinstance(link.get("members"), list)
        and member_id in [str(value) for value in link["members"]]
    ]
    if not matches:
        return terminal.paint("No verified direct node link", ui.DIM)
    link = matches[0]
    speed = _number(link.get("speed_mbps"))
    speed_text = (
        f"{speed / 1000:g} Gbit/s"
        if speed >= 1000
        else f"{speed:g} Mbit/s"
    )
    text = " · ".join(
        part
        for part in (
            "Verified direct link",
            str(link.get("kind") or "link").title(),
            speed_text,
            "RDMA" if link.get("rdma") is True else None,
        )
        if part is not None
    )
    return terminal.paint(terminal.clip(text, width), ui.DIM)


def _tree_node_lines(
    terminal: ui.Terminal,
    node: Mapping[str, Any],
    links: Sequence[Mapping[str, Any]],
    *,
    frame: int,
    width: int,
    branch: str = "",
    rendered_branch: str | None = None,
) -> list[str]:
    spinner = SPINNER[frame % len(SPINNER)] if terminal.unicode else "*"
    continuation = " " * len(branch)
    return [
        (rendered_branch if rendered_branch is not None else branch)
        + _node_header(terminal, node, spinner, max(8, width - len(branch))),
        continuation + _node_detail(terminal, node, max(8, width - len(branch))),
        continuation + _node_models(terminal, node, max(8, width - len(branch))),
        continuation
        + _node_link_text(
            terminal,
            str(node.get("member_id")),
            links,
            max(8, width - len(branch)),
        ),
    ]


def topology_lines(
    payload: Mapping[str, Any],
    terminal: ui.Terminal,
    *,
    frame: int = 0,
) -> list[str]:
    width = max(42, min(terminal.width, 76) - 6)
    title = terminal.paint("Topology", ui.BOLD)
    brand = terminal.logo()
    gap = " " * max(2, width - len(_plain(title)) - len(_plain(brand)))
    nodes_value = payload.get("nodes")
    links_value = payload.get("links")
    nodes_list = (
        [row for row in nodes_value if isinstance(row, Mapping)]
        if isinstance(nodes_value, list)
        else []
    )
    links = (
        [row for row in links_value if isinstance(row, Mapping)]
        if isinstance(links_value, list)
        else []
    )
    nodes = {str(row.get("member_id")): row for row in nodes_list}
    running_models = sum(
        1
        for row in nodes_list
        for model in (
            row.get("models", []) if isinstance(row.get("models"), list) else []
        )
        if isinstance(model, Mapping) and model.get("state") == "running"
    )
    summary = (
        f"{len(nodes_list)} node{'s' if len(nodes_list) != 1 else ''} · "
        f"{running_models} model{'s' if running_models > 1 else ''} running"
    )
    lines = [title + gap + brand]
    updates = payload.get("updates")
    update_lines = (
        ui.update_available_lines(updates, terminal, width=width)
        if isinstance(updates, list)
        else []
    )
    if update_lines:
        lines.extend(("", *update_lines))
    lines.extend(("", terminal.paint("● ", ui.BOLD, ui.GREEN) + terminal.paint(summary, ui.BOLD)))
    mains = sorted(
        (row for row in nodes_list if row.get("role") == "main"),
        key=lambda row: str(row.get("member_id")),
    )
    children = sorted(
        (row for row in nodes_list if row.get("role") == "child"),
        key=lambda row: (str(row.get("name")), str(row.get("member_id"))),
    )
    roots = mains or [row for row in nodes_list if row not in children]
    for root in roots:
        lines.extend(("", *_tree_node_lines(
            terminal, root, links, frame=frame, width=width
        )))
    for index, child in enumerate(children):
        connection = str(child.get("connection") or "Network")
        branch = "└── " if index == len(children) - 1 else "├── "
        lines.extend(
            (
                _tree_pulse(terminal, "│", frame=frame, segment=0),
                _tree_pulse(
                    terminal,
                    f"[{connection}]",
                    frame=frame,
                    segment=1,
                ),
                _tree_pulse(terminal, "│", frame=frame, segment=2),
                *_tree_node_lines(
                    terminal,
                    child,
                    links,
                    frame=frame,
                    width=width,
                    branch=branch,
                    rendered_branch=_tree_pulse(
                        terminal,
                        branch,
                        frame=frame,
                        segment=3,
                    ),
                ),
            )
        )
    if links:
        lines.extend(("", terminal.paint("Direct links", ui.BOLD)))
        for link in links:
            link_rows = _link_lines(terminal, link, nodes, frame=frame, width=width)
            if link_rows:
                lines.extend(("", *link_rows))
    return _panel(terminal, lines)


def topology_text(
    payload: Mapping[str, Any],
    *,
    stream: Any = None,
    environ: Mapping[str, str] | None = None,
    frame: int = 0,
) -> str:
    target = sys.stdout if stream is None else stream
    terminal = ui.Terminal(target, environ=environ)
    return "\n".join(topology_lines(payload, terminal, frame=frame)) + "\n"


def live_topology(snapshot: Callable[[], Mapping[str, Any]]) -> int:
    """Animate verified topology while refreshing authenticated data once per second."""

    terminal = ui.Terminal(sys.stdout)
    payload: Mapping[str, Any] = {}
    next_snapshot = 0.0
    frame = 0
    alternate_screen = False
    try:
        while True:
            now = time.monotonic()
            if now >= next_snapshot:
                payload = dict(snapshot())
                next_snapshot = now + SNAPSHOT_SECONDS
            prefix = "\033[?1049h\033[?25l\033[H" if not alternate_screen else "\033[H"
            alternate_screen = True
            terminal.stream.write(
                prefix
                + "\n".join(topology_lines(payload, terminal, frame=frame))
                + "\n\033[J"
            )
            terminal.stream.flush()
            frame += 1
            time.sleep(REFRESH_SECONDS)
    except KeyboardInterrupt:
        return 0
    finally:
        if alternate_screen:
            terminal.stream.write("\033[?25h\033[?1049l\n")
            terminal.stream.flush()
