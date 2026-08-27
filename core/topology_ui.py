#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Live, read-only rendering for verified node topology."""

from __future__ import annotations

import re
import sys
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from . import ui


ANSI = re.compile(r"\033\[[0-9;]*m")
SPINNER = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")
REFRESH_SECONDS = 0.08
PULSE_STEP_SECONDS = REFRESH_SECONDS * 2.5
SNAPSHOT_SECONDS = 1.0


class _TopologySnapshotWorker:
    """Refresh topology state without ever blocking animation rendering."""

    def __init__(
        self,
        snapshot: Callable[[], Mapping[str, Any]],
        initial: Mapping[str, Any],
    ) -> None:
        self.snapshot = snapshot
        self.lock = threading.Lock()
        self.stopped = threading.Event()
        self.payload = dict(initial)
        self.failure: BaseException | None = None
        self.thread = threading.Thread(
            target=self._run,
            name="letsinfer-topology-snapshot",
            daemon=True,
        )

    def start(self) -> None:
        self.thread.start()

    def _run(self) -> None:
        while not self.stopped.wait(SNAPSHOT_SECONDS):
            try:
                value = dict(self.snapshot())
            except BaseException as error:
                with self.lock:
                    self.failure = error
                return
            with self.lock:
                self.payload = value

    def current(self) -> dict[str, Any]:
        with self.lock:
            failure = self.failure
            payload = dict(self.payload)
        if failure is not None:
            raise failure
        return payload

    def close(self) -> None:
        self.stopped.set()
        self.thread.join(timeout=SNAPSHOT_SECONDS + 1.0)


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
    online = node.get("online") is not False and node.get("state") != "offline"
    paused = node.get("state") == "paused"
    name = str(node.get("name") or str(node.get("member_id") or "unknown")[:8])
    role = str(node.get("role") or "node").upper()
    role_suffix = " · MAIN" if role == "MAIN" else ""
    state_suffix = " · ONLINE" if online else " · OFFLINE"
    if paused:
        state_suffix += " · PAUSED"
    mark = spinner if online else "○" if terminal.unicode else "!"
    fixed_width = len(mark) + 1 + len(role_suffix) + len(state_suffix)
    rendered_name = terminal.clip(name, max(1, width - fixed_width))
    rendered = terminal.paint(
        mark,
        ui.BOLD,
        ui.BLUE if online else ui.RED,
    )
    rendered += " " + terminal.paint(rendered_name, ui.BOLD, ui.LIGHT)
    if role_suffix:
        rendered += terminal.paint(role_suffix, ui.DIM)
    rendered += terminal.paint(" · ", ui.DIM)
    rendered += terminal.paint(
        "ONLINE" if online else "OFFLINE",
        ui.BOLD,
        ui.GREEN if online else ui.RED,
    )
    if paused:
        rendered += terminal.paint(" · ", ui.DIM)
        rendered += terminal.paint("PAUSED", ui.BOLD, ui.YELLOW)
    return rendered


def _node_detail(terminal: ui.Terminal, node: Mapping[str, Any], width: int) -> str:
    accelerator = str(node.get("accelerator") or "accelerator unknown")
    memory = node.get("system_memory_gib", node.get("memory_total_gib"))
    accelerator_memory = node.get("accelerator_memory_gib")
    if (
        node.get("memory_topology") == "discrete"
        and isinstance(accelerator_memory, int)
        and not isinstance(accelerator_memory, bool)
        and isinstance(memory, int)
        and not isinstance(memory, bool)
    ):
        detail = f"{accelerator} · {accelerator_memory} G VRAM · {memory} G RAM"
    else:
        memory_text = (
            f"{memory} G"
            if isinstance(memory, int) and not isinstance(memory, bool)
            else "memory —"
        )
        detail = f"{accelerator} · {memory_text}"
    return terminal.paint(terminal.clip(detail, width), ui.DIM)


def _node_models(terminal: ui.Terminal, node: Mapping[str, Any], width: int) -> str:
    models = node.get("models")
    values: list[str] = []
    if isinstance(models, list):
        for row in models:
            if not isinstance(row, Mapping):
                continue
            model = str(row.get("model") or "model")
            state = str(row.get("state") or "unknown")
            if state == "running":
                values.append(model)
            else:
                label = "paused" if state == "stopped" else state
                values.append(f"{model} · {label.upper()}")
    text = ", ".join(value for value in values if value) or "No model placement"
    return terminal.paint(terminal.clip(text, width), ui.DIM)


def _tree_node_lines(
    terminal: ui.Terminal,
    node: Mapping[str, Any],
    *,
    frame: int,
    width: int,
    branch: str = "",
    rendered_branch: str | None = None,
    rendered_continuation: str | None = None,
) -> list[str]:
    spinner = SPINNER[frame % len(SPINNER)] if terminal.unicode else "*"
    continuation = (
        rendered_continuation
        if rendered_continuation is not None
        else " " * len(branch)
    )
    return [
        (rendered_branch if rendered_branch is not None else branch)
        + _node_header(terminal, node, spinner, max(8, width - len(branch))),
        continuation + _node_detail(terminal, node, max(8, width - len(branch))),
        continuation + _node_models(terminal, node, max(8, width - len(branch))),
    ]


def _edge_link(
    parent: Mapping[str, Any] | None,
    child: Mapping[str, Any],
    links: Sequence[Mapping[str, Any]],
) -> Mapping[str, Any] | None:
    if parent is None:
        return None
    wanted = {
        str(parent.get("member_id")),
        str(child.get("member_id")),
    }
    return next(
        (
            link
            for link in links
            if isinstance(link.get("members"), list)
            and {str(value) for value in link["members"]} == wanted
        ),
        None,
    )


def _edge_capability(link: Mapping[str, Any]) -> str:
    speed = link.get("speed_mbps")
    speed_text = (
        f"{speed / 1000:g} Gbit/s"
        if isinstance(speed, int) and not isinstance(speed, bool) and speed >= 1000
        else f"{speed} Mbit/s"
        if isinstance(speed, int) and not isinstance(speed, bool)
        else "speed —"
    )
    return " · ".join(
        value
        for value in (
            speed_text,
            "RDMA" if link.get("rdma") is True else None,
            f"MTU {link['mtu']}"
            if isinstance(link.get("mtu"), int)
            and not isinstance(link.get("mtu"), bool)
            else None,
        )
        if value is not None
    )


def topology_lines(
    payload: Mapping[str, Any],
    terminal: ui.Terminal,
    *,
    frame: int = 0,
    pulse_frame: int | None = None,
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
    pulse = frame if pulse_frame is None else pulse_frame
    running_models = len({
        str(model.get("model"))
        for row in nodes_list
        for model in (
            row.get("models", []) if isinstance(row.get("models"), list) else []
        )
        if isinstance(model, Mapping) and model.get("state") == "running"
    })
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
            terminal, root, frame=frame, width=width
        )))
    for index, child in enumerate(children):
        pulse_segments = max(4, len(children) * 4)
        pulse_base = index * 4
        verified = _edge_link(roots[0] if roots else None, child, links)
        connection = (
            "ConnectX"
            if verified is not None and verified.get("kind") == "connectx"
            else str(verified.get("kind") or "Network").title()
            if verified is not None
            else str(child.get("connection") or "Network")
        )
        connection_line = _tree_pulse(
            terminal,
            "│",
            frame=pulse,
            segment=pulse_base + 1,
            segments=pulse_segments,
        ) + " " + terminal.paint(f"[{connection}]", ui.LIGHT)
        if verified is not None:
            connection_line += "  " + terminal.paint(
                _edge_capability(verified),
                ui.DIM,
            )
        branch = "└── " if index == len(children) - 1 else "├── "
        rendered_branch = _tree_pulse(
            terminal,
            branch,
            frame=pulse,
            segment=pulse_base + 3,
            segments=pulse_segments,
        )
        rendered_continuation = (
            _tree_pulse(
                terminal,
                "│",
                frame=pulse,
                segment=pulse_base + 3,
                segments=pulse_segments,
            )
            + "   "
            if index < len(children) - 1
            else " " * len(branch)
        )
        lines.extend(
            (
                _tree_pulse(
                    terminal,
                    "│",
                    frame=pulse,
                    segment=pulse_base,
                    segments=pulse_segments,
                ),
                connection_line,
                _tree_pulse(
                    terminal,
                    "│",
                    frame=pulse,
                    segment=pulse_base + 2,
                    segments=pulse_segments,
                ),
                *_tree_node_lines(
                    terminal,
                    child,
                    frame=frame,
                    width=width,
                    branch=branch,
                    rendered_branch=rendered_branch,
                    rendered_continuation=rendered_continuation,
                ),
            )
        )
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
    """Animate smoothly while topology snapshots refresh off the render path."""

    terminal = ui.Terminal(sys.stdout)
    worker: _TopologySnapshotWorker | None = None
    alternate_screen = False
    try:
        worker = _TopologySnapshotWorker(snapshot, dict(snapshot()))
        worker.start()
        animation_started = time.monotonic()
        next_frame = animation_started
        while True:
            now = time.monotonic()
            frame = int(max(0.0, now - animation_started) / REFRESH_SECONDS)
            pulse_frame = int(
                max(0.0, now - animation_started) / PULSE_STEP_SECONDS
            )
            payload = worker.current()
            prefix = "\033[?1049h\033[?25l\033[H" if not alternate_screen else "\033[H"
            alternate_screen = True
            terminal.stream.write(
                prefix
                + "\n".join(
                    topology_lines(
                        payload,
                        terminal,
                        frame=frame,
                        pulse_frame=pulse_frame,
                    )
                )
                + "\n\033[J"
            )
            terminal.stream.flush()
            next_frame += REFRESH_SECONDS
            now = time.monotonic()
            if next_frame <= now:
                next_frame = now + REFRESH_SECONDS
            time.sleep(next_frame - now)
    except KeyboardInterrupt:
        return 0
    finally:
        if worker is not None:
            worker.close()
        if alternate_screen:
            terminal.stream.write("\033[?25h\033[?1049l\n")
            terminal.stream.flush()
