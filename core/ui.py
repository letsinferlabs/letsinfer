#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Small, dependency-free terminal presentation primitives for Let's Infer."""

from __future__ import annotations

import argparse
import builtins
import contextlib
import os
import re
import sys
import textwrap
import threading
import time
from types import TracebackType
from typing import Any, Callable, Iterable, Iterator, Mapping, TextIO


RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
# Shared product palette. True-color terminals render the same states as the
# macOS app and website; redirected output and TERM=dumb remain byte-clean,
# while NO_COLOR retains the human layout without terminal escape sequences.
LIGHT = "\033[38;2;247;247;247m"
DARK = "\033[38;2;30;30;30m"
LIGHT_BACKGROUND = "\033[48;2;247;247;247m"
BLUE = "\033[38;2;0;156;223m"
PURPLE = "\033[38;2;151;57;153m"
GREEN = "\033[38;2;97;187;70m"
YELLOW = "\033[38;2;255;185;0m"
ORANGE = "\033[38;2;247;130;0m"
RED = "\033[38;2;226;56;56m"
CYAN = BLUE
# Exact chromatic constants from private-design/colors.json. The runtime keeps
# literal values so it never depends on the private design repository.
HISTORY_CHART_COLORS = (
    BLUE,
    PURPLE,
    GREEN,
    YELLOW,
    ORANGE,
    RED,
)
CLEAR_LINE = "\r\033[2K"
ANSI = re.compile(r"\033\[[0-9;]*m")
LIVE_STATUS_REFRESH_SECONDS = 1.0
LIVE_STATUS_TELEMETRY_GRACE_SECONDS = 3.0
_activity = threading.local()


def _isatty(stream: TextIO) -> bool:
    try:
        return bool(stream.isatty())
    except (AttributeError, OSError):
        return False


def _can_encode(stream: TextIO, value: str) -> bool:
    encoding = getattr(stream, "encoding", None) or "utf-8"
    try:
        value.encode(encoding)
    except (LookupError, UnicodeEncodeError):
        return False
    return True


class Terminal:
    """A terminal capability snapshot with restrained status rendering."""

    def __init__(
        self,
        stream: TextIO | None = None,
        *,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        self.stream = sys.stderr if stream is None else stream
        self.environ = os.environ if environ is None else environ
        term = self.environ.get("TERM", "")
        self.interactive = _isatty(self.stream) and term.lower() != "dumb"
        self.color = self.interactive and "NO_COLOR" not in self.environ
        self.unicode = self.interactive and _can_encode(
            self.stream, "ϟ✓✗•"
        )
        width = self.environ.get("COLUMNS", "")
        if width.isdecimal() and int(width) > 0:
            self.width = int(width)
        elif not self.interactive:
            # Redirected output has no terminal geometry. Avoid a syscall on
            # every argparse formatter and use the stable plain-output width.
            self.width = 80
        else:
            try:
                self.width = os.get_terminal_size(self.stream.fileno()).columns
            except (AttributeError, OSError, ValueError):
                self.width = 80

    def paint(self, value: str, *styles: str) -> str:
        if not self.color or not styles:
            return value
        return "".join(styles) + value + RESET

    def clip(self, value: str, width: int) -> str:
        """Fit plain text to a terminal column budget before adding styles."""
        if width <= 0:
            return ""
        plain = ANSI.sub("", value)
        if len(plain) <= width:
            return value
        suffix = "…" if self.unicode else "..."
        if width <= len(suffix):
            return suffix[:width]
        return plain[: width - len(suffix)].rstrip() + suffix

    def wrap(self, value: str, width: int) -> list[str]:
        """Wrap human prose without ever truncating actionable information."""

        width = max(1, width)
        lines: list[str] = []
        for paragraph in value.splitlines() or [""]:
            lines.extend(
                textwrap.wrap(
                    paragraph,
                    width=width,
                    replace_whitespace=False,
                    drop_whitespace=True,
                    break_long_words=True,
                    break_on_hyphens=False,
                )
                or [""]
            )
        return lines

    def logo(self, section: str | None = None) -> str:
        lockup = self.paint(
            f" {self.mark}  LET'S INFER ",
            BOLD,
            DARK,
            LIGHT_BACKGROUND,
        )
        if not section:
            return lockup
        return f"{lockup} {self.paint(f'/  {section.upper()}', DIM)}"

    def command_header(self, title: str) -> tuple[str, ...]:
        """Place command identity left and the exact product badge right."""

        left = self.paint(title, BOLD)
        brand = self.logo()
        if len(ANSI.sub("", left)) + 2 + len(ANSI.sub("", brand)) <= self.width:
            gap = " " * max(
                2,
                self.width
                - len(ANSI.sub("", left))
                - len(ANSI.sub("", brand)),
            )
            return (left + gap + brand,)
        padding = " " * max(0, self.width - len(ANSI.sub("", brand)))
        return (padding + brand, left)

    def command(self, command: str, description: str) -> str:
        command_width = min(34, max(24, self.width // 2))
        command_text = self.paint(command.ljust(command_width), BOLD, GREEN)
        detail = self.paint(
            self.clip(description, max(1, self.width - command_width - 2)), DIM
        )
        return f"  {command_text}{detail}"

    @property
    def mark(self) -> str:
        return "ϟ" if self.unicode else ">"

    def _label(self, kind: str) -> tuple[str, str]:
        if kind == "success":
            return ("✓" if self.unicode else "OK", GREEN)
        if kind == "warning":
            return ("!", YELLOW)
        if kind == "error":
            return ("✗" if self.unicode else "ERROR", RED)
        return ("•" if self.unicode else "STATUS", CYAN)

    def line(self, kind: str, message: str) -> None:
        label, color = self._label(kind)
        self.stream.write(f"{self.paint(label, BOLD, color)} {message}\n")
        self.stream.flush()

    def status(self, message: str) -> None:
        self.line("status", message)

    def success(self, message: str) -> None:
        self.line("success", message)

    def warning(self, message: str) -> None:
        self.line("warning", message)

    def error(self, message: str) -> None:
        self.line("error", message)


def _section(value: str) -> str:
    """Turn an action identifier into the quiet command breadcrumb."""

    return value.replace(".", " / ").replace("-", " ")


def command_header(
    action: str,
    *,
    stream: TextIO | None = None,
    environ: Mapping[str, str] | None = None,
) -> bool:
    """Open one human command surface with the status lockup.

    The caller chooses the stream. Redirected and machine-readable commands
    deliberately get no frame, so stdout remains a stable data contract.
    """

    target = sys.stderr if stream is None else stream
    terminal = Terminal(target, environ=environ)
    if not terminal.interactive:
        return False
    title = _section(action).replace(" / ", " ").title()
    target.write("\n".join(terminal.command_header(title)) + "\n\n")
    target.flush()
    return True


def confirm(
    message: str,
    *,
    stream: TextIO | None = None,
    environ: Mapping[str, str] | None = None,
) -> bool:
    """Render one consistent destructive-choice prompt and read its answer."""

    # Prompts take terminal ownership.  Clear any delayed activity line first
    # so typed input can never land inside an animation frame.
    before_external_output()
    target = sys.stderr if stream is None else stream
    terminal = Terminal(target, environ=environ)
    target.write(
        f"{terminal.paint('?', BOLD, YELLOW)} "
        f"{terminal.paint(message, BOLD)} "
        f"{terminal.paint('[y/N]', DIM)} "
    )
    target.flush()
    try:
        answer = builtins.input()
    except EOFError:
        return False
    return answer.strip().lower() in {"y", "yes"}


def home(
    *,
    stream: TextIO | None = None,
    environ: Mapping[str, str] | None = None,
) -> None:
    """Render the quiet, action-first no-command surface."""

    target = sys.stdout if stream is None else stream
    terminal = Terminal(target, environ=environ)
    target.write(
        f"{terminal.logo()}\n\n"
        f"{terminal.paint('Your inference node is ready', BOLD)}\n"
        f"{terminal.paint('Install a model to start serving on one local endpoint.', DIM)}\n\n"
        f"{terminal.command('letsinfer model install <model>', 'Install a model')}\n"
        f"{terminal.command('letsinfer status', 'View node health')}\n"
        f"{terminal.command('letsinfer --help', 'Explore commands')}\n\n"
    )
    target.flush()


def update_labels(records: Iterable[object]) -> list[str]:
    """Normalize update records or status dictionaries for every UI surface."""
    labels = []
    for record in records:
        if isinstance(record, Mapping):
            kind = record.get("kind", "")
            subject = record.get("display_subject") or record.get("subject", "")
            version = record.get("version") or record.get("available_version", "")
        else:
            kind = getattr(record, "kind", "")
            subject = getattr(record, "label", getattr(record, "subject", ""))
            version = getattr(record, "available_version", "")
        label = "Core" if kind == "core" else subject
        if isinstance(label, str) and label and isinstance(version, str) and version:
            labels.append(f"{label} {version}")
    return labels


def _update_callout_lines(
    terminal: Terminal,
    headline: str,
    detail: str,
    *,
    width: int | None = None,
) -> list[str]:
    outer_width = max(32, min(width or terminal.width, 76))
    content_width = outer_width - 4
    border = "─" * (outer_width - 2)
    headline_lines = terminal.wrap(headline, content_width - 2)
    detail_lines = terminal.wrap(detail, content_width - 2)
    rendered: list[tuple[str, str]] = []
    for index, line in enumerate(headline_lines):
        if index == 0:
            plain = "! " + line
            styled = (
                terminal.paint("!", BOLD, YELLOW)
                + " "
                + terminal.paint(line, BOLD)
            )
        else:
            plain = "  " + line
            styled = "  " + terminal.paint(line, BOLD)
        rendered.append((plain, styled))
    rendered.extend(
        ("  " + line, "  " + terminal.paint(line, DIM))
        for line in detail_lines
    )
    lines = [terminal.paint(f"┌{border}┐", YELLOW)]
    for plain, styled in rendered:
        padding = " " * max(0, content_width - len(plain))
        lines.append(
            terminal.paint("│", YELLOW)
            + " "
            + styled
            + padding
            + " "
            + terminal.paint("│", YELLOW)
        )
    lines.append(terminal.paint(f"└{border}┘", YELLOW))
    return lines


def update_available_lines(
    records: Iterable[object],
    terminal: Terminal,
    *,
    width: int | None = None,
) -> list[str]:
    """Render one shared update-availability callout for owned UI surfaces."""
    labels = update_labels(records)
    if not labels:
        return []
    return _update_callout_lines(
        terminal,
        "Update available · " + " · ".join(labels),
        "Run `letsinfer update check` for verified details.",
        width=width,
    )


def _update_callout(
    terminal: Terminal,
    headline: str,
    detail: str,
) -> None:
    for line in _update_callout_lines(terminal, headline, detail):
        terminal.stream.write(line + "\n")
    terminal.stream.write("\n")
    terminal.stream.flush()


def update_notice(
    records: Iterable[object],
    *,
    stream: TextIO | None = None,
    environ: Mapping[str, str] | None = None,
    cleared: bool = False,
    attention: bool = False,
) -> None:
    """Render a verified availability change without touching the network.

    ``cleared`` is used only after a background refresh replaced a previously
    rendered availability notice with an empty verified set. Terminal
    scrollback cannot retract the old line, so emit an explicit correction.
    """
    target = sys.stderr if stream is None else stream
    terminal = Terminal(target, environ=environ)
    if not terminal.interactive:
        return
    if cleared and attention:
        raise ValueError("an update refresh cannot be both current and unresolved")
    values = tuple(records)
    labels = update_labels(values)
    if not labels:
        if cleared:
            terminal.success("Update state refreshed · installed components are current")
        elif attention:
            _update_callout(
                terminal,
                "Update state changed · verification needs attention",
                "Run `letsinfer update check` for verified details.",
            )
        return
    for line in update_available_lines(values, terminal):
        terminal.stream.write(line + "\n")
    terminal.stream.write("\n")
    terminal.stream.flush()


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def node_status(
    payload: Mapping[str, Any],
    *,
    stream: TextIO | None = None,
    environ: Mapping[str, str] | None = None,
) -> None:
    """Render complete node and model health from one status snapshot."""
    target = sys.stdout if stream is None else stream
    terminal = Terminal(target, environ=environ)
    identity = _mapping(payload.get("identity"))
    services = _mapping(payload.get("services"))
    models = payload.get("models")
    model_rows = [item for item in models if isinstance(item, Mapping)] \
        if isinstance(models, list) else []
    nodes = payload.get("nodes")
    node_rows = [item for item in nodes if isinstance(item, Mapping)] \
        if isinstance(nodes, list) else []
    links = payload.get("links")
    link_rows = [item for item in links if isinstance(item, Mapping)] \
        if isinstance(links, list) else []
    role = str(identity.get("role") or "node")
    node_ready = services.get("node_active") == "active"
    gateway_expected = role == "main"
    gateway_ready = (
        services.get("gateway_active") == "active"
        and services.get("gateway_health") is True
        and services.get("gateway_auth_required") is True
        and services.get("gateway_authenticated") is True
    )
    ready = node_ready and (gateway_ready if gateway_expected else True)

    target.write(f"{terminal.logo()}\n\n")
    updates = payload.get("updates")
    update_lines = (
        update_available_lines(updates, terminal)
        if isinstance(updates, list)
        else []
    )
    if update_lines:
        target.write("\n".join(update_lines) + "\n\n")
    state_color = GREEN if ready else YELLOW
    state_mark = "●" if terminal.unicode else "*"
    state = "ONLINE" if ready else "ATTENTION"
    display_name = terminal.clip(
        str(identity.get("display_name") or "Let's Infer node"),
        max(1, terminal.width - len(state) - 5),
    )
    target.write(
        f"{terminal.paint(state_mark, BOLD, state_color)} "
        f"{terminal.paint(state, BOLD, state_color)}  "
        f"{terminal.paint(display_name, BOLD)}\n"
    )
    detail = terminal.clip(
        f"{role} · {identity.get('machine_id') or 'local machine'}",
        max(1, terminal.width - 2),
    )
    target.write(f"  {terminal.paint(detail, DIM)}\n\n")

    def row(label: str, ok: bool, state_text: str, detail_text: str) -> None:
        color = GREEN if ok else RED
        label_text = terminal.clip(label.upper(), 10).ljust(10)
        state_value = terminal.clip(state_text, 14).ljust(14)
        detail_value = terminal.clip(detail_text, terminal.width - 26)
        target.write(
            f"  {terminal.paint(label_text, DIM)}"
            f"{terminal.paint(state_value, BOLD, color)}"
            f"{terminal.paint(detail_value, DIM)}\n"
        )

    row("Node", node_ready, "Active" if node_ready else "Unavailable", role)
    if node_rows:
        paused = sum(item.get("state") == "paused" for item in node_rows)
        row(
            "Topology",
            all(item.get("state") in {"active", "paused"} for item in node_rows),
            f"{len(node_rows)} node(s)",
            f"{paused} paused" if paused else "all active",
        )
    if link_rows:
        verified = sum(item.get("verified") is True for item in link_rows)
        row(
            "Links",
            verified == len(link_rows),
            f"{verified}/{len(link_rows)} verified",
            "background evidence",
        )
    if gateway_expected:
        row(
            "API",
            gateway_ready,
            "Ready" if gateway_ready else "Unavailable",
            str(payload.get("endpoint") or "LAN HTTP · API key"),
        )
    if model_rows:
        for model in model_rows:
            model_state = str(model.get("state") or "unknown")
            replicas = model.get("replicas")
            detail_text = str(model.get("model") or "unknown model")
            if isinstance(replicas, int):
                detail_text += f" · {replicas} replica(s)"
            row(
                "Model",
                model_state == "running",
                model_state.title(),
                detail_text,
            )
    else:
        row("Runtime", True, "Not installed", "use `letsinfer model install <model>`")
    target.flush()


class Spinner:
    """A delayed TTY spinner which always restores a clean terminal line."""

    _UNICODE_FRAMES = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")
    _ASCII_FRAMES = ("|", "/", "-", "\\")

    def __init__(
        self,
        terminal: Terminal,
        message: str,
        *,
        done: str | None = None,
        section: str | None = None,
        delay: float = 0.18,
        interval: float = 0.08,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.terminal = terminal
        self.message = message
        self.done = done
        self.section = section
        self.delay = max(0.0, delay)
        self.interval = max(0.01, interval)
        self._clock = clock
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._started_at = 0.0
        self._rendered = False

    @property
    def enabled(self) -> bool:
        return self.terminal.interactive

    def __enter__(self) -> Spinner:
        if not self.enabled:
            return self
        self._started_at = self._clock()
        if self.section is not None:
            self.terminal.stream.write(
                f"{self.terminal.logo(_section(self.section))}\n"
                f"   {self.terminal.paint(self.message, DIM)}\n\n"
            )
            self.terminal.stream.flush()
        self._thread = threading.Thread(
            target=self._animate,
            name="letsinfer-cli-spinner",
            daemon=True,
        )
        self._thread.start()
        return self

    def _animate(self) -> None:
        if self._stop.wait(self.delay):
            return
        frames = self._UNICODE_FRAMES if self.terminal.unicode else self._ASCII_FRAMES
        frame_index = 0
        while not self._stop.is_set():
            elapsed = self._clock() - self._started_at
            frame = self.terminal.paint(frames[frame_index % len(frames)], BLUE)
            suffix = self.terminal.paint(f"{elapsed:0.1f}s", DIM)
            try:
                self.terminal.stream.write(
                    f"{CLEAR_LINE}{frame} {self.message}  {suffix}"
                )
                self.terminal.stream.flush()
                self._rendered = True
            except (BrokenPipeError, OSError, ValueError):
                return
            frame_index += 1
            if self._stop.wait(self.interval):
                return

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        self.before_output()
        if not self.enabled:
            return False
        if exc_type is None and self.done is not None:
            self.terminal.success(self.done)
        return False

    def before_output(self) -> None:
        """Stop animation before a command writes its durable result."""
        if not self.enabled or self._stop.is_set():
            return
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=max(1.0, self.interval * 4))
        if self._rendered:
            try:
                self.terminal.stream.write(CLEAR_LINE)
                self.terminal.stream.flush()
            except (BrokenPipeError, OSError, ValueError):
                return


class StepProgress:
    """One bounded TTY owner for truthful multi-stage operations."""

    _UNICODE_FRAMES = Spinner._UNICODE_FRAMES
    _ASCII_FRAMES = Spinner._ASCII_FRAMES

    def __init__(
        self,
        terminal: Terminal,
        steps: Iterable[str],
        *,
        section: str,
        show_header: bool = True,
        interval: float = 0.08,
    ) -> None:
        self.terminal = terminal
        self.steps = tuple(steps)
        if not self.steps:
            raise ValueError("step progress requires at least one step")
        self.section = section
        self.show_header = show_header
        self.interval = max(0.01, interval)
        self.current = 0
        self.failed = False
        self._frame = 0
        self._rendered = False
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None

    @property
    def enabled(self) -> bool:
        return self.terminal.interactive

    def __enter__(self) -> StepProgress:
        if not self.enabled:
            return self
        if self.show_header:
            self.terminal.stream.write(
                f"{self.terminal.logo(_section(self.section))}\n\n"
            )
        with self._lock:
            self._render()
        self._thread = threading.Thread(
            target=self._animate,
            name="letsinfer-cli-steps",
            daemon=True,
        )
        self._thread.start()
        return self

    def _row(self, index: int, frame: str) -> str:
        label = self.terminal.clip(self.steps[index], max(1, self.terminal.width - 5))
        if index < self.current:
            mark = "✓" if self.terminal.unicode else "+"
            return f"{self.terminal.paint(mark, BOLD, GREEN)}  {label}"
        if index == self.current and self.failed:
            mark = "✗" if self.terminal.unicode else "x"
            return (
                f"{self.terminal.paint(mark, BOLD, RED)}  {label}  "
                f"{self.terminal.paint('Failed', BOLD, RED)}"
            )
        if index == self.current and self.current < len(self.steps):
            return f"{self.terminal.paint(frame, BLUE)}  {self.terminal.paint(label, BOLD)}"
        mark = "○" if self.terminal.unicode else "o"
        return f"{self.terminal.paint(mark, DIM)}  {self.terminal.paint(label, DIM)}"

    def _render(self) -> None:
        frames = self._UNICODE_FRAMES if self.terminal.unicode else self._ASCII_FRAMES
        frame = frames[self._frame % len(frames)]
        if self._rendered:
            self.terminal.stream.write(f"\033[{len(self.steps)}A")
        for index in range(len(self.steps)):
            self.terminal.stream.write(f"{CLEAR_LINE}{self._row(index, frame)}\n")
        self.terminal.stream.flush()
        self._rendered = True

    def _animate(self) -> None:
        while not self._stop.wait(self.interval):
            with self._lock:
                if self.failed or self.current >= len(self.steps):
                    return
                self._frame += 1
                try:
                    self._render()
                except (BrokenPipeError, OSError, ValueError):
                    return

    def advance(self) -> None:
        if self.current >= len(self.steps):
            raise RuntimeError("step progress is already complete")
        self.current += 1
        if self.enabled:
            with self._lock:
                self._frame = 0
                self._render()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=max(1.0, self.interval * 4))
        if self.enabled:
            with self._lock:
                if exc_type is not None:
                    self.failed = True
                self._render()
            self.terminal.stream.write("\n")
            self.terminal.stream.flush()
        return False


class _GuardedWriter:
    def __init__(self, stream: TextIO, spinner: Spinner) -> None:
        self._stream = stream
        self._spinner = spinner

    def write(self, value: str) -> int:
        self._spinner.before_output()
        return self._stream.write(value)

    def writelines(self, values: Iterable[str]) -> None:
        self._spinner.before_output()
        self._stream.writelines(values)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._stream, name)


@contextlib.contextmanager
def protect_stdout(spinner: Spinner) -> Iterator[None]:
    """Clear an active spinner before ordinary command output begins."""
    if not spinner.enabled:
        yield
        return
    previous = getattr(_activity, "spinner", None)
    _activity.spinner = spinner
    try:
        with contextlib.redirect_stdout(_GuardedWriter(sys.stdout, spinner)):
            yield
    finally:
        if previous is None:
            del _activity.spinner
        else:
            _activity.spinner = previous


def before_external_output() -> None:
    """Clear the current activity before a child process inherits the terminal."""
    spinner = getattr(_activity, "spinner", None)
    if isinstance(spinner, Spinner):
        spinner.before_output()


class HelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Raw formatter used beneath the terminal-aware parser presentation."""

    _width_key: tuple[object, ...] | None = None
    _cached_width = 78

    def __init__(self, *args: object, **kwargs: object) -> None:
        stream = sys.stdout
        key = (
            id(stream),
            _isatty(stream),
            os.environ.get("COLUMNS", ""),
            os.environ.get("TERM", ""),
        )
        if key != type(self)._width_key:
            # Argparse otherwise calls ``shutil.get_terminal_size`` for every
            # formatter it creates—hundreds of syscalls for this command tree.
            # One capability snapshot preserves responsive TTY help without
            # charging that cost per subparser/action.
            type(self)._cached_width = max(20, Terminal(stream).width - 2)
            type(self)._width_key = key
        kwargs.setdefault("width", type(self)._cached_width)
        super().__init__(*args, **kwargs)


class ArgumentParser(argparse.ArgumentParser):
    """Parser which propagates the branded formatter to every subcommand."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        kwargs.setdefault("formatter_class", HelpFormatter)
        super().__init__(*args, **kwargs)

    def format_help(self) -> str:
        value = super().format_help()
        terminal = Terminal(sys.stdout)
        has_subcommands = any(
            isinstance(action, argparse._SubParsersAction)
            for action in self._actions
        )
        command = self.prog.removeprefix("letsinfer ").strip()
        title = (
            command.replace("-", " ").title()
            if command and command != "letsinfer"
            else "Commands"
        )
        banner = "\n".join(terminal.command_header(title)) + "\n\n"
        replacements = {
            "usage:": terminal.paint("Usage:", BOLD, CYAN),
            "positional arguments:": terminal.paint(
                "Commands:" if has_subcommands else "Arguments:", BOLD, CYAN
            ),
            "options:": terminal.paint("Options:", BOLD, CYAN),
            "optional arguments:": terminal.paint("Options:", BOLD, CYAN),
        }
        for source, replacement in replacements.items():
            value = value.replace(source, replacement)
        return banner + value

    def error(self, message: str) -> None:
        terminal = Terminal(sys.stderr)
        if not terminal.interactive:
            super().error(message)
        command = self.prog.removeprefix("letsinfer ").strip()
        title = (
            command.replace("-", " ").title()
            if command and command != "letsinfer"
            else "Command"
        )
        usage = super().format_usage().replace(
            "usage:", terminal.paint("Usage:", BOLD, CYAN), 1
        )
        required = message.startswith("the following arguments are required:")
        sys.stderr.write("\n".join(terminal.command_header(title)) + f"\n\n{usage}")
        if not required:
            detail = "\n".join(
                f"   {terminal.paint(line, DIM)}"
                for line in terminal.wrap(message, terminal.width - 3)
            )
            sys.stderr.write(f"\n{detail}\n")
        sys.stderr.flush()
        raise SystemExit(2)


def progress(
    message: str,
    *,
    done: str | None = None,
    section: str | None = None,
    stream: TextIO | None = None,
    environ: Mapping[str, str] | None = None,
    enabled: bool = True,
) -> Spinner:
    terminal = Terminal(stream, environ=environ)
    if not enabled:
        terminal.interactive = False
        terminal.color = False
        terminal.unicode = False
    return Spinner(terminal, message, done=done, section=section)


def fatal(
    message: str,
    *,
    stream: TextIO | None = None,
    section: str | None = None,
) -> None:
    """Write the existing FATAL contract, styling only its TTY label."""
    target = sys.stderr if stream is None else stream
    terminal = Terminal(target)
    if terminal.interactive:
        if section is not None:
            target.write(f"{terminal.logo(_section(section))}\n\n")
        mark = "✗" if terminal.unicode else "ERROR"
        target.write(
            f"{terminal.paint(mark, BOLD, RED)}  "
            f"{terminal.paint('FAILED', BOLD, RED)}\n"
        )
        for line in terminal.wrap(message, terminal.width - 3):
            target.write(f"   {terminal.paint(line, DIM)}\n")
    else:
        target.write(f"FATAL: {message}\n")
    target.flush()


def runtime_status(
    payload: Mapping[str, Any],
    *,
    stream: TextIO | None = None,
    environ: Mapping[str, str] | None = None,
) -> None:
    """Render one preview-derived status snapshot."""
    from .status_ui import dashboard_lines

    target = sys.stdout if stream is None else stream
    terminal = Terminal(target, environ=environ)
    target.write("\n".join(dashboard_lines(payload, terminal)) + "\n")
    target.flush()


def live_runtime_status(snapshot: Callable[[], Mapping[str, Any]]) -> int:
    """Refresh the interactive dashboard until the user presses Ctrl-C."""
    from .status_ui import dashboard_lines

    terminal = Terminal(sys.stdout)
    history: dict[str, list[float]] = {
        "gpu": [],
        "memory": [],
        "cpu": [],
        "nvme": [],
        "power": [],
        "network": [],
        "gpu_temp": [],
        "cpu_temp": [],
        "nvme_temp": [],
    }
    first = True
    alternate_screen = False
    last_telemetry: dict[str, Any] | None = None
    last_telemetry_at: float | None = None
    last_history_sequence: int | None = None
    next_refresh = time.monotonic()

    def wait_for_refresh() -> None:
        nonlocal next_refresh
        next_refresh += LIVE_STATUS_REFRESH_SECONDS
        now = time.monotonic()
        if next_refresh <= now:
            next_refresh = now + LIVE_STATUS_REFRESH_SECONDS
        time.sleep(next_refresh - now)

    try:
        while True:
            payload = dict(snapshot())
            if "service" not in payload:
                prefix = "\033[?1049h\033[?25l\033[H" if first else "\033[H"
                alternate_screen = True
                sys.stdout.write(prefix)
                node_status(payload)
                sys.stdout.write("\033[J")
                sys.stdout.flush()
                first = False
                wait_for_refresh()
                continue
            now = time.monotonic()
            current_telemetry = payload.get("telemetry")
            telemetry = (
                dict(current_telemetry)
                if isinstance(current_telemetry, Mapping)
                else {}
            )
            telemetry.pop("display_state", None)
            telemetry.pop("display_age_seconds", None)
            current_sample_fresh = (
                isinstance(current_telemetry, Mapping)
                and current_telemetry.get("fresh") is not False
            )
            if current_sample_fresh:
                last_telemetry = dict(telemetry)
                last_telemetry_at = now
            elif (
                last_telemetry is not None
                and last_telemetry_at is not None
                and now - last_telemetry_at <= LIVE_STATUS_TELEMETRY_GRACE_SECONDS
            ):
                # Keep current site-wide counters, but retain the last verified
                # local sample while that member's stream reconnects.
                for field in (
                    "sample_member_id",
                    "sample_sequence",
                    "sample_unix_ms",
                    "system",
                    "workload",
                ):
                    if field in last_telemetry:
                        telemetry[field] = last_telemetry[field]
                telemetry["display_state"] = "reconnecting"
                telemetry["display_age_seconds"] = max(0.0, now - last_telemetry_at)
            else:
                telemetry["display_state"] = "unavailable"
            payload["telemetry"] = telemetry
            system = _mapping(telemetry.get("system"))
            sample_sequence = telemetry.get("sample_sequence")
            sequence = (
                sample_sequence
                if isinstance(sample_sequence, int)
                and not isinstance(sample_sequence, bool)
                else None
            )
            record_history = (
                telemetry.get("display_state") != "reconnecting"
                and (sequence is None or sequence != last_history_sequence)
            )
            if record_history:
                for name, fields, divisor in (
                    ("gpu", ("gpu_percent",), 1.0),
                    ("memory", ("memory_percent",), 1.0),
                    ("cpu", ("cpu_percent",), 1.0),
                    ("nvme", ("disk_percent",), 1.0),
                    ("power", ("power_deci_w",), 10.0),
                    ("network", ("network_rx_kib_s", "network_tx_kib_s"), 1.0),
                    ("gpu_temp", ("gpu_temp_deci_c",), 10.0),
                    ("cpu_temp", ("system_temp_deci_c",), 10.0),
                    ("nvme_temp", ("nvme_temp_deci_c",), 10.0),
                ):
                    values = [system.get(field) for field in fields]
                    if all(
                        isinstance(value, (int, float))
                        and not isinstance(value, bool)
                        and float(value) >= 0
                        for value in values
                    ):
                        history[name].append(
                            sum(float(value) for value in values) / divisor
                        )
                        del history[name][:-300]
                if sequence is not None:
                    last_history_sequence = sequence
            lines = dashboard_lines(payload, terminal, session_history=history)
            prefix = "\033[?1049h\033[?25l\033[H" if first else "\033[H"
            alternate_screen = True
            sys.stdout.write(prefix + "\n".join(lines) + "\n\033[J")
            sys.stdout.flush()
            first = False
            wait_for_refresh()
    except KeyboardInterrupt:
        return 0
    finally:
        if alternate_screen:
            sys.stdout.write("\033[?25h\033[?1049l\n")
            sys.stdout.flush()
