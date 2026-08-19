#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Small, dependency-free terminal presentation primitives for Let's Infer."""

from __future__ import annotations

import argparse
import contextlib
import os
import sys
import threading
import time
from types import TracebackType
from typing import Any, Callable, Iterable, Iterator, Mapping, TextIO


RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
CLEAR_LINE = "\r\033[2K"
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
        if len(value) <= width:
            return value
        suffix = "…" if self.unicode else "..."
        if width <= len(suffix):
            return suffix[:width]
        return value[: width - len(suffix)].rstrip() + suffix

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


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _mib(value: object) -> str:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        return "unavailable"
    return f"{value / (1024 * 1024):.1f} MiB"


def _context(value: object) -> str:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        return "unknown context"
    if value >= 1_000_000:
        return f"{value / 1_000_000:.1f}M context"
    if value >= 1_000:
        return f"{value / 1_000:.0f}K context"
    return f"{value} context"


def runtime_status(
    payload: Mapping[str, Any],
    *,
    stream: TextIO | None = None,
    environ: Mapping[str, str] | None = None,
) -> None:
    """Render one compact interactive runtime-health card."""
    target = sys.stdout if stream is None else stream
    terminal = Terminal(target, environ=environ)
    service = _mapping(payload.get("service"))
    container = _mapping(payload.get("container"))
    protection = _mapping(payload.get("protection"))
    capacity = _mapping(container.get("capacity"))

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
        and service.get("gateway_model_identity") is True
    )
    safety_ready = (
        protection.get("armed") is True
        and protection.get("trip_latched") is False
    )
    service_states = (
        service.get("active") == "active",
        service.get("engine_active") == "active",
        service.get("gateway_active") == "active",
        service.get("site_active") == "active",
        service.get("recovery_timer_active") == "active",
    )
    services_ready = sum(service_states)
    ready = engine_ready and api_ready and safety_ready and services_ready == 5

    model = str(container.get("model") or "No model")
    engine = str(container.get("engine") or "unknown")
    engine_name = {
        "dwarfstar": "DwarfStar",
        "llama.cpp": "llama.cpp",
        "sglang": "SGLang",
        "vllm": "vLLM",
    }.get(engine, engine)
    target_name = str(container.get("target") or "unknown target")
    version = str(container.get("runtime_version") or "unknown version")

    header = terminal.paint("LET'S INFER", BOLD)
    target.write(
        f"{terminal.paint(terminal.mark, BOLD, YELLOW)}  {header}\n\n"
    )
    state_color = GREEN if ready else YELLOW
    state_mark = "●" if terminal.unicode else "*"
    state = "ONLINE" if ready else "ATTENTION"
    state_prefix_width = len(state_mark) + 1 + len(state) + 2
    model = terminal.clip(model, terminal.width - state_prefix_width)
    target.write(
        f"{terminal.paint(state_mark, BOLD, state_color)} "
        f"{terminal.paint(state, BOLD, state_color)}  "
        f"{terminal.paint(model, BOLD)}\n"
    )
    runtime_identity = terminal.clip(
        f"{engine_name} · {target_name} · {version}",
        terminal.width - 2,
    )
    target.write(
        f"  {terminal.paint(runtime_identity, DIM)}\n\n"
    )

    def row(label: str, ok: bool, state_text: str, detail: str) -> None:
        color = GREEN if ok else RED
        label_text = terminal.clip(label.upper(), 10).ljust(10)
        state_value = terminal.clip(state_text, 12).ljust(12)
        detail = terminal.clip(detail, terminal.width - 24)
        target.write(
            f"  {terminal.paint(label_text, DIM)}"
            f"{terminal.paint(state_value, BOLD, color)}"
            f"{terminal.paint(detail, DIM)}\n"
        )

    endpoint = str(service.get("gateway_endpoint") or "LAN HTTP · API key")
    row("API", api_ready, "Ready" if api_ready else "Unavailable", endpoint)
    context = _context(capacity.get("max_context_tokens"))
    active = capacity.get("max_active_requests")
    active_detail = f" · {active} active" if isinstance(active, int) else ""
    row(
        "Engine",
        engine_ready,
        "Healthy" if engine_ready else str(container.get("state") or "Unknown").title(),
        f"{context}{active_detail}",
    )
    row(
        "Safety",
        safety_ready,
        "Armed" if safety_ready else "Blocked",
        "no trip · recovery ready"
        if safety_ready
        else "protection needs attention",
    )
    row(
        "Services",
        services_ready == 5,
        f"{services_ready}/5",
        "all five units active"
        if services_ready == 5
        else f"{5 - services_ready} unit(s) need attention",
    )
    memory = _mib(service.get("memory_current_bytes"))
    memory_limit = _mib(service.get("memory_limit_bytes"))
    within_limit = service.get("within_memory_limit") is True
    row(
        "Watchdog",
        within_limit,
        "Normal" if within_limit else "High",
        f"{memory} / {memory_limit}",
    )
    target.flush()


def site_status(
    payload: Mapping[str, Any],
    *,
    stream: TextIO | None = None,
    environ: Mapping[str, str] | None = None,
) -> None:
    """Render a fresh site's control-plane health before a runtime is installed."""
    target = sys.stdout if stream is None else stream
    terminal = Terminal(target, environ=environ)
    identity = _mapping(payload.get("identity"))
    services = _mapping(payload.get("services"))
    role = str(identity.get("role") or "site")
    site_ready = services.get("site_active") == "active"
    gateway_expected = role == "coordinator"
    gateway_ready = (
        services.get("gateway_active") == "active"
        and services.get("gateway_health") is True
        and services.get("gateway_auth_required") is True
        and services.get("gateway_authenticated") is True
    )
    ready = site_ready and (gateway_ready if gateway_expected else True)

    header = terminal.paint("LET'S INFER", BOLD)
    target.write(
        f"{terminal.paint(terminal.mark, BOLD, YELLOW)}  "
        f"{header}\n\n"
    )
    state_color = GREEN if ready else YELLOW
    state_mark = "●" if terminal.unicode else "*"
    state = "ONLINE" if ready else "ATTENTION"
    display_name = terminal.clip(
        str(identity.get("display_name") or "Let's Infer site"),
        max(1, terminal.width - len(state) - 5),
    )
    target.write(
        f"{terminal.paint(state_mark, BOLD, state_color)} "
        f"{terminal.paint(state, BOLD, state_color)}  "
        f"{terminal.paint(display_name, BOLD)}\n"
    )
    detail = terminal.clip(
        f"{role} · {identity.get('member_id') or 'local member'}",
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

    row("Site", site_ready, "Active" if site_ready else "Unavailable", role)
    if gateway_expected:
        row(
            "API",
            gateway_ready,
            "Ready" if gateway_ready else "Unavailable",
            str(payload.get("endpoint") or "LAN HTTP · API key"),
        )
    row("Runtime", True, "Not installed", "use `letsinfer install <model>`")
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
        delay: float = 0.18,
        interval: float = 0.08,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.terminal = terminal
        self.message = message
        self.done = done
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
            frame = self.terminal.paint(frames[frame_index % len(frames)], CYAN)
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
        title = "LET'S INFER"
        if command and command != "letsinfer":
            title += f"  /  {command}"
        banner = (
            f"{terminal.paint(terminal.mark, BOLD, YELLOW)}  "
            f"{terminal.paint(title, BOLD)}\n\n"
        )
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


def progress(
    message: str,
    *,
    done: str | None = None,
    stream: TextIO | None = None,
    environ: Mapping[str, str] | None = None,
    enabled: bool = True,
) -> Spinner:
    terminal = Terminal(stream, environ=environ)
    if not enabled:
        terminal.interactive = False
        terminal.color = False
        terminal.unicode = False
    return Spinner(terminal, message, done=done)


def fatal(message: str, *, stream: TextIO | None = None) -> None:
    """Write the existing FATAL contract, styling only its TTY label."""
    target = sys.stderr if stream is None else stream
    terminal = Terminal(target)
    label = terminal.paint("FATAL:", BOLD, RED)
    target.write(f"{label} {message}\n")
    target.flush()
