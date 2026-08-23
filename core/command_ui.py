#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Composable human-command presentation using the status design language.

This module deliberately depends only on :mod:`core.ui`.  The live status
dashboard owns its layout; ordinary commands use the primitives here instead
of reaching into status_ui's private helpers.

There are two output contracts:

* an interactive terminal gets the product lockup, semantic colour, bounded
  panels, and width-aware layouts;
* redirected output remains plain, ANSI-free, and untruncated so it stays safe
  to capture or pipe.

Machine JSON remains the command handler's responsibility.  ``object()`` is a
human renderer: on a terminal it presents mappings as records, while on a
redirected stream it emits ordinary JSON without terminal decoration.
"""

from __future__ import annotations

import builtins
import getpass
import json
import re
import sys
import textwrap
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Iterable, Mapping, Sequence, TextIO

from . import ui


_ANSI = re.compile(r"\033\[[0-9;]*m")
_PANEL_MAX_WIDTH = 76
_PANEL_MIN_WIDTH = 32
_RECORD_LABEL_WIDTH = 13
_RECORD_VALUE_WIDTH = 14


class Semantic(str, Enum):
    """Stable semantic states shared by command result surfaces."""

    INFO = "info"
    WORKING = "working"
    SUCCESS = "success"
    WARNING = "warning"
    PRESSURE = "pressure"
    ERROR = "error"
    MUTED = "muted"


@dataclass(frozen=True)
class _SemanticStyle:
    unicode_mark: str
    ascii_mark: str
    plain_label: str
    color: str


_SEMANTICS: Mapping[Semantic, _SemanticStyle] = {
    Semantic.INFO: _SemanticStyle("•", "*", "INFO", ui.BLUE),
    Semantic.WORKING: _SemanticStyle("•", "*", "WORKING", ui.BLUE),
    Semantic.SUCCESS: _SemanticStyle("✓", "OK", "OK", ui.GREEN),
    Semantic.WARNING: _SemanticStyle("!", "!", "WARNING", ui.YELLOW),
    Semantic.PRESSURE: _SemanticStyle("!", "!", "PRESSURE", ui.ORANGE),
    Semantic.ERROR: _SemanticStyle("✗", "x", "ERROR", ui.RED),
    Semantic.MUTED: _SemanticStyle("○", "-", "", ui.DIM),
}


@dataclass(frozen=True)
class TableColumn:
    """One column in a width-aware table.

    ``key`` addresses mapping rows.  Sequence rows use the column's ordinal
    position.  Widths are display columns, not bytes.  ``formatter`` receives
    the raw cell value and the complete row.
    """

    key: str
    heading: str
    min_width: int = 3
    max_width: int | None = None
    weight: int = 1
    align: str = "left"
    formatter: Callable[[object, object], str] | None = None

    def __post_init__(self) -> None:
        if self.min_width < 1:
            raise ValueError("table column min_width must be positive")
        if self.max_width is not None and self.max_width < self.min_width:
            raise ValueError("table column max_width cannot be below min_width")
        if self.weight < 1:
            raise ValueError("table column weight must be positive")
        if self.align not in {"left", "right"}:
            raise ValueError("table column align must be 'left' or 'right'")


@dataclass(frozen=True)
class RecordRow:
    """A status-language label/value/detail row."""

    label: str
    value: object
    detail: object = ""
    semantic: Semantic | str | None = None
    value_bold: bool = True


class PromptUnavailable(RuntimeError):
    """Raised when a caller requires a TTY but none is available."""


def _plain_width(value: str) -> int:
    return len(_ANSI.sub("", value))


def _wrap_plain(
    value: object,
    width: int,
    *,
    initial_indent: str = "",
    subsequent_indent: str | None = None,
    break_long_words: bool = True,
) -> list[str]:
    """Wrap prose without truncating words or explicit input lines."""

    width = max(1, width)
    subsequent = initial_indent if subsequent_indent is None else subsequent_indent
    source_lines = str(value).splitlines() or [""]
    rendered: list[str] = []
    for source in source_lines:
        if not source:
            rendered.append(initial_indent.rstrip())
            continue
        rendered.extend(
            textwrap.wrap(
                source,
                width=width,
                initial_indent=initial_indent,
                subsequent_indent=subsequent,
                expand_tabs=True,
                replace_whitespace=False,
                drop_whitespace=True,
                break_long_words=break_long_words,
                break_on_hyphens=False,
            )
            or [initial_indent.rstrip()]
        )
    return rendered


def _wrap_verbatim(value: object, width: int, *, indent: str = "") -> list[str]:
    """Split an opaque value at fixed columns without changing its bytes."""

    width = max(1, width)
    available = max(1, width - len(indent))
    source_lines = str(value).split("\n")
    rendered: list[str] = []
    for source in source_lines:
        # Keep carriage returns and other visible characters untouched.  The
        # only inserted bytes are display newlines and the requested indent.
        if not source:
            rendered.append(indent)
            continue
        rendered.extend(
            indent + source[offset : offset + available]
            for offset in range(0, len(source), available)
        )
    return rendered


def _one_line(value: object) -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    text = str(value)
    return " ".join(text.splitlines()) if "\n" in text or "\r" in text else text


def _semantic(value: Semantic | str | None) -> Semantic | None:
    if value is None or isinstance(value, Semantic):
        return value
    try:
        return Semantic(value)
    except ValueError as error:
        choices = ", ".join(item.value for item in Semantic)
        raise ValueError(f"unknown semantic {value!r}; expected one of {choices}") from error


def _cell(row: object, column: TableColumn, index: int) -> object:
    if isinstance(row, Mapping):
        return row.get(column.key)
    if isinstance(row, Sequence) and not isinstance(row, (str, bytes, bytearray)):
        return row[index] if index < len(row) else None
    return getattr(row, column.key, None)


class PromptFacade:
    """Consistent text, secret, confirmation, and choice prompts.

    Prompt text is written to ``stream`` and answers are read through injected
    callables, which keeps command handlers testable.  Non-TTY prompts remain
    plain by default.  Set ``require_tty=True`` when prompting would be unsafe
    in an automated invocation.
    """

    def __init__(
        self,
        terminal: ui.Terminal,
        *,
        input_fn: Callable[[], str] | None = None,
        secret_fn: Callable[..., str] | None = None,
    ) -> None:
        self.terminal = terminal
        self.stream = terminal.stream
        self._input = builtins.input if input_fn is None else input_fn
        self._input_echoes = input_fn is None
        self._secret = getpass.getpass if secret_fn is None else secret_fn
        self._secret_accepts_stream = secret_fn is None

    def _read_line(self) -> str:
        answer = self._input()
        if not self._input_echoes:
            self.stream.write("\n")
            self.stream.flush()
        return answer

    def _ensure_available(self, require_tty: bool) -> None:
        if require_tty and not self.terminal.interactive:
            raise PromptUnavailable("an interactive terminal is required")

    def _prefix(self) -> str:
        return self.terminal.paint("?", ui.BOLD, ui.YELLOW)

    def _write_prompt(self, message: str, hint: str = "") -> None:
        # A prompt is an interactive surface, not progress output.  Hand the
        # terminal over cleanly before asking for input.
        ui.before_external_output()
        if not self.terminal.interactive:
            suffix = f" {hint}" if hint else ""
            self.stream.write(f"{message}{suffix} ")
            self.stream.flush()
            return

        width = max(1, self.terminal.width)
        prefix = "? " if width >= 2 else ""
        continuation = " " * len(prefix)
        plain_lines = _wrap_plain(
            message,
            width,
            initial_indent=prefix,
            subsequent_indent=continuation,
        )

        if hint:
            if len(plain_lines[-1]) + len(hint) + 1 <= width:
                plain_lines[-1] += f" {hint}"
                hint_first_line = len(plain_lines) - 1
                hint_start = len(plain_lines[-1]) - len(hint)
            else:
                hint_first_line = len(plain_lines)
                hint_lines = _wrap_plain(
                    hint,
                    width,
                    initial_indent=continuation,
                    subsequent_indent=continuation,
                )
                plain_lines.extend(hint_lines)
                hint_start = len(continuation)
        else:
            hint_first_line = -1
            hint_start = -1

        first_mark = self._prefix()
        for index, line in enumerate(plain_lines):
            if index == 0 and prefix:
                body = line[2:]
                if hint_first_line == 0:
                    split = max(0, hint_start - 2)
                    rendered = (
                        first_mark
                        + " "
                        + self.terminal.paint(body[:split], ui.BOLD)
                        + self.terminal.paint(body[split:], ui.DIM)
                    )
                else:
                    rendered = first_mark + " " + self.terminal.paint(body, ui.BOLD)
            elif index == hint_first_line:
                rendered = (
                    self.terminal.paint(line[:hint_start], ui.BOLD)
                    + self.terminal.paint(line[hint_start:], ui.DIM)
                )
            elif hint_first_line >= 0 and index > hint_first_line:
                rendered = self.terminal.paint(line, ui.DIM)
            else:
                rendered = self.terminal.paint(line, ui.BOLD)
            self.stream.write(rendered + (" " if index == len(plain_lines) - 1 else "\n"))
        self.stream.flush()

    def text(
        self,
        message: str,
        *,
        default: str | None = None,
        required: bool = False,
        require_tty: bool = False,
        validator: Callable[[str], bool | str] | None = None,
    ) -> str:
        """Read one line, optionally validating until a usable value arrives."""

        self._ensure_available(require_tty)
        hint = f"[{default}]" if default is not None else ""
        while True:
            self._write_prompt(message, hint)
            try:
                answer = self._read_line()
            except EOFError as error:
                if default is not None:
                    return default
                raise PromptUnavailable("no prompt input is available") from error
            answer = answer.strip()
            if not answer and default is not None:
                answer = default
            if not answer and required:
                self._validation_error("A value is required.")
                continue
            if validator is not None and answer:
                verdict = validator(answer)
                if verdict is not True:
                    self._validation_error(
                        verdict if isinstance(verdict, str) else "That value is not valid."
                    )
                    continue
            return answer

    def secret(
        self,
        message: str,
        *,
        required: bool = True,
        require_tty: bool = False,
    ) -> str:
        """Read a secret without echoing it."""

        self._ensure_available(require_tty)
        while True:
            self._write_prompt(message)
            try:
                if self._secret_accepts_stream:
                    answer = self._secret("", stream=self.stream)
                else:
                    answer = self._secret()
                    self.stream.write("\n")
                    self.stream.flush()
            except EOFError as error:
                raise PromptUnavailable("no prompt input is available") from error
            if answer or not required:
                return answer
            self._validation_error("A value is required.")

    def confirm(
        self,
        message: str,
        *,
        default: bool = False,
        require_tty: bool = False,
    ) -> bool:
        """Ask a yes/no question, returning ``default`` for an empty answer."""

        self._ensure_available(require_tty)
        hint = "[Y/n]" if default else "[y/N]"
        while True:
            self._write_prompt(message, hint)
            try:
                answer = self._read_line().strip().lower()
            except EOFError:
                return default
            if not answer:
                return default
            if answer in {"y", "yes"}:
                return True
            if answer in {"n", "no"}:
                return False
            self._validation_error("Enter yes or no.")

    def choose(
        self,
        message: str,
        choices: Sequence[str],
        *,
        default: str | None = None,
        require_tty: bool = False,
    ) -> str:
        """Choose one value by its name or one-based index."""

        if not choices:
            raise ValueError("choices cannot be empty")
        if default is not None and default not in choices:
            raise ValueError("default must be one of the choices")
        self._ensure_available(require_tty)
        for index, choice in enumerate(choices, 1):
            prefix = f"  {str(index).rjust(2)}  "
            if self.terminal.interactive:
                lines = _wrap_plain(
                    choice,
                    self.terminal.width,
                    initial_indent=prefix,
                    subsequent_indent=" " * len(prefix),
                )
                # Paint only the ordinal so the choice remains easy to scan.
                lines[0] = (
                    f"  {self.terminal.paint(str(index).rjust(2), ui.DIM)}  "
                    + lines[0][len(prefix) :]
                )
            else:
                lines = [f"{prefix}{choice}"]
            self.stream.write("\n".join(lines) + "\n")
        self.stream.flush()

        def validate(answer: str) -> bool | str:
            if answer in choices:
                return True
            if answer.isdecimal() and 1 <= int(answer) <= len(choices):
                return True
            return "Choose a listed name or number."

        answer = self.text(
            message,
            default=default,
            required=True,
            require_tty=require_tty,
            validator=validate,
        )
        return choices[int(answer) - 1] if answer.isdecimal() else answer

    def _validation_error(self, message: str) -> None:
        if self.terminal.interactive:
            mark = "!"
            prefix = f"{mark} "
            lines = _wrap_plain(
                message,
                self.terminal.width,
                initial_indent=prefix,
                subsequent_indent=" " * len(prefix),
            )
            lines[0] = (
                f"{self.terminal.paint(mark, ui.BOLD, ui.RED)} "
                + self.terminal.paint(lines[0][len(prefix) :], ui.RED)
            )
            for index in range(1, len(lines)):
                lines[index] = self.terminal.paint(lines[index], ui.RED)
            self.stream.write("\n".join(lines) + "\n")
        else:
            lines = str(message).splitlines() or [""]
            self.stream.write(f"ERROR: {lines[0]}\n")
            for line in lines[1:]:
                self.stream.write(f"       {line}\n")
        self.stream.flush()


class CommandUI:
    """One output owner for an ordinary human-facing command."""

    def __init__(
        self,
        stream: TextIO | None = None,
        *,
        environ: Mapping[str, str] | None = None,
        prompt_stream: TextIO | None = None,
        input_fn: Callable[[], str] | None = None,
        secret_fn: Callable[..., str] | None = None,
    ) -> None:
        self.stream = sys.stdout if stream is None else stream
        self.terminal = ui.Terminal(self.stream, environ=environ)
        prompt_target = (
            sys.stderr
            if prompt_stream is None and stream is None
            else self.stream
            if prompt_stream is None
            else prompt_stream
        )
        prompt_terminal = (
            self.terminal
            if prompt_target is self.stream
            else ui.Terminal(prompt_target, environ=environ)
        )
        self.prompt = PromptFacade(
            prompt_terminal,
            input_fn=input_fn,
            secret_fn=secret_fn,
        )
        self._header_rendered = False

    @property
    def interactive(self) -> bool:
        return self.terminal.interactive

    @property
    def content_width(self) -> int:
        if not self.interactive:
            return max(1, self.terminal.width)
        outer = min(max(1, self.terminal.width), _PANEL_MAX_WIDTH)
        return max(1, outer - 6)

    def _write(self, lines: Iterable[str], *, trailing_blank: bool = False) -> None:
        values = tuple(lines)
        if values:
            # A durable result takes terminal ownership from any generic
            # activity indicator before its first byte is written.  This also
            # covers stderr-owned records such as one-time secret metadata;
            # stdout protection alone cannot safely serialize those writes.
            ui.before_external_output()
            self.stream.write("\n".join(values) + "\n")
        if trailing_blank:
            self.stream.write("\n")
        self.stream.flush()

    def render_wrapped(
        self,
        value: object,
        *,
        indent: int = 0,
        subsequent_indent: int | None = None,
        semantic: Semantic | str | None = None,
        bold: bool = False,
        muted: bool = False,
    ) -> tuple[str, ...]:
        """Render complete prose, wrapping only on an interactive terminal.

        Explicit newlines are retained.  Redirected output is never width
        limited.  Use :meth:`render_verbatim` for opaque identifiers whose
        characters must not be whitespace-normalized.
        """

        if indent < 0 or (subsequent_indent is not None and subsequent_indent < 0):
            raise ValueError("indent cannot be negative")
        first_prefix = " " * indent
        rest_prefix = " " * (
            indent if subsequent_indent is None else subsequent_indent
        )
        if self.interactive:
            lines = _wrap_plain(
                _ANSI.sub("", str(value)),
                self.content_width,
                initial_indent=first_prefix,
                subsequent_indent=rest_prefix,
            )
        else:
            source = str(value).splitlines() or [""]
            lines = [
                (first_prefix if index == 0 else rest_prefix) + line
                for index, line in enumerate(source)
            ]

        meaning = _semantic(semantic)
        styles: list[str] = []
        if bold:
            styles.append(ui.BOLD)
        if meaning is not None:
            styles.append(_SEMANTICS[meaning].color)
        if muted:
            styles.append(ui.DIM)
        if self.interactive and styles:
            lines = [self.terminal.paint(line, *styles) for line in lines]
        return tuple(lines)

    def wrapped(
        self,
        value: object,
        *,
        indent: int = 0,
        subsequent_indent: int | None = None,
        semantic: Semantic | str | None = None,
        bold: bool = False,
        muted: bool = False,
    ) -> None:
        self._write(
            self.render_wrapped(
                value,
                indent=indent,
                subsequent_indent=subsequent_indent,
                semantic=semantic,
                bold=bold,
                muted=muted,
            )
        )

    def render_verbatim(
        self,
        value: object,
        *,
        label: str | None = None,
        indent: int = 0,
        copyable: bool = False,
    ) -> tuple[str, ...]:
        """Render an ID, digest, path, or command without truncation.

        The default wraps at fixed character boundaries so every character is
        visible within the command surface.  ``copyable=True`` emits the value
        unstyled and on its original lines; that is the sole primitive allowed
        to deliberately exceed terminal width, making one-drag copy/paste
        possible for long digests and commands.
        """

        if indent < 0:
            raise ValueError("indent cannot be negative")
        text = str(value)
        prefix = " " * indent
        if not self.interactive:
            source = text.split("\n")
            if label is None:
                return tuple(prefix + line for line in source)
            first, *rest = source
            return tuple(
                [f"{prefix}{label}\t{first}", *(prefix + line for line in rest)]
            )

        lines: list[str] = []
        if label is not None:
            lines.extend(self.render_wrapped(label, indent=indent, bold=True, muted=True))
        if copyable:
            lines.extend(prefix + line for line in text.split("\n"))
        else:
            lines.extend(_wrap_verbatim(text, self.content_width, indent=prefix))
        return tuple(lines)

    def verbatim(
        self,
        value: object,
        *,
        label: str | None = None,
        indent: int = 0,
        copyable: bool = False,
    ) -> None:
        self._write(
            self.render_verbatim(
                value,
                label=label,
                indent=indent,
                copyable=copyable,
            )
        )

    def render_header(
        self,
        title: str,
        *,
        state: str | None = None,
        semantic: Semantic | str = Semantic.INFO,
        detail: str | None = None,
    ) -> tuple[str, ...]:
        """Render a status-style title at left and product badge at right."""

        if not self.interactive:
            return ()
        meaning = _semantic(semantic) or Semantic.INFO
        style = _SEMANTICS[meaning]
        brand = self.terminal.logo()
        title_text = self.terminal.paint(title, ui.BOLD)
        if state:
            state_text = self.terminal.paint(state, ui.BOLD, style.color)
            left = f"{title_text}  {state_text}"
        else:
            left = title_text
        header_width = max(1, self.terminal.width)
        if _plain_width(left) + 2 + _plain_width(brand) > header_width:
            # If the complete title/state and exact badge do not both fit,
            # stack them.  Neither product identity nor command identity is
            # decorative enough to truncate.
            brand_padding = " " * max(0, header_width - _plain_width(brand))
            lines = [f"{brand_padding}{brand}"]
            lines.extend(self.render_wrapped(title, bold=True))
            if state:
                lines.extend(
                    self.render_wrapped(
                        state,
                        semantic=meaning,
                        bold=True,
                    )
                )
            if detail:
                lines.extend(
                    self.render_wrapped(
                        detail,
                        muted=True,
                    )
                )
            return tuple(lines)
        gap = " " * max(2, header_width - _plain_width(left) - _plain_width(brand))
        lines = [f"{left}{gap}{brand}"]
        if detail:
            lines.extend(
                self.render_wrapped(
                    detail,
                    muted=True,
                )
            )
        return tuple(lines)

    def header(
        self,
        title: str,
        *,
        state: str | None = None,
        semantic: Semantic | str = Semantic.INFO,
        detail: str | None = None,
    ) -> None:
        if self._header_rendered:
            return
        lines = self.render_header(
            title,
            state=state,
            semantic=semantic,
            detail=detail,
        )
        if lines:
            self._write(lines, trailing_blank=True)
            self._header_rendered = True

    def render_panel(
        self,
        lines: Iterable[str],
        *,
        title: str | None = None,
    ) -> tuple[str, ...]:
        """Bound content to one status-width panel.

        Redirected output receives the original unboxed lines without clipping.
        """

        values = [str(value) for value in lines]
        if title:
            title_line = (
                self.terminal.paint(title, ui.BOLD)
                if self.interactive
                else title
            )
            values = [title_line, "", *values]
        if not self.interactive:
            return tuple(values)

        available = max(1, self.terminal.width)
        if available < _PANEL_MIN_WIDTH:
            rendered: list[str] = []
            for value in values:
                rendered.extend(_wrap_plain(_ANSI.sub("", value), available))
            return tuple(rendered)
        outer_width = min(available, _PANEL_MAX_WIDTH)
        inner_width = outer_width - 6
        horizontal = "─" if self.terminal.unicode else "-"
        vertical = "│" if self.terminal.unicode else "|"
        corners = ("┌", "┐", "└", "┘") if self.terminal.unicode else ("+", "+", "+", "+")
        top_left, top_right, bottom_left, bottom_right = corners
        border = horizontal * (outer_width - 2)
        rendered = [self.terminal.paint(f"{top_left}{border}{top_right}", ui.DIM)]
        for value in values:
            if _plain_width(value) <= inner_width:
                wrapped = [value]
            else:
                # Clipping a panel line would silently hide paths, errors, and
                # security metadata.  Long styled rows become plain only on
                # their wrapped continuation, but never lose content.
                wrapped = _wrap_plain(_ANSI.sub("", value), inner_width)
            for segment in wrapped:
                padding = " " * max(0, inner_width - _plain_width(segment))
                rendered.append(
                    f"{self.terminal.paint(vertical, ui.DIM)}  {segment}{padding}  "
                    f"{self.terminal.paint(vertical, ui.DIM)}"
                )
        rendered.append(
            self.terminal.paint(f"{bottom_left}{border}{bottom_right}", ui.DIM)
        )
        return tuple(rendered)

    def panel(self, lines: Iterable[str], *, title: str | None = None) -> None:
        self._write(self.render_panel(lines, title=title))

    def render_result(
        self,
        message: str,
        *,
        semantic: Semantic | str = Semantic.INFO,
        detail: str | None = None,
        plain: str | None = None,
    ) -> str:
        """Render one truthful result, including wrapped continuation lines."""

        return "\n".join(
            self.render_result_lines(
                message,
                semantic=semantic,
                detail=detail,
                plain=plain,
            )
        )

    def render_result_lines(
        self,
        message: str,
        *,
        semantic: Semantic | str = Semantic.INFO,
        detail: str | None = None,
        plain: str | None = None,
    ) -> tuple[str, ...]:
        """Render a semantic result without truncating its message or detail."""

        meaning = _semantic(semantic) or Semantic.INFO
        style = _SEMANTICS[meaning]
        if not self.interactive:
            if plain is not None:
                return tuple(str(plain).splitlines() or [""])
            prefix = f"{style.plain_label}: " if style.plain_label else ""
            message_lines = str(message).splitlines() or [""]
            lines = [f"{prefix}{message_lines[0]}"]
            lines.extend(" " * len(prefix) + line for line in message_lines[1:])
            if detail:
                lines.extend(f"  {line}" for line in str(detail).splitlines())
            return tuple(lines)

        mark = style.unicode_mark if self.terminal.unicode else style.ascii_mark
        mark_text = self.terminal.paint(mark, ui.BOLD, style.color)
        prefix_width = _plain_width(mark) + 2
        message_lines = _wrap_plain(
            _ANSI.sub("", str(message)),
            self.content_width,
            initial_indent=" " * prefix_width,
            subsequent_indent=" " * prefix_width,
        )
        if not message_lines:
            message_lines = [" " * prefix_width]
        first = message_lines[0][prefix_width:]
        rendered = [
            f"{mark_text}  {self.terminal.paint(first, ui.BOLD, style.color)}"
        ]
        for line in message_lines[1:]:
            rendered.append(self.terminal.paint(line, ui.BOLD, style.color))
        if detail:
            rendered.extend(
                self.render_wrapped(
                    detail,
                    indent=prefix_width,
                    subsequent_indent=prefix_width,
                    muted=True,
                )
            )
        return tuple(rendered)

    def result(
        self,
        message: str,
        *,
        semantic: Semantic | str = Semantic.INFO,
        detail: str | None = None,
        plain: str | None = None,
    ) -> None:
        self._write(
            self.render_result_lines(
                message,
                semantic=semantic,
                detail=detail,
                plain=plain,
            )
        )

    def render_record_row(
        self,
        row: RecordRow,
        *,
        label_width: int = _RECORD_LABEL_WIDTH,
        value_width: int = _RECORD_VALUE_WIDTH,
        indent: int = 0,
    ) -> str:
        """Render one record, joining wrapped continuation lines with newlines."""

        return "\n".join(
            self.render_record_row_lines(
                row,
                label_width=label_width,
                value_width=value_width,
                indent=indent,
            )
        )

    def render_record_row_lines(
        self,
        row: RecordRow,
        *,
        label_width: int = _RECORD_LABEL_WIDTH,
        value_width: int = _RECORD_VALUE_WIDTH,
        indent: int = 0,
    ) -> tuple[str, ...]:
        """Render an aligned record row without truncating its detail."""

        label = _one_line(row.label)
        value = _one_line(row.value)
        detail = "" if row.detail is None or row.detail == "" else str(row.detail)
        meaning = _semantic(row.semantic)
        if not self.interactive:
            detail_lines = detail.splitlines() if detail else []
            suffix = f"\t{detail_lines[0]}" if detail_lines else ""
            lines = [f"{' ' * indent}{label}\t{value}{suffix}"]
            lines.extend(f"{' ' * indent}\t\t{line}" for line in detail_lines[1:])
            return tuple(lines)

        available = max(1, self.content_width - indent)
        if available < 32:
            label_lines = self.render_wrapped(
                label,
                indent=indent,
                subsequent_indent=indent,
                muted=True,
            )
            value_lines = self.render_verbatim(
                value,
                indent=indent + min(2, max(0, available - 1)),
            )
            if self.interactive and (row.value_bold or meaning is not None):
                styles = [ui.BOLD] if row.value_bold else []
                if meaning is not None:
                    styles.append(_SEMANTICS[meaning].color)
                value_lines = tuple(
                    self.terminal.paint(line, *styles) for line in value_lines
                )
            detail_lines = (
                self.render_wrapped(
                    detail,
                    indent=indent + min(2, max(0, available - 1)),
                    subsequent_indent=indent + min(2, max(0, available - 1)),
                    muted=True,
                )
                if detail
                else ()
            )
            return (*label_lines, *value_lines, *detail_lines)
        label_width = min(max(1, label_width), available)
        remaining = max(1, available - label_width)
        value_width = min(
            max(1, value_width if detail else remaining),
            remaining,
        )
        detail_width = max(0, available - label_width - value_width)
        label_text = self.terminal.paint(
            self.terminal.clip(label, label_width).ljust(label_width), ui.DIM
        )
        value_styles = [ui.BOLD] if row.value_bold else []
        if meaning is not None:
            value_styles.append(_SEMANTICS[meaning].color)
        value_lines = _wrap_verbatim(value, value_width)
        value_text = self.terminal.paint(value_lines[0].ljust(value_width), *value_styles)
        if not detail:
            first = f"{' ' * indent}{label_text}{value_text}".rstrip()
            continuation_prefix = " " * (indent + label_width)
            continuations = tuple(
                continuation_prefix
                + self.terminal.paint(line.ljust(value_width), *value_styles).rstrip()
                for line in value_lines[1:]
            )
            return (first, *continuations)
        if detail_width <= 0:
            first = f"{' ' * indent}{label_text}{value_text}".rstrip()
            value_continuations = tuple(
                " " * (indent + label_width)
                + self.terminal.paint(line.ljust(value_width), *value_styles).rstrip()
                for line in value_lines[1:]
            )
            continuation = self.render_wrapped(
                detail,
                indent=indent + 2,
                subsequent_indent=indent + 2,
                muted=True,
            )
            return (first, *value_continuations, *continuation)
        detail_lines = _wrap_plain(detail, detail_width)
        first_detail = self.terminal.paint(detail_lines[0], ui.DIM)
        first = f"{' ' * indent}{label_text}{value_text}{first_detail}".rstrip()
        value_continuation_prefix = " " * (indent + label_width)
        value_continuations = tuple(
            value_continuation_prefix
            + self.terminal.paint(line.ljust(value_width), *value_styles).rstrip()
            for line in value_lines[1:]
        )
        detail_continuation_prefix = " " * (indent + label_width + value_width)
        detail_continuations = tuple(
            detail_continuation_prefix + self.terminal.paint(line, ui.DIM)
            for line in detail_lines[1:]
        )
        return (first, *value_continuations, *detail_continuations)

    def render_records(
        self,
        rows: Iterable[RecordRow | Sequence[object]],
        *,
        label_width: int = _RECORD_LABEL_WIDTH,
        value_width: int = _RECORD_VALUE_WIDTH,
        indent: int = 0,
    ) -> tuple[str, ...]:
        normalized: list[RecordRow] = []
        for row in rows:
            if isinstance(row, RecordRow):
                normalized.append(row)
                continue
            values = tuple(row)
            if not 2 <= len(values) <= 4:
                raise ValueError("record rows need label, value, optional detail and semantic")
            normalized.append(
                RecordRow(
                    str(values[0]),
                    values[1],
                    values[2] if len(values) >= 3 else "",
                    values[3] if len(values) >= 4 else None,
                )
            )
        rendered: list[str] = []
        for row in normalized:
            rendered.extend(
                self.render_record_row_lines(
                    row,
                    label_width=label_width,
                    value_width=value_width,
                    indent=indent,
                )
            )
        return tuple(rendered)

    def records(
        self,
        rows: Iterable[RecordRow | Sequence[object]],
        *,
        label_width: int = _RECORD_LABEL_WIDTH,
        value_width: int = _RECORD_VALUE_WIDTH,
        indent: int = 0,
    ) -> None:
        self._write(
            self.render_records(
                rows,
                label_width=label_width,
                value_width=value_width,
                indent=indent,
            )
        )

    def _table_widths(
        self,
        columns: Sequence[TableColumn],
        cells: Sequence[Sequence[str]],
    ) -> list[int]:
        natural_widths = []
        for index, column in enumerate(columns):
            natural = max(
                len(column.heading),
                *(len(row[index]) for row in cells),
            )
            if column.max_width is not None:
                natural = min(natural, column.max_width)
            natural_widths.append(max(column.min_width, natural))
        if not self.interactive:
            return natural_widths

        separators = 2 * max(0, len(columns) - 1)
        budget = max(len(columns), self.content_width - separators)
        widths = [1] * len(columns)
        remaining = max(0, budget - len(columns))

        def grow(targets: Sequence[int]) -> None:
            nonlocal remaining
            while remaining:
                candidates = [
                    index
                    for index, target in enumerate(targets)
                    if widths[index] < target
                ]
                if not candidates:
                    return
                total_weight = sum(columns[index].weight for index in candidates)
                starting = remaining
                changed = False
                for index in candidates:
                    share = max(
                        1,
                        starting * columns[index].weight // max(1, total_weight),
                    )
                    grant = min(targets[index] - widths[index], share, remaining)
                    if grant:
                        widths[index] += grant
                        remaining -= grant
                        changed = True
                    if not remaining:
                        return
                if not changed:
                    return

        # Honor preferred minimums first, then spend the remaining display
        # budget toward natural widths. Runtime is bounded by columns/passes,
        # never by the length of an untrusted cell.
        grow([max(1, column.min_width) for column in columns])
        grow(natural_widths)
        return widths

    def render_table(
        self,
        columns: Sequence[TableColumn],
        rows: Iterable[object],
        *,
        empty_message: str = "No records found",
        semantic_key: str = "_semantic",
        plain_separator: str = "\t",
        plain_header: bool = True,
    ) -> tuple[str, ...]:
        """Render a table that shrinks only on an interactive terminal."""

        if not columns:
            raise ValueError("table requires at least one column")
        materialized = list(rows)
        if not materialized:
            return self.render_empty(empty_message)

        cell_rows: list[list[str]] = []
        meanings: list[Semantic | None] = []
        for row in materialized:
            values: list[str] = []
            for index, column in enumerate(columns):
                raw = _cell(row, column, index)
                rendered = (
                    column.formatter(raw, row)
                    if column.formatter is not None
                    else _one_line(raw)
                )
                values.append(_one_line(rendered))
            cell_rows.append(values)
            raw_semantic = row.get(semantic_key) if isinstance(row, Mapping) else None
            meanings.append(_semantic(raw_semantic))

        if not self.interactive:
            body = [plain_separator.join(values) for values in cell_rows]
            if not plain_header:
                return tuple(body)
            heading = plain_separator.join(column.heading for column in columns)
            return tuple([heading, *body])

        # A horizontal table needs one display cell per column plus separators.
        # At smaller widths switch to records instead of overflowing or hiding
        # columns.
        if len(columns) + 2 * (len(columns) - 1) > self.content_width:
            rendered: list[str] = []
            for row_index, values in enumerate(cell_rows):
                if rendered:
                    rendered.append("")
                for column_index, column in enumerate(columns):
                    rendered.extend(
                        self.render_record_row_lines(
                            RecordRow(
                                column.heading,
                                values[column_index],
                                semantic=(
                                    meanings[row_index]
                                    if column_index == 0
                                    else None
                                ),
                            ),
                            label_width=max(1, min(13, self.content_width // 2)),
                            value_width=max(1, self.content_width // 2),
                        )
                    )
            return tuple(rendered)

        widths = self._table_widths(columns, cell_rows)

        def align(value: str, width: int, direction: str) -> str:
            return value.rjust(width) if direction == "right" else value.ljust(width)

        heading = "  ".join(
            self.terminal.paint(
                align(
                    column.heading[: widths[index]],
                    widths[index],
                    column.align,
                ),
                ui.BOLD,
                ui.DIM,
            )
            for index, column in enumerate(columns)
        ).rstrip()
        rendered_rows = [heading]
        for row_index, values in enumerate(cell_rows):
            meaning = meanings[row_index]
            wrapped_cells = [
                _wrap_verbatim(value, widths[column_index])
                for column_index, value in enumerate(values)
            ]
            row_height = max(len(cell) for cell in wrapped_cells)
            row_lines: list[str] = []
            for line_index in range(row_height):
                cells_out = []
                for column_index, column in enumerate(columns):
                    chunks = wrapped_cells[column_index]
                    chunk = chunks[line_index] if line_index < len(chunks) else ""
                    value = align(chunk, widths[column_index], column.align)
                    styles = (
                        (ui.BOLD, _SEMANTICS[meaning].color)
                        if meaning is not None and column_index == 0
                        else ()
                    )
                    cells_out.append(self.terminal.paint(value, *styles))
                row_lines.append("  ".join(cells_out).rstrip())
            rendered_rows.extend(row_lines)
        return tuple(rendered_rows)

    def table(
        self,
        columns: Sequence[TableColumn],
        rows: Iterable[object],
        *,
        empty_message: str = "No records found",
        semantic_key: str = "_semantic",
        plain_separator: str = "\t",
        plain_header: bool = True,
    ) -> None:
        self._write(
            self.render_table(
                columns,
                rows,
                empty_message=empty_message,
                semantic_key=semantic_key,
                plain_separator=plain_separator,
                plain_header=plain_header,
            )
        )

    def render_empty(
        self,
        message: str,
        *,
        detail: str | None = None,
        plain: str | None = None,
    ) -> tuple[str, ...]:
        """Render an explicit, quiet empty state."""

        if not self.interactive:
            if plain is not None:
                return tuple(str(plain).splitlines() or [""])
            lines = str(message).splitlines() or [""]
            if detail:
                lines.extend(f"  {line}" for line in str(detail).splitlines())
            return tuple(lines)
        mark = "○" if self.terminal.unicode else "-"
        prefix_width = len(mark) + 2
        message_lines = _wrap_plain(
            _ANSI.sub("", str(message)),
            self.content_width,
            initial_indent=" " * prefix_width,
            subsequent_indent=" " * prefix_width,
        )
        first_text = message_lines[0][prefix_width:]
        lines = [
            f"{self.terminal.paint(mark, ui.DIM)}  "
            f"{self.terminal.paint(first_text, ui.BOLD)}"
        ]
        lines.extend(self.terminal.paint(line, ui.BOLD) for line in message_lines[1:])
        if detail:
            lines.extend(
                self.render_wrapped(
                    detail,
                    indent=prefix_width,
                    subsequent_indent=prefix_width,
                    muted=True,
                )
            )
        return tuple(lines)

    def empty(
        self,
        message: str,
        *,
        detail: str | None = None,
        plain: str | None = None,
    ) -> None:
        self._write(self.render_empty(message, detail=detail, plain=plain))

    def _object_lines(
        self,
        value: object,
        *,
        depth: int,
        max_depth: int,
        max_items: int,
    ) -> list[str]:
        indent = depth * 2
        ellipsis = "…" if self.terminal.unicode else "..."
        missing = "—" if self.terminal.unicode else "-"
        if depth >= max_depth:
            return [" " * indent + self.terminal.paint(ellipsis, ui.DIM)]
        if isinstance(value, Mapping):
            if not value:
                return [" " * indent + self.terminal.paint(missing, ui.DIM)]
            lines: list[str] = []
            entries = list(value.items())
            for index, (key, item) in enumerate(entries):
                if index >= max_items:
                    lines.append(
                        " " * indent
                        + self.terminal.paint(
                            f"{ellipsis} {len(entries) - max_items} more", ui.DIM
                        )
                    )
                    break
                label = str(key).replace("_", " ").strip().title()
                if isinstance(item, (Mapping, list, tuple)):
                    lines.append(" " * indent + self.terminal.paint(label, ui.BOLD))
                    lines.extend(
                        self._object_lines(
                            item,
                            depth=depth + 1,
                            max_depth=max_depth,
                            max_items=max_items,
                        )
                    )
                else:
                    lines.extend(
                        self.render_record_row_lines(
                            RecordRow(label, item),
                            indent=indent,
                        )
                    )
            return lines
        if isinstance(value, (list, tuple)):
            if not value:
                return [" " * indent + self.terminal.paint(missing, ui.DIM)]
            if all(not isinstance(item, (Mapping, list, tuple)) for item in value):
                joined = ", ".join(_one_line(item) for item in value[:max_items])
                if len(value) > max_items:
                    joined += f", {ellipsis} {len(value) - max_items} more"
                return list(
                    self.render_wrapped(
                        joined,
                        indent=indent,
                        subsequent_indent=indent,
                    )
                )
            lines = []
            for index, item in enumerate(value):
                if index >= max_items:
                    lines.append(
                        " " * indent
                        + self.terminal.paint(
                            f"{ellipsis} {len(value) - max_items} more", ui.DIM
                        )
                    )
                    break
                lines.append(" " * indent + self.terminal.paint(f"{index + 1}.", ui.BOLD, ui.DIM))
                lines.extend(
                    self._object_lines(
                        item,
                        depth=depth + 1,
                        max_depth=max_depth,
                        max_items=max_items,
                    )
                )
            return lines
        return [" " * indent + _one_line(value)]

    def render_object(
        self,
        value: object,
        *,
        title: str | None = None,
        max_depth: int = 6,
        max_items: int = 100,
    ) -> tuple[str, ...]:
        """Render JSON-like data for people without exposing raw JSON on TTY."""

        if max_depth < 1:
            raise ValueError("max_depth must be positive")
        if max_items < 1:
            raise ValueError("max_items must be positive")
        if not self.interactive:
            return tuple(
                json.dumps(
                    value,
                    indent=2,
                    ensure_ascii=True,
                    sort_keys=False,
                    default=str,
                ).splitlines()
            )
        lines = self._object_lines(
            value,
            depth=0,
            max_depth=max_depth,
            max_items=max_items,
        )
        return self.render_panel(lines, title=title)

    def object(
        self,
        value: object,
        *,
        title: str | None = None,
        max_depth: int = 6,
        max_items: int = 100,
    ) -> None:
        self._write(
            self.render_object(
                value,
                title=title,
                max_depth=max_depth,
                max_items=max_items,
            )
        )


__all__ = [
    "CommandUI",
    "PromptFacade",
    "PromptUnavailable",
    "RecordRow",
    "Semantic",
    "TableColumn",
]
