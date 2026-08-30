#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Small benchmark-owned terminal status surface."""

from __future__ import annotations

import contextlib
import os
import sys
from collections.abc import Iterator, Mapping
from typing import TextIO


class Terminal:
    """Captures only the terminal capabilities used by benchmark diagnostics."""

    # Creates one stable stream capability snapshot without product CLI dependencies.
    def __init__(
        self,
        stream: TextIO | None = None,
        *,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        self.stream = sys.stderr if stream is None else stream
        environment = os.environ if environ is None else environ
        try:
            is_terminal = bool(self.stream.isatty())
        except (AttributeError, OSError):
            is_terminal = False
        self.interactive = is_terminal and environment.get("TERM", "").lower() != "dumb"
        self.unicode = self.interactive

    # Writes one compact benchmark state without owning general product presentation.
    def status(self, message: str) -> None:
        label = "•" if self.unicode else "STATUS"
        self.stream.write(f"{label} {message}\n")
        self.stream.flush()


# Presents one bounded benchmark activity and its successful completion.
@contextlib.contextmanager
def progress(
    message: str,
    *,
    done: str | None = None,
    stream: TextIO | None = None,
    **_unused: object,
) -> Iterator[None]:
    terminal = Terminal(stream)
    terminal.status(message)
    try:
        yield
    except BaseException:
        terminal.status(f"Failed: {message}")
        raise
    terminal.status(done or message)
