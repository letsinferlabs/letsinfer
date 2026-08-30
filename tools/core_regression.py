#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Run every repository regression suite through one stable entry point."""

from __future__ import annotations

import argparse
import dataclasses
import os
import pathlib
import subprocess
import sys
import time
from collections.abc import Sequence


REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[1]


@dataclasses.dataclass(frozen=True)
class Suite:
    name: str
    path: pathlib.Path
    description: str


SUITES = (
    Suite("tooling", pathlib.Path("tests/cli"), "build, release, and installer tools"),
    Suite("benchmarks", pathlib.Path("tests/benchmarks"), "benchmark contracts"),
    Suite("regression", pathlib.Path("tests/regression"), "suite ownership contracts"),
    Suite(
        "macos-contract",
        pathlib.Path("apps/macos/tests"),
        "cross-platform macOS release contracts",
    ),
)


def test_modules(root: pathlib.Path = REPOSITORY_ROOT) -> dict[str, tuple[pathlib.Path, ...]]:
    """Return the test modules owned by each registered suite."""
    return {
        suite.name: tuple(sorted((root / suite.path).glob("test_*.py")))
        for suite in SUITES
    }


def unregistered_test_modules(
    root: pathlib.Path = REPOSITORY_ROOT,
) -> tuple[pathlib.Path, ...]:
    """Find tests that the canonical runner would silently omit."""
    registered = {
        path.resolve()
        for paths in test_modules(root).values()
        for path in paths
    }
    discovered = {
        path.resolve()
        for base in (root / "tests", root / "apps")
        if base.is_dir()
        for path in base.rglob("test_*.py")
    }
    return tuple(sorted(discovered - registered))


def validate_inventory(root: pathlib.Path = REPOSITORY_ROOT) -> None:
    missing = [suite.name for suite in SUITES if not (root / suite.path).is_dir()]
    empty = [name for name, paths in test_modules(root).items() if not paths]
    unregistered = unregistered_test_modules(root)
    if missing or empty or unregistered:
        details = []
        if missing:
            details.append(f"missing suites: {', '.join(missing)}")
        if empty:
            details.append(f"empty suites: {', '.join(empty)}")
        if unregistered:
            details.append(
                "unregistered tests: "
                + ", ".join(str(path.relative_to(root)) for path in unregistered)
            )
        raise RuntimeError("; ".join(details))


def _arguments(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--suite",
        action="append",
        choices=[suite.name for suite in SUITES],
        help="run only this suite; repeat to select more than one",
    )
    parser.add_argument("--list", action="store_true", help="list suites without running them")
    parser.add_argument("--verbose", action="store_true", help="show individual test names")
    parser.add_argument("--fail-fast", action="store_true", help="stop after the first failure")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _arguments(argv)
    try:
        validate_inventory()
    except RuntimeError as error:
        print(f"Regression inventory error: {error}", file=sys.stderr)
        return 2

    selected = [
        suite for suite in SUITES if arguments.suite is None or suite.name in arguments.suite
    ]
    modules = test_modules()
    if arguments.list:
        for suite in selected:
            print(f"{suite.name:16} {len(modules[suite.name]):2} modules  {suite.description}")
        return 0

    environment = dict(os.environ)
    environment.update(PYTHONDONTWRITEBYTECODE="1", PYTHONHASHSEED="0")
    started = time.monotonic()
    for index, suite in enumerate(selected, 1):
        print(
            f"[{index}/{len(selected)}] {suite.name}: "
            f"{len(modules[suite.name])} modules · {suite.description}",
            flush=True,
        )
        command = [
            sys.executable,
            "-m",
            "unittest",
            "discover",
            "-s",
            str(suite.path),
            "-p",
            "test_*.py",
        ]
        if arguments.verbose:
            command.append("-v")
        if arguments.fail_fast:
            command.append("-f")
        completed = subprocess.run(command, cwd=REPOSITORY_ROOT, env=environment)
        if completed.returncode:
            print(f"FAILED {suite.name}", file=sys.stderr)
            return completed.returncode

    elapsed = time.monotonic() - started
    module_count = sum(len(modules[suite.name]) for suite in selected)
    print(
        f"PASS {len(selected)} suites · {module_count} modules · {elapsed:.1f}s",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
