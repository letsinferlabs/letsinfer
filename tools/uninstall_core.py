#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Remove an immutable Let's Infer core installation after user-state teardown."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
from collections.abc import Sequence


LAUNCHERS = ("letsinfer", "letsinfer-recovery")


class CoreUninstallError(RuntimeError):
    """The installed core layout is not safe to remove."""


def _within(path: pathlib.Path, parent: pathlib.Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(parent.resolve(strict=True))
    except (OSError, ValueError):
        return False
    return True


def _remove_managed_launcher(path: pathlib.Path, store: pathlib.Path) -> bool:
    if not path.exists() and not path.is_symlink():
        return False
    if not path.is_symlink():
        raise CoreUninstallError(f"refusing to remove non-symlink launcher: {path}")
    if not _within(path, store):
        raise CoreUninstallError(f"launcher does not target this installation: {path}")
    path.unlink()
    return True


def remove(
    source: pathlib.Path,
    *,
    launcher_directory: pathlib.Path,
    operator_home: pathlib.Path,
) -> dict[str, object]:
    source = source.resolve(strict=True)
    manifest_path = source / "SOURCE-MANIFEST.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CoreUninstallError("source is not an immutable Let's Infer installation") from error
    if manifest.get("product") != "letsinfer":
        raise CoreUninstallError("installed source manifest has the wrong product")
    if len(source.parents) < 4 or source.parents[1].name != "letsinfer":
        raise CoreUninstallError("installed source is outside the versioned core layout")
    store = source.parents[1]
    prefix = source.parents[3]
    allowed_prefixes = {
        pathlib.Path("/opt/letsinfer"),
        operator_home.expanduser().resolve(strict=False) / ".local",
    }
    if prefix not in allowed_prefixes:
        raise CoreUninstallError(f"refusing to remove unsupported install prefix: {prefix}")
    allowed_launcher_directories = {prefix / "bin", pathlib.Path("/usr/local/bin")}
    launcher_directory = launcher_directory.expanduser().resolve(strict=False)
    if launcher_directory not in allowed_launcher_directories:
        raise CoreUninstallError(
            f"refusing to remove unsupported launcher directory: {launcher_directory}"
        )

    removed_launchers: list[str] = []
    candidates = {
        launcher_directory / name for name in LAUNCHERS
    } | {
        prefix / "bin" / name for name in LAUNCHERS
    } | {
        operator_home / ".local" / "bin" / name for name in LAUNCHERS
    }
    for path in sorted(candidates):
        if _remove_managed_launcher(path, store):
            removed_launchers.append(str(path))

    shutil.rmtree(store)
    for directory in (prefix / "bin", prefix / "lib", prefix):
        try:
            directory.rmdir()
        except OSError:
            pass
    return {
        "prefix": str(prefix),
        "removed_launchers": removed_launchers,
        "removed_store": str(store),
    }


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="remove an immutable Let's Infer core")
    parser.add_argument("--source", type=pathlib.Path, required=True)
    parser.add_argument("--launcher-directory", type=pathlib.Path, required=True)
    parser.add_argument("--operator-home", type=pathlib.Path, required=True)
    parser.add_argument("--quiet", action="store_true")
    parsed = parser.parse_args(arguments)
    try:
        result = remove(
            parsed.source,
            launcher_directory=parsed.launcher_directory,
            operator_home=parsed.operator_home,
        )
    except CoreUninstallError as error:
        parser.error(str(error))
    if not parsed.quiet:
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
