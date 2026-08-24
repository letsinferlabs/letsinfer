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


def _managed_launcher_present(path: pathlib.Path, store: pathlib.Path) -> bool:
    if not path.exists() and not path.is_symlink():
        return False
    if not path.is_symlink():
        raise CoreUninstallError(f"refusing to remove non-symlink launcher: {path}")
    if not _within(path, store):
        raise CoreUninstallError(f"launcher does not target this installation: {path}")
    return True


def _optional_managed_launcher_present(
    path: pathlib.Path, store: pathlib.Path
) -> bool:
    """Return true only for an alternate launcher owned by this core store."""

    if not path.exists() and not path.is_symlink():
        return False
    return path.is_symlink() and _within(path, store)


def remove(
    source: pathlib.Path,
    *,
    launcher_directory: pathlib.Path,
    letsinfer_home: pathlib.Path,
) -> dict[str, object]:
    source = source.resolve(strict=True)
    manifest_path = source / "SOURCE-MANIFEST.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CoreUninstallError("source is not an immutable Let's Infer installation") from error
    if manifest.get("product") != "letsinfer":
        raise CoreUninstallError("installed source manifest has the wrong product")
    home = letsinfer_home.expanduser().resolve(strict=True)
    if (
        len(source.parents) < 4
        or source.parent.parent.name != "versions"
        or source.parent.parent.parent.name != "core"
        or source.parent.parent.parent.parent != home
    ):
        raise CoreUninstallError("installed source is outside the versioned core layout")
    store = home / "core"
    current = store / "current"
    if not current.is_symlink() or current.resolve(strict=True) != source:
        raise CoreUninstallError("source is not LETSINFER_HOME/core/current")
    launcher_directory = launcher_directory.expanduser().resolve(strict=False)
    if not launcher_directory.is_absolute() or launcher_directory == pathlib.Path("/"):
        raise CoreUninstallError(
            f"refusing to remove unsupported launcher directory: {launcher_directory}"
        )

    primary_candidates = {launcher_directory / name for name in LAUNCHERS}
    user_launcher_directory = (
        home.parent.parent / "bin"
        if home.name == "letsinfer"
        and home.parent.name == "share"
        and home.parent.parent.name == ".local"
        else None
    )
    alternate_candidates = (
        {
            user_launcher_directory / name
            for name in LAUNCHERS
        }
        if user_launcher_directory is not None
        and user_launcher_directory != launcher_directory
        else set()
    )
    managed_launchers = [
        path
        for path in sorted(primary_candidates)
        if _managed_launcher_present(path, store)
    ]
    managed_launchers.extend(
        path
        for path in sorted(alternate_candidates)
        if _optional_managed_launcher_present(path, store)
    )
    # Validate every launcher before mutating any of them.  A malformed second
    # launcher must not leave the primary CLI already removed.
    removed_launchers: list[str] = []
    for path in managed_launchers:
        path.unlink()
        removed_launchers.append(str(path))

    shutil.rmtree(store)
    return {
        "home": str(home),
        "removed_launchers": removed_launchers,
        "removed_store": str(store),
    }


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="remove an immutable Let's Infer core")
    parser.add_argument("--source", type=pathlib.Path, required=True)
    parser.add_argument("--launcher-directory", type=pathlib.Path, required=True)
    parser.add_argument("--letsinfer-home", type=pathlib.Path, required=True)
    parser.add_argument("--quiet", action="store_true")
    parsed = parser.parse_args(arguments)
    try:
        result = remove(
            parsed.source,
            launcher_directory=parsed.launcher_directory,
            letsinfer_home=parsed.letsinfer_home,
        )
    except CoreUninstallError as error:
        parser.error(str(error))
    if not parsed.quiet:
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
