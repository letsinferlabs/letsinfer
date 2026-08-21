#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Remove superseded immutable core identities after a verified update."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
from collections.abc import Sequence
from typing import Any


INSTALL_MANIFEST = "SOURCE-MANIFEST.json"
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[0-9]+)?$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class CorePruneError(RuntimeError):
    """The immutable core store is not safe to prune."""


def _manifest_identity(root: pathlib.Path) -> str:
    manifest_path = root / INSTALL_MANIFEST
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise CorePruneError(f"core identity has no regular manifest: {root}")
    try:
        payload = manifest_path.read_bytes()
        manifest = json.loads(payload)
    except (OSError, json.JSONDecodeError) as error:
        raise CorePruneError(f"core identity manifest is invalid: {root}") from error
    if manifest.get("product") != "letsinfer":
        raise CorePruneError(f"core identity has the wrong product: {root}")
    return hashlib.sha256(payload).hexdigest()


def plan(
    active_source: pathlib.Path,
    *,
    operator_home: pathlib.Path,
) -> dict[str, Any]:
    supplied_source = active_source.expanduser()
    if supplied_source.is_symlink():
        raise CorePruneError("active core source must not be a symlink")
    active_source = supplied_source.resolve(strict=True)
    if not active_source.is_dir():
        raise CorePruneError("active core source must be a regular directory")
    if len(active_source.parents) < 4:
        raise CorePruneError("active core source is outside the versioned layout")
    version_root = active_source.parent
    product_root = version_root.parent
    library_root = product_root.parent
    prefix = library_root.parent
    if product_root.name != "letsinfer" or library_root.name != "lib":
        raise CorePruneError("active core source is outside the versioned layout")
    allowed_prefixes = {
        pathlib.Path("/opt/letsinfer"),
        operator_home.expanduser().resolve(strict=False) / ".local",
    }
    if prefix not in allowed_prefixes:
        raise CorePruneError(f"unsupported core install prefix: {prefix}")
    if not VERSION_RE.fullmatch(version_root.name):
        raise CorePruneError("active core version directory is invalid")
    active_identity = _manifest_identity(active_source)
    if active_source.name != active_identity:
        raise CorePruneError("active core directory does not match its manifest identity")

    remove: list[pathlib.Path] = []
    for candidate_version in sorted(product_root.iterdir()):
        if candidate_version.is_symlink() or not candidate_version.is_dir():
            raise CorePruneError(
                f"core version entry is not a regular directory: {candidate_version}"
            )
        if not VERSION_RE.fullmatch(candidate_version.name):
            raise CorePruneError(f"unexpected core version directory: {candidate_version}")
        for candidate in sorted(candidate_version.iterdir()):
            if candidate == active_source:
                continue
            if candidate.is_symlink() or not candidate.is_dir():
                raise CorePruneError(
                    f"core identity entry is not a regular directory: {candidate}"
                )
            if not SHA256_RE.fullmatch(candidate.name):
                raise CorePruneError(f"unexpected core identity directory: {candidate}")
            if _manifest_identity(candidate) != candidate.name:
                raise CorePruneError(
                    f"core identity does not match its manifest: {candidate}"
                )
            remove.append(candidate)
    return {
        "schema_version": 1,
        "active_source": str(active_source),
        "product_root": str(product_root),
        "remove": [str(path) for path in remove],
    }


def _remove_readonly_tree(root: pathlib.Path) -> None:
    directories: list[pathlib.Path] = []
    for path in root.rglob("*"):
        if path.is_symlink():
            raise CorePruneError(f"core identity contains a symlink: {path}")
        if path.is_dir():
            directories.append(path)
    for directory in sorted(directories, key=lambda path: len(path.parts), reverse=True):
        directory.chmod(0o700)
    root.chmod(0o700)
    shutil.rmtree(root)


def prune(
    active_source: pathlib.Path,
    *,
    operator_home: pathlib.Path,
    dry_run: bool = False,
) -> dict[str, Any]:
    result = plan(active_source, operator_home=operator_home)
    if dry_run:
        return {**result, "dry_run": True, "removed": []}
    removed: list[str] = []
    for value in result["remove"]:
        path = pathlib.Path(value)
        _remove_readonly_tree(path)
        removed.append(value)
    product_root = pathlib.Path(result["product_root"])
    active_version = pathlib.Path(result["active_source"]).parent
    for version in sorted(product_root.iterdir()):
        if version != active_version:
            try:
                version.rmdir()
            except OSError:
                pass
    descriptor = os.open(product_root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return {**result, "dry_run": False, "removed": removed}


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="prune superseded Let's Infer cores")
    parser.add_argument("--active-source", type=pathlib.Path, required=True)
    parser.add_argument("--operator-home", type=pathlib.Path, required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    parsed = parser.parse_args(arguments)
    try:
        result = prune(
            parsed.active_source,
            operator_home=parsed.operator_home,
            dry_run=parsed.dry_run,
        )
    except CorePruneError as error:
        parser.error(str(error))
    if not parsed.quiet:
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
