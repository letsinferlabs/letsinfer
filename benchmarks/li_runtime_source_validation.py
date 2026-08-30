#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Benchmark-owned immutable source-tree verification."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import stat
from typing import Any


MAXIMUM_SOURCE_FILES = 20_000
MAXIMUM_SOURCE_BYTES = 4 * 1024 * 1024 * 1024
SOURCE_MANIFEST = "SOURCE-MANIFEST.json"


class RuntimeSourceValidationError(ValueError):
    """A benchmark source tree is mutable, aliased, unbounded, or corrupt."""


# Returns whether one source-relative path is contained without normalization aliases.
def _relative_path(value: str) -> pathlib.PurePosixPath:
    path = pathlib.PurePosixPath(value)
    if not value or path.is_absolute() or any(part in {".", ".."} for part in path.parts):
        raise RuntimeSourceValidationError("source manifest path is unsafe")
    return path


# Returns one exact lowercase SHA-256 identity without an unbounded allocation.
def _sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


# Inventories one bounded regular tree without following any filesystem alias.
def _source_files(root: pathlib.Path) -> dict[str, os.stat_result]:
    files: dict[str, os.stat_result] = {}
    total = 0
    for directory, names, filenames in os.walk(root, followlinks=False):
        current = pathlib.Path(directory)
        for name in names:
            path = current / name
            if path.is_symlink() or not path.is_dir():
                raise RuntimeSourceValidationError("source tree contains an aliased directory")
        for name in filenames:
            path = current / name
            details = path.lstat()
            if path.is_symlink() or not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
                raise RuntimeSourceValidationError("source tree contains a non-regular file")
            relative = path.relative_to(root).as_posix()
            _relative_path(relative)
            total += details.st_size
            files[relative] = details
            if len(files) > MAXIMUM_SOURCE_FILES or total > MAXIMUM_SOURCE_BYTES:
                raise RuntimeSourceValidationError("source tree exceeds its benchmark boundary")
    return files


# Verifies one optional deterministic source manifest against every exact tree byte.
def _verify_source_manifest(
    root: pathlib.Path,
    files: dict[str, os.stat_result],
) -> None:
    manifest_path = root / SOURCE_MANIFEST
    if SOURCE_MANIFEST not in files:
        return
    try:
        document = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeSourceValidationError("source manifest is unreadable") from error
    if (
        not isinstance(document, dict)
        or set(document) != {"schema_version", "product", "files"}
        or document.get("schema_version") != 1
        or document.get("product") != "letsinfer"
        or not isinstance(document.get("files"), list)
    ):
        raise RuntimeSourceValidationError("source manifest identity is invalid")
    expected: set[str] = set()
    for record in document["files"]:
        if not isinstance(record, dict) or set(record) != {"path", "bytes", "mode", "sha256"}:
            raise RuntimeSourceValidationError("source manifest record is invalid")
        relative = _relative_path(record.get("path")) if isinstance(record.get("path"), str) else None
        if relative is None:
            raise RuntimeSourceValidationError("source manifest record path is invalid")
        value = relative.as_posix()
        if value in expected or value not in files:
            raise RuntimeSourceValidationError("source manifest inventory differs")
        details = files[value]
        digest = record.get("sha256")
        if (
            not isinstance(record.get("bytes"), int)
            or isinstance(record.get("bytes"), bool)
            or record["bytes"] != details.st_size
            or record.get("mode") != stat.S_IMODE(details.st_mode)
            or not isinstance(digest, str)
            or len(digest) != 64
            or _sha256(root / relative) != digest
        ):
            raise RuntimeSourceValidationError("source manifest content differs")
        expected.add(value)
    if set(files) != expected | {SOURCE_MANIFEST}:
        raise RuntimeSourceValidationError("source tree contains unmanifested files")


# Verifies immutable source bytes without importing product lifecycle code.
def verify_runtime_sources(manifest: dict[str, Any], source_root: pathlib.Path) -> None:
    if not isinstance(manifest, dict) or not manifest:
        raise RuntimeSourceValidationError("runtime execution manifest is unavailable")
    try:
        root = source_root.resolve(strict=True)
    except OSError as error:
        raise RuntimeSourceValidationError("runtime source root is unavailable") from error
    if source_root.is_symlink() or not root.is_dir():
        raise RuntimeSourceValidationError("runtime source root is unsafe")
    manifest_path = root / SOURCE_MANIFEST
    if manifest_path.exists() or manifest_path.is_symlink():
        _verify_source_manifest(root, _source_files(root))
