#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Install an immutable user-local Let's Infer CLI source tree."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import shutil
import stat
from collections.abc import Sequence
from typing import Any

from core import PRODUCT_VERSION
from tools.source_archive import public_files, source_manifest


INSTALL_MANIFEST = "SOURCE-MANIFEST.json"
LAUNCHERS = ("letsinfer", "letsinfer-recovery")


class CoreInstallError(RuntimeError):
    """The immutable CLI installation cannot be completed safely."""


# Returns one canonical JSON document for immutable source identity.
def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


# Persists directory metadata after one atomic filesystem transition.
def _fsync_directory(path: pathlib.Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


# Verifies one installed source tree against its exact manifest.
def _verify_installed_tree(root: pathlib.Path, expected: dict[str, Any]) -> None:
    manifest_path = root / INSTALL_MANIFEST
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise CoreInstallError("installed source manifest is missing")
    try:
        actual = json.loads(manifest_path.read_bytes())
    except (OSError, json.JSONDecodeError) as error:
        raise CoreInstallError("installed source manifest is invalid") from error
    if actual != expected:
        raise CoreInstallError("installed source manifest differs from requested source")
    expected_paths = {item["path"] for item in expected["files"]}
    actual_paths: set[str] = set()
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise CoreInstallError("installed source tree contains a symlink")
        if path.is_dir():
            continue
        relative = path.relative_to(root).as_posix()
        if relative != INSTALL_MANIFEST:
            actual_paths.add(relative)
    if actual_paths != expected_paths:
        raise CoreInstallError("installed source tree has unexpected or missing files")
    for record in expected["files"]:
        path = root.joinpath(*pathlib.PurePosixPath(record["path"]).parts)
        try:
            content = path.read_bytes()
            mode = stat.S_IMODE(path.stat().st_mode)
        except OSError as error:
            raise CoreInstallError(f"cannot verify installed source {record['path']}") from error
        expected_mode = 0o555 if record["mode"] & 0o111 else 0o444
        if (
            len(content) != record["bytes"]
            or hashlib.sha256(content).hexdigest() != record["sha256"]
            or mode != expected_mode
        ):
            raise CoreInstallError(f"installed source mismatch: {record['path']}")


# Replaces one managed symlink through an atomic same-directory transition.
def _atomic_link(link: pathlib.Path, target: pathlib.Path, *, parent_mode: int) -> None:
    link.parent.mkdir(mode=parent_mode, parents=True, exist_ok=True)
    if link.exists() and not link.is_symlink():
        raise CoreInstallError(f"refusing to replace a non-symlink: {link}")
    temporary = link.with_name(f".{link.name}.{os.getpid()}.tmp")
    try:
        temporary.unlink(missing_ok=True)
        temporary.symlink_to(target)
        os.replace(temporary, link)
        _fsync_directory(link.parent)
    finally:
        temporary.unlink(missing_ok=True)


# Installs and activates one immutable Core source identity.
def install(
    source: pathlib.Path,
    home: pathlib.Path,
    *,
    launcher_root: pathlib.Path | None = None,
    python_executable: pathlib.Path | None = None,
) -> dict[str, Any]:
    source = source.resolve(strict=True)
    home = home.expanduser().resolve(strict=False)
    python: pathlib.Path | None = None
    if python_executable is not None:
        if not python_executable.is_absolute():
            raise CoreInstallError("Python executable must be an absolute path")
        try:
            python = pathlib.Path(os.path.abspath(python_executable))
            details = python.stat()
        except OSError as error:
            raise CoreInstallError("Python executable is unavailable") from error
        if not stat.S_ISREG(details.st_mode) or not os.access(python, os.X_OK):
            raise CoreInstallError("Python executable must be a regular executable")
    if home in {pathlib.Path("/"), pathlib.Path.home()}:
        raise CoreInstallError("LETSINFER_HOME is too broad")
    if home.exists() and (home.is_symlink() or not home.is_dir()):
        raise CoreInstallError("LETSINFER_HOME must be a real directory")
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    home.chmod(0o700)
    core = home / "core"
    if core.exists() and (core.is_symlink() or not core.is_dir()):
        raise CoreInstallError("core store must be a real directory")
    core.mkdir(mode=0o700, parents=True, exist_ok=True)
    core.chmod(0o700)
    records = public_files(source)
    manifest = source_manifest(records)
    manifest_bytes = _canonical_json(manifest)
    identity = hashlib.sha256(manifest_bytes).hexdigest()
    versions = core / "versions" / PRODUCT_VERSION
    destination = versions / identity
    versions.mkdir(mode=0o755, parents=True, exist_ok=True)
    if destination.exists():
        if destination.is_symlink() or not destination.is_dir():
            raise CoreInstallError("installed source identity is not a real directory")
        _verify_installed_tree(destination, manifest)
    else:
        staging = versions / f".{identity}.{os.getpid()}.tmp"
        if staging.exists():
            raise CoreInstallError("installation staging path already exists")
        staging.mkdir(mode=0o755)
        try:
            for record in records:
                relative = pathlib.PurePosixPath(record["path"])
                path = staging.joinpath(*relative.parts)
                path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                descriptor = os.open(
                    path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    record["mode"],
                )
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(record["content"])
                    handle.flush()
                    os.fsync(handle.fileno())
                path.chmod(0o555 if record["mode"] & 0o111 else 0o444)
            manifest_path = staging / INSTALL_MANIFEST
            descriptor = os.open(
                manifest_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444
            )
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(manifest_bytes)
                handle.flush()
                os.fsync(handle.fileno())
            manifest_path.chmod(0o444)
            os.replace(staging, destination)
            for directory in sorted(
                (path for path in destination.rglob("*") if path.is_dir()),
                key=lambda path: len(path.parts),
                reverse=True,
            ):
                directory.chmod(0o555)
            destination.chmod(0o555)
            _fsync_directory(versions)
        except BaseException:
            if staging.exists():
                for path in staging.rglob("*"):
                    if path.is_dir():
                        path.chmod(0o755)
                    else:
                        path.chmod(0o644)
                staging.chmod(0o755)
                shutil.rmtree(staging)
            raise
        _verify_installed_tree(destination, manifest)
    _atomic_link(core / "current", destination, parent_mode=0o700)
    if python is not None:
        _atomic_link(core / "python", python, parent_mode=0o700)
    bin_root = launcher_root.expanduser().resolve(strict=False) if launcher_root else None
    for name in LAUNCHERS:
        target = core / "current" / "bin" / name
        installed = destination / "bin" / name
        if not installed.is_file() or installed.is_symlink():
            raise CoreInstallError(f"installed launcher is unavailable: {name}")
        if bin_root is not None:
            _atomic_link(bin_root / name, target, parent_mode=0o755)
    return {
        "schema_version": 2,
        "version": PRODUCT_VERSION,
        "source_sha256": identity,
        "source_root": str(destination),
        "current": str(core / "current"),
        "command": str(bin_root / "letsinfer") if bin_root else str(core / "current/bin/letsinfer"),
    }


# Parses the Core installation contract and emits its machine result.
def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="install the immutable Let's Infer CLI")
    parser.add_argument("--source", type=pathlib.Path, default=pathlib.Path("."))
    parser.add_argument(
        "--home",
        type=pathlib.Path,
        default=pathlib.Path(os.environ.get("LETSINFER_HOME", "~/.local/share/letsinfer")),
    )
    parser.add_argument("--launcher-root", type=pathlib.Path)
    parser.add_argument("--python", type=pathlib.Path)
    parsed = parser.parse_args(arguments)
    try:
        result = install(
            parsed.source,
            parsed.home,
            launcher_root=parsed.launcher_root,
            python_executable=parsed.python,
        )
    except CoreInstallError as error:
        parser.error(str(error))
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
