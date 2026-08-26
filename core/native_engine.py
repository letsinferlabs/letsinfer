#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Verified native Engine staging and macOS launchd lifecycle."""

from __future__ import annotations

import hashlib
import fcntl
import json
import os
import pathlib
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request
import zipfile
from collections.abc import Mapping, Sequence
from typing import Any

from .engine_distribution import (
    EMBEDDED_APP_KIND,
    NATIVE_ARCHIVE_KIND,
    PYTHON_STANDALONE_KIND,
    EngineDistributionError,
    validate_engine_distribution,
)
from .paths import data_root


MAX_ARCHIVE_FILES = 10_000
MAX_EXPANDED_BYTES = 2 << 30
MAX_STAGED_FILES = 100_000
MAX_STAGED_BYTES = 4 << 30
USER_AGENT = "letsinfer/native-engine-v1"


class NativeEngineError(RuntimeError):
    """A native Engine payload or lifecycle transition failed closed."""


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(4 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _tree_sha256(root: pathlib.Path) -> str:
    records: list[dict[str, Any]] = []
    total = 0
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if relative == "receipt.json":
            continue
        if path.is_symlink():
            raise NativeEngineError("native Engine payload contains a symlink")
        if path.is_dir():
            continue
        if not path.is_file() or len(records) >= MAX_STAGED_FILES:
            raise NativeEngineError("native Engine payload file set is invalid")
        details = path.stat()
        total += details.st_size
        if total > MAX_STAGED_BYTES:
            raise NativeEngineError("native Engine payload exceeds its staged bound")
        records.append(
            {
                "path": relative,
                "bytes": details.st_size,
                "executable": bool(stat.S_IMODE(details.st_mode) & 0o111),
                "sha256": sha256_file(path),
            }
        )
    if not records:
        raise NativeEngineError("native Engine payload is empty")
    return hashlib.sha256(
        canonical_bytes(
            {
                "contract": "letsinfer-native-staged-tree-v1",
                "files": records,
            }
        )
    ).hexdigest()


def _private_directory(path: pathlib.Path) -> None:
    if path.is_symlink():
        raise NativeEngineError(f"native Engine directory cannot be a symlink: {path}")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    details = path.stat()
    if not stat.S_ISDIR(details.st_mode) or details.st_uid != os.getuid():
        raise NativeEngineError(f"native Engine directory must be user-owned: {path}")
    path.chmod(0o700)


def native_engine_root() -> pathlib.Path:
    return data_root() / "native-engines"


def payload_root(distribution: Mapping[str, Any]) -> pathlib.Path:
    try:
        value = validate_engine_distribution(distribution)
    except EngineDistributionError as error:
        raise NativeEngineError(str(error)) from error
    return native_engine_root() / str(value["payload_id"]).removeprefix("sha256:")


def calculated_payload_id(
    distribution: Mapping[str, Any],
    runtime_root: pathlib.Path,
) -> str:
    """Bind native upstream bytes to the matching runtime-owned adapter inputs."""

    try:
        value = validate_engine_distribution(distribution)
    except EngineDistributionError as error:
        raise NativeEngineError(str(error)) from error
    entrypoint = runtime_root / value["entrypoint"]
    if entrypoint.is_symlink() or not entrypoint.is_file():
        raise NativeEngineError("native Engine entrypoint is unavailable")
    subject: dict[str, Any] = {
        key: item for key, item in value.items() if key != "payload_id"
    }
    subject["materializer"] = "letsinfer-native-engine-v5"
    adapter_root = entrypoint.parent
    adapter_files: list[dict[str, Any]] = []
    for path in sorted(adapter_root.rglob("*")):
        relative = path.relative_to(runtime_root)
        if "__pycache__" in relative.parts:
            continue
        if path.is_symlink():
            raise NativeEngineError("native Engine adapter cannot contain symlinks")
        if path.is_dir():
            continue
        if not path.is_file() or len(adapter_files) >= 256:
            raise NativeEngineError("native Engine adapter file set is invalid")
        details = path.stat()
        adapter_files.append(
            {
                "path": relative.as_posix(),
                "bytes": details.st_size,
                "executable": bool(stat.S_IMODE(details.st_mode) & 0o111),
                "sha256": sha256_file(path),
            }
        )
    if not adapter_files or value["entrypoint"] not in {
        item["path"] for item in adapter_files
    }:
        raise NativeEngineError("native Engine adapter closure is incomplete")
    subject["adapter_files"] = adapter_files
    if value["kind"] == PYTHON_STANDALONE_KIND:
        lock = runtime_root / value["requirements_lock"]
        if lock.is_symlink() or not lock.is_file():
            raise NativeEngineError("native Engine requirements lock is unavailable")
        subject["requirements_lock_sha256"] = sha256_file(lock)
    return "sha256:" + hashlib.sha256(canonical_bytes(subject)).hexdigest()


def verify_payload_id(
    distribution: Mapping[str, Any],
    runtime_root: pathlib.Path,
) -> None:
    expected = validate_engine_distribution(distribution)["payload_id"]
    actual = calculated_payload_id(distribution, runtime_root)
    if actual != expected:
        raise NativeEngineError(
            f"native Engine payload identity differs (expected {expected}, got {actual})"
        )


def _download_archive(value: Mapping[str, Any], output: pathlib.Path) -> None:
    url = str(value["url"])
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise NativeEngineError("native Engine archive URL must use HTTPS")
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    digest = hashlib.sha256()
    total = 0
    try:
        with urllib.request.urlopen(request, timeout=60) as response, output.open(
            "xb"
        ) as handle:
            if urllib.parse.urlsplit(response.geturl()).scheme != "https":
                raise NativeEngineError("native Engine archive left HTTPS")
            while True:
                chunk = response.read(4 << 20)
                if not chunk:
                    break
                total += len(chunk)
                if total > value["bytes"]:
                    raise NativeEngineError("native Engine archive exceeds its declared size")
                digest.update(chunk)
                handle.write(chunk)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as error:
        raise NativeEngineError(f"native Engine download failed: {error}") from error
    if total != value["bytes"] or digest.hexdigest() != value["sha256"]:
        raise NativeEngineError("native Engine archive identity differs")


def _safe_member(name: str, strip_prefix: pathlib.PurePosixPath) -> pathlib.PurePosixPath | None:
    path = pathlib.PurePosixPath(name)
    if path.is_absolute() or "." in path.parts or ".." in path.parts:
        raise NativeEngineError("native Engine archive contains an unsafe path")
    if path.parts[: len(strip_prefix.parts)] != strip_prefix.parts:
        return None
    relative = pathlib.PurePosixPath(*path.parts[len(strip_prefix.parts) :])
    if not relative.parts:
        return None
    return relative


def _extract_archive(
    archive: pathlib.Path,
    destination: pathlib.Path,
    *,
    archive_format: str,
    strip_prefix: str,
) -> None:
    prefix = pathlib.PurePosixPath(strip_prefix)
    files = 0
    total = 0
    if archive_format == "tar.gz":
        links: dict[pathlib.PurePosixPath, pathlib.PurePosixPath] = {}
        with tarfile.open(archive, mode="r:gz") as source:
            for member in source:
                relative = _safe_member(member.name, prefix)
                if relative is None:
                    continue
                if member.issym() or member.islnk():
                    raw_target = pathlib.PurePosixPath(member.linkname)
                    archive_target = (
                        raw_target
                        if raw_target.is_absolute()
                        else pathlib.PurePosixPath(member.name).parent / raw_target
                    )
                    if archive_target.is_absolute() or ".." in archive_target.parts:
                        raise NativeEngineError(
                            "native Engine archive link escapes its root"
                        )
                    target_relative = _safe_member(archive_target.as_posix(), prefix)
                    if target_relative is None:
                        raise NativeEngineError(
                            "native Engine archive link leaves its prefix"
                        )
                    links[relative] = target_relative
                    continue
                if not (member.isfile() or member.isdir()):
                    raise NativeEngineError("native Engine archive contains unsafe entries")
                target = destination.joinpath(*relative.parts)
                if member.isdir():
                    _private_directory(target)
                    continue
                files += 1
                total += member.size
                if files > MAX_ARCHIVE_FILES or total > MAX_EXPANDED_BYTES:
                    raise NativeEngineError("native Engine archive exceeds its expanded bound")
                _private_directory(target.parent)
                extracted = source.extractfile(member)
                if extracted is None:
                    raise NativeEngineError("native Engine archive file is unavailable")
                with target.open("xb") as output:
                    shutil.copyfileobj(extracted, output, length=4 << 20)
                target.chmod(0o755 if member.mode & 0o111 else 0o644)
        for relative, target_relative in links.items():
            seen: set[pathlib.PurePosixPath] = set()
            while target_relative in links:
                if target_relative in seen:
                    raise NativeEngineError("native Engine archive links contain a cycle")
                seen.add(target_relative)
                target_relative = links[target_relative]
            source_path = destination.joinpath(*target_relative.parts)
            target_path = destination.joinpath(*relative.parts)
            if source_path.is_symlink() or not source_path.is_file():
                raise NativeEngineError("native Engine archive link target is unavailable")
            _private_directory(target_path.parent)
            shutil.copyfile(source_path, target_path)
            target_path.chmod(stat.S_IMODE(source_path.stat().st_mode))
    elif archive_format == "zip":
        with zipfile.ZipFile(archive) as source:
            for member in source.infolist():
                relative = _safe_member(member.filename, prefix)
                if relative is None:
                    continue
                mode = member.external_attr >> 16
                if stat.S_ISLNK(mode):
                    raise NativeEngineError("native Engine archive contains a symlink")
                target = destination.joinpath(*relative.parts)
                if member.is_dir():
                    _private_directory(target)
                    continue
                files += 1
                total += member.file_size
                if files > MAX_ARCHIVE_FILES or total > MAX_EXPANDED_BYTES:
                    raise NativeEngineError("native Engine archive exceeds its expanded bound")
                _private_directory(target.parent)
                with source.open(member) as extracted, target.open("xb") as output:
                    shutil.copyfileobj(extracted, output, length=4 << 20)
                target.chmod(0o755 if mode & 0o111 else 0o644)
    else:  # pragma: no cover - schema validation owns this boundary.
        raise NativeEngineError("native Engine archive format is unsupported")
    if files == 0:
        raise NativeEngineError("native Engine archive is empty after prefix removal")


def _run(command: Sequence[str]) -> None:
    try:
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
    except OSError as error:
        raise NativeEngineError(f"native Engine command is unavailable: {command[0]}") from error
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise NativeEngineError(
            f"native Engine command failed: {pathlib.Path(command[0]).name}: {detail}"
        )


def _installed_payload(root: pathlib.Path, value: Mapping[str, Any]) -> bool:
    if not root.exists() and not root.is_symlink():
        return False
    if root.is_symlink():
        raise NativeEngineError("native Engine payload cannot be a symlink")
    details = root.stat()
    if not stat.S_ISDIR(details.st_mode) or details.st_uid != os.getuid():
        raise NativeEngineError("native Engine payload must be a user-owned directory")
    receipt = root / "receipt.json"
    if receipt.is_symlink() or not receipt.is_file():
        return False
    try:
        current = json.loads(receipt.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    if (
        not isinstance(current, dict)
        or set(current) != {"schema_version", "distribution", "tree_sha256"}
        or current.get("schema_version") != 3
        or current.get("distribution") != dict(value)
        or not isinstance(current.get("tree_sha256"), str)
    ):
        return False
    try:
        return current["tree_sha256"] == _tree_sha256(root)
    except NativeEngineError:
        return False


def verify_staged_native_engine(distribution: Mapping[str, Any]) -> pathlib.Path:
    """Verify the complete staged native payload without downloading inputs."""

    value = validate_engine_distribution(distribution)
    if value["kind"] == EMBEDDED_APP_KIND:
        raise NativeEngineError("embedded application Engines stage inside the application")
    root = payload_root(value)
    if not _installed_payload(root, value):
        raise NativeEngineError("the exact native Engine payload is absent or corrupt")
    return root


def stage_native_engine(
    distribution: Mapping[str, Any],
    runtime_root: pathlib.Path,
) -> pathlib.Path:
    """Materialize a complete native Engine under its immutable payload ID."""

    value = validate_engine_distribution(distribution)
    if value["kind"] == EMBEDDED_APP_KIND:
        raise NativeEngineError("embedded application Engines stage inside the application")
    if value["platform"] != "macos/arm64" or platform.system() != "Darwin" or platform.machine() != "arm64":
        raise NativeEngineError("native macOS Engine requires macos/arm64")
    verify_payload_id(value, runtime_root)
    root = payload_root(value)
    _private_directory(native_engine_root())
    lock_path = native_engine_root() / f".{root.name}.lock"
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    with os.fdopen(descriptor, "r+b") as lock:
        details = os.fstat(lock.fileno())
        if not stat.S_ISREG(details.st_mode) or details.st_uid != os.getuid():
            raise NativeEngineError("native Engine payload lock is unsafe")
        os.fchmod(lock.fileno(), 0o600)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        if _installed_payload(root, value):
            return root
        if root.exists():
            shutil.rmtree(root)
        staging = pathlib.Path(
            tempfile.mkdtemp(prefix=f".{root.name}.", dir=native_engine_root())
        )
        try:
            if value["kind"] == NATIVE_ARCHIVE_KIND:
                archive = staging / "engine.archive"
                _download_archive(value["archive"], archive)
                upstream = staging / "upstream"
                _private_directory(upstream)
                _extract_archive(
                    archive,
                    upstream,
                    archive_format=value["archive"]["format"],
                    strip_prefix=value["archive"]["strip_prefix"],
                )
                archive.unlink()
                executable = upstream / value["upstream_executable"]
                if (
                    executable.is_symlink()
                    or not executable.is_file()
                    or not os.access(executable, os.X_OK)
                ):
                    raise NativeEngineError("native Engine executable is unavailable")
            else:
                python_archive = staging / "python.archive"
                _download_archive(value["python"]["archive"], python_archive)
                python_root = staging / "python"
                _private_directory(python_root)
                _extract_archive(
                    python_archive,
                    python_root,
                    archive_format=value["python"]["archive"]["format"],
                    strip_prefix=value["python"]["archive"]["strip_prefix"],
                )
                python_archive.unlink()
                interpreter = python_root / "bin" / "python3"
                if (
                    interpreter.is_symlink()
                    or not interpreter.is_file()
                    or not os.access(interpreter, os.X_OK)
                ):
                    raise NativeEngineError("native Engine CPython executable is unavailable")
                observed = subprocess.run(
                    [str(interpreter), "-c", "import platform; print(platform.python_version())"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if (
                    observed.returncode != 0
                    or observed.stdout.strip() != value["python"]["version"]
                ):
                    raise NativeEngineError("native Engine CPython version differs")
                packages = staging / "site-packages"
                _private_directory(packages)
                _run(
                    [
                        str(interpreter),
                        "-m",
                        "pip",
                        "install",
                        "--disable-pip-version-check",
                        "--no-deps",
                        "--require-hashes",
                        "--target",
                        str(packages),
                        "-r",
                        str(runtime_root / value["requirements_lock"]),
                    ]
                )
            tree_sha256 = _tree_sha256(staging)
            (staging / "receipt.json").write_bytes(
                canonical_bytes(
                    {
                        "schema_version": 3,
                        "distribution": value,
                        "tree_sha256": tree_sha256,
                    }
                )
            )
            (staging / "receipt.json").chmod(0o600)
            staging.replace(root)
            return root
        except BaseException:
            if staging.exists():
                shutil.rmtree(staging)
            raise


def native_launch_command(
    distribution: Mapping[str, Any],
    runtime_root: pathlib.Path,
    command: str = "serve",
) -> tuple[str, ...]:
    value = validate_engine_distribution(distribution)
    root = payload_root(value)
    entrypoint = runtime_root / value["entrypoint"]
    if value["kind"] == NATIVE_ARCHIVE_KIND:
        return (sys.executable, str(entrypoint), command)
    if value["kind"] == PYTHON_STANDALONE_KIND:
        return (
            str(root / "python" / "bin" / "python3"),
            str(entrypoint),
            command,
        )
    raise NativeEngineError("embedded application Engine has no host launch command")


def native_launch_environment(
    distribution: Mapping[str, Any],
    runtime_root: pathlib.Path,
) -> dict[str, str]:
    value = validate_engine_distribution(distribution)
    root = payload_root(value)
    result = {
        "LETSINFER_NATIVE_ENGINE_ROOT": str(root),
        "LETSINFER_RUNTIME_ROOT": str(runtime_root),
    }
    if value["kind"] == NATIVE_ARCHIVE_KIND:
        result["LETSINFER_NATIVE_UPSTREAM_EXECUTABLE"] = str(
            root / "upstream" / value["upstream_executable"]
        )
    elif value["kind"] == PYTHON_STANDALONE_KIND:
        result["PYTHONPATH"] = os.pathsep.join(
            (
                str((runtime_root / value["entrypoint"]).parent),
                str(root / "site-packages"),
            )
        )
        result["PYTHONDONTWRITEBYTECODE"] = "1"
        result["PYTHONNOUSERSITE"] = "1"
        result["PYTHONSAFEPATH"] = "1"
    return result
