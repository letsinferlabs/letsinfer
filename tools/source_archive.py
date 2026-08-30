#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Build and verify deterministic public Let's Infer source archives."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import pathlib
import re
import stat
import tarfile
import tempfile
from collections.abc import Iterable, Sequence
from typing import Any


ARCHIVE_ROOT = "letsinfer"
MANIFEST_NAME = "SOURCE-MANIFEST.json"
RUST_TOOLCHAIN_NAME = "rust-toolchain.toml"
RUST_TOOLCHAIN_CONTENT = (
    b'[toolchain]\n'
    b'channel = "1.97.1"\n'
    b'components = ["rustfmt"]\n'
    b'profile = "minimal"\n'
)
PUBLIC_ROOT_FILES = (
    ".gitignore",
    "LICENSE",
    "NOTICE",
    "README.md",
    "install.sh",
    RUST_TOOLCHAIN_NAME,
)
PUBLIC_DIRECTORIES = (
    "benchmarks",
    "bin",
    "cache",
    "core",
    "documentation",
    "installer",
    "schemas",
    "tests",
    "tools",
)
PUBLIC_PRODUCT_DIRECTORIES = frozenset({"apps"})
LOCAL_ONLY_PATHS = frozenset(
    {"AGENTS.md", "CLAUDE.md", "letsinfer.md", "context", "scratchpad"}
)
GENERATED_DIRECTORY_NAMES = frozenset(
    {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "DerivedData",
        "__pycache__",
        "build",
        "dist",
        "target",
        "xcuserdata",
    }
)
GENERATED_FILE_SUFFIXES = (".pyc", ".pyo", ".swp", ".swo", "~")
SENSITIVE_FILE_NAMES = frozenset({".env", "service.json"})
SENSITIVE_FILE_SUFFIXES = (".crt", ".key", ".pem", ".token")
PUBLIC_TRUST_FILES = frozenset(
    {
        "core/trust/catalog-public-key.pem",
        "core/trust/release-public-key.pem",
    }
)
PRIVATE_KEY_MARKERS = (
    b"-----BEGIN " + b"PRIVATE KEY-----",
    b"-----BEGIN " + b"EC PRIVATE KEY-----",
    b"-----BEGIN " + b"OPENSSH PRIVATE KEY-----",
)
MAX_PUBLIC_FILES = 10_000
MAX_PUBLIC_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 25_000
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class SourceArchiveError(RuntimeError):
    """The source tree or archive violates the public-source contract."""


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _is_generated(relative: pathlib.PurePosixPath) -> bool:
    return bool(
        GENERATED_DIRECTORY_NAMES.intersection(relative.parts)
        or relative.name == ".DS_Store"
        or relative.name.endswith(GENERATED_FILE_SUFFIXES)
    )


def _normalized_mode(mode: int) -> int:
    return 0o755 if mode & 0o111 else 0o644


# Requires one canonical compiler declaration and rejects private key material.
def _validate_public_content(relative: pathlib.PurePosixPath, content: bytes) -> None:
    if relative.as_posix() == RUST_TOOLCHAIN_NAME and content != RUST_TOOLCHAIN_CONTENT:
        raise SourceArchiveError("public source Rust toolchain declaration is invalid")
    if any(marker in content for marker in PRIVATE_KEY_MARKERS):
        raise SourceArchiveError(f"private key material is forbidden in public source: {relative}")


def _validate_public_relative(value: Any) -> pathlib.PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise SourceArchiveError("public source path is invalid")
    relative = pathlib.PurePosixPath(value)
    if relative.is_absolute() or ".." in relative.parts or relative.as_posix() != value:
        raise SourceArchiveError(f"public source path is unsafe: {value}")
    root = relative.parts[0]
    if not (
        value in PUBLIC_ROOT_FILES
        or (root in PUBLIC_DIRECTORIES and len(relative.parts) > 1)
    ):
        raise SourceArchiveError(f"public source path is outside the allowlist: {value}")
    if root in LOCAL_ONLY_PATHS or _is_generated(relative):
        raise SourceArchiveError(f"public source path is local or generated: {value}")
    if relative.name in SENSITIVE_FILE_NAMES or (
        relative.name.endswith(SENSITIVE_FILE_SUFFIXES)
        and value not in PUBLIC_TRUST_FILES
    ):
        raise SourceArchiveError(f"sensitive file is forbidden in public source: {value}")
    return relative


def _inspect_file(root: pathlib.Path, relative: pathlib.PurePosixPath) -> dict[str, Any]:
    _validate_public_relative(relative.as_posix())
    path = root.joinpath(*relative.parts)
    try:
        metadata = path.lstat()
    except OSError as error:
        raise SourceArchiveError(f"cannot inspect public source {relative}: {error}") from error
    if stat.S_ISLNK(metadata.st_mode):
        raise SourceArchiveError(f"public source must not contain symlinks: {relative}")
    if not stat.S_ISREG(metadata.st_mode):
        raise SourceArchiveError(f"public source is not a regular file: {relative}")
    if metadata.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX):
        raise SourceArchiveError(f"public source has a special mode: {relative}")
    try:
        content = path.read_bytes()
    except OSError as error:
        raise SourceArchiveError(f"cannot read public source {relative}: {error}") from error
    _validate_public_content(relative, content)
    return {
        "path": relative.as_posix(),
        "bytes": len(content),
        "mode": _normalized_mode(metadata.st_mode),
        "sha256": _sha256_bytes(content),
        "content": content,
    }


def public_files(root: pathlib.Path) -> list[dict[str, Any]]:
    root = root.resolve(strict=True)
    records: list[dict[str, Any]] = []
    for name in PUBLIC_ROOT_FILES:
        records.append(_inspect_file(root, pathlib.PurePosixPath(name)))
    for directory_name in PUBLIC_DIRECTORIES:
        directory = root / directory_name
        if not directory.is_dir() or directory.is_symlink():
            raise SourceArchiveError(f"public source directory is missing: {directory_name}")
        # Converts one native traversal failure into the stable source-archive boundary.
        def fail_walk(error: OSError) -> None:
            raise SourceArchiveError(
                f"cannot enumerate public source directory {directory_name}: {error}"
            ) from error

        for current, directory_names, file_names in os.walk(
            directory, topdown=True, followlinks=False, onerror=fail_walk
        ):
            current_path = pathlib.Path(current)
            retained_directories = []
            for name in sorted(directory_names):
                path = current_path / name
                relative = pathlib.PurePosixPath(path.relative_to(root).as_posix())
                if _is_generated(relative):
                    continue
                if path.is_symlink():
                    records.append(_inspect_file(root, relative))
                    continue
                retained_directories.append(name)
            directory_names[:] = retained_directories
            for name in sorted(file_names):
                path = current_path / name
                relative = pathlib.PurePosixPath(path.relative_to(root).as_posix())
                if not _is_generated(relative):
                    records.append(_inspect_file(root, relative))
    paths = [record["path"] for record in records]
    if len(paths) != len(set(paths)):
        raise SourceArchiveError("public source file list contains duplicate paths")
    if LOCAL_ONLY_PATHS.intersection(pathlib.PurePosixPath(path).parts[0] for path in paths):
        raise SourceArchiveError("local-only development material entered public source inputs")
    if PUBLIC_PRODUCT_DIRECTORIES.intersection(
        pathlib.PurePosixPath(path).parts[0] for path in paths
    ):
        raise SourceArchiveError("separately released product material entered core source inputs")
    if len(records) > MAX_PUBLIC_FILES:
        raise SourceArchiveError("public source exceeds the file-count limit")
    if sum(int(record["bytes"]) for record in records) > MAX_PUBLIC_BYTES:
        raise SourceArchiveError("public source exceeds the byte limit")
    return sorted(records, key=lambda item: item["path"])


def source_manifest(records: Sequence[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "product": "letsinfer",
        "files": [
            {
                "path": record["path"],
                "bytes": record["bytes"],
                "mode": record["mode"],
                "sha256": record["sha256"],
            }
            for record in records
        ],
    }


def _tar_info(name: str, *, mode: int, size: int = 0, directory: bool = False) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name=name)
    info.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
    info.mode = mode
    info.size = 0 if directory else size
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    return info


def _parent_directories(paths: Iterable[str]) -> list[str]:
    directories = {ARCHIVE_ROOT}
    for value in paths:
        current = pathlib.PurePosixPath(ARCHIVE_ROOT, value).parent
        while str(current) != ".":
            directories.add(current.as_posix())
            if current.as_posix() == ARCHIVE_ROOT:
                break
            current = current.parent
    return sorted(directories, key=lambda item: (item.count("/"), item))


def build_archive(root: pathlib.Path, output: pathlib.Path) -> dict[str, Any]:
    records = public_files(root)
    manifest = source_manifest(records)
    manifest_bytes = _canonical_json(manifest)
    memory = io.BytesIO()
    paths = [record["path"] for record in records] + [MANIFEST_NAME]
    with tarfile.open(fileobj=memory, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for directory in _parent_directories(paths):
            archive.addfile(_tar_info(directory, mode=0o755, directory=True))
        archive.addfile(
            _tar_info(
                f"{ARCHIVE_ROOT}/{MANIFEST_NAME}",
                mode=0o644,
                size=len(manifest_bytes),
            ),
            io.BytesIO(manifest_bytes),
        )
        for record in records:
            archive.addfile(
                _tar_info(
                    f"{ARCHIVE_ROOT}/{record['path']}",
                    mode=record["mode"],
                    size=record["bytes"],
                ),
                io.BytesIO(record["content"]),
            )
    output = output.resolve()
    output.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
                compressed.write(memory.getvalue())
            raw.flush()
            os.fsync(raw.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)
    result = verify_archive(output)
    result["archive_sha256"] = hashlib.sha256(output.read_bytes()).hexdigest()
    return result


def verify_archive(path: pathlib.Path) -> dict[str, Any]:
    path = path.resolve(strict=True)
    try:
        archive = tarfile.open(path, mode="r:gz")
    except (OSError, tarfile.TarError) as error:
        raise SourceArchiveError(f"cannot open source archive: {error}") from error
    with archive:
        members: list[tarfile.TarInfo] = []
        try:
            archived_file_bytes = 0
            for member in archive:
                members.append(member)
                if len(members) > MAX_ARCHIVE_MEMBERS:
                    raise SourceArchiveError("source archive exceeds the member-count limit")
                if member.isreg():
                    archived_file_bytes += member.size
                    if archived_file_bytes > MAX_PUBLIC_BYTES + MAX_MANIFEST_BYTES:
                        raise SourceArchiveError("source archive exceeds the byte limit")
        except (OSError, tarfile.TarError) as error:
            raise SourceArchiveError(f"cannot read source archive: {error}") from error
        names = [member.name for member in members]
        if len(names) != len(set(names)):
            raise SourceArchiveError("source archive contains duplicate members")
        expected_prefix = f"{ARCHIVE_ROOT}/"
        for member in members:
            pure = pathlib.PurePosixPath(member.name)
            if pure.is_absolute() or ".." in pure.parts:
                raise SourceArchiveError("source archive contains an unsafe path")
            if member.name != ARCHIVE_ROOT and not member.name.startswith(expected_prefix):
                raise SourceArchiveError("source archive contains an unexpected root")
            if not (member.isdir() or member.isreg()):
                raise SourceArchiveError("source archive contains a non-file member")
            expected_mode = 0o755 if member.isdir() else 0o644
            if (
                member.uid != 0
                or member.gid != 0
                or member.uname != ""
                or member.gname != ""
                or member.mtime != 0
                or member.mode not in ({0o755} if member.isdir() else {0o644, 0o755})
                or member.pax_headers
            ):
                raise SourceArchiveError("source archive metadata is not normalized")
            if member.isdir() and member.size != 0:
                raise SourceArchiveError("source archive directory has content")
            if member.isdir() and member.mode != expected_mode:
                raise SourceArchiveError("source archive directory mode is not normalized")
        if not members or names[0] != ARCHIVE_ROOT:
            raise SourceArchiveError("source archive root is missing")
        try:
            manifest_member = archive.getmember(f"{ARCHIVE_ROOT}/{MANIFEST_NAME}")
        except KeyError as error:
            raise SourceArchiveError("source archive manifest is missing") from error
        if not manifest_member.isreg() or manifest_member.mode != 0o644:
            raise SourceArchiveError("source archive manifest metadata is invalid")
        if manifest_member.size > MAX_MANIFEST_BYTES:
            raise SourceArchiveError("source archive manifest exceeds the byte limit")
        handle = archive.extractfile(manifest_member)
        if handle is None:
            raise SourceArchiveError("source archive manifest is unreadable")
        try:
            manifest_bytes = handle.read(MAX_MANIFEST_BYTES + 1)
            if len(manifest_bytes) > MAX_MANIFEST_BYTES:
                raise SourceArchiveError("source archive manifest exceeds the byte limit")
            manifest = json.loads(manifest_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise SourceArchiveError("source archive manifest is invalid") from error
        if _canonical_json(manifest) != manifest_bytes:
            raise SourceArchiveError("source archive manifest is not canonical JSON")
        if not isinstance(manifest, dict) or set(manifest) != {"schema_version", "product", "files"}:
            raise SourceArchiveError("source archive manifest fields are invalid")
        if (
            type(manifest["schema_version"]) is not int
            or manifest["schema_version"] != 1
            or manifest["product"] != "letsinfer"
        ):
            raise SourceArchiveError("source archive manifest identity is invalid")
        if not isinstance(manifest["files"], list):
            raise SourceArchiveError("source archive file records are invalid")
        if len(manifest["files"]) > MAX_PUBLIC_FILES:
            raise SourceArchiveError("source archive exceeds the file-count limit")
        expected_files: dict[str, dict[str, Any]] = {}
        total_bytes = 0
        for item in manifest["files"]:
            if not isinstance(item, dict) or set(item) != {"path", "bytes", "mode", "sha256"}:
                raise SourceArchiveError("source archive file record is invalid")
            relative = _validate_public_relative(item["path"])
            if (
                isinstance(item["bytes"], bool)
                or not isinstance(item["bytes"], int)
                or item["bytes"] < 0
                or item["mode"] not in (0o644, 0o755)
                or not isinstance(item["sha256"], str)
                or SHA256_RE.fullmatch(item["sha256"]) is None
            ):
                raise SourceArchiveError(f"source archive file record is invalid: {relative}")
            if item["path"] in expected_files:
                raise SourceArchiveError("source archive manifest has duplicate paths")
            expected_files[item["path"]] = item
            total_bytes += item["bytes"]
            if total_bytes > MAX_PUBLIC_BYTES:
                raise SourceArchiveError("source archive exceeds the byte limit")
        if len(expected_files) != len(manifest["files"]):
            raise SourceArchiveError("source archive manifest has duplicate paths")
        if RUST_TOOLCHAIN_NAME not in expected_files:
            raise SourceArchiveError("source archive Rust toolchain declaration is missing")
        actual_files = {
            member.name.removeprefix(expected_prefix): member
            for member in members
            if member.isreg() and member.name != f"{ARCHIVE_ROOT}/{MANIFEST_NAME}"
        }
        if set(actual_files) != set(expected_files):
            raise SourceArchiveError("source archive files do not match its manifest")
        expected_directories = set(_parent_directories([*expected_files, MANIFEST_NAME]))
        actual_directories = {member.name for member in members if member.isdir()}
        if actual_directories != expected_directories:
            raise SourceArchiveError("source archive directories do not match its manifest")
        for relative, expected in expected_files.items():
            member = actual_files[relative]
            if member.size != expected["bytes"]:
                raise SourceArchiveError(f"source archive member mismatch: {relative}")
            handle = archive.extractfile(member)
            if handle is None:
                raise SourceArchiveError(f"source archive member is unreadable: {relative}")
            content = handle.read(expected["bytes"] + 1)
            if (
                expected["path"] != relative
                or expected["bytes"] != len(content)
                or expected["mode"] != member.mode
                or expected["sha256"] != _sha256_bytes(content)
            ):
                raise SourceArchiveError(f"source archive member mismatch: {relative}")
            _validate_public_content(pathlib.PurePosixPath(relative), content)
    return {
        "schema_version": 1,
        "files": len(expected_files),
        "manifest_sha256": _sha256_bytes(_canonical_json(manifest)),
    }


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="build or verify public source archives")
    operations = parser.add_subparsers(dest="operation", required=True)
    build = operations.add_parser("build")
    build.add_argument("--source", type=pathlib.Path, default=pathlib.Path("."))
    build.add_argument("--output", type=pathlib.Path, required=True)
    verify = operations.add_parser("verify")
    verify.add_argument("archive", type=pathlib.Path)
    parsed = parser.parse_args(arguments)
    try:
        if parsed.operation == "build":
            result = build_archive(parsed.source, parsed.output)
        else:
            result = verify_archive(parsed.archive)
            result["archive_sha256"] = hashlib.sha256(parsed.archive.read_bytes()).hexdigest()
    except SourceArchiveError as error:
        parser.error(str(error))
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
