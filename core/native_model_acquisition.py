#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Dependency-free acquisition of exact public Hugging Face revisions."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import Any


REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REPOSITORY_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$"
)
MAX_METADATA_BYTES = 16 << 20
MAX_FILES = 10_000
MAX_TOTAL_BYTES = 1 << 40
USER_AGENT = "letsinfer/huggingface-http-v1"


class NativeModelAcquisitionError(RuntimeError):
    """A public model revision is mutable, unsafe, incomplete, or corrupt."""


def _safe_relative(value: Any) -> pathlib.PurePosixPath:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 4096:
        raise NativeModelAcquisitionError("Hugging Face path is invalid")
    path = pathlib.PurePosixPath(value)
    if path.is_absolute() or "." in path.parts or ".." in path.parts:
        raise NativeModelAcquisitionError("Hugging Face path escapes the snapshot")
    if any("\x00" in part or not part for part in path.parts):
        raise NativeModelAcquisitionError("Hugging Face path is invalid")
    return path


def _request(url: str) -> urllib.request.Request:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise NativeModelAcquisitionError("model acquisition requires credential-free HTTPS")
    return urllib.request.Request(url, headers={"User-Agent": USER_AGENT})


def _read_json(url: str) -> tuple[Any, str | None]:
    try:
        with urllib.request.urlopen(_request(url), timeout=30) as response:
            payload = response.read(MAX_METADATA_BYTES + 1)
            link = response.headers.get("Link")
    except OSError as error:
        raise NativeModelAcquisitionError(
            f"Hugging Face metadata request failed: {error}"
        ) from error
    if len(payload) > MAX_METADATA_BYTES:
        raise NativeModelAcquisitionError("Hugging Face metadata exceeds its bound")
    try:
        return json.loads(payload), link
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeModelAcquisitionError("Hugging Face metadata is invalid") from error


def _next_link(value: str | None) -> str | None:
    if value is None:
        return None
    for item in value.split(","):
        match = re.fullmatch(r'\s*<([^>]+)>;\s*rel="next"\s*', item)
        if match is not None:
            return match.group(1)
    return None


def snapshot_files(
    repository: str,
    revision: str,
    *,
    filename: str | None = None,
) -> tuple[dict[str, Any], ...]:
    """Return the closed public file inventory for one immutable commit."""

    if REPOSITORY_RE.fullmatch(repository) is None or REVISION_RE.fullmatch(revision) is None:
        raise NativeModelAcquisitionError("model repository or revision is invalid")
    if filename is not None:
        _safe_relative(filename)
    owner, name = repository.split("/", 1)
    url = (
        "https://huggingface.co/api/models/"
        f"{urllib.parse.quote(owner, safe='')}/{urllib.parse.quote(name, safe='')}"
        f"/tree/{revision}?recursive=true&limit=1000"
    )
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    while url is not None:
        value, link = _read_json(url)
        if not isinstance(value, list):
            raise NativeModelAcquisitionError("Hugging Face tree response is invalid")
        for item in value:
            if not isinstance(item, dict) or item.get("type") not in {"file", "directory"}:
                raise NativeModelAcquisitionError("Hugging Face tree entry is invalid")
            if item["type"] == "directory":
                continue
            path = _safe_relative(item.get("path")).as_posix()
            if filename is not None and path != filename:
                continue
            if path in seen:
                raise NativeModelAcquisitionError("Hugging Face tree contains duplicates")
            size = item.get("size")
            if not isinstance(size, int) or isinstance(size, bool) or size < 0:
                raise NativeModelAcquisitionError("Hugging Face file size is invalid")
            lfs = item.get("lfs")
            sha256 = None
            if lfs is not None:
                if not isinstance(lfs, dict) or not isinstance(lfs.get("oid"), str):
                    raise NativeModelAcquisitionError("Hugging Face LFS identity is invalid")
                sha256 = lfs["oid"].removeprefix("sha256:")
                if SHA256_RE.fullmatch(sha256) is None:
                    raise NativeModelAcquisitionError("Hugging Face LFS SHA-256 is invalid")
            seen.add(path)
            records.append({"path": path, "bytes": size, "sha256": sha256})
            if len(records) > MAX_FILES or sum(record["bytes"] for record in records) > MAX_TOTAL_BYTES:
                raise NativeModelAcquisitionError("Hugging Face snapshot exceeds its bound")
        url = _next_link(link)
    if not records or (filename is not None and {item["path"] for item in records} != {filename}):
        raise NativeModelAcquisitionError("Hugging Face snapshot is missing required files")
    return tuple(sorted(records, key=lambda item: item["path"]))


def _download(
    url: str,
    destination: pathlib.Path,
    *,
    expected_bytes: int,
    expected_sha256: str | None,
) -> None:
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.incoming")
    if temporary.exists():
        temporary.unlink()
    digest = hashlib.sha256()
    total = 0
    try:
        with urllib.request.urlopen(_request(url), timeout=60) as response, temporary.open(
            "xb"
        ) as handle:
            final = urllib.parse.urlsplit(response.geturl())
            if final.scheme != "https":
                raise NativeModelAcquisitionError("model download left HTTPS")
            while True:
                chunk = response.read(4 << 20)
                if not chunk:
                    break
                total += len(chunk)
                if total > expected_bytes:
                    raise NativeModelAcquisitionError("model file exceeds its declared size")
                digest.update(chunk)
                handle.write(chunk)
            handle.flush()
            os.fsync(handle.fileno())
        if total != expected_bytes:
            raise NativeModelAcquisitionError("model file size does not match metadata")
        if expected_sha256 is not None and digest.hexdigest() != expected_sha256:
            raise NativeModelAcquisitionError("model file SHA-256 does not match metadata")
        temporary.chmod(0o600)
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)


def acquire_snapshot(
    repository: str,
    revision: str,
    destination: pathlib.Path,
    *,
    filename: str | None = None,
    expected_file_sha256: str | None = None,
    progress: Callable[[str], None] | None = None,
) -> None:
    """Materialize one exact snapshot without executing repository code."""

    records = snapshot_files(repository, revision, filename=filename)
    if destination.exists():
        raise NativeModelAcquisitionError("model acquisition destination already exists")
    destination.mkdir(mode=0o700, parents=True)
    try:
        for record in records:
            if progress is not None:
                progress(str(record["path"]))
            expected = record["sha256"]
            if filename is not None and expected_file_sha256 is not None:
                if expected is not None and expected != expected_file_sha256:
                    raise NativeModelAcquisitionError(
                        "runtime model SHA-256 differs from Hugging Face metadata"
                    )
                expected = expected_file_sha256
            path = "/".join(
                urllib.parse.quote(part, safe="")
                for part in pathlib.PurePosixPath(record["path"]).parts
            )
            url = (
                f"https://huggingface.co/{repository}/resolve/{revision}/{path}"
                "?download=true"
            )
            _download(
                url,
                destination.joinpath(*pathlib.PurePosixPath(record["path"]).parts),
                expected_bytes=int(record["bytes"]),
                expected_sha256=expected,
            )
    except BaseException:
        for path in sorted(destination.rglob("*"), reverse=True):
            if path.is_file():
                path.unlink()
            elif path.is_dir():
                path.rmdir()
        destination.rmdir()
        raise
