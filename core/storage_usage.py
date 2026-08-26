#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Fail-closed accounting and cleanup for Let's Infer-owned local storage."""

from __future__ import annotations

import contextlib
import dataclasses
import fcntl
import json
import os
import pathlib
import re
import shutil
import stat
import tempfile
import threading
import time
import uuid
from collections.abc import Iterable, Iterator, Mapping, Sequence
from typing import Any


SCHEMA_VERSION = 1
CATEGORY_ORDER = (
    "models",
    "runtimes",
    "caches",
    "benchmarks",
    "engines",
    "core",
    "state",
    "configuration",
    "logs",
)
CATEGORY_LABELS = {
    "models": "Models",
    "runtimes": "Runtimes",
    "caches": "Caches",
    "benchmarks": "Benchmarks",
    "engines": "OCI metadata",
    "core": "Core versions",
    "state": "State",
    "configuration": "Configuration",
    "logs": "Logs",
}
RECLAIMABLE_CATEGORIES = frozenset({"models", "caches", "benchmarks"})
IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class StorageUsageError(RuntimeError):
    """Storage cannot be measured or removed without crossing an ownership boundary."""


@dataclasses.dataclass(frozen=True)
class TreeUsage:
    allocated_bytes: int
    logical_bytes: int
    files: int

    def __add__(self, other: "TreeUsage") -> "TreeUsage":
        return TreeUsage(
            self.allocated_bytes + other.allocated_bytes,
            self.logical_bytes + other.logical_bytes,
            self.files + other.files,
        )


EMPTY_USAGE = TreeUsage(0, 0, 0)


@dataclasses.dataclass(frozen=True)
class CleanupCandidate:
    category: str
    path: pathlib.Path
    allowed_root: pathlib.Path
    usage: TreeUsage
    reason: str
    models: tuple[str, ...]
    device: int
    inode: int

    def document(self, home: pathlib.Path) -> dict[str, Any]:
        return {
            "category": self.category,
            "path": str(self.path.relative_to(home)),
            "allocated_bytes": self.usage.allocated_bytes,
            "logical_bytes": self.usage.logical_bytes,
            "files": self.usage.files,
            "reason": self.reason,
            "models": list(self.models),
            "download_again_before_start": bool(self.models),
        }


@dataclasses.dataclass(frozen=True)
class RuntimeStorageReference:
    model: str
    model_paths: tuple[pathlib.Path, ...]
    cache_paths: tuple[pathlib.Path, ...]
    active: bool


_THREAD_LOCK = threading.RLock()
_LOCK_DEPTH = threading.local()


def _private_directory(path: pathlib.Path) -> None:
    if path.is_symlink():
        raise StorageUsageError(f"storage directory cannot be a symlink: {path}")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    details = path.stat()
    if not stat.S_ISDIR(details.st_mode) or details.st_uid != os.getuid():
        raise StorageUsageError(
            f"storage directory must be private and user-owned: {path}"
        )
    path.chmod(0o700)


@contextlib.contextmanager
def storage_lock(home: pathlib.Path) -> Iterator[None]:
    """Serialize cleanup with model acquisition and local Engine startup."""

    home = pathlib.Path(os.path.abspath(home.expanduser()))
    with _THREAD_LOCK:
        depth = int(getattr(_LOCK_DEPTH, "value", 0))
        if depth:
            _LOCK_DEPTH.value = depth + 1
            try:
                yield
            finally:
                _LOCK_DEPTH.value -= 1
            return
        lock_root = home / "state/storage"
        _private_directory(lock_root)
        path = lock_root / "usage.lock"
        descriptor = os.open(
            path,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            details = os.fstat(descriptor)
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_uid != os.getuid()
                or stat.S_IMODE(details.st_mode) != 0o600
            ):
                raise StorageUsageError(
                    "storage cleanup lock must be private and user-owned"
                )
            with os.fdopen(descriptor, "r+", encoding="utf-8") as handle:
                descriptor = -1
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                _LOCK_DEPTH.value = 1
                try:
                    yield
                finally:
                    _LOCK_DEPTH.value = 0
        finally:
            if descriptor >= 0:
                os.close(descriptor)


def _allocated_bytes(details: os.stat_result) -> int:
    blocks = getattr(details, "st_blocks", None)
    return int(blocks) * 512 if isinstance(blocks, int) else int(details.st_size)


def tree_usage(path: pathlib.Path) -> TreeUsage:
    """Measure one tree without following symlinks or counting hard links twice."""

    if not path.exists() and not path.is_symlink():
        return EMPTY_USAGE
    stack = [path]
    seen: set[tuple[int, int]] = set()
    allocated = 0
    logical = 0
    files = 0
    while stack:
        current = stack.pop()
        try:
            details = current.lstat()
        except FileNotFoundError:
            continue
        identity = (int(details.st_dev), int(details.st_ino))
        if identity in seen:
            continue
        seen.add(identity)
        allocated += _allocated_bytes(details)
        logical += int(details.st_size)
        if stat.S_ISDIR(details.st_mode):
            try:
                with os.scandir(current) as entries:
                    stack.extend(pathlib.Path(entry.path) for entry in entries)
            except FileNotFoundError:
                continue
        else:
            files += 1
    return TreeUsage(allocated, logical, files)


def _absolute(path: pathlib.Path) -> pathlib.Path:
    return pathlib.Path(os.path.abspath(path.expanduser()))


def _contained(path: pathlib.Path, root: pathlib.Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _validate_candidate_tree(path: pathlib.Path, allowed_root: pathlib.Path) -> os.stat_result:
    path = _absolute(path)
    allowed_root = _absolute(allowed_root)
    if path == allowed_root.parent or not _contained(path, allowed_root):
        raise StorageUsageError(f"cleanup target escapes its owned root: {path}")
    current = allowed_root
    for part in path.relative_to(allowed_root).parts:
        current = current / part
        details = current.lstat()
        if stat.S_ISLNK(details.st_mode):
            raise StorageUsageError(f"cleanup target traverses a symlink: {current}")
    details = path.lstat()
    if not stat.S_ISDIR(details.st_mode) or details.st_uid != os.getuid():
        raise StorageUsageError(
            f"cleanup target must be a user-owned directory: {path}"
        )
    stack = [path]
    while stack:
        current = stack.pop()
        with os.scandir(current) as entries:
            for entry in entries:
                child = pathlib.Path(entry.path)
                child_details = entry.stat(follow_symlinks=False)
                mode = child_details.st_mode
                if child_details.st_uid != os.getuid():
                    raise StorageUsageError(
                        f"cleanup target contains data owned by another user: {child}"
                    )
                if stat.S_ISDIR(mode):
                    stack.append(child)
                elif not (stat.S_ISREG(mode) or stat.S_ISLNK(mode)):
                    raise StorageUsageError(
                        f"cleanup target contains an unsupported file type: {child}"
                    )
    return details


def cleanup_candidate(
    *,
    category: str,
    path: pathlib.Path,
    allowed_root: pathlib.Path,
    reason: str,
    models: Iterable[str] = (),
) -> CleanupCandidate:
    if category not in RECLAIMABLE_CATEGORIES:
        raise StorageUsageError(f"category is not reclaimable: {category}")
    path = _absolute(path)
    details = _validate_candidate_tree(path, allowed_root)
    return CleanupCandidate(
        category=category,
        path=path,
        allowed_root=_absolute(allowed_root),
        usage=tree_usage(path),
        reason=reason,
        models=tuple(sorted(set(models))),
        device=int(details.st_dev),
        inode=int(details.st_ino),
    )


def _children(path: pathlib.Path) -> tuple[pathlib.Path, ...]:
    if not path.exists():
        return ()
    details = path.lstat()
    if not stat.S_ISDIR(details.st_mode) or stat.S_ISLNK(details.st_mode):
        raise StorageUsageError(f"managed storage root is unsafe: {path}")
    with os.scandir(path) as entries:
        return tuple(
            sorted((pathlib.Path(item.path) for item in entries), key=str)
        )


def _related(left: pathlib.Path, right: pathlib.Path) -> bool:
    left = _absolute(left)
    right = _absolute(right)
    return left == right or _contained(left, right) or _contained(right, left)


def cleanup_plan(
    home: pathlib.Path,
    references: Sequence[RuntimeStorageReference],
    *,
    benchmark_roots: Sequence[pathlib.Path],
    benchmark_active: bool,
) -> tuple[CleanupCandidate, ...]:
    """Classify only exact inactive model/cache and completed benchmark trees."""

    home = _absolute(home)
    model_root = home / "models"
    cache = home / "cache"
    candidates: list[CleanupCandidate] = []
    model_references: dict[pathlib.Path, list[RuntimeStorageReference]] = {}
    for reference in references:
        for path in reference.model_paths:
            absolute = _absolute(path)
            if _contained(absolute, model_root):
                model_references.setdefault(absolute, []).append(reference)
    for owner in _children(model_root):
        if owner.is_symlink() or not owner.is_dir():
            continue
        for snapshot in _children(owner):
            if snapshot.is_symlink() or not snapshot.is_dir():
                continue
            related = [
                reference
                for path, values in model_references.items()
                if _related(snapshot, path)
                for reference in values
            ]
            if any(reference.active for reference in related):
                continue
            models = {reference.model for reference in related}
            reason = (
                "inactive model data; exact artifacts will be downloaded again before start"
                if models
                else "model data is not referenced by an installed local runtime"
            )
            candidates.append(
                cleanup_candidate(
                    category="models",
                    path=snapshot,
                    allowed_root=model_root,
                    reason=reason,
                    models=models,
                )
            )

    active_cache_paths = {
        _absolute(path)
        for reference in references
        if reference.active
        for path in reference.cache_paths
        if _contained(_absolute(path), cache)
    }
    cache_targets: list[pathlib.Path] = []
    for root in _children(cache):
        if root.is_symlink() or not root.is_dir():
            continue
        if root.name in {"prefix-store", "runtime"}:
            cache_targets.extend(
                child
                for child in _children(root)
                if child.is_dir() and not child.is_symlink()
            )
        else:
            cache_targets.append(root)
    for target in cache_targets:
        if any(_related(target, protected) for protected in active_cache_paths):
            continue
        candidates.append(
            cleanup_candidate(
                category="caches",
                path=target,
                allowed_root=cache,
                reason="rebuildable cache is not used by a running local runtime",
                models=(),
            )
        )

    if not benchmark_active:
        for root in benchmark_roots:
            absolute = _absolute(root)
            if not absolute.exists():
                continue
            allowed = home / ("benchmarks" if _contained(absolute, home / "benchmarks") else "state")
            candidates.append(
                cleanup_candidate(
                    category="benchmarks",
                    path=absolute,
                    allowed_root=allowed,
                    reason="completed local benchmark results and job logs",
                )
            )
    candidates.sort(key=lambda item: (CATEGORY_ORDER.index(item.category), str(item.path)))
    for index, left in enumerate(candidates):
        for right in candidates[index + 1 :]:
            if _related(left.path, right.path):
                raise StorageUsageError(
                    "cleanup plan contains overlapping targets: "
                    f"{left.path} and {right.path}"
                )
    return tuple(candidates)


def container_runtime_usage(
    run_command: Any,
    *,
    managed_label: str,
) -> dict[str, Any]:
    """Report exact managed-container writes and unique-image logical sizes."""

    listed = run_command(
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            f"label={managed_label}=true",
            "--format",
            "{{.ID}}",
        ],
        check=False,
    )
    if listed.returncode != 0:
        return {
            "available": False,
            "included_in_total": False,
            "managed_containers": 0,
            "writable_bytes": None,
            "image_logical_bytes": None,
            "reason": "container runtime usage is unavailable",
        }
    identifiers = tuple(
        line.strip() for line in listed.stdout.splitlines() if line.strip()
    )
    if any(not re.fullmatch(r"[0-9a-f]{12,64}", item) for item in identifiers):
        return {
            "available": False,
            "included_in_total": False,
            "managed_containers": 0,
            "writable_bytes": None,
            "image_logical_bytes": None,
            "reason": "container runtime returned an invalid managed identity",
        }
    if not identifiers:
        return {
            "available": True,
            "included_in_total": False,
            "managed_containers": 0,
            "writable_bytes": 0,
            "image_logical_bytes": 0,
            "reason": "shared image layers are reported separately and never pruned",
        }
    inspected = run_command(
        ["docker", "container", "inspect", "--size", *identifiers],
        check=False,
    )
    if inspected.returncode != 0:
        return {
            "available": False,
            "included_in_total": False,
            "managed_containers": len(identifiers),
            "writable_bytes": None,
            "image_logical_bytes": None,
            "reason": "managed container sizes are unavailable",
        }
    try:
        containers = json.loads(inspected.stdout)
    except json.JSONDecodeError:
        containers = None
    if not isinstance(containers, list) or any(
        not isinstance(item, dict) for item in containers
    ):
        return {
            "available": False,
            "included_in_total": False,
            "managed_containers": len(identifiers),
            "writable_bytes": None,
            "image_logical_bytes": None,
            "reason": "managed container size response is invalid",
        }
    writable = 0
    images: set[str] = set()
    for item in containers:
        labels = item.get("Config", {}).get("Labels") or {}
        size = item.get("SizeRw")
        image = item.get("Image")
        if (
            labels.get(managed_label) != "true"
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or not isinstance(image, str)
            or not IMAGE_ID_RE.fullmatch(image)
        ):
            return {
                "available": False,
                "included_in_total": False,
                "managed_containers": len(identifiers),
                "writable_bytes": None,
                "image_logical_bytes": None,
                "reason": "managed container ownership or size is invalid",
            }
        writable += size
        images.add(image)
    image_bytes = 0
    if images:
        image_result = run_command(
            ["docker", "image", "inspect", *sorted(images)], check=False
        )
        if image_result.returncode != 0:
            return {
                "available": False,
                "included_in_total": False,
                "managed_containers": len(identifiers),
                "writable_bytes": writable,
                "image_logical_bytes": None,
                "reason": "managed Engine image sizes are unavailable",
            }
        try:
            image_records = json.loads(image_result.stdout)
        except json.JSONDecodeError:
            image_records = None
        if not isinstance(image_records, list) or any(
            not isinstance(item, dict)
            or not isinstance(item.get("Size"), int)
            or isinstance(item.get("Size"), bool)
            or item["Size"] < 0
            for item in image_records
        ):
            return {
                "available": False,
                "included_in_total": False,
                "managed_containers": len(identifiers),
                "writable_bytes": writable,
                "image_logical_bytes": None,
                "reason": "managed Engine image size response is invalid",
            }
        image_bytes = sum(int(item["Size"]) for item in image_records)
    return {
        "available": True,
        "included_in_total": False,
        "managed_containers": len(identifiers),
        "writable_bytes": writable,
        "image_logical_bytes": image_bytes,
        "reason": (
            "image size is logical and may share layers; container storage is "
            "never included in reclaimable bytes or pruned"
        ),
    }


def managed_container_running(
    run_command: Any,
    name: str,
    *,
    managed_label: str,
) -> bool:
    """Distinguish an absent container from an unavailable Docker authority."""

    result = run_command(["docker", "container", "inspect", name], check=False)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip().lower()
        if "no such object" in detail or "no such container" in detail:
            return False
        raise StorageUsageError(
            "cannot determine whether managed container "
            f"{name} is active; cleanup is disabled"
        )
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise StorageUsageError(
            f"cannot decode managed container state for {name}"
        ) from error
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise StorageUsageError(f"managed container state is invalid for {name}")
    labels = value[0].get("Config", {}).get("Labels") or {}
    if labels.get(managed_label) != "true":
        raise StorageUsageError(
            f"container {name} is not owned by Let’s Infer; cleanup is disabled"
        )
    return value[0].get("State", {}).get("Running") is True


def format_bytes(value: int) -> str:
    """Render compact binary units without implying SI disk accounting."""

    amount = float(max(0, value))
    units = ("B", "K", "M", "G", "T", "P")
    unit = units[0]
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            break
        amount /= 1024
    if unit == "B":
        return f"{int(amount)} {unit}"
    return f"{amount:.1f} {unit}"


def _category_roots(home: pathlib.Path) -> Mapping[str, tuple[pathlib.Path, ...]]:
    return {
        "models": (home / "models",),
        "runtimes": (home / "runtimes",),
        "caches": (home / "cache",),
        "benchmarks": (home / "benchmarks",),
        "engines": (home / "oci",),
        "core": (home / "core",),
        "state": (home / "state",),
        "configuration": (home / "config", home / "secrets"),
        "logs": (home / "logs",),
    }


def usage_report(
    home: pathlib.Path,
    candidates: Sequence[CleanupCandidate],
) -> dict[str, Any]:
    home = _absolute(home)
    roots = _category_roots(home)
    categories: list[dict[str, Any]] = []
    total = EMPTY_USAGE
    for category in CATEGORY_ORDER:
        usage = EMPTY_USAGE
        for root in roots[category]:
            usage += tree_usage(root)
        reclaimable = sum(
            item.usage.allocated_bytes
            for item in candidates
            if item.category == category
        )
        categories.append(
            {
                "id": category,
                "label": CATEGORY_LABELS[category],
                "allocated_bytes": usage.allocated_bytes,
                "logical_bytes": usage.logical_bytes,
                "files": usage.files,
                "reclaimable_bytes": reclaimable,
                "reclaimable_items": sum(
                    1 for item in candidates if item.category == category
                ),
            }
        )
        total += usage
    existing = home
    while not existing.exists() and existing != existing.parent:
        existing = existing.parent
    disk = shutil.disk_usage(existing)
    return {
        "schema_version": SCHEMA_VERSION,
        "home": str(home),
        "filesystem": {
            "total_bytes": disk.total,
            "used_bytes": disk.used,
            "free_bytes": disk.free,
        },
        "total_allocated_bytes": total.allocated_bytes,
        "total_logical_bytes": total.logical_bytes,
        "total_reclaimable_bytes": sum(
            item.usage.allocated_bytes for item in candidates
        ),
        "categories": categories,
        "candidates": [item.document(home) for item in candidates],
        "container_runtime": {
            "included": False,
            "reason": (
                "Docker and other Engine stores may share layers with non-Let's Infer "
                "workloads; node usage never estimates or prunes shared storage"
            ),
        },
    }


def _write_receipt(path: pathlib.Path, value: Mapping[str, Any]) -> None:
    _private_directory(path.parent)
    payload = (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")
    with tempfile.NamedTemporaryFile(
        prefix=f".{path.name}.", dir=path.parent, delete=False
    ) as handle:
        temporary = pathlib.Path(handle.name)
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    temporary.chmod(0o600)
    temporary.replace(path)
    descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def execute_cleanup(
    home: pathlib.Path,
    candidates: Sequence[CleanupCandidate],
) -> dict[str, Any]:
    """Remove an already reviewed plan and durably record every completed item."""

    home = _absolute(home)
    cleanup_id = uuid.uuid4().hex
    receipt_path = home / "state/storage/cleanups" / f"{cleanup_id}.json"
    receipt: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "cleanup_id": cleanup_id,
        "state": "running",
        "started_at_unix_ns": time.time_ns(),
        "finished_at_unix_ns": None,
        "requested": [item.document(home) for item in candidates],
        "removed": [],
        "error": None,
    }
    _write_receipt(receipt_path, receipt)
    try:
        for item in candidates:
            details = _validate_candidate_tree(item.path, item.allowed_root)
            if (int(details.st_dev), int(details.st_ino)) != (
                item.device,
                item.inode,
            ):
                raise StorageUsageError(
                    f"cleanup target changed after review: {item.path}"
                )
            shutil.rmtree(item.path)
            parent_descriptor = os.open(item.path.parent, os.O_RDONLY)
            try:
                os.fsync(parent_descriptor)
            finally:
                os.close(parent_descriptor)
            receipt["removed"].append(item.document(home))
            _write_receipt(receipt_path, receipt)
    except BaseException as error:
        receipt["state"] = "failed"
        receipt["finished_at_unix_ns"] = time.time_ns()
        receipt["error"] = type(error).__name__
        _write_receipt(receipt_path, receipt)
        raise
    receipt["state"] = "completed"
    receipt["finished_at_unix_ns"] = time.time_ns()
    _write_receipt(receipt_path, receipt)
    return {
        "cleanup_id": cleanup_id,
        "receipt": str(receipt_path),
        "removed": list(receipt["removed"]),
        "removed_allocated_bytes": sum(
            int(item["allocated_bytes"]) for item in receipt["removed"]
        ),
        "models_to_download_again": sorted(
            {
                model
                for item in receipt["removed"]
                for model in item["models"]
            }
        ),
    }
