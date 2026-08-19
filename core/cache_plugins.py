# SPDX-License-Identifier: AGPL-3.0-only
"""Core-owned, reproducible cache plugins installed beside engine runtimes."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import tempfile
from collections.abc import Callable, Sequence
from typing import Any


SGLANG_CACHE_BUILDER_IMAGE = (
    "ghcr.io/pyo3/maturin@sha256:"
    "b6c8b59a0170b77eb31a35b56034abd39972483ad0ebfff344deaa42a85f3bd3"
)
SGLANG_CACHE_SOURCE_DATE_EPOCH = 1785594180
DESCRIPTOR_NAME = "LETSINFER-CACHE-PLUGIN.json"


class CachePluginError(RuntimeError):
    """A core cache plugin is absent, corrupt, or unreproducible."""


def _sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def _sources(source_root: pathlib.Path) -> list[tuple[str, pathlib.Path]]:
    crate = source_root / "cache/letsinfer_prefix_store"
    connector = source_root / "connectors/letsinfer_sglang_cache"
    paths = [crate / "Cargo.toml", crate / "Cargo.lock"]
    paths.extend(sorted((crate / "src").glob("*.rs")))
    paths.extend([connector / "__init__.py", connector / "backend.py"])
    rows = []
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise CachePluginError(f"core cache source is missing or unsafe: {path}")
        rows.append((path.relative_to(source_root).as_posix(), path))
    return rows


def source_identity(source_root: pathlib.Path) -> str:
    rows = [{"path": name, "sha256": _sha256(path)} for name, path in _sources(source_root)]
    return hashlib.sha256(_canonical(rows)).hexdigest()


def verify_sglang_plugin(
    plugin_root: pathlib.Path,
    *,
    source_root: pathlib.Path,
    core_version: str,
) -> dict[str, Any]:
    descriptor_path = plugin_root / DESCRIPTOR_NAME
    if plugin_root.is_symlink() or descriptor_path.is_symlink() or not descriptor_path.is_file():
        raise CachePluginError("SGLang core cache plugin is not installed")
    try:
        descriptor = json.loads(descriptor_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise CachePluginError(f"cannot read SGLang cache plugin descriptor: {error}") from error
    if set(descriptor) != {
        "schema_version",
        "core_version",
        "source_identity",
        "builder_image",
        "artifacts",
    }:
        raise CachePluginError("SGLang cache plugin descriptor has unknown fields")
    if (
        descriptor["schema_version"] != 1
        or descriptor["core_version"] != core_version
        or descriptor["source_identity"] != source_identity(source_root)
        or descriptor["builder_image"] != SGLANG_CACHE_BUILDER_IMAGE
    ):
        raise CachePluginError("SGLang cache plugin identity is stale")
    artifacts = descriptor["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) != 3:
        raise CachePluginError("SGLang cache plugin artifact set is invalid")
    expected_names = {
        "letsinfer_sglang_cache/__init__.py",
        "letsinfer_sglang_cache/backend.py",
    }
    wheel_count = 0
    allowed = {DESCRIPTOR_NAME}
    for row in artifacts:
        if not isinstance(row, dict) or set(row) != {"path", "sha256"}:
            raise CachePluginError("SGLang cache plugin artifact entry is invalid")
        relative = pathlib.PurePosixPath(row["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise CachePluginError("SGLang cache plugin path is unsafe")
        path = plugin_root.joinpath(*relative.parts)
        if path.is_symlink() or not path.is_file() or _sha256(path) != row["sha256"]:
            raise CachePluginError(f"SGLang cache plugin artifact is corrupt: {relative}")
        allowed.add(relative.as_posix())
        if relative.suffix == ".whl":
            wheel_count += 1
        else:
            expected_names.discard(relative.as_posix())
    if wheel_count != 1 or expected_names:
        raise CachePluginError("SGLang cache plugin artifact set is incomplete")
    actual = {
        path.relative_to(plugin_root).as_posix()
        for path in plugin_root.rglob("*")
        if path.is_file()
    }
    if actual != allowed:
        raise CachePluginError("SGLang cache plugin contains untracked files")
    return descriptor


def install_sglang_plugin(
    plugin_root: pathlib.Path,
    *,
    source_root: pathlib.Path,
    core_version: str,
    platform: str,
    run: Callable[[Sequence[str]], None],
    store: Callable[[pathlib.Path, str], pathlib.Path],
) -> dict[str, Any]:
    """Build once from signed core source, dedupe by digest, and atomically install."""
    identity = source_identity(source_root)
    plugin_root.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="letsinfer-sglang-cache-") as temporary_value:
        temporary = pathlib.Path(temporary_value)
        crate_source = source_root / "cache/letsinfer_prefix_store"
        build_source = temporary / "source"
        build_output = temporary / "output"
        shutil.copytree(crate_source, build_source, ignore=shutil.ignore_patterns("target", "dist"))
        build_output.mkdir()
        run(
            [
                "docker",
                "run",
                "--rm",
                "--pull",
                "missing",
                "--platform",
                platform,
                "-e",
                f"SOURCE_DATE_EPOCH={SGLANG_CACHE_SOURCE_DATE_EPOCH}",
                "-e",
                "RUSTFLAGS=--remap-path-prefix=/io=letsinfer_prefix_store",
                "-e",
                "CARGO_TARGET_DIR=/tmp/target",
                "-v",
                f"{build_source}:/io:ro",
                "-v",
                f"{build_output}:/output",
                SGLANG_CACHE_BUILDER_IMAGE,
                "build",
                "--release",
                "--locked",
                "--features",
                "python",
                "--compatibility",
                "manylinux_2_34",
                "--out",
                "/output",
            ]
        )
        wheels = list(build_output.glob("*.whl"))
        if len(wheels) != 1:
            raise CachePluginError("SGLang cache build did not produce exactly one wheel")

        staging = pathlib.Path(
            tempfile.mkdtemp(prefix=f".{plugin_root.name}.install-", dir=plugin_root.parent)
        )
        backup = plugin_root.with_name(f".{plugin_root.name}.previous-{os.getpid()}")
        moved = False
        try:
            artifact_sources = [
                (
                    "letsinfer_sglang_cache/__init__.py",
                    source_root / "connectors/letsinfer_sglang_cache/__init__.py",
                ),
                (
                    "letsinfer_sglang_cache/backend.py",
                    source_root / "connectors/letsinfer_sglang_cache/backend.py",
                ),
                (wheels[0].name, wheels[0]),
            ]
            artifacts = []
            for relative, source in artifact_sources:
                digest = _sha256(source)
                shared = store(source, digest)
                destination = staging / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(shared, destination)
                artifacts.append({"path": relative, "sha256": digest})
            descriptor = {
                "schema_version": 1,
                "core_version": core_version,
                "source_identity": identity,
                "builder_image": SGLANG_CACHE_BUILDER_IMAGE,
                "artifacts": artifacts,
            }
            (staging / DESCRIPTOR_NAME).write_bytes(_canonical(descriptor))
            if backup.exists():
                raise CachePluginError(f"stale cache plugin backup exists: {backup}")
            if plugin_root.exists():
                plugin_root.replace(backup)
                moved = True
            staging.replace(plugin_root)
            plugin_root.chmod(0o700)
            if moved:
                shutil.rmtree(backup)
            return verify_sglang_plugin(
                plugin_root, source_root=source_root, core_version=core_version
            )
        except BaseException:
            shutil.rmtree(staging, ignore_errors=True)
            if moved and backup.exists() and not plugin_root.exists():
                backup.replace(plugin_root)
            raise
