#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Canonical user-owned storage paths for Let's Infer."""

from __future__ import annotations

import os
import pathlib
import stat


HOME_ENV = "LETSINFER_HOME"
HOME_DEFAULTED_ENV = "LETSINFER_HOME_DEFAULTED"
CONFIG_ENV = "LETSINFER_CONFIG_HOME"
DATA_ENV = "LETSINFER_DATA_HOME"
RUNTIME_ENV = "LETSINFER_RUNTIME_HOME"
MODELS_ENV = "LETSINFER_MODELS_HOME"


class PathContractError(RuntimeError):
    """A configured Let's Infer storage root is unsafe."""


def _environment_path(name: str) -> pathlib.Path | None:
    value = os.environ.get(name)
    if value is None:
        return None
    if not value.strip():
        raise PathContractError(f"{name} cannot be empty")
    path = pathlib.Path(value).expanduser()
    if not path.is_absolute():
        raise PathContractError(f"{name} must be an absolute path")
    if path in {pathlib.Path("/"), pathlib.Path.home()}:
        raise PathContractError(f"{name} is too broad: {path}")
    return path


def home_root() -> pathlib.Path:
    """Return the one user-owned Let's Infer home."""

    root = _environment_path(HOME_ENV) or pathlib.Path.home() / ".local/share/letsinfer"
    if root in {pathlib.Path("/"), pathlib.Path.home()}:
        raise PathContractError(f"{HOME_ENV} is too broad: {root}")
    return root


def config_root() -> pathlib.Path:
    # Narrow legacy overrides remain useful for isolated tests and managed
    # deployments. LETSINFER_HOME owns the ordinary installation contract.
    override = _environment_path(CONFIG_ENV)
    if override is not None:
        return override
    current = home_root() / "config"
    legacy = pathlib.Path.home() / ".config" / "letsinfer"
    defaulted = os.environ.get(HOME_DEFAULTED_ENV) == "1" or HOME_ENV not in os.environ
    if (
        defaulted
        and (legacy / "site.json").is_file()
        and not (current / "site.json").exists()
    ):
        return legacy
    return current


def data_root() -> pathlib.Path:
    override = _environment_path(DATA_ENV)
    if override is not None:
        return override
    current = home_root() / "state"
    legacy = home_root()
    defaulted = os.environ.get(HOME_DEFAULTED_ENV) == "1" or HOME_ENV not in os.environ
    if (
        defaulted
        and (legacy / "site.sqlite3").is_file()
        and not (current / "site.sqlite3").exists()
    ):
        return legacy
    return current


def runtime_root() -> pathlib.Path:
    return _environment_path(RUNTIME_ENV) or home_root() / "runtimes"


def models_root() -> pathlib.Path:
    return _environment_path(MODELS_ENV) or home_root() / "models"


def cache_root() -> pathlib.Path:
    return home_root() / "cache"


def benchmarks_root() -> pathlib.Path:
    return home_root() / "benchmarks"


def evidence_root() -> pathlib.Path:
    return home_root() / "evidence"


def logs_root() -> pathlib.Path:
    return home_root() / "logs"


def managed_roots() -> tuple[pathlib.Path, ...]:
    return (
        config_root(),
        data_root(),
        runtime_root(),
        models_root(),
        cache_root(),
        benchmarks_root(),
        evidence_root(),
        logs_root(),
    )


def ensure_private_directory(path: pathlib.Path) -> pathlib.Path:
    if path.is_symlink():
        raise PathContractError(f"Let's Infer directory cannot be a symlink: {path}")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    details = path.stat()
    if not stat.S_ISDIR(details.st_mode) or details.st_uid != os.getuid():
        raise PathContractError(
            f"Let's Infer directory must be owned by the current user: {path}"
        )
    path.chmod(0o700)
    return path


def ensure_home() -> pathlib.Path:
    root = ensure_private_directory(home_root())
    for path in managed_roots():
        ensure_private_directory(path)
    return root
