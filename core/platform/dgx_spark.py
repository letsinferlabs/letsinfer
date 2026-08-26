#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Isolated DGX Spark network-plan provider for generic Core setup."""

from __future__ import annotations

import json
import pathlib
import subprocess
from collections.abc import Mapping, Sequence


CONNECTX_INTERFACES = ("enp1s0f0np0", "enp1s0f1np1")


def _release_values(path: pathlib.Path) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return {}
    result: dict[str, str] = {}
    for line in lines:
        key, separator, value = line.partition("=")
        if separator and key:
            result[key] = value.strip().strip('"')
    return result


def _interface_addresses() -> dict[str, tuple[str, ...]]:
    try:
        completed = subprocess.run(
            ["ip", "-json", "address", "show"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        rows = json.loads(completed.stdout) if completed.returncode == 0 else []
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        rows = []
    result: dict[str, tuple[str, ...]] = {}
    for row in rows if isinstance(rows, list) else ():
        if not isinstance(row, dict) or not isinstance(row.get("ifname"), str):
            continue
        values = tuple(
            str(item["local"])
            for item in row.get("addr_info", ())
            if isinstance(item, dict) and isinstance(item.get("local"), str)
        )
        result[row["ifname"]] = values
    return result


def network_plan(
    *,
    etc_root: pathlib.Path = pathlib.Path("/etc"),
    sys_class: pathlib.Path = pathlib.Path("/sys/class"),
    require_live: bool = True,
    addresses: Mapping[str, Sequence[str]] | None = None,
):
    """Return the Spark provider's plan, or None when it does not apply."""

    if _release_values(etc_root / "dgx-release").get("DGX_PLATFORM") != "GX10":
        return None
    if (etc_root / "netplan/99-nvidia-sync-cluster.yaml").exists():
        return None
    present = tuple(
        name for name in CONNECTX_INTERFACES if (sys_class / "net" / name).is_dir()
    )
    if present != CONNECTX_INTERFACES:
        return None
    if require_live:
        live = tuple(
            name
            for name in present
            if _read_integer(sys_class / "net" / name / "carrier") == 1
        )
        if not live:
            return None
        observed = addresses if addresses is not None else _interface_addresses()
        if all(tuple(observed.get(name, ())) for name in live):
            return None

    # Imported lazily to keep provider selection free of module cycles.
    from .network import NetworkPlan

    return NetworkPlan(
        provider="nvidia-dgx-spark-connectx-v1",
        backend="networkmanager",
        interfaces=CONNECTX_INTERFACES,
        settings=(
            ("ipv4.method", "link-local"),
            ("ipv6.method", "disabled"),
        ),
    )


def _read_integer(path: pathlib.Path) -> int:
    try:
        return int(path.read_text(encoding="ascii").strip())
    except (OSError, UnicodeError, ValueError):
        return -1
