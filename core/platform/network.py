#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Generic privileged network-plan boundary with isolated platform providers."""

from __future__ import annotations

import argparse
import dataclasses
import json
import pathlib
import re
import subprocess
import sys
from collections.abc import Callable, Sequence


ID_RE = re.compile(r"^[a-z][a-z0-9.-]{0,63}$")
INTERFACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
SETTING_RE = re.compile(r"^[a-z][a-z0-9.-]{0,63}$")
VALUE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
Runner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]


class NetworkPlanError(RuntimeError):
    """A detected platform network plan cannot be applied safely."""


@dataclasses.dataclass(frozen=True)
class NetworkPlan:
    provider: str
    backend: str
    interfaces: tuple[str, ...]
    settings: tuple[tuple[str, str], ...]

    def validate(self) -> None:
        if not ID_RE.fullmatch(self.provider) or self.backend != "networkmanager":
            raise NetworkPlanError("platform network provider identity is invalid")
        if (
            not self.interfaces
            or len(self.interfaces) != len(set(self.interfaces))
            or any(not INTERFACE_RE.fullmatch(value) for value in self.interfaces)
        ):
            raise NetworkPlanError("platform network interfaces are invalid")
        if (
            not self.settings
            or len(self.settings) != len({key for key, _value in self.settings})
            or {key for key, _value in self.settings}
            != {"ipv4.method", "ipv6.method"}
            or any(
                not SETTING_RE.fullmatch(key) or not VALUE_RE.fullmatch(value)
                for key, value in self.settings
            )
        ):
            raise NetworkPlanError("platform network settings are invalid")


def host_network_plan(
    *,
    require_live: bool = True,
    etc_root: pathlib.Path = pathlib.Path("/etc"),
    sys_class: pathlib.Path = pathlib.Path("/sys/class"),
) -> NetworkPlan | None:
    """Select at most one isolated provider for the current host."""

    from . import dgx_spark

    values = [
        value
        for value in (
            dgx_spark.network_plan(
                etc_root=etc_root,
                sys_class=sys_class,
                require_live=require_live,
            ),
        )
        if value is not None
    ]
    if len(values) > 1:
        raise NetworkPlanError("multiple platform network providers matched this host")
    if not values:
        return None
    values[0].validate()
    return values[0]


def _default_runner(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        check=False,
        capture_output=True,
        text=True,
    )


def _run(
    runner: Runner,
    command: Sequence[str],
    *,
    expected: frozenset[int] = frozenset({0}),
) -> subprocess.CompletedProcess[str]:
    completed = runner(tuple(command))
    if completed.returncode not in expected:
        detail = (completed.stderr or completed.stdout).strip() or "command failed"
        raise NetworkPlanError(f"{' '.join(command)}: {detail}")
    return completed


def apply_network_plan(
    plan: NetworkPlan,
    *,
    runner: Runner = _default_runner,
    sys_class: pathlib.Path = pathlib.Path("/sys/class"),
) -> dict[str, object]:
    """Apply one approved provider plan without overwriting external ownership."""

    plan.validate()
    profile_ids = tuple(
        value
        for value in _run(
            runner,
            ("nmcli", "-t", "-f", "UUID", "connection", "show"),
        ).stdout.splitlines()
        if UUID_RE.fullmatch(value)
    )
    profiles: dict[str, tuple[str, str, str]] = {}
    for identifier in profile_ids:
        fields = _run(
            runner,
            (
                "nmcli", "-g", "connection.interface-name,ipv4.method,ipv6.method",
                "connection", "show", identifier,
            ),
        ).stdout.splitlines()
        if len(fields) != 3 or fields[0] not in plan.interfaces:
            continue
        if fields[0] in profiles:
            raise NetworkPlanError(
                f"multiple network profiles own interface {fields[0]}"
            )
        profiles[fields[0]] = (identifier, fields[1], fields[2])
    if set(profiles) != set(plan.interfaces):
        raise NetworkPlanError("platform network profiles are incomplete")

    desired = dict(plan.settings)
    if all(
        ipv4 == desired["ipv4.method"] and ipv6 == desired["ipv6.method"]
        for _identifier, ipv4, ipv6 in profiles.values()
    ):
        return {"provider": plan.provider, "state": "configured"}
    if any(
        ipv4 not in {"auto", "disabled", desired["ipv4.method"]}
        or ipv6 not in {"auto", "disabled", desired["ipv6.method"]}
        for _identifier, ipv4, ipv6 in profiles.values()
    ):
        return {"provider": plan.provider, "state": "externally-managed"}

    changed: list[tuple[str, str, str, str]] = []
    try:
        for interface in plan.interfaces:
            identifier, ipv4, ipv6 = profiles[interface]
            _run(
                runner,
                (
                    "sudo", "nmcli", "connection", "modify", identifier,
                    "ipv4.method", desired["ipv4.method"],
                    "ipv6.method", desired["ipv6.method"],
                ),
            )
            changed.append((interface, identifier, ipv4, ipv6))
        for interface, identifier, _ipv4, _ipv6 in changed:
            if _read_carrier(sys_class / "net" / interface / "carrier") == 1:
                _run(
                    runner,
                    ("sudo", "nmcli", "connection", "up", identifier, "ifname", interface),
                )
    except NetworkPlanError as failure:
        for interface, identifier, ipv4, ipv6 in reversed(changed):
            _run(
                runner,
                (
                    "sudo", "nmcli", "connection", "modify", identifier,
                    "ipv4.method", ipv4, "ipv6.method", ipv6,
                ),
                expected=frozenset({0, 1, 2, 4, 10}),
            )
            if _read_carrier(sys_class / "net" / interface / "carrier") == 1:
                _run(
                    runner,
                    ("sudo", "nmcli", "connection", "up", identifier, "ifname", interface),
                    expected=frozenset({0, 1, 2, 4, 10}),
                )
        raise NetworkPlanError(
            "platform network configuration failed and was rolled back"
        ) from failure
    return {
        "provider": plan.provider,
        "state": "configured",
        "interfaces": list(plan.interfaces),
    }


def _read_carrier(path: pathlib.Path) -> int:
    try:
        return int(path.read_text(encoding="ascii").strip())
    except (OSError, UnicodeError, ValueError):
        return -1


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="letsinfer-platform-network")
    parser.add_argument("operation", choices=("apply-if-detected",))
    arguments = parser.parse_args(argv)
    plan = host_network_plan(require_live=False)
    result = (
        {"state": "not-applicable"}
        if plan is None
        else apply_network_plan(plan)
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
