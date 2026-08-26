#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Authenticated member facts, topology graphs, and target placement."""

from __future__ import annotations

import dataclasses
import hashlib
import ipaddress
import json
import math
import re
import time
from collections import deque
from collections.abc import Mapping, Sequence
from typing import Any

from ..state_plane import member_available


ID_RE = re.compile(r"^[0-9a-f]{32}$")
SAFE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
INTERFACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,31}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_FACT_AGE_SECONDS = 30


class TopologyError(ValueError):
    """Topology facts or a requested placement are unsafe or ambiguous."""


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _positive(value: Any, where: str, *, allow_zero: bool = False) -> int:
    minimum = 0 if allow_zero else 1
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise TopologyError(f"{where} must be {'non-negative' if allow_zero else 'positive'}")
    return value


def validate_member_facts(value: Any, where: str = "member facts") -> dict[str, Any]:
    required = {
        "schema_version", "member_id", "observed_at_unix", "platform", "accelerator",
        "memory", "storage", "network", "software", "health",
    }
    if (
        not isinstance(value, dict)
        or set(value) not in (required, required | {"inventory"})
        or type(value.get("schema_version")) is not int
        or value.get("schema_version") != 1
    ):
        raise TopologyError(f"{where} has an unsupported schema")
    if not isinstance(value.get("member_id"), str) or not ID_RE.fullmatch(value["member_id"]):
        raise TopologyError(f"{where}.member_id is invalid")
    _positive(value.get("observed_at_unix"), f"{where}.observed_at_unix")
    if not isinstance(value.get("platform"), str) or not re.fullmatch(r"[a-z0-9._-]+/[a-z0-9._-]+", value["platform"]):
        raise TopologyError(f"{where}.platform must be os/architecture")

    accelerator = value.get("accelerator")
    if not isinstance(accelerator, dict) or set(accelerator) != {
        "vendor", "architecture", "count", "partitioning", "minimum_memory_gib", "devices"
    }:
        raise TopologyError(f"{where}.accelerator has invalid fields")
    for key in ("vendor", "architecture"):
        if not isinstance(accelerator[key], str) or not SAFE_RE.fullmatch(accelerator[key]):
            raise TopologyError(f"{where}.accelerator.{key} is invalid")
    count = _positive(accelerator["count"], f"{where}.accelerator.count")
    if accelerator["partitioning"] not in {"full-device", "mig"}:
        raise TopologyError(f"{where}.accelerator.partitioning is invalid")
    _positive(accelerator["minimum_memory_gib"], f"{where}.accelerator.minimum_memory_gib")
    devices = accelerator["devices"]
    if not isinstance(devices, list) or len(devices) != count or not all(isinstance(item, str) and item for item in devices):
        raise TopologyError(f"{where}.accelerator.devices does not match count")

    memory = value.get("memory")
    if not isinstance(memory, dict) or set(memory) != {"topology", "total_gib", "available_gib"}:
        raise TopologyError(f"{where}.memory has invalid fields")
    if memory["topology"] not in {"unified", "discrete"}:
        raise TopologyError(f"{where}.memory.topology is invalid")
    total = _positive(memory["total_gib"], f"{where}.memory.total_gib")
    available = _positive(memory["available_gib"], f"{where}.memory.available_gib", allow_zero=True)
    if available > total:
        raise TopologyError(f"{where}.memory.available_gib exceeds total")

    storage = value.get("storage")
    if not isinstance(storage, dict) or set(storage) != {"total_gib", "available_gib", "cache_available_gib"}:
        raise TopologyError(f"{where}.storage has invalid fields")
    storage_total = _positive(storage["total_gib"], f"{where}.storage.total_gib")
    for key in ("available_gib", "cache_available_gib"):
        amount = _positive(storage[key], f"{where}.storage.{key}", allow_zero=True)
        if amount > storage_total:
            raise TopologyError(f"{where}.storage.{key} exceeds total")

    network = value.get("network")
    if not isinstance(network, dict) or set(network) != {"interfaces", "links"}:
        raise TopologyError(f"{where}.network has invalid fields")
    if not isinstance(network["interfaces"], list) or not all(
        isinstance(interface, dict)
        and set(interface) == {"name", "addresses", "mtu", "speed_mbps", "rdma"}
        and isinstance(interface["name"], str)
        and isinstance(interface["addresses"], list)
        and all(isinstance(address, str) for address in interface["addresses"])
        and isinstance(interface["rdma"], bool)
        for interface in network["interfaces"]
    ):
        raise TopologyError(f"{where}.network.interfaces is invalid")
    for interface in network["interfaces"]:
        _positive(interface["mtu"], f"{where}.network.interfaces.mtu")
        _positive(interface["speed_mbps"], f"{where}.network.interfaces.speed_mbps", allow_zero=True)
    interface_names = [interface["name"] for interface in network["interfaces"]]
    if len(interface_names) != len(set(interface_names)):
        raise TopologyError(f"{where}.network.interfaces contains duplicate names")
    interfaces = {interface["name"]: interface for interface in network["interfaces"]}
    if not isinstance(network["links"], list):
        raise TopologyError(f"{where}.network.links must be a list")
    for link in network["links"]:
        if not isinstance(link, dict) or set(link) != {
            "peer_member_id", "interface", "kind", "speed_mbps", "mtu", "rdma",
            "verified", "observed_at_unix", "peer_certificate_sha256", "proof_sha256",
        }:
            raise TopologyError(f"{where}.network.links entry is invalid")
        if not ID_RE.fullmatch(str(link["peer_member_id"])) or not isinstance(link["verified"], bool):
            raise TopologyError(f"{where}.network.links peer identity is invalid")
        if link["kind"] not in {"connectx", "ethernet", "wifi", "other"} or not isinstance(link["rdma"], bool):
            raise TopologyError(f"{where}.network.links kind is invalid")
        _positive(link["speed_mbps"], f"{where}.network.links.speed_mbps", allow_zero=True)
        _positive(link["mtu"], f"{where}.network.links.mtu")
        _positive(link["observed_at_unix"], f"{where}.network.links.observed_at_unix")
        for field in ("peer_certificate_sha256", "proof_sha256"):
            if not isinstance(link[field], str) or not SHA256_RE.fullmatch(link[field]):
                raise TopologyError(f"{where}.network.links.{field} is invalid")
        interface = interfaces.get(link["interface"])
        if interface is None:
            raise TopologyError(f"{where}.network.links interface is not present")
        if (
            (interface["speed_mbps"] and link["speed_mbps"] > interface["speed_mbps"])
            or link["mtu"] > interface["mtu"]
            or (link["rdma"] and not interface["rdma"])
        ):
            raise TopologyError(
                f"{where}.network.links exceeds the reported interface capability"
            )

    software = value.get("software")
    if not isinstance(software, dict) or set(software) != {"driver", "container_runtime", "letsinfer_version"}:
        raise TopologyError(f"{where}.software has invalid fields")
    if not all(isinstance(software[key], str) and software[key] for key in software):
        raise TopologyError(f"{where}.software contains invalid values")

    health = value.get("health")
    if not isinstance(health, dict) or set(health) != {
        "state", "memory_pressure", "protection_trip", "max_temperature_c"
    }:
        raise TopologyError(f"{where}.health has invalid fields")
    if health["state"] not in {"healthy", "degraded", "offline"}:
        raise TopologyError(f"{where}.health.state is invalid")
    if not isinstance(health["memory_pressure"], bool) or not isinstance(health["protection_trip"], bool):
        raise TopologyError(f"{where}.health flags are invalid")
    temperature = health["max_temperature_c"]
    if (
        not isinstance(temperature, (int, float))
        or isinstance(temperature, bool)
        or not math.isfinite(float(temperature))
        or not -1 <= float(temperature) <= 250
    ):
        raise TopologyError(f"{where}.health.max_temperature_c is invalid")

    if "inventory" not in value:
        return value
    inventory = value["inventory"]
    text_fields = {
        "hostname", "operating_system", "kernel_version", "product_vendor",
        "product_name", "product_version", "serial_number", "serial_source",
        "system_uuid", "machine_id_sha256", "board_vendor", "board_name",
        "board_version", "board_serial", "chassis_vendor", "chassis_type",
        "chassis_serial", "bios_vendor", "bios_version", "bios_date",
        "cpu_model", "gpu_name", "gpu_uuid", "nvidia_driver_version",
        "dgx_name", "dgx_software_version", "dgx_base_build_version",
        "dgx_build_date", "dgx_commit_id", "dgx_platform", "dgx_update_date",
        "nvme_model", "nvme_serial", "nvme_firmware",
        "default_network_interface", "last_login",
    }
    integer_fields = {
        "cpu_core_count", "uptime_seconds", "process_count",
        "login_session_count", "firmware_update_count",
    }
    required_inventory = text_fields | integer_fields | {
        "dmi_serial_requires_privilege", "network_addresses", "active_users",
        "containers",
    }
    if not isinstance(inventory, dict) or set(inventory) != required_inventory:
        raise TopologyError(f"{where}.inventory has invalid fields")
    for key in text_fields:
        item = inventory[key]
        if item is not None and (
            not isinstance(item, str)
            or not item
            or len(item.encode("utf-8")) > 1024
            or "\x00" in item
        ):
            raise TopologyError(f"{where}.inventory.{key} is invalid")
    machine_id = inventory["machine_id_sha256"]
    if machine_id is not None and not SHA256_RE.fullmatch(machine_id):
        raise TopologyError(f"{where}.inventory.machine_id_sha256 is invalid")
    for key in integer_fields:
        item = inventory[key]
        if item is not None and (
            not isinstance(item, int) or isinstance(item, bool) or item < 0
        ):
            raise TopologyError(f"{where}.inventory.{key} is invalid")
    if not isinstance(inventory["dmi_serial_requires_privilege"], bool):
        raise TopologyError(
            f"{where}.inventory.dmi_serial_requires_privilege is invalid"
        )
    addresses = inventory["network_addresses"]
    if not isinstance(addresses, list) or len(addresses) > 256:
        raise TopologyError(f"{where}.inventory.network_addresses is invalid")
    for address in addresses:
        if (
            not isinstance(address, dict)
            or set(address) != {"interface", "family", "address"}
            or not isinstance(address["interface"], str)
            or not INTERFACE_RE.fullmatch(address["interface"])
            or address["family"] not in {"inet", "inet6"}
        ):
            raise TopologyError(f"{where}.inventory.network_addresses is invalid")
        try:
            parsed = ipaddress.ip_address(address["address"])
        except ValueError as error:
            raise TopologyError(
                f"{where}.inventory.network_addresses is invalid"
            ) from error
        if (parsed.version == 6) != (address["family"] == "inet6"):
            raise TopologyError(f"{where}.inventory.network_addresses is invalid")
    users = inventory["active_users"]
    if (
        not isinstance(users, list)
        or len(users) > 64
        or not all(isinstance(user, str) and 0 < len(user) <= 256 for user in users)
    ):
        raise TopologyError(f"{where}.inventory.active_users is invalid")
    containers = inventory["containers"]
    if not isinstance(containers, list) or len(containers) > 128:
        raise TopologyError(f"{where}.inventory.containers is invalid")
    for container in containers:
        if (
            not isinstance(container, dict)
            or set(container) != {"name", "image", "status"}
            or not isinstance(container["name"], str)
            or not container["name"]
            or any(
                item is not None and (
                    not isinstance(item, str) or not item or len(item) > 1024
                )
                for item in (container["image"], container["status"])
            )
        ):
            raise TopologyError(f"{where}.inventory.containers is invalid")
    return value


def facts_sha256(value: dict[str, Any]) -> str:
    validate_member_facts(value)
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


@dataclasses.dataclass(frozen=True)
class Placement:
    strategy: str
    member_ids: tuple[str, ...]
    device_uuids: Mapping[str, tuple[str, ...]]
    topology_sha256: str
    reason: str


@dataclasses.dataclass(frozen=True)
class TargetPlacement:
    """The sole highest-priority catalog target that fits this site."""

    target_id: str
    placement: Placement


class TopologyGraph:
    def __init__(
        self,
        facts: Sequence[dict[str, Any]],
        *,
        now_unix: int | None = None,
        member_certificates: Mapping[str, str] | None = None,
        allocated_devices: Mapping[str, Sequence[str]] | None = None,
    ) -> None:
        now = now_unix or int(time.time())
        self.members: dict[str, dict[str, Any]] = {}
        for fact in facts:
            validated = validate_member_facts(fact)
            member_id = validated["member_id"]
            if member_id in self.members:
                raise TopologyError(f"duplicate topology member {member_id}")
            if now - validated["observed_at_unix"] > MAX_FACT_AGE_SECONDS:
                raise TopologyError(f"topology facts are stale for member {member_id}")
            if validated["observed_at_unix"] > now + 5:
                raise TopologyError(f"topology facts are from the future for member {member_id}")
            self.members[member_id] = validated
        if not self.members:
            raise TopologyError("topology requires at least one member")
        self.allocated_devices: dict[str, frozenset[str]] = {}
        for member_id in self.members:
            allocated = () if allocated_devices is None else allocated_devices.get(member_id, ())
            if (
                not isinstance(allocated, Sequence)
                or isinstance(allocated, (str, bytes))
                or any(not isinstance(item, str) or not item for item in allocated)
                or len(allocated) != len(set(allocated))
            ):
                raise TopologyError(f"allocated device inventory is invalid for member {member_id}")
            known = set(self.members[member_id]["accelerator"]["devices"])
            if set(allocated) - known:
                raise TopologyError(f"allocated device inventory contains an unknown device on {member_id}")
            self.allocated_devices[member_id] = frozenset(allocated)
        if member_certificates is not None:
            if set(member_certificates) != set(self.members) or any(
                not isinstance(digest, str) or not SHA256_RE.fullmatch(digest)
                for digest in member_certificates.values()
            ):
                raise TopologyError("topology membership certificate bindings are incomplete")
            for member_id, fact in self.members.items():
                for link in fact["network"]["links"]:
                    peer = link["peer_member_id"]
                    if (
                        peer in self.members
                        and link["peer_certificate_sha256"]
                        != member_certificates[peer]
                    ):
                        raise TopologyError(
                            f"topology link certificate changed for {member_id}->{peer}"
                        )
        self.links: dict[tuple[str, str], dict[str, Any]] = {}
        for member_id, fact in self.members.items():
            for link in fact["network"]["links"]:
                peer = link["peer_member_id"]
                if (
                    peer not in self.members
                    or peer == member_id
                    or not link["verified"]
                    or now - link["observed_at_unix"] > MAX_FACT_AGE_SECONDS
                    or link["observed_at_unix"] > now + 5
                ):
                    continue
                reverse = next(
                    (
                        candidate
                        for candidate in self.members[peer]["network"]["links"]
                        if candidate["peer_member_id"] == member_id
                        and candidate["verified"]
                        and now - candidate["observed_at_unix"] <= MAX_FACT_AGE_SECONDS
                        and candidate["observed_at_unix"] <= now + 5
                    ),
                    None,
                )
                if reverse is None:
                    continue
                key = tuple(sorted((member_id, peer)))
                self.links[key] = {
                    "members": list(key),
                    "kind": link["kind"] if link["kind"] == reverse["kind"] else "other",
                    "speed_mbps": min(link["speed_mbps"], reverse["speed_mbps"]),
                    "mtu": min(link["mtu"], reverse["mtu"]),
                    "rdma": bool(link["rdma"] and reverse["rdma"]),
                    "observed_at_unix": min(
                        link["observed_at_unix"], reverse["observed_at_unix"]
                    ),
                    "proofs": sorted(
                        [link["proof_sha256"], reverse["proof_sha256"]]
                    ),
                }

    def document(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "members": [self.members[key] for key in sorted(self.members)],
            "links": [self.links[key] for key in sorted(self.links)],
        }

    def sha256(self) -> str:
        return hashlib.sha256(canonical_bytes(self.document())).hexdigest()

    def _member_matches(self, member: dict[str, Any], target: Mapping[str, Any]) -> bool:
        accelerator = member["accelerator"]
        expected_accelerator = target["accelerator"]
        memory = member["memory"]
        expected_memory = target["memory"]
        return (
            member["platform"] == target["platform"]
            and all(accelerator[key] == expected_accelerator[key] for key in ("vendor", "architecture", "partitioning"))
            and len(self.available_devices(member["member_id"])) >= expected_accelerator["count"]
            and accelerator["minimum_memory_gib"] >= expected_accelerator.get("minimum_memory_gib", 0)
            and memory["topology"] == expected_memory["topology"]
            and memory["total_gib"] >= expected_memory["minimum_total_gib"]
            and member_available(member["health"])
        )

    def available_devices(self, member_id: str) -> tuple[str, ...]:
        """Return stable, currently unallocated accelerator identities."""
        if member_id not in self.members:
            raise TopologyError(f"unknown topology member {member_id}")
        allocated = self.allocated_devices.get(member_id, frozenset())
        return tuple(
            sorted(
                device
                for device in self.members[member_id]["accelerator"]["devices"]
                if device not in allocated
            )
        )

    def _link_satisfies(self, left: str, right: str, contract: Mapping[str, Any]) -> bool:
        link = self.links.get(tuple(sorted((left, right))))
        if link is None:
            return False
        kind = contract.get("kind", "any")
        return (
            (kind == "any" or link["kind"] == kind)
            and (not contract.get("rdma_required", False) or link["rdma"])
            and link["speed_mbps"] >= contract.get("minimum_speed_mbps", 0)
            and link["mtu"] >= contract.get("minimum_mtu", 0)
        )

    def _connected(self, members: Sequence[str], interconnect: Mapping[str, Any]) -> bool:
        if len(members) < 2:
            return True
        required = set(members)
        visited = {members[0]}
        queue = deque([members[0]])
        while queue:
            current = queue.popleft()
            for candidate in members:
                if candidate not in visited and self._link_satisfies(current, candidate, interconnect):
                    visited.add(candidate)
                    queue.append(candidate)
        return visited == required

    def placement_available(
        self,
        members: Sequence[str],
        *,
        strategy: str,
        interconnect: Mapping[str, Any] | None = None,
    ) -> bool:
        """Return whether an existing placement is safe on the current graph."""
        if (
            strategy not in {"single", "parallel"}
            or not members
            or len(members) != len(set(members))
            or any(member_id not in self.members for member_id in members)
            or any(
                not member_available(self.members[member_id]["health"])
                for member_id in members
            )
        ):
            return False
        if strategy != "parallel" or len(members) == 1:
            return True
        if not isinstance(interconnect, Mapping):
            raise TopologyError(
                "parallel placement has no interconnect contract"
            )
        return self._connected(tuple(members), interconnect)

    def resolve(self, target: Mapping[str, Any], *, coordinator_id: str) -> Placement:
        placement = target["placement"]
        compatible = sorted(
            member_id for member_id, facts in self.members.items() if self._member_matches(facts, target)
        )
        strategy = placement["strategy"]
        count = placement["node_count"]
        if strategy == "single":
            count = 1
        if len(compatible) < count:
            raise TopologyError(
                f"target {target['id']} requires {count} compatible member(s); found {len(compatible)}"
            )
        # Deterministic combinations without exposing a user-facing target picker.
        from itertools import combinations

        candidates: list[tuple[str, ...]] = []
        for selected in combinations(compatible, count):
            if strategy != "parallel" or len(selected) == 1 or self._connected(selected, placement["interconnect"]):
                candidates.append(selected)
        if not candidates:
            raise TopologyError(f"target {target['id']} has no topology-compatible placement")
        # Prefer keeping the site coordinator in the placement, then stable IDs.
        candidates.sort(key=lambda selected: (coordinator_id not in selected, selected))
        selected = candidates[0]
        devices_per_member = target["accelerator"]["count"]
        device_uuids = {
            member_id: self.available_devices(member_id)[:devices_per_member]
            for member_id in selected
        }
        return Placement(
            strategy=strategy,
            member_ids=selected,
            device_uuids=device_uuids,
            topology_sha256=self.sha256(),
            reason=f"qualified {strategy} target {target['id']}",
        )

    def engine_addresses(
        self,
        placement: Placement,
        interconnect: Mapping[str, Any],
    ) -> dict[str, str]:
        """Select one verified engine-traffic address on each distributed member."""
        interfaces = self.engine_interfaces(placement, interconnect)
        result: dict[str, str] = {}
        for member_id, interface_name in interfaces.items():
            facts = self.members[member_id]
            interface = next(
                (
                    item
                    for item in facts["network"]["interfaces"]
                    if item["name"] == interface_name
                ),
                None,
            )
            if interface is None:
                raise TopologyError(
                    "verified engine interface disappeared from member facts"
                )
            addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
            for text in interface["addresses"]:
                try:
                    address = ipaddress.ip_address(text.split("%", 1)[0])
                except ValueError:
                    continue
                if not address.is_loopback and not address.is_unspecified:
                    addresses.append(address)
            addresses.sort(key=lambda item: (item.version != 4, int(item)))
            if not addresses:
                raise TopologyError(
                    f"parallel member {member_id} has no usable engine address"
                )
            chosen = str(addresses[0])
            result[member_id] = (
                f"[{chosen}]" if addresses[0].version == 6 else chosen
            )
        return result

    def engine_interfaces(
        self,
        placement: Placement,
        interconnect: Mapping[str, Any],
    ) -> dict[str, str]:
        """Select one verified engine-traffic interface on every group member."""
        if (
            placement.strategy != "parallel"
            or placement.topology_sha256 != self.sha256()
            or set(placement.member_ids) - set(self.members)
        ):
            raise TopologyError(
                "engine interfaces require this exact parallel placement"
            )
        selected = set(placement.member_ids)
        result: dict[str, str] = {}
        for member_id in placement.member_ids:
            facts = self.members[member_id]
            links = [
                link
                for link in facts["network"]["links"]
                if link["peer_member_id"] in selected
                and self._link_satisfies(
                    member_id, link["peer_member_id"], interconnect
                )
            ]
            interfaces = {link["interface"] for link in links}
            if not links or len(interfaces) != 1:
                raise TopologyError(
                    f"parallel member {member_id} has no single verified engine interface"
                )
            interface_name = next(iter(interfaces))
            interface = next(
                (
                    item
                    for item in facts["network"]["interfaces"]
                    if item["name"] == interface_name
                ),
                None,
            )
            if interface is None:
                raise TopologyError("verified engine interface disappeared from member facts")
            if interconnect.get("rdma_required") is True and interface["rdma"] is not True:
                raise TopologyError(
                    f"parallel member {member_id} engine interface is not RDMA-capable"
                )
            result[member_id] = interface_name
        return result

    def placement_connections(self, placement: Placement) -> list[dict[str, Any]]:
        """Return the verified link facts connecting one exact placement."""
        if (
            placement.topology_sha256 != self.sha256()
            or set(placement.member_ids) - set(self.members)
        ):
            raise TopologyError("connection facts require this exact placement")
        selected = set(placement.member_ids)
        return [
            {
                "nodes": list(key),
                "kind": link["kind"],
                "speed_mbps": link["speed_mbps"],
                "mtu": link["mtu"],
                "rdma": link["rdma"],
            }
            for key, link in sorted(self.links.items())
            if set(key) <= selected
        ]

    def resolve_catalog_targets(
        self,
        targets: Mapping[str, Mapping[str, Any]],
        *,
        coordinator_id: str,
    ) -> TargetPlacement:
        """Select one catalog target using the product placement policy.

        Parallel and single-member targets are considered in that order. More
        than one compatible target at the best available
        strategy is a catalog defect; target choice is never delegated to the
        user or resolved by incidental dictionary order.
        """
        if not targets:
            raise TopologyError("catalog model has no target variants")
        priority = {"parallel": 0, "single": 1}
        candidates: list[TargetPlacement] = []
        failures: list[str] = []
        for target_id in sorted(targets):
            target = targets[target_id]
            if target.get("id") != target_id:
                raise TopologyError(
                    f"catalog target key {target_id} differs from target contract identity"
                )
            try:
                candidates.append(
                    TargetPlacement(
                        target_id=target_id,
                        placement=self.resolve(target, coordinator_id=coordinator_id),
                    )
                )
            except TopologyError as error:
                failures.append(f"{target_id}: {error}")
        if not candidates:
            detail = "; ".join(failures)
            raise TopologyError(
                "catalog has no topology-compatible target"
                + (f" ({detail})" if detail else "")
            )
        best_priority = min(
            priority[candidate.placement.strategy] for candidate in candidates
        )
        best = [
            candidate
            for candidate in candidates
            if priority[candidate.placement.strategy] == best_priority
        ]
        if len(best) != 1:
            choices = ", ".join(candidate.target_id for candidate in best)
            raise TopologyError(
                "catalog target contracts are ambiguous for this site "
                f"({choices})"
            )
        return best[0]
