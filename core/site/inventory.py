#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded local hardware inventory for authenticated site topology facts."""

from __future__ import annotations

import pathlib
import ipaddress
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import stat
import subprocess
import time
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from ..state_plane import member_health_state
from .topology import validate_member_facts


class InventoryError(RuntimeError):
    """The local member cannot publish complete, trustworthy facts."""


INTERFACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,31}$")
RDMA_DEVICE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
RDMA_VERBS_RE = re.compile(r"^uverbs(?:0|[1-9][0-9]*)$")


def _read_text(path: pathlib.Path, *, maximum_bytes: int = 4096) -> str | None:
    """Read one bounded system fact, treating absent/restricted data as unknown."""
    try:
        with path.open("r", encoding="utf-8", errors="strict") as handle:
            value = handle.read(maximum_bytes + 1)
    except (OSError, UnicodeError):
        return None
    if len(value.encode("utf-8")) > maximum_bytes:
        return None
    return value.strip() or None


def _release_values(path: pathlib.Path) -> dict[str, str]:
    result: dict[str, str] = {}
    value = _read_text(path, maximum_bytes=32768)
    if value is None:
        return result
    for line in value.splitlines():
        if not line or line.lstrip().startswith("#") or "=" not in line:
            continue
        key, raw = line.split("=", 1)
        key = key.strip()
        raw = raw.strip()
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", key):
            continue
        if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in {'"', "'"}:
            raw = raw[1:-1]
        if raw and len(raw.encode("utf-8")) <= 1024:
            result[key] = raw
    return result


def _default_interface(proc_root: pathlib.Path) -> str | None:
    value = _read_text(proc_root / "net/route", maximum_bytes=131072)
    if value is None:
        return None
    for line in value.splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 2 and fields[1] == "00000000" and INTERFACE_RE.fullmatch(fields[0]):
            return fields[0]
    return None


def _cpu_model(proc_root: pathlib.Path) -> str | None:
    value = _read_text(proc_root / "cpuinfo", maximum_bytes=2 * 1024 * 1024)
    if value is None:
        return None
    for field in ("model name", "Hardware", "Processor"):
        for line in value.splitlines():
            key, separator, raw = line.partition(":")
            if separator and key.strip() == field and raw.strip():
                return raw.strip()[:512]
    try:
        rows = json.loads(_command(["lscpu", "--json"])).get("lscpu", [])
    except (InventoryError, AttributeError, json.JSONDecodeError, TypeError):
        return None
    models: list[str] = []
    for row in rows:
        if not isinstance(row, dict) or str(row.get("field", "")).rstrip(":") != "Model name":
            continue
        value = row.get("data")
        if isinstance(value, str) and value and value not in models:
            models.append(value)
    return " / ".join(models)[:512] or None


def _machine_id_sha256(etc_root: pathlib.Path) -> str | None:
    value = _read_text(etc_root / "machine-id", maximum_bytes=128)
    if value is None or not re.fullmatch(r"[0-9a-fA-F]{32}", value):
        return None
    return hashlib.sha256(value.lower().encode("ascii")).hexdigest()


def _first_nvme(sys_class: pathlib.Path) -> pathlib.Path | None:
    root = sys_class / "nvme"
    try:
        candidates = sorted(
            (path for path in root.iterdir() if re.fullmatch(r"nvme[0-9]+", path.name)),
            key=lambda path: path.name,
        )
    except OSError:
        return None
    return candidates[0] if candidates else None


def _inventory_details(
    device: Mapping[str, Any],
    *,
    network_interfaces: Sequence[Mapping[str, Any]],
    driver: str,
    sys_class: pathlib.Path,
    proc_root: pathlib.Path,
    etc_root: pathlib.Path,
) -> dict[str, Any]:
    dmi_root = sys_class / "dmi/id"
    os_release = _release_values(etc_root / "os-release")
    dgx = _release_values(etc_root / "dgx-release")
    product_serial_path = dmi_root / "product_serial"
    product_serial = _read_text(product_serial_path)
    dgx_serial = dgx.get("DGX_SERIAL_NUMBER")
    nvme = _first_nvme(sys_class)
    accelerator = device.get("accelerator", {})
    gpu_names = accelerator.get("names", []) if isinstance(accelerator, Mapping) else []
    gpu_uuids = accelerator.get("uuids", []) if isinstance(accelerator, Mapping) else []
    addresses: list[dict[str, str]] = []
    for interface in network_interfaces:
        name = interface.get("name")
        if not isinstance(name, str):
            continue
        for address in interface.get("addresses", []):
            try:
                parsed = ipaddress.ip_address(address)
            except ValueError:
                continue
            addresses.append(
                {
                    "interface": name,
                    "family": "inet6" if parsed.version == 6 else "inet",
                    "address": str(parsed),
                }
            )
    uptime_text = _read_text(proc_root / "uptime", maximum_bytes=128)
    try:
        uptime_seconds = int(float((uptime_text or "").split()[0]))
    except (IndexError, ValueError):
        uptime_seconds = None
    try:
        process_count = sum(
            1 for path in proc_root.iterdir() if path.name.isdigit() and path.is_dir()
        )
    except OSError:
        process_count = None
    return {
        "hostname": socket.gethostname()[:255] or None,
        "operating_system": os_release.get("PRETTY_NAME"),
        "kernel_version": platform.release()[:255] or None,
        "product_vendor": _read_text(dmi_root / "sys_vendor"),
        "product_name": _read_text(dmi_root / "product_name"),
        "product_version": _read_text(dmi_root / "product_version"),
        "serial_number": dgx_serial or product_serial,
        "serial_source": (
            "NVIDIA DGX release" if dgx_serial else "DMI" if product_serial else None
        ),
        "system_uuid": _read_text(dmi_root / "product_uuid"),
        "machine_id_sha256": _machine_id_sha256(etc_root),
        "dmi_serial_requires_privilege": product_serial_path.exists() and product_serial is None,
        "board_vendor": _read_text(dmi_root / "board_vendor"),
        "board_name": _read_text(dmi_root / "board_name"),
        "board_version": _read_text(dmi_root / "board_version"),
        "board_serial": _read_text(dmi_root / "board_serial"),
        "chassis_vendor": _read_text(dmi_root / "chassis_vendor"),
        "chassis_type": _read_text(dmi_root / "chassis_type"),
        "chassis_serial": _read_text(dmi_root / "chassis_serial"),
        "bios_vendor": _read_text(dmi_root / "bios_vendor"),
        "bios_version": _read_text(dmi_root / "bios_version"),
        "bios_date": _read_text(dmi_root / "bios_date"),
        "cpu_model": _cpu_model(proc_root),
        "cpu_core_count": os.cpu_count(),
        "gpu_name": gpu_names[0] if isinstance(gpu_names, list) and gpu_names else None,
        "gpu_uuid": gpu_uuids[0] if isinstance(gpu_uuids, list) and gpu_uuids else None,
        "nvidia_driver_version": driver,
        "dgx_name": dgx.get("DGX_PRETTY_NAME"),
        "dgx_software_version": dgx.get("DGX_OTA_VERSION"),
        "dgx_base_build_version": dgx.get("DGX_SWBUILD_VERSION"),
        "dgx_build_date": dgx.get("DGX_SWBUILD_DATE"),
        "dgx_commit_id": dgx.get("DGX_COMMIT_ID"),
        "dgx_platform": dgx.get("DGX_PLATFORM"),
        "dgx_update_date": dgx.get("DGX_OTA_DATE"),
        "nvme_model": _read_text(nvme / "model") if nvme else None,
        "nvme_serial": _read_text(nvme / "serial") if nvme else None,
        "nvme_firmware": _read_text(nvme / "firmware_rev") if nvme else None,
        "network_addresses": addresses,
        "default_network_interface": _default_interface(proc_root),
        "uptime_seconds": uptime_seconds,
        "process_count": process_count,
        "active_users": [],
        "login_session_count": None,
        "last_login": None,
        "firmware_update_count": None,
        "containers": [],
    }


def _read_positive(path: pathlib.Path, *, default: int = 0) -> int:
    try:
        value = int(path.read_text(encoding="ascii").strip())
    except (OSError, UnicodeDecodeError, ValueError):
        return default
    return value if value >= 0 else default


def _command(command: Sequence[str]) -> str:
    try:
        result = subprocess.run(
            list(command), text=True, capture_output=True, check=False, timeout=10
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise InventoryError(f"cannot run {command[0]} for member inventory") from error
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise InventoryError(f"member inventory command failed: {command[0]}: {detail}")
    return result.stdout.strip()


def _rdma_interface_devices(sys_class: pathlib.Path) -> dict[str, tuple[str, ...]]:
    result: dict[str, list[str]] = {}
    root = sys_class / "infiniband"
    if not root.is_dir():
        return {}
    try:
        devices = sorted(root.iterdir(), key=lambda item: item.name)
    except OSError:
        return {}
    for device in devices:
        if not RDMA_DEVICE_RE.fullmatch(device.name):
            continue
        net = device / "device/net"
        if net.is_dir():
            try:
                interfaces = sorted(net.iterdir(), key=lambda item: item.name)
            except OSError:
                continue
            for interface in interfaces:
                if interface.is_dir() and INTERFACE_RE.fullmatch(interface.name):
                    result.setdefault(interface.name, []).append(device.name)
    return {
        name: tuple(sorted(set(device_names)))
        for name, device_names in result.items()
    }


def _rdma_interfaces(sys_class: pathlib.Path) -> set[str]:
    return set(_rdma_interface_devices(sys_class))


def _rdma_verbs_devices(sys_class: pathlib.Path, device: str) -> tuple[str, ...]:
    """Resolve userspace verbs names for one HCA across supported sysfs layouts."""
    result: set[str] = set()
    device_root = sys_class / "infiniband" / device
    direct = device_root / "device/infiniband_verbs"
    try:
        result.update(
            item.name
            for item in direct.iterdir()
            if RDMA_VERBS_RE.fullmatch(item.name)
        )
    except OSError:
        pass
    global_root = sys_class / "infiniband_verbs"
    try:
        candidates = list(global_root.iterdir())
    except OSError:
        candidates = []
    try:
        hca_device = (device_root / "device").resolve(strict=True)
    except OSError:
        hca_device = None
    for item in candidates:
        if not RDMA_VERBS_RE.fullmatch(item.name):
            continue
        ibdev = item / "ibdev"
        try:
            linked_name = ibdev.resolve(strict=True).name if ibdev.is_symlink() else None
        except OSError:
            linked_name = None
        text_name = _read_text(ibdev, maximum_bytes=128)
        try:
            same_device = (
                hca_device is not None
                and (item / "device").resolve(strict=True) == hca_device
            )
        except OSError:
            same_device = False
        if linked_name == device or text_name == device or same_device:
            result.add(item.name)
    return tuple(sorted(result))


def resolve_connectx_rdma_binding(
    name: str,
    local_address: str,
    peer_addresses: Sequence[str],
    *,
    minimum_speed_mbps: int,
    minimum_mtu: int,
    sys_class: pathlib.Path = pathlib.Path("/sys/class"),
    dev_root: pathlib.Path = pathlib.Path("/dev"),
    lstat: Callable[[pathlib.Path], os.stat_result] = os.lstat,
    access: Callable[[pathlib.Path, int], bool] = os.access,
) -> dict[str, Any]:
    """Resolve one sealed ConnectX interface to exact usable verbs devices."""
    if (
        not isinstance(minimum_speed_mbps, int)
        or isinstance(minimum_speed_mbps, bool)
        or minimum_speed_mbps <= 0
        or not isinstance(minimum_mtu, int)
        or isinstance(minimum_mtu, bool)
        or minimum_mtu <= 0
    ):
        raise InventoryError("RDMA link requirements are invalid")
    verified = verify_direct_connectx_interface(name, sys_class=sys_class)
    if (
        verified["speed_mbps"] < minimum_speed_mbps
        or verified["mtu"] < minimum_mtu
    ):
        raise InventoryError("live ConnectX link no longer meets its sealed contract")
    try:
        local = str(ipaddress.ip_address(local_address.strip("[]")))
    except (AttributeError, ValueError) as error:
        raise InventoryError("RDMA local address is invalid") from error
    try:
        rows = json.loads(
            _command(["ip", "-json", "address", "show", "dev", name])
        )
    except (json.JSONDecodeError, TypeError) as error:
        raise InventoryError("RDMA interface address inventory is unavailable") from error
    current_addresses: set[str] = set()
    if not isinstance(rows, list):
        raise InventoryError("RDMA interface address inventory is unavailable")
    for row in rows:
        if not isinstance(row, dict):
            continue
        for item in row.get("addr_info", []):
            if not isinstance(item, dict) or not isinstance(item.get("local"), str):
                continue
            try:
                current_addresses.add(str(ipaddress.ip_address(item["local"])))
            except ValueError:
                continue
    if local not in current_addresses:
        raise InventoryError("sealed RDMA address is not assigned to its interface")
    if (
        not isinstance(peer_addresses, Sequence)
        or isinstance(peer_addresses, (str, bytes))
        or not peer_addresses
    ):
        raise InventoryError("RDMA peer addresses are unavailable")
    normalized_peers: list[str] = []
    for value in peer_addresses:
        if not isinstance(value, str):
            raise InventoryError("RDMA peer address is invalid")
        try:
            peer = str(ipaddress.ip_address(value.strip("[]")))
        except ValueError as error:
            raise InventoryError("RDMA peer address is invalid") from error
        if peer == local or peer in normalized_peers:
            raise InventoryError("RDMA peer addresses are invalid")
        proof = verify_direct_connectx_peer(name, peer, sys_class=sys_class)
        if proof.get("local_address") not in {None, local}:
            raise InventoryError("RDMA peer route selected a different local address")
        normalized_peers.append(peer)

    devices = _rdma_interface_devices(sys_class).get(name, ())
    if len(devices) != 1:
        raise InventoryError("ConnectX interface does not map to exactly one RDMA device")
    device = devices[0]
    verbs = _rdma_verbs_devices(sys_class, device)
    if not verbs:
        raise InventoryError("ConnectX RDMA device has no userspace verbs device")
    device_nodes = [dev_root / "infiniband/rdma_cm"] + [
        dev_root / "infiniband" / verb for verb in verbs
    ]
    resolved_nodes: list[dict[str, Any]] = []
    for path in device_nodes:
        try:
            details = lstat(path)
        except OSError as error:
            raise InventoryError(f"RDMA device node is unavailable: {path.name}") from error
        if stat.S_ISLNK(details.st_mode) or not stat.S_ISCHR(details.st_mode):
            raise InventoryError(f"RDMA device node is not a character device: {path.name}")
        if not access(path, os.R_OK | os.W_OK):
            raise InventoryError(f"RDMA device node is not usable: {path.name}")
        resolved_nodes.append(
            {
                "path": str(path),
                "major": os.major(details.st_rdev),
                "minor": os.minor(details.st_rdev),
            }
        )
    return {
        "interface": name,
        "device": device,
        "local_address": local,
        "peer_addresses": normalized_peers,
        "device_nodes": resolved_nodes,
    }


def _network_interfaces(sys_class: pathlib.Path) -> list[dict[str, Any]]:
    rdma = _rdma_interfaces(sys_class)
    addresses: dict[str, list[str]] = {}
    try:
        rows = json.loads(_command(["ip", "-json", "address", "show"]))
        if not isinstance(rows, list):
            raise ValueError("address inventory is not a list")
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("ifname"), str):
                continue
            values = []
            for item in row.get("addr_info", []):
                if isinstance(item, dict) and isinstance(item.get("local"), str):
                    values.append(item["local"])
            addresses[row["ifname"]] = sorted(set(values))
    except (InventoryError, ValueError, TypeError):
        # Interface identity, MTU, speed, and RDMA capability still come from
        # sysfs. An address can legitimately be absent during direct-link setup.
        addresses = {}

    root = sys_class / "net"
    if not root.is_dir():
        raise InventoryError("network interface inventory is unavailable")
    result: list[dict[str, Any]] = []
    for interface in sorted(root.iterdir(), key=lambda item: item.name):
        if interface.name == "lo":
            continue
        mtu = _read_positive(interface / "mtu")
        if mtu < 1:
            raise InventoryError(f"network MTU is unavailable for {interface.name}")
        result.append(
            {
                "name": interface.name,
                "addresses": addresses.get(interface.name, []),
                "mtu": mtu,
                "speed_mbps": _read_positive(interface / "speed"),
                "rdma": interface.name in rdma,
            }
        )
    if not result:
        raise InventoryError("no non-loopback network interface is available")
    return result


def verify_direct_connectx_interface(
    name: str,
    *,
    sys_class: pathlib.Path = pathlib.Path("/sys/class"),
) -> dict[str, Any]:
    """Verify that an approved no-code invite is bound to a live ConnectX link."""
    if not isinstance(name, str) or not INTERFACE_RE.fullmatch(name):
        raise InventoryError("direct ConnectX interface name is invalid")
    interface = sys_class / "net" / name
    if not interface.is_dir():
        raise InventoryError(f"direct ConnectX interface does not exist: {name}")
    if name not in _rdma_interfaces(sys_class):
        raise InventoryError(f"direct interface is not RDMA-capable: {name}")
    carrier = _read_positive(interface / "carrier")
    if carrier != 1:
        raise InventoryError(f"direct ConnectX link does not have carrier: {name}")
    try:
        operstate = (interface / "operstate").read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError) as error:
        raise InventoryError(f"direct ConnectX link state is unavailable: {name}") from error
    if operstate not in {"up", "unknown"}:
        raise InventoryError(f"direct ConnectX link is not up: {name}")
    speed = _read_positive(interface / "speed")
    mtu = _read_positive(interface / "mtu")
    if speed < 1 or mtu < 1500:
        raise InventoryError(f"direct ConnectX link capabilities are invalid: {name}")
    driver_link = interface / "device/driver"
    try:
        driver = driver_link.resolve(strict=True).name
    except OSError as error:
        raise InventoryError(f"direct ConnectX driver is unavailable: {name}") from error
    if driver != "mlx5_core":
        raise InventoryError(f"direct RDMA interface is not ConnectX/mlx5: {name}")
    return {
        "interface": name,
        "driver": driver,
        "carrier": True,
        "rdma": True,
        "speed_mbps": speed,
        "mtu": mtu,
    }


def select_direct_connectx_interface(
    *, sys_class: pathlib.Path = pathlib.Path("/sys/class")
) -> dict[str, Any]:
    """Select the sole live direct ConnectX interface, never an arbitrary one."""
    candidates: list[dict[str, Any]] = []
    for name in sorted(_rdma_interfaces(sys_class)):
        try:
            candidates.append(
                verify_direct_connectx_interface(name, sys_class=sys_class)
            )
        except InventoryError:
            continue
    if not candidates:
        raise InventoryError("no live direct ConnectX interface is available")
    if len(candidates) != 1:
        raise InventoryError("direct ConnectX interface selection is ambiguous")
    return candidates[0]


def verify_direct_connectx_peer(
    name: str,
    peer_address: str,
    *,
    sys_class: pathlib.Path = pathlib.Path("/sys/class"),
) -> dict[str, Any]:
    """Prove that an enrollment peer is reached directly over the approved link."""
    direct_link = verify_direct_connectx_interface(name, sys_class=sys_class)
    try:
        peer = str(ipaddress.ip_address(peer_address))
    except ValueError as error:
        raise InventoryError("ConnectX enrollment peer address is invalid") from error
    try:
        routes = json.loads(_command(["ip", "-json", "route", "get", peer]))
    except (json.JSONDecodeError, TypeError) as error:
        raise InventoryError("ConnectX peer route is unavailable") from error
    if (
        not isinstance(routes, list)
        or len(routes) != 1
        or not isinstance(routes[0], dict)
    ):
        raise InventoryError("ConnectX peer route is ambiguous")
    route = routes[0]
    if route.get("dev") != name or "gateway" in route:
        raise InventoryError(
            f"enrollment peer is not directly reachable over approved ConnectX interface: {name}"
        )
    result = {**direct_link, "peer_address": peer, "route_interface": name}
    local_address = route.get("prefsrc", route.get("src"))
    if local_address is not None:
        try:
            local = ipaddress.ip_address(local_address)
        except ValueError as error:
            raise InventoryError("ConnectX local route address is invalid") from error
        if local.is_unspecified:
            raise InventoryError("ConnectX local route address is invalid")
        result["local_address"] = str(local)
    return result


def verify_direct_peer_interface(
    name: str,
    peer_address: str,
    *,
    kind: str,
    sys_class: pathlib.Path = pathlib.Path("/sys/class"),
) -> dict[str, Any]:
    """Verify one physical peer route and report the local link capabilities."""
    if kind not in {"connectx", "ethernet", "wifi", "other"}:
        raise InventoryError("peer link kind is invalid")
    if kind == "connectx":
        return {
            **verify_direct_connectx_peer(name, peer_address, sys_class=sys_class),
            "kind": kind,
        }
    if not isinstance(name, str) or not INTERFACE_RE.fullmatch(name):
        raise InventoryError("peer interface name is invalid")
    interface = sys_class / "net" / name
    if not interface.is_dir():
        raise InventoryError(f"peer interface does not exist: {name}")
    if _read_positive(interface / "carrier") != 1:
        raise InventoryError(f"peer link does not have carrier: {name}")
    try:
        operstate = (interface / "operstate").read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError) as error:
        raise InventoryError(f"peer link state is unavailable: {name}") from error
    if operstate not in {"up", "unknown"}:
        raise InventoryError(f"peer link is not up: {name}")
    speed = _read_positive(interface / "speed")
    mtu = _read_positive(interface / "mtu")
    if speed < 1 or mtu < 576:
        raise InventoryError(f"peer link capabilities are invalid: {name}")
    try:
        peer = str(ipaddress.ip_address(peer_address))
        routes = json.loads(_command(["ip", "-json", "route", "get", peer]))
    except (ValueError, json.JSONDecodeError, TypeError) as error:
        raise InventoryError("peer route is unavailable") from error
    if (
        not isinstance(routes, list)
        or len(routes) != 1
        or not isinstance(routes[0], dict)
        or routes[0].get("dev") != name
        or "gateway" in routes[0]
    ):
        raise InventoryError(f"peer is not directly reachable over interface: {name}")
    return {
        "interface": name,
        "kind": kind,
        "carrier": True,
        "rdma": name in _rdma_interfaces(sys_class),
        "speed_mbps": speed,
        "mtu": mtu,
        "peer_address": peer,
        "route_interface": name,
    }


def collect_local_facts(
    member_id: str,
    device: Mapping[str, Any],
    *,
    data_path: pathlib.Path,
    protection_trip_path: pathlib.Path,
    memory_pressure_available_bytes: int,
    product_version: str,
    links: Sequence[Mapping[str, Any]] = (),
    sys_class: pathlib.Path = pathlib.Path("/sys/class"),
    meminfo_path: pathlib.Path = pathlib.Path("/proc/meminfo"),
    proc_root: pathlib.Path = pathlib.Path("/proc"),
    etc_root: pathlib.Path = pathlib.Path("/etc"),
    now_unix: int | None = None,
) -> dict[str, Any]:
    """Collect one strict, bounded topology snapshot without exposing secrets."""
    if (
        not isinstance(memory_pressure_available_bytes, int)
        or isinstance(memory_pressure_available_bytes, bool)
        or memory_pressure_available_bytes <= 0
    ):
        raise InventoryError("memory-pressure threshold is invalid")
    accelerator = device.get("accelerator")
    memory = device.get("memory")
    platform_value = device.get("platform")
    if not isinstance(accelerator, Mapping) or not isinstance(memory, Mapping):
        raise InventoryError("host device fingerprint is incomplete")
    count = accelerator.get("count")
    minimum_memory = accelerator.get("minimum_memory_gib", memory.get("total_gib"))
    if (
        not isinstance(count, int)
        or isinstance(count, bool)
        or count < 1
        or not isinstance(minimum_memory, int)
        or isinstance(minimum_memory, bool)
        or minimum_memory < 1
    ):
        raise InventoryError("host accelerator memory inventory is incomplete")
    data_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    usage = shutil.disk_usage(data_path)
    meminfo = meminfo_path.read_text(encoding="utf-8")
    available_kib = next(
        (
            int(line.split()[1])
            for line in meminfo.splitlines()
            if line.startswith("MemAvailable:")
        ),
        None,
    )
    if available_kib is None:
        raise InventoryError("host available-memory inventory is unavailable")
    try:
        driver = _command(
            ["nvidia-smi", "--query-gpu=driver_version", "--format=csv,noheader,nounits"]
        ).splitlines()[0].strip()
        temperatures = [
            float(value)
            for value in _command(
                ["nvidia-smi", "--query-gpu=temperature.gpu", "--format=csv,noheader,nounits"]
            ).splitlines()
        ]
        container_runtime = _command(["docker", "--version"])
    except (IndexError, ValueError) as error:
        raise InventoryError("accelerator telemetry inventory is invalid") from error
    devices = accelerator.get("uuids")
    if not isinstance(devices, list) or len(devices) != count:
        raise InventoryError("stable accelerator identities are unavailable")
    protection_tripped = _protection_trip_exists(protection_trip_path)
    memory_pressure = available_kib * 1024 <= memory_pressure_available_bytes
    network_interfaces = _network_interfaces(sys_class)
    facts = {
        "schema_version": 1,
        "member_id": member_id,
        "observed_at_unix": now_unix or int(time.time()),
        "platform": platform_value,
        "accelerator": {
            "vendor": accelerator.get("vendor"),
            "architecture": accelerator.get("architecture"),
            "count": count,
            "partitioning": accelerator.get("partitioning"),
            "minimum_memory_gib": minimum_memory,
            "devices": devices,
        },
        "memory": {
            "topology": memory.get("topology"),
            "total_gib": memory.get("total_gib"),
            "available_gib": available_kib // 1048576,
        },
        "storage": {
            "total_gib": usage.total // (1024**3),
            "available_gib": usage.free // (1024**3),
            "cache_available_gib": usage.free // (1024**3),
        },
        "network": {
            "interfaces": network_interfaces,
            "links": [dict(link) for link in links],
        },
        "software": {
            "driver": driver,
            "container_runtime": container_runtime,
            "letsinfer_version": product_version,
        },
        "health": {
            # Loaded inference engines commonly preallocate weights, KV cache,
            # and graph workspaces. Low host headroom is telemetry, not proof
            # that the healthy engine cannot admit through its own scheduler.
            "state": member_health_state(protection_tripped=protection_tripped),
            "memory_pressure": memory_pressure,
            "protection_trip": protection_tripped,
            "max_temperature_c": max(temperatures),
        },
        "inventory": _inventory_details(
            device,
            network_interfaces=network_interfaces,
            driver=driver,
            sys_class=sys_class,
            proc_root=proc_root,
            etc_root=etc_root,
        ),
    }
    try:
        return validate_member_facts(facts)
    except ValueError as error:
        raise InventoryError(str(error)) from error


def _protection_trip_exists(path: pathlib.Path) -> bool:
    """Return whether any bounded protected-engine slot has a safe trip latch."""
    if not path.exists():
        return False
    if path.is_symlink():
        raise InventoryError("protection trip path cannot be a symlink")
    if path.is_file():
        return True
    if not path.is_dir():
        raise InventoryError("protection trip root is not a directory")
    children = list(path.iterdir())
    if len(children) > 64:
        raise InventoryError("protection trip root exceeds the engine-group limit")
    for child in children:
        if not re.fullmatch(r"[0-9a-f]{32}", child.name):
            continue
        if child.is_symlink() or not child.is_dir():
            raise InventoryError("protected-engine slot is unsafe")
        trip = child / "protection-trip.json"
        if trip.is_symlink():
            raise InventoryError("protection trip latch is unsafe")
        if trip.is_file():
            return True
    return False
