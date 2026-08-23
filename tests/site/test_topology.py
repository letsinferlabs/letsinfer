# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import copy
import pathlib
import tempfile
import time
import unittest
from unittest import mock

from core.site import inventory
from core.site.topology import TopologyError, TopologyGraph


def facts(member_id: str, peer_id: str | None = None) -> dict:
    links = []
    if peer_id is not None:
        links.append({
            "peer_member_id": peer_id, "interface": "enp1s0", "kind": "connectx",
            "speed_mbps": 200_000, "mtu": 9000, "rdma": True, "verified": True,
            "observed_at_unix": int(time.time()),
            "peer_certificate_sha256": "a" * 64,
            "proof_sha256": "b" * 64,
        })
    return {
        "schema_version": 1,
        "member_id": member_id,
        "observed_at_unix": int(time.time()),
        "platform": "linux/arm64",
        "accelerator": {
            "vendor": "nvidia", "architecture": "sm_121", "count": 1,
            "partitioning": "full-device", "minimum_memory_gib": 128,
            "devices": ["GPU-0"],
        },
        "memory": {"topology": "unified", "total_gib": 128, "available_gib": 100},
        "storage": {"total_gib": 1000, "available_gib": 700, "cache_available_gib": 600},
        "network": {
            "interfaces": [{
                "name": "enp1s0", "addresses": ["192.0.2.10"], "mtu": 9000,
                "speed_mbps": 200_000, "rdma": True,
            }],
            "links": links,
        },
        "software": {"driver": "fixture", "container_runtime": "fixture", "letsinfer_version": "0.11.0-rc.2"},
        "health": {"state": "healthy", "memory_pressure": False, "protection_trip": False, "max_temperature_c": 55},
    }


def target(strategy: str, count: int) -> dict:
    return {
        "id": f"fixture-{strategy}",
        "platform": "linux/arm64",
        "accelerator": {
            "vendor": "nvidia", "architecture": "sm_121", "count": 1,
            "partitioning": "full-device", "minimum_memory_gib": 120,
        },
        "memory": {"topology": "unified", "minimum_total_gib": 120},
        "placement": {
            "strategy": strategy, "member_count": count,
            "engine_strategy": "fixture",
            "interconnect": {
                "kind": "connectx", "rdma_required": True,
                "minimum_speed_mbps": 100_000, "minimum_mtu": 9000,
            } if strategy == "parallel" else {
                "kind": "any", "rdma_required": False,
                "minimum_speed_mbps": 0, "minimum_mtu": 0,
            },
        },
    }


class TopologyTests(unittest.TestCase):
    def test_arm_cpu_model_uses_bounded_lscpu_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            proc_root = pathlib.Path(directory)
            (proc_root / "cpuinfo").write_text(
                "processor: 0\nCPU part: 0xd87\n", encoding="ascii"
            )
            payload = (
                '{"lscpu":['
                '{"field":"Model name:","data":"Cortex-X925"},'
                '{"field":"Model name:","data":"Cortex-A725"}]}'
            )
            with mock.patch.object(inventory, "_command", return_value=payload):
                self.assertEqual(
                    inventory._cpu_model(proc_root),
                    "Cortex-X925 / Cortex-A725",
                )

    def test_boolean_schema_and_accelerator_count_are_rejected(self) -> None:
        for field in ("schema_version", "accelerator.count"):
            invalid = facts("1" * 32)
            if field == "schema_version":
                invalid[field] = True
            else:
                invalid["accelerator"]["count"] = True
            with self.subTest(field=field):
                with self.assertRaisesRegex(TopologyError, "schema|count"):
                    TopologyGraph([invalid])

    def test_member_temperature_rejects_boolean_nonfinite_and_impossible_values(self) -> None:
        for value in (True, float("nan"), float("inf"), -2, 251):
            invalid = facts("1" * 32)
            invalid["health"]["max_temperature_c"] = value
            with self.subTest(value=value):
                with self.assertRaisesRegex(TopologyError, "temperature"):
                    TopologyGraph([invalid])

    def test_connectx_no_code_path_requires_live_mlx5_rdma_interface(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "sys/class"
            interface = root / "net/enp1s0"
            (interface / "device").mkdir(parents=True)
            for name, value in (
                ("carrier", "1\n"), ("operstate", "up\n"),
                ("speed", "200000\n"), ("mtu", "9000\n"),
            ):
                (interface / name).write_text(value, encoding="ascii")
            driver = pathlib.Path(directory) / "drivers/mlx5_core"
            driver.mkdir(parents=True)
            (interface / "device/driver").symlink_to(driver, target_is_directory=True)
            (root / "infiniband/mlx5_0/device/net/enp1s0").mkdir(parents=True)
            verified = inventory.verify_direct_connectx_interface(
                "enp1s0", sys_class=root
            )
            self.assertEqual(verified["driver"], "mlx5_core")
            self.assertEqual(verified["speed_mbps"], 200000)
            self.assertEqual(
                inventory.select_direct_connectx_interface(sys_class=root)["interface"],
                "enp1s0",
            )
            (interface / "carrier").write_text("0\n", encoding="ascii")
            with self.assertRaisesRegex(inventory.InventoryError, "carrier"):
                inventory.verify_direct_connectx_interface("enp1s0", sys_class=root)

    def test_connectx_peer_must_route_directly_over_approved_interface(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "sys/class"
            interface = root / "net/enp1s0"
            (interface / "device").mkdir(parents=True)
            for name, value in (
                ("carrier", "1\n"), ("operstate", "up\n"),
                ("speed", "200000\n"), ("mtu", "9000\n"),
            ):
                (interface / name).write_text(value, encoding="ascii")
            driver = pathlib.Path(directory) / "drivers/mlx5_core"
            driver.mkdir(parents=True)
            (interface / "device/driver").symlink_to(driver, target_is_directory=True)
            (root / "infiniband/mlx5_0/device/net/enp1s0").mkdir(parents=True)
            with mock.patch.object(
                inventory,
                "_command",
                return_value='[{"dst":"192.0.2.20","dev":"enp1s0"}]',
            ):
                proof = inventory.verify_direct_connectx_peer(
                    "enp1s0", "192.0.2.20", sys_class=root
                )
            self.assertEqual(proof["peer_address"], "192.0.2.20")
            with mock.patch.object(
                inventory,
                "_command",
                return_value='[{"dst":"192.0.2.20","dev":"eth0"}]',
            ):
                with self.assertRaisesRegex(inventory.InventoryError, "not directly"):
                    inventory.verify_direct_connectx_peer(
                        "enp1s0", "192.0.2.20", sys_class=root
                    )

    def test_local_inventory_uses_stable_devices_and_bounded_facts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            sys_class = root / "sys/class"
            interface = sys_class / "net/enp1s0"
            interface.mkdir(parents=True)
            (interface / "mtu").write_text("9000\n", encoding="ascii")
            (interface / "speed").write_text("200000\n", encoding="ascii")
            rdma = sys_class / "infiniband/mlx5_0/device/net/enp1s0"
            rdma.mkdir(parents=True)
            meminfo = root / "meminfo"
            meminfo.write_text("MemAvailable: 104857600 kB\n", encoding="ascii")
            proc_root = root / "proc"
            (proc_root / "net").mkdir(parents=True)
            (proc_root / "1").mkdir()
            (proc_root / "2").mkdir()
            (proc_root / "uptime").write_text("1234.50 0.0\n", encoding="ascii")
            (proc_root / "cpuinfo").write_text(
                "model name\t: Fixture CPU\n", encoding="ascii"
            )
            (proc_root / "net/route").write_text(
                "Iface Destination Gateway\nenp1s0 00000000 00000000\n",
                encoding="ascii",
            )
            etc_root = root / "etc"
            etc_root.mkdir()
            (etc_root / "os-release").write_text(
                'PRETTY_NAME="Fixture Linux"\n', encoding="utf-8"
            )
            (etc_root / "dgx-release").write_text(
                'DGX_PRETTY_NAME="Fixture DGX"\nDGX_OTA_VERSION="1.2.3"\n',
                encoding="utf-8",
            )
            (etc_root / "machine-id").write_text("a" * 32 + "\n", encoding="ascii")
            dmi = sys_class / "dmi/id"
            dmi.mkdir(parents=True)
            for name, value in (
                ("sys_vendor", "NVIDIA"),
                ("product_name", "DGX Spark"),
                ("board_vendor", "NVIDIA"),
                ("board_name", "Fixture Board"),
                ("bios_version", "1.0"),
            ):
                (dmi / name).write_text(value + "\n", encoding="utf-8")
            nvme = sys_class / "nvme/nvme0"
            nvme.mkdir(parents=True)
            (nvme / "model").write_text("Fixture NVMe\n", encoding="utf-8")
            (nvme / "serial").write_text("NVME-1\n", encoding="utf-8")
            (nvme / "firmware_rev").write_text("FW1\n", encoding="utf-8")
            commands = {
                "ip": '[{"ifname":"enp1s0","addr_info":[{"local":"192.0.2.10"}]}]',
                "driver_version": "600.1",
                "temperature.gpu": "55",
                "docker": "Docker version 30.0.0",
            }

            def command(arguments: list[str]) -> str:
                if arguments[0] == "ip":
                    return commands["ip"]
                if arguments[0] == "docker":
                    return commands["docker"]
                for key in ("driver_version", "temperature.gpu"):
                    if key in arguments[1]:
                        return commands[key]
                raise AssertionError(arguments)

            device = {
                "platform": "linux/arm64",
                "accelerator": {
                    "vendor": "nvidia", "architecture": "sm_121", "count": 1,
                    "partitioning": "full-device", "minimum_memory_gib": 128,
                    "names": ["NVIDIA GB10"],
                    "uuids": ["GPU-fixture"],
                },
                "memory": {"topology": "unified", "total_gib": 128},
            }
            with mock.patch.object(inventory, "_command", side_effect=command):
                result = inventory.collect_local_facts(
                    "1" * 32,
                    device,
                    data_path=root / "data",
                    protection_trip_path=root / "trip.json",
                    memory_pressure_available_bytes=16 << 30,
                    product_version="0.11.0-rc.2",
                    sys_class=sys_class,
                    meminfo_path=meminfo,
                    proc_root=proc_root,
                    etc_root=etc_root,
                    now_unix=1_700_000_000,
                )
            self.assertEqual(result["accelerator"]["devices"], ["GPU-fixture"])
            self.assertEqual(result["network"]["interfaces"][0]["speed_mbps"], 200000)
            self.assertTrue(result["network"]["interfaces"][0]["rdma"])
            self.assertEqual(result["memory"]["available_gib"], 100)
            self.assertFalse(result["health"]["memory_pressure"])
            self.assertEqual(result["inventory"]["product_name"], "DGX Spark")
            self.assertEqual(result["inventory"]["operating_system"], "Fixture Linux")
            self.assertEqual(result["inventory"]["cpu_model"], "Fixture CPU")
            self.assertEqual(result["inventory"]["gpu_name"], "NVIDIA GB10")
            self.assertEqual(result["inventory"]["nvme_model"], "Fixture NVMe")
            self.assertEqual(result["inventory"]["uptime_seconds"], 1234)
            self.assertEqual(result["inventory"]["process_count"], 2)

            meminfo.write_text("MemAvailable: 10485760 kB\n", encoding="ascii")
            with mock.patch.object(inventory, "_command", side_effect=command):
                pressured = inventory.collect_local_facts(
                    "1" * 32,
                    device,
                    data_path=root / "data",
                    protection_trip_path=root / "trip.json",
                    memory_pressure_available_bytes=16 << 30,
                    product_version="0.11.0-rc.2",
                    sys_class=sys_class,
                    meminfo_path=meminfo,
                    proc_root=proc_root,
                    etc_root=etc_root,
                    now_unix=1_700_000_000,
                )
            self.assertTrue(pressured["health"]["memory_pressure"])
            self.assertEqual(pressured["health"]["state"], "healthy")

    def test_parallel_requires_bidirectional_verified_link(self) -> None:
        left, right = "1" * 32, "2" * 32
        graph = TopologyGraph([facts(left, right), facts(right, left)])
        placement = graph.resolve(target("parallel", 2), coordinator_id=left)
        self.assertEqual(placement.member_ids, (left, right))
        self.assertEqual(
            graph.engine_addresses(
                placement, target("parallel", 2)["placement"]["interconnect"]
            ),
            {left: "192.0.2.10", right: "192.0.2.10"},
        )
        broken = facts(right)
        with self.assertRaisesRegex(TopologyError, "no topology-compatible"):
            TopologyGraph([facts(left, right), broken]).resolve(
                target("parallel", 2), coordinator_id=left
            )

    def test_links_are_bound_to_enrolled_peer_certificates_and_interfaces(self) -> None:
        left, right = "1" * 32, "2" * 32
        certificates = {left: "a" * 64, right: "a" * 64}
        graph = TopologyGraph(
            [facts(left, right), facts(right, left)],
            member_certificates=certificates,
        )
        self.assertTrue(graph.links)
        with self.assertRaisesRegex(TopologyError, "certificate changed"):
            TopologyGraph(
                [facts(left, right), facts(right, left)],
                member_certificates={left: "a" * 64, right: "d" * 64},
            )
        exaggerated = facts(left, right)
        exaggerated["network"]["links"][0]["speed_mbps"] += 1
        with self.assertRaisesRegex(TopologyError, "exceeds"):
            TopologyGraph([exaggerated, facts(right, left)])

    def test_memory_telemetry_does_not_block_placement_but_stale_facts_do(self) -> None:
        member_id = "1" * 32
        pressured = facts(member_id)
        pressured["health"]["memory_pressure"] = True
        placement = TopologyGraph([pressured]).resolve(
            target("single", 1), coordinator_id=member_id
        )
        self.assertEqual(placement.member_ids, (member_id,))
        stale = facts(member_id)
        stale["observed_at_unix"] -= 31
        with self.assertRaisesRegex(TopologyError, "stale"):
            TopologyGraph([stale])

    def test_catalog_selection_prefers_parallel_then_single(self) -> None:
        left, right = "1" * 32, "2" * 32
        graph = TopologyGraph([facts(left, right), facts(right, left)])
        targets = {
            candidate["id"]: candidate
            for candidate in (
                target("single", 1),
                target("parallel", 2),
            )
        }
        selected = graph.resolve_catalog_targets(targets, coordinator_id=left)
        self.assertEqual(selected.target_id, "fixture-parallel")
        self.assertEqual(selected.placement.member_ids, (left, right))

        del targets["fixture-parallel"]
        selected = graph.resolve_catalog_targets(targets, coordinator_id=left)
        self.assertEqual(selected.target_id, "fixture-single")

    def test_catalog_selection_rejects_same_strategy_ambiguity(self) -> None:
        member_id = "1" * 32
        first = target("single", 1)
        second = copy.deepcopy(first)
        second["id"] = "fixture-single-other"
        graph = TopologyGraph([facts(member_id)])
        with self.assertRaisesRegex(TopologyError, "ambiguous.*fixture-single"):
            graph.resolve_catalog_targets(
                {first["id"]: first, second["id"]: second},
                coordinator_id=member_id,
            )


if __name__ == "__main__":
    unittest.main()
