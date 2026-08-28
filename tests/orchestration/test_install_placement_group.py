#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import argparse
import pathlib
import tempfile
import types
import unittest
from unittest import mock

from core import cli
from tests.orchestration.helpers import release_identity


class _Store:
    def __init__(
        self,
        members: list[dict] | None = None,
        *,
        service_id: str = "0" * 32,
    ) -> None:
        self._members = members or []
        self.service_id = service_id
        self.groups: list[dict] = []
        self.allocation_states: list[tuple[str, str]] = []

    def __enter__(self):
        return self

    def __exit__(self, *_arguments):
        return None

    def members(self):
        return list(self._members)

    def placement_groups(self):
        return []

    def register_placement_group(self, plan, **kwargs):
        value = {
            "placement_group_id": plan["placement_group_id"],
            "state": "staging",
            "endpoint": None,
        }
        self.groups.append(value)
        return value

    def set_placement_group_endpoint(self, placement_group_id, endpoint, *, state):
        value = {
            "placement_group_id": placement_group_id,
            "state": state,
            "endpoint": endpoint,
        }
        self.groups.append(value)
        return value

    def ensure_model_service(self, _model):
        return {"service_id": self.service_id}

    def reserve_placement_devices(self, _placement_group_id, _placements):
        return None

    def set_placement_group_allocation_state(self, placement_group_id, state):
        self.allocation_states.append((placement_group_id, state))


class PlacementGroupInstallTests(unittest.TestCase):
    def test_site_control_endpoint_preserves_ports_and_brackets_ipv6(self) -> None:
        self.assertEqual(
            cli._site_control_endpoint("child.example:9770"),
            "https://child.example:9770",
        )
        self.assertEqual(
            cli._site_control_endpoint("2001:db8::1"),
            "https://[2001:db8::1]:9770",
        )
        self.assertEqual(
            cli._site_control_endpoint("[2001:db8::1]:9771"),
            "https://[2001:db8::1]:9771",
        )

    def test_normal_install_delegates_to_signed_catalog_node_planner(self) -> None:
        arguments = argparse.Namespace(
            model="example-model",
            engine=None,
            catalog=None,
            no_service=False,
        )
        with mock.patch.object(
            cli, "_install_catalog_nodes", return_value=17
        ) as install_nodes:
            self.assertEqual(cli.install(arguments), 17)
        install_nodes.assert_called_once_with(arguments)

    def test_post_start_finalization_failure_stops_group_and_marks_failed(self) -> None:
        member_ids = ("a" * 32,)
        records = [
            {
                "member_id": member_id,
                "state": "active",
                "address": f"{index}.example:9770",
                "certificate_sha256": str(index + 3) * 64,
            }
            for index, member_id in enumerate(member_ids)
        ]
        node_id = "f" * 32
        service_id = cli.logical_service_id(node_id, "example-model")
        store = _Store(records, service_id=service_id)
        placement = types.SimpleNamespace(
            node_ids=member_ids,
            topology_sha256="4" * 64,
            device_uuids={member_ids[0]: ("GPU-fixture",)},
        )
        graph = mock.Mock()
        manifest = {
            "model": {"alias": "example-model"},
            "engine": {
                "name": "example-engine",
                "model_format": "huggingface-snapshot",
                "cache_provider": "none",
            },
            "cache": {"persistent": False},
            "serving": {
                "max_connections": 16,
                "max_active_requests": 8,
                "max_context_tokens": 65536,
            },
        }
        runtime = types.SimpleNamespace(
            digest="6" * 64,
            runtime={
                "id": "engine--owner--model--one-node",
                "version": "1.0.0",
                "engine": {"distribution": {"kind": "oci-container"}},
                "orchestration": None,
            },
        )
        instances = []

        class Orchestrator:
            def __init__(self, **kwargs):
                self.plan = kwargs["plan"]
                self.engine_credential = "x" * 48
                self.engine_credential_sha256 = "5" * 64
                self.results = {}
                self.states = {
                    placement.placement_id: {"state": "staged"}
                    for placement in self.plan.placements
                }
                self.stop_calls = 0
                instances.append(self)

            def stage(self):
                return None

            def start(self):
                certificate = (
                    "-----BEGIN CERTIFICATE-----\nfixture\n"
                    "-----END CERTIFICATE-----\n"
                )
                self.results = {
                    placement.placement_id: {
                        "endpoint": "https://192.0.2.10:18000",
                        "tls_certificate_pem": certificate,
                        "tls_certificate_sha256": "6" * 64,
                    }
                    for placement in self.plan.placements
                }
                for state in self.states.values():
                    state["state"] = "running"

            def stop(self):
                self.stop_calls += 1
                for state in self.states.values():
                    state["state"] = "stopped"

        arguments = argparse.Namespace(
            no_service=False,
            no_start=False,
            no_build_image=False,
        )
        target = {
            "id": "one-node",
            "placement": {
                "strategy": "single",
                "node_count": 1,
                "interconnect": {"kind": "none"},
            },
        }
        sealed_release = release_identity(manifest_sha256="7" * 64)
        sealed_release.update({
            "logical_model": "example-model",
            "source": "registry.example/runtime@sha256:" + "9" * 64,
            "target_id": "one-node",
        })
        with tempfile.TemporaryDirectory() as directory:
            with (
                mock.patch.object(
                    cli,
                    "resolve_manifest_placement",
                    return_value=(types.SimpleNamespace(site_id=node_id), graph, placement),
                ),
                mock.patch.object(cli, "verify_descriptor", return_value=runtime),
                mock.patch.object(cli, "validate_target_binding", return_value=None),
                mock.patch.object(cli, "target_contract", return_value=target),
                mock.patch.object(cli, "sha256_file", return_value="7" * 64),
                mock.patch.object(
                    cli,
                    "service_placement_identity",
                    return_value={"placement_id": "8" * 32},
                ),
                mock.patch.object(cli, "_site_store", return_value=store),
                mock.patch.object(cli, "PlacementGroupOrchestrator", Orchestrator),
                mock.patch.object(cli, "site_config_root", return_value=pathlib.Path(directory)),
                mock.patch.object(
                    cli,
                    "secrets_root",
                    return_value=pathlib.Path(directory) / "secrets",
                ),
                mock.patch.object(cli, "certificate_sha256", return_value="6" * 64),
                mock.patch.object(
                    cli,
                    "write_selection",
                    side_effect=cli.RuntimePackError("synthetic receipt failure"),
                ),
                self.assertRaisesRegex(cli.LetsInferError, "runtime receipt failed"),
            ):
                cli.install_placement_group(
                    arguments,
                    source="registry.example/runtime@sha256:" + "9" * 64,
                    manifest_path=pathlib.Path("/control/release.json"),
                    manifest=manifest,
                    control_root=pathlib.Path("/control"),
                    receipt={"object_root": "/objects/runtime"},
                    release_identity=sealed_release,
                )

        self.assertEqual(instances[0].stop_calls, 1)
        self.assertEqual(store.groups[-1]["state"], "failed")
        self.assertIsNone(store.groups[-1]["endpoint"])
        self.assertEqual(store.allocation_states[-1][1], "released")


if __name__ == "__main__":
    unittest.main()
