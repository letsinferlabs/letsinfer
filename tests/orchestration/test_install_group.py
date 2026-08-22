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


class _Store:
    def __init__(self, members: list[dict] | None = None) -> None:
        self._members = members or []
        self.placements: list[dict] = []

    def __enter__(self):
        return self

    def __exit__(self, *_arguments):
        return None

    def members(self):
        return list(self._members)

    def engine_groups(self):
        return []

    def set_placement(self, placement):
        self.placements.append(dict(placement))
        return dict(placement)


class EngineGroupInstallTests(unittest.TestCase):
    def test_normal_install_dispatches_a_multi_member_target(self) -> None:
        source = "registry.example/runtime@sha256:" + "1" * 64
        manifest_path = pathlib.Path("/control/releases/release.json")
        control_root = pathlib.Path("/control")
        manifest = {
            "serving": {"qualified": True},
            "target": {"placement": {"strategy": "distributed"}},
        }
        receipt = {"source": source}
        arguments = argparse.Namespace(
            model="example-model",
            engine=None,
            catalog=None,
            no_service=False,
        )
        with (
            mock.patch.object(
                cli,
                "_runtime_source_for_install",
                return_value=(source, "recommended", "1.0.0", "target", "2" * 64),
            ),
            mock.patch.object(
                cli,
                "prepare_runtime_install",
                return_value=(manifest_path, manifest, control_root, receipt),
            ),
            mock.patch.object(cli, "verify_runtime_sources"),
            mock.patch.object(cli, "user_lingering_enabled", return_value=True),
            mock.patch.object(
                cli,
                "target_contract",
                return_value={"placement": {"strategy": "distributed"}},
            ),
            mock.patch.object(cli, "install_engine_group", return_value=17) as install_group,
        ):
            self.assertEqual(cli.install(arguments), 17)

        install_group.assert_called_once_with(
            arguments,
            source=source,
            manifest_path=manifest_path,
            manifest=manifest,
            control_root=control_root,
            receipt=receipt,
        )

    def test_post_start_finalization_failure_stops_group_and_marks_failed(self) -> None:
        member_ids = ("a" * 32, "b" * 32)
        records = [
            {
                "member_id": member_id,
                "state": "active",
                "address": f"{index}.example:9770",
                "certificate_sha256": str(index + 3) * 64,
            }
            for index, member_id in enumerate(member_ids)
        ]
        store = _Store(records)
        placement = types.SimpleNamespace(
            strategy="distributed",
            member_ids=member_ids,
            engine_coordinator_id=member_ids[0],
            topology_sha256="4" * 64,
        )
        graph = mock.Mock()
        graph.engine_addresses.return_value = {
            member_ids[0]: "192.0.2.10",
            member_ids[1]: "192.0.2.11",
        }
        contract = {
            "schema_version": 1,
            "strategy": "distributed",
            "member_count": 2,
            "engine_strategy": "tensor-parallel",
            "failure_policy": "whole-group",
            "minimum_healthy_members": 2,
            "startup_order": ["engine-member", "engine-coordinator"],
            "roles": {
                "engine-member": {
                    "assignment": "members",
                    "launcher": "runtime-command",
                    "port_count": 2,
                    "command": ["/opt/runtime/member"],
                    "environment": {},
                    "inference_endpoint": False,
                    "readiness": {
                        "kind": "exec",
                        "command": ["/opt/runtime/ready"],
                        "interval_seconds": 1,
                        "timeout_seconds": 1,
                        "retries": 2,
                    },
                },
                "engine-coordinator": {
                    "assignment": "engine-coordinator",
                    "launcher": "runtime-command",
                    "port_count": 2,
                    "command": ["/opt/runtime/coordinator"],
                    "environment": {},
                    "inference_endpoint": True,
                    "readiness": {
                        "kind": "exec",
                        "command": ["/opt/runtime/ready"],
                        "interval_seconds": 1,
                        "timeout_seconds": 1,
                        "retries": 2,
                    },
                },
            },
        }
        manifest = {
            "model": {"alias": "example-model"},
            "serving": {
                "max_connections": 16,
                "max_active_requests": 8,
                "max_context_tokens": 65536,
            },
        }
        runtime = types.SimpleNamespace(
            digest="5" * 64,
            runtime={
                "id": "engine--owner--model--two-node",
                "version": "1.0.0",
                "orchestration": contract,
            },
        )
        instances = []

        class Orchestrator:
            def __init__(self, **kwargs):
                self.plan = kwargs["plan"]
                self.engine_credential = "x" * 48
                self.results = {}
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
                    assignment.member_id: {
                        "endpoint": "https://192.0.2.10:18000",
                        "tls_certificate_pem": certificate,
                        "tls_certificate_sha256": "6" * 64,
                    }
                    for assignment in self.plan.assignments
                }

            def stop(self):
                self.stop_calls += 1

        arguments = argparse.Namespace(
            no_service=False,
            no_start=False,
            no_build_image=False,
        )
        target = {
            "id": "two-node",
            "placement": {
                "strategy": "distributed",
                "interconnect": {"kind": "connectx"},
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            with (
                mock.patch.object(cli, "resolve_manifest_placement", return_value=(mock.sentinel.identity, graph, placement)),
                mock.patch.object(cli, "verify_descriptor", return_value=runtime),
                mock.patch.object(cli, "validate_target_binding", return_value=contract),
                mock.patch.object(cli, "target_contract", return_value=target),
                mock.patch.object(cli, "sha256_file", return_value="7" * 64),
                mock.patch.object(
                    cli,
                    "service_placement_identity",
                    return_value={"placement_id": "8" * 32},
                ),
                mock.patch.object(cli, "_site_store", return_value=store),
                mock.patch.object(cli, "EngineGroupOrchestrator", Orchestrator),
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
                cli.install_engine_group(
                    arguments,
                    source="registry.example/runtime@sha256:" + "9" * 64,
                    manifest_path=pathlib.Path("/control/release.json"),
                    manifest=manifest,
                    control_root=pathlib.Path("/control"),
                    receipt={"object_root": "/objects/runtime"},
                )

        self.assertEqual(instances[0].stop_calls, 1)
        self.assertEqual(store.placements[-1]["state"], "failed")
        self.assertEqual(store.placements[-1]["endpoints"], [])


if __name__ == "__main__":
    unittest.main()
