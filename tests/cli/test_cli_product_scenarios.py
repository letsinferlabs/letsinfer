#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Exact public-command outputs over one hermetic mocked product state."""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import pathlib
import tempfile
import types
import unittest
from unittest import mock

from core import cli
from core.actions import ACTIONS, MutationClass, action
from tests.regression.cli_cases import CLI_CASES


FIXTURE = pathlib.Path(__file__).parent / "fixtures/product-command-scenarios.json"


class MockProductEnvironment:
    def __init__(self, state: dict[str, object]) -> None:
        self.state = state

    def output(self, action_id: str) -> dict[str, object]:
        node = self.state["node"]
        nodes = self.state["nodes"]
        models = self.state["models"]
        benchmark = self.state["benchmark"]
        controllers = self.state["controllers"]
        keys = self.state["keys"]
        exposure = self.state["exposure"]
        audit = self.state["audit"]
        updates = self.state["updates"]
        exact: dict[str, dict[str, object]] = {
            "status": {
                "node": node,
                "nodes": nodes,
                "hardware": self.state["hardware"],
                "models": models,
                "services": self.state["services"],
            },
            "topology": {
                "nodes": nodes,
                "links": [
                    {
                        "left": nodes[0]["node_id"],
                        "right": nodes[1]["node_id"],
                        "verified": nodes[1]["state"] == "active",
                    }
                ],
                "models": models,
            },
            "doctor": {
                "ready": all(item["passed"] for item in self.state["checks"]),
                "checks": self.state["checks"],
            },
            "uninstall": {"removed": True, "models_preserved": False},
            "node.info": {"node": node, "hardware": self.state["hardware"]},
            "node.list": {"nodes": nodes},
            "node.usage": {
                "home": "/mock/letsinfer",
                "total_allocated_bytes": 150000000000,
                "total_reclaimable_bytes": 12000000000,
                "categories": [
                    {
                        "id": "models",
                        "allocated_bytes": 140000000000,
                        "reclaimable_bytes": 12000000000,
                    }
                ],
            },
            "node.add": {"discovered": self.state["discovered"], "pending": []},
            "node.pause": {"node_id": "child-1", "state": "paused"},
            "node.resume": {"node_id": "child-1", "state": "active"},
            "node.remove": {"node_id": "child-1", "state": "removed"},
            "model.list": {"models": models},
            "model.install": {"model": "ling-3-flash", "nodes": ["main-1"], "state": "running"},
            "model.remove": {"model": "ling-3-flash", "state": "removed"},
            "model.pause": {"model": "ling-3-flash", "state": "paused"},
            "model.resume": {"model": "ling-3-flash", "state": "running"},
            "model.restart": {"model": "ling-3-flash", "state": "running", "restarted": True},
            "model.recover": {"model": "ling-3-flash", "state": "running", "trip_cleared": True},
            "model.rollback": {"model": "ling-3-flash", "version": "0.1.0-rc.1"},
            "model.logs": {"model": "ling-3-flash", "lines": ["engine ready"]},
            "benchmark.run": {"job_id": "benchmark-1", "state": "running"},
            "benchmark.list": {"cells": benchmark["cells"]},
            "benchmark.status": benchmark,
            "benchmark.stop": {"job_id": "benchmark-1", "state": "cancelled"},
            "benchmark.clean": {"removed_roots": 2},
            "benchmark.verification.run": {"job_id": "verification-1", "state": "running"},
            "benchmark.verification.status": {"job_id": "verification-1", "state": "measuring"},
            "benchmark.verification.stop": {"job_id": "verification-1", "state": "cancelled"},
            "auth.controller.add": {"controller": "mac-1", "state": "paired"},
            "auth.controller.list": {"controllers": controllers},
            "auth.controller.revoke": {"controller": "mac-1", "state": "revoked"},
            "auth.key.create": {"key_id": "key-2", "secret": "shown-once"},
            "auth.key.list": {"keys": keys},
            "auth.key.show": {"key": keys[0]},
            "auth.key.rotate": {"key_id": "key-1", "secret": "rotated-once"},
            "auth.key.revoke": {"key_id": "key-1", "state": "revoked"},
            "auth.key.update": {"key_id": "key-1", "concurrency": 4},
            "exposure.status": exposure,
            "exposure.enable": {"enabled": True, "url": exposure["url"]},
            "exposure.disable": {"enabled": False},
            "audit.list": {"events": audit["events"]},
            "audit.show": {"event": audit["events"][0]},
            "audit.verify": {"valid": True, "events": len(audit["events"])},
            "audit.export": {"exported": len(audit["events"])},
            "update.check": updates,
            "update.core": {"component": "core", "version": updates["core"]},
            "update.model": {"component": "model", "updates": updates["models"]},
        }
        return {"action": action_id, **exact[action_id]}

    def handler(self, action_id: str):
        def invoke(_arguments: argparse.Namespace) -> int:
            print(json.dumps(self.output(action_id), sort_keys=True))
            return 0

        return invoke


def public_actions() -> set[str]:
    return {
        name
        for name, metadata in ACTIONS.items()
        if metadata.mutation is not MutationClass.INTERNAL
    }


class ProductCommandScenarioTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def run_command(
        self,
        action_id: str,
        state_name: str,
    ) -> dict[str, object]:
        environment = MockProductEnvironment(self.fixture["states"][state_name])
        arguments = cli.parser().parse_args(list(CLI_CASES[action_id]))
        self.assertEqual(arguments.action_id, action_id)
        arguments.action = environment.handler(action_id)
        parsed = mock.Mock()
        parsed.parse_args.return_value = arguments
        stdout = io.StringIO()
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as temporary:
            with (
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
                mock.patch.object(cli, "parser", return_value=parsed),
                mock.patch.object(
                    cli,
                    "source_root",
                    return_value=pathlib.Path(temporary),
                ),
                mock.patch.object(
                    cli,
                    "_authorize_command",
                    return_value=(action(action_id), None),
                ),
                mock.patch.object(cli, "_audit_marker", return_value=None),
                mock.patch.object(cli, "_audit_command_result"),
            ):
                result = cli.main(["scenario"])
        return {
            "exit_code": result,
            "stdout": json.loads(stdout.getvalue()),
            "stderr": stderr.getvalue(),
        }

    def test_every_public_leaf_matches_the_exact_healthy_output_fixture(self) -> None:
        expected = self.fixture["expected"]["healthy"]
        self.assertEqual(set(expected), public_actions())
        for action_id in sorted(public_actions()):
            with self.subTest(action=action_id):
                self.assertEqual(
                    self.run_command(action_id, "healthy"),
                    expected[action_id],
                )

    def test_degraded_read_surfaces_match_the_exact_output_fixture(self) -> None:
        expected = self.fixture["expected"]["degraded"]
        for action_id, value in expected.items():
            with self.subTest(action=action_id):
                self.assertEqual(self.run_command(action_id, "degraded"), value)

    def test_real_status_json_keeps_complete_mock_state_when_models_exist(self) -> None:
        groups = [
            {
                "group_id": "group-1",
                "model": "ling-3-flash",
                "runtime": "runtime-a",
                "target": "dgx-spark",
                "state": "running",
            },
            {
                "group_id": "group-2",
                "model": "ling-3-flash",
                "runtime": "runtime-a",
                "target": "dgx-spark",
                "state": "running",
            },
        ]
        node_details = {
            "node": {"member_id": "main-1", "state": "active"},
            "nodes": [
                {"member_id": "main-1", "state": "active"},
                {"member_id": "child-1", "state": "paused"},
            ],
            "hardware": {"accelerators": [{"uuid": "GPU-1"}]},
            "links": [{"left": "main-1", "right": "child-1", "verified": True}],
        }
        identity = types.SimpleNamespace(role="main", member_id="main-1")
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = pathlib.Path(temporary)
            identity_path = mock.Mock()
            identity_path.exists.return_value = True
            with (
                contextlib.redirect_stdout(output),
                mock.patch.object(cli, "site_identity_path", return_value=identity_path),
                mock.patch.object(cli, "read_site_identity", return_value=identity),
                mock.patch.object(cli, "identity_json", return_value={"role": "main"}),
                mock.patch.object(cli, "_engine_group_status", return_value=groups),
                mock.patch.object(
                    cli,
                    "active_service_config_path",
                    return_value=temporary_path / "absent-service.json",
                ),
                mock.patch.object(cli, "site_config_root", return_value=temporary_path),
                mock.patch.object(
                    cli,
                    "_service_state",
                    return_value=("enabled", "active", 1024),
                ),
                mock.patch.object(cli, "api_status", return_value=200),
                mock.patch.object(
                    cli,
                    "local_inference_endpoint",
                    return_value="http://main.local:8000/v1",
                ),
                mock.patch.object(
                    cli,
                    "_complete_local_node_status",
                    return_value=node_details,
                ),
                mock.patch.object(cli, "_local_controller_telemetry", return_value={}),
                mock.patch.object(
                    cli,
                    "runtime_lifecycle",
                    return_value={"state": "ready", "reason": "healthy"},
                ),
            ):
                result = cli.status(
                    argparse.Namespace(
                        json=True,
                        name=None,
                        config=None,
                        model=None,
                        _single_snapshot=True,
                    )
                )
        payload = json.loads(output.getvalue())
        self.assertEqual(result, 0)
        self.assertEqual(payload["engine_groups"], groups)
        self.assertEqual(payload["models"], [{
            "group_ids": ["group-1", "group-2"],
            "model": "ling-3-flash",
            "replicas": 2,
            "runtimes": ["runtime-a"],
            "state": "running",
            "targets": ["dgx-spark"],
        }])
        for key, value in node_details.items():
            self.assertEqual(payload[key], value)

    def test_real_node_pause_json_uses_public_paused_state(self) -> None:
        store = mock.Mock()
        store.set_member_draining.return_value = {
            "member_id": "child-1",
            "state": "draining",
        }
        context = mock.MagicMock()
        context.__enter__.return_value = store
        output = io.StringIO()
        identity = types.SimpleNamespace(
            role="main",
            member_id="main-1",
            coordinator_id="main-1",
        )
        rows = [
            {
                "member_id": "child-1",
                "display_name": "Workshop",
                "role": "child",
                "state": "active",
            }
        ]
        with (
            contextlib.redirect_stdout(output),
            mock.patch.object(cli, "read_site_identity", return_value=identity),
            mock.patch.object(cli, "_node_command_rows", return_value=rows),
            mock.patch.object(cli, "_site_store", return_value=context),
        ):
            result = cli.member_drain_command(
                argparse.Namespace(member="child-1", json=True, yes=True)
            )
        self.assertEqual(result, 0)
        self.assertEqual(
            json.loads(output.getvalue()),
            {"member_id": "child-1", "state": "paused"},
        )

    def test_real_model_pause_uses_public_paused_state(self) -> None:
        output = io.StringIO()
        with (
            contextlib.redirect_stdout(output),
            mock.patch.object(
                cli,
                "_engine_group_lifecycle",
                return_value={
                    "group_id": "group-1",
                    "member_states": [{"member_id": "main-1"}],
                },
            ),
            mock.patch.object(cli, "qualification_service_config_path") as path,
            mock.patch.object(cli, "_human_presenter", return_value=None),
        ):
            path.return_value.is_file.return_value = False
            result = cli.model_pause_command(
                argparse.Namespace(model="ling-3-flash", action_id="model.pause")
            )
        self.assertEqual(result, 0)
        self.assertEqual(output.getvalue(), "PAUSED group=group-1 members=1\n")


if __name__ == "__main__":
    unittest.main()
