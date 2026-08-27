#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import os
import pathlib
import plistlib
import subprocess
import tempfile
import unittest

from core.platform.macos import (
    GATEWAY_LABEL,
    LAUNCHD_BOOTSTRAP_RETRY_DELAY_SECONDS,
    NODE_LABEL,
    LaunchAgentTransaction,
    LaunchAgent,
    MacOSServiceError,
    install_launch_agent,
    remove_launch_agent,
    render_launch_agent,
)


class FakeRunner:
    def __init__(self) -> None:
        self.commands: list[tuple[str, ...]] = []
        self.loaded = False

    def __call__(self, command: object) -> subprocess.CompletedProcess[str]:
        value = tuple(str(item) for item in command)  # type: ignore[arg-type]
        self.commands.append(value)
        if value[:2] == ("launchctl", "bootstrap"):
            self.loaded = True
        elif value[:2] == ("launchctl", "bootout"):
            self.loaded = False
        return subprocess.CompletedProcess(
            value,
            0 if value[:2] != ("launchctl", "print") or self.loaded else 1,
            "",
            "",
        )


class ScriptedBootstrapRunner(FakeRunner):
    def __init__(self) -> None:
        super().__init__()
        self.bootstrap_results: list[tuple[int, str]] = []

    def __call__(self, command: object) -> subprocess.CompletedProcess[str]:
        value = tuple(str(item) for item in command)  # type: ignore[arg-type]
        if value[:2] == ("launchctl", "bootstrap") and self.bootstrap_results:
            self.commands.append(value)
            returncode, detail = self.bootstrap_results.pop(0)
            if returncode == 0:
                self.loaded = True
            return subprocess.CompletedProcess(value, returncode, "", detail)
        return super().__call__(value)


class MultiServiceRunner:
    def __init__(self) -> None:
        self.commands: list[tuple[str, ...]] = []
        self.loaded: set[str] = set()

    def __call__(self, command: object) -> subprocess.CompletedProcess[str]:
        value = tuple(str(item) for item in command)  # type: ignore[arg-type]
        self.commands.append(value)
        if value[:2] == ("launchctl", "bootstrap"):
            self.loaded.add(pathlib.Path(value[-1]).stem)
        elif value[:2] == ("launchctl", "bootout"):
            self.loaded.discard(value[-1].rsplit("/", 1)[-1])
        if value[:2] == ("launchctl", "print"):
            returncode = 0 if value[-1].rsplit("/", 1)[-1] in self.loaded else 1
        else:
            returncode = 0
        return subprocess.CompletedProcess(value, returncode, "", "")


class MacOSServiceTests(unittest.TestCase):
    def test_render_is_direct_deterministic_and_private(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = pathlib.Path(temporary)
            agent = LaunchAgent(
                label=NODE_LABEL,
                arguments=("/opt/letsinfer/bin/letsinfer", "node-agent", "--port", "9770"),
                environment={"PYTHONDONTWRITEBYTECODE": "1"},
            )
            first = render_launch_agent(agent, home=home)
            second = render_launch_agent(agent, home=home)
            self.assertEqual(first, second)
            value = plistlib.loads(first)
            self.assertEqual(value["ProgramArguments"], list(agent.arguments))
            self.assertNotIn("Program", value)
            self.assertEqual(value["Umask"], 0o077)
            self.assertTrue(value["KeepAlive"])

    def test_install_uses_bootstrap_enable_and_kickstart(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = pathlib.Path(temporary)
            runner = MultiServiceRunner()
            agent = LaunchAgent(
                label=GATEWAY_LABEL,
                arguments=("/opt/letsinfer/bin/letsinfer", "gateway", "--port", "8000"),
            )
            install_launch_agent(agent, home=home, runner=runner)
            self.assertTrue(
                (home / "Library/LaunchAgents/ai.letsinfer.gateway.plist").is_file()
            )
            actions = [command[1] for command in runner.commands if command[0] == "launchctl"]
            self.assertIn("bootstrap", actions)
            self.assertIn("enable", actions)
            self.assertIn("kickstart", actions)
            self.assertNotIn("load", actions)

    def test_replacement_retries_transient_launchd_bootstrap_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = pathlib.Path(temporary)
            runner = ScriptedBootstrapRunner()
            original = LaunchAgent(
                label=GATEWAY_LABEL,
                arguments=("/opt/letsinfer/old", "gateway", "--port", "8000"),
            )
            replacement = LaunchAgent(
                label=GATEWAY_LABEL,
                arguments=("/opt/letsinfer/new", "gateway", "--port", "8000"),
            )
            install_launch_agent(original, home=home, runner=runner)
            runner.bootstrap_results = [
                (5, "Bootstrap failed: 5: Input/output error"),
                (5, "Bootstrap failed: 5: Input/output error"),
                (0, ""),
            ]
            delays: list[float] = []

            install_launch_agent(
                replacement,
                home=home,
                runner=runner,
                sleeper=delays.append,
            )

            self.assertEqual(
                delays,
                [
                    LAUNCHD_BOOTSTRAP_RETRY_DELAY_SECONDS,
                    LAUNCHD_BOOTSTRAP_RETRY_DELAY_SECONDS,
                ],
            )
            path = home / "Library/LaunchAgents/ai.letsinfer.gateway.plist"
            self.assertEqual(
                plistlib.loads(path.read_bytes())["ProgramArguments"],
                list(replacement.arguments),
            )
            self.assertTrue(runner.loaded)

    def test_rollback_retries_transient_launchd_bootstrap_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = pathlib.Path(temporary)
            runner = ScriptedBootstrapRunner()
            original = LaunchAgent(
                label=GATEWAY_LABEL,
                arguments=("/opt/letsinfer/old", "gateway", "--port", "8000"),
            )
            replacement = LaunchAgent(
                label=GATEWAY_LABEL,
                arguments=("/opt/letsinfer/new", "gateway", "--port", "8000"),
            )
            install_launch_agent(original, home=home, runner=runner)
            runner.bootstrap_results = [
                (64, "Bootstrap failed: invalid service"),
                (5, "Bootstrap failed: 5: Input/output error"),
                (0, ""),
            ]
            delays: list[float] = []

            with self.assertRaisesRegex(
                MacOSServiceError, "previous service restored"
            ):
                install_launch_agent(
                    replacement,
                    home=home,
                    runner=runner,
                    sleeper=delays.append,
                )

            self.assertEqual(
                delays, [LAUNCHD_BOOTSTRAP_RETRY_DELAY_SECONDS]
            )
            path = home / "Library/LaunchAgents/ai.letsinfer.gateway.plist"
            self.assertEqual(
                plistlib.loads(path.read_bytes())["ProgramArguments"],
                list(original.arguments),
            )
            self.assertTrue(runner.loaded)

    def test_shell_and_relative_executables_are_rejected(self) -> None:
        with self.assertRaises(MacOSServiceError):
            render_launch_agent(
                LaunchAgent(label=NODE_LABEL, arguments=("sh", "-c", "echo unsafe"))
            )

    def test_remove_boots_out_and_deletes_only_the_named_agent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = pathlib.Path(temporary)
            runner = MultiServiceRunner()
            agent = LaunchAgent(
                label=GATEWAY_LABEL,
                arguments=("/opt/letsinfer/bin/letsinfer", "gateway", "--port", "8000"),
            )
            install_launch_agent(agent, home=home, runner=runner)
            path = home / "Library/LaunchAgents/ai.letsinfer.gateway.plist"
            self.assertTrue(path.is_file())

            remove_launch_agent(GATEWAY_LABEL, home=home, runner=runner)

            self.assertFalse(path.exists())
            self.assertIn(
                ("launchctl", "bootout", f"gui/{os.getuid()}/{GATEWAY_LABEL}"),
                runner.commands,
            )

    def test_transaction_commit_keeps_replacement_node_and_removed_gateway(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = pathlib.Path(temporary)
            runner = MultiServiceRunner()
            gateway = LaunchAgent(
                label=GATEWAY_LABEL,
                arguments=("/opt/letsinfer/old", "gateway"),
            )
            old_node = LaunchAgent(
                label=NODE_LABEL,
                arguments=("/opt/letsinfer/old", "node-agent"),
            )
            new_node = LaunchAgent(
                label=NODE_LABEL,
                arguments=("/opt/letsinfer/new", "node-agent"),
            )
            install_launch_agent(gateway, home=home, runner=runner)
            install_launch_agent(old_node, home=home, runner=runner)

            with LaunchAgentTransaction(
                (GATEWAY_LABEL, NODE_LABEL), home=home, runner=runner
            ) as transaction:
                transaction.remove(GATEWAY_LABEL)
                transaction.remove(NODE_LABEL)
                install_launch_agent(new_node, home=home, runner=runner)
                transaction.commit()

            gateway_path = home / f"Library/LaunchAgents/{GATEWAY_LABEL}.plist"
            node_path = home / f"Library/LaunchAgents/{NODE_LABEL}.plist"
            self.assertFalse(gateway_path.exists())
            self.assertEqual(
                plistlib.loads(node_path.read_bytes())["ProgramArguments"],
                list(new_node.arguments),
            )

    def test_transaction_failure_restores_exact_agents_and_loaded_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = pathlib.Path(temporary)
            runner = MultiServiceRunner()
            gateway = LaunchAgent(
                label=GATEWAY_LABEL,
                arguments=("/opt/letsinfer/old", "gateway"),
            )
            node = LaunchAgent(
                label=NODE_LABEL,
                arguments=("/opt/letsinfer/old", "node-agent"),
            )
            install_launch_agent(gateway, home=home, runner=runner)
            gateway_path = home / f"Library/LaunchAgents/{GATEWAY_LABEL}.plist"
            gateway_bytes = gateway_path.read_bytes()
            remove_launch_agent(GATEWAY_LABEL, home=home, runner=runner)
            gateway_path.write_bytes(gateway_bytes)
            gateway_path.chmod(0o600)
            install_launch_agent(node, home=home, runner=runner)

            with self.assertRaisesRegex(RuntimeError, "fixture"):
                with LaunchAgentTransaction(
                    (GATEWAY_LABEL, NODE_LABEL), home=home, runner=runner
                ) as transaction:
                    transaction.remove(GATEWAY_LABEL)
                    transaction.remove(NODE_LABEL)
                    raise RuntimeError("fixture")

            node_path = home / f"Library/LaunchAgents/{NODE_LABEL}.plist"
            self.assertEqual(gateway_path.read_bytes(), gateway_bytes)
            self.assertEqual(
                plistlib.loads(node_path.read_bytes())["ProgramArguments"],
                list(node.arguments),
            )
            node_target = f"gui/{os.getuid()}/{NODE_LABEL}"
            gateway_target = f"gui/{os.getuid()}/{GATEWAY_LABEL}"
            self.assertEqual(
                runner(("launchctl", "print", node_target)).returncode,
                0,
            )
            self.assertNotEqual(
                runner(("launchctl", "print", gateway_target)).returncode,
                0,
            )
