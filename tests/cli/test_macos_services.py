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
    SITE_LABEL,
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


class MacOSServiceTests(unittest.TestCase):
    def test_render_is_direct_deterministic_and_private(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = pathlib.Path(temporary)
            agent = LaunchAgent(
                label=SITE_LABEL,
                arguments=("/opt/letsinfer/bin/letsinfer", "site-agent", "--port", "9770"),
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
            runner = FakeRunner()
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

    def test_shell_and_relative_executables_are_rejected(self) -> None:
        with self.assertRaises(MacOSServiceError):
            render_launch_agent(
                LaunchAgent(label=SITE_LABEL, arguments=("sh", "-c", "echo unsafe"))
            )

    def test_remove_boots_out_and_deletes_only_the_named_agent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = pathlib.Path(temporary)
            runner = FakeRunner()
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
