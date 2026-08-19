# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import re
import time
import unittest
from unittest import mock

from core import cli as letsinfer
from core import ui
from core.actions import ACTIONS, AuditPolicy, CommandScope, MutationClass


class FakeStream(io.StringIO):
    def __init__(self, *, tty: bool, encoding: str = "utf-8") -> None:
        super().__init__()
        self._tty = tty
        self._encoding = encoding

    def isatty(self) -> bool:
        return self._tty

    @property
    def encoding(self) -> str:
        return self._encoding


class TerminalTests(unittest.TestCase):
    def test_tty_status_uses_the_logo_motif_and_color(self) -> None:
        stream = FakeStream(tty=True)
        terminal = ui.Terminal(stream, environ={"TERM": "xterm-256color"})
        terminal.status("Resolving runtime")
        terminal.success("Ready")
        self.assertTrue(terminal.interactive)
        self.assertTrue(terminal.color)
        self.assertEqual(terminal.mark, "ϟ")
        self.assertIn("\033[", stream.getvalue())
        self.assertIn("Resolving runtime", stream.getvalue())
        self.assertIn("Ready", stream.getvalue())

    def test_no_color_keeps_interaction_without_escape_styling(self) -> None:
        stream = FakeStream(tty=True)
        terminal = ui.Terminal(
            stream,
            environ={"TERM": "xterm-256color", "NO_COLOR": "1"},
        )
        terminal.warning("Memory pressure")
        self.assertTrue(terminal.interactive)
        self.assertFalse(terminal.color)
        self.assertNotIn("\033[", stream.getvalue())
        self.assertEqual(stream.getvalue(), "! Memory pressure\n")

    def test_non_tty_and_dumb_terminal_use_plain_fallback(self) -> None:
        for stream, environ in (
            (FakeStream(tty=False), {"TERM": "xterm-256color"}),
            (FakeStream(tty=True), {"TERM": "dumb"}),
        ):
            with self.subTest(tty=stream.isatty(), term=environ["TERM"]):
                terminal = ui.Terminal(stream, environ=environ)
                terminal.error("Unavailable")
                self.assertFalse(terminal.interactive)
                self.assertFalse(terminal.color)
                self.assertEqual(stream.getvalue(), "ERROR Unavailable\n")

    def test_spinner_cleans_its_line_and_finishes_once(self) -> None:
        stream = FakeStream(tty=True)
        terminal = ui.Terminal(stream, environ={"TERM": "xterm-256color"})
        spinner = ui.Spinner(
            terminal,
            "Installing runtime",
            done="Runtime installed",
            delay=0,
            interval=0.01,
        )
        with spinner:
            time.sleep(0.035)
        rendered = stream.getvalue()
        self.assertIn("Installing runtime", rendered)
        self.assertIn(ui.CLEAR_LINE, rendered)
        self.assertEqual(rendered.count("Runtime installed"), 1)
        self.assertTrue(rendered.endswith("Runtime installed\n"))
        self.assertIsNotNone(spinner._thread)
        self.assertFalse(spinner._thread.is_alive())

    def test_disabled_spinner_is_silent(self) -> None:
        stream = FakeStream(tty=False)
        with ui.progress("Working", done="Done", stream=stream):
            pass
        self.assertEqual(stream.getvalue(), "")

    def test_external_output_stops_the_current_spinner(self) -> None:
        stream = FakeStream(tty=True)
        terminal = ui.Terminal(stream, environ={"TERM": "xterm-256color"})
        spinner = ui.Spinner(
            terminal,
            "Downloading image",
            done="Image ready",
            delay=0,
            interval=0.01,
        )
        with spinner, ui.protect_stdout(spinner):
            time.sleep(0.02)
            ui.before_external_output()
            self.assertTrue(spinner._stop.is_set())
        self.assertIn(ui.CLEAR_LINE, stream.getvalue())
        self.assertIn("Image ready", stream.getvalue())

    def test_spinner_cleans_up_without_success_on_failure(self) -> None:
        stream = FakeStream(tty=True)
        terminal = ui.Terminal(stream, environ={"TERM": "xterm-256color"})
        spinner = ui.Spinner(
            terminal,
            "Starting inference",
            done="Inference ready",
            delay=0,
            interval=0.01,
        )
        with self.assertRaisesRegex(RuntimeError, "failed"):
            with spinner:
                time.sleep(0.02)
                raise RuntimeError("failed")
        rendered = stream.getvalue()
        self.assertIn(ui.CLEAR_LINE, rendered)
        self.assertNotIn("Inference ready", rendered)
        self.assertIsNotNone(spinner._thread)
        self.assertFalse(spinner._thread.is_alive())

    def test_step_progress_marks_completed_current_and_upcoming_rows(self) -> None:
        stream = FakeStream(tty=True)
        terminal = ui.Terminal(
            stream, environ={"TERM": "xterm-256color", "NO_COLOR": "1"}
        )
        with ui.StepProgress(
            terminal,
            ("Install core", "Rebind runtime", "Verify update"),
            section="update",
            interval=1,
        ) as progress:
            progress.advance()
            progress.advance()
            progress.advance()
        rendered = stream.getvalue()
        self.assertIn("LET'S INFER  /  UPDATE", rendered)
        self.assertIn("✓  Install core", rendered)
        self.assertIn("✓  Rebind runtime", rendered)
        self.assertIn("✓  Verify update", rendered)
        self.assertIn("○  Verify update", rendered)

    def test_step_progress_failure_marks_only_the_active_row(self) -> None:
        stream = FakeStream(tty=True)
        terminal = ui.Terminal(
            stream, environ={"TERM": "xterm-256color", "NO_COLOR": "1"}
        )
        with self.assertRaisesRegex(RuntimeError, "broken"):
            with ui.StepProgress(
                terminal,
                ("Install core", "Rebind runtime", "Verify update"),
                section="update",
                interval=1,
            ) as progress:
                progress.advance()
                raise RuntimeError("broken")
        rendered = stream.getvalue()
        self.assertIn("✗  Rebind runtime  Failed", rendered)
        self.assertIn("○  Verify update", rendered)

    def test_step_progress_is_silent_for_non_tty_output(self) -> None:
        stream = FakeStream(tty=False)
        terminal = ui.Terminal(stream, environ={"TERM": "xterm-256color"})
        with ui.StepProgress(
            terminal, ("Install", "Verify"), section="update"
        ) as progress:
            progress.advance()
            progress.advance()
        self.assertEqual(stream.getvalue(), "")

    def test_runtime_status_is_a_compact_branded_health_card(self) -> None:
        stream = FakeStream(tty=True)
        payload = {
            "service": {
                "active": "active",
                "engine_active": "active",
                "gateway_active": "active",
                "gateway_health": True,
                "gateway_auth_required": True,
                "gateway_authenticated": True,
                "gateway_model_identity": True,
                "gateway_endpoint": "http://homeai.local:8000/v1",
                "site_active": "active",
                "recovery_timer_active": "active",
                "memory_current_bytes": 19 * 1024 * 1024,
                "memory_limit_bytes": 30 * 1024 * 1024,
                "within_memory_limit": True,
            },
            "container": {
                "state": "running",
                "healthy": True,
                "docker_health": "healthy",
                "model_identity": True,
                "model": "deepseek-v4-flash",
                "engine": "dwarfstar",
                "target": "dgx-spark",
                "runtime_version": "0.11.0-rc.3",
                "capacity": {
                    "max_context_tokens": 557056,
                    "max_active_requests": 128,
                },
            },
            "protection": {"armed": True, "trip_latched": False},
            "telemetry": {
                "active_requests": 2,
                "queued_requests": 1,
                "rates": {
                    "output_tokens_per_second": 58.9,
                    "decode_tokens_per_second": 27.1,
                    "prefill_tokens_per_second": 219.4,
                },
            },
        }
        ui.runtime_status(
            payload,
            stream=stream,
            environ={"TERM": "xterm-256color"},
        )
        rendered = stream.getvalue()
        self.assertIn("LET'S INFER", rendered)
        self.assertIn("ONLINE", rendered)
        self.assertIn("deepseek-v4-flash", rendered)
        self.assertIn("DwarfStar · dgx-spark · 0.11.0-rc.3", rendered)
        self.assertIn("557K context · 128 active", rendered)
        self.assertIn("http://homeai.local:8000/v1", rendered)
        self.assertIn("19.0 MiB / 30.0 MiB", rendered)
        self.assertIn("Request path", rendered)
        self.assertIn("Scheduler", rendered)
        self.assertIn("Performance", rendered)
        self.assertIn("58.9 tok/s", rendered)
        self.assertIn("\033[", rendered)

    def test_runtime_status_calls_out_a_protection_trip(self) -> None:
        stream = FakeStream(tty=True)
        ui.runtime_status(
            {
                "service": {
                    "active": "active",
                    "engine_active": "active",
                    "gateway_active": "active",
                    "gateway_health": True,
                    "gateway_auth_required": True,
                    "gateway_authenticated": True,
                    "gateway_model_identity": True,
                    "site_active": "active",
                    "recovery_timer_active": "active",
                    "memory_current_bytes": 1,
                    "memory_limit_bytes": 2,
                    "within_memory_limit": True,
                },
                "container": {
                    "state": "running",
                    "healthy": True,
                    "docker_health": "healthy",
                    "model_identity": True,
                },
                "protection": {"armed": False, "trip_latched": True},
            },
            stream=stream,
            environ={"TERM": "xterm-256color", "NO_COLOR": "1"},
        )
        rendered = stream.getvalue()
        self.assertIn("ATTENTION", rendered)
        self.assertIn("Blocked", rendered)
        self.assertNotIn("\033[", rendered)

    def test_runtime_status_renders_startup_as_a_transition(self) -> None:
        stream = FakeStream(tty=True)
        payload = {
            "service": {
                "active": "active",
                "engine_active": "activating",
                "gateway_active": "active",
                "gateway_health": True,
                "gateway_auth_required": True,
                "gateway_authenticated": True,
                "gateway_model_identity": False,
                "gateway_endpoint": "http://homeai.local:8000/v1",
                "site_active": "active",
                "recovery_timer_active": "active",
                "memory_current_bytes": 19 * 1024 * 1024,
                "memory_limit_bytes": 30 * 1024 * 1024,
                "within_memory_limit": True,
            },
            "container": {
                "state": "running",
                "healthy": False,
                "docker_health": "starting",
                "model_identity": False,
                "model": "qwen3.8-27b",
                "engine": "sglang",
                "target": "dgx-spark",
                "runtime_version": "0.1.0-rc.3",
            },
            "protection": {
                "phase": "starting",
                "armed": False,
                "trip_latched": False,
            },
        }
        payload["lifecycle"] = letsinfer.runtime_lifecycle(payload)
        self.assertEqual(payload["lifecycle"]["state"], "starting")
        self.assertTrue(payload["lifecycle"]["transitional"])

        ui.runtime_status(
            payload,
            stream=stream,
            environ={"TERM": "xterm-256color", "NO_COLOR": "1"},
        )
        rendered = stream.getvalue()
        self.assertIn("STARTING", rendered)
        self.assertIn("Waiting", rendered)
        self.assertIn("Starting", rendered)
        self.assertIn("Arming", rendered)
        self.assertIn("engine unit activating", rendered)
        self.assertNotIn("ATTENTION", rendered)
        self.assertNotIn("Unavailable", rendered)
        self.assertNotIn("protection needs attention", rendered)

    def test_runtime_status_labels_a_healthy_candidate_without_false_service_failures(self) -> None:
        stream = FakeStream(tty=True)
        payload = {
            "service": {
                "active": "active",
                "engine_active": "inactive",
                "gateway_active": "active",
                "gateway_health": True,
                "gateway_auth_required": True,
                "gateway_authenticated": True,
                "gateway_model_identity": True,
                "gateway_endpoint": "http://homeai.local:8000/v1",
                "site_active": "active",
                "recovery_timer_active": "inactive",
                "runtime_mode": "qualification",
                "memory_current_bytes": 19 * 1024 * 1024,
                "memory_limit_bytes": 30 * 1024 * 1024,
                "within_memory_limit": True,
            },
            "container": {
                "state": "running",
                "healthy": True,
                "docker_health": "healthy",
                "model_identity": True,
                "model": "qwen3.8-27b",
                "engine": "sglang",
                "target": "dgx-spark",
                "runtime_version": "0.1.0-rc.5",
                "qualification_mode": True,
                "capacity": {
                    "max_context_tokens": 262144,
                    "max_active_requests": 8,
                },
            },
            "protection": {"armed": True, "trip_latched": False},
        }
        payload["lifecycle"] = letsinfer.runtime_lifecycle(payload)
        ui.runtime_status(
            payload,
            stream=stream,
            environ={"TERM": "xterm-256color", "NO_COLOR": "1"},
        )
        rendered = stream.getvalue()
        self.assertIn("UNQUALIFIED", rendered)
        self.assertIn("QUALIFICATION · SGLang · dgx-spark · 0.1.0-rc.5", rendered)
        self.assertIn("262K context · 8 active", rendered)
        self.assertIn("3/3", rendered)
        self.assertIn("candidate control plane active", rendered)
        self.assertIn("API       Ready", rendered)
        self.assertNotIn("FAILED", rendered)
        self.assertNotIn("unit(s) need attention", rendered)

    def test_runtime_status_does_not_call_a_reachable_api_unavailable(self) -> None:
        stream = FakeStream(tty=True)
        payload = {
            "service": {
                "active": "active",
                "engine_active": "active",
                "gateway_active": "active",
                "gateway_health": True,
                "gateway_auth_required": True,
                "gateway_authenticated": True,
                "gateway_model_identity": True,
                "runtime_metadata_ready": False,
                "gateway_endpoint": "http://homeai.local:8000/v1",
                "site_active": "active",
                "recovery_timer_active": "active",
                "memory_current_bytes": 19 * 1024 * 1024,
                "memory_limit_bytes": 30 * 1024 * 1024,
                "within_memory_limit": True,
            },
            "container": {
                "state": "running",
                "healthy": True,
                "docker_health": "healthy",
                "model_identity": True,
                "model": "qwen3.8-27b",
                "engine": "sglang",
                "target": "dgx-spark",
                "runtime_version": "0.1.0-rc.2",
            },
            "protection": {"armed": True, "trip_latched": False},
        }
        payload["lifecycle"] = letsinfer.runtime_lifecycle(payload)
        ui.runtime_status(
            payload,
            stream=stream,
            environ={"TERM": "xterm-256color", "NO_COLOR": "1"},
        )
        rendered = stream.getvalue()
        self.assertIn("API       Ready", rendered)
        self.assertIn("RUNTIME   Incompatible", rendered)
        self.assertNotIn("API       Unavailable", rendered)

    def test_site_status_is_branded_without_claiming_a_runtime(self) -> None:
        stream = FakeStream(tty=True)
        ui.site_status(
            {
                "identity": {
                    "display_name": "Home",
                    "role": "coordinator",
                    "member_id": "homeai",
                },
                "endpoint": "http://homeai.local:8000/v1",
                "services": {
                    "site_active": "active",
                    "gateway_active": "active",
                    "gateway_health": True,
                    "gateway_auth_required": True,
                    "gateway_authenticated": True,
                },
                "runtime": None,
            },
            stream=stream,
            environ={"TERM": "xterm-256color", "NO_COLOR": "1"},
        )
        rendered = stream.getvalue()
        self.assertIn("LET'S INFER", rendered)
        self.assertIn("ONLINE", rendered)
        self.assertIn("Home", rendered)
        self.assertIn("Not installed", rendered)
        self.assertIn("http://homeai.local:8000/v1", rendered)
        self.assertNotIn("\033[", rendered)

    def test_runtime_status_fits_an_eighty_column_terminal(self) -> None:
        stream = FakeStream(tty=True)
        ui.runtime_status(
            {
                "service": {
                    "active": "active",
                    "engine_active": "active",
                    "gateway_active": "active",
                    "gateway_health": True,
                    "gateway_auth_required": True,
                    "gateway_authenticated": True,
                    "gateway_model_identity": True,
                    "site_active": "active",
                    "recovery_timer_active": "active",
                    "memory_current_bytes": 19 * 1024 * 1024,
                    "memory_limit_bytes": 30 * 1024 * 1024,
                    "within_memory_limit": True,
                },
                "container": {
                    "state": "running",
                    "healthy": True,
                    "docker_health": "healthy",
                    "model_identity": True,
                    "model": "a-model-name-that-is-deliberately-long-enough-to-need-bounding",
                    "engine": "dwarfstar",
                    "target": "a-deliberately-long-target-name-for-terminal-rendering",
                    "runtime_version": "0.11.0-release-candidate-with-a-long-suffix",
                    "capacity": {
                        "max_context_tokens": 557056,
                        "max_active_requests": 128,
                    },
                },
                "protection": {"armed": True, "trip_latched": False},
            },
            stream=stream,
            environ={"TERM": "xterm-256color", "COLUMNS": "80"},
        )
        rendered = stream.getvalue()
        plain = re.sub(r"\x1b\[[0-9;]*m", "", rendered)
        self.assertTrue(all(len(line) <= 80 for line in plain.splitlines()))
        self.assertIn("SERVICES", plain)
        self.assertIn("all five units active", plain)


class HelpTests(unittest.TestCase):
    def test_root_without_a_command_shows_the_action_first_home(self) -> None:
        stdout = FakeStream(tty=True)
        stderr = FakeStream(tty=True)
        with (
            mock.patch.dict(os.environ, {"TERM": "xterm-256color"}, clear=True),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            result = letsinfer.main([])
        self.assertEqual(result, 0)
        self.assertIn("LET'S INFER", stdout.getvalue())
        self.assertIn("Your inference site is ready", stdout.getvalue())
        self.assertIn("letsinfer install <model>", stdout.getvalue())
        self.assertNotIn("Usage:", stdout.getvalue())
        self.assertEqual(stderr.getvalue(), "")

    def test_tty_help_is_branded_and_colored(self) -> None:
        stream = FakeStream(tty=True)
        with (
            mock.patch.dict(os.environ, {"TERM": "xterm-256color"}, clear=True),
            contextlib.redirect_stdout(stream),
        ):
            value = letsinfer.parser().format_help()
        self.assertIn("ϟ", value)
        self.assertIn("LET'S INFER", value)
        self.assertIn("\033[", value)
        self.assertIn("Usage:", value)
        self.assertIn("Commands:", value)
        self.assertIn("letsinfer [-h] COMMAND", value)

    def test_subcommand_help_carries_a_quiet_breadcrumb(self) -> None:
        stream = FakeStream(tty=False)
        with contextlib.redirect_stdout(stream):
            root = letsinfer.parser()
            subparsers = next(
                action
                for action in root._actions
                if isinstance(action, argparse._SubParsersAction)
            )
            value = subparsers.choices["install"].format_help()
        self.assertIn("LET'S INFER  /  INSTALL", value)
        self.assertNotIn("\033[", value)
        self.assertIn("Arguments:", value)
        self.assertNotIn("Commands:\n  model", value)

    def test_piped_help_is_branded_but_has_no_terminal_escapes(self) -> None:
        stream = FakeStream(tty=False)
        with contextlib.redirect_stdout(stream):
            value = letsinfer.parser().format_help()
        self.assertIn("LET'S INFER", value)
        self.assertNotIn("\033[", value)
        self.assertIn("Usage:", value)

    def test_root_without_a_tty_keeps_the_plain_help_contract(self) -> None:
        stdout = FakeStream(tty=False)
        with contextlib.redirect_stdout(stdout):
            result = letsinfer.main([])
        self.assertEqual(result, 0)
        self.assertIn("Usage:", stdout.getvalue())
        self.assertNotIn("\033[", stdout.getvalue())


class MainOutputTests(unittest.TestCase):
    def _metadata(self, name: str = "setup") -> object:
        return argparse.Namespace(
            name=name,
            scope=CommandScope.COORDINATOR,
            mutation=MutationClass.SITE,
            audit=AuditPolicy.NONE,
        )

    def test_json_mode_keeps_stdout_and_stderr_byte_clean(self) -> None:
        payload = {"installation_id": "a" * 64, "state": "ready"}

        def action(_arguments: argparse.Namespace) -> int:
            print(json.dumps(payload, separators=(",", ":")))
            return 0

        arguments = argparse.Namespace(
            command="setup",
            action=action,
            action_id="setup",
            json=True,
            port=1,
            engine_port=None,
            tail=0,
        )
        parser = mock.Mock()
        parser.parse_args.return_value = arguments
        stdout = FakeStream(tty=True)
        stderr = FakeStream(tty=True)
        with (
            mock.patch.object(letsinfer, "parser", return_value=parser),
            mock.patch.object(
                letsinfer,
                "_authorize_command",
                return_value=(self._metadata(), None),
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            result = letsinfer.main(["setup", "--json"])
        self.assertEqual(result, 0)
        self.assertEqual(
            stdout.getvalue(),
            json.dumps(payload, separators=(",", ":")) + "\n",
        )
        self.assertEqual(stderr.getvalue(), "")

    def test_every_public_mutation_has_compact_activity_language(self) -> None:
        mutations = {
            name
            for name, action in ACTIONS.items()
            if action.mutation in {MutationClass.NODE, MutationClass.SITE}
        }
        self.assertEqual(
            mutations - {"benchmark"}, set(letsinfer.ACTION_PROGRESS) - {"verify"}
        )
        self.assertNotIn("key.list", letsinfer.ACTION_PROGRESS)
        self.assertNotIn("key.show", letsinfer.ACTION_PROGRESS)

    def test_key_secret_and_warning_keep_their_stream_contracts(self) -> None:
        token = "li_once_secret"

        def action(_arguments: argparse.Namespace) -> int:
            print("KEY app id=fixture")
            print(token)
            print("This token is shown once. Store it now.", file=os.sys.stderr)
            return 0

        arguments = argparse.Namespace(
            command="key",
            action=action,
            action_id="key.create",
            json=False,
            port=1,
            engine_port=None,
            tail=0,
        )
        parser = mock.Mock()
        parser.parse_args.return_value = arguments
        stdout = FakeStream(tty=True)
        stderr = FakeStream(tty=True)
        with (
            mock.patch.dict(os.environ, {"TERM": "xterm-256color"}, clear=True),
            mock.patch.object(letsinfer, "parser", return_value=parser),
            mock.patch.object(
                letsinfer,
                "_authorize_command",
                return_value=(self._metadata("key.create"), None),
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            result = letsinfer.main(["key", "create", "app"])
        self.assertEqual(result, 0)
        self.assertEqual(stdout.getvalue(), f"KEY app id=fixture\n{token}\n")
        self.assertIn("This token is shown once. Store it now.", stderr.getvalue())
        self.assertIn("API key created", stderr.getvalue())
        self.assertNotIn("LET'S INFER", stderr.getvalue())

    def test_read_result_is_unadorned_and_non_tty_mutation_is_byte_stable(self) -> None:
        for name, output in (
            ("key.list", "fixture\tactive\n"),
            ("member.approve", "APPROVED fixture\n"),
        ):
            with self.subTest(name=name):
                arguments = argparse.Namespace(
                    command=name.split(".")[0],
                    action=lambda _arguments, value=output: print(value, end="") or 0,
                    action_id=name,
                    json=False,
                    port=1,
                    engine_port=None,
                    tail=0,
                )
                parser = mock.Mock()
                parser.parse_args.return_value = arguments
                stdout = FakeStream(tty=False)
                stderr = FakeStream(tty=False)
                with (
                    mock.patch.object(letsinfer, "parser", return_value=parser),
                    mock.patch.object(
                        letsinfer,
                        "_authorize_command",
                        return_value=(self._metadata(name), None),
                    ),
                    contextlib.redirect_stdout(stdout),
                    contextlib.redirect_stderr(stderr),
                ):
                    result = letsinfer.main([name.split(".")[0]])
                self.assertEqual(result, 0)
                self.assertEqual(stdout.getvalue(), output)
                self.assertEqual(stderr.getvalue(), "")

    def test_human_tty_action_animates_without_changing_its_result(self) -> None:
        def action(_arguments: argparse.Namespace) -> int:
            time.sleep(0.22)
            print("INSTALLED RUNTIME fixture")
            return 0

        arguments = argparse.Namespace(
            command="install",
            action=action,
            action_id="install",
            json=False,
            port=1,
            engine_port=None,
            tail=0,
        )
        parser = mock.Mock()
        parser.parse_args.return_value = arguments
        stdout = FakeStream(tty=True)
        stderr = FakeStream(tty=True)
        with (
            mock.patch.dict(os.environ, {"TERM": "xterm-256color"}, clear=True),
            mock.patch.object(letsinfer, "parser", return_value=parser),
            mock.patch.object(
                letsinfer,
                "_authorize_command",
                return_value=(self._metadata("install"), None),
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            result = letsinfer.main(["install", "fixture"])
        self.assertEqual(result, 0)
        self.assertEqual(stdout.getvalue(), "INSTALLED RUNTIME fixture\n")
        self.assertIn("Installing the runtime", stderr.getvalue())
        self.assertIn("LET'S INFER  /  INSTALL", stderr.getvalue())
        self.assertIn("Runtime installed", stderr.getvalue())
        self.assertIn(ui.CLEAR_LINE, stderr.getvalue())

    def test_update_leaves_the_installer_as_the_only_interactive_progress_owner(self) -> None:
        arguments = argparse.Namespace(
            command="update",
            action=lambda _arguments: 0,
            action_id="update",
            json=False,
            port=1,
            engine_port=None,
            tail=0,
        )
        parser = mock.Mock()
        parser.parse_args.return_value = arguments
        progress = mock.Mock(return_value=contextlib.nullcontext())
        with (
            mock.patch.object(letsinfer, "parser", return_value=parser),
            mock.patch.object(
                letsinfer,
                "_authorize_command",
                return_value=(self._metadata("update"), None),
            ),
            mock.patch.object(ui, "progress", progress),
            mock.patch.object(
                ui, "protect_stdout", return_value=contextlib.nullcontext()
            ),
        ):
            self.assertEqual(letsinfer.main(["update"]), 0)
        progress.assert_called_once_with(
            "Updating Let's Infer core", done="Core updated", enabled=False
        )

    def test_non_tty_error_contract_is_unchanged(self) -> None:
        arguments = argparse.Namespace(
            command="setup",
            action=lambda _arguments: 0,
            action_id="setup",
            json=False,
            port=0,
            engine_port=None,
            tail=0,
        )
        parser = mock.Mock()
        parser.parse_args.return_value = arguments
        stderr = FakeStream(tty=False)
        with (
            mock.patch.object(letsinfer, "parser", return_value=parser),
            mock.patch.object(
                letsinfer,
                "_authorize_command",
                return_value=(self._metadata(), None),
            ),
            contextlib.redirect_stderr(stderr),
        ):
            result = letsinfer.main(["setup"])
        self.assertEqual(result, 1)
        self.assertEqual(stderr.getvalue(), "FATAL: port must be between 1 and 65535\n")

    def test_tty_error_uses_the_bounded_failure_state(self) -> None:
        stream = FakeStream(tty=True)
        with mock.patch.dict(os.environ, {"TERM": "xterm-256color"}, clear=True):
            ui.fatal("runtime is unavailable", stream=stream)
        plain = re.sub(r"\x1b\[[0-9;]*m", "", stream.getvalue())
        self.assertIn("FAILED", plain)
        self.assertIn("runtime is unavailable", plain)
        self.assertNotIn("FATAL:", plain)
        self.assertIn("\033[38;2;226;56;56m", stream.getvalue())


if __name__ == "__main__":
    unittest.main()
