#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Stable contracts for the shared human CLI presentation layer."""

from __future__ import annotations

import contextlib
import io
import json
import pathlib
import unittest
from unittest import mock

from core import cli, ui
from core.actions import ACTIONS, MutationClass
from core.ui_contracts import (
    OutputContract,
    ProgressKind,
    SurfaceKind,
    UI_CONTRACTS,
    validate_contracts,
)


FIXTURES = pathlib.Path(__file__).with_name("fixtures") / "ui"


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


def serving_payload() -> dict[str, object]:
    """One deterministic status snapshot whose bytes predate the CLI audit."""

    return {
        "service": {
            "active": "active",
            "engine_active": "active",
            "gateway_active": "active",
            "gateway_health": True,
            "gateway_auth_required": True,
            "gateway_authenticated": True,
            "gateway_model_identity": True,
            "gateway_endpoint": "http://homeai.local:8000/v1",
            "node_active": "active",
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
            "connected_clients": 1,
            "queued_requests": 1,
            "rates": {
                "output_tokens_per_second": 58.9,
                "decode_tokens_per_second": 27.1,
                "prefill_tokens_per_second": 219.4,
            },
        },
    }


class PresentationInventoryTests(unittest.TestCase):
    def test_every_public_action_has_exactly_one_presentation_contract(self) -> None:
        validate_contracts(ACTIONS, UI_CONTRACTS)
        self.assertEqual(set(ACTIONS), set(UI_CONTRACTS))
        for name, action in ACTIONS.items():
            with self.subTest(action=name):
                presentation = UI_CONTRACTS[name]
                if action.mutation is MutationClass.INTERNAL:
                    self.assertFalse(presentation.branded)
                    self.assertIs(presentation.surface, SurfaceKind.INTERNAL)
                    self.assertIs(presentation.output, OutputContract.INTERNAL)
                else:
                    self.assertTrue(presentation.branded)

    def test_special_surfaces_are_narrow_and_explicit(self) -> None:
        self.assertIs(
            UI_CONTRACTS["status"].surface, SurfaceKind.FROZEN_STATUS
        )
        self.assertIs(
            UI_CONTRACTS["benchmark"].output, OutputContract.LIVE_DASHBOARD
        )
        self.assertIs(UI_CONTRACTS["logs"].output, OutputContract.RAW_STDOUT)
        self.assertIs(
            UI_CONTRACTS["audit.export"].output,
            OutputContract.ARTIFACT_RESULT,
        )

    def test_named_steps_have_an_explicit_advancing_owner(self) -> None:
        declared = {
            action_id
            for action_id, presentation in UI_CONTRACTS.items()
            if presentation.progress is ProgressKind.STEPS
        }
        self.assertEqual(
            declared,
            {"update"} | set(cli.HANDLER_STEP_PROGRESS),
        )
        self.assertEqual(cli.HANDLER_STEP_PROGRESS, {"topology.probe"})

    def test_topology_probe_advances_each_truthful_stage(self) -> None:
        events: list[str] = []

        class Progress:
            def __enter__(self) -> Progress:
                events.append("enter")
                return self

            def advance(self) -> None:
                events.append("advance")

            def __exit__(self, *_args: object) -> None:
                events.append("exit")

        store = mock.MagicMock()
        store.__enter__.return_value.members.return_value = [
            {
                "member_id": "left",
                "state": "active",
                "address": "left.local",
                "certificate_sha256": "a" * 64,
            },
            {
                "member_id": "right",
                "state": "active",
                "address": "right.local",
                "certificate_sha256": "b" * 64,
            },
        ]
        arguments = mock.Mock(
            action_id="topology.probe",
            left="left",
            right="right",
            left_interface=None,
            right_interface=None,
            kind="lan",
            json=True,
        )
        stdout = io.StringIO()
        with (
            mock.patch.object(cli, "_command_step_progress", return_value=Progress()),
            mock.patch.object(cli, "_site_store", return_value=store),
            mock.patch.object(
                cli,
                "request_member_link_probe",
                side_effect=({"direction": "left"}, {"direction": "right"}),
            ) as probe,
            mock.patch.object(
                cli,
                "_synchronize_member_facts",
                return_value={"failed": [], "refreshed": ["left", "right"]},
            ),
            contextlib.redirect_stdout(stdout),
        ):
            self.assertEqual(cli.topology_probe_command(arguments), 0)
        self.assertEqual(events, ["enter", "advance", "advance", "advance", "exit"])
        self.assertEqual(probe.call_count, 2)
        self.assertEqual(
            json.loads(stdout.getvalue()),
            {
                "links": [{"direction": "left"}, {"direction": "right"}],
                "refreshed": ["left", "right"],
            },
        )

    def test_handler_owned_progress_is_explicit_for_prompt_handoffs(self) -> None:
        self.assertEqual(
            cli.POST_PROMPT_PROGRESS,
            {
                "node.move",
                "child.join",
                "install",
                "upgrade",
                "rollback",
                "pair",
                "uninstall",
            },
        )

    def test_handler_owned_activity_is_silent_in_json_mode(self) -> None:
        stdout = FakeStream(tty=True)
        stderr = FakeStream(tty=True)
        arguments = mock.Mock(action_id="install", json=True)
        with (
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
            cli._command_activity(arguments, action_id="install"),
        ):
            pass
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "")

    def test_pairing_waits_have_live_activity_only_around_the_waits(self) -> None:
        events: list[str] = []
        state = mock.Mock()
        state.condition = cli.threading.Condition()
        state.candidate = {
            "confirmation_code": "123456",
            "name": "Mac",
            "id": "controller-id",
        }
        state.error = None
        state.deadline = cli.time.monotonic() + 30
        state.completed = True
        state.approved = False
        server = mock.Mock()
        presenter = mock.Mock()

        def activity(
            _arguments: object,
            message: str,
            **_kwargs: object,
        ) -> contextlib.AbstractContextManager[None]:
            events.append(message)
            return contextlib.nullcontext()

        def confirm(_message: str) -> bool:
            events.append("confirm")
            return True

        arguments = mock.Mock(
            timeout=30,
            config=None,
            role="administrator",
            action_id="pair",
        )
        config = {
            "installation_id": "i" * 64,
            "watchdog_controller_allowlist_file": "/tmp/allowlist",
            "watchdog_controller_ca_key_file": "/tmp/ca-key",
            "watchdog_cert_file": "/tmp/cert",
            "watchdog_key_file": "/tmp/key",
            "watchdog_listen": "127.0.0.1",
        }
        with (
            mock.patch.object(
                cli, "_controller_management_config", return_value=config
            ) as management_config,
            mock.patch.object(cli, "_reload_controller_authorization"),
            mock.patch.object(cli, "_ControllerPairingState", return_value=state),
            mock.patch.object(cli, "_controller_pairing_tls_context"),
            mock.patch.object(cli, "_ControllerPairingServer", return_value=server),
            mock.patch.object(cli, "_human_presenter", return_value=presenter),
            mock.patch.object(cli, "_command_activity", side_effect=activity),
            mock.patch.object(
                cli.ui,
                "protect_stdout",
                side_effect=lambda _owner: contextlib.nullcontext(),
            ),
            mock.patch.object(cli.ui, "confirm", side_effect=confirm),
            mock.patch.object(cli.secrets, "randbelow", return_value=12345678),
        ):
            self.assertEqual(cli.pair_controller(arguments), 0)
        management_config.assert_called_once_with(None)
        self.assertEqual(
            events,
            ["Waiting for a controller", "confirm", "Completing controller pairing"],
        )
        server.shutdown.assert_called_once_with()
        server.server_close.assert_called_once_with()


class CommandPrimitiveTests(unittest.TestCase):
    def test_command_header_uses_the_exact_status_lockup_and_section(self) -> None:
        stream = FakeStream(tty=True)
        self.assertTrue(
            ui.command_header(
                "key.create",
                stream=stream,
                environ={"TERM": "xterm-256color"},
            )
        )
        self.assertEqual(
            stream.getvalue(),
            ui.BOLD
            + ui.DARK
            + ui.LIGHT_BACKGROUND
            + " ϟ  LET'S INFER "
            + ui.RESET
            + " "
            + ui.DIM
            + "/  KEY / CREATE"
            + ui.RESET
            + "\n\n",
        )

    def test_command_header_retains_layout_without_color(self) -> None:
        stream = FakeStream(tty=True)
        ui.command_header(
            "child.join",
            stream=stream,
            environ={"TERM": "xterm-256color", "NO_COLOR": "1"},
        )
        self.assertEqual(
            stream.getvalue(), " ϟ  LET'S INFER  /  CHILD / JOIN\n\n"
        )

    def test_command_header_is_silent_for_redirected_and_dumb_terminals(self) -> None:
        cases = (
            (FakeStream(tty=False), {"TERM": "xterm-256color"}),
            (FakeStream(tty=True), {"TERM": "dumb"}),
        )
        for stream, environ in cases:
            with self.subTest(tty=stream.isatty(), term=environ["TERM"]):
                self.assertFalse(
                    ui.command_header("install", stream=stream, environ=environ)
                )
                self.assertEqual(stream.getvalue(), "")

    def test_ascii_terminal_uses_the_status_lockup_fallback(self) -> None:
        stream = FakeStream(tty=True, encoding="ascii")
        ui.command_header(
            "install", stream=stream, environ={"TERM": "xterm-256color"}
        )
        plain = ui.ANSI.sub("", stream.getvalue())
        self.assertEqual(plain, " >  LET'S INFER  /  INSTALL\n\n")
        self.assertNotIn("ϟ", plain)

    def test_explicit_spinner_section_does_not_depend_on_message_wording(self) -> None:
        stream = FakeStream(tty=True)
        terminal = ui.Terminal(
            stream, environ={"TERM": "xterm-256color", "NO_COLOR": "1"}
        )
        spinner = ui.Spinner(
            terminal,
            "Please wait",
            done="Audit verified",
            section="audit.verify",
            delay=60,
        )
        with spinner:
            pass
        self.assertEqual(
            stream.getvalue(),
            " ϟ  LET'S INFER  /  AUDIT / VERIFY\n"
            "   Please wait\n\n"
            "✓ Audit verified\n",
        )

    def test_disabled_section_spinner_is_fully_silent(self) -> None:
        stream = FakeStream(tty=False)
        with ui.progress(
            "Working",
            done="Done",
            section="install",
            stream=stream,
        ):
            pass
        self.assertEqual(stream.getvalue(), "")

    def test_step_progress_can_follow_an_existing_header_without_duplication(self) -> None:
        stream = FakeStream(tty=True)
        terminal = ui.Terminal(
            stream, environ={"TERM": "xterm-256color", "NO_COLOR": "1"}
        )
        ui.command_header(
            "update", stream=stream, environ={"TERM": "xterm", "NO_COLOR": "1"}
        )
        with ui.StepProgress(
            terminal,
            ("Install core", "Verify update"),
            section="update",
            show_header=False,
            interval=60,
        ) as progress:
            progress.advance()
            progress.advance()
        self.assertEqual(stream.getvalue().count("LET'S INFER"), 1)
        self.assertIn("✓  Install core", stream.getvalue())
        self.assertIn("✓  Verify update", stream.getvalue())

    def test_confirmation_prompt_uses_shared_warning_grammar(self) -> None:
        stream = FakeStream(tty=True)
        with mock.patch("builtins.input", return_value="yes"):
            self.assertTrue(
                ui.confirm(
                    "Remove all local data?",
                    stream=stream,
                    environ={"TERM": "xterm", "NO_COLOR": "1"},
                )
            )
        self.assertEqual(stream.getvalue(), "? Remove all local data? [y/N] ")

    def test_confirmation_defaults_to_no_on_eof(self) -> None:
        stream = FakeStream(tty=False)
        with mock.patch("builtins.input", side_effect=EOFError):
            self.assertFalse(ui.confirm("Continue?", stream=stream, environ={}))
        self.assertEqual(stream.getvalue(), "? Continue? [y/N] ")

    def test_tty_fatal_can_retain_the_command_context(self) -> None:
        stream = FakeStream(tty=True)
        with mock.patch.dict("os.environ", {"TERM": "xterm", "NO_COLOR": "1"}, clear=True):
            ui.fatal("runtime is unavailable", stream=stream, section="start")
        self.assertEqual(
            stream.getvalue(),
            " ϟ  LET'S INFER  /  START\n\n"
            "✗  FAILED\n"
            "   runtime is unavailable\n",
        )

    def test_parser_errors_are_branded_only_on_a_human_terminal(self) -> None:
        parser = ui.ArgumentParser(prog="letsinfer key create")
        parser.add_argument("name")
        stream = FakeStream(tty=True)
        with (
            contextlib.redirect_stderr(stream),
            mock.patch.dict("os.environ", {"TERM": "xterm", "NO_COLOR": "1"}, clear=True),
            self.assertRaises(SystemExit) as stopped,
        ):
            parser.parse_args([])
        self.assertEqual(stopped.exception.code, 2)
        self.assertEqual(stream.getvalue().count("LET'S INFER"), 1)
        self.assertIn("/  KEY CREATE", stream.getvalue())
        self.assertIn("FAILED", stream.getvalue())
        self.assertIn("the following arguments are required: name", stream.getvalue())

    def test_palette_is_the_exact_shared_design_palette(self) -> None:
        self.assertEqual(
            {
                "dark": ui.DARK,
                "light": ui.LIGHT,
                "blue": ui.BLUE,
                "purple": ui.PURPLE,
                "green": ui.GREEN,
                "yellow": ui.YELLOW,
                "orange": ui.ORANGE,
                "red": ui.RED,
            },
            {
                "dark": "\033[38;2;30;30;30m",
                "light": "\033[38;2;247;247;247m",
                "blue": "\033[38;2;0;156;223m",
                "purple": "\033[38;2;151;57;153m",
                "green": "\033[38;2;97;187;70m",
                "yellow": "\033[38;2;255;185;0m",
                "orange": "\033[38;2;247;130;0m",
                "red": "\033[38;2;226;56;56m",
            },
        )


class ImmutableStatusContractTests(unittest.TestCase):
    def test_serving_status_bytes_remain_unchanged_at_eighty_columns(self) -> None:
        stream = FakeStream(tty=True)
        ui.runtime_status(
            serving_payload(),
            stream=stream,
            environ={
                "TERM": "xterm-256color",
                "NO_COLOR": "1",
                "COLUMNS": "80",
            },
        )
        expected = (FIXTURES / "status-serving-80.txt").read_text(encoding="utf-8")
        self.assertEqual(stream.getvalue(), expected)


if __name__ == "__main__":
    unittest.main()
