#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Width, channel, and ordering contracts for ordinary CLI presentation."""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Callable, Iterator
from unittest import mock

from core import cli, command_ui, ui
from core.actions import ACTIONS, MutationClass, action
from core.ui_contracts import (
    OutputContract,
    ProgressKind,
    SurfaceKind,
    UI_CONTRACTS,
)
from core.updates.manager import UpdateRecord, UpdateSnapshot


WIDTHS = (20, 32, 80, 120)
OPAQUE = "Q" * 97
LONG_ID = "node_" + "Z" * 96
LONG_DIGEST = "sha256:" + "f" * 64
LONG_PATH = "/var/lib/letsinfer/" + "/".join(("qualified-runtime",) * 8)


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


def presenter(
    width: int,
    *,
    tty: bool = True,
    no_color: bool = True,
    term: str = "xterm-256color",
    input_fn: Callable[[], str] | None = None,
    secret_fn: Callable[[], str] | None = None,
) -> tuple[command_ui.CommandUI, FakeStream]:
    stream = FakeStream(tty=tty)
    environ = {"TERM": term, "COLUMNS": str(width)}
    if no_color:
        environ["NO_COLOR"] = "1"
    return (
        command_ui.CommandUI(
            stream,
            environ=environ,
            input_fn=input_fn,
            secret_fn=secret_fn,
        ),
        stream,
    )


def plain(lines: tuple[str, ...] | list[str]) -> str:
    return "\n".join(ui.ANSI.sub("", line) for line in lines)


class HeaderMatrixTests(unittest.TestCase):
    def test_header_keeps_the_exact_right_badge_at_every_supported_width(self) -> None:
        expected_badge = " ϟ  LET'S INFER "
        for width in WIDTHS:
            with self.subTest(width=width):
                output, _ = presenter(width)
                rendered = tuple(ui.ANSI.sub("", line) for line in output.render_header(
                    "Qualified Runtime", state="READY", detail="Verified locally"
                ))
                self.assertTrue(rendered)
                badge_lines = [line for line in rendered if "LET'S INFER" in line]
                self.assertEqual(len(badge_lines), 1)
                self.assertTrue(badge_lines[0].endswith(expected_badge))
                combined = "\n".join(rendered)
                self.assertIn("Qualified Runtime", combined.replace("\n", " "))
                self.assertIn("READY", combined)
                self.assertNotIn("…", combined)
                self.assertLessEqual(max(map(len, rendered)), width)

    def test_header_is_idempotent(self) -> None:
        for width in WIDTHS:
            with self.subTest(width=width):
                output, stream = presenter(width)
                output.header("Install Runtime", state="READY")
                once = stream.getvalue()
                output.header("A Different Header", state="FAILED")
                self.assertEqual(stream.getvalue(), once)
                self.assertNotIn("A Different Header", once)

    def test_durable_write_hands_off_from_an_active_spinner_first(self) -> None:
        output, stream = presenter(80)
        events: list[str] = []

        class OrderedStream:
            def write(self, value: str) -> int:
                events.append("write")
                return stream.write(value)

            def flush(self) -> None:
                stream.flush()

            def isatty(self) -> bool:
                return True

            @property
            def encoding(self) -> str:
                return "utf-8"

        ordered = command_ui.CommandUI(
            OrderedStream(),
            environ={"TERM": "xterm", "NO_COLOR": "1", "COLUMNS": "80"},
        )
        with mock.patch.object(
            command_ui.ui,
            "before_external_output",
            side_effect=lambda: events.append("handoff"),
        ):
            ordered.result("Created", semantic="success")

        self.assertEqual(events[0], "handoff")
        self.assertIn("write", events[1:])


class WidthAndFidelityMatrixTests(unittest.TestCase):
    def _surfaces(self, output: command_ui.CommandUI) -> dict[str, tuple[str, ...]]:
        columns = (
            command_ui.TableColumn("kind", "KIND"),
            command_ui.TableColumn("identity", "IDENTITY"),
        )
        return {
            "wrapped": output.render_wrapped(OPAQUE),
            "verbatim": output.render_verbatim(OPAQUE),
            "result": output.render_result_lines(OPAQUE, detail="detail"),
            "record": output.render_records(
                (command_ui.RecordRow("Identity", OPAQUE, "detail"),)
            ),
            "table": output.render_table(
                columns, ({"kind": "runtime", "identity": OPAQUE},)
            ),
            "panel": output.render_panel((OPAQUE,), title="Evidence"),
            "object": output.render_object({"identity": OPAQUE}, title="Object"),
        }

    def test_every_surface_stays_within_20_32_80_and_120_columns(self) -> None:
        for width in WIDTHS:
            output, _ = presenter(width)
            for surface, lines in self._surfaces(output).items():
                with self.subTest(width=width, surface=surface):
                    for line in lines:
                        self.assertLessEqual(len(ui.ANSI.sub("", line)), width)

    def test_tty_wrapping_is_reconstructable_for_every_surface(self) -> None:
        for width in WIDTHS:
            output, _ = presenter(width)
            for surface, lines in self._surfaces(output).items():
                with self.subTest(width=width, surface=surface):
                    rendered = plain(lines)
                    self.assertEqual(rendered.count("Q"), len(OPAQUE))
                    self.assertNotIn("…", rendered)
                    self.assertNotIn("...", rendered)

    def test_verbatim_ids_digests_and_paths_are_reconstructable_on_tty(self) -> None:
        for width in WIDTHS:
            output, _ = presenter(width)
            for value in (LONG_ID, LONG_DIGEST, LONG_PATH):
                with self.subTest(width=width, value=value[:7]):
                    lines = output.render_verbatim(value, indent=2)
                    reconstructed = "".join(
                        ui.ANSI.sub("", line)[2:] for line in lines
                    )
                    self.assertEqual(reconstructed, value)
                    self.assertTrue(all(len(ui.ANSI.sub("", line)) <= width for line in lines))

    def test_non_tty_surfaces_are_plain_and_never_width_limited(self) -> None:
        output, _ = presenter(20, tty=False, no_color=False)
        columns = (
            command_ui.TableColumn("id", "ID"),
            command_ui.TableColumn("path", "PATH"),
        )

        self.assertEqual(output.render_wrapped(LONG_PATH), (LONG_PATH,))
        for value in (LONG_ID, LONG_DIGEST, LONG_PATH):
            self.assertEqual(output.render_verbatim(value), (value,))
        self.assertEqual(
            output.render_records(
                (command_ui.RecordRow("Digest", LONG_DIGEST, LONG_PATH),)
            ),
            (f"Digest\t{LONG_DIGEST}\t{LONG_PATH}",),
        )
        self.assertEqual(
            output.render_table(
                columns, ({"id": LONG_ID, "path": LONG_PATH},)
            ),
            ("ID\tPATH", f"{LONG_ID}\t{LONG_PATH}"),
        )
        self.assertEqual(
            output.render_result_lines(
                LONG_ID, semantic=command_ui.Semantic.SUCCESS, detail=LONG_PATH
            ),
            (f"OK: {LONG_ID}", f"  {LONG_PATH}"),
        )
        self.assertEqual(
            output.render_panel((LONG_ID, LONG_DIGEST, LONG_PATH), title="Evidence"),
            ("Evidence", "", LONG_ID, LONG_DIGEST, LONG_PATH),
        )
        object_lines = output.render_object(
            {"id": LONG_ID, "digest": LONG_DIGEST, "path": LONG_PATH}
        )
        self.assertEqual(json.loads("\n".join(object_lines))["path"], LONG_PATH)
        combined = "\n".join((*object_lines,))
        self.assertNotIn("\033[", combined)
        self.assertNotIn("…", combined)

    def test_dumb_and_redirected_streams_are_unstyled_noninteractive_surfaces(self) -> None:
        cases = (
            (True, "dumb"),
            (False, "xterm-256color"),
        )
        for tty, term in cases:
            with self.subTest(tty=tty, term=term):
                output, stream = presenter(20, tty=tty, term=term, no_color=False)
                self.assertFalse(output.interactive)
                self.assertEqual(output.render_header("Install"), ())
                self.assertEqual(output.render_wrapped(LONG_PATH), (LONG_PATH,))
                output.result(LONG_ID)
                self.assertEqual(stream.getvalue(), f"INFO: {LONG_ID}\n")
                self.assertNotIn("\033[", stream.getvalue())

    def test_no_color_retains_tty_layout_without_ansi(self) -> None:
        output, _ = presenter(32, tty=True, no_color=True)
        self.assertTrue(output.interactive)
        rendered = "\n".join(
            output.render_panel(
                output.render_result_lines("Verified", semantic="success"),
                title="Result",
            )
        )
        self.assertIn("LET'S INFER", plain(output.render_header("Verify")))
        self.assertIn("┌", rendered)
        self.assertNotIn("\033[", rendered)


class PromptFacadeTests(unittest.TestCase):
    def test_text_supports_defaults_required_values_and_validation(self) -> None:
        answers = iter(("", "bad", "valid"))
        output, stream = presenter(32, input_fn=lambda: next(answers))
        value = output.prompt.text(
            "Runtime name",
            required=True,
            validator=lambda answer: True if answer == "valid" else "Use a valid name.",
        )
        self.assertEqual(value, "valid")
        self.assertIn("A value is required.", stream.getvalue())
        self.assertIn("Use a valid name.", stream.getvalue())
        self.assertEqual(stream.getvalue().count("Runtime name"), 3)

        default_output, default_stream = presenter(32, input_fn=lambda: "")
        self.assertEqual(
            default_output.prompt.text("Node", default="Home"),
            "Home",
        )
        self.assertIn("[Home]", default_stream.getvalue())

    def test_secret_is_not_echoed_and_retries_required_input(self) -> None:
        answers = iter(("", "correct horse battery staple"))
        output, stream = presenter(32, secret_fn=lambda: next(answers))
        self.assertEqual(
            output.prompt.secret("API secret"),
            "correct horse battery staple",
        )
        rendered = stream.getvalue()
        self.assertEqual(rendered.count("API secret"), 2)
        self.assertIn("A value is required.", rendered)
        self.assertNotIn("correct horse", rendered)

    def test_choice_accepts_name_index_and_default(self) -> None:
        cases = (("2", "beta"), ("alpha", "alpha"), ("", "beta"))
        for answer, expected in cases:
            with self.subTest(answer=answer or "default"):
                output, stream = presenter(32, input_fn=lambda answer=answer: answer)
                self.assertEqual(
                    output.prompt.choose(
                        "Runtime", ("alpha", "beta"), default="beta"
                    ),
                    expected,
                )
                self.assertIn("1", stream.getvalue())
                self.assertIn("alpha", stream.getvalue())
                self.assertIn("2", stream.getvalue())
                self.assertIn("beta", stream.getvalue())

    def test_confirmation_reprompts_and_respects_each_default(self) -> None:
        answers = iter(("perhaps", "yes"))
        output, stream = presenter(32, input_fn=lambda: next(answers))
        self.assertTrue(output.prompt.confirm("Continue?"))
        self.assertIn("Enter yes or no.", stream.getvalue())

        default_output, _ = presenter(32, input_fn=lambda: "")
        self.assertTrue(default_output.prompt.confirm("Continue?", default=True))

    def test_require_tty_rejects_every_prompt_before_reading(self) -> None:
        reads: list[str] = []
        output, stream = presenter(
            80,
            tty=False,
            input_fn=lambda: reads.append("text") or "answer",
            secret_fn=lambda: reads.append("secret") or "secret",
        )
        calls: tuple[Callable[[], object], ...] = (
            lambda: output.prompt.text("Text", require_tty=True),
            lambda: output.prompt.secret("Secret", require_tty=True),
            lambda: output.prompt.confirm("Confirm", require_tty=True),
            lambda: output.prompt.choose("Choice", ("one",), require_tty=True),
        )
        for call in calls:
            with self.subTest(call=call), self.assertRaises(command_ui.PromptUnavailable):
                call()
        self.assertEqual(reads, [])
        self.assertEqual(stream.getvalue(), "")


class _ProgressProbe:
    def __init__(self, events: list[str], done: str | None) -> None:
        self.events = events
        self.done = done
        self.enabled = True

    def __enter__(self) -> _ProgressProbe:
        self.events.append("progress-enter")
        return self

    def before_output(self) -> None:
        return None

    def __exit__(self, *_: object) -> bool:
        if self.done is not None:
            self.events.append("completion")
        return False


class WholeCommandDispatchMatrixTests(unittest.TestCase):
    """Exercise every action at the real dispatcher boundary.

    Handlers are deliberately synthetic: these tests prove the shared UI,
    update, and progress policy in ``main`` without invoking host services,
    network access, credentials, Docker, or runtime state.
    """

    _BADGE = (
        ui.BOLD
        + ui.DARK
        + ui.LIGHT_BACKGROUND
        + " ϟ  LET'S INFER "
        + ui.RESET
    )

    def _run(
        self,
        action_id: str,
        *,
        handler: Callable[[argparse.Namespace], int] | None = None,
        json_output: bool = False,
        attributes: dict[str, object] | None = None,
        cached: tuple[UpdateSnapshot, ...] | None = None,
    ) -> dict[str, object]:
        namespace = argparse.Namespace(
            action_id=action_id,
            action=handler or (lambda _arguments: 0),
            json=json_output,
        )
        # A mocked parser must still provide the real parser's non-raw
        # defaults.  In particular, ``audit export`` deliberately treats
        # ``output=None`` as a raw stdout mode.
        normal_defaults: dict[str, object] = {}
        for selector in UI_CONTRACTS[action_id].raw_variants:
            name, expected = selector.split("=", 1)
            normal_defaults[name] = {
                "true": False,
                "false": True,
                "none": "synthetic-output",
            }.get(expected, "__normal_ui__")
        for name, value in normal_defaults.items():
            setattr(namespace, name, value)
        for name, value in (attributes or {}).items():
            setattr(namespace, name, value)

        command_parser = mock.Mock()
        command_parser.parse_args.return_value = namespace
        manager = mock.Mock()
        snapshots = cached or (UpdateSnapshot(()),)
        if len(snapshots) == 1:
            manager.cached.return_value = snapshots[0]
        else:
            manager.cached.side_effect = snapshots
        refresh_request = mock.Mock()
        update_notice = mock.Mock()
        progress_calls = mock.Mock()
        progress_events: list[str] = []

        def progress_factory(_message: str, **keywords: object) -> _ProgressProbe:
            progress_calls(_message, **keywords)
            return _ProgressProbe(progress_events, keywords.get("done"))

        stdout = FakeStream(tty=True)
        stderr = FakeStream(tty=True)
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / cli.CORE_SOURCE_MANIFEST).write_text("{}\n", encoding="utf-8")
            with (
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
                mock.patch.dict(
                    os.environ,
                    {"TERM": "xterm-256color", "COLUMNS": "80"},
                    clear=True,
                ),
                mock.patch.object(cli, "parser", return_value=command_parser),
                mock.patch.object(cli, "source_root", return_value=root),
                mock.patch.object(cli, "_update_manager", return_value=manager),
                mock.patch.object(
                    cli, "request_background_refresh", refresh_request
                ),
                mock.patch.object(cli.ui, "update_notice", update_notice),
                mock.patch.object(cli.ui, "progress", side_effect=progress_factory),
                mock.patch.object(
                    cli,
                    "_authorize_command",
                    return_value=(action(action_id), None),
                ),
                mock.patch.object(cli, "_audit_marker", return_value=None),
                mock.patch.object(cli, "_audit_command_result"),
            ):
                result = cli.main(["synthetic"])

        return {
            "result": result,
            "stdout": stdout.getvalue(),
            "stderr": stderr.getvalue(),
            "manager": manager,
            "refresh": refresh_request,
            "notice": update_notice,
            "progress": progress_calls,
            "progress_events": tuple(progress_events),
        }

    def test_every_public_action_has_exactly_one_exact_product_badge(self) -> None:
        owned_outputs = {
            OutputContract.FROZEN_STATUS,
            OutputContract.LIVE_DASHBOARD,
        }
        for action_id, metadata in ACTIONS.items():
            if metadata.mutation is MutationClass.INTERNAL:
                continue
            presentation = UI_CONTRACTS[action_id]

            def safe_handler(
                _arguments: argparse.Namespace,
                *,
                owns_surface: bool = presentation.output in owned_outputs,
            ) -> int:
                if owns_surface:
                    sys.stdout.write(f"{ui.Terminal(sys.stdout).logo()}\n")
                return 0

            with self.subTest(action=action_id):
                run = self._run(action_id, handler=safe_handler)
                stdout = str(run["stdout"])
                stderr = str(run["stderr"])
                combined = stdout + stderr
                self.assertEqual(run["result"], 0)
                self.assertEqual(combined.count(self._BADGE), 1)
                self.assertEqual(combined.count("LET'S INFER"), 1)
                if presentation.output in owned_outputs:
                    self.assertEqual(stderr, "")
                    self.assertEqual(stdout, f"{self._BADGE}\n")
                else:
                    self.assertEqual(stdout, "")
                    first_line = stderr.splitlines()[0]
                    self.assertTrue(first_line.endswith(self._BADGE))
                    self.assertIn(presentation.title, ui.ANSI.sub("", first_line))

    def test_every_public_action_requests_a_nonblocking_update_refresh(self) -> None:
        for action_id, metadata in ACTIONS.items():
            if metadata.mutation is MutationClass.INTERNAL:
                continue
            with self.subTest(action=action_id):
                run = self._run(action_id)
                refresh = run["refresh"]
                self.assertIsInstance(refresh, mock.Mock)
                refresh.assert_called_once()
                call = refresh.call_args
                self.assertIs(call.args[0], run["manager"])
                self.assertEqual(call.kwargs["installed"], True)
                self.assertEqual(call.kwargs["public_command"], True)
                self.assertEqual(call.kwargs["worker_context"], False)
                self.assertEqual(
                    call.kwargs["explicit_check"],
                    action_id in {"update", "update.check", "uninstall"},
                )

    def test_dispatcher_progress_is_bounded_by_each_declared_policy(self) -> None:
        handler_progress_owners = {
            "uninstall",
            *cli.HANDLER_STEP_PROGRESS,
        }
        # Uninstall cannot animate before its confirmation prompt and therefore
        # owns its two post-confirmation spinners. Topology probe owns truthful
        # step boundaries. Their handler behavior has focused tests elsewhere.
        self.assertEqual(handler_progress_owners, {"uninstall", "topology.probe"})
        special_progress_owners = {
            "update",
            *handler_progress_owners,
        }
        for action_id, metadata in ACTIONS.items():
            if metadata.mutation is MutationClass.INTERNAL:
                continue
            presentation = UI_CONTRACTS[action_id]
            expected = (
                presentation.progress in {ProgressKind.SPINNER, ProgressKind.STEPS}
                and action_id in {**cli.ACTION_PROGRESS, **cli.READ_PROGRESS}
                and action_id not in special_progress_owners
            )
            with self.subTest(action=action_id, policy=presentation.progress.value):
                run = self._run(action_id)
                progress = run["progress"]
                self.assertIsInstance(progress, mock.Mock)
                if not expected:
                    progress.assert_not_called()
                    continue
                progress.assert_called_once()
                call = progress.call_args
                message, done = (
                    cli.ACTION_PROGRESS.get(action_id)
                    or cli.READ_PROGRESS[action_id]
                )
                self.assertEqual(call.args, (message,))
                self.assertEqual(call.kwargs, {"done": done, "enabled": True})
                self.assertEqual(
                    run["progress_events"],
                    ("progress-enter", "completion"),
                )

    def test_every_machine_action_stays_clean_while_requesting_updates(self) -> None:
        payload = '{"safe":true}\n'
        for action_id, metadata in ACTIONS.items():
            presentation = UI_CONTRACTS[action_id]
            if (
                metadata.mutation is MutationClass.INTERNAL
                or not presentation.supports_json
            ):
                continue

            def json_handler(_arguments: argparse.Namespace) -> int:
                sys.stdout.write(payload)
                return 0

            with self.subTest(action=action_id):
                run = self._run(
                    action_id,
                    handler=json_handler,
                    json_output=True,
                )
                self.assertEqual(run["result"], 0)
                self.assertEqual(run["stdout"].encode("utf-8"), payload.encode("utf-8"))
                self.assertEqual(run["stderr"], "")
                self.assertNotIn("LET'S INFER", run["stdout"] + run["stderr"])
                run["refresh"].assert_called_once()
                run["notice"].assert_not_called()
                for call in run["progress"].call_args_list:
                    self.assertEqual(call.kwargs.get("enabled"), False)

    def test_every_raw_variant_stays_clean_while_requesting_updates(self) -> None:
        payload = "raw\x00payload\n"
        for action_id, metadata in ACTIONS.items():
            if metadata.mutation is MutationClass.INTERNAL:
                continue
            for selector in UI_CONTRACTS[action_id].raw_variants:
                name, expected = selector.split("=", 1)
                value: object = {
                    "true": True,
                    "false": False,
                    "none": None,
                }.get(expected, expected)

                def raw_handler(_arguments: argparse.Namespace) -> int:
                    sys.stdout.write(payload)
                    return 0

                with self.subTest(action=action_id, selector=selector):
                    run = self._run(
                        action_id,
                        handler=raw_handler,
                        attributes={name: value},
                    )
                    self.assertEqual(run["result"], 0)
                    self.assertEqual(
                        run["stdout"].encode("utf-8"), payload.encode("utf-8")
                    )
                    self.assertEqual(run["stderr"], "")
                    self.assertNotIn("LET'S INFER", run["stdout"] + run["stderr"])
                    if name == "job_worker" and value is True:
                        run["refresh"].assert_not_called()
                    else:
                        run["refresh"].assert_called_once()
                    run["notice"].assert_not_called()
                    for call in run["progress"].call_args_list:
                        self.assertEqual(call.kwargs.get("enabled"), False)

    def test_every_internal_action_is_chrome_and_update_state_free(self) -> None:
        payload = "internal\n"
        for action_id, metadata in ACTIONS.items():
            if metadata.mutation is not MutationClass.INTERNAL:
                continue

            def internal_handler(_arguments: argparse.Namespace) -> int:
                sys.stdout.write(payload)
                return 0

            with self.subTest(action=action_id):
                run = self._run(action_id, handler=internal_handler)
                self.assertEqual(run["result"], 0)
                self.assertEqual(run["stdout"], payload)
                self.assertEqual(run["stderr"], "")
                self.assertNotIn("LET'S INFER", run["stdout"] + run["stderr"])
                run["manager"].cached.assert_not_called()
                run["refresh"].assert_not_called()
                run["notice"].assert_not_called()
                run["progress"].assert_not_called()

    def test_verified_background_change_is_reflected_before_completion(self) -> None:
        initial = UpdateSnapshot(())
        changed = UpdateSnapshot(
            (
                UpdateRecord(
                    "core",
                    "core",
                    "1.0.0",
                    "old-core",
                    "1.0.1",
                    "new-core",
                    "https://example.invalid/release",
                    "available",
                    1_800_000_000,
                    1_800_000_000,
                    None,
                ),
            )
        )
        owned_outputs = {
            OutputContract.FROZEN_STATUS,
            OutputContract.LIVE_DASHBOARD,
        }
        excluded = {"update", "update.check", "uninstall"}
        for action_id, metadata in ACTIONS.items():
            presentation = UI_CONTRACTS[action_id]
            if (
                metadata.mutation is MutationClass.INTERNAL
                or not presentation.show_cached_updates
                or presentation.output in owned_outputs
                or action_id in excluded
            ):
                continue
            with self.subTest(action=action_id):
                run = self._run(action_id, cached=(initial, changed))
                notice = run["notice"]
                self.assertEqual(notice.call_count, 2)
                self.assertEqual(notice.call_args_list[0].args, (initial.available,))
                self.assertEqual(notice.call_args_list[1].args, (changed.available,))


class DispatcherPresentationTests(unittest.TestCase):
    @contextlib.contextmanager
    def _dispatch_streams(self) -> Iterator[tuple[FakeStream, FakeStream]]:
        stdout = FakeStream(tty=True)
        stderr = FakeStream(tty=True)
        with (
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
            mock.patch.dict(
                os.environ,
                {"TERM": "xterm-256color", "NO_COLOR": "1", "COLUMNS": "80"},
                clear=True,
            ),
        ):
            yield stdout, stderr

    def _run_namespace(self, namespace: argparse.Namespace) -> tuple[int, str, str]:
        parser = mock.Mock()
        parser.parse_args.return_value = namespace
        parser.print_help.return_value = None
        with (
            self._dispatch_streams() as (stdout, stderr),
            mock.patch.object(cli, "parser", return_value=parser),
            mock.patch.object(
                cli,
                "_authorize_command",
                return_value=(action(namespace.action_id), None),
            ),
            mock.patch.object(cli, "_audit_marker", return_value=None),
            mock.patch.object(cli, "_audit_command_result"),
            mock.patch.object(cli.ui, "update_notice"),
        ):
            result = cli.main(["synthetic"])
        return result, stdout.getvalue(), stderr.getvalue()

    def test_every_declared_json_variant_has_byte_clean_stdout(self) -> None:
        payload = '{"contract":"json"}\n'
        for action_id, presentation in UI_CONTRACTS.items():
            if not presentation.supports_json:
                continue
            with self.subTest(action=action_id):
                namespace = argparse.Namespace(
                    action_id=action_id,
                    action=lambda _: sys.stdout.write(payload) and 0,
                    json=True,
                )
                result, stdout, stderr = self._run_namespace(namespace)
                self.assertEqual(result, 0)
                self.assertEqual(stdout.encode("utf-8"), payload.encode("utf-8"))
                self.assertNotIn("LET'S INFER", stdout + stderr)
                self.assertNotRegex(stdout + stderr, r"[⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏]")
                self.assertNotIn("\033[", stdout + stderr)

    def test_every_declared_raw_variant_has_byte_clean_stdout(self) -> None:
        payload = "raw\x00bytes\n"
        for action_id, presentation in UI_CONTRACTS.items():
            for selector in presentation.raw_variants:
                name, expected = selector.split("=", 1)
                value: object = {
                    "true": True,
                    "false": False,
                    "none": None,
                }.get(expected, expected)
                with self.subTest(action=action_id, selector=selector):
                    namespace = argparse.Namespace(
                        action_id=action_id,
                        action=lambda _: sys.stdout.write(payload) and 0,
                        json=False,
                        **{name: value},
                    )
                    result, stdout, stderr = self._run_namespace(namespace)
                    self.assertEqual(result, 0)
                    self.assertEqual(stdout.encode("utf-8"), payload.encode("utf-8"))
                    self.assertNotIn("LET'S INFER", stdout + stderr)
                    self.assertNotRegex(stdout + stderr, r"[⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏]")
                    self.assertNotIn("\033[", stdout + stderr)

    def test_logs_keep_stdout_raw_and_brand_only_the_control_channel(self) -> None:
        payload = "2026-08-23T12:00:00Z engine ready\n"
        namespace = argparse.Namespace(
            action_id="logs",
            action=lambda _: sys.stdout.write(payload) and 0,
            json=False,
        )
        result, stdout, stderr = self._run_namespace(namespace)
        self.assertEqual(result, 0)
        self.assertEqual(stdout.encode("utf-8"), payload.encode("utf-8"))
        self.assertEqual(stderr.count("LET'S INFER"), 1)
        self.assertIn("Logs", stderr)
        self.assertNotIn(payload.strip(), stderr)
        self.assertNotRegex(stderr, r"[⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏]")

    def test_internal_actions_never_emit_branding(self) -> None:
        for action_id, presentation in UI_CONTRACTS.items():
            if presentation.surface is not SurfaceKind.INTERNAL:
                continue
            with self.subTest(action=action_id):
                namespace = argparse.Namespace(
                    action_id=action_id,
                    action=lambda _: sys.stdout.write("internal\n") and 0,
                    json=False,
                )
                result, stdout, stderr = self._run_namespace(namespace)
                self.assertEqual(result, 0)
                self.assertEqual(stdout, "internal\n")
                self.assertNotIn("LET'S INFER", stdout + stderr)
                self.assertNotIn("\033[", stdout + stderr)

    def test_completion_is_emitted_only_after_audit_and_finalizer(self) -> None:
        events: list[str] = []

        def handler(arguments: argparse.Namespace) -> int:
            events.append("action")
            arguments.after_audit = lambda: events.append("finalizer") or 0
            return 0

        namespace = argparse.Namespace(
            action_id="install",
            action=handler,
            json=False,
        )
        parser = mock.Mock()
        parser.parse_args.return_value = namespace
        with (
            self._dispatch_streams(),
            mock.patch.object(cli, "parser", return_value=parser),
            mock.patch.object(
                cli, "_authorize_command", return_value=(action("install"), None)
            ),
            mock.patch.object(cli, "_audit_marker", return_value=7),
            mock.patch.object(
                cli,
                "_audit_command_result",
                side_effect=lambda *_args, **_kwargs: events.append("audit"),
            ),
            mock.patch.object(cli.ui, "update_notice"),
            mock.patch.object(
                cli.ui,
                "progress",
                side_effect=lambda _message, **kwargs: _ProgressProbe(
                    events, kwargs.get("done")
                ),
            ),
        ):
            self.assertEqual(cli.main(["install"]), 0)

        self.assertEqual(
            events,
            ["progress-enter", "action", "audit", "finalizer", "completion"],
        )

    def test_cancelled_command_suppresses_success_completion(self) -> None:
        def cancel(arguments: argparse.Namespace) -> int:
            arguments.suppress_completion = True
            sys.stderr.write("Uninstall cancelled\n")
            return 0

        namespace = argparse.Namespace(
            action_id="uninstall",
            action=cancel,
            json=False,
        )
        result, _stdout, stderr = self._run_namespace(namespace)
        self.assertEqual(result, 0)
        self.assertIn("Uninstall cancelled", stderr)
        self.assertNotIn("Service removed", stderr)

    def test_logs_own_the_only_raw_stdout_contract(self) -> None:
        raw = {
            action_id
            for action_id, presentation in UI_CONTRACTS.items()
            if presentation.output is OutputContract.RAW_STDOUT
        }
        self.assertEqual(raw, {"logs"})


class ChildFailurePresentationTests(unittest.TestCase):
    def test_child_failure_redacts_credentials_and_terminal_controls(self) -> None:
        command = ["tool", "--token", "super-secret", "--mode", "check"]
        failure = subprocess.CalledProcessError(
            2,
            command,
            stderr="\033[31mAuthorization: Bearer second-secret\033[0m\nfailed",
        )
        with (
            mock.patch.object(cli.subprocess, "run", side_effect=failure),
            self.assertRaises(cli.LetsInferError) as raised,
        ):
            cli.run(command)
        message = str(raised.exception)
        self.assertNotIn("super-secret", message)
        self.assertNotIn("second-secret", message)
        self.assertNotIn("\033", message)
        self.assertIn("[REDACTED]", message)
        self.assertIn("failed", message)

    def test_child_diagnostic_is_bounded(self) -> None:
        value = "\n".join(f"line-{index}-" + "x" * 600 for index in range(100))
        rendered = cli._safe_diagnostic(value)
        self.assertNotIn("line-0-", rendered)
        self.assertIn("line-99-", rendered)
        self.assertLessEqual(len(rendered), 4096)


class BenchmarkSurfaceTests(unittest.TestCase):
    def test_dashboard_preserves_full_evidence_path_and_update_context(self) -> None:
        stream = FakeStream(tty=True)
        terminal = ui.Terminal(
            stream,
            environ={"TERM": "xterm", "NO_COLOR": "1", "COLUMNS": "32"},
        )
        update = type(
            "Update",
            (),
            {
                "kind": "core",
                "subject": "core",
                "available_version": "1.2.3",
            },
        )()
        rendered = cli._benchmark_dashboard(
            {"state": "running", "runtime": "runtime", "output_directory": OPAQUE},
            {"message": "Wait", "phase": "start"},
            1.0,
            terminal,
            "*",
            (update,),
        )
        self.assertEqual(rendered.count("Q"), len(OPAQUE))
        self.assertNotIn("…", rendered)
        self.assertIn("UPDATE AVAILABLE", rendered)
        self.assertIn("Core 1.2.3", rendered)


if __name__ == "__main__":
    unittest.main()
