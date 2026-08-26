#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Per-command update requests stay cheap, detached, and cache-bound."""

from __future__ import annotations

import argparse
import contextlib
import io
import os
import pathlib
import tempfile
import unittest
from unittest import mock

from core import cli
from core.actions import action as command_action
from core.updates.background import (
    DISABLE_BACKGROUND_UPDATE_ENV,
    request_background_refresh,
    snapshot_is_fresh,
)
from core.updates.manager import UpdateRecord, UpdateSnapshot


NOW = 1_800_000_000


def snapshot(*, checked_at: int = NOW, status: str = "current") -> UpdateSnapshot:
    return UpdateSnapshot(
        (
            UpdateRecord(
                "core",
                "core",
                "1.0.0",
                "core-a",
                None,
                None,
                None,
                status,
                checked_at,
                checked_at if status == "current" else None,
                None if status == "current" else "network_unavailable",
            ),
        )
    )


class SnapshotFreshnessTests(unittest.TestCase):
    def test_empty_and_stale_snapshots_need_refresh(self):
        self.assertFalse(snapshot_is_fresh(UpdateSnapshot(()), now=NOW))
        self.assertFalse(snapshot_is_fresh(snapshot(checked_at=NOW - 61), now=NOW))

    def test_sixty_second_boundary_is_fresh(self):
        self.assertTrue(snapshot_is_fresh(snapshot(checked_at=NOW - 60), now=NOW))

    def test_recent_failure_is_coalesced_too(self):
        self.assertTrue(
            snapshot_is_fresh(
                snapshot(checked_at=NOW - 10, status="unknown"),
                now=NOW,
            )
        )

    def test_large_future_timestamp_does_not_suppress_refresh(self):
        self.assertFalse(snapshot_is_fresh(snapshot(checked_at=NOW + 61), now=NOW))

    def test_negative_freshness_is_rejected(self):
        with self.assertRaises(ValueError):
            snapshot_is_fresh(snapshot(), now=NOW, max_age_seconds=-1)


class BackgroundRefreshRequestTests(unittest.TestCase):
    def setUp(self):
        self.manager = mock.Mock()
        self.manager.cached.return_value = UpdateSnapshot(())
        self.manager.installed.return_value = (mock.sentinel.core,)
        self.callbacks = []

    def launch(self, callback):
        self.callbacks.append(callback)
        return True

    def request(self, **keywords):
        return request_background_refresh(
            self.manager,
            environ={},
            clock=lambda: NOW,
            launcher=self.launch,
            **keywords,
        )

    def test_stale_request_returns_before_refresh_runs(self):
        self.assertTrue(self.request(snapshot=snapshot(checked_at=NOW - 61)))
        self.manager.refresh.assert_not_called()
        self.assertEqual(len(self.callbacks), 1)
        self.callbacks[0]()
        self.manager.refresh.assert_called_once_with()

    def test_empty_cache_requests_refresh(self):
        self.assertTrue(self.request())
        self.manager.cached.assert_called_once_with()
        self.assertEqual(len(self.callbacks), 1)

    def test_recent_cache_avoids_worker(self):
        self.assertFalse(self.request(snapshot=snapshot()))
        self.assertEqual(self.callbacks, [])
        self.manager.refresh.assert_not_called()

    def test_recent_partial_cache_refreshes_after_component_change(self):
        self.manager.installed.return_value = (
            mock.sentinel.core,
            mock.sentinel.runtime,
        )
        self.assertTrue(self.request(snapshot=snapshot()))
        self.assertEqual(len(self.callbacks), 1)

    def test_explicit_internal_nonpublic_and_uninstalled_paths_skip(self):
        for keyword in (
            {"explicit_check": True},
            {"worker_context": True},
            {"public_command": False},
            {"installed": False},
        ):
            with self.subTest(keyword=keyword):
                self.assertFalse(self.request(**keyword))
        self.manager.cached.assert_not_called()
        self.assertEqual(self.callbacks, [])

    def test_environment_opt_out_skips_before_cache_access(self):
        self.assertFalse(
            request_background_refresh(
                self.manager,
                environ={DISABLE_BACKGROUND_UPDATE_ENV: "yes"},
                clock=lambda: NOW,
                launcher=self.launch,
            )
        )
        self.manager.cached.assert_not_called()
        self.assertEqual(self.callbacks, [])

    def test_false_environment_value_does_not_disable(self):
        self.assertTrue(
            request_background_refresh(
                self.manager,
                environ={DISABLE_BACKGROUND_UPDATE_ENV: "0"},
                clock=lambda: NOW,
                launcher=self.launch,
            )
        )

    def test_launch_failure_is_silent(self):
        def fail(_callback):
            raise OSError("fork unavailable")

        self.assertFalse(
            request_background_refresh(
                self.manager,
                snapshot=UpdateSnapshot(()),
                environ={},
                clock=lambda: NOW,
                launcher=fail,
            )
        )

    def test_refresh_failure_is_silent_inside_worker(self):
        self.manager.refresh.side_effect = RuntimeError("offline")
        self.assertTrue(self.request())
        self.callbacks[0]()


class _TTY(io.StringIO):
    def isatty(self):
        return True


class CommandBackgroundRefreshTests(unittest.TestCase):
    def _run(
        self,
        action_id: str,
        *,
        manager: mock.Mock,
        json_output: bool = False,
        job_worker: bool = False,
    ) -> tuple[int, mock.Mock, mock.Mock]:
        namespace = argparse.Namespace(
            action_id=action_id,
            action=lambda _arguments: 0,
            json=json_output,
            job_worker=job_worker,
        )
        parser = mock.Mock()
        parser.parse_args.return_value = namespace
        refresh_request = mock.Mock()
        update_notice = mock.Mock()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / cli.CORE_SOURCE_MANIFEST).write_text("{}\n", encoding="utf-8")
            stdout = _TTY() if not json_output else io.StringIO()
            stderr = _TTY() if not json_output else io.StringIO()
            with (
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
                mock.patch.dict(
                    os.environ,
                    {"TERM": "xterm", "NO_COLOR": "1", "COLUMNS": "80"},
                    clear=True,
                ),
                mock.patch.object(cli, "parser", return_value=parser),
                mock.patch.object(cli, "source_root", return_value=root),
                mock.patch.object(cli, "_update_manager", return_value=manager),
                mock.patch.object(cli, "request_background_refresh", refresh_request),
                mock.patch.object(cli.ui, "update_notice", update_notice),
                mock.patch.object(
                    cli,
                    "_authorize_command",
                    return_value=(command_action(action_id), None),
                ),
                mock.patch.object(cli, "_audit_marker", return_value=None),
                mock.patch.object(cli, "_audit_command_result"),
                mock.patch.object(cli, "ACTION_PROGRESS", {}),
                mock.patch.object(cli, "READ_PROGRESS", {}),
            ):
                result = cli.main(["synthetic"])
        return result, refresh_request, update_notice

    def test_public_command_requests_refresh_even_with_machine_output(self):
        manager = mock.Mock()
        cached = snapshot()
        manager.cached.return_value = cached
        result, request, _notice = self._run(
            "node.info",
            manager=manager,
            json_output=True,
        )
        self.assertEqual(result, 0)
        request.assert_called_once_with(
            manager,
            snapshot=cached,
            installed=True,
            public_command=True,
            explicit_check=False,
            worker_context=False,
        )

    def test_internal_worker_does_not_open_or_request_update_state(self):
        manager = mock.Mock()
        result, request, _notice = self._run(
            "service-stop",
            manager=manager,
        )
        self.assertEqual(result, 0)
        manager.cached.assert_not_called()
        request.assert_not_called()

    def test_verified_change_is_rendered_if_refresh_finishes_during_command(self):
        initial = snapshot()
        available = UpdateSnapshot(
            (
                UpdateRecord(
                    "core",
                    "core",
                    "1.0.0",
                    "core-a",
                    "1.0.1",
                    "core-b",
                    "https://example.invalid/release",
                    "available",
                    NOW,
                    NOW,
                    None,
                ),
            )
        )
        manager = mock.Mock()
        manager.cached.side_effect = (initial, available)
        result, request, notice = self._run("node.info", manager=manager)
        self.assertEqual(result, 0)
        request.assert_called_once()
        self.assertEqual(notice.call_count, 2)
        self.assertEqual(notice.call_args_list[-1].args, (available.available,))
        self.assertEqual(
            notice.call_args_list[-1].kwargs,
            {"cleared": False, "attention": False},
        )

    def test_verified_withdrawal_corrects_the_initial_notice(self):
        initial = UpdateSnapshot(
            (
                UpdateRecord(
                    "core",
                    "core",
                    "1.0.0",
                    "core-a",
                    "1.0.1",
                    "core-b",
                    "https://example.invalid/release",
                    "available",
                    NOW,
                    NOW,
                    None,
                ),
            )
        )
        current = snapshot()
        manager = mock.Mock()
        manager.cached.side_effect = (initial, current)
        result, request, notice = self._run("node.info", manager=manager)
        self.assertEqual(result, 0)
        request.assert_called_once()
        self.assertEqual(notice.call_count, 2)
        self.assertEqual(notice.call_args_list[-1].args, (current.available,))
        self.assertEqual(
            notice.call_args_list[-1].kwargs,
            {"cleared": True, "attention": False},
        )

    def test_unresolved_withdrawal_does_not_claim_components_are_current(self):
        initial = UpdateSnapshot(
            (
                UpdateRecord(
                    "core", "core", "1.0.0", "core-a", "1.0.1", "core-b",
                    "https://example.invalid/release", "available", NOW, NOW, None,
                ),
            )
        )
        unresolved = snapshot(status="unknown")
        manager = mock.Mock()
        manager.cached.side_effect = (initial, unresolved)
        result, request, notice = self._run("node.info", manager=manager)
        self.assertEqual(result, 0)
        request.assert_called_once()
        self.assertEqual(
            notice.call_args_list[-1].kwargs,
            {"cleared": False, "attention": True},
        )


if __name__ == "__main__":
    unittest.main()
