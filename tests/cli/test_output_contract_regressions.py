#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Regressions for machine, redirected, and split-terminal CLI surfaces."""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import unittest
from unittest import mock

from core import benchmark_verification, cli
from core.site.state import SiteIdentity


class _TTY(io.StringIO):
    def isatty(self) -> bool:
        return True

    @property
    def encoding(self) -> str:
        return "utf-8"


def _child_identity() -> SiteIdentity:
    return SiteIdentity(
        site_id="1" * 32,
        member_id="2" * 32,
        installation_id="3" * 64,
        display_name="Worker",
        role="child",
        coordinator_id="4" * 32,
        coordinator_address="main.local",
        site_public_key_sha256="5" * 64,
        member_public_key_sha256="6" * 64,
        created_at_unix=1_700_000_000,
    )


class SetupMachineOutputTests(unittest.TestCase):
    def test_child_facts_warning_does_not_break_setup_json(self) -> None:
        arguments = argparse.Namespace(
            no_service=True,
            name="Worker",
            address=None,
            json=True,
        )
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(cli, "ensure_letsinfer_home"),
            mock.patch.object(cli, "setup_site", return_value=_child_identity()),
            mock.patch.object(
                cli,
                "refresh_local_member_facts",
                side_effect=cli.LetsInferError("facts endpoint unavailable"),
            ),
            mock.patch.object(cli, "install_core_plane_services") as install,
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            self.assertEqual(cli.setup_command(arguments), 0)

        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["role"], "child")
        self.assertEqual(payload["display_name"], "Worker")
        self.assertIn("facts endpoint unavailable", stderr.getvalue())
        install.assert_not_called()


class VerificationSplitTerminalTests(unittest.TestCase):
    def test_redirected_stdout_keeps_github_auth_on_interactive_stderr(self) -> None:
        identity = benchmark_verification.GitHubIdentity("Verifier", 42, "User")
        stdin = _TTY()
        stdout = io.StringIO()
        stderr = _TTY()
        with (
            mock.patch.dict(
                os.environ,
                {"TERM": "xterm-256color", "NO_COLOR": "1", "COLUMNS": "80"},
                clear=True,
            ),
            mock.patch.object(cli.sys, "stdin", stdin),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
            mock.patch("builtins.input", return_value="yes"),
            mock.patch.object(
                benchmark_verification,
                "gh_version",
                return_value=(2, 45, 0),
            ),
            mock.patch.object(
                benchmark_verification,
                "github_identity",
                side_effect=(
                    benchmark_verification.VerificationError(
                        "GitHub CLI is not authenticated"
                    ),
                    identity,
                ),
            ) as github_identity,
        ):
            self.assertEqual(cli._interactive_github_identity(), identity)

        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("GitHub authentication is required", stderr.getvalue())
        self.assertIn("@Verifier", stderr.getvalue())
        self.assertEqual(github_identity.call_count, 2)


class OneTimeSecretOutputTests(unittest.TestCase):
    def test_redirected_key_create_and_rotate_emit_only_the_token_on_stdout(self) -> None:
        cases = (
            (
                "create",
                argparse.Namespace(
                    name="app",
                    model=[],
                    expires_at=None,
                    requests_per_minute=None,
                    tokens_per_minute=None,
                    concurrency=None,
                    max_context=None,
                    tenant=None,
                    application=None,
                    json=False,
                ),
                {"name": "app", "key_id": "key-create"},
                "li_create_once",
            ),
            (
                "rotate",
                argparse.Namespace(key="app", json=False),
                {"name": "app", "key_id": "key-rotate"},
                "li_rotate_once",
            ),
        )
        for operation, arguments, metadata, token in cases:
            with self.subTest(operation=operation):
                store = mock.Mock()
                if operation == "create":
                    store.create_key.return_value = (metadata, token)
                    command = cli.key_create_command
                else:
                    store.rotate_key.return_value = (metadata, token)
                    command = cli.key_rotate_command
                context = mock.MagicMock()
                context.__enter__.return_value = store
                stdout = io.StringIO()
                stderr = io.StringIO()
                with (
                    mock.patch.object(cli, "_site_store", return_value=context),
                    contextlib.redirect_stdout(stdout),
                    contextlib.redirect_stderr(stderr),
                ):
                    self.assertEqual(command(arguments), 0)

                self.assertEqual(stdout.getvalue(), token + "\n")
                self.assertIn(metadata["key_id"], stderr.getvalue())
                self.assertIn("shown once", stderr.getvalue())
                self.assertNotIn(token, stderr.getvalue())

    def test_key_json_keeps_metadata_and_token_in_one_structured_document(self) -> None:
        metadata = {"name": "app", "key_id": "key-create"}
        token = "li_json_once"
        store = mock.Mock()
        store.create_key.return_value = (metadata, token)
        context = mock.MagicMock()
        context.__enter__.return_value = store
        arguments = argparse.Namespace(
            name="app",
            model=[],
            expires_at=None,
            requests_per_minute=None,
            tokens_per_minute=None,
            concurrency=None,
            max_context=None,
            tenant=None,
            application=None,
            json=True,
        )
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(cli, "_site_store", return_value=context),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            self.assertEqual(cli.key_create_command(arguments), 0)

        self.assertEqual(
            json.loads(stdout.getvalue()),
            {"key": metadata, "token": token, "token_shown_once": True},
        )
        self.assertEqual(stderr.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
