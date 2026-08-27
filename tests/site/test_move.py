# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import argparse
import contextlib
import io
import os
import pathlib
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from core import cli
from core.site import control, move, state


class SiteMoveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.source_environment = {
            "LETSINFER_HOME": str(self.root / "source"),
        }
        self.destination_environment = {
            "LETSINFER_HOME": str(self.root / "destination"),
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def joined_child(self) -> tuple[state.SiteIdentity, state.SiteIdentity]:
        with mock.patch.dict(os.environ, self.destination_environment):
            destination = state.setup_site("Home", "destination.local")
            with state.SiteStore(identity=destination) as store:
                invite = store.create_invite("lan")
            destination_control = control.SiteControlState(
                destination, facts_provider=lambda: {}
            )
            challenge = destination_control.challenge(invite["invite_id"])
        with mock.patch.dict(os.environ, self.source_environment):
            source = state.setup_site("Source", "source.local")
            candidate = state.existing_member_identity(source)
            transcript = control.enrollment_transcript(
                challenge,
                candidate,
                member_name="Source member",
                member_address="source.local",
            )
            proof = state.member_proof(transcript)
        with mock.patch.dict(os.environ, self.destination_environment):
            response = destination_control.enroll(
                {
                    "protocol": control.PROTOCOL,
                    "invite_id": invite["invite_id"],
                    "code": invite["code"],
                    "member_id": candidate["member_id"],
                    "member_name": "Source member",
                    "member_address": "source.local",
                    "member_public_key": candidate["member_public_key"],
                    "installation_id": candidate["installation_id"],
                    "installation_created_at_unix": candidate["created_at_unix"],
                    "proof_signature": proof,
                }
            )
        with mock.patch.dict(os.environ, self.source_environment):
            with move.LocalMoveTransaction(source) as transaction:
                state.install_member_identity(
                    response["document"],
                    response["signature"],
                    response["site_public_key"],
                    response["site_ca_certificate"],
                    response["member_certificate"],
                )
                child = transaction.commit()
        return source, child

    def test_failed_move_restores_site_and_preserves_runtime_objects(self) -> None:
        with mock.patch.dict(os.environ, self.source_environment):
            source = state.setup_site("Source", "source.local")
            old_secret = state.secrets_root() / "api-key"
            old_secret.write_text("source-only\n", encoding="ascii")
            old_secret.chmod(0o600)
            runtime = state.data_root() / "runtimes/objects/example"
            runtime.mkdir(parents=True)
            (runtime / "runtime.json").write_text("{}\n", encoding="ascii")
            gateway = state.data_root() / "gateway"
            gateway.mkdir()
            (gateway / "telemetry.state").write_text("old\n", encoding="ascii")
            with self.assertRaisesRegex(RuntimeError, "cancel"):
                with move.LocalMoveTransaction(source):
                    self.assertFalse(old_secret.exists())
                    self.assertTrue((state.secrets_root() / "member.key").is_file())
                    self.assertTrue(runtime.is_dir())
                    raise RuntimeError("cancel")
            self.assertEqual(state.read_identity(), source)
            self.assertEqual(old_secret.read_text(encoding="ascii"), "source-only\n")
            self.assertTrue((gateway / "telemetry.state").is_file())
            self.assertTrue((runtime / "runtime.json").is_file())

    def test_move_replaces_site_credentials_but_preserves_physical_identity(self) -> None:
        with mock.patch.dict(os.environ, self.destination_environment):
            destination = state.setup_site("Home", "destination.local")
            with state.SiteStore(identity=destination) as store:
                invite = store.create_invite("lan")
            destination_control = control.SiteControlState(
                destination,
                facts_provider=lambda: {},
            )
        with mock.patch.dict(os.environ, self.source_environment):
            source = state.setup_site("Source", "source.local")
            old_site_public = state.site_public_key_path().read_bytes()
            old_secret = state.secrets_root() / "api-key"
            old_secret.write_text("source-only\n", encoding="ascii")
            old_secret.chmod(0o600)
            runtime = state.data_root() / "runtimes/objects/example"
            runtime.mkdir(parents=True)
            (runtime / "runtime.json").write_text("{}\n", encoding="ascii")
            with state.SiteStore(identity=source) as store:
                plan = move.plan_local_move(store)
            self.assertEqual(plan.blocking_reasons, ())
            with move.LocalMoveTransaction(source) as transaction:
                candidate = state.prepare_member_identity()
                with mock.patch.dict(os.environ, self.destination_environment):
                    challenge = destination_control.challenge(invite["invite_id"])
                with mock.patch.dict(os.environ, self.source_environment):
                    transcript = control.enrollment_transcript(
                        challenge,
                        candidate,
                        member_name="Source member",
                        member_address="source.local",
                    )
                    proof = state.member_proof(transcript)
                with mock.patch.dict(os.environ, self.destination_environment):
                    response = destination_control.enroll(
                        {
                            "protocol": control.PROTOCOL,
                            "invite_id": invite["invite_id"],
                            "code": invite["code"],
                            "member_id": candidate["member_id"],
                            "member_name": "Source member",
                            "member_address": "source.local",
                            "member_public_key": candidate["member_public_key"],
                            "installation_id": candidate["installation_id"],
                            "installation_created_at_unix": candidate["created_at_unix"],
                            "proof_signature": proof,
                        }
                    )
                with mock.patch.dict(os.environ, self.source_environment):
                    state.install_member_identity(
                        response["document"],
                        response["signature"],
                        response["site_public_key"],
                        response["site_ca_certificate"],
                        response["member_certificate"],
                    )
                    replacement = transaction.commit()
            self.assertEqual(replacement.site_id, destination.site_id)
            self.assertEqual(replacement.member_id, source.member_id)
            self.assertEqual(replacement.installation_id, source.installation_id)
            self.assertEqual(replacement.created_at_unix, source.created_at_unix)
            self.assertFalse(state.site_key_path().exists())
            self.assertNotEqual(state.site_public_key_path().read_bytes(), old_site_public)
            self.assertFalse(old_secret.exists())
            self.assertTrue((runtime / "runtime.json").is_file())
            self.assertFalse(state.database_path().exists())

    def test_child_detach_preserves_physical_identity_and_rolls_back_before_commit(self) -> None:
        source, child = self.joined_child()
        with mock.patch.dict(os.environ, self.source_environment):
            with self.assertRaisesRegex(RuntimeError, "cancel"):
                with move.LocalDetachTransaction(child):
                    detached = state.setup_site("Detached", "detached.local")
                    self.assertEqual(detached.role, "main")
                    raise RuntimeError("cancel")
            self.assertEqual(state.read_identity(), child)

            with move.LocalDetachTransaction(child) as transaction:
                detached = state.setup_site("Detached", "detached.local")
                replacement = transaction.commit()
            self.assertEqual(replacement, detached)
            self.assertEqual(replacement.role, "main")
            self.assertNotEqual(replacement.site_id, child.site_id)
            self.assertEqual(replacement.member_id, source.member_id)
            self.assertEqual(replacement.installation_id, source.installation_id)
            self.assertEqual(replacement.created_at_unix, source.created_at_unix)

    def test_prepared_move_requires_destination_approval_before_commit(self) -> None:
        with mock.patch.dict(os.environ, self.destination_environment):
            destination = state.setup_site("Home", "destination.local")
            with state.SiteStore(identity=destination) as store:
                invite = store.create_invite("remote")
            destination_control = control.SiteControlState(
                destination, facts_provider=lambda: {}
            )
            challenge = destination_control.challenge(invite["invite_id"])
        with mock.patch.dict(os.environ, self.source_environment):
            source = state.setup_site("Source", "source.local")
            candidate = state.existing_member_identity(source)
            transcript = control.enrollment_transcript(
                challenge,
                candidate,
                member_name="Source member",
                member_address="source.local",
            )
            proof = state.member_proof(transcript)
        with mock.patch.dict(os.environ, self.destination_environment):
            response = destination_control.enroll(
                {
                    "protocol": control.PROTOCOL,
                    "invite_id": invite["invite_id"],
                    "code": invite["code"],
                    "member_id": candidate["member_id"],
                    "member_name": "Source member",
                    "member_address": "source.local",
                    "member_public_key": candidate["member_public_key"],
                    "installation_id": candidate["installation_id"],
                    "installation_created_at_unix": candidate["created_at_unix"],
                    "proof_signature": proof,
                }
            )
            package = control.EnrollmentPackage(
                document=response["document"],
                signature=response["signature"],
                site_public_key=response["site_public_key"],
                site_ca_certificate=response["site_ca_certificate"],
                member_certificate=response["member_certificate"],
                comparison_code=response["comparison_code"],
            )
        with mock.patch.dict(os.environ, self.source_environment), mock.patch.object(
            move, "request_membership", return_value=package
        ):
            prepared = move.prepare_local_move(
                endpoint="https://destination.local:9770",
                invite_id=invite["invite_id"],
                code=invite["code"],
                coordinator_certificate_sha256="1" * 64,
                member_name="Source member",
                member_address="source.local",
                now_unix=100,
            )
            with mock.patch.object(
                move,
                "fetch_candidate_membership",
                return_value={
                    "site_id": destination.site_id,
                    "member_id": source.member_id,
                    "state": "pending",
                },
            ), self.assertRaisesRegex(state.SiteError, "not been approved"):
                move.apply_prepared_move(prepared, now_unix=101)

        with mock.patch.dict(os.environ, self.destination_environment):
            with state.SiteStore(identity=destination) as store:
                store.approve_member(source.member_id, response["comparison_code"])
        with mock.patch.dict(os.environ, self.source_environment), mock.patch.object(
            move,
            "fetch_candidate_membership",
            return_value={
                "site_id": destination.site_id,
                "member_id": source.member_id,
                "state": "active",
            },
        ):
            replacement = move.apply_prepared_move(prepared, now_unix=101)
            self.assertEqual(replacement.site_id, destination.site_id)
            self.assertEqual(replacement.member_id, source.member_id)

    def test_controller_move_uses_launchd_transaction_and_restarts_after_response(self) -> None:
        events: list[str] = []

        class Services:
            def __enter__(self):
                events.append("snapshot")
                return self

            def remove(self, label: str) -> None:
                events.append(f"remove:{label}")

            def commit(self) -> None:
                events.append("commit")

            def __exit__(self, *_: object) -> None:
                events.append("exit")

        replacement = object()

        def apply(_prepared: object, *, before_transaction: object):
            before_transaction()  # type: ignore[operator]
            events.append("identity")
            return replacement

        with (
            mock.patch.object(cli.platform, "system", return_value="Darwin"),
            mock.patch.object(
                cli.macos_services, "user_domain_available", return_value=True
            ),
            mock.patch.object(
                cli.macos_services,
                "service_state",
                return_value=("enabled", "active", None),
            ),
            mock.patch.object(
                cli.macos_services,
                "LaunchAgentTransaction",
                return_value=Services(),
            ),
            mock.patch.object(cli, "apply_prepared_move", side_effect=apply),
        ):
            self.assertIs(cli._apply_controller_site_move(object()), replacement)

        self.assertEqual(
            events,
            [
                "snapshot",
                f"remove:{cli.macos_services.GATEWAY_LABEL}",
                "identity",
                "commit",
                "exit",
            ],
        )
        completed = {"move": {"move_id": "a" * 32}}
        with (
            mock.patch.object(cli.platform, "system", return_value="Darwin"),
            mock.patch.object(
                cli.macos_services, "restart_launch_agent"
            ) as restart,
        ):
            cli._controller_administration_completed("node.move.commit", completed)
        restart.assert_called_once_with(cli.macos_services.NODE_LABEL)

    def test_explicit_macos_move_rebinds_only_launchd_node_service(self) -> None:
        source = state.SiteIdentity(
            site_id="1" * 32,
            member_id="2" * 32,
            installation_id="3" * 64,
            display_name="Source",
            role="main",
            coordinator_id="2" * 32,
            coordinator_address="source.local",
            site_public_key_sha256="4" * 64,
            member_public_key_sha256="5" * 64,
            created_at_unix=1_700_000_000,
        )
        child = state.SiteIdentity(
            site_id="6" * 32,
            member_id=source.member_id,
            installation_id=source.installation_id,
            display_name="Source",
            role="child",
            coordinator_id="7" * 32,
            coordinator_address="main.local",
            site_public_key_sha256="8" * 64,
            member_public_key_sha256=source.member_public_key_sha256,
            created_at_unix=source.created_at_unix,
        )
        events: list[str] = []

        class Services:
            def __enter__(self):
                events.append("snapshot")
                return self

            def remove(self, label: str) -> None:
                events.append(f"remove:{label}")

            def commit(self) -> None:
                events.append("services-commit")

            def __exit__(self, *_: object) -> None:
                events.append("services-exit")

        class IdentityTransaction:
            def __init__(self, _: object) -> None:
                pass

            def __enter__(self):
                events.append("identity-stage")
                return self

            def commit(self):
                events.append("identity-commit")
                return child

            def __exit__(self, *_: object) -> None:
                events.append("identity-exit")

        plan = SimpleNamespace(
            document=lambda: {"blocking_reasons": []},
            blocking_reasons=(),
        )
        store = mock.Mock()
        enrollment = SimpleNamespace(
            identity=child,
            state="active",
            approval_expires_at_unix=None,
            comparison_code=None,
        )
        arguments = argparse.Namespace(
            action_id="node.add",
            apply=True,
            source_site_id=source.site_id,
            endpoint="https://main.local:9770",
            invite="9" * 32,
            coordinator_certificate_sha256="a" * 64,
            code="12345678",
            name="Source",
            address="source.local",
            no_service=False,
            json=True,
        )
        with (
            mock.patch.object(cli, "read_site_identity", return_value=source),
            mock.patch.object(
                cli,
                "_site_store",
                side_effect=lambda: contextlib.nullcontext(store),
            ),
            mock.patch.object(cli, "plan_local_move", return_value=plan),
            mock.patch.object(cli.platform, "system", return_value="Darwin"),
            mock.patch.object(cli, "user_lingering_enabled", return_value=True),
            mock.patch.object(
                cli, "_unit_enabled_active", return_value=("enabled", "active")
            ),
            mock.patch.object(
                cli.macos_services,
                "LaunchAgentTransaction",
                return_value=Services(),
            ),
            mock.patch.object(cli, "LocalMoveTransaction", IdentityTransaction),
            mock.patch.object(cli, "join_site", return_value=enrollment),
            mock.patch.object(cli, "install_node_service_only") as install_node,
            mock.patch.object(cli, "ensure_core_watchdog_tls") as watchdog_tls,
            mock.patch.object(cli, "install_core_watchdog_service") as watchdog_service,
            mock.patch.object(
                cli, "_command_activity", return_value=contextlib.nullcontext()
            ),
            mock.patch.object(
                cli.ui, "protect_stdout", return_value=contextlib.nullcontext()
            ),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(cli.site_move_command(arguments), 0)

        install_node.assert_called_once_with()
        watchdog_tls.assert_not_called()
        watchdog_service.assert_not_called()
        self.assertEqual(
            events,
            [
                "snapshot",
                f"remove:{cli.macos_services.GATEWAY_LABEL}",
                f"remove:{cli.macos_services.NODE_LABEL}",
                "identity-stage",
                "identity-commit",
                "identity-exit",
                "services-commit",
                "services-exit",
            ],
        )


if __name__ == "__main__":
    unittest.main()
