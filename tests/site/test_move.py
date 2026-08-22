# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import os
import pathlib
import tempfile
import unittest
from unittest import mock

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

    def test_prepared_move_requires_destination_approval_before_commit(self) -> None:
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


if __name__ == "__main__":
    unittest.main()
