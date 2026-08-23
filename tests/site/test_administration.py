# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import dataclasses
import hashlib
import os
import pathlib
import tempfile
import time
import unittest
from unittest import mock

from core.site import administration, control, move, state


CONTROLLER = "a" * 32


class SiteAdministrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.temporary.name)
        self.environment = mock.patch.dict(
            os.environ,
            {"LETSINFER_HOME": str(root)},
        )
        self.environment.start()
        self.identity = state.setup_site("Home", "home.local")

    def tearDown(self) -> None:
        self.environment.stop()
        self.temporary.cleanup()

    def test_plan_and_invite_are_narrow_and_controller_audited(self) -> None:
        admin = administration.SiteAdministration(self.identity)
        plan = admin.perform(
            controller_id=CONTROLLER, action="node.move.plan", payload={}
        )
        self.assertEqual(plan["plan"]["source_site_id"], self.identity.site_id)
        invite = admin.perform(
            controller_id=CONTROLLER,
            action="child.invite",
            payload={
                "mode": "lan",
                "expires_in": 180,
                "candidate_public_key_sha256": None,
                "direct_interface": None,
                "candidate_endpoint": None,
            },
        )["invite"]
        self.assertRegex(invite["code"], r"^[0-9]{8}$")
        self.assertEqual(invite["endpoint"], "https://home.local:9770")
        with state.SiteStore(identity=self.identity) as store:
            event = store.audit_rows(limit=1)[0]
        self.assertEqual(event["action"], "child.invite")
        self.assertEqual(event["actor_type"], "controller")
        self.assertEqual(event["actor_id"], CONTROLLER)
        with self.assertRaisesRegex(administration.AdministrationError, "schema"):
            admin.perform(
                controller_id=CONTROLLER,
                action="child.invite",
                payload={"mode": "lan"},
            )

    def test_member_drain_and_resume_are_narrow_controller_operations(self) -> None:
        admin = administration.SiteAdministration(self.identity)
        drained = admin.perform(
            controller_id=CONTROLLER,
            action="child.drain",
            payload={"member_id": self.identity.member_id},
        )
        self.assertEqual(drained["membership"]["state"], "draining")
        resumed = admin.perform(
            controller_id=CONTROLLER,
            action="child.resume",
            payload={"member_id": self.identity.member_id},
        )
        self.assertEqual(resumed["membership"]["state"], "active")
        with state.SiteStore(identity=self.identity) as store:
            events = store.audit_rows(limit=2)
        self.assertEqual(
            [event["action"] for event in events],
            ["child.resume", "child.drain"],
        )
        self.assertTrue(all(event["actor_type"] == "controller" for event in events))
        self.assertTrue(all(event["actor_id"] == CONTROLLER for event in events))
        with self.assertRaisesRegex(administration.AdministrationError, "schema"):
            admin.perform(
                controller_id=CONTROLLER,
                action="child.drain",
                payload={"member_id": self.identity.member_id, "force": True},
            )

    def test_prepared_connectx_member_can_be_cancelled_before_move_commit(self) -> None:
        member_id = "e" * 32
        now = int(time.time())
        with state.SiteStore(identity=self.identity) as store:
            store.connection.execute(
                """INSERT INTO members
                   (member_id,display_name,role,address,public_key_sha256,public_key_pem,
                    certificate_sha256,certificate_pem,state,approval_code_hash,
                    approval_expires_at_unix,facts_json,facts_signature_base64,
                    facts_sha256,joined_at_unix,updated_at_unix)
                   VALUES(?,?,'child',?,?,?,?,?,'active',NULL,NULL,'{}',NULL,NULL,?,?)""",
                (
                    member_id,
                    "Prepared member",
                    "child.local",
                    hashlib.sha256(b"prepared-key").hexdigest(),
                    "synthetic-public-key",
                    hashlib.sha256(b"prepared-certificate").hexdigest(),
                    "synthetic-certificate",
                    now,
                    now,
                ),
            )
        admin = administration.SiteAdministration(self.identity)
        result = admin.perform(
            controller_id=CONTROLLER,
            action="child.cancel",
            payload={"member_id": member_id},
        )
        self.assertEqual(result["membership"]["state"], "removed")
        with state.SiteStore(identity=self.identity) as store:
            self.assertNotIn(member_id, {row["member_id"] for row in store.members()})
            event = store.audit_rows(limit=1)[0]
        self.assertEqual(event["action"], "child.remove")
        self.assertEqual(event["actor_id"], CONTROLLER)

    def test_fresh_member_adoption_is_direct_signed_and_controller_audited(self) -> None:
        admin = administration.SiteAdministration(self.identity)
        response = {
            "protocol": "letsinfer-node-adoption-v1",
            "state": "committed",
            "source_site_id": "b" * 32,
            "destination_site_id": self.identity.site_id,
            "member_id": "c" * 32,
            "move_id": "d" * 32,
        }
        with (
            mock.patch.object(
                administration,
                "select_direct_connectx_interface",
                return_value={"interface": "enp1s0"},
            ),
            mock.patch.object(
                administration,
                "resolve_direct_peer",
                return_value="192.0.2.20",
            ),
            mock.patch.object(
                administration,
                "verify_direct_connectx_peer",
                return_value={
                    "interface": "enp1s0",
                    "peer_address": "192.0.2.20",
                    "local_address": "192.0.2.10",
                },
            ),
            mock.patch.object(
                administration, "request_adoption", return_value=response
            ) as request,
        ):
            result = admin.perform(
                controller_id=CONTROLLER,
                action="child.adopt",
                payload={
                    "source_endpoint": "https://192.0.2.20:9770",
                    "source_site_id": "b" * 32,
                    "source_member_id": "c" * 32,
                    "source_public_key_sha256": "e" * 64,
                    "source_certificate_sha256": "f" * 64,
                },
            )
        self.assertEqual(result, {"adoption": response})
        self.assertEqual(request.call_args.kwargs["source_member_address"], "192.0.2.20")
        self.assertEqual(
            request.call_args.kwargs["invite"]["endpoint"],
            "https://192.0.2.10:9770",
        )
        with state.SiteStore(identity=self.identity) as store:
            self.assertEqual(store.audit_rows(limit=1)[0]["action"], "child.adopt")

    def test_prepared_move_is_bound_to_its_controller(self) -> None:
        destination_site = "b" * 32
        package = control.EnrollmentPackage(
            document={
                "site_id": destination_site,
                "member_id": self.identity.member_id,
                "state": "active",
                "approval_expires_at_unix": None,
            },
            signature="signature",
            site_public_key="public",
            site_ca_certificate="ca",
            member_certificate="certificate",
            comparison_code=None,
        )
        prepared = move.PreparedMove(
            move_id="c" * 32,
            source=self.identity,
            plan=move.MovePlan(
                source_site_id=self.identity.site_id,
                source_member_id=self.identity.member_id,
                destination_effect="replace-local-site-membership",
                member_count=1,
                controller_count=1,
                api_key_count=0,
                placement_count=0,
                active_placements=(),
                blocking_reasons=(),
                preserved_data=(),
                reset_state=(),
            ),
            destination_endpoint="https://destination.local:9770",
            coordinator_certificate_sha256="d" * 64,
            package=package,
            created_at_unix=int(time.time()),
            expires_at_unix=int(time.time()) + 300,
        )
        replacement = dataclasses.replace(
            self.identity,
            site_id=destination_site,
            role="child",
            coordinator_id="e" * 32,
            coordinator_address="destination.local",
        )
        admin = administration.SiteAdministration(
            self.identity, move_apply=lambda value: replacement
        )
        payload = {
            "source_site_id": self.identity.site_id,
            "endpoint": "https://destination.local:9770",
            "invite_id": "f" * 32,
            "code": None,
            "main_certificate_sha256": "d" * 64,
            "member_name": "Source",
            "member_address": "source.local",
        }
        with mock.patch.object(
            administration, "prepare_local_move", return_value=prepared
        ):
            result = admin.perform(
                controller_id=CONTROLLER,
                action="node.move.prepare",
                payload=payload,
            )
        self.assertEqual(result["move"]["move_id"], prepared.move_id)
        with self.assertRaisesRegex(administration.AdministrationError, "another"):
            admin.perform(
                controller_id="1" * 32,
                action="node.move.commit",
                payload={"move_id": prepared.move_id},
            )
        committed = admin.perform(
            controller_id=CONTROLLER,
            action="node.move.commit",
            payload={"move_id": prepared.move_id},
        )
        self.assertEqual(committed["move"]["state"], "committed")

        second = dataclasses.replace(prepared, move_id="9" * 32)
        with mock.patch.object(
            administration, "prepare_local_move", return_value=second
        ):
            admin.perform(
                controller_id=CONTROLLER,
                action="node.move.prepare",
                payload=payload,
            )
        cancelled = admin.perform(
            controller_id=CONTROLLER,
            action="node.move.cancel",
            payload={"move_id": second.move_id},
        )
        self.assertEqual(cancelled["move"]["state"], "cancelled")
        with self.assertRaisesRegex(administration.AdministrationError, "unknown"):
            admin.perform(
                controller_id=CONTROLLER,
                action="node.move.commit",
                payload={"move_id": second.move_id},
            )

    def test_api_key_lifecycle_is_controller_audited_and_returns_secret_once(self) -> None:
        admin = administration.SiteAdministration(self.identity)
        policy = {
            "models": ["example-model"],
            "expires_at_unix": int(time.time()) + 3600,
            "requests_per_minute": 60,
            "tokens_per_minute": 100_000,
            "concurrency_limit": 4,
            "context_limit": 65_536,
            "tenant": "home",
            "application": "mac-app",
        }
        created = admin.perform(
            controller_id=CONTROLLER,
            action="key.create",
            payload={"name": "mac-app", **policy},
        )
        self.assertRegex(created["token"], r"^li_[0-9a-f]{16}_[A-Za-z0-9_-]+$")
        key_id = created["key"]["key_id"]
        listed = admin.perform(
            controller_id=CONTROLLER, action="key.list", payload={}
        )
        self.assertEqual([item["key_id"] for item in listed["keys"]], [key_id])
        self.assertNotIn("token", listed["keys"][0])
        shown = admin.perform(
            controller_id=CONTROLLER,
            action="key.show",
            payload={"key": key_id},
        )
        self.assertEqual(shown["key"]["models"], ["example-model"])

        updated = admin.perform(
            controller_id=CONTROLLER,
            action="key.policy",
            payload={"key": key_id, **{**policy, "concurrency_limit": 8}},
        )
        self.assertEqual(updated["key"]["concurrency_limit"], 8)
        rotated = admin.perform(
            controller_id=CONTROLLER,
            action="key.rotate",
            payload={"key": key_id},
        )
        self.assertNotEqual(rotated["key"]["key_id"], key_id)
        self.assertNotEqual(rotated["token"], created["token"])
        revoked = admin.perform(
            controller_id=CONTROLLER,
            action="key.revoke",
            payload={"key": rotated["key"]["key_id"]},
        )
        self.assertIsNotNone(revoked["key"]["revoked_at_unix"])
        with state.SiteStore(identity=self.identity) as store:
            events = store.audit_rows(limit=20)
        key_events = [event for event in events if event["action"].startswith("key.")]
        self.assertTrue(key_events)
        self.assertTrue(all(event["actor_type"] == "controller" for event in key_events))
        self.assertTrue(all(event["actor_id"] == CONTROLLER for event in key_events))
        self.assertNotIn(created["token"], str(key_events))


if __name__ == "__main__":
    unittest.main()
