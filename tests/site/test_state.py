# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import copy
import json
import os
import pathlib
import sqlite3
import tempfile
import unittest
from unittest import mock

from core.orchestration import build_group_plan
from core.site import state


class SiteStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.temporary.name)
        self.environment = mock.patch.dict(
            os.environ,
            {"LETSINFER_HOME": str(root)},
            clear=False,
        )
        self.environment.start()

    def tearDown(self) -> None:
        self.environment.stop()
        self.temporary.cleanup()

    def test_setup_separates_site_and_member_keys(self) -> None:
        identity = state.setup_site("Home", "127.0.0.1")
        self.assertEqual(identity.role, "coordinator")
        self.assertNotEqual(
            state.site_key_path().read_bytes(), state.member_key_path().read_bytes()
        )
        for path in (
            state.identity_path(), state.site_key_path(), state.site_public_key_path(),
            state.site_ca_certificate_path(), state.member_key_path(),
            state.member_public_key_path(), state.member_certificate_path(),
            state.database_path(),
        ):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        with state.SiteStore(identity=identity) as store:
            self.assertEqual(store.members()[0]["member_id"], identity.member_id)
            self.assertTrue(store.verify_audit()["valid"])

    def test_fresh_adoption_window_expires_and_closes_after_external_pairing(self) -> None:
        identity = state.setup_site("Home", "127.0.0.1")
        certificate = (
            "-----BEGIN CERTIFICATE-----\n"
            "synthetic-controller-certificate\n"
            "-----END CERTIFICATE-----\n"
        )
        with state.SiteStore(identity=identity) as store:
            current = store.adoption()
            self.assertTrue(current["eligible"])
            self.assertRegex(current["nonce"], r"^[0-9a-f]{64}$")
            self.assertFalse(
                store.adoption(now_unix=current["expires_at_unix"] + 1)["eligible"]
            )
            store.upsert_controller(
                controller_id="a" * 32,
                name="Local",
                role="administrator",
                certificate_sha256="b" * 64,
                certificate_pem=certificate,
            )
            self.assertTrue(store.adoption()["eligible"])
            store.upsert_controller(
                controller_id="c" * 32,
                name="Mac",
                role="administrator",
                certificate_sha256="d" * 64,
                certificate_pem=certificate,
            )
            self.assertIn(
                "external_controller_exists", store.adoption()["reasons"]
            )

    def test_key_rotation_is_one_atomic_mutation_and_secret_is_not_stored(self) -> None:
        identity = state.setup_site()
        with state.SiteStore(identity=identity) as store:
            original, old_token = store.create_key(
                "application", models=["fixture-model"], concurrency_limit=4
            )
            before = store.verify_audit()["events"]
            replacement, new_token = store.rotate_key("application")
            after = store.verify_audit()["events"]
            self.assertEqual(after, before + 1)
            self.assertEqual(replacement["name"], "application")
            self.assertEqual(replacement["rotated_from"], original["key_id"])
            self.assertIsNone(store.authenticate_key(old_token))
            self.assertEqual(store.authenticate_key(new_token)["key_id"], replacement["key_id"])
        database_bytes = state.database_path().read_bytes()
        self.assertNotIn(old_token.encode("ascii"), database_bytes)
        self.assertNotIn(new_token.encode("ascii"), database_bytes)

    def test_api_key_tags_remain_bounded_on_create_and_policy_update(self) -> None:
        identity = state.setup_site()
        with state.SiteStore(identity=identity) as store:
            with self.assertRaisesRegex(state.SiteError, "tenant is invalid"):
                store.create_key("oversized-create", tenant="x" * 129)
            key, _token = store.create_key("bounded-tags", tenant="tenant")
            with self.assertRaisesRegex(state.SiteError, "application is invalid"):
                store.update_key_policy(key["key_id"], application="x" * 129)
            current = store.key(key["key_id"])
            self.assertEqual(current["tenant"], "tenant")
            self.assertIsNone(current["application"])
            with self.assertRaisesRegex(state.SiteError, "sequence of model names"):
                store.create_key("string-model-scope", models="fixture-model")
            with self.assertRaisesRegex(state.SiteError, "expires_at_unix"):
                store.update_key_policy(key["key_id"], expires_at_unix=True)

    def test_audit_chain_detects_owner_tampering(self) -> None:
        identity = state.setup_site()
        with state.SiteStore(identity=identity) as store:
            store.create_key("application")
            store.connection.execute("DROP TRIGGER audit_events_no_update")
            store.connection.execute(
                "UPDATE audit_events SET reason='tampered' WHERE sequence=1"
            )
            with self.assertRaisesRegex(state.SiteError, "hash mismatch"):
                store.verify_audit()

    def test_signed_audit_checkpoint_detects_owner_tampering(self) -> None:
        with mock.patch.object(state, "CHECKPOINT_INTERVAL", 2):
            identity = state.setup_site()
            with state.SiteStore(identity=identity) as store:
                store.create_key("application")
                self.assertTrue(store.verify_audit()["valid"])
                store.connection.execute(
                    "DROP TRIGGER audit_checkpoints_no_update"
                )
                store.connection.execute(
                    "UPDATE audit_checkpoints SET event_hash=? WHERE sequence=2",
                    ("f" * 64,),
                )
                with self.assertRaisesRegex(state.SiteError, "checkpoint mismatch"):
                    store.verify_audit()

    def test_complete_audit_iterator_is_chronological_and_unlimited(self) -> None:
        identity = state.setup_site()
        with state.SiteStore(identity=identity) as store:
            for index in range(5):
                store.record_action("fixture.read", str(index), "success")
            rows = list(store.iter_audit_rows())
            self.assertEqual(
                [row["sequence"] for row in rows],
                list(range(1, len(rows) + 1)),
            )
            self.assertEqual(len(rows), store.verify_audit()["events"])

    def test_controller_authority_is_sqlite_backed_and_audited(self) -> None:
        identity = state.setup_site()
        certificate = (
            "-----BEGIN CERTIFICATE-----\n"
            "synthetic-controller-certificate\n"
            "-----END CERTIFICATE-----\n"
        )
        with state.SiteStore(identity=identity) as store:
            before = store.verify_audit()["events"]
            created = store.upsert_controller(
                controller_id="a" * 32,
                name="Desk Mac",
                role="administrator",
                certificate_sha256="b" * 64,
                certificate_pem=certificate,
            )
            self.assertEqual(created["controller_id"], "a" * 32)
            rows = store.controllers()
            self.assertEqual(rows[0]["role"], "administrator")
            self.assertNotIn("certificate_pem", rows[0])
            self.assertEqual(store.verify_audit()["events"], before + 1)
            store.revoke_controller("a" * 32)
            self.assertEqual(store.controllers(), [])
            self.assertEqual(store.verify_audit()["events"], before + 2)

    def test_placement_schema_is_closed_and_rejects_numeric_coercion(self) -> None:
        identity = state.setup_site()
        placement = {
            "placement_id": "a" * 32,
            "model": "fixture-model",
            "runtime": "fixture-model/fixture-engine/fixture-target@1",
            "target": "fixture-target",
            "strategy": "single",
            "state": "running",
            "topology_sha256": "b" * 64,
            "members": [identity.member_id],
            "endpoints": [{
                "member_id": identity.member_id,
                "url": "http://127.0.0.1:18000",
                "credential_file": str(state.config_root() / "engine.key"),
                "ca_file": None,
                "token_count_path": "/v1/token-count",
                "token_count_protocol": "letsinfer-token-count-v1",
                "max_active_requests": 1,
                "max_context_tokens": 4096,
                "healthy": True,
                "memory_pressure": False,
                "temperature_c": -1,
                "prefix_keys": [],
            }],
            "capacity": {
                "max_connections": 16,
                "max_active_requests": 1,
                "max_context_tokens": 4096,
            },
        }
        with state.SiteStore(identity=identity) as store:
            store.set_placement(placement)
            invalid: list[tuple[str, dict]] = []
            for label, path, value in (
                ("boolean endpoint capacity", ("endpoints", 0, "max_active_requests"), True),
                ("string endpoint capacity", ("endpoints", 0, "max_context_tokens"), "4096"),
                ("boolean aggregate capacity", ("capacity", "max_active_requests"), False),
                ("non-string prefix", ("endpoints", 0, "prefix_keys"), [1]),
                ("public plaintext backend", ("endpoints", 0, "url"), "http://192.0.2.1:18000"),
            ):
                candidate = copy.deepcopy(placement)
                target = candidate
                for item in path[:-1]:
                    target = target[item]
                target[path[-1]] = value
                invalid.append((label, candidate))
            extra_endpoint = copy.deepcopy(placement)
            extra_endpoint["endpoints"][0]["internal_note"] = "not-schema"
            invalid.append(("unknown endpoint field", extra_endpoint))
            extra_capacity = copy.deepcopy(placement)
            extra_capacity["capacity"]["scheduler_hint"] = 1
            invalid.append(("unknown capacity field", extra_capacity))
            no_endpoint = copy.deepcopy(placement)
            no_endpoint["endpoints"] = []
            invalid.append(("running without endpoint", no_endpoint))

            for label, candidate in invalid:
                with self.subTest(label=label):
                    with self.assertRaises(state.SiteError):
                        store.set_placement(candidate)

    def test_new_running_placement_atomically_supersedes_old_model_placement(self) -> None:
        identity = state.setup_site()
        endpoint = {
            "member_id": identity.member_id,
            "url": "http://127.0.0.1:18000",
            "credential_file": str(state.config_root() / "engine.key"),
            "ca_file": None,
            "token_count_path": "/v1/token-count",
            "token_count_protocol": "letsinfer-token-count-v1",
            "max_active_requests": 1,
            "max_context_tokens": 4096,
            "healthy": True,
            "memory_pressure": False,
            "temperature_c": -1,
            "prefix_keys": [],
        }
        first = {
            "placement_id": "a" * 32,
            "model": "fixture-model",
            "runtime": "fixture-model/fixture-engine/fixture-target@1",
            "target": "fixture-target",
            "strategy": "single",
            "state": "running",
            "topology_sha256": "b" * 64,
            "members": [identity.member_id],
            "endpoints": [endpoint],
            "capacity": {
                "max_connections": 16,
                "max_active_requests": 1,
                "max_context_tokens": 4096,
            },
        }
        second = copy.deepcopy(first)
        second.update(
            {
                "placement_id": "c" * 32,
                "runtime": "fixture-model/fixture-engine/fixture-target@2",
                "topology_sha256": "d" * 64,
            }
        )
        with state.SiteStore(identity=identity) as store:
            store.set_placement(first)
            before = store.verify_audit()["events"]
            store.set_placement(second)
            placements = {row["placement_id"]: row for row in store.placements()}
            self.assertEqual(placements[first["placement_id"]]["state"], "stopped")
            self.assertEqual(placements[second["placement_id"]]["state"], "running")
            self.assertEqual(store.verify_audit()["events"], before + 1)

    def test_member_drain_and_resume_are_atomic_audited_admission_states(self) -> None:
        identity = state.setup_site()
        with state.SiteStore(identity=identity) as store:
            before = store.verify_audit()["events"]
            drained = store.set_member_draining(identity.member_id, True)
            self.assertEqual(
                drained, {"member_id": identity.member_id, "state": "draining"}
            )
            self.assertEqual(store.members()[0]["state"], "draining")
            resumed = store.set_member_draining(identity.member_id, False)
            self.assertEqual(
                resumed, {"member_id": identity.member_id, "state": "active"}
            )
            self.assertEqual(store.members()[0]["state"], "active")
            events = store.audit_rows(limit=2)
            self.assertEqual(
                [event["action"] for event in events],
                ["member.resume", "member.drain"],
            )
            self.assertTrue(all(event["outcome"] == "success" for event in events))
            self.assertEqual(store.verify_audit()["events"], before + 2)

            store.connection.execute(
                "UPDATE members SET state='offline' WHERE member_id=?",
                (identity.member_id,),
            )
            with self.assertRaisesRegex(state.SiteError, "cannot be resumed"):
                store.set_member_draining(identity.member_id, False)
            self.assertEqual(store.members()[0]["state"], "offline")
            self.assertEqual(store.audit_rows(limit=1)[0]["outcome"], "failed")

    def test_audit_insert_failure_rolls_back_the_site_mutation(self) -> None:
        identity = state.setup_site()
        with state.SiteStore(identity=identity) as store:
            store.connection.execute(
                """CREATE TEMP TRIGGER reject_audit_insert
                   BEFORE INSERT ON audit_events
                   BEGIN SELECT RAISE(ABORT,'synthetic audit failure'); END"""
            )
            with self.assertRaisesRegex(
                state.SiteError, "mutation failed and its audit event could not be recorded"
            ):
                store.set_member_draining(identity.member_id, True)
            self.assertEqual(store.members()[0]["state"], "active")
            store.connection.execute("DROP TRIGGER reject_audit_insert")

    def test_topology_plan_is_immutable_audited_and_supersedes_pending_plan(self) -> None:
        identity = state.setup_site()
        proposed = {
            "schema_version": 1,
            "model": "example-model",
            "target": "example-target",
            "placement": {"strategy": "single", "members": [identity.member_id]},
            "automatic_restart": False,
        }
        with state.SiteStore(identity=identity) as store:
            before = store.verify_audit()["events"]
            first = store.create_topology_plan(
                "example-model", current=[], proposed=proposed
            )
            self.assertRegex(first["plan_id"], r"^[0-9a-f]{32}$")
            self.assertEqual(store.topology_plans()[0]["proposed"], proposed)
            changed = json.loads(json.dumps(proposed))
            changed["target"] = "example-target-v2"
            second = store.create_topology_plan(
                "example-model", current=[], proposed=changed
            )
            self.assertNotEqual(first["plan_id"], second["plan_id"])
            self.assertEqual(store.topology_plans()[0]["plan_id"], second["plan_id"])
            closed = store.topology_plans(include_closed=True)
            self.assertEqual(
                {row["plan_id"]: row["state"] for row in closed},
                {first["plan_id"]: "cancelled", second["plan_id"]: "pending"},
            )
            self.assertEqual(store.verify_audit()["events"], before + 2)

    def test_public_exposure_state_and_audit_commit_together(self) -> None:
        identity = state.setup_site()
        with state.SiteStore(identity=identity) as store:
            before = store.verify_audit()["events"]
            enabled = store.set_exposure(
                provider="tailscale-funnel",
                public_url="https://inference.example.ts.net",
                state="enabled",
                inference_target="http://127.0.0.1:8000",
                configuration_sha256="a" * 64,
            )
            self.assertEqual(enabled, store.exposure())
            self.assertEqual(store.verify_audit()["events"], before + 1)

    def test_engine_group_transition_is_placement_bound_and_audited(self) -> None:
        identity = state.setup_site()
        other = "f" * 32
        contract = {
            "schema_version": 1,
            "strategy": "replicated",
            "member_count": 2,
            "engine_strategy": "replica-pool",
            "failure_policy": "replica-independent",
            "minimum_healthy_members": 1,
            "startup_order": ["replica"],
            "roles": {
                "replica": {
                    "assignment": "all",
                    "launcher": "manifest",
                    "port_count": 1,
                    "environment": {},
                    "inference_endpoint": True,
                    "readiness": {"kind": "manifest"},
                }
            },
        }
        plan = build_group_plan(
            contract,
            member_ids=(identity.member_id, other),
            member_addresses={identity.member_id: "a.local:9770", other: "b.local:9770"},
            engine_coordinator_id=identity.member_id,
            topology_sha256="1" * 64,
            manifest_sha256="2" * 64,
            runtime_digest="3" * 64,
            member_port_bases={identity.member_id: 18000, other: 18000},
        )
        placement_id = "4" * 32
        members = [
            {
                "member_id": item.member_id,
                "role": item.role,
                "rank": item.rank,
                "state": "staging",
                "operation_id": None,
                "error": None,
            }
            for item in plan.assignments
        ]
        with state.SiteStore(identity=identity) as store:
            store.set_placement({
                "placement_id": placement_id,
                "model": "example-model",
                "runtime": "example-runtime",
                "target": "example-target",
                "strategy": "replicated",
                "state": "starting",
                "topology_sha256": "1" * 64,
                "members": [item.member_id for item in plan.assignments],
                "endpoints": [],
                "capacity": {},
            })
            before = store.verify_audit()["events"]
            stored = store.set_engine_group(
                plan.document(),
                placement_id=placement_id,
                source="registry.example/runtime@sha256:" + "5" * 64,
                engine_credential_sha256="6" * 64,
                desired_state="running",
                state="staging",
                members=members,
                action="group.stage",
            )
            self.assertEqual(stored["group_id"], plan.group_id)
            rows = store.engine_groups()
            self.assertEqual(rows[0]["state"], "staging")
            self.assertEqual(rows[0]["plan"], plan.document())
            self.assertEqual(store.verify_audit()["events"], before + 1)

    def test_membership_invite_is_one_use_and_site_key_never_moves(self) -> None:
        coordinator_home = pathlib.Path(self.temporary.name) / "coordinator"
        candidate_home = pathlib.Path(self.temporary.name) / "candidate"
        with mock.patch.dict(
            os.environ,
            {"LETSINFER_HOME": str(coordinator_home)},
        ):
            coordinator = state.setup_site("Home", "coordinator.local")
            with state.SiteStore(identity=coordinator) as store:
                invite = store.create_invite("lan")
        with mock.patch.dict(
            os.environ,
            {"LETSINFER_HOME": str(candidate_home)},
        ):
            candidate = state.prepare_member_identity()
            transcript = {
                "contract": "letsinfer-member-enrollment-v1",
                "site_id": coordinator.site_id,
                "invite_id": invite["invite_id"],
                "nonce": invite["nonce"],
                "member_id": candidate["member_id"],
                "member_name": "Member B",
                "member_address": "member-b.local",
                "member_public_key_sha256": candidate["member_public_key_sha256"],
                "installation_id": candidate["installation_id"],
                "installation_created_at_unix": candidate["created_at_unix"],
            }
            proof = state.member_proof(transcript)
        with mock.patch.dict(
            os.environ,
            {"LETSINFER_HOME": str(coordinator_home)},
        ):
            with state.SiteStore(identity=state.read_identity()) as store:
                incorrect = "00000000" if invite["code"] != "00000000" else "99999999"
                with self.assertRaisesRegex(state.SiteError, "incorrect"):
                    store.enroll_member(
                        invite_id=invite["invite_id"], code=incorrect,
                        member_id=candidate["member_id"], member_name="Member B",
                        member_address="member-b.local",
                        member_public_key=candidate["member_public_key"],
                        installation_id=candidate["installation_id"],
                        installation_created_at_unix=candidate["created_at_unix"],
                        proof_signature=proof,
                    )
                enrolled = store.enroll_member(
                    invite_id=invite["invite_id"], code=invite["code"],
                    member_id=candidate["member_id"], member_name="Member B",
                    member_address="member-b.local",
                    member_public_key=candidate["member_public_key"],
                    installation_id=candidate["installation_id"],
                    installation_created_at_unix=candidate["created_at_unix"],
                    proof_signature=proof,
                )
                with self.assertRaisesRegex(state.SiteError, "already consumed"):
                    store.enroll_member(
                        invite_id=invite["invite_id"], code=invite["code"],
                        member_id=candidate["member_id"], member_name="Member B",
                        member_address="member-b.local",
                        member_public_key=candidate["member_public_key"],
                        installation_id=candidate["installation_id"],
                        installation_created_at_unix=candidate["created_at_unix"],
                        proof_signature=proof,
                    )
        with mock.patch.dict(
            os.environ,
            {"LETSINFER_HOME": str(candidate_home)},
        ):
            joined = state.install_member_identity(
                enrolled["document"],
                enrolled["signature"],
                enrolled["site_public_key"],
                enrolled["site_ca_certificate"],
                enrolled["member_certificate"],
            )
            self.assertEqual(joined.role, "member")
            self.assertFalse(state.site_key_path().exists())
            self.assertTrue(state.member_certificate_path().exists())

    def test_expired_and_unapproved_enrollment_is_denied_and_audited(self) -> None:
        coordinator_home = pathlib.Path(self.temporary.name) / "denial-coordinator"
        candidate_home = pathlib.Path(self.temporary.name) / "denial-candidate"
        with mock.patch.dict(
            os.environ,
            {"LETSINFER_HOME": str(candidate_home)},
        ):
            candidate = state.prepare_member_identity()
        with mock.patch.dict(
            os.environ,
            {"LETSINFER_HOME": str(coordinator_home)},
        ):
            coordinator = state.setup_site("Home", "coordinator.local")
            with state.SiteStore(identity=coordinator) as store:
                expired = store.create_invite("lan")
                store.connection.execute(
                    "UPDATE membership_invites SET expires_at_unix=1 WHERE invite_id=?",
                    (expired["invite_id"],),
                )
                with self.assertRaisesRegex(state.SiteError, "expired"):
                    store.public_invite(expired["invite_id"])
                self.assertEqual(
                    store.audit_rows(limit=1)[0]["reason"], "invite_expired"
                )
                invite = store.create_invite(
                    "connectx",
                    candidate_public_key_sha256="f" * 64,
                    direct_interface="enp1s0",
                )
        transcript = {
            "contract": "letsinfer-member-enrollment-v1",
            "site_id": coordinator.site_id,
            "invite_id": invite["invite_id"],
            "nonce": invite["nonce"],
            "member_id": candidate["member_id"],
            "member_name": "Unapproved",
            "member_address": "192.0.2.20",
            "member_public_key_sha256": candidate["member_public_key_sha256"],
            "installation_id": candidate["installation_id"],
            "installation_created_at_unix": candidate["created_at_unix"],
        }
        with mock.patch.dict(
            os.environ,
            {"LETSINFER_HOME": str(candidate_home)},
        ):
            proof = state.member_proof(transcript)
        with mock.patch.dict(
            os.environ,
            {"LETSINFER_HOME": str(coordinator_home)},
        ):
            with state.SiteStore(identity=coordinator) as store:
                with self.assertRaisesRegex(state.SiteError, "approved ConnectX"):
                    store.enroll_member(
                        invite_id=invite["invite_id"],
                        code=None,
                        member_id=candidate["member_id"],
                        member_name="Unapproved",
                        member_address="192.0.2.20",
                        member_public_key=candidate["member_public_key"],
                        installation_id=candidate["installation_id"],
                        installation_created_at_unix=candidate["created_at_unix"],
                        proof_signature=proof,
                    )
                event = store.audit_rows(limit=1)[0]
                self.assertEqual(event["outcome"], "denied")
                self.assertEqual(event["reason"], "unapproved_connectx_identity")


if __name__ == "__main__":
    unittest.main()
