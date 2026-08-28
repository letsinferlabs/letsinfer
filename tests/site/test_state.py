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

from core.orchestration import build_single_placement_group_plan
from tests.gateway.helpers import insert_member, routing_facts, set_member_facts
from tests.orchestration.helpers import release_identity
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

    def register_group(
        self,
        store: state.SiteStore,
        identity: state.SiteIdentity,
        *,
        model: str = "fixture-model",
        runtime_digit: str = "3",
        topology_digit: str = "1",
    ):
        release = release_identity(
            manifest_sha256="2" * 64,
            runtime_digest=runtime_digit * 64,
        )
        service_id = store.ensure_model_service(model)["service_id"]
        plan = build_single_placement_group_plan(
            member_id=identity.member_id,
            member_address="node.local:9770",
            device_uuids=[f"GPU-{identity.member_id[:8]}"],
            topology_sha256=topology_digit * 64,
            manifest_sha256="2" * 64,
            runtime_digest=runtime_digit * 64,
            service_id=service_id,
            release=release,
            port_base=18000,
        )
        store.register_placement_group(
            plan.document(),
            source=release["source"],
            model=model,
            runtime=f"{model}/fixture-engine/fixture-target@{runtime_digit}",
            target="fixture-target",
            capacity={
                "max_connections": 16,
                "max_active_requests": 1,
                "max_context_tokens": 4096,
                "interconnect": {
                    "kind": "any",
                    "rdma_required": False,
                    "minimum_speed_mbps": 0,
                    "minimum_mtu": 0,
                },
            },
            engine_credential_sha256="6" * 64,
        )
        return plan, release

    def test_setup_separates_site_and_member_keys(self) -> None:
        identity = state.setup_site("Home", "127.0.0.1")
        self.assertEqual(identity.role, "main")
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

    def test_read_identity_migrates_verified_schema_three_bytes(self) -> None:
        expected = state.setup_site("Home", "127.0.0.1")
        value = json.loads(state.identity_path().read_text(encoding="utf-8"))
        value["schema_version"] = 3
        state.identity_path().write_text(
            json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )

        self.assertEqual(state.read_identity(), expected)
        migrated = json.loads(state.identity_path().read_text(encoding="utf-8"))
        self.assertEqual(migrated["schema_version"], 4)

    def test_schema_three_migration_verifies_keys_before_mutation(self) -> None:
        state.setup_site("Home", "127.0.0.1")
        value = json.loads(state.identity_path().read_text(encoding="utf-8"))
        value["schema_version"] = 3
        value["member_public_key_sha256"] = "0" * 64
        state.identity_path().write_text(
            json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )

        with self.assertRaisesRegex(state.SiteError, "cryptographic keys"):
            state.read_identity()
        preserved = json.loads(state.identity_path().read_text(encoding="utf-8"))
        self.assertEqual(preserved["schema_version"], 3)

    def test_cleanup_exposure_reader_survives_invalid_site_identity(self) -> None:
        identity = state.setup_site("Home", "127.0.0.1")
        with state.SiteStore(identity=identity) as store:
            expected = store.set_exposure(
                provider="tailscale-funnel",
                public_url="https://home.example.ts.net",
                state="enabled",
                inference_target="http://127.0.0.1:8000",
                configuration_sha256="a" * 64,
            )
            state.identity_path().write_text(
                '{"schema_version":1}\n', encoding="utf-8"
            )
            # Keep the writer open so the row remains in WAL during cleanup.
            self.assertEqual(state.read_exposure_for_cleanup(), expected)

    def test_cleanup_exposure_reader_accepts_an_empty_owned_table(self) -> None:
        state.setup_site("Home", "127.0.0.1")
        self.assertIsNone(state.read_exposure_for_cleanup())

    def test_cleanup_readers_reject_a_dangling_database_symlink(self) -> None:
        database = state.database_path()
        database.parent.mkdir(parents=True, mode=0o700)
        database.symlink_to(database.parent / "missing.sqlite3")
        with self.assertRaisesRegex(state.SiteError, "cannot be a symlink"):
            state.read_exposure_for_cleanup()
        with self.assertRaisesRegex(state.SiteError, "cannot be a symlink"):
            state.has_active_placement_groups_for_cleanup()

    def test_cleanup_detects_active_placement_groups_without_identity(self) -> None:
        identity = state.setup_site("Home", "127.0.0.1")
        with state.SiteStore(identity=identity) as store:
            plan, _release = self.register_group(store, identity)
            placement_group_id = plan.placement_group_id
            state.identity_path().unlink()
            self.assertTrue(state.has_active_placement_groups_for_cleanup())
            for incomplete_state in ("failed", "removing"):
                store.connection.execute(
                    "UPDATE placement_groups SET desired_state='removed', state=? "
                    "WHERE placement_group_id=?",
                    (incomplete_state, placement_group_id),
                )
                self.assertTrue(state.has_active_placement_groups_for_cleanup())
            store.connection.execute(
                "UPDATE placement_groups SET state='removed' "
                "WHERE placement_group_id=?",
                (placement_group_id,),
            )
            self.assertFalse(state.has_active_placement_groups_for_cleanup())

    def test_schema_four_contains_only_placement_group_and_placement_state(self) -> None:
        identity = state.setup_site("Home", "127.0.0.1")
        with state.SiteStore(identity=identity) as store:
            group_columns = {
                row["name"]
                for row in store.connection.execute("PRAGMA table_info(placement_groups)")
            }
            placement_columns = {
                row["name"]
                for row in store.connection.execute("PRAGMA table_info(placements)")
            }
            request_summary_columns = {
                row["name"]
                for row in store.connection.execute(
                    "PRAGMA table_info(request_summaries)"
                )
            }
            self.assertIn("endpoint_json", group_columns)
            self.assertIn("plan_json", group_columns)
            self.assertNotIn("placement_id", group_columns)
            self.assertNotIn("strategy", group_columns)
            self.assertIn("placement_group_id", placement_columns)
            self.assertIn("node_id", placement_columns)
            self.assertIn("task_id", placement_columns)
            self.assertIn("placement_group_id", request_summary_columns)
            self.assertIn("placement_id", request_summary_columns)
            self.assertIn("node_id", request_summary_columns)
            self.assertNotIn("member_id", request_summary_columns)
            self.assertEqual(
                store.connection.execute(
                    "SELECT value FROM site_meta WHERE key='schema_version'"
                ).fetchone()[0],
                "4",
            )

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

    def test_placement_group_endpoint_schema_is_closed(self) -> None:
        identity = state.setup_site()
        with state.SiteStore(identity=identity) as store:
            plan, release = self.register_group(store, identity)
            placement = plan.placements[0]
            store.set_placement_group(
                plan.document(),
                source=release["source"],
                engine_credential_sha256="6" * 64,
                desired_state="running",
                state="running",
                placements=[
                    {
                        "placement_id": placement.placement_id,
                        "node_id": placement.node_id,
                        "task_id": placement.task_id,
                        "state": "running",
                        "operation_id": "a" * 32,
                        "error": None,
                    }
                ],
                action="placement_group.start",
            )
            endpoint = {
                "placement_id": placement.placement_id,
                "node_id": placement.node_id,
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
            running = store.set_placement_group_endpoint(
                plan.placement_group_id,
                endpoint,
                state="running",
            )
            self.assertEqual(running["endpoint"], endpoint)

            unknown = {**endpoint, "internal_note": "not-schema"}
            with self.assertRaises(state.SiteError):
                store.set_placement_group_endpoint(
                    plan.placement_group_id,
                    unknown,
                    state="running",
                )
            wrong = {**endpoint, "placement_id": "f" * 32}
            with self.assertRaises(state.SiteError):
                store.set_placement_group_endpoint(
                    plan.placement_group_id,
                    wrong,
                    state="running",
                )
            with self.assertRaises(state.SiteError):
                store.set_placement_group_endpoint(
                    plan.placement_group_id,
                    None,
                    state="running",
                )


    def test_replica_placement_groups_share_one_model_service(self) -> None:
        identity = state.setup_site()
        with state.SiteStore(identity=identity) as store:
            first, _first_release = self.register_group(
                store,
                identity,
                runtime_digit="3",
                topology_digit="1",
            )
            before = store.verify_audit()["events"]
            second, _second_release = self.register_group(
                store,
                identity,
                runtime_digit="4",
                topology_digit="5",
            )
            placement_groups = store.placement_groups()
            self.assertEqual(
                {row["placement_group_id"] for row in placement_groups},
                {first.placement_group_id, second.placement_group_id},
            )
            self.assertEqual(
                {row["service_id"] for row in placement_groups},
                {first.service_id},
            )
            self.assertEqual(len(store.placements()), 2)
            self.assertEqual(store.verify_audit()["events"], before + 2)


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
                ["child.resume", "child.drain"],
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

    def test_placement_group_transition_is_placement_bound_and_audited(self) -> None:
        identity = state.setup_site()
        with state.SiteStore(identity=identity) as store:
            plan, sealed_release = self.register_group(
                store,
                identity,
                model="example-model",
            )
            placement_states = [
                {
                    "placement_id": item.placement_id,
                    "node_id": item.node_id,
                    "task_id": item.task_id,
                    "state": "staging",
                    "operation_id": None,
                    "error": None,
                }
                for item in plan.placements
            ]
            before = store.verify_audit()["events"]
            stored = store.set_placement_group(
                plan.document(),
                source=sealed_release["source"],
                engine_credential_sha256="6" * 64,
                desired_state="running",
                state="staging",
                placements=placement_states,
                action="placement_group.stage",
            )
            self.assertEqual(stored["placement_group_id"], plan.placement_group_id)
            self.assertEqual(stored["placements"][0]["state"], "staging")
            self.assertEqual(stored["plan"], plan.document())
            self.assertEqual(store.verify_audit()["events"], before + 1)


    def test_device_reservation_ignores_unrelated_invalid_node_inventory(self) -> None:
        identity = state.setup_site()
        unrelated = "e" * 32
        with state.SiteStore(identity=identity) as store:
            set_member_facts(
                store,
                identity.member_id,
                routing_facts(identity.member_id),
            )
            insert_member(store, unrelated)
            store.connection.execute(
                "UPDATE members SET facts_json='{}' WHERE member_id=?",
                (unrelated,),
            )
            plan, _release = self.register_group(store, identity)
            placement = plan.placements[0]
            allocations = store.reserve_placement_devices(
                plan.placement_group_id,
                [{
                    "placement_id": placement.placement_id,
                    "node_id": placement.node_id,
                    "device_uuids": list(placement.device_uuids),
                }],
            )
        self.assertEqual(len(allocations), 1)
        self.assertEqual(allocations[0]["node_id"], identity.member_id)

    def test_membership_invite_is_one_use_and_site_key_never_moves(self) -> None:
        coordinator_home = pathlib.Path(self.temporary.name) / "main"
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
                "contract": "letsinfer-child-enrollment-v1",
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
            self.assertEqual(joined.role, "child")
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
            "contract": "letsinfer-child-enrollment-v1",
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
