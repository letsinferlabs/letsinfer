# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import os
import multiprocessing
import pathlib
import ssl
import tempfile
import time
import unittest
from unittest import mock

from core.site import control, controller, state, telemetry


def facts(member_id: str) -> dict:
    return {
        "schema_version": 1,
        "member_id": member_id,
        "observed_at_unix": int(time.time()),
        "platform": "linux/arm64",
        "accelerator": {
            "vendor": "nvidia",
            "architecture": "sm_121",
            "count": 1,
            "partitioning": "full-device",
            "minimum_memory_gib": 128,
            "devices": ["GPU-fixture"],
        },
        "memory": {"topology": "unified", "total_gib": 128, "available_gib": 100},
        "storage": {"total_gib": 1000, "available_gib": 700, "cache_available_gib": 600},
        "network": {
            "interfaces": [{
                "name": "enp1s0", "addresses": ["192.0.2.10"], "mtu": 9000,
                "speed_mbps": 200000, "rdma": True,
            }],
            "links": [],
        },
        "software": {
            "driver": "fixture", "container_runtime": "fixture",
            "letsinfer_version": "0.11.0-rc.2",
        },
        "health": {
            "state": "healthy", "memory_pressure": False,
            "protection_trip": False, "max_temperature_c": 55,
        },
    }


def telemetry_sample(member_id: str) -> dict:
    system = {
        "cpu_core_percent": [10], "cpu_percent": 10, "gpu_percent": 20,
        "memory_percent": 30, "disk_percent": 40, "gpu_memory_percent": 50,
        "gpu_engine_percent": [20, 0, 0, 0, 0, 0],
        "system_temp_deci_c": 400, "gpu_temp_deci_c": 500,
        "nvme_temp_deci_c": -1, "power_deci_w": 500, "load1_centi": 100,
        "memory_used_mib": 1, "memory_total_mib": 2,
        "disk_used_mib": 3, "disk_total_mib": 4,
        "network_rx_kib_s": 5, "network_tx_kib_s": 6,
        "disk_read_kib_s": 7, "disk_write_kib_s": 8,
        "cpu_clock_mhz": 1000, "gpu_clock_mhz": 900,
        "vram_clock_mhz": -1, "system_ram_clock_mhz": -1,
    }
    inference = {
        "gateway_available": True, "active_requests": 1, "queued_requests": 0,
        **{field: 1 for field in telemetry.COUNTER_FIELDS},
    }
    return {
        "schema_version": telemetry.TELEMETRY_SCHEMA_VERSION,
        "member_id": member_id, "sequence": 1,
        "unix_ms": int(time.time() * 1000), "monotonic_ms": 1,
        "system": system, "inference": inference,
        "workload": {"type": 1, "id": 1, "gpu_available": True, "throttled": False},
    }


def serve_requests(
    environment: dict[str, str],
    count: int,
    ready: multiprocessing.Queue,
) -> None:
    os.environ.update(environment)
    try:
        identity = state.read_identity()
        server = control.SiteControlServer(
            ("127.0.0.1", 0),
            control.SiteControlState(identity, facts_provider=lambda: facts(identity.member_id)),
        )
        ready.put(("ready", server.server_address[1]))
        for _ in range(count):
            server.handle_request()
        server.server_close()
    except BaseException as error:
        ready.put(("error", repr(error)))
        raise


class SiteControlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.coordinator_environment = {
            "LETSINFER_HOME": str(self.root / "main"),
        }
        self.member_environment = {
            "LETSINFER_HOME": str(self.root / "child"),
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_listener_allows_immediate_managed_restart(self) -> None:
        self.assertTrue(control.SiteControlServer.allow_reuse_address)
        self.assertTrue(controller.ControllerServer.allow_reuse_address)

    def test_enrollment_contract_provisions_only_member_credentials(self) -> None:
        with mock.patch.dict(os.environ, self.coordinator_environment):
            coordinator = state.setup_site("Home", "coordinator.local")
            with state.SiteStore(identity=coordinator) as store:
                invite = store.create_invite("lan")
            coordinator_control = control.SiteControlState(
                coordinator, facts_provider=lambda: facts(coordinator.member_id)
            )
            challenge = coordinator_control.challenge(invite["invite_id"])
            discovery = coordinator_control.discovery()
            self.assertEqual(
                set(discovery),
                {
                    "protocol", "display_name", "site_id", "member_id", "role",
                    "claimed_state", "public_key_sha256", "certificate_sha256",
                    "direct_connectx", "adoption_nonce", "adoption_expires_at_unix",
                },
            )
        with mock.patch.dict(os.environ, self.member_environment):
            candidate = state.prepare_member_identity()
            transcript = control.enrollment_transcript(
                challenge,
                candidate,
                member_name="Member B",
                member_address="member-b.local",
            )
            proof = state.member_proof(transcript)
        with mock.patch.dict(os.environ, self.coordinator_environment):
            response = coordinator_control.enroll({
                "protocol": control.PROTOCOL,
                "invite_id": invite["invite_id"],
                "code": invite["code"],
                "member_id": candidate["member_id"],
                "member_name": "Member B",
                "member_address": "member-b.local",
                "member_public_key": candidate["member_public_key"],
                "installation_id": candidate["installation_id"],
                "installation_created_at_unix": candidate["created_at_unix"],
                "proof_signature": proof,
            })
            self.assertEqual(response["document"]["state"], "pending")
            self.assertRegex(response["comparison_code"], r"^[0-9]{6}$")
            with state.SiteStore(identity=coordinator) as store:
                pending = next(
                    row for row in store.members() if row["member_id"] == candidate["member_id"]
                )
                self.assertEqual(pending["state"], "pending")
                wrong_code = (
                    "000000" if response["comparison_code"] != "000000" else "999999"
                )
                with self.assertRaisesRegex(state.SiteError, "incorrect"):
                    store.approve_member(candidate["member_id"], wrong_code)
                approved = store.approve_member(
                    candidate["member_id"], response["comparison_code"]
                )
                self.assertEqual(approved["state"], "active")
            self.assertEqual(
                coordinator_control.membership(candidate["member_id"]),
                {
                    "protocol": control.PROTOCOL,
                    "site_id": coordinator.site_id,
                    "member_id": candidate["member_id"],
                    "state": "active",
                    "approval_expires_at_unix": None,
                },
            )
        with mock.patch.dict(os.environ, self.member_environment):
            joined = state.install_member_identity(
                response["document"], response["signature"], response["site_public_key"],
                response["site_ca_certificate"], response["member_certificate"],
            )
            self.assertEqual(joined.role, "child")
            self.assertFalse(state.site_key_path().exists())
            self.assertTrue(state.member_key_path().exists())
            self.assertTrue(state.member_certificate_path().exists())
            member_control = control.SiteControlState(
                joined, facts_provider=lambda: facts(joined.member_id)
            )
            signed = member_control.facts()
        with mock.patch.dict(os.environ, self.coordinator_environment):
            with state.SiteStore(identity=coordinator) as store:
                updated = store.update_member_facts(
                    joined.member_id, signed["facts"], signed["signature"]
                )
                self.assertEqual(updated["member_id"], joined.member_id)

    def test_challenge_rejects_used_invite(self) -> None:
        with mock.patch.dict(os.environ, self.coordinator_environment):
            coordinator = state.setup_site("Home", "coordinator.local")
            with state.SiteStore(identity=coordinator) as store:
                invite = store.create_invite("lan")
                store.connection.execute(
                    "UPDATE membership_invites SET consumed_at_unix=? WHERE invite_id=?",
                    (int(time.time()), invite["invite_id"]),
                )
            coordinator_control = control.SiteControlState(
                coordinator, facts_provider=lambda: facts(coordinator.member_id)
            )
            with self.assertRaisesRegex(control.ControlError, "already consumed"):
                coordinator_control.challenge(invite["invite_id"])

    def test_enrollment_rate_limiter_is_bounded_and_recovers(self) -> None:
        current = [100.0]
        limiter = control.PeerRateLimiter(
            limit=2, window_seconds=10, max_peers=2, clock=lambda: current[0]
        )
        self.assertTrue(limiter.allow("192.0.2.1"))
        self.assertTrue(limiter.allow("192.0.2.1"))
        self.assertFalse(limiter.allow("192.0.2.1"))
        self.assertTrue(limiter.allow("192.0.2.2"))
        self.assertTrue(limiter.allow("192.0.2.3"))
        self.assertLessEqual(len(limiter.requests), 2)
        current[0] += 11
        self.assertTrue(limiter.allow("192.0.2.1"))

    def test_coordinator_accepts_only_active_member_signed_telemetry(self) -> None:
        with mock.patch.dict(os.environ, self.coordinator_environment):
            coordinator = state.setup_site("Home", "coordinator.local")
            aggregate = telemetry.TelemetryAggregator()
            coordinator_control = control.SiteControlState(
                coordinator,
                facts_provider=lambda: facts(coordinator.member_id),
                telemetry=aggregate,
            )
            document = telemetry.signed_sample(telemetry_sample(coordinator.member_id))
            self.assertEqual(
                coordinator_control.accept_telemetry(
                    document, requester_member_id=coordinator.member_id
                ),
                {"protocol": telemetry.PROTOCOL, "accepted": True},
            )
            self.assertEqual(
                aggregate.snapshot()["aggregate"]["requests_received"], 1
            )
            changed = dict(document)
            changed["sample"] = dict(document["sample"], sequence=2)
            with self.assertRaisesRegex(control.ControlError, "signature"):
                coordinator_control.accept_telemetry(
                    changed, requester_member_id=coordinator.member_id
                )
            with self.assertRaisesRegex(control.ControlError, "identity"):
                coordinator_control.accept_telemetry(
                    document, requester_member_id="f" * 32
                )

    def test_coordinator_accepts_own_in_process_telemetry_without_signature(self) -> None:
        with mock.patch.dict(os.environ, self.coordinator_environment):
            coordinator = state.setup_site("Home", "coordinator.local")
            aggregate = telemetry.TelemetryAggregator()
            coordinator_control = control.SiteControlState(
                coordinator,
                facts_provider=lambda: facts(coordinator.member_id),
                telemetry=aggregate,
            )
            sample = telemetry_sample(coordinator.member_id)
            self.assertEqual(
                coordinator_control.accept_local_telemetry(
                    sample, requester_member_id=coordinator.member_id
                ),
                {"protocol": telemetry.PROTOCOL, "accepted": True},
            )
            self.assertEqual(
                aggregate.snapshot()["aggregate"]["requests_received"], 1
            )
            with self.assertRaisesRegex(control.ControlError, "requester identity"):
                coordinator_control.accept_local_telemetry(
                    sample, requester_member_id="f" * 32
                )
            with self.assertRaisesRegex(control.ControlError, "sample identity"):
                coordinator_control.accept_local_telemetry(
                    {**sample, "member_id": "e" * 32},
                    requester_member_id=coordinator.member_id,
                )

    def test_connectx_enrollment_is_active_only_after_direct_route_proof(self) -> None:
        with mock.patch.dict(os.environ, self.member_environment):
            candidate = state.prepare_member_identity()
        with mock.patch.dict(os.environ, self.coordinator_environment):
            coordinator = state.setup_site("Home", "coordinator.local")
            with state.SiteStore(identity=coordinator) as store:
                invite = store.create_invite(
                    "connectx",
                    candidate_public_key_sha256=candidate["member_public_key_sha256"],
                    direct_interface="enp1s0",
                )
            coordinator_control = control.SiteControlState(
                coordinator, facts_provider=lambda: facts(coordinator.member_id)
            )
            with mock.patch.object(control, "verify_direct_connectx_peer") as verify_route:
                challenge = coordinator_control.challenge(
                    invite["invite_id"], peer_address="192.0.2.20"
                )
        with mock.patch.dict(os.environ, self.member_environment):
            transcript = control.enrollment_transcript(
                challenge,
                candidate,
                member_name="Member B",
                member_address="192.0.2.20",
            )
            proof = state.member_proof(transcript)
        with mock.patch.dict(os.environ, self.coordinator_environment):
            with mock.patch.object(control, "verify_direct_connectx_peer") as verify_route:
                response = coordinator_control.enroll(
                    {
                        "protocol": control.PROTOCOL,
                        "invite_id": invite["invite_id"],
                        "code": None,
                        "member_id": candidate["member_id"],
                        "member_name": "Member B",
                        "member_address": "192.0.2.20",
                        "member_public_key": candidate["member_public_key"],
                        "installation_id": candidate["installation_id"],
                        "installation_created_at_unix": candidate["created_at_unix"],
                        "proof_signature": proof,
                    },
                    peer_address="192.0.2.20",
                )
                verify_route.assert_called_once_with("enp1s0", "192.0.2.20")
            self.assertEqual(response["document"]["state"], "active")
            self.assertIsNone(response["comparison_code"])

    def test_fresh_adoption_requires_direct_validation_and_runs_completion(self) -> None:
        with mock.patch.dict(os.environ, self.coordinator_environment):
            coordinator = state.setup_site("Fresh", "192.0.2.20")
            completed: list[dict] = []
            result = {
                "protocol": "letsinfer-node-adoption-v1",
                "state": "committed",
                "source_site_id": coordinator.site_id,
                "destination_site_id": "a" * 32,
                "member_id": coordinator.member_id,
                "move_id": "b" * 32,
            }
            coordinator_control = control.SiteControlState(
                coordinator,
                facts_provider=lambda: facts(coordinator.member_id),
                adoption_provider=lambda document: result,
                adoption_completed_provider=lambda value: completed.append(dict(value)),
            )
            with (
                mock.patch.object(
                    control,
                    "select_direct_connectx_interface",
                    return_value={"interface": "enp1s0"},
                ),
                mock.patch(
                    "core.site.adoption.validate_adoption_request",
                    return_value={"destination_site_id": "a" * 32},
                ) as validate,
            ):
                response = coordinator_control.adopt(
                    {"synthetic": True}, peer_address="192.0.2.10"
                )
                coordinator_control.adoption_completed(response)
            self.assertEqual(response, result)
            self.assertEqual(completed, [result])
            self.assertEqual(validate.call_args.kwargs["direct_interface"], "enp1s0")

    @unittest.skipUnless(getattr(ssl, "HAS_TLSv1_3", False), "TLS 1.3 unavailable")
    def test_tls_enrollment_and_coordinator_only_fact_fetch_round_trip(self) -> None:
        with mock.patch.dict(os.environ, self.coordinator_environment):
            coordinator = state.setup_site("Home", "127.0.0.1")
            with state.SiteStore(identity=coordinator) as store:
                invite = store.create_invite("lan")
            coordinator_certificate = control.SiteControlState(
                coordinator, facts_provider=lambda: facts(coordinator.member_id)
            ).certificate_sha256
        ready: multiprocessing.Queue = multiprocessing.Queue()
        process = multiprocessing.Process(
            target=serve_requests,
            args=(self.coordinator_environment, 2, ready),
        )
        process.start()
        status, value = ready.get(timeout=10)
        self.assertEqual(status, "ready", value)
        with mock.patch.dict(os.environ, self.member_environment):
            enrollment = control.join_site(
                f"https://127.0.0.1:{value}",
                invite_id=invite["invite_id"],
                code=invite["code"],
                coordinator_certificate_sha256=coordinator_certificate,
                member_name="Member B",
                member_address="127.0.0.1",
            )
            member = enrollment.identity
            self.assertEqual(enrollment.state, "pending")
        process.join(timeout=10)
        self.assertEqual(process.exitcode, 0)

        with mock.patch.dict(os.environ, self.coordinator_environment):
            with state.SiteStore(identity=coordinator) as store:
                row = next(item for item in store.members() if item["member_id"] == member.member_id)
        ready = multiprocessing.Queue()
        process = multiprocessing.Process(
            target=serve_requests,
            args=(self.member_environment, 1, ready),
        )
        process.start()
        status, value = ready.get(timeout=10)
        self.assertEqual(status, "ready", value)
        with mock.patch.dict(os.environ, self.coordinator_environment):
            signed = control.fetch_member_facts(
                f"https://127.0.0.1:{value}",
                expected_member_id=member.member_id,
                expected_certificate_sha256=row["certificate_sha256"],
            )
            with state.SiteStore(identity=coordinator) as store:
                store.update_member_facts(
                    member.member_id, signed["facts"], signed["signature"]
                )
        process.join(timeout=10)
        self.assertEqual(process.exitcode, 0)


if __name__ == "__main__":
    unittest.main()
