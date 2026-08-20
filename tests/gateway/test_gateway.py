# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import dataclasses
import json
import os
import pathlib
import tempfile
import threading
import time
import unittest
from unittest import mock

from core.gateway import server
from core.site import state
from tests.gateway.helpers import (
    insert_member,
    routing_facts,
    routing_link,
    set_member_facts,
)


class GatewayPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.temporary.name)
        self.environment = mock.patch.dict(
            os.environ,
            {
                "LETSINFER_CONFIG_HOME": str(root / "config"),
                "LETSINFER_DATA_HOME": str(root / "data"),
            },
            clear=False,
        )
        self.environment.start()
        self.identity = state.setup_site("Home", "127.0.0.1")
        with state.SiteStore(identity=self.identity) as store:
            set_member_facts(
                store,
                self.identity.member_id,
                routing_facts(self.identity.member_id, temperature_c=35.0),
            )
            self.key, self.token = store.create_key(
                "client", models=["fixture-model"], concurrency_limit=2
            )
            store.set_alias("fixture", "fixture-model")
            store.set_placement(self.placement())

    def tearDown(self) -> None:
        self.environment.stop()
        self.temporary.cleanup()

    def placement(self, *, temperature: float = 45.0) -> dict:
        return {
            "placement_id": "a" * 32,
            "model": "fixture-model",
            "runtime": "fixture-model/fixture-engine/fixture-target",
            "target": "fixture-target",
            "strategy": "single",
            "state": "running",
            "topology_sha256": "b" * 64,
            "members": [self.identity.member_id],
            "endpoints": [{
                "member_id": self.identity.member_id,
                "url": "http://127.0.0.1:18000",
                "credential_file": str(state.config_root() / "backend-api-key"),
                "ca_file": None,
                "token_count_path": "/v1/token-count",
                "token_count_protocol": "letsinfer-token-count-v1",
                "max_active_requests": 1,
                "max_context_tokens": 557056,
                "healthy": True,
                "memory_pressure": False,
                "temperature_c": temperature,
                "prefix_keys": ["shared"],
            }],
            "capacity": {"max_active_requests": 1, "max_context_tokens": 557056},
        }

    def test_metrics_publisher_fails_startup_on_unsafe_destination(self) -> None:
        root = pathlib.Path(self.temporary.name)
        real = root / "real-metrics"
        real.mkdir()
        link = root / "metrics-link"
        link.symlink_to(real, target_is_directory=True)
        with self.assertRaisesRegex(server.GatewayError, "symlink"):
            server.MetricsPublisher(link / "gateway.state")

    def test_backend_response_timeout_supports_long_context_prefill(self) -> None:
        backend = server.Backend(
            placement_id="a" * 32,
            member_id="b" * 32,
            model="fixture-model",
            url="http://127.0.0.1:18000",
            credential_file="/api-key",
            ca_file=None,
            token_count_path="/v1/token-count",
            token_count_protocol="letsinfer-token-count-v1",
            max_active_requests=1,
            max_context_tokens=557_056,
            healthy=True,
            memory_pressure=False,
            temperature_c=40.0,
            prefix_keys=set(),
        )
        handler = object.__new__(server.GatewayHandler)
        with mock.patch.object(
            server.http.client, "HTTPConnection"
        ) as connection:
            actual, host = handler._connect(backend)

        self.assertIs(actual, connection.return_value)
        self.assertEqual(host, "127.0.0.1:18000")
        connection.assert_called_once_with(
            "127.0.0.1",
            18000,
            timeout=server.BACKEND_RESPONSE_TIMEOUT_SECONDS,
        )
        self.assertGreaterEqual(server.BACKEND_RESPONSE_TIMEOUT_SECONDS, 3600)

    def test_sglang_token_count_is_translated_and_normalized(self) -> None:
        backend = server.Backend(
            placement_id="a" * 32,
            member_id="b" * 32,
            model="fixture-model",
            url="http://127.0.0.1:18000",
            credential_file="/api-key",
            ca_file=None,
            token_count_path="/v1/messages/count_tokens",
            token_count_protocol="sglang-anthropic-count-tokens-v1",
            max_active_requests=1,
            max_context_tokens=1_000_000,
            healthy=True,
            memory_pressure=False,
            temperature_c=40.0,
            prefix_keys=set(),
            engine="sglang",
        )
        response = mock.MagicMock(status=200)
        response.read.return_value = b'{"input_tokens":17}'
        connection = mock.MagicMock()
        connection.getresponse.return_value = response
        handler = object.__new__(server.GatewayHandler)
        request = json.dumps(
            {
                "model": "fixture-model",
                "messages": [{"role": "user", "content": "hello"}],
                "max_tokens": 1,
            }
        ).encode()
        with (
            mock.patch.object(
                handler,
                "_connect",
                return_value=(connection, "127.0.0.1:18000"),
            ),
            mock.patch.object(server, "_read_backend_token", return_value="secret"),
        ):
            self.assertEqual(handler._count_tokens(backend, request), 17)
        sent = connection.request.call_args.kwargs["body"]
        self.assertEqual(
            json.loads(sent)["messages"],
            [{"role": "user", "content": "hello"}],
        )

    def test_sglang_reasoning_history_uses_exact_openai_tokenize_fallback(self) -> None:
        backend = server.Backend(
            placement_id="a" * 32,
            member_id="b" * 32,
            model="fixture-model",
            url="http://127.0.0.1:18000",
            credential_file="/api-key",
            ca_file=None,
            token_count_path="/v1/messages/count_tokens",
            token_count_protocol="sglang-anthropic-count-tokens-v1",
            max_active_requests=1,
            max_context_tokens=1_000_000,
            healthy=True,
            memory_pressure=False,
            temperature_c=40.0,
            prefix_keys=set(),
        )
        response = mock.MagicMock(status=200)
        response.read.side_effect = [
            b'{"tokens":[11,12,13],"count":3,',
            b'"max_model_len":1000000}',
            b"",
        ]
        connection = mock.MagicMock()
        connection.getresponse.return_value = response
        handler = object.__new__(server.GatewayHandler)
        request = json.dumps(
            {
                "model": "fixture-model",
                "messages": [
                    {"role": "user", "content": "hello"},
                    {
                        "role": "assistant",
                        "content": "hi",
                        "reasoning_content": "thinking",
                    },
                    {"role": "user", "content": "again"},
                ],
                "max_tokens": 1,
            }
        ).encode()
        with (
            mock.patch.object(
                handler,
                "_connect",
                return_value=(connection, "127.0.0.1:18000"),
            ),
            mock.patch.object(server, "_read_backend_token", return_value="secret"),
        ):
            self.assertEqual(handler._count_tokens(backend, request), 3)
        call = connection.request.call_args
        self.assertEqual(call.args[1], "/v1/tokenize")
        self.assertEqual(
            json.loads(call.kwargs["body"])["messages"][1]["reasoning_content"],
            "thinking",
        )

    def test_metrics_health_fails_closed_when_publication_is_stale(self) -> None:
        path = pathlib.Path(self.temporary.name) / "gateway.state"
        publisher = server.MetricsPublisher(path)
        try:
            self.assertTrue(publisher.healthy())
            with publisher.lock:
                publisher.last_success_monotonic = (
                    time.monotonic() - publisher.MAX_STALE_SECONDS - 1
                )
                publisher.last_error = "GatewayError"
            self.assertFalse(publisher.healthy())
        finally:
            publisher.close()

    @staticmethod
    def add_member(store: state.SiteStore, member_id: str) -> None:
        insert_member(store, member_id)

    def test_api_secret_authentication_and_alias_resolution(self) -> None:
        policy = server.PolicySnapshot(self.identity)
        policy.reload(force=True)
        authenticated = policy.authenticate(self.token)
        self.assertIsNotNone(authenticated)
        self.assertNotIn("secret_hash", authenticated)
        self.assertEqual(policy.resolve_model("fixture"), "fixture-model")
        self.assertIsNone(policy.authenticate(self.token + "x"))

    def test_corrupt_persisted_capacity_cannot_coerce_into_gateway_limits(self) -> None:
        with state.SiteStore(identity=self.identity) as store:
            placement = self.placement()
            placement["endpoints"][0]["max_active_requests"] = True
            store.connection.execute(
                "UPDATE placements SET endpoints_json=? WHERE placement_id=?",
                (
                    json.dumps(
                        placement["endpoints"], sort_keys=True, separators=(",", ":")
                    ),
                    placement["placement_id"],
                ),
            )
        with self.assertRaisesRegex(server.GatewayError, "capacity is invalid"):
            server.PolicySnapshot(self.identity).reload(force=True)

    def test_revoked_and_expired_api_keys_are_rejected_immediately(self) -> None:
        policy = server.PolicySnapshot(self.identity)
        policy.reload(force=True)
        self.assertIsNotNone(policy.authenticate(self.token))

        with state.SiteStore(identity=self.identity) as store:
            store.revoke_key(self.key["key_id"])
        self.assertIsNone(policy.authenticate(self.token))

        with state.SiteStore(identity=self.identity) as store:
            _expired, expired_token = store.create_key(
                "expired-client",
                models=["fixture-model"],
                expires_at_unix=int(time.time()) - 1,
            )
        self.assertIsNone(policy.authenticate(expired_token))

    def test_capacity_survives_policy_reload_and_release(self) -> None:
        policy = server.PolicySnapshot(self.identity)
        policy.reload(force=True)
        selected, _ = policy.acquire_backend(
            "fixture-model", prefix_key="shared", timeout=0.1
        )
        with state.SiteStore(identity=self.identity) as store:
            store.set_placement(self.placement(temperature=50.0))
        policy.reload(force=True)
        policy.release_backend(selected)
        replacement, _ = policy.acquire_backend(
            "fixture-model", prefix_key="shared", timeout=0.1
        )
        self.assertEqual(replacement.temperature_c, 50.0)
        policy.release_backend(replacement)

    def test_member_drain_blocks_new_work_without_losing_inflight_capacity(self) -> None:
        policy = server.PolicySnapshot(self.identity)
        policy.reload(force=True)
        inflight, _ = policy.acquire_backend(
            "fixture-model", prefix_key=None, timeout=0.1
        )
        with state.SiteStore(identity=self.identity) as store:
            store.set_member_draining(self.identity.member_id, True)
        policy.reload(force=True)
        self.assertEqual(policy.backends, [])

        with state.SiteStore(identity=self.identity) as store:
            store.set_member_draining(self.identity.member_id, False)
        policy.reload(force=True)
        self.assertEqual(policy.active[inflight.key], 1)
        with self.assertRaisesRegex(server.GatewayError, "queue timeout"):
            policy.acquire_backend("fixture-model", prefix_key=None, timeout=0.01)
        policy.release_backend(inflight)
        resumed, _ = policy.acquire_backend(
            "fixture-model", prefix_key=None, timeout=0.1
        )
        policy.release_backend(resumed)

    def test_distributed_placement_fails_closed_when_any_member_is_draining(self) -> None:
        other = "e" * 32
        with state.SiteStore(identity=self.identity) as store:
            self.add_member(store, other)
            local_certificate = next(
                row["certificate_sha256"]
                for row in store.members()
                if row["member_id"] == self.identity.member_id
            )
            other_certificate = next(
                row["certificate_sha256"]
                for row in store.members()
                if row["member_id"] == other
            )
            set_member_facts(
                store,
                self.identity.member_id,
                routing_facts(
                    self.identity.member_id,
                    temperature_c=35.0,
                    address="192.0.2.10",
                    links=[routing_link(other, peer_certificate_sha256=other_certificate)],
                ),
            )
            set_member_facts(
                store,
                other,
                routing_facts(
                    other,
                    address="192.0.2.11",
                    links=[
                        routing_link(
                            self.identity.member_id,
                            peer_certificate_sha256=local_certificate,
                        )
                    ],
                ),
            )
            placement = self.placement()
            placement["strategy"] = "distributed"
            placement["members"] = [self.identity.member_id, other]
            placement["capacity"]["interconnect"] = {
                "kind": "connectx",
                "rdma_required": True,
                "minimum_speed_mbps": 100_000,
                "minimum_mtu": 9000,
            }
            store.set_placement(placement)
        policy = server.PolicySnapshot(self.identity)
        policy.reload(force=True)
        self.assertEqual(len(policy.backends), 1)

        with state.SiteStore(identity=self.identity) as store:
            store.set_member_draining(other, True)
        policy.reload(force=True)
        self.assertEqual(policy.backends, [])
        with state.SiteStore(identity=self.identity) as store:
            store.set_member_draining(other, False)
        policy.reload(force=True)
        self.assertEqual(len(policy.backends), 1)

        with state.SiteStore(identity=self.identity) as store:
            stale = int(time.time()) - 60
            set_member_facts(
                store,
                other,
                routing_facts(
                    other,
                    address="192.0.2.11",
                    links=[
                        routing_link(
                            self.identity.member_id,
                            peer_certificate_sha256=local_certificate,
                            observed_at_unix=stale,
                        )
                    ],
                ),
            )
        policy.reload(force=True)
        self.assertEqual(policy.backends, [])

    def test_distributed_placement_rejects_multiple_inference_endpoints(self) -> None:
        other = "e" * 32
        with state.SiteStore(identity=self.identity) as store:
            self.add_member(store, other)
            local_certificate = next(
                row["certificate_sha256"]
                for row in store.members()
                if row["member_id"] == self.identity.member_id
            )
            other_certificate = next(
                row["certificate_sha256"]
                for row in store.members()
                if row["member_id"] == other
            )
            set_member_facts(
                store,
                self.identity.member_id,
                routing_facts(
                    self.identity.member_id,
                    address="192.0.2.10",
                    links=[routing_link(other, peer_certificate_sha256=other_certificate)],
                ),
            )
            set_member_facts(
                store,
                other,
                routing_facts(
                    other,
                    address="192.0.2.11",
                    links=[
                        routing_link(
                            self.identity.member_id,
                            peer_certificate_sha256=local_certificate,
                        )
                    ],
                ),
            )
            placement = self.placement()
            placement["strategy"] = "distributed"
            placement["members"] = [self.identity.member_id, other]
            placement["endpoints"].append(
                {
                    **placement["endpoints"][0],
                    "member_id": other,
                    "url": "http://127.0.0.1:18001",
                }
            )
            placement["capacity"]["interconnect"] = {
                "kind": "connectx",
                "rdma_required": True,
                "minimum_speed_mbps": 100_000,
                "minimum_mtu": 9000,
            }
            with self.assertRaisesRegex(
                state.SiteError, "permits only one inference endpoint"
            ):
                store.set_placement(placement)

    def test_replica_placement_keeps_only_active_member_endpoints(self) -> None:
        other = "e" * 32
        with state.SiteStore(identity=self.identity) as store:
            self.add_member(store, other)
            placement = self.placement()
            placement["strategy"] = "replicated"
            placement["members"] = [self.identity.member_id, other]
            placement["endpoints"].append(
                {
                    **placement["endpoints"][0],
                    "member_id": other,
                    "url": "http://127.0.0.1:18001",
                }
            )
            store.set_placement(placement)
            store.set_member_draining(self.identity.member_id, True)
        policy = server.PolicySnapshot(self.identity)
        policy.reload(force=True)
        self.assertEqual([backend.member_id for backend in policy.backends], [other])

    def test_replica_load_balancing_queues_until_capacity_is_released(self) -> None:
        other = "e" * 32
        with state.SiteStore(identity=self.identity) as store:
            self.add_member(store, other)
            placement = self.placement()
            placement["strategy"] = "replicated"
            placement["members"] = [self.identity.member_id, other]
            placement["endpoints"].append(
                {
                    **placement["endpoints"][0],
                    "member_id": other,
                    "url": "http://127.0.0.1:18001",
                }
            )
            store.set_placement(placement)

        policy = server.PolicySnapshot(self.identity)
        policy.reload(force=True)
        first, _ = policy.acquire_backend(
            "fixture-model", prefix_key=None, timeout=0.1
        )
        second, _ = policy.acquire_backend(
            "fixture-model", prefix_key=None, timeout=0.1
        )
        self.assertNotEqual(first.member_id, second.member_id)

        completed = threading.Event()
        selected: list[server.Backend] = []

        def wait_for_capacity() -> None:
            backend, _ = policy.acquire_backend(
                "fixture-model", prefix_key=None, timeout=1
            )
            selected.append(backend)
            completed.set()

        waiter = threading.Thread(target=wait_for_capacity)
        waiter.start()
        self.assertFalse(completed.wait(0.05))
        policy.release_backend(first)
        self.assertTrue(completed.wait(1))
        waiter.join(timeout=1)
        self.assertEqual(selected[0].key, first.key)
        policy.release_backend(selected[0])
        policy.release_backend(second)

    def test_live_member_health_pressure_temperature_and_staleness_drive_routing(self) -> None:
        policy = server.PolicySnapshot(self.identity)
        with state.SiteStore(identity=self.identity) as store:
            set_member_facts(
                store,
                self.identity.member_id,
                routing_facts(self.identity.member_id, temperature_c=72.5),
            )
        policy.reload(force=True)
        self.assertEqual(policy.backends[0].temperature_c, 72.5)

        with state.SiteStore(identity=self.identity) as store:
            set_member_facts(
                store,
                self.identity.member_id,
                routing_facts(self.identity.member_id, memory_pressure=True),
            )
        policy.reload(force=True)
        self.assertTrue(policy.backends[0].memory_pressure)
        with self.assertRaisesRegex(server.AdmissionError, "memory headroom"):
            policy.acquire_backend("fixture-model", prefix_key=None, timeout=0.01)

        with state.SiteStore(identity=self.identity) as store:
            set_member_facts(
                store,
                self.identity.member_id,
                routing_facts(
                    self.identity.member_id,
                    observed_at_unix=int(time.time()) - 60,
                ),
            )
        policy.reload(force=True)
        self.assertEqual(policy.backends, [])

    def test_memory_pressure_waiter_runs_when_headroom_returns(self) -> None:
        policy = server.PolicySnapshot(self.identity)
        with state.SiteStore(identity=self.identity) as store:
            set_member_facts(
                store,
                self.identity.member_id,
                routing_facts(self.identity.member_id, memory_pressure=True),
            )
        policy.reload(force=True)
        selected: list[server.Backend] = []
        completed = threading.Event()

        def wait_for_headroom() -> None:
            backend, _ = policy.acquire_backend(
                "fixture-model", prefix_key=None, timeout=1
            )
            selected.append(backend)
            completed.set()

        waiter = threading.Thread(target=wait_for_headroom)
        waiter.start()
        self.assertFalse(completed.wait(0.1))
        with state.SiteStore(identity=self.identity) as store:
            set_member_facts(
                store,
                self.identity.member_id,
                routing_facts(self.identity.member_id, memory_pressure=False),
            )
        policy.reload(force=True)
        self.assertTrue(completed.wait(1))
        waiter.join(timeout=1)
        self.assertEqual(len(selected), 1)
        policy.release_backend(selected[0])

    def test_prefix_affinity_is_bounded_and_survives_policy_reload(self) -> None:
        other = "e" * 32
        with state.SiteStore(identity=self.identity) as store:
            insert_member(store, other)
            placement = self.placement(temperature=40.0)
            placement["strategy"] = "replicated"
            placement["members"] = [self.identity.member_id, other]
            placement["endpoints"].append(
                {
                    **placement["endpoints"][0],
                    "member_id": other,
                    "url": "http://127.0.0.1:18001",
                    "temperature_c": 50.0,
                    "prefix_keys": [],
                }
            )
            store.set_placement(placement)
        policy = server.PolicySnapshot(self.identity)
        policy.reload(force=True)
        first, _ = policy.acquire_backend(
            "fixture-model", prefix_key="conversation", timeout=0.1
        )
        policy.release_backend(first)
        affinity_target = next(
            backend for backend in policy.backends if backend.member_id == other
        )
        policy.record_prefix_affinity(affinity_target, "conversation")
        policy.reload(force=True)
        selected, _ = policy.acquire_backend(
            "fixture-model", prefix_key="conversation", timeout=0.1
        )
        self.assertEqual(selected.member_id, other)
        policy.release_backend(selected)

        with mock.patch.object(server, "PREFIX_AFFINITY_MAX_ENTRIES", 2):
            for suffix in ("a", "b", "c"):
                policy.record_prefix_affinity(affinity_target, suffix)
        self.assertLessEqual(len(policy.prefix_affinity), 2)

    def test_excluded_failed_placement_fails_without_reselecting_it(self) -> None:
        policy = server.PolicySnapshot(self.identity)
        policy.reload(force=True)
        only = policy.backends[0]
        with self.assertRaisesRegex(server.GatewayError, "all qualified placements failed"):
            policy.acquire_backend(
                "fixture-model", prefix_key=None, timeout=0.1, excluded={only.key}
            )

    def test_backend_failure_uses_bounded_cooldown_and_success_clears_it(self) -> None:
        policy = server.PolicySnapshot(self.identity)
        policy.reload(force=True)
        backend = policy.backends[0]
        with mock.patch.object(server.time, "monotonic", return_value=10.0):
            policy.mark_backend_failure(backend)
            self.assertFalse(policy.backend_available(backend))
        self.assertEqual(policy.unavailable_until[backend.key], 11.0)
        with mock.patch.object(server.time, "monotonic", return_value=11.0):
            self.assertTrue(policy.backend_available(backend))
            policy.mark_backend_failure(backend)
        self.assertEqual(policy.unavailable_until[backend.key], 13.0)
        policy.mark_backend_success(backend)
        self.assertTrue(policy.backend_available(backend, now=10.0))

    def test_quota_state_restores_recent_durable_usage(self) -> None:
        now_ms = int(time.time() * 1000)
        with state.SiteStore(identity=self.identity) as store:
            with store.transaction():
                store.connection.execute(
                    """INSERT INTO request_summaries
                       (request_id,key_id,model,received_unix_ms,completed_unix_ms,status,
                        input_tokens,output_tokens,cached_tokens,retries,exact_tokens)
                       VALUES(?,?,?,?,?,'completed',100,50,0,0,1)""",
                    ("request-1", self.key["key_id"], "fixture-model", now_ms, now_ms),
                )
        quotas = server.QuotaState(self.identity)
        policy = {
            "key_id": self.key["key_id"], "requests_per_minute": 1,
            "tokens_per_minute": 150, "concurrency_limit": 1,
        }
        with self.assertRaisesRegex(server.AdmissionError, "request-rate"):
            quotas.admit(policy)

    def test_each_api_key_quota_is_enforced_independently(self) -> None:
        quotas = server.QuotaState(self.identity)
        key_id = self.key["key_id"]

        request_policy = {
            "key_id": key_id,
            "requests_per_minute": 1,
            "tokens_per_minute": None,
            "concurrency_limit": None,
        }
        quotas.admit(request_policy)
        quotas.complete(key_id, 0)
        with self.assertRaisesRegex(server.AdmissionError, "request-rate"):
            quotas.admit(request_policy)

        token_key = "f" * 16
        now_ms = int(time.time() * 1000)
        with state.SiteStore(identity=self.identity) as store:
            with store.transaction():
                store.connection.execute(
                    """INSERT INTO request_summaries
                       (request_id,key_id,model,received_unix_ms,completed_unix_ms,status,
                        input_tokens,output_tokens,cached_tokens,retries,exact_tokens)
                       VALUES(?,?,?,?,?,'completed',100,50,0,0,1)""",
                    ("request-token-quota", token_key, "fixture-model", now_ms, now_ms),
                )
        restored = server.QuotaState(self.identity)
        token_policy = {
            "key_id": token_key,
            "requests_per_minute": None,
            "tokens_per_minute": 150,
            "concurrency_limit": None,
        }
        with self.assertRaisesRegex(server.AdmissionError, "token-rate"):
            restored.admit(token_policy)

        concurrency_key = "e" * 16
        concurrency_policy = {
            "key_id": concurrency_key,
            "requests_per_minute": None,
            "tokens_per_minute": None,
            "concurrency_limit": 1,
        }
        quotas.admit(concurrency_policy)
        with self.assertRaisesRegex(server.AdmissionError, "concurrency"):
            quotas.admit(concurrency_policy)
        quotas.complete(concurrency_key, 0)

    def test_token_quota_reserves_exact_demand_across_concurrent_requests(self) -> None:
        quotas = server.QuotaState(self.identity)
        policy = {
            "key_id": "d" * 16,
            "requests_per_minute": None,
            "tokens_per_minute": 20,
            "concurrency_limit": None,
        }
        quotas.admit(policy)
        first = quotas.reserve_tokens(policy, 15)
        quotas.admit(policy)
        with self.assertRaisesRegex(server.AdmissionError, "token-rate"):
            quotas.reserve_tokens(policy, 6)
        quotas.complete(policy["key_id"], 0)
        quotas.complete(policy["key_id"], 10, reserved_tokens=first)

        quotas.admit(policy)
        second = quotas.reserve_tokens(policy, 10)
        self.assertEqual(second, 10)
        quotas.complete(policy["key_id"], 10, reserved_tokens=second)

    def test_usage_parser_accepts_only_complete_exact_usage(self) -> None:
        usage = server._usage_from_tail(json.dumps({
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 4,
                "prompt_tokens_details": {"cached_tokens": 3},
            }
        }).encode())
        self.assertTrue(usage.exact)
        self.assertEqual((usage.input_tokens, usage.output_tokens, usage.cached_tokens), (10, 4, 3))
        self.assertFalse(server._usage_from_tail(b'{"usage":{"prompt_tokens":10}}').exact)
        for field in ("prompt_tokens", "completion_tokens"):
            invalid = {
                "usage": {
                    "prompt_tokens": 10,
                    "completion_tokens": 4,
                    field: True,
                }
            }
            self.assertFalse(server._usage_from_tail(json.dumps(invalid).encode()).exact)
        self.assertFalse(server._usage_from_tail(json.dumps({
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 4,
                "prompt_tokens_details": {"cached_tokens": True},
            }
        }).encode()).exact)

    def test_sglang_stream_instrumentation_preserves_request_fields(self) -> None:
        backend = server.Backend(
            placement_id="a" * 32,
            member_id="b" * 32,
            model="fixture-model",
            url="http://127.0.0.1:18000",
            credential_file="/api-key",
            ca_file=None,
            token_count_path="/v1/messages/count_tokens",
            token_count_protocol="sglang-anthropic-count-tokens-v1",
            max_active_requests=1,
            max_context_tokens=1_000_000,
            healthy=True,
            memory_pressure=False,
            temperature_c=40.0,
            prefix_keys=set(),
            engine="sglang",
        )
        body = json.dumps({
            "model": "fixture-model",
            "messages": [{"role": "user", "content": "hi"}],
            "stream": True,
            "stream_options": {"include_usage": False},
            "temperature": 0.2,
        }).encode()
        result = json.loads(server._instrument_stream_usage(backend, body))
        self.assertEqual(result["temperature"], 0.2)
        self.assertEqual(result["stream_options"], {
            "include_usage": True,
            "continuous_usage_stats": True,
        })
        self.assertEqual(
            server._instrument_stream_usage(
                dataclasses.replace(backend, engine="unknown"),
                body,
            ),
            body,
        )

    def test_each_engine_adapter_requests_its_native_exact_stream_usage(self) -> None:
        body = json.dumps({"model": "fixture-model", "stream": True}).encode()
        base = server.Backend(
            placement_id="a" * 32,
            member_id="b" * 32,
            model="fixture-model",
            url="http://127.0.0.1:18000",
            credential_file="/api-key",
            ca_file=None,
            token_count_path=None,
            token_count_protocol=None,
            max_active_requests=1,
            max_context_tokens=1_000_000,
            healthy=True,
            memory_pressure=False,
            temperature_c=40.0,
            prefix_keys=set(),
        )
        for engine in ("dwarfstar", "llama.cpp", "sglang", "vllm"):
            with self.subTest(engine=engine):
                value = json.loads(server._instrument_stream_usage(
                    dataclasses.replace(base, engine=engine), body
                ))
                self.assertTrue(value["stream_options"]["include_usage"])
                self.assertEqual(
                    value["stream_options"].get("continuous_usage_stats"),
                    True if engine in {"sglang", "vllm"} else None,
                )

    def test_each_engine_native_usage_reconciles_without_fabrication(self) -> None:
        continuous = (
            b'data: {"choices":[{"index":0}],"usage":{"prompt_tokens":8,'
            b'"completion_tokens":1}}\n\n'
            b'data: {"choices":[{"index":0}],"usage":{"prompt_tokens":8,'
            b'"completion_tokens":3}}\n\n'
        )
        final_only = (
            b'data: {"choices":[],"usage":{"prompt_tokens":8,'
            b'"completion_tokens":3}}\n\n'
        )
        for engine in ("dwarfstar", "llama.cpp", "sglang", "vllm"):
            with self.subTest(engine=engine):
                tracker = server.StreamingUsageTracker()
                changes = tracker.feed(
                    continuous if engine in {"sglang", "vllm"} else final_only
                )
                self.assertEqual(changes["input_tokens"], 8)
                self.assertEqual(changes["output_tokens"], 3)
                usage, remaining = tracker.reconcile(
                    server.RequestUsage(8, 3, 0, True), exact_prompt_tokens=8
                )
                self.assertTrue(usage.exact)
                self.assertEqual(remaining, {
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "cached_tokens": 0,
                })

    def test_cancelled_stream_keeps_only_observed_exact_usage(self) -> None:
        tracker = server.StreamingUsageTracker()
        tracker.feed(
            b'data: {"choices":[{"index":0}],"usage":{"prompt_tokens":8,'
            b'"completion_tokens":2}}\n\n'
        )
        usage, remaining = tracker.reconcile(
            server.RequestUsage(), exact_prompt_tokens=8
        )
        self.assertEqual(usage.input_tokens, 8)
        self.assertEqual(usage.output_tokens, 2)
        self.assertEqual(remaining["output_tokens"], 0)

    def test_stream_usage_parser_handles_fragments_and_cumulative_counts(self) -> None:
        tracker = server.StreamingUsageTracker()
        payload = (
            b'data: {"choices":[{"index":0}],"usage":{"prompt_tokens":10,'
            b'"completion_tokens":1,"prompt_tokens_details":{"cached_tokens":3}}}\n\n'
            b'data: {"choices":[{"index":0}],"usage":{"prompt_tokens":10,'
            b'"completion_tokens":4,"prompt_tokens_details":{"cached_tokens":3}}}\n\n'
        )
        totals = {"input_tokens": 0, "output_tokens": 0, "cached_tokens": 0}
        for chunk in (payload[:7], payload[7:31], payload[31:119], payload[119:]):
            for key, value in tracker.feed(chunk).items():
                totals[key] += value
        self.assertEqual(totals, {
            "input_tokens": 10,
            "output_tokens": 4,
            "cached_tokens": 3,
        })

        usage, changes = tracker.reconcile(
            server.RequestUsage(10, 4, 3, True),
            exact_prompt_tokens=10,
        )
        self.assertTrue(usage.exact)
        self.assertEqual(changes, {
            "input_tokens": 0,
            "output_tokens": 0,
            "cached_tokens": 0,
        })

    def test_stream_usage_ignores_malformed_and_bounds_partial_lines(self) -> None:
        tracker = server.StreamingUsageTracker(max_pending_bytes=32)
        self.assertEqual(
            tracker.feed(b'data: {"usage":{"prompt_tokens":10}}\n'),
            {"input_tokens": 0, "output_tokens": 0, "cached_tokens": 0},
        )
        tracker.feed(b"data: " + b"x" * 100)
        tracker.feed(b"\n")
        self.assertEqual(len(tracker.pending), 0)
        self.assertFalse(tracker.saw_exact)

    def test_usage_reconciliation_falls_back_to_exact_prompt_count(self) -> None:
        tracker = server.StreamingUsageTracker()
        usage, changes = tracker.reconcile(
            server.RequestUsage(),
            exact_prompt_tokens=37,
        )
        self.assertEqual(usage.input_tokens, 37)
        self.assertIsNone(usage.output_tokens)
        self.assertEqual(changes["input_tokens"], 37)
        self.assertEqual(changes["output_tokens"], 0)


if __name__ == "__main__":
    unittest.main()
