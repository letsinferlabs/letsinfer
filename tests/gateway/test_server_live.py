# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import http.server
import json
import os
import pathlib
import socket
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from unittest import mock

from core.gateway import server
from core.site import state
from tests.gateway.helpers import insert_member, routing_facts, set_member_facts


MODEL = "fixture-model"
BACKEND_SECRET = "fixture-backend-secret-0123456789abcdef"


class _BackendHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *_arguments: object) -> None:
        return

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        if self.headers.get("Authorization") != f"Bearer {BACKEND_SECRET}":
            self.send_error(401)
            return
        if self.path in {"/v1/token-count", "/v1/messages/count_tokens"}:
            value = (
                {"input_tokens": self.server.prompt_tokens}
                if self.path == "/v1/messages/count_tokens"
                else {
                    "object": "token_count",
                    "model": MODEL,
                    "prompt_tokens": self.server.prompt_tokens,
                }
            )
            payload = json.dumps(value, separators=(",", ":")).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        self.server.requests.append((self.path, body))
        if self.server.mode == "unavailable":
            self.send_response(503)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.server.mode == "client-error":
            payload = b'{"error":{"message":"invalid request"}}'
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if self.server.mode == "partial":
            payload = b'data: {"choices":[{"delta":{"content":"partial"}}]}\n\n'
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(payload) + 100))
            self.end_headers()
            self.wfile.write(payload)
            self.wfile.flush()
            self.close_connection = True
            return
        if self.server.mode == "stream":
            chunks = [
                b'data: {"choices":[{"index":0,"delta":{"content":"a"}}],'
                b'"usage":{"prompt_tokens":16,"completion_tokens":1}}\n\n',
                b'data: {"choices":[{"index":0,"delta":{"content":"bc"}}],'
                b'"usage":{"prompt_tokens":16,"completion_tokens":3}}\n\n',
                b'data: {"choices":[],"usage":{"prompt_tokens":16,'
                b'"completion_tokens":3}}\n\ndata: [DONE]\n\n',
            ]
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(chunks[0])
            self.wfile.flush()
            self.server.stream_started.set()
            self.server.release_stream.wait(timeout=5)
            for chunk in chunks[1:]:
                self.wfile.write(chunk)
                self.wfile.flush()
            self.close_connection = True
            return

        payload = json.dumps(
            {
                "id": "completion",
                "object": "chat.completion",
                "model": MODEL,
                "choices": [{"message": {"role": "assistant", "content": "ok"}}],
                "usage": {
                    "prompt_tokens": self.server.prompt_tokens,
                    "completion_tokens": 4,
                    "prompt_tokens_details": {"cached_tokens": 2},
                },
            },
            separators=(",", ":"),
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class _Backend(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, *, mode: str = "success", prompt_tokens: int = 16) -> None:
        super().__init__(("127.0.0.1", 0), _BackendHandler)
        self.mode = mode
        self.prompt_tokens = prompt_tokens
        self.requests: list[tuple[str, bytes]] = []
        self.stream_started = threading.Event()
        self.release_stream = threading.Event()
        self.worker = threading.Thread(target=self.serve_forever, daemon=True)
        self.worker.start()

    def close(self) -> None:
        self.release_stream.set()
        self.shutdown()
        self.server_close()
        self.worker.join(timeout=2)


class LiveGatewayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.environment = mock.patch.dict(
            os.environ,
            {
                "LETSINFER_CONFIG_HOME": str(self.root / "config"),
                "LETSINFER_DATA_HOME": str(self.root / "data"),
            },
            clear=False,
        )
        self.environment.start()
        self.identity = state.setup_site("Home", "127.0.0.1")
        self.backend_token = self.root / "backend-token"
        self.backend_token.write_text(BACKEND_SECRET + "\n", encoding="ascii")
        self.backend_token.chmod(0o600)
        self.backends = [_Backend(), _Backend()]
        with state.SiteStore(identity=self.identity) as store:
            _, self.token = store.create_key(
                "client", models=[MODEL], context_limit=128
            )
            store.set_alias("fixture", MODEL)
            for index, _backend in enumerate(self.backends):
                insert_member(store, f"{index + 1:032x}")
            store.set_placement(self._placement(self.backends))

        self.gateway = server.GatewayServer(
            ("127.0.0.1", 0),
            identity=self.identity,
            telemetry_file=self.root / "gateway.metrics",
            queue_timeout_seconds=1,
            max_connections=16,
        )
        self.gateway_worker = threading.Thread(
            target=self.gateway.serve_forever, daemon=True
        )
        self.gateway_worker.start()
        self.base_url = f"http://127.0.0.1:{self.gateway.server_port}"

    def tearDown(self) -> None:
        self.gateway.shutdown()
        self.gateway.server_close()
        self.gateway_worker.join(timeout=2)
        for backend in self.backends:
            backend.close()
        self.environment.stop()
        self.temporary.cleanup()

    def test_listener_allows_immediate_managed_restart(self) -> None:
        self.assertNotEqual(
            self.gateway.socket.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR),
            0,
        )
        with urllib.request.urlopen(self.base_url + "/health", timeout=2) as response:
            self.assertEqual(response.status, 200)
        port = self.gateway.server_port
        self.gateway.shutdown()
        self.gateway.server_close()
        self.gateway_worker.join(timeout=2)
        self.gateway = server.GatewayServer(
            ("127.0.0.1", port),
            identity=self.identity,
            telemetry_file=self.root / "gateway.metrics",
            queue_timeout_seconds=1,
            max_connections=16,
        )
        self.gateway_worker = threading.Thread(
            target=self.gateway.serve_forever, daemon=True
        )
        self.gateway_worker.start()
        self.assertEqual(self.gateway.server_port, port)

    def _placement(self, backends: list[_Backend]) -> dict:
        members = [f"{index + 1:032x}" for index in range(len(backends))]
        endpoints = []
        for index, backend in enumerate(backends):
            endpoints.append(
                {
                    "member_id": members[index],
                    "url": f"http://127.0.0.1:{backend.server_port}",
                    "credential_file": str(self.backend_token),
                    "ca_file": None,
                    "token_count_path": "/v1/token-count",
                    "token_count_protocol": "letsinfer-token-count-v1",
                    "max_active_requests": 1,
                    "max_context_tokens": 256,
                    "healthy": True,
                    "memory_pressure": False,
                    "temperature_c": 40.0 + index,
                    "prefix_keys": ["shared"] if index else [],
                }
            )
        return {
            "placement_id": f"{1:032x}",
            "model": MODEL,
            "runtime": f"{MODEL}/fixture/target@1.0.0",
            "target": "fixture-target",
            "strategy": "replicated",
            "state": "running",
            "topology_sha256": f"{1:064x}",
            "members": members,
            "endpoints": endpoints,
            "capacity": {
                "max_active_requests": len(backends),
                "max_context_tokens": 256,
            },
        }

    def _request(
        self,
        path: str,
        *,
        body: dict | None = None,
        token: str | None = None,
    ) -> tuple[int, bytes]:
        payload = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(
            self.base_url + path,
            data=payload,
            method="GET" if payload is None else "POST",
        )
        if payload is not None:
            request.add_header("Content-Type", "application/json")
        if token is not None:
            request.add_header("Authorization", f"Bearer {token}")
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, response.read()

    def _summaries(self) -> list[dict]:
        deadline = time.monotonic() + 2
        rows: list[dict] = []
        while time.monotonic() < deadline:
            with state.SiteStore(identity=self.identity) as store:
                rows = [
                    dict(row)
                    for row in store.connection.execute(
                        "SELECT * FROM request_summaries ORDER BY received_unix_ms"
                    )
                ]
            if rows:
                return rows
            time.sleep(0.01)
        return rows

    def test_authentication_alias_and_model_listing_use_the_site_registry(self) -> None:
        with self.assertRaises(urllib.error.HTTPError) as raised:
            self._request("/v1/models")
        self.assertEqual(raised.exception.code, 401)
        status, body = self._request("/v1/models", token=self.token)
        self.assertEqual(status, 200)
        self.assertEqual(
            [item["id"] for item in json.loads(body)["data"]],
            ["fixture", MODEL],
        )

    def test_memory_pressure_keeps_discovery_but_pauses_inference(self) -> None:
        with state.SiteStore(identity=self.identity) as store:
            for index in range(len(self.backends)):
                member_id = f"{index + 1:032x}"
                set_member_facts(
                    store,
                    member_id,
                    routing_facts(member_id, memory_pressure=True),
                )
        self.gateway.policy.reload(force=True)
        status, body = self._request("/v1/models", token=self.token)
        self.assertEqual(status, 200)
        self.assertEqual(
            [item["id"] for item in json.loads(body)["data"]],
            ["fixture", MODEL],
        )
        with self.assertRaises(urllib.error.HTTPError) as raised:
            self._request(
                "/v1/chat/completions",
                body={
                    "model": MODEL,
                    "messages": [{"role": "user", "content": "hello"}],
                    "max_tokens": 1,
                },
                token=self.token,
            )
        self.assertEqual(raised.exception.code, 503)
        error_payload = json.loads(raised.exception.read())
        self.assertEqual(error_payload, {
            "error": {
                "message": "qualified placement is waiting for memory headroom",
                "type": "memory_pressure",
            }
        })

    def test_impossible_context_fails_before_memory_pressure_queue(self) -> None:
        with state.SiteStore(identity=self.identity) as store:
            _, unbounded_token = store.create_key("unbounded", models=[MODEL])
            for index in range(len(self.backends)):
                member_id = f"{index + 1:032x}"
                set_member_facts(
                    store,
                    member_id,
                    routing_facts(member_id, memory_pressure=True),
                )
        for backend in self.backends:
            backend.prompt_tokens = 250
        self.gateway.policy.reload(force=True)

        started = time.monotonic()
        with self.assertRaises(urllib.error.HTTPError) as raised:
            self._request(
                "/v1/chat/completions",
                body={
                    "model": MODEL,
                    "messages": [{"role": "user", "content": "too long"}],
                    "max_tokens": 10,
                },
                token=unbounded_token,
            )
        self.assertEqual(raised.exception.code, 400)
        self.assertLess(time.monotonic() - started, 0.75)
        self.assertEqual(json.loads(raised.exception.read()), {
            "error": {
                "message": "request exceeds every qualified placement's context capacity",
                "type": "context_length_exceeded",
            }
        })
        self.assertEqual([backend.requests for backend in self.backends], [[], []])

    def test_browser_preflight_and_model_listing_preserve_api_key_auth(self) -> None:
        preflight = urllib.request.Request(
            self.base_url + "/v1/models",
            method="OPTIONS",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": (
                    "authorization, content-type, x-stainless-lang"
                ),
            },
        )
        with urllib.request.urlopen(preflight, timeout=5) as response:
            self.assertEqual(response.status, 204)
            self.assertEqual(response.headers["Access-Control-Allow-Origin"], "*")
            self.assertEqual(
                response.headers["Access-Control-Allow-Headers"],
                "authorization, content-type, x-stainless-lang",
            )

        models = urllib.request.Request(
            self.base_url + "/v1/models",
            headers={
                "Origin": "http://localhost:3000",
                "Authorization": f"Bearer {self.token}",
            },
        )
        with urllib.request.urlopen(models, timeout=5) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(response.headers["Access-Control-Allow-Origin"], "*")
            self.assertEqual(
                [item["id"] for item in json.loads(response.read())["data"]],
                ["fixture", MODEL],
            )

        hidden = urllib.request.Request(
            self.base_url + "/watchdog/v1/status",
            method="OPTIONS",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "GET",
            },
        )
        with self.assertRaises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(hidden, timeout=5)
        self.assertEqual(raised.exception.code, 404)

    def test_inference_listener_has_no_control_pairing_or_watchdog_routes(self) -> None:
        status, body = self._request("/health")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"status": "ok"})

        for path in (
            "/control/v1/site",
            "/site/v1/facts",
            "/pair",
            "/watchdog/v1/status",
            "/v1/token-count",
            "/v1/admin",
        ):
            request = urllib.request.Request(
                self.base_url + path,
                data=b"{}",
                method="POST",
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "Content-Type": "application/json",
                },
            )
            with self.subTest(path=path):
                with self.assertRaises(urllib.error.HTTPError) as raised:
                    urllib.request.urlopen(request, timeout=5)
                self.assertEqual(raised.exception.code, 404)
        self.assertEqual(len(self.backends[0].requests), 0)
        self.assertEqual(len(self.backends[1].requests), 0)

    def test_model_scope_denial_happens_before_inference_dispatch(self) -> None:
        with state.SiteStore(identity=self.identity) as store:
            _key, restricted_token = store.create_key(
                "restricted-client", models=["another-model"]
            )
        status, body = self._request("/v1/models", token=restricted_token)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["data"], [])

        request = urllib.request.Request(
            self.base_url + "/v1/chat/completions",
            data=json.dumps(
                {"model": MODEL, "messages": [{"role": "user", "content": "hi"}]}
            ).encode(),
            method="POST",
            headers={
                "Authorization": f"Bearer {restricted_token}",
                "Content-Type": "application/json",
            },
        )
        with self.assertRaises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(request, timeout=5)
        self.assertEqual(raised.exception.code, 403)
        self.assertEqual(json.loads(raised.exception.read())["error"]["type"], "model_forbidden")
        self.assertEqual(len(self.backends[0].requests), 0)
        self.assertEqual(len(self.backends[1].requests), 0)

    def test_revocation_and_expiration_take_effect_at_the_gateway_boundary(self) -> None:
        with state.SiteStore(identity=self.identity) as store:
            _key, expired_token = store.create_key(
                "expired-client",
                models=[MODEL],
                expires_at_unix=int(time.time()) - 1,
            )
        with self.assertRaises(urllib.error.HTTPError) as raised:
            self._request("/v1/models", token=expired_token)
        self.assertEqual(raised.exception.code, 401)

        with state.SiteStore(identity=self.identity) as store:
            store.revoke_key("client")
        with self.assertRaises(urllib.error.HTTPError) as raised:
            self._request("/v1/models", token=self.token)
        self.assertEqual(raised.exception.code, 401)

    def test_retry_happens_before_headers_and_records_exact_usage(self) -> None:
        self.backends[0].mode = "unavailable"
        status, body = self._request(
            "/v1/chat/completions",
            token=self.token,
            body={
                "model": MODEL,
                "messages": [{"role": "user", "content": "hi"}],
                "max_tokens": 16,
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["choices"][0]["message"]["content"], "ok")
        self.assertEqual(len(self.backends[0].requests), 1)
        self.assertEqual(len(self.backends[1].requests), 1)
        rows = self._summaries()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "completed")
        self.assertEqual(rows[0]["retries"], 1)
        self.assertEqual(rows[0]["input_tokens"], 16)
        self.assertEqual(rows[0]["output_tokens"], 4)
        self.assertEqual(rows[0]["cached_tokens"], 2)
        self.assertEqual(rows[0]["exact_tokens"], 1)

    def test_sglang_stream_usage_updates_live_and_reconciles_once(self) -> None:
        backend = self.backends[0]
        backend.mode = "stream"
        with state.SiteStore(identity=self.identity) as store:
            placement = self._placement(self.backends)
            placement["runtime"] = f"{MODEL}/sglang/target@1"
            placement["endpoints"][0]["token_count_protocol"] = (
                "sglang-anthropic-count-tokens-v1"
            )
            placement["endpoints"][0]["token_count_path"] = (
                "/v1/messages/count_tokens"
            )
            store.set_placement(placement)
        self.gateway.policy.reload(force=True)

        result: list[tuple[int, bytes]] = []
        worker = threading.Thread(
            target=lambda: result.append(self._request(
                "/v1/chat/completions",
                token=self.token,
                body={
                    "model": MODEL,
                    "messages": [{"role": "user", "content": "hi"}],
                    "max_tokens": 16,
                    "stream": True,
                },
            )),
            daemon=True,
        )
        worker.start()
        self.assertTrue(backend.stream_started.wait(timeout=2))
        deadline = time.monotonic() + 2
        while (
            self.gateway.metrics.snapshot()["output_tokens"] < 1
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)
        live = self.gateway.metrics.snapshot()
        self.assertEqual(live["input_tokens"], 16)
        self.assertEqual(live["output_tokens"], 1)
        self.assertEqual(live["active_requests"], 1)

        backend.release_stream.set()
        worker.join(timeout=3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(result[0][0], 200)
        sent = json.loads(backend.requests[0][1])
        self.assertEqual(sent["stream_options"], {
            "include_usage": True,
            "continuous_usage_stats": True,
        })
        final = self.gateway.metrics.snapshot()
        self.assertEqual(final["input_tokens"], 16)
        self.assertEqual(final["output_tokens"], 3)
        rows = self._summaries()
        self.assertEqual(rows[0]["input_tokens"], 16)
        self.assertEqual(rows[0]["output_tokens"], 3)

    def test_backend_is_never_retried_after_response_headers(self) -> None:
        self.backends[0].mode = "partial"
        status, body = self._request(
            "/v1/chat/completions",
            token=self.token,
            body={
                "model": MODEL,
                "messages": [{"role": "user", "content": "hi"}],
                "max_tokens": 16,
            },
        )
        self.assertEqual(status, 200)
        self.assertIn(b"partial", body)
        self.assertEqual(len(self.backends[0].requests), 1)
        self.assertEqual(len(self.backends[1].requests), 0)
        rows = self._summaries()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "failed")
        self.assertEqual(rows[0]["retries"], 0)

    def test_backend_client_error_increments_failed_request_telemetry(self) -> None:
        self.backends[0].mode = "client-error"
        request = urllib.request.Request(
            self.base_url + "/v1/chat/completions",
            data=json.dumps(
                {
                    "model": MODEL,
                    "messages": [{"role": "user", "content": "hi"}],
                    "max_tokens": 16,
                }
            ).encode(),
            method="POST",
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
            },
        )
        with self.assertRaises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(request, timeout=5)
        self.assertEqual(raised.exception.code, 400)
        rows = self._summaries()
        self.assertEqual(self.gateway.metrics.snapshot()["requests_failed"], 1)
        self.assertEqual(rows[0]["status"], "failed")

    def test_exact_context_admission_fails_before_inference_dispatch(self) -> None:
        request = urllib.request.Request(
            self.base_url + "/v1/chat/completions",
            data=json.dumps(
                {"model": MODEL, "messages": [{"role": "user", "content": "hi"}]}
            ).encode(),
            method="POST",
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
            },
        )
        with self.assertRaises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(request, timeout=5)
        self.assertEqual(raised.exception.code, 400)
        self.assertEqual(
            json.loads(raised.exception.read())["error"]["type"],
            "token_budget_required",
        )

        self.backends[0].prompt_tokens = 120
        self.backends[1].prompt_tokens = 120
        request = urllib.request.Request(
            self.base_url + "/v1/chat/completions",
            data=json.dumps(
                {
                    "model": MODEL,
                    "messages": [{"role": "user", "content": "hi"}],
                    "max_tokens": 16,
                }
            ).encode(),
            method="POST",
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
            },
        )
        with self.assertRaises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(request, timeout=5)
        self.assertEqual(raised.exception.code, 400)
        self.assertEqual(len(self.backends[0].requests), 0)
        self.assertEqual(len(self.backends[1].requests), 0)

    def test_exact_token_quota_is_reserved_before_inference_dispatch(self) -> None:
        with state.SiteStore(identity=self.identity) as store:
            _key, token = store.create_key(
                "quota-client", models=[MODEL], tokens_per_minute=20
            )
        for body, expected_type in (
            (
                {
                    "model": MODEL,
                    "messages": [{"role": "user", "content": "hi"}],
                    "max_tokens": 5,
                },
                "rate_limit",
            ),
            (
                {
                    "model": MODEL,
                    "messages": [{"role": "user", "content": "hi"}],
                },
                "token_budget_required",
            ),
        ):
            request = urllib.request.Request(
                self.base_url + "/v1/chat/completions",
                data=json.dumps(body).encode(),
                method="POST",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
            )
            with self.subTest(expected_type=expected_type):
                with self.assertRaises(urllib.error.HTTPError) as raised:
                    urllib.request.urlopen(request, timeout=5)
                self.assertEqual(json.loads(raised.exception.read())["error"]["type"], expected_type)
        self.assertEqual(len(self.backends[0].requests), 0)
        self.assertEqual(len(self.backends[1].requests), 0)


if __name__ == "__main__":
    unittest.main()
