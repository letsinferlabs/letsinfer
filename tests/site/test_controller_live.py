# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import hashlib
import http.client
import json
import os
import pathlib
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from unittest import mock

from core.site.administration import SiteAdministration
from core.site.controller import ControllerServer, ControllerState, tls_context
from core.site.state import SiteStore, setup_site
from core.site.telemetry import TelemetryAggregator


ADMINISTRATOR = "a" * 32
VIEWER = "b" * 32


class LiveControllerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not getattr(ssl, "HAS_TLSv1_3", False):
            raise unittest.SkipTest("TLS 1.3 is unavailable in this Python runtime")

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.environment = mock.patch.dict(
            os.environ,
            {"LETSINFER_HOME": str(self.root)},
            clear=False,
        )
        self.environment.start()
        self.identity = setup_site("Home", "127.0.0.1")
        self.ca_cert, self.ca_key = self._certificate_authority()
        self.server_cert, self.server_key, _ = self._certificate(
            "server", identity="IP:127.0.0.1", server=True
        )
        admin_cert, admin_key, admin_der = self._certificate(
            "administrator",
            identity=f"URI:urn:letsinfer:controller:{ADMINISTRATOR}",
            server=False,
        )
        viewer_cert, viewer_key, viewer_der = self._certificate(
            "viewer",
            identity=f"URI:urn:letsinfer:controller:{VIEWER}",
            server=False,
        )
        with SiteStore(identity=self.identity) as store:
            store.upsert_controller(
                controller_id=ADMINISTRATOR,
                name="Administrator",
                role="administrator",
                certificate_sha256=hashlib.sha256(admin_der).hexdigest(),
                certificate_pem=admin_cert.read_text(encoding="ascii"),
            )
            store.upsert_controller(
                controller_id=VIEWER,
                name="Viewer",
                role="viewer",
                certificate_sha256=hashlib.sha256(viewer_der).hexdigest(),
                certificate_pem=viewer_cert.read_text(encoding="ascii"),
            )
        administration = SiteAdministration(self.identity)

        def action_provider(_principal, action, payload, operation_id):
            return {
                "resource": "runtime" if action == "install" else "placement",
                "identifier": operation_id,
                "state": "installed" if action == "install" else "running",
                "model": payload["model"],
            }

        self.state = ControllerState(
            self.identity,
            TelemetryAggregator(),
            site_provider=lambda: {
                "schema_version": 1,
                "site_id": self.identity.site_id,
                "name": self.identity.display_name,
            },
            action_provider=action_provider,
            administration_provider=lambda principal, action, payload: administration.perform(
                controller_id=principal.controller_id,
                action=action,
                payload=payload,
            ),
        )
        self.server = ControllerServer(
            ("127.0.0.1", 0),
            self.state,
            context=tls_context(self.server_cert, self.server_key, self.ca_cert),
        )
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()
        self.admin_tls = self._client_context(admin_cert, admin_key)
        self.viewer_tls = self._client_context(viewer_cert, viewer_key)

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(timeout=2)
        self.state.close()
        self.environment.stop()
        self.temporary.cleanup()

    def test_listener_allows_immediate_managed_restart(self) -> None:
        self.assertNotEqual(
            self.server.socket.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR),
            0,
        )

    def test_slow_tls_peer_does_not_block_other_controller_requests(self) -> None:
        blocker = socket.create_connection(
            ("127.0.0.1", self.server.server_port), timeout=1
        )
        try:
            time.sleep(0.05)
            started = time.monotonic()
            status, body, _ = self._call(
                self.viewer_tls, "GET", "/control/v1/site"
            )
            self.assertEqual(status, 200)
            self.assertEqual(body["controller"]["role"], "viewer")
            self.assertLess(time.monotonic() - started, 1.0)
        finally:
            blocker.close()

    def _certificate_authority(self) -> tuple[pathlib.Path, pathlib.Path]:
        certificate = self.root / "ca.crt"
        key = self.root / "ca.key"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-days", "1", "-subj", "/CN=controller-test-ca",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-keyout", str(key), "-out", str(certificate),
            ],
            check=True,
            capture_output=True,
        )
        return certificate, key

    def _certificate(
        self, name: str, *, identity: str, server: bool
    ) -> tuple[pathlib.Path, pathlib.Path, bytes]:
        key = self.root / f"{name}.key"
        request = self.root / f"{name}.csr"
        certificate = self.root / f"{name}.crt"
        extensions = self.root / f"{name}.ext"
        extensions.write_text(
            f"subjectAltName={identity}\n"
            f"extendedKeyUsage={'serverAuth' if server else 'clientAuth'}\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\n",
            encoding="ascii",
        )
        subprocess.run(
            [
                "openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
                "-subj", f"/CN={name}", "-keyout", str(key), "-out", str(request),
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "openssl", "x509", "-req", "-sha256", "-days", "1",
                "-in", str(request), "-CA", str(self.ca_cert),
                "-CAkey", str(self.ca_key), "-CAcreateserial",
                "-extfile", str(extensions), "-out", str(certificate),
            ],
            check=True,
            capture_output=True,
        )
        der = subprocess.run(
            ["openssl", "x509", "-in", str(certificate), "-outform", "DER"],
            check=True,
            capture_output=True,
        ).stdout
        return certificate, key, der

    def _client_context(
        self, certificate: pathlib.Path, key: pathlib.Path
    ) -> ssl.SSLContext:
        context = ssl.create_default_context(cafile=str(self.ca_cert))
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(certificate, key)
        return context

    def _call(
        self,
        context: ssl.SSLContext,
        method: str,
        path: str,
        body: dict | None = None,
    ) -> tuple[int, dict, dict[str, str]]:
        connection = http.client.HTTPSConnection(
            "127.0.0.1", self.server.server_port, context=context, timeout=5
        )
        payload = None if body is None else json.dumps(body).encode()
        headers = {} if payload is None else {"Content-Type": "application/json"}
        try:
            connection.request(method, path, body=payload, headers=headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read()), dict(response.getheaders())
        finally:
            connection.close()

    @staticmethod
    def _key_payload() -> dict:
        return {
            "name": "desktop",
            "models": ["fixture-model"],
            "expires_at_unix": None,
            "requests_per_minute": 60,
            "tokens_per_minute": 1000,
            "concurrency_limit": 2,
            "context_limit": 4096,
            "tenant": "home",
            "application": "mac-app",
        }

    def test_mtls_rbac_actions_and_one_time_key_secret(self) -> None:
        status, body, _ = self._call(
            self.viewer_tls, "GET", "/control/v1/site"
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["controller"]["role"], "viewer")

        status, body, _ = self._call(
            self.viewer_tls,
            "POST",
            "/control/v1/actions/restart",
            {"model": "fixture-model"},
        )
        self.assertEqual(status, 403)
        self.assertIn("operator", body["error"])

        status, accepted, _ = self._call(
            self.admin_tls,
            "POST",
            "/control/v1/actions/install",
            {"model": "fixture-model", "engine": None},
        )
        self.assertEqual(status, 202)
        operation_id = accepted["action"]["operation_id"]
        deadline = time.monotonic() + 2
        while True:
            status, operation, _ = self._call(
                self.admin_tls,
                "GET",
                f"/control/v1/actions/{operation_id}",
            )
            if operation["action"]["state"] != "accepted":
                break
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.01)
        self.assertEqual(status, 200)
        self.assertEqual(operation["action"]["state"], "succeeded")
        self.assertEqual(operation["action"]["result"]["state"], "installed")

        status, created, headers = self._call(
            self.admin_tls,
            "POST",
            "/control/v1/keys/create",
            self._key_payload(),
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers["Cache-Control"], "no-store")
        token = created["result"]["token"]
        self.assertTrue(token.startswith("li_"))
        status, listed, _ = self._call(
            self.admin_tls, "GET", "/control/v1/keys"
        )
        self.assertEqual(status, 200)
        self.assertNotIn("token", listed["result"])
        self.assertTrue(
            all("token" not in item for item in listed["result"]["keys"])
        )

        status, denied, _ = self._call(
            self.viewer_tls,
            "POST",
            "/control/v1/members/drain",
            {"member_id": self.identity.member_id},
        )
        self.assertEqual(status, 403)
        self.assertIn("administrator", denied["error"])
        status, drained, _ = self._call(
            self.admin_tls,
            "POST",
            "/control/v1/members/drain",
            {"member_id": self.identity.member_id},
        )
        self.assertEqual(status, 200)
        self.assertEqual(drained["result"]["membership"]["state"], "draining")
        status, resumed, _ = self._call(
            self.admin_tls,
            "POST",
            "/control/v1/members/resume",
            {"member_id": self.identity.member_id},
        )
        self.assertEqual(status, 200)
        self.assertEqual(resumed["result"]["membership"]["state"], "active")
        with SiteStore(identity=self.identity) as store:
            self.assertNotIn(token, json.dumps(store.keys()))
            self.assertNotIn(token, json.dumps(store.audit_rows()))

        anonymous = ssl.create_default_context(cafile=str(self.ca_cert))
        anonymous.minimum_version = ssl.TLSVersion.TLSv1_3
        anonymous.maximum_version = ssl.TLSVersion.TLSv1_3
        with self.assertRaises((ssl.SSLError, OSError)):
            self._call(anonymous, "GET", "/control/v1/site")


if __name__ == "__main__":
    unittest.main()
