# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import hashlib
import os
import pathlib
import tempfile
import time
import unittest
from unittest import mock

from core.site.controller import (
    ControllerError,
    ControllerPrincipal,
    ControllerState,
)
from core.site.state import SiteStore, setup_site
from core.site.telemetry import TelemetryAggregator


CONTROLLER = "a" * 32
CERTIFICATE = (
    "-----BEGIN CERTIFICATE-----\n"
    "synthetic-controller-certificate\n"
    "-----END CERTIFICATE-----\n"
)


class ControllerStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.temporary.name)
        self.environment = mock.patch.dict(
            os.environ,
            {"LETSINFER_HOME": str(root)},
        )
        self.environment.start()

    def tearDown(self) -> None:
        self.environment.stop()
        self.temporary.cleanup()

    @staticmethod
    def certificate() -> dict:
        return {"subjectAltName": (("URI", f"urn:letsinfer:controller:{CONTROLLER}"),)}

    def test_live_registry_role_authorizes_read_and_revocation_is_immediate(self) -> None:
        identity = setup_site()
        der = b"synthetic-controller-der"
        fingerprint = hashlib.sha256(der).hexdigest()
        with SiteStore(identity=identity) as store:
            store.upsert_controller(
                controller_id=CONTROLLER,
                name="Desk Mac",
                role="viewer",
                certificate_sha256=fingerprint,
                certificate_pem=CERTIFICATE,
            )
        controller = ControllerState(
            identity,
            TelemetryAggregator(),
            site_provider=lambda: {"schema_version": 1, "site_id": identity.site_id},
        )
        principal = controller.authorize(self.certificate(), der)
        self.assertEqual(principal.role, "viewer")
        self.assertEqual(controller.node(principal)["node"]["site_id"], identity.site_id)
        with self.assertRaisesRegex(ControllerError, "cannot perform"):
            controller.authorize(self.certificate(), der, minimum_role="operator")
        with SiteStore(identity=identity) as store:
            store.revoke_controller(CONTROLLER)
        with self.assertRaisesRegex(ControllerError, "not authorized"):
            controller.authorize(self.certificate(), der)

    def test_fingerprint_and_controller_identity_are_both_required(self) -> None:
        identity = setup_site()
        der = b"controller"
        with SiteStore(identity=identity) as store:
            store.upsert_controller(
                controller_id=CONTROLLER,
                name="Desk Mac",
                role="administrator",
                certificate_sha256=hashlib.sha256(der).hexdigest(),
                certificate_pem=CERTIFICATE,
            )
        controller = ControllerState(
            identity, TelemetryAggregator(), site_provider=lambda: {}
        )
        with self.assertRaisesRegex(ControllerError, "not authorized"):
            controller.authorize(self.certificate(), b"different")
        malformed = {"subjectAltName": (("URI", "urn:letsinfer:controller:bad"),)}
        with self.assertRaisesRegex(ControllerError, "identity"):
            controller.authorize(malformed, der)

    def test_registered_local_certificate_may_omit_controller_uri(self) -> None:
        identity = setup_site()
        der = b"node-local-controller"
        local_id = hashlib.sha256(
            f"letsinfer-local-controller-v1:{identity.installation_id}".encode("ascii")
        ).hexdigest()[:32]
        with SiteStore(identity=identity) as store:
            store.upsert_controller(
                controller_id=local_id,
                name="Let's Infer local controller",
                role="administrator",
                certificate_sha256=hashlib.sha256(der).hexdigest(),
                certificate_pem=CERTIFICATE,
            )
        controller = ControllerState(
            identity, TelemetryAggregator(), site_provider=lambda: {}
        )
        certificate = {"subjectAltName": (("DNS", "localhost"),)}
        principal = controller.authorize(certificate, der)
        self.assertEqual(principal.controller_id, local_id)
        self.assertEqual(principal.role, "administrator")
        with self.assertRaisesRegex(ControllerError, "not authorized"):
            controller.authorize(certificate, b"different-local-certificate")
        malformed = {
            "subjectAltName": (("URI", "urn:letsinfer:controller:bad"),)
        }
        with self.assertRaisesRegex(ControllerError, "identity"):
            controller.authorize(malformed, der)

    def test_telemetry_history_is_bounded(self) -> None:
        identity = setup_site()
        controller = ControllerState(
            identity, TelemetryAggregator(), site_provider=lambda: {}
        )
        principal = mock.Mock(controller_id=CONTROLLER, role="viewer")
        result = controller.telemetry_view(principal, history_seconds=300)
        self.assertEqual(result["history"], [])
        with self.assertRaisesRegex(ControllerError, "between 0 and 300"):
            controller.telemetry_view(principal, history_seconds=301)

    def test_operator_actions_are_bounded_allowlisted_and_asynchronous(self) -> None:
        identity = setup_site()
        calls: list[tuple[str, str, str]] = []

        def action_provider(principal, action, payload, operation_id):
            calls.append((principal.controller_id, action, payload["model"]))
            return {
                "resource": "placement",
                "identifier": operation_id,
                "state": "stopped" if action == "stop" else "running",
                "model": payload["model"],
            }

        controller = ControllerState(
            identity,
            TelemetryAggregator(),
            site_provider=lambda: {},
            action_provider=action_provider,
        )
        viewer = ControllerPrincipal(CONTROLLER, "viewer", "1" * 64)
        with self.assertRaisesRegex(ControllerError, "operator action"):
            controller.submit_action(
                viewer, action="restart", payload={"model": "example-model"}
            )
        operator = ControllerPrincipal(CONTROLLER, "operator", "1" * 64)
        for action in ("start", "stop", "restart", "recover"):
            accepted = controller.submit_action(
                operator, action=action, payload={"model": "example-model"}
            )
            operation_id = accepted["action"]["operation_id"]
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                status = controller.action_status(operator, operation_id)
                if status["action"]["state"] == "succeeded":
                    break
                time.sleep(0.01)
            self.assertEqual(status["action"]["state"], "succeeded")
        controller.close()
        self.assertEqual(
            calls,
            [
                (CONTROLLER, "start", "example-model"),
                (CONTROLLER, "stop", "example-model"),
                (CONTROLLER, "restart", "example-model"),
                (CONTROLLER, "recover", "example-model"),
            ],
        )
        with self.assertRaisesRegex(ControllerError, "invalid"):
            controller.submit_action(
                operator, action="shell", payload={"model": "example-model"}
            )

    def test_administrator_actions_have_strict_payloads_and_results(self) -> None:
        identity = setup_site()

        def action_provider(_principal, action, payload, operation_id):
            self.assertEqual(action, "install")
            self.assertEqual(payload, {"model": "example-model", "engine": None})
            return {
                "resource": "runtime",
                "identifier": operation_id,
                "state": "installed",
                "model": "example-model",
            }

        controller = ControllerState(
            identity,
            TelemetryAggregator(),
            site_provider=lambda: {},
            action_provider=action_provider,
        )
        operator = ControllerPrincipal(CONTROLLER, "operator", "1" * 64)
        with self.assertRaisesRegex(ControllerError, "administrator"):
            controller.submit_action(
                operator,
                action="install",
                payload={"model": "example-model", "engine": None},
            )
        administrator = ControllerPrincipal(
            CONTROLLER, "administrator", "1" * 64
        )
        accepted = controller.submit_action(
            administrator,
            action="install",
            payload={"model": "example-model", "engine": None},
        )
        operation_id = accepted["action"]["operation_id"]
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            status = controller.action_status(administrator, operation_id)
            if status["action"]["state"] == "succeeded":
                break
            time.sleep(0.01)
        controller.close()
        self.assertEqual(status["action"]["result"]["resource"], "runtime")
        with self.assertRaisesRegex(ControllerError, "requires model and engine"):
            controller.submit_action(
                administrator,
                action="install",
                payload={"model": "example-model"},
            )

    def test_site_administration_requires_administrator_and_is_allowlisted(self) -> None:
        identity = setup_site()
        calls: list[tuple[str, str, dict]] = []
        completed: list[tuple[str, dict]] = []

        def provider(principal, action, payload):
            calls.append((principal.controller_id, action, dict(payload)))
            return {"plan": {"source_site_id": identity.site_id}}

        controller = ControllerState(
            identity,
            TelemetryAggregator(),
            site_provider=lambda: {},
            administration_provider=provider,
            administration_completed_provider=lambda action, result: completed.append(
                (action, dict(result))
            ),
        )
        operator = ControllerPrincipal(CONTROLLER, "operator", "1" * 64)
        with self.assertRaisesRegex(ControllerError, "cannot administer"):
            controller.administer(
                operator, action="node.move.plan", payload={}
            )
        administrator = ControllerPrincipal(
            CONTROLLER, "administrator", "1" * 64
        )
        result = controller.administer(
            administrator, action="node.move.plan", payload={}
        )
        self.assertEqual(result["result"]["plan"]["source_site_id"], identity.site_id)
        self.assertEqual(calls, [(CONTROLLER, "node.move.plan", {})])
        controller.administration_completed("node.move.plan", result["result"])
        self.assertEqual(completed[0][0], "node.move.plan")
        controller.administer(
            administrator,
            action="child.adopt",
            payload={"source_site_id": "2" * 32},
        )
        self.assertEqual(calls[-1][1], "child.adopt")
        with self.assertRaisesRegex(ControllerError, "invalid"):
            controller.administer(
                administrator, action="shell", payload={}
            )


if __name__ == "__main__":
    unittest.main()
