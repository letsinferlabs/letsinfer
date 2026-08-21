#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Private role-authorized controller view of one logical site."""

from __future__ import annotations

import dataclasses
import hashlib
import http.server
import json
import pathlib
import queue
import re
import socketserver
import ssl
import sys
import threading
import urllib.parse
import uuid
from collections.abc import Callable, Mapping
from typing import Any

from .state import SiteError, SiteIdentity, SiteStore
from .telemetry import TelemetryAggregator


PROTOCOL = "letsinfer-controller-control-v1"
DEFAULT_PORT = 9771
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_REQUEST_BYTES = 4096
MAX_ACTION_RESULTS = 32
MAX_PENDING_ACTIONS = 4
REQUEST_TIMEOUT_SECONDS = 15
MAX_CONCURRENT_REQUESTS = 8
ID_RE = re.compile(r"^[0-9a-f]{32}$")
MODEL_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
OPERATOR_ACTIONS = {"start", "stop", "restart", "recover"}
ADMINISTRATOR_ACTIONS = {"install", "topology-plan", "expose", "unexpose"}
ACTION_RESOURCES = {
    "stop": ("placement", {"stopped"}),
    "start": ("placement", {"running"}),
    "restart": ("placement", {"running"}),
    "recover": ("placement", {"running"}),
    "install": ("runtime", {"installed"}),
    "topology-plan": ("topology-plan", {"pending", "unchanged"}),
    "expose": ("exposure", {"enabled"}),
    "unexpose": ("exposure", {"disabled"}),
}


class ControllerError(RuntimeError):
    """Controller authentication, authorization, or response failed closed."""


@dataclasses.dataclass(frozen=True)
class ControllerPrincipal:
    controller_id: str
    role: str
    certificate_sha256: str


ROLE_LEVEL = {"viewer": 0, "operator": 1, "administrator": 2}


def controller_id_from_certificate(certificate: Mapping[str, Any]) -> str:
    identities = [
        value.removeprefix("urn:letsinfer:controller:")
        for kind, value in certificate.get("subjectAltName", ())
        if kind == "URI" and value.startswith("urn:letsinfer:controller:")
    ]
    if len(identities) != 1 or not ID_RE.fullmatch(identities[0]):
        raise ControllerError("controller certificate identity is invalid")
    return identities[0]


def _local_controller_id(installation_id: str) -> str:
    return hashlib.sha256(
        f"letsinfer-local-controller-v1:{installation_id}".encode("ascii")
    ).hexdigest()[:32]


class ControllerState:
    def __init__(
        self,
        identity: SiteIdentity,
        telemetry: TelemetryAggregator,
        *,
        site_provider: Callable[[], Mapping[str, Any]],
        action_provider: Callable[
            [ControllerPrincipal, str, Mapping[str, Any], str], Mapping[str, Any]
        ]
        | None = None,
        administration_provider: Callable[
            [ControllerPrincipal, str, Mapping[str, Any]], Mapping[str, Any]
        ]
        | None = None,
        administration_completed_provider: Callable[
            [str, Mapping[str, Any]], None
        ]
        | None = None,
    ) -> None:
        if identity.role != "coordinator":
            raise ControllerError("private controller API is coordinator-only")
        self.identity = identity
        self.telemetry = telemetry
        self.site_provider = site_provider
        self.action_provider = action_provider
        self.administration_provider = administration_provider
        self.administration_completed_provider = administration_completed_provider
        self._actions: dict[str, dict[str, Any]] = {}
        self._actions_lock = threading.Lock()
        self._action_queue: queue.Queue[
            tuple[ControllerPrincipal, str, dict[str, Any], str] | None
        ] = queue.Queue(maxsize=MAX_PENDING_ACTIONS)
        self._action_worker: threading.Thread | None = None
        if action_provider is not None:
            self._action_worker = threading.Thread(
                target=self._run_actions,
                name="letsinfer-controller-actions",
                daemon=True,
            )
            self._action_worker.start()

    def _remember_action(self, operation_id: str, value: Mapping[str, Any]) -> None:
        with self._actions_lock:
            self._actions[operation_id] = dict(value)
            while len(self._actions) > MAX_ACTION_RESULTS:
                del self._actions[next(iter(self._actions))]

    def _run_actions(self) -> None:
        while True:
            item = self._action_queue.get()
            if item is None:
                self._action_queue.task_done()
                return
            principal, action, payload, operation_id = item
            try:
                if self.action_provider is None:
                    raise ControllerError("controller actions are unavailable")
                result = self.action_provider(
                    principal, action, dict(payload), operation_id
                )
                self._validate_action_result(action, payload, result)
                self._audit_async_action(
                    principal,
                    action,
                    payload,
                    operation_id,
                    outcome="success",
                )
                self._remember_action(
                    operation_id,
                    {
                        "operation_id": operation_id,
                        "controller_id": principal.controller_id,
                        "action": action,
                        "state": "succeeded",
                        "result": dict(result),
                    },
                )
            except Exception as error:
                try:
                    self._audit_async_action(
                        principal,
                        action,
                        payload,
                        operation_id,
                        outcome="failed",
                        reason=type(error).__name__,
                    )
                except SiteError:
                    pass
                self._remember_action(
                    operation_id,
                    {
                        "operation_id": operation_id,
                        "controller_id": principal.controller_id,
                        "action": action,
                        "state": "failed",
                        "error": type(error).__name__,
                    },
                )
            finally:
                self._action_queue.task_done()

    def _audit_async_action(
        self,
        principal: ControllerPrincipal,
        action: str,
        payload: Mapping[str, Any],
        operation_id: str,
        *,
        outcome: str,
        reason: str | None = None,
    ) -> None:
        target = payload.get("model")
        if not isinstance(target, str):
            target = ACTION_RESOURCES[action][0]
        with SiteStore(identity=self.identity) as store:
            store.record_action(
                f"controller.{action}",
                target,
                outcome,
                reason,
                actor_type="controller",
                actor_id=principal.controller_id,
                origin_interface="controller-api",
                correlation_id=operation_id,
            )

    def close(self) -> None:
        if self._action_worker is None:
            return
        try:
            self._action_queue.put_nowait(None)
        except queue.Full:
            return
        self._action_worker.join(timeout=1)

    def authorize(
        self,
        certificate: Mapping[str, Any],
        certificate_der: bytes,
        *,
        minimum_role: str = "viewer",
    ) -> ControllerPrincipal:
        fingerprint = hashlib.sha256(certificate_der).hexdigest()
        controller_uris = [
            value
            for kind, value in certificate.get("subjectAltName", ())
            if kind == "URI" and value.startswith("urn:letsinfer:controller:")
        ]
        if controller_uris:
            controller_id = controller_id_from_certificate(certificate)
        else:
            # The node-local certificate predates controller URI identities.
            # It may authenticate only as the deterministic local controller,
            # and only when its exact fingerprint is the active registry row.
            # Remote certificates still require their URI SAN.
            controller_id = _local_controller_id(self.identity.installation_id)
        try:
            with SiteStore(identity=self.identity) as store:
                row = next(
                    (
                        candidate
                        for candidate in store.controllers()
                        if candidate["controller_id"] == controller_id
                        and candidate["certificate_sha256"] == fingerprint
                    ),
                    None,
                )
                if row is None:
                    store.record_denied(
                        "controller.authorize",
                        controller_id,
                        "controller_not_authorized",
                        actor_type="controller",
                        actor_id=controller_id,
                        origin_interface="controller-api",
                    )
        except SiteError as error:
            raise ControllerError(str(error)) from error
        if row is None:
            raise ControllerError("controller is not authorized")
        role = str(row["role"])
        if role not in ROLE_LEVEL or minimum_role not in ROLE_LEVEL:
            raise ControllerError("controller role is invalid")
        if ROLE_LEVEL[role] < ROLE_LEVEL[minimum_role]:
            try:
                with SiteStore(identity=self.identity) as store:
                    store.record_denied(
                        "controller.authorize",
                        controller_id,
                        "insufficient_controller_role",
                        actor_type="controller",
                        actor_id=controller_id,
                        origin_interface="controller-api",
                    )
            except SiteError:
                pass
            raise ControllerError(
                f"controller role {role} cannot perform a {minimum_role} action"
            )
        return ControllerPrincipal(controller_id, role, fingerprint)

    def submit_action(
        self,
        principal: ControllerPrincipal,
        *,
        action: str,
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        if self.action_provider is None:
            self._record_denied(principal, "controller.action", "unavailable")
            raise ControllerError("controller actions are unavailable")
        minimum_role = (
            "operator" if action in OPERATOR_ACTIONS else "administrator"
        )
        if action not in OPERATOR_ACTIONS | ADMINISTRATOR_ACTIONS:
            self._record_denied(principal, "controller.action", "invalid_action")
            raise ControllerError("controller action is invalid")
        if ROLE_LEVEL.get(principal.role, -1) < ROLE_LEVEL[minimum_role]:
            self._record_denied(
                principal, "controller.action", "insufficient_controller_role"
            )
            raise ControllerError(
                f"controller role cannot perform an {minimum_role} action"
            )
        try:
            safe_payload = self._validate_action_payload(action, payload)
        except ControllerError:
            self._record_denied(
                principal, f"controller.{action}", "invalid_action_payload"
            )
            raise
        operation_id = uuid.uuid4().hex
        accepted = {
            "operation_id": operation_id,
            "controller_id": principal.controller_id,
            "action": action,
            "state": "accepted",
        }
        self._remember_action(operation_id, accepted)
        try:
            self._action_queue.put_nowait(
                (principal, action, safe_payload, operation_id)
            )
        except queue.Full as error:
            with self._actions_lock:
                self._actions.pop(operation_id, None)
            try:
                self._audit_async_action(
                    principal,
                    action,
                    safe_payload,
                    operation_id,
                    outcome="denied",
                    reason="action_queue_full",
                )
            except SiteError:
                pass
            raise ControllerError("controller action queue is full") from error
        return {
            "protocol": PROTOCOL,
            "controller": {"id": principal.controller_id, "role": principal.role},
            "action": accepted,
        }

    def _record_denied(
        self, principal: ControllerPrincipal, action: str, reason: str
    ) -> None:
        try:
            with SiteStore(identity=self.identity) as store:
                store.record_denied(
                    action,
                    "controller-api",
                    reason,
                    actor_type="controller",
                    actor_id=principal.controller_id,
                    origin_interface="controller-api",
                )
        except SiteError:
            pass

    @staticmethod
    def _validate_action_payload(
        action: str, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        if not isinstance(payload, Mapping):
            raise ControllerError("controller action payload is invalid")
        value = dict(payload)
        if action in OPERATOR_ACTIONS:
            if set(value) != {"model"} or not isinstance(
                value.get("model"), str
            ) or not MODEL_RE.fullmatch(value["model"]):
                raise ControllerError("controller runtime action requires one model")
            return value
        if action in {"install", "topology-plan"}:
            if set(value) != {"model", "engine"}:
                raise ControllerError(
                    f"controller {action} action requires model and engine"
                )
            model = value.get("model")
            engine = value.get("engine")
            if not isinstance(model, str) or not MODEL_RE.fullmatch(model):
                raise ControllerError(f"controller {action} model is invalid")
            if engine is not None and (
                not isinstance(engine, str) or not MODEL_RE.fullmatch(engine)
            ):
                raise ControllerError(f"controller {action} engine is invalid")
            return value
        if action in {"expose", "unexpose"} and not value:
            return value
        raise ControllerError("controller action payload is invalid")

    @staticmethod
    def _validate_action_result(
        action: str,
        payload: Mapping[str, Any],
        result: Any,
    ) -> None:
        if not isinstance(result, Mapping) or set(result) != {
            "resource",
            "identifier",
            "state",
            "model",
        }:
            raise ControllerError("controller action returned an invalid result")
        resource, states = ACTION_RESOURCES[action]
        identifier = result.get("identifier")
        model = result.get("model")
        expected_model = payload.get("model")
        if (
            result.get("resource") != resource
            or result.get("state") not in states
            or not isinstance(identifier, str)
            or not identifier
            or len(identifier.encode("utf-8")) > 512
            or any(character in identifier for character in "\r\n\x00")
            or model != expected_model
        ):
            raise ControllerError("controller action returned an invalid result")

    def action_status(
        self, principal: ControllerPrincipal, operation_id: str
    ) -> dict[str, Any]:
        if ROLE_LEVEL.get(principal.role, -1) < ROLE_LEVEL["operator"]:
            raise ControllerError("controller role cannot inspect runtime actions")
        if not ID_RE.fullmatch(operation_id):
            raise ControllerError("controller operation identity is invalid")
        with self._actions_lock:
            action = self._actions.get(operation_id)
            value = None if action is None else dict(action)
        if value is None:
            raise ControllerError("controller operation is unknown or expired")
        if (
            value["controller_id"] != principal.controller_id
            and principal.role != "administrator"
        ):
            raise ControllerError("controller operation belongs to another controller")
        value.pop("controller_id", None)
        return {
            "protocol": PROTOCOL,
            "controller": {"id": principal.controller_id, "role": principal.role},
            "action": value,
        }

    def site(self, principal: ControllerPrincipal) -> dict[str, Any]:
        value = dict(self.site_provider())
        return {
            "protocol": PROTOCOL,
            "controller": {
                "id": principal.controller_id,
                "role": principal.role,
            },
            "site": value,
        }

    def administer(
        self,
        principal: ControllerPrincipal,
        *,
        action: str,
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        if ROLE_LEVEL.get(principal.role, -1) < ROLE_LEVEL["administrator"]:
            self._record_denied(
                principal,
                "controller.administer",
                "insufficient_controller_role",
            )
            raise ControllerError("controller role cannot administer the site")
        if self.administration_provider is None:
            self._record_denied(
                principal, "controller.administer", "administration_unavailable"
            )
            raise ControllerError("site administration is unavailable")
        if action not in {
            "site.move.plan",
            "site.move.prepare",
            "site.move.commit",
            "site.move.cancel",
            "member.invite",
            "member.adopt",
            "member.approve",
            "member.cancel",
            "member.drain",
            "member.resume",
            "member.remove",
            "key.list",
            "key.show",
            "key.create",
            "key.rotate",
            "key.revoke",
            "key.policy",
        }:
            self._record_denied(
                principal, "controller.administer", "invalid_action"
            )
            raise ControllerError("site administrator action is invalid")
        try:
            result = self.administration_provider(
                principal, action, dict(payload)
            )
        except Exception as error:
            try:
                with SiteStore(identity=self.identity) as store:
                    store.record_action(
                        "controller.administer",
                        action,
                        "failed",
                        type(error).__name__,
                        actor_type="controller",
                        actor_id=principal.controller_id,
                        origin_interface="controller-api",
                    )
            except SiteError:
                pass
            raise ControllerError(str(error)) from error
        if not isinstance(result, Mapping) or not result:
            raise ControllerError("site administrator returned an invalid result")
        return {
            "protocol": PROTOCOL,
            "controller": {"id": principal.controller_id, "role": principal.role},
            "result": dict(result),
        }

    def administration_completed(
        self, action: str, result: Mapping[str, Any]
    ) -> None:
        if self.administration_completed_provider is not None:
            self.administration_completed_provider(action, result)

    def telemetry_view(
        self, principal: ControllerPrincipal, *, history_seconds: int
    ) -> dict[str, Any]:
        if history_seconds < 0 or history_seconds > 300:
            raise ControllerError("telemetry history must be between 0 and 300 seconds")
        history = self.telemetry.recent(seconds=history_seconds)
        return {
            "protocol": PROTOCOL,
            "controller": {
                "id": principal.controller_id,
                "role": principal.role,
            },
            "telemetry": self.telemetry.snapshot(),
            "history": history,
        }


class _Handler(http.server.BaseHTTPRequestHandler):
    server_version = "LetsInferController/1"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *_arguments: Any) -> None:
        return

    @property
    def state(self) -> ControllerState:
        return self.server.controller_state  # type: ignore[attr-defined]

    def _principal(self, minimum_role: str = "viewer") -> ControllerPrincipal:
        certificate_der = self.connection.getpeercert(binary_form=True)
        certificate = self.connection.getpeercert()
        if not isinstance(certificate_der, bytes) or not certificate_der or not isinstance(certificate, dict):
            raise ControllerError("controller certificate is unavailable")
        return self.state.authorize(
            certificate, certificate_der, minimum_role=minimum_role
        )

    def _json_body(self) -> dict[str, Any]:
        content_type = self.headers.get("Content-Type", "").partition(";")[0].strip()
        length_text = self.headers.get("Content-Length", "")
        try:
            length = int(length_text)
        except ValueError as error:
            raise ControllerError("controller request length is invalid") from error
        if content_type != "application/json" or length not in range(1, MAX_REQUEST_BYTES + 1):
            raise ControllerError("controller request body is invalid")
        try:
            value = json.loads(self.rfile.read(length))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ControllerError("controller request is invalid JSON") from error
        if not isinstance(value, dict):
            raise ControllerError("controller request must be an object")
        return value

    def _respond(self, status: int, value: Mapping[str, Any]) -> None:
        body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(body) > MAX_RESPONSE_BYTES:
            status = 507
            body = b'{"error":"controller response exceeds the bounded limit"}'
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def do_GET(self) -> None:  # noqa: N802
        try:
            principal = self._principal()
            parsed = urllib.parse.urlsplit(self.path)
            if parsed.path == "/control/v1/site" and not parsed.query:
                self._respond(200, self.state.site(principal))
                return
            if parsed.path == "/control/v1/site-move/plan" and not parsed.query:
                principal = self._principal("administrator")
                self._respond(
                    200,
                    self.state.administer(
                        principal, action="site.move.plan", payload={}
                    ),
                )
                return
            if parsed.path == "/control/v1/keys" and not parsed.query:
                principal = self._principal("administrator")
                self._respond(
                    200,
                    self.state.administer(
                        principal, action="key.list", payload={}
                    ),
                )
                return
            key_match = re.fullmatch(
                r"/control/v1/keys/([a-z0-9][a-z0-9._-]{0,127})",
                parsed.path,
            )
            if key_match is not None and not parsed.query:
                principal = self._principal("administrator")
                self._respond(
                    200,
                    self.state.administer(
                        principal,
                        action="key.show",
                        payload={"key": key_match.group(1)},
                    ),
                )
                return
            if parsed.path == "/control/v1/telemetry":
                values = urllib.parse.parse_qs(
                    parsed.query, keep_blank_values=True, strict_parsing=bool(parsed.query)
                )
                if set(values) - {"history"} or any(len(items) != 1 for items in values.values()):
                    raise ControllerError("controller telemetry query is invalid")
                history = int(values.get("history", ["0"])[0])
                self._respond(
                    200,
                    self.state.telemetry_view(principal, history_seconds=history),
                )
                return
            match = re.fullmatch(r"/control/v1/actions/([0-9a-f]{32})", parsed.path)
            if match is not None and not parsed.query:
                principal = self._principal("operator")
                self._respond(200, self.state.action_status(principal, match.group(1)))
                return
            self._respond(404, {"error": "not found"})
        except (ControllerError, ValueError) as error:
            self._respond(403, {"error": str(error)})

    def do_POST(self) -> None:  # noqa: N802
        try:
            parsed = urllib.parse.urlsplit(self.path)
            administrator_actions = {
                "/control/v1/members/invite": "member.invite",
                "/control/v1/members/adopt": "member.adopt",
                "/control/v1/members/approve": "member.approve",
                "/control/v1/members/cancel": "member.cancel",
                "/control/v1/members/drain": "member.drain",
                "/control/v1/members/resume": "member.resume",
                "/control/v1/members/remove": "member.remove",
                "/control/v1/keys/create": "key.create",
                "/control/v1/keys/rotate": "key.rotate",
                "/control/v1/keys/revoke": "key.revoke",
                "/control/v1/keys/policy": "key.policy",
                "/control/v1/site-move/prepare": "site.move.prepare",
                "/control/v1/site-move/commit": "site.move.commit",
                "/control/v1/site-move/cancel": "site.move.cancel",
            }
            administrator_action = administrator_actions.get(parsed.path)
            if administrator_action is not None and not parsed.query:
                principal = self._principal("administrator")
                response = self.state.administer(
                    principal,
                    action=administrator_action,
                    payload=self._json_body(),
                )
                try:
                    self._respond(200, response)
                finally:
                    self.state.administration_completed(
                        administrator_action, response["result"]
                    )
                return
            match = re.fullmatch(
                r"/control/v1/actions/"
                r"(start|stop|restart|recover|install|topology-plan|expose|unexpose)",
                parsed.path,
            )
            if match is None or parsed.query:
                self._respond(404, {"error": "not found"})
                return
            action = match.group(1)
            principal = self._principal(
                "operator" if action in OPERATOR_ACTIONS else "administrator"
            )
            self._respond(
                202,
                self.state.submit_action(
                    principal,
                    action=action,
                    payload=self._json_body(),
                ),
            )
        except ControllerError as error:
            self._respond(403, {"error": str(error)})


def tls_context(
    certificate: pathlib.Path,
    private_key: pathlib.Path,
    controller_ca: pathlib.Path,
) -> ssl.SSLContext:
    if not getattr(ssl, "HAS_TLSv1_3", False):
        raise ControllerError("private controller API requires TLS 1.3")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    try:
        context.load_cert_chain(certificate, private_key)
        context.load_verify_locations(controller_ca)
    except (OSError, ssl.SSLError) as error:
        raise ControllerError(f"cannot load private controller TLS material: {error}") from error
    context.verify_mode = ssl.CERT_REQUIRED
    return context


class ControllerServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Small bounded controller listener; one slow client cannot stall peers."""

    allow_reuse_address = True
    request_queue_size = MAX_CONCURRENT_REQUESTS
    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        state: ControllerState,
        *,
        context: ssl.SSLContext,
    ) -> None:
        self._request_slots = threading.BoundedSemaphore(MAX_CONCURRENT_REQUESTS)
        super().__init__(address, _Handler, bind_and_activate=False)
        self.controller_state = state
        self.socket = context.wrap_socket(
            self.socket,
            server_side=True,
            do_handshake_on_connect=False,
        )
        self.server_bind()
        self.server_activate()

    def get_request(self) -> tuple[ssl.SSLSocket, Any]:
        connection, address = super().get_request()
        connection.settimeout(REQUEST_TIMEOUT_SECONDS)
        return connection, address

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._request_slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._request_slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()

    def handle_error(self, request: Any, client_address: Any) -> None:
        error = sys.exc_info()[1]
        if isinstance(error, (ConnectionError, TimeoutError, ssl.SSLError)):
            return
        super().handle_error(request, client_address)
