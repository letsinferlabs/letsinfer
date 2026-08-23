#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Narrow administrator operations exposed by the private controller API."""

from __future__ import annotations

import hashlib
import re
import ssl
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from typing import Any

from .adoption import AdoptionError, request_adoption, resolve_direct_peer
from .control import DEFAULT_PORT
from .inventory import (
    InventoryError,
    select_direct_connectx_interface,
    verify_direct_connectx_peer,
    verify_direct_connectx_interface,
)
from .move import PreparedMove, apply_prepared_move, plan_local_move, prepare_local_move
from .state import SiteError, SiteIdentity, SiteStore, member_certificate_path


ID_RE = re.compile(r"^[0-9a-f]{32}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_PREPARED_MOVES = 4
KEY_POLICY_FIELDS = {
    "models",
    "expires_at_unix",
    "requests_per_minute",
    "tokens_per_minute",
    "concurrency_limit",
    "context_limit",
    "tenant",
    "application",
}


class AdministrationError(RuntimeError):
    """A private administrator request was malformed or unsafe."""


MoveApply = Callable[[PreparedMove], SiteIdentity]


def _certificate_sha256() -> str:
    try:
        pem = member_certificate_path().read_text(encoding="ascii")
        der = ssl.PEM_cert_to_DER_cert(pem)
    except (OSError, UnicodeError, ValueError) as error:
        raise AdministrationError("site controller certificate is unavailable") from error
    return hashlib.sha256(der).hexdigest()


def _endpoint(address: str) -> str:
    host = f"[{address}]" if ":" in address and not address.startswith("[") else address
    return f"https://{host}:{DEFAULT_PORT}"


class SiteAdministration:
    """Bounded in-memory main-node transaction state for Mac administration."""

    def __init__(
        self,
        identity: SiteIdentity,
        *,
        move_apply: MoveApply = apply_prepared_move,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if identity.role != "main":
            raise AdministrationError("node administration is main-only")
        self.identity = identity
        self.move_apply = move_apply
        self.clock = clock
        self._moves: dict[str, tuple[str, PreparedMove]] = {}
        self._lock = threading.Lock()

    def _prune(self) -> None:
        now = int(self.clock())
        for move_id, (_, prepared) in list(self._moves.items()):
            if prepared.expires_at_unix < now:
                self._moves.pop(move_id, None)

    def perform(
        self,
        *,
        controller_id: str,
        action: str,
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        if not ID_RE.fullmatch(controller_id):
            raise AdministrationError("controller identity is invalid")
        if not isinstance(payload, Mapping):
            raise AdministrationError("administrator request must be an object")
        if action == "node.move.plan":
            if payload:
                raise AdministrationError("node move plan does not accept arguments")
            with SiteStore(identity=self.identity) as store:
                plan = plan_local_move(store).document()
                store.record_action(
                    "node.move.plan",
                    self.identity.site_id,
                    "success",
                    actor_type="controller",
                    actor_id=controller_id,
                    origin_interface="controller-api",
                )
                return {"plan": plan}
        if action == "child.invite":
            return self._invite(controller_id, payload)
        if action == "child.adopt":
            return self._adopt(controller_id, payload)
        if action == "child.approve":
            return self._approve(controller_id, payload)
        if action == "child.cancel":
            return self._cancel_member(controller_id, payload)
        if action == "child.drain":
            return self._set_member_draining(controller_id, payload, True)
        if action == "child.resume":
            return self._set_member_draining(controller_id, payload, False)
        if action == "child.remove":
            return self._remove_member(controller_id, payload)
        if action == "key.list":
            return self._list_keys(controller_id, payload)
        if action == "key.show":
            return self._show_key(controller_id, payload)
        if action == "key.create":
            return self._create_key(controller_id, payload)
        if action == "key.rotate":
            return self._rotate_key(controller_id, payload)
        if action == "key.revoke":
            return self._revoke_key(controller_id, payload)
        if action == "key.policy":
            return self._update_key_policy(controller_id, payload)
        if action == "node.move.prepare":
            return self._prepare_move(controller_id, payload)
        if action == "node.move.commit":
            return self._commit_move(controller_id, payload)
        if action == "node.move.cancel":
            return self._cancel_move(controller_id, payload)
        raise AdministrationError("administrator action is not supported")

    @staticmethod
    def _key_reference(payload: Mapping[str, Any]) -> str:
        if set(payload) != {"key"}:
            raise AdministrationError("API key request schema is invalid")
        reference = payload.get("key")
        if (
            not isinstance(reference, str)
            or not reference
            or len(reference) > 128
            or re.fullmatch(r"[a-z0-9][a-z0-9._-]*", reference) is None
        ):
            raise AdministrationError("API key reference is invalid")
        return reference

    @staticmethod
    def _key_policy(payload: Mapping[str, Any]) -> dict[str, Any]:
        models = payload.get("models")
        if (
            not isinstance(models, list)
            or len(models) > 128
            or any(not isinstance(item, str) for item in models)
        ):
            raise AdministrationError("API key model policy is invalid")
        integers = (
            "expires_at_unix",
            "requests_per_minute",
            "tokens_per_minute",
            "concurrency_limit",
            "context_limit",
        )
        for field in integers:
            value = payload.get(field)
            if value is not None and (
                not isinstance(value, int) or isinstance(value, bool) or value <= 0
            ):
                raise AdministrationError(f"API key {field} is invalid")
        for field in ("tenant", "application"):
            value = payload.get(field)
            if value is not None and (
                not isinstance(value, str)
                or not value
                or len(value.encode("utf-8")) > 128
            ):
                raise AdministrationError(f"API key {field} is invalid")
        return {field: payload.get(field) for field in KEY_POLICY_FIELDS}

    def _list_keys(
        self, controller_id: str, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        if payload:
            raise AdministrationError("API key list does not accept arguments")
        with SiteStore(identity=self.identity) as store:
            values = store.keys()
            store.record_action(
                "key.list",
                "api-keys",
                "success",
                actor_type="controller",
                actor_id=controller_id,
                origin_interface="controller-api",
            )
        return {"keys": values}

    def _show_key(
        self, controller_id: str, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        reference = self._key_reference(payload)
        try:
            with SiteStore(identity=self.identity) as store:
                value = store.key(reference)
                store.record_action(
                    "key.show",
                    value["key_id"],
                    "success",
                    actor_type="controller",
                    actor_id=controller_id,
                    origin_interface="controller-api",
                )
        except SiteError as error:
            raise AdministrationError(str(error)) from error
        return {"key": value}

    def _create_key(
        self, controller_id: str, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        if set(payload) != KEY_POLICY_FIELDS | {"name"}:
            raise AdministrationError("API key creation schema is invalid")
        name = payload.get("name")
        if not isinstance(name, str):
            raise AdministrationError("API key name is invalid")
        policy = self._key_policy(payload)
        correlation = uuid.uuid4().hex
        try:
            with SiteStore(identity=self.identity) as store:
                value, token = store.create_key(
                    name,
                    **policy,
                    actor_type="controller",
                    actor_id=controller_id,
                    origin_interface="controller-api",
                    correlation_id=correlation,
                )
        except SiteError as error:
            raise AdministrationError(str(error)) from error
        return {"key": value, "token": token}

    def _rotate_key(
        self, controller_id: str, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        reference = self._key_reference(payload)
        correlation = uuid.uuid4().hex
        try:
            with SiteStore(identity=self.identity) as store:
                value, token = store.rotate_key(
                    reference,
                    actor_type="controller",
                    actor_id=controller_id,
                    origin_interface="controller-api",
                    correlation_id=correlation,
                )
        except SiteError as error:
            raise AdministrationError(str(error)) from error
        return {"key": value, "token": token}

    def _revoke_key(
        self, controller_id: str, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        reference = self._key_reference(payload)
        correlation = uuid.uuid4().hex
        try:
            with SiteStore(identity=self.identity) as store:
                value = store.revoke_key(
                    reference,
                    actor_type="controller",
                    actor_id=controller_id,
                    origin_interface="controller-api",
                    correlation_id=correlation,
                )
        except SiteError as error:
            raise AdministrationError(str(error)) from error
        return {"key": value}

    def _update_key_policy(
        self, controller_id: str, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        if set(payload) != KEY_POLICY_FIELDS | {"key"}:
            raise AdministrationError("API key policy schema is invalid")
        reference = self._key_reference({"key": payload.get("key")})
        policy = self._key_policy(payload)
        correlation = uuid.uuid4().hex
        try:
            with SiteStore(identity=self.identity) as store:
                value = store.update_key_policy(
                    reference,
                    **policy,
                    actor_type="controller",
                    actor_id=controller_id,
                    origin_interface="controller-api",
                    correlation_id=correlation,
                )
        except SiteError as error:
            raise AdministrationError(str(error)) from error
        return {"key": value}

    def _remove_member(
        self, controller_id: str, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        if set(payload) != {"member_id"}:
            raise AdministrationError("member removal schema is invalid")
        member_id = payload.get("member_id")
        if not isinstance(member_id, str) or not ID_RE.fullmatch(member_id):
            raise AdministrationError("member removal identity is invalid")
        try:
            with SiteStore(identity=self.identity) as store:
                result = store.remove_member(
                    member_id,
                    actor_type="controller",
                    actor_id=controller_id,
                    origin_interface="controller-api",
                    correlation_id=uuid.uuid4().hex,
                )
        except SiteError as error:
            raise AdministrationError(str(error)) from error
        return {"membership": result}

    def _set_member_draining(
        self,
        controller_id: str,
        payload: Mapping[str, Any],
        draining: bool,
    ) -> dict[str, Any]:
        if set(payload) != {"member_id"}:
            raise AdministrationError("member routing-state schema is invalid")
        member_id = payload.get("member_id")
        if not isinstance(member_id, str) or not ID_RE.fullmatch(member_id):
            raise AdministrationError("member routing-state identity is invalid")
        try:
            with SiteStore(identity=self.identity) as store:
                result = store.set_member_draining(
                    member_id,
                    draining,
                    actor_type="controller",
                    actor_id=controller_id,
                    origin_interface="controller-api",
                    correlation_id=uuid.uuid4().hex,
                )
        except SiteError as error:
            raise AdministrationError(str(error)) from error
        return {"membership": result}

    def _invite(
        self, controller_id: str, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        expected = {
            "mode",
            "expires_in",
            "candidate_public_key_sha256",
            "direct_interface",
            "candidate_endpoint",
        }
        if set(payload) != expected:
            raise AdministrationError("member invite schema is invalid")
        mode = payload.get("mode")
        expires = payload.get("expires_in")
        if mode not in {"lan", "remote", "connectx"}:
            raise AdministrationError("member invite mode is invalid")
        if not isinstance(expires, int) or isinstance(expires, bool):
            raise AdministrationError("member invite expiry is invalid")
        candidate = payload.get("candidate_public_key_sha256")
        interface = payload.get("direct_interface")
        candidate_endpoint = payload.get("candidate_endpoint")
        direct_link = None
        if mode == "connectx":
            if not isinstance(candidate, str) or not SHA256_RE.fullmatch(candidate):
                raise AdministrationError("ConnectX invite candidate is invalid")
            if not isinstance(interface, str):
                raise AdministrationError("ConnectX invite interface is invalid")
            try:
                direct_link = (
                    select_direct_connectx_interface()
                    if interface == "auto"
                    else verify_direct_connectx_interface(interface)
                )
            except InventoryError as error:
                raise AdministrationError(str(error)) from error
            interface = direct_link["interface"]
            if not isinstance(candidate_endpoint, str):
                raise AdministrationError("ConnectX invite candidate endpoint is invalid")
            try:
                peer_address = resolve_direct_peer(candidate_endpoint, interface)
                direct_link = verify_direct_connectx_peer(interface, peer_address)
            except (AdoptionError, InventoryError) as error:
                raise AdministrationError(str(error)) from error
            if not isinstance(direct_link.get("local_address"), str):
                raise AdministrationError(
                    "ConnectX route does not declare a local endpoint address"
                )
        elif candidate is not None or interface is not None or candidate_endpoint is not None:
            raise AdministrationError("code-based invite cannot bind a direct link")
        correlation = uuid.uuid4().hex
        try:
            with SiteStore(identity=self.identity) as store:
                invite = store.create_invite(
                    str(mode),
                    candidate_public_key_sha256=(
                        str(candidate) if candidate is not None else None
                    ),
                    direct_interface=(str(interface) if interface is not None else None),
                    lifetime_seconds=expires,
                    actor_type="controller",
                    actor_id=controller_id,
                    origin_interface="controller-api",
                    correlation_id=correlation,
                )
        except SiteError as error:
            raise AdministrationError(str(error)) from error
        invite["endpoint"] = _endpoint(
            direct_link["local_address"]
            if direct_link is not None
            else self.identity.coordinator_address
        )
        invite["main_certificate_sha256"] = _certificate_sha256()
        if direct_link is not None:
            invite["direct_link"] = direct_link
        return {"invite": invite}

    def _adopt(
        self, controller_id: str, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        expected = {
            "source_endpoint",
            "source_site_id",
            "source_member_id",
            "source_public_key_sha256",
            "source_certificate_sha256",
        }
        if set(payload) != expected:
            raise AdministrationError("fresh-member adoption schema is invalid")
        for field in ("source_site_id", "source_member_id"):
            if not isinstance(payload.get(field), str) or not ID_RE.fullmatch(
                payload[field]
            ):
                raise AdministrationError(f"fresh-member {field} is invalid")
        for field in ("source_public_key_sha256", "source_certificate_sha256"):
            if not isinstance(payload.get(field), str) or not SHA256_RE.fullmatch(
                payload[field]
            ):
                raise AdministrationError(f"fresh-member {field} is invalid")
        source_endpoint = payload.get("source_endpoint")
        if not isinstance(source_endpoint, str):
            raise AdministrationError("fresh-member endpoint is invalid")
        if payload["source_site_id"] == self.identity.site_id:
            raise AdministrationError("fresh member already belongs to this site")
        correlation = uuid.uuid4().hex
        try:
            invite = self._invite(
                controller_id,
                {
                    "mode": "connectx",
                    "expires_in": 180,
                    "candidate_public_key_sha256": payload[
                        "source_public_key_sha256"
                    ],
                    "direct_interface": "auto",
                    "candidate_endpoint": source_endpoint,
                },
            )["invite"]
            direct_link = invite.get("direct_link")
            if not isinstance(direct_link, Mapping) or not isinstance(
                direct_link.get("peer_address"), str
            ):
                raise AdministrationError("fresh-member direct route is unavailable")
            response = request_adoption(
                source_endpoint=source_endpoint,
                source_site_id=payload["source_site_id"],
                source_member_id=payload["source_member_id"],
                source_public_key_sha256=payload["source_public_key_sha256"],
                source_certificate_sha256=payload["source_certificate_sha256"],
                destination=self.identity,
                invite=invite,
                source_member_address=direct_link["peer_address"],
            )
            with SiteStore(identity=self.identity) as store:
                store.record_action(
                    "child.adopt",
                    payload["source_member_id"],
                    "success",
                    actor_type="controller",
                    actor_id=controller_id,
                    origin_interface="controller-api",
                    correlation_id=correlation,
                )
        except (AdoptionError, AdministrationError, InventoryError, SiteError) as error:
            try:
                with SiteStore(identity=self.identity) as store:
                    store.record_action(
                        "child.adopt",
                        str(payload.get("source_member_id", "unknown")),
                        "failed",
                        type(error).__name__,
                        actor_type="controller",
                        actor_id=controller_id,
                        origin_interface="controller-api",
                        correlation_id=correlation,
                    )
            except SiteError as audit_error:
                raise AdministrationError(
                    "fresh-member adoption failed and its audit could not be recorded"
                ) from audit_error
            raise AdministrationError(str(error)) from error
        return {"adoption": response}

    def _approve(
        self, controller_id: str, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        if set(payload) != {"member_id", "comparison_code"}:
            raise AdministrationError("member approval schema is invalid")
        member_id = payload.get("member_id")
        comparison_code = payload.get("comparison_code")
        if not isinstance(member_id, str) or not ID_RE.fullmatch(member_id):
            raise AdministrationError("member approval identity is invalid")
        if not isinstance(comparison_code, str):
            raise AdministrationError("member comparison code is invalid")
        correlation = uuid.uuid4().hex
        try:
            with SiteStore(identity=self.identity) as store:
                result = store.approve_member(
                    member_id,
                    comparison_code,
                    actor_type="controller",
                    actor_id=controller_id,
                    origin_interface="controller-api",
                    correlation_id=correlation,
                )
        except SiteError as error:
            raise AdministrationError(str(error)) from error
        return {"membership": result}

    def _prepare_move(
        self, controller_id: str, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        expected = {
            "source_site_id",
            "endpoint",
            "invite_id",
            "code",
            "main_certificate_sha256",
            "member_name",
            "member_address",
        }
        if set(payload) != expected:
            raise AdministrationError("node move preparation schema is invalid")
        if payload.get("source_site_id") != self.identity.site_id:
            raise AdministrationError("node move source identity changed")
        text_fields = (
            "endpoint",
            "invite_id",
            "main_certificate_sha256",
            "member_name",
            "member_address",
        )
        if any(not isinstance(payload.get(field), str) for field in text_fields):
            raise AdministrationError("node move preparation value is invalid")
        code = payload.get("code")
        if code is not None and not isinstance(code, str):
            raise AdministrationError("node move child code is invalid")
        try:
            prepared = prepare_local_move(
                endpoint=str(payload["endpoint"]),
                invite_id=str(payload["invite_id"]),
                code=code,
                coordinator_certificate_sha256=str(
                    payload["main_certificate_sha256"]
                ),
                member_name=str(payload["member_name"]),
                member_address=str(payload["member_address"]),
            )
        except SiteError as error:
            raise AdministrationError(str(error)) from error
        with self._lock:
            self._prune()
            if len(self._moves) >= MAX_PREPARED_MOVES:
                raise AdministrationError("prepared node move limit reached")
            self._moves[prepared.move_id] = (controller_id, prepared)
        with SiteStore(identity=self.identity) as store:
            store.record_action(
                "node.move.prepare",
                prepared.package.document["site_id"],
                "success",
                actor_type="controller",
                actor_id=controller_id,
                origin_interface="controller-api",
                correlation_id=prepared.move_id,
            )
        return {"move": prepared.document()}

    def _cancel_member(
        self, controller_id: str, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        if set(payload) != {"member_id"}:
            raise AdministrationError("prepared member cancellation schema is invalid")
        member_id = payload.get("member_id")
        if not isinstance(member_id, str) or not ID_RE.fullmatch(member_id):
            raise AdministrationError("prepared member identity is invalid")
        try:
            with SiteStore(identity=self.identity) as store:
                row = next(
                    (item for item in store.members() if item["member_id"] == member_id),
                    None,
                )
                if row is None or row["state"] not in {"pending", "active"}:
                    raise SiteError("member is not a cancellable prepared enrollment")
                result = store.remove_member(
                    member_id,
                    actor_type="controller",
                    actor_id=controller_id,
                    origin_interface="controller-api",
                )
        except SiteError as error:
            raise AdministrationError(str(error)) from error
        return {"membership": result}

    def _cancel_move(
        self, controller_id: str, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        if set(payload) != {"move_id"}:
            raise AdministrationError("node move cancellation schema is invalid")
        move_id = payload.get("move_id")
        if not isinstance(move_id, str) or not ID_RE.fullmatch(move_id):
            raise AdministrationError("prepared node move identity is invalid")
        with self._lock:
            self._prune()
            record = self._moves.get(move_id)
            if record is None:
                raise AdministrationError("prepared node move is unknown or expired")
            owner, prepared = record
            if owner != controller_id:
                raise AdministrationError(
                    "prepared node move belongs to another controller"
                )
            self._moves.pop(move_id, None)
        with SiteStore(identity=self.identity) as store:
            store.record_action(
                "node.move.cancel",
                prepared.package.document["site_id"],
                "success",
                actor_type="controller",
                actor_id=controller_id,
                origin_interface="controller-api",
                correlation_id=move_id,
            )
        return {"move": {"move_id": move_id, "state": "cancelled"}}

    def _commit_move(
        self, controller_id: str, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        if set(payload) != {"move_id"}:
            raise AdministrationError("node move commit schema is invalid")
        move_id = payload.get("move_id")
        if not isinstance(move_id, str) or not ID_RE.fullmatch(move_id):
            raise AdministrationError("prepared node move identity is invalid")
        with self._lock:
            self._prune()
            record = self._moves.get(move_id)
        if record is None:
            raise AdministrationError("prepared node move is unknown or expired")
        owner, prepared = record
        if owner != controller_id:
            raise AdministrationError("prepared node move belongs to another controller")
        try:
            replacement = self.move_apply(prepared)
        except SiteError as error:
            raise AdministrationError(str(error)) from error
        with self._lock:
            self._moves.pop(move_id, None)
        return {
            "move": {
                "schema_version": 1,
                "move_id": move_id,
                "source_site_id": prepared.source.site_id,
                "destination_site_id": replacement.site_id,
                "member_id": replacement.member_id,
                "state": "committed",
            }
        }
