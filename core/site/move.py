#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Explicit, rollback-safe replacement of one local site membership."""

from __future__ import annotations

import dataclasses
import json
import pathlib
import shutil
import time
import uuid
from collections.abc import Callable
from typing import Any

from .control import (
    ControlError,
    EnrollmentPackage,
    fetch_candidate_membership,
    install_membership,
    request_membership,
)

from .state import (
    SiteError,
    SiteIdentity,
    SiteStore,
    config_root,
    data_root,
    identity_path,
    member_key_path,
    member_public_key_path,
    pending_installation_path,
    read_identity,
    secrets_root,
    existing_member_identity,
    _private_file,
)


@dataclasses.dataclass(frozen=True)
class MovePlan:
    source_site_id: str
    source_member_id: str
    destination_effect: str
    member_count: int
    controller_count: int
    api_key_count: int
    placement_count: int
    active_placements: tuple[dict[str, Any], ...]
    blocking_reasons: tuple[str, ...]
    preserved_data: tuple[str, ...]
    reset_state: tuple[str, ...]

    def document(self) -> dict[str, Any]:
        value = dataclasses.asdict(self)
        for field in (
            "active_placements", "blocking_reasons", "preserved_data", "reset_state"
        ):
            value[field] = list(value[field])
        return value


@dataclasses.dataclass(frozen=True)
class PreparedMove:
    """One bounded, verified destination enrollment awaiting local commit."""

    move_id: str
    source: SiteIdentity
    plan: MovePlan
    destination_endpoint: str
    coordinator_certificate_sha256: str
    package: EnrollmentPackage
    created_at_unix: int
    expires_at_unix: int

    def document(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "move_id": self.move_id,
            "source_site_id": self.source.site_id,
            "destination_site_id": self.package.document["site_id"],
            "member_id": self.source.member_id,
            "membership_state": self.package.state,
            "comparison_code": self.package.comparison_code,
            "created_at_unix": self.created_at_unix,
            "expires_at_unix": self.expires_at_unix,
            "plan": self.plan.document(),
        }


def plan_local_move(store: SiteStore) -> MovePlan:
    """Describe the exact local effects without mutating either site."""
    members = store.members()
    placements = [
        dict(row)
        for row in store.connection.execute(
            "SELECT placement_id,model,runtime,target,strategy,state FROM placements "
            "WHERE state IN ('starting','running','draining') ORDER BY placement_id"
        )
    ]
    blockers: list[str] = []
    if len(members) != 1 or members[0]["member_id"] != store.identity.member_id:
        blockers.append(
            "the coordinator must transfer or remove every other source-site member first"
        )
    if placements:
        blockers.append("all source-site placements must be stopped before the move")
    controllers = store.connection.execute(
        "SELECT COUNT(*) FROM controllers WHERE revoked_at_unix IS NULL"
    ).fetchone()[0]
    keys = store.connection.execute(
        "SELECT COUNT(*) FROM api_keys WHERE revoked_at_unix IS NULL"
    ).fetchone()[0]
    return MovePlan(
        source_site_id=store.identity.site_id,
        source_member_id=store.identity.member_id,
        destination_effect="replace-local-site-membership",
        member_count=len(members),
        controller_count=int(controllers),
        api_key_count=int(keys),
        placement_count=len(placements),
        active_placements=tuple(placements),
        blocking_reasons=tuple(blockers),
        preserved_data=(
            "physical member key and member id",
            "installation id and installation timestamp",
            "model artifacts",
            "immutable runtime objects",
            "engine image layers",
            "prefix and runtime caches",
        ),
        reset_state=(
            "source site private key and certificates",
            "source controller and API credentials",
            "source SQLite authority and audit chain",
            "source gateway and Watchdog state",
            "source runtime service configuration",
        ),
    )


def prepare_local_move(
    *,
    endpoint: str,
    invite_id: str,
    code: str | None,
    coordinator_certificate_sha256: str,
    member_name: str,
    member_address: str,
    now_unix: int | None = None,
) -> PreparedMove:
    """Enroll the preserved physical identity without replacing local state yet."""
    source = read_identity()
    if source.role != "main":
        raise SiteError("only a coordinator can move its machine into another site")
    with SiteStore(identity=source) as store:
        plan = plan_local_move(store)
    if plan.blocking_reasons:
        raise SiteError("node move is blocked: " + "; ".join(plan.blocking_reasons))
    try:
        package = request_membership(
            endpoint,
            invite_id=invite_id,
            code=code,
            coordinator_certificate_sha256=coordinator_certificate_sha256,
            member_name=member_name,
            member_address=member_address,
            candidate=existing_member_identity(source),
        )
    except ControlError as error:
        raise SiteError(str(error)) from error
    if package.document.get("site_id") == source.site_id:
        raise SiteError("node move destination is the current node")
    if (
        package.document.get("member_id") != source.member_id
        or package.document.get("installation_id") != source.installation_id
        or package.document.get("installation_created_at_unix")
        != source.created_at_unix
        or package.document.get("member_public_key_sha256")
        != source.member_public_key_sha256
    ):
        raise SiteError("prepared node move changed the physical installation identity")
    now = int(time.time()) if now_unix is None else now_unix
    remote_expiry = package.approval_expires_at_unix
    expires = min(now + 600, remote_expiry) if remote_expiry is not None else now + 600
    if expires <= now:
        raise SiteError("prepared node move already expired")
    return PreparedMove(
        move_id=uuid.uuid4().hex,
        source=source,
        plan=plan,
        destination_endpoint=endpoint,
        coordinator_certificate_sha256=coordinator_certificate_sha256,
        package=package,
        created_at_unix=now,
        expires_at_unix=expires,
    )


def apply_prepared_move(
    prepared: PreparedMove,
    *,
    now_unix: int | None = None,
    before_transaction: Callable[[], None] | None = None,
    before_commit: Callable[[SiteIdentity], None] | None = None,
) -> SiteIdentity:
    """Verify destination approval, then atomically replace local site authority."""
    now = int(time.time()) if now_unix is None else now_unix
    if now > prepared.expires_at_unix:
        raise SiteError("prepared node move expired")
    current = read_identity()
    if current != prepared.source:
        raise SiteError("source site identity changed after move preparation")
    with SiteStore(identity=current) as store:
        current_plan = plan_local_move(store)
    if current_plan.document() != prepared.plan.document():
        raise SiteError("source site state changed after move preparation")
    try:
        membership = fetch_candidate_membership(
            prepared.destination_endpoint,
            package=prepared.package,
            coordinator_certificate_sha256=prepared.coordinator_certificate_sha256,
        )
    except ControlError as error:
        raise SiteError(str(error)) from error
    if membership["state"] != "active":
        raise SiteError("destination membership has not been approved")
    if before_transaction is not None:
        before_transaction()
    with LocalMoveTransaction(current) as transaction:
        try:
            enrollment = install_membership(prepared.package)
        except ControlError as error:
            raise SiteError(str(error)) from error
        if enrollment.identity.site_id != membership["site_id"]:
            raise SiteError("installed membership destination changed")
        if before_commit is not None:
            before_commit(enrollment.identity)
        return transaction.commit()


class LocalMoveTransaction:
    """Stage a local site replacement and restore exact state unless committed."""

    _DATA_NAMES = (
        "site.sqlite3",
        "site.sqlite3-wal",
        "site.sqlite3-shm",
        "gateway",
        "watchdog/data-v1",
        "site-links.json",
    )

    def __init__(self, source: SiteIdentity) -> None:
        if source.role != "main":
            raise SiteError("only a coordinator can move its machine into another site")
        self.source = source
        self.config = config_root()
        self.secrets = secrets_root()
        self.data = data_root()
        token = uuid.uuid4().hex
        self.config_backup = self.config.parent / f".{self.config.name}.site-move-{token}"
        self.secrets_backup = self.secrets.parent / f".{self.secrets.name}.site-move-{token}"
        self.data_backup = self.data / f".site-move-{token}"
        self.committed = False
        self.started = False

    def __enter__(self) -> "LocalMoveTransaction":
        if self.config.is_symlink() or not self.config.is_dir():
            raise SiteError("site configuration root is unsafe")
        if self.secrets.is_symlink() or not self.secrets.is_dir():
            raise SiteError("site secrets root is unsafe")
        if (
            self.config_backup.exists()
            or self.secrets_backup.exists()
            or self.data_backup.exists()
        ):
            raise SiteError("node move staging path already exists")
        member_key = _private_file(member_key_path(), minimum_bytes=128)
        member_public = _private_file(member_public_key_path(), minimum_bytes=128)
        self.config.rename(self.config_backup)
        try:
            self.secrets.rename(self.secrets_backup)
            self.config.mkdir(mode=0o700)
            self.secrets.mkdir(mode=0o700)
            for root, name, payload in (
                (self.secrets, "member.key", member_key),
                (self.config, "member.pub", member_public),
                (
                    self.config,
                    "member-id",
                    (self.source.member_id + "\n").encode("ascii"),
                ),
                (
                    self.config,
                    pending_installation_path().name,
                    (
                        json.dumps(
                            {
                                "installation_id": self.source.installation_id,
                                "created_at_unix": self.source.created_at_unix,
                            },
                            sort_keys=True,
                            separators=(",", ":"),
                        )
                        + "\n"
                    ).encode("ascii"),
                ),
            ):
                destination = root / name
                destination.write_bytes(payload)
                destination.chmod(0o600)
            self.data.mkdir(mode=0o700, parents=True, exist_ok=True)
            self.data_backup.mkdir(mode=0o700)
            for relative in self._DATA_NAMES:
                source = self.data / relative
                if not source.exists():
                    continue
                if source.is_symlink():
                    raise SiteError(f"node move state cannot be a symlink: {source}")
                destination = self.data_backup / relative
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                source.rename(destination)
        except BaseException:
            self._restore()
            raise
        self.started = True
        return self

    def commit(self) -> SiteIdentity:
        if not self.started:
            raise SiteError("node move transaction has not started")
        replacement = read_identity()
        if replacement.role != "child":
            raise SiteError("node move destination did not install a child identity")
        if replacement.site_id == self.source.site_id:
            raise SiteError("node move destination is the current node")
        if (
            replacement.member_id != self.source.member_id
            or replacement.installation_id != self.source.installation_id
            or replacement.created_at_unix != self.source.created_at_unix
            or replacement.member_public_key_sha256
            != self.source.member_public_key_sha256
        ):
            raise SiteError("node move changed the physical installation identity")
        self.committed = True
        shutil.rmtree(self.config_backup)
        shutil.rmtree(self.secrets_backup)
        shutil.rmtree(self.data_backup)
        return replacement

    def _restore(self) -> None:
        if self.config_backup.exists():
            if self.config.exists():
                shutil.rmtree(self.config)
            self.config_backup.rename(self.config)
        if self.secrets_backup.exists():
            if self.secrets.exists():
                shutil.rmtree(self.secrets)
            self.secrets_backup.rename(self.secrets)
        if self.data_backup.exists():
            for relative in self._DATA_NAMES:
                current = self.data / relative
                if current.exists():
                    if current.is_dir() and not current.is_symlink():
                        shutil.rmtree(current)
                    else:
                        current.unlink()
                staged = self.data_backup / relative
                if staged.exists():
                    current.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    staged.rename(current)
            shutil.rmtree(self.data_backup)

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if not self.committed:
            self._restore()
