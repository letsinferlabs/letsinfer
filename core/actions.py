#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Declarative command authorization for the Let's Infer CLI."""

from __future__ import annotations

import dataclasses
import enum
from collections.abc import Iterable


class CommandScope(str, enum.Enum):
    MAIN = "main"
    CHILD = "child"
    ALL = "all"


class MutationClass(str, enum.Enum):
    READ = "read"
    LOCAL = "local"
    NODE = "node"
    INTERNAL = "internal"


class AuditPolicy(str, enum.Enum):
    NONE = "none"
    SUCCESS = "success"
    ALWAYS = "always"
    SENSITIVE_READ = "sensitive-read"


@dataclasses.dataclass(frozen=True)
class Action:
    name: str
    scope: CommandScope
    mutation: MutationClass
    audit: AuditPolicy
    requires_site: bool = True


def _action(
    name: str,
    scope: CommandScope,
    mutation: MutationClass,
    audit: AuditPolicy,
    *,
    requires_site: bool = True,
) -> Action:
    return Action(name, scope, mutation, audit, requires_site)


# Every parser leaf must bind one of these exact actions. There is deliberately
# no default scope and aliases are not registered.
ACTIONS = {
    action.name: action
    for action in (
        _action("status", CommandScope.ALL, MutationClass.READ, AuditPolicy.NONE),
        _action("topology", CommandScope.MAIN, MutationClass.READ, AuditPolicy.NONE),
        _action("doctor", CommandScope.ALL, MutationClass.READ, AuditPolicy.NONE),
        _action(
            "uninstall",
            CommandScope.MAIN,
            MutationClass.NODE,
            AuditPolicy.ALWAYS,
            requires_site=False,
        ),
        _action("node.info", CommandScope.ALL, MutationClass.READ, AuditPolicy.NONE),
        _action("node.list", CommandScope.ALL, MutationClass.READ, AuditPolicy.NONE),
        _action("node.add", CommandScope.ALL, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action("node.pause", CommandScope.ALL, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action("node.resume", CommandScope.ALL, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action("node.remove", CommandScope.ALL, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action(
            "model.list",
            CommandScope.ALL,
            MutationClass.READ,
            AuditPolicy.NONE,
            requires_site=False,
        ),
        _action("model.install", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action("model.remove", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action("model.pause", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action("model.resume", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action("model.restart", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action("model.recover", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action("model.rollback", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action("model.logs", CommandScope.ALL, MutationClass.READ, AuditPolicy.SENSITIVE_READ),
        _action("benchmark.run", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action("benchmark.list", CommandScope.MAIN, MutationClass.READ, AuditPolicy.NONE),
        _action("benchmark.status", CommandScope.MAIN, MutationClass.READ, AuditPolicy.NONE),
        _action("benchmark.stop", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action("benchmark.clean", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action(
            "benchmark.verification.run",
            CommandScope.MAIN,
            MutationClass.NODE,
            AuditPolicy.ALWAYS,
        ),
        _action(
            "benchmark.verification.status",
            CommandScope.MAIN,
            MutationClass.READ,
            AuditPolicy.NONE,
        ),
        _action(
            "benchmark.verification.stop",
            CommandScope.MAIN,
            MutationClass.NODE,
            AuditPolicy.ALWAYS,
        ),
        _action("auth.controller.add", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action(
            "auth.controller.list",
            CommandScope.MAIN,
            MutationClass.READ,
            AuditPolicy.SENSITIVE_READ,
        ),
        _action(
            "auth.controller.revoke",
            CommandScope.MAIN,
            MutationClass.NODE,
            AuditPolicy.ALWAYS,
        ),
        _action("auth.key.create", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action(
            "auth.key.list",
            CommandScope.MAIN,
            MutationClass.READ,
            AuditPolicy.SENSITIVE_READ,
        ),
        _action(
            "auth.key.show",
            CommandScope.MAIN,
            MutationClass.READ,
            AuditPolicy.SENSITIVE_READ,
        ),
        _action("auth.key.rotate", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action("auth.key.revoke", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action("auth.key.update", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action("exposure.status", CommandScope.MAIN, MutationClass.READ, AuditPolicy.NONE),
        _action("exposure.enable", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action("exposure.disable", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action("audit.list", CommandScope.MAIN, MutationClass.READ, AuditPolicy.SENSITIVE_READ),
        _action("audit.show", CommandScope.MAIN, MutationClass.READ, AuditPolicy.SENSITIVE_READ),
        _action("audit.verify", CommandScope.MAIN, MutationClass.READ, AuditPolicy.SENSITIVE_READ),
        _action("audit.export", CommandScope.MAIN, MutationClass.READ, AuditPolicy.SENSITIVE_READ),
        _action("update.check", CommandScope.ALL, MutationClass.READ, AuditPolicy.NONE, requires_site=False),
        _action("update.core", CommandScope.ALL, MutationClass.LOCAL, AuditPolicy.SUCCESS, requires_site=False),
        _action("update.model", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action(
            "core-setup",
            CommandScope.ALL,
            MutationClass.INTERNAL,
            AuditPolicy.NONE,
            requires_site=False,
        ),
        _action("service-start", CommandScope.ALL, MutationClass.INTERNAL, AuditPolicy.NONE),
        _action("service-stop", CommandScope.ALL, MutationClass.INTERNAL, AuditPolicy.NONE),
        _action("gateway", CommandScope.MAIN, MutationClass.INTERNAL, AuditPolicy.NONE),
        _action("node-agent", CommandScope.ALL, MutationClass.INTERNAL, AuditPolicy.NONE),
        _action("core-rebind", CommandScope.ALL, MutationClass.INTERNAL, AuditPolicy.NONE, requires_site=False),
        _action("core-prune", CommandScope.ALL, MutationClass.INTERNAL, AuditPolicy.NONE, requires_site=False),
    )
}


def action(name: str) -> Action:
    try:
        return ACTIONS[name]
    except KeyError as error:
        raise ValueError(f"unregistered command action: {name}") from error


def validate_registry(parser_actions: Iterable[str]) -> None:
    leaves = list(parser_actions)
    if len(leaves) != len(set(leaves)):
        raise ValueError("CLI parser contains duplicate action identifiers")
    unknown = sorted(set(leaves) - ACTIONS.keys())
    missing = sorted(ACTIONS.keys() - set(leaves))
    if unknown or missing:
        raise ValueError(
            "CLI action registry mismatch: "
            f"unregistered={unknown or '-'} unused={missing or '-'}"
        )
    for item in ACTIONS.values():
        if (
            item.mutation is MutationClass.NODE
            and item.scope is not CommandScope.MAIN
            and item.name not in {
                "node.add",
                "node.pause",
                "node.resume",
                "node.remove",
            }
        ):
            raise ValueError(f"node mutation is not main-scoped: {item.name}")
        if item.mutation is MutationClass.NODE and item.audit is not AuditPolicy.ALWAYS:
            raise ValueError(f"node mutation is not mandatorily audited: {item.name}")


def help_label(text: str, action_name: str) -> str:
    metadata = action(action_name)
    return f"{text} [scope: {metadata.scope.value}]"
