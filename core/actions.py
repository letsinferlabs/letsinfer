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
        _action("setup", CommandScope.ALL, MutationClass.NODE, AuditPolicy.ALWAYS, requires_site=False),
        _action("node.status", CommandScope.ALL, MutationClass.READ, AuditPolicy.NONE),
        _action("node.move", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action("hardware", CommandScope.ALL, MutationClass.READ, AuditPolicy.NONE, requires_site=False),
        _action("update", CommandScope.ALL, MutationClass.LOCAL, AuditPolicy.SUCCESS, requires_site=False),
        _action("update.check", CommandScope.ALL, MutationClass.READ, AuditPolicy.NONE, requires_site=False),
        _action("topology.show", CommandScope.MAIN, MutationClass.READ, AuditPolicy.SENSITIVE_READ),
        _action("topology.probe", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action("topology.plan", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action("list", CommandScope.ALL, MutationClass.READ, AuditPolicy.NONE, requires_site=False),
        _action("runtimes", CommandScope.ALL, MutationClass.READ, AuditPolicy.NONE),
        _action("pack", CommandScope.ALL, MutationClass.LOCAL, AuditPolicy.SUCCESS, requires_site=False),
        _action("inspect", CommandScope.ALL, MutationClass.READ, AuditPolicy.NONE, requires_site=False),
        _action("upgrade", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action("rollback", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action("verify", CommandScope.ALL, MutationClass.READ, AuditPolicy.NONE),
        _action("acquire", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action("benchmark", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action("install", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action("scale", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action("serve", CommandScope.ALL, MutationClass.LOCAL, AuditPolicy.ALWAYS),
        _action("status", CommandScope.ALL, MutationClass.READ, AuditPolicy.NONE),
        _action("doctor", CommandScope.ALL, MutationClass.READ, AuditPolicy.NONE),
        _action("logs", CommandScope.ALL, MutationClass.READ, AuditPolicy.SENSITIVE_READ),
        _action("start", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action("restart", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action("recover", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action("stop", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action(
            "uninstall",
            CommandScope.MAIN,
            MutationClass.NODE,
            AuditPolicy.ALWAYS,
            requires_site=False,
        ),
        _action("exposure.status", CommandScope.MAIN, MutationClass.READ, AuditPolicy.NONE),
        _action("expose", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action("unexpose", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action("pair", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action("controllers.list", CommandScope.MAIN, MutationClass.READ, AuditPolicy.SENSITIVE_READ),
        _action("controllers.forget", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action("key.create", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action("key.list", CommandScope.MAIN, MutationClass.READ, AuditPolicy.SENSITIVE_READ),
        _action("key.show", CommandScope.MAIN, MutationClass.READ, AuditPolicy.SENSITIVE_READ),
        _action("key.rotate", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action("key.revoke", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action("key.policy", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action("audit.list", CommandScope.MAIN, MutationClass.READ, AuditPolicy.SENSITIVE_READ),
        _action("audit.show", CommandScope.MAIN, MutationClass.READ, AuditPolicy.SENSITIVE_READ),
        _action("audit.verify", CommandScope.MAIN, MutationClass.READ, AuditPolicy.SENSITIVE_READ),
        _action("audit.export", CommandScope.MAIN, MutationClass.READ, AuditPolicy.SENSITIVE_READ),
        _action("child.list", CommandScope.ALL, MutationClass.READ, AuditPolicy.NONE),
        _action("child.prepare", CommandScope.ALL, MutationClass.LOCAL, AuditPolicy.NONE, requires_site=False),
        _action("child.join", CommandScope.CHILD, MutationClass.LOCAL, AuditPolicy.NONE, requires_site=False),
        _action("child.invite", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action("child.approve", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action("child.sync", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action("child.drain", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action("child.resume", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action("child.remove", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action("alias.list", CommandScope.ALL, MutationClass.READ, AuditPolicy.NONE),
        _action("alias.set", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action("alias.remove", CommandScope.MAIN, MutationClass.NODE, AuditPolicy.ALWAYS),
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
        if item.mutation is MutationClass.NODE and item.scope is not CommandScope.MAIN \
                and item.name != "setup":
            raise ValueError(f"node mutation is not main-scoped: {item.name}")
        if item.mutation is MutationClass.NODE and item.audit is not AuditPolicy.ALWAYS:
            raise ValueError(f"node mutation is not mandatorily audited: {item.name}")


def help_label(text: str, action_name: str) -> str:
    metadata = action(action_name)
    return f"{text} [scope: {metadata.scope.value}]"
