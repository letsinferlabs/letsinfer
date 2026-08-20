#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Declarative command authorization for the Let's Infer CLI."""

from __future__ import annotations

import dataclasses
import enum
from collections.abc import Iterable


class CommandScope(str, enum.Enum):
    COORDINATOR = "coordinator"
    MEMBER = "member"
    ALL = "all"


class MutationClass(str, enum.Enum):
    READ = "read"
    NODE = "node"
    SITE = "site"
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
        _action("setup", CommandScope.ALL, MutationClass.SITE, AuditPolicy.ALWAYS, requires_site=False),
        _action("site.status", CommandScope.ALL, MutationClass.READ, AuditPolicy.NONE),
        _action("site.move", CommandScope.COORDINATOR, MutationClass.SITE, AuditPolicy.ALWAYS),
        _action("releases", CommandScope.ALL, MutationClass.READ, AuditPolicy.NONE),
        _action("engines", CommandScope.ALL, MutationClass.READ, AuditPolicy.NONE, requires_site=False),
        _action("hardware", CommandScope.ALL, MutationClass.READ, AuditPolicy.NONE, requires_site=False),
        _action("update", CommandScope.ALL, MutationClass.NODE, AuditPolicy.SUCCESS, requires_site=False),
        _action("update.check", CommandScope.ALL, MutationClass.READ, AuditPolicy.NONE, requires_site=False),
        _action("topology.show", CommandScope.COORDINATOR, MutationClass.READ, AuditPolicy.SENSITIVE_READ),
        _action("topology.probe", CommandScope.COORDINATOR, MutationClass.SITE, AuditPolicy.ALWAYS),
        _action("topology.plan", CommandScope.COORDINATOR, MutationClass.SITE, AuditPolicy.ALWAYS),
        _action("runtimes", CommandScope.ALL, MutationClass.READ, AuditPolicy.NONE),
        _action("pack", CommandScope.ALL, MutationClass.NODE, AuditPolicy.SUCCESS, requires_site=False),
        _action("derive", CommandScope.COORDINATOR, MutationClass.SITE, AuditPolicy.ALWAYS),
        _action("inspect", CommandScope.ALL, MutationClass.READ, AuditPolicy.NONE, requires_site=False),
        _action("upgrade", CommandScope.COORDINATOR, MutationClass.SITE, AuditPolicy.ALWAYS),
        _action("rollback", CommandScope.COORDINATOR, MutationClass.SITE, AuditPolicy.ALWAYS),
        _action("verify", CommandScope.ALL, MutationClass.READ, AuditPolicy.NONE),
        _action("acquire", CommandScope.COORDINATOR, MutationClass.SITE, AuditPolicy.ALWAYS),
        _action("benchmark", CommandScope.COORDINATOR, MutationClass.SITE, AuditPolicy.ALWAYS),
        _action("install", CommandScope.COORDINATOR, MutationClass.SITE, AuditPolicy.ALWAYS),
        _action("serve", CommandScope.ALL, MutationClass.NODE, AuditPolicy.ALWAYS),
        _action("status", CommandScope.ALL, MutationClass.READ, AuditPolicy.NONE),
        _action("doctor", CommandScope.ALL, MutationClass.READ, AuditPolicy.NONE),
        _action("logs", CommandScope.ALL, MutationClass.READ, AuditPolicy.SENSITIVE_READ),
        _action("start", CommandScope.COORDINATOR, MutationClass.SITE, AuditPolicy.ALWAYS),
        _action("restart", CommandScope.COORDINATOR, MutationClass.SITE, AuditPolicy.ALWAYS),
        _action("recover", CommandScope.COORDINATOR, MutationClass.SITE, AuditPolicy.ALWAYS),
        _action("stop", CommandScope.COORDINATOR, MutationClass.SITE, AuditPolicy.ALWAYS),
        _action("uninstall", CommandScope.COORDINATOR, MutationClass.SITE, AuditPolicy.ALWAYS),
        _action("exposure.status", CommandScope.COORDINATOR, MutationClass.READ, AuditPolicy.NONE),
        _action("expose", CommandScope.COORDINATOR, MutationClass.SITE, AuditPolicy.ALWAYS),
        _action("unexpose", CommandScope.COORDINATOR, MutationClass.SITE, AuditPolicy.ALWAYS),
        _action("pair", CommandScope.COORDINATOR, MutationClass.SITE, AuditPolicy.ALWAYS),
        _action("controllers.list", CommandScope.COORDINATOR, MutationClass.READ, AuditPolicy.SENSITIVE_READ),
        _action("controllers.forget", CommandScope.COORDINATOR, MutationClass.SITE, AuditPolicy.ALWAYS),
        _action("key.create", CommandScope.COORDINATOR, MutationClass.SITE, AuditPolicy.ALWAYS),
        _action("key.list", CommandScope.COORDINATOR, MutationClass.READ, AuditPolicy.SENSITIVE_READ),
        _action("key.show", CommandScope.COORDINATOR, MutationClass.READ, AuditPolicy.SENSITIVE_READ),
        _action("key.rotate", CommandScope.COORDINATOR, MutationClass.SITE, AuditPolicy.ALWAYS),
        _action("key.revoke", CommandScope.COORDINATOR, MutationClass.SITE, AuditPolicy.ALWAYS),
        _action("key.policy", CommandScope.COORDINATOR, MutationClass.SITE, AuditPolicy.ALWAYS),
        _action("audit.list", CommandScope.COORDINATOR, MutationClass.READ, AuditPolicy.SENSITIVE_READ),
        _action("audit.show", CommandScope.COORDINATOR, MutationClass.READ, AuditPolicy.SENSITIVE_READ),
        _action("audit.verify", CommandScope.COORDINATOR, MutationClass.READ, AuditPolicy.SENSITIVE_READ),
        _action("audit.export", CommandScope.COORDINATOR, MutationClass.READ, AuditPolicy.SENSITIVE_READ),
        _action("member.list", CommandScope.ALL, MutationClass.READ, AuditPolicy.NONE),
        _action("member.prepare", CommandScope.ALL, MutationClass.NODE, AuditPolicy.NONE, requires_site=False),
        _action("member.join", CommandScope.MEMBER, MutationClass.NODE, AuditPolicy.NONE, requires_site=False),
        _action("member.invite", CommandScope.COORDINATOR, MutationClass.SITE, AuditPolicy.ALWAYS),
        _action("member.approve", CommandScope.COORDINATOR, MutationClass.SITE, AuditPolicy.ALWAYS),
        _action("member.sync", CommandScope.COORDINATOR, MutationClass.SITE, AuditPolicy.ALWAYS),
        _action("member.drain", CommandScope.COORDINATOR, MutationClass.SITE, AuditPolicy.ALWAYS),
        _action("member.resume", CommandScope.COORDINATOR, MutationClass.SITE, AuditPolicy.ALWAYS),
        _action("member.remove", CommandScope.COORDINATOR, MutationClass.SITE, AuditPolicy.ALWAYS),
        _action("alias.list", CommandScope.ALL, MutationClass.READ, AuditPolicy.NONE),
        _action("alias.set", CommandScope.COORDINATOR, MutationClass.SITE, AuditPolicy.ALWAYS),
        _action("alias.remove", CommandScope.COORDINATOR, MutationClass.SITE, AuditPolicy.ALWAYS),
        _action("service-start", CommandScope.ALL, MutationClass.INTERNAL, AuditPolicy.NONE),
        _action("service-stop", CommandScope.ALL, MutationClass.INTERNAL, AuditPolicy.NONE),
        _action("gateway", CommandScope.COORDINATOR, MutationClass.INTERNAL, AuditPolicy.NONE),
        _action("site-agent", CommandScope.ALL, MutationClass.INTERNAL, AuditPolicy.NONE),
        _action("core-rebind", CommandScope.ALL, MutationClass.INTERNAL, AuditPolicy.NONE, requires_site=False),
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
        if item.mutation is MutationClass.SITE and item.scope is not CommandScope.COORDINATOR \
                and item.name != "setup":
            raise ValueError(f"site mutation is not coordinator-scoped: {item.name}")
        if item.mutation is MutationClass.SITE and item.audit is not AuditPolicy.ALWAYS:
            raise ValueError(f"site mutation is not mandatorily audited: {item.name}")


def help_label(text: str, action_name: str) -> str:
    metadata = action(action_name)
    return f"{text} [scope: {metadata.scope.value}]"
