#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Fail-closed presentation contracts for every Let's Infer CLI action.

This module declares presentation policy only.  It deliberately does not
render output or infer a policy from an action's authorization metadata.  A
new CLI action must make every presentation decision explicitly before the
action registry and this registry can validate together.
"""

from __future__ import annotations

import dataclasses
import enum
from collections.abc import Mapping

from .actions import ACTIONS, Action, MutationClass


@enum.unique
class SurfaceKind(str, enum.Enum):
    """The interactive surface owned by one command."""

    FROZEN_STATUS = "frozen-status"
    LIST = "list"
    DETAIL = "detail"
    MUTATION = "mutation"
    WORKFLOW = "workflow"
    LIVE = "live"
    RAW = "raw"
    INTERNAL = "internal"


@enum.unique
class OutputContract(str, enum.Enum):
    """The durable result channel a presenter must preserve."""

    FROZEN_STATUS = "frozen-status"
    RECORD = "record"
    TABLE = "table"
    MUTATION_RESULT = "mutation-result"
    ARTIFACT_RESULT = "artifact-result"
    SENSITIVE_RESULT = "sensitive-result"
    ONE_TIME_SECRET = "one-time-secret"
    LIVE_DASHBOARD = "live-dashboard"
    RAW_STDOUT = "raw-stdout"
    INTERNAL = "internal"


@enum.unique
class ProgressKind(str, enum.Enum):
    """How an interactive command communicates ongoing work."""

    NONE = "none"
    SPINNER = "spinner"
    STEPS = "steps"
    LIVE = "live"
    PASSTHROUGH = "passthrough"


@enum.unique
class PromptKind(str, enum.Enum):
    """The kind of interactive decision or protected input a command owns."""

    NONE = "none"
    CONFIRM = "confirm"
    SECRET = "secret"
    WORKFLOW = "workflow"
    MIXED = "mixed"


@dataclasses.dataclass(frozen=True)
class UiContract:
    """One complete, explicit presentation contract for an action."""

    action_id: str
    title: str
    surface: SurfaceKind
    output: OutputContract
    progress: ProgressKind
    prompt: PromptKind
    steps: tuple[str, ...]
    supports_json: bool
    # Raw variants use the literal ``argparse`` destination and normalized
    # value (for example, ``command=true`` or ``output=none``).  They identify
    # modes which must suppress all human chrome even when the action's normal
    # result is presented interactively.
    raw_variants: tuple[str, ...]
    branded: bool
    show_cached_updates: bool


# Every Action has one literal entry.  Repetition here is intentional: neither
# authorization class nor command spelling is allowed to silently select a UI.
UI_CONTRACTS: Mapping[str, UiContract] = {
    "setup": UiContract(
        action_id="setup",
        title="Set Up",
        surface=SurfaceKind.MUTATION,
        output=OutputContract.MUTATION_RESULT,
        progress=ProgressKind.SPINNER,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=True,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "node.status": UiContract(
        action_id="node.status",
        title="Node",
        surface=SurfaceKind.DETAIL,
        output=OutputContract.RECORD,
        progress=ProgressKind.NONE,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=True,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "node.move": UiContract(
        action_id="node.move",
        title="Move Node",
        surface=SurfaceKind.WORKFLOW,
        output=OutputContract.MUTATION_RESULT,
        progress=ProgressKind.SPINNER,
        prompt=PromptKind.SECRET,
        steps=(),
        supports_json=True,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "hardware": UiContract(
        action_id="hardware",
        title="Hardware",
        surface=SurfaceKind.DETAIL,
        output=OutputContract.RECORD,
        progress=ProgressKind.SPINNER,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=True,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "update": UiContract(
        action_id="update",
        title="Update",
        surface=SurfaceKind.MUTATION,
        output=OutputContract.MUTATION_RESULT,
        progress=ProgressKind.STEPS,
        prompt=PromptKind.NONE,
        steps=("Resolve and install core", "Rebind services and runtime", "Verify update"),
        supports_json=False,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "update.check": UiContract(
        action_id="update.check",
        title="Check for Updates",
        surface=SurfaceKind.DETAIL,
        output=OutputContract.RECORD,
        progress=ProgressKind.SPINNER,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=True,
        raw_variants=(),
        branded=True,
        show_cached_updates=False,
    ),
    "topology.show": UiContract(
        action_id="topology.show",
        title="Topology",
        surface=SurfaceKind.DETAIL,
        output=OutputContract.RECORD,
        progress=ProgressKind.SPINNER,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=True,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "topology.probe": UiContract(
        action_id="topology.probe",
        title="Probe Topology",
        surface=SurfaceKind.MUTATION,
        output=OutputContract.MUTATION_RESULT,
        progress=ProgressKind.STEPS,
        prompt=PromptKind.NONE,
        steps=("Validate endpoints", "Probe bidirectional link", "Record verified link"),
        supports_json=True,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "topology.plan": UiContract(
        action_id="topology.plan",
        title="Plan Placement",
        surface=SurfaceKind.WORKFLOW,
        output=OutputContract.RECORD,
        progress=ProgressKind.SPINNER,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=True,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "list": UiContract(
        action_id="list",
        title="Available Runtimes",
        surface=SurfaceKind.LIST,
        output=OutputContract.TABLE,
        progress=ProgressKind.SPINNER,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=True,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "runtimes": UiContract(
        action_id="runtimes",
        title="Installed Runtimes",
        surface=SurfaceKind.LIST,
        output=OutputContract.TABLE,
        progress=ProgressKind.NONE,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=False,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "pack": UiContract(
        action_id="pack",
        title="Pack Runtime",
        surface=SurfaceKind.MUTATION,
        output=OutputContract.ARTIFACT_RESULT,
        progress=ProgressKind.SPINNER,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=False,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "inspect": UiContract(
        action_id="inspect",
        title="Inspect Runtime",
        surface=SurfaceKind.DETAIL,
        output=OutputContract.RECORD,
        progress=ProgressKind.SPINNER,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=True,
        raw_variants=("command=true",),
        branded=True,
        show_cached_updates=True,
    ),
    "upgrade": UiContract(
        action_id="upgrade",
        title="Upgrade Runtime",
        surface=SurfaceKind.MUTATION,
        output=OutputContract.MUTATION_RESULT,
        progress=ProgressKind.SPINNER,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=False,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "rollback": UiContract(
        action_id="rollback",
        title="Roll Back Runtime",
        surface=SurfaceKind.MUTATION,
        output=OutputContract.MUTATION_RESULT,
        progress=ProgressKind.SPINNER,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=False,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "verify": UiContract(
        action_id="verify",
        title="Verify Runtime",
        surface=SurfaceKind.DETAIL,
        output=OutputContract.RECORD,
        progress=ProgressKind.SPINNER,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=False,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "acquire": UiContract(
        action_id="acquire",
        title="Acquire Model",
        surface=SurfaceKind.MUTATION,
        output=OutputContract.MUTATION_RESULT,
        progress=ProgressKind.SPINNER,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=False,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "benchmark": UiContract(
        action_id="benchmark",
        title="Benchmark",
        surface=SurfaceKind.LIVE,
        output=OutputContract.LIVE_DASHBOARD,
        progress=ProgressKind.LIVE,
        prompt=PromptKind.MIXED,
        steps=(),
        supports_json=True,
        raw_variants=("list=true", "job_worker=true"),
        branded=True,
        show_cached_updates=True,
    ),
    "install": UiContract(
        action_id="install",
        title="Install Runtime",
        surface=SurfaceKind.WORKFLOW,
        output=OutputContract.MUTATION_RESULT,
        progress=ProgressKind.SPINNER,
        prompt=PromptKind.CONFIRM,
        steps=(),
        supports_json=False,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "scale": UiContract(
        action_id="scale",
        title="Scale Runtime",
        surface=SurfaceKind.MUTATION,
        output=OutputContract.MUTATION_RESULT,
        progress=ProgressKind.SPINNER,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=False,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "serve": UiContract(
        action_id="serve",
        title="Serve Runtime",
        surface=SurfaceKind.MUTATION,
        output=OutputContract.MUTATION_RESULT,
        progress=ProgressKind.SPINNER,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=False,
        raw_variants=("dry_run=true",),
        branded=True,
        show_cached_updates=True,
    ),
    "status": UiContract(
        action_id="status",
        title="Status",
        surface=SurfaceKind.FROZEN_STATUS,
        output=OutputContract.FROZEN_STATUS,
        progress=ProgressKind.LIVE,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=True,
        raw_variants=(),
        branded=True,
        show_cached_updates=False,
    ),
    "doctor": UiContract(
        action_id="doctor",
        title="Doctor",
        surface=SurfaceKind.DETAIL,
        output=OutputContract.RECORD,
        progress=ProgressKind.SPINNER,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=True,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "logs": UiContract(
        action_id="logs",
        title="Logs",
        surface=SurfaceKind.RAW,
        output=OutputContract.RAW_STDOUT,
        progress=ProgressKind.PASSTHROUGH,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=False,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "start": UiContract(
        action_id="start",
        title="Start Runtime",
        surface=SurfaceKind.MUTATION,
        output=OutputContract.MUTATION_RESULT,
        progress=ProgressKind.SPINNER,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=False,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "restart": UiContract(
        action_id="restart",
        title="Restart Runtime",
        surface=SurfaceKind.MUTATION,
        output=OutputContract.MUTATION_RESULT,
        progress=ProgressKind.SPINNER,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=False,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "recover": UiContract(
        action_id="recover",
        title="Recover Runtime",
        surface=SurfaceKind.MUTATION,
        output=OutputContract.MUTATION_RESULT,
        progress=ProgressKind.SPINNER,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=False,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "stop": UiContract(
        action_id="stop",
        title="Stop Runtime",
        surface=SurfaceKind.MUTATION,
        output=OutputContract.MUTATION_RESULT,
        progress=ProgressKind.SPINNER,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=False,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "uninstall": UiContract(
        action_id="uninstall",
        title="Uninstall",
        surface=SurfaceKind.WORKFLOW,
        output=OutputContract.MUTATION_RESULT,
        progress=ProgressKind.SPINNER,
        prompt=PromptKind.CONFIRM,
        steps=(),
        supports_json=False,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "exposure.status": UiContract(
        action_id="exposure.status",
        title="Public Exposure",
        surface=SurfaceKind.DETAIL,
        output=OutputContract.RECORD,
        progress=ProgressKind.SPINNER,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=True,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "expose": UiContract(
        action_id="expose",
        title="Expose Inference",
        surface=SurfaceKind.MUTATION,
        output=OutputContract.MUTATION_RESULT,
        progress=ProgressKind.SPINNER,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=True,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "unexpose": UiContract(
        action_id="unexpose",
        title="Disable Exposure",
        surface=SurfaceKind.MUTATION,
        output=OutputContract.MUTATION_RESULT,
        progress=ProgressKind.SPINNER,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=True,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "pair": UiContract(
        action_id="pair",
        title="Pair Controller",
        surface=SurfaceKind.WORKFLOW,
        output=OutputContract.SENSITIVE_RESULT,
        progress=ProgressKind.LIVE,
        prompt=PromptKind.WORKFLOW,
        steps=(),
        supports_json=False,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "controllers.list": UiContract(
        action_id="controllers.list",
        title="Controllers",
        surface=SurfaceKind.LIST,
        output=OutputContract.TABLE,
        progress=ProgressKind.NONE,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=True,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "controllers.forget": UiContract(
        action_id="controllers.forget",
        title="Forget Controller",
        surface=SurfaceKind.MUTATION,
        output=OutputContract.MUTATION_RESULT,
        progress=ProgressKind.SPINNER,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=True,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "key.create": UiContract(
        action_id="key.create",
        title="Create API Key",
        surface=SurfaceKind.WORKFLOW,
        output=OutputContract.ONE_TIME_SECRET,
        progress=ProgressKind.SPINNER,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=True,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "key.list": UiContract(
        action_id="key.list",
        title="API Keys",
        surface=SurfaceKind.LIST,
        output=OutputContract.TABLE,
        progress=ProgressKind.NONE,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=True,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "key.show": UiContract(
        action_id="key.show",
        title="API Key",
        surface=SurfaceKind.DETAIL,
        output=OutputContract.RECORD,
        progress=ProgressKind.NONE,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=True,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "key.rotate": UiContract(
        action_id="key.rotate",
        title="Rotate API Key",
        surface=SurfaceKind.WORKFLOW,
        output=OutputContract.ONE_TIME_SECRET,
        progress=ProgressKind.SPINNER,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=True,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "key.revoke": UiContract(
        action_id="key.revoke",
        title="Revoke API Key",
        surface=SurfaceKind.MUTATION,
        output=OutputContract.MUTATION_RESULT,
        progress=ProgressKind.SPINNER,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=True,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "key.policy": UiContract(
        action_id="key.policy",
        title="Update API Key Policy",
        surface=SurfaceKind.MUTATION,
        output=OutputContract.MUTATION_RESULT,
        progress=ProgressKind.SPINNER,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=True,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "audit.list": UiContract(
        action_id="audit.list",
        title="Audit Events",
        surface=SurfaceKind.LIST,
        output=OutputContract.TABLE,
        progress=ProgressKind.NONE,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=True,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "audit.show": UiContract(
        action_id="audit.show",
        title="Audit Event",
        surface=SurfaceKind.DETAIL,
        output=OutputContract.RECORD,
        progress=ProgressKind.NONE,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=True,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "audit.verify": UiContract(
        action_id="audit.verify",
        title="Verify Audit Chain",
        surface=SurfaceKind.DETAIL,
        output=OutputContract.RECORD,
        progress=ProgressKind.SPINNER,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=True,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "audit.export": UiContract(
        action_id="audit.export",
        title="Export Audit Chain",
        surface=SurfaceKind.MUTATION,
        output=OutputContract.ARTIFACT_RESULT,
        progress=ProgressKind.SPINNER,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=False,
        raw_variants=("output=none",),
        branded=True,
        show_cached_updates=True,
    ),
    "child.list": UiContract(
        action_id="child.list",
        title="Child Nodes",
        surface=SurfaceKind.LIST,
        output=OutputContract.TABLE,
        progress=ProgressKind.NONE,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=True,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "child.prepare": UiContract(
        action_id="child.prepare",
        title="Prepare Child",
        surface=SurfaceKind.MUTATION,
        output=OutputContract.SENSITIVE_RESULT,
        progress=ProgressKind.SPINNER,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=True,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "child.join": UiContract(
        action_id="child.join",
        title="Join Node",
        surface=SurfaceKind.WORKFLOW,
        output=OutputContract.MUTATION_RESULT,
        progress=ProgressKind.SPINNER,
        prompt=PromptKind.SECRET,
        steps=(),
        supports_json=True,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "child.invite": UiContract(
        action_id="child.invite",
        title="Invite Child",
        surface=SurfaceKind.WORKFLOW,
        output=OutputContract.SENSITIVE_RESULT,
        progress=ProgressKind.SPINNER,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=True,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "child.approve": UiContract(
        action_id="child.approve",
        title="Approve Child",
        surface=SurfaceKind.MUTATION,
        output=OutputContract.MUTATION_RESULT,
        progress=ProgressKind.SPINNER,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=True,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "child.sync": UiContract(
        action_id="child.sync",
        title="Sync Children",
        surface=SurfaceKind.MUTATION,
        output=OutputContract.MUTATION_RESULT,
        progress=ProgressKind.SPINNER,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=True,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "child.drain": UiContract(
        action_id="child.drain",
        title="Drain Child",
        surface=SurfaceKind.MUTATION,
        output=OutputContract.MUTATION_RESULT,
        progress=ProgressKind.SPINNER,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=True,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "child.resume": UiContract(
        action_id="child.resume",
        title="Resume Child",
        surface=SurfaceKind.MUTATION,
        output=OutputContract.MUTATION_RESULT,
        progress=ProgressKind.SPINNER,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=True,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "child.remove": UiContract(
        action_id="child.remove",
        title="Remove Child",
        surface=SurfaceKind.MUTATION,
        output=OutputContract.MUTATION_RESULT,
        progress=ProgressKind.SPINNER,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=True,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "alias.list": UiContract(
        action_id="alias.list",
        title="Model Aliases",
        surface=SurfaceKind.LIST,
        output=OutputContract.TABLE,
        progress=ProgressKind.NONE,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=True,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "alias.set": UiContract(
        action_id="alias.set",
        title="Set Model Alias",
        surface=SurfaceKind.MUTATION,
        output=OutputContract.MUTATION_RESULT,
        progress=ProgressKind.SPINNER,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=True,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "alias.remove": UiContract(
        action_id="alias.remove",
        title="Remove Model Alias",
        surface=SurfaceKind.MUTATION,
        output=OutputContract.MUTATION_RESULT,
        progress=ProgressKind.SPINNER,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=True,
        raw_variants=(),
        branded=True,
        show_cached_updates=True,
    ),
    "service-start": UiContract(
        action_id="service-start",
        title="Service Start",
        surface=SurfaceKind.INTERNAL,
        output=OutputContract.INTERNAL,
        progress=ProgressKind.PASSTHROUGH,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=False,
        raw_variants=(),
        branded=False,
        show_cached_updates=False,
    ),
    "service-stop": UiContract(
        action_id="service-stop",
        title="Service Stop",
        surface=SurfaceKind.INTERNAL,
        output=OutputContract.INTERNAL,
        progress=ProgressKind.NONE,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=False,
        raw_variants=(),
        branded=False,
        show_cached_updates=False,
    ),
    "gateway": UiContract(
        action_id="gateway",
        title="Gateway",
        surface=SurfaceKind.INTERNAL,
        output=OutputContract.INTERNAL,
        progress=ProgressKind.PASSTHROUGH,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=False,
        raw_variants=(),
        branded=False,
        show_cached_updates=False,
    ),
    "node-agent": UiContract(
        action_id="node-agent",
        title="Node Agent",
        surface=SurfaceKind.INTERNAL,
        output=OutputContract.INTERNAL,
        progress=ProgressKind.PASSTHROUGH,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=False,
        raw_variants=(),
        branded=False,
        show_cached_updates=False,
    ),
    "core-rebind": UiContract(
        action_id="core-rebind",
        title="Core Rebind",
        surface=SurfaceKind.INTERNAL,
        output=OutputContract.INTERNAL,
        progress=ProgressKind.NONE,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=False,
        raw_variants=(),
        branded=False,
        show_cached_updates=False,
    ),
    "core-prune": UiContract(
        action_id="core-prune",
        title="Core Prune",
        surface=SurfaceKind.INTERNAL,
        output=OutputContract.INTERNAL,
        progress=ProgressKind.NONE,
        prompt=PromptKind.NONE,
        steps=(),
        supports_json=True,
        raw_variants=(),
        branded=False,
        show_cached_updates=False,
    ),
}


def validate_contracts(
    actions: Mapping[str, Action], contracts: Mapping[str, UiContract]
) -> None:
    """Reject missing, extra, internally inconsistent, or inferred contracts."""

    action_ids = set(actions)
    contract_ids = set(contracts)
    missing = sorted(action_ids - contract_ids)
    unknown = sorted(contract_ids - action_ids)
    if missing or unknown:
        raise ValueError(
            "CLI UI contract registry mismatch: "
            f"missing={missing or '-'} unknown={unknown or '-'}"
        )

    declared_ids = [item.action_id for item in contracts.values()]
    if len(declared_ids) != len(set(declared_ids)):
        raise ValueError("CLI UI contracts contain duplicate action identifiers")

    for action_id, item in contracts.items():
        if item.action_id != action_id:
            raise ValueError(
                f"CLI UI contract key does not match action_id: {action_id}"
            )
        if not item.title or item.title.strip() != item.title:
            raise ValueError(f"CLI UI contract has an invalid title: {action_id}")
        if item.progress is ProgressKind.STEPS:
            if not item.steps or any(not step.strip() for step in item.steps):
                raise ValueError(
                    f"step progress requires named steps: {action_id}"
                )
        elif item.steps:
            raise ValueError(
                f"non-step progress cannot declare steps: {action_id}"
            )
        if len(item.raw_variants) != len(set(item.raw_variants)) or any(
            not value.strip()
            or value.count("=") != 1
            or not all(part.strip() for part in value.split("=", 1))
            for value in item.raw_variants
        ):
            raise ValueError(f"CLI UI contract has invalid raw variants: {action_id}")

        action = actions[action_id]
        internal = action.mutation is MutationClass.INTERNAL
        if internal != (item.surface is SurfaceKind.INTERNAL):
            raise ValueError(
                f"internal action and UI surface disagree: {action_id}"
            )
        if internal:
            if item.output is not OutputContract.INTERNAL:
                raise ValueError(f"internal action has public output: {action_id}")
            if item.branded or item.show_cached_updates:
                raise ValueError(f"internal action has public chrome: {action_id}")
            if item.prompt is not PromptKind.NONE:
                raise ValueError(f"internal action declares a prompt: {action_id}")
        elif not item.branded:
            raise ValueError(f"public action is not branded: {action_id}")

        if item.show_cached_updates and not item.branded:
            raise ValueError(
                f"unbranded action cannot show cached updates: {action_id}"
            )

        allowed_outputs = {
            SurfaceKind.FROZEN_STATUS: {OutputContract.FROZEN_STATUS},
            SurfaceKind.LIST: {OutputContract.TABLE},
            SurfaceKind.DETAIL: {OutputContract.RECORD},
            SurfaceKind.MUTATION: {
                OutputContract.MUTATION_RESULT,
                OutputContract.ARTIFACT_RESULT,
                OutputContract.SENSITIVE_RESULT,
            },
            SurfaceKind.WORKFLOW: {
                OutputContract.RECORD,
                OutputContract.MUTATION_RESULT,
                OutputContract.SENSITIVE_RESULT,
                OutputContract.ONE_TIME_SECRET,
            },
            SurfaceKind.LIVE: {OutputContract.LIVE_DASHBOARD},
            SurfaceKind.RAW: {OutputContract.RAW_STDOUT},
            SurfaceKind.INTERNAL: {OutputContract.INTERNAL},
        }
        if item.output not in allowed_outputs[item.surface]:
            raise ValueError(
                f"CLI UI surface and output disagree: {action_id}"
            )

        if item.prompt is not PromptKind.NONE and item.surface not in {
            SurfaceKind.WORKFLOW,
            SurfaceKind.LIVE,
        }:
            raise ValueError(f"prompt has no workflow surface: {action_id}")
        if item.progress is ProgressKind.PASSTHROUGH and item.surface not in {
            SurfaceKind.RAW,
            SurfaceKind.INTERNAL,
        }:
            raise ValueError(
                f"passthrough progress has no raw surface: {action_id}"
            )
        if (
            action.mutation in {MutationClass.LOCAL, MutationClass.NODE}
            and item.surface
            in {
                SurfaceKind.FROZEN_STATUS,
                SurfaceKind.LIST,
                SurfaceKind.DETAIL,
                SurfaceKind.RAW,
            }
        ):
            raise ValueError(
                f"mutating action has a read-only UI surface: {action_id}"
            )

        if item.surface is SurfaceKind.FROZEN_STATUS:
            if action_id != "status" or item.output is not OutputContract.FROZEN_STATUS:
                raise ValueError("only status may own the frozen status surface")
        elif item.output is OutputContract.FROZEN_STATUS:
            raise ValueError(f"non-status action uses frozen output: {action_id}")

        if item.output is OutputContract.ONE_TIME_SECRET and action_id not in {
            "key.create",
            "key.rotate",
        }:
            raise ValueError(f"unexpected one-time-secret output: {action_id}")
        if item.progress is ProgressKind.LIVE and item.surface not in {
            SurfaceKind.FROZEN_STATUS,
            SurfaceKind.LIVE,
            SurfaceKind.WORKFLOW,
        }:
            raise ValueError(f"live progress has no live surface: {action_id}")


def contract(action_id: str) -> UiContract:
    """Return the exact contract; unknown actions never receive a default."""

    try:
        return UI_CONTRACTS[action_id]
    except KeyError as error:
        raise ValueError(f"unregistered CLI UI contract: {action_id}") from error


validate_contracts(ACTIONS, UI_CONTRACTS)
