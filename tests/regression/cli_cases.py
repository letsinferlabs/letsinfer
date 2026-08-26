# SPDX-License-Identifier: AGPL-3.0-only
"""Minimal valid argument vectors for every CLI leaf."""

from __future__ import annotations


CLI_CASES = {
    "status": ("status", "--json"),
    "doctor": ("doctor", "--json"),
    "node.info": ("node", "info", "--json"),
    "node.list": ("node", "list", "--json"),
    "node.add": ("node", "add", "--json"),
    "node.pause": ("node", "pause", "child", "--json"),
    "node.resume": ("node", "resume", "child", "--json"),
    "node.remove": ("node", "remove", "child", "--json"),
    "model.list": ("model", "list", "--json"),
    "model.install": ("model", "install", "model"),
    "model.remove": ("model", "remove", "model", "--all-nodes", "--json"),
    "model.pause": ("model", "pause", "model"),
    "model.resume": ("model", "resume", "model"),
    "model.restart": ("model", "restart", "model"),
    "model.recover": ("model", "recover", "model"),
    "model.rollback": ("model", "rollback", "model", "--dry-run"),
    "model.logs": ("model", "logs", "model", "--tail", "0"),
    "benchmark.run": ("benchmark", "run", "model", "--c1"),
    "benchmark.list": ("benchmark", "list", "model", "--c1"),
    "benchmark.status": ("benchmark", "status", "--json"),
    "benchmark.stop": ("benchmark", "stop"),
    "benchmark.clean": ("benchmark", "clean", "--yes"),
    "benchmark.verification.run": (
        "benchmark", "verification", "run", "https://example.invalid/pr/1"
    ),
    "benchmark.verification.status": (
        "benchmark", "verification", "status", "--json"
    ),
    "benchmark.verification.stop": ("benchmark", "verification", "stop"),
    "auth.controller.add": ("auth", "controller", "add", "--timeout", "30"),
    "auth.controller.list": ("auth", "controller", "list", "--json"),
    "auth.controller.revoke": (
        "auth", "controller", "revoke", "controller", "--json"
    ),
    "auth.key.create": ("auth", "key", "create", "application", "--json"),
    "auth.key.list": ("auth", "key", "list", "--json"),
    "auth.key.show": ("auth", "key", "show", "key", "--json"),
    "auth.key.rotate": ("auth", "key", "rotate", "key", "--json"),
    "auth.key.revoke": ("auth", "key", "revoke", "key", "--json"),
    "auth.key.update": ("auth", "key", "update", "key", "--json"),
    "exposure.status": ("exposure", "status", "--json"),
    "exposure.enable": ("exposure", "enable", "--json"),
    "exposure.disable": ("exposure", "disable", "--json"),
    "audit.list": ("audit", "list", "--json"),
    "audit.show": ("audit", "show", "1", "--json"),
    "audit.verify": ("audit", "verify", "--json"),
    "audit.export": ("audit", "export", "--output", "audit.json"),
    "update.check": ("update", "check", "--json"),
    "update.core": ("update", "core", "1.2.3"),
    "update.model": ("update", "model", "model", "--dry-run"),
    "uninstall": ("uninstall",),
    "core-setup": ("core-setup", "--json"),
    "service-start": ("service-start", "--config", "service.json"),
    "service-stop": ("service-stop", "--config", "service.json"),
    "gateway": ("gateway", "--telemetry-file", "telemetry.json"),
    "node-agent": ("node-agent",),
    "core-rebind": ("core-rebind",),
    "core-prune": ("core-prune", "--dry-run", "--json"),
}
