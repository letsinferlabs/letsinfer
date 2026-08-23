#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import copy


def release_identity(
    *,
    manifest_sha256: str = "5" * 64,
    runtime_digest: str = "6" * 64,
) -> dict[str, object]:
    return {
        "logical_model": "fixture-model",
        "candidate_id": "fixture-runtime",
        "version": "1.2.3-rc.1",
        "source": "registry.example/runtime@sha256:" + "7" * 64,
        "runtime_digest": runtime_digest,
        "manifest_sha256": manifest_sha256,
        "engine_oci": "registry.example/engine@sha256:" + "8" * 64,
        "model_uri": "hf://example/model",
        "artifacts": [{
            "name": "model",
            "uri": "hf://example/model",
            "revision": "9" * 40,
            "sha256": None,
        }],
        "target_id": "fixture-target",
        "target_contract_sha256": "a" * 64,
        "qualification": "qualified",
        "benchmark": {
            "id": "b" * 64,
            "evidence": "registry.example/evidence@sha256:" + "c" * 64,
        },
        "authors": ["Letsinfer"],
        "license": "AGPL-3.0-only",
    }


def parallel_contract(member_count: int = 3) -> dict[str, object]:
    readiness = {
        "kind": "exec",
        "command": ["/opt/runtime/ready"],
        "interval_seconds": 2,
        "timeout_seconds": 3,
        "retries": 90,
    }
    return {
        "schema_version": 2,
        "strategy": "parallel",
        "member_count": member_count,
        "engine_strategy": "tensor-parallel",
        "failure_policy": "whole-group",
        "minimum_healthy_members": member_count,
        "startup_order": ["engine-member", "engine-coordinator"],
        "roles": {
            "engine-member": {
                "assignment": "members",
                "launcher": "runtime-command",
                "port_count": 4,
                "command": ["/opt/runtime/launch", "child"],
                "environment": {"ENGINE_LOG_LEVEL": "info"},
                "inference_endpoint": False,
                "readiness": copy.deepcopy(readiness),
            },
            "engine-coordinator": {
                "assignment": "engine-coordinator",
                "launcher": "runtime-command",
                "port_count": 4,
                "command": ["/opt/runtime/launch", "main"],
                "environment": {},
                "inference_endpoint": True,
                "readiness": copy.deepcopy(readiness),
            },
        },
    }
