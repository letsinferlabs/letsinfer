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


def parallel_contract(node_count: int = 3) -> dict[str, object]:
    readiness = {
        "kind": "exec",
        "command": ["/opt/runtime/ready"],
        "interval_seconds": 2,
        "timeout_seconds": 3,
        "retries": 90,
    }
    return {
        "schema_version": 3,
        "failure_policy": "whole-group",
        "endpoint_owner": "task-0",
        "startup_order": [
            [f"task-{index}" for index in range(1, node_count)],
            ["task-0"],
        ] if node_count > 1 else [["task-0"]],
        "tasks": [
            {
                "task_id": f"task-{index}",
                "launcher": "runtime-command",
                "port_count": 4,
                "command": ["/opt/runtime/launch", f"task-{index}"],
                "environment": {"ENGINE_LOG_LEVEL": "info"} if index else {},
                "readiness": copy.deepcopy(readiness),
            }
            for index in range(node_count)
        ],
    }


def parallel_connections(member_ids: tuple[str, ...]) -> list[dict[str, object]]:
    return [
        {
            "nodes": sorted((member_ids[index - 1], member_ids[index])),
            "kind": "connectx",
            "speed_mbps": 200_000,
            "mtu": 9000,
            "rdma": True,
        }
        for index in range(1, len(member_ids))
    ]
