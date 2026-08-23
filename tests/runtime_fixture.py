#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Small schema-v4 runtime candidates shared by engine-neutral core tests."""

from __future__ import annotations

from typing import Any


def runtime_candidate() -> dict[str, Any]:
    return {
        "schema_version": 4,
        "id": "example-engine--example--model--test-target",
        "version": "1.0.0",
        "logical_model": "example-model",
        "target": {
            "id": "test-target",
            "platform": "linux/arm64",
            "accelerator": {
                "vendor": "example",
                "architecture": "example-v1",
                "count": 1,
                "partitioning": "full-device",
            },
            "memory": {"topology": "unified", "minimum_total_gib": 8},
            "placement": {
                "strategy": "single",
                "member_count": 1,
                "engine_strategy": "single-node",
                "interconnect": {
                    "kind": "any",
                    "rdma_required": False,
                    "minimum_speed_mbps": 0,
                    "minimum_mtu": 0,
                },
            },
        },
        "engine": {
            "id": "example-engine",
            "protocol": {"version": 2},
            "oci": {
                "reference": "registry.example/engine@sha256:" + "1" * 64,
                "immutable_id": "sha256:" + "2" * 64,
            },
            "model_format": "huggingface-snapshot",
            "cache_provider": "example-cache-v1",
            "arguments": ["--model", "${artifact:model}"],
            "environment": {"EXAMPLE_MODE": "test"},
        },
        "model": {
            "uri": "hf://Example/Model",
            "artifact": "model",
            "acquisition": {
                "image": "registry.example/acquire@sha256:" + "3" * 64,
            },
        },
        "artifacts": [
            {
                "name": "model",
                "uri": "hf://Example/Model",
                "format": "huggingface-snapshot",
                "revision": "4" * 40,
            }
        ],
        "container": {
            "memory_bytes": 8 * 1024**3,
            "shm_bytes": 1024**3,
            "min_available_gib": 4,
            "runtime_min_available_gib": 1,
            "startup_timeout_seconds": 60,
        },
        "cache": {
            "provider": "example-cache-v1",
            "persistent": False,
            "prewarm": False,
            "replay_output_policy": None,
            "config": {},
        },
        "serving": {
            "max_connections": 16,
            "max_active_requests": 4,
            "max_context_tokens": 32768,
        },
        "benchmark": {"contract": {}},
    }
