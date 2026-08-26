#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Small schema-v6 runtime candidates shared by engine-neutral core tests."""

from __future__ import annotations

from typing import Any


def runtime_candidate() -> dict[str, Any]:
    return {
        "schema_version": 6,
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
                "node_count": 1,
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
            "distribution": {
                "kind": "oci-container",
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
                "kind": "oci-container",
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
        "benchmark": {
            "contract": {
                "schema_version": 2,
                "suite": "letsinfer-code-prose-v1",
                "generator": {"id": "letsinfer-code-prose", "version": 2},
                "tokenizer": {
                    "capability": "engine-rendered-chat-count-v1",
                    "model_sha256": "3d20b7ab253233a978ba1e941ebfc05fe927c4d016f080b88137d96725f8c429",
                    "engine_image_sha256": "2" * 64,
                    "render_contract": "openai-chat-user-v1",
                },
                "request": {
                    "output_tokens": 128,
                    "min_completion_tokens": 1,
                    "require_natural_stop": True,
                    "temperature": 0,
                    "seed": 42,
                },
                "sample_interval_seconds": 5,
                "cases": [
                    {"id": "32k", "prompt_tokens": 32768, "concurrencies": [1]}
                ],
            }
        },
    }
