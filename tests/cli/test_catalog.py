#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Catalog cache and public runtime discovery regressions."""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import pathlib
import tempfile
import unittest
from unittest import mock

from core import cli, runtime_packs
from core.catalog import CatalogManager, CatalogSnapshot


CANDIDATE = "sglang--radixark--qwen3.8-27b-nvfp4--dgx-spark"


def catalog() -> dict:
    target = {
        "id": "dgx-spark",
        "platform": "linux/arm64",
        "accelerator": {
            "vendor": "nvidia",
            "architecture": "sm_121",
            "count": 1,
            "partitioning": "full-device",
        },
        "memory": {"topology": "unified", "minimum_total_gib": 118},
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
    }
    release = {
        "authors": ["MiaAI-Lab", "Letsinfer"],
        "license": "AGPL-3.0-only",
        "source": "ghcr.io/letsinferlabs/runtimes/qwen@sha256:" + "1" * 64,
        "qualified": True,
        "revoked": False,
        "engine": "sglang",
        "engine_oci": "ghcr.io/letsinferlabs/engines/qwen@sha256:" + "2" * 64,
        "model_uri": "hf://RadixArk/Qwen3.8-27B-NVFP4",
        "benchmark": {
            "id": "3" * 64,
            "suite": "letsinfer-code-prose-v1",
            "score": 42.5,
            "evidence": "ghcr.io/letsinferlabs/benchmarks/qwen@sha256:" + "4" * 64,
        },
    }
    return {
        "schema_version": 5,
        "recommendation_policy": {
            "id": "letsinfer-throughput-geomean-v1",
            "benchmark_suite": "letsinfer-code-prose-v1",
            "metric": "aggregate_tps",
            "cache": "uncached",
            "tie_breakers": ["score", "version", "candidate"],
        },
        "targets": {"dgx-spark": {"match": target}},
        "models": {
            "qwen3.8-27b": {
                "targets": {
                    "dgx-spark": {
                        "recommended": {
                            "candidate": CANDIDATE,
                            "version": "0.1.0-rc.12",
                        },
                        "candidates": {
                            CANDIDATE: {
                                "latest": "0.1.0-rc.12",
                                "releases": {"0.1.0-rc.12": release},
                            }
                        },
                    }
                }
            }
        },
    }


class CatalogTests(unittest.TestCase):
    def test_local_catalog_uses_the_same_strict_schema_as_remote(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "catalog.json"
            path.write_bytes(runtime_packs.canonical_bytes(catalog()))
            snapshot = CatalogManager(str(path)).load()
        self.assertEqual(snapshot.document, catalog())
        self.assertFalse(snapshot.stale)

    def test_corrupt_cache_is_replaced_instead_of_becoming_permanent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            root.mkdir(exist_ok=True)
            (root / "current.json").write_text("not json", encoding="utf-8")
            (root / "current.json").chmod(0o600)
            manager = CatalogManager(
                "https://example.invalid/catalog.json", root=root
            )
            fresh = CatalogSnapshot(catalog(), manager.location, "5" * 64, 100, False)
            with mock.patch.object(manager, "refresh", return_value=fresh) as refresh:
                self.assertIs(manager.load(), fresh)
            refresh.assert_called_once_with()

    def test_list_shows_all_runtime_authors_and_recommendation(self) -> None:
        snapshot = CatalogSnapshot(catalog(), "catalog.json", "5" * 64, 100, False)
        arguments = argparse.Namespace(
            catalog="catalog.json",
            refresh=False,
            all_targets=True,
            model=None,
            versions=False,
            json=False,
        )
        output = io.StringIO()
        with (
            mock.patch.object(cli.CatalogManager, "load", return_value=snapshot),
            mock.patch.object(cli, "selections", return_value=[]),
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(cli.list_available_runtimes(arguments), 0)
        rendered = output.getvalue()
        self.assertIn("AUTHOR", rendered)
        self.assertIn("MiaAI-Lab, Letsinfer", rendered)
        self.assertIn("recommended", rendered)

    def test_list_json_keeps_authors_structured(self) -> None:
        snapshot = CatalogSnapshot(catalog(), "catalog.json", "5" * 64, 100, False)
        arguments = argparse.Namespace(
            catalog="catalog.json",
            refresh=False,
            all_targets=True,
            model="qwen3.8-27b",
            versions=True,
            json=True,
        )
        output = io.StringIO()
        with (
            mock.patch.object(cli.CatalogManager, "load", return_value=snapshot),
            mock.patch.object(cli, "selections", return_value=[]),
            contextlib.redirect_stdout(output),
        ):
            cli.list_available_runtimes(arguments)
        payload = json.loads(output.getvalue())
        self.assertEqual(
            payload["runtimes"][0]["authors"], ["MiaAI-Lab", "Letsinfer"]
        )


if __name__ == "__main__":
    unittest.main()
