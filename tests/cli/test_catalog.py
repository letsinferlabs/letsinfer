#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Catalog cache and public runtime discovery regressions."""

from __future__ import annotations

import argparse
import copy
import contextlib
import errno
import io
import json
import pathlib
import tempfile
import unittest
from unittest import mock

from core import catalog as catalog_module, cli, command_ui, runtime_packs
from core.catalog import CatalogManager, CatalogSnapshot, _snapshot_identity
from core.orchestration.contracts import validate_release_identity
from core.revocations import canonical_bytes as revocation_bytes, empty_ledger


CANDIDATE = "sglang--radixark--qwen3.8-27b-nvfp4--dgx-spark"


class _TerminalStream(io.StringIO):
    encoding = "utf-8"

    def isatty(self) -> bool:
        return True


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
            "node_count": 1,
            "interconnect": {
                "kind": "any",
                "rdma_required": False,
                "minimum_speed_mbps": 0,
                "minimum_mtu": 0,
            },
        },
    }
    release = {
        "authors": [
            {"github_login": "MiaAI-Lab", "github_id": 1, "github_type": "User"},
            {"github_login": "letsinferlabs", "github_id": 2, "github_type": "Organization"},
        ],
        "license": "AGPL-3.0-only",
        "source": "ghcr.io/letsinferlabs/runtimes/qwen@sha256:" + "1" * 64,
        "engine": "sglang",
        "engine_distribution": {
            "kind": "oci-container",
            "reference": "ghcr.io/letsinferlabs/engines/qwen@sha256:" + "2" * 64,
        },
        "model_uri": "hf://RadixArk/Qwen3.8-27B-NVFP4",
        "benchmark": {
            "id": "3" * 64,
            "suite": "letsinfer-code-prose-v1",
            "score": 42.5,
        },
        "provenance": {
            "method": "maintainer-qualified-pre-community-v1",
            "repository": "letsinferlabs/runtimes",
            "pull_request": 1,
            "pull_request_url": "https://github.com/letsinferlabs/runtimes/pull/1",
            "proposal_head_sha": "5" * 40,
            "qualified_commit_sha": "6" * 40,
        },
        "verification": {
            "method": "maintainer-qualified-pre-community-v1",
            "verifiers": [],
        },
    }
    return {
        "schema_version": runtime_packs.CATALOG_SCHEMA_VERSION,
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
    def test_group_release_accepts_catalog_consensus_without_embedded_record(self) -> None:
        release = catalog()["models"]["qwen3.8-27b"]["targets"]["dgx-spark"][
            "candidates"
        ][CANDIDATE]["releases"]["0.1.0-rc.12"]
        runtime = {
            "logical_model": "qwen3.8-27b",
            "engine": {
                "id": release["engine"],
                "distribution": {
                    **release["engine_distribution"],
                    "immutable_id": "sha256:" + "7" * 64,
                },
            },
            "model": {"uri": release["model_uri"]},
            "artifacts": [
                {
                    "name": "model",
                    "uri": release["model_uri"],
                    "revision": "4" * 40,
                }
            ],
            "benchmark": {"contract": {"schema_version": 7}},
        }
        pack = runtime_packs.RuntimePack(
            pathlib.Path("/runtime"), {}, runtime, "5" * 64
        )
        identity = cli._group_release_identity(
            catalog_release_value=release,
            candidate_id=CANDIDATE,
            version="0.1.0-rc.12",
            source=release["source"],
            target_id="dgx-spark",
            target_sha256="6" * 64,
            runtime=pack,
            manifest_sha256="7" * 64,
        )
        self.assertEqual(
            identity["benchmark"], {"id": "3" * 64, "evidence": None}
        )
        self.assertEqual(identity["authors"], ["MiaAI-Lab", "letsinferlabs"])
        self.assertIs(validate_release_identity(identity), identity)

        runtime["benchmark"]["record"] = {"id": "8" * 64}
        with self.assertRaisesRegex(
            cli.LetsInferError,
            "signed catalog release does not match the installed runtime bytes",
        ):
            cli._group_release_identity(
                catalog_release_value=release,
                candidate_id=CANDIDATE,
                version="0.1.0-rc.12",
                source=release["source"],
                target_id="dgx-spark",
                target_sha256="6" * 64,
                runtime=pack,
                manifest_sha256="7" * 64,
            )

    def test_group_release_accepts_a_signed_unscored_runtime(self) -> None:
        release = catalog()["models"]["qwen3.8-27b"]["targets"]["dgx-spark"][
            "candidates"
        ][CANDIDATE]["releases"]["0.1.0-rc.12"]
        release["benchmark"] = None
        runtime = {
            "logical_model": "qwen3.8-27b",
            "engine": {
                "id": release["engine"],
                "distribution": {
                    **release["engine_distribution"],
                    "immutable_id": "sha256:" + "7" * 64,
                },
            },
            "model": {"uri": release["model_uri"]},
            "artifacts": [
                {
                    "name": "model",
                    "uri": release["model_uri"],
                    "revision": "4" * 40,
                }
            ],
            "benchmark": {"contract": {"schema_version": 7}},
        }
        identity = cli._group_release_identity(
            catalog_release_value=release,
            candidate_id=CANDIDATE,
            version="0.1.0-rc.12",
            source=release["source"],
            target_id="dgx-spark",
            target_sha256="6" * 64,
            runtime=runtime_packs.RuntimePack(
                pathlib.Path("/runtime"), {}, runtime, "5" * 64
            ),
            manifest_sha256="7" * 64,
        )
        self.assertIsNone(identity["benchmark"])
        self.assertIs(validate_release_identity(identity), identity)

    def test_catalog_accepts_current_two_verifier_consensus(self) -> None:
        document = catalog()
        release = document["models"]["qwen3.8-27b"]["targets"]["dgx-spark"][
            "candidates"
        ][CANDIDATE]["releases"]["0.1.0-rc.12"]
        release["provenance"] = {
            "repository": "letsinferlabs/runtimes",
            "pull_request": 17,
            "pull_request_url": "https://github.com/letsinferlabs/runtimes/pull/17",
            "proposal_head_sha": "5" * 40,
            "execution_sha256": "6" * 64,
            "qualified_commit_sha": "7" * 40,
            "consensus_sha256": "8" * 64,
        }
        release["verification"] = {
            "method": "community-two-independent-v1",
            "consensus_path": f"{CANDIDATE}/benchmark.consensus.json",
            "consensus_sha256": "8" * 64,
            "verifiers": [
                {
                    "github_login": f"Verifier{number}",
                    "github_id": 100 + number,
                    "github_type": "User",
                }
                for number in range(2)
            ],
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "catalog.json"
            path.write_bytes(runtime_packs.canonical_bytes(document))
            self.assertEqual(runtime_packs.load_catalog(str(path)), document)

    def test_signed_schema6_catalog_normalizes_exact_engine_oci_projection(self) -> None:
        expected = catalog()
        legacy = copy.deepcopy(expected)
        legacy["schema_version"] = runtime_packs.LEGACY_CATALOG_SCHEMA_VERSION
        release = legacy["models"]["qwen3.8-27b"]["targets"]["dgx-spark"][
            "candidates"
        ][CANDIDATE]["releases"]["0.1.0-rc.12"]
        distribution = release.pop("engine_distribution")
        release["engine_oci"] = distribution["reference"]
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "catalog.json"
            path.write_bytes(runtime_packs.canonical_bytes(legacy))

            loaded = runtime_packs.load_catalog(str(path))

        self.assertEqual(loaded, expected)

    def test_malformed_schema6_catalog_is_not_normalized(self) -> None:
        legacy = copy.deepcopy(catalog())
        legacy["schema_version"] = runtime_packs.LEGACY_CATALOG_SCHEMA_VERSION
        release = legacy["models"]["qwen3.8-27b"]["targets"]["dgx-spark"][
            "candidates"
        ][CANDIDATE]["releases"]["0.1.0-rc.12"]
        release["engine_oci"] = "latest"
        release.pop("engine_distribution")
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "catalog.json"
            path.write_bytes(runtime_packs.canonical_bytes(legacy))
            with self.assertRaisesRegex(
                runtime_packs.RuntimePackError,
                "unsupported runtime catalog schema_version",
            ):
                runtime_packs.load_catalog(str(path))

    def test_maintainer_bypass_requires_marked_author_score_for_recommendation(
        self,
    ) -> None:
        document = catalog()
        target = document["models"]["qwen3.8-27b"]["targets"]["dgx-spark"]
        release = target["candidates"][CANDIDATE]["releases"]["0.1.0-rc.12"]
        release["benchmark"] = None
        release["provenance"] = {
            "repository": "letsinferlabs/runtimes",
            "pull_request": 17,
            "pull_request_url": "https://github.com/letsinferlabs/runtimes/pull/17",
            "proposal_head_sha": "5" * 40,
            "execution_sha256": "6" * 64,
            "qualified_commit_sha": "7" * 40,
            "consensus_sha256": "8" * 64,
        }
        release["verification"] = {
            "method": "allowlisted-maintainer-bypass-v1",
            "consensus_path": f"{CANDIDATE}/benchmark.consensus.json",
            "consensus_sha256": "8" * 64,
            "verifiers": [],
            "waiver": {
                "schema_version": 1,
                "policy": "allowlisted-maintainer-bypass-v1",
                "actor": {
                    "github_login": "Maintainer",
                    "github_id": 100,
                    "github_type": "User",
                },
                "reason": "Sole-maintainer release authorization",
                "comment_id": 123,
                "comment_url": (
                    "https://github.com/letsinferlabs/runtimes/pull/17"
                    "#issuecomment-123"
                ),
                "issued_at": "2026-08-25T02:00:00Z",
            },
        }
        target["recommended"] = None
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "catalog.json"
            path.write_bytes(runtime_packs.canonical_bytes(document))
            loaded = runtime_packs.load_catalog(str(path))
            self.assertEqual(
                runtime_packs.catalog_release(
                    loaded,
                    "qwen3.8-27b",
                    CANDIDATE,
                    target="dgx-spark",
                )[-2:],
                ("0.1.0-rc.12", release["source"]),
            )
            with self.assertRaisesRegex(runtime_packs.RuntimePackError, "no qualified"):
                runtime_packs.catalog_release(
                    loaded, "qwen3.8-27b", None, target="dgx-spark"
                )

            target["recommended"] = {
                "candidate": CANDIDATE,
                "version": "0.1.0-rc.12",
            }
            path.write_bytes(runtime_packs.canonical_bytes(document))
            with self.assertRaisesRegex(runtime_packs.RuntimePackError, "unscored"):
                runtime_packs.load_catalog(str(path))

            release["benchmark"] = {
                "id": "9" * 64,
                "suite": "letsinfer-code-prose-v1",
                "score": 1.0,
            }
            path.write_bytes(runtime_packs.canonical_bytes(document))
            with self.assertRaisesRegex(
                runtime_packs.RuntimePackError, "consensus qualification"
            ):
                runtime_packs.load_catalog(str(path))

            release["verification"]["benchmark_source"] = "author-benchmark-v1"
            path.write_bytes(runtime_packs.canonical_bytes(document))
            loaded = runtime_packs.load_catalog(str(path))
            self.assertEqual(
                runtime_packs.catalog_release(
                    loaded, "qwen3.8-27b", None, target="dgx-spark"
                )[-2:],
                ("0.1.0-rc.12", release["source"]),
            )

            release["verification"]["benchmark_source"] = "untrusted"
            path.write_bytes(runtime_packs.canonical_bytes(document))
            with self.assertRaisesRegex(
                runtime_packs.RuntimePackError, "consensus qualification"
            ):
                runtime_packs.load_catalog(str(path))

    def test_catalog_accepts_only_a_fully_bound_runtime_contract_migration(self) -> None:
        document = catalog()
        target = document["models"]["qwen3.8-27b"]["targets"]["dgx-spark"]
        candidate = target["candidates"][CANDIDATE]
        release = candidate["releases"].pop("0.1.0-rc.12")
        candidate["latest"] = "0.1.0-rc.13"
        target["recommended"]["version"] = "0.1.0-rc.13"
        release["source"] = (
            "ghcr.io/letsinferlabs/runtimes/qwen@sha256:" + "9" * 64
        )
        release["provenance"] = {
            "method": "runtime-contract-migration-v1",
            "repository": "letsinferlabs/runtimes",
            "pull_request": 1,
            "pull_request_url": "https://github.com/letsinferlabs/runtimes/pull/1",
            "proposal_head_sha": "5" * 40,
            "qualified_commit_sha": "6" * 40,
            "from_version": "0.1.0-rc.12",
            "from_source": "ghcr.io/letsinferlabs/runtimes/qwen@sha256:" + "1" * 64,
            "benchmark_record_sha256": "7" * 64,
            "execution_contract_sha256": "8" * 64,
        }
        release["verification"] = {
            "method": "runtime-contract-migration-v1",
            "from_version": "0.1.0-rc.12",
            "from_source": "ghcr.io/letsinferlabs/runtimes/qwen@sha256:" + "1" * 64,
            "benchmark_record_path": f"{CANDIDATE}/benchmark.previous.json",
            "benchmark_record_sha256": "7" * 64,
            "execution_contract_sha256": "8" * 64,
            "verifiers": [],
        }
        candidate["releases"]["0.1.0-rc.13"] = release
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "catalog.json"
            path.write_bytes(runtime_packs.canonical_bytes(document))
            self.assertEqual(runtime_packs.load_catalog(str(path)), document)
            release["verification"]["execution_contract_sha256"] = "a" * 64
            path.write_bytes(runtime_packs.canonical_bytes(document))
            with self.assertRaisesRegex(
                runtime_packs.RuntimePackError, "contract migration"
            ):
                runtime_packs.load_catalog(str(path))

    def test_cache_identity_binds_catalog_and_revocation_bytes(self) -> None:
        catalog_data = b'{"schema_version":7}\n'
        self.assertNotEqual(
            _snapshot_identity(catalog_data, b'{"sequence":0}\n'),
            _snapshot_identity(catalog_data, b'{"sequence":1}\n'),
        )

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

    def test_refresh_reuses_existing_snapshot_on_linux_enotempty(self) -> None:
        data = runtime_packs.canonical_bytes(catalog())
        ledger = empty_ledger()
        ledger_data = revocation_bytes(ledger)
        identity = _snapshot_identity(data, ledger_data)
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            destination = root / "objects" / identity
            destination.mkdir(parents=True)
            manager = CatalogManager(
                "https://example.invalid/catalog.json",
                root=root,
                clock=lambda: 100,
            )
            with (
                mock.patch.object(
                    catalog_module,
                    "_download",
                    side_effect=[data, b"catalog-signature"],
                ),
                mock.patch.object(
                    catalog_module,
                    "_catalog_public_key",
                    return_value=b"public-key",
                ),
                mock.patch.object(
                    catalog_module,
                    "load_ledger",
                    return_value=(ledger, ledger_data, b"ledger-signature"),
                ),
                mock.patch.object(
                    catalog_module,
                    "load_catalog",
                    return_value=catalog(),
                ),
                mock.patch.object(
                    pathlib.Path,
                    "replace",
                    side_effect=OSError(errno.ENOTEMPTY, "Directory not empty"),
                ),
            ):
                snapshot = manager.refresh()

            self.assertEqual(snapshot.document, catalog())
            self.assertEqual(
                json.loads((root / "current.json").read_text(encoding="utf-8")),
                {"schema_version": 2, "snapshot_sha256": identity},
            )
            self.assertFalse(any(root.glob(".incoming-*")))

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
        self.assertIn("MiaAI-Lab, letsinferlabs", rendered)
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
            payload["models"][0]["authors"],
            [
                {"github_login": "MiaAI-Lab", "github_id": 1, "github_type": "User"},
                {"github_login": "letsinferlabs", "github_id": 2, "github_type": "Organization"},
            ],
        )

    def test_list_uses_compact_records_on_an_eighty_column_terminal(self) -> None:
        snapshot = CatalogSnapshot(catalog(), "catalog.json", "5" * 64, 100, False)
        arguments = argparse.Namespace(
            catalog="catalog.json",
            refresh=False,
            all_targets=True,
            model=None,
            versions=False,
            json=False,
        )
        output = _TerminalStream()
        presenter = command_ui.CommandUI(
            output,
            environ={"TERM": "xterm-256color", "NO_COLOR": "1", "COLUMNS": "80"},
        )
        with (
            mock.patch.object(cli.CatalogManager, "load", return_value=snapshot),
            mock.patch.object(cli, "selections", return_value=[]),
            mock.patch.object(cli, "_human_presenter", return_value=presenter),
        ):
            self.assertEqual(cli.list_available_runtimes(arguments), 0)
        rendered = output.getvalue()
        self.assertIn("qwen3.8-27b  0.1.0-rc.12", rendered)
        self.assertIn("sglang · dgx-spark · recommended", rendered)
        self.assertIn("By MiaAI-Lab, letsinferlabs · legacy verification", rendered)
        self.assertNotIn("MODEL", rendered)

    def test_list_keeps_the_table_on_a_wide_terminal(self) -> None:
        snapshot = CatalogSnapshot(catalog(), "catalog.json", "5" * 64, 100, False)
        arguments = argparse.Namespace(
            catalog="catalog.json",
            refresh=False,
            all_targets=True,
            model=None,
            versions=False,
            json=False,
        )
        output = _TerminalStream()
        presenter = command_ui.CommandUI(
            output,
            environ={"TERM": "xterm-256color", "NO_COLOR": "1", "COLUMNS": "140"},
        )
        with (
            mock.patch.object(cli.CatalogManager, "load", return_value=snapshot),
            mock.patch.object(cli, "selections", return_value=[]),
            mock.patch.object(cli, "_human_presenter", return_value=presenter),
        ):
            self.assertEqual(cli.list_available_runtimes(arguments), 0)
        rendered = output.getvalue()
        self.assertIn("MODEL", rendered)
        self.assertIn("AUTHOR", rendered)
        self.assertNotIn("By MiaAI-Lab", rendered)

    def test_list_shows_community_verifier_count(self) -> None:
        document = catalog()
        release = document["models"]["qwen3.8-27b"]["targets"]["dgx-spark"][
            "candidates"
        ][CANDIDATE]["releases"]["0.1.0-rc.12"]
        release["provenance"] = {
            "repository": "letsinferlabs/runtimes",
            "pull_request": 17,
            "pull_request_url": "https://github.com/letsinferlabs/runtimes/pull/17",
            "proposal_head_sha": "5" * 40,
            "execution_sha256": "6" * 64,
            "qualified_commit_sha": "7" * 40,
            "consensus_sha256": "8" * 64,
        }
        release["verification"] = {
            "method": "community-consensus-v1",
            "consensus_path": f"{CANDIDATE}/benchmark.consensus.json",
            "consensus_sha256": "8" * 64,
            "verifiers": [
                {
                    "github_login": f"Verifier{number}",
                    "github_id": 100 + number,
                    "github_type": "User",
                }
                for number in range(3)
            ],
        }
        snapshot = CatalogSnapshot(document, "catalog.json", "5" * 64, 100, False)
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
            cli.list_available_runtimes(arguments)
        self.assertIn("VERIFIED", output.getvalue())
        self.assertRegex(output.getvalue(), r"\s3\s+recommended")

    def test_list_json_preserves_unscored_maintainer_release(self) -> None:
        document = catalog()
        target = document["models"]["qwen3.8-27b"]["targets"]["dgx-spark"]
        target["recommended"] = None
        release = target["candidates"][CANDIDATE]["releases"]["0.1.0-rc.12"]
        release["benchmark"] = None
        release["verification"] = {
            "method": "allowlisted-maintainer-bypass-v1",
            "consensus_path": f"{CANDIDATE}/benchmark.consensus.json",
            "consensus_sha256": "8" * 64,
            "verifiers": [],
            "waiver": {},
        }
        snapshot = CatalogSnapshot(document, "catalog.json", "5" * 64, 100, False)
        arguments = argparse.Namespace(
            catalog="catalog.json",
            refresh=False,
            all_targets=True,
            model=None,
            versions=False,
            json=True,
        )
        output = io.StringIO()
        with (
            mock.patch.object(cli.CatalogManager, "load", return_value=snapshot),
            mock.patch.object(cli, "selections", return_value=[]),
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(cli.list_available_runtimes(arguments), 0)
        rows = json.loads(output.getvalue())["models"]
        self.assertEqual(len(rows), 1)
        self.assertIsNone(rows[0]["benchmark_id"])
        self.assertIsNone(rows[0]["benchmark_score"])
        self.assertFalse(rows[0]["recommended"])


if __name__ == "__main__":
    unittest.main()
