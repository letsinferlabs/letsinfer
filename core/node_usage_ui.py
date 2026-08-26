#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Human presentation for local node storage accounting."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from . import command_ui
from .storage_usage import format_bytes


def render(presenter: command_ui.CommandUI, report: Mapping[str, Any]) -> None:
    presenter.table(
        (
            command_ui.TableColumn("label", "CATEGORY", min_width=12),
            command_ui.TableColumn("used", "USED", min_width=8, align="right"),
            command_ui.TableColumn(
                "reclaimable", "RECLAIMABLE", min_width=11, align="right"
            ),
            command_ui.TableColumn("items", "ITEMS", min_width=5, align="right"),
        ),
        [
            {
                "label": item["label"],
                "used": format_bytes(int(item["allocated_bytes"])),
                "reclaimable": format_bytes(int(item["reclaimable_bytes"])),
                "items": int(item["reclaimable_items"]),
                "_semantic": (
                    command_ui.Semantic.WARNING
                    if item["reclaimable_bytes"]
                    else command_ui.Semantic.INFO
                ),
            }
            for item in report["categories"]
        ],
    )
    records = [
        command_ui.RecordRow(
            "Let’s Infer", format_bytes(int(report["total_allocated_bytes"]))
        ),
        command_ui.RecordRow(
            "Reclaimable", format_bytes(int(report["total_reclaimable_bytes"]))
        ),
        command_ui.RecordRow(
            "Disk free",
            format_bytes(int(report["filesystem"]["free_bytes"])),
            f"of {format_bytes(int(report['filesystem']['total_bytes']))}",
        ),
    ]
    container = report["container_runtime"]
    if container.get("available") is True:
        records.extend(
            (
                command_ui.RecordRow(
                    "Images",
                    format_bytes(int(container["image_logical_bytes"])),
                    "Logical size; shared layers excluded from totals",
                ),
                command_ui.RecordRow(
                    "Writes",
                    format_bytes(int(container["writable_bytes"])),
                    f"{int(container['managed_containers'])} managed container(s)",
                ),
            )
        )
    else:
        records.append(
            command_ui.RecordRow(
                "Docker",
                "Unavailable",
                str(container.get("reason") or "Not included"),
            )
        )
    presenter.records(tuple(records))
