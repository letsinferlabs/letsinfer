# SPDX-License-Identifier: AGPL-3.0-only
"""Authoritative core and runtime update state."""

from .manager import (
    Component,
    UpdateManager,
    UpdatePoller,
    UpdateRecord,
    UpdateSnapshot,
    compare_versions,
)

__all__ = [
    "Component",
    "UpdateManager",
    "UpdatePoller",
    "UpdateRecord",
    "UpdateSnapshot",
    "compare_versions",
]
