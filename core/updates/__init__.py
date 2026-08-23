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
from .background import (
    BACKGROUND_REFRESH_INTERVAL_SECONDS,
    DISABLE_BACKGROUND_UPDATE_ENV,
    request_background_refresh,
    snapshot_is_fresh,
)

__all__ = [
    "Component",
    "UpdateManager",
    "UpdatePoller",
    "UpdateRecord",
    "UpdateSnapshot",
    "BACKGROUND_REFRESH_INTERVAL_SECONDS",
    "DISABLE_BACKGROUND_UPDATE_ENV",
    "compare_versions",
    "request_background_refresh",
    "snapshot_is_fresh",
]
