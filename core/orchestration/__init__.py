#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Runtime-owned engine topology and core-owned group lifecycle contracts."""

from .contracts import (
    GroupPlan,
    OrchestrationError,
    TaskAssignment,
    build_group_plan,
    build_single_group_plan,
    validate_orchestration_contract,
    validate_group_document,
    validate_target_binding,
    orchestration_contract_sha256,
)
from .member import MemberAgent, MemberJobError, MemberJobStore, PROTOCOL as MEMBER_JOB_PROTOCOL
from .credentials import (
    GroupCredentialError,
    credential_sha256,
    derive_group_credential,
    ensure_master as ensure_group_credential_master,
)

__all__ = [
    "GroupPlan",
    "OrchestrationError",
    "TaskAssignment",
    "build_group_plan",
    "build_single_group_plan",
    "MemberAgent",
    "MemberJobError",
    "MemberJobStore",
    "MEMBER_JOB_PROTOCOL",
    "GroupCredentialError",
    "credential_sha256",
    "derive_group_credential",
    "ensure_group_credential_master",
    "validate_orchestration_contract",
    "validate_group_document",
    "validate_target_binding",
    "orchestration_contract_sha256",
]
