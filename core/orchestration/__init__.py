#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Runtime-owned execution topology and Core-owned placement-group contracts."""

from .contracts import (
    PlacementGroupPlan,
    OrchestrationError,
    Placement,
    bind_endpoint_node,
    build_placement_group_plan,
    build_single_placement_group_plan,
    validate_orchestration_contract,
    validate_placement_group_document,
    validate_placement_group_target_interconnect,
    validate_target_binding,
    orchestration_contract_sha256,
)
from .member import MemberAgent, MemberJobError, MemberJobStore, PROTOCOL as MEMBER_JOB_PROTOCOL
from .credentials import (
    PlacementGroupCredentialError,
    credential_sha256,
    derive_placement_group_credential,
    ensure_master as ensure_placement_group_credential_master,
)

__all__ = [
    "PlacementGroupPlan",
    "OrchestrationError",
    "Placement",
    "bind_endpoint_node",
    "build_placement_group_plan",
    "build_single_placement_group_plan",
    "MemberAgent",
    "MemberJobError",
    "MemberJobStore",
    "MEMBER_JOB_PROTOCOL",
    "PlacementGroupCredentialError",
    "credential_sha256",
    "derive_placement_group_credential",
    "ensure_placement_group_credential_master",
    "validate_orchestration_contract",
    "validate_placement_group_document",
    "validate_placement_group_target_interconnect",
    "validate_target_binding",
    "orchestration_contract_sha256",
]
