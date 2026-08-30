// SPDX-License-Identifier: AGPL-3.0-only

use li_core_interface::{Node, NodeId, NodeRole, UnixMilliseconds};

use crate::NodeManagerError;

// Selects one complete local node authority transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocalNodeRoleTransition {
    BecomeChild { main: Node },
    BecomeMain,
}

impl LocalNodeRoleTransition {
    // Returns the target role represented by this transition.
    pub const fn target_role(&self) -> NodeRole {
        match self {
            Self::BecomeChild { .. } => NodeRole::Child,
            Self::BecomeMain => NodeRole::Main,
        }
    }
}

// Proves external placement and gateway impact is clear for one exact role transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalNodeRoleTransitionProof {
    local_node_id: NodeId,
    from_role: NodeRole,
    to_role: NodeRole,
    authority_node_id: NodeId,
    issued_at: UnixMilliseconds,
    expires_at: UnixMilliseconds,
}

impl LocalNodeRoleTransitionProof {
    // Creates one bounded proof without encoding placement or gateway internals.
    pub fn new(
        local_node_id: NodeId,
        from_role: NodeRole,
        to_role: NodeRole,
        authority_node_id: NodeId,
        issued_at: UnixMilliseconds,
        expires_at: UnixMilliseconds,
    ) -> Result<Self, NodeManagerError> {
        if from_role == to_role
            || authority_node_id == local_node_id
            || expires_at.value() < issued_at.value()
            || expires_at.value() - issued_at.value() > 5 * 60 * 1_000
        {
            return Err(NodeManagerError::InvalidLocalRoleTransition {
                reason: "readiness proof identity, roles, or validity window is invalid",
            });
        }
        Ok(Self {
            local_node_id,
            from_role,
            to_role,
            authority_node_id,
            issued_at,
            expires_at,
        })
    }

    // Requires this proof to match one exact role transition at commit time.
    pub(crate) fn validate(
        &self,
        local_node_id: &NodeId,
        from_role: NodeRole,
        to_role: NodeRole,
        authority_node_id: &NodeId,
        now: UnixMilliseconds,
    ) -> Result<(), NodeManagerError> {
        if &self.local_node_id != local_node_id
            || self.from_role != from_role
            || self.to_role != to_role
            || &self.authority_node_id != authority_node_id
            || now.value() < self.issued_at.value()
            || now.value() > self.expires_at.value()
        {
            return Err(NodeManagerError::InvalidLocalRoleTransition {
                reason: "readiness proof does not bind the requested transition",
            });
        }
        Ok(())
    }
}

// Defines the narrow cross-manager readiness capability consumed by NodeManager.
pub trait LocalNodeRoleReadinessProvider: Send + Sync {
    // Proves placements, gateway exposure, and dependent operations are safe to reconfigure.
    fn proof(
        &self,
        local: &Node,
        transition: &LocalNodeRoleTransition,
        now: UnixMilliseconds,
    ) -> Result<LocalNodeRoleTransitionProof, NodeManagerError>;
}
