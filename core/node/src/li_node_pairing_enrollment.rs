// SPDX-License-Identifier: AGPL-3.0-only

use li_core_interface::{Node, NodeRole, NodeState, UnixMilliseconds};
use li_database::{DatabaseCollection, DatabaseRevision, DatabaseTransaction};

use crate::{
    event_if_applied, node_record, node_with_role, outbox_record, pending_outbox_event,
    LocalNodeRoleReadinessProvider, LocalNodeRoleTransition, NodeManager, NodeManagerChange,
    NodeManagerError, NodeManagerEvent,
};

impl NodeManager {
    // Atomically appends one validated child enrollment and outbox event to caller-owned state.
    pub fn enroll_child_with_transaction(
        &self,
        idempotency_key: &str,
        child: Node,
        transaction: DatabaseTransaction,
    ) -> Result<NodeManagerChange<Node>, NodeManagerError> {
        self.require_active_main()?;
        if transaction.idempotency_key() != idempotency_key {
            return Err(NodeManagerError::InvalidNodeEnrollment {
                reason: "enrollment transaction identity differs from its replay identity",
            });
        }
        if child.role() != NodeRole::Child
            || child.state() != NodeState::Pending
            || child.identity().node_id() == self.local_node_id()
        {
            return Err(NodeManagerError::InvalidNodeEnrollment {
                reason: "enrollment requires one distinct pending child",
            });
        }
        if let Some((existing, _revision)) = self.node_if_available(child.identity().node_id())? {
            if existing != child {
                return Err(NodeManagerError::NodeIdentityConflict {
                    reason: "node identity is already enrolled with different state",
                });
            }
        } else {
            self.require_unique_node_identity(&child)?;
        }

        let node_id = child.identity().node_id().clone();
        let event = NodeManagerEvent::NodeEnrolled {
            node_id: node_id.clone(),
        };
        let outbox =
            pending_outbox_event(idempotency_key, &event, child.timestamps().updated_at())?;
        let result = self.database.write_transaction(
            transaction
                .save(node_record(&child), DatabaseRevision::Missing)?
                .save(outbox_record(&outbox), DatabaseRevision::Missing)?,
        )?;
        let commits = result.commit().commits();
        let node_commit = commits
            .iter()
            .find(|commit| {
                commit.collection == DatabaseCollection::Nodes
                    && commit.identifier == node_id.as_str()
            })
            .ok_or(NodeManagerError::CorruptState {
                reason: "pairing enrollment transaction omitted the child node commit",
            })?;
        if commits
            .iter()
            .filter(|commit| commit.collection == DatabaseCollection::Outbox)
            .count()
            != 1
        {
            return Err(NodeManagerError::CorruptState {
                reason: "pairing enrollment transaction has an invalid outbox commit",
            });
        }
        Ok(NodeManagerChange::committed(
            child,
            node_commit.revision,
            event_if_applied(result.disposition(), event),
        ))
    }

    // Atomically commits verified pairing state with local child and destination main authority.
    #[allow(clippy::too_many_arguments)]
    pub fn activate_paired_child_with_transaction(
        &self,
        idempotency_key: &str,
        expected_local_revision: u64,
        main: &Node,
        changed_at: UnixMilliseconds,
        readiness: &dyn LocalNodeRoleReadinessProvider,
        transaction: DatabaseTransaction,
    ) -> Result<NodeManagerChange<Node>, NodeManagerError> {
        if transaction.idempotency_key() != idempotency_key {
            return Err(NodeManagerError::InvalidLocalRoleTransition {
                reason: "pairing transaction identity differs from its replay identity",
            });
        }
        let (local, local_revision) = self.node_with_revision(self.local_node_id())?;
        let transition = LocalNodeRoleTransition::BecomeChild { main: main.clone() };
        if let Some(observed) =
            self.observed_local_role_transition(&local, local_revision, &transition)?
        {
            return Ok(observed);
        }
        if local.role() != NodeRole::Main
            || local.state() != NodeState::Active
            || main.role() != NodeRole::Main
            || main.state() != NodeState::Active
            || main.identity().node_id() == local.identity().node_id()
        {
            return Err(NodeManagerError::InvalidLocalRoleTransition {
                reason: "paired child activation requires distinct active main authority",
            });
        }
        let current_main = self.active_main_with_revision()?.0;
        if current_main.identity().node_id() != local.identity().node_id() {
            return Err(NodeManagerError::InvalidLocalRoleTransition {
                reason: "the local node does not own current main authority",
            });
        }
        let (authority, authority_revision) = self.authority_record(main)?;
        let proof = readiness.proof(&local, &transition, changed_at)?;
        proof.validate(
            local.identity().node_id(),
            NodeRole::Main,
            NodeRole::Child,
            authority.identity().node_id(),
            changed_at,
        )?;
        let updated_local = node_with_role(&local, NodeRole::Child, NodeState::Active, changed_at)?;
        let event = NodeManagerEvent::LocalRoleChanged {
            node_id: self.local_node_id().clone(),
            role: NodeRole::Child,
        };
        let outbox = pending_outbox_event(idempotency_key, &event, changed_at)?;
        let result = self.database.write_transaction(
            transaction
                .save(
                    node_record(&updated_local),
                    DatabaseRevision::Exact(expected_local_revision),
                )?
                .save(node_record(&authority), authority_revision)?
                .save(outbox_record(&outbox), DatabaseRevision::Missing)?,
        )?;
        let revision = paired_child_transaction_revision(
            result.commit().commits(),
            updated_local.identity().node_id().as_str(),
            authority.identity().node_id().as_str(),
        )?;
        Ok(NodeManagerChange::committed(
            updated_local,
            revision,
            event_if_applied(result.disposition(), event),
        ))
    }

    // Atomically restores local main authority while deleting one failed pairing's state.
    #[allow(clippy::too_many_arguments)]
    pub fn restore_paired_main_with_transaction(
        &self,
        idempotency_key: &str,
        expected_local_revision: u64,
        paired_main: &Node,
        changed_at: UnixMilliseconds,
        readiness: &dyn LocalNodeRoleReadinessProvider,
        transaction: DatabaseTransaction,
    ) -> Result<NodeManagerChange<Node>, NodeManagerError> {
        if transaction.idempotency_key() != idempotency_key {
            return Err(NodeManagerError::InvalidLocalRoleTransition {
                reason: "pairing rollback transaction identity differs from its replay identity",
            });
        }
        let (local, local_revision) = self.node_with_revision(self.local_node_id())?;
        let authority = self.node_if_available(paired_main.identity().node_id())?;
        if local.role() == NodeRole::Main
            && local.state() == NodeState::Active
            && authority.is_none()
        {
            return Ok(NodeManagerChange::observed(local, local_revision));
        }
        let Some((authority, authority_revision)) = authority else {
            return Err(NodeManagerError::InvalidLocalRoleTransition {
                reason: "pairing rollback is missing its exact main authority",
            });
        };
        if local.role() != NodeRole::Child
            || local.state() != NodeState::Active
            || !crate::same_node_authority(&authority, paired_main)
        {
            return Err(NodeManagerError::InvalidLocalRoleTransition {
                reason: "pairing rollback authority differs from committed child state",
            });
        }
        let transition = LocalNodeRoleTransition::BecomeMain;
        let proof = readiness.proof(&local, &transition, changed_at)?;
        proof.validate(
            local.identity().node_id(),
            NodeRole::Child,
            NodeRole::Main,
            authority.identity().node_id(),
            changed_at,
        )?;
        let updated_local = node_with_role(&local, NodeRole::Main, NodeState::Active, changed_at)?;
        let event = NodeManagerEvent::LocalRoleChanged {
            node_id: self.local_node_id().clone(),
            role: NodeRole::Main,
        };
        let outbox = pending_outbox_event(idempotency_key, &event, changed_at)?;
        let result = self.database.write_transaction(
            transaction
                .save(
                    node_record(&updated_local),
                    DatabaseRevision::Exact(expected_local_revision),
                )?
                .delete::<crate::NodeDatabaseRecord>(
                    authority.identity().node_id().as_str(),
                    DatabaseRevision::Exact(authority_revision),
                )?
                .save(outbox_record(&outbox), DatabaseRevision::Missing)?,
        )?;
        let revision = paired_main_restoration_revision(
            result.commit().commits(),
            updated_local.identity().node_id().as_str(),
            authority.identity().node_id().as_str(),
        )?;
        Ok(NodeManagerChange::committed(
            updated_local,
            revision,
            event_if_applied(result.disposition(), event),
        ))
    }
}

// Returns the local revision from one caller-prefixed pairing activation transaction.
fn paired_child_transaction_revision(
    commits: &[li_database::DatabaseCommit],
    local_node_id: &str,
    authority_node_id: &str,
) -> Result<u64, NodeManagerError> {
    let values =
        commits
            .get(commits.len().saturating_sub(3)..)
            .ok_or(NodeManagerError::CorruptState {
                reason: "paired child transaction omitted authority commits",
            })?;
    let local = &values[0];
    let authority = &values[1];
    let outbox = &values[2];
    if local.collection != DatabaseCollection::Nodes
        || local.identifier != local_node_id
        || authority.collection != DatabaseCollection::Nodes
        || authority.identifier != authority_node_id
        || outbox.collection != DatabaseCollection::Outbox
    {
        return Err(NodeManagerError::CorruptState {
            reason: "paired child transaction authority commits are inconsistent",
        });
    }
    Ok(local.revision)
}

// Returns the local revision from one caller-prefixed pairing rollback transaction.
fn paired_main_restoration_revision(
    commits: &[li_database::DatabaseCommit],
    local_node_id: &str,
    authority_node_id: &str,
) -> Result<u64, NodeManagerError> {
    let values =
        commits
            .get(commits.len().saturating_sub(3)..)
            .ok_or(NodeManagerError::CorruptState {
                reason: "pairing rollback transaction omitted authority commits",
            })?;
    let local = &values[0];
    let authority = &values[1];
    let outbox = &values[2];
    if local.collection != DatabaseCollection::Nodes
        || local.identifier != local_node_id
        || authority.collection != DatabaseCollection::Nodes
        || authority.identifier != authority_node_id
        || outbox.collection != DatabaseCollection::Outbox
    {
        return Err(NodeManagerError::CorruptState {
            reason: "pairing rollback transaction authority commits are inconsistent",
        });
    }
    Ok(local.revision)
}
