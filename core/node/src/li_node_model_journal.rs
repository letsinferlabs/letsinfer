// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;
use std::sync::Arc;

use li_core_interface::{
    LogicalModelName, ModelServiceId, NodeId, OperationId, PlacementGroupId, PlacementGroupState,
    RuntimeCandidateId, RuntimeInstallationId, TargetId, TechnicalName, UnixMilliseconds,
};
use li_database::{
    DatabaseCollection, DatabaseCommand, DatabaseCommitDisposition, DatabaseError, DatabaseManager,
    DatabaseMutation, DatabaseQuery, DatabaseRecord, DatabaseResult, DatabaseRevision,
    DatabaseWriteResult,
};
use serde::{Deserialize, Serialize};

use crate::li_node_model_contract::{
    planned_placement_group_id, planned_restoration_group_id, NodeModelAction, NodeModelError,
    NodeModelInstallGroup, NodeModelJournal, NodeModelJournalState, NodeModelJournalStore,
    NodeModelRemovalRetention, NodeModelRetainedGroup, NodeModelRetainedNode,
    NodeModelRuntimeDisposition, NodeModelRuntimeReceipt, VersionedNodeModelJournal,
    MAX_INSTALL_GROUPS,
};

// Stores one normalized install group inside the private journal schema.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct InstallGroupDatabaseRecord {
    node_ids: Vec<String>,
    explicit_candidate_id: Option<String>,
}

// Stores one exact runtime disposition inside the private journal schema.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeReceiptDatabaseRecord {
    group_index: usize,
    node_id: String,
    candidate_id: String,
    installation_id: Option<String>,
    disposition: String,
}

// Stores one exact pre-command placement-group state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct InitialGroupStateDatabaseRecord {
    placement_group_id: String,
    state: String,
}

// Stores one exact node and retained runtime installation assignment.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RetainedNodeDatabaseRecord {
    node_id: String,
    installation_id: String,
}

// Stores one exact removed group and its deterministic failure-restoration identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RetainedGroupDatabaseRecord {
    source_group_id: String,
    restoration_group_id: String,
    initial_state: String,
    nodes: Vec<RetainedNodeDatabaseRecord>,
}

// Stores one closed restart-safe model lifecycle journal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct NodeModelJournalDatabaseRecord {
    operation_id: String,
    idempotency_key: String,
    action: String,
    service_id: String,
    logical_model: String,
    install_groups: Vec<InstallGroupDatabaseRecord>,
    rollback_target_id: Option<String>,
    retained_groups: Vec<RetainedGroupDatabaseRecord>,
    runtime_receipts: Vec<RuntimeReceiptDatabaseRecord>,
    planned_group_ids: Vec<String>,
    placement_group_ids: Vec<String>,
    initial_group_states: Vec<InitialGroupStateDatabaseRecord>,
    removal_node_ids: Vec<String>,
    removal_runtime_retention: String,
    state: String,
    failure_code: Option<String>,
    created_at_unix_milliseconds: u64,
    updated_at_unix_milliseconds: u64,
}

impl DatabaseRecord for NodeModelJournalDatabaseRecord {
    const COLLECTION: DatabaseCollection = DatabaseCollection::ModelLifecycles;

    // Returns the exact operation identity for this normalized command.
    fn identifier(&self) -> &str {
        &self.operation_id
    }
}

// Adapts the model lifecycle journal to DatabaseManager persistence.
pub struct DatabaseNodeModelJournalStore {
    database: Arc<DatabaseManager>,
}

impl DatabaseNodeModelJournalStore {
    // Creates one adapter without transferring DatabaseManager lifecycle ownership.
    pub const fn new(database: Arc<DatabaseManager>) -> Self {
        Self { database }
    }
}

impl NodeModelJournalStore for DatabaseNodeModelJournalStore {
    // Creates or exactly replays one normalized command.
    fn create(
        &self,
        journal: NodeModelJournal,
    ) -> Result<VersionedNodeModelJournal, NodeModelError> {
        let record = journal_record(&journal);
        let idempotency_key = format!("model_lifecycle:create:{}", journal.operation_id.as_str());
        let result = self.database.write(DatabaseCommand::save(
            idempotency_key.clone(),
            record,
            DatabaseRevision::Missing,
        ));
        match result {
            Ok(change) => {
                validate_journal_commit(
                    &change,
                    &idempotency_key,
                    &journal.operation_id,
                    DatabaseMutation::Created,
                    1,
                )?;
                match change.disposition() {
                    DatabaseCommitDisposition::Applied => {
                        Ok(VersionedNodeModelJournal::new(journal, 1))
                    }
                    DatabaseCommitDisposition::Replayed => self
                        .read(&journal.operation_id)?
                        .filter(|stored| stored.revision() == 1 && stored.journal() == &journal)
                        .ok_or(NodeModelError::JournalConflict),
                }
            }
            Err(DatabaseError::Conflict { .. }) => self
                .read(&journal.operation_id)?
                .filter(|stored| stored.journal() == &journal)
                .ok_or(NodeModelError::JournalConflict),
            Err(error) => Err(journal_database_error(error)),
        }
    }

    // Returns one fully validated command journal.
    fn read(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<VersionedNodeModelJournal>, NodeModelError> {
        match self
            .database
            .read(DatabaseQuery::<NodeModelJournalDatabaseRecord>::record(
                operation_id.as_str(),
            )) {
            Ok(DatabaseResult::Record(stored)) => Ok(Some(VersionedNodeModelJournal::new(
                journal_from_record(stored.value)?,
                stored.revision,
            ))),
            Ok(DatabaseResult::Records(_)) => Err(NodeModelError::JournalCorrupt),
            Err(DatabaseError::NotFound { .. }) => Ok(None),
            Err(error) => Err(journal_database_error(error)),
        }
    }

    // Returns every fully validated command journal in database order.
    fn all(&self) -> Result<Vec<VersionedNodeModelJournal>, NodeModelError> {
        match self
            .database
            .read(DatabaseQuery::<NodeModelJournalDatabaseRecord>::all())
        {
            Ok(DatabaseResult::Records(records)) => records
                .into_iter()
                .map(|stored| {
                    Ok(VersionedNodeModelJournal::new(
                        journal_from_record(stored.value)?,
                        stored.revision,
                    ))
                })
                .collect(),
            Ok(DatabaseResult::Record(_)) => Err(NodeModelError::JournalCorrupt),
            Err(error) => Err(journal_database_error(error)),
        }
    }

    // Advances one exact optimistic journal revision.
    fn replace(
        &self,
        journal: NodeModelJournal,
        expected_revision: u64,
    ) -> Result<VersionedNodeModelJournal, NodeModelError> {
        let next_revision = expected_revision
            .checked_add(1)
            .ok_or(NodeModelError::JournalConflict)?;
        let idempotency_key = format!(
            "model_lifecycle:replace:{}:{expected_revision}",
            journal.operation_id.as_str()
        );
        let result = self
            .database
            .write(DatabaseCommand::save(
                idempotency_key.clone(),
                journal_record(&journal),
                DatabaseRevision::Exact(expected_revision),
            ))
            .map_err(journal_database_error)?;
        validate_journal_commit(
            &result,
            &idempotency_key,
            &journal.operation_id,
            DatabaseMutation::Updated,
            next_revision,
        )?;
        match result.disposition() {
            DatabaseCommitDisposition::Applied => {
                Ok(VersionedNodeModelJournal::new(journal, next_revision))
            }
            DatabaseCommitDisposition::Replayed => self
                .read(&journal.operation_id)?
                .filter(|stored| stored.revision() == next_revision && stored.journal() == &journal)
                .ok_or(NodeModelError::JournalConflict),
        }
    }
}

// Verifies one database commit receipt before trusting its optimistic revision.
fn validate_journal_commit(
    result: &DatabaseWriteResult,
    idempotency_key: &str,
    operation_id: &OperationId,
    mutation: DatabaseMutation,
    revision: u64,
) -> Result<(), NodeModelError> {
    let commit = result.commit();
    if commit.idempotency_key != idempotency_key
        || commit.collection != DatabaseCollection::ModelLifecycles
        || commit.identifier != operation_id.as_str()
        || commit.mutation != mutation
        || commit.revision != revision
    {
        return Err(NodeModelError::JournalCorrupt);
    }
    Ok(())
}

// Converts one database failure to the journal's stable surface.
fn journal_database_error(error: DatabaseError) -> NodeModelError {
    match error {
        DatabaseError::Conflict { .. } | DatabaseError::IdempotencyConflict { .. } => {
            NodeModelError::JournalConflict
        }
        DatabaseError::Corrupt { .. } => NodeModelError::JournalCorrupt,
        DatabaseError::NotFound { .. }
        | DatabaseError::InvalidInput { .. }
        | DatabaseError::Unavailable { .. }
        | DatabaseError::Closed => NodeModelError::JournalUnavailable,
    }
}

// Projects one typed journal into its closed private database schema.
fn journal_record(journal: &NodeModelJournal) -> NodeModelJournalDatabaseRecord {
    NodeModelJournalDatabaseRecord {
        operation_id: journal.operation_id.as_str().to_string(),
        idempotency_key: journal.idempotency_key.as_str().to_string(),
        action: action_name(journal.action).to_string(),
        service_id: journal.service_id.as_str().to_string(),
        logical_model: journal.logical_model.as_str().to_string(),
        install_groups: journal
            .install_groups
            .iter()
            .map(|group| InstallGroupDatabaseRecord {
                node_ids: group
                    .node_ids
                    .iter()
                    .map(|node_id| node_id.as_str().to_string())
                    .collect(),
                explicit_candidate_id: group
                    .explicit_candidate_id
                    .as_ref()
                    .map(|candidate_id| candidate_id.as_str().to_string()),
            })
            .collect(),
        rollback_target_id: journal
            .rollback_target_id
            .as_ref()
            .map(|target_id| target_id.as_str().to_string()),
        retained_groups: journal
            .retained_groups
            .iter()
            .map(|group| RetainedGroupDatabaseRecord {
                source_group_id: group.source_group_id.as_str().to_string(),
                restoration_group_id: group.restoration_group_id.as_str().to_string(),
                initial_state: placement_group_state_name(group.initial_state).to_string(),
                nodes: group
                    .nodes
                    .iter()
                    .map(|node| RetainedNodeDatabaseRecord {
                        node_id: node.node_id.as_str().to_string(),
                        installation_id: node.installation_id.as_str().to_string(),
                    })
                    .collect(),
            })
            .collect(),
        runtime_receipts: journal
            .runtime_receipts
            .iter()
            .map(|receipt| RuntimeReceiptDatabaseRecord {
                group_index: receipt.group_index,
                node_id: receipt.node_id.as_str().to_string(),
                candidate_id: receipt.candidate_id.as_str().to_string(),
                installation_id: receipt
                    .installation_id
                    .as_ref()
                    .map(|installation_id| installation_id.as_str().to_string()),
                disposition: runtime_disposition_name(receipt.disposition).to_string(),
            })
            .collect(),
        planned_group_ids: journal
            .planned_group_ids
            .iter()
            .map(|placement_group_id| placement_group_id.as_str().to_string())
            .collect(),
        placement_group_ids: journal
            .placement_group_ids
            .iter()
            .map(|placement_group_id| placement_group_id.as_str().to_string())
            .collect(),
        initial_group_states: journal
            .initial_group_states
            .iter()
            .map(
                |(placement_group_id, state)| InitialGroupStateDatabaseRecord {
                    placement_group_id: placement_group_id.as_str().to_string(),
                    state: placement_group_state_name(*state).to_string(),
                },
            )
            .collect(),
        removal_node_ids: journal
            .removal_node_ids
            .iter()
            .map(|node_id| node_id.as_str().to_string())
            .collect(),
        removal_runtime_retention: removal_runtime_retention_name(
            journal.removal_runtime_retention,
        )
        .to_string(),
        state: journal_state_name(journal.state).to_string(),
        failure_code: journal
            .failure_code
            .as_ref()
            .map(|failure_code| failure_code.as_str().to_string()),
        created_at_unix_milliseconds: journal.created_at.value(),
        updated_at_unix_milliseconds: journal.updated_at.value(),
    }
}

// Reconstructs and validates one closed private database journal.
fn journal_from_record(
    record: NodeModelJournalDatabaseRecord,
) -> Result<NodeModelJournal, NodeModelError> {
    let install_groups: Vec<_> = record
        .install_groups
        .into_iter()
        .map(|group| {
            NodeModelInstallGroup::new(
                group
                    .node_ids
                    .into_iter()
                    .map(|node_id| {
                        NodeId::parse(&node_id).map_err(|_| NodeModelError::JournalCorrupt)
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                group
                    .explicit_candidate_id
                    .map(|candidate_id| {
                        RuntimeCandidateId::parse(&candidate_id)
                            .map_err(|_| NodeModelError::JournalCorrupt)
                    })
                    .transpose()?,
            )
            .map_err(|_| NodeModelError::JournalCorrupt)
        })
        .collect::<Result<_, _>>()?;
    let runtime_receipts: Vec<_> = record
        .runtime_receipts
        .into_iter()
        .map(|receipt| {
            let disposition = runtime_disposition(&receipt.disposition)?;
            let installation_id = receipt
                .installation_id
                .map(|installation_id| {
                    RuntimeInstallationId::parse(&installation_id)
                        .map_err(|_| NodeModelError::JournalCorrupt)
                })
                .transpose()?;
            if (disposition == NodeModelRuntimeDisposition::InstallPending)
                == installation_id.is_some()
            {
                return Err(NodeModelError::JournalCorrupt);
            }
            Ok(NodeModelRuntimeReceipt {
                group_index: receipt.group_index,
                node_id: NodeId::parse(&receipt.node_id)
                    .map_err(|_| NodeModelError::JournalCorrupt)?,
                candidate_id: RuntimeCandidateId::parse(&receipt.candidate_id)
                    .map_err(|_| NodeModelError::JournalCorrupt)?,
                installation_id,
                disposition,
            })
        })
        .collect::<Result<_, _>>()?;
    let placement_group_ids = record
        .placement_group_ids
        .into_iter()
        .map(|placement_group_id| {
            PlacementGroupId::parse(&placement_group_id).map_err(|_| NodeModelError::JournalCorrupt)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let planned_group_ids = record
        .planned_group_ids
        .into_iter()
        .map(|placement_group_id| {
            PlacementGroupId::parse(&placement_group_id).map_err(|_| NodeModelError::JournalCorrupt)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let initial_group_states = record
        .initial_group_states
        .into_iter()
        .map(|entry| -> Result<_, NodeModelError> {
            Ok((
                PlacementGroupId::parse(&entry.placement_group_id)
                    .map_err(|_| NodeModelError::JournalCorrupt)?,
                placement_group_state(&entry.state)?,
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let retained_groups = record
        .retained_groups
        .into_iter()
        .map(|group| {
            NodeModelRetainedGroup::new(
                PlacementGroupId::parse(&group.source_group_id)
                    .map_err(|_| NodeModelError::JournalCorrupt)?,
                PlacementGroupId::parse(&group.restoration_group_id)
                    .map_err(|_| NodeModelError::JournalCorrupt)?,
                placement_group_state(&group.initial_state)?,
                group
                    .nodes
                    .into_iter()
                    .map(|node| {
                        Ok(NodeModelRetainedNode::new(
                            NodeId::parse(&node.node_id)
                                .map_err(|_| NodeModelError::JournalCorrupt)?,
                            RuntimeInstallationId::parse(&node.installation_id)
                                .map_err(|_| NodeModelError::JournalCorrupt)?,
                        ))
                    })
                    .collect::<Result<Vec<_>, NodeModelError>>()?,
            )
            .map_err(|_| NodeModelError::JournalCorrupt)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let removal_node_ids = record
        .removal_node_ids
        .into_iter()
        .map(|node_id| NodeId::parse(&node_id).map_err(|_| NodeModelError::JournalCorrupt))
        .collect::<Result<Vec<_>, _>>()?;
    let action = action(&record.action)?;
    let state = journal_state(&record.state)?;
    let journal = NodeModelJournal {
        operation_id: OperationId::parse(&record.operation_id)
            .map_err(|_| NodeModelError::JournalCorrupt)?,
        idempotency_key: TechnicalName::parse(&record.idempotency_key)
            .map_err(|_| NodeModelError::JournalCorrupt)?,
        action,
        service_id: ModelServiceId::parse(&record.service_id)
            .map_err(|_| NodeModelError::JournalCorrupt)?,
        logical_model: LogicalModelName::parse(&record.logical_model)
            .map_err(|_| NodeModelError::JournalCorrupt)?,
        install_groups,
        rollback_target_id: record
            .rollback_target_id
            .map(|target_id| {
                TargetId::parse(&target_id).map_err(|_| NodeModelError::JournalCorrupt)
            })
            .transpose()?,
        retained_groups,
        runtime_receipts,
        planned_group_ids,
        placement_group_ids,
        initial_group_states,
        removal_node_ids,
        removal_runtime_retention: removal_runtime_retention(&record.removal_runtime_retention)?,
        state,
        failure_code: record
            .failure_code
            .map(|failure_code| {
                TechnicalName::parse(&failure_code).map_err(|_| NodeModelError::JournalCorrupt)
            })
            .transpose()?,
        created_at: UnixMilliseconds::new(record.created_at_unix_milliseconds),
        updated_at: UnixMilliseconds::new(record.updated_at_unix_milliseconds),
    };
    validate_journal(&journal)?;
    Ok(journal)
}

// Validates all cross-field journal invariants after private persistence decode.
fn validate_journal(journal: &NodeModelJournal) -> Result<(), NodeModelError> {
    let failure_required = matches!(
        journal.state,
        NodeModelJournalState::CleanupPending | NodeModelJournalState::Failed
    );
    if journal.created_at.value() == 0
        || journal.updated_at < journal.created_at
        || failure_required != journal.failure_code.is_some()
        || matches!(
            journal.action,
            NodeModelAction::Install | NodeModelAction::Update | NodeModelAction::Rollback
        ) != !journal.install_groups.is_empty()
        || (journal.action != NodeModelAction::Rollback && journal.rollback_target_id.is_some())
        || journal.install_groups.len() > MAX_INSTALL_GROUPS
        || journal.planned_group_ids.len() > MAX_INSTALL_GROUPS
        || journal.placement_group_ids.len() > MAX_INSTALL_GROUPS
        || journal.retained_groups.len() > MAX_INSTALL_GROUPS
    {
        return Err(NodeModelError::JournalCorrupt);
    }
    let runtime_keys: HashSet<_> = journal
        .runtime_receipts
        .iter()
        .map(|receipt| (receipt.group_index, &receipt.node_id))
        .collect();
    let placement_ids: HashSet<_> = journal.placement_group_ids.iter().collect();
    let planned_ids: HashSet<_> = journal.planned_group_ids.iter().collect();
    let initial_ids: HashSet<_> = journal
        .initial_group_states
        .iter()
        .map(|(placement_group_id, _)| placement_group_id)
        .collect();
    let retained_source_ids: HashSet<_> = journal
        .retained_groups
        .iter()
        .map(NodeModelRetainedGroup::source_group_id)
        .collect();
    let retained_restoration_ids: HashSet<_> = journal
        .retained_groups
        .iter()
        .map(NodeModelRetainedGroup::restoration_group_id)
        .collect();
    let removal_ids: HashSet<_> = journal.removal_node_ids.iter().collect();
    let removal_ids_sorted = journal
        .removal_node_ids
        .windows(2)
        .all(|identities| identities[0].as_str() < identities[1].as_str());
    let runtime_receipts_sorted = journal.runtime_receipts.windows(2).all(|receipts| {
        (receipts[0].group_index, receipts[0].node_id.as_str())
            < (receipts[1].group_index, receipts[1].node_id.as_str())
    });
    let install_group_plan_matches = !matches!(
        journal.action,
        NodeModelAction::Install | NodeModelAction::Update | NodeModelAction::Rollback
    ) || (journal.planned_group_ids.len()
        == journal.install_groups.len()
        && journal
            .planned_group_ids
            .iter()
            .enumerate()
            .all(|(group_index, planned)| {
                planned_placement_group_id(&journal.operation_id, group_index)
                    .is_ok_and(|expected| &expected == planned)
            })
        && journal.placement_group_ids.len() <= journal.planned_group_ids.len()
        && journal
            .placement_group_ids
            .iter()
            .zip(&journal.planned_group_ids)
            .all(|(committed, planned)| committed == planned));
    let existing_group_plan_matches = matches!(
        journal.action,
        NodeModelAction::Install | NodeModelAction::Update | NodeModelAction::Rollback
    ) || (journal.runtime_receipts.is_empty()
        && journal.placement_group_ids.len() == journal.initial_group_states.len()
        && journal
            .placement_group_ids
            .iter()
            .zip(&journal.initial_group_states)
            .all(|(planned, (initial, _))| planned == initial));
    let action_owned_fields_are_closed = match journal.action {
        NodeModelAction::Install => {
            journal.rollback_target_id.is_none()
                && journal.retained_groups.is_empty()
                && journal.initial_group_states.is_empty()
                && journal.removal_node_ids.is_empty()
                && journal.removal_runtime_retention
                    == NodeModelRemovalRetention::RemoveUnreferencedRuntimes
        }
        NodeModelAction::Update => {
            journal.rollback_target_id.is_none()
                && !journal.retained_groups.is_empty()
                && journal.retained_groups.len() == journal.install_groups.len()
                && !journal.initial_group_states.is_empty()
                && journal.initial_group_states.len() == journal.install_groups.len()
                && journal.removal_node_ids.is_empty()
                && journal.removal_runtime_retention
                    == NodeModelRemovalRetention::RemoveUnreferencedRuntimes
        }
        NodeModelAction::Rollback => {
            !journal.retained_groups.is_empty()
                && journal.retained_groups.len() == journal.install_groups.len()
                && journal.initial_group_states.len() == journal.install_groups.len()
                && journal.removal_node_ids.is_empty()
                && journal.removal_runtime_retention
                    == NodeModelRemovalRetention::RemoveUnreferencedRuntimes
        }
        NodeModelAction::Pause
        | NodeModelAction::Resume
        | NodeModelAction::Restart
        | NodeModelAction::Recover => {
            journal.install_groups.is_empty()
                && journal.rollback_target_id.is_none()
                && journal.retained_groups.is_empty()
                && journal.runtime_receipts.is_empty()
                && journal.planned_group_ids.is_empty()
                && journal.removal_node_ids.is_empty()
                && journal.removal_runtime_retention
                    == NodeModelRemovalRetention::RemoveUnreferencedRuntimes
        }
        NodeModelAction::Remove => {
            journal.install_groups.is_empty()
                && journal.rollback_target_id.is_none()
                && journal.retained_groups.is_empty()
                && journal.runtime_receipts.is_empty()
                && journal.planned_group_ids.is_empty()
        }
    };
    if runtime_keys.len() != journal.runtime_receipts.len()
        || !runtime_receipts_sorted
        || !install_group_plan_matches
        || !existing_group_plan_matches
        || !action_owned_fields_are_closed
        || placement_ids.len() != journal.placement_group_ids.len()
        || planned_ids.len() != journal.planned_group_ids.len()
        || initial_ids.len() != journal.initial_group_states.len()
        || retained_source_ids.len() != journal.retained_groups.len()
        || retained_restoration_ids.len() != journal.retained_groups.len()
        || journal
            .retained_groups
            .iter()
            .enumerate()
            .any(|(group_index, group)| {
                !planned_restoration_group_id(&journal.operation_id, group_index)
                    .is_ok_and(|expected| &expected == group.restoration_group_id())
                    || group.source_group_id() == group.restoration_group_id()
                    || journal.initial_group_states.get(group_index).is_none_or(
                        |(group_id, state)| {
                            group_id != group.source_group_id() || *state != group.initial_state()
                        },
                    )
                    || journal
                        .install_groups
                        .get(group_index)
                        .is_none_or(|install_group| {
                            let retained_nodes = group
                                .nodes()
                                .iter()
                                .map(NodeModelRetainedNode::node_id)
                                .collect::<HashSet<_>>();
                            let install_nodes =
                                install_group.node_ids.iter().collect::<HashSet<_>>();
                            retained_nodes != install_nodes
                        })
            })
        || journal.removal_node_ids.len() > 64
        || removal_ids.len() != journal.removal_node_ids.len()
        || (!journal.removal_node_ids.is_empty() && !removal_ids_sorted)
        || journal.runtime_receipts.iter().any(|receipt| {
            receipt.group_index >= journal.install_groups.len()
                || !journal.install_groups[receipt.group_index]
                    .node_ids
                    .contains(&receipt.node_id)
        })
    {
        return Err(NodeModelError::JournalCorrupt);
    }
    Ok(())
}

// Returns one stable private persistence name for a model action.
fn action_name(action: NodeModelAction) -> &'static str {
    match action {
        NodeModelAction::Install => "install",
        NodeModelAction::Update => "update",
        NodeModelAction::Pause => "pause",
        NodeModelAction::Resume => "resume",
        NodeModelAction::Restart => "restart",
        NodeModelAction::Recover => "recover",
        NodeModelAction::Remove => "remove",
        NodeModelAction::Rollback => "rollback",
    }
}

// Parses one stable private model action.
fn action(value: &str) -> Result<NodeModelAction, NodeModelError> {
    match value {
        "install" => Ok(NodeModelAction::Install),
        "update" => Ok(NodeModelAction::Update),
        "pause" => Ok(NodeModelAction::Pause),
        "resume" => Ok(NodeModelAction::Resume),
        "restart" => Ok(NodeModelAction::Restart),
        "recover" => Ok(NodeModelAction::Recover),
        "remove" => Ok(NodeModelAction::Remove),
        "rollback" => Ok(NodeModelAction::Rollback),
        _ => Err(NodeModelError::JournalCorrupt),
    }
}

// Returns one stable private persistence name for a runtime disposition.
fn runtime_disposition_name(disposition: NodeModelRuntimeDisposition) -> &'static str {
    match disposition {
        NodeModelRuntimeDisposition::InstallPending => "install_pending",
        NodeModelRuntimeDisposition::Created => "created",
        NodeModelRuntimeDisposition::Reused => "reused",
        NodeModelRuntimeDisposition::OwnershipUnknown => "ownership_unknown",
    }
}

// Parses one stable private runtime disposition.
fn runtime_disposition(value: &str) -> Result<NodeModelRuntimeDisposition, NodeModelError> {
    match value {
        "install_pending" => Ok(NodeModelRuntimeDisposition::InstallPending),
        "created" => Ok(NodeModelRuntimeDisposition::Created),
        "reused" => Ok(NodeModelRuntimeDisposition::Reused),
        "ownership_unknown" => Ok(NodeModelRuntimeDisposition::OwnershipUnknown),
        _ => Err(NodeModelError::JournalCorrupt),
    }
}

// Returns one stable private persistence name for model-removal runtime retention.
fn removal_runtime_retention_name(retention: NodeModelRemovalRetention) -> &'static str {
    match retention {
        NodeModelRemovalRetention::RemoveUnreferencedRuntimes => "remove_unreferenced_runtimes",
        NodeModelRemovalRetention::PreserveModels => "preserve_models",
    }
}

// Parses one stable private model-removal runtime-retention decision.
fn removal_runtime_retention(value: &str) -> Result<NodeModelRemovalRetention, NodeModelError> {
    match value {
        "remove_unreferenced_runtimes" => Ok(NodeModelRemovalRetention::RemoveUnreferencedRuntimes),
        "preserve_models" => Ok(NodeModelRemovalRetention::PreserveModels),
        _ => Err(NodeModelError::JournalCorrupt),
    }
}

// Returns one stable private persistence name for a journal state.
fn journal_state_name(state: NodeModelJournalState) -> &'static str {
    match state {
        NodeModelJournalState::Prepared => "prepared",
        NodeModelJournalState::Executing => "executing",
        NodeModelJournalState::Compensating => "compensating",
        NodeModelJournalState::CleanupPending => "cleanup_pending",
        NodeModelJournalState::Succeeded => "succeeded",
        NodeModelJournalState::RolledBack => "rolled_back",
        NodeModelJournalState::Failed => "failed",
    }
}

// Parses one stable private journal state.
fn journal_state(value: &str) -> Result<NodeModelJournalState, NodeModelError> {
    match value {
        "prepared" => Ok(NodeModelJournalState::Prepared),
        "executing" => Ok(NodeModelJournalState::Executing),
        "compensating" => Ok(NodeModelJournalState::Compensating),
        "cleanup_pending" => Ok(NodeModelJournalState::CleanupPending),
        "succeeded" => Ok(NodeModelJournalState::Succeeded),
        "rolled_back" => Ok(NodeModelJournalState::RolledBack),
        "failed" => Ok(NodeModelJournalState::Failed),
        _ => Err(NodeModelError::JournalCorrupt),
    }
}

// Returns one stable private placement-group state name.
fn placement_group_state_name(state: PlacementGroupState) -> &'static str {
    match state {
        PlacementGroupState::Staging => "staging",
        PlacementGroupState::Staged => "staged",
        PlacementGroupState::Starting => "starting",
        PlacementGroupState::Running => "running",
        PlacementGroupState::Degraded => "degraded",
        PlacementGroupState::Stopping => "stopping",
        PlacementGroupState::Stopped => "stopped",
        PlacementGroupState::Recovering => "recovering",
        PlacementGroupState::Removing => "removing",
        PlacementGroupState::Removed => "removed",
        PlacementGroupState::Failed => "failed",
    }
}

// Parses one stable private placement-group state.
fn placement_group_state(value: &str) -> Result<PlacementGroupState, NodeModelError> {
    match value {
        "staging" => Ok(PlacementGroupState::Staging),
        "staged" => Ok(PlacementGroupState::Staged),
        "starting" => Ok(PlacementGroupState::Starting),
        "running" => Ok(PlacementGroupState::Running),
        "degraded" => Ok(PlacementGroupState::Degraded),
        "stopping" => Ok(PlacementGroupState::Stopping),
        "stopped" => Ok(PlacementGroupState::Stopped),
        "recovering" => Ok(PlacementGroupState::Recovering),
        "removing" => Ok(PlacementGroupState::Removing),
        "removed" => Ok(PlacementGroupState::Removed),
        "failed" => Ok(PlacementGroupState::Failed),
        _ => Err(NodeModelError::JournalCorrupt),
    }
}
