// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use li_benchmark_manager::BenchmarkSubject;
use li_core_interface::{
    InstallationId, LogicalModelName, OperationId, PlacementGroupId, PlacementGroupState,
    RuntimeInstallationId, Sha256Digest,
};
use li_database::{
    DatabaseCollection, DatabaseCommand, DatabaseCommitDisposition, DatabaseError, DatabaseManager,
    DatabaseQuery, DatabaseRecord, DatabaseResult, DatabaseRevision,
};
use serde::{Deserialize, Serialize};

use crate::{
    NodeBenchmarkCandidateHandoffError, NodeBenchmarkCandidateHandoffPhase,
    NodeBenchmarkCandidateHandoffRecord, NodeBenchmarkCandidateHandoffStore,
    VersionedNodeBenchmarkCandidateHandoff,
};

// Stores one private benchmark subject without exposing it through a transport schema.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct BenchmarkSubjectDatabaseRecord {
    installation_id: String,
    runtime_installation_id: String,
    model: String,
    placement_group_id: String,
    execution_sha256: String,
    benchmark_contract_sha256: String,
    target_contract_sha256: String,
}

// Stores one Node-owned candidate handoff phase without candidate artifact paths.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct BenchmarkCandidateHandoffDatabaseRecord {
    transaction_id: String,
    request_sha256: String,
    baseline: BenchmarkSubjectDatabaseRecord,
    baseline_record_sha256: String,
    baseline_initial_state: String,
    candidate_installation_id: String,
    candidate_group_id: String,
    restoration_group_id: String,
    runtime_execution_sha256: String,
    phase: String,
}

impl DatabaseRecord for BenchmarkCandidateHandoffDatabaseRecord {
    const COLLECTION: DatabaseCollection = DatabaseCollection::BenchmarkHandoffs;

    // Returns the deterministic verification transaction identity.
    fn identifier(&self) -> &str {
        &self.transaction_id
    }
}

// Adapts the Node-owned candidate handoff journal to DatabaseManager.
pub struct DatabaseNodeBenchmarkCandidateHandoffStore {
    database: Arc<DatabaseManager>,
}

impl DatabaseNodeBenchmarkCandidateHandoffStore {
    // Creates one adapter without transferring DatabaseManager lifecycle ownership.
    pub const fn new(database: Arc<DatabaseManager>) -> Self {
        Self { database }
    }
}

impl NodeBenchmarkCandidateHandoffStore for DatabaseNodeBenchmarkCandidateHandoffStore {
    // Reads one validated durable handoff transaction.
    fn read(
        &self,
        transaction_id: &OperationId,
    ) -> Result<Option<VersionedNodeBenchmarkCandidateHandoff>, NodeBenchmarkCandidateHandoffError>
    {
        match self.database.read(
            DatabaseQuery::<BenchmarkCandidateHandoffDatabaseRecord>::record(
                transaction_id.as_str(),
            ),
        ) {
            Ok(DatabaseResult::Record(stored)) => {
                Ok(Some(VersionedNodeBenchmarkCandidateHandoff::new(
                    handoff(stored.value)?,
                    stored.revision,
                )))
            }
            Ok(DatabaseResult::Records(_)) => {
                Err(NodeBenchmarkCandidateHandoffError::StoreUnavailable)
            }
            Err(DatabaseError::NotFound { .. }) => Ok(None),
            Err(_) => Err(NodeBenchmarkCandidateHandoffError::StoreUnavailable),
        }
    }

    // Creates one record exactly once before provider mutation.
    fn create(
        &self,
        record: NodeBenchmarkCandidateHandoffRecord,
    ) -> Result<VersionedNodeBenchmarkCandidateHandoff, NodeBenchmarkCandidateHandoffError> {
        let result = self
            .database
            .write(DatabaseCommand::save(
                format!(
                    "benchmark-handoff:{}:create",
                    record.transaction_id().as_str()
                ),
                handoff_record(&record),
                DatabaseRevision::Missing,
            ))
            .map_err(|_| NodeBenchmarkCandidateHandoffError::StoreUnavailable)?;
        require_applied(result.disposition())?;
        Ok(VersionedNodeBenchmarkCandidateHandoff::new(
            record,
            result.commit().revision,
        ))
    }

    // Replaces one exact revision for the next durable phase.
    fn replace(
        &self,
        record: NodeBenchmarkCandidateHandoffRecord,
        expected_revision: u64,
    ) -> Result<VersionedNodeBenchmarkCandidateHandoff, NodeBenchmarkCandidateHandoffError> {
        let result = self
            .database
            .write(DatabaseCommand::save(
                format!(
                    "benchmark-handoff:{}:{}",
                    record.transaction_id().as_str(),
                    expected_revision
                ),
                handoff_record(&record),
                DatabaseRevision::Exact(expected_revision),
            ))
            .map_err(|error| match error {
                DatabaseError::Conflict { .. } => NodeBenchmarkCandidateHandoffError::Conflict,
                _ => NodeBenchmarkCandidateHandoffError::StoreUnavailable,
            })?;
        require_applied(result.disposition())?;
        Ok(VersionedNodeBenchmarkCandidateHandoff::new(
            record,
            result.commit().revision,
        ))
    }
}

// Projects one validated domain record into the closed private database shape.
fn handoff_record(
    record: &NodeBenchmarkCandidateHandoffRecord,
) -> BenchmarkCandidateHandoffDatabaseRecord {
    BenchmarkCandidateHandoffDatabaseRecord {
        transaction_id: record.transaction_id().as_str().to_string(),
        request_sha256: record.request_sha256().as_str().to_string(),
        baseline: subject_record(record.baseline()),
        baseline_record_sha256: record.baseline_record_sha256().as_str().to_string(),
        baseline_initial_state: placement_state(record.baseline_initial_state()).to_string(),
        candidate_installation_id: record.candidate_installation_id().as_str().to_string(),
        candidate_group_id: record.candidate_group_id().as_str().to_string(),
        restoration_group_id: record.restoration_group_id().as_str().to_string(),
        runtime_execution_sha256: record.runtime_execution_sha256().as_str().to_string(),
        phase: phase(record.phase()).to_string(),
    }
}

// Restores one domain record while rejecting every unknown enum or malformed identity.
fn handoff(
    record: BenchmarkCandidateHandoffDatabaseRecord,
) -> Result<NodeBenchmarkCandidateHandoffRecord, NodeBenchmarkCandidateHandoffError> {
    NodeBenchmarkCandidateHandoffRecord::restore(
        OperationId::parse(&record.transaction_id).map_err(|_| invalid())?,
        Sha256Digest::parse(&record.request_sha256).map_err(|_| invalid())?,
        subject(record.baseline)?,
        Sha256Digest::parse(&record.baseline_record_sha256).map_err(|_| invalid())?,
        parse_placement_state(&record.baseline_initial_state)?,
        RuntimeInstallationId::parse(&record.candidate_installation_id).map_err(|_| invalid())?,
        PlacementGroupId::parse(&record.candidate_group_id).map_err(|_| invalid())?,
        PlacementGroupId::parse(&record.restoration_group_id).map_err(|_| invalid())?,
        Sha256Digest::parse(&record.runtime_execution_sha256).map_err(|_| invalid())?,
        parse_phase(&record.phase)?,
    )
}

// Projects one private benchmark subject into scalar database identities.
fn subject_record(subject: &BenchmarkSubject) -> BenchmarkSubjectDatabaseRecord {
    BenchmarkSubjectDatabaseRecord {
        installation_id: subject.installation_id().as_str().to_string(),
        runtime_installation_id: subject.runtime_installation_id().as_str().to_string(),
        model: subject.model().as_str().to_string(),
        placement_group_id: subject.placement_group_id().as_str().to_string(),
        execution_sha256: subject.execution_sha256().as_str().to_string(),
        benchmark_contract_sha256: subject.benchmark_contract_sha256().as_str().to_string(),
        target_contract_sha256: subject.target_contract_sha256().as_str().to_string(),
    }
}

// Restores one benchmark subject from private scalar identities.
fn subject(
    record: BenchmarkSubjectDatabaseRecord,
) -> Result<BenchmarkSubject, NodeBenchmarkCandidateHandoffError> {
    Ok(BenchmarkSubject::new(
        InstallationId::parse(&record.installation_id).map_err(|_| invalid())?,
        RuntimeInstallationId::parse(&record.runtime_installation_id).map_err(|_| invalid())?,
        LogicalModelName::parse(&record.model).map_err(|_| invalid())?,
        PlacementGroupId::parse(&record.placement_group_id).map_err(|_| invalid())?,
        Sha256Digest::parse(&record.execution_sha256).map_err(|_| invalid())?,
        Sha256Digest::parse(&record.benchmark_contract_sha256).map_err(|_| invalid())?,
        Sha256Digest::parse(&record.target_contract_sha256).map_err(|_| invalid())?,
    ))
}

// Returns the closed database token for one retained baseline state.
const fn placement_state(state: PlacementGroupState) -> &'static str {
    match state {
        PlacementGroupState::Running => "running",
        PlacementGroupState::Stopped => "stopped",
        _ => "invalid",
    }
}

// Restores one admitted baseline state and rejects every other placement lifecycle value.
fn parse_placement_state(
    value: &str,
) -> Result<PlacementGroupState, NodeBenchmarkCandidateHandoffError> {
    match value {
        "running" => Ok(PlacementGroupState::Running),
        "stopped" => Ok(PlacementGroupState::Stopped),
        _ => Err(invalid()),
    }
}

// Returns the stable private token for one handoff phase.
const fn phase(value: NodeBenchmarkCandidateHandoffPhase) -> &'static str {
    match value {
        NodeBenchmarkCandidateHandoffPhase::Prepared => "prepared",
        NodeBenchmarkCandidateHandoffPhase::CandidateAcquired => "candidate_acquired",
        NodeBenchmarkCandidateHandoffPhase::BaselineActivated => "baseline_activated",
        NodeBenchmarkCandidateHandoffPhase::BaselineReleasing => "baseline_releasing",
        NodeBenchmarkCandidateHandoffPhase::BaselineReleased => "baseline_released",
        NodeBenchmarkCandidateHandoffPhase::CandidateStaged => "candidate_staged",
        NodeBenchmarkCandidateHandoffPhase::CandidateRunning => "candidate_running",
        NodeBenchmarkCandidateHandoffPhase::Restoring => "restoring",
        NodeBenchmarkCandidateHandoffPhase::BaselineRestored => "baseline_restored",
        NodeBenchmarkCandidateHandoffPhase::Completed => "completed",
    }
}

// Restores one exact phase token and rejects forward-version values.
fn parse_phase(
    value: &str,
) -> Result<NodeBenchmarkCandidateHandoffPhase, NodeBenchmarkCandidateHandoffError> {
    match value {
        "prepared" => Ok(NodeBenchmarkCandidateHandoffPhase::Prepared),
        "candidate_acquired" => Ok(NodeBenchmarkCandidateHandoffPhase::CandidateAcquired),
        "baseline_activated" => Ok(NodeBenchmarkCandidateHandoffPhase::BaselineActivated),
        "baseline_releasing" => Ok(NodeBenchmarkCandidateHandoffPhase::BaselineReleasing),
        "baseline_released" => Ok(NodeBenchmarkCandidateHandoffPhase::BaselineReleased),
        "candidate_staged" => Ok(NodeBenchmarkCandidateHandoffPhase::CandidateStaged),
        "candidate_running" => Ok(NodeBenchmarkCandidateHandoffPhase::CandidateRunning),
        "restoring" => Ok(NodeBenchmarkCandidateHandoffPhase::Restoring),
        "baseline_restored" => Ok(NodeBenchmarkCandidateHandoffPhase::BaselineRestored),
        "completed" => Ok(NodeBenchmarkCandidateHandoffPhase::Completed),
        _ => Err(invalid()),
    }
}

// Requires DatabaseManager to have applied the exact optimistic mutation.
fn require_applied(
    disposition: DatabaseCommitDisposition,
) -> Result<(), NodeBenchmarkCandidateHandoffError> {
    match disposition {
        DatabaseCommitDisposition::Applied => Ok(()),
        DatabaseCommitDisposition::Replayed => Err(NodeBenchmarkCandidateHandoffError::Conflict),
    }
}

// Returns one terse private-decoding failure.
const fn invalid() -> NodeBenchmarkCandidateHandoffError {
    NodeBenchmarkCandidateHandoffError::StoreUnavailable
}
