// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use li_core_interface::{FailureDescription, Sha256Digest, TechnicalName};
use li_core_update_manager::{
    ActivatedCoreUpdate, CoreInstallation, CoreServiceSnapshot, CoreUpdatePhase, CoreUpdateRecord,
    CoreUpdateStore, CoreUpdateStoreError, CoreVersion, PreparedCoreUpdate,
    VersionedCoreUpdateRecord,
};
use li_database::{
    DatabaseCollection, DatabaseCommand, DatabaseError, DatabaseManager, DatabaseQuery,
    DatabaseRecord, DatabaseResult, DatabaseRevision,
};
use serde::{Deserialize, Serialize};

const CORE_UPDATE_RECORD_SCHEMA_NAME: &str = "li_core_update_record";
const CORE_UPDATE_RECORD_SCHEMA_VERSION: u32 = 1;

// Identifies the exact CoreUpdateManager journal persistence contract.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CoreUpdateDatabaseSchema {
    name: String,
    version: u32,
}

// Stores one private persistence projection of a resumable Core update journal.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CoreUpdateDatabaseRecord {
    schema: CoreUpdateDatabaseSchema,
    update_id: String,
    idempotency_key: String,
    requested_version: Option<String>,
    phase: String,
    current_version: Option<String>,
    current_source_identity: Option<String>,
    prepared_receipt_id: Option<String>,
    prepared_version: Option<String>,
    prepared_source_identity: Option<String>,
    service_snapshot_receipt_id: Option<String>,
    activation_receipt_id: Option<String>,
    activation_previous_version: Option<String>,
    activation_previous_source_identity: Option<String>,
    activation_version: Option<String>,
    activation_source_identity: Option<String>,
    failure_code: Option<String>,
    failure_message: Option<String>,
}

impl DatabaseRecord for CoreUpdateDatabaseRecord {
    const COLLECTION: DatabaseCollection = DatabaseCollection::CoreUpdates;

    // Returns the caller-owned replay identity for direct journal lookup.
    fn identifier(&self) -> &str {
        &self.idempotency_key
    }
}

// Persists CoreUpdateManager journals through the shared serialized database writer.
pub struct DatabaseCoreUpdateStore {
    database: Arc<DatabaseManager>,
}

impl DatabaseCoreUpdateStore {
    // Creates one update adapter without taking DatabaseManager lifecycle ownership.
    pub const fn new(database: Arc<DatabaseManager>) -> Self {
        Self { database }
    }

    // Returns every validated update journal for composition-owned reference analysis.
    pub fn records(&self) -> Result<Vec<VersionedCoreUpdateRecord>, CoreUpdateStoreError> {
        match self
            .database
            .read(DatabaseQuery::<CoreUpdateDatabaseRecord>::all())
        {
            Ok(DatabaseResult::Records(records)) => records
                .into_iter()
                .map(|record| {
                    Ok(VersionedCoreUpdateRecord::new(
                        update_from_record(record.value)?,
                        record.revision,
                    ))
                })
                .collect(),
            Ok(DatabaseResult::Record(_)) => Err(CoreUpdateStoreError::Corrupt),
            Err(error) => Err(update_store_error(error)),
        }
    }
}

impl CoreUpdateStore for DatabaseCoreUpdateStore {
    // Reads and validates one exact update journal when present.
    fn read(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<VersionedCoreUpdateRecord>, CoreUpdateStoreError> {
        match self
            .database
            .read(DatabaseQuery::<CoreUpdateDatabaseRecord>::record(
                idempotency_key,
            )) {
            Ok(DatabaseResult::Record(stored)) => Ok(Some(VersionedCoreUpdateRecord::new(
                update_from_record(stored.value)?,
                stored.revision,
            ))),
            Ok(DatabaseResult::Records(_)) => Err(CoreUpdateStoreError::Corrupt),
            Err(DatabaseError::NotFound { .. }) => Ok(None),
            Err(error) => Err(update_store_error(error)),
        }
    }

    // Creates one journal exactly once through a deterministic database command.
    fn create(
        &self,
        record: CoreUpdateRecord,
    ) -> Result<VersionedCoreUpdateRecord, CoreUpdateStoreError> {
        let result = self
            .database
            .write(DatabaseCommand::save(
                database_idempotency_key(&record, "create", 0),
                update_record(&record),
                DatabaseRevision::Missing,
            ))
            .map_err(update_store_error)?;
        Ok(VersionedCoreUpdateRecord::new(
            record,
            result.commit().revision,
        ))
    }

    // Replaces one exact journal revision through a replay-safe database command.
    fn replace(
        &self,
        record: CoreUpdateRecord,
        expected_revision: u64,
    ) -> Result<VersionedCoreUpdateRecord, CoreUpdateStoreError> {
        let result = self
            .database
            .write(DatabaseCommand::save(
                database_idempotency_key(&record, phase_name(record.phase()), expected_revision),
                update_record(&record),
                DatabaseRevision::Exact(expected_revision),
            ))
            .map_err(update_store_error)?;
        Ok(VersionedCoreUpdateRecord::new(
            record,
            result.commit().revision,
        ))
    }
}

// Projects one validated update journal into private persistence fields.
fn update_record(record: &CoreUpdateRecord) -> CoreUpdateDatabaseRecord {
    let (current_version, current_source_identity) = installation_fields(record.current());
    let (prepared_receipt_id, prepared_version, prepared_source_identity) = match record.prepared()
    {
        Some(prepared) => {
            let (version, identity) = installation_fields(Some(prepared.installation()));
            (
                Some(prepared.receipt_id().as_str().to_string()),
                version,
                identity,
            )
        }
        None => (None, None, None),
    };
    let (
        activation_receipt_id,
        activation_previous_version,
        activation_previous_source_identity,
        activation_version,
        activation_source_identity,
    ) = match record.activation() {
        Some(activation) => {
            let (previous_version, previous_identity) =
                installation_fields(Some(activation.previous()));
            let (version, identity) = installation_fields(Some(activation.installation()));
            (
                Some(activation.receipt_id().as_str().to_string()),
                previous_version,
                previous_identity,
                version,
                identity,
            )
        }
        None => (None, None, None, None, None),
    };
    CoreUpdateDatabaseRecord {
        schema: CoreUpdateDatabaseSchema {
            name: CORE_UPDATE_RECORD_SCHEMA_NAME.to_string(),
            version: CORE_UPDATE_RECORD_SCHEMA_VERSION,
        },
        update_id: record.update_id().as_str().to_string(),
        idempotency_key: record.idempotency_key().to_string(),
        requested_version: record
            .requested_version()
            .map(|version| version.as_str().to_string()),
        phase: phase_name(record.phase()).to_string(),
        current_version,
        current_source_identity,
        prepared_receipt_id,
        prepared_version,
        prepared_source_identity,
        service_snapshot_receipt_id: record
            .service_snapshot()
            .map(|snapshot| snapshot.receipt_id().as_str().to_string()),
        activation_receipt_id,
        activation_previous_version,
        activation_previous_source_identity,
        activation_version,
        activation_source_identity,
        failure_code: record
            .failure()
            .map(|failure| failure.code().as_str().to_string()),
        failure_message: record
            .failure()
            .map(|failure| failure.message().to_string()),
    }
}

// Reconstructs one validated update journal from private persistence.
fn update_from_record(
    record: CoreUpdateDatabaseRecord,
) -> Result<CoreUpdateRecord, CoreUpdateStoreError> {
    if record.schema.name != CORE_UPDATE_RECORD_SCHEMA_NAME
        || record.schema.version != CORE_UPDATE_RECORD_SCHEMA_VERSION
    {
        return Err(CoreUpdateStoreError::Corrupt);
    }
    let current = installation(
        record.current_version.as_deref(),
        record.current_source_identity.as_deref(),
    )?;
    let prepared_installation = installation(
        record.prepared_version.as_deref(),
        record.prepared_source_identity.as_deref(),
    )?;
    let prepared = optional_receipt(
        record.prepared_receipt_id.as_deref(),
        prepared_installation,
        PreparedCoreUpdate::new,
    )?;
    let previous = installation(
        record.activation_previous_version.as_deref(),
        record.activation_previous_source_identity.as_deref(),
    )?;
    let activated = installation(
        record.activation_version.as_deref(),
        record.activation_source_identity.as_deref(),
    )?;
    let activation = match (record.activation_receipt_id.as_deref(), previous, activated) {
        (Some(receipt), Some(previous), Some(activated)) => Some(
            ActivatedCoreUpdate::new(parse_digest(receipt)?, previous, activated)
                .map_err(|_| CoreUpdateStoreError::Corrupt)?,
        ),
        (None, None, None) => None,
        _ => return Err(CoreUpdateStoreError::Corrupt),
    };
    let failure = match (record.failure_code, record.failure_message) {
        (Some(code), Some(message)) => Some(
            FailureDescription::new(
                TechnicalName::parse(&code).map_err(|_| CoreUpdateStoreError::Corrupt)?,
                &message,
            )
            .map_err(|_| CoreUpdateStoreError::Corrupt)?,
        ),
        (None, None) => None,
        _ => return Err(CoreUpdateStoreError::Corrupt),
    };
    CoreUpdateRecord::restore(
        parse_digest(&record.update_id)?,
        &record.idempotency_key,
        record
            .requested_version
            .as_deref()
            .map(CoreVersion::parse)
            .transpose()
            .map_err(|_| CoreUpdateStoreError::Corrupt)?,
        update_phase(&record.phase)?,
        current,
        prepared,
        record
            .service_snapshot_receipt_id
            .as_deref()
            .map(parse_digest)
            .transpose()?
            .map(CoreServiceSnapshot::new),
        activation,
        failure,
    )
    .map_err(|_| CoreUpdateStoreError::Corrupt)
}

// Returns optional version and source-identity persistence fields.
fn installation_fields(
    installation: Option<&CoreInstallation>,
) -> (Option<String>, Option<String>) {
    match installation {
        Some(installation) => (
            Some(installation.version().as_str().to_string()),
            Some(installation.source_identity().as_str().to_string()),
        ),
        None => (None, None),
    }
}

// Reconstructs one installation only when both identity fields are present.
fn installation(
    version: Option<&str>,
    source_identity: Option<&str>,
) -> Result<Option<CoreInstallation>, CoreUpdateStoreError> {
    match (version, source_identity) {
        (Some(version), Some(identity)) => Ok(Some(CoreInstallation::new(
            CoreVersion::parse(version).map_err(|_| CoreUpdateStoreError::Corrupt)?,
            parse_digest(identity)?,
        ))),
        (None, None) => Ok(None),
        _ => Err(CoreUpdateStoreError::Corrupt),
    }
}

// Reconstructs one optional receipt only when receipt and value are both present.
fn optional_receipt<Value, ResultValue>(
    receipt: Option<&str>,
    value: Option<Value>,
    constructor: impl FnOnce(Sha256Digest, Value) -> ResultValue,
) -> Result<Option<ResultValue>, CoreUpdateStoreError> {
    match (receipt, value) {
        (Some(receipt), Some(value)) => Ok(Some(constructor(parse_digest(receipt)?, value))),
        (None, None) => Ok(None),
        _ => Err(CoreUpdateStoreError::Corrupt),
    }
}

// Parses one exact lowercase SHA-256 persistence value.
fn parse_digest(value: &str) -> Result<Sha256Digest, CoreUpdateStoreError> {
    Sha256Digest::parse(value).map_err(|_| CoreUpdateStoreError::Corrupt)
}

// Returns one bounded database replay key for an exact journal transition.
fn database_idempotency_key(
    record: &CoreUpdateRecord,
    phase: &str,
    expected_revision: u64,
) -> String {
    format!(
        "core-update:{}:{phase}:{expected_revision}",
        record.update_id().as_str()
    )
}

// Maps one DatabaseManager failure into the narrow update-store contract.
fn update_store_error(error: DatabaseError) -> CoreUpdateStoreError {
    match error {
        DatabaseError::Conflict { .. } | DatabaseError::IdempotencyConflict { .. } => {
            CoreUpdateStoreError::Conflict
        }
        DatabaseError::Corrupt { .. } => CoreUpdateStoreError::Corrupt,
        DatabaseError::NotFound { .. }
        | DatabaseError::InvalidInput { .. }
        | DatabaseError::Unavailable { .. }
        | DatabaseError::Closed => CoreUpdateStoreError::Unavailable,
    }
}

// Returns the private persistence name for one update phase.
fn phase_name(phase: CoreUpdatePhase) -> &'static str {
    match phase {
        CoreUpdatePhase::Requested => "requested",
        CoreUpdatePhase::Prepared => "prepared",
        CoreUpdatePhase::ServicesSnapshotted => "services_snapshotted",
        CoreUpdatePhase::Activated => "activated",
        CoreUpdatePhase::ServicesRebound => "services_rebound",
        CoreUpdatePhase::Verified => "verified",
        CoreUpdatePhase::Committed => "committed",
        CoreUpdatePhase::RollingBack => "rolling_back",
        CoreUpdatePhase::Current => "current",
        CoreUpdatePhase::CleanupPending => "cleanup_pending",
        CoreUpdatePhase::Succeeded => "succeeded",
        CoreUpdatePhase::RolledBack => "rolled_back",
        CoreUpdatePhase::RecoveryRequired => "recovery_required",
    }
}

// Parses one private update-phase persistence value.
fn update_phase(value: &str) -> Result<CoreUpdatePhase, CoreUpdateStoreError> {
    match value {
        "requested" => Ok(CoreUpdatePhase::Requested),
        "prepared" => Ok(CoreUpdatePhase::Prepared),
        "services_snapshotted" => Ok(CoreUpdatePhase::ServicesSnapshotted),
        "activated" => Ok(CoreUpdatePhase::Activated),
        "services_rebound" => Ok(CoreUpdatePhase::ServicesRebound),
        "verified" => Ok(CoreUpdatePhase::Verified),
        "committed" => Ok(CoreUpdatePhase::Committed),
        "rolling_back" => Ok(CoreUpdatePhase::RollingBack),
        "current" => Ok(CoreUpdatePhase::Current),
        "cleanup_pending" => Ok(CoreUpdatePhase::CleanupPending),
        "succeeded" => Ok(CoreUpdatePhase::Succeeded),
        "rolled_back" => Ok(CoreUpdatePhase::RolledBack),
        "recovery_required" => Ok(CoreUpdatePhase::RecoveryRequired),
        _ => Err(CoreUpdateStoreError::Corrupt),
    }
}
