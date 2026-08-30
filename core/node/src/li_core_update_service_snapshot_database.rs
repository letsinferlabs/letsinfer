// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use li_core_interface::Sha256Digest;
use li_core_update_manager::{
    CoreInstallation, CoreUpdateError, CoreUpdateNodeRole, CoreUpdateResidentService,
    CoreUpdateServiceContext, CoreUpdateServicePlatform, CoreUpdateServiceSnapshotRecord,
    CoreUpdateServiceSnapshotStore, CoreUpdateServiceState, CoreVersion,
};
use li_database::{
    DatabaseCollection, DatabaseCommand, DatabaseError, DatabaseManager, DatabaseQuery,
    DatabaseRecord, DatabaseResult, DatabaseRevision,
};
use serde::{Deserialize, Serialize};

const SNAPSHOT_SCHEMA_NAME: &str = "li_core_update_service_snapshot";
const SNAPSHOT_SCHEMA_VERSION: u32 = 2;

// Identifies the exact CoreUpdateManager service-snapshot persistence contract.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CoreUpdateServiceSnapshotDatabaseSchema {
    name: String,
    version: u32,
}

// Stores one resident-service identity within a closed update snapshot record.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CoreUpdateServiceStateDatabaseRecord {
    service: String,
    loaded_identity: Option<String>,
    active_identity: Option<String>,
}

// Stores one complete pre-update service snapshot under its immutable update identity.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CoreUpdateServiceSnapshotDatabaseRecord {
    schema: CoreUpdateServiceSnapshotDatabaseSchema,
    update_id: String,
    receipt_id: String,
    current_version: String,
    current_source_identity: String,
    platform: String,
    role: String,
    services: Vec<CoreUpdateServiceStateDatabaseRecord>,
}

impl DatabaseRecord for CoreUpdateServiceSnapshotDatabaseRecord {
    const COLLECTION: DatabaseCollection = DatabaseCollection::CoreUpdateServiceSnapshots;

    // Returns the immutable Core update identity that owns this snapshot.
    fn identifier(&self) -> &str {
        &self.update_id
    }
}

// Persists exact Core service restoration snapshots through DatabaseManager.
pub struct DatabaseCoreUpdateServiceSnapshotStore {
    database: Arc<DatabaseManager>,
}

impl DatabaseCoreUpdateServiceSnapshotStore {
    // Creates one snapshot adapter without taking DatabaseManager lifecycle ownership.
    pub const fn new(database: Arc<DatabaseManager>) -> Self {
        Self { database }
    }

    // Reads one exact typed record and validates its content-bound receipt.
    fn read_snapshot(
        &self,
        update_id: &Sha256Digest,
    ) -> Result<Option<CoreUpdateServiceSnapshotRecord>, CoreUpdateError> {
        match self.database.read(
            DatabaseQuery::<CoreUpdateServiceSnapshotDatabaseRecord>::record(update_id.as_str()),
        ) {
            Ok(DatabaseResult::Record(stored)) => snapshot_from_record(stored.value).map(Some),
            Ok(DatabaseResult::Records(_)) => Err(snapshot_corrupt()),
            Err(DatabaseError::NotFound { .. }) => Ok(None),
            Err(_) => Err(snapshot_unavailable()),
        }
    }
}

impl CoreUpdateServiceSnapshotStore for DatabaseCoreUpdateServiceSnapshotStore {
    // Returns one prior exact snapshot when the update already crossed its snapshot phase.
    fn read(
        &self,
        update_id: &Sha256Digest,
    ) -> Result<Option<CoreUpdateServiceSnapshotRecord>, CoreUpdateError> {
        self.read_snapshot(update_id)
    }

    // Creates one snapshot exactly once and reconciles only byte-equivalent concurrent replay.
    fn store(
        &self,
        snapshot: CoreUpdateServiceSnapshotRecord,
    ) -> Result<CoreUpdateServiceSnapshotRecord, CoreUpdateError> {
        if let Some(existing) = self.read_snapshot(snapshot.update_id())? {
            return require_same_snapshot(existing, snapshot);
        }
        let idempotency_key = format!(
            "core-update-service-snapshot:{}:{}",
            snapshot.update_id().as_str(),
            snapshot.receipt_id().as_str()
        );
        let record = snapshot_record(&snapshot);
        match self.database.write(DatabaseCommand::save(
            idempotency_key,
            record,
            DatabaseRevision::Missing,
        )) {
            Ok(result)
                if result.commit().collection == DatabaseCollection::CoreUpdateServiceSnapshots
                    && result.commit().identifier == snapshot.update_id().as_str()
                    && result.commit().revision == 1 =>
            {
                Ok(snapshot)
            }
            Ok(_) => Err(snapshot_corrupt()),
            Err(DatabaseError::Conflict { .. }) => self
                .read_snapshot(snapshot.update_id())?
                .ok_or_else(snapshot_unavailable)
                .and_then(|existing| require_same_snapshot(existing, snapshot)),
            Err(_) => Err(snapshot_unavailable()),
        }
    }
}

// Projects one validated snapshot into its private database representation.
fn snapshot_record(
    snapshot: &CoreUpdateServiceSnapshotRecord,
) -> CoreUpdateServiceSnapshotDatabaseRecord {
    CoreUpdateServiceSnapshotDatabaseRecord {
        schema: CoreUpdateServiceSnapshotDatabaseSchema {
            name: SNAPSHOT_SCHEMA_NAME.to_string(),
            version: SNAPSHOT_SCHEMA_VERSION,
        },
        update_id: snapshot.update_id().as_str().to_string(),
        receipt_id: snapshot.receipt_id().as_str().to_string(),
        current_version: snapshot.current().version().as_str().to_string(),
        current_source_identity: snapshot.current().source_identity().as_str().to_string(),
        platform: platform_name(snapshot.context().platform()).to_string(),
        role: role_name(snapshot.context().role()).to_string(),
        services: snapshot
            .services()
            .iter()
            .map(|state| CoreUpdateServiceStateDatabaseRecord {
                service: service_name(state.service()).to_string(),
                loaded_identity: state
                    .loaded_identity()
                    .map(|identity| identity.as_str().to_string()),
                active_identity: state
                    .active_identity()
                    .map(|identity| identity.as_str().to_string()),
            })
            .collect(),
    }
}

// Reconstructs and rehashes one complete snapshot before returning it to update policy.
fn snapshot_from_record(
    record: CoreUpdateServiceSnapshotDatabaseRecord,
) -> Result<CoreUpdateServiceSnapshotRecord, CoreUpdateError> {
    if record.schema.name != SNAPSHOT_SCHEMA_NAME
        || record.schema.version != SNAPSHOT_SCHEMA_VERSION
    {
        return Err(snapshot_corrupt());
    }
    let update_id = parse_digest(&record.update_id)?;
    let receipt_id = parse_digest(&record.receipt_id)?;
    let current = CoreInstallation::new(
        CoreVersion::parse(&record.current_version).map_err(|_| snapshot_corrupt())?,
        parse_digest(&record.current_source_identity)?,
    );
    let context = CoreUpdateServiceContext::new(platform(&record.platform)?, role(&record.role)?);
    let services = record
        .services
        .into_iter()
        .map(|state| {
            CoreUpdateServiceState::new(
                service(&state.service)?,
                optional_digest(state.loaded_identity.as_deref())?,
                optional_digest(state.active_identity.as_deref())?,
            )
            .map_err(|_| snapshot_corrupt())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let snapshot = CoreUpdateServiceSnapshotRecord::new(update_id, current, context, services)?;
    if snapshot.receipt_id() != &receipt_id {
        return Err(snapshot_corrupt());
    }
    Ok(snapshot)
}

// Accepts only an exact replay of one already-authoritative immutable snapshot.
fn require_same_snapshot(
    existing: CoreUpdateServiceSnapshotRecord,
    proposed: CoreUpdateServiceSnapshotRecord,
) -> Result<CoreUpdateServiceSnapshotRecord, CoreUpdateError> {
    if existing == proposed {
        Ok(existing)
    } else {
        Err(CoreUpdateError::InvalidContract {
            reason: "Core service snapshot conflicts with durable state",
        })
    }
}

// Returns the stable persistence name for one supported service platform.
const fn platform_name(platform: CoreUpdateServicePlatform) -> &'static str {
    match platform {
        CoreUpdateServicePlatform::Linux => "linux",
        CoreUpdateServicePlatform::Macos => "macos",
    }
}

// Parses one closed service platform from private persistence.
fn platform(value: &str) -> Result<CoreUpdateServicePlatform, CoreUpdateError> {
    match value {
        "linux" => Ok(CoreUpdateServicePlatform::Linux),
        "macos" => Ok(CoreUpdateServicePlatform::Macos),
        _ => Err(snapshot_corrupt()),
    }
}

// Returns the stable persistence name for one local node role.
const fn role_name(role: CoreUpdateNodeRole) -> &'static str {
    match role {
        CoreUpdateNodeRole::Main => "main",
        CoreUpdateNodeRole::Child => "child",
    }
}

// Parses one closed local node role from private persistence.
fn role(value: &str) -> Result<CoreUpdateNodeRole, CoreUpdateError> {
    match value {
        "main" => Ok(CoreUpdateNodeRole::Main),
        "child" => Ok(CoreUpdateNodeRole::Child),
        _ => Err(snapshot_corrupt()),
    }
}

// Returns the stable persistence name for one resident service.
const fn service_name(service: CoreUpdateResidentService) -> &'static str {
    match service {
        CoreUpdateResidentService::Node => "node",
        CoreUpdateResidentService::Gateway => "gateway",
        CoreUpdateResidentService::Watchdog => "watchdog",
    }
}

// Parses one closed resident service from private persistence.
fn service(value: &str) -> Result<CoreUpdateResidentService, CoreUpdateError> {
    match value {
        "node" => Ok(CoreUpdateResidentService::Node),
        "gateway" => Ok(CoreUpdateResidentService::Gateway),
        "watchdog" => Ok(CoreUpdateResidentService::Watchdog),
        _ => Err(snapshot_corrupt()),
    }
}

// Parses one required lowercase SHA-256 identity.
fn parse_digest(value: &str) -> Result<Sha256Digest, CoreUpdateError> {
    Sha256Digest::parse(value).map_err(|_| snapshot_corrupt())
}

// Parses one optional lowercase SHA-256 identity.
fn optional_digest(value: Option<&str>) -> Result<Option<Sha256Digest>, CoreUpdateError> {
    value.map(parse_digest).transpose()
}

// Returns one stable corruption error without persistence bytes.
fn snapshot_corrupt() -> CoreUpdateError {
    CoreUpdateError::InvalidContract {
        reason: "persisted Core service snapshot is corrupt",
    }
}

// Returns one stable availability error without database mechanics.
fn snapshot_unavailable() -> CoreUpdateError {
    CoreUpdateError::provider(
        "service snapshot store",
        "durable service snapshot state is unavailable",
    )
}
