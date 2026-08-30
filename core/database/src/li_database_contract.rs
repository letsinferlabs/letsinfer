// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub const DEFAULT_BUSY_TIMEOUT: Duration = Duration::from_secs(5);
pub const DEFAULT_WRITE_QUEUE_CAPACITY: usize = 64;

// Identifies one stable Core domain without exposing its SQLite representation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DatabaseCollection {
    Authentication,
    AuditCheckpoints,
    AuditEvents,
    AuditReplays,
    AuditState,
    Benchmarks,
    BenchmarkHandoffs,
    CommandAuditSessions,
    Configuration,
    Controllers,
    CoreUpdateServiceSnapshots,
    CoreUpdates,
    GatewayExposure,
    GatewayUsage,
    HardwareObservations,
    ModelLifecycles,
    RuntimeInstallations,
    Nodes,
    Operations,
    Outbox,
    Pairings,
    PairingReplays,
    PeerCredentials,
    Placements,
    Services,
}

impl DatabaseCollection {
    // Returns the private storage identity for this domain collection.
    pub(crate) const fn storage_name(self) -> &'static str {
        match self {
            Self::Authentication => "authentication",
            Self::AuditCheckpoints => "audit_checkpoints",
            Self::AuditEvents => "audit_events",
            Self::AuditReplays => "audit_replays",
            Self::AuditState => "audit_state",
            Self::Benchmarks => "benchmarks",
            Self::BenchmarkHandoffs => "benchmark_handoffs",
            Self::CommandAuditSessions => "command_audit_sessions",
            Self::Configuration => "configuration",
            Self::Controllers => "controllers",
            Self::CoreUpdateServiceSnapshots => "core_update_service_snapshots",
            Self::CoreUpdates => "core_updates",
            Self::GatewayExposure => "gateway_exposure",
            Self::GatewayUsage => "gateway_usage",
            Self::HardwareObservations => "hardware_observations",
            Self::ModelLifecycles => "model_lifecycles",
            Self::RuntimeInstallations => "runtime_installations",
            Self::Nodes => "nodes",
            Self::Operations => "operations",
            Self::Outbox => "outbox",
            Self::Pairings => "pairings",
            Self::PairingReplays => "pairing_replays",
            Self::PeerCredentials => "peer_credentials",
            Self::Placements => "placements",
            Self::Services => "services",
        }
    }
}

impl fmt::Display for DatabaseCollection {
    // Presents the stable domain name without leaking a table name.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.storage_name())
    }
}

// Defines the typed value contract stored by the DatabaseManager.
pub trait DatabaseRecord: Clone + DeserializeOwned + Serialize + Send + Sync + 'static {
    const COLLECTION: DatabaseCollection;
    const VERSION: u32 = 1;

    // Returns the stable identity used to address this record.
    fn identifier(&self) -> &str;
}

// Describes the revision that must be observed before a mutation may commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseRevision {
    Any,
    Missing,
    Exact(u64),
}

impl fmt::Display for DatabaseRevision {
    // Presents the expected revision in stable error language.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => formatter.write_str("any"),
            Self::Missing => formatter.write_str("missing"),
            Self::Exact(revision) => write!(formatter, "{revision}"),
        }
    }
}

// Carries one typed read without exposing SQL or physical schema details.
pub enum DatabaseQuery<Record> {
    Record {
        identifier: String,
        record_type: PhantomData<fn() -> Record>,
    },
    All {
        record_type: PhantomData<fn() -> Record>,
    },
}

impl<Record> DatabaseQuery<Record> {
    // Creates a query for one exact record identity.
    pub fn record(identifier: impl Into<String>) -> Self {
        Self::Record {
            identifier: identifier.into(),
            record_type: PhantomData,
        }
    }

    // Creates a query for every record in one typed collection.
    pub fn all() -> Self {
        Self::All {
            record_type: PhantomData,
        }
    }
}

// Carries one typed mutation with idempotency and optimistic revision policy.
pub enum DatabaseCommand<Record> {
    Save {
        idempotency_key: String,
        record: Record,
        expected_revision: DatabaseRevision,
    },
    Delete {
        idempotency_key: String,
        identifier: String,
        expected_revision: DatabaseRevision,
        record_type: PhantomData<fn() -> Record>,
    },
}

impl<Record> DatabaseCommand<Record> {
    // Creates one idempotent record creation or replacement command.
    pub fn save(
        idempotency_key: impl Into<String>,
        record: Record,
        expected_revision: DatabaseRevision,
    ) -> Self {
        Self::Save {
            idempotency_key: idempotency_key.into(),
            record,
            expected_revision,
        }
    }

    // Creates one idempotent record deletion command.
    pub fn delete(
        idempotency_key: impl Into<String>,
        identifier: impl Into<String>,
        expected_revision: DatabaseRevision,
    ) -> Self {
        Self::Delete {
            idempotency_key: idempotency_key.into(),
            identifier: identifier.into(),
            expected_revision,
            record_type: PhantomData,
        }
    }
}

// Returns typed committed state for one record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DatabaseStoredRecord<Record> {
    pub value: Record,
    pub revision: u64,
    pub created_at_unix_milliseconds: i64,
    pub updated_at_unix_milliseconds: i64,
}

// Returns the typed result of one database query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DatabaseResult<Record> {
    Record(DatabaseStoredRecord<Record>),
    Records(Vec<DatabaseStoredRecord<Record>>),
}

// Identifies the mutation that produced one committed revision.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DatabaseMutation {
    Created,
    Updated,
    Deleted,
}

// Describes one durable mutation after its transaction commits.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DatabaseCommit {
    pub idempotency_key: String,
    pub collection: DatabaseCollection,
    pub identifier: String,
    pub mutation: DatabaseMutation,
    pub revision: u64,
    pub committed_at_unix_milliseconds: i64,
}

// Distinguishes one new durable mutation from an idempotent replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseCommitDisposition {
    Applied,
    Replayed,
}

// Returns one commit together with whether this call created it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DatabaseWriteResult {
    commit: DatabaseCommit,
    disposition: DatabaseCommitDisposition,
}

impl DatabaseWriteResult {
    // Creates one exact write result after the storage transaction resolves.
    pub(crate) const fn new(
        commit: DatabaseCommit,
        disposition: DatabaseCommitDisposition,
    ) -> Self {
        Self {
            commit,
            disposition,
        }
    }

    // Returns the durable commit produced by this command or its first application.
    pub const fn commit(&self) -> &DatabaseCommit {
        &self.commit
    }

    // Returns whether this call applied or replayed the durable mutation.
    pub const fn disposition(&self) -> DatabaseCommitDisposition {
        self.disposition
    }
}

// Announces one mutation only after its transaction is durable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DatabaseEvent {
    pub collection: DatabaseCollection,
    pub identifier: String,
    pub mutation: DatabaseMutation,
    pub revision: u64,
    pub committed_at_unix_milliseconds: i64,
}

impl DatabaseEvent {
    // Creates the post-commit event corresponding to one durable mutation.
    pub(crate) fn from_commit(commit: &DatabaseCommit) -> Self {
        Self {
            collection: commit.collection,
            identifier: commit.identifier.clone(),
            mutation: commit.mutation,
            revision: commit.revision,
            committed_at_unix_milliseconds: commit.committed_at_unix_milliseconds,
        }
    }
}

// Supplies time explicitly so production and tests use the same write path.
pub trait DatabaseClock: Send + Sync {
    // Returns the current non-negative Unix timestamp in milliseconds.
    fn now_unix_milliseconds(&self) -> Result<i64, DatabaseError>;
}

// Reads time from the active host for production database commits.
#[derive(Default)]
pub struct SystemDatabaseClock;

impl DatabaseClock for SystemDatabaseClock {
    // Returns host time as a bounded signed SQLite integer.
    fn now_unix_milliseconds(&self) -> Result<i64, DatabaseError> {
        let duration = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| {
            DatabaseError::Unavailable {
                reason: "system clock is before the Unix epoch",
            }
        })?;
        i64::try_from(duration.as_millis()).map_err(|_| DatabaseError::Unavailable {
            reason: "system clock exceeds the database timestamp range",
        })
    }
}

// Configures one DatabaseManager without hiding native dependencies.
pub struct DatabaseConfiguration {
    database_path: PathBuf,
    write_queue_capacity: usize,
    busy_timeout: Duration,
    clock: Arc<dyn DatabaseClock>,
}

impl DatabaseConfiguration {
    // Creates the ordinary production configuration for one database path.
    pub fn new(database_path: impl Into<PathBuf>) -> Self {
        Self {
            database_path: database_path.into(),
            write_queue_capacity: DEFAULT_WRITE_QUEUE_CAPACITY,
            busy_timeout: DEFAULT_BUSY_TIMEOUT,
            clock: Arc::new(SystemDatabaseClock),
        }
    }

    // Replaces the bounded writer queue capacity.
    pub fn with_write_queue_capacity(mut self, capacity: usize) -> Self {
        self.write_queue_capacity = capacity;
        self
    }

    // Replaces the bounded SQLite lock wait.
    pub fn with_busy_timeout(mut self, timeout: Duration) -> Self {
        self.busy_timeout = timeout;
        self
    }

    // Replaces the native clock for deterministic composition or tests.
    pub fn with_clock(mut self, clock: Arc<dyn DatabaseClock>) -> Self {
        self.clock = clock;
        self
    }

    // Returns the exact database path owned by this configuration.
    pub fn database_path(&self) -> &Path {
        &self.database_path
    }

    // Returns the bounded writer queue capacity.
    pub(crate) const fn write_queue_capacity(&self) -> usize {
        self.write_queue_capacity
    }

    // Returns the bounded SQLite lock wait.
    pub(crate) const fn busy_timeout(&self) -> Duration {
        self.busy_timeout
    }

    // Returns the injected commit clock.
    pub(crate) fn clock(&self) -> Arc<dyn DatabaseClock> {
        Arc::clone(&self.clock)
    }
}

// Describes one stable database contract failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DatabaseError {
    NotFound {
        collection: DatabaseCollection,
        identifier: String,
    },
    Conflict {
        collection: DatabaseCollection,
        identifier: String,
        expected: DatabaseRevision,
        observed: Option<u64>,
    },
    IdempotencyConflict {
        idempotency_key: String,
    },
    InvalidInput {
        field: &'static str,
        reason: &'static str,
    },
    Corrupt {
        reason: &'static str,
    },
    Unavailable {
        reason: &'static str,
    },
    Closed,
}

impl fmt::Display for DatabaseError {
    // Presents a stable failure without leaking SQL or stored values.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound {
                collection,
                identifier,
            } => write!(formatter, "{collection} record was not found: {identifier}"),
            Self::Conflict {
                collection,
                identifier,
                expected,
                observed,
            } => {
                let observed = observed
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "missing".to_string());
                write!(
                    formatter,
                    "{collection} record revision conflict for {identifier}: expected {expected}, observed {observed}"
                )
            }
            Self::IdempotencyConflict { idempotency_key } => write!(
                formatter,
                "idempotency key was already used for a different command: {idempotency_key}"
            ),
            Self::InvalidInput { field, reason } => {
                write!(formatter, "database {field} is invalid: {reason}")
            }
            Self::Corrupt { reason } => write!(formatter, "database is corrupt: {reason}"),
            Self::Unavailable { reason } => write!(formatter, "database is unavailable: {reason}"),
            Self::Closed => formatter.write_str("database manager is closed"),
        }
    }
}

impl Error for DatabaseError {}
