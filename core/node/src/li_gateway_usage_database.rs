// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use li_core_interface::{ApiKeyId, Sha256Digest, UnixMilliseconds};
use li_database::{
    DatabaseCollection, DatabaseCommand, DatabaseCommitDisposition, DatabaseError, DatabaseManager,
    DatabaseQuery, DatabaseRecord, DatabaseResult, DatabaseRevision,
};
use li_gateway_manager::{
    GatewayError, GatewayUsageRecord, GatewayUsageRuntimeCounterProvider, GatewayUsageStore,
};
use serde::{Deserialize, Serialize};

const MAXIMUM_USAGE_RECORDS: usize = 1_000_000;

// Stores one completed secret-free Gateway request under its immutable request identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct GatewayUsageDatabaseRecord {
    request_id: String,
    key_id: String,
    received_at_unix_milliseconds: u64,
    completed_at_unix_milliseconds: u64,
    tokens: u64,
}

impl DatabaseRecord for GatewayUsageDatabaseRecord {
    const COLLECTION: DatabaseCollection = DatabaseCollection::GatewayUsage;

    // Returns the immutable request identity used for idempotent completion replay.
    fn identifier(&self) -> &str {
        &self.request_id
    }
}

// Persists completed Gateway usage and exposes write-health counters to telemetry.
pub struct DatabaseGatewayUsageStore {
    database: Arc<DatabaseManager>,
    write_errors: AtomicU64,
}

impl DatabaseGatewayUsageStore {
    // Creates one adapter without transferring database lifecycle ownership.
    pub const fn new(database: Arc<DatabaseManager>) -> Self {
        Self {
            database,
            write_errors: AtomicU64::new(0),
        }
    }

    // Records one failed durable write without permitting counter wraparound.
    fn record_write_error(&self) {
        let _ = self
            .write_errors
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                Some(value.saturating_add(1))
            });
    }

    // Creates one immutable completion record and preserves its exact commit disposition for IPC.
    pub fn record_for_gateway_api(
        &self,
        usage: &GatewayUsageRecord,
    ) -> Result<crate::NodeGatewayUsageDisposition, crate::NodeGatewayApiError> {
        let record = usage_database_record(usage);
        let result = self.database.write(DatabaseCommand::save(
            format!("gateway_usage:{}", usage.request_id().as_str()),
            record.clone(),
            DatabaseRevision::Missing,
        ));
        let result = match result {
            Ok(result) => result,
            Err(DatabaseError::IdempotencyConflict { .. }) => {
                self.record_write_error();
                return Err(crate::NodeGatewayApiError::ReplayConflict);
            }
            Err(_) => {
                self.record_write_error();
                return Err(crate::NodeGatewayApiError::Unavailable);
            }
        };
        if result.disposition() == DatabaseCommitDisposition::Replayed {
            let replay = self
                .database
                .read(DatabaseQuery::<GatewayUsageDatabaseRecord>::record(
                    usage.request_id().as_str(),
                ))
                .map_err(|_| {
                    self.record_write_error();
                    crate::NodeGatewayApiError::Unavailable
                })?;
            let DatabaseResult::Record(replay) = replay else {
                self.record_write_error();
                return Err(crate::NodeGatewayApiError::CorruptState);
            };
            if replay.value != record || replay.revision != result.commit().revision {
                self.record_write_error();
                return Err(crate::NodeGatewayApiError::ReplayConflict);
            }
            return Ok(crate::NodeGatewayUsageDisposition::Replayed);
        }
        Ok(crate::NodeGatewayUsageDisposition::Applied)
    }
}

impl GatewayUsageStore for DatabaseGatewayUsageStore {
    // Returns validated matching usage at or after the rolling-window boundary.
    fn recent(
        &self,
        key_id: &ApiKeyId,
        since: UnixMilliseconds,
    ) -> Result<Vec<GatewayUsageRecord>, GatewayError> {
        let DatabaseResult::Records(records) = self
            .database
            .read(DatabaseQuery::<GatewayUsageDatabaseRecord>::all())
            .map_err(usage_database_error)?
        else {
            return Err(usage_error("Gateway usage collection is malformed"));
        };
        if records.len() > MAXIMUM_USAGE_RECORDS {
            return Err(usage_error("Gateway usage collection exceeds its bound"));
        }
        let mut matching = records
            .into_iter()
            .map(|record| usage_from_database_record(record.value))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|usage| {
                usage.key_id() == key_id && usage.completed_at().value() >= since.value()
            })
            .collect::<Vec<_>>();
        matching.sort_by(|left, right| {
            left.completed_at()
                .value()
                .cmp(&right.completed_at().value())
                .then_with(|| left.request_id().as_str().cmp(right.request_id().as_str()))
        });
        Ok(matching)
    }

    // Creates one immutable completion record or verifies an exact idempotent replay.
    fn record(&self, usage: &GatewayUsageRecord) -> Result<(), GatewayError> {
        self.record_for_gateway_api(usage)
            .map(|_| ())
            .map_err(|_| usage_error("Gateway usage persistence is unavailable"))
    }
}

impl GatewayUsageRuntimeCounterProvider for DatabaseGatewayUsageStore {
    // Reports synchronous persistence failures; records are never silently dropped.
    fn usage_counters(&self) -> Result<(u64, u64), GatewayError> {
        Ok((0, self.write_errors.load(Ordering::Acquire)))
    }
}

// Converts one public usage record to its private stable database shape.
fn usage_database_record(usage: &GatewayUsageRecord) -> GatewayUsageDatabaseRecord {
    GatewayUsageDatabaseRecord {
        request_id: usage.request_id().as_str().to_string(),
        key_id: usage.key_id().as_str().to_string(),
        received_at_unix_milliseconds: usage.received_at().value(),
        completed_at_unix_milliseconds: usage.completed_at().value(),
        tokens: usage.tokens(),
    }
}

// Validates one private record and reconstructs its exact public usage value.
fn usage_from_database_record(
    record: GatewayUsageDatabaseRecord,
) -> Result<GatewayUsageRecord, GatewayError> {
    GatewayUsageRecord::new(
        Sha256Digest::parse(&record.request_id)
            .map_err(|_| usage_error("Gateway usage request identity is invalid"))?,
        ApiKeyId::parse(&record.key_id)
            .map_err(|_| usage_error("Gateway usage key identity is invalid"))?,
        UnixMilliseconds::new(record.received_at_unix_milliseconds),
        UnixMilliseconds::new(record.completed_at_unix_milliseconds),
        record.tokens,
    )
}

// Maps storage failures to one redacted Gateway provider boundary.
fn usage_database_error(_error: DatabaseError) -> GatewayError {
    usage_error("Gateway usage persistence is unavailable")
}

// Returns one stable Gateway usage provider failure.
fn usage_error(reason: &'static str) -> GatewayError {
    GatewayError::provider("usage", reason)
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;
    use li_database::DatabaseConfiguration;

    // Creates one isolated native database and its concrete Gateway usage adapter.
    fn environment() -> (TempDir, Arc<DatabaseManager>, DatabaseGatewayUsageStore) {
        let directory = TempDir::new().unwrap();
        let database = Arc::new(
            DatabaseManager::open(DatabaseConfiguration::new(directory.path().join("core.db")))
                .unwrap(),
        );
        let store = DatabaseGatewayUsageStore::new(database.clone());
        (directory, database, store)
    }

    // Creates one exact completed usage fixture under a caller-selected request identity.
    fn usage(request: char, key: char, tokens: u64) -> GatewayUsageRecord {
        GatewayUsageRecord::new(
            Sha256Digest::parse(&request.to_string().repeat(64)).unwrap(),
            ApiKeyId::parse(&key.to_string().repeat(32)).unwrap(),
            UnixMilliseconds::new(1_000),
            UnixMilliseconds::new(2_000),
            tokens,
        )
        .unwrap()
    }

    // Persists exact usage, replays idempotently, and filters by key and rolling boundary.
    #[test]
    fn ordinary_persistence_and_exact_replay_are_deterministic() {
        let (_directory, _database, store) = environment();
        let first = usage('1', 'a', 12);
        assert_eq!(
            store.record_for_gateway_api(&first).unwrap(),
            crate::NodeGatewayUsageDisposition::Applied
        );
        assert_eq!(
            store.record_for_gateway_api(&first).unwrap(),
            crate::NodeGatewayUsageDisposition::Replayed
        );
        store.record(&usage('2', 'b', 20)).unwrap();
        assert_eq!(
            store
                .recent(first.key_id(), UnixMilliseconds::new(1_500))
                .unwrap(),
            vec![first]
        );
        assert_eq!(store.usage_counters().unwrap(), (0, 0));
    }

    // Rejects one request-identity replay whose committed content differs.
    #[test]
    fn conflicting_replay_fails_and_advances_write_health() {
        let (_directory, _database, store) = environment();
        store.record_for_gateway_api(&usage('1', 'a', 12)).unwrap();
        assert_eq!(
            store.record_for_gateway_api(&usage('1', 'a', 13)),
            Err(crate::NodeGatewayApiError::ReplayConflict)
        );
        assert_eq!(store.usage_counters().unwrap(), (0, 1));
    }

    // Rejects malformed collection content instead of partially rebuilding quota state.
    #[test]
    fn corrupt_collection_fails_closed() {
        let (_directory, database, store) = environment();
        database
            .write(DatabaseCommand::save(
                "corrupt-usage",
                GatewayUsageDatabaseRecord {
                    request_id: "not-a-digest".to_string(),
                    key_id: "a".repeat(32),
                    received_at_unix_milliseconds: 1_000,
                    completed_at_unix_milliseconds: 2_000,
                    tokens: 1,
                },
                DatabaseRevision::Missing,
            ))
            .unwrap();
        assert!(store
            .recent(
                &ApiKeyId::parse(&"a".repeat(32)).unwrap(),
                UnixMilliseconds::new(0)
            )
            .is_err());
    }

    // Surfaces native storage loss without inventing an empty rolling window.
    #[test]
    fn storage_failure_is_not_treated_as_empty_usage() {
        let (directory, _database, store) = environment();
        std::fs::remove_file(directory.path().join("core.db")).unwrap();
        assert!(store
            .recent(
                &ApiKeyId::parse(&"a".repeat(32)).unwrap(),
                UnixMilliseconds::new(0)
            )
            .is_err());
    }
}
