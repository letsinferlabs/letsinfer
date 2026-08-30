// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::{Arc, Mutex};

use li_core_interface::Sha256Digest;
use li_database::{
    DatabaseCollection, DatabaseCommand, DatabaseError, DatabaseManager, DatabaseQuery,
    DatabaseRecord, DatabaseResult, DatabaseRevision,
};
use li_gateway_manager::{
    GatewayExposure, GatewayExposureError, GatewayExposureStore, LETSINFER_PUBLIC_INFERENCE_TARGET,
};
use serde::{Deserialize, Serialize};

const EXPOSURE_IDENTIFIER: &str = "gateway_exposure";
const EXPOSURE_PROVIDER: &str = "tailscale-funnel";
const EXPOSURE_SCHEMA_NAME: &str = "letsinfer.gateway-exposure";
const EXPOSURE_SCHEMA_VERSION: u32 = 1;

// Identifies the exact private Gateway exposure persistence schema.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct GatewayExposureDatabaseSchema {
    name: String,
    version: u32,
}

// Stores the enabled identity or one durable disabled tombstone under a singleton key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct GatewayExposureDatabaseRecord {
    schema: GatewayExposureDatabaseSchema,
    identifier: String,
    state: String,
    provider: String,
    public_url: Option<String>,
    inference_target: String,
    configuration_sha256: Option<String>,
}

impl DatabaseRecord for GatewayExposureDatabaseRecord {
    const COLLECTION: DatabaseCollection = DatabaseCollection::GatewayExposure;

    // Returns the one stable singleton identity for public exposure state.
    fn identifier(&self) -> &str {
        &self.identifier
    }
}

// Persists Gateway exposure through DatabaseManager with exact compare-and-replace semantics.
pub struct DatabaseGatewayExposureStore {
    database: Arc<DatabaseManager>,
    replacement_lock: Mutex<()>,
}

impl DatabaseGatewayExposureStore {
    // Creates one adapter without taking DatabaseManager lifecycle ownership.
    pub const fn new(database: Arc<DatabaseManager>) -> Self {
        Self {
            database,
            replacement_lock: Mutex::new(()),
        }
    }

    // Reads and validates the private record together with its optimistic revision.
    fn versioned_exposure(
        &self,
    ) -> Result<(Option<GatewayExposure>, DatabaseRevision, u64), GatewayExposureError> {
        match self
            .database
            .read(DatabaseQuery::<GatewayExposureDatabaseRecord>::record(
                EXPOSURE_IDENTIFIER,
            )) {
            Ok(DatabaseResult::Record(record)) => {
                let exposure = exposure_from_record(record.value)?;
                Ok((
                    exposure,
                    DatabaseRevision::Exact(record.revision),
                    record.revision,
                ))
            }
            Ok(DatabaseResult::Records(_)) => Err(GatewayExposureError::StateUnavailable),
            Err(DatabaseError::NotFound { .. }) => Ok((None, DatabaseRevision::Missing, 0)),
            Err(error) => Err(exposure_database_error(error)),
        }
    }
}

impl GatewayExposureStore for DatabaseGatewayExposureStore {
    // Reads one complete enabled exposure or the durable disabled state.
    fn exposure(&self) -> Result<Option<GatewayExposure>, GatewayExposureError> {
        self.versioned_exposure().map(|(exposure, _, _)| exposure)
    }

    // Serializes an exact observed-state comparison and durable replacement.
    fn replace(
        &self,
        expected: Option<&GatewayExposure>,
        replacement: Option<&GatewayExposure>,
    ) -> Result<(), GatewayExposureError> {
        let _guard = self
            .replacement_lock
            .lock()
            .map_err(|_| GatewayExposureError::StateUnavailable)?;
        let (current, expected_revision, revision) = self.versioned_exposure()?;
        if current.as_ref() != expected {
            return Err(GatewayExposureError::StateUnavailable);
        }
        let record = exposure_record(replacement);
        self.database
            .write(DatabaseCommand::save(
                replacement_key(revision, replacement),
                record,
                expected_revision,
            ))
            .map_err(exposure_database_error)?;
        Ok(())
    }
}

// Projects one optional enabled identity into the exact enabled or disabled record shape.
fn exposure_record(exposure: Option<&GatewayExposure>) -> GatewayExposureDatabaseRecord {
    GatewayExposureDatabaseRecord {
        schema: GatewayExposureDatabaseSchema {
            name: EXPOSURE_SCHEMA_NAME.to_string(),
            version: EXPOSURE_SCHEMA_VERSION,
        },
        identifier: EXPOSURE_IDENTIFIER.to_string(),
        state: if exposure.is_some() {
            "enabled".to_string()
        } else {
            "disabled".to_string()
        },
        provider: EXPOSURE_PROVIDER.to_string(),
        public_url: exposure.map(|value| value.public_url().to_string()),
        inference_target: LETSINFER_PUBLIC_INFERENCE_TARGET.to_string(),
        configuration_sha256: exposure
            .map(|value| value.configuration_sha256().as_str().to_string()),
    }
}

// Reconstructs one public exposure only from the exact current private schema.
fn exposure_from_record(
    record: GatewayExposureDatabaseRecord,
) -> Result<Option<GatewayExposure>, GatewayExposureError> {
    if record.schema
        != (GatewayExposureDatabaseSchema {
            name: EXPOSURE_SCHEMA_NAME.to_string(),
            version: EXPOSURE_SCHEMA_VERSION,
        })
        || record.identifier != EXPOSURE_IDENTIFIER
        || record.provider != EXPOSURE_PROVIDER
        || record.inference_target != LETSINFER_PUBLIC_INFERENCE_TARGET
    {
        return Err(GatewayExposureError::StateUnavailable);
    }
    match (
        record.state.as_str(),
        record.public_url,
        record.configuration_sha256,
    ) {
        ("disabled", None, None) => Ok(None),
        ("enabled", Some(public_url), Some(configuration_sha256)) => GatewayExposure::new(
            public_url,
            Sha256Digest::parse(&configuration_sha256)
                .map_err(|_| GatewayExposureError::StateUnavailable)?,
        )
        .map(Some)
        .map_err(|_| GatewayExposureError::StateUnavailable),
        _ => Err(GatewayExposureError::StateUnavailable),
    }
}

// Derives one replay-safe write identity from the previous revision and replacement identity.
fn replacement_key(revision: u64, exposure: Option<&GatewayExposure>) -> String {
    match exposure {
        Some(exposure) => format!(
            "gateway_exposure:{revision}:enabled:{}",
            exposure.configuration_sha256().as_str()
        ),
        None => format!("gateway_exposure:{revision}:disabled"),
    }
}

// Maps every database implementation failure to one stable redacted exposure error.
fn exposure_database_error(_error: DatabaseError) -> GatewayExposureError {
    GatewayExposureError::StateUnavailable
}

#[cfg(test)]
mod tests {
    use std::sync::Barrier;
    use std::thread;

    use li_database::DatabaseConfiguration;
    use tempfile::TempDir;

    use super::*;

    // Creates one isolated native database and the concrete exposure adapter.
    fn environment() -> (
        TempDir,
        Arc<DatabaseManager>,
        Arc<DatabaseGatewayExposureStore>,
    ) {
        let directory = TempDir::new().expect("temporary directory");
        let database = Arc::new(
            DatabaseManager::open(DatabaseConfiguration::new(directory.path().join("core.db")))
                .expect("database"),
        );
        let store = Arc::new(DatabaseGatewayExposureStore::new(database.clone()));
        (directory, database, store)
    }

    // Creates one exact valid exposure identity from deterministic fixture values.
    fn exposure(public_url: &str, digest: char) -> GatewayExposure {
        GatewayExposure::new(
            public_url.to_string(),
            Sha256Digest::parse(&digest.to_string().repeat(64)).expect("digest"),
        )
        .expect("exposure")
    }

    // Persists enable, disable, and same-identity re-enable across store reconstruction.
    #[test]
    fn lifecycle_is_exact_replay_safe_and_restart_durable() {
        let (_directory, database, store) = environment();
        let enabled = exposure("https://inference.example.ts.net", 'a');
        assert_eq!(store.exposure().expect("initial"), None);
        store.replace(None, Some(&enabled)).expect("enable");
        assert_eq!(store.exposure().expect("enabled"), Some(enabled.clone()));
        let reconstructed = DatabaseGatewayExposureStore::new(database);
        assert_eq!(
            reconstructed.exposure().expect("reconstructed"),
            Some(enabled.clone())
        );
        reconstructed
            .replace(Some(&enabled), None)
            .expect("disable");
        assert_eq!(reconstructed.exposure().expect("disabled"), None);
        reconstructed
            .replace(None, Some(&enabled))
            .expect("re-enable");
        assert_eq!(reconstructed.exposure().expect("re-enabled"), Some(enabled));
    }

    // Rejects a stale expected identity without changing the committed exposure.
    #[test]
    fn stale_compare_and_replace_is_mutation_free() {
        let (_directory, _database, store) = environment();
        let committed = exposure("https://inference.example.ts.net", 'a');
        let stale = exposure("https://stale.example.ts.net", 'b');
        store.replace(None, Some(&committed)).expect("enable");
        assert_eq!(
            store.replace(Some(&stale), None),
            Err(GatewayExposureError::StateUnavailable)
        );
        assert_eq!(store.exposure().expect("unchanged"), Some(committed));
    }

    // Serializes racing initial enables so exactly one complete identity can commit.
    #[test]
    fn concurrent_enable_compare_and_replace_has_one_winner() {
        let (_directory, _database, store) = environment();
        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for (host, digest) in [('a', 'a'), ('b', 'b')] {
            let store = store.clone();
            let barrier = barrier.clone();
            workers.push(thread::spawn(move || {
                let candidate = exposure(&format!("https://{host}.example.ts.net"), digest);
                barrier.wait();
                (candidate.clone(), store.replace(None, Some(&candidate)))
            }));
        }
        barrier.wait();
        let results = workers
            .into_iter()
            .map(|worker| worker.join().expect("worker"))
            .collect::<Vec<_>>();
        assert_eq!(
            results.iter().filter(|(_, result)| result.is_ok()).count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|(_, result)| *result == Err(GatewayExposureError::StateUnavailable))
                .count(),
            1
        );
        let committed = store.exposure().expect("committed").expect("enabled");
        assert!(results
            .iter()
            .any(|(candidate, result)| result.is_ok() && candidate == &committed));
    }

    // Rejects every invalid closed-schema state rather than partially reconstructing it.
    #[test]
    fn malformed_record_matrix_fails_closed() {
        let mutations = [
            GatewayExposureDatabaseRecord {
                schema: GatewayExposureDatabaseSchema {
                    name: "wrong".to_string(),
                    version: EXPOSURE_SCHEMA_VERSION,
                },
                ..exposure_record(None)
            },
            GatewayExposureDatabaseRecord {
                state: "enabled".to_string(),
                ..exposure_record(None)
            },
            GatewayExposureDatabaseRecord {
                provider: "foreign".to_string(),
                ..exposure_record(None)
            },
            GatewayExposureDatabaseRecord {
                inference_target: "http://127.0.0.1:9000".to_string(),
                ..exposure_record(None)
            },
            GatewayExposureDatabaseRecord {
                state: "enabled".to_string(),
                public_url: Some("https://invalid/path".to_string()),
                configuration_sha256: Some("a".repeat(64)),
                ..exposure_record(None)
            },
        ];
        for record in mutations {
            let (_directory, database, store) = environment();
            database
                .write(DatabaseCommand::save(
                    "corrupt fixture",
                    record,
                    DatabaseRevision::Missing,
                ))
                .expect("fixture");
            assert_eq!(
                store.exposure(),
                Err(GatewayExposureError::StateUnavailable)
            );
        }
    }
}
