// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::path::Path;
use std::sync::mpsc::{Receiver, Sender, SyncSender};
use std::sync::Arc;
use std::time::Duration;

use rusqlite::{params, Connection, ErrorCode, OpenFlags, OptionalExtension, Transaction};
use sha2::{Digest, Sha256};

use crate::li_database_contract::{
    DatabaseClock, DatabaseCollection, DatabaseCommand, DatabaseCommit, DatabaseCommitDisposition,
    DatabaseError, DatabaseEvent, DatabaseMutation, DatabaseRecord, DatabaseRevision,
    DatabaseStoredRecord, DatabaseWriteResult,
};
use crate::li_database_transaction::{DatabaseTransactionCommit, DatabaseTransactionWriteResult};

const APPLICATION_ID: i64 = 0x4C49_4442;
const DATABASE_SCHEMA_VERSION: i64 = 1;
const MAX_IDENTIFIER_BYTES: usize = 255;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 255;
const MAX_RECORD_BYTES: usize = 1024 * 1024;
const RECORDS_TABLE_SCHEMA: &str = "CREATE TABLE li_database_records (
    collection TEXT NOT NULL,
    identifier TEXT NOT NULL,
    record_version INTEGER NOT NULL CHECK(record_version > 0),
    revision INTEGER NOT NULL CHECK(revision > 0),
    payload BLOB NOT NULL,
    created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0),
    updated_at_unix_ms INTEGER NOT NULL CHECK(updated_at_unix_ms >= 0),
    PRIMARY KEY (collection, identifier)
)";
const IDEMPOTENCY_TABLE_SCHEMA: &str = "CREATE TABLE li_database_idempotency (
    idempotency_key TEXT PRIMARY KEY,
    command_sha256 TEXT NOT NULL,
    commit_json BLOB NOT NULL,
    committed_at_unix_ms INTEGER NOT NULL CHECK(committed_at_unix_ms >= 0)
)";

// Carries one type-erased command only after its public contract is validated.
pub(crate) enum PreparedCommand {
    Save {
        collection: DatabaseCollection,
        record_version: u32,
        identifier: String,
        payload: Vec<u8>,
        idempotency_key: String,
        expected_revision: DatabaseRevision,
    },
    Delete {
        collection: DatabaseCollection,
        record_version: u32,
        identifier: String,
        idempotency_key: String,
        expected_revision: DatabaseRevision,
    },
}

impl PreparedCommand {
    // Returns the typed collection mutated by this command.
    pub(crate) fn collection(&self) -> DatabaseCollection {
        match self {
            Self::Save { collection, .. } | Self::Delete { collection, .. } => *collection,
        }
    }

    // Returns the exact record identity mutated by this command.
    pub(crate) fn identifier(&self) -> &str {
        match self {
            Self::Save { identifier, .. } | Self::Delete { identifier, .. } => identifier,
        }
    }

    // Returns the caller-owned replay identity for this command.
    fn idempotency_key(&self) -> &str {
        match self {
            Self::Save {
                idempotency_key, ..
            }
            | Self::Delete {
                idempotency_key, ..
            } => idempotency_key,
        }
    }

    // Returns a deterministic digest binding every mutation input.
    fn digest(&self) -> String {
        let mut digest = Sha256::new();
        match self {
            Self::Save {
                collection,
                record_version,
                identifier,
                payload,
                expected_revision,
                ..
            } => {
                update_digest_field(&mut digest, b"save");
                update_digest_field(&mut digest, collection.storage_name().as_bytes());
                update_digest_field(&mut digest, &record_version.to_be_bytes());
                update_digest_field(&mut digest, identifier.as_bytes());
                update_digest_field(&mut digest, revision_bytes(*expected_revision).as_bytes());
                update_digest_field(&mut digest, payload);
            }
            Self::Delete {
                collection,
                record_version,
                identifier,
                expected_revision,
                ..
            } => {
                update_digest_field(&mut digest, b"delete");
                update_digest_field(&mut digest, collection.storage_name().as_bytes());
                update_digest_field(&mut digest, &record_version.to_be_bytes());
                update_digest_field(&mut digest, identifier.as_bytes());
                update_digest_field(&mut digest, revision_bytes(*expected_revision).as_bytes());
            }
        }
        format!("{:x}", digest.finalize())
    }
}

// Carries one request through the private serialized writer boundary.
pub(crate) enum WriterMessage {
    Command {
        command: PreparedCommand,
        response_sender: SyncSender<Result<DatabaseWriteResult, DatabaseError>>,
    },
    Transaction {
        idempotency_key: String,
        commands: Vec<PreparedCommand>,
        response_sender: SyncSender<Result<DatabaseTransactionWriteResult, DatabaseError>>,
    },
    Shutdown,
}

// Validates and prepares the filesystem location without opening SQLite.
pub(crate) fn configure_database_path(path: &Path) -> Result<(), DatabaseError> {
    let parent = path.parent().ok_or(DatabaseError::InvalidInput {
        field: "path",
        reason: "path must have a parent directory",
    })?;
    let parent_exists = parent.exists();
    if !parent_exists {
        fs::create_dir_all(parent).map_err(|_| DatabaseError::Unavailable {
            reason: "database directory could not be created",
        })?;
        set_private_directory_mode(parent)?;
    }
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(DatabaseError::InvalidInput {
                field: "path",
                reason: "existing database must be a regular file",
            });
        }
    }
    Ok(())
}

// Opens and verifies the one connection permitted to mutate SQLite state.
pub(crate) fn initialize_writer(
    path: &Path,
    busy_timeout: Duration,
) -> Result<Connection, DatabaseError> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_FULL_MUTEX,
    )
    .map_err(database_error)?;
    connection
        .busy_timeout(busy_timeout)
        .map_err(database_error)?;
    connection
        .execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA locking_mode = NORMAL;
             PRAGMA synchronous = FULL;",
        )
        .map_err(database_error)?;
    create_or_validate_database_schema(&connection)?;
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
        .map_err(database_error)?;
    if journal_mode.to_lowercase() != "wal" {
        return Err(DatabaseError::Unavailable {
            reason: "WAL mode could not be enabled",
        });
    }
    verify_database(&connection)?;
    set_private_file_mode(path)?;
    Ok(connection)
}

// Owns the connection and processes every accepted write in arrival order.
pub(crate) fn run_writer(
    mut connection: Connection,
    clock: Arc<dyn DatabaseClock>,
    receiver: Receiver<WriterMessage>,
    event_sender: Sender<DatabaseEvent>,
) {
    while let Ok(message) = receiver.recv() {
        match message {
            WriterMessage::Command {
                command,
                response_sender,
            } => {
                let result = execute_command(&mut connection, clock.as_ref(), &command);
                if let Ok((commit, is_new_commit)) = &result {
                    if *is_new_commit {
                        let _ = event_sender.send(DatabaseEvent::from_commit(commit));
                    }
                }
                let response = result.map(|(commit, is_new_commit)| {
                    let disposition = if is_new_commit {
                        DatabaseCommitDisposition::Applied
                    } else {
                        DatabaseCommitDisposition::Replayed
                    };
                    DatabaseWriteResult::new(commit, disposition)
                });
                let _ = response_sender.send(response);
            }
            WriterMessage::Transaction {
                idempotency_key,
                commands,
                response_sender,
            } => {
                let result = execute_transaction(
                    &mut connection,
                    clock.as_ref(),
                    &idempotency_key,
                    &commands,
                );
                if let Ok((commits, is_new_commit)) = &result {
                    if *is_new_commit {
                        for commit in commits {
                            let _ = event_sender.send(DatabaseEvent::from_commit(commit));
                        }
                    }
                }
                let response = result.map(|(commits, is_new_commit)| {
                    let disposition = if is_new_commit {
                        DatabaseCommitDisposition::Applied
                    } else {
                        DatabaseCommitDisposition::Replayed
                    };
                    DatabaseTransactionWriteResult::new(
                        DatabaseTransactionCommit::new(commits),
                        disposition,
                    )
                });
                let _ = response_sender.send(response);
            }
            WriterMessage::Shutdown => break,
        }
    }
}

// Converts one typed public command into bounded private storage input.
pub(crate) fn prepare_command<Record: DatabaseRecord>(
    command: DatabaseCommand<Record>,
) -> Result<PreparedCommand, DatabaseError> {
    if Record::VERSION == 0 {
        return Err(DatabaseError::InvalidInput {
            field: "record version",
            reason: "version must be greater than zero",
        });
    }
    match command {
        DatabaseCommand::Save {
            idempotency_key,
            record,
            expected_revision,
        } => {
            let identifier = record.identifier().to_string();
            validate_identifier(&identifier)?;
            validate_idempotency_key(&idempotency_key)?;
            let payload = serde_json::to_vec(&record).map_err(|_| DatabaseError::InvalidInput {
                field: "record",
                reason: "record could not be encoded",
            })?;
            if payload.len() > MAX_RECORD_BYTES {
                return Err(DatabaseError::InvalidInput {
                    field: "record",
                    reason: "encoded record exceeds the size limit",
                });
            }
            Ok(PreparedCommand::Save {
                collection: Record::COLLECTION,
                record_version: Record::VERSION,
                identifier,
                payload,
                idempotency_key,
                expected_revision,
            })
        }
        DatabaseCommand::Delete {
            idempotency_key,
            identifier,
            expected_revision,
            ..
        } => {
            validate_identifier(&identifier)?;
            validate_idempotency_key(&idempotency_key)?;
            Ok(PreparedCommand::Delete {
                collection: Record::COLLECTION,
                record_version: Record::VERSION,
                identifier,
                idempotency_key,
                expected_revision,
            })
        }
    }
}

// Validates one transaction replay identity before mutations are collected.
pub(crate) fn validate_transaction_idempotency_key(
    idempotency_key: &str,
) -> Result<(), DatabaseError> {
    validate_idempotency_key(idempotency_key)
}

// Reads and decodes one exact typed record from committed state.
pub(crate) fn read_one_record<Record: DatabaseRecord>(
    connection: &Connection,
    identifier: &str,
) -> Result<DatabaseStoredRecord<Record>, DatabaseError> {
    validate_identifier(identifier)?;
    let stored = connection
        .query_row(
            "SELECT record_version, revision, payload, created_at_unix_ms, updated_at_unix_ms
             FROM li_database_records
             WHERE collection = ?1 AND identifier = ?2",
            params![Record::COLLECTION.storage_name(), identifier],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()
        .map_err(database_error)?;
    let stored = stored.ok_or_else(|| DatabaseError::NotFound {
        collection: Record::COLLECTION,
        identifier: identifier.to_string(),
    })?;
    decode_record::<Record>(identifier, stored)
}

// Reads and decodes one complete typed collection in identity order.
pub(crate) fn read_all_records<Record: DatabaseRecord>(
    connection: &Connection,
) -> Result<Vec<DatabaseStoredRecord<Record>>, DatabaseError> {
    let mut statement = connection
        .prepare(
            "SELECT identifier, record_version, revision, payload,
                    created_at_unix_ms, updated_at_unix_ms
             FROM li_database_records
             WHERE collection = ?1
             ORDER BY identifier ASC",
        )
        .map_err(database_error)?;
    let rows = statement
        .query_map(params![Record::COLLECTION.storage_name()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })
        .map_err(database_error)?;
    let mut records = Vec::new();
    for row in rows {
        let (identifier, record_version, revision, payload, created_at, updated_at) =
            row.map_err(database_error)?;
        records.push(decode_record::<Record>(
            &identifier,
            (record_version, revision, payload, created_at, updated_at),
        )?);
    }
    Ok(records)
}

// Maps private SQLite failures onto the stable manager error surface.
pub(crate) fn database_error(error: rusqlite::Error) -> DatabaseError {
    match error.sqlite_error_code() {
        Some(ErrorCode::DatabaseBusy) | Some(ErrorCode::DatabaseLocked) => {
            DatabaseError::Unavailable {
                reason: "write lock did not become available before the busy timeout",
            }
        }
        Some(ErrorCode::DatabaseCorrupt) | Some(ErrorCode::NotADatabase) => {
            DatabaseError::Corrupt {
                reason: "SQLite rejected the database structure",
            }
        }
        _ => DatabaseError::Unavailable {
            reason: "SQLite operation failed",
        },
    }
}

// Executes one command atomically and distinguishes replay from a new commit.
fn execute_command(
    connection: &mut Connection,
    clock: &dyn DatabaseClock,
    command: &PreparedCommand,
) -> Result<(DatabaseCommit, bool), DatabaseError> {
    let command_digest = command.digest();
    if let Some((stored_digest, value)) = idempotent_value(connection, command.idempotency_key())? {
        if stored_digest == command_digest {
            let commit = serde_json::from_slice(&value).map_err(|_| DatabaseError::Corrupt {
                reason: "stored idempotency result is invalid",
            })?;
            return Ok((commit, false));
        }
        return Err(DatabaseError::IdempotencyConflict {
            idempotency_key: command.idempotency_key().to_string(),
        });
    }

    let observed_at = clock.now_unix_milliseconds()?;
    if observed_at < 0 {
        return Err(DatabaseError::Unavailable {
            reason: "commit clock returned a negative timestamp",
        });
    }
    let transaction = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(database_error)?;
    let commit = apply_command(&transaction, command, observed_at)?;
    store_idempotent_commit(
        &transaction,
        command.idempotency_key(),
        &command_digest,
        &commit,
    )?;
    transaction.commit().map_err(database_error)?;
    Ok((commit, true))
}

// Executes a bounded set of record mutations in one atomic transaction.
fn execute_transaction(
    connection: &mut Connection,
    clock: &dyn DatabaseClock,
    idempotency_key: &str,
    commands: &[PreparedCommand],
) -> Result<(Vec<DatabaseCommit>, bool), DatabaseError> {
    if commands.is_empty() {
        return Err(DatabaseError::InvalidInput {
            field: "transaction",
            reason: "transaction must contain at least one mutation",
        });
    }
    if commands
        .iter()
        .any(|command| command.idempotency_key() != idempotency_key)
    {
        return Err(DatabaseError::Corrupt {
            reason: "transaction mutation has a different replay identity",
        });
    }
    let transaction_digest = transaction_digest(commands);
    if let Some((stored_digest, value)) = idempotent_value(connection, idempotency_key)? {
        if stored_digest == transaction_digest {
            let commits = serde_json::from_slice(&value).map_err(|_| DatabaseError::Corrupt {
                reason: "stored transaction result is invalid",
            })?;
            return Ok((commits, false));
        }
        return Err(DatabaseError::IdempotencyConflict {
            idempotency_key: idempotency_key.to_string(),
        });
    }
    let observed_at = clock.now_unix_milliseconds()?;
    if observed_at < 0 {
        return Err(DatabaseError::Unavailable {
            reason: "commit clock returned a negative timestamp",
        });
    }
    let transaction = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(database_error)?;
    let mut commits = Vec::with_capacity(commands.len());
    for command in commands {
        commits.push(apply_command(&transaction, command, observed_at)?);
    }
    store_idempotent_transaction(&transaction, idempotency_key, &transaction_digest, &commits)?;
    transaction.commit().map_err(database_error)?;
    Ok((commits, true))
}

// Returns one deterministic digest binding ordered transaction mutations.
fn transaction_digest(commands: &[PreparedCommand]) -> String {
    let mut digest = Sha256::new();
    update_digest_field(&mut digest, b"transaction");
    update_digest_field(&mut digest, &(commands.len() as u64).to_be_bytes());
    for command in commands {
        update_digest_field(&mut digest, command.digest().as_bytes());
    }
    format!("{:x}", digest.finalize())
}

// Applies one prepared mutation inside an already-open immediate transaction.
fn apply_command(
    transaction: &Transaction<'_>,
    command: &PreparedCommand,
    observed_at: i64,
) -> Result<DatabaseCommit, DatabaseError> {
    match command {
        PreparedCommand::Save {
            collection,
            record_version,
            identifier,
            payload,
            idempotency_key,
            expected_revision,
        } => save_record(
            transaction,
            *collection,
            *record_version,
            identifier,
            payload,
            idempotency_key,
            *expected_revision,
            observed_at,
        ),
        PreparedCommand::Delete {
            collection,
            record_version,
            identifier,
            idempotency_key,
            expected_revision,
        } => delete_record(
            transaction,
            *collection,
            *record_version,
            identifier,
            idempotency_key,
            *expected_revision,
            observed_at,
        ),
    }
}

// Creates or replaces one record after enforcing its revision condition.
#[allow(clippy::too_many_arguments)]
fn save_record(
    transaction: &Transaction<'_>,
    collection: DatabaseCollection,
    record_version: u32,
    identifier: &str,
    payload: &[u8],
    idempotency_key: &str,
    expected_revision: DatabaseRevision,
    observed_at: i64,
) -> Result<DatabaseCommit, DatabaseError> {
    let existing = record_state(transaction, collection, identifier)?;
    require_revision(
        collection,
        identifier,
        expected_revision,
        existing.map(|value| value.0),
    )?;
    let (mutation, revision, created_at, committed_at) = match existing {
        Some((revision, created_at, updated_at, existing_record_version)) => {
            if existing_record_version != record_version {
                return Err(DatabaseError::Corrupt {
                    reason: "stored record version does not match its typed contract",
                });
            }
            let next_revision = revision.checked_add(1).ok_or(DatabaseError::Corrupt {
                reason: "record revision overflowed",
            })?;
            (
                DatabaseMutation::Updated,
                next_revision,
                created_at,
                observed_at.max(updated_at),
            )
        }
        None => (DatabaseMutation::Created, 1, observed_at, observed_at),
    };

    if mutation == DatabaseMutation::Created {
        transaction
            .execute(
                "INSERT INTO li_database_records (
                    collection, identifier, record_version, revision, payload,
                    created_at_unix_ms, updated_at_unix_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    collection.storage_name(),
                    identifier,
                    i64::from(record_version),
                    revision_to_sql(revision)?,
                    payload,
                    created_at,
                    committed_at,
                ],
            )
            .map_err(database_error)?;
    } else {
        let previous_revision = revision - 1;
        let changed = transaction
            .execute(
                "UPDATE li_database_records
                 SET revision = ?1, payload = ?2, updated_at_unix_ms = ?3
                 WHERE collection = ?4 AND identifier = ?5 AND revision = ?6",
                params![
                    revision_to_sql(revision)?,
                    payload,
                    committed_at,
                    collection.storage_name(),
                    identifier,
                    revision_to_sql(previous_revision)?,
                ],
            )
            .map_err(database_error)?;
        if changed != 1 {
            return Err(DatabaseError::Conflict {
                collection,
                identifier: identifier.to_string(),
                expected: DatabaseRevision::Exact(previous_revision),
                observed: record_state(transaction, collection, identifier)?.map(|value| value.0),
            });
        }
    }

    Ok(DatabaseCommit {
        idempotency_key: idempotency_key.to_string(),
        collection,
        identifier: identifier.to_string(),
        mutation,
        revision,
        committed_at_unix_milliseconds: committed_at,
    })
}

// Removes one exact record after enforcing its revision condition.
#[allow(clippy::too_many_arguments)]
fn delete_record(
    transaction: &Transaction<'_>,
    collection: DatabaseCollection,
    record_version: u32,
    identifier: &str,
    idempotency_key: &str,
    expected_revision: DatabaseRevision,
    observed_at: i64,
) -> Result<DatabaseCommit, DatabaseError> {
    let existing = record_state(transaction, collection, identifier)?;
    let Some((revision, _, updated_at, existing_record_version)) = existing else {
        return Err(DatabaseError::NotFound {
            collection,
            identifier: identifier.to_string(),
        });
    };
    if existing_record_version != record_version {
        return Err(DatabaseError::Corrupt {
            reason: "stored record version does not match its typed contract",
        });
    }
    require_revision(collection, identifier, expected_revision, Some(revision))?;
    let changed = transaction
        .execute(
            "DELETE FROM li_database_records
             WHERE collection = ?1 AND identifier = ?2 AND revision = ?3",
            params![
                collection.storage_name(),
                identifier,
                revision_to_sql(revision)?,
            ],
        )
        .map_err(database_error)?;
    if changed != 1 {
        return Err(DatabaseError::Conflict {
            collection,
            identifier: identifier.to_string(),
            expected: DatabaseRevision::Exact(revision),
            observed: record_state(transaction, collection, identifier)?.map(|value| value.0),
        });
    }
    let committed_at = observed_at.max(updated_at);
    let next_revision = revision.checked_add(1).ok_or(DatabaseError::Corrupt {
        reason: "record revision overflowed",
    })?;
    Ok(DatabaseCommit {
        idempotency_key: idempotency_key.to_string(),
        collection,
        identifier: identifier.to_string(),
        mutation: DatabaseMutation::Deleted,
        revision: next_revision,
        committed_at_unix_milliseconds: committed_at,
    })
}

// Returns the committed revision and timestamps for one record when present.
fn record_state(
    transaction: &Transaction<'_>,
    collection: DatabaseCollection,
    identifier: &str,
) -> Result<Option<(u64, i64, i64, u32)>, DatabaseError> {
    let state = transaction
        .query_row(
            "SELECT revision, created_at_unix_ms, updated_at_unix_ms, record_version
             FROM li_database_records
             WHERE collection = ?1 AND identifier = ?2",
            params![collection.storage_name(), identifier],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()
        .map_err(database_error)?;
    state
        .map(|(revision, created_at, updated_at, record_version)| {
            Ok((
                revision_from_sql(revision)?,
                valid_timestamp(created_at)?,
                valid_timestamp(updated_at)?,
                u32::try_from(record_version).map_err(|_| DatabaseError::Corrupt {
                    reason: "stored record version is invalid",
                })?,
            ))
        })
        .transpose()
}

// Enforces optimistic creation, replacement, or deletion policy.
fn require_revision(
    collection: DatabaseCollection,
    identifier: &str,
    expected: DatabaseRevision,
    observed: Option<u64>,
) -> Result<(), DatabaseError> {
    let is_valid = match expected {
        DatabaseRevision::Any => true,
        DatabaseRevision::Missing => observed.is_none(),
        DatabaseRevision::Exact(revision) => observed == Some(revision),
    };
    if is_valid {
        return Ok(());
    }
    Err(DatabaseError::Conflict {
        collection,
        identifier: identifier.to_string(),
        expected,
        observed,
    })
}

// Returns prior encoded output and its command digest for one replay identity.
fn idempotent_value(
    connection: &Connection,
    idempotency_key: &str,
) -> Result<Option<(String, Vec<u8>)>, DatabaseError> {
    connection
        .query_row(
            "SELECT command_sha256, commit_json
             FROM li_database_idempotency
             WHERE idempotency_key = ?1",
            params![idempotency_key],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()
        .map_err(database_error)
}

// Stores one replay result in the same transaction as its mutation.
fn store_idempotent_commit(
    transaction: &Transaction<'_>,
    idempotency_key: &str,
    command_digest: &str,
    commit: &DatabaseCommit,
) -> Result<(), DatabaseError> {
    let commit_json = serde_json::to_vec(commit).map_err(|_| DatabaseError::Unavailable {
        reason: "commit result could not be encoded",
    })?;
    transaction
        .execute(
            "INSERT INTO li_database_idempotency (
                idempotency_key, command_sha256, commit_json, committed_at_unix_ms
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                idempotency_key,
                command_digest,
                commit_json,
                commit.committed_at_unix_milliseconds,
            ],
        )
        .map_err(database_error)?;
    Ok(())
}

// Stores one ordered transaction result beside its atomic mutations.
fn store_idempotent_transaction(
    transaction: &Transaction<'_>,
    idempotency_key: &str,
    transaction_digest: &str,
    commits: &[DatabaseCommit],
) -> Result<(), DatabaseError> {
    let commit_json = serde_json::to_vec(commits).map_err(|_| DatabaseError::Unavailable {
        reason: "transaction result could not be encoded",
    })?;
    let committed_at = commits
        .iter()
        .map(|commit| commit.committed_at_unix_milliseconds)
        .max()
        .ok_or(DatabaseError::Corrupt {
            reason: "transaction result is empty",
        })?;
    transaction
        .execute(
            "INSERT INTO li_database_idempotency (
                idempotency_key, command_sha256, commit_json, committed_at_unix_ms
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                idempotency_key,
                transaction_digest,
                commit_json,
                committed_at,
            ],
        )
        .map_err(database_error)?;
    Ok(())
}

// Decodes one stored row through the caller's exact record type and version.
fn decode_record<Record: DatabaseRecord>(
    identifier: &str,
    stored: (i64, i64, Vec<u8>, i64, i64),
) -> Result<DatabaseStoredRecord<Record>, DatabaseError> {
    let (record_version, revision, payload, created_at, updated_at) = stored;
    if record_version != i64::from(Record::VERSION) {
        return Err(DatabaseError::Corrupt {
            reason: "stored record version does not match its typed contract",
        });
    }
    let value: Record = serde_json::from_slice(&payload).map_err(|_| DatabaseError::Corrupt {
        reason: "stored record payload is invalid",
    })?;
    if value.identifier() != identifier {
        return Err(DatabaseError::Corrupt {
            reason: "stored record identity does not match its payload",
        });
    }
    Ok(DatabaseStoredRecord {
        value,
        revision: revision_from_sql(revision)?,
        created_at_unix_milliseconds: valid_timestamp(created_at)?,
        updated_at_unix_milliseconds: valid_timestamp(updated_at)?,
    })
}

// Creates only a blank database or validates one exact current schema.
fn create_or_validate_database_schema(connection: &Connection) -> Result<(), DatabaseError> {
    let application_id: i64 = connection
        .query_row("PRAGMA application_id", [], |row| row.get(0))
        .map_err(database_error)?;
    let schema_version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(database_error)?;
    let schema_objects = database_schema_objects(connection)?;
    if application_id == 0 && schema_version == 0 && schema_objects.is_empty() {
        create_database_schema(connection)?;
        return verify_database_schema(connection);
    }
    if application_id == 0 && !schema_objects.is_empty() {
        return Err(DatabaseError::Corrupt {
            reason: "unidentified SQLite database already contains schema objects",
        });
    }
    if application_id != APPLICATION_ID {
        return Err(DatabaseError::Corrupt {
            reason: "SQLite application identity is not Let's Infer Core",
        });
    }
    if schema_version != DATABASE_SCHEMA_VERSION {
        return Err(DatabaseError::Corrupt {
            reason: "database schema version is unsupported by this Core build",
        });
    }
    verify_database_schema(connection)
}

// Materializes the complete current schema in one transaction.
fn create_database_schema(connection: &Connection) -> Result<(), DatabaseError> {
    connection
        .execute_batch(&format!(
            "BEGIN IMMEDIATE;
             PRAGMA application_id = {APPLICATION_ID};
             {RECORDS_TABLE_SCHEMA};
             {IDEMPOTENCY_TABLE_SCHEMA};
             PRAGMA user_version = {DATABASE_SCHEMA_VERSION};
             COMMIT;"
        ))
        .map_err(database_error)
}

// Returns every caller-defined SQLite schema object in stable order.
fn database_schema_objects(
    connection: &Connection,
) -> Result<Vec<(String, String, String)>, DatabaseError> {
    let mut statement = connection
        .prepare(
            "SELECT type, name, sql FROM sqlite_schema
             WHERE name NOT LIKE 'sqlite_%' AND sql IS NOT NULL
             ORDER BY type ASC, name ASC",
        )
        .map_err(database_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(database_error)?;
    let mut objects = Vec::new();
    for row in rows {
        objects.push(row.map_err(database_error)?);
    }
    Ok(objects)
}

// Verifies identity, version, and the complete closed schema without mutation.
fn verify_database_schema(connection: &Connection) -> Result<(), DatabaseError> {
    let application_id: i64 = connection
        .query_row("PRAGMA application_id", [], |row| row.get(0))
        .map_err(database_error)?;
    let schema_version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(database_error)?;
    let expected_objects = vec![
        (
            "table".to_string(),
            "li_database_idempotency".to_string(),
            normalized_schema_sql(IDEMPOTENCY_TABLE_SCHEMA),
        ),
        (
            "table".to_string(),
            "li_database_records".to_string(),
            normalized_schema_sql(RECORDS_TABLE_SCHEMA),
        ),
    ];
    let observed_objects = database_schema_objects(connection)?
        .into_iter()
        .map(|(object_type, name, sql)| (object_type, name, normalized_schema_sql(&sql)))
        .collect::<Vec<_>>();
    if application_id != APPLICATION_ID
        || schema_version != DATABASE_SCHEMA_VERSION
        || observed_objects != expected_objects
    {
        return Err(DatabaseError::Corrupt {
            reason: "database schema does not exactly match this Core build",
        });
    }
    Ok(())
}

// Normalizes insignificant SQL whitespace before exact schema comparison.
fn normalized_schema_sql(sql: &str) -> String {
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
}

// Verifies SQLite structure before the manager reports readiness.
fn verify_database(connection: &Connection) -> Result<(), DatabaseError> {
    let result: String = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(database_error)?;
    if result != "ok" {
        return Err(DatabaseError::Corrupt {
            reason: "SQLite quick check failed",
        });
    }
    verify_database_schema(connection)
}

// Validates one public record identity before it reaches SQLite.
fn validate_identifier(identifier: &str) -> Result<(), DatabaseError> {
    if identifier.is_empty() || identifier.len() > MAX_IDENTIFIER_BYTES {
        return Err(DatabaseError::InvalidInput {
            field: "identifier",
            reason: "identifier must contain between 1 and 255 bytes",
        });
    }
    if identifier.trim() != identifier || identifier.chars().any(char::is_control) {
        return Err(DatabaseError::InvalidInput {
            field: "identifier",
            reason: "identifier must be canonical and contain no control characters",
        });
    }
    Ok(())
}

// Validates one caller-owned replay identity before it reaches SQLite.
fn validate_idempotency_key(idempotency_key: &str) -> Result<(), DatabaseError> {
    if idempotency_key.is_empty() || idempotency_key.len() > MAX_IDEMPOTENCY_KEY_BYTES {
        return Err(DatabaseError::InvalidInput {
            field: "idempotency key",
            reason: "key must contain between 1 and 255 bytes",
        });
    }
    if idempotency_key.trim() != idempotency_key || idempotency_key.chars().any(char::is_control) {
        return Err(DatabaseError::InvalidInput {
            field: "idempotency key",
            reason: "key must be canonical and contain no control characters",
        });
    }
    Ok(())
}

// Converts a positive public revision into SQLite's signed integer range.
fn revision_to_sql(revision: u64) -> Result<i64, DatabaseError> {
    if revision == 0 {
        return Err(DatabaseError::InvalidInput {
            field: "revision",
            reason: "revision must be greater than zero",
        });
    }
    i64::try_from(revision).map_err(|_| DatabaseError::InvalidInput {
        field: "revision",
        reason: "revision exceeds the SQLite integer range",
    })
}

// Converts one stored SQLite revision into the public positive range.
fn revision_from_sql(revision: i64) -> Result<u64, DatabaseError> {
    if revision <= 0 {
        return Err(DatabaseError::Corrupt {
            reason: "stored record revision is invalid",
        });
    }
    u64::try_from(revision).map_err(|_| DatabaseError::Corrupt {
        reason: "stored record revision is invalid",
    })
}

// Rejects negative timestamps read from persistent state.
fn valid_timestamp(timestamp: i64) -> Result<i64, DatabaseError> {
    if timestamp < 0 {
        return Err(DatabaseError::Corrupt {
            reason: "stored record timestamp is invalid",
        });
    }
    Ok(timestamp)
}

// Encodes one revision condition for deterministic command identity.
fn revision_bytes(revision: DatabaseRevision) -> String {
    match revision {
        DatabaseRevision::Any => "any".to_string(),
        DatabaseRevision::Missing => "missing".to_string(),
        DatabaseRevision::Exact(value) => format!("exact:{value}"),
    }
}

// Adds one length-delimited value to a deterministic command digest.
fn update_digest_field(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

// Restricts a newly created database file to its owning user.
#[cfg(unix)]
fn set_private_file_mode(path: &Path) -> Result<(), DatabaseError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|_| {
        DatabaseError::Unavailable {
            reason: "database file permissions could not be restricted",
        }
    })
}

// Leaves platform file permissions to a future native provider.
#[cfg(not(unix))]
fn set_private_file_mode(_path: &Path) -> Result<(), DatabaseError> {
    Ok(())
}

// Restricts a newly created private directory without widening existing access.
#[cfg(unix)]
fn set_private_directory_mode(path: &Path) -> Result<(), DatabaseError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::metadata(path).map_err(|_| DatabaseError::Unavailable {
        reason: "database directory could not be inspected",
    })?;
    let current_mode = metadata.permissions().mode() & 0o777;
    let private_mode = current_mode & 0o700;
    fs::set_permissions(path, fs::Permissions::from_mode(private_mode)).map_err(|_| {
        DatabaseError::Unavailable {
            reason: "database directory permissions could not be restricted",
        }
    })
}

// Leaves platform directory permissions to a future native provider.
#[cfg(not(unix))]
fn set_private_directory_mode(_path: &Path) -> Result<(), DatabaseError> {
    Ok(())
}
