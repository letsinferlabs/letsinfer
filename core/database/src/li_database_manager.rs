// SPDX-License-Identifier: AGPL-3.0-only

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::Mutex;
use std::thread::{self, JoinHandle};

use rusqlite::{Connection, OpenFlags};

use crate::li_database_contract::{
    DatabaseCommand, DatabaseConfiguration, DatabaseError, DatabaseEvent, DatabaseQuery,
    DatabaseRecord, DatabaseResult, DatabaseWriteResult,
};
use crate::li_database_storage::{
    configure_database_path, initialize_writer, prepare_command, read_all_records, read_one_record,
    run_writer, PreparedCommand, WriterMessage,
};
use crate::li_database_transaction::{DatabaseTransaction, DatabaseTransactionWriteResult};

// Owns one SQLite lifecycle and the only serialized write boundary.
pub struct DatabaseManager {
    database_path: PathBuf,
    busy_timeout: std::time::Duration,
    writer_sender: SyncSender<WriterMessage>,
    event_receiver: Mutex<Option<Receiver<DatabaseEvent>>>,
    worker: Option<JoinHandle<()>>,
    is_closed: AtomicBool,
}

impl DatabaseManager {
    // Opens one new or exact-current database before accepting any work.
    pub fn open(configuration: DatabaseConfiguration) -> Result<Self, DatabaseError> {
        validate_configuration(&configuration)?;
        configure_database_path(configuration.database_path())?;

        let database_path = configuration.database_path().to_path_buf();
        let busy_timeout = configuration.busy_timeout();
        let clock = configuration.clock();
        let (writer_sender, writer_receiver) =
            mpsc::sync_channel(configuration.write_queue_capacity());
        let (event_sender, event_receiver) = mpsc::channel();
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        let worker_path = database_path.clone();
        let worker = thread::Builder::new()
            .name("li_database_writer".to_string())
            .spawn(move || {
                let writer = initialize_writer(&worker_path, busy_timeout);
                match writer {
                    Ok(connection) => {
                        let _ = ready_sender.send(Ok(()));
                        run_writer(connection, clock, writer_receiver, event_sender);
                    }
                    Err(error) => {
                        let _ = ready_sender.send(Err(error));
                    }
                }
            })
            .map_err(|_| DatabaseError::Unavailable {
                reason: "writer thread could not start",
            })?;

        match ready_receiver.recv() {
            Ok(Ok(())) => Ok(Self {
                database_path,
                busy_timeout,
                writer_sender,
                event_receiver: Mutex::new(Some(event_receiver)),
                worker: Some(worker),
                is_closed: AtomicBool::new(false),
            }),
            Ok(Err(error)) => {
                let _ = worker.join();
                Err(error)
            }
            Err(_) => {
                let _ = worker.join();
                Err(DatabaseError::Unavailable {
                    reason: "writer stopped during initialization",
                })
            }
        }
    }

    // Executes one typed query against committed WAL state.
    pub fn read<Record: DatabaseRecord>(
        &self,
        query: DatabaseQuery<Record>,
    ) -> Result<DatabaseResult<Record>, DatabaseError> {
        self.require_open()?;
        let connection = open_reader(&self.database_path, self.busy_timeout)?;
        match query {
            DatabaseQuery::Record { identifier, .. } => {
                let record = read_one_record::<Record>(&connection, &identifier)?;
                Ok(DatabaseResult::Record(record))
            }
            DatabaseQuery::All { .. } => {
                let records = read_all_records::<Record>(&connection)?;
                Ok(DatabaseResult::Records(records))
            }
        }
    }

    // Serializes one typed command through the bounded writer queue.
    pub fn write<Record: DatabaseRecord>(
        &self,
        command: DatabaseCommand<Record>,
    ) -> Result<DatabaseWriteResult, DatabaseError> {
        self.require_open()?;
        let prepared = prepare_command(command)?;
        self.send_command(prepared)
    }

    // Serializes one multi-record transaction through the same writer owner.
    pub fn write_transaction(
        &self,
        transaction: DatabaseTransaction,
    ) -> Result<DatabaseTransactionWriteResult, DatabaseError> {
        self.require_open()?;
        if transaction.is_empty() {
            return Err(DatabaseError::InvalidInput {
                field: "transaction",
                reason: "transaction must contain at least one mutation",
            });
        }
        let (idempotency_key, commands) = transaction.into_parts();
        let (response_sender, response_receiver) = mpsc::sync_channel(1);
        self.writer_sender
            .send(WriterMessage::Transaction {
                idempotency_key,
                commands,
                response_sender,
            })
            .map_err(|_| DatabaseError::Closed)?;
        response_receiver
            .recv()
            .map_err(|_| DatabaseError::Closed)?
    }

    // Transfers the single post-commit event stream to the node agent.
    pub fn take_event_receiver(&self) -> Result<Receiver<DatabaseEvent>, DatabaseError> {
        let mut receiver = self
            .event_receiver
            .lock()
            .map_err(|_| DatabaseError::Closed)?;
        receiver.take().ok_or(DatabaseError::InvalidInput {
            field: "event receiver",
            reason: "receiver ownership was already transferred",
        })
    }

    // Stops the writer after all previously accepted commands complete.
    pub fn close(mut self) -> Result<(), DatabaseError> {
        self.stop_writer()
    }

    // Sends one prepared mutation and waits for its exact durable result.
    fn send_command(&self, command: PreparedCommand) -> Result<DatabaseWriteResult, DatabaseError> {
        let (response_sender, response_receiver) = mpsc::sync_channel(1);
        self.writer_sender
            .send(WriterMessage::Command {
                command,
                response_sender,
            })
            .map_err(|_| DatabaseError::Closed)?;
        response_receiver
            .recv()
            .map_err(|_| DatabaseError::Closed)?
    }

    // Rejects work after the manager begins its terminal lifecycle transition.
    fn require_open(&self) -> Result<(), DatabaseError> {
        if self.is_closed.load(Ordering::Acquire) {
            return Err(DatabaseError::Closed);
        }
        Ok(())
    }

    // Performs the one idempotent writer shutdown and joins its owner thread.
    fn stop_writer(&mut self) -> Result<(), DatabaseError> {
        if self.is_closed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let _ = self.writer_sender.send(WriterMessage::Shutdown);
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        worker.join().map_err(|_| DatabaseError::Unavailable {
            reason: "writer thread terminated unexpectedly",
        })
    }
}

impl Drop for DatabaseManager {
    // Releases the owned writer when the node agent releases the manager.
    fn drop(&mut self) {
        let _ = self.stop_writer();
    }
}

// Validates the explicit native configuration before creating any resource.
fn validate_configuration(configuration: &DatabaseConfiguration) -> Result<(), DatabaseError> {
    if !configuration.database_path().is_absolute() {
        return Err(DatabaseError::InvalidInput {
            field: "path",
            reason: "path must be absolute",
        });
    }
    if configuration.database_path().file_name().is_none() {
        return Err(DatabaseError::InvalidInput {
            field: "path",
            reason: "path must identify a database file",
        });
    }
    if configuration.write_queue_capacity() == 0 {
        return Err(DatabaseError::InvalidInput {
            field: "write queue capacity",
            reason: "capacity must be greater than zero",
        });
    }
    if configuration.busy_timeout().is_zero() {
        return Err(DatabaseError::InvalidInput {
            field: "busy timeout",
            reason: "timeout must be greater than zero",
        });
    }
    Ok(())
}

// Opens one isolated read-only connection over the last committed WAL state.
fn open_reader(
    path: &Path,
    busy_timeout: std::time::Duration,
) -> Result<Connection, DatabaseError> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(crate::li_database_storage::database_error)?;
    connection
        .busy_timeout(busy_timeout)
        .map_err(crate::li_database_storage::database_error)?;
    connection
        .execute_batch("PRAGMA query_only = ON; PRAGMA foreign_keys = ON;")
        .map_err(crate::li_database_storage::database_error)?;
    Ok(connection)
}
