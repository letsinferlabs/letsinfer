// SPDX-License-Identifier: AGPL-3.0-only

use crate::li_database_contract::{
    DatabaseCommand, DatabaseCommit, DatabaseCommitDisposition, DatabaseError, DatabaseRecord,
    DatabaseRevision,
};
use crate::li_database_storage::{
    prepare_command, validate_transaction_idempotency_key, PreparedCommand,
};

const MAX_TRANSACTION_MUTATIONS: usize = 256;

// Collects typed mutations that must commit or roll back together.
pub struct DatabaseTransaction {
    idempotency_key: String,
    commands: Vec<PreparedCommand>,
}

impl DatabaseTransaction {
    // Creates one empty transaction with a caller-owned replay identity.
    pub fn new(idempotency_key: impl Into<String>) -> Result<Self, DatabaseError> {
        let idempotency_key = idempotency_key.into();
        validate_transaction_idempotency_key(&idempotency_key)?;
        Ok(Self {
            idempotency_key,
            commands: Vec::new(),
        })
    }

    // Adds one typed creation or replacement to this transaction.
    pub fn save<Record: DatabaseRecord>(
        mut self,
        record: Record,
        expected_revision: DatabaseRevision,
    ) -> Result<Self, DatabaseError> {
        let command = prepare_command(DatabaseCommand::save(
            self.idempotency_key.clone(),
            record,
            expected_revision,
        ))?;
        self.add_command(command)?;
        Ok(self)
    }

    // Adds one typed deletion to this transaction.
    pub fn delete<Record: DatabaseRecord>(
        mut self,
        identifier: impl Into<String>,
        expected_revision: DatabaseRevision,
    ) -> Result<Self, DatabaseError> {
        let command = prepare_command(DatabaseCommand::<Record>::delete(
            self.idempotency_key.clone(),
            identifier,
            expected_revision,
        ))?;
        self.add_command(command)?;
        Ok(self)
    }

    // Returns the number of mutations that will commit atomically.
    pub const fn len(&self) -> usize {
        self.commands.len()
    }

    // Returns whether this transaction contains no mutation.
    pub const fn is_empty(&self) -> bool {
        self.commands.is_empty()
    }

    // Returns the caller-owned replay identity shared by every transaction mutation.
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    // Transfers validated transaction storage to DatabaseManager.
    pub(crate) fn into_parts(self) -> (String, Vec<PreparedCommand>) {
        (self.idempotency_key, self.commands)
    }

    // Adds one mutation only when its target is unique and the batch is bounded.
    fn add_command(&mut self, command: PreparedCommand) -> Result<(), DatabaseError> {
        if self.commands.len() >= MAX_TRANSACTION_MUTATIONS {
            return Err(DatabaseError::InvalidInput {
                field: "transaction",
                reason: "transaction exceeds the mutation limit",
            });
        }
        if self.commands.iter().any(|current| {
            current.collection() == command.collection()
                && current.identifier() == command.identifier()
        }) {
            return Err(DatabaseError::InvalidInput {
                field: "transaction",
                reason: "transaction contains duplicate record targets",
            });
        }
        self.commands.push(command);
        Ok(())
    }
}

// Describes every record mutation committed by one atomic transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DatabaseTransactionCommit {
    commits: Vec<DatabaseCommit>,
}

impl DatabaseTransactionCommit {
    // Creates one ordered commit collection after SQLite commits.
    pub(crate) const fn new(commits: Vec<DatabaseCommit>) -> Self {
        Self { commits }
    }

    // Returns the record commits in caller-supplied mutation order.
    pub fn commits(&self) -> &[DatabaseCommit] {
        &self.commits
    }
}

// Returns one transaction commit together with replay disposition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DatabaseTransactionWriteResult {
    commit: DatabaseTransactionCommit,
    disposition: DatabaseCommitDisposition,
}

impl DatabaseTransactionWriteResult {
    // Creates one exact atomic write result.
    pub(crate) const fn new(
        commit: DatabaseTransactionCommit,
        disposition: DatabaseCommitDisposition,
    ) -> Self {
        Self {
            commit,
            disposition,
        }
    }

    // Returns every record commit produced by the transaction.
    pub const fn commit(&self) -> &DatabaseTransactionCommit {
        &self.commit
    }

    // Returns whether this call applied or replayed the transaction.
    pub const fn disposition(&self) -> DatabaseCommitDisposition {
        self.disposition
    }
}
