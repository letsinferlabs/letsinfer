// SPDX-License-Identifier: AGPL-3.0-only

use std::num::{NonZeroU32, NonZeroU64};
use std::sync::Arc;

use li_authentication_manager::{
    ApiKey, ApiKeyLimits, ApiKeyModelScope, ApiKeyPolicy, AuthenticationRecord,
    AuthenticationRotation, AuthenticationStore, AuthenticationStoreError,
    VersionedAuthenticationRecord,
};
use li_core_interface::{ApiKeyId, DisplayName, LogicalModelName, TechnicalName, UnixMilliseconds};
use li_database::{
    DatabaseCollection, DatabaseCommand, DatabaseCommitDisposition, DatabaseError, DatabaseManager,
    DatabaseQuery, DatabaseRecord, DatabaseResult, DatabaseRevision, DatabaseTransaction,
};
use serde::{Deserialize, Serialize};

const AUTHENTICATION_RECORD_SCHEMA_NAME: &str = "li_authentication_record";
const AUTHENTICATION_RECORD_SCHEMA_VERSION: u32 = 1;

// Identifies the exact private authentication persistence contract.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthenticationDatabaseSchema {
    name: String,
    version: u32,
}

// Stores one API-key verifier and policy in DatabaseManager's private schema.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthenticationDatabaseRecord {
    schema: AuthenticationDatabaseSchema,
    key_id: String,
    name: String,
    selected_models: Option<Vec<String>>,
    expires_at_unix_milliseconds: Option<u64>,
    requests_per_minute: Option<u32>,
    tokens_per_minute: Option<u64>,
    concurrency: Option<u32>,
    context_tokens: Option<u64>,
    tenant: Option<String>,
    application: Option<String>,
    created_at_unix_milliseconds: u64,
    revoked_at_unix_milliseconds: Option<u64>,
    rotated_from: Option<String>,
    salt: [u8; 16],
    verifier: [u8; 32],
}

impl DatabaseRecord for AuthenticationDatabaseRecord {
    const COLLECTION: DatabaseCollection = DatabaseCollection::Authentication;

    // Returns the exact API-key identity used by private persistence.
    fn identifier(&self) -> &str {
        &self.key_id
    }
}

// Adapts AuthenticationManager's narrow store contract to DatabaseManager.
pub struct DatabaseAuthenticationStore {
    database: Arc<DatabaseManager>,
}

impl DatabaseAuthenticationStore {
    // Creates one adapter without transferring database lifecycle ownership.
    pub const fn new(database: Arc<DatabaseManager>) -> Self {
        Self { database }
    }
}

impl AuthenticationStore for DatabaseAuthenticationStore {
    // Returns one validated API-key record when it exists.
    fn read(
        &self,
        key_id: &ApiKeyId,
    ) -> Result<Option<VersionedAuthenticationRecord>, AuthenticationStoreError> {
        match self
            .database
            .read(DatabaseQuery::<AuthenticationDatabaseRecord>::record(
                key_id.as_str(),
            )) {
            Ok(DatabaseResult::Record(stored)) => Ok(Some(versioned_authentication_record(
                stored.value,
                stored.revision,
            )?)),
            Ok(DatabaseResult::Records(_)) => Err(AuthenticationStoreError::Corrupt),
            Err(DatabaseError::NotFound { .. }) => Ok(None),
            Err(error) => Err(authentication_store_error(error)),
        }
    }

    // Returns every validated API-key record in stable identity order.
    fn all(&self) -> Result<Vec<VersionedAuthenticationRecord>, AuthenticationStoreError> {
        match self
            .database
            .read(DatabaseQuery::<AuthenticationDatabaseRecord>::all())
        {
            Ok(DatabaseResult::Records(records)) => records
                .into_iter()
                .map(|stored| versioned_authentication_record(stored.value, stored.revision))
                .collect(),
            Ok(DatabaseResult::Record(_)) => Err(AuthenticationStoreError::Corrupt),
            Err(error) => Err(authentication_store_error(error)),
        }
    }

    // Creates one exact API-key record and rejects replay as a concurrent write.
    fn create(
        &self,
        record: AuthenticationRecord,
    ) -> Result<VersionedAuthenticationRecord, AuthenticationStoreError> {
        let key_id = record.api_key().key_id().clone();
        let result = self
            .database
            .write(DatabaseCommand::save(
                format!("authentication:create:{}", key_id.as_str()),
                authentication_database_record(&record),
                DatabaseRevision::Missing,
            ))
            .map_err(authentication_store_error)?;
        require_applied(result.disposition())?;
        Ok(VersionedAuthenticationRecord::new(
            record,
            result.commit().revision,
        ))
    }

    // Replaces one exact API-key revision and rejects replay as observation.
    fn replace(
        &self,
        record: AuthenticationRecord,
        expected_revision: u64,
    ) -> Result<VersionedAuthenticationRecord, AuthenticationStoreError> {
        let key_id = record.api_key().key_id().clone();
        let result = self
            .database
            .write(DatabaseCommand::save(
                format!(
                    "authentication:replace:{}:{expected_revision}",
                    key_id.as_str()
                ),
                authentication_database_record(&record),
                DatabaseRevision::Exact(expected_revision),
            ))
            .map_err(authentication_store_error)?;
        require_applied(result.disposition())?;
        Ok(VersionedAuthenticationRecord::new(
            record,
            result.commit().revision,
        ))
    }

    // Revokes one key and creates its replacement in one database transaction.
    fn rotate(
        &self,
        revoked: AuthenticationRecord,
        expected_revision: u64,
        replacement: AuthenticationRecord,
    ) -> Result<AuthenticationRotation, AuthenticationStoreError> {
        let revoked_id = revoked.api_key().key_id().clone();
        let replacement_id = replacement.api_key().key_id().clone();
        let transaction = DatabaseTransaction::new(format!(
            "authentication:rotate:{}:{}",
            revoked_id.as_str(),
            replacement_id.as_str()
        ))
        .map_err(authentication_store_error)?
        .save(
            authentication_database_record(&revoked),
            DatabaseRevision::Exact(expected_revision),
        )
        .map_err(authentication_store_error)?
        .save(
            authentication_database_record(&replacement),
            DatabaseRevision::Missing,
        )
        .map_err(authentication_store_error)?;
        let result = self
            .database
            .write_transaction(transaction)
            .map_err(authentication_store_error)?;
        require_applied(result.disposition())?;
        let commits = result.commit().commits();
        if commits.len() != 2
            || commits[0].identifier != revoked_id.as_str()
            || commits[1].identifier != replacement_id.as_str()
        {
            return Err(AuthenticationStoreError::Corrupt);
        }
        Ok(AuthenticationRotation::new(
            VersionedAuthenticationRecord::new(revoked, commits[0].revision),
            VersionedAuthenticationRecord::new(replacement, commits[1].revision),
        ))
    }
}

// Projects one authentication record into private database fields.
fn authentication_database_record(record: &AuthenticationRecord) -> AuthenticationDatabaseRecord {
    let api_key = record.api_key();
    AuthenticationDatabaseRecord {
        schema: AuthenticationDatabaseSchema {
            name: AUTHENTICATION_RECORD_SCHEMA_NAME.to_string(),
            version: AUTHENTICATION_RECORD_SCHEMA_VERSION,
        },
        key_id: api_key.key_id().as_str().to_string(),
        name: api_key.name().as_str().to_string(),
        selected_models: api_key
            .policy()
            .model_scope()
            .selected_models()
            .map(|models| {
                models
                    .iter()
                    .map(|model| model.as_str().to_string())
                    .collect()
            }),
        expires_at_unix_milliseconds: api_key.policy().expires_at().map(UnixMilliseconds::value),
        requests_per_minute: api_key
            .policy()
            .limits()
            .requests_per_minute()
            .map(NonZeroU32::get),
        tokens_per_minute: api_key
            .policy()
            .limits()
            .tokens_per_minute()
            .map(NonZeroU64::get),
        concurrency: api_key.policy().limits().concurrency().map(NonZeroU32::get),
        context_tokens: api_key
            .policy()
            .limits()
            .context_tokens()
            .map(NonZeroU64::get),
        tenant: api_key
            .policy()
            .tenant()
            .map(|value| value.as_str().to_string()),
        application: api_key
            .policy()
            .application()
            .map(|value| value.as_str().to_string()),
        created_at_unix_milliseconds: api_key.created_at().value(),
        revoked_at_unix_milliseconds: api_key.revoked_at().map(UnixMilliseconds::value),
        rotated_from: api_key
            .rotated_from()
            .map(|identity| identity.as_str().to_string()),
        salt: *record.salt(),
        verifier: *record.verifier(),
    }
}

// Reconstructs one validated authentication record from private database fields.
fn authentication_record(
    record: AuthenticationDatabaseRecord,
) -> Result<AuthenticationRecord, AuthenticationStoreError> {
    if record.schema.name != AUTHENTICATION_RECORD_SCHEMA_NAME
        || record.schema.version != AUTHENTICATION_RECORD_SCHEMA_VERSION
    {
        return Err(AuthenticationStoreError::Corrupt);
    }
    let model_scope = match record.selected_models {
        None => ApiKeyModelScope::all(),
        Some(models) => ApiKeyModelScope::selected(
            models
                .into_iter()
                .map(|model| {
                    LogicalModelName::parse(&model).map_err(|_| AuthenticationStoreError::Corrupt)
                })
                .collect::<Result<Vec<_>, _>>()?,
        )
        .map_err(|_| AuthenticationStoreError::Corrupt)?,
    };
    let limits = ApiKeyLimits::new(
        record.requests_per_minute.and_then(NonZeroU32::new),
        record.tokens_per_minute.and_then(NonZeroU64::new),
        record.concurrency.and_then(NonZeroU32::new),
        record.context_tokens.and_then(NonZeroU64::new),
    );
    if record.requests_per_minute == Some(0)
        || record.tokens_per_minute == Some(0)
        || record.concurrency == Some(0)
        || record.context_tokens == Some(0)
    {
        return Err(AuthenticationStoreError::Corrupt);
    }
    let policy = ApiKeyPolicy::new(
        model_scope,
        record
            .expires_at_unix_milliseconds
            .map(UnixMilliseconds::new),
        limits,
        record
            .tenant
            .map(|value| TechnicalName::parse(&value))
            .transpose()
            .map_err(|_| AuthenticationStoreError::Corrupt)?,
        record
            .application
            .map(|value| TechnicalName::parse(&value))
            .transpose()
            .map_err(|_| AuthenticationStoreError::Corrupt)?,
    );
    let api_key = ApiKey::new(
        ApiKeyId::parse(&record.key_id).map_err(|_| AuthenticationStoreError::Corrupt)?,
        DisplayName::parse(&record.name).map_err(|_| AuthenticationStoreError::Corrupt)?,
        policy,
        UnixMilliseconds::new(record.created_at_unix_milliseconds),
        record
            .revoked_at_unix_milliseconds
            .map(UnixMilliseconds::new),
        record
            .rotated_from
            .map(|value| ApiKeyId::parse(&value))
            .transpose()
            .map_err(|_| AuthenticationStoreError::Corrupt)?,
    )
    .map_err(|_| AuthenticationStoreError::Corrupt)?;
    Ok(AuthenticationRecord::new(
        api_key,
        record.salt,
        record.verifier,
    ))
}

// Returns one reconstructed record with its optimistic database revision.
fn versioned_authentication_record(
    record: AuthenticationDatabaseRecord,
    revision: u64,
) -> Result<VersionedAuthenticationRecord, AuthenticationStoreError> {
    Ok(VersionedAuthenticationRecord::new(
        authentication_record(record)?,
        revision,
    ))
}

// Converts DatabaseManager failures to AuthenticationStore's narrow surface.
fn authentication_store_error(error: DatabaseError) -> AuthenticationStoreError {
    match error {
        DatabaseError::Conflict { .. } | DatabaseError::IdempotencyConflict { .. } => {
            AuthenticationStoreError::Conflict
        }
        DatabaseError::Corrupt { .. } => AuthenticationStoreError::Corrupt,
        DatabaseError::NotFound { .. }
        | DatabaseError::InvalidInput { .. }
        | DatabaseError::Unavailable { .. }
        | DatabaseError::Closed => AuthenticationStoreError::Unavailable,
    }
}

// Requires one store mutation to be newly applied rather than replayed.
fn require_applied(disposition: DatabaseCommitDisposition) -> Result<(), AuthenticationStoreError> {
    match disposition {
        DatabaseCommitDisposition::Applied => Ok(()),
        DatabaseCommitDisposition::Replayed => Err(AuthenticationStoreError::Conflict),
    }
}
