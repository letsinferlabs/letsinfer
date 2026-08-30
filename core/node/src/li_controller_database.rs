// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use li_authentication_manager::{
    AuthenticationStoreError, Controller, ControllerCertificate, ControllerRole, ControllerState,
    ControllerStore, VersionedController,
};
use li_core_interface::{ControllerId, DisplayName, Sha256Digest, UnixMilliseconds};
use li_database::{
    DatabaseCollection, DatabaseCommand, DatabaseCommitDisposition, DatabaseError, DatabaseManager,
    DatabaseQuery, DatabaseRecord, DatabaseResult, DatabaseRevision,
};
use serde::{Deserialize, Serialize};

const CONTROLLER_RECORD_SCHEMA_NAME: &str = "li_controller_record";
const CONTROLLER_RECORD_SCHEMA_VERSION: u32 = 1;

// Identifies the exact private controller persistence contract.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ControllerDatabaseSchema {
    name: String,
    version: u32,
}

// Stores only validated public controller material and lifecycle metadata.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ControllerDatabaseRecord {
    schema: ControllerDatabaseSchema,
    controller_id: String,
    name: String,
    role: String,
    state: String,
    certificate_sha256: String,
    public_key_sha256: String,
    certificate_public_material_base64: String,
    certificate_valid_from_unix_milliseconds: u64,
    certificate_expires_at_unix_milliseconds: u64,
    issued_at_unix_milliseconds: u64,
    activated_at_unix_milliseconds: Option<u64>,
    revoked_at_unix_milliseconds: Option<u64>,
}

impl DatabaseRecord for ControllerDatabaseRecord {
    const COLLECTION: DatabaseCollection = DatabaseCollection::Controllers;

    // Returns the exact controller identity used by private persistence.
    fn identifier(&self) -> &str {
        &self.controller_id
    }
}

// Adapts AuthenticationManager's controller store port to DatabaseManager.
pub struct DatabaseControllerStore {
    database: Arc<DatabaseManager>,
}

impl DatabaseControllerStore {
    // Creates one adapter without transferring DatabaseManager lifecycle ownership.
    pub const fn new(database: Arc<DatabaseManager>) -> Self {
        Self { database }
    }
}

impl ControllerStore for DatabaseControllerStore {
    // Returns one fully validated controller record when it exists.
    fn read(
        &self,
        controller_id: &ControllerId,
    ) -> Result<Option<VersionedController>, AuthenticationStoreError> {
        match self
            .database
            .read(DatabaseQuery::<ControllerDatabaseRecord>::record(
                controller_id.as_str(),
            )) {
            Ok(DatabaseResult::Record(stored)) => {
                Ok(Some(versioned_controller(stored.value, stored.revision)?))
            }
            Ok(DatabaseResult::Records(_)) => Err(AuthenticationStoreError::Corrupt),
            Err(DatabaseError::NotFound { .. }) => Ok(None),
            Err(error) => Err(controller_store_error(error)),
        }
    }

    // Returns every fully validated controller record in database identity order.
    fn all(&self) -> Result<Vec<VersionedController>, AuthenticationStoreError> {
        match self
            .database
            .read(DatabaseQuery::<ControllerDatabaseRecord>::all())
        {
            Ok(DatabaseResult::Records(records)) => records
                .into_iter()
                .map(|stored| versioned_controller(stored.value, stored.revision))
                .collect(),
            Ok(DatabaseResult::Record(_)) => Err(AuthenticationStoreError::Corrupt),
            Err(error) => Err(controller_store_error(error)),
        }
    }

    // Creates one exact controller record with replay resolved by AuthenticationManager.
    fn create(
        &self,
        controller: Controller,
    ) -> Result<VersionedController, AuthenticationStoreError> {
        let controller_id = controller.controller_id().clone();
        let result = self
            .database
            .write(DatabaseCommand::save(
                format!(
                    "controller:create:{}:{}",
                    controller_id.as_str(),
                    controller.certificate().certificate_sha256().as_str()
                ),
                controller_database_record(&controller),
                DatabaseRevision::Missing,
            ))
            .map_err(controller_store_error)?;
        require_controller_commit(
            result.disposition(),
            result.commit().collection,
            &result.commit().identifier,
            &controller_id,
        )?;
        Ok(VersionedController::new(
            controller,
            result.commit().revision,
        ))
    }

    // Replaces one exact controller revision for activation, revocation, or replacement.
    fn replace(
        &self,
        controller: Controller,
        expected_revision: u64,
    ) -> Result<VersionedController, AuthenticationStoreError> {
        let controller_id = controller.controller_id().clone();
        let result = self
            .database
            .write(DatabaseCommand::save(
                format!(
                    "controller:replace:{}:{expected_revision}:{}:{}:{}",
                    controller_id.as_str(),
                    controller.state().as_str(),
                    controller.certificate().certificate_sha256().as_str(),
                    controller
                        .revoked_at()
                        .map(UnixMilliseconds::value)
                        .unwrap_or(0)
                ),
                controller_database_record(&controller),
                DatabaseRevision::Exact(expected_revision),
            ))
            .map_err(controller_store_error)?;
        require_controller_commit(
            result.disposition(),
            result.commit().collection,
            &result.commit().identifier,
            &controller_id,
        )?;
        Ok(VersionedController::new(
            controller,
            result.commit().revision,
        ))
    }
}

// Projects one validated controller into strict private database fields.
fn controller_database_record(controller: &Controller) -> ControllerDatabaseRecord {
    let certificate = controller.certificate();
    ControllerDatabaseRecord {
        schema: ControllerDatabaseSchema {
            name: CONTROLLER_RECORD_SCHEMA_NAME.to_string(),
            version: CONTROLLER_RECORD_SCHEMA_VERSION,
        },
        controller_id: controller.controller_id().as_str().to_string(),
        name: controller.name().as_str().to_string(),
        role: controller.role().as_str().to_string(),
        state: controller.state().as_str().to_string(),
        certificate_sha256: certificate.certificate_sha256().as_str().to_string(),
        public_key_sha256: certificate.public_key_sha256().as_str().to_string(),
        certificate_public_material_base64: STANDARD_NO_PAD.encode(certificate.public_material()),
        certificate_valid_from_unix_milliseconds: certificate.valid_from().value(),
        certificate_expires_at_unix_milliseconds: certificate.expires_at().value(),
        issued_at_unix_milliseconds: controller.issued_at().value(),
        activated_at_unix_milliseconds: controller.activated_at().map(UnixMilliseconds::value),
        revoked_at_unix_milliseconds: controller.revoked_at().map(UnixMilliseconds::value),
    }
}

// Reconstructs one validated controller from strict private database fields.
fn controller_record(
    record: ControllerDatabaseRecord,
) -> Result<Controller, AuthenticationStoreError> {
    if record.schema.name != CONTROLLER_RECORD_SCHEMA_NAME
        || record.schema.version != CONTROLLER_RECORD_SCHEMA_VERSION
    {
        return Err(AuthenticationStoreError::Corrupt);
    }
    let controller_id = ControllerId::parse(&record.controller_id)
        .map_err(|_| AuthenticationStoreError::Corrupt)?;
    let certificate = ControllerCertificate::new(
        controller_id.clone(),
        Sha256Digest::parse(&record.certificate_sha256)
            .map_err(|_| AuthenticationStoreError::Corrupt)?,
        Sha256Digest::parse(&record.public_key_sha256)
            .map_err(|_| AuthenticationStoreError::Corrupt)?,
        STANDARD_NO_PAD
            .decode(record.certificate_public_material_base64)
            .map_err(|_| AuthenticationStoreError::Corrupt)?,
        UnixMilliseconds::new(record.certificate_valid_from_unix_milliseconds),
        UnixMilliseconds::new(record.certificate_expires_at_unix_milliseconds),
    )
    .map_err(|_| AuthenticationStoreError::Corrupt)?;
    Controller::restore(
        controller_id,
        DisplayName::parse(&record.name).map_err(|_| AuthenticationStoreError::Corrupt)?,
        ControllerRole::parse(&record.role).map_err(|_| AuthenticationStoreError::Corrupt)?,
        certificate,
        ControllerState::parse(&record.state).map_err(|_| AuthenticationStoreError::Corrupt)?,
        UnixMilliseconds::new(record.issued_at_unix_milliseconds),
        record
            .activated_at_unix_milliseconds
            .map(UnixMilliseconds::new),
        record
            .revoked_at_unix_milliseconds
            .map(UnixMilliseconds::new),
    )
    .map_err(|_| AuthenticationStoreError::Corrupt)
}

// Returns one reconstructed controller together with its optimistic revision.
fn versioned_controller(
    record: ControllerDatabaseRecord,
    revision: u64,
) -> Result<VersionedController, AuthenticationStoreError> {
    Ok(VersionedController::new(
        controller_record(record)?,
        revision,
    ))
}

// Converts DatabaseManager failures to the narrow controller-store surface.
fn controller_store_error(error: DatabaseError) -> AuthenticationStoreError {
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

// Requires one applied mutation to target the exact isolated controller collection and identity.
fn require_controller_commit(
    disposition: DatabaseCommitDisposition,
    collection: DatabaseCollection,
    identifier: &str,
    controller_id: &ControllerId,
) -> Result<(), AuthenticationStoreError> {
    if disposition != DatabaseCommitDisposition::Applied
        || collection != DatabaseCollection::Controllers
        || identifier != controller_id.as_str()
    {
        return Err(AuthenticationStoreError::Conflict);
    }
    Ok(())
}
