// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use li_core_interface::{
    CredentialId, DisplayName, InstallationId, MachineId, NetworkInterfaceName, NodeAddress,
    NodeId, NodeIdentity, PairingInviteId, Sha256Digest, UnixMilliseconds,
};
use li_database::{
    DatabaseCollection, DatabaseCommand, DatabaseError, DatabaseManager, DatabaseQuery,
    DatabaseRecord, DatabaseResult, DatabaseRevision, DatabaseTransaction,
};
use li_pairing_manager::{
    PairingCredentials, PairingEnrollmentMaterial, PairingError, PairingMembershipState,
    PairingMode, PairingOpenReplayMaterial, PairingPeerCredentialMaterial, PairingRecord,
    PairingRecordState, PairingReplayIdentity, PairingReplayOperation, PairingReplayRecord,
    PairingStore, VersionedPairingRecord,
};
use serde::{Deserialize, Serialize};

const PAIRING_RECORD_SCHEMA_NAME: &str = "li_node_pairing_record";
const PAIRING_REPLAY_SCHEMA_NAME: &str = "li_node_pairing_replay";
const PAIRING_SCHEMA_VERSION: u32 = 1;

// Stores the required nested persistence schema identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PairingSchemaDatabaseRecord {
    name: String,
    version: u32,
}

// Stores one durable PairingManager record in its dedicated database collection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PairingDatabaseRecord {
    schema: PairingSchemaDatabaseRecord,
    invite_id: String,
    main_node_id: String,
    mode: PairingModeDatabaseRecord,
    nonce: String,
    open_replay: PairingReplayIdentityDatabaseRecord,
    enrollment_replay: Option<PairingReplayIdentityDatabaseRecord>,
    approval_replay: Option<PairingReplayIdentityDatabaseRecord>,
    setup_salt: Vec<u8>,
    created_at_unix_milliseconds: u64,
    expires_at_unix_milliseconds: u64,
    attempts: u8,
    state: String,
    comparison_code: Option<Vec<u8>>,
    enrollment: Option<PairingEnrollmentDatabaseRecord>,
    credentials: Option<PairingCredentialsDatabaseRecord>,
}

impl DatabaseRecord for PairingDatabaseRecord {
    const COLLECTION: DatabaseCollection = DatabaseCollection::Pairings;

    // Returns the exact invitation identity used for indexed persistence.
    fn identifier(&self) -> &str {
        &self.invite_id
    }
}

// Stores one durable idempotency mapping separately from invitation pruning.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PairingReplayDatabaseRecord {
    schema: PairingSchemaDatabaseRecord,
    idempotency_sha256: String,
    request_sha256: String,
    operation: String,
    invite_id: String,
    open: Option<PairingOpenReplayDatabaseRecord>,
}

impl DatabaseRecord for PairingReplayDatabaseRecord {
    const COLLECTION: DatabaseCollection = DatabaseCollection::PairingReplays;

    // Returns the idempotency digest used for exact indexed replay lookup.
    fn identifier(&self) -> &str {
        &self.idempotency_sha256
    }
}

// Stores one replay identity without caller key or payload disclosure.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PairingReplayIdentityDatabaseRecord {
    idempotency_sha256: String,
    request_sha256: String,
}

// Stores non-secret open response inputs after invitation pruning.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PairingOpenReplayDatabaseRecord {
    mode: PairingModeDatabaseRecord,
    nonce: String,
    setup_salt: Vec<u8>,
    expires_at_unix_milliseconds: u64,
}

// Stores one closed pairing mode without ambiguous optional combinations.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PairingModeDatabaseRecord {
    kind: String,
    candidate_public_key: Option<String>,
    direct_interface: Option<String>,
}

// Stores the verified child and exact certificate lifecycle needed after restart.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PairingEnrollmentDatabaseRecord {
    child_node_id: String,
    child_machine_id: String,
    child_installation_id: String,
    child_name: String,
    child_address: String,
    child_public_key_fingerprint: String,
    credential_id: String,
    peer_leaf_sha256: String,
    credential_valid_from_unix_milliseconds: u64,
    credential_expires_at_unix_milliseconds: u64,
    credential_state: String,
}

// Stores only the public trust response package required for exact enrollment replay.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PairingCredentialsDatabaseRecord {
    main_public_key: Vec<u8>,
    main_ca_certificate: Vec<u8>,
    child_certificate: Vec<u8>,
    membership_signature: Vec<u8>,
    child_leaf_sha256: String,
    valid_from_unix_milliseconds: u64,
    expires_at_unix_milliseconds: u64,
}

// Persists PairingManager-owned records through the one shared DatabaseManager authority.
pub struct DatabasePairingStore {
    database: Arc<DatabaseManager>,
}

impl DatabasePairingStore {
    // Creates one adapter without opening or owning a second persistence path.
    pub const fn new(database: Arc<DatabaseManager>) -> Self {
        Self { database }
    }

    // Builds one exact pairing replacement for a larger atomic application transaction.
    pub fn replacing_transaction(
        &self,
        record: &PairingRecord,
        expected_revision: u64,
        idempotency_key: &str,
    ) -> Result<DatabaseTransaction, PairingError> {
        if expected_revision == 0 {
            return Err(PairingError::StoreCorrupt);
        }
        let replay = replacement_replay_record(record)?;
        DatabaseTransaction::new(idempotency_key)
            .and_then(|transaction| {
                transaction.save(
                    pairing_database_record(record),
                    DatabaseRevision::Exact(expected_revision),
                )
            })
            .and_then(|transaction| {
                transaction.save(
                    pairing_replay_database_record(&replay),
                    DatabaseRevision::Missing,
                )
            })
            .map_err(pairing_database_error)
    }

    // Reads one exact pairing projection and validates its indexed identity and revision.
    fn read_pairing(
        &self,
        invite_id: &PairingInviteId,
    ) -> Result<Option<VersionedPairingRecord>, PairingError> {
        match self
            .database
            .read(DatabaseQuery::<PairingDatabaseRecord>::record(
                invite_id.as_str(),
            )) {
            Ok(DatabaseResult::Record(stored)) => {
                let record = pairing_record(stored.value)?;
                if record.invite_id() != invite_id {
                    return Err(PairingError::StoreCorrupt);
                }
                VersionedPairingRecord::new(record, stored.revision).map(Some)
            }
            Ok(DatabaseResult::Records(_)) => Err(PairingError::StoreCorrupt),
            Err(DatabaseError::NotFound { .. }) => Ok(None),
            Err(error) => Err(pairing_database_error(error)),
        }
    }

    // Reads and validates one exact replay mapping by its idempotency digest.
    fn read_replay(
        &self,
        idempotency_sha256: &Sha256Digest,
    ) -> Result<Option<PairingReplayRecord>, PairingError> {
        match self
            .database
            .read(DatabaseQuery::<PairingReplayDatabaseRecord>::record(
                idempotency_sha256.as_str(),
            )) {
            Ok(DatabaseResult::Record(stored)) => {
                let replay = pairing_replay_record(stored.value)?;
                if replay.identity().idempotency_sha256() != idempotency_sha256 {
                    return Err(PairingError::StoreCorrupt);
                }
                Ok(Some(replay))
            }
            Ok(DatabaseResult::Records(_)) => Err(PairingError::StoreCorrupt),
            Err(DatabaseError::NotFound { .. }) => Ok(None),
            Err(error) => Err(pairing_database_error(error)),
        }
    }

    // Verifies one write by reconstructing the exact current record and revision.
    fn verified_write(
        &self,
        desired: &PairingRecord,
        revision: u64,
    ) -> Result<VersionedPairingRecord, PairingError> {
        let current = self
            .read_pairing(desired.invite_id())?
            .ok_or(PairingError::StoreConflict)?;
        if current.revision() != revision || current.record() != desired {
            return Err(PairingError::StoreConflict);
        }
        Ok(current)
    }
}

impl PairingStore for DatabasePairingStore {
    // Atomically creates one absent invitation and its durable open replay mapping.
    fn create(&self, record: PairingRecord) -> Result<VersionedPairingRecord, PairingError> {
        let replay = PairingReplayRecord::open(&record)?;
        let transaction = DatabaseTransaction::new(format!(
            "pairing:open:{}",
            record.open_replay().idempotency_sha256().as_str()
        ))
        .and_then(|transaction| {
            transaction.save(pairing_database_record(&record), DatabaseRevision::Missing)
        })
        .and_then(|transaction| {
            transaction.save(
                pairing_replay_database_record(&replay),
                DatabaseRevision::Missing,
            )
        })
        .map_err(pairing_database_error)?;
        let result = self
            .database
            .write_transaction(transaction)
            .map_err(pairing_database_error)?;
        let commits = result.commit().commits();
        if commits.len() != 2
            || commits[0].collection != DatabaseCollection::Pairings
            || commits[1].collection != DatabaseCollection::PairingReplays
        {
            return Err(PairingError::StoreCorrupt);
        }
        self.verified_write(&record, commits[0].revision)
    }

    // Reads one exact invitation without alternate identity lookup.
    fn pairing(
        &self,
        invite_id: &PairingInviteId,
    ) -> Result<Option<VersionedPairingRecord>, PairingError> {
        self.read_pairing(invite_id)
    }

    // Resolves one exact durable replay mapping without scanning invitation payloads.
    fn replay(
        &self,
        idempotency_sha256: &Sha256Digest,
    ) -> Result<Option<PairingReplayRecord>, PairingError> {
        self.read_replay(idempotency_sha256)
    }

    // Returns only the caller-bounded durable pairing set.
    fn pairings(
        &self,
        maximum_results: usize,
    ) -> Result<Vec<VersionedPairingRecord>, PairingError> {
        if maximum_results == 0 || maximum_results > 17 {
            return Err(PairingError::StoreCorrupt);
        }
        let stored = match self
            .database
            .read(DatabaseQuery::<PairingDatabaseRecord>::all())
            .map_err(pairing_database_error)?
        {
            DatabaseResult::Records(records) => records,
            DatabaseResult::Record(_) => return Err(PairingError::StoreCorrupt),
        };
        if stored.len() > maximum_results {
            return Err(PairingError::StoreCorrupt);
        }
        stored
            .into_iter()
            .map(|stored| {
                VersionedPairingRecord::new(pairing_record(stored.value)?, stored.revision)
            })
            .collect()
    }

    // Replaces one pairing record only at the exact observed revision.
    fn replace(
        &self,
        record: PairingRecord,
        expected_revision: u64,
    ) -> Result<VersionedPairingRecord, PairingError> {
        if expected_revision == 0 {
            return Err(PairingError::StoreCorrupt);
        }
        let result = self
            .database
            .write(DatabaseCommand::save(
                format!(
                    "pairing:replace:{}:{expected_revision}",
                    record.invite_id().as_str()
                ),
                pairing_database_record(&record),
                DatabaseRevision::Exact(expected_revision),
            ))
            .map_err(pairing_database_error)?;
        self.verified_write(&record, result.commit().revision)
    }

    // Atomically removes one failed open mutation and its exact durable replay mapping.
    fn rollback_create(
        &self,
        record: &PairingRecord,
        expected_revision: u64,
    ) -> Result<(), PairingError> {
        if expected_revision == 0 {
            return Err(PairingError::StoreCorrupt);
        }
        let transaction = DatabaseTransaction::new(format!(
            "pairing:rollback-open:{}:{expected_revision}",
            record.invite_id().as_str()
        ))
        .and_then(|transaction| {
            transaction.delete::<PairingDatabaseRecord>(
                record.invite_id().as_str(),
                DatabaseRevision::Exact(expected_revision),
            )
        })
        .and_then(|transaction| {
            transaction.delete::<PairingReplayDatabaseRecord>(
                record.open_replay().idempotency_sha256().as_str(),
                DatabaseRevision::Any,
            )
        })
        .map_err(pairing_database_error)?;
        let result = self
            .database
            .write_transaction(transaction)
            .map_err(pairing_database_error)?;
        let commits = result.commit().commits();
        if commits.len() != 2
            || commits[0].collection != DatabaseCollection::Pairings
            || commits[1].collection != DatabaseCollection::PairingReplays
        {
            return Err(PairingError::StoreCorrupt);
        }
        Ok(())
    }

    // Deletes one exact invitation without deleting another pairing identity.
    fn delete(
        &self,
        invite_id: &PairingInviteId,
        expected_revision: u64,
    ) -> Result<(), PairingError> {
        if expected_revision == 0 {
            return Err(PairingError::StoreCorrupt);
        }
        self.database
            .write(DatabaseCommand::<PairingDatabaseRecord>::delete(
                format!("pairing:delete:{}:{expected_revision}", invite_id.as_str()),
                invite_id.as_str(),
                DatabaseRevision::Exact(expected_revision),
            ))
            .map_err(pairing_database_error)?;
        Ok(())
    }
}

// Projects one validated PairingManager record into the closed database schema.
pub(crate) fn pairing_database_record(record: &PairingRecord) -> PairingDatabaseRecord {
    PairingDatabaseRecord {
        schema: schema(PAIRING_RECORD_SCHEMA_NAME),
        invite_id: record.invite_id().as_str().to_string(),
        main_node_id: record.main_node_id().as_str().to_string(),
        mode: pairing_mode_database_record(record.mode()),
        nonce: record.nonce().as_str().to_string(),
        open_replay: pairing_replay_identity_database_record(record.open_replay()),
        enrollment_replay: record
            .enrollment_replay()
            .map(pairing_replay_identity_database_record),
        approval_replay: record
            .approval_replay()
            .map(pairing_replay_identity_database_record),
        setup_salt: record.setup_salt().to_vec(),
        created_at_unix_milliseconds: record.created_at().value(),
        expires_at_unix_milliseconds: record.expires_at().value(),
        attempts: record.attempts(),
        state: pairing_state_name(record.state()).to_string(),
        comparison_code: record.comparison_code_bytes().map(|value| value.to_vec()),
        enrollment: record.enrollment().map(pairing_enrollment_database_record),
        credentials: record
            .credentials()
            .map(pairing_credentials_database_record),
    }
}

// Projects one replay mapping into its strict dedicated persistence schema.
fn pairing_replay_database_record(replay: &PairingReplayRecord) -> PairingReplayDatabaseRecord {
    PairingReplayDatabaseRecord {
        schema: schema(PAIRING_REPLAY_SCHEMA_NAME),
        idempotency_sha256: replay.identity().idempotency_sha256().as_str().to_string(),
        request_sha256: replay.identity().request_sha256().as_str().to_string(),
        operation: pairing_replay_operation_name(replay.operation_kind()).to_string(),
        invite_id: replay.invite_id().as_str().to_string(),
        open: replay
            .open_material()
            .map(|material| PairingOpenReplayDatabaseRecord {
                mode: pairing_mode_database_record(material.mode()),
                nonce: material.nonce().as_str().to_string(),
                setup_salt: material.salt().to_vec(),
                expires_at_unix_milliseconds: material.expires_at().value(),
            }),
    }
}

// Projects one replay identity without retaining its caller-supplied key.
fn pairing_replay_identity_database_record(
    replay: &PairingReplayIdentity,
) -> PairingReplayIdentityDatabaseRecord {
    PairingReplayIdentityDatabaseRecord {
        idempotency_sha256: replay.idempotency_sha256().as_str().to_string(),
        request_sha256: replay.request_sha256().as_str().to_string(),
    }
}

// Projects the issued public response package without any private trust material.
fn pairing_credentials_database_record(
    credentials: &PairingCredentials,
) -> PairingCredentialsDatabaseRecord {
    PairingCredentialsDatabaseRecord {
        main_public_key: credentials.site_public_key().to_vec(),
        main_ca_certificate: credentials.site_ca_certificate().to_vec(),
        child_certificate: credentials.member_certificate().to_vec(),
        membership_signature: credentials.membership_signature().to_vec(),
        child_leaf_sha256: credentials.member_leaf_sha256().as_str().to_string(),
        valid_from_unix_milliseconds: credentials.member_valid_from().value(),
        expires_at_unix_milliseconds: credentials.member_expires_at().value(),
    }
}

// Projects one closed pairing mode into primitive persistence fields.
fn pairing_mode_database_record(mode: &PairingMode) -> PairingModeDatabaseRecord {
    match mode {
        PairingMode::Lan => PairingModeDatabaseRecord {
            kind: "lan".to_string(),
            candidate_public_key: None,
            direct_interface: None,
        },
        PairingMode::Remote => PairingModeDatabaseRecord {
            kind: "remote".to_string(),
            candidate_public_key: None,
            direct_interface: None,
        },
        PairingMode::ConnectX {
            candidate_public_key,
            direct_interface,
        } => PairingModeDatabaseRecord {
            kind: "connectx".to_string(),
            candidate_public_key: Some(candidate_public_key.as_str().to_string()),
            direct_interface: Some(direct_interface.as_str().to_string()),
        },
    }
}

// Projects verified child enrollment and certificate facts into persistence.
fn pairing_enrollment_database_record(
    enrollment: &PairingEnrollmentMaterial,
) -> PairingEnrollmentDatabaseRecord {
    PairingEnrollmentDatabaseRecord {
        child_node_id: enrollment.child_identity().node_id().as_str().to_string(),
        child_machine_id: enrollment
            .child_identity()
            .machine_id()
            .as_str()
            .to_string(),
        child_installation_id: enrollment
            .child_identity()
            .installation_id()
            .as_str()
            .to_string(),
        child_name: enrollment.child_name().as_str().to_string(),
        child_address: enrollment.child_address().as_str().to_string(),
        child_public_key_fingerprint: enrollment
            .child_public_key_fingerprint()
            .as_str()
            .to_string(),
        credential_id: enrollment
            .peer_credential()
            .credential_id()
            .as_str()
            .to_string(),
        peer_leaf_sha256: enrollment
            .peer_credential()
            .peer_leaf_sha256()
            .as_str()
            .to_string(),
        credential_valid_from_unix_milliseconds: enrollment.peer_credential().valid_from().value(),
        credential_expires_at_unix_milliseconds: enrollment.peer_credential().expires_at().value(),
        credential_state: pairing_membership_state_name(enrollment.peer_credential().state())
            .to_string(),
    }
}

// Reconstructs one closed durable pairing record without silent defaults.
fn pairing_record(record: PairingDatabaseRecord) -> Result<PairingRecord, PairingError> {
    require_schema(&record.schema, PAIRING_RECORD_SCHEMA_NAME)?;
    let salt: [u8; 16] = record
        .setup_salt
        .try_into()
        .map_err(|_| PairingError::StoreCorrupt)?;
    let comparison_code = record
        .comparison_code
        .map(|value| value.try_into().map_err(|_| PairingError::StoreCorrupt))
        .transpose()?;
    PairingRecord::restore(
        NodeId::parse(&record.main_node_id).map_err(|_| PairingError::StoreCorrupt)?,
        PairingInviteId::parse(&record.invite_id).map_err(|_| PairingError::StoreCorrupt)?,
        pairing_mode(record.mode)?,
        Sha256Digest::parse(&record.nonce).map_err(|_| PairingError::StoreCorrupt)?,
        pairing_replay_identity(record.open_replay)?,
        record
            .enrollment_replay
            .map(pairing_replay_identity)
            .transpose()?,
        record
            .approval_replay
            .map(pairing_replay_identity)
            .transpose()?,
        salt,
        UnixMilliseconds::new(record.created_at_unix_milliseconds),
        UnixMilliseconds::new(record.expires_at_unix_milliseconds),
        record.attempts,
        pairing_state(&record.state)?,
        comparison_code,
        record.enrollment.map(pairing_enrollment).transpose()?,
        record.credentials.map(pairing_credentials).transpose()?,
    )
}

// Reconstructs and validates one dedicated replay mapping with exact schema identity.
fn pairing_replay_record(
    record: PairingReplayDatabaseRecord,
) -> Result<PairingReplayRecord, PairingError> {
    require_schema(&record.schema, PAIRING_REPLAY_SCHEMA_NAME)?;
    let identity = PairingReplayIdentity::new(
        Sha256Digest::parse(&record.idempotency_sha256).map_err(|_| PairingError::StoreCorrupt)?,
        Sha256Digest::parse(&record.request_sha256).map_err(|_| PairingError::StoreCorrupt)?,
    );
    let invite_id =
        PairingInviteId::parse(&record.invite_id).map_err(|_| PairingError::StoreCorrupt)?;
    let operation = pairing_replay_operation(&record.operation)?;
    match (operation, record.open) {
        (PairingReplayOperation::Open, Some(open)) => {
            let salt: [u8; 16] = open
                .setup_salt
                .try_into()
                .map_err(|_| PairingError::StoreCorrupt)?;
            PairingReplayRecord::restore_open(
                identity,
                invite_id,
                PairingOpenReplayMaterial::new(
                    pairing_mode(open.mode)?,
                    Sha256Digest::parse(&open.nonce).map_err(|_| PairingError::StoreCorrupt)?,
                    salt,
                    UnixMilliseconds::new(open.expires_at_unix_milliseconds),
                ),
            )
        }
        (PairingReplayOperation::Enroll | PairingReplayOperation::Approve, None) => {
            PairingReplayRecord::operation(identity, operation, invite_id)
        }
        _ => Err(PairingError::StoreCorrupt),
    }
}

// Reconstructs one replay identity from exact canonical digests.
fn pairing_replay_identity(
    record: PairingReplayIdentityDatabaseRecord,
) -> Result<PairingReplayIdentity, PairingError> {
    Ok(PairingReplayIdentity::new(
        Sha256Digest::parse(&record.idempotency_sha256).map_err(|_| PairingError::StoreCorrupt)?,
        Sha256Digest::parse(&record.request_sha256).map_err(|_| PairingError::StoreCorrupt)?,
    ))
}

// Reconstructs one exact issued public credential response package.
fn pairing_credentials(
    record: PairingCredentialsDatabaseRecord,
) -> Result<PairingCredentials, PairingError> {
    PairingCredentials::new(
        record.main_public_key,
        record.main_ca_certificate,
        record.child_certificate,
        record.membership_signature,
        Sha256Digest::parse(&record.child_leaf_sha256).map_err(|_| PairingError::StoreCorrupt)?,
        UnixMilliseconds::new(record.valid_from_unix_milliseconds),
        UnixMilliseconds::new(record.expires_at_unix_milliseconds),
    )
}

// Reconstructs one exact closed pairing mode.
fn pairing_mode(record: PairingModeDatabaseRecord) -> Result<PairingMode, PairingError> {
    match (
        record.kind.as_str(),
        record.candidate_public_key,
        record.direct_interface,
    ) {
        ("lan", None, None) => Ok(PairingMode::Lan),
        ("remote", None, None) => Ok(PairingMode::Remote),
        ("connectx", Some(fingerprint), Some(interface)) => Ok(PairingMode::ConnectX {
            candidate_public_key: Sha256Digest::parse(&fingerprint)
                .map_err(|_| PairingError::StoreCorrupt)?,
            direct_interface: NetworkInterfaceName::parse(&interface)
                .map_err(|_| PairingError::StoreCorrupt)?,
        }),
        _ => Err(PairingError::StoreCorrupt),
    }
}

// Reconstructs exact child enrollment and certificate lifecycle facts.
fn pairing_enrollment(
    record: PairingEnrollmentDatabaseRecord,
) -> Result<PairingEnrollmentMaterial, PairingError> {
    Ok(PairingEnrollmentMaterial::new(
        NodeIdentity::new(
            NodeId::parse(&record.child_node_id).map_err(|_| PairingError::StoreCorrupt)?,
            MachineId::parse(&record.child_machine_id).map_err(|_| PairingError::StoreCorrupt)?,
            InstallationId::parse(&record.child_installation_id)
                .map_err(|_| PairingError::StoreCorrupt)?,
        ),
        DisplayName::parse(&record.child_name).map_err(|_| PairingError::StoreCorrupt)?,
        NodeAddress::parse(&record.child_address).map_err(|_| PairingError::StoreCorrupt)?,
        Sha256Digest::parse(&record.child_public_key_fingerprint)
            .map_err(|_| PairingError::StoreCorrupt)?,
        PairingPeerCredentialMaterial::new(
            CredentialId::parse(&record.credential_id).map_err(|_| PairingError::StoreCorrupt)?,
            Sha256Digest::parse(&record.peer_leaf_sha256)
                .map_err(|_| PairingError::StoreCorrupt)?,
            UnixMilliseconds::new(record.credential_valid_from_unix_milliseconds),
            UnixMilliseconds::new(record.credential_expires_at_unix_milliseconds),
            pairing_membership_state(&record.credential_state)?,
        )?,
    ))
}

// Returns the closed database name for one pairing record state.
fn pairing_state_name(state: PairingRecordState) -> &'static str {
    match state {
        PairingRecordState::Open => "open",
        PairingRecordState::PendingApproval => "pending_approval",
        PairingRecordState::Active => "active",
    }
}

// Reconstructs one closed pairing state without compatibility fallbacks.
fn pairing_state(value: &str) -> Result<PairingRecordState, PairingError> {
    match value {
        "open" => Ok(PairingRecordState::Open),
        "pending_approval" => Ok(PairingRecordState::PendingApproval),
        "active" => Ok(PairingRecordState::Active),
        _ => Err(PairingError::StoreCorrupt),
    }
}

// Returns the closed database name for one membership approval state.
fn pairing_membership_state_name(state: PairingMembershipState) -> &'static str {
    match state {
        PairingMembershipState::PendingApproval => "pending_approval",
        PairingMembershipState::Active => "active",
    }
}

// Reconstructs one exact membership approval state.
fn pairing_membership_state(value: &str) -> Result<PairingMembershipState, PairingError> {
    match value {
        "pending_approval" => Ok(PairingMembershipState::PendingApproval),
        "active" => Ok(PairingMembershipState::Active),
        _ => Err(PairingError::StoreCorrupt),
    }
}

// Selects the new replay mapping that must join one pairing replacement atomically.
fn replacement_replay_record(record: &PairingRecord) -> Result<PairingReplayRecord, PairingError> {
    if let Some(replay) = record.approval_replay() {
        return PairingReplayRecord::operation(
            replay.clone(),
            PairingReplayOperation::Approve,
            record.invite_id().clone(),
        );
    }
    let replay = record
        .enrollment_replay()
        .ok_or(PairingError::StoreCorrupt)?;
    PairingReplayRecord::operation(
        replay.clone(),
        PairingReplayOperation::Enroll,
        record.invite_id().clone(),
    )
}

// Creates one nested schema identity using the repository-wide name/version convention.
fn schema(name: &str) -> PairingSchemaDatabaseRecord {
    PairingSchemaDatabaseRecord {
        name: name.to_string(),
        version: PAIRING_SCHEMA_VERSION,
    }
}

// Refuses every unsupported pairing persistence schema without migration fallback.
fn require_schema(
    observed: &PairingSchemaDatabaseRecord,
    expected_name: &str,
) -> Result<(), PairingError> {
    if observed.name != expected_name || observed.version != PAIRING_SCHEMA_VERSION {
        return Err(PairingError::StoreCorrupt);
    }
    Ok(())
}

// Returns the closed persistence name for one replay operation.
fn pairing_replay_operation_name(operation: PairingReplayOperation) -> &'static str {
    match operation {
        PairingReplayOperation::Open => "open",
        PairingReplayOperation::Enroll => "enroll",
        PairingReplayOperation::Approve => "approve",
    }
}

// Reconstructs one replay operation without compatibility aliases.
fn pairing_replay_operation(value: &str) -> Result<PairingReplayOperation, PairingError> {
    match value {
        "open" => Ok(PairingReplayOperation::Open),
        "enroll" => Ok(PairingReplayOperation::Enroll),
        "approve" => Ok(PairingReplayOperation::Approve),
        _ => Err(PairingError::StoreCorrupt),
    }
}

// Collapses database outcomes into PairingManager's fixed redacted persistence surface.
fn pairing_database_error(error: DatabaseError) -> PairingError {
    match error {
        DatabaseError::Conflict { .. } | DatabaseError::IdempotencyConflict { .. } => {
            PairingError::StoreConflict
        }
        DatabaseError::Corrupt { .. } => PairingError::StoreCorrupt,
        DatabaseError::NotFound { .. }
        | DatabaseError::InvalidInput { .. }
        | DatabaseError::Unavailable { .. }
        | DatabaseError::Closed => PairingError::StoreUnavailable,
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use li_database::{DatabaseConfiguration, DatabaseRevision};

    use super::*;

    // Returns one repeated canonical SHA-256 fixture.
    fn digest(character: char) -> Sha256Digest {
        Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
    }

    // Returns one ordinary open record whose setup code exists only as derivable material.
    fn open_record() -> PairingRecord {
        PairingRecord::open(
            NodeId::parse(&"1".repeat(32)).expect("main node"),
            PairingInviteId::parse(&"2".repeat(32)).expect("invitation"),
            PairingMode::Lan,
            digest('3'),
            PairingReplayIdentity::new(digest('4'), digest('5')),
            [0x06; 16],
            UnixMilliseconds::new(1_000),
            UnixMilliseconds::new(181_000),
        )
        .expect("open record")
    }

    // Opens one deterministic temporary database at the supplied exact path.
    fn database(path: &Path) -> Arc<DatabaseManager> {
        Arc::new(
            DatabaseManager::open(DatabaseConfiguration::new(path.to_path_buf()))
                .expect("database"),
        )
    }

    // Proves restart reconstruction and publish-failure rollback cover pairing and replay together.
    #[test]
    fn durable_open_reconstructs_after_restart_and_rolls_back_atomically() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("core.sqlite3");
        let record = open_record();
        {
            let manager = database(&path);
            let store = DatabasePairingStore::new(manager);
            let stored = store.create(record.clone()).expect("create");
            assert_eq!(stored.record(), &record);
        }
        {
            let manager = database(&path);
            let store = DatabasePairingStore::new(manager);
            assert_eq!(
                store
                    .pairing(record.invite_id())
                    .expect("restart pairing")
                    .expect("persisted pairing")
                    .record(),
                &record
            );
            assert_eq!(
                store
                    .replay(record.open_replay().idempotency_sha256())
                    .expect("restart replay")
                    .expect("persisted replay")
                    .invite_id(),
                record.invite_id()
            );
            let revision = store
                .pairing(record.invite_id())
                .expect("pairing")
                .expect("record")
                .revision();
            store
                .rollback_create(&record, revision)
                .expect("rollback create");
            assert!(store
                .pairing(record.invite_id())
                .expect("rolled back pairing")
                .is_none());
            assert!(store
                .replay(record.open_replay().idempotency_sha256())
                .expect("rolled back replay")
                .is_none());
        }
    }

    // Proves a late replay collision rolls back the earlier staged invitation mutation.
    #[test]
    fn replay_collision_never_leaves_a_partial_invitation() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let manager = database(&directory.path().join("core.sqlite3"));
        let store = DatabasePairingStore::new(manager.clone());
        let record = open_record();
        let replay = PairingReplayRecord::open(&record).expect("replay");
        manager
            .write(DatabaseCommand::save(
                "seed-replay-collision",
                pairing_replay_database_record(&replay),
                DatabaseRevision::Missing,
            ))
            .expect("seed collision");

        assert!(matches!(
            store.create(record.clone()),
            Err(PairingError::StoreConflict)
        ));
        assert!(store
            .pairing(record.invite_id())
            .expect("partial pairing lookup")
            .is_none());
    }

    // Rejects structural, schema, and semantic corruption without retaining plaintext setup codes.
    #[test]
    fn persisted_pairing_documents_are_closed_versioned_and_secret_free() {
        let record = open_record();
        let pairing_value =
            serde_json::to_value(pairing_database_record(&record)).expect("pairing JSON");
        let replay_value = serde_json::to_value(pairing_replay_database_record(
            &PairingReplayRecord::open(&record).expect("replay"),
        ))
        .expect("replay JSON");
        let serialized = format!("{pairing_value}{replay_value}");
        assert!(!serialized.contains("12345678"));
        assert!(!serialized.contains("setup_code"));

        let mut unsupported_pairing = pairing_value.clone();
        unsupported_pairing["schema"]["version"] = serde_json::json!(2);
        let unsupported_pairing: PairingDatabaseRecord =
            serde_json::from_value(unsupported_pairing).expect("structural pairing");
        assert_eq!(
            pairing_record(unsupported_pairing),
            Err(PairingError::StoreCorrupt)
        );
        let mut unsupported_replay = replay_value.clone();
        unsupported_replay["schema"]["name"] = serde_json::json!("other");
        let unsupported_replay: PairingReplayDatabaseRecord =
            serde_json::from_value(unsupported_replay).expect("structural replay");
        assert_eq!(
            pairing_replay_record(unsupported_replay),
            Err(PairingError::StoreCorrupt)
        );

        let mut short_salt = pairing_value.clone();
        short_salt["setup_salt"] = serde_json::json!([1, 2, 3]);
        let short_salt: PairingDatabaseRecord =
            serde_json::from_value(short_salt).expect("structural salt");
        assert_eq!(pairing_record(short_salt), Err(PairingError::StoreCorrupt));
        let mut unknown = pairing_value;
        unknown["unknown"] = serde_json::json!(true);
        assert!(serde_json::from_value::<PairingDatabaseRecord>(unknown).is_err());

        let pairing_schema: serde_json::Value = serde_json::from_str(include_str!(
            "../../../schemas/node/li_node_pairing_record_v1.schema.json"
        ))
        .expect("pairing schema");
        let replay_schema: serde_json::Value = serde_json::from_str(include_str!(
            "../../../schemas/node/li_node_pairing_replay_v1.schema.json"
        ))
        .expect("replay schema");
        assert_eq!(
            pairing_schema["properties"]["schema"]["properties"]["name"]["const"],
            PAIRING_RECORD_SCHEMA_NAME
        );
        assert_eq!(
            replay_schema["properties"]["schema"]["properties"]["name"]["const"],
            PAIRING_REPLAY_SCHEMA_NAME
        );
    }
}
