// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use li_core_interface::Sha256Digest;
use li_core_update_manager::{
    CoreInstallation, CoreUpdateNodeRole, CoreUpdateServiceContext, CoreUpdateServicePlatform,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    CoreServiceCutoverBegin, CoreServiceCutoverProvider, CoreServiceCutoverReceipt,
    CoreServiceCutoverRecovery, CoreServiceDefinition, CoreServiceSetupError,
};

const MAXIMUM_NATIVE_SNAPSHOT_BYTES: usize = 1024 * 1024;
const SERVICE_CUTOVER_SCHEMA_NAME: &str = "li_core_service_cutover";
const SERVICE_CUTOVER_SCHEMA_VERSION: u32 = 1;

// Carries the nested JSON schema identity required by every cutover record.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredSchemaIdentity {
    name: String,
    version: u32,
}

// Carries one immutable installation identity in the durable JSON record.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredInstallation {
    version: String,
    source_identity: String,
}

// Carries one exact expected service-definition identity in the durable JSON record.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredDefinitionIdentity {
    service_identity: String,
    sha256: String,
}

// Carries one opaque native snapshot and its independently verified identity.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredNativeSnapshot {
    bytes_base64: String,
    sha256: String,
}

// Defines the closed JSON representation persisted by the system cutover store.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredServiceCutoverRecord {
    schema: StoredSchemaIdentity,
    request_id: String,
    receipt_id: String,
    platform: String,
    role: String,
    phase: String,
    installation: StoredInstallation,
    definitions: Vec<StoredDefinitionIdentity>,
    native_snapshot: StoredNativeSnapshot,
}

// Carries one bounded content-addressed native snapshot without exposing platform fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreServiceCutoverNativeSnapshot {
    bytes: Vec<u8>,
    sha256: Sha256Digest,
}

impl CoreServiceCutoverNativeSnapshot {
    // Creates one opaque native snapshot after enforcing its storage bound.
    pub fn new(bytes: Vec<u8>) -> Result<Self, CoreServiceSetupError> {
        if bytes.is_empty() || bytes.len() > MAXIMUM_NATIVE_SNAPSHOT_BYTES {
            return Err(CoreServiceSetupError::InvalidContract {
                reason: "native service snapshot is invalid",
            });
        }
        let sha256 = digest(&bytes)?;
        Ok(Self { bytes, sha256 })
    }

    // Returns the exact native snapshot bytes owned by the platform adapter.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    // Returns the content identity bound into the durable cutover receipt.
    pub const fn sha256(&self) -> &Sha256Digest {
        &self.sha256
    }
}

// Identifies the exact durable phase of one crash-replayable service cutover.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreServiceCutoverPhase {
    Prepared,
    Restoring,
    Restored,
    Committed,
}

// Stores one expected replacement definition identity without retaining its executable path.
#[derive(Clone, Debug, Eq, PartialEq)]
struct CoreServiceCutoverDefinitionIdentity {
    service_identity: String,
    sha256: Sha256Digest,
}

// Binds one crash-replayable native snapshot to the exact requested replacement set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreServiceCutoverRecord {
    request_id: Sha256Digest,
    receipt_id: Sha256Digest,
    context: CoreUpdateServiceContext,
    installation: CoreInstallation,
    definitions: Vec<CoreServiceCutoverDefinitionIdentity>,
    native_snapshot: CoreServiceCutoverNativeSnapshot,
    phase: CoreServiceCutoverPhase,
}

impl CoreServiceCutoverRecord {
    // Creates one prepared record whose receipt binds the request and exact native snapshot.
    pub fn new(
        context: CoreUpdateServiceContext,
        installation: CoreInstallation,
        definitions: &[CoreServiceDefinition],
        native_snapshot: CoreServiceCutoverNativeSnapshot,
    ) -> Result<Self, CoreServiceSetupError> {
        validate_definition_set(context, definitions)?;
        let definitions = definitions
            .iter()
            .map(|definition| CoreServiceCutoverDefinitionIdentity {
                service_identity: definition.service_identity().to_string(),
                sha256: definition.sha256().clone(),
            })
            .collect::<Vec<_>>();
        let request_id = request_identity(context, &installation, &definitions)?;
        let receipt_id = receipt_identity(&request_id, native_snapshot.sha256())?;
        Ok(Self {
            request_id,
            receipt_id,
            context,
            installation,
            definitions,
            native_snapshot,
            phase: CoreServiceCutoverPhase::Prepared,
        })
    }

    // Returns the exact replacement request identity used for replay conflict detection.
    pub const fn request_id(&self) -> &Sha256Digest {
        &self.request_id
    }

    // Returns the opaque receipt required for commit or restoration.
    pub const fn receipt_id(&self) -> &Sha256Digest {
        &self.receipt_id
    }

    // Returns the immutable platform and local role captured before mutation.
    pub const fn context(&self) -> CoreUpdateServiceContext {
        self.context
    }

    // Returns the exact Core installation requested by this cutover.
    pub const fn installation(&self) -> &CoreInstallation {
        &self.installation
    }

    // Returns the opaque native snapshot required for retirement or restoration.
    pub const fn native_snapshot(&self) -> &CoreServiceCutoverNativeSnapshot {
        &self.native_snapshot
    }

    // Returns whether this record still authorizes restoration or records final commit.
    pub const fn phase(&self) -> CoreServiceCutoverPhase {
        self.phase
    }

    // Returns one expected valid successor without changing any receipt-bound input.
    pub fn transitioned(
        &self,
        expected: CoreServiceCutoverPhase,
        next: CoreServiceCutoverPhase,
    ) -> Result<Self, CoreServiceSetupError> {
        if self.phase != expected || !is_valid_phase_transition(expected, next) {
            return Err(CoreServiceSetupError::InvalidContract {
                reason: "service cutover phase transition is invalid",
            });
        }
        let mut record = self.clone();
        record.phase = next;
        Ok(record)
    }

    // Recomputes all identities before trusting a value returned by durable storage.
    pub fn validate(&self) -> Result<(), CoreServiceSetupError> {
        validate_definition_identities(self.context, &self.definitions)?;
        let native_identity = digest(self.native_snapshot.bytes())?;
        let request_identity =
            request_identity(self.context, &self.installation, &self.definitions)?;
        let receipt_identity = receipt_identity(&request_identity, &native_identity)?;
        if native_identity != *self.native_snapshot.sha256()
            || request_identity != self.request_id
            || receipt_identity != self.receipt_id
        {
            return Err(CoreServiceSetupError::InvalidContract {
                reason: "service cutover record identity is invalid",
            });
        }
        Ok(())
    }

    // Encodes one validated record as the canonical closed JSON persistence document.
    pub fn encoded_json(&self) -> Result<Vec<u8>, CoreServiceSetupError> {
        self.validate()?;
        let stored = StoredServiceCutoverRecord {
            schema: StoredSchemaIdentity {
                name: SERVICE_CUTOVER_SCHEMA_NAME.to_string(),
                version: SERVICE_CUTOVER_SCHEMA_VERSION,
            },
            request_id: self.request_id.as_str().to_string(),
            receipt_id: self.receipt_id.as_str().to_string(),
            platform: platform_text(self.context.platform()).to_string(),
            role: role_text(self.context.role()).to_string(),
            phase: phase_text(self.phase).to_string(),
            installation: StoredInstallation {
                version: self.installation.version().as_str().to_string(),
                source_identity: self.installation.source_identity().as_str().to_string(),
            },
            definitions: self
                .definitions
                .iter()
                .map(|definition| StoredDefinitionIdentity {
                    service_identity: definition.service_identity.clone(),
                    sha256: definition.sha256.as_str().to_string(),
                })
                .collect(),
            native_snapshot: StoredNativeSnapshot {
                bytes_base64: BASE64.encode(self.native_snapshot.bytes()),
                sha256: self.native_snapshot.sha256().as_str().to_string(),
            },
        };
        let mut bytes = serde_json::to_vec_pretty(&stored).map_err(|_| {
            CoreServiceSetupError::InvalidContract {
                reason: "service cutover record could not be encoded",
            }
        })?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    // Decodes one closed JSON document and recomputes every receipt-bound identity.
    pub fn decode_json(bytes: &[u8]) -> Result<Self, CoreServiceSetupError> {
        let stored: StoredServiceCutoverRecord =
            serde_json::from_slice(bytes).map_err(|_| CoreServiceSetupError::InvalidContract {
                reason: "service cutover record is malformed",
            })?;
        if stored.schema.name != SERVICE_CUTOVER_SCHEMA_NAME
            || stored.schema.version != SERVICE_CUTOVER_SCHEMA_VERSION
        {
            return Err(CoreServiceSetupError::InvalidContract {
                reason: "service cutover record schema is unsupported",
            });
        }
        let context = CoreUpdateServiceContext::new(
            parse_platform(&stored.platform)?,
            parse_role(&stored.role)?,
        );
        let installation = CoreInstallation::new(
            li_core_update_manager::CoreVersion::parse(&stored.installation.version).map_err(
                |_| CoreServiceSetupError::InvalidContract {
                    reason: "service cutover installation is invalid",
                },
            )?,
            parse_digest(&stored.installation.source_identity)?,
        );
        let definitions = stored
            .definitions
            .into_iter()
            .map(|definition| {
                Ok(CoreServiceCutoverDefinitionIdentity {
                    service_identity: definition.service_identity,
                    sha256: parse_digest(&definition.sha256)?,
                })
            })
            .collect::<Result<Vec<_>, CoreServiceSetupError>>()?;
        let snapshot_bytes = BASE64
            .decode(stored.native_snapshot.bytes_base64.as_bytes())
            .map_err(|_| CoreServiceSetupError::InvalidContract {
                reason: "service cutover native snapshot encoding is invalid",
            })?;
        if BASE64.encode(&snapshot_bytes) != stored.native_snapshot.bytes_base64 {
            return Err(CoreServiceSetupError::InvalidContract {
                reason: "service cutover native snapshot encoding is noncanonical",
            });
        }
        let native_snapshot = CoreServiceCutoverNativeSnapshot {
            bytes: snapshot_bytes,
            sha256: parse_digest(&stored.native_snapshot.sha256)?,
        };
        let record = Self {
            request_id: parse_digest(&stored.request_id)?,
            receipt_id: parse_digest(&stored.receipt_id)?,
            context,
            installation,
            definitions,
            native_snapshot,
            phase: parse_phase(&stored.phase)?,
        };
        record.validate()?;
        Ok(record)
    }

    // Tests whether a replay request is exactly the one bound to this record.
    fn matches_request(
        &self,
        context: CoreUpdateServiceContext,
        installation: &CoreInstallation,
        definitions: &[CoreServiceDefinition],
    ) -> Result<bool, CoreServiceSetupError> {
        validate_definition_set(context, definitions)?;
        let identities = definitions
            .iter()
            .map(|definition| CoreServiceCutoverDefinitionIdentity {
                service_identity: definition.service_identity().to_string(),
                sha256: definition.sha256().clone(),
            })
            .collect::<Vec<_>>();
        Ok(self.request_id == request_identity(context, installation, &identities)?)
    }
}

// Persists one authoritative active or last-committed cutover record.
pub trait CoreServiceCutoverStore: Send + Sync {
    // Reads the optional authoritative record without mutating it.
    fn read(&self) -> Result<Option<CoreServiceCutoverRecord>, CoreServiceSetupError>;

    // Creates a prepared record once and returns the authoritative stored value.
    fn create(
        &self,
        record: CoreServiceCutoverRecord,
    ) -> Result<CoreServiceCutoverRecord, CoreServiceSetupError>;

    // Atomically applies one exact expected phase transition and returns the durable value.
    fn transition(
        &self,
        receipt: &CoreServiceCutoverReceipt,
        expected: CoreServiceCutoverPhase,
        next: CoreServiceCutoverPhase,
    ) -> Result<CoreServiceCutoverRecord, CoreServiceSetupError>;

    // Removes only the exact record whose receipt is supplied.
    fn remove(&self, receipt: &CoreServiceCutoverReceipt) -> Result<(), CoreServiceSetupError>;
}

// Owns exact platform observation, retirement, and restoration mechanics.
pub trait CoreServiceCutoverNativeHost: Send + Sync {
    // Captures every current Rust-native definition and activity state.
    fn snapshot(
        &self,
        context: CoreUpdateServiceContext,
    ) -> Result<CoreServiceCutoverNativeSnapshot, CoreServiceSetupError>;

    // Retires a newly stored snapshot only after an exact pre-mutation compare-and-swap.
    fn retire(
        &self,
        snapshot: &CoreServiceCutoverNativeSnapshot,
    ) -> Result<(), CoreServiceSetupError>;

    // Resumes only an exact or provably monotonic partial retirement of one durable snapshot.
    fn resume_retirement(
        &self,
        snapshot: &CoreServiceCutoverNativeSnapshot,
    ) -> Result<(), CoreServiceSetupError>;

    // Restores exact definitions/enablement while keeping prior inactive or failed units stopped.
    fn restore(
        &self,
        snapshot: &CoreServiceCutoverNativeSnapshot,
    ) -> Result<(), CoreServiceSetupError>;
}

// Coordinates durable crash replay while a native host owns platform-specific mechanics.
pub struct DurableCoreServiceCutoverProvider {
    store: Arc<dyn CoreServiceCutoverStore>,
    host: Arc<dyn CoreServiceCutoverNativeHost>,
}

impl DurableCoreServiceCutoverProvider {
    // Creates one cutover provider from explicit persistence and native capabilities.
    pub fn new(
        store: Arc<dyn CoreServiceCutoverStore>,
        host: Arc<dyn CoreServiceCutoverNativeHost>,
    ) -> Self {
        Self { store, host }
    }

    // Loads and validates the exact receipt-bound durable record.
    fn required_record(
        &self,
        receipt: &CoreServiceCutoverReceipt,
    ) -> Result<CoreServiceCutoverRecord, CoreServiceSetupError> {
        let record = self
            .store
            .read()?
            .ok_or(CoreServiceSetupError::InvalidContract {
                reason: "service cutover record is unavailable",
            })?;
        record.validate()?;
        if record.receipt_id() != receipt.receipt_id() {
            return Err(CoreServiceSetupError::InvalidContract {
                reason: "service cutover receipt does not match durable state",
            });
        }
        Ok(record)
    }

    // Applies one exact durable transition and verifies the complete returned record.
    fn transition_record(
        &self,
        record: &CoreServiceCutoverRecord,
        expected: CoreServiceCutoverPhase,
        next: CoreServiceCutoverPhase,
    ) -> Result<CoreServiceCutoverRecord, CoreServiceSetupError> {
        let receipt = CoreServiceCutoverReceipt::new(record.receipt_id().clone());
        let transitioned = self.store.transition(&receipt, expected, next)?;
        transitioned.validate()?;
        if transitioned != record.transitioned(expected, next)? {
            return Err(CoreServiceSetupError::RecoveryRequired {
                reason: "service cutover transition returned conflicting state",
            });
        }
        Ok(transitioned)
    }

    // Completes one prepared or interrupted restoration and clears its durable checkpoint.
    fn restore_record(
        &self,
        record: CoreServiceCutoverRecord,
    ) -> Result<(), CoreServiceSetupError> {
        let recovery = match record.phase() {
            CoreServiceCutoverPhase::Prepared => self.transition_record(
                &record,
                CoreServiceCutoverPhase::Prepared,
                CoreServiceCutoverPhase::Restoring,
            )?,
            CoreServiceCutoverPhase::Restoring => record,
            CoreServiceCutoverPhase::Restored => record,
            CoreServiceCutoverPhase::Committed => {
                return Err(CoreServiceSetupError::InvalidContract {
                    reason: "a committed service cutover cannot be restored",
                })
            }
        };
        let restored = if recovery.phase() == CoreServiceCutoverPhase::Restored {
            recovery
        } else {
            self.host.restore(recovery.native_snapshot())?;
            self.transition_record(
                &recovery,
                CoreServiceCutoverPhase::Restoring,
                CoreServiceCutoverPhase::Restored,
            )
            .map_err(|_| CoreServiceSetupError::RecoveryRequired {
                reason: "restored service cutover phase could not be persisted",
            })?
        };
        let receipt = CoreServiceCutoverReceipt::new(restored.receipt_id().clone());
        self.store
            .remove(&receipt)
            .map_err(|_| CoreServiceSetupError::RecoveryRequired {
                reason: "restored service cutover record could not be cleared",
            })
    }

    // Restores one prepared snapshot after retirement failed and retains safe replay state.
    fn compensate_failed_retirement(
        &self,
        record: &CoreServiceCutoverRecord,
    ) -> Result<(), CoreServiceSetupError> {
        if self.restore_record(record.clone()).is_err() {
            return Err(CoreServiceSetupError::RecoveryRequired {
                reason: "native service retirement could not be restored",
            });
        }
        Err(CoreServiceSetupError::RolledBack {
            reason: "native service retirement failed",
        })
    }

    // Clears an unchanged compare-and-swap conflict without restoring a stale native snapshot.
    fn clear_retirement_conflict(
        &self,
        record: &CoreServiceCutoverRecord,
    ) -> Result<(), CoreServiceSetupError> {
        let receipt = CoreServiceCutoverReceipt::new(record.receipt_id().clone());
        self.store
            .remove(&receipt)
            .map_err(|_| CoreServiceSetupError::RecoveryRequired {
                reason: "unchanged service cutover record could not be cleared",
            })?;
        Err(CoreServiceSetupError::RolledBack {
            reason: "native service state changed before retirement",
        })
    }

    // Retires only the exact durable snapshot or selects its mutation-safe compensation path.
    fn retire_record(
        &self,
        record: &CoreServiceCutoverRecord,
        clear_unchanged_conflict: bool,
    ) -> Result<(), CoreServiceSetupError> {
        let retirement = if clear_unchanged_conflict {
            self.host.retire(record.native_snapshot())
        } else {
            self.host.resume_retirement(record.native_snapshot())
        };
        match retirement {
            Ok(()) => Ok(()),
            Err(CoreServiceSetupError::RolledBack {
                reason: "native service state changed before retirement",
            }) if clear_unchanged_conflict => self.clear_retirement_conflict(record),
            Err(CoreServiceSetupError::RolledBack {
                reason: "native service state changed before retirement",
            }) => Err(CoreServiceSetupError::RecoveryRequired {
                reason: "prepared native service state changed before retirement",
            }),
            Err(_) => self.compensate_failed_retirement(record),
        }
    }
}

impl CoreServiceCutoverProvider for DurableCoreServiceCutoverProvider {
    // Creates or replays one durable snapshot before replacing native service ownership.
    fn begin(
        &self,
        context: CoreUpdateServiceContext,
        installation: &CoreInstallation,
        definitions: &[CoreServiceDefinition],
    ) -> Result<CoreServiceCutoverBegin, CoreServiceSetupError> {
        validate_definition_set(context, definitions)?;
        if let Some(existing) = self.store.read()? {
            existing.validate()?;
            let receipt = CoreServiceCutoverReceipt::new(existing.receipt_id().clone());
            match existing.phase() {
                CoreServiceCutoverPhase::Committed => {
                    if existing.matches_request(context, installation, definitions)? {
                        return Ok(CoreServiceCutoverBegin::AlreadyCommitted(receipt));
                    }
                    self.store.remove(&receipt)?;
                }
                CoreServiceCutoverPhase::Prepared => {
                    if !existing.matches_request(context, installation, definitions)? {
                        return Err(CoreServiceSetupError::RecoveryRequired {
                            reason: "another service cutover requires recovery",
                        });
                    }
                    self.retire_record(&existing, false)?;
                    return Ok(CoreServiceCutoverBegin::Prepared(receipt));
                }
                CoreServiceCutoverPhase::Restoring => {
                    self.restore_record(existing).map_err(|_| {
                        CoreServiceSetupError::RecoveryRequired {
                            reason: "interrupted service restoration could not complete",
                        }
                    })?;
                    return Err(CoreServiceSetupError::RolledBack {
                        reason: "interrupted service restoration completed",
                    });
                }
                CoreServiceCutoverPhase::Restored => {
                    self.restore_record(existing).map_err(|_| {
                        CoreServiceSetupError::RecoveryRequired {
                            reason: "completed service restoration could not be cleared",
                        }
                    })?;
                    return Err(CoreServiceSetupError::RolledBack {
                        reason: "completed service restoration was cleared",
                    });
                }
            }
        }
        let snapshot = self.host.snapshot(context)?;
        let proposed =
            CoreServiceCutoverRecord::new(context, installation.clone(), definitions, snapshot)?;
        let stored = self.store.create(proposed.clone())?;
        stored.validate()?;
        if stored != proposed {
            return Err(CoreServiceSetupError::RecoveryRequired {
                reason: "service cutover store returned conflicting state",
            });
        }
        self.retire_record(&stored, true)?;
        Ok(CoreServiceCutoverBegin::Prepared(
            CoreServiceCutoverReceipt::new(stored.receipt_id().clone()),
        ))
    }

    // Marks a verified cutover committed while retaining bounded replay evidence.
    fn commit(&self, receipt: &CoreServiceCutoverReceipt) -> Result<(), CoreServiceSetupError> {
        let record = self.required_record(receipt)?;
        if record.phase() == CoreServiceCutoverPhase::Committed {
            return Ok(());
        }
        self.transition_record(
            &record,
            CoreServiceCutoverPhase::Prepared,
            CoreServiceCutoverPhase::Committed,
        )?;
        Ok(())
    }

    // Restores one uncommitted native snapshot through durable restoring and restored phases.
    fn restore(&self, receipt: &CoreServiceCutoverReceipt) -> Result<(), CoreServiceSetupError> {
        let record = self.required_record(receipt)?;
        self.restore_record(record)
    }

    // Observes only the two durable phases owned by pre-journal setup recovery.
    fn recovery(&self) -> Result<CoreServiceCutoverRecovery, CoreServiceSetupError> {
        let Some(record) = self.store.read()? else {
            return Ok(CoreServiceCutoverRecovery::None);
        };
        record.validate()?;
        match record.phase() {
            CoreServiceCutoverPhase::Restoring => Ok(CoreServiceCutoverRecovery::Restoring),
            CoreServiceCutoverPhase::Restored => Ok(CoreServiceCutoverRecovery::Restored),
            CoreServiceCutoverPhase::Prepared | CoreServiceCutoverPhase::Committed => {
                Ok(CoreServiceCutoverRecovery::None)
            }
        }
    }

    // Restores native state and persists Restored without clearing outer compensation authority.
    fn resume_recovery(&self) -> Result<(), CoreServiceSetupError> {
        let record = self
            .store
            .read()?
            .ok_or(CoreServiceSetupError::RecoveryRequired {
                reason: "interrupted service restoration record is unavailable",
            })?;
        record.validate()?;
        match record.phase() {
            CoreServiceCutoverPhase::Restoring => {
                self.host.restore(record.native_snapshot())?;
                self.transition_record(
                    &record,
                    CoreServiceCutoverPhase::Restoring,
                    CoreServiceCutoverPhase::Restored,
                )?;
                Ok(())
            }
            CoreServiceCutoverPhase::Restored => Ok(()),
            CoreServiceCutoverPhase::Prepared | CoreServiceCutoverPhase::Committed => {
                Err(CoreServiceSetupError::RecoveryRequired {
                    reason: "service cutover is not awaiting restoration",
                })
            }
        }
    }

    // Removes only a Restored record after the setup owner has retired its reversible journal.
    fn complete_recovery(&self) -> Result<(), CoreServiceSetupError> {
        let Some(record) = self.store.read()? else {
            return Ok(());
        };
        record.validate()?;
        if record.phase() != CoreServiceCutoverPhase::Restored {
            return Err(CoreServiceSetupError::RecoveryRequired {
                reason: "service restoration is not complete",
            });
        }
        self.store
            .remove(&CoreServiceCutoverReceipt::new(record.receipt_id().clone()))
    }
}

// Requires the exact platform-appropriate replacement identities in startup order.
fn validate_definition_set(
    context: CoreUpdateServiceContext,
    definitions: &[CoreServiceDefinition],
) -> Result<(), CoreServiceSetupError> {
    let expected: &[&str] = match context.platform() {
        CoreUpdateServicePlatform::Linux => &[
            "li_node.service",
            "li_watchdog.service",
            "li_gateway.service",
        ],
        CoreUpdateServicePlatform::Macos => &["ai.letsinfer.node", "ai.letsinfer.gateway"],
    };
    if definitions.len() != expected.len()
        || definitions
            .iter()
            .zip(expected)
            .any(|(definition, expected)| definition.service_identity() != *expected)
    {
        return Err(CoreServiceSetupError::InvalidContract {
            reason: "service cutover definition set is invalid",
        });
    }
    Ok(())
}

// Requires persisted definition identities to preserve the exact platform order.
fn validate_definition_identities(
    context: CoreUpdateServiceContext,
    definitions: &[CoreServiceCutoverDefinitionIdentity],
) -> Result<(), CoreServiceSetupError> {
    let expected: &[&str] = match context.platform() {
        CoreUpdateServicePlatform::Linux => &[
            "li_node.service",
            "li_watchdog.service",
            "li_gateway.service",
        ],
        CoreUpdateServicePlatform::Macos => &["ai.letsinfer.node", "ai.letsinfer.gateway"],
    };
    if definitions.len() != expected.len()
        || definitions
            .iter()
            .zip(expected)
            .any(|(definition, expected)| definition.service_identity != *expected)
    {
        return Err(CoreServiceSetupError::InvalidContract {
            reason: "service cutover definition set is invalid",
        });
    }
    Ok(())
}

// Derives one exact replacement request identity independently of native host state.
fn request_identity(
    context: CoreUpdateServiceContext,
    installation: &CoreInstallation,
    definitions: &[CoreServiceCutoverDefinitionIdentity],
) -> Result<Sha256Digest, CoreServiceSetupError> {
    let mut value = Sha256::new();
    append_field(&mut value, b"li_core_service_cutover_request_v1");
    append_field(&mut value, platform_identity(context.platform()));
    append_field(&mut value, role_identity(context.role()));
    append_field(&mut value, installation.version().as_str().as_bytes());
    append_field(
        &mut value,
        installation.source_identity().as_str().as_bytes(),
    );
    for definition in definitions {
        append_field(&mut value, definition.service_identity.as_bytes());
        append_field(&mut value, definition.sha256.as_str().as_bytes());
    }
    finished_digest(value)
}

// Derives one restoration receipt from the exact request and native snapshot identities.
fn receipt_identity(
    request_id: &Sha256Digest,
    snapshot_id: &Sha256Digest,
) -> Result<Sha256Digest, CoreServiceSetupError> {
    let mut value = Sha256::new();
    append_field(&mut value, b"li_core_service_cutover_receipt_v1");
    append_field(&mut value, request_id.as_str().as_bytes());
    append_field(&mut value, snapshot_id.as_str().as_bytes());
    finished_digest(value)
}

// Appends one unambiguous length-delimited receipt field.
fn append_field(value: &mut Sha256, field: &[u8]) {
    value.update((field.len() as u64).to_be_bytes());
    value.update(field);
}

// Returns the fixed platform receipt field.
const fn platform_identity(platform: CoreUpdateServicePlatform) -> &'static [u8] {
    match platform {
        CoreUpdateServicePlatform::Linux => b"linux",
        CoreUpdateServicePlatform::Macos => b"macos",
    }
}

// Returns the fixed local-role receipt field.
const fn role_identity(role: CoreUpdateNodeRole) -> &'static [u8] {
    match role {
        CoreUpdateNodeRole::Main => b"main",
        CoreUpdateNodeRole::Child => b"child",
    }
}

// Returns the closed JSON platform value.
const fn platform_text(platform: CoreUpdateServicePlatform) -> &'static str {
    match platform {
        CoreUpdateServicePlatform::Linux => "linux",
        CoreUpdateServicePlatform::Macos => "macos",
    }
}

// Parses one closed JSON platform value.
fn parse_platform(value: &str) -> Result<CoreUpdateServicePlatform, CoreServiceSetupError> {
    match value {
        "linux" => Ok(CoreUpdateServicePlatform::Linux),
        "macos" => Ok(CoreUpdateServicePlatform::Macos),
        _ => Err(CoreServiceSetupError::InvalidContract {
            reason: "service cutover platform is invalid",
        }),
    }
}

// Returns the closed JSON local-role value.
const fn role_text(role: CoreUpdateNodeRole) -> &'static str {
    match role {
        CoreUpdateNodeRole::Main => "main",
        CoreUpdateNodeRole::Child => "child",
    }
}

// Parses one closed JSON local-role value.
fn parse_role(value: &str) -> Result<CoreUpdateNodeRole, CoreServiceSetupError> {
    match value {
        "main" => Ok(CoreUpdateNodeRole::Main),
        "child" => Ok(CoreUpdateNodeRole::Child),
        _ => Err(CoreServiceSetupError::InvalidContract {
            reason: "service cutover node role is invalid",
        }),
    }
}

// Returns the closed JSON cutover phase value.
const fn phase_text(phase: CoreServiceCutoverPhase) -> &'static str {
    match phase {
        CoreServiceCutoverPhase::Prepared => "prepared",
        CoreServiceCutoverPhase::Restoring => "restoring",
        CoreServiceCutoverPhase::Restored => "restored",
        CoreServiceCutoverPhase::Committed => "committed",
    }
}

// Parses one closed JSON cutover phase value.
fn parse_phase(value: &str) -> Result<CoreServiceCutoverPhase, CoreServiceSetupError> {
    match value {
        "prepared" => Ok(CoreServiceCutoverPhase::Prepared),
        "restoring" => Ok(CoreServiceCutoverPhase::Restoring),
        "restored" => Ok(CoreServiceCutoverPhase::Restored),
        "committed" => Ok(CoreServiceCutoverPhase::Committed),
        _ => Err(CoreServiceSetupError::InvalidContract {
            reason: "service cutover phase is invalid",
        }),
    }
}

// Returns whether one durable phase edge belongs to the closed cutover lifecycle.
const fn is_valid_phase_transition(
    expected: CoreServiceCutoverPhase,
    next: CoreServiceCutoverPhase,
) -> bool {
    matches!(
        (expected, next),
        (
            CoreServiceCutoverPhase::Prepared,
            CoreServiceCutoverPhase::Restoring | CoreServiceCutoverPhase::Committed
        ) | (
            CoreServiceCutoverPhase::Restoring,
            CoreServiceCutoverPhase::Restored
        )
    )
}

// Parses one canonical SHA-256 field without accepting case or prefix variants.
fn parse_digest(value: &str) -> Result<Sha256Digest, CoreServiceSetupError> {
    Sha256Digest::parse(value).map_err(|_| CoreServiceSetupError::InvalidContract {
        reason: "service cutover digest is invalid",
    })
}

// Computes one canonical SHA-256 identity for bounded cutover bytes.
fn digest(bytes: &[u8]) -> Result<Sha256Digest, CoreServiceSetupError> {
    Sha256Digest::parse(&format!("{:x}", Sha256::digest(bytes))).map_err(|_| {
        CoreServiceSetupError::InvalidContract {
            reason: "service cutover identity could not be derived",
        }
    })
}

// Converts one completed receipt hash into the canonical digest value.
fn finished_digest(value: Sha256) -> Result<Sha256Digest, CoreServiceSetupError> {
    Sha256Digest::parse(&format!("{:x}", value.finalize())).map_err(|_| {
        CoreServiceSetupError::InvalidContract {
            reason: "service cutover identity could not be derived",
        }
    })
}
