// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;

use li_core_interface::{NodeId, Sha256Digest, TechnicalName};

pub const AUDIT_GENESIS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
pub const PRODUCTION_CHECKPOINT_INTERVAL: u64 = 100;

const MAX_ACTOR_ID_BYTES: usize = 128;
const MAX_CHECKPOINT_SIGNATURE_BYTES: usize = 4096;
const MAX_REPLAY_ID_BYTES: usize = 128;
const MAX_TARGET_BYTES: usize = 255;

// Identifies one audit event independently of its chain sequence.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AuditEventId(String);

impl AuditEventId {
    // Parses one production-compatible lowercase 128-bit hexadecimal identity.
    pub fn parse(value: &str) -> Result<Self, AuditError> {
        require_lower_hex(value, 32, "event identity")?;
        Ok(Self(value.to_string()))
    }

    // Returns the canonical event identity.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// Identifies every audit event belonging to one logical command.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AuditCorrelationId(String);

impl AuditCorrelationId {
    // Parses one production-compatible lowercase 128-bit hexadecimal identity.
    pub fn parse(value: &str) -> Result<Self, AuditError> {
        require_lower_hex(value, 32, "correlation identity")?;
        Ok(Self(value.to_string()))
    }

    // Returns the canonical correlation identity.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// Identifies one replay-safe append intent without carrying command content.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AuditReplayId(String);

impl AuditReplayId {
    // Parses one bounded opaque replay identity with no whitespace or secret markers.
    pub fn parse(value: &str) -> Result<Self, AuditError> {
        if !is_safe_identifier(value, MAX_REPLAY_ID_BYTES) || contains_secret_marker(value) {
            return Err(AuditError::invalid(
                "replay identity",
                "identity must be bounded printable identifier text",
            ));
        }
        Ok(Self(value.to_string()))
    }

    // Returns the exact caller-owned replay identity.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// Stores one Unix timestamp that remains representable by SQLite INTEGER.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AuditUnixNanoseconds(u64);

impl AuditUnixNanoseconds {
    // Creates one positive timestamp within the signed persistence range.
    pub fn new(value: u64) -> Result<Self, AuditError> {
        if value == 0 || value > i64::MAX as u64 {
            return Err(AuditError::invalid(
                "audit timestamp",
                "timestamp must fit the positive signed 64-bit range",
            ));
        }
        Ok(Self(value))
    }

    // Returns the timestamp as Unix nanoseconds.
    pub const fn value(self) -> u64 {
        self.0
    }
}

// Identifies the closed kind of principal responsible for an event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditActorType {
    LocalUser,
    Controller,
    NodeCandidate,
    Node,
    System,
}

impl AuditActorType {
    // Returns the stable production actor label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalUser => "local-user",
            Self::Controller => "controller",
            Self::NodeCandidate => "node-candidate",
            Self::Node => "node",
            Self::System => "system",
        }
    }
}

// Stores one bounded actor identity rather than arbitrary actor metadata.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AuditActorId(String);

impl AuditActorId {
    // Parses one single-line principal identity without secret-shaped content.
    pub fn parse(value: &str) -> Result<Self, AuditError> {
        if !is_safe_principal(value, MAX_ACTOR_ID_BYTES) || contains_secret_marker(value) {
            return Err(AuditError::invalid(
                "actor identity",
                "identity must be bounded principal text",
            ));
        }
        Ok(Self(value.to_string()))
    }

    // Returns the canonical principal identity.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// Binds one closed actor kind to its validated identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditActor {
    kind: AuditActorType,
    identifier: AuditActorId,
}

impl AuditActor {
    // Creates one complete actor identity.
    pub const fn new(kind: AuditActorType, identifier: AuditActorId) -> Self {
        Self { kind, identifier }
    }

    // Returns the actor kind.
    pub const fn kind(&self) -> AuditActorType {
        self.kind
    }

    // Returns the actor identifier.
    pub const fn identifier(&self) -> &AuditActorId {
        &self.identifier
    }
}

// Identifies the closed interface at which one action originated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditOriginInterface {
    Cli,
    Controller,
    Pairing,
    Gateway,
    Node,
    System,
}

impl AuditOriginInterface {
    // Returns the stable origin-interface label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cli => "cli",
            Self::Controller => "controller",
            Self::Pairing => "pairing",
            Self::Gateway => "gateway",
            Self::Node => "node",
            Self::System => "system",
        }
    }
}

// Binds an action to its exact originating node and interface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditOrigin {
    node_id: NodeId,
    interface: AuditOriginInterface,
}

impl AuditOrigin {
    // Creates one complete action origin.
    pub const fn new(node_id: NodeId, interface: AuditOriginInterface) -> Self {
        Self { node_id, interface }
    }

    // Returns the originating node identity.
    pub const fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    // Returns the originating interface.
    pub const fn interface(&self) -> AuditOriginInterface {
        self.interface
    }
}

// Stores one canonical action name.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AuditAction(TechnicalName);

impl AuditAction {
    // Parses one lowercase action identifier such as `node.setup`.
    pub fn parse(value: &str) -> Result<Self, AuditError> {
        TechnicalName::parse(value)
            .map(Self)
            .map_err(|_| AuditError::invalid("audit action", "action name is invalid"))
    }

    // Returns the canonical action name.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

// Stores one bounded action target identity without arbitrary target data.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AuditTarget(String);

impl AuditTarget {
    // Parses one printable stable identity with no whitespace or secret markers.
    pub fn parse(value: &str) -> Result<Self, AuditError> {
        if !is_safe_target(value, MAX_TARGET_BYTES) || contains_secret_marker(value) {
            return Err(AuditError::invalid(
                "audit target",
                "target must be bounded stable identity text",
            ));
        }
        Ok(Self(value.to_string()))
    }

    // Returns the canonical target identity.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// Identifies the complete result of one audited action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditOutcome {
    Success,
    Denied,
    Failed,
}

impl AuditOutcome {
    // Returns the stable production outcome label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Denied => "denied",
            Self::Failed => "failed",
        }
    }
}

// Stores one bounded machine-readable reason code rather than arbitrary text.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AuditReason(TechnicalName);

impl AuditReason {
    // Parses one canonical reason code with the shared 64-byte bound.
    pub fn parse(value: &str) -> Result<Self, AuditError> {
        TechnicalName::parse(value)
            .map(Self)
            .map_err(|_| AuditError::invalid("audit reason", "reason code is invalid"))
    }

    // Returns the canonical reason code.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

// Defines one caller-validated action summary before chain metadata is assigned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditAppendRequest {
    replay_id: AuditReplayId,
    correlation_id: AuditCorrelationId,
    actor: AuditActor,
    origin: AuditOrigin,
    action: AuditAction,
    target: AuditTarget,
    before_sha256: Option<Sha256Digest>,
    after_sha256: Option<Sha256Digest>,
    outcome: AuditOutcome,
    reason: Option<AuditReason>,
}

impl AuditAppendRequest {
    // Creates one structurally secret-free action summary.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        replay_id: AuditReplayId,
        correlation_id: AuditCorrelationId,
        actor: AuditActor,
        origin: AuditOrigin,
        action: AuditAction,
        target: AuditTarget,
        before_sha256: Option<Sha256Digest>,
        after_sha256: Option<Sha256Digest>,
        outcome: AuditOutcome,
        reason: Option<AuditReason>,
    ) -> Result<Self, AuditError> {
        if outcome == AuditOutcome::Success && reason.is_some() {
            return Err(AuditError::invalid(
                "audit reason",
                "successful actions cannot carry a failure reason",
            ));
        }
        if outcome != AuditOutcome::Success && reason.is_none() {
            return Err(AuditError::invalid(
                "audit reason",
                "denied and failed actions require a reason code",
            ));
        }
        Ok(Self {
            replay_id,
            correlation_id,
            actor,
            origin,
            action,
            target,
            before_sha256,
            after_sha256,
            outcome,
            reason,
        })
    }

    // Returns the caller-owned replay identity.
    pub const fn replay_id(&self) -> &AuditReplayId {
        &self.replay_id
    }

    // Returns the logical command correlation identity.
    pub const fn correlation_id(&self) -> &AuditCorrelationId {
        &self.correlation_id
    }

    // Returns the responsible principal.
    pub const fn actor(&self) -> &AuditActor {
        &self.actor
    }

    // Returns the originating node and interface.
    pub const fn origin(&self) -> &AuditOrigin {
        &self.origin
    }

    // Returns the audited action.
    pub const fn action(&self) -> &AuditAction {
        &self.action
    }

    // Returns the exact action target identity.
    pub const fn target(&self) -> &AuditTarget {
        &self.target
    }

    // Returns the optional hash of prior state.
    pub const fn before_sha256(&self) -> Option<&Sha256Digest> {
        self.before_sha256.as_ref()
    }

    // Returns the optional hash of resulting state.
    pub const fn after_sha256(&self) -> Option<&Sha256Digest> {
        self.after_sha256.as_ref()
    }

    // Returns the action outcome.
    pub const fn outcome(&self) -> AuditOutcome {
        self.outcome
    }

    // Returns the bounded denial or failure reason.
    pub const fn reason(&self) -> Option<&AuditReason> {
        self.reason.as_ref()
    }
}

// Stores one complete append-only audit event reconstructed from persistence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditEvent {
    sequence: u64,
    event_id: AuditEventId,
    correlation_id: AuditCorrelationId,
    timestamp: AuditUnixNanoseconds,
    node_id: NodeId,
    actor: AuditActor,
    origin: AuditOrigin,
    action: AuditAction,
    target: AuditTarget,
    before_sha256: Option<Sha256Digest>,
    after_sha256: Option<Sha256Digest>,
    outcome: AuditOutcome,
    reason: Option<AuditReason>,
    previous_hash: Sha256Digest,
    event_hash: Sha256Digest,
}

impl AuditEvent {
    // Reconstructs one structurally valid persisted event before chain verification.
    #[allow(clippy::too_many_arguments)]
    pub fn from_persisted(
        sequence: u64,
        event_id: AuditEventId,
        correlation_id: AuditCorrelationId,
        timestamp: AuditUnixNanoseconds,
        node_id: NodeId,
        actor: AuditActor,
        origin: AuditOrigin,
        action: AuditAction,
        target: AuditTarget,
        before_sha256: Option<Sha256Digest>,
        after_sha256: Option<Sha256Digest>,
        outcome: AuditOutcome,
        reason: Option<AuditReason>,
        previous_hash: Sha256Digest,
        event_hash: Sha256Digest,
    ) -> Result<Self, AuditError> {
        if sequence == 0 || sequence > i64::MAX as u64 {
            return Err(AuditError::invalid(
                "audit sequence",
                "sequence must fit the positive signed 64-bit range",
            ));
        }
        if outcome == AuditOutcome::Success && reason.is_some()
            || outcome != AuditOutcome::Success && reason.is_none()
        {
            return Err(AuditError::invalid(
                "audit event",
                "outcome and reason are inconsistent",
            ));
        }
        Ok(Self {
            sequence,
            event_id,
            correlation_id,
            timestamp,
            node_id,
            actor,
            origin,
            action,
            target,
            before_sha256,
            after_sha256,
            outcome,
            reason,
            previous_hash,
            event_hash,
        })
    }

    // Returns the chronological sequence.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    // Returns the stable event identity.
    pub const fn event_id(&self) -> &AuditEventId {
        &self.event_id
    }

    // Returns the logical command correlation identity.
    pub const fn correlation_id(&self) -> &AuditCorrelationId {
        &self.correlation_id
    }

    // Returns the event timestamp.
    pub const fn timestamp(&self) -> AuditUnixNanoseconds {
        self.timestamp
    }

    // Returns the owning node identity.
    pub const fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    // Returns the responsible principal.
    pub const fn actor(&self) -> &AuditActor {
        &self.actor
    }

    // Returns the originating node and interface.
    pub const fn origin(&self) -> &AuditOrigin {
        &self.origin
    }

    // Returns the audited action.
    pub const fn action(&self) -> &AuditAction {
        &self.action
    }

    // Returns the exact action target identity.
    pub const fn target(&self) -> &AuditTarget {
        &self.target
    }

    // Returns the optional hash of prior state.
    pub const fn before_sha256(&self) -> Option<&Sha256Digest> {
        self.before_sha256.as_ref()
    }

    // Returns the optional hash of resulting state.
    pub const fn after_sha256(&self) -> Option<&Sha256Digest> {
        self.after_sha256.as_ref()
    }

    // Returns the action outcome.
    pub const fn outcome(&self) -> AuditOutcome {
        self.outcome
    }

    // Returns the bounded denial or failure reason.
    pub const fn reason(&self) -> Option<&AuditReason> {
        self.reason.as_ref()
    }

    // Returns the exact preceding chain hash.
    pub const fn previous_hash(&self) -> &Sha256Digest {
        &self.previous_hash
    }

    // Returns this event's complete chain hash.
    pub const fn event_hash(&self) -> &Sha256Digest {
        &self.event_hash
    }
}

// Stores one periodic signature bound to an exact event hash.
#[derive(Clone, Eq, PartialEq)]
pub struct AuditCheckpoint {
    sequence: u64,
    event_hash: Sha256Digest,
    signature: Vec<u8>,
    created_at: AuditUnixNanoseconds,
}

impl AuditCheckpoint {
    // Reconstructs one bounded persisted checkpoint before signature verification.
    pub fn from_persisted(
        sequence: u64,
        event_hash: Sha256Digest,
        signature: Vec<u8>,
        created_at: AuditUnixNanoseconds,
    ) -> Result<Self, AuditError> {
        if sequence == 0 || sequence > i64::MAX as u64 {
            return Err(AuditError::invalid(
                "checkpoint sequence",
                "sequence must fit the positive signed 64-bit range",
            ));
        }
        if signature.is_empty() || signature.len() > MAX_CHECKPOINT_SIGNATURE_BYTES {
            return Err(AuditError::invalid(
                "checkpoint signature",
                "signature must contain between 1 and 4096 bytes",
            ));
        }
        Ok(Self {
            sequence,
            event_hash,
            signature,
            created_at,
        })
    }

    // Returns the signed event sequence.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    // Returns the signed event hash.
    pub const fn event_hash(&self) -> &Sha256Digest {
        &self.event_hash
    }

    // Returns the opaque checkpoint signature for verification only.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    // Returns when the checkpoint was created.
    pub const fn created_at(&self) -> AuditUnixNanoseconds {
        self.created_at
    }
}

impl fmt::Debug for AuditCheckpoint {
    // Redacts opaque signature bytes from diagnostic output.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuditCheckpoint")
            .field("sequence", &self.sequence)
            .field("event_hash", &self.event_hash)
            .field("signature", &"<redacted>")
            .field("created_at", &self.created_at)
            .finish()
    }
}

// Defines one bounded periodic checkpoint policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditCheckpointPolicy {
    interval: u64,
}

impl AuditCheckpointPolicy {
    // Creates one policy with a positive bounded interval.
    pub fn new(interval: u64) -> Result<Self, AuditError> {
        if interval == 0 || interval > 10_000 {
            return Err(AuditError::invalid(
                "checkpoint interval",
                "interval must be between 1 and 10000 events",
            ));
        }
        Ok(Self { interval })
    }

    // Creates the production 100-event checkpoint policy.
    pub const fn production() -> Self {
        Self {
            interval: PRODUCTION_CHECKPOINT_INTERVAL,
        }
    }

    // Returns whether one event sequence requires a signed checkpoint.
    pub const fn requires_checkpoint(self, sequence: u64) -> bool {
        sequence != 0 && sequence % self.interval == 0
    }

    // Returns the configured event interval.
    pub const fn interval(self) -> u64 {
        self.interval
    }
}

// Reports one verified complete chain head.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditVerification {
    events: usize,
    checkpoints: usize,
    head_sha256: Sha256Digest,
}

impl AuditVerification {
    // Creates one verification receipt after every chain boundary succeeds.
    pub(crate) const fn new(events: usize, checkpoints: usize, head_sha256: Sha256Digest) -> Self {
        Self {
            events,
            checkpoints,
            head_sha256,
        }
    }

    // Returns the number of verified events.
    pub const fn events(&self) -> usize {
        self.events
    }

    // Returns the number of verified checkpoints.
    pub const fn checkpoints(&self) -> usize {
        self.checkpoints
    }

    // Returns the verified chain head.
    pub const fn head_sha256(&self) -> &Sha256Digest {
        &self.head_sha256
    }
}

// Describes one stable integrity boundary that cannot be repaired by verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuditIntegrityError {
    Sequence { sequence: u64 },
    EventIdentity { sequence: u64 },
    Node { sequence: u64 },
    PreviousHash { sequence: u64 },
    EventHash { sequence: u64 },
    CheckpointMissing { sequence: u64 },
    CheckpointUnexpected { sequence: u64 },
    CheckpointHash { sequence: u64 },
    CheckpointTime { sequence: u64 },
    CheckpointSignature { sequence: u64 },
}

impl fmt::Display for AuditIntegrityError {
    // Presents the first exact chain boundary that failed closed.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (subject, sequence) = match self {
            Self::Sequence { sequence } => ("sequence", sequence),
            Self::EventIdentity { sequence } => ("event identity", sequence),
            Self::Node { sequence } => ("node identity", sequence),
            Self::PreviousHash { sequence } => ("previous hash", sequence),
            Self::EventHash { sequence } => ("event hash", sequence),
            Self::CheckpointMissing { sequence } => ("checkpoint is missing", sequence),
            Self::CheckpointUnexpected { sequence } => ("checkpoint is unexpected", sequence),
            Self::CheckpointHash { sequence } => ("checkpoint hash", sequence),
            Self::CheckpointTime { sequence } => ("checkpoint time", sequence),
            Self::CheckpointSignature { sequence } => ("checkpoint signature", sequence),
        };
        write!(formatter, "audit {subject} mismatch at sequence {sequence}")
    }
}

// Describes one stable store failure without exposing persistence details.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuditStoreError {
    Conflict,
    ReplayConflict,
    Unavailable,
    Corrupt,
}

impl fmt::Display for AuditStoreError {
    // Presents a stable persistence failure.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conflict => formatter.write_str("audit chain revision conflicted"),
            Self::ReplayConflict => formatter.write_str("audit replay identity conflicted"),
            Self::Unavailable => formatter.write_str("audit store is unavailable"),
            Self::Corrupt => formatter.write_str("audit store is corrupt"),
        }
    }
}

impl Error for AuditStoreError {}

// Describes one stable AuditManager failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuditError {
    InvalidInput {
        field: &'static str,
        reason: &'static str,
    },
    NotFound,
    IdempotencyConflict,
    Contention,
    ExportLimitExceeded,
    Provider {
        capability: &'static str,
        reason: &'static str,
    },
    Store(AuditStoreError),
    Integrity(AuditIntegrityError),
}

impl AuditError {
    // Creates one stable invalid-input failure at its exact field boundary.
    pub const fn invalid(field: &'static str, reason: &'static str) -> Self {
        Self::InvalidInput { field, reason }
    }

    // Creates one redacted injected-provider failure.
    pub const fn provider(capability: &'static str, reason: &'static str) -> Self {
        Self::Provider { capability, reason }
    }
}

impl fmt::Display for AuditError {
    // Presents stable manager language without event content or signature bytes.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput { field, reason } => write!(formatter, "invalid {field}: {reason}"),
            Self::NotFound => formatter.write_str("audit event is not registered"),
            Self::IdempotencyConflict => {
                formatter.write_str("audit replay identity conflicts with its action")
            }
            Self::Contention => formatter.write_str("audit chain remained contested"),
            Self::ExportLimitExceeded => formatter.write_str("audit export exceeds its bound"),
            Self::Provider { capability, reason } => {
                write!(formatter, "audit {capability} failed: {reason}")
            }
            Self::Store(error) => write!(formatter, "{error}"),
            Self::Integrity(error) => write!(formatter, "{error}"),
        }
    }
}

impl Error for AuditError {}

impl From<AuditStoreError> for AuditError {
    // Preserves one stable store failure at the manager boundary.
    fn from(error: AuditStoreError) -> Self {
        Self::Store(error)
    }
}

impl From<AuditIntegrityError> for AuditError {
    // Preserves one exact integrity failure at the manager boundary.
    fn from(error: AuditIntegrityError) -> Self {
        Self::Integrity(error)
    }
}

// Requires one exact lowercase hexadecimal value.
fn require_lower_hex(value: &str, length: usize, field: &'static str) -> Result<(), AuditError> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(AuditError::invalid(
            field,
            "identity must be canonical lowercase hexadecimal text",
        ));
    }
    Ok(())
}

// Returns whether one opaque identity uses only bounded printable token characters.
fn is_safe_identifier(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

// Returns whether one principal identity is printable, bounded, and single-line.
fn is_safe_principal(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'@'))
}

// Returns whether one target is stable identity text rather than prose or content.
fn is_safe_target(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'@' | b':' | b'/')
        })
}

// Rejects common secret envelopes even when their characters are otherwise printable.
fn contains_secret_marker(value: &str) -> bool {
    let lowercase = value.to_ascii_lowercase();
    lowercase.starts_with("bearer")
        || lowercase.starts_with("sk-")
        || lowercase.contains("private_key")
        || lowercase.contains("private-key")
        || lowercase.contains("-----begin")
}
