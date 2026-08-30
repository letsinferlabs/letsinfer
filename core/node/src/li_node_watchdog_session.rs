// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::num::NonZeroU64;
use std::sync::Arc;

use li_core_interface::{
    NodeId, PlacementGroupId, PlacementGroupState, PlacementId, PlacementState, Sha256Digest,
};
use li_database::{
    DatabaseCollection, DatabaseCommitDisposition, DatabaseError, DatabaseManager, DatabaseQuery,
    DatabaseRecord, DatabaseResult, DatabaseRevision, DatabaseTransaction,
};
use li_placement_manager::{
    LinuxPlacementProtectedTargetProvider, PlacementProtectedTarget, PlacementProtectionPhase,
    PlacementStore,
};
use li_watchdog_manager::{
    WatchdogControllerBinding, WatchdogControllerSessionProvider, WatchdogError,
    WatchdogLinuxProcessProvider, WatchdogProcessState, WatchdogProtectedEngine,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::DatabasePlacementStore;
use crate::{NodeProtectionApiError, NodeProtectionControllerBindingProvider};

const CONTROLLER_RECORD_PREFIX: &str = "li_watchdog_controller_";
const CERTIFICATE_RECORD_PREFIX: &str = "li_watchdog_certificate_";

// Identifies one authorized Watchdog controller without borrowing credential semantics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeWatchdogControllerId(String);

impl NodeWatchdogControllerId {
    // Parses one exact lowercase 128-bit controller identity.
    pub fn parse(value: &str) -> Result<Self, NodeWatchdogSessionError> {
        if value.len() != 32
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(NodeWatchdogSessionError::InvalidContract);
        }
        Ok(Self(value.to_string()))
    }

    // Returns the canonical controller identity text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// Selects one exact placement-group and placement pair without active-group convention.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeWatchdogTargetKey {
    placement_group_id: PlacementGroupId,
    placement_id: PlacementId,
}

// Carries one revalidated session target and its exact current protected process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeWatchdogProtocolTarget {
    key: NodeWatchdogTargetKey,
    protected: PlacementProtectedTarget,
}

impl NodeWatchdogProtocolTarget {
    // Returns the exact group and placement selected by the controller session.
    pub const fn key(&self) -> &NodeWatchdogTargetKey {
        &self.key
    }

    // Returns the exact process-bound protection target pinned by the session.
    pub const fn protected(&self) -> &PlacementProtectedTarget {
        &self.protected
    }
}

impl NodeWatchdogTargetKey {
    // Creates one explicit target from exact group and placement identities.
    pub const fn new(placement_group_id: PlacementGroupId, placement_id: PlacementId) -> Self {
        Self {
            placement_group_id,
            placement_id,
        }
    }

    // Returns the exact placement group selected by the controller session.
    pub const fn placement_group_id(&self) -> &PlacementGroupId {
        &self.placement_group_id
    }

    // Returns the exact placement selected by the controller session.
    pub const fn placement_id(&self) -> &PlacementId {
        &self.placement_id
    }
}

// Names the only two durable controller authorization states.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeWatchdogSessionState {
    Active,
    Revoked,
}

// Binds one certificate to a monotonic controller generation and explicit target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeWatchdogSession {
    controller_id: NodeWatchdogControllerId,
    certificate_sha256: Sha256Digest,
    session_generation: NonZeroU64,
    target: NodeWatchdogTargetKey,
    protected_target_sha256: Option<Sha256Digest>,
    state: NodeWatchdogSessionState,
}

impl NodeWatchdogSession {
    // Creates one active session from exact authorization and target identities.
    pub const fn active(
        controller_id: NodeWatchdogControllerId,
        certificate_sha256: Sha256Digest,
        session_generation: NonZeroU64,
        target: NodeWatchdogTargetKey,
    ) -> Self {
        Self {
            controller_id,
            certificate_sha256,
            session_generation,
            target,
            protected_target_sha256: None,
            state: NodeWatchdogSessionState::Active,
        }
    }

    // Produces the next terminal generation without changing certificate or target identity.
    pub fn revoked(
        &self,
        session_generation: NonZeroU64,
    ) -> Result<Self, NodeWatchdogSessionError> {
        if self.state != NodeWatchdogSessionState::Active
            || session_generation.get() != self.session_generation.get().checked_add(1).unwrap_or(0)
        {
            return Err(NodeWatchdogSessionError::InvalidContract);
        }
        Ok(Self {
            controller_id: self.controller_id.clone(),
            certificate_sha256: self.certificate_sha256.clone(),
            session_generation,
            target: self.target.clone(),
            protected_target_sha256: self.protected_target_sha256.clone(),
            state: NodeWatchdogSessionState::Revoked,
        })
    }

    // Returns the exact authorized controller identity.
    pub const fn controller_id(&self) -> &NodeWatchdogControllerId {
        &self.controller_id
    }

    // Returns the authenticated peer leaf digest.
    pub const fn certificate_sha256(&self) -> &Sha256Digest {
        &self.certificate_sha256
    }

    // Returns the restart-safe nonzero controller generation.
    pub const fn session_generation(&self) -> NonZeroU64 {
        self.session_generation
    }

    // Returns the exact selected placement identity.
    pub const fn target(&self) -> &NodeWatchdogTargetKey {
        &self.target
    }

    // Returns the exact protected descriptor identity after authority binding.
    pub const fn protected_target_sha256(&self) -> Option<&Sha256Digest> {
        self.protected_target_sha256.as_ref()
    }

    // Returns whether this generation remains authorized or is terminally revoked.
    pub const fn state(&self) -> NodeWatchdogSessionState {
        self.state
    }

    // Binds one active proposal to the exact process descriptor observed by authority.
    fn bind_target(
        &mut self,
        target: &PlacementProtectedTarget,
    ) -> Result<(), NodeWatchdogSessionError> {
        self.protected_target_sha256 = Some(protected_target_digest(target)?);
        Ok(())
    }
}

// Returns one session together with the revision required by its next mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionedNodeWatchdogSession {
    session: NodeWatchdogSession,
    revision: u64,
}

impl VersionedNodeWatchdogSession {
    // Creates one validated private persistence projection.
    const fn new(session: NodeWatchdogSession, revision: u64) -> Self {
        Self { session, revision }
    }

    // Returns the immutable session projection.
    pub const fn session(&self) -> &NodeWatchdogSession {
        &self.session
    }

    // Returns the optimistic controller-record revision.
    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

// Names exact target resolution failures without exposing process or certificate values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeWatchdogTargetError {
    Missing,
    Ambiguous,
    Inactive,
    ReplacedProcess,
    Unavailable,
}

// Resolves one explicit placement-group and placement pair to its protected process.
pub trait NodeWatchdogTargetProvider: Send + Sync {
    // Returns only an active target whose durable and live process identities agree.
    fn active_target(
        &self,
        target: &NodeWatchdogTargetKey,
    ) -> Result<PlacementProtectedTarget, NodeWatchdogTargetError>;
}

// Verifies one process-bound placement target through the resident Linux kernel boundary.
pub trait NodeWatchdogProcessProvider: Send + Sync {
    // Returns only when the exact protected descriptor still names one running process.
    fn require_running(
        &self,
        target: &PlacementProtectedTarget,
    ) -> Result<(), NodeWatchdogTargetError>;
}

// Adapts Watchdog's pidfd-backed process provider to Node's exact target judgment.
pub struct LinuxNodeWatchdogProcessProvider {
    processes: Arc<dyn WatchdogLinuxProcessProvider>,
}

impl LinuxNodeWatchdogProcessProvider {
    // Creates one adapter without duplicating Linux process identity ownership.
    pub const fn new(processes: Arc<dyn WatchdogLinuxProcessProvider>) -> Self {
        Self { processes }
    }
}

impl NodeWatchdogProcessProvider for LinuxNodeWatchdogProcessProvider {
    // Requires descriptor identity, pidfd binding, and a currently running process.
    fn require_running(
        &self,
        target: &PlacementProtectedTarget,
    ) -> Result<(), NodeWatchdogTargetError> {
        let target = watchdog_target(target).map_err(|_| NodeWatchdogTargetError::Unavailable)?;
        let process = self
            .processes
            .bind(&target)
            .map_err(|_| NodeWatchdogTargetError::ReplacedProcess)?
            .ok_or(NodeWatchdogTargetError::Inactive)?;
        match process
            .state()
            .map_err(|_| NodeWatchdogTargetError::Unavailable)?
        {
            WatchdogProcessState::Running => Ok(()),
            WatchdogProcessState::Exited => Err(NodeWatchdogTargetError::Inactive),
        }
    }
}

// Resolves exact persisted placement state against live execution and durable protection.
pub struct PersistedNodeWatchdogTargetProvider {
    local_node_id: NodeId,
    placements: Arc<DatabasePlacementStore>,
    protection: Arc<dyn LinuxPlacementProtectedTargetProvider>,
    processes: Arc<dyn NodeWatchdogProcessProvider>,
}

impl PersistedNodeWatchdogTargetProvider {
    // Creates one provider bound to the local Node and shared placement authority.
    pub const fn new(
        local_node_id: NodeId,
        placements: Arc<DatabasePlacementStore>,
        protection: Arc<dyn LinuxPlacementProtectedTargetProvider>,
        processes: Arc<dyn NodeWatchdogProcessProvider>,
    ) -> Self {
        Self {
            local_node_id,
            placements,
            protection,
            processes,
        }
    }
}

impl NodeWatchdogTargetProvider for PersistedNodeWatchdogTargetProvider {
    // Requires one exact local active placement and one unchanged protected process.
    fn active_target(
        &self,
        target: &NodeWatchdogTargetKey,
    ) -> Result<PlacementProtectedTarget, NodeWatchdogTargetError> {
        let record = self
            .placements
            .read(target.placement_group_id())
            .map_err(|_| NodeWatchdogTargetError::Unavailable)?
            .ok_or(NodeWatchdogTargetError::Missing)?;
        let record = record.record();
        let mut matches = record
            .placements()
            .iter()
            .filter(|placement| placement.placement_id() == target.placement_id());
        let placement = matches.next().ok_or(NodeWatchdogTargetError::Missing)?;
        if matches.next().is_some() {
            return Err(NodeWatchdogTargetError::Ambiguous);
        }
        if placement.placement_group_id() != target.placement_group_id()
            || record.group().placement_group_id() != target.placement_group_id()
        {
            return Err(NodeWatchdogTargetError::Ambiguous);
        }
        if placement.assignment().node_id() != &self.local_node_id {
            return Err(NodeWatchdogTargetError::Inactive);
        }
        let protected = self
            .protection
            .active_target(placement)
            .map_err(|_| NodeWatchdogTargetError::Unavailable)?
            .ok_or(NodeWatchdogTargetError::Inactive)?;
        let state_matches = match protected.phase() {
            PlacementProtectionPhase::Starting => {
                record.group().state() == PlacementGroupState::Starting
                    && placement.state() == PlacementState::Starting
            }
            PlacementProtectionPhase::Armed => {
                record.group().state() == PlacementGroupState::Running
                    && placement.state() == PlacementState::Running
            }
            _ => false,
        };
        if !state_matches {
            return Err(NodeWatchdogTargetError::Inactive);
        }
        self.processes.require_running(&protected)?;
        Ok(protected)
    }
}

// Names stable authority, persistence, and target failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeWatchdogSessionError {
    InvalidContract,
    NotFound,
    Revoked,
    Conflict,
    Corrupt,
    StoreUnavailable,
    Target(NodeWatchdogTargetError),
}

impl fmt::Display for NodeWatchdogSessionError {
    // Presents fixed failure classes without controller, certificate, or process values.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidContract => formatter.write_str("Watchdog session contract is invalid"),
            Self::NotFound => formatter.write_str("Watchdog session is unavailable"),
            Self::Revoked => formatter.write_str("Watchdog session is revoked"),
            Self::Conflict => formatter.write_str("Watchdog session changed concurrently"),
            Self::Corrupt => formatter.write_str("Watchdog session state is corrupt"),
            Self::StoreUnavailable => formatter.write_str("Watchdog session store is unavailable"),
            Self::Target(_) => formatter.write_str("Watchdog placement target is unavailable"),
        }
    }
}

impl Error for NodeWatchdogSessionError {}

// Stores controller and certificate index records through one closed private shape.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NodeWatchdogSessionDatabaseRecord {
    record_id: String,
    record_kind: String,
    controller_id: String,
    certificate_sha256: String,
    session_generation: u64,
    target_placement_group_id: String,
    target_placement_id: String,
    protected_target_sha256: String,
    state: String,
}

impl DatabaseRecord for NodeWatchdogSessionDatabaseRecord {
    const COLLECTION: DatabaseCollection = DatabaseCollection::Configuration;

    // Returns the controller or certificate-scoped private record identity.
    fn identifier(&self) -> &str {
        &self.record_id
    }
}

// Retains one decoded certificate index together with its independent revision.
struct VersionedCertificateRecord {
    session: NodeWatchdogSession,
    revision: u64,
}

// Owns durable Watchdog controller authorization and exact target resolution.
pub struct NodeWatchdogSessionAuthority {
    database: Arc<DatabaseManager>,
    targets: Arc<dyn NodeWatchdogTargetProvider>,
}

impl NodeWatchdogSessionAuthority {
    // Creates one authority over the shared DatabaseManager and explicit target resolver.
    pub const fn new(
        database: Arc<DatabaseManager>,
        targets: Arc<dyn NodeWatchdogTargetProvider>,
    ) -> Self {
        Self { database, targets }
    }

    // Returns whether composition supplied this exact shared DatabaseManager authority.
    pub fn uses_database(&self, database: &Arc<DatabaseManager>) -> bool {
        Arc::ptr_eq(&self.database, database)
    }

    // Creates generation one and its exact certificate index atomically.
    pub fn create(
        &self,
        idempotency_key: &str,
        mut session: NodeWatchdogSession,
    ) -> Result<VersionedNodeWatchdogSession, NodeWatchdogSessionError> {
        if session.state() != NodeWatchdogSessionState::Active
            || session.session_generation().get() != 1
        {
            return Err(NodeWatchdogSessionError::InvalidContract);
        }
        let protected = self
            .targets
            .active_target(session.target())
            .map_err(NodeWatchdogSessionError::Target)?;
        session.bind_target(&protected)?;
        let transaction = DatabaseTransaction::new(idempotency_key)
            .map_err(database_error)?
            .save(controller_record(&session)?, DatabaseRevision::Missing)
            .map_err(database_error)?
            .save(certificate_record(&session)?, DatabaseRevision::Missing)
            .map_err(database_error)?;
        let result = self
            .database
            .write_transaction(transaction)
            .map_err(database_error)?;
        validate_commits(
            result.disposition(),
            result.commit().commits(),
            &session,
            session.certificate_sha256(),
            1,
            1,
            None,
        )?;
        Ok(VersionedNodeWatchdogSession::new(session, 1))
    }

    // Advances exactly one active generation for target change or certificate rotation.
    pub fn replace(
        &self,
        idempotency_key: &str,
        mut replacement: NodeWatchdogSession,
        expected_revision: u64,
    ) -> Result<VersionedNodeWatchdogSession, NodeWatchdogSessionError> {
        if replacement.state() == NodeWatchdogSessionState::Active {
            let protected = self
                .targets
                .active_target(replacement.target())
                .map_err(NodeWatchdogSessionError::Target)?;
            replacement.bind_target(&protected)?;
        }
        let current = self
            .read(replacement.controller_id())?
            .ok_or(NodeWatchdogSessionError::NotFound)?;
        if current.session() == &replacement
            && current.revision() == expected_revision.checked_add(1).unwrap_or(0)
        {
            return Ok(current);
        }
        if current.revision() != expected_revision
            || current.session().state() != NodeWatchdogSessionState::Active
            || replacement.controller_id() != current.session().controller_id()
            || replacement.session_generation().get()
                != current
                    .session()
                    .session_generation()
                    .get()
                    .checked_add(1)
                    .unwrap_or(0)
            || (replacement.state() == NodeWatchdogSessionState::Revoked
                && (replacement.certificate_sha256() != current.session().certificate_sha256()
                    || replacement.target() != current.session().target()))
        {
            return Err(NodeWatchdogSessionError::Conflict);
        }
        if replacement.protected_target_sha256().is_none() {
            return Err(NodeWatchdogSessionError::Corrupt);
        }
        let old_certificate = self
            .read_certificate(current.session().certificate_sha256())?
            .ok_or(NodeWatchdogSessionError::Corrupt)?;
        if old_certificate.session != *current.session()
            || old_certificate.session.state() != NodeWatchdogSessionState::Active
        {
            return Err(NodeWatchdogSessionError::Corrupt);
        }
        let rotating = replacement.certificate_sha256() != current.session().certificate_sha256();
        if rotating
            && self
                .read_certificate(replacement.certificate_sha256())?
                .is_some()
        {
            return Err(NodeWatchdogSessionError::Conflict);
        }
        let transaction = DatabaseTransaction::new(idempotency_key)
            .map_err(database_error)?
            .save(
                controller_record(&replacement)?,
                DatabaseRevision::Exact(expected_revision),
            )
            .map_err(database_error)?;
        let transaction = if rotating {
            let retired = NodeWatchdogSession {
                controller_id: current.session().controller_id().clone(),
                certificate_sha256: current.session().certificate_sha256().clone(),
                session_generation: replacement.session_generation(),
                target: replacement.target().clone(),
                protected_target_sha256: replacement.protected_target_sha256().cloned(),
                state: NodeWatchdogSessionState::Revoked,
            };
            transaction
                .save(
                    certificate_record(&retired)?,
                    DatabaseRevision::Exact(old_certificate.revision),
                )
                .map_err(database_error)?
                .save(certificate_record(&replacement)?, DatabaseRevision::Missing)
                .map_err(database_error)?
        } else {
            transaction
                .save(
                    certificate_record(&replacement)?,
                    DatabaseRevision::Exact(old_certificate.revision),
                )
                .map_err(database_error)?
        };
        let result = self
            .database
            .write_transaction(transaction)
            .map_err(database_error)?;
        let next_revision = expected_revision
            .checked_add(1)
            .ok_or(NodeWatchdogSessionError::Conflict)?;
        validate_commits(
            result.disposition(),
            result.commit().commits(),
            &replacement,
            current.session().certificate_sha256(),
            next_revision,
            old_certificate.revision.saturating_add(1),
            rotating.then_some(1),
        )?;
        Ok(VersionedNodeWatchdogSession::new(
            replacement,
            next_revision,
        ))
    }

    // Revokes one active controller by advancing to its exact terminal generation.
    pub fn revoke(
        &self,
        idempotency_key: &str,
        controller_id: &NodeWatchdogControllerId,
        expected_revision: u64,
    ) -> Result<VersionedNodeWatchdogSession, NodeWatchdogSessionError> {
        let current = self
            .read(controller_id)?
            .ok_or(NodeWatchdogSessionError::NotFound)?;
        if current.session().state() == NodeWatchdogSessionState::Revoked
            && current.revision() == expected_revision.checked_add(1).unwrap_or(0)
        {
            return Ok(current);
        }
        let next = NonZeroU64::new(
            current
                .session()
                .session_generation()
                .get()
                .checked_add(1)
                .ok_or(NodeWatchdogSessionError::Conflict)?,
        )
        .ok_or(NodeWatchdogSessionError::Conflict)?;
        self.replace(
            idempotency_key,
            current.session().revoked(next)?,
            expected_revision,
        )
    }

    // Reads one exact controller record without scanning heterogeneous configuration state.
    pub fn read(
        &self,
        controller_id: &NodeWatchdogControllerId,
    ) -> Result<Option<VersionedNodeWatchdogSession>, NodeWatchdogSessionError> {
        match self
            .database
            .read(DatabaseQuery::<NodeWatchdogSessionDatabaseRecord>::record(
                controller_record_id(controller_id),
            )) {
            Ok(DatabaseResult::Record(stored)) => Ok(Some(VersionedNodeWatchdogSession::new(
                session_from_record(stored.value, "controller")?,
                stored.revision,
            ))),
            Ok(DatabaseResult::Records(_)) => Err(NodeWatchdogSessionError::Corrupt),
            Err(DatabaseError::NotFound { .. }) => Ok(None),
            Err(error) => Err(database_error(error)),
        }
    }

    // Reads one certificate index directly by authenticated leaf digest.
    fn read_certificate(
        &self,
        certificate_sha256: &Sha256Digest,
    ) -> Result<Option<VersionedCertificateRecord>, NodeWatchdogSessionError> {
        match self
            .database
            .read(DatabaseQuery::<NodeWatchdogSessionDatabaseRecord>::record(
                certificate_record_id(certificate_sha256),
            )) {
            Ok(DatabaseResult::Record(stored)) => Ok(Some(VersionedCertificateRecord {
                session: session_from_record(stored.value, "certificate")?,
                revision: stored.revision,
            })),
            Ok(DatabaseResult::Records(_)) => Err(NodeWatchdogSessionError::Corrupt),
            Err(DatabaseError::NotFound { .. }) => Ok(None),
            Err(error) => Err(database_error(error)),
        }
    }

    // Resolves one authenticated leaf through both exact durable indexes.
    fn binding(
        &self,
        certificate_sha256: &Sha256Digest,
    ) -> Result<WatchdogControllerBinding, NodeWatchdogSessionError> {
        let indexed = self
            .read_certificate(certificate_sha256)?
            .ok_or(NodeWatchdogSessionError::NotFound)?;
        if indexed.session.state() != NodeWatchdogSessionState::Active {
            return Err(NodeWatchdogSessionError::Revoked);
        }
        let current = self
            .read(indexed.session.controller_id())?
            .ok_or(NodeWatchdogSessionError::Corrupt)?;
        if current.session() != &indexed.session {
            return Err(NodeWatchdogSessionError::Corrupt);
        }
        let target = self
            .targets
            .active_target(indexed.session.target())
            .map_err(NodeWatchdogSessionError::Target)?;
        let observed_target_sha256 = protected_target_digest(&target)?;
        if indexed.session.protected_target_sha256() != Some(&observed_target_sha256) {
            return Err(NodeWatchdogSessionError::Target(
                NodeWatchdogTargetError::ReplacedProcess,
            ));
        }
        let protected = watchdog_target(&target)?;
        WatchdogControllerBinding::new(
            indexed.session.controller_id().as_str(),
            indexed.session.certificate_sha256().as_str(),
            indexed.session.session_generation().get(),
            protected,
        )
        .map_err(|_| NodeWatchdogSessionError::Corrupt)
    }

    // Resolves an already-authenticated binding back to its exact persisted target identity.
    pub fn target_for_binding(
        &self,
        binding: &WatchdogControllerBinding,
    ) -> Result<NodeWatchdogProtocolTarget, NodeWatchdogSessionError> {
        let certificate = Sha256Digest::parse(binding.certificate_sha256())
            .map_err(|_| NodeWatchdogSessionError::InvalidContract)?;
        let current = self.binding(&certificate)?;
        if &current != binding {
            return Err(NodeWatchdogSessionError::Conflict);
        }
        let key = self
            .read_certificate(&certificate)?
            .map(|record| record.session.target().clone())
            .ok_or(NodeWatchdogSessionError::NotFound)?;
        let protected = self
            .targets
            .active_target(&key)
            .map_err(NodeWatchdogSessionError::Target)?;
        Ok(NodeWatchdogProtocolTarget { key, protected })
    }
}

impl WatchdogControllerSessionProvider for NodeWatchdogSessionAuthority {
    // Resolves one verified leaf to its exact current controller, generation, and process.
    fn binding_for_certificate(
        &self,
        certificate_sha256: &str,
    ) -> Result<WatchdogControllerBinding, WatchdogError> {
        let certificate =
            Sha256Digest::parse(certificate_sha256).map_err(|_| watchdog_session_error())?;
        self.binding(&certificate)
            .map_err(|_| watchdog_session_error())
    }
}

impl NodeProtectionControllerBindingProvider for NodeWatchdogSessionAuthority {
    // Resolves one authenticated certificate while retaining stable redacted failure meaning.
    fn resolve(
        &self,
        certificate_sha256: &Sha256Digest,
    ) -> Result<WatchdogControllerBinding, NodeProtectionApiError> {
        self.binding(certificate_sha256)
            .map_err(protection_api_error)
    }
}

// Maps Node-owned session failures to the closed protection-channel failure vocabulary.
pub(crate) const fn protection_api_error(
    error: NodeWatchdogSessionError,
) -> NodeProtectionApiError {
    match error {
        NodeWatchdogSessionError::InvalidContract => NodeProtectionApiError::InvalidContract,
        NodeWatchdogSessionError::NotFound | NodeWatchdogSessionError::Revoked => {
            NodeProtectionApiError::AuthorizationDenied
        }
        NodeWatchdogSessionError::Conflict => NodeProtectionApiError::Conflict,
        NodeWatchdogSessionError::Corrupt => NodeProtectionApiError::Corrupt,
        NodeWatchdogSessionError::StoreUnavailable | NodeWatchdogSessionError::Target(_) => {
            NodeProtectionApiError::ProviderUnavailable
        }
    }
}

// Creates one controller-scoped private record only after process binding.
fn controller_record(
    session: &NodeWatchdogSession,
) -> Result<NodeWatchdogSessionDatabaseRecord, NodeWatchdogSessionError> {
    session_record(
        session,
        "controller",
        controller_record_id(session.controller_id()),
    )
}

// Creates one certificate-scoped private index record only after process binding.
fn certificate_record(
    session: &NodeWatchdogSession,
) -> Result<NodeWatchdogSessionDatabaseRecord, NodeWatchdogSessionError> {
    session_record(
        session,
        "certificate",
        certificate_record_id(session.certificate_sha256()),
    )
}

// Projects one typed session into the shared closed private record shape.
fn session_record(
    session: &NodeWatchdogSession,
    record_kind: &str,
    record_id: String,
) -> Result<NodeWatchdogSessionDatabaseRecord, NodeWatchdogSessionError> {
    let protected_target_sha256 = session
        .protected_target_sha256()
        .ok_or(NodeWatchdogSessionError::Corrupt)?;
    Ok(NodeWatchdogSessionDatabaseRecord {
        record_id,
        record_kind: record_kind.to_string(),
        controller_id: session.controller_id().as_str().to_string(),
        certificate_sha256: session.certificate_sha256().as_str().to_string(),
        session_generation: session.session_generation().get(),
        target_placement_group_id: session.target().placement_group_id().as_str().to_string(),
        target_placement_id: session.target().placement_id().as_str().to_string(),
        protected_target_sha256: protected_target_sha256.as_str().to_string(),
        state: session_state_name(session.state()).to_string(),
    })
}

// Reconstructs one session only when record kind and derived identity agree exactly.
fn session_from_record(
    record: NodeWatchdogSessionDatabaseRecord,
    expected_kind: &str,
) -> Result<NodeWatchdogSession, NodeWatchdogSessionError> {
    if record.record_kind != expected_kind {
        return Err(NodeWatchdogSessionError::Corrupt);
    }
    let controller_id = NodeWatchdogControllerId::parse(&record.controller_id)?;
    let certificate_sha256 = Sha256Digest::parse(&record.certificate_sha256)
        .map_err(|_| NodeWatchdogSessionError::Corrupt)?;
    let expected_id = match expected_kind {
        "controller" => controller_record_id(&controller_id),
        "certificate" => certificate_record_id(&certificate_sha256),
        _ => return Err(NodeWatchdogSessionError::Corrupt),
    };
    if record.record_id != expected_id {
        return Err(NodeWatchdogSessionError::Corrupt);
    }
    Ok(NodeWatchdogSession {
        controller_id,
        certificate_sha256,
        session_generation: NonZeroU64::new(record.session_generation)
            .ok_or(NodeWatchdogSessionError::Corrupt)?,
        target: NodeWatchdogTargetKey::new(
            PlacementGroupId::parse(&record.target_placement_group_id)
                .map_err(|_| NodeWatchdogSessionError::Corrupt)?,
            PlacementId::parse(&record.target_placement_id)
                .map_err(|_| NodeWatchdogSessionError::Corrupt)?,
        ),
        protected_target_sha256: Some(
            Sha256Digest::parse(&record.protected_target_sha256)
                .map_err(|_| NodeWatchdogSessionError::Corrupt)?,
        ),
        state: session_state(&record.state)?,
    })
}

// Converts one Placement-owned exact target into Watchdog's unchanged descriptor contract.
fn watchdog_target(
    target: &PlacementProtectedTarget,
) -> Result<WatchdogProtectedEngine, NodeWatchdogSessionError> {
    WatchdogProtectedEngine::parse(&protected_target_descriptor(target)?)
        .map_err(|_| NodeWatchdogSessionError::Corrupt)
}

// Hashes the exact process-bound descriptor identity pinned by one controller generation.
fn protected_target_digest(
    target: &PlacementProtectedTarget,
) -> Result<Sha256Digest, NodeWatchdogSessionError> {
    let descriptor = protected_target_descriptor(target)?;
    let digest = Sha256::digest(descriptor.as_bytes());
    Sha256Digest::parse(
        &digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    )
    .map_err(|_| NodeWatchdogSessionError::Corrupt)
}

// Returns the canonical descriptor bytes shared by target hashing and Watchdog parsing.
fn protected_target_descriptor(
    target: &PlacementProtectedTarget,
) -> Result<String, NodeWatchdogSessionError> {
    let phase = match target.phase() {
        PlacementProtectionPhase::Starting => "starting",
        PlacementProtectionPhase::Armed => "armed",
        _ => return Err(NodeWatchdogSessionError::Corrupt),
    };
    let process = target.process();
    Ok(format!(
        "version=1\ngeneration={}\nphase={}\ncontainer_name={}\ncontainer_id={}\npid={}\nstart_ticks={}\nboot_id={}\ncgroup={}\n",
        target.generation().as_str(),
        phase,
        process.container_name().as_str(),
        process.container_id().as_str(),
        process.process_id(),
        process.process_start_ticks(),
        process.boot_id().as_str(),
        process.cgroup()
    ))
}

// Validates the exact ordered transaction result without accepting partial persistence.
fn validate_commits(
    disposition: DatabaseCommitDisposition,
    commits: &[li_database::DatabaseCommit],
    session: &NodeWatchdogSession,
    old_certificate_sha256: &Sha256Digest,
    controller_revision: u64,
    old_certificate_revision: u64,
    new_certificate_revision: Option<u64>,
) -> Result<(), NodeWatchdogSessionError> {
    let expected_count = if new_certificate_revision.is_some() {
        3
    } else {
        2
    };
    if !matches!(
        disposition,
        DatabaseCommitDisposition::Applied | DatabaseCommitDisposition::Replayed
    ) || commits.len() != expected_count
        || commits[0].collection != DatabaseCollection::Configuration
        || commits[0].identifier != controller_record_id(session.controller_id())
        || commits[0].revision != controller_revision
        || commits[1].collection != DatabaseCollection::Configuration
        || commits[1].identifier != certificate_record_id(old_certificate_sha256)
        || commits[1].revision != old_certificate_revision
    {
        return Err(NodeWatchdogSessionError::Corrupt);
    }
    if let Some(revision) = new_certificate_revision {
        if commits[2].collection != DatabaseCollection::Configuration
            || commits[2].identifier != certificate_record_id(session.certificate_sha256())
            || commits[2].revision != revision
        {
            return Err(NodeWatchdogSessionError::Corrupt);
        }
    } else if commits[1].identifier != certificate_record_id(session.certificate_sha256()) {
        return Err(NodeWatchdogSessionError::Corrupt);
    }
    Ok(())
}

// Returns the controller record identity without exposing physical database layout.
fn controller_record_id(controller_id: &NodeWatchdogControllerId) -> String {
    format!("{CONTROLLER_RECORD_PREFIX}{}", controller_id.as_str())
}

// Returns the direct certificate-index record identity.
fn certificate_record_id(certificate_sha256: &Sha256Digest) -> String {
    format!("{CERTIFICATE_RECORD_PREFIX}{}", certificate_sha256.as_str())
}

// Returns the stable private text for one session state.
fn session_state_name(state: NodeWatchdogSessionState) -> &'static str {
    match state {
        NodeWatchdogSessionState::Active => "active",
        NodeWatchdogSessionState::Revoked => "revoked",
    }
}

// Reconstructs one closed session state from private persistence.
fn session_state(value: &str) -> Result<NodeWatchdogSessionState, NodeWatchdogSessionError> {
    match value {
        "active" => Ok(NodeWatchdogSessionState::Active),
        "revoked" => Ok(NodeWatchdogSessionState::Revoked),
        _ => Err(NodeWatchdogSessionError::Corrupt),
    }
}

// Maps database conflicts distinctly while redacting every native persistence detail.
fn database_error(error: DatabaseError) -> NodeWatchdogSessionError {
    match error {
        DatabaseError::Conflict { .. } | DatabaseError::IdempotencyConflict { .. } => {
            NodeWatchdogSessionError::Conflict
        }
        DatabaseError::Corrupt { .. } => NodeWatchdogSessionError::Corrupt,
        _ => NodeWatchdogSessionError::StoreUnavailable,
    }
}

// Returns one stable Watchdog-facing resolver failure without peer or target identity.
fn watchdog_session_error() -> WatchdogError {
    WatchdogError::provider("controller session", "authorization is unavailable")
}
