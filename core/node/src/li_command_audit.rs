// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::sync::Arc;

use li_audit_manager::{
    AuditAction, AuditActor, AuditAppendRequest, AuditCorrelationId, AuditError, AuditEvent,
    AuditEventId, AuditExport, AuditExportLimit, AuditManager, AuditOrigin, AuditOriginInterface,
    AuditOutcome, AuditReason, AuditReplayId, AuditTarget, AuditVerification,
};
use li_core_interface::{NodeRole, Sha256Digest, TechnicalName};
use li_database::{
    DatabaseCollection, DatabaseCommand, DatabaseCommitDisposition, DatabaseError, DatabaseManager,
    DatabaseQuery, DatabaseRecord, DatabaseResult, DatabaseRevision,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const NODE_COMMAND_AUDIT_SESSION_SCHEMA_NAME: &str = "li_node_command_audit_session";
pub const NODE_COMMAND_AUDIT_SESSION_SCHEMA_VERSION: u32 = 1;
pub const NODE_AUDIT_EXPORT_MAXIMUM_BYTES: usize = 700 * 1024;
pub const NODE_AUDIT_EXPORT_MAXIMUM_EVENTS: usize = 10_000;

const MARKER_PREFIX: &str = "li_cli_audit_";
const MAXIMUM_TRANSITION_ATTEMPTS: usize = 8;

// Owns one complete manager-produced audit export under the private transport ceiling.
#[derive(Clone, Eq, PartialEq)]
pub struct NodeAuditExport {
    document: Vec<u8>,
    events: usize,
}

// Carries one manager-verified chain receipt across the private Node boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeAuditVerification {
    events: usize,
    checkpoints: usize,
    head_sha256: Sha256Digest,
}

impl NodeAuditVerification {
    // Projects one verification receipt produced by the existing AuditManager.
    pub(crate) fn from_manager(verification: AuditVerification) -> Self {
        Self {
            events: verification.events(),
            checkpoints: verification.checkpoints(),
            head_sha256: verification.head_sha256().clone(),
        }
    }

    // Reconstructs one bounded wire receipt without claiming to re-run verification locally.
    pub fn new(
        events: usize,
        checkpoints: usize,
        head_sha256: Sha256Digest,
    ) -> Result<Self, AuditError> {
        if events > NODE_AUDIT_EXPORT_MAXIMUM_EVENTS || checkpoints > events {
            return Err(AuditError::invalid(
                "node audit verification",
                "event or checkpoint count is invalid",
            ));
        }
        Ok(Self {
            events,
            checkpoints,
            head_sha256,
        })
    }

    // Returns the complete verified event count.
    pub const fn events(&self) -> usize {
        self.events
    }

    // Returns the complete verified checkpoint count.
    pub const fn checkpoints(&self) -> usize {
        self.checkpoints
    }

    // Returns the verified chain-head digest.
    pub const fn head_sha256(&self) -> &Sha256Digest {
        &self.head_sha256
    }
}

impl NodeAuditExport {
    // Creates one wire-decoded export only when its document and count remain bounded.
    pub fn new(document: Vec<u8>, events: usize) -> Result<Self, AuditError> {
        if document.is_empty()
            || document.len() > NODE_AUDIT_EXPORT_MAXIMUM_BYTES
            || events > NODE_AUDIT_EXPORT_MAXIMUM_EVENTS
            || std::str::from_utf8(&document).is_err()
        {
            return Err(AuditError::invalid(
                "node audit export",
                "document or event count exceeds the private API bound",
            ));
        }
        Ok(Self { document, events })
    }

    // Projects one already-bounded AuditManager document without re-encoding it.
    fn from_manager(export: AuditExport) -> Self {
        Self {
            document: export.bytes().to_vec(),
            events: export.events(),
        }
    }

    // Returns the exact canonical JSON document produced by AuditManager.
    pub fn document(&self) -> &[u8] {
        &self.document
    }

    // Returns the complete number of events encoded in the document.
    pub const fn events(&self) -> usize {
        self.events
    }
}

impl fmt::Debug for NodeAuditExport {
    // Avoids duplicating the complete audit document through diagnostic output.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NodeAuditExport")
            .field("document_bytes", &self.document.len())
            .field("events", &self.events)
            .finish()
    }
}

// Defines the existing AuditManager queries exposed through the private Node owner.
pub trait NodeAuditApiPort: Send + Sync {
    // Returns recent events under the caller-selected manager bound.
    fn list(&self, limit: usize) -> Result<Vec<AuditEvent>, AuditError>;

    // Returns one exact event by its stable identity.
    fn show(&self, event_id: &AuditEventId) -> Result<AuditEvent, AuditError>;

    // Verifies the complete chain without mutation.
    fn verify(&self) -> Result<NodeAuditVerification, AuditError>;

    // Returns one complete verified export under the private transport ceiling.
    fn export(&self) -> Result<NodeAuditExport, AuditError>;
}

// Names the three command-audit policies that require a Node-owned lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeCommandAuditPolicy {
    Success,
    Always,
    SensitiveRead,
}

impl NodeCommandAuditPolicy {
    // Returns the stable private persistence and wire name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Always => "always",
            Self::SensitiveRead => "sensitive_read",
        }
    }
}

// Preserves the registry-owned mutation class without command arguments.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeCommandAuditMutation {
    Read,
    Local,
    Node,
    Internal,
}

// Names the bounded resource classes that may be identified in a command audit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeCommandAuditTargetKind {
    Node,
    Model,
    ApiKey,
    Benchmark,
    AuditEvent,
    Core,
    Service,
}

impl NodeCommandAuditTargetKind {
    // Returns the stable wire and persistence name of this target class.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::Model => "model",
            Self::ApiKey => "api_key",
            Self::Benchmark => "benchmark",
            Self::AuditEvent => "audit_event",
            Self::Core => "core",
            Self::Service => "service",
        }
    }
}

// Binds one closed resource class to a validated non-secret identifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeCommandAuditTarget {
    kind: NodeCommandAuditTargetKind,
    identifier: String,
}

impl NodeCommandAuditTarget {
    // Creates one unambiguous target without accepting separator aliases or secret-shaped text.
    pub fn new(
        kind: NodeCommandAuditTargetKind,
        identifier: &str,
    ) -> Result<Self, NodeCommandAuditError> {
        if identifier.contains(':') || AuditTarget::parse(identifier).is_err() {
            return Err(NodeCommandAuditError::InvalidRequest);
        }
        Ok(Self {
            kind,
            identifier: identifier.to_string(),
        })
    }

    // Returns the closed resource class.
    pub const fn kind(&self) -> NodeCommandAuditTargetKind {
        self.kind
    }

    // Returns the validated identifier without its wire class.
    pub fn identifier(&self) -> &str {
        &self.identifier
    }

    // Creates the canonical AuditManager target projection.
    fn audit_target(&self) -> Result<AuditTarget, NodeCommandAuditError> {
        AuditTarget::parse(&format!("{}:{}", self.kind.as_str(), self.identifier))
            .map_err(|_| NodeCommandAuditError::InvalidRequest)
    }
}

impl NodeCommandAuditMutation {
    // Returns the stable private persistence and wire name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Local => "local",
            Self::Node => "node",
            Self::Internal => "internal",
        }
    }
}

// Carries only the authorized action metadata required before command mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeCommandAuditIntent {
    action: TechnicalName,
    target: Option<NodeCommandAuditTarget>,
    policy: NodeCommandAuditPolicy,
    mutation: NodeCommandAuditMutation,
    local_role: NodeRole,
}

impl NodeCommandAuditIntent {
    // Creates one secret-free authorized command intent.
    pub const fn new(
        action: TechnicalName,
        policy: NodeCommandAuditPolicy,
        mutation: NodeCommandAuditMutation,
        local_role: NodeRole,
    ) -> Self {
        Self {
            action,
            target: None,
            policy,
            mutation,
            local_role,
        }
    }

    // Returns the exact canonical command action.
    pub const fn action(&self) -> &TechnicalName {
        &self.action
    }

    // Adds one already-validated non-secret target identity when the command has one.
    pub fn with_target(mut self, target: NodeCommandAuditTarget) -> Self {
        self.target = Some(target);
        self
    }

    // Returns the explicit stable target identity when the command supplied one.
    pub const fn target(&self) -> Option<&NodeCommandAuditTarget> {
        self.target.as_ref()
    }

    // Returns the registry-selected audit policy.
    pub const fn policy(&self) -> NodeCommandAuditPolicy {
        self.policy
    }

    // Returns the registry-selected mutation class.
    pub const fn mutation(&self) -> NodeCommandAuditMutation {
        self.mutation
    }

    // Returns the local role already used to authorize the command.
    pub const fn local_role(&self) -> NodeRole {
        self.local_role
    }
}

// Opens one replay-safe lifecycle under the private transport request identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeCommandAuditOpenRequest {
    command_id: Sha256Digest,
    intent: NodeCommandAuditIntent,
}

impl NodeCommandAuditOpenRequest {
    // Creates one command identity and intent pair without accepting caller text.
    pub const fn new(command_id: Sha256Digest, intent: NodeCommandAuditIntent) -> Self {
        Self { command_id, intent }
    }

    // Returns the exact private request identity reused for durable replay.
    pub const fn command_id(&self) -> &Sha256Digest {
        &self.command_id
    }

    // Returns the complete secret-free command intent.
    pub const fn intent(&self) -> &NodeCommandAuditIntent {
        &self.intent
    }
}

// Holds one opaque intent-bound lifecycle marker.
#[derive(Clone, Eq, PartialEq)]
pub struct NodeCommandAuditMarker {
    value: String,
    command_id: Sha256Digest,
    binding: Sha256Digest,
}

impl NodeCommandAuditMarker {
    // Parses one exact marker without retaining rejected text in an error.
    pub fn parse(value: &str) -> Result<Self, NodeCommandAuditError> {
        let body = value
            .strip_prefix(MARKER_PREFIX)
            .ok_or(NodeCommandAuditError::InvalidRequest)?;
        let (command_id, binding) = body
            .split_once('_')
            .ok_or(NodeCommandAuditError::InvalidRequest)?;
        if binding.contains('_') {
            return Err(NodeCommandAuditError::InvalidRequest);
        }
        Ok(Self {
            value: value.to_string(),
            command_id: Sha256Digest::parse(command_id)
                .map_err(|_| NodeCommandAuditError::InvalidRequest)?,
            binding: Sha256Digest::parse(binding)
                .map_err(|_| NodeCommandAuditError::InvalidRequest)?,
        })
    }

    // Returns the complete opaque value only for transport and matching completion.
    pub fn as_str(&self) -> &str {
        &self.value
    }

    // Returns the durable session identity embedded in this marker.
    pub const fn command_id(&self) -> &Sha256Digest {
        &self.command_id
    }

    // Returns the exact intent binding only for coordinator integrity checks.
    const fn binding(&self) -> &Sha256Digest {
        &self.binding
    }
}

impl fmt::Debug for NodeCommandAuditMarker {
    // Redacts the complete replay identity from ordinary diagnostics.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NodeCommandAuditMarker(<redacted>)")
    }
}

// Names every terminal command outcome carried to the Node audit owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeCommandAuditOutcome {
    Succeeded,
    Failed,
    Denied,
    Cancelled,
}

impl NodeCommandAuditOutcome {
    // Returns the stable private persistence and wire name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Denied => "denied",
            Self::Cancelled => "cancelled",
        }
    }
}

// Carries one terminal action and a normalized non-secret failure reason.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeCommandAuditResult {
    action: TechnicalName,
    outcome: NodeCommandAuditOutcome,
    reason: Option<AuditReason>,
}

impl NodeCommandAuditResult {
    // Creates one terminal result while replacing invalid failure text with a closed reason.
    pub fn new(
        action: TechnicalName,
        outcome: NodeCommandAuditOutcome,
        failure_code: Option<&str>,
    ) -> Result<Self, NodeCommandAuditError> {
        let reason = match outcome {
            NodeCommandAuditOutcome::Succeeded => {
                if failure_code.is_some() {
                    return Err(NodeCommandAuditError::InvalidRequest);
                }
                None
            }
            NodeCommandAuditOutcome::Denied => {
                Some(normalized_reason(failure_code, "command_denied")?)
            }
            NodeCommandAuditOutcome::Failed => {
                Some(normalized_reason(failure_code, "command_failed")?)
            }
            NodeCommandAuditOutcome::Cancelled => {
                Some(normalized_reason(failure_code, "command_cancelled")?)
            }
        };
        Ok(Self {
            action,
            outcome,
            reason,
        })
    }

    // Returns the exact action that reached a terminal result.
    pub const fn action(&self) -> &TechnicalName {
        &self.action
    }

    // Returns the exact terminal lifecycle outcome.
    pub const fn outcome(&self) -> NodeCommandAuditOutcome {
        self.outcome
    }

    // Returns only the normalized durable reason identity.
    pub fn failure_code(&self) -> Option<&str> {
        self.reason.as_ref().map(AuditReason::as_str)
    }
}

// Completes one previously opened marker without copying the original command arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeCommandAuditCompletionRequest {
    marker: NodeCommandAuditMarker,
    result: NodeCommandAuditResult,
}

impl NodeCommandAuditCompletionRequest {
    // Creates one exact marker and terminal-result pair.
    pub const fn new(marker: NodeCommandAuditMarker, result: NodeCommandAuditResult) -> Self {
        Self { marker, result }
    }

    // Returns the opaque opened marker.
    pub const fn marker(&self) -> &NodeCommandAuditMarker {
        &self.marker
    }

    // Returns the complete normalized terminal result.
    pub const fn result(&self) -> &NodeCommandAuditResult {
        &self.result
    }
}

// Distinguishes a new open from the exact response replayed after delivery uncertainty.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeCommandAuditOpenDisposition {
    Opened,
    Replayed,
}

// Returns the intent-bound marker and its exact open disposition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeCommandAuditOpenReceipt {
    marker: NodeCommandAuditMarker,
    disposition: NodeCommandAuditOpenDisposition,
}

impl NodeCommandAuditOpenReceipt {
    // Creates one validated open receipt from coordinator-owned values.
    pub const fn new(
        marker: NodeCommandAuditMarker,
        disposition: NodeCommandAuditOpenDisposition,
    ) -> Self {
        Self {
            marker,
            disposition,
        }
    }

    // Returns the opaque marker required for terminal completion.
    pub const fn marker(&self) -> &NodeCommandAuditMarker {
        &self.marker
    }

    // Returns whether this call created or replayed the exact open session.
    pub const fn disposition(&self) -> NodeCommandAuditOpenDisposition {
        self.disposition
    }
}

// Distinguishes one newly completed lifecycle from an exact durable replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeCommandAuditCompletionDisposition {
    Completed,
    Replayed,
}

// Returns the optional durable event identity and exact completion disposition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeCommandAuditCompletionReceipt {
    event_id: Option<AuditEventId>,
    disposition: NodeCommandAuditCompletionDisposition,
}

impl NodeCommandAuditCompletionReceipt {
    // Creates one terminal receipt after the session journal is durably complete.
    pub const fn new(
        event_id: Option<AuditEventId>,
        disposition: NodeCommandAuditCompletionDisposition,
    ) -> Self {
        Self {
            event_id,
            disposition,
        }
    }

    // Returns the appended audit event when this policy and outcome require one.
    pub const fn event_id(&self) -> Option<&AuditEventId> {
        self.event_id.as_ref()
    }

    // Returns whether this call completed or replayed the exact terminal state.
    pub const fn disposition(&self) -> NodeCommandAuditCompletionDisposition {
        self.disposition
    }
}

// Describes one closed Node-owned command-audit failure without provider diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeCommandAuditError {
    InvalidRequest,
    UnknownMarker,
    Conflict,
    Corrupt,
    Unavailable,
}

impl fmt::Display for NodeCommandAuditError {
    // Presents stable secret-free command-audit language.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest => formatter.write_str("command audit request is invalid"),
            Self::UnknownMarker => formatter.write_str("command audit marker is unknown"),
            Self::Conflict => formatter.write_str("command audit lifecycle conflicts"),
            Self::Corrupt => formatter.write_str("command audit state is corrupt"),
            Self::Unavailable => formatter.write_str("command audit is unavailable"),
        }
    }
}

impl Error for NodeCommandAuditError {}

// Supplies the two Node-owned lifecycle operations consumed by the private API.
pub trait NodeCommandAuditApiPort: Send + Sync {
    // Opens or exactly replays one intent before command mutation begins.
    fn open(
        &self,
        request: NodeCommandAuditOpenRequest,
    ) -> Result<NodeCommandAuditOpenReceipt, NodeCommandAuditError>;

    // Claims, records, and completes one terminal result exactly once.
    fn complete(
        &self,
        request: NodeCommandAuditCompletionRequest,
    ) -> Result<NodeCommandAuditCompletionReceipt, NodeCommandAuditError>;
}

// Stores one validated session phase for restart-safe terminal completion.
#[derive(Clone, Debug, Eq, PartialEq)]
enum NodeCommandAuditSessionState {
    Open,
    Completing(NodeCommandAuditResult),
    Completed {
        result: NodeCommandAuditResult,
        event_id: Option<AuditEventId>,
    },
}

// Binds one request identity to its exact intent, marker, and terminal phase.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeCommandAuditSession {
    command_id: Sha256Digest,
    intent: NodeCommandAuditIntent,
    marker: NodeCommandAuditMarker,
    state: NodeCommandAuditSessionState,
}

impl NodeCommandAuditSession {
    // Creates one open durable session after marker binding succeeds.
    fn open(
        command_id: Sha256Digest,
        intent: NodeCommandAuditIntent,
        marker: NodeCommandAuditMarker,
    ) -> Self {
        Self {
            command_id,
            intent,
            marker,
            state: NodeCommandAuditSessionState::Open,
        }
    }

    // Returns a copy claimed for one exact terminal result.
    fn completing(&self, result: NodeCommandAuditResult) -> Self {
        Self {
            command_id: self.command_id.clone(),
            intent: self.intent.clone(),
            marker: self.marker.clone(),
            state: NodeCommandAuditSessionState::Completing(result),
        }
    }

    // Returns a copy durably completed with the policy-selected event identity.
    fn completed(&self, result: NodeCommandAuditResult, event_id: Option<AuditEventId>) -> Self {
        Self {
            command_id: self.command_id.clone(),
            intent: self.intent.clone(),
            marker: self.marker.clone(),
            state: NodeCommandAuditSessionState::Completed { result, event_id },
        }
    }
}

// Carries one optimistic durable session revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionedNodeCommandAuditSession {
    session: NodeCommandAuditSession,
    revision: u64,
}

impl VersionedNodeCommandAuditSession {
    // Creates one store-owned session observation.
    const fn new(session: NodeCommandAuditSession, revision: u64) -> Self {
        Self { session, revision }
    }

    // Returns the complete validated session for deterministic store tests.
    pub const fn session(&self) -> &NodeCommandAuditSession {
        &self.session
    }

    // Returns the optimistic persistence revision observed with this session.
    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

// Isolates durable session persistence from Node command-audit policy.
pub trait NodeCommandAuditSessionStore: Send + Sync {
    // Returns one exact session when it exists.
    fn read(
        &self,
        command_id: &Sha256Digest,
    ) -> Result<Option<VersionedNodeCommandAuditSession>, NodeCommandAuditError>;

    // Creates one previously absent session.
    fn create(
        &self,
        session: NodeCommandAuditSession,
    ) -> Result<VersionedNodeCommandAuditSession, NodeCommandAuditError>;

    // Replaces one exact observed revision.
    fn replace(
        &self,
        session: NodeCommandAuditSession,
        expected_revision: u64,
    ) -> Result<VersionedNodeCommandAuditSession, NodeCommandAuditError>;
}

// Owns the Node-resident begin/complete lifecycle over the durable audit chain and session store.
pub struct NodeCommandAuditCoordinator {
    manager: Arc<AuditManager>,
    store: Arc<dyn NodeCommandAuditSessionStore>,
    actor: AuditActor,
    origin: AuditOrigin,
}

impl NodeCommandAuditCoordinator {
    // Creates one coordinator only when its CLI origin belongs to the exact audit ledger.
    pub fn new(
        manager: Arc<AuditManager>,
        store: Arc<dyn NodeCommandAuditSessionStore>,
        actor: AuditActor,
        origin: AuditOrigin,
    ) -> Result<Self, NodeCommandAuditError> {
        if origin.node_id() != manager.node_id() || origin.interface() != AuditOriginInterface::Cli
        {
            return Err(NodeCommandAuditError::InvalidRequest);
        }
        Ok(Self {
            manager,
            store,
            actor,
            origin,
        })
    }

    // Returns one existing exact open replay or rejects every divergent/terminal reuse.
    fn open_replay(
        &self,
        request: &NodeCommandAuditOpenRequest,
        marker: &NodeCommandAuditMarker,
        existing: VersionedNodeCommandAuditSession,
    ) -> Result<NodeCommandAuditOpenReceipt, NodeCommandAuditError> {
        if existing.session.command_id != *request.command_id()
            || existing.session.intent != *request.intent()
            || existing.session.marker != *marker
            || !matches!(existing.session.state, NodeCommandAuditSessionState::Open)
        {
            return Err(NodeCommandAuditError::Conflict);
        }
        Ok(NodeCommandAuditOpenReceipt::new(
            marker.clone(),
            NodeCommandAuditOpenDisposition::Replayed,
        ))
    }

    // Claims one exact result before any policy-selected append can occur.
    fn claim(
        &self,
        marker: &NodeCommandAuditMarker,
        result: &NodeCommandAuditResult,
    ) -> Result<(VersionedNodeCommandAuditSession, bool), NodeCommandAuditError> {
        for _attempt in 0..MAXIMUM_TRANSITION_ATTEMPTS {
            let current = self
                .store
                .read(marker.command_id())?
                .ok_or(NodeCommandAuditError::UnknownMarker)?;
            if current.session.marker != *marker
                || current.session.intent.action() != result.action()
                || marker.binding()
                    != marker_for(&current.session.command_id, &current.session.intent)?.binding()
                || marker_for(&current.session.command_id, &current.session.intent)? != *marker
            {
                return Err(NodeCommandAuditError::Conflict);
            }
            match &current.session.state {
                NodeCommandAuditSessionState::Open => {
                    let completing = current.session.completing(result.clone());
                    match self.store.replace(completing, current.revision) {
                        Ok(claimed) => return Ok((claimed, true)),
                        Err(NodeCommandAuditError::Conflict) => continue,
                        Err(error) => return Err(error),
                    }
                }
                NodeCommandAuditSessionState::Completing(existing) if existing == result => {
                    return Ok((current, false))
                }
                NodeCommandAuditSessionState::Completed {
                    result: existing,
                    event_id,
                } if existing == result => {
                    self.verify_completed(&current.session, existing, event_id.as_ref())?;
                    return Ok((current, false));
                }
                NodeCommandAuditSessionState::Completing(_)
                | NodeCommandAuditSessionState::Completed { .. } => {
                    return Err(NodeCommandAuditError::Conflict)
                }
            }
        }
        Err(NodeCommandAuditError::Conflict)
    }

    // Replays the durable append or ledger verification for one completed session.
    fn verify_completed(
        &self,
        session: &NodeCommandAuditSession,
        result: &NodeCommandAuditResult,
        event_id: Option<&AuditEventId>,
    ) -> Result<(), NodeCommandAuditError> {
        if should_append(session.intent.policy(), result.outcome()) {
            let receipt = self
                .manager
                .append(self.append_request(session, result)?)
                .map_err(|_| NodeCommandAuditError::Unavailable)?;
            if Some(receipt.entry().event().event_id()) != event_id {
                return Err(NodeCommandAuditError::Corrupt);
            }
        } else {
            self.manager
                .verify()
                .map_err(|_| NodeCommandAuditError::Unavailable)?;
            if event_id.is_some() {
                return Err(NodeCommandAuditError::Corrupt);
            }
        }
        Ok(())
    }

    // Creates one exact idempotent AuditManager append request from a claimed session.
    fn append_request(
        &self,
        session: &NodeCommandAuditSession,
        result: &NodeCommandAuditResult,
    ) -> Result<AuditAppendRequest, NodeCommandAuditError> {
        let (outcome, reason) = match result.outcome() {
            NodeCommandAuditOutcome::Succeeded => (AuditOutcome::Success, None),
            NodeCommandAuditOutcome::Denied => (AuditOutcome::Denied, result.reason.clone()),
            NodeCommandAuditOutcome::Failed | NodeCommandAuditOutcome::Cancelled => {
                (AuditOutcome::Failed, result.reason.clone())
            }
        };
        let binding = binding_for(&session.command_id, &session.intent)?;
        AuditAppendRequest::new(
            AuditReplayId::parse(&format!("li_cli_{}", binding.as_str()))
                .map_err(|_| NodeCommandAuditError::Corrupt)?,
            AuditCorrelationId::parse(&binding.as_str()[..32])
                .map_err(|_| NodeCommandAuditError::Corrupt)?,
            self.actor.clone(),
            self.origin.clone(),
            AuditAction::parse(session.intent.action().as_str())
                .map_err(|_| NodeCommandAuditError::Corrupt)?,
            match session.intent.target() {
                Some(target) => target.audit_target(),
                None => {
                    AuditTarget::parse("local-node").map_err(|_| NodeCommandAuditError::Corrupt)
                }
            }?,
            None,
            None,
            outcome,
            reason,
        )
        .map_err(|_| NodeCommandAuditError::Corrupt)
    }
}

impl NodeAuditApiPort for NodeCommandAuditCoordinator {
    // Returns recent events through the coordinator's existing AuditManager owner.
    fn list(&self, limit: usize) -> Result<Vec<AuditEvent>, AuditError> {
        self.manager.list(limit)
    }

    // Returns one exact event through the coordinator's existing AuditManager owner.
    fn show(&self, event_id: &AuditEventId) -> Result<AuditEvent, AuditError> {
        self.manager.show(event_id)
    }

    // Verifies the complete audit chain through its existing manager.
    fn verify(&self) -> Result<NodeAuditVerification, AuditError> {
        self.manager
            .verify()
            .map(NodeAuditVerification::from_manager)
    }

    // Produces one complete verified document under the private wire ceiling.
    fn export(&self) -> Result<NodeAuditExport, AuditError> {
        let limit = AuditExportLimit::new(
            NODE_AUDIT_EXPORT_MAXIMUM_EVENTS,
            NODE_AUDIT_EXPORT_MAXIMUM_BYTES,
        )?;
        self.manager
            .export(limit)
            .map(NodeAuditExport::from_manager)
    }
}

impl NodeCommandAuditApiPort for NodeCommandAuditCoordinator {
    // Verifies the complete chain and durably opens or replays one exact intent.
    fn open(
        &self,
        request: NodeCommandAuditOpenRequest,
    ) -> Result<NodeCommandAuditOpenReceipt, NodeCommandAuditError> {
        self.manager
            .verify()
            .map_err(|_| NodeCommandAuditError::Unavailable)?;
        let marker = marker_for(request.command_id(), request.intent())?;
        if let Some(existing) = self.store.read(request.command_id())? {
            return self.open_replay(&request, &marker, existing);
        }
        let session = NodeCommandAuditSession::open(
            request.command_id().clone(),
            request.intent().clone(),
            marker.clone(),
        );
        match self.store.create(session) {
            Ok(_) => Ok(NodeCommandAuditOpenReceipt::new(
                marker,
                NodeCommandAuditOpenDisposition::Opened,
            )),
            Err(NodeCommandAuditError::Conflict) => {
                let existing = self
                    .store
                    .read(request.command_id())?
                    .ok_or(NodeCommandAuditError::Conflict)?;
                self.open_replay(&request, &marker, existing)
            }
            Err(error) => Err(error),
        }
    }

    // Claims the result, resumes any interrupted append, and durably closes the session.
    fn complete(
        &self,
        request: NodeCommandAuditCompletionRequest,
    ) -> Result<NodeCommandAuditCompletionReceipt, NodeCommandAuditError> {
        let (claimed, newly_claimed) = self.claim(request.marker(), request.result())?;
        if let NodeCommandAuditSessionState::Completed { result, event_id } = &claimed.session.state
        {
            if result != request.result() {
                return Err(NodeCommandAuditError::Conflict);
            }
            return Ok(NodeCommandAuditCompletionReceipt::new(
                event_id.clone(),
                NodeCommandAuditCompletionDisposition::Replayed,
            ));
        }
        let event_id = if should_append(claimed.session.intent.policy(), request.result().outcome())
        {
            Some(
                self.manager
                    .append(self.append_request(&claimed.session, request.result())?)
                    .map_err(|_| NodeCommandAuditError::Unavailable)?
                    .entry()
                    .event()
                    .event_id()
                    .clone(),
            )
        } else {
            self.manager
                .verify()
                .map_err(|_| NodeCommandAuditError::Unavailable)?;
            None
        };
        for _attempt in 0..MAXIMUM_TRANSITION_ATTEMPTS {
            let current = self
                .store
                .read(request.marker().command_id())?
                .ok_or(NodeCommandAuditError::Corrupt)?;
            match &current.session.state {
                NodeCommandAuditSessionState::Completing(result) if result == request.result() => {
                    let completed = current
                        .session
                        .completed(request.result().clone(), event_id.clone());
                    match self.store.replace(completed, current.revision) {
                        Ok(_) => {
                            return Ok(NodeCommandAuditCompletionReceipt::new(
                                event_id,
                                if newly_claimed {
                                    NodeCommandAuditCompletionDisposition::Completed
                                } else {
                                    NodeCommandAuditCompletionDisposition::Replayed
                                },
                            ))
                        }
                        Err(NodeCommandAuditError::Conflict) => continue,
                        Err(error) => return Err(error),
                    }
                }
                NodeCommandAuditSessionState::Completed {
                    result,
                    event_id: existing_event,
                } if result == request.result() && existing_event == &event_id => {
                    return Ok(NodeCommandAuditCompletionReceipt::new(
                        event_id,
                        NodeCommandAuditCompletionDisposition::Replayed,
                    ))
                }
                _ => return Err(NodeCommandAuditError::Conflict),
            }
        }
        Err(NodeCommandAuditError::Conflict)
    }
}

// Stores the nested stable identity of one private command-audit session record.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CommandAuditDatabaseSchema {
    name: String,
    version: u32,
}

// Stores one closed restart-safe command-audit session without command arguments or messages.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CommandAuditDatabaseRecord {
    schema: CommandAuditDatabaseSchema,
    command_id: String,
    action: String,
    target_kind: Option<String>,
    target_identifier: Option<String>,
    policy: String,
    mutation: String,
    local_role: String,
    marker: String,
    phase: String,
    outcome: Option<String>,
    failure_code: Option<String>,
    event_id: Option<String>,
}

impl DatabaseRecord for CommandAuditDatabaseRecord {
    const COLLECTION: DatabaseCollection = DatabaseCollection::CommandAuditSessions;

    // Returns the private transport request identity that owns this lifecycle.
    fn identifier(&self) -> &str {
        &self.command_id
    }
}

// Persists command-audit sessions through DatabaseManager's serialized optimistic writer.
pub struct DatabaseNodeCommandAuditSessionStore {
    database: Arc<DatabaseManager>,
}

impl DatabaseNodeCommandAuditSessionStore {
    // Creates one adapter without taking shared database lifecycle ownership.
    pub const fn new(database: Arc<DatabaseManager>) -> Self {
        Self { database }
    }
}

impl NodeCommandAuditSessionStore for DatabaseNodeCommandAuditSessionStore {
    // Reads and reconstructs one exact durable command lifecycle.
    fn read(
        &self,
        command_id: &Sha256Digest,
    ) -> Result<Option<VersionedNodeCommandAuditSession>, NodeCommandAuditError> {
        match self
            .database
            .read(DatabaseQuery::<CommandAuditDatabaseRecord>::record(
                command_id.as_str(),
            )) {
            Ok(DatabaseResult::Record(stored)) => Ok(Some(VersionedNodeCommandAuditSession::new(
                session_from_record(stored.value)?,
                stored.revision,
            ))),
            Ok(DatabaseResult::Records(_)) => Err(NodeCommandAuditError::Corrupt),
            Err(DatabaseError::NotFound { .. }) => Ok(None),
            Err(error) => Err(database_error(error)),
        }
    }

    // Creates one open session under an exact missing-revision precondition.
    fn create(
        &self,
        session: NodeCommandAuditSession,
    ) -> Result<VersionedNodeCommandAuditSession, NodeCommandAuditError> {
        let result = self
            .database
            .write(DatabaseCommand::save(
                format!("command-audit:open:{}", session.command_id.as_str()),
                session_record(&session),
                DatabaseRevision::Missing,
            ))
            .map_err(database_error)?;
        if result.disposition() == DatabaseCommitDisposition::Replayed {
            return Err(NodeCommandAuditError::Conflict);
        }
        Ok(VersionedNodeCommandAuditSession::new(
            session,
            result.commit().revision,
        ))
    }

    // Replaces one exact phase revision through a deterministic replay identity.
    fn replace(
        &self,
        session: NodeCommandAuditSession,
        expected_revision: u64,
    ) -> Result<VersionedNodeCommandAuditSession, NodeCommandAuditError> {
        let result = self
            .database
            .write(DatabaseCommand::save(
                format!(
                    "command-audit:{}:{}:{expected_revision}",
                    session.command_id.as_str(),
                    session_phase(&session.state)
                ),
                session_record(&session),
                DatabaseRevision::Exact(expected_revision),
            ))
            .map_err(database_error)?;
        Ok(VersionedNodeCommandAuditSession::new(
            session,
            result.commit().revision,
        ))
    }
}

// Projects one validated session into its closed private persistence fields.
fn session_record(session: &NodeCommandAuditSession) -> CommandAuditDatabaseRecord {
    let (outcome, failure_code, event_id) = match &session.state {
        NodeCommandAuditSessionState::Open => (None, None, None),
        NodeCommandAuditSessionState::Completing(result) => (
            Some(result.outcome().as_str().to_string()),
            result.failure_code().map(str::to_string),
            None,
        ),
        NodeCommandAuditSessionState::Completed { result, event_id } => (
            Some(result.outcome().as_str().to_string()),
            result.failure_code().map(str::to_string),
            event_id.as_ref().map(|value| value.as_str().to_string()),
        ),
    };
    CommandAuditDatabaseRecord {
        schema: CommandAuditDatabaseSchema {
            name: NODE_COMMAND_AUDIT_SESSION_SCHEMA_NAME.to_string(),
            version: NODE_COMMAND_AUDIT_SESSION_SCHEMA_VERSION,
        },
        command_id: session.command_id.as_str().to_string(),
        action: session.intent.action().as_str().to_string(),
        target_kind: session
            .intent
            .target()
            .map(|target| target.kind().as_str().to_string()),
        target_identifier: session
            .intent
            .target()
            .map(|target| target.identifier().to_string()),
        policy: session.intent.policy().as_str().to_string(),
        mutation: session.intent.mutation().as_str().to_string(),
        local_role: role_name(session.intent.local_role()).to_string(),
        marker: session.marker.as_str().to_string(),
        phase: session_phase(&session.state).to_string(),
        outcome,
        failure_code,
        event_id,
    }
}

// Reconstructs one validated session while rejecting every inconsistent field combination.
fn session_from_record(
    record: CommandAuditDatabaseRecord,
) -> Result<NodeCommandAuditSession, NodeCommandAuditError> {
    if record.schema.name != NODE_COMMAND_AUDIT_SESSION_SCHEMA_NAME
        || record.schema.version != NODE_COMMAND_AUDIT_SESSION_SCHEMA_VERSION
    {
        return Err(NodeCommandAuditError::Corrupt);
    }
    let command_id =
        Sha256Digest::parse(&record.command_id).map_err(|_| NodeCommandAuditError::Corrupt)?;
    let intent = NodeCommandAuditIntent::new(
        TechnicalName::parse(&record.action).map_err(|_| NodeCommandAuditError::Corrupt)?,
        policy(&record.policy)?,
        mutation(&record.mutation)?,
        role(&record.local_role)?,
    );
    let intent = match (record.target_kind, record.target_identifier) {
        (Some(kind), Some(identifier)) => intent.with_target(
            NodeCommandAuditTarget::new(target_kind(&kind)?, &identifier)
                .map_err(|_| NodeCommandAuditError::Corrupt)?,
        ),
        (None, None) => intent,
        _ => return Err(NodeCommandAuditError::Corrupt),
    };
    let marker = NodeCommandAuditMarker::parse(&record.marker)
        .map_err(|_| NodeCommandAuditError::Corrupt)?;
    if marker.command_id() != &command_id || marker_for(&command_id, &intent)? != marker {
        return Err(NodeCommandAuditError::Corrupt);
    }
    let result = match (record.outcome.as_deref(), record.failure_code.as_deref()) {
        (Some(outcome), failure) => {
            let result = NodeCommandAuditResult::new(
                intent.action().clone(),
                outcome_from_name(outcome)?,
                failure,
            )?;
            if result.failure_code() != failure {
                return Err(NodeCommandAuditError::Corrupt);
            }
            Some(result)
        }
        (None, None) => None,
        (None, Some(_)) => return Err(NodeCommandAuditError::Corrupt),
    };
    let event_id = record
        .event_id
        .map(|value| AuditEventId::parse(&value))
        .transpose()
        .map_err(|_| NodeCommandAuditError::Corrupt)?;
    let state = match (record.phase.as_str(), result, event_id) {
        ("open", None, None) => NodeCommandAuditSessionState::Open,
        ("completing", Some(result), None) => NodeCommandAuditSessionState::Completing(result),
        ("completed", Some(result), event_id)
            if should_append(intent.policy(), result.outcome()) == event_id.is_some() =>
        {
            NodeCommandAuditSessionState::Completed { result, event_id }
        }
        _ => return Err(NodeCommandAuditError::Corrupt),
    };
    Ok(NodeCommandAuditSession {
        command_id,
        intent,
        marker,
        state,
    })
}

// Creates one intent-bound marker without host path or native entropy discovery.
fn marker_for(
    command_id: &Sha256Digest,
    intent: &NodeCommandAuditIntent,
) -> Result<NodeCommandAuditMarker, NodeCommandAuditError> {
    let binding = binding_for(command_id, intent)?;
    NodeCommandAuditMarker::parse(&format!(
        "{MARKER_PREFIX}{}_{}",
        command_id.as_str(),
        binding.as_str()
    ))
}

// Hashes one closed length-prefixed intent so lexical concatenation cannot alias a marker.
fn binding_for(
    command_id: &Sha256Digest,
    intent: &NodeCommandAuditIntent,
) -> Result<Sha256Digest, NodeCommandAuditError> {
    let mut hasher = Sha256::new();
    for value in [
        "li_node_command_audit_v1",
        command_id.as_str(),
        intent.action().as_str(),
        intent
            .target()
            .map_or("<local-node>", |target| target.kind().as_str()),
        intent
            .target()
            .map_or("<none>", NodeCommandAuditTarget::identifier),
        intent.policy().as_str(),
        intent.mutation().as_str(),
        role_name(intent.local_role()),
    ] {
        let length =
            u64::try_from(value.len()).map_err(|_| NodeCommandAuditError::InvalidRequest)?;
        hasher.update(length.to_be_bytes());
        hasher.update(value.as_bytes());
    }
    let digest = hasher.finalize();
    Sha256Digest::parse(&hexadecimal(&digest)).map_err(|_| NodeCommandAuditError::Corrupt)
}

// Returns whether one policy and result requires a durable audit event.
const fn should_append(policy: NodeCommandAuditPolicy, outcome: NodeCommandAuditOutcome) -> bool {
    match policy {
        NodeCommandAuditPolicy::Success => matches!(outcome, NodeCommandAuditOutcome::Succeeded),
        NodeCommandAuditPolicy::Always | NodeCommandAuditPolicy::SensitiveRead => true,
    }
}

// Preserves a valid stable failure code or substitutes one closed generic reason.
fn normalized_reason(
    value: Option<&str>,
    fallback: &str,
) -> Result<AuditReason, NodeCommandAuditError> {
    value
        .filter(|value| !secret_shaped(value))
        .and_then(|value| AuditReason::parse(value).ok())
        .or_else(|| AuditReason::parse(fallback).ok())
        .ok_or(NodeCommandAuditError::InvalidRequest)
}

// Rejects common secret-bearing failure text before it can reach persistence or diagnostics.
fn secret_shaped(value: &str) -> bool {
    let lowercase = value.to_ascii_lowercase();
    lowercase.starts_with("bearer")
        || lowercase.starts_with("sk-")
        || lowercase.starts_with("li_")
        || lowercase.contains("secret")
        || lowercase.contains("token")
        || lowercase.contains("password")
        || lowercase.contains("credential")
        || lowercase.contains("private_key")
        || lowercase.contains("private-key")
        || lowercase.contains("-----begin")
}

// Returns the stable persistence phase name.
const fn session_phase(state: &NodeCommandAuditSessionState) -> &'static str {
    match state {
        NodeCommandAuditSessionState::Open => "open",
        NodeCommandAuditSessionState::Completing(_) => "completing",
        NodeCommandAuditSessionState::Completed { .. } => "completed",
    }
}

// Parses one exact persisted audit policy.
fn policy(value: &str) -> Result<NodeCommandAuditPolicy, NodeCommandAuditError> {
    match value {
        "success" => Ok(NodeCommandAuditPolicy::Success),
        "always" => Ok(NodeCommandAuditPolicy::Always),
        "sensitive_read" => Ok(NodeCommandAuditPolicy::SensitiveRead),
        _ => Err(NodeCommandAuditError::Corrupt),
    }
}

// Parses one exact persisted mutation class.
fn mutation(value: &str) -> Result<NodeCommandAuditMutation, NodeCommandAuditError> {
    match value {
        "read" => Ok(NodeCommandAuditMutation::Read),
        "local" => Ok(NodeCommandAuditMutation::Local),
        "node" => Ok(NodeCommandAuditMutation::Node),
        "internal" => Ok(NodeCommandAuditMutation::Internal),
        _ => Err(NodeCommandAuditError::Corrupt),
    }
}

// Parses one exact persisted command target class.
fn target_kind(value: &str) -> Result<NodeCommandAuditTargetKind, NodeCommandAuditError> {
    match value {
        "node" => Ok(NodeCommandAuditTargetKind::Node),
        "model" => Ok(NodeCommandAuditTargetKind::Model),
        "api_key" => Ok(NodeCommandAuditTargetKind::ApiKey),
        "benchmark" => Ok(NodeCommandAuditTargetKind::Benchmark),
        "audit_event" => Ok(NodeCommandAuditTargetKind::AuditEvent),
        "core" => Ok(NodeCommandAuditTargetKind::Core),
        "service" => Ok(NodeCommandAuditTargetKind::Service),
        _ => Err(NodeCommandAuditError::Corrupt),
    }
}

// Returns one exact persisted Node role name.
const fn role_name(role: NodeRole) -> &'static str {
    match role {
        NodeRole::Main => "main",
        NodeRole::Child => "child",
    }
}

// Parses one exact persisted Node role name.
fn role(value: &str) -> Result<NodeRole, NodeCommandAuditError> {
    match value {
        "main" => Ok(NodeRole::Main),
        "child" => Ok(NodeRole::Child),
        _ => Err(NodeCommandAuditError::Corrupt),
    }
}

// Parses one exact persisted terminal outcome.
fn outcome_from_name(value: &str) -> Result<NodeCommandAuditOutcome, NodeCommandAuditError> {
    match value {
        "succeeded" => Ok(NodeCommandAuditOutcome::Succeeded),
        "failed" => Ok(NodeCommandAuditOutcome::Failed),
        "denied" => Ok(NodeCommandAuditOutcome::Denied),
        "cancelled" => Ok(NodeCommandAuditOutcome::Cancelled),
        _ => Err(NodeCommandAuditError::Corrupt),
    }
}

// Maps one database failure into the closed command-audit persistence boundary.
fn database_error(error: DatabaseError) -> NodeCommandAuditError {
    match error {
        DatabaseError::Conflict { .. } | DatabaseError::IdempotencyConflict { .. } => {
            NodeCommandAuditError::Conflict
        }
        DatabaseError::Corrupt { .. } => NodeCommandAuditError::Corrupt,
        _ => NodeCommandAuditError::Unavailable,
    }
}

// Encodes one digest byte slice as lowercase hexadecimal text.
fn hexadecimal(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut value, "{byte:02x}").expect("writing to a String cannot fail");
    }
    value
}
