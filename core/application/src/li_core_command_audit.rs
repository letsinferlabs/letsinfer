// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::sync::Arc;

use getrandom::fill;
use li_audit_manager::{
    AuditAction, AuditActor, AuditAppendRequest, AuditCorrelationId, AuditManager, AuditOrigin,
    AuditOriginInterface, AuditOutcome, AuditReason, AuditReplayId, AuditTarget,
};
use li_core_cli::{
    ActionId, AuditPolicy, CommandAuditError, CommandAuditIntent, CommandAuditMarker,
    CommandAuditOutcome, CommandAuditPort, CommandAuditResult,
};

const IDENTITY_BYTES: usize = 16;
const MARKER_PREFIX: &str = "li_cli_audit_";
const REPLAY_PREFIX: &str = "li_cli_";

// Carries one unpredictable marker, correlation identity, and replay identity as one unit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreCommandAuditIdentity {
    marker: String,
    correlation_id: AuditCorrelationId,
    replay_id: AuditReplayId,
}

impl CoreCommandAuditIdentity {
    // Creates one validated identity set for a specific command action.
    pub fn new(
        action: ActionId,
        marker: &str,
        correlation_id: AuditCorrelationId,
        replay_id: AuditReplayId,
    ) -> Result<Self, CoreCommandAuditConfigurationError> {
        let expected_prefix = format!("{REPLAY_PREFIX}{}_", action.as_str());
        let marker_nonce = marker.strip_prefix(MARKER_PREFIX).unwrap_or_default();
        if !marker.starts_with(MARKER_PREFIX)
            || marker.len() != MARKER_PREFIX.len() + IDENTITY_BYTES * 2
            || !marker_nonce
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || correlation_id.as_str() != marker_nonce
            || replay_id.as_str() != format!("{expected_prefix}{marker_nonce}")
        {
            return Err(CoreCommandAuditConfigurationError::InvalidIdentity);
        }
        Ok(Self {
            marker: marker.to_string(),
            correlation_id,
            replay_id,
        })
    }

    // Returns the opaque process marker presented to the CLI application.
    pub fn marker(&self) -> &str {
        &self.marker
    }
}

// Supplies unpredictable command markers without owning audit persistence or policy.
pub trait CoreCommandAuditIdentityProvider: Send + Sync {
    // Returns one fresh identity set bound to the exact command action.
    fn identity(&self, action: ActionId) -> Result<CoreCommandAuditIdentity, CommandAuditError>;
}

// Reads production command identity material from the operating-system random source.
#[derive(Default)]
pub struct SystemCoreCommandAuditIdentityProvider;

impl CoreCommandAuditIdentityProvider for SystemCoreCommandAuditIdentityProvider {
    // Creates one marker and derives its correlation and replay identities from the same nonce.
    fn identity(&self, action: ActionId) -> Result<CoreCommandAuditIdentity, CommandAuditError> {
        let mut bytes = [0_u8; IDENTITY_BYTES];
        fill(&mut bytes).map_err(|_| audit_error("command audit identity is unavailable"))?;
        let nonce = hexadecimal(&bytes);
        bytes.fill(0);
        let marker = format!("{MARKER_PREFIX}{nonce}");
        let correlation_id = AuditCorrelationId::parse(&nonce)
            .map_err(|_| audit_error("command audit identity is invalid"))?;
        let replay_id =
            AuditReplayId::parse(&format!("{REPLAY_PREFIX}{}_{nonce}", action.as_str()))
                .map_err(|_| audit_error("command audit replay identity is invalid"))?;
        CoreCommandAuditIdentity::new(action, &marker, correlation_id, replay_id)
            .map_err(|_| audit_error("command audit identity is invalid"))
    }
}

// Describes an invalid application-level audit composition before command execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreCommandAuditConfigurationError {
    NodeIdentityMismatch,
    InvalidIdentity,
}

impl fmt::Display for CoreCommandAuditConfigurationError {
    // Presents stable configuration language without exposing marker values.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NodeIdentityMismatch => {
                formatter.write_str("the command audit node identity does not match its ledger")
            }
            Self::InvalidIdentity => {
                formatter.write_str("the command audit identity contract is invalid")
            }
        }
    }
}

impl Error for CoreCommandAuditConfigurationError {}

// Retains only the secret-free context required to finish one opened command lifecycle.
#[derive(Clone)]
struct PendingCommandAudit {
    intent: CommandAuditIntent,
    identity: CoreCommandAuditIdentity,
}

// Owns the process-local bridge from CLI audit hooks to the node's durable AuditManager.
pub struct CoreCommandAuditPort {
    manager: Arc<AuditManager>,
    actor: AuditActor,
    origin: AuditOrigin,
    identities: Arc<dyn CoreCommandAuditIdentityProvider>,
    pending: BTreeMap<String, PendingCommandAudit>,
}

impl CoreCommandAuditPort {
    // Creates one audit bridge after binding its origin to the exact ledger owner.
    pub fn new(
        manager: Arc<AuditManager>,
        actor: AuditActor,
        origin: AuditOrigin,
        identities: Arc<dyn CoreCommandAuditIdentityProvider>,
    ) -> Result<Self, CoreCommandAuditConfigurationError> {
        if origin.node_id() != manager.node_id() || origin.interface() != AuditOriginInterface::Cli
        {
            return Err(CoreCommandAuditConfigurationError::NodeIdentityMismatch);
        }
        Ok(Self {
            manager,
            actor,
            origin,
            identities,
            pending: BTreeMap::new(),
        })
    }

    // Returns the number of open process-local audit lifecycles awaiting completion.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    // Builds one secret-free durable terminal request from its matching opened intent.
    fn request(
        &self,
        pending: &PendingCommandAudit,
        result: &CommandAuditResult,
    ) -> Result<AuditAppendRequest, CommandAuditError> {
        let (outcome, reason) = audit_result(result)?;
        AuditAppendRequest::new(
            pending.identity.replay_id.clone(),
            pending.identity.correlation_id.clone(),
            self.actor.clone(),
            self.origin.clone(),
            AuditAction::parse(result.action().as_str()).map_err(|_| audit_contract_error())?,
            AuditTarget::parse(
                &pending
                    .intent
                    .target()
                    .map(|target| format!("{}:{}", target.kind().as_str(), target.identifier()))
                    .unwrap_or_else(|| "local-node".to_string()),
            )
            .map_err(|_| audit_contract_error())?,
            None,
            None,
            outcome,
            reason,
        )
        .map_err(|_| audit_contract_error())
    }
}

impl CommandAuditPort for CoreCommandAuditPort {
    // Verifies the ledger and opens one unique marker before manager execution begins.
    fn will_execute(
        &mut self,
        intent: CommandAuditIntent,
    ) -> Result<Option<CommandAuditMarker>, CommandAuditError> {
        if intent.policy() == AuditPolicy::None {
            return Ok(None);
        }
        self.manager
            .verify()
            .map_err(|_| audit_error("the command audit ledger is unavailable"))?;
        let identity = self.identities.identity(intent.action())?;
        if self.pending.contains_key(identity.marker()) {
            return Err(audit_error("the command audit marker was reused"));
        }
        let marker = CommandAuditMarker::new(identity.marker())?;
        self.pending.insert(
            identity.marker().to_string(),
            PendingCommandAudit { intent, identity },
        );
        Ok(Some(marker))
    }

    // Appends the matching terminal event once and retains failed appends for explicit recovery.
    fn did_execute(
        &mut self,
        marker: &CommandAuditMarker,
        result: CommandAuditResult,
    ) -> Result<(), CommandAuditError> {
        let pending = self
            .pending
            .get(marker.as_str())
            .ok_or_else(|| audit_error("the command audit marker is unknown"))?;
        if pending.intent.action() != result.action() {
            return Err(audit_error(
                "the command audit action changed before completion",
            ));
        }
        if should_append(pending.intent.policy(), result.outcome()) {
            let request = self.request(pending, &result)?;
            self.manager
                .append(request)
                .map_err(|_| audit_error("the command audit result could not be recorded"))?;
        }
        self.pending.remove(marker.as_str());
        Ok(())
    }
}

// Returns whether one terminal result belongs in the policy-selected audit trail.
const fn should_append(policy: AuditPolicy, outcome: CommandAuditOutcome) -> bool {
    match policy {
        AuditPolicy::None => false,
        AuditPolicy::Success => matches!(outcome, CommandAuditOutcome::Succeeded),
        AuditPolicy::Always | AuditPolicy::SensitiveRead => true,
    }
}

// Converts one CLI terminal result into the closed AuditManager outcome and reason vocabulary.
fn audit_result(
    result: &CommandAuditResult,
) -> Result<(AuditOutcome, Option<AuditReason>), CommandAuditError> {
    match result.outcome() {
        CommandAuditOutcome::Succeeded => Ok((AuditOutcome::Success, None)),
        CommandAuditOutcome::Denied => Ok((
            AuditOutcome::Denied,
            Some(audit_reason(result.failure_code(), "command_denied")?),
        )),
        CommandAuditOutcome::Failed => Ok((
            AuditOutcome::Failed,
            Some(audit_reason(result.failure_code(), "command_failed")?),
        )),
        CommandAuditOutcome::Cancelled => Ok((
            AuditOutcome::Failed,
            Some(audit_reason(result.failure_code(), "command_cancelled")?),
        )),
    }
}

// Preserves a valid stable capability code or substitutes one closed generic reason.
fn audit_reason(value: Option<&str>, fallback: &str) -> Result<AuditReason, CommandAuditError> {
    value
        .and_then(|value| AuditReason::parse(value).ok())
        .or_else(|| AuditReason::parse(fallback).ok())
        .ok_or_else(audit_contract_error)
}

// Encodes one byte slice as lowercase hexadecimal text.
fn hexadecimal(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut value, "{byte:02x}").expect("writing to a String cannot fail");
    }
    value
}

// Creates one stable redacted audit operation failure.
fn audit_error(message: &'static str) -> CommandAuditError {
    CommandAuditError::new("cli.audit_unavailable", message)
}

// Creates one stable internal-contract failure without copying rejected values.
fn audit_contract_error() -> CommandAuditError {
    CommandAuditError::new(
        "cli.audit_contract_invalid",
        "the command audit result is invalid",
    )
}
