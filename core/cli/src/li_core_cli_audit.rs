// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;

use crate::{ActionId, AuditPolicy, CommandContext, MutationClass};

const AUDIT_MARKER_MAX_BYTES: usize = 256;
const AUDIT_FAILURE_MAX_BYTES: usize = 2048;
const AUDIT_TARGET_MAX_BYTES: usize = 255;

// Names the closed resource classes that can safely cross the command-audit boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandAuditTargetKind {
    Node,
    Model,
    ApiKey,
    Benchmark,
    AuditEvent,
    Core,
    Service,
}

impl CommandAuditTargetKind {
    // Returns the stable Node wire and audit-ledger name for this resource class.
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

// Binds one resource class to a validated stable identifier without retaining raw arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandAuditTarget {
    kind: CommandAuditTargetKind,
    identifier: String,
}

impl CommandAuditTarget {
    // Creates one bounded unambiguous target that cannot carry common secret envelopes.
    pub fn new(
        kind: CommandAuditTargetKind,
        identifier: impl Into<String>,
    ) -> Result<Self, CommandAuditError> {
        let identifier = identifier.into();
        if identifier.is_empty()
            || identifier.len() > AUDIT_TARGET_MAX_BYTES
            || identifier.contains(':')
            || !identifier.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'@' | b'/')
            })
            || secret_shaped(&identifier)
        {
            return Err(CommandAuditError::new(
                "cli.audit_target_invalid",
                "command audit target is invalid",
            ));
        }
        Ok(Self { kind, identifier })
    }

    // Returns the closed target resource class.
    pub const fn kind(&self) -> CommandAuditTargetKind {
        self.kind
    }

    // Returns the validated stable identifier without a raw argument envelope.
    pub fn identifier(&self) -> &str {
        &self.identifier
    }
}

// Describes one authorized command before any manager mutation can begin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandAuditIntent {
    action: ActionId,
    target: Option<CommandAuditTarget>,
    policy: AuditPolicy,
    mutation: MutationClass,
    context: CommandContext,
}

impl CommandAuditIntent {
    // Creates one audit intent without copying command arguments or secret-bearing values.
    pub const fn new(
        action: ActionId,
        policy: AuditPolicy,
        mutation: MutationClass,
        context: CommandContext,
    ) -> Self {
        Self {
            action,
            target: None,
            policy,
            mutation,
            context,
        }
    }

    // Returns the exact action identity entering execution.
    pub const fn action(&self) -> ActionId {
        self.action
    }

    // Adds one validated target projection without changing command ownership.
    pub fn with_target(mut self, target: CommandAuditTarget) -> Self {
        self.target = Some(target);
        self
    }

    // Returns the explicit resource identity when this command has one before execution.
    pub const fn target(&self) -> Option<&CommandAuditTarget> {
        self.target.as_ref()
    }

    // Returns the registry-owned audit lifecycle.
    pub const fn policy(&self) -> AuditPolicy {
        self.policy
    }

    // Returns the mutation class without exposing parsed values.
    pub const fn mutation(&self) -> MutationClass {
        self.mutation
    }

    // Returns the configured-node context used during authorization.
    pub const fn context(&self) -> CommandContext {
        self.context
    }
}

// Holds one opaque audit position returned before manager execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandAuditMarker {
    value: String,
}

impl CommandAuditMarker {
    // Creates one bounded opaque marker without assigning it persistence meaning.
    pub fn new(value: impl Into<String>) -> Result<Self, CommandAuditError> {
        let value = value.into();
        if value.is_empty() || value.len() > AUDIT_MARKER_MAX_BYTES {
            return Err(CommandAuditError::new(
                "cli.audit_marker_invalid",
                "command audit marker is empty or exceeds 256 bytes",
            ));
        }
        if value.chars().any(char::is_control) {
            return Err(CommandAuditError::new(
                "cli.audit_marker_invalid",
                "command audit marker contains control characters",
            ));
        }
        Ok(Self { value })
    }

    // Returns the opaque marker only to the matching audit completion boundary.
    pub fn as_str(&self) -> &str {
        &self.value
    }
}

// Names every terminal command outcome written to the durable audit owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandAuditOutcome {
    Succeeded,
    Failed,
    Denied,
    Cancelled,
}

// Describes the terminal result paired with a previously issued audit marker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandAuditResult {
    action: ActionId,
    outcome: CommandAuditOutcome,
    failure_code: Option<String>,
}

impl CommandAuditResult {
    // Creates one redacted result containing only action, outcome, and stable failure code.
    pub fn new(action: ActionId, outcome: CommandAuditOutcome, failure_code: Option<&str>) -> Self {
        Self {
            action,
            outcome,
            failure_code: failure_code.map(str::to_owned),
        }
    }

    // Returns the exact action whose lifecycle completed.
    pub const fn action(&self) -> ActionId {
        self.action
    }

    // Returns the terminal lifecycle outcome.
    pub const fn outcome(&self) -> CommandAuditOutcome {
        self.outcome
    }

    // Returns the stable failure identity without copying its user message.
    pub fn failure_code(&self) -> Option<&str> {
        self.failure_code.as_deref()
    }
}

// Describes one unavailable or rejected durable audit operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandAuditError {
    code: &'static str,
    message: String,
}

impl CommandAuditError {
    // Creates one bounded audit failure for the application boundary.
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        let mut message = message.into();
        if message.is_empty() {
            message = "command audit is unavailable".to_owned();
        }
        message
            .retain(|character| !character.is_control() || character == '\n' || character == '\t');
        truncate_utf8(&mut message, AUDIT_FAILURE_MAX_BYTES);
        Self { code, message }
    }

    // Returns the stable machine identity of the audit failure.
    pub const fn code(&self) -> &'static str {
        self.code
    }

    // Returns the bounded user-safe audit explanation.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for CommandAuditError {
    // Presents the bounded audit explanation without any stored event content.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for CommandAuditError {}

// Owns the mandatory pre-execution and terminal-result audit boundaries.
pub trait CommandAuditPort {
    // Opens one audit lifecycle before any native manager can execute.
    fn will_execute(
        &mut self,
        intent: CommandAuditIntent,
    ) -> Result<Option<CommandAuditMarker>, CommandAuditError>;

    // Completes one opened lifecycle after the manager reaches a terminal result.
    fn did_execute(
        &mut self,
        marker: &CommandAuditMarker,
        result: CommandAuditResult,
    ) -> Result<(), CommandAuditError>;
}

// Reports whether this policy requires a pre-execution audit availability check.
pub const fn begins_audit(policy: AuditPolicy) -> bool {
    !matches!(policy, AuditPolicy::None)
}

// Reports whether this policy requires a terminal hook for its opened marker.
pub const fn completes_audit(policy: AuditPolicy, _outcome: CommandAuditOutcome) -> bool {
    !matches!(policy, AuditPolicy::None)
}

// Truncates text at a valid UTF-8 boundary without exceeding the byte limit.
fn truncate_utf8(value: &mut String, maximum_bytes: usize) {
    if value.len() <= maximum_bytes {
        return;
    }
    let mut boundary = maximum_bytes;
    while !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    value.truncate(boundary);
}

// Rejects common secret envelopes even when they fit the stable-identifier character set.
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
