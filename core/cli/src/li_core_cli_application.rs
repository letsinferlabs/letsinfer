// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::io::Write;

use sha2::{Digest, Sha256};

use crate::{
    authorize, begins_audit, command_output_mode, completes_audit, dispatch_native_command,
    display_contract, AuditPolicy, CliDisplayError, CliDisplayPort, CommandAuditIntent,
    CommandAuditMarker, CommandAuditOutcome, CommandAuditPort, CommandAuditResult,
    CommandAuditTarget, CommandAuditTargetKind, CommandContext, CommandFailure, CommandFailureKind,
    CommandInvocation, CommandOutput, CommandOutputMode, CommandParser, CommandProgressEvent,
    CommandProgressPort, CoreCommandCapabilities, DisplayEvent, DisplayProgressKind, LocalRole,
};

// Names the stable process exits owned by the Rust CLI application boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum CliExitCode {
    Success = 0,
    Failure = 1,
    Usage = 2,
    Cancelled = 130,
}

impl CliExitCode {
    // Returns the exact operating-system status value for this terminal outcome.
    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}

// Describes a failure to resolve the immutable local role used for authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandContextError {
    code: &'static str,
    message: String,
}

impl CommandContextError {
    // Creates one bounded context failure supplied by native Node composition.
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        let message = message.into();
        Self {
            code,
            message: if message.is_empty() {
                "cannot resolve local node context".to_owned()
            } else {
                message
            },
        }
    }

    // Returns the stable machine identity of this context failure.
    pub const fn code(&self) -> &'static str {
        self.code
    }

    // Returns the user-safe context failure explanation.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for CommandContextError {
    // Presents the context failure without exposing its provider implementation.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for CommandContextError {}

// Supplies the configured-node fact without granting the CLI database access.
pub trait CommandContextPort {
    // Resolves one immutable command context before authorization and dispatch.
    fn command_context(&mut self) -> Result<CommandContext, CommandContextError>;
}

// Runs the process-facing native CLI with the centralized plain stream display.
pub fn run_native_cli<I, S, Context, Capabilities, Audit, StandardOutput, StandardError>(
    arguments: I,
    context: &mut Context,
    capabilities: &mut Capabilities,
    audit: &mut Audit,
    standard_output: &mut StandardOutput,
    standard_error: &mut StandardError,
) -> CliExitCode
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
    Context: CommandContextPort,
    Capabilities: CoreCommandCapabilities<Output = CommandOutput>,
    Audit: CommandAuditPort,
    StandardOutput: Write,
    StandardError: Write,
{
    let mut display = crate::StreamCliDisplay::new(standard_output, standard_error);
    CliApplication::new(context, capabilities, audit, &mut display).run(arguments)
}

// Owns parse, context, authorization, audit, dispatch, progress, and display ordering.
pub struct CliApplication<'a, Context, Capabilities, Audit, Display>
where
    Context: CommandContextPort,
    Capabilities: CoreCommandCapabilities<Output = CommandOutput>,
    Audit: CommandAuditPort,
    Display: CliDisplayPort,
{
    context: &'a mut Context,
    capabilities: &'a mut Capabilities,
    audit: &'a mut Audit,
    display: &'a mut Display,
}

impl<'a, Context, Capabilities, Audit, Display>
    CliApplication<'a, Context, Capabilities, Audit, Display>
where
    Context: CommandContextPort,
    Capabilities: CoreCommandCapabilities<Output = CommandOutput>,
    Audit: CommandAuditPort,
    Display: CliDisplayPort,
{
    // Creates one application from explicit native ports and one display owner.
    pub const fn new(
        context: &'a mut Context,
        capabilities: &'a mut Capabilities,
        audit: &'a mut Audit,
        display: &'a mut Display,
    ) -> Self {
        Self {
            context,
            capabilities,
            audit,
            display,
        }
    }

    // Runs one complete command lifecycle without invoking a shell or Python process.
    pub fn run<I, S>(&mut self, arguments: I) -> CliExitCode
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let parser = match CommandParser::new() {
            Ok(parser) => parser,
            Err(error) => {
                return self.fatal(
                    "cli.registry_invalid",
                    error.to_string(),
                    CliExitCode::Failure,
                )
            }
        };
        let invocation = match parser.parse(arguments) {
            Ok(invocation) => invocation,
            Err(error) => {
                return self.fatal(
                    "cli.arguments_invalid",
                    error.to_string(),
                    CliExitCode::Usage,
                )
            }
        };
        let contract = display_contract(invocation.action());
        let output_mode = command_output_mode(&invocation, contract);
        let context = match self.context.command_context() {
            Ok(context) => context,
            Err(error) => return self.fatal(error.code(), error.message(), CliExitCode::Failure),
        };
        let command = match authorize(invocation, context) {
            Ok(command) => command,
            Err(error) => {
                let message = authorization_message(&error);
                let _ = self.display.display(DisplayEvent::NotAllowed { message });
                return CliExitCode::Failure;
            }
        };

        if output_mode == CommandOutputMode::Human
            && contract.is_branded()
            && !contract.owns_complete_surface()
            && self
                .display
                .display(DisplayEvent::Header {
                    title: contract.title(),
                })
                .is_err()
        {
            return CliExitCode::Failure;
        }

        let generic_progress = output_mode == CommandOutputMode::Human
            && matches!(
                contract.progress(),
                DisplayProgressKind::Spinner | DisplayProgressKind::Steps
            )
            && command.invocation().boolean(crate::ArgumentId::DryRun) != Some(true);
        if generic_progress {
            if let Some(message) = contract.progress_start() {
                if self
                    .display
                    .display(DisplayEvent::ProgressStarted { message })
                    .is_err()
                {
                    return CliExitCode::Failure;
                }
            }
        }

        let metadata = command.metadata();
        let audit_intent = CommandAuditIntent::new(
            metadata.id(),
            metadata.audit(),
            metadata.mutation(),
            context,
        );
        let audit_intent = match command_audit_target(command.invocation()) {
            Ok(Some(target)) => audit_intent.with_target(target),
            Ok(None) => audit_intent,
            Err(error) => {
                if generic_progress {
                    let _ = self.display.display(DisplayEvent::ProgressFailed);
                }
                return self.fatal(error.code(), error.message(), CliExitCode::Failure);
            }
        };
        let audit_marker = match self.begin_audit(metadata.audit(), audit_intent) {
            Ok(marker) => marker,
            Err(error) => {
                if generic_progress {
                    let _ = self.display.display(DisplayEvent::ProgressFailed);
                }
                return self.fatal(error.code(), error.message(), CliExitCode::Failure);
            }
        };

        let (result, progress_error) = {
            let mut progress = ApplicationProgress {
                display: self.display,
                enabled: output_mode == CommandOutputMode::Human,
                failure: None,
            };
            let result = dispatch_native_command(self.capabilities, &command, &mut progress);
            (result, progress.failure)
        };

        match result {
            Ok(output) => self.finish_success(
                metadata.audit(),
                metadata.id(),
                audit_marker,
                output_mode,
                contract.progress_done(),
                generic_progress,
                output,
                progress_error,
            ),
            Err(failure) => self.finish_failure(
                metadata.audit(),
                metadata.id(),
                audit_marker,
                generic_progress,
                failure,
                progress_error,
            ),
        }
    }

    // Opens the mandatory audit lifecycle before dispatch when policy requires it.
    fn begin_audit(
        &mut self,
        policy: AuditPolicy,
        intent: CommandAuditIntent,
    ) -> Result<Option<CommandAuditMarker>, crate::CommandAuditError> {
        if !begins_audit(policy) {
            return Ok(None);
        }
        let requires_marker = intent.context().local_role() == Some(LocalRole::Main);
        let marker = self.audit.will_execute(intent)?;
        if requires_marker && marker.is_none() {
            return Err(crate::CommandAuditError::new(
                "cli.audit_marker_missing",
                "mandatory node audit did not open an execution marker",
            ));
        }
        Ok(marker)
    }

    // Completes audit and output only after native manager execution succeeds.
    #[allow(clippy::too_many_arguments)]
    fn finish_success(
        &mut self,
        policy: AuditPolicy,
        action: crate::ActionId,
        marker: Option<CommandAuditMarker>,
        output_mode: CommandOutputMode,
        completion: Option<&'static str>,
        generic_progress: bool,
        output: CommandOutput,
        progress_error: Option<CliDisplayError>,
    ) -> CliExitCode {
        if let Some(marker) = marker.as_ref() {
            if completes_audit(policy, CommandAuditOutcome::Succeeded) {
                let result = CommandAuditResult::new(action, CommandAuditOutcome::Succeeded, None);
                if let Err(error) = self.audit.did_execute(marker, result) {
                    if generic_progress {
                        let _ = self.display.display(DisplayEvent::ProgressFailed);
                    }
                    return self.fatal(error.code(), error.message(), CliExitCode::Failure);
                }
            }
        }
        if progress_error.is_some() {
            return CliExitCode::Failure;
        }
        if generic_progress && !output.suppresses_completion() {
            if let Some(message) = completion {
                if self
                    .display
                    .display(DisplayEvent::ProgressCompleted { message })
                    .is_err()
                {
                    return CliExitCode::Failure;
                }
            }
        }
        let event = match output_mode {
            CommandOutputMode::Json => match output.machine() {
                Some(value) => DisplayEvent::MachineDocument(value.clone()),
                None => {
                    return self.fatal(
                        "cli.machine_output_missing",
                        "command did not return its declared JSON document",
                        CliExitCode::Failure,
                    )
                }
            },
            CommandOutputMode::Human | CommandOutputMode::Internal => {
                DisplayEvent::HumanDocument(output.presentation().clone())
            }
        };
        if self.display.display(event).is_err() {
            CliExitCode::Failure
        } else {
            CliExitCode::Success
        }
    }

    // Records and presents one denied, cancelled, or failed native manager result.
    #[allow(clippy::too_many_arguments)]
    fn finish_failure(
        &mut self,
        policy: AuditPolicy,
        action: crate::ActionId,
        marker: Option<CommandAuditMarker>,
        generic_progress: bool,
        failure: CommandFailure,
        progress_error: Option<CliDisplayError>,
    ) -> CliExitCode {
        let outcome = audit_outcome(failure.kind());
        if let Some(marker) = marker.as_ref() {
            if completes_audit(policy, outcome) {
                let result = CommandAuditResult::new(action, outcome, Some(failure.code()));
                let _ = self.audit.did_execute(marker, result);
            }
        }
        if progress_error.is_some() {
            return exit_for_failure(failure.kind());
        }
        if generic_progress {
            let _ = self.display.display(DisplayEvent::ProgressFailed);
        }
        let event = match failure.kind() {
            CommandFailureKind::Failed => DisplayEvent::Fatal {
                code: failure.code().to_owned(),
                message: failure.message().to_owned(),
            },
            CommandFailureKind::Denied => DisplayEvent::Denied {
                message: failure.message().to_owned(),
            },
            CommandFailureKind::Cancelled => DisplayEvent::Cancelled,
        };
        let _ = self.display.display(event);
        exit_for_failure(failure.kind())
    }

    // Presents one fatal boundary failure and returns its predetermined process exit.
    fn fatal(
        &mut self,
        code: impl Into<String>,
        message: impl Into<String>,
        exit: CliExitCode,
    ) -> CliExitCode {
        let _ = self.display.display(DisplayEvent::Fatal {
            code: code.into(),
            message: message.into(),
        });
        exit
    }
}

// Projects only typed stable command selectors into a closed resource class before execution.
fn command_audit_target(
    invocation: &CommandInvocation,
) -> Result<Option<CommandAuditTarget>, crate::CommandAuditError> {
    use crate::{ActionId, ArgumentId};

    let selected = match invocation.action() {
        ActionId::NodeInfo => invocation
            .text(ArgumentId::Node)
            .map(|value| (CommandAuditTargetKind::Node, value)),
        ActionId::NodePause | ActionId::NodeResume | ActionId::NodeRemove => invocation
            .text(ArgumentId::Member)
            .map(|value| (CommandAuditTargetKind::Node, value)),
        ActionId::NodeAdd => invocation
            .text(ArgumentId::Address)
            .map(|value| (CommandAuditTargetKind::Node, value)),
        ActionId::ModelInstall
        | ActionId::ModelRemove
        | ActionId::ModelPause
        | ActionId::ModelResume
        | ActionId::ModelRestart
        | ActionId::ModelRecover
        | ActionId::ModelRollback
        | ActionId::ModelLogs
        | ActionId::UpdateModel => invocation
            .text(ArgumentId::Model)
            .map(|value| (CommandAuditTargetKind::Model, value)),
        ActionId::BenchmarkStatus | ActionId::BenchmarkStop | ActionId::BenchmarkClean => None,
        ActionId::AuthControllerRevoke => invocation
            .text(ArgumentId::Controller)
            .map(|value| (CommandAuditTargetKind::ApiKey, value)),
        ActionId::AuthKeyCreate => invocation
            .text(ArgumentId::Name)
            .map(|value| (CommandAuditTargetKind::ApiKey, value)),
        ActionId::AuthKeyShow
        | ActionId::AuthKeyRotate
        | ActionId::AuthKeyRevoke
        | ActionId::AuthKeyUpdate => invocation
            .text(ArgumentId::Key)
            .map(|value| (CommandAuditTargetKind::ApiKey, value)),
        ActionId::AuditShow => invocation
            .text(ArgumentId::Event)
            .map(|value| (CommandAuditTargetKind::AuditEvent, value)),
        ActionId::UpdateCore => invocation
            .text(ArgumentId::Version)
            .map(|value| (CommandAuditTargetKind::Core, value)),
        _ => None,
    };
    selected
        .map(|(kind, value)| CommandAuditTarget::new(kind, selector_identity(value)))
        .transpose()
}

// Hashes a normalized selector so raw arguments and secret-shaped values never enter audit state.
fn selector_identity(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    let mut identity = String::with_capacity(7 + digest.len() * 2);
    identity.push_str("sha256-");
    for byte in digest {
        use std::fmt::Write;
        write!(&mut identity, "{byte:02x}").expect("writing to a String cannot fail");
    }
    identity
}

// Relays manager progress to the display owner while retaining the first stream failure.
struct ApplicationProgress<'a, Display>
where
    Display: CliDisplayPort,
{
    display: &'a mut Display,
    enabled: bool,
    failure: Option<CliDisplayError>,
}

impl<Display> CommandProgressPort for ApplicationProgress<'_, Display>
where
    Display: CliDisplayPort,
{
    // Converts typed manager progress into display events without returning stream ownership.
    fn report(&mut self, event: CommandProgressEvent) {
        if !self.enabled || self.failure.is_some() {
            return;
        }
        let event = match event {
            CommandProgressEvent::Detail(message) => DisplayEvent::ProgressDetail { message },
            CommandProgressEvent::Output(value) => DisplayEvent::RawOutput(value),
            CommandProgressEvent::Step {
                completed,
                total,
                message,
            } => DisplayEvent::ProgressStep {
                completed,
                total,
                message,
            },
        };
        if let Err(error) = self.display.display(event) {
            self.failure = Some(error);
        }
    }

    // Stops a live producer after the display owner reports one terminal stream failure.
    fn is_cancelled(&self) -> bool {
        self.failure.is_some()
    }
}

// Converts authorization details into stable product language without manager internals.
fn authorization_message(error: &crate::CommandAuthorizationError) -> String {
    match error {
        crate::CommandAuthorizationError::ConfiguredNodeRequired { .. } => {
            "This command requires a configured node; rerun the installer first.".to_owned()
        }
        crate::CommandAuthorizationError::ScopeDenied {
            required: crate::CommandScope::Main,
            actual: LocalRole::Child,
            ..
        } => "Please run this from the main node.".to_owned(),
        crate::CommandAuthorizationError::ScopeDenied {
            required: crate::CommandScope::Child,
            actual: LocalRole::Main,
            ..
        } => "Please run this from a child node.".to_owned(),
        _ => "This command is not allowed from the current node.".to_owned(),
    }
}

// Maps one native capability outcome into the durable audit vocabulary.
const fn audit_outcome(kind: CommandFailureKind) -> CommandAuditOutcome {
    match kind {
        CommandFailureKind::Failed => CommandAuditOutcome::Failed,
        CommandFailureKind::Denied => CommandAuditOutcome::Denied,
        CommandFailureKind::Cancelled => CommandAuditOutcome::Cancelled,
    }
}

// Maps one native capability outcome into its stable process exit.
const fn exit_for_failure(kind: CommandFailureKind) -> CliExitCode {
    match kind {
        CommandFailureKind::Failed | CommandFailureKind::Denied => CliExitCode::Failure,
        CommandFailureKind::Cancelled => CliExitCode::Cancelled,
    }
}
