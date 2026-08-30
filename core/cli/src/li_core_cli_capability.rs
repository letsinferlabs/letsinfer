// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;

use crate::{ActionId, AuthorizedCommand, CommandInvocation};

const FAILURE_CODE_MAX_BYTES: usize = 96;
const FAILURE_MESSAGE_MAX_BYTES: usize = 4096;

// Distinguishes ordinary execution failure from expected denial and cancellation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandFailureKind {
    Failed,
    Denied,
    Cancelled,
}

// Describes one stable native capability failure without exposing manager internals.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandFailure {
    kind: CommandFailureKind,
    code: String,
    message: String,
}

impl CommandFailure {
    // Creates one validated failure suitable for audit and user presentation.
    pub fn new(
        kind: CommandFailureKind,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Result<Self, CommandFailureContractError> {
        let code = code.into();
        let message = message.into();
        validate_failure_code(&code)?;
        validate_failure_message(&message)?;
        Ok(Self {
            kind,
            code,
            message,
        })
    }

    // Returns the lifecycle classification used to select the process exit code.
    pub const fn kind(&self) -> CommandFailureKind {
        self.kind
    }

    // Returns the stable machine and audit identity of the failure.
    pub fn code(&self) -> &str {
        &self.code
    }

    // Returns the bounded user-safe failure explanation.
    pub fn message(&self) -> &str {
        &self.message
    }
}

// Describes a malformed capability failure before it can cross the CLI boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandFailureContractError {
    reason: &'static str,
}

impl CommandFailureContractError {
    // Creates one closed contract failure from a static invariant description.
    const fn new(reason: &'static str) -> Self {
        Self { reason }
    }
}

impl fmt::Display for CommandFailureContractError {
    // Presents the exact capability contract that was violated.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid command failure: {}", self.reason)
    }
}

impl Error for CommandFailureContractError {}

// Reports one truthful manager-owned progress transition to the application.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandProgressEvent {
    Detail(String),
    Output(Vec<u8>),
    Step {
        completed: usize,
        total: usize,
        message: String,
    },
}

// Receives manager progress without giving managers terminal or stream ownership.
pub trait CommandProgressPort {
    // Reports one progress transition which the application may suppress in machine mode.
    fn report(&mut self, event: CommandProgressEvent);

    // Reports whether a bounded live command must stop before its next provider call.
    fn is_cancelled(&self) -> bool {
        false
    }
}

// Names the host and resident-service leaves owned by native Core composition.
#[derive(Clone, Copy, Debug)]
pub enum HostCommand<'a> {
    Status(&'a CommandInvocation),
    Topology(&'a CommandInvocation),
    Doctor(&'a CommandInvocation),
    Uninstall(&'a CommandInvocation),
}

impl<'a> HostCommand<'a> {
    // Returns the exact parsed invocation carried by this host command.
    pub const fn invocation(self) -> &'a CommandInvocation {
        match self {
            Self::Status(value)
            | Self::Topology(value)
            | Self::Doctor(value)
            | Self::Uninstall(value) => value,
        }
    }
}

// Names every node identity, membership, and local-usage leaf.
#[derive(Clone, Copy, Debug)]
pub enum NodeCommand<'a> {
    Info(&'a CommandInvocation),
    List(&'a CommandInvocation),
    Usage(&'a CommandInvocation),
    Add(&'a CommandInvocation),
    Pause(&'a CommandInvocation),
    Resume(&'a CommandInvocation),
    Remove(&'a CommandInvocation),
}

impl<'a> NodeCommand<'a> {
    // Returns the exact parsed invocation carried by this node command.
    pub const fn invocation(self) -> &'a CommandInvocation {
        match self {
            Self::Info(value)
            | Self::List(value)
            | Self::Usage(value)
            | Self::Add(value)
            | Self::Pause(value)
            | Self::Resume(value)
            | Self::Remove(value) => value,
        }
    }
}

// Names every logical-model and placement-group lifecycle leaf.
#[derive(Clone, Copy, Debug)]
pub enum ModelCommand<'a> {
    List(&'a CommandInvocation),
    Install(&'a CommandInvocation),
    Remove(&'a CommandInvocation),
    Pause(&'a CommandInvocation),
    Resume(&'a CommandInvocation),
    Restart(&'a CommandInvocation),
    Recover(&'a CommandInvocation),
    Rollback(&'a CommandInvocation),
    Logs(&'a CommandInvocation),
}

impl<'a> ModelCommand<'a> {
    // Returns the exact parsed invocation carried by this model command.
    pub const fn invocation(self) -> &'a CommandInvocation {
        match self {
            Self::List(value)
            | Self::Install(value)
            | Self::Remove(value)
            | Self::Pause(value)
            | Self::Resume(value)
            | Self::Restart(value)
            | Self::Recover(value)
            | Self::Rollback(value)
            | Self::Logs(value) => value,
        }
    }
}

// Names every ordinary and community-verification benchmark leaf.
#[derive(Clone, Copy, Debug)]
pub enum BenchmarkCommand<'a> {
    Run(&'a CommandInvocation),
    List(&'a CommandInvocation),
    Status(&'a CommandInvocation),
    Stop(&'a CommandInvocation),
    Clean(&'a CommandInvocation),
    VerificationRun(&'a CommandInvocation),
    VerificationStatus(&'a CommandInvocation),
    VerificationStop(&'a CommandInvocation),
}

impl<'a> BenchmarkCommand<'a> {
    // Returns the exact parsed invocation carried by this benchmark command.
    pub const fn invocation(self) -> &'a CommandInvocation {
        match self {
            Self::Run(value)
            | Self::List(value)
            | Self::Status(value)
            | Self::Stop(value)
            | Self::Clean(value)
            | Self::VerificationRun(value)
            | Self::VerificationStatus(value)
            | Self::VerificationStop(value) => value,
        }
    }
}

// Names every controller and inference-key authentication leaf.
#[derive(Clone, Copy, Debug)]
pub enum AuthenticationCommand<'a> {
    ControllerAdd(&'a CommandInvocation),
    ControllerList(&'a CommandInvocation),
    ControllerRevoke(&'a CommandInvocation),
    KeyCreate(&'a CommandInvocation),
    KeyList(&'a CommandInvocation),
    KeyShow(&'a CommandInvocation),
    KeyRotate(&'a CommandInvocation),
    KeyRevoke(&'a CommandInvocation),
    KeyUpdate(&'a CommandInvocation),
}

impl<'a> AuthenticationCommand<'a> {
    // Returns the exact parsed invocation carried by this authentication command.
    pub const fn invocation(self) -> &'a CommandInvocation {
        match self {
            Self::ControllerAdd(value)
            | Self::ControllerList(value)
            | Self::ControllerRevoke(value)
            | Self::KeyCreate(value)
            | Self::KeyList(value)
            | Self::KeyShow(value)
            | Self::KeyRotate(value)
            | Self::KeyRevoke(value)
            | Self::KeyUpdate(value) => value,
        }
    }
}

// Names the public Gateway exposure policy leaves.
#[derive(Clone, Copy, Debug)]
pub enum ExposureCommand<'a> {
    Status(&'a CommandInvocation),
    Enable(&'a CommandInvocation),
    Disable(&'a CommandInvocation),
}

impl<'a> ExposureCommand<'a> {
    // Returns the exact parsed invocation carried by this exposure command.
    pub const fn invocation(self) -> &'a CommandInvocation {
        match self {
            Self::Status(value) | Self::Enable(value) | Self::Disable(value) => value,
        }
    }
}

// Names the durable audit-chain read and export leaves.
#[derive(Clone, Copy, Debug)]
pub enum AuditCommand<'a> {
    List(&'a CommandInvocation),
    Show(&'a CommandInvocation),
    Verify(&'a CommandInvocation),
    Export(&'a CommandInvocation),
}

impl<'a> AuditCommand<'a> {
    // Returns the exact parsed invocation carried by this audit command.
    pub const fn invocation(self) -> &'a CommandInvocation {
        match self {
            Self::List(value) | Self::Show(value) | Self::Verify(value) | Self::Export(value) => {
                value
            }
        }
    }
}

// Names Core and model update leaves without conflating their lifecycle owners.
#[derive(Clone, Copy, Debug)]
pub enum UpdateCommand<'a> {
    Check(&'a CommandInvocation),
    Core(&'a CommandInvocation),
    Model(&'a CommandInvocation),
}

impl<'a> UpdateCommand<'a> {
    // Returns the exact parsed invocation carried by this update command.
    pub const fn invocation(self) -> &'a CommandInvocation {
        match self {
            Self::Check(value) | Self::Core(value) | Self::Model(value) => value,
        }
    }
}

// Supplies the native manager adapters required by the complete command registry.
pub trait CoreCommandCapabilities {
    type Output;

    // Executes one host or resident-service command through native Core owners.
    fn execute_host(
        &mut self,
        command: HostCommand<'_>,
        progress: &mut dyn CommandProgressPort,
    ) -> Result<Self::Output, CommandFailure>;

    // Executes one node identity or coordination command through NodeManager.
    fn execute_node(
        &mut self,
        command: NodeCommand<'_>,
        progress: &mut dyn CommandProgressPort,
    ) -> Result<Self::Output, CommandFailure>;

    // Executes one model-service lifecycle command through native orchestration.
    fn execute_model(
        &mut self,
        command: ModelCommand<'_>,
        progress: &mut dyn CommandProgressPort,
    ) -> Result<Self::Output, CommandFailure>;

    // Executes one benchmark lifecycle command through BenchmarkManager.
    fn execute_benchmark(
        &mut self,
        command: BenchmarkCommand<'_>,
        progress: &mut dyn CommandProgressPort,
    ) -> Result<Self::Output, CommandFailure>;

    // Executes one controller or inference-key command through AuthenticationManager.
    fn execute_authentication(
        &mut self,
        command: AuthenticationCommand<'_>,
        progress: &mut dyn CommandProgressPort,
    ) -> Result<Self::Output, CommandFailure>;

    // Executes one public-exposure command through the Gateway policy owner.
    fn execute_exposure(
        &mut self,
        command: ExposureCommand<'_>,
        progress: &mut dyn CommandProgressPort,
    ) -> Result<Self::Output, CommandFailure>;

    // Executes one audit-chain query or export through the audit authority.
    fn execute_audit(
        &mut self,
        command: AuditCommand<'_>,
        progress: &mut dyn CommandProgressPort,
    ) -> Result<Self::Output, CommandFailure>;

    // Executes one update command through the applicable lifecycle owner.
    fn execute_update(
        &mut self,
        command: UpdateCommand<'_>,
        progress: &mut dyn CommandProgressPort,
    ) -> Result<Self::Output, CommandFailure>;
}

// Routes every authorized action to one explicit native capability group.
pub fn dispatch_native_command<Capabilities>(
    capabilities: &mut Capabilities,
    command: &AuthorizedCommand,
    progress: &mut dyn CommandProgressPort,
) -> Result<Capabilities::Output, CommandFailure>
where
    Capabilities: CoreCommandCapabilities,
{
    let invocation = command.invocation();
    match invocation.action() {
        ActionId::Status => capabilities.execute_host(HostCommand::Status(invocation), progress),
        ActionId::Topology => {
            capabilities.execute_host(HostCommand::Topology(invocation), progress)
        }
        ActionId::Doctor => capabilities.execute_host(HostCommand::Doctor(invocation), progress),
        ActionId::Uninstall => {
            capabilities.execute_host(HostCommand::Uninstall(invocation), progress)
        }
        ActionId::NodeInfo => capabilities.execute_node(NodeCommand::Info(invocation), progress),
        ActionId::NodeList => capabilities.execute_node(NodeCommand::List(invocation), progress),
        ActionId::NodeUsage => capabilities.execute_node(NodeCommand::Usage(invocation), progress),
        ActionId::NodeAdd => capabilities.execute_node(NodeCommand::Add(invocation), progress),
        ActionId::NodePause => capabilities.execute_node(NodeCommand::Pause(invocation), progress),
        ActionId::NodeResume => {
            capabilities.execute_node(NodeCommand::Resume(invocation), progress)
        }
        ActionId::NodeRemove => {
            capabilities.execute_node(NodeCommand::Remove(invocation), progress)
        }
        ActionId::ModelList => capabilities.execute_model(ModelCommand::List(invocation), progress),
        ActionId::ModelInstall => {
            capabilities.execute_model(ModelCommand::Install(invocation), progress)
        }
        ActionId::ModelRemove => {
            capabilities.execute_model(ModelCommand::Remove(invocation), progress)
        }
        ActionId::ModelPause => {
            capabilities.execute_model(ModelCommand::Pause(invocation), progress)
        }
        ActionId::ModelResume => {
            capabilities.execute_model(ModelCommand::Resume(invocation), progress)
        }
        ActionId::ModelRestart => {
            capabilities.execute_model(ModelCommand::Restart(invocation), progress)
        }
        ActionId::ModelRecover => {
            capabilities.execute_model(ModelCommand::Recover(invocation), progress)
        }
        ActionId::ModelRollback => {
            capabilities.execute_model(ModelCommand::Rollback(invocation), progress)
        }
        ActionId::ModelLogs => capabilities.execute_model(ModelCommand::Logs(invocation), progress),
        ActionId::BenchmarkRun => {
            capabilities.execute_benchmark(BenchmarkCommand::Run(invocation), progress)
        }
        ActionId::BenchmarkList => {
            capabilities.execute_benchmark(BenchmarkCommand::List(invocation), progress)
        }
        ActionId::BenchmarkStatus => {
            capabilities.execute_benchmark(BenchmarkCommand::Status(invocation), progress)
        }
        ActionId::BenchmarkStop => {
            capabilities.execute_benchmark(BenchmarkCommand::Stop(invocation), progress)
        }
        ActionId::BenchmarkClean => {
            capabilities.execute_benchmark(BenchmarkCommand::Clean(invocation), progress)
        }
        ActionId::BenchmarkVerificationRun => {
            capabilities.execute_benchmark(BenchmarkCommand::VerificationRun(invocation), progress)
        }
        ActionId::BenchmarkVerificationStatus => capabilities
            .execute_benchmark(BenchmarkCommand::VerificationStatus(invocation), progress),
        ActionId::BenchmarkVerificationStop => {
            capabilities.execute_benchmark(BenchmarkCommand::VerificationStop(invocation), progress)
        }
        ActionId::AuthControllerAdd => capabilities
            .execute_authentication(AuthenticationCommand::ControllerAdd(invocation), progress),
        ActionId::AuthControllerList => capabilities
            .execute_authentication(AuthenticationCommand::ControllerList(invocation), progress),
        ActionId::AuthControllerRevoke => capabilities.execute_authentication(
            AuthenticationCommand::ControllerRevoke(invocation),
            progress,
        ),
        ActionId::AuthKeyCreate => capabilities
            .execute_authentication(AuthenticationCommand::KeyCreate(invocation), progress),
        ActionId::AuthKeyList => capabilities
            .execute_authentication(AuthenticationCommand::KeyList(invocation), progress),
        ActionId::AuthKeyShow => capabilities
            .execute_authentication(AuthenticationCommand::KeyShow(invocation), progress),
        ActionId::AuthKeyRotate => capabilities
            .execute_authentication(AuthenticationCommand::KeyRotate(invocation), progress),
        ActionId::AuthKeyRevoke => capabilities
            .execute_authentication(AuthenticationCommand::KeyRevoke(invocation), progress),
        ActionId::AuthKeyUpdate => capabilities
            .execute_authentication(AuthenticationCommand::KeyUpdate(invocation), progress),
        ActionId::ExposureStatus => {
            capabilities.execute_exposure(ExposureCommand::Status(invocation), progress)
        }
        ActionId::ExposureEnable => {
            capabilities.execute_exposure(ExposureCommand::Enable(invocation), progress)
        }
        ActionId::ExposureDisable => {
            capabilities.execute_exposure(ExposureCommand::Disable(invocation), progress)
        }
        ActionId::AuditList => capabilities.execute_audit(AuditCommand::List(invocation), progress),
        ActionId::AuditShow => capabilities.execute_audit(AuditCommand::Show(invocation), progress),
        ActionId::AuditVerify => {
            capabilities.execute_audit(AuditCommand::Verify(invocation), progress)
        }
        ActionId::AuditExport => {
            capabilities.execute_audit(AuditCommand::Export(invocation), progress)
        }
        ActionId::UpdateCheck => {
            capabilities.execute_update(UpdateCommand::Check(invocation), progress)
        }
        ActionId::UpdateCore => {
            capabilities.execute_update(UpdateCommand::Core(invocation), progress)
        }
        ActionId::UpdateModel => {
            capabilities.execute_update(UpdateCommand::Model(invocation), progress)
        }
    }
}

// Enforces the bounded lowercase namespace used by errors and audit records.
fn validate_failure_code(value: &str) -> Result<(), CommandFailureContractError> {
    if value.is_empty() || value.len() > FAILURE_CODE_MAX_BYTES {
        return Err(CommandFailureContractError::new(
            "code must contain between 1 and 96 bytes",
        ));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte))
    {
        return Err(CommandFailureContractError::new(
            "code contains unsupported characters",
        ));
    }
    Ok(())
}

// Rejects empty, oversized, or control-bearing text before it reaches a terminal.
fn validate_failure_message(value: &str) -> Result<(), CommandFailureContractError> {
    if value.is_empty() || value.len() > FAILURE_MESSAGE_MAX_BYTES {
        return Err(CommandFailureContractError::new(
            "message must contain between 1 and 4096 bytes",
        ));
    }
    if value
        .chars()
        .any(|character| character.is_control() && character != '\n' && character != '\t')
    {
        return Err(CommandFailureContractError::new(
            "message contains unsupported control characters",
        ));
    }
    Ok(())
}
