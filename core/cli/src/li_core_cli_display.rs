// SPDX-License-Identifier: AGPL-3.0-only

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::io::{self, Write};
use std::rc::Rc;

use crate::{ActionId, ArgumentId, CommandInvocation};

const NATIVE_CLI_ROOT_HELP: &str = "Let's Infer\n\nUsage:\n  letsinfer <command> [options]\n  letsinfer --help\n\nCommands:\n  status\n  topology\n  doctor\n  node\n  model\n  benchmark\n  auth\n  exposure\n  audit\n  update\n  uninstall\n";

// Returns the complete configuration-free public root help document.
pub const fn native_cli_root_help() -> &'static str {
    NATIVE_CLI_ROOT_HELP
}

// Distinguishes ordinary, warning, successful, failed, and quiet presentation states.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisplaySemantic {
    Information,
    Working,
    Success,
    Warning,
    Pressure,
    Error,
    Muted,
}

// Describes the human interaction shape owned by one command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisplaySurface {
    FrozenStatus,
    List,
    Detail,
    Mutation,
    Workflow,
    Live,
    Raw,
    Internal,
}

// Describes the durable output shape expected from one command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisplayOutputContract {
    FrozenStatus,
    Table,
    Record,
    MutationResult,
    SensitiveResult,
    OneTimeSecret,
    RawStandardOutput,
    LiveDashboard,
    ArtifactResult,
    Internal,
}

// Describes whether the application or handler owns progress presentation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisplayProgressKind {
    None,
    Spinner,
    Steps,
    Live,
    Passthrough,
}

// Binds one action to its explicit title, surface, output, and progress policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DisplayContract {
    action: ActionId,
    title: &'static str,
    surface: DisplaySurface,
    output: DisplayOutputContract,
    progress: DisplayProgressKind,
    branded: bool,
    progress_start: Option<&'static str>,
    progress_done: Option<&'static str>,
    steps: &'static [&'static str],
}

impl DisplayContract {
    // Returns the exact action identity governed by this presentation contract.
    pub const fn action(self) -> ActionId {
        self.action
    }

    // Returns the stable user-facing command title.
    pub const fn title(self) -> &'static str {
        self.title
    }

    // Returns the interaction surface selected for human output.
    pub const fn surface(self) -> DisplaySurface {
        self.surface
    }

    // Returns the durable result shape expected from native handlers.
    pub const fn output(self) -> DisplayOutputContract {
        self.output
    }

    // Returns the explicit progress owner and behavior.
    pub const fn progress(self) -> DisplayProgressKind {
        self.progress
    }

    // Reports whether an interactive command receives the product header.
    pub const fn is_branded(self) -> bool {
        self.branded
    }

    // Returns the ordinary application-owned progress message when declared.
    pub const fn progress_start(self) -> Option<&'static str> {
        self.progress_start
    }

    // Returns the ordinary successful completion message when declared.
    pub const fn progress_done(self) -> Option<&'static str> {
        self.progress_done
    }

    // Returns the ordered steps owned by a bounded multi-stage command.
    pub const fn steps(self) -> &'static [&'static str] {
        self.steps
    }

    // Reports whether this surface renders its own complete frame.
    pub const fn owns_complete_surface(self) -> bool {
        matches!(
            self.output,
            DisplayOutputContract::FrozenStatus | DisplayOutputContract::LiveDashboard
        )
    }
}

// Distinguishes human, machine JSON, and supervised internal output lifecycles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandOutputMode {
    Human,
    Json,
    Internal,
}

// Holds one finite JSON number while preserving its deterministic decimal bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MachineNumber {
    value: String,
}

// Owns one secret shared by the mutually exclusive human and JSON presentation paths.
#[derive(Clone)]
pub struct OneTimeSecret {
    value: Rc<RefCell<Option<String>>>,
}

impl OneTimeSecret {
    // Creates one single-presentation secret without copying its bytes.
    pub fn new(value: String) -> Self {
        Self {
            value: Rc::new(RefCell::new(Some(value))),
        }
    }

    // Transfers the secret to the selected display sink exactly once.
    fn take(&self) -> Result<String, DisplayContractError> {
        self.value
            .borrow_mut()
            .take()
            .ok_or_else(|| DisplayContractError::new("one-time secret was already presented"))
    }
}

impl fmt::Debug for OneTimeSecret {
    // Redacts secret bytes from debug output at every generic display boundary.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OneTimeSecret(<redacted>)")
    }
}

impl PartialEq for OneTimeSecret {
    // Compares only presentation state and never secret bytes.
    fn eq(&self, other: &Self) -> bool {
        self.value.borrow().is_some() == other.value.borrow().is_some()
    }
}

impl Eq for OneTimeSecret {}

impl MachineNumber {
    // Converts one finite native decimal into a JSON-compatible number.
    pub fn from_f64(value: f64) -> Result<Self, DisplayContractError> {
        if !value.is_finite() {
            return Err(DisplayContractError::new("machine numbers must be finite"));
        }
        Ok(Self {
            value: value.to_string(),
        })
    }

    // Returns the validated decimal bytes used by deterministic JSON serialization.
    pub fn as_str(&self) -> &str {
        &self.value
    }
}

// Holds a deterministic JSON value without requiring handlers to pre-serialize bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MachineValue {
    Null,
    Boolean(bool),
    Integer(i64),
    Unsigned(u64),
    Number(MachineNumber),
    String(String),
    OneTimeSecret(OneTimeSecret),
    Array(Vec<MachineValue>),
    Object(BTreeMap<String, MachineValue>),
}

impl MachineValue {
    // Creates a deterministically ordered object from explicit key-value fields.
    pub fn object<I, K>(fields: I) -> Self
    where
        I: IntoIterator<Item = (K, MachineValue)>,
        K: Into<String>,
    {
        Self::Object(
            fields
                .into_iter()
                .map(|(key, value)| (key.into(), value))
                .collect(),
        )
    }

    // Serializes this value as one compact deterministic JSON document.
    pub fn to_json(&self) -> Result<String, DisplayContractError> {
        let mut output = String::new();
        write_machine_value(self, &mut output)?;
        Ok(output)
    }
}

impl From<&str> for MachineValue {
    // Converts borrowed text into one owned JSON string.
    fn from(value: &str) -> Self {
        Self::String(value.to_owned())
    }
}

impl From<String> for MachineValue {
    // Converts owned text into one JSON string without changing its content.
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<bool> for MachineValue {
    // Converts one boolean into its exact JSON representation.
    fn from(value: bool) -> Self {
        Self::Boolean(value)
    }
}

impl From<i64> for MachineValue {
    // Converts one signed integer into its exact JSON representation.
    fn from(value: i64) -> Self {
        Self::Integer(value)
    }
}

impl From<u64> for MachineValue {
    // Converts one unsigned integer into its exact JSON representation.
    fn from(value: u64) -> Self {
        Self::Unsigned(value)
    }
}

// Describes one label, value, and optional detail row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayRecord {
    label: String,
    value: String,
    detail: Option<String>,
    semantic: DisplaySemantic,
}

impl DisplayRecord {
    // Creates one explicit record row for centralized rendering.
    pub fn new(
        label: impl Into<String>,
        value: impl Into<String>,
        detail: Option<String>,
        semantic: DisplaySemantic,
    ) -> Self {
        Self {
            label: label.into(),
            value: value.into(),
            detail,
            semantic,
        }
    }
}

// Describes one complete table with explicit headings and rectangular rows.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayTable {
    headings: Vec<String>,
    rows: Vec<Vec<String>>,
}

impl DisplayTable {
    // Creates a table only when every row matches the declared heading count.
    pub fn new(
        headings: Vec<String>,
        rows: Vec<Vec<String>>,
    ) -> Result<Self, DisplayContractError> {
        if headings.is_empty() {
            return Err(DisplayContractError::new(
                "a display table requires at least one heading",
            ));
        }
        if rows.iter().any(|row| row.len() != headings.len()) {
            return Err(DisplayContractError::new(
                "every display table row must match its heading count",
            ));
        }
        Ok(Self { headings, rows })
    }
}

// Names the composable human blocks accepted by the single display owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DisplayBlock {
    Result {
        title: String,
        detail: Option<String>,
        semantic: DisplaySemantic,
    },
    Records(Vec<DisplayRecord>),
    Table(DisplayTable),
    Verbatim {
        label: Option<String>,
        value: String,
    },
    OneTimeSecret {
        label: Option<String>,
        value: OneTimeSecret,
    },
    Raw(String),
    RawBytes(Vec<u8>),
}

// Holds the ordered human result without granting handlers stream ownership.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CommandPresentation {
    blocks: Vec<DisplayBlock>,
}

impl CommandPresentation {
    // Creates a presentation from blocks already classified by the CLI handler adapter.
    pub fn new(blocks: Vec<DisplayBlock>) -> Self {
        Self { blocks }
    }

    // Creates one empty result for commands whose lifecycle is the complete output.
    pub const fn empty() -> Self {
        Self { blocks: Vec::new() }
    }

    // Returns the ordered blocks to the display owner without exposing writable state.
    pub fn blocks(&self) -> &[DisplayBlock] {
        &self.blocks
    }
}

// Carries both human presentation data and an optional machine JSON document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandOutput {
    presentation: CommandPresentation,
    machine: Option<MachineValue>,
    suppress_completion: bool,
}

impl CommandOutput {
    // Creates one result while keeping human and machine representations distinct.
    pub const fn new(presentation: CommandPresentation, machine: Option<MachineValue>) -> Self {
        Self {
            presentation,
            machine,
            suppress_completion: false,
        }
    }

    // Suppresses a generic completion line when the handler owns the final surface.
    pub const fn without_completion(mut self) -> Self {
        self.suppress_completion = true;
        self
    }

    // Returns the human presentation owned by the display component.
    pub const fn presentation(&self) -> &CommandPresentation {
        &self.presentation
    }

    // Returns the machine document without fabricating one from human text.
    pub const fn machine(&self) -> Option<&MachineValue> {
        self.machine.as_ref()
    }

    // Reports whether the handler already completed the visible lifecycle.
    pub const fn suppresses_completion(&self) -> bool {
        self.suppress_completion
    }
}

// Describes a malformed presentation before it can reach output streams.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayContractError {
    reason: &'static str,
}

impl DisplayContractError {
    // Creates one closed presentation error from a static invariant description.
    const fn new(reason: &'static str) -> Self {
        Self { reason }
    }
}

impl fmt::Display for DisplayContractError {
    // Presents the exact display contract that was violated.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid command presentation: {}", self.reason)
    }
}

impl Error for DisplayContractError {}

// Names one application-to-display transition with no implicit stream selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DisplayEvent {
    Header {
        title: &'static str,
    },
    ProgressStarted {
        message: &'static str,
    },
    ProgressDetail {
        message: String,
    },
    ProgressStep {
        completed: usize,
        total: usize,
        message: String,
    },
    ProgressCompleted {
        message: &'static str,
    },
    ProgressFailed,
    RawOutput(Vec<u8>),
    HumanDocument(CommandPresentation),
    MachineDocument(MachineValue),
    NotAllowed {
        message: String,
    },
    Denied {
        message: String,
    },
    Cancelled,
    Fatal {
        code: String,
        message: String,
    },
}

// Describes one output failure without leaking the captured document.
#[derive(Debug)]
pub struct CliDisplayError {
    source: io::Error,
}

impl fmt::Display for CliDisplayError {
    // Presents the underlying stream failure as one stable display error.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "cannot write command output: {}", self.source)
    }
}

impl Error for CliDisplayError {}

impl From<io::Error> for CliDisplayError {
    // Preserves the native stream error behind the CLI display boundary.
    fn from(source: io::Error) -> Self {
        Self { source }
    }
}

impl From<DisplayContractError> for CliDisplayError {
    // Converts one presentation-state violation into fixed non-secret display language.
    fn from(_error: DisplayContractError) -> Self {
        Self {
            source: io::Error::other("command presentation is unavailable"),
        }
    }
}

// Receives all visible application events at one centralized boundary.
pub trait CliDisplayPort {
    // Renders one event atomically with respect to its selected output stream.
    fn display(&mut self, event: DisplayEvent) -> Result<(), CliDisplayError>;
}

// Renders deterministic plain output to separately owned stdout and stderr streams.
pub struct StreamCliDisplay<StandardOutput, StandardError>
where
    StandardOutput: Write,
    StandardError: Write,
{
    standard_output: StandardOutput,
    standard_error: StandardError,
}

impl<StandardOutput, StandardError> StreamCliDisplay<StandardOutput, StandardError>
where
    StandardOutput: Write,
    StandardError: Write,
{
    // Creates one display owner without discovering or replacing either stream.
    pub const fn new(standard_output: StandardOutput, standard_error: StandardError) -> Self {
        Self {
            standard_output,
            standard_error,
        }
    }

    // Returns the owned streams after application execution for deterministic inspection.
    pub fn into_streams(self) -> (StandardOutput, StandardError) {
        (self.standard_output, self.standard_error)
    }

    // Writes one human document through the centralized block renderer.
    fn write_presentation(
        &mut self,
        presentation: &CommandPresentation,
    ) -> Result<(), CliDisplayError> {
        for block in presentation.blocks() {
            match block {
                DisplayBlock::Result {
                    title,
                    detail,
                    semantic,
                } => {
                    let mark = semantic_mark(*semantic);
                    writeln!(self.standard_output, "{mark} {title}")?;
                    if let Some(detail) = detail {
                        writeln!(self.standard_output, "  {detail}")?;
                    }
                }
                DisplayBlock::Records(records) => {
                    for record in records {
                        let detail = record
                            .detail
                            .as_ref()
                            .map(|value| format!(" · {value}"))
                            .unwrap_or_default();
                        writeln!(
                            self.standard_output,
                            "{}: {}{}",
                            record.label, record.value, detail
                        )?;
                    }
                }
                DisplayBlock::Table(table) => {
                    writeln!(self.standard_output, "{}", table.headings.join("  "))?;
                    for row in &table.rows {
                        writeln!(self.standard_output, "{}", row.join("  "))?;
                    }
                }
                DisplayBlock::Verbatim { label, value } => {
                    if let Some(label) = label {
                        writeln!(self.standard_output, "{label}")?;
                    }
                    write!(self.standard_output, "{value}")?;
                    if !value.ends_with('\n') {
                        writeln!(self.standard_output)?;
                    }
                }
                DisplayBlock::OneTimeSecret { label, value } => {
                    if let Some(label) = label {
                        writeln!(self.standard_output, "{label}")?;
                    }
                    let value = value.take()?;
                    write!(self.standard_output, "{value}")?;
                    if !value.ends_with('\n') {
                        writeln!(self.standard_output)?;
                    }
                }
                DisplayBlock::Raw(value) => {
                    write!(self.standard_output, "{value}")?;
                    if !value.ends_with('\n') {
                        writeln!(self.standard_output)?;
                    }
                }
                DisplayBlock::RawBytes(value) => {
                    self.standard_output.write_all(value)?;
                }
            }
        }
        self.standard_output.flush()?;
        Ok(())
    }
}

impl<StandardOutput, StandardError> CliDisplayPort
    for StreamCliDisplay<StandardOutput, StandardError>
where
    StandardOutput: Write,
    StandardError: Write,
{
    // Renders each semantic event through its one declared stream.
    fn display(&mut self, event: DisplayEvent) -> Result<(), CliDisplayError> {
        match event {
            DisplayEvent::Header { title } => {
                writeln!(self.standard_error, "LET'S INFER · {title}")?;
            }
            DisplayEvent::ProgressStarted { message } => {
                writeln!(self.standard_error, "WORKING: {message}")?;
            }
            DisplayEvent::ProgressDetail { message } => {
                writeln!(self.standard_error, "  {message}")?;
            }
            DisplayEvent::ProgressStep {
                completed,
                total,
                message,
            } => {
                writeln!(self.standard_error, "  STEP {completed}/{total}: {message}")?;
            }
            DisplayEvent::ProgressCompleted { message } => {
                writeln!(self.standard_error, "OK: {message}")?;
            }
            DisplayEvent::ProgressFailed => {
                writeln!(self.standard_error, "FAILED")?;
            }
            DisplayEvent::RawOutput(value) => {
                self.standard_output.write_all(&value)?;
                self.standard_output.flush()?;
            }
            DisplayEvent::HumanDocument(presentation) => {
                self.write_presentation(&presentation)?;
            }
            DisplayEvent::MachineDocument(value) => {
                writeln!(self.standard_output, "{}", value.to_json()?)?;
                self.standard_output.flush()?;
            }
            DisplayEvent::NotAllowed { message } => {
                writeln!(self.standard_error, "NOT ALLOWED: {message}")?;
            }
            DisplayEvent::Denied { message } => {
                writeln!(self.standard_error, "{message}")?;
            }
            DisplayEvent::Cancelled => {
                writeln!(self.standard_error, "Cancelled")?;
            }
            DisplayEvent::Fatal { code: _, message } => {
                writeln!(self.standard_error, "FATAL: {message}")?;
            }
        }
        self.standard_error.flush()?;
        Ok(())
    }
}

// Returns the explicit presentation contract for one exact action.
pub const fn display_contract(action: ActionId) -> DisplayContract {
    use DisplayOutputContract as Output;
    use DisplayProgressKind as Progress;
    use DisplaySurface as Surface;

    match action {
        ActionId::Status => contract(
            action,
            "Status",
            Surface::FrozenStatus,
            Output::FrozenStatus,
            Progress::Live,
            true,
            None,
            None,
            &[],
        ),
        ActionId::Topology => contract(
            action,
            "Topology",
            Surface::Live,
            Output::LiveDashboard,
            Progress::Live,
            true,
            None,
            None,
            &[],
        ),
        ActionId::Doctor => contract(
            action,
            "Doctor",
            Surface::Detail,
            Output::Record,
            Progress::Spinner,
            true,
            Some("Checking node readiness"),
            Some("Readiness check complete"),
            &[],
        ),
        ActionId::Uninstall => contract(
            action,
            "Uninstall",
            Surface::Workflow,
            Output::MutationResult,
            Progress::Spinner,
            true,
            Some("Removing the service"),
            Some("Service removed"),
            &[],
        ),
        ActionId::NodeInfo => contract(
            action,
            "Node Information",
            Surface::Workflow,
            Output::Record,
            Progress::None,
            true,
            None,
            None,
            &[],
        ),
        ActionId::NodeList => contract(
            action,
            "Nodes",
            Surface::List,
            Output::Table,
            Progress::None,
            true,
            None,
            None,
            &[],
        ),
        ActionId::NodeUsage => contract(
            action,
            "Node Usage",
            Surface::Workflow,
            Output::Record,
            Progress::None,
            true,
            None,
            None,
            &[],
        ),
        ActionId::NodeAdd => contract(
            action,
            "Add Node",
            Surface::Workflow,
            Output::SensitiveResult,
            Progress::Live,
            true,
            None,
            None,
            &[],
        ),
        ActionId::NodePause => contract(
            action,
            "Pause Node",
            Surface::Workflow,
            Output::MutationResult,
            Progress::Spinner,
            true,
            Some("Pausing the child"),
            Some("Child paused"),
            &[],
        ),
        ActionId::NodeResume => contract(
            action,
            "Resume Node",
            Surface::Workflow,
            Output::MutationResult,
            Progress::Spinner,
            true,
            Some("Resuming the child"),
            Some("Child active"),
            &[],
        ),
        ActionId::NodeRemove => contract(
            action,
            "Remove Node",
            Surface::Workflow,
            Output::MutationResult,
            Progress::Spinner,
            true,
            Some("Removing the child"),
            Some("Child removed"),
            &[],
        ),
        ActionId::ModelList => contract(
            action,
            "Models",
            Surface::List,
            Output::Table,
            Progress::Spinner,
            true,
            Some("Loading models"),
            Some("Models loaded"),
            &[],
        ),
        ActionId::ModelInstall => contract(
            action,
            "Install Model",
            Surface::Workflow,
            Output::MutationResult,
            Progress::Spinner,
            true,
            Some("Installing models"),
            Some("Models installed"),
            &[],
        ),
        ActionId::ModelRemove => contract(
            action,
            "Remove Model",
            Surface::Mutation,
            Output::MutationResult,
            Progress::Spinner,
            true,
            Some("Removing the model"),
            Some("Model removed"),
            &[],
        ),
        ActionId::ModelPause => contract(
            action,
            "Pause Model",
            Surface::Mutation,
            Output::MutationResult,
            Progress::Spinner,
            true,
            Some("Pausing inference"),
            Some("Model paused"),
            &[],
        ),
        ActionId::ModelResume => contract(
            action,
            "Resume Model",
            Surface::Mutation,
            Output::MutationResult,
            Progress::Spinner,
            true,
            Some("Checking model data and resuming inference"),
            Some("Model active"),
            &[],
        ),
        ActionId::ModelRestart => contract(
            action,
            "Restart Model",
            Surface::Mutation,
            Output::MutationResult,
            Progress::Spinner,
            true,
            Some("Checking model data and restarting inference"),
            Some("Model active"),
            &[],
        ),
        ActionId::ModelRecover => contract(
            action,
            "Recover Model",
            Surface::Mutation,
            Output::MutationResult,
            Progress::Spinner,
            true,
            Some("Checking model data and recovering inference"),
            Some("Model recovered"),
            &[],
        ),
        ActionId::ModelRollback => contract(
            action,
            "Roll Back Model",
            Surface::Mutation,
            Output::MutationResult,
            Progress::Spinner,
            true,
            Some("Restoring the previous runtime"),
            Some("Model restored"),
            &[],
        ),
        ActionId::ModelLogs => contract(
            action,
            "Model Logs",
            Surface::Raw,
            Output::RawStandardOutput,
            Progress::Passthrough,
            true,
            None,
            None,
            &[],
        ),
        ActionId::BenchmarkRun => live_contract(action, "Run Benchmark"),
        ActionId::BenchmarkList => contract(
            action,
            "Benchmark Cells",
            Surface::List,
            Output::Table,
            Progress::None,
            true,
            None,
            None,
            &[],
        ),
        ActionId::BenchmarkStatus => live_contract(action, "Benchmark Status"),
        ActionId::BenchmarkStop => live_contract(action, "Stop Benchmark"),
        ActionId::BenchmarkClean => live_contract(action, "Clean Benchmarks"),
        ActionId::BenchmarkVerificationRun => live_contract(action, "Verify Runtime Proposal"),
        ActionId::BenchmarkVerificationStatus => live_contract(action, "Verification Status"),
        ActionId::BenchmarkVerificationStop => live_contract(action, "Stop Verification"),
        ActionId::AuthControllerAdd => contract(
            action,
            "Add Controller",
            Surface::Workflow,
            Output::SensitiveResult,
            Progress::Live,
            true,
            None,
            None,
            &[],
        ),
        ActionId::AuthControllerList => contract(
            action,
            "Controllers",
            Surface::List,
            Output::Table,
            Progress::None,
            true,
            None,
            None,
            &[],
        ),
        ActionId::AuthControllerRevoke => contract(
            action,
            "Revoke Controller",
            Surface::Mutation,
            Output::MutationResult,
            Progress::Spinner,
            true,
            Some("Revoking the controller"),
            Some("Controller revoked"),
            &[],
        ),
        ActionId::AuthKeyCreate => contract(
            action,
            "Create API Key",
            Surface::Workflow,
            Output::OneTimeSecret,
            Progress::Spinner,
            true,
            Some("Creating the API key"),
            Some("API key created"),
            &[],
        ),
        ActionId::AuthKeyList => contract(
            action,
            "API Keys",
            Surface::List,
            Output::Table,
            Progress::None,
            true,
            None,
            None,
            &[],
        ),
        ActionId::AuthKeyShow => contract(
            action,
            "API Key",
            Surface::Detail,
            Output::Record,
            Progress::None,
            true,
            None,
            None,
            &[],
        ),
        ActionId::AuthKeyRotate => contract(
            action,
            "Rotate API Key",
            Surface::Workflow,
            Output::OneTimeSecret,
            Progress::Spinner,
            true,
            Some("Rotating the API key"),
            Some("API key rotated"),
            &[],
        ),
        ActionId::AuthKeyRevoke => contract(
            action,
            "Revoke API Key",
            Surface::Mutation,
            Output::MutationResult,
            Progress::Spinner,
            true,
            Some("Revoking the API key"),
            Some("API key revoked"),
            &[],
        ),
        ActionId::AuthKeyUpdate => contract(
            action,
            "Update API Key",
            Surface::Mutation,
            Output::MutationResult,
            Progress::Spinner,
            true,
            Some("Updating the API key"),
            Some("API key updated"),
            &[],
        ),
        ActionId::ExposureStatus => contract(
            action,
            "Exposure",
            Surface::Detail,
            Output::Record,
            Progress::Spinner,
            true,
            Some("Checking public exposure"),
            Some("Exposure checked"),
            &[],
        ),
        ActionId::ExposureEnable => contract(
            action,
            "Enable Exposure",
            Surface::Mutation,
            Output::MutationResult,
            Progress::Spinner,
            true,
            Some("Enabling public inference"),
            Some("Public inference enabled"),
            &[],
        ),
        ActionId::ExposureDisable => contract(
            action,
            "Disable Exposure",
            Surface::Mutation,
            Output::MutationResult,
            Progress::Spinner,
            true,
            Some("Disabling public inference"),
            Some("Public inference disabled"),
            &[],
        ),
        ActionId::AuditList => contract(
            action,
            "Audit Events",
            Surface::List,
            Output::Table,
            Progress::None,
            true,
            None,
            None,
            &[],
        ),
        ActionId::AuditShow => contract(
            action,
            "Audit Event",
            Surface::Detail,
            Output::Record,
            Progress::None,
            true,
            None,
            None,
            &[],
        ),
        ActionId::AuditVerify => contract(
            action,
            "Verify Audit Chain",
            Surface::Detail,
            Output::Record,
            Progress::Spinner,
            true,
            Some("Verifying the audit chain"),
            Some("Audit chain verified"),
            &[],
        ),
        ActionId::AuditExport => contract(
            action,
            "Export Audit Chain",
            Surface::Mutation,
            Output::ArtifactResult,
            Progress::Spinner,
            true,
            Some("Exporting the audit chain"),
            Some("Audit chain exported"),
            &[],
        ),
        ActionId::UpdateCheck => contract(
            action,
            "Check for Updates",
            Surface::Detail,
            Output::Record,
            Progress::Spinner,
            true,
            Some("Checking for updates"),
            Some("Update check complete"),
            &[],
        ),
        ActionId::UpdateCore => contract(
            action,
            "Update Core",
            Surface::Mutation,
            Output::MutationResult,
            Progress::Steps,
            true,
            Some("Updating Let's Infer Core"),
            Some("Core updated"),
            &[
                "Resolve and install core",
                "Rebind services and runtime",
                "Verify update",
            ],
        ),
        ActionId::UpdateModel => contract(
            action,
            "Update Model",
            Surface::Mutation,
            Output::MutationResult,
            Progress::Spinner,
            true,
            Some("Updating model runtimes"),
            Some("Models updated"),
            &[],
        ),
    }
}

// Resolves JSON before internal mode so hidden setup and prune retain machine output.
pub fn command_output_mode(
    invocation: &CommandInvocation,
    contract: DisplayContract,
) -> CommandOutputMode {
    if invocation.boolean(ArgumentId::Json) == Some(true) {
        CommandOutputMode::Json
    } else if invocation.action() == ActionId::AuditExport
        && invocation.argument(ArgumentId::Output).is_none()
    {
        CommandOutputMode::Internal
    } else if contract.surface() == DisplaySurface::Internal {
        CommandOutputMode::Internal
    } else {
        CommandOutputMode::Human
    }
}

// Constructs one explicit display contract without inferring policy from authorization.
const fn contract(
    action: ActionId,
    title: &'static str,
    surface: DisplaySurface,
    output: DisplayOutputContract,
    progress: DisplayProgressKind,
    branded: bool,
    progress_start: Option<&'static str>,
    progress_done: Option<&'static str>,
    steps: &'static [&'static str],
) -> DisplayContract {
    DisplayContract {
        action,
        title,
        surface,
        output,
        progress,
        branded,
        progress_start,
        progress_done,
        steps,
    }
}

// Constructs one benchmark-owned live surface without generic progress language.
const fn live_contract(action: ActionId, title: &'static str) -> DisplayContract {
    contract(
        action,
        title,
        DisplaySurface::Live,
        DisplayOutputContract::LiveDashboard,
        DisplayProgressKind::Live,
        true,
        None,
        None,
        &[],
    )
}

// Returns one stable plain mark for a semantic result row.
const fn semantic_mark(semantic: DisplaySemantic) -> &'static str {
    match semantic {
        DisplaySemantic::Information => "INFO",
        DisplaySemantic::Working => "WORKING",
        DisplaySemantic::Success => "OK",
        DisplaySemantic::Warning => "WARNING",
        DisplaySemantic::Pressure => "PRESSURE",
        DisplaySemantic::Error => "ERROR",
        DisplaySemantic::Muted => "-",
    }
}

// Recursively writes one deterministic JSON value into the supplied string.
fn write_machine_value(
    value: &MachineValue,
    output: &mut String,
) -> Result<(), DisplayContractError> {
    match value {
        MachineValue::Null => output.push_str("null"),
        MachineValue::Boolean(value) => output.push_str(if *value { "true" } else { "false" }),
        MachineValue::Integer(value) => output.push_str(&value.to_string()),
        MachineValue::Unsigned(value) => output.push_str(&value.to_string()),
        MachineValue::Number(value) => output.push_str(value.as_str()),
        MachineValue::String(value) => write_json_string(value, output),
        MachineValue::OneTimeSecret(value) => write_json_string(&value.take()?, output),
        MachineValue::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                write_machine_value(value, output)?;
            }
            output.push(']');
        }
        MachineValue::Object(values) => {
            output.push('{');
            for (index, (key, value)) in values.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                write_json_string(key, output);
                output.push(':');
                write_machine_value(value, output)?;
            }
            output.push('}');
        }
    }
    Ok(())
}

// Escapes one JSON string without changing Unicode scalar values.
fn write_json_string(value: &str, output: &mut String) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character <= '\u{1f}' => {
                output.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => output.push(character),
        }
    }
    output.push('"');
}
