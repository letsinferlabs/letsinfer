// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::ActionId;

// Names every typed value accepted by the current Core command surface.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ArgumentId {
    Address,
    Approve,
    AllNodes,
    AllTargets,
    ApiKeyFile,
    Application,
    BaseUrl,
    C1,
    C2,
    C4,
    C8,
    C16,
    CaCertFile,
    Candidate,
    Catalog,
    Category,
    CertificateSha256,
    Clean,
    Concurrency,
    Container,
    Context32k,
    Context64k,
    Context128k,
    Context256k,
    Controller,
    Detach,
    DryRun,
    Event,
    ExpiresAt,
    Follow,
    Interface,
    Installed,
    Invitation,
    Json,
    KeepModels,
    Key,
    LaunchDirectory,
    Limit,
    MaxContext,
    MeasuredCommit,
    Member,
    Model,
    Mode,
    Name,
    Node,
    Output,
    OutputDirectory,
    PlacementGroup,
    PullRequest,
    Refresh,
    RequestsPerMinute,
    RequireStable,
    ResidentPlacementGroup,
    Role,
    Runtime,
    SourceAttestation,
    StoreRoot,
    Tail,
    Target,
    Tenant,
    Timeout,
    TokensPerMinute,
    Version,
    Versions,
    WatchdogTripFile,
    Join,
    Yes,
}

// Holds one canonical parsed value without untyped string-key lookups.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArgumentValue {
    Boolean(bool),
    Integer(i64),
    Path(PathBuf),
    Text(String),
    TextList(Vec<String>),
}

// Holds one exact leaf identity and its typed normalized arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandInvocation {
    action: ActionId,
    arguments: BTreeMap<ArgumentId, ArgumentValue>,
}

impl CommandInvocation {
    // Creates one parsed invocation after the declarative parser validates it.
    pub(crate) fn new(action: ActionId, arguments: BTreeMap<ArgumentId, ArgumentValue>) -> Self {
        Self { action, arguments }
    }

    // Returns the exact leaf action selected by the argument path.
    pub const fn action(&self) -> ActionId {
        self.action
    }

    // Returns one typed parsed value when the command declares it.
    pub fn argument(&self, id: ArgumentId) -> Option<&ArgumentValue> {
        self.arguments.get(&id)
    }

    // Returns one typed boolean and rejects value-kind confusion.
    pub fn boolean(&self, id: ArgumentId) -> Option<bool> {
        match self.argument(id) {
            Some(ArgumentValue::Boolean(value)) => Some(*value),
            _ => None,
        }
    }

    // Returns one typed integer and rejects value-kind confusion.
    pub fn integer(&self, id: ArgumentId) -> Option<i64> {
        match self.argument(id) {
            Some(ArgumentValue::Integer(value)) => Some(*value),
            _ => None,
        }
    }

    // Returns one typed filesystem path and rejects value-kind confusion.
    pub fn path(&self, id: ArgumentId) -> Option<&Path> {
        match self.argument(id) {
            Some(ArgumentValue::Path(value)) => Some(value),
            _ => None,
        }
    }

    // Returns one typed text value and rejects value-kind confusion.
    pub fn text(&self, id: ArgumentId) -> Option<&str> {
        match self.argument(id) {
            Some(ArgumentValue::Text(value)) => Some(value),
            _ => None,
        }
    }

    // Returns one repeatable text value and rejects value-kind confusion.
    pub fn text_list(&self, id: ArgumentId) -> Option<&[String]> {
        match self.argument(id) {
            Some(ArgumentValue::TextList(value)) => Some(value),
            _ => None,
        }
    }
}

// Describes the value syntax of one declared long option.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OptionValueKind {
    Flag,
    Integer,
    Path,
    Text,
    RepeatedText,
}

// Describes one argparse-compatible explicit default.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OptionDefault {
    None,
    Integer(i64),
    Text(&'static str),
    EmptyTextList,
}

// Describes one exact long option on a command leaf.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OptionSpec {
    pub(crate) name: &'static str,
    pub(crate) argument: ArgumentId,
    pub(crate) kind: OptionValueKind,
    pub(crate) required: bool,
    pub(crate) default: OptionDefault,
    pub(crate) choices: &'static [&'static str],
}

// Describes one ordered positional value on a command leaf.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PositionalSpec {
    pub(crate) argument: ArgumentId,
    pub(crate) required: bool,
}

// Declares one exact parser leaf independently of any handler implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandSpec {
    action: ActionId,
    path: &'static [&'static str],
    options: &'static [OptionSpec],
    positionals: &'static [PositionalSpec],
}

impl CommandSpec {
    // Returns the action bound to this exact parser leaf.
    pub const fn action(self) -> ActionId {
        self.action
    }

    // Returns the exact command words that select this leaf.
    pub const fn path(self) -> &'static [&'static str] {
        self.path
    }

    // Returns the leaf's private option declarations to the parser.
    pub(crate) const fn options(self) -> &'static [OptionSpec] {
        self.options
    }

    // Returns the leaf's ordered positional declarations to the parser.
    pub(crate) const fn positionals(self) -> &'static [PositionalSpec] {
        self.positionals
    }
}

// Creates one declarative command leaf.
const fn command(
    action: ActionId,
    path: &'static [&'static str],
    options: &'static [OptionSpec],
    positionals: &'static [PositionalSpec],
) -> CommandSpec {
    CommandSpec {
        action,
        path,
        options,
        positionals,
    }
}

// Creates one optional boolean flag with argparse's false default.
const fn flag(name: &'static str, argument: ArgumentId) -> OptionSpec {
    OptionSpec {
        name,
        argument,
        kind: OptionValueKind::Flag,
        required: false,
        default: OptionDefault::None,
        choices: &[],
    }
}

// Creates one optional text option without a fabricated default.
const fn text(name: &'static str, argument: ArgumentId) -> OptionSpec {
    OptionSpec {
        name,
        argument,
        kind: OptionValueKind::Text,
        required: false,
        default: OptionDefault::None,
        choices: &[],
    }
}

// Creates one optional filesystem-path option without touching the filesystem.
const fn path(name: &'static str, argument: ArgumentId) -> OptionSpec {
    OptionSpec {
        name,
        argument,
        kind: OptionValueKind::Path,
        required: false,
        default: OptionDefault::None,
        choices: &[],
    }
}

// Creates one optional text option constrained to a closed vocabulary.
const fn choice(
    name: &'static str,
    argument: ArgumentId,
    choices: &'static [&'static str],
    default: OptionDefault,
) -> OptionSpec {
    OptionSpec {
        name,
        argument,
        kind: OptionValueKind::Text,
        required: false,
        default,
        choices,
    }
}

// Creates one optional integer option without a fabricated default.
const fn integer(name: &'static str, argument: ArgumentId) -> OptionSpec {
    OptionSpec {
        name,
        argument,
        kind: OptionValueKind::Integer,
        required: false,
        default: OptionDefault::None,
        choices: &[],
    }
}

// Creates one optional integer option with an explicit parser default.
const fn integer_default(name: &'static str, argument: ArgumentId, default: i64) -> OptionSpec {
    OptionSpec {
        default: OptionDefault::Integer(default),
        ..integer(name, argument)
    }
}

// Creates one append option preserving absence instead of inventing an empty list.
const fn repeated_text(name: &'static str, argument: ArgumentId) -> OptionSpec {
    OptionSpec {
        name,
        argument,
        kind: OptionValueKind::RepeatedText,
        required: false,
        default: OptionDefault::None,
        choices: &[],
    }
}

// Creates one append option with argparse's explicit empty-list default.
const fn repeated_text_empty(name: &'static str, argument: ArgumentId) -> OptionSpec {
    OptionSpec {
        default: OptionDefault::EmptyTextList,
        ..repeated_text(name, argument)
    }
}

// Creates one append option constrained to a closed vocabulary.
const fn repeated_choice(
    name: &'static str,
    argument: ArgumentId,
    choices: &'static [&'static str],
) -> OptionSpec {
    OptionSpec {
        choices,
        ..repeated_text(name, argument)
    }
}

// Creates one required positional value.
const fn required(argument: ArgumentId) -> PositionalSpec {
    PositionalSpec {
        argument,
        required: true,
    }
}

// Creates one optional positional value.
const fn optional(argument: ArgumentId) -> PositionalSpec {
    PositionalSpec {
        argument,
        required: false,
    }
}

const JSON: &[OptionSpec] = &[flag("--json", ArgumentId::Json)];
const MODEL_REQUIRED: &[PositionalSpec] = &[required(ArgumentId::Model)];
const KEY_REQUIRED: &[PositionalSpec] = &[required(ArgumentId::Key)];
const BENCHMARK_SELECTIONS: &[OptionSpec] = &[
    flag("--c1", ArgumentId::C1),
    flag("--c2", ArgumentId::C2),
    flag("--c4", ArgumentId::C4),
    flag("--c8", ArgumentId::C8),
    flag("--c16", ArgumentId::C16),
    flag("--32k", ArgumentId::Context32k),
    flag("--64k", ArgumentId::Context64k),
    flag("--128k", ArgumentId::Context128k),
    flag("--256k", ArgumentId::Context256k),
    flag("--json", ArgumentId::Json),
];
const KEY_POLICY_CREATE: &[OptionSpec] = &[
    repeated_text_empty("--model", ArgumentId::Model),
    integer("--expires-at", ArgumentId::ExpiresAt),
    integer("--requests-per-minute", ArgumentId::RequestsPerMinute),
    integer("--tokens-per-minute", ArgumentId::TokensPerMinute),
    integer("--concurrency", ArgumentId::Concurrency),
    integer("--max-context", ArgumentId::MaxContext),
    text("--tenant", ArgumentId::Tenant),
    text("--application", ArgumentId::Application),
    flag("--json", ArgumentId::Json),
];
const KEY_POLICY_UPDATE: &[OptionSpec] = &[
    repeated_text("--model", ArgumentId::Model),
    integer("--expires-at", ArgumentId::ExpiresAt),
    integer("--requests-per-minute", ArgumentId::RequestsPerMinute),
    integer("--tokens-per-minute", ArgumentId::TokensPerMinute),
    integer("--concurrency", ArgumentId::Concurrency),
    integer("--max-context", ArgumentId::MaxContext),
    text("--tenant", ArgumentId::Tenant),
    text("--application", ArgumentId::Application),
    flag("--json", ArgumentId::Json),
];

const COMMANDS: &[CommandSpec] = &[
    command(ActionId::Status, &["status"], JSON, &[]),
    command(ActionId::Topology, &["topology"], JSON, &[]),
    command(
        ActionId::Doctor,
        &["doctor"],
        &[
            flag("--json", ArgumentId::Json),
            flag("--require-stable", ArgumentId::RequireStable),
        ],
        &[],
    ),
    command(
        ActionId::Uninstall,
        &["uninstall"],
        &[
            flag("--keep-models", ArgumentId::KeepModels),
            flag("--json", ArgumentId::Json),
            flag("--yes", ArgumentId::Yes),
        ],
        &[],
    ),
    command(
        ActionId::NodeInfo,
        &["node", "info"],
        &[
            text("--catalog", ArgumentId::Catalog),
            flag("--json", ArgumentId::Json),
        ],
        &[optional(ArgumentId::Node)],
    ),
    command(ActionId::NodeList, &["node", "list"], JSON, &[]),
    command(
        ActionId::NodeUsage,
        &["node", "usage"],
        &[
            flag("--clean", ArgumentId::Clean),
            repeated_choice(
                "--category",
                ArgumentId::Category,
                &["benchmarks", "caches", "models"],
            ),
            flag("--yes", ArgumentId::Yes),
            flag("--json", ArgumentId::Json),
        ],
        &[],
    ),
    command(
        ActionId::NodeAdd,
        &["node", "add"],
        &[
            flag("--join", ArgumentId::Join),
            text("--approve", ArgumentId::Approve),
            choice(
                "--mode",
                ArgumentId::Mode,
                &["lan", "remote", "connectx"],
                OptionDefault::Text("lan"),
            ),
            text("--invitation", ArgumentId::Invitation),
            text("--address", ArgumentId::Address),
            text("--certificate-sha256", ArgumentId::CertificateSha256),
            text("--interface", ArgumentId::Interface),
            flag("--yes", ArgumentId::Yes),
            integer_default("--timeout", ArgumentId::Timeout, 180),
            flag("--json", ArgumentId::Json),
        ],
        &[],
    ),
    command(
        ActionId::NodePause,
        &["node", "pause"],
        &[
            flag("--yes", ArgumentId::Yes),
            flag("--json", ArgumentId::Json),
        ],
        &[optional(ArgumentId::Member)],
    ),
    command(
        ActionId::NodeResume,
        &["node", "resume"],
        &[
            flag("--yes", ArgumentId::Yes),
            flag("--json", ArgumentId::Json),
        ],
        &[optional(ArgumentId::Member)],
    ),
    command(
        ActionId::NodeRemove,
        &["node", "remove"],
        &[
            flag("--yes", ArgumentId::Yes),
            flag("--json", ArgumentId::Json),
        ],
        &[optional(ArgumentId::Member)],
    ),
    command(
        ActionId::ModelList,
        &["model", "list"],
        &[
            flag("--versions", ArgumentId::Versions),
            flag("--all-targets", ArgumentId::AllTargets),
            flag("--installed", ArgumentId::Installed),
            flag("--refresh", ArgumentId::Refresh),
            text("--catalog", ArgumentId::Catalog),
            flag("--json", ArgumentId::Json),
        ],
        &[optional(ArgumentId::Model)],
    ),
    command(
        ActionId::ModelInstall,
        &["model", "install"],
        &[
            text("--runtime", ArgumentId::Runtime),
            text("--catalog", ArgumentId::Catalog),
            repeated_text("--node", ArgumentId::Node),
            flag("--all-nodes", ArgumentId::AllNodes),
            flag("--json", ArgumentId::Json),
        ],
        &[optional(ArgumentId::Model)],
    ),
    command(
        ActionId::ModelRemove,
        &["model", "remove"],
        &[
            repeated_text("--node", ArgumentId::Node),
            flag("--all-nodes", ArgumentId::AllNodes),
            flag("--json", ArgumentId::Json),
        ],
        MODEL_REQUIRED,
    ),
    command(
        ActionId::ModelPause,
        &["model", "pause"],
        &[],
        MODEL_REQUIRED,
    ),
    command(
        ActionId::ModelResume,
        &["model", "resume"],
        &[],
        MODEL_REQUIRED,
    ),
    command(
        ActionId::ModelRestart,
        &["model", "restart"],
        &[],
        MODEL_REQUIRED,
    ),
    command(
        ActionId::ModelRecover,
        &["model", "recover"],
        &[],
        MODEL_REQUIRED,
    ),
    command(
        ActionId::ModelRollback,
        &["model", "rollback"],
        &[
            text("--target", ArgumentId::Target),
            flag("--dry-run", ArgumentId::DryRun),
            flag("--yes", ArgumentId::Yes),
            flag("--json", ArgumentId::Json),
        ],
        MODEL_REQUIRED,
    ),
    command(
        ActionId::ModelLogs,
        &["model", "logs"],
        &[
            text("--placement-group", ArgumentId::PlacementGroup),
            integer_default("--tail", ArgumentId::Tail, 200),
            flag("--follow", ArgumentId::Follow),
        ],
        MODEL_REQUIRED,
    ),
    command(
        ActionId::BenchmarkRun,
        &["benchmark", "run"],
        BENCHMARK_SELECTIONS,
        MODEL_REQUIRED,
    ),
    command(
        ActionId::BenchmarkList,
        &["benchmark", "list"],
        BENCHMARK_SELECTIONS,
        MODEL_REQUIRED,
    ),
    command(
        ActionId::BenchmarkStatus,
        &["benchmark", "status"],
        JSON,
        &[],
    ),
    command(ActionId::BenchmarkStop, &["benchmark", "stop"], JSON, &[]),
    command(
        ActionId::BenchmarkClean,
        &["benchmark", "clean"],
        &[
            flag("--yes", ArgumentId::Yes),
            flag("--json", ArgumentId::Json),
        ],
        &[],
    ),
    command(
        ActionId::BenchmarkVerificationRun,
        &["benchmark", "verification", "run"],
        &[
            text("--candidate", ArgumentId::Candidate),
            flag("--detach", ArgumentId::Detach),
            flag("--json", ArgumentId::Json),
        ],
        &[required(ArgumentId::PullRequest)],
    ),
    command(
        ActionId::BenchmarkVerificationStatus,
        &["benchmark", "verification", "status"],
        JSON,
        &[],
    ),
    command(
        ActionId::BenchmarkVerificationStop,
        &["benchmark", "verification", "stop"],
        JSON,
        &[],
    ),
    command(
        ActionId::AuthControllerAdd,
        &["auth", "controller", "add"],
        &[
            integer_default("--timeout", ArgumentId::Timeout, 180),
            choice(
                "--role",
                ArgumentId::Role,
                &["viewer", "operator", "administrator"],
                OptionDefault::Text("administrator"),
            ),
        ],
        &[],
    ),
    command(
        ActionId::AuthControllerList,
        &["auth", "controller", "list"],
        JSON,
        &[],
    ),
    command(
        ActionId::AuthControllerRevoke,
        &["auth", "controller", "revoke"],
        JSON,
        &[required(ArgumentId::Controller)],
    ),
    command(
        ActionId::AuthKeyCreate,
        &["auth", "key", "create"],
        KEY_POLICY_CREATE,
        &[required(ArgumentId::Name)],
    ),
    command(ActionId::AuthKeyList, &["auth", "key", "list"], JSON, &[]),
    command(
        ActionId::AuthKeyShow,
        &["auth", "key", "show"],
        JSON,
        KEY_REQUIRED,
    ),
    command(
        ActionId::AuthKeyRotate,
        &["auth", "key", "rotate"],
        JSON,
        KEY_REQUIRED,
    ),
    command(
        ActionId::AuthKeyRevoke,
        &["auth", "key", "revoke"],
        JSON,
        KEY_REQUIRED,
    ),
    command(
        ActionId::AuthKeyUpdate,
        &["auth", "key", "update"],
        KEY_POLICY_UPDATE,
        KEY_REQUIRED,
    ),
    command(ActionId::ExposureStatus, &["exposure", "status"], JSON, &[]),
    command(ActionId::ExposureEnable, &["exposure", "enable"], JSON, &[]),
    command(
        ActionId::ExposureDisable,
        &["exposure", "disable"],
        JSON,
        &[],
    ),
    command(
        ActionId::AuditList,
        &["audit", "list"],
        &[
            integer_default("--limit", ArgumentId::Limit, 100),
            flag("--json", ArgumentId::Json),
        ],
        &[],
    ),
    command(
        ActionId::AuditShow,
        &["audit", "show"],
        JSON,
        &[required(ArgumentId::Event)],
    ),
    command(ActionId::AuditVerify, &["audit", "verify"], JSON, &[]),
    command(
        ActionId::AuditExport,
        &["audit", "export"],
        &[path("--output", ArgumentId::Output)],
        &[],
    ),
    command(
        ActionId::UpdateCheck,
        &["update", "check"],
        &[
            text("--catalog", ArgumentId::Catalog),
            flag("--json", ArgumentId::Json),
        ],
        &[],
    ),
    command(
        ActionId::UpdateCore,
        &["update", "core"],
        &[
            flag("--yes", ArgumentId::Yes),
            flag("--json", ArgumentId::Json),
        ],
        &[optional(ArgumentId::Version)],
    ),
    command(
        ActionId::UpdateModel,
        &["update", "model"],
        &[
            text("--target", ArgumentId::Target),
            text("--catalog", ArgumentId::Catalog),
            flag("--dry-run", ArgumentId::DryRun),
            flag("--yes", ArgumentId::Yes),
            flag("--json", ArgumentId::Json),
        ],
        &[optional(ArgumentId::Model)],
    ),
];

// Returns the complete immutable parser leaf registry.
pub const fn command_specs() -> &'static [CommandSpec] {
    COMMANDS
}
