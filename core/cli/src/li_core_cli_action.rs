// SPDX-License-Identifier: AGPL-3.0-only

// Describes the node role on which one command may execute.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CommandScope {
    Main,
    Child,
    All,
}

// Classifies whether one public command reads or mutates local or node state.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MutationClass {
    Read,
    Local,
    Node,
}

// Describes the audit record required around one command lifecycle.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AuditPolicy {
    None,
    Success,
    Always,
    SensitiveRead,
}

// Names every exact public Core command without aliases.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ActionId {
    Status,
    Topology,
    Doctor,
    Uninstall,
    NodeInfo,
    NodeList,
    NodeUsage,
    NodeAdd,
    NodePause,
    NodeResume,
    NodeRemove,
    ModelList,
    ModelInstall,
    ModelRemove,
    ModelPause,
    ModelResume,
    ModelRestart,
    ModelRecover,
    ModelRollback,
    ModelLogs,
    BenchmarkRun,
    BenchmarkList,
    BenchmarkStatus,
    BenchmarkStop,
    BenchmarkClean,
    BenchmarkVerificationRun,
    BenchmarkVerificationStatus,
    BenchmarkVerificationStop,
    AuthControllerAdd,
    AuthControllerList,
    AuthControllerRevoke,
    AuthKeyCreate,
    AuthKeyList,
    AuthKeyShow,
    AuthKeyRotate,
    AuthKeyRevoke,
    AuthKeyUpdate,
    ExposureStatus,
    ExposureEnable,
    ExposureDisable,
    AuditList,
    AuditShow,
    AuditVerify,
    AuditExport,
    UpdateCheck,
    UpdateCore,
    UpdateModel,
}

impl ActionId {
    // Returns the stable wire and audit identity of this action.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Topology => "topology",
            Self::Doctor => "doctor",
            Self::Uninstall => "uninstall",
            Self::NodeInfo => "node.info",
            Self::NodeList => "node.list",
            Self::NodeUsage => "node.usage",
            Self::NodeAdd => "node.add",
            Self::NodePause => "node.pause",
            Self::NodeResume => "node.resume",
            Self::NodeRemove => "node.remove",
            Self::ModelList => "model.list",
            Self::ModelInstall => "model.install",
            Self::ModelRemove => "model.remove",
            Self::ModelPause => "model.pause",
            Self::ModelResume => "model.resume",
            Self::ModelRestart => "model.restart",
            Self::ModelRecover => "model.recover",
            Self::ModelRollback => "model.rollback",
            Self::ModelLogs => "model.logs",
            Self::BenchmarkRun => "benchmark.run",
            Self::BenchmarkList => "benchmark.list",
            Self::BenchmarkStatus => "benchmark.status",
            Self::BenchmarkStop => "benchmark.stop",
            Self::BenchmarkClean => "benchmark.clean",
            Self::BenchmarkVerificationRun => "benchmark.verification.run",
            Self::BenchmarkVerificationStatus => "benchmark.verification.status",
            Self::BenchmarkVerificationStop => "benchmark.verification.stop",
            Self::AuthControllerAdd => "auth.controller.add",
            Self::AuthControllerList => "auth.controller.list",
            Self::AuthControllerRevoke => "auth.controller.revoke",
            Self::AuthKeyCreate => "auth.key.create",
            Self::AuthKeyList => "auth.key.list",
            Self::AuthKeyShow => "auth.key.show",
            Self::AuthKeyRotate => "auth.key.rotate",
            Self::AuthKeyRevoke => "auth.key.revoke",
            Self::AuthKeyUpdate => "auth.key.update",
            Self::ExposureStatus => "exposure.status",
            Self::ExposureEnable => "exposure.enable",
            Self::ExposureDisable => "exposure.disable",
            Self::AuditList => "audit.list",
            Self::AuditShow => "audit.show",
            Self::AuditVerify => "audit.verify",
            Self::AuditExport => "audit.export",
            Self::UpdateCheck => "update.check",
            Self::UpdateCore => "update.core",
            Self::UpdateModel => "update.model",
        }
    }
}

// Binds one action identity to its authorization and audit contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionMetadata {
    id: ActionId,
    scope: CommandScope,
    mutation: MutationClass,
    audit: AuditPolicy,
    requires_configured_node: bool,
}

impl ActionMetadata {
    // Returns the exact action identity.
    pub const fn id(self) -> ActionId {
        self.id
    }

    // Returns the explicit role scope without deriving a default.
    pub const fn scope(self) -> CommandScope {
        self.scope
    }

    // Returns the state-mutation class used by policy and presentation.
    pub const fn mutation(self) -> MutationClass {
        self.mutation
    }

    // Returns the audit lifecycle required for this action.
    pub const fn audit(self) -> AuditPolicy {
        self.audit
    }

    // Reports whether authorization requires a configured local node.
    pub const fn requires_configured_node(self) -> bool {
        self.requires_configured_node
    }
}

// Creates one closed metadata record for the declarative registry.
const fn metadata(
    id: ActionId,
    scope: CommandScope,
    mutation: MutationClass,
    audit: AuditPolicy,
    requires_configured_node: bool,
) -> ActionMetadata {
    ActionMetadata {
        id,
        scope,
        mutation,
        audit,
        requires_configured_node,
    }
}

const ACTIONS: &[ActionMetadata] = &[
    metadata(
        ActionId::Status,
        CommandScope::All,
        MutationClass::Read,
        AuditPolicy::None,
        true,
    ),
    metadata(
        ActionId::Topology,
        CommandScope::Main,
        MutationClass::Read,
        AuditPolicy::None,
        true,
    ),
    metadata(
        ActionId::Doctor,
        CommandScope::All,
        MutationClass::Read,
        AuditPolicy::None,
        true,
    ),
    metadata(
        ActionId::Uninstall,
        CommandScope::All,
        MutationClass::Node,
        AuditPolicy::None,
        false,
    ),
    metadata(
        ActionId::NodeInfo,
        CommandScope::All,
        MutationClass::Read,
        AuditPolicy::None,
        true,
    ),
    metadata(
        ActionId::NodeList,
        CommandScope::All,
        MutationClass::Read,
        AuditPolicy::None,
        true,
    ),
    metadata(
        ActionId::NodeUsage,
        CommandScope::All,
        MutationClass::Local,
        AuditPolicy::Always,
        true,
    ),
    metadata(
        ActionId::NodeAdd,
        CommandScope::All,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    metadata(
        ActionId::NodePause,
        CommandScope::All,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    metadata(
        ActionId::NodeResume,
        CommandScope::All,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    metadata(
        ActionId::NodeRemove,
        CommandScope::All,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    metadata(
        ActionId::ModelList,
        CommandScope::All,
        MutationClass::Read,
        AuditPolicy::None,
        false,
    ),
    metadata(
        ActionId::ModelInstall,
        CommandScope::Main,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    metadata(
        ActionId::ModelRemove,
        CommandScope::Main,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    metadata(
        ActionId::ModelPause,
        CommandScope::Main,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    metadata(
        ActionId::ModelResume,
        CommandScope::Main,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    metadata(
        ActionId::ModelRestart,
        CommandScope::Main,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    metadata(
        ActionId::ModelRecover,
        CommandScope::Main,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    metadata(
        ActionId::ModelRollback,
        CommandScope::Main,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    metadata(
        ActionId::ModelLogs,
        CommandScope::All,
        MutationClass::Read,
        AuditPolicy::SensitiveRead,
        true,
    ),
    metadata(
        ActionId::BenchmarkRun,
        CommandScope::Main,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    metadata(
        ActionId::BenchmarkList,
        CommandScope::Main,
        MutationClass::Read,
        AuditPolicy::None,
        true,
    ),
    metadata(
        ActionId::BenchmarkStatus,
        CommandScope::Main,
        MutationClass::Read,
        AuditPolicy::None,
        true,
    ),
    metadata(
        ActionId::BenchmarkStop,
        CommandScope::Main,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    metadata(
        ActionId::BenchmarkClean,
        CommandScope::Main,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    metadata(
        ActionId::BenchmarkVerificationRun,
        CommandScope::Main,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    metadata(
        ActionId::BenchmarkVerificationStatus,
        CommandScope::Main,
        MutationClass::Read,
        AuditPolicy::None,
        true,
    ),
    metadata(
        ActionId::BenchmarkVerificationStop,
        CommandScope::Main,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    metadata(
        ActionId::AuthControllerAdd,
        CommandScope::Main,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    metadata(
        ActionId::AuthControllerList,
        CommandScope::Main,
        MutationClass::Read,
        AuditPolicy::SensitiveRead,
        true,
    ),
    metadata(
        ActionId::AuthControllerRevoke,
        CommandScope::Main,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    metadata(
        ActionId::AuthKeyCreate,
        CommandScope::Main,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    metadata(
        ActionId::AuthKeyList,
        CommandScope::Main,
        MutationClass::Read,
        AuditPolicy::SensitiveRead,
        true,
    ),
    metadata(
        ActionId::AuthKeyShow,
        CommandScope::Main,
        MutationClass::Read,
        AuditPolicy::SensitiveRead,
        true,
    ),
    metadata(
        ActionId::AuthKeyRotate,
        CommandScope::Main,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    metadata(
        ActionId::AuthKeyRevoke,
        CommandScope::Main,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    metadata(
        ActionId::AuthKeyUpdate,
        CommandScope::Main,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    metadata(
        ActionId::ExposureStatus,
        CommandScope::Main,
        MutationClass::Read,
        AuditPolicy::None,
        true,
    ),
    metadata(
        ActionId::ExposureEnable,
        CommandScope::Main,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    metadata(
        ActionId::ExposureDisable,
        CommandScope::Main,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    metadata(
        ActionId::AuditList,
        CommandScope::Main,
        MutationClass::Read,
        AuditPolicy::SensitiveRead,
        true,
    ),
    metadata(
        ActionId::AuditShow,
        CommandScope::Main,
        MutationClass::Read,
        AuditPolicy::SensitiveRead,
        true,
    ),
    metadata(
        ActionId::AuditVerify,
        CommandScope::Main,
        MutationClass::Read,
        AuditPolicy::SensitiveRead,
        true,
    ),
    metadata(
        ActionId::AuditExport,
        CommandScope::Main,
        MutationClass::Read,
        AuditPolicy::SensitiveRead,
        true,
    ),
    metadata(
        ActionId::UpdateCheck,
        CommandScope::All,
        MutationClass::Read,
        AuditPolicy::None,
        false,
    ),
    metadata(
        ActionId::UpdateCore,
        CommandScope::All,
        MutationClass::Local,
        AuditPolicy::Success,
        false,
    ),
    metadata(
        ActionId::UpdateModel,
        CommandScope::Main,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
];

// Returns the complete immutable action registry.
pub const fn actions() -> &'static [ActionMetadata] {
    ACTIONS
}

// Resolves exact metadata for one closed action identity.
pub fn action(id: ActionId) -> &'static ActionMetadata {
    ACTIONS
        .iter()
        .find(|metadata| metadata.id == id)
        .expect("every ActionId must have registry metadata")
}
