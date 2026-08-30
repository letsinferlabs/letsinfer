// SPDX-License-Identifier: AGPL-3.0-only

mod li_core_cli_action;
mod li_core_cli_application;
mod li_core_cli_audit;
mod li_core_cli_capability;
mod li_core_cli_command;
mod li_core_cli_dispatch;
mod li_core_cli_display;
mod li_core_cli_node_client;
mod li_core_cli_node_exchange;
mod li_core_cli_node_process;
mod li_core_cli_parser;

pub use li_core_cli_action::{
    action, actions, ActionId, ActionMetadata, AuditPolicy, CommandScope, MutationClass,
};
pub use li_core_cli_application::{
    run_native_cli, CliApplication, CliExitCode, CommandContextError, CommandContextPort,
};
pub use li_core_cli_audit::{
    begins_audit, completes_audit, CommandAuditError, CommandAuditIntent, CommandAuditMarker,
    CommandAuditOutcome, CommandAuditPort, CommandAuditResult, CommandAuditTarget,
    CommandAuditTargetKind,
};
pub use li_core_cli_capability::{
    dispatch_native_command, AuditCommand, AuthenticationCommand, BenchmarkCommand, CommandFailure,
    CommandFailureContractError, CommandFailureKind, CommandProgressEvent, CommandProgressPort,
    CoreCommandCapabilities, ExposureCommand, HostCommand, ModelCommand, NodeCommand,
    UpdateCommand,
};
pub use li_core_cli_command::{
    command_specs, ArgumentId, ArgumentValue, CommandInvocation, CommandSpec,
};
pub use li_core_cli_dispatch::{
    authorize, authorize_and_dispatch, AuthorizedCommand, CommandAuthorizationError,
    CommandContext, CommandDispatcher, CommandExecutionError, LocalRole,
};
pub use li_core_cli_display::{
    command_output_mode, display_contract, native_cli_root_help, CliDisplayError, CliDisplayPort,
    CommandOutput, CommandOutputMode, CommandPresentation, DisplayBlock, DisplayContract,
    DisplayContractError, DisplayEvent, DisplayOutputContract, DisplayProgressKind, DisplayRecord,
    DisplaySemantic, DisplaySurface, DisplayTable, MachineNumber, MachineValue, OneTimeSecret,
    StreamCliDisplay,
};
pub use li_core_cli_node_client::{
    NodePrivateClient, NodePrivateClientConfiguration, NodePrivateClientConfigurationError,
    NodePrivateClientError, NodePrivateDocumentExchangeError, NodePrivateDocumentExchangePort,
    NodeRequestIdentityError, NodeRequestIdentitySource, SystemNodeRequestIdentitySource,
};
pub use li_core_cli_node_exchange::{
    NodePrivateUnixConnectError, NodePrivateUnixConnector, NodePrivateUnixIoError,
    NodePrivateUnixStream, SystemNodePrivateDocumentExchange, SystemNodePrivateUnixConnector,
    UnixNodePrivateDocumentExchange, UnixNodePrivateExchangeConfigurationError,
};
pub use li_core_cli_node_process::{
    compose_system_native_node_cli, run_native_node_cli, NativeAuditExportFileError,
    NativeAuditExportFilePort, NativeChildLifecyclePort, NativeControllerEnrollmentCommitPort,
    NativeControllerEnrollmentPort, NativeNodeCliCapabilities, NativeNodeCliCompositionError,
    NativeNodeCliProcess, NativeNodeCommandAuditPort, NativeNodeCommandClock,
    NativeNodeCommandClockError, NativeNodePairingEndpoint, NativeNodePairingJoinRequest,
    NativeNodePairingJoinSource, NativeNodePairingMode, NativeNodePairingPort,
    NativeUninstallModelDisposition, NativeUninstallPort, NativeUninstallReceipt,
    PairedMainChildLifecycle, SystemNativeAuditExportFile, SystemNativeNodeCliProcess,
    SystemNativeNodeCommandClock,
};
pub use li_core_cli_parser::{CommandParser, CommandParserError};
