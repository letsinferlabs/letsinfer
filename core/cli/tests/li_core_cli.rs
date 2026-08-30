// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeSet;

use li_core_cli::{
    actions, authorize, authorize_and_dispatch, command_specs, dispatch_native_command, ActionId,
    ArgumentId, AuditCommand, AuditPolicy, AuthenticationCommand, BenchmarkCommand,
    CommandAuthorizationError, CommandContext, CommandDispatcher, CommandExecutionError,
    CommandFailure, CommandParser, CommandParserError, CommandProgressEvent, CommandProgressPort,
    CommandScope, CoreCommandCapabilities, ExposureCommand, HostCommand, LocalRole, ModelCommand,
    MutationClass, NodeCommand, UpdateCommand,
};

const CASES: &[(ActionId, &[&str])] = &[
    (ActionId::Status, &["status", "--json"]),
    (ActionId::Topology, &["topology", "--json"]),
    (ActionId::Doctor, &["doctor", "--json"]),
    (ActionId::NodeInfo, &["node", "info", "--json"]),
    (ActionId::NodeList, &["node", "list", "--json"]),
    (ActionId::NodeUsage, &["node", "usage", "--json"]),
    (ActionId::NodeAdd, &["node", "add", "--json"]),
    (ActionId::NodePause, &["node", "pause", "child", "--json"]),
    (ActionId::NodeResume, &["node", "resume", "child", "--json"]),
    (ActionId::NodeRemove, &["node", "remove", "child", "--json"]),
    (ActionId::ModelList, &["model", "list", "--json"]),
    (ActionId::ModelInstall, &["model", "install", "model"]),
    (
        ActionId::ModelRemove,
        &["model", "remove", "model", "--all-nodes", "--json"],
    ),
    (ActionId::ModelPause, &["model", "pause", "model"]),
    (ActionId::ModelResume, &["model", "resume", "model"]),
    (ActionId::ModelRestart, &["model", "restart", "model"]),
    (ActionId::ModelRecover, &["model", "recover", "model"]),
    (
        ActionId::ModelRollback,
        &["model", "rollback", "model", "--dry-run"],
    ),
    (
        ActionId::ModelLogs,
        &["model", "logs", "model", "--tail", "0"],
    ),
    (
        ActionId::BenchmarkRun,
        &["benchmark", "run", "model", "--c1"],
    ),
    (
        ActionId::BenchmarkList,
        &["benchmark", "list", "model", "--c1"],
    ),
    (
        ActionId::BenchmarkStatus,
        &["benchmark", "status", "--json"],
    ),
    (ActionId::BenchmarkStop, &["benchmark", "stop"]),
    (ActionId::BenchmarkClean, &["benchmark", "clean", "--yes"]),
    (
        ActionId::BenchmarkVerificationRun,
        &[
            "benchmark",
            "verification",
            "run",
            "https://example.invalid/pr/1",
        ],
    ),
    (
        ActionId::BenchmarkVerificationStatus,
        &["benchmark", "verification", "status", "--json"],
    ),
    (
        ActionId::BenchmarkVerificationStop,
        &["benchmark", "verification", "stop"],
    ),
    (
        ActionId::AuthControllerAdd,
        &["auth", "controller", "add", "--timeout", "30"],
    ),
    (
        ActionId::AuthControllerList,
        &["auth", "controller", "list", "--json"],
    ),
    (
        ActionId::AuthControllerRevoke,
        &["auth", "controller", "revoke", "controller", "--json"],
    ),
    (
        ActionId::AuthKeyCreate,
        &["auth", "key", "create", "application", "--json"],
    ),
    (ActionId::AuthKeyList, &["auth", "key", "list", "--json"]),
    (
        ActionId::AuthKeyShow,
        &["auth", "key", "show", "key", "--json"],
    ),
    (
        ActionId::AuthKeyRotate,
        &["auth", "key", "rotate", "key", "--json"],
    ),
    (
        ActionId::AuthKeyRevoke,
        &["auth", "key", "revoke", "key", "--json"],
    ),
    (
        ActionId::AuthKeyUpdate,
        &["auth", "key", "update", "key", "--json"],
    ),
    (ActionId::ExposureStatus, &["exposure", "status", "--json"]),
    (ActionId::ExposureEnable, &["exposure", "enable", "--json"]),
    (
        ActionId::ExposureDisable,
        &["exposure", "disable", "--json"],
    ),
    (ActionId::AuditList, &["audit", "list", "--json"]),
    (ActionId::AuditShow, &["audit", "show", "1", "--json"]),
    (ActionId::AuditVerify, &["audit", "verify", "--json"]),
    (
        ActionId::AuditExport,
        &["audit", "export", "--output", "audit.json"],
    ),
    (ActionId::UpdateCheck, &["update", "check", "--json"]),
    (ActionId::UpdateCore, &["update", "core", "1.2.3"]),
    (
        ActionId::UpdateModel,
        &["update", "model", "model", "--dry-run"],
    ),
    (ActionId::Uninstall, &["uninstall"]),
];

const EXPECTED_ACTION_NAMES: &[&str] = &[
    "status",
    "topology",
    "doctor",
    "uninstall",
    "node.info",
    "node.list",
    "node.usage",
    "node.add",
    "node.pause",
    "node.resume",
    "node.remove",
    "model.list",
    "model.install",
    "model.remove",
    "model.pause",
    "model.resume",
    "model.restart",
    "model.recover",
    "model.rollback",
    "model.logs",
    "benchmark.run",
    "benchmark.list",
    "benchmark.status",
    "benchmark.stop",
    "benchmark.clean",
    "benchmark.verification.run",
    "benchmark.verification.status",
    "benchmark.verification.stop",
    "auth.controller.add",
    "auth.controller.list",
    "auth.controller.revoke",
    "auth.key.create",
    "auth.key.list",
    "auth.key.show",
    "auth.key.rotate",
    "auth.key.revoke",
    "auth.key.update",
    "exposure.status",
    "exposure.enable",
    "exposure.disable",
    "audit.list",
    "audit.show",
    "audit.verify",
    "audit.export",
    "update.check",
    "update.core",
    "update.model",
];

const EXPECTED_METADATA: &[(ActionId, CommandScope, MutationClass, AuditPolicy, bool)] = &[
    (
        ActionId::Status,
        CommandScope::All,
        MutationClass::Read,
        AuditPolicy::None,
        true,
    ),
    (
        ActionId::Topology,
        CommandScope::Main,
        MutationClass::Read,
        AuditPolicy::None,
        true,
    ),
    (
        ActionId::Doctor,
        CommandScope::All,
        MutationClass::Read,
        AuditPolicy::None,
        true,
    ),
    (
        ActionId::Uninstall,
        CommandScope::All,
        MutationClass::Node,
        AuditPolicy::None,
        false,
    ),
    (
        ActionId::NodeInfo,
        CommandScope::All,
        MutationClass::Read,
        AuditPolicy::None,
        true,
    ),
    (
        ActionId::NodeList,
        CommandScope::All,
        MutationClass::Read,
        AuditPolicy::None,
        true,
    ),
    (
        ActionId::NodeUsage,
        CommandScope::All,
        MutationClass::Local,
        AuditPolicy::Always,
        true,
    ),
    (
        ActionId::NodeAdd,
        CommandScope::All,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    (
        ActionId::NodePause,
        CommandScope::All,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    (
        ActionId::NodeResume,
        CommandScope::All,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    (
        ActionId::NodeRemove,
        CommandScope::All,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    (
        ActionId::ModelList,
        CommandScope::All,
        MutationClass::Read,
        AuditPolicy::None,
        false,
    ),
    (
        ActionId::ModelInstall,
        CommandScope::Main,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    (
        ActionId::ModelRemove,
        CommandScope::Main,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    (
        ActionId::ModelPause,
        CommandScope::Main,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    (
        ActionId::ModelResume,
        CommandScope::Main,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    (
        ActionId::ModelRestart,
        CommandScope::Main,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    (
        ActionId::ModelRecover,
        CommandScope::Main,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    (
        ActionId::ModelRollback,
        CommandScope::Main,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    (
        ActionId::ModelLogs,
        CommandScope::All,
        MutationClass::Read,
        AuditPolicy::SensitiveRead,
        true,
    ),
    (
        ActionId::BenchmarkRun,
        CommandScope::Main,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    (
        ActionId::BenchmarkList,
        CommandScope::Main,
        MutationClass::Read,
        AuditPolicy::None,
        true,
    ),
    (
        ActionId::BenchmarkStatus,
        CommandScope::Main,
        MutationClass::Read,
        AuditPolicy::None,
        true,
    ),
    (
        ActionId::BenchmarkStop,
        CommandScope::Main,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    (
        ActionId::BenchmarkClean,
        CommandScope::Main,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    (
        ActionId::BenchmarkVerificationRun,
        CommandScope::Main,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    (
        ActionId::BenchmarkVerificationStatus,
        CommandScope::Main,
        MutationClass::Read,
        AuditPolicy::None,
        true,
    ),
    (
        ActionId::BenchmarkVerificationStop,
        CommandScope::Main,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    (
        ActionId::AuthControllerAdd,
        CommandScope::Main,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    (
        ActionId::AuthControllerList,
        CommandScope::Main,
        MutationClass::Read,
        AuditPolicy::SensitiveRead,
        true,
    ),
    (
        ActionId::AuthControllerRevoke,
        CommandScope::Main,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    (
        ActionId::AuthKeyCreate,
        CommandScope::Main,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    (
        ActionId::AuthKeyList,
        CommandScope::Main,
        MutationClass::Read,
        AuditPolicy::SensitiveRead,
        true,
    ),
    (
        ActionId::AuthKeyShow,
        CommandScope::Main,
        MutationClass::Read,
        AuditPolicy::SensitiveRead,
        true,
    ),
    (
        ActionId::AuthKeyRotate,
        CommandScope::Main,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    (
        ActionId::AuthKeyRevoke,
        CommandScope::Main,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    (
        ActionId::AuthKeyUpdate,
        CommandScope::Main,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    (
        ActionId::ExposureStatus,
        CommandScope::Main,
        MutationClass::Read,
        AuditPolicy::None,
        true,
    ),
    (
        ActionId::ExposureEnable,
        CommandScope::Main,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    (
        ActionId::ExposureDisable,
        CommandScope::Main,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
    (
        ActionId::AuditList,
        CommandScope::Main,
        MutationClass::Read,
        AuditPolicy::SensitiveRead,
        true,
    ),
    (
        ActionId::AuditShow,
        CommandScope::Main,
        MutationClass::Read,
        AuditPolicy::SensitiveRead,
        true,
    ),
    (
        ActionId::AuditVerify,
        CommandScope::Main,
        MutationClass::Read,
        AuditPolicy::SensitiveRead,
        true,
    ),
    (
        ActionId::AuditExport,
        CommandScope::Main,
        MutationClass::Read,
        AuditPolicy::SensitiveRead,
        true,
    ),
    (
        ActionId::UpdateCheck,
        CommandScope::All,
        MutationClass::Read,
        AuditPolicy::None,
        false,
    ),
    (
        ActionId::UpdateCore,
        CommandScope::All,
        MutationClass::Local,
        AuditPolicy::Success,
        false,
    ),
    (
        ActionId::UpdateModel,
        CommandScope::Main,
        MutationClass::Node,
        AuditPolicy::Always,
        true,
    ),
];

// Records exact authorized leaves without replacing parser or authorization behavior.
#[derive(Default)]
struct DispatcherMock {
    calls: Vec<ActionId>,
}

impl CommandDispatcher for DispatcherMock {
    type Output = ActionId;
    type Error = &'static str;

    // Records one authorized action and returns it to the table-driven assertion.
    fn dispatch(
        &mut self,
        command: li_core_cli::AuthorizedCommand,
    ) -> Result<Self::Output, Self::Error> {
        let action = command.invocation().action();
        self.calls.push(action);
        Ok(action)
    }
}

macro_rules! record_capability {
    ($method:ident, $command:ty) => {
        // Records one typed capability dispatch without executing a native provider.
        fn $method(
            &mut self,
            command: $command,
            _progress: &mut dyn CommandProgressPort,
        ) -> Result<Self::Output, CommandFailure> {
            let action = command.invocation().action();
            self.calls.push(action);
            Ok(action)
        }
    };
}

impl CoreCommandCapabilities for DispatcherMock {
    type Output = ActionId;

    record_capability!(execute_host, HostCommand<'_>);
    record_capability!(execute_node, NodeCommand<'_>);
    record_capability!(execute_model, ModelCommand<'_>);
    record_capability!(execute_benchmark, BenchmarkCommand<'_>);
    record_capability!(execute_authentication, AuthenticationCommand<'_>);
    record_capability!(execute_exposure, ExposureCommand<'_>);
    record_capability!(execute_audit, AuditCommand<'_>);
    record_capability!(execute_update, UpdateCommand<'_>);
}

#[derive(Default)]
struct ProgressSink;

impl CommandProgressPort for ProgressSink {
    // Accepts progress while the registry test observes only typed capability routing.
    fn report(&mut self, _event: CommandProgressEvent) {}
}

// Proves the parser, action registry, and metadata table are exact.
#[test]
fn registry_and_parser_leaves_are_exact() {
    let parser = CommandParser::new().expect("valid declarative contract");
    let registered = actions()
        .iter()
        .map(|metadata| metadata.id())
        .collect::<BTreeSet<_>>();
    let parser_leaves = command_specs()
        .iter()
        .map(|specification| specification.action())
        .collect::<BTreeSet<_>>();
    let cases = CASES
        .iter()
        .map(|(action, _)| *action)
        .collect::<BTreeSet<_>>();
    assert_eq!(registered, parser_leaves);
    assert_eq!(registered, cases);
    assert_eq!(registered.len(), 47);
    assert_eq!(
        actions()
            .iter()
            .map(|metadata| metadata.id().as_str())
            .collect::<BTreeSet<_>>(),
        EXPECTED_ACTION_NAMES
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
    );

    let actual_metadata = actions()
        .iter()
        .map(|metadata| {
            (
                metadata.id(),
                metadata.scope(),
                metadata.mutation(),
                metadata.audit(),
                metadata.requires_configured_node(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(actual_metadata, EXPECTED_METADATA);
    for (expected, arguments) in CASES {
        let parsed = parser.parse(*arguments).expect("minimal leaf parses");
        assert_eq!(parsed.action(), *expected);
    }
}

// Proves representative complex leaves preserve typed values, repeats, choices, and defaults.
#[test]
fn representative_options_are_typed_and_normalized() {
    let parser = CommandParser::new().expect("parser");
    let node = parser
        .parse([
            "node",
            "add",
            "--join",
            "--mode=remote",
            "--invitation",
            "7f3a0c9a39ea44609e1f5a8df81c59ef",
            "--address=homeai.local",
            "--certificate-sha256",
            "abc",
            "--timeout",
            "30",
            "--json",
        ])
        .expect("node add");
    assert_eq!(node.boolean(ArgumentId::Join), Some(true));
    assert_eq!(node.text(ArgumentId::Mode), Some("remote"));
    assert_eq!(
        node.text(ArgumentId::Invitation),
        Some("7f3a0c9a39ea44609e1f5a8df81c59ef")
    );
    assert_eq!(node.text(ArgumentId::Address), Some("homeai.local"));
    assert_eq!(node.text(ArgumentId::CertificateSha256), Some("abc"));
    assert_eq!(node.integer(ArgumentId::Timeout), Some(30));
    assert_eq!(node.boolean(ArgumentId::Json), Some(true));

    let benchmark = parser
        .parse([
            "benchmark",
            "run",
            "model",
            "--c1",
            "--c16",
            "--32k",
            "--256k",
        ])
        .expect("benchmark run");
    assert_eq!(benchmark.text(ArgumentId::Model), Some("model"));
    assert_eq!(benchmark.boolean(ArgumentId::C1), Some(true));
    assert_eq!(benchmark.boolean(ArgumentId::C16), Some(true));
    assert_eq!(benchmark.boolean(ArgumentId::Context32k), Some(true));
    assert_eq!(benchmark.boolean(ArgumentId::Context256k), Some(true));
    assert!(parser
        .parse(["benchmark", "run", "model", "--job-worker"])
        .is_err());
    let verification = parser
        .parse([
            "benchmark",
            "verification",
            "run",
            "https://github.com/letsinferlabs/runtimes/pull/41",
            "--candidate",
            "vllm--owner--model--spark",
            "--detach",
        ])
        .expect("verification run");
    assert_eq!(
        verification.text(ArgumentId::PullRequest),
        Some("https://github.com/letsinferlabs/runtimes/pull/41")
    );
    assert_eq!(
        verification.text(ArgumentId::Candidate),
        Some("vllm--owner--model--spark")
    );
    assert_eq!(verification.boolean(ArgumentId::Detach), Some(true));
    assert!(parser
        .parse([
            "benchmark",
            "verification",
            "run",
            "https://github.com/letsinferlabs/runtimes/pull/41",
            "--job-worker",
        ])
        .is_err());
    assert!(parser
        .parse([
            "benchmark",
            "verification",
            "run",
            "https://github.com/letsinferlabs/runtimes/pull/41",
            "--job-id",
            "legacy",
        ])
        .is_err());

    let key = parser
        .parse([
            "auth",
            "key",
            "create",
            "application",
            "--model",
            "first",
            "--model",
            "second",
            "--concurrency",
            "4",
        ])
        .expect("key create");
    assert_eq!(key.text(ArgumentId::Name), Some("application"));
    assert_eq!(
        key.text_list(ArgumentId::Model),
        Some(["first".to_owned(), "second".to_owned()].as_slice())
    );
    assert_eq!(key.integer(ArgumentId::Concurrency), Some(4));

    let controller = parser
        .parse(["auth", "controller", "add"])
        .expect("controller defaults");
    assert_eq!(controller.integer(ArgumentId::Timeout), Some(180));
    assert_eq!(controller.text(ArgumentId::Role), Some("administrator"));
}

// Proves invalid, incomplete, and retired vocabulary fails at the parser boundary.
#[test]
fn unknown_retired_and_malformed_arguments_are_rejected() {
    let parser = CommandParser::new().expect("parser");
    for arguments in [
        &["site", "status"][..],
        &["member", "list"][..],
        &["coordinator", "status"][..],
        &["model", "scale", "model"][..],
        &["model", "update", "model"][..],
        &["setup"][..],
        &["start"][..],
        &["node"][..],
        &["core-setup"][..],
        &["service-start"][..],
        &["service-stop"][..],
        &["gateway"][..],
        &["node-agent"][..],
        &["core-rebind"][..],
        &["core-prune"][..],
    ] {
        assert!(matches!(
            parser.parse(arguments),
            Err(CommandParserError::UnknownCommand { .. })
        ));
    }
    assert!(matches!(
        parser.parse(["model", "remove"]),
        Err(CommandParserError::MissingPositional {
            argument: ArgumentId::Model
        })
    ));
    assert!(matches!(
        parser.parse(["auth", "controller", "add", "--role", "owner"]),
        Err(CommandParserError::InvalidChoice { .. })
    ));
    assert!(matches!(
        parser.parse(["status", "--raw"]),
        Err(CommandParserError::UnknownOption { .. })
    ));
    assert!(matches!(
        parser.parse(["model", "install", "model", "--replace-existing"]),
        Err(CommandParserError::UnknownOption { .. })
    ));
}

// Proves configured-node and role gates run before an injected dispatcher.
#[test]
fn authorization_rejects_before_dispatch() {
    let mut dispatcher = DispatcherMock::default();
    let missing_node =
        authorize_and_dispatch(["status"], CommandContext::unconfigured(), &mut dispatcher);
    assert_eq!(
        missing_node,
        Err(CommandExecutionError::Authorization(
            CommandAuthorizationError::ConfiguredNodeRequired {
                action: ActionId::Status
            }
        ))
    );
    let child_denial = authorize_and_dispatch(
        ["topology"],
        CommandContext::configured(LocalRole::Child),
        &mut dispatcher,
    );
    assert_eq!(
        child_denial,
        Err(CommandExecutionError::Authorization(
            CommandAuthorizationError::ScopeDenied {
                action: ActionId::Topology,
                required: CommandScope::Main,
                actual: LocalRole::Child,
            }
        ))
    );
    assert_eq!(
        authorize_and_dispatch(
            ["uninstall"],
            CommandContext::configured(LocalRole::Child),
            &mut dispatcher,
        ),
        Ok(ActionId::Uninstall)
    );

    assert_eq!(
        authorize_and_dispatch(
            ["update", "check"],
            CommandContext::unconfigured(),
            &mut dispatcher,
        ),
        Ok(ActionId::UpdateCheck)
    );
    assert_eq!(
        authorize_and_dispatch(
            ["uninstall"],
            CommandContext::unconfigured(),
            &mut dispatcher,
        ),
        Ok(ActionId::Uninstall)
    );
    assert_eq!(
        dispatcher.calls,
        [
            ActionId::Uninstall,
            ActionId::UpdateCheck,
            ActionId::Uninstall
        ]
    );
}

// Proves every public leaf reaches one typed Rust capability exactly once.
#[test]
fn every_leaf_reaches_one_typed_capability() {
    let mut dispatcher = DispatcherMock::default();
    let parser = CommandParser::new().expect("parser");
    let mut progress = ProgressSink;
    for (expected, arguments) in CASES {
        let invocation = parser.parse(*arguments).expect("registered leaf parses");
        let command = authorize(invocation, CommandContext::configured(LocalRole::Main))
            .expect("registered leaf authorizes");
        let result = dispatch_native_command(&mut dispatcher, &command, &mut progress)
            .expect("registered leaf dispatches through a typed capability");
        assert_eq!(result, *expected);
    }
    assert_eq!(dispatcher.calls.len(), CASES.len());
    assert_eq!(
        dispatcher.calls,
        CASES.iter().map(|case| case.0).collect::<Vec<_>>()
    );
}
