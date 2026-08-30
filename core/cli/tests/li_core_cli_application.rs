// SPDX-License-Identifier: AGPL-3.0-only

use std::cell::RefCell;
use std::io;
use std::rc::Rc;

use li_core_cli::{
    actions, authorize, dispatch_native_command, display_contract, run_native_cli, AuditCommand,
    AuthenticationCommand, BenchmarkCommand, CliApplication, CliDisplayError, CliDisplayPort,
    CliExitCode, CommandAuditError, CommandAuditIntent, CommandAuditMarker, CommandAuditOutcome,
    CommandAuditPort, CommandAuditResult, CommandContext, CommandContextError, CommandContextPort,
    CommandFailure, CommandFailureKind, CommandOutput, CommandParser, CommandPresentation,
    CommandProgressEvent, CommandProgressPort, CoreCommandCapabilities, DisplayBlock,
    DisplayContract, DisplayEvent, DisplayOutputContract, DisplayProgressKind, DisplayRecord,
    DisplaySemantic, DisplaySurface, DisplayTable, ExposureCommand, HostCommand, LocalRole,
    MachineNumber, MachineValue, ModelCommand, NodeCommand, OneTimeSecret, StreamCliDisplay,
    UpdateCommand,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CapabilityOwner {
    Host,
    Node,
    Model,
    Benchmark,
    Authentication,
    Exposure,
    Audit,
    Update,
}

struct ContextMock {
    result: Result<CommandContext, CommandContextError>,
    calls: usize,
    timeline: Rc<RefCell<Vec<&'static str>>>,
}

impl CommandContextPort for ContextMock {
    // Returns the injected immutable role while recording the application boundary.
    fn command_context(&mut self) -> Result<CommandContext, CommandContextError> {
        self.calls += 1;
        self.timeline.borrow_mut().push("context");
        self.result.clone()
    }
}

struct CapabilitiesMock {
    result: Result<CommandOutput, CommandFailure>,
    progress: Vec<CommandProgressEvent>,
    calls: Vec<(CapabilityOwner, li_core_cli::ActionId)>,
    timeline: Rc<RefCell<Vec<&'static str>>>,
}

impl CapabilitiesMock {
    // Records one typed owner call and returns the injected native result.
    fn respond(
        &mut self,
        owner: CapabilityOwner,
        action: li_core_cli::ActionId,
        progress: &mut dyn CommandProgressPort,
    ) -> Result<CommandOutput, CommandFailure> {
        self.calls.push((owner, action));
        self.timeline.borrow_mut().push("capability");
        for event in self.progress.clone() {
            progress.report(event);
        }
        self.result.clone()
    }
}

impl CoreCommandCapabilities for CapabilitiesMock {
    type Output = CommandOutput;

    // Executes one mocked host command through the common deterministic result.
    fn execute_host(
        &mut self,
        command: HostCommand<'_>,
        progress: &mut dyn CommandProgressPort,
    ) -> Result<Self::Output, CommandFailure> {
        self.respond(
            CapabilityOwner::Host,
            command.invocation().action(),
            progress,
        )
    }

    // Executes one mocked node command through the common deterministic result.
    fn execute_node(
        &mut self,
        command: NodeCommand<'_>,
        progress: &mut dyn CommandProgressPort,
    ) -> Result<Self::Output, CommandFailure> {
        self.respond(
            CapabilityOwner::Node,
            command.invocation().action(),
            progress,
        )
    }

    // Executes one mocked model command through the common deterministic result.
    fn execute_model(
        &mut self,
        command: ModelCommand<'_>,
        progress: &mut dyn CommandProgressPort,
    ) -> Result<Self::Output, CommandFailure> {
        self.respond(
            CapabilityOwner::Model,
            command.invocation().action(),
            progress,
        )
    }

    // Executes one mocked benchmark command through the common deterministic result.
    fn execute_benchmark(
        &mut self,
        command: BenchmarkCommand<'_>,
        progress: &mut dyn CommandProgressPort,
    ) -> Result<Self::Output, CommandFailure> {
        self.respond(
            CapabilityOwner::Benchmark,
            command.invocation().action(),
            progress,
        )
    }

    // Executes one mocked authentication command through the deterministic result.
    fn execute_authentication(
        &mut self,
        command: AuthenticationCommand<'_>,
        progress: &mut dyn CommandProgressPort,
    ) -> Result<Self::Output, CommandFailure> {
        self.respond(
            CapabilityOwner::Authentication,
            command.invocation().action(),
            progress,
        )
    }

    // Executes one mocked exposure command through the common deterministic result.
    fn execute_exposure(
        &mut self,
        command: ExposureCommand<'_>,
        progress: &mut dyn CommandProgressPort,
    ) -> Result<Self::Output, CommandFailure> {
        self.respond(
            CapabilityOwner::Exposure,
            command.invocation().action(),
            progress,
        )
    }

    // Executes one mocked audit command through the common deterministic result.
    fn execute_audit(
        &mut self,
        command: AuditCommand<'_>,
        progress: &mut dyn CommandProgressPort,
    ) -> Result<Self::Output, CommandFailure> {
        self.respond(
            CapabilityOwner::Audit,
            command.invocation().action(),
            progress,
        )
    }

    // Executes one mocked update command through the common deterministic result.
    fn execute_update(
        &mut self,
        command: UpdateCommand<'_>,
        progress: &mut dyn CommandProgressPort,
    ) -> Result<Self::Output, CommandFailure> {
        self.respond(
            CapabilityOwner::Update,
            command.invocation().action(),
            progress,
        )
    }
}

struct AuditMock {
    will_result: Result<Option<CommandAuditMarker>, CommandAuditError>,
    did_result: Result<(), CommandAuditError>,
    intents: Vec<CommandAuditIntent>,
    results: Vec<CommandAuditResult>,
    timeline: Rc<RefCell<Vec<&'static str>>>,
}

impl CommandAuditPort for AuditMock {
    // Records one pre-execution intent and returns the injected opaque marker.
    fn will_execute(
        &mut self,
        intent: CommandAuditIntent,
    ) -> Result<Option<CommandAuditMarker>, CommandAuditError> {
        self.timeline.borrow_mut().push("audit.will");
        self.intents.push(intent);
        self.will_result.clone()
    }

    // Records one terminal result and returns the injected persistence outcome.
    fn did_execute(
        &mut self,
        _marker: &CommandAuditMarker,
        result: CommandAuditResult,
    ) -> Result<(), CommandAuditError> {
        self.timeline.borrow_mut().push("audit.did");
        self.results.push(result);
        self.did_result.clone()
    }
}

struct DisplayMock {
    events: Vec<DisplayEvent>,
    fail_at: Option<usize>,
    timeline: Rc<RefCell<Vec<&'static str>>>,
}

impl CliDisplayPort for DisplayMock {
    // Captures one display event and optionally fails at an exact deterministic index.
    fn display(&mut self, event: DisplayEvent) -> Result<(), CliDisplayError> {
        self.timeline.borrow_mut().push("display");
        let index = self.events.len();
        self.events.push(event);
        if self.fail_at == Some(index) {
            Err(CliDisplayError::from(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "fixture stream closed",
            )))
        } else {
            Ok(())
        }
    }
}

#[derive(Default)]
struct ProgressSink;

impl CommandProgressPort for ProgressSink {
    // Accepts progress while testing the standalone typed routing boundary.
    fn report(&mut self, _event: CommandProgressEvent) {}
}

// Creates one complete dual-mode result shared by deterministic application fixtures.
fn successful_output() -> CommandOutput {
    CommandOutput::new(
        CommandPresentation::new(vec![DisplayBlock::Result {
            title: "Model paused".to_owned(),
            detail: Some("fixture-model".to_owned()),
            semantic: DisplaySemantic::Success,
        }]),
        Some(MachineValue::object([
            ("model", MachineValue::from("fixture-model")),
            ("state", MachineValue::from("paused")),
        ])),
    )
}

// Creates native application mocks with one configured main-node context.
fn mocks(
    result: Result<CommandOutput, CommandFailure>,
) -> (ContextMock, CapabilitiesMock, AuditMock, DisplayMock) {
    let timeline = Rc::new(RefCell::new(Vec::new()));
    (
        ContextMock {
            result: Ok(CommandContext::configured(LocalRole::Main)),
            calls: 0,
            timeline: timeline.clone(),
        },
        CapabilitiesMock {
            result,
            progress: Vec::new(),
            calls: Vec::new(),
            timeline: timeline.clone(),
        },
        AuditMock {
            will_result: Ok(Some(
                CommandAuditMarker::new("fixture-marker").expect("marker"),
            )),
            did_result: Ok(()),
            intents: Vec::new(),
            results: Vec::new(),
            timeline: timeline.clone(),
        },
        DisplayMock {
            events: Vec::new(),
            fail_at: None,
            timeline,
        },
    )
}

// Proves representative leaves route to every explicit native capability owner.
#[test]
fn native_router_reaches_every_typed_owner() {
    let (context, mut capabilities, audit, display) = mocks(Ok(successful_output()));
    let cases: &[(CapabilityOwner, &[&str])] = &[
        (CapabilityOwner::Host, &["doctor"]),
        (CapabilityOwner::Node, &["node", "list"]),
        (CapabilityOwner::Model, &["model", "pause", "fixture-model"]),
        (CapabilityOwner::Benchmark, &["benchmark", "status"]),
        (CapabilityOwner::Authentication, &["auth", "key", "list"]),
        (CapabilityOwner::Exposure, &["exposure", "status"]),
        (CapabilityOwner::Audit, &["audit", "verify"]),
        (CapabilityOwner::Update, &["update", "check"]),
    ];
    let parser = CommandParser::new().expect("parser");
    let mut progress = ProgressSink;
    for (owner, arguments) in cases {
        let invocation = parser.parse(*arguments).expect("representative leaf");
        let action = invocation.action();
        let command = authorize(invocation, CommandContext::configured(LocalRole::Main))
            .expect("authorized command");
        dispatch_native_command(&mut capabilities, &command, &mut progress)
            .expect("native dispatch");
        assert_eq!(capabilities.calls.last(), Some(&(*owner, action)));
    }
    assert_eq!(capabilities.calls.len(), cases.len());
    assert_eq!(context.calls, 0);
    assert!(audit.intents.is_empty());
    assert!(display.events.is_empty());
}

// Proves human success orders context, header, audit, progress, dispatch, and result.
#[test]
fn human_success_has_one_ordered_application_lifecycle() {
    let (mut context, mut capabilities, mut audit, mut display) = mocks(Ok(successful_output()));
    capabilities.progress = vec![CommandProgressEvent::Detail(
        "Waiting for the placement group".to_owned(),
    )];
    let timeline = context.timeline.clone();
    let exit = CliApplication::new(&mut context, &mut capabilities, &mut audit, &mut display)
        .run(["model", "pause", "fixture-model"]);
    assert_eq!(exit, CliExitCode::Success);
    assert_eq!(capabilities.calls.len(), 1);
    assert_eq!(audit.intents.len(), 1);
    assert_eq!(audit.results.len(), 1);
    assert_eq!(audit.results[0].outcome(), CommandAuditOutcome::Succeeded);
    assert_eq!(
        display.events,
        vec![
            DisplayEvent::Header {
                title: "Pause Model"
            },
            DisplayEvent::ProgressStarted {
                message: "Pausing inference"
            },
            DisplayEvent::ProgressDetail {
                message: "Waiting for the placement group".to_owned()
            },
            DisplayEvent::ProgressCompleted {
                message: "Model paused"
            },
            DisplayEvent::HumanDocument(successful_output().presentation().clone()),
        ]
    );
    assert_eq!(
        *timeline.borrow(),
        [
            "context",
            "display",
            "display",
            "audit.will",
            "capability",
            "display",
            "audit.did",
            "display",
            "display",
        ]
    );
}

// Proves JSON mode emits one clean machine document and suppresses human chrome.
#[test]
fn json_mode_emits_only_the_machine_document() {
    let expected = successful_output()
        .machine()
        .expect("machine output")
        .clone();
    let (mut context, mut capabilities, mut audit, mut display) = mocks(Ok(successful_output()));
    capabilities.progress = vec![CommandProgressEvent::Step {
        completed: 1,
        total: 2,
        message: "fixture".to_owned(),
    }];
    let exit = CliApplication::new(&mut context, &mut capabilities, &mut audit, &mut display)
        .run(["model", "remove", "fixture-model", "--json"]);
    assert_eq!(exit, CliExitCode::Success);
    assert_eq!(display.events, [DisplayEvent::MachineDocument(expected)]);
    assert_eq!(audit.results[0].outcome(), CommandAuditOutcome::Succeeded);
}

// Proves the process-facing entry binds application output to the centralized stream display.
#[test]
fn native_process_entry_owns_stdout_and_stderr_selection() {
    let (mut context, mut capabilities, mut audit, _display) = mocks(Ok(successful_output()));
    let mut standard_output = Vec::new();
    let mut standard_error = Vec::new();
    let exit = run_native_cli(
        ["model", "remove", "fixture-model", "--json"],
        &mut context,
        &mut capabilities,
        &mut audit,
        &mut standard_output,
        &mut standard_error,
    );
    assert_eq!(exit, CliExitCode::Success);
    assert_eq!(
        String::from_utf8(standard_output).expect("stdout"),
        "{\"model\":\"fixture-model\",\"state\":\"paused\"}\n"
    );
    assert!(standard_error.is_empty());
}

// Proves parse and scope failures cannot reach native capabilities or audit mutation.
#[test]
fn invalid_and_unauthorized_commands_stop_before_native_dispatch() {
    let (mut context, mut capabilities, mut audit, mut display) = mocks(Ok(successful_output()));
    let usage = CliApplication::new(&mut context, &mut capabilities, &mut audit, &mut display)
        .run(["retired", "command"]);
    assert_eq!(usage, CliExitCode::Usage);
    assert_eq!(context.calls, 0);
    assert!(capabilities.calls.is_empty());
    assert!(audit.intents.is_empty());
    assert!(matches!(
        display.events.as_slice(),
        [DisplayEvent::Fatal { code, .. }] if code == "cli.arguments_invalid"
    ));

    context.result = Ok(CommandContext::configured(LocalRole::Child));
    display.events.clear();
    let denied = CliApplication::new(&mut context, &mut capabilities, &mut audit, &mut display)
        .run(["topology"]);
    assert_eq!(denied, CliExitCode::Failure);
    assert!(capabilities.calls.is_empty());
    assert!(audit.intents.is_empty());
    assert_eq!(
        display.events,
        [DisplayEvent::NotAllowed {
            message: "Please run this from the main node.".to_owned()
        }]
    );
}

// Proves each terminal manager outcome selects the matching audit and exit contract.
#[test]
fn manager_failure_kinds_have_distinct_terminal_contracts() {
    let cases = [
        (
            CommandFailureKind::Failed,
            CommandAuditOutcome::Failed,
            CliExitCode::Failure,
        ),
        (
            CommandFailureKind::Denied,
            CommandAuditOutcome::Denied,
            CliExitCode::Failure,
        ),
        (
            CommandFailureKind::Cancelled,
            CommandAuditOutcome::Cancelled,
            CliExitCode::Cancelled,
        ),
    ];
    for (kind, audit_outcome, expected_exit) in cases {
        let failure =
            CommandFailure::new(kind, "fixture.failure", "fixture failure").expect("valid failure");
        let (mut context, mut capabilities, mut audit, mut display) = mocks(Err(failure));
        let exit = CliApplication::new(&mut context, &mut capabilities, &mut audit, &mut display)
            .run(["model", "pause", "fixture-model"]);
        assert_eq!(exit, expected_exit);
        assert_eq!(audit.results.len(), 1);
        assert_eq!(audit.results[0].outcome(), audit_outcome);
        assert_eq!(audit.results[0].failure_code(), Some("fixture.failure"));
        assert!(matches!(
            display.events.get(2),
            Some(DisplayEvent::ProgressFailed)
        ));
        match kind {
            CommandFailureKind::Failed => assert!(matches!(
                display.events.last(),
                Some(DisplayEvent::Fatal { code, .. }) if code == "fixture.failure"
            )),
            CommandFailureKind::Denied => assert!(matches!(
                display.events.last(),
                Some(DisplayEvent::Denied { .. })
            )),
            CommandFailureKind::Cancelled => {
                assert_eq!(display.events.last(), Some(&DisplayEvent::Cancelled))
            }
        }
    }
}

// Proves unavailable audit state fails closed before dispatch and after successful mutation.
#[test]
fn mandatory_audit_failures_surround_native_execution() {
    let (mut context, mut capabilities, mut audit, mut display) = mocks(Ok(successful_output()));
    audit.will_result = Err(CommandAuditError::new(
        "cli.audit_unavailable",
        "audit store unavailable",
    ));
    let before = CliApplication::new(&mut context, &mut capabilities, &mut audit, &mut display)
        .run(["model", "pause", "fixture-model"]);
    assert_eq!(before, CliExitCode::Failure);
    assert!(capabilities.calls.is_empty());
    assert!(audit.results.is_empty());

    let (mut context, mut capabilities, mut audit, mut display) = mocks(Ok(successful_output()));
    audit.will_result = Ok(None);
    let missing_marker =
        CliApplication::new(&mut context, &mut capabilities, &mut audit, &mut display).run([
            "model",
            "pause",
            "fixture-model",
        ]);
    assert_eq!(missing_marker, CliExitCode::Failure);
    assert!(capabilities.calls.is_empty());
    assert!(matches!(
        display.events.last(),
        Some(DisplayEvent::Fatal { code, .. }) if code == "cli.audit_marker_missing"
    ));

    let (mut context, mut capabilities, mut audit, mut display) = mocks(Ok(successful_output()));
    audit.did_result = Err(CommandAuditError::new(
        "cli.audit_result_unavailable",
        "audit commit unavailable",
    ));
    let after = CliApplication::new(&mut context, &mut capabilities, &mut audit, &mut display)
        .run(["model", "pause", "fixture-model"]);
    assert_eq!(after, CliExitCode::Failure);
    assert_eq!(capabilities.calls.len(), 1);
    assert!(!display
        .events
        .iter()
        .any(|event| matches!(event, DisplayEvent::HumanDocument(_))));
    assert!(matches!(
        display.events.last(),
        Some(DisplayEvent::Fatal { code, .. }) if code == "cli.audit_result_unavailable"
    ));
}

// Proves display failures cannot leave a successfully opened audit marker incomplete.
#[test]
fn display_failures_respect_the_audit_lifecycle_boundary() {
    let (mut context, mut capabilities, mut audit, mut display) = mocks(Ok(successful_output()));
    display.fail_at = Some(1);
    let before_marker =
        CliApplication::new(&mut context, &mut capabilities, &mut audit, &mut display).run([
            "model",
            "pause",
            "fixture-model",
        ]);
    assert_eq!(before_marker, CliExitCode::Failure);
    assert!(capabilities.calls.is_empty());
    assert!(audit.intents.is_empty());
    assert!(audit.results.is_empty());

    let (mut context, mut capabilities, mut audit, mut display) = mocks(Ok(successful_output()));
    capabilities.progress = vec![CommandProgressEvent::Detail("fixture detail".to_owned())];
    display.fail_at = Some(2);
    let after_marker =
        CliApplication::new(&mut context, &mut capabilities, &mut audit, &mut display).run([
            "model",
            "pause",
            "fixture-model",
        ]);
    assert_eq!(after_marker, CliExitCode::Failure);
    assert_eq!(capabilities.calls.len(), 1);
    assert_eq!(audit.intents.len(), 1);
    assert_eq!(audit.results.len(), 1);
    assert_eq!(audit.results[0].outcome(), CommandAuditOutcome::Succeeded);
}

// Proves a success-only policy still receives the terminal hook needed to close its marker.
#[test]
fn success_only_audit_closes_a_failed_update_marker() {
    let failure = CommandFailure::new(
        CommandFailureKind::Failed,
        "update.download_failed",
        "cannot download update",
    )
    .expect("failure");
    let (mut context, mut capabilities, mut audit, mut display) = mocks(Err(failure));
    let exit = CliApplication::new(&mut context, &mut capabilities, &mut audit, &mut display)
        .run(["update", "core"]);
    assert_eq!(exit, CliExitCode::Failure);
    assert_eq!(audit.intents.len(), 1);
    assert_eq!(audit.results.len(), 1);
    assert_eq!(audit.results[0].outcome(), CommandAuditOutcome::Failed);
}

// Proves a requested JSON command fails rather than deriving JSON from human text.
#[test]
fn missing_machine_document_fails_after_successful_audit() {
    let output = CommandOutput::new(CommandPresentation::empty(), None);
    let (mut context, mut capabilities, mut audit, mut display) = mocks(Ok(output));
    let exit = CliApplication::new(&mut context, &mut capabilities, &mut audit, &mut display)
        .run(["audit", "verify", "--json"]);
    assert_eq!(exit, CliExitCode::Failure);
    assert_eq!(audit.results.len(), 1);
    assert!(matches!(
        display.events.last(),
        Some(DisplayEvent::Fatal { code, .. }) if code == "cli.machine_output_missing"
    ));
}

// Proves the centralized stream renderer keeps stdout machine-clean and stderr semantic.
#[test]
fn stream_display_has_stable_human_json_and_failure_bytes() {
    let table = DisplayTable::new(
        vec!["NAME".to_owned(), "STATE".to_owned()],
        vec![vec!["fixture".to_owned(), "ready".to_owned()]],
    )
    .expect("table");
    let presentation = CommandPresentation::new(vec![
        DisplayBlock::Records(vec![DisplayRecord::new(
            "Node",
            "homeai",
            Some("Main".to_owned()),
            DisplaySemantic::Success,
        )]),
        DisplayBlock::Table(table),
    ]);
    let mut display = StreamCliDisplay::new(Vec::new(), Vec::new());
    display
        .display(DisplayEvent::Header { title: "Nodes" })
        .expect("header");
    display
        .display(DisplayEvent::HumanDocument(presentation))
        .expect("human");
    display
        .display(DisplayEvent::MachineDocument(MachineValue::object([
            ("line", MachineValue::from("one\ntwo")),
            ("ready", MachineValue::from(true)),
        ])))
        .expect("json");
    display
        .display(DisplayEvent::Fatal {
            code: "fixture.failure".to_owned(),
            message: "fixture failed".to_owned(),
        })
        .expect("failure");
    let (standard_output, standard_error) = display.into_streams();
    assert_eq!(
        String::from_utf8(standard_output).expect("stdout"),
        "Node: homeai · Main\nNAME  STATE\nfixture  ready\n{\"line\":\"one\\ntwo\",\"ready\":true}\n"
    );
    assert_eq!(
        String::from_utf8(standard_error).expect("stderr"),
        "LET'S INFER · Nodes\nFATAL: fixture failed\n"
    );
}

// Writes opaque finite and live log bytes without UTF-8 conversion or newline fabrication.
#[test]
fn stream_display_preserves_opaque_runtime_log_bytes() {
    let mut display = StreamCliDisplay::new(Vec::new(), Vec::new());
    display
        .display(DisplayEvent::HumanDocument(CommandPresentation::new(vec![
            DisplayBlock::RawBytes(vec![0, 255, b'\n']),
        ])))
        .expect("finite bytes");
    display
        .display(DisplayEvent::RawOutput(vec![b'x', 0, b'y']))
        .expect("live bytes");
    let (standard_output, standard_error) = display.into_streams();
    assert_eq!(standard_output, [0, 255, b'\n', b'x', 0, b'y']);
    assert!(standard_error.is_empty());
}

// Proves every public registry leaf has one explicit presentation contract.
#[test]
fn display_contracts_cover_the_closed_registry() {
    let contracts = actions()
        .iter()
        .map(|metadata| display_contract(metadata.id()))
        .collect::<Vec<DisplayContract>>();
    assert_eq!(contracts.len(), 47);
    assert!(contracts
        .iter()
        .zip(actions())
        .all(|(contract, metadata)| contract.action() == metadata.id()));
    assert_eq!(
        contracts
            .iter()
            .filter(|contract| contract.surface() == DisplaySurface::Internal)
            .count(),
        0
    );
    let core_update = display_contract(li_core_cli::ActionId::UpdateCore);
    assert_eq!(core_update.progress(), DisplayProgressKind::Steps);
    assert_eq!(core_update.steps().len(), 3);
    assert_eq!(core_update.output(), DisplayOutputContract::MutationResult);
}

// Proves malformed stable failures and table shapes are rejected at construction.
#[test]
fn capability_and_display_values_reject_ambiguous_contracts() {
    assert!(CommandFailure::new(CommandFailureKind::Failed, "UPPER", "message").is_err());
    assert!(CommandFailure::new(CommandFailureKind::Failed, "valid.code", "").is_err());
    assert!(DisplayTable::new(
        vec!["ONE".to_owned(), "TWO".to_owned()],
        vec![vec!["only-one".to_owned()]],
    )
    .is_err());
    assert!(MachineNumber::from_f64(f64::NAN).is_err());
    assert_eq!(
        MachineValue::Number(MachineNumber::from_f64(12.5).expect("number"))
            .to_json()
            .expect("JSON"),
        "12.5"
    );
}

// Shares one secret across output modes and redacts every debug and failure path.
#[test]
fn one_time_secret_display_is_single_presentation_and_debug_redacted() {
    let token = format!("li_{}_{}", "a".repeat(32), "b".repeat(64));
    let secret = OneTimeSecret::new(token.clone());
    let machine = MachineValue::object([("token", MachineValue::OneTimeSecret(secret.clone()))]);
    let human = CommandPresentation::new(vec![DisplayBlock::OneTimeSecret {
        label: Some("Token".to_string()),
        value: secret,
    }]);
    assert!(!format!("{machine:?}{human:?}").contains(&token));

    let mut display = StreamCliDisplay::new(Vec::new(), Vec::new());
    display
        .display(DisplayEvent::MachineDocument(machine))
        .expect("first presentation");
    let error = display
        .display(DisplayEvent::HumanDocument(human))
        .expect_err("second presentation");
    assert!(!format!("{error:?}").contains(&token));
    let (standard_output, standard_error) = display.into_streams();
    let standard_output = String::from_utf8(standard_output).expect("standard output");
    assert_eq!(standard_output.matches(&token).count(), 1);
    assert!(!String::from_utf8(standard_error)
        .expect("standard error")
        .contains(&token));
}
