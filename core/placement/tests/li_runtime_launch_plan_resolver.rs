// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use li_core_interface::{
    CredentialId, DeviceId, EndpointOwnership, EntityTimestamps, NetworkInterfaceName, NodeAddress,
    NodeId, Placement, PlacementAssignment, PlacementGroupId, PlacementId, PlacementResources,
    PlacementState, PortRange, RuntimeInstallationId, RuntimeSource, Sha256Digest, TaskId,
    UnixMilliseconds,
};
use li_placement_manager::{
    LinuxRuntimeLaunchTemplate, MacosRuntimeLaunchTemplate, PlacementCredentialReferences,
    PlacementError, PlacementLaunchPlanResolver, ResolvedPlacementLaunchPlan,
    RuntimePlacementExecution, RuntimePlacementExecutionProvider,
    RuntimePlacementLaunchPlanResolver, RuntimePlacementReadiness, RuntimeServingContract,
    ShellFreeCommand, ShellFreeEnvironmentValue,
};

// Returns one exact placement fixture with configurable endpoint ownership.
fn placement(endpoint_owner: bool) -> Placement {
    Placement::new(
        PlacementId::parse(&"1".repeat(32)).expect("placement"),
        PlacementGroupId::parse(&"2".repeat(32)).expect("group"),
        PlacementAssignment::new(
            NodeId::parse(&"3".repeat(32)).expect("node"),
            RuntimeInstallationId::parse(&"4".repeat(32)).expect("installation"),
            li_core_interface::HardwareObservationId::parse(&"6".repeat(32))
                .expect("hardware observation"),
            li_core_interface::BootId::parse("11111111-2222-3333-4444-555555555555").expect("boot"),
            li_core_interface::UnixMilliseconds::new(900),
            TaskId::parse("task-0").expect("task"),
            NodeAddress::parse("node.local").expect("address"),
            PlacementResources::new(
                PortRange::new(18_000, 2).expect("ports"),
                vec![DeviceId::parse("GPU-A").expect("GPU")],
                Some(NetworkInterfaceName::parse("enp1s0f0np0").expect("RDMA")),
            )
            .expect("resources"),
            if endpoint_owner {
                EndpointOwnership::Owner
            } else {
                EndpointOwnership::Participant
            },
        ),
        PlacementState::Staging,
        None,
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(1_000))
            .expect("timestamps"),
    )
    .expect("placement")
}

// Returns exact reference-only credential inputs.
fn credentials(placement: &Placement) -> PlacementCredentialReferences {
    PlacementCredentialReferences::new(
        placement.placement_id().clone(),
        CredentialId::parse(&"5".repeat(32)).expect("credential"),
        CredentialId::parse(&"6".repeat(32)).expect("CA"),
        PathBuf::from("/private/engine.key"),
        PathBuf::from("/private/engine.crt"),
        PathBuf::from("/private/engine-tls.key"),
        Sha256Digest::parse(&"7".repeat(64)).expect("certificate"),
        Sha256Digest::parse(&"8".repeat(64)).expect("bundle"),
    )
    .expect("credentials")
}

// Returns one generic serving contract.
fn serving() -> RuntimeServingContract {
    RuntimeServingContract::new(
        NodeAddress::parse("127.0.0.1").expect("host"),
        4,
        262_144,
        Some("/v1/letsinfer/token-count".to_string()),
    )
    .expect("serving")
}

// Returns one Core-owned Docker command root without argv.
fn docker() -> ShellFreeCommand {
    ShellFreeCommand::new(
        PathBuf::from("/usr/bin/docker"),
        Vec::new(),
        Vec::new(),
        vec![
            ShellFreeEnvironmentValue::core("HOME", "/home/fixture").expect("home"),
            ShellFreeEnvironmentValue::core("PATH", "/usr/bin:/bin").expect("path"),
        ],
        PathBuf::from("/tmp"),
    )
    .expect("Docker")
}

// Returns one complete Linux runtime launch template.
fn linux_template(readiness: RuntimePlacementReadiness) -> LinuxRuntimeLaunchTemplate {
    LinuxRuntimeLaunchTemplate::new(
        docker(),
        RuntimeSource::parse(&format!(
            "ghcr.io/letsinferlabs/engine@sha256:{}",
            "a".repeat(64)
        ))
        .expect("image"),
        Sha256Digest::parse(&"b".repeat(64)).expect("image identity"),
        vec![
            "/opt/letsinfer/bin/engine-adapter".to_string(),
            "serve".to_string(),
        ],
        vec![ShellFreeEnvironmentValue::runtime("RUNTIME_MODE", "serve").expect("runtime")],
        readiness,
        PathBuf::from("/runtime"),
        PathBuf::from("/models"),
        PathBuf::from("/cache"),
        64 * 1024 * 1024 * 1024,
        8 * 1024 * 1024 * 1024,
        8 * 1024 * 1024 * 1024,
        1_000,
        1_000,
        Some("0-7".to_string()),
        vec![PathBuf::from("/dev/infiniband/rdma_cm")],
        BTreeMap::from([("vendor.fixture".to_string(), "true".to_string())]),
        vec!["--ulimit".to_string(), "memlock=1024:1024".to_string()],
    )
    .expect("Linux template")
}

// Returns one complete macOS runtime launch template.
fn macos_template() -> MacosRuntimeLaunchTemplate {
    MacosRuntimeLaunchTemplate::new(
        ShellFreeCommand::new(
            PathBuf::from("/usr/bin/printf"),
            vec!["serve".to_string()],
            vec![ShellFreeEnvironmentValue::runtime("RUNTIME_MODE", "native").expect("runtime")],
            Vec::new(),
            PathBuf::from("/tmp"),
        )
        .expect("command"),
        3,
        Duration::from_millis(1),
    )
    .expect("macOS template")
}

// Mocks RuntimeManager's exact execution projection.
struct MockExecutionProvider {
    value: Mutex<Option<RuntimePlacementExecution>>,
    fail: AtomicBool,
}

impl MockExecutionProvider {
    // Creates one deterministic execution provider.
    fn new(value: RuntimePlacementExecution) -> Self {
        Self {
            value: Mutex::new(Some(value)),
            fail: AtomicBool::new(false),
        }
    }
}

impl RuntimePlacementExecutionProvider for MockExecutionProvider {
    // Returns the configured execution contract or provider failure.
    fn execution(
        &self,
        _placement: &Placement,
    ) -> Result<RuntimePlacementExecution, PlacementError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(PlacementError::ExecutionUnavailable);
        }
        self.value
            .lock()
            .expect("execution")
            .clone()
            .ok_or(PlacementError::ExecutionUnavailable)
    }
}

// Returns one Linux execution bundle matching a placement.
fn linux_execution(
    placement: &Placement,
    readiness: RuntimePlacementReadiness,
) -> RuntimePlacementExecution {
    RuntimePlacementExecution::Linux {
        runtime_installation_id: placement.assignment().runtime_installation_id().clone(),
        task_id: placement.assignment().task_id().clone(),
        port_count: placement.assignment().resources().ports().count(),
        device_count: placement.assignment().resources().device_ids().len() as u16,
        serving: serving(),
        launch: linux_template(readiness),
    }
}

// Returns one macOS execution bundle matching a placement.
fn macos_execution(placement: &Placement) -> RuntimePlacementExecution {
    RuntimePlacementExecution::Macos {
        runtime_installation_id: placement.assignment().runtime_installation_id().clone(),
        task_id: placement.assignment().task_id().clone(),
        port_count: placement.assignment().resources().ports().count(),
        device_count: placement.assignment().resources().device_ids().len() as u16,
        executable_identity: Sha256Digest::parse(&"9".repeat(64)).expect("executable"),
        serving: serving(),
        launch: macos_template(),
    }
}

// Resolves one complete Linux command from exact runtime, resource, and credential inputs.
#[test]
fn resolver_builds_sealed_linux_plan() {
    let placement = placement(true);
    let resolver = RuntimePlacementLaunchPlanResolver::new(Arc::new(MockExecutionProvider::new(
        linux_execution(
            &placement,
            RuntimePlacementReadiness::Endpoint {
                attempts: 3,
                interval: Duration::from_millis(1),
            },
        ),
    )));
    let resolved = resolver
        .resolve(&placement, &credentials(&placement))
        .expect("resolve");
    let ResolvedPlacementLaunchPlan::Linux(plan) = &resolved else {
        panic!("expected Linux plan");
    };
    let arguments = plan.create_command().arguments();
    for required in [
        "--restart",
        "no",
        "--read-only",
        "--gpus",
        "device=GPU-A",
        "/private/engine.key:/run/secrets/li_engine_credential:ro",
        "/private/engine.crt:/run/secrets/li_engine_tls_certificate.pem:ro",
        "/private/engine-tls.key:/run/secrets/li_engine_tls_private_key.pem:ro",
        "LETSINFER_RDMA_INTERFACE=enp1s0f0np0",
        "/opt/letsinfer/bin/engine-adapter",
    ] {
        assert!(
            arguments.iter().any(|value| value == required),
            "{required}"
        );
    }
    assert!(resolved.validate_for(&placement).is_ok());
    assert!(resolved
        .validate_credentials(&credentials(&placement))
        .is_ok());
}

// Resolves one native launchd command with Core-owned protected references.
#[test]
fn resolver_builds_separate_macos_plan() {
    let placement = placement(true);
    let resolver = RuntimePlacementLaunchPlanResolver::new(Arc::new(MockExecutionProvider::new(
        macos_execution(&placement),
    )));
    let resolved = resolver
        .resolve(&placement, &credentials(&placement))
        .expect("resolve");
    let ResolvedPlacementLaunchPlan::Macos(plan) = &resolved else {
        panic!("expected macOS plan");
    };
    assert_eq!(
        plan.command().executable(),
        PathBuf::from("/usr/bin/printf")
    );
    for name in [
        "LETSINFER_ENGINE_PROTOCOL",
        "LETSINFER_PLACEMENT_ID",
        "LETSINFER_API_KEY_FILE",
        "LETSINFER_TLS_CERT_FILE",
        "LETSINFER_TLS_KEY_FILE",
    ] {
        assert!(plan
            .command()
            .environment()
            .iter()
            .any(|value| value.name() == name));
    }
    assert!(resolved
        .validate_credentials(&credentials(&placement))
        .is_ok());
}

// Keeps participant execution private while retaining exact credential file references.
#[test]
fn resolver_keeps_participant_endpoint_private() {
    let placement = placement(false);
    let resolver = RuntimePlacementLaunchPlanResolver::new(Arc::new(MockExecutionProvider::new(
        linux_execution(
            &placement,
            RuntimePlacementReadiness::Exec {
                arguments: vec!["/opt/runtime/ready".to_string()],
                attempts: 2,
                interval: Duration::from_millis(1),
            },
        ),
    )));
    let resolved = resolver
        .resolve(&placement, &credentials(&placement))
        .expect("resolve");
    let ResolvedPlacementLaunchPlan::Linux(plan) = &resolved else {
        panic!("expected Linux plan");
    };
    assert!(plan.endpoint().is_none());
    assert!(resolved
        .validate_credentials(&credentials(&placement))
        .is_ok());
}

// Rejects changed runtime installation, task, port count, and device count independently.
#[test]
fn resolver_rejects_every_execution_binding_mismatch() {
    let placement = placement(true);
    for mismatch in ["installation", "task", "ports", "devices"] {
        let execution = RuntimePlacementExecution::Linux {
            runtime_installation_id: if mismatch == "installation" {
                RuntimeInstallationId::parse(&"9".repeat(32)).expect("changed")
            } else {
                placement.assignment().runtime_installation_id().clone()
            },
            task_id: if mismatch == "task" {
                TaskId::parse("task-1").expect("changed")
            } else {
                placement.assignment().task_id().clone()
            },
            port_count: if mismatch == "ports" { 1 } else { 2 },
            device_count: if mismatch == "devices" { 2 } else { 1 },
            serving: serving(),
            launch: linux_template(RuntimePlacementReadiness::Endpoint {
                attempts: 1,
                interval: Duration::from_millis(1),
            }),
        };
        assert!(
            RuntimePlacementLaunchPlanResolver::new(Arc::new(MockExecutionProvider::new(
                execution
            )))
            .resolve(&placement, &credentials(&placement))
            .is_err(),
            "{mismatch}"
        );
    }
}

// Rejects credential references owned by another placement before runtime lookup.
#[test]
fn resolver_rejects_foreign_credential_references() {
    let local = placement(true);
    let foreign = placement(false);
    let changed = PlacementCredentialReferences::new(
        PlacementId::parse(&"9".repeat(32)).expect("foreign"),
        credentials(&foreign).credential_id().clone(),
        credentials(&foreign).ca_credential_id().clone(),
        PathBuf::from("/private/engine.key"),
        PathBuf::from("/private/engine.crt"),
        PathBuf::from("/private/engine-tls.key"),
        credentials(&foreign).tls_certificate_sha256().clone(),
        credentials(&foreign).credential_bundle_sha256().clone(),
    )
    .expect("foreign references");
    assert!(
        RuntimePlacementLaunchPlanResolver::new(Arc::new(MockExecutionProvider::new(
            macos_execution(&local)
        )))
        .resolve(&local, &changed)
        .is_err()
    );
}

// Rejects zero serving limits and invalid token-count paths.
#[test]
fn serving_contract_rejects_invalid_boundaries() {
    assert!(RuntimeServingContract::new(
        NodeAddress::parse("node.local").expect("host"),
        0,
        1,
        None,
    )
    .is_err());
    assert!(RuntimeServingContract::new(
        NodeAddress::parse("node.local").expect("host"),
        1,
        1,
        Some("relative".to_string()),
    )
    .is_err());
}

// Rejects shells, secrets, protected environment, unsafe roots, and Core Docker options.
#[test]
fn linux_template_rejects_every_unsafe_runtime_surface() {
    let base = || {
        (
            docker(),
            RuntimeSource::parse(&format!(
                "ghcr.io/letsinferlabs/engine@sha256:{}",
                "a".repeat(64)
            ))
            .expect("image"),
            Sha256Digest::parse(&"b".repeat(64)).expect("image identity"),
        )
    };
    for surface in [
        "shell",
        "secret",
        "protected",
        "root",
        "option",
        "root_user",
    ] {
        let (docker, image, image_id) = base();
        let command = if surface == "shell" {
            vec!["/bin/sh".to_string()]
        } else {
            vec!["/opt/engine".to_string()]
        };
        let environment = match surface {
            "secret" => {
                vec![ShellFreeEnvironmentValue::runtime("HF_TOKEN", "plaintext").expect("secret")]
            }
            "protected" => {
                vec![
                    ShellFreeEnvironmentValue::protected("LETSINFER_TASK_ID", "changed")
                        .expect("protected"),
                ]
            }
            _ => Vec::new(),
        };
        assert!(
            LinuxRuntimeLaunchTemplate::new(
                docker,
                image,
                image_id,
                command,
                environment,
                RuntimePlacementReadiness::Endpoint {
                    attempts: 1,
                    interval: Duration::from_millis(1),
                },
                if surface == "root" {
                    PathBuf::from("relative")
                } else {
                    PathBuf::from("/runtime")
                },
                PathBuf::from("/models"),
                PathBuf::from("/cache"),
                1,
                1,
                1,
                if surface == "root_user" { 0 } else { 1000 },
                1000,
                None,
                Vec::new(),
                BTreeMap::new(),
                if surface == "option" {
                    vec!["--name".to_string(), "foreign".to_string()]
                } else {
                    Vec::new()
                },
            )
            .is_err(),
            "{surface}"
        );
    }
}

// Rejects Core-owned or secret-bearing native environment and submillisecond readiness.
#[test]
fn macos_template_rejects_unsafe_runtime_surface() {
    let command = |environment| {
        ShellFreeCommand::new(
            PathBuf::from("/usr/bin/printf"),
            vec!["serve".to_string()],
            environment,
            Vec::new(),
            PathBuf::from("/tmp"),
        )
        .expect("command")
    };
    assert!(MacosRuntimeLaunchTemplate::new(
        command(vec![ShellFreeEnvironmentValue::runtime(
            "HF_TOKEN",
            "plaintext"
        )
        .expect("secret")]),
        1,
        Duration::from_millis(1),
    )
    .is_err());
    let protected_command = ShellFreeCommand::new(
        PathBuf::from("/usr/bin/printf"),
        Vec::new(),
        Vec::new(),
        vec![
            ShellFreeEnvironmentValue::protected("LETSINFER_TASK_ID", "changed")
                .expect("protected"),
        ],
        PathBuf::from("/tmp"),
    )
    .expect("command");
    assert!(
        MacosRuntimeLaunchTemplate::new(protected_command, 1, Duration::from_millis(1),).is_err()
    );
    assert!(
        MacosRuntimeLaunchTemplate::new(command(Vec::new()), 1, Duration::from_nanos(1),).is_err()
    );
}

// Propagates RuntimeManager execution-provider failure without fabricating a plan.
#[test]
fn resolver_propagates_execution_provider_failure() {
    let placement = placement(true);
    let provider = Arc::new(MockExecutionProvider::new(macos_execution(&placement)));
    provider.fail.store(true, Ordering::SeqCst);
    assert_eq!(
        RuntimePlacementLaunchPlanResolver::new(provider)
            .resolve(&placement, &credentials(&placement))
            .expect_err("provider failure"),
        PlacementError::ExecutionUnavailable
    );
}

// Resolving the same immutable inputs produces the same launch-plan identity.
#[test]
fn resolver_is_deterministic_for_identical_inputs() {
    let placement = placement(true);
    let execution = macos_execution(&placement);
    let first = RuntimePlacementLaunchPlanResolver::new(Arc::new(MockExecutionProvider::new(
        execution.clone(),
    )))
    .resolve(&placement, &credentials(&placement))
    .expect("first");
    let second =
        RuntimePlacementLaunchPlanResolver::new(Arc::new(MockExecutionProvider::new(execution)))
            .resolve(&placement, &credentials(&placement))
            .expect("second");
    assert_eq!(
        first.identity(&placement).expect("first identity"),
        second.identity(&placement).expect("second identity")
    );
}
