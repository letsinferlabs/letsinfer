// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use li_core_interface::{
    EndpointAddress, EndpointHealth, EndpointOwnership, EndpointScheme, LogicalModelName,
    NodeAddress, Placement, PlacementEndpoint, RuntimeInstallationId, Sha256Digest, TaskId,
    TokenCountContract, TokenCountProtocol,
};
use li_runtime_manager::RuntimeExecutionImageReference;

use crate::{
    LinuxContainerLaunchPlan, LinuxContainerReadiness, MacosLaunchAgentPlan,
    PlacementCredentialReferences, PlacementError, PlacementLaunchPlanResolver,
    ResolvedPlacementLaunchPlan, ShellFreeCommand, ShellFreeEnvironmentValue,
};

// Describes one runtime-owned readiness contract without platform process policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimePlacementReadiness {
    Endpoint {
        attempts: u16,
        interval: Duration,
    },
    Exec {
        arguments: Vec<String>,
        attempts: u16,
        interval: Duration,
    },
}

// Describes generic serving and endpoint limits owned by one runtime release.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeServingContract {
    endpoint_host: NodeAddress,
    max_active_requests: u32,
    max_context_tokens: u64,
    token_count_path: Option<String>,
    served_model: Option<LogicalModelName>,
}

impl RuntimeServingContract {
    // Creates one positive serving contract without making a routing decision.
    pub fn new(
        endpoint_host: NodeAddress,
        max_active_requests: u32,
        max_context_tokens: u64,
        token_count_path: Option<String>,
    ) -> Result<Self, PlacementError> {
        if max_active_requests == 0 || max_context_tokens == 0 {
            return Err(PlacementError::InvalidRequest {
                reason: "runtime serving limits must be positive",
            });
        }
        if let Some(path) = &token_count_path {
            TokenCountContract::new(path, TokenCountProtocol::LetsInferV1).map_err(|_| {
                PlacementError::InvalidRequest {
                    reason: "runtime token-count path is invalid",
                }
            })?;
        }
        Ok(Self {
            endpoint_host,
            max_active_requests,
            max_context_tokens,
            token_count_path,
            served_model: None,
        })
    }

    // Binds the protocol-owned served model identity used by native launch adapters.
    pub fn with_served_model(mut self, served_model: LogicalModelName) -> Self {
        self.served_model = Some(served_model);
        self
    }
}

// Carries one runtime's generic Linux container launch inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxRuntimeLaunchTemplate {
    docker: ShellFreeCommand,
    image_reference: RuntimeExecutionImageReference,
    image_id: Sha256Digest,
    engine_command: Vec<String>,
    engine_environment: Vec<ShellFreeEnvironmentValue>,
    readiness: RuntimePlacementReadiness,
    runtime_root: PathBuf,
    model_root: PathBuf,
    cache_root: PathBuf,
    memory_bytes: u64,
    shared_memory_bytes: u64,
    temporary_bytes: u64,
    user_id: u32,
    group_id: u32,
    cpuset: Option<String>,
    device_nodes: Vec<PathBuf>,
    additional_labels: BTreeMap<String, String>,
    additional_options: Vec<String>,
}

impl LinuxRuntimeLaunchTemplate {
    // Creates one bounded engine-neutral Linux launch template.
    #[allow(clippy::too_many_arguments)]
    pub fn new<ImageReference>(
        docker: ShellFreeCommand,
        image_reference: ImageReference,
        image_id: Sha256Digest,
        engine_command: Vec<String>,
        engine_environment: Vec<ShellFreeEnvironmentValue>,
        readiness: RuntimePlacementReadiness,
        runtime_root: PathBuf,
        model_root: PathBuf,
        cache_root: PathBuf,
        memory_bytes: u64,
        shared_memory_bytes: u64,
        temporary_bytes: u64,
        user_id: u32,
        group_id: u32,
        cpuset: Option<String>,
        device_nodes: Vec<PathBuf>,
        additional_labels: BTreeMap<String, String>,
        additional_options: Vec<String>,
    ) -> Result<Self, PlacementError>
    where
        ImageReference: Into<RuntimeExecutionImageReference>,
    {
        let image_reference = image_reference.into();
        validate_runtime_command(&engine_command)?;
        validate_runtime_environment(&engine_environment)?;
        validate_roots(&runtime_root, &model_root, &cache_root)?;
        ShellFreeCommand::new(
            PathBuf::from(&engine_command[0]),
            engine_command.iter().skip(1).cloned().collect(),
            engine_environment.clone(),
            Vec::new(),
            runtime_root.clone(),
        )?
        .validate_persistable()?;
        validate_linux_options(&additional_options)?;
        if docker.arguments().len() != 0
            || memory_bytes == 0
            || shared_memory_bytes == 0
            || temporary_bytes == 0
            || user_id == 0
            || group_id == 0
            || device_nodes.len() > 32
            || device_nodes.iter().any(|path| {
                !path.is_absolute()
                    || !path.starts_with("/dev")
                    || path
                        .components()
                        .any(|component| matches!(component, std::path::Component::ParentDir))
            })
            || additional_labels.len() > 64
            || additional_labels.iter().any(|(key, value)| {
                key.starts_with("ai.letsinfer.")
                    || key.is_empty()
                    || key.len() > 255
                    || value.len() > 1024
                    || key.chars().any(char::is_control)
                    || value.chars().any(char::is_control)
            })
            || cpuset.as_ref().is_some_and(|value| {
                value.is_empty()
                    || value.len() > 1024
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || matches!(byte, b',' | b'-'))
            })
        {
            return Err(PlacementError::InvalidRequest {
                reason: "Linux runtime launch template is invalid or unbounded",
            });
        }
        Ok(Self {
            docker,
            image_reference,
            image_id,
            engine_command,
            engine_environment,
            readiness,
            runtime_root,
            model_root,
            cache_root,
            memory_bytes,
            shared_memory_bytes,
            temporary_bytes,
            user_id,
            group_id,
            cpuset,
            device_nodes,
            additional_labels,
            additional_options,
        })
    }
}

// Carries one runtime's generic macOS native launch inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacosRuntimeLaunchTemplate {
    command: ShellFreeCommand,
    core_environment: Vec<ShellFreeEnvironmentValue>,
    readiness_attempts: u16,
    readiness_interval: Duration,
    log_root: Option<PathBuf>,
}

impl MacosRuntimeLaunchTemplate {
    // Creates one runtime-owned native command without Core environment overrides.
    pub fn new(
        command: ShellFreeCommand,
        readiness_attempts: u16,
        readiness_interval: Duration,
    ) -> Result<Self, PlacementError> {
        if command
            .environment()
            .iter()
            .any(|value| !value.is_runtime_owned() || value.validate_persistable().is_err())
            || command.validate_persistable().is_err()
            || readiness_attempts == 0
            || readiness_attempts > 3_600
            || readiness_interval.is_zero()
            || readiness_interval > Duration::from_secs(60)
            || Duration::from_millis(readiness_interval.as_millis() as u64) != readiness_interval
        {
            return Err(PlacementError::InvalidRequest {
                reason: "macOS runtime launch template is invalid or unbounded",
            });
        }
        Ok(Self {
            command,
            core_environment: Vec::new(),
            readiness_attempts,
            readiness_interval,
            log_root: None,
        })
    }

    // Adds one exact Core-owned private log root for native launchd output.
    pub fn with_log_root(mut self, log_root: PathBuf) -> Result<Self, PlacementError> {
        if !log_root.is_absolute()
            || log_root
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err(PlacementError::InvalidRequest {
                reason: "macOS runtime log root is invalid",
            });
        }
        self.log_root = Some(log_root);
        Ok(self)
    }

    // Adds explicit Core-owned native paths without allowing runtime overrides.
    pub fn with_core_environment(
        mut self,
        core_environment: Vec<ShellFreeEnvironmentValue>,
    ) -> Result<Self, PlacementError> {
        if core_environment
            .iter()
            .any(|value| !value.is_core_owned() || value.validate_persistable().is_err())
        {
            return Err(PlacementError::InvalidRequest {
                reason: "macOS Core execution environment is invalid",
            });
        }
        self.core_environment = core_environment;
        Ok(self)
    }
}

// Binds one runtime installation and opaque task to generic execution inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimePlacementExecution {
    Linux {
        runtime_installation_id: RuntimeInstallationId,
        task_id: TaskId,
        port_count: u16,
        device_count: u16,
        serving: RuntimeServingContract,
        launch: LinuxRuntimeLaunchTemplate,
    },
    Macos {
        runtime_installation_id: RuntimeInstallationId,
        task_id: TaskId,
        port_count: u16,
        device_count: u16,
        executable_identity: li_core_interface::Sha256Digest,
        serving: RuntimeServingContract,
        launch: MacosRuntimeLaunchTemplate,
    },
}

// Supplies already-verified runtime execution inputs without exposing runtime storage.
pub trait RuntimePlacementExecutionProvider: Send + Sync {
    // Returns one exact generic task execution contract for a placement.
    fn execution(&self, placement: &Placement)
        -> Result<RuntimePlacementExecution, PlacementError>;
}

// Resolves typed runtime execution into sealed Linux or macOS launch plans.
pub struct RuntimePlacementLaunchPlanResolver {
    executions: Arc<dyn RuntimePlacementExecutionProvider>,
}

impl RuntimePlacementLaunchPlanResolver {
    // Creates one resolver from RuntimeManager's narrow verified execution capability.
    pub const fn new(executions: Arc<dyn RuntimePlacementExecutionProvider>) -> Self {
        Self { executions }
    }
}

impl PlacementLaunchPlanResolver for RuntimePlacementLaunchPlanResolver {
    // Binds runtime inputs, exact placement resources, and reference-only credentials.
    fn resolve(
        &self,
        placement: &Placement,
        credentials: &PlacementCredentialReferences,
    ) -> Result<ResolvedPlacementLaunchPlan, PlacementError> {
        if credentials.placement_id() != placement.placement_id() {
            return Err(PlacementError::InvalidRequest {
                reason: "placement credentials belong to another placement",
            });
        }
        match self.executions.execution(placement)? {
            RuntimePlacementExecution::Linux {
                runtime_installation_id,
                task_id,
                port_count,
                device_count,
                serving,
                launch,
            } => {
                validate_execution_binding(
                    placement,
                    &runtime_installation_id,
                    &task_id,
                    port_count,
                    device_count,
                )?;
                resolve_linux_plan(placement, credentials, serving, launch)
            }
            RuntimePlacementExecution::Macos {
                runtime_installation_id,
                task_id,
                port_count,
                device_count,
                executable_identity,
                serving,
                launch,
            } => {
                validate_execution_binding(
                    placement,
                    &runtime_installation_id,
                    &task_id,
                    port_count,
                    device_count,
                )?;
                resolve_macos_plan(placement, credentials, executable_identity, serving, launch)
            }
        }
    }
}

// Builds one sealed Docker command from runtime inputs and Core-owned placement facts.
fn resolve_linux_plan(
    placement: &Placement,
    credentials: &PlacementCredentialReferences,
    serving: RuntimeServingContract,
    launch: LinuxRuntimeLaunchTemplate,
) -> Result<ResolvedPlacementLaunchPlan, PlacementError> {
    let container_name = format!("li_placement_{}", placement.placement_id().as_str());
    let mut arguments = vec![
        "run".to_string(),
        "--detach".to_string(),
        "--pull".to_string(),
        "never".to_string(),
        "--restart".to_string(),
        "no".to_string(),
        "--name".to_string(),
        container_name,
        "--log-driver".to_string(),
        "local".to_string(),
        "--log-opt".to_string(),
        "max-size=8m".to_string(),
        "--log-opt".to_string(),
        "max-file=2".to_string(),
    ];
    for (key, value) in protected_labels(placement) {
        arguments.extend(["--label".to_string(), format!("{key}={value}")]);
    }
    arguments.extend([
        "--label".to_string(),
        format!(
            "ai.letsinfer.credential_bundle_sha256={}",
            credentials.credential_bundle_sha256().as_str()
        ),
    ]);
    for (key, value) in launch.additional_labels {
        arguments.extend(["--label".to_string(), format!("{key}={value}")]);
    }
    arguments.extend([
        "--init".to_string(),
        "--read-only".to_string(),
        "--cap-drop".to_string(),
        "ALL".to_string(),
        "--security-opt".to_string(),
        "no-new-privileges=true".to_string(),
        "--user".to_string(),
        format!("{}:{}", launch.user_id, launch.group_id),
        "--network".to_string(),
        "host".to_string(),
        "--ipc".to_string(),
        "host".to_string(),
        "--gpus".to_string(),
        format!(
            "device={}",
            placement
                .assignment()
                .resources()
                .device_ids()
                .iter()
                .map(|value| value.as_str())
                .collect::<Vec<_>>()
                .join(",")
        ),
        "--memory".to_string(),
        launch.memory_bytes.to_string(),
        "--memory-swap".to_string(),
        launch.memory_bytes.to_string(),
        "--shm-size".to_string(),
        launch.shared_memory_bytes.to_string(),
        "--tmpfs".to_string(),
        format!("/tmp:rw,nosuid,nodev,exec,size={}", launch.temporary_bytes),
    ]);
    if let Some(cpuset) = launch.cpuset {
        arguments.extend(["--cpuset-cpus".to_string(), cpuset]);
    }
    for device in launch.device_nodes {
        let device = device.to_string_lossy().into_owned();
        arguments.extend(["--device".to_string(), format!("{device}:{device}:rwm")]);
    }
    add_mount(
        &mut arguments,
        &launch.runtime_root,
        "/opt/letsinfer/runtime-pack",
        true,
    );
    add_mount(&mut arguments, &launch.model_root, "/models", true);
    add_mount(&mut arguments, &launch.cache_root, "/root", false);
    add_mount(
        &mut arguments,
        credentials.engine_credential_file(),
        "/run/secrets/li_engine_credential",
        true,
    );
    add_mount(
        &mut arguments,
        credentials.tls_certificate_file(),
        "/run/secrets/li_engine_tls_certificate.pem",
        true,
    );
    add_mount(
        &mut arguments,
        credentials.tls_private_key_file(),
        "/run/secrets/li_engine_tls_private_key.pem",
        true,
    );
    for (name, value) in protected_container_environment(placement, &serving) {
        arguments.extend(["--env".to_string(), format!("{name}={value}")]);
    }
    arguments.extend([
        "--env".to_string(),
        format!(
            "LETSINFER_CREDENTIAL_BUNDLE_SHA256={}",
            credentials.credential_bundle_sha256().as_str()
        ),
    ]);
    for value in launch.engine_environment {
        arguments.extend([
            "--env".to_string(),
            format!("{}={}", value.name(), value.value()),
        ]);
    }
    if let Some(interface) = placement.assignment().resources().rdma_interface() {
        arguments.extend([
            "--env".to_string(),
            format!("LETSINFER_RDMA_INTERFACE={}", interface.as_str()),
        ]);
    }
    arguments.extend(launch.additional_options);
    arguments.extend([
        "--entrypoint".to_string(),
        launch.engine_command[0].clone(),
        launch.image_reference.as_str().to_string(),
    ]);
    arguments.extend(launch.engine_command.into_iter().skip(1));
    let command = launch.docker.with_arguments(arguments)?;
    let endpoint = placement_endpoint(placement, credentials, &serving)?;
    Ok(ResolvedPlacementLaunchPlan::Linux(
        LinuxContainerLaunchPlan::new(
            placement,
            launch.image_reference,
            launch.image_id,
            command,
            match launch.readiness {
                RuntimePlacementReadiness::Endpoint { attempts, interval } => {
                    LinuxContainerReadiness::endpoint(attempts, interval)?
                }
                RuntimePlacementReadiness::Exec {
                    arguments,
                    attempts,
                    interval,
                } => LinuxContainerReadiness::exec(arguments, attempts, interval)?,
            },
            endpoint,
        )?,
    ))
}

// Builds one sealed launchd command by adding only Core-owned placement references.
fn resolve_macos_plan(
    placement: &Placement,
    credentials: &PlacementCredentialReferences,
    executable_identity: li_core_interface::Sha256Digest,
    serving: RuntimeServingContract,
    launch: MacosRuntimeLaunchTemplate,
) -> Result<ResolvedPlacementLaunchPlan, PlacementError> {
    let runtime_environment = launch
        .command
        .environment()
        .iter()
        .map(|value| ShellFreeEnvironmentValue::runtime(value.name(), value.value()))
        .collect::<Result<Vec<_>, PlacementError>>()?;
    let mut protected_environment = launch.core_environment;
    protected_environment.extend([
        ShellFreeEnvironmentValue::protected("LETSINFER_ENGINE_PROTOCOL", "2")?,
        ShellFreeEnvironmentValue::protected(
            "LETSINFER_PLACEMENT_GROUP_ID",
            placement.placement_group_id().as_str(),
        )?,
        ShellFreeEnvironmentValue::protected(
            "LETSINFER_PLACEMENT_ID",
            placement.placement_id().as_str(),
        )?,
        ShellFreeEnvironmentValue::protected(
            "LETSINFER_NODE_ID",
            placement.assignment().node_id().as_str(),
        )?,
        ShellFreeEnvironmentValue::protected(
            "LETSINFER_TASK_ID",
            placement.assignment().task_id().as_str(),
        )?,
        ShellFreeEnvironmentValue::protected(
            "LETSINFER_PORT_BASE",
            &placement
                .assignment()
                .resources()
                .ports()
                .base()
                .to_string(),
        )?,
        ShellFreeEnvironmentValue::protected(
            "LETSINFER_PORT_COUNT",
            &placement
                .assignment()
                .resources()
                .ports()
                .count()
                .to_string(),
        )?,
        ShellFreeEnvironmentValue::protected(
            "LETSINFER_API_KEY_FILE",
            credentials
                .engine_credential_file()
                .to_str()
                .ok_or(PlacementError::ExecutionUnavailable)?,
        )?,
        ShellFreeEnvironmentValue::protected(
            "LETSINFER_TLS_CERT_FILE",
            credentials
                .tls_certificate_file()
                .to_str()
                .ok_or(PlacementError::ExecutionUnavailable)?,
        )?,
        ShellFreeEnvironmentValue::protected(
            "LETSINFER_TLS_KEY_FILE",
            credentials
                .tls_private_key_file()
                .to_str()
                .ok_or(PlacementError::ExecutionUnavailable)?,
        )?,
        ShellFreeEnvironmentValue::protected(
            "LETSINFER_CREDENTIAL_BUNDLE_SHA256",
            credentials.credential_bundle_sha256().as_str(),
        )?,
    ]);
    if let Some(served_model) = &serving.served_model {
        let listen_port = placement
            .assignment()
            .resources()
            .ports()
            .base()
            .to_string();
        let engine_port = if placement.assignment().endpoint_ownership() == EndpointOwnership::Owner
        {
            listen_port.clone()
        } else {
            "-1".to_string()
        };
        protected_environment.extend([
            ShellFreeEnvironmentValue::protected(
                "LETSINFER_LISTEN_HOST",
                serving.endpoint_host.as_str(),
            )?,
            ShellFreeEnvironmentValue::protected("LETSINFER_LISTEN_PORT", &listen_port)?,
            ShellFreeEnvironmentValue::protected("LETSINFER_ENGINE_PORT", &engine_port)?,
            ShellFreeEnvironmentValue::protected("LETSINFER_SERVED_MODEL", served_model.as_str())?,
        ]);
    }
    let command = ShellFreeCommand::new(
        launch.command.executable().to_path_buf(),
        launch.command.arguments().to_vec(),
        runtime_environment,
        protected_environment,
        launch.command.working_directory().to_path_buf(),
    )?;
    let plan = MacosLaunchAgentPlan::new(
        placement,
        command,
        executable_identity,
        placement_endpoint(placement, credentials, &serving)?,
        launch.readiness_attempts,
        launch.readiness_interval,
    )?;
    Ok(ResolvedPlacementLaunchPlan::Macos(match launch.log_root {
        Some(log_root) => plan.with_log_root(log_root)?,
        None => plan,
    }))
}

// Requires runtime identity and resource counts to match one exact placement.
fn validate_execution_binding(
    placement: &Placement,
    runtime_installation_id: &RuntimeInstallationId,
    task_id: &TaskId,
    port_count: u16,
    device_count: u16,
) -> Result<(), PlacementError> {
    if runtime_installation_id != placement.assignment().runtime_installation_id()
        || task_id != placement.assignment().task_id()
        || port_count != placement.assignment().resources().ports().count()
        || usize::from(device_count) != placement.assignment().resources().device_ids().len()
    {
        return Err(PlacementError::InvalidRequest {
            reason: "runtime execution contract differs from placement resources",
        });
    }
    Ok(())
}

// Returns the one endpoint exposed by an owner placement.
fn placement_endpoint(
    placement: &Placement,
    credentials: &PlacementCredentialReferences,
    serving: &RuntimeServingContract,
) -> Result<Option<PlacementEndpoint>, PlacementError> {
    if placement.assignment().endpoint_ownership() == EndpointOwnership::Participant {
        return Ok(None);
    }
    Ok(Some(
        PlacementEndpoint::new(
            placement.placement_id().clone(),
            placement.assignment().node_id().clone(),
            EndpointAddress::new(
                EndpointScheme::Https,
                serving.endpoint_host.clone(),
                placement.assignment().resources().ports().base(),
            )
            .map_err(|_| PlacementError::EndpointUnavailable)?,
            credentials.credential_id().clone(),
            Some(credentials.ca_credential_id().clone()),
            serving
                .token_count_path
                .as_deref()
                .map(|path| TokenCountContract::new(path, TokenCountProtocol::LetsInferV1))
                .transpose()
                .map_err(|_| PlacementError::EndpointUnavailable)?,
            serving.max_active_requests,
            serving.max_context_tokens,
            EndpointHealth::new(true, false, None, Vec::new())
                .map_err(|_| PlacementError::EndpointUnavailable)?,
        )
        .map_err(|_| PlacementError::EndpointUnavailable)?,
    ))
}

// Adds one exact host path mount without accepting a shell fragment.
fn add_mount(arguments: &mut Vec<String>, source: &Path, destination: &str, read_only: bool) {
    arguments.push("--volume".to_string());
    arguments.push(format!(
        "{}:{}{}",
        source.to_string_lossy(),
        destination,
        if read_only { ":ro" } else { "" }
    ));
}

// Returns protected container labels derived only from Core identities.
fn protected_labels(placement: &Placement) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("ai.letsinfer.managed".to_string(), "true".to_string()),
        (
            "ai.letsinfer.placement_group_id".to_string(),
            placement.placement_group_id().as_str().to_string(),
        ),
        (
            "ai.letsinfer.placement_id".to_string(),
            placement.placement_id().as_str().to_string(),
        ),
        (
            "ai.letsinfer.node_id".to_string(),
            placement.assignment().node_id().as_str().to_string(),
        ),
        (
            "ai.letsinfer.task_id".to_string(),
            placement.assignment().task_id().as_str().to_string(),
        ),
    ])
}

// Returns protected in-container environment derived only from placement identity.
fn protected_container_environment(
    placement: &Placement,
    serving: &RuntimeServingContract,
) -> Vec<(&'static str, String)> {
    let mut environment = vec![
        ("LETSINFER_ENGINE_PROTOCOL", "2".to_string()),
        (
            "LETSINFER_PLACEMENT_GROUP_ID",
            placement.placement_group_id().as_str().to_string(),
        ),
        (
            "LETSINFER_PLACEMENT_ID",
            placement.placement_id().as_str().to_string(),
        ),
        (
            "LETSINFER_NODE_ID",
            placement.assignment().node_id().as_str().to_string(),
        ),
        (
            "LETSINFER_TASK_ID",
            placement.assignment().task_id().as_str().to_string(),
        ),
        (
            "LETSINFER_PORT_BASE",
            placement
                .assignment()
                .resources()
                .ports()
                .base()
                .to_string(),
        ),
        (
            "LETSINFER_PORT_COUNT",
            placement
                .assignment()
                .resources()
                .ports()
                .count()
                .to_string(),
        ),
        (
            "LETSINFER_API_KEY_FILE",
            "/run/secrets/li_engine_credential".to_string(),
        ),
        (
            "LETSINFER_TLS_CERT_FILE",
            "/run/secrets/li_engine_tls_certificate.pem".to_string(),
        ),
        (
            "LETSINFER_TLS_KEY_FILE",
            "/run/secrets/li_engine_tls_private_key.pem".to_string(),
        ),
    ];
    if let Some(served_model) = &serving.served_model {
        environment.extend([
            (
                "LETSINFER_RUNTIME_CONFIG",
                "/opt/letsinfer/runtime-pack/runtime.json".to_string(),
            ),
            (
                "LETSINFER_RUNTIME_ROOT",
                "/opt/letsinfer/runtime-pack".to_string(),
            ),
            ("LETSINFER_MODEL_ROOT", "/models".to_string()),
            (
                "LETSINFER_CACHE_ROOT",
                "/root/.cache/letsinfer-prefix-store".to_string(),
            ),
            (
                "LETSINFER_LISTEN_HOST",
                serving.endpoint_host.as_str().to_string(),
            ),
            (
                "LETSINFER_LISTEN_PORT",
                placement
                    .assignment()
                    .resources()
                    .ports()
                    .base()
                    .to_string(),
            ),
            (
                "LETSINFER_ENGINE_PORT",
                if placement.assignment().endpoint_ownership() == EndpointOwnership::Owner {
                    placement
                        .assignment()
                        .resources()
                        .ports()
                        .base()
                        .to_string()
                } else {
                    "-1".to_string()
                },
            ),
            ("LETSINFER_SERVED_MODEL", served_model.as_str().to_string()),
        ]);
    }
    environment
}

// Requires one absolute shell-free runtime command.
fn validate_runtime_command(command: &[String]) -> Result<(), PlacementError> {
    let executable = command.first().map(Path::new);
    let forbidden = ["bash", "dash", "env", "fish", "ksh", "sh", "zsh"];
    if command.is_empty()
        || command.len() > 128
        || command.iter().map(String::len).sum::<usize>() > 16 * 1024
        || command.iter().any(|value| {
            value.is_empty() || value.len() > 4_096 || value.chars().any(char::is_control)
        })
        || executable.is_none_or(|value| !value.is_absolute())
        || executable
            .and_then(Path::file_name)
            .and_then(|value| value.to_str())
            .is_some_and(|value| forbidden.contains(&value))
    {
        return Err(PlacementError::InvalidRequest {
            reason: "runtime execution argv is invalid or unsafe",
        });
    }
    Ok(())
}

// Requires runtime-owned environment without protected or secret values.
fn validate_runtime_environment(
    environment: &[ShellFreeEnvironmentValue],
) -> Result<(), PlacementError> {
    if environment
        .iter()
        .any(|value| !value.is_runtime_owned() || value.validate_persistable().is_err())
    {
        return Err(PlacementError::InvalidRequest {
            reason: "runtime execution environment is protected or secret-bearing",
        });
    }
    Ok(())
}

// Requires three distinct absolute material roots.
fn validate_roots(runtime: &Path, model: &Path, cache: &Path) -> Result<(), PlacementError> {
    if !runtime.is_absolute()
        || !model.is_absolute()
        || !cache.is_absolute()
        || runtime == model
        || runtime == cache
        || model == cache
    {
        return Err(PlacementError::InvalidRequest {
            reason: "runtime execution material roots are invalid",
        });
    }
    Ok(())
}

// Rejects protected Docker lifecycle and identity options from runtime templates.
fn validate_linux_options(options: &[String]) -> Result<(), PlacementError> {
    let protected = [
        "--detach",
        "--name",
        "--restart",
        "--label",
        "--rm",
        "--entrypoint",
        "--volume",
        "-v",
        "--env",
        "-e",
        "--gpus",
        "--memory",
        "--memory-swap",
        "--network",
        "--ipc",
        "--user",
        "--device",
        "--cpuset-cpus",
        "--shm-size",
        "--tmpfs",
    ];
    if options.len() > 128
        || options.iter().map(String::len).sum::<usize>() > 16 * 1024
        || options.iter().any(|value| {
            value.is_empty()
                || value.len() > 4_096
                || value.chars().any(char::is_control)
                || protected.contains(&value.as_str())
                || protected
                    .iter()
                    .any(|option| value.starts_with(&format!("{option}=")))
        })
    {
        return Err(PlacementError::InvalidRequest {
            reason: "runtime Docker options contain protected or unbounded values",
        });
    }
    Ok(())
}
