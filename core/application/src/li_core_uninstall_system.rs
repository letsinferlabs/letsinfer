// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use li_core_cli::{
    CommandFailure, CommandProgressPort, NativeUninstallModelDisposition, NativeUninstallPort,
    NativeUninstallReceipt, NodePrivateClient, NodePrivateClientError,
    NodePrivateDocumentExchangePort, NodeRequestIdentitySource,
};
use li_core_interface::{ModelServiceId, NodeRole, OperationId, Sha256Digest, TechnicalName};
use li_core_update_manager::{CoreInstallation, CoreUpdateReleasePlatform};
#[cfg(test)]
use li_node_manager::NodeUninstallModelTarget;
use li_node_manager::{
    NodeConfiguration, NodeModelCommandIdentity, NodeModelRemovalRetention,
    NodeModelRemovalSelection, NodeModelRemoveRequest, NodePrivateRequest, NodePrivateResponse,
    NodeRuntimeModelRetention, NodeRuntimeRemovalDisposition, NodeUninstallBeginReceipt,
    NodeUninstallInventory, NodeUninstallRequest, NodeUninstallSessionDisposition,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    ApplicationCoreCliUninstall, CoreNativeServiceCommandOutput, CoreNativeServiceCommandRunner,
    CoreNativeServiceRetirementState, CoreNativeServiceSupervisor, CoreProcessPlatform,
    CoreResidentProcess, CoreUninstallBenchmarkPort, CoreUninstallBoundary,
    CoreUninstallBoundaryReceipt, CoreUninstallCoordinator, CoreUninstallError,
    CoreUninstallExposurePort, CoreUninstallImmutableCorePort, CoreUninstallModelDisposition,
    CoreUninstallMutationBarrierPort, CoreUninstallOwnedTarget, CoreUninstallOwnerDataPort,
    CoreUninstallPlan, CoreUninstallPreflight, CoreUninstallPreflightPort,
    CoreUninstallRuntimePort, CoreUninstallServicePort, CoreUninstallSession,
    CoreUninstallSessionError, CoreUninstallSessionPhase, CoreUninstallSessionRecoveryState,
    CoreUninstallSessionRetention, CoreUninstallTargetKind, CoreUninstallWorkloadPort,
    FilesystemCoreUninstallSessionOwner, SystemCoreNativeServiceCommandRunner,
    SystemCoreNativeServiceIo, SystemCoreNativeServiceSupervisor,
    SystemCoreUninstallSessionIdSource,
};

const NATIVE_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const MAXIMUM_NATIVE_OUTPUT_BYTES: usize = 1024 * 1024;
const BENCHMARK_POLL_INTERVAL: Duration = Duration::from_millis(100);
const MANAGED_CONTAINER_LABEL: &str = "ai.letsinfer.managed=true";

// Binds one Docker container to its canonical identity, immutable image, and managed label.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ManagedDockerContainerTarget {
    container_id: String,
    image_id: String,
}

impl ManagedDockerContainerTarget {
    // Creates one exact target from a Docker inspection record rather than a mutable reference.
    fn from_inspection(
        bytes: &[u8],
        failure: CoreUninstallError,
    ) -> Result<Self, CoreUninstallError> {
        let record = docker_inspection_record(bytes, failure)?;
        if record
            .pointer("/Config/Labels/ai.letsinfer.managed")
            .and_then(Value::as_str)
            != Some("true")
        {
            return Err(failure);
        }
        Ok(Self {
            container_id: canonical_container_id(
                record.get("Id").and_then(Value::as_str),
                failure,
            )?,
            image_id: canonical_image_id(record.get("Image").and_then(Value::as_str), failure)?,
        })
    }

    // Creates one target from the closed durable-plan representation.
    fn from_identity(identity: &str) -> Result<Self, CoreUninstallError> {
        let (container_id, remainder) = identity
            .strip_prefix("container:")
            .and_then(|value| value.split_once(":image:"))
            .ok_or(CoreUninstallError::InvalidPlan)?;
        let (image_id, label) = remainder
            .split_once(":label:")
            .ok_or(CoreUninstallError::InvalidPlan)?;
        if label != MANAGED_CONTAINER_LABEL {
            return Err(CoreUninstallError::InvalidPlan);
        }
        Ok(Self {
            container_id: canonical_container_id(
                Some(container_id),
                CoreUninstallError::InvalidPlan,
            )?,
            image_id: canonical_image_id(Some(image_id), CoreUninstallError::InvalidPlan)?,
        })
    }

    // Returns the exact non-secret transcript committed to the uninstall plan.
    fn identity(&self) -> String {
        format!(
            "container:{}:image:{}:label:{MANAGED_CONTAINER_LABEL}",
            self.container_id, self.image_id
        )
    }
}

// Records whether one exact Docker target was present at the cleanup observation boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ManagedDockerTargetPresence {
    Absent,
    Present,
}

// Couples the durable application session to Node's immutable uninstall inventory.
struct ActiveCoreUninstallSession {
    durable: CoreUninstallSession,
    node: Option<NodeUninstallBeginReceipt>,
}

// Validates and removes exact native files without granting policy to the coordinator.
pub trait CoreUninstallNativeRemovalPort: Send + Sync {
    // Validates one exact owner tree without following any symlink in its contents.
    fn validate_owner_tree(
        &self,
        path: &Path,
        owner_user_id: u32,
    ) -> Result<(), CoreUninstallError>;

    // Validates one exact launcher resolves to this immutable Core executable.
    fn validate_launcher(
        &self,
        launcher: &Path,
        executable: &Path,
        privilege_command: Option<&Path>,
        owner_user_id: u32,
    ) -> Result<(), CoreUninstallError>;

    // Removes one previously validated owner tree without following symlinks.
    fn remove_owner_tree(&self, path: &Path, owner_user_id: u32) -> Result<(), CoreUninstallError>;

    // Removes one previously validated launcher through its exact configured authority.
    fn remove_launcher(
        &self,
        launcher: &Path,
        privilege_command: Option<&Path>,
        owner_user_id: u32,
    ) -> Result<(), CoreUninstallError>;
}

// Applies no-follow owner validation and optional shell-free sudo launcher retirement.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemCoreUninstallNativeRemoval;

impl CoreUninstallNativeRemovalPort for SystemCoreUninstallNativeRemoval {
    // Traverses every entry and rejects ownership drift or any link before mutation.
    fn validate_owner_tree(
        &self,
        path: &Path,
        owner_user_id: u32,
    ) -> Result<(), CoreUninstallError> {
        validate_owner_tree(path, owner_user_id)
    }

    // Requires one exact symlink target and acquires configured privilege before teardown begins.
    fn validate_launcher(
        &self,
        launcher: &Path,
        executable: &Path,
        privilege_command: Option<&Path>,
        owner_user_id: u32,
    ) -> Result<(), CoreUninstallError> {
        let metadata =
            fs::symlink_metadata(launcher).map_err(|_| CoreUninstallError::PreflightRejected)?;
        if !metadata.file_type().is_symlink()
            || fs::canonicalize(launcher).ok().as_deref() != Some(executable)
        {
            return Err(CoreUninstallError::PreflightRejected);
        }
        if metadata.uid() == owner_user_id {
            if privilege_command.is_some() {
                return Err(CoreUninstallError::PreflightRejected);
            }
            return Ok(());
        }
        let privilege_command = privilege_command.ok_or(CoreUninstallError::PreflightRejected)?;
        validate_privilege_command(privilege_command)?;
        let status = Command::new(privilege_command)
            .arg("-v")
            .status()
            .map_err(|_| CoreUninstallError::PreflightRejected)?;
        if status.success() {
            Ok(())
        } else {
            Err(CoreUninstallError::PreflightRejected)
        }
    }

    // Removes one complete exact tree after repeating ownership validation at its mutation edge.
    fn remove_owner_tree(&self, path: &Path, owner_user_id: u32) -> Result<(), CoreUninstallError> {
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(CoreUninstallError::PreflightRejected),
            Ok(_) => {}
        }
        validate_owner_tree(path, owner_user_id)?;
        make_owner_tree_writable(path, owner_user_id)?;
        if path.is_dir() {
            fs::remove_dir_all(path).map_err(|_| CoreUninstallError::PreflightRejected)
        } else {
            fs::remove_file(path).map_err(|_| CoreUninstallError::PreflightRejected)
        }
    }

    // Retires one exact launcher directly or through the already-authorized sudo executable.
    fn remove_launcher(
        &self,
        launcher: &Path,
        privilege_command: Option<&Path>,
        owner_user_id: u32,
    ) -> Result<(), CoreUninstallError> {
        let metadata = match fs::symlink_metadata(launcher) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(CoreUninstallError::PreflightRejected),
        };
        if !metadata.file_type().is_symlink() {
            return Err(CoreUninstallError::PreflightRejected);
        }
        if metadata.uid() == owner_user_id {
            return fs::remove_file(launcher).map_err(|_| CoreUninstallError::PreflightRejected);
        }
        let privilege_command = privilege_command.ok_or(CoreUninstallError::PreflightRejected)?;
        validate_privilege_command(privilege_command)?;
        let remove_command = if cfg!(target_os = "macos") {
            "/bin/rm"
        } else {
            "/usr/bin/rm"
        };
        let status = Command::new(privilege_command)
            .args(["--", remove_command, "-f", "--"])
            .arg(launcher)
            .status()
            .map_err(|_| CoreUninstallError::PreflightRejected)?;
        if status.success() {
            Ok(())
        } else {
            Err(CoreUninstallError::PreflightRejected)
        }
    }
}

// Owns every production adapter used by one linear native uninstall coordinator.
struct SystemCoreUninstallPorts<Exchange, Identity>
where
    Exchange: NodePrivateDocumentExchangePort + Send,
    Identity: NodeRequestIdentitySource + Send,
{
    owner_user_id: u32,
    configuration: NodeConfiguration,
    installation: CoreInstallation,
    launcher_file: PathBuf,
    privilege_command: Option<PathBuf>,
    client: Mutex<NodePrivateClient<Exchange, Identity>>,
    uninstall_session_owner: FilesystemCoreUninstallSessionOwner,
    uninstall_session: Mutex<Option<ActiveCoreUninstallSession>>,
    services: Arc<dyn CoreNativeServiceSupervisor>,
    command_runner: Arc<dyn CoreNativeServiceCommandRunner>,
    removal: Arc<dyn CoreUninstallNativeRemovalPort>,
}

impl<Exchange, Identity> SystemCoreUninstallPorts<Exchange, Identity>
where
    Exchange: NodePrivateDocumentExchangePort + Send,
    Identity: NodeRequestIdentitySource + Send,
{
    // Sends one request through the dedicated uninstall client without exposing transport detail.
    fn request(
        &self,
        request: NodePrivateRequest,
    ) -> Result<NodePrivateResponse, CoreUninstallError> {
        self.client
            .lock()
            .map_err(|_| CoreUninstallError::OperationConflict)?
            .execute(request)
            .map_err(|_| CoreUninstallError::PreflightRejected)
    }

    // Sends one already-bound uninstall request while preserving stable lease conflicts.
    fn request_uninstall(
        &self,
        request: NodeUninstallRequest,
    ) -> Result<NodePrivateResponse, CoreUninstallError> {
        self.client
            .lock()
            .map_err(|_| CoreUninstallError::OperationConflict)?
            .execute(NodePrivateRequest::Uninstall(request))
            .map_err(uninstall_barrier_client_error)
    }

    // Returns the exact active lease and atomic inventory retained by the barrier adapter.
    fn uninstall_session(&self) -> Result<NodeUninstallBeginReceipt, CoreUninstallError> {
        self.uninstall_session
            .lock()
            .map_err(|_| CoreUninstallError::OperationConflict)?
            .as_ref()
            .and_then(|session| session.node.clone())
            .ok_or(CoreUninstallError::OperationConflict)
    }

    // Returns the exact platform resident set in safe retirement order.
    fn resident_processes(&self) -> &'static [CoreResidentProcess] {
        match self.configuration.core_update().release_platform() {
            CoreUpdateReleasePlatform::LinuxArm64 | CoreUpdateReleasePlatform::LinuxX86_64 => &[
                CoreResidentProcess::Gateway,
                CoreResidentProcess::Watchdog,
                CoreResidentProcess::Node,
            ],
            CoreUpdateReleasePlatform::MacosArm64 => {
                &[CoreResidentProcess::Gateway, CoreResidentProcess::Node]
            }
        }
    }

    // Returns the service-supervision family already selected by setup.
    fn process_platform(&self) -> CoreProcessPlatform {
        match self.configuration.core_update().release_platform() {
            CoreUpdateReleasePlatform::LinuxArm64 | CoreUpdateReleasePlatform::LinuxX86_64 => {
                CoreProcessPlatform::Linux
            }
            CoreUpdateReleasePlatform::MacosArm64 => CoreProcessPlatform::Macos,
        }
    }

    // Executes one bounded shell-free Docker command while retaining its exact status.
    fn docker_output(
        &self,
        arguments: &[String],
    ) -> Result<CoreNativeServiceCommandOutput, CoreUninstallError> {
        self.command_runner
            .run(
                self.configuration.model().docker_command(),
                arguments,
                NATIVE_COMMAND_TIMEOUT,
                MAXIMUM_NATIVE_OUTPUT_BYTES,
            )
            .map_err(|_| CoreUninstallError::PreflightRejected)
    }

    // Executes one successful bounded shell-free Docker command for preflight discovery.
    fn docker(&self, arguments: &[String]) -> Result<Vec<u8>, CoreUninstallError> {
        let output = self.docker_output(arguments)?;
        if output.status() != 0 {
            return Err(CoreUninstallError::PreflightRejected);
        }
        Ok(output.stdout().to_vec())
    }

    // Returns the exact immutable Core source selected by the installation identity.
    fn core_source(&self) -> PathBuf {
        self.configuration
            .core_update()
            .letsinfer_home()
            .join("core/versions")
            .join(self.installation.version().as_str())
            .join(self.installation.source_identity().as_str())
    }

    // Replays the exact lease when a recovered service transaction still observes Node active.
    fn reconcile_node_for_service_retirement(
        &self,
        plan: &CoreUninstallPlan,
    ) -> Result<(), CoreUninstallError> {
        let (session_id, retention, already_reconciled) = {
            let current = self
                .uninstall_session
                .lock()
                .map_err(|_| CoreUninstallError::OperationConflict)?;
            let session = current
                .as_ref()
                .ok_or(CoreUninstallError::OperationConflict)?;
            (
                session.durable.session_id().clone(),
                session.durable.retention(),
                session.node.is_some(),
            )
        };
        if already_reconciled {
            return Ok(());
        }
        let expected = planned_service_identity(plan, CoreResidentProcess::Node)?;
        let node = self
            .services
            .retirement_state(self.process_platform(), CoreResidentProcess::Node)
            .map_err(|_| {
                CoreUninstallError::BoundaryFailed(CoreUninstallBoundary::PlatformServices)
            })?;
        if !node_reconciliation_requires_replay(&node, &expected)? {
            return Ok(());
        }
        let model_retention = match retention {
            CoreUninstallSessionRetention::KeepModels => NodeRuntimeModelRetention::Preserve,
            CoreUninstallSessionRetention::RemoveModels => NodeRuntimeModelRetention::Remove,
        };
        let response = self.request_uninstall(NodeUninstallRequest::Begin {
            session_id: session_id.clone(),
            model_retention,
        })?;
        let NodePrivateResponse::UninstallBegan(receipt) = response else {
            return Err(CoreUninstallError::OperationConflict);
        };
        if receipt.session_id() != &session_id
            || receipt.model_retention() != model_retention
            || receipt.disposition() != NodeUninstallSessionDisposition::Replayed
        {
            return Err(CoreUninstallError::OperationConflict);
        }
        validate_uninstall_inventory_plan(receipt.inventory(), plan)?;
        let mut current = self
            .uninstall_session
            .lock()
            .map_err(|_| CoreUninstallError::OperationConflict)?;
        let session = current
            .as_mut()
            .filter(|session| session.durable.session_id() == &session_id)
            .ok_or(CoreUninstallError::OperationConflict)?;
        if session.node.is_some() {
            return Err(CoreUninstallError::OperationConflict);
        }
        session.node = Some(receipt);
        Ok(())
    }
}

impl<Exchange, Identity> CoreUninstallMutationBarrierPort
    for SystemCoreUninstallPorts<Exchange, Identity>
where
    Exchange: NodePrivateDocumentExchangePort + Send,
    Identity: NodeRequestIdentitySource + Send,
{
    // Acquires one retention-bound lease and retains its atomic inventory before preflight.
    fn begin(
        &self,
        model_disposition: CoreUninstallModelDisposition,
    ) -> Result<Sha256Digest, CoreUninstallError> {
        let model_retention = uninstall_runtime_model_retention(model_disposition);
        let mut current = self
            .uninstall_session
            .lock()
            .map_err(|_| CoreUninstallError::OperationConflict)?;
        if current.is_some() {
            return Err(CoreUninstallError::OperationConflict);
        }
        let durable = self
            .uninstall_session_owner
            .begin(uninstall_session_retention(model_disposition))
            .map_err(uninstall_session_error)?;
        let session_id = durable.session_id().clone();
        let recovery = durable.recovery_state().map_err(uninstall_session_error)?;
        if recovery.phase() >= CoreUninstallSessionPhase::ServicesRetiring {
            *current = Some(ActiveCoreUninstallSession {
                durable,
                node: None,
            });
            return Ok(session_id);
        }
        let response = self.request_uninstall(NodeUninstallRequest::Begin {
            session_id: session_id.clone(),
            model_retention,
        })?;
        let NodePrivateResponse::UninstallBegan(receipt) = response else {
            return Err(CoreUninstallError::PreflightRejected);
        };
        if receipt.session_id() != &session_id || receipt.model_retention() != model_retention {
            return Err(CoreUninstallError::PreflightRejected);
        }
        if let Some(plan) = recovery.plan() {
            if receipt.disposition() != NodeUninstallSessionDisposition::Replayed {
                return Err(CoreUninstallError::OperationConflict);
            }
            validate_uninstall_inventory_plan(receipt.inventory(), plan)?;
        }
        *current = Some(ActiveCoreUninstallSession {
            durable,
            node: Some(receipt),
        });
        Ok(session_id)
    }

    // Returns the exact durable recovery projection retained under the process lock.
    fn recovery_state(
        &self,
        session_id: &Sha256Digest,
    ) -> Result<CoreUninstallSessionRecoveryState, CoreUninstallError> {
        let current = self
            .uninstall_session
            .lock()
            .map_err(|_| CoreUninstallError::OperationConflict)?;
        let session = current
            .as_ref()
            .filter(|session| session.durable.session_id() == session_id)
            .ok_or(CoreUninstallError::OperationConflict)?;
        session
            .durable
            .recovery_state()
            .map_err(uninstall_session_error)
    }

    // Persists one exact plan before any external mutation begins.
    fn persist_plan(
        &self,
        session_id: &Sha256Digest,
        plan: &CoreUninstallPlan,
    ) -> Result<(), CoreUninstallError> {
        let mut current = self
            .uninstall_session
            .lock()
            .map_err(|_| CoreUninstallError::OperationConflict)?;
        let session = current
            .as_mut()
            .filter(|session| session.durable.session_id() == session_id)
            .ok_or(CoreUninstallError::OperationConflict)?;
        session
            .durable
            .persist_plan(plan)
            .map_err(uninstall_session_error)
    }

    // Appends one canonical receipt to the durable contiguous prefix.
    fn append_receipt(
        &self,
        session_id: &Sha256Digest,
        receipt: &CoreUninstallBoundaryReceipt,
    ) -> Result<(), CoreUninstallError> {
        let mut current = self
            .uninstall_session
            .lock()
            .map_err(|_| CoreUninstallError::OperationConflict)?;
        let session = current
            .as_mut()
            .filter(|session| session.durable.session_id() == session_id)
            .ok_or(CoreUninstallError::OperationConflict)?;
        session
            .durable
            .append_receipt(receipt)
            .map_err(uninstall_session_error)
    }

    // Advances one exact durable recovery phase without allowing a skipped transition.
    fn advance_phase(
        &self,
        session_id: &Sha256Digest,
        phase: CoreUninstallSessionPhase,
    ) -> Result<(), CoreUninstallError> {
        let mut current = self
            .uninstall_session
            .lock()
            .map_err(|_| CoreUninstallError::OperationConflict)?;
        let session = current
            .as_mut()
            .filter(|session| session.durable.session_id() == session_id)
            .ok_or(CoreUninstallError::OperationConflict)?;
        session
            .durable
            .advance_phase(phase)
            .map_err(uninstall_session_error)
    }

    // Releases only the matching retained lease when teardown stops before service retirement.
    fn cancel(&self, session_id: &Sha256Digest) -> Result<(), CoreUninstallError> {
        let mut current = self
            .uninstall_session
            .lock()
            .map_err(|_| CoreUninstallError::OperationConflict)?;
        let receipt = current
            .as_ref()
            .and_then(|session| session.node.as_ref())
            .filter(|receipt| receipt.session_id() == session_id)
            .ok_or(CoreUninstallError::OperationConflict)?;
        let response = self.request_uninstall(NodeUninstallRequest::Cancel {
            session_id: receipt.session_id().clone(),
        })?;
        let NodePrivateResponse::UninstallCanceled(canceled) = response else {
            return Err(CoreUninstallError::OperationConflict);
        };
        if canceled.session_id() != session_id {
            return Err(CoreUninstallError::OperationConflict);
        }
        let session = current
            .take()
            .ok_or(CoreUninstallError::OperationConflict)?;
        session
            .durable
            .retire_after_node_cancel()
            .map_err(uninstall_session_error)
    }
}

impl<Exchange, Identity> CoreUninstallPreflightPort for SystemCoreUninstallPorts<Exchange, Identity>
where
    Exchange: NodePrivateDocumentExchangePort + Send,
    Identity: NodeRequestIdentitySource + Send,
{
    // Inventories Node, database, Docker, services, data, launcher, and Core before mutation.
    fn preflight(
        &self,
        model_disposition: CoreUninstallModelDisposition,
    ) -> Result<CoreUninstallPreflight, CoreUninstallError> {
        let session = self.uninstall_session()?;
        if session.model_retention() != uninstall_runtime_model_retention(model_disposition) {
            return Err(CoreUninstallError::PreflightRejected);
        }
        let inventory = session.inventory();
        let mut targets = Vec::new();
        inventory_main_control_plane_targets(inventory, &mut targets)?;
        inventory_runtime_installation_targets(inventory, &mut targets)?;
        for process in self.resident_processes() {
            let service = self
                .services
                .retirement_state(self.process_platform(), *process)
                .map_err(|_| CoreUninstallError::PreflightRejected)?;
            targets.push(platform_service_target(*process, &service)?);
        }
        let docker_available = self.process_platform() != CoreProcessPlatform::Macos
            || self.configuration.model().docker_command() != Path::new("/usr/bin/false");
        let container_bytes = if docker_available {
            self.docker(&[
                "container".to_string(),
                "ls".to_string(),
                "--all".to_string(),
                "--quiet".to_string(),
                "--no-trunc".to_string(),
                "--filter".to_string(),
                format!("label={MANAGED_CONTAINER_LABEL}"),
            ])?
        } else {
            Vec::new()
        };
        let mut images = BTreeSet::new();
        for listed_container_id in bounded_lines(&container_bytes)? {
            let listed_container_id = canonical_container_id(
                Some(&listed_container_id),
                CoreUninstallError::PreflightRejected,
            )?;
            let inspection = self.docker(&[
                "container".to_string(),
                "inspect".to_string(),
                listed_container_id.clone(),
            ])?;
            let container = ManagedDockerContainerTarget::from_inspection(
                &inspection,
                CoreUninstallError::PreflightRejected,
            )?;
            if container.container_id != listed_container_id {
                return Err(CoreUninstallError::PreflightRejected);
            }
            images.insert(container.image_id.clone());
            targets.push(owned_target(
                CoreUninstallTargetKind::ManagedContainer,
                container.identity(),
            )?);
        }
        if docker_available {
            let image_bytes = self.docker(&[
                "image".to_string(),
                "ls".to_string(),
                "--quiet".to_string(),
                "--no-trunc".to_string(),
                "--filter".to_string(),
                format!("label={MANAGED_CONTAINER_LABEL}"),
            ])?;
            for listed_image_id in bounded_lines(&image_bytes)? {
                let listed_image_id = canonical_image_id(
                    Some(&listed_image_id),
                    CoreUninstallError::PreflightRejected,
                )?;
                let inspection = self.docker(&[
                    "image".to_string(),
                    "inspect".to_string(),
                    listed_image_id.clone(),
                ])?;
                let inspected_image_id = managed_image_id_from_inspection(
                    &inspection,
                    CoreUninstallError::PreflightRejected,
                )?;
                if inspected_image_id != listed_image_id {
                    return Err(CoreUninstallError::PreflightRejected);
                }
                images.insert(inspected_image_id);
            }
        }
        for image in images {
            targets.push(owned_target(
                CoreUninstallTargetKind::ManagedImage,
                format!("image:{image}"),
            )?);
        }
        let home = self.configuration.core_update().letsinfer_home();
        let configuration_owner_root =
            top_level_owner_root(home, self.configuration.core_update().configuration_root())?;
        validate_owner_entry(home, self.owner_user_id)?;
        for entry in fs::read_dir(home).map_err(|_| CoreUninstallError::PreflightRejected)? {
            let path = entry
                .map_err(|_| CoreUninstallError::PreflightRejected)?
                .path();
            if path.file_name().is_some_and(|name| name == "core") {
                continue;
            }
            let kind = if path == self.configuration.model().installation_root() {
                if model_disposition == CoreUninstallModelDisposition::KeepModels {
                    self.removal
                        .validate_owner_tree(&path, self.owner_user_id)?;
                    continue;
                }
                CoreUninstallTargetKind::ModelRoot
            } else if path == configuration_owner_root {
                CoreUninstallTargetKind::CoreConfiguration
            } else {
                CoreUninstallTargetKind::OwnerRoot
            };
            self.removal
                .validate_owner_tree(&path, self.owner_user_id)?;
            targets.push(owned_target(kind, format!("path:{}", path.display()))?);
        }
        let source = self.core_source();
        let current = home.join("core/current");
        let manifest: Value = fs::read(source.join("SOURCE-MANIFEST.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .ok_or(CoreUninstallError::PreflightRejected)?;
        if !fs::symlink_metadata(&current).is_ok_and(|metadata| metadata.file_type().is_symlink())
            || fs::canonicalize(&current).ok().as_deref() != Some(source.as_path())
            || manifest.get("product").and_then(Value::as_str) != Some("letsinfer")
        {
            return Err(CoreUninstallError::PreflightRejected);
        }
        validate_core_store(&home.join("core"), &current, self.owner_user_id)?;
        self.removal.validate_launcher(
            &self.launcher_file,
            &source.join("bin/li_letsinfer"),
            self.privilege_command.as_deref(),
            self.owner_user_id,
        )?;
        targets.push(owned_target(
            CoreUninstallTargetKind::CoreInstallation,
            format!("path:{}", home.join("core").display()),
        )?);
        targets.push(owned_target(
            CoreUninstallTargetKind::Launcher,
            format!("path:{}", self.launcher_file.display()),
        )?);
        let benchmark_wait = self
            .configuration
            .benchmark()
            .map_or(Duration::from_secs(30), |configuration| {
                configuration.stop_grace()
            });
        let ownership = digest_text(&format!(
            "{}:{}:{}",
            self.installation.version().as_str(),
            self.installation.source_identity().as_str(),
            self.owner_user_id
        ))?;
        CoreUninstallPlan::new(ownership, model_disposition, benchmark_wait, targets)
            .map(CoreUninstallPreflight::Ready)
    }
}

// Resolves the sole home child that must survive until terminal Core retirement.
fn top_level_owner_root(home: &Path, owned_path: &Path) -> Result<PathBuf, CoreUninstallError> {
    let relative = owned_path
        .strip_prefix(home)
        .map_err(|_| CoreUninstallError::PreflightRejected)?;
    let component = relative
        .components()
        .next()
        .filter(|component| matches!(component, std::path::Component::Normal(_)))
        .ok_or(CoreUninstallError::PreflightRejected)?;
    let root = home.join(component.as_os_str());
    if root == home.join("core") {
        return Err(CoreUninstallError::PreflightRejected);
    }
    Ok(root)
}

// Projects authority-owned targets from the atomic Node lease only on the local main.
fn inventory_main_control_plane_targets(
    inventory: &NodeUninstallInventory,
    targets: &mut Vec<CoreUninstallOwnedTarget>,
) -> Result<(), CoreUninstallError> {
    if inventory.local_role() == NodeRole::Child {
        return Ok(());
    }
    if let Some(benchmark) = inventory.active_benchmark_id() {
        targets.push(owned_target(
            CoreUninstallTargetKind::ActiveBenchmark,
            format!("benchmark:{}", benchmark.as_str()),
        )?);
    }
    if let Some(exposure) = inventory.exposure_configuration_sha256() {
        targets.push(owned_target(
            CoreUninstallTargetKind::PublicExposure,
            format!("exposure:{}", exposure.as_str()),
        )?);
    }
    for model in inventory.model_targets() {
        for group in model.placement_group_ids() {
            targets.push(owned_target(
                CoreUninstallTargetKind::PlacementGroup,
                format!("placement_group:{}", group.as_str()),
            )?);
        }
        targets.push(owned_target(
            CoreUninstallTargetKind::ModelService,
            format!("model_service:{}", model.service_id().as_str()),
        )?);
    }
    Ok(())
}

// Projects every exact RuntimeManager closure from the same atomic Node lease inventory.
fn inventory_runtime_installation_targets(
    inventory: &NodeUninstallInventory,
    targets: &mut Vec<CoreUninstallOwnedTarget>,
) -> Result<(), CoreUninstallError> {
    for installation_id in inventory.runtime_installation_ids() {
        targets.push(owned_target(
            CoreUninstallTargetKind::RuntimeInstallation,
            format!("runtime_installation:{}", installation_id.as_str()),
        )?);
    }
    Ok(())
}

// Requires a replayed Node lease to reproduce the stored plan's complete Node-owned subset.
fn validate_uninstall_inventory_plan(
    inventory: &NodeUninstallInventory,
    plan: &CoreUninstallPlan,
) -> Result<(), CoreUninstallError> {
    let mut observed = Vec::new();
    inventory_main_control_plane_targets(inventory, &mut observed)?;
    inventory_runtime_installation_targets(inventory, &mut observed)?;
    observed.sort_by(|left, right| {
        left.kind()
            .cmp(&right.kind())
            .then_with(|| left.identity().cmp(right.identity()))
    });
    let expected = plan
        .targets()
        .iter()
        .filter(|target| {
            matches!(
                target.kind(),
                CoreUninstallTargetKind::ActiveBenchmark
                    | CoreUninstallTargetKind::PublicExposure
                    | CoreUninstallTargetKind::PlacementGroup
                    | CoreUninstallTargetKind::ModelService
                    | CoreUninstallTargetKind::RuntimeInstallation
            )
        })
        .collect::<Vec<_>>();
    if observed.len() != expected.len()
        || observed
            .iter()
            .zip(expected)
            .any(|(observed, expected)| observed != expected)
    {
        return Err(CoreUninstallError::OperationConflict);
    }
    Ok(())
}

impl<Exchange, Identity> CoreUninstallBenchmarkPort for SystemCoreUninstallPorts<Exchange, Identity>
where
    Exchange: NodePrivateDocumentExchangePort + Send,
    Identity: NodeRequestIdentitySource + Send,
{
    // Requests one active benchmark stop and proves its terminal journal before the deadline.
    fn stop_and_wait(
        &self,
        plan: &CoreUninstallPlan,
    ) -> Result<CoreUninstallBoundaryReceipt, CoreUninstallError> {
        let target = target_identity(plan, CoreUninstallTargetKind::ActiveBenchmark, "benchmark:")?;
        let Some(job_id) = target else {
            return CoreUninstallBoundaryReceipt::completed(
                plan,
                CoreUninstallBoundary::BenchmarkExit,
            );
        };
        let job_id = OperationId::parse(&job_id).map_err(|_| CoreUninstallError::InvalidPlan)?;
        let session_id = self.uninstall_session()?.session_id().clone();
        let response = self.request(NodePrivateRequest::Uninstall(
            NodeUninstallRequest::StopBenchmark {
                session_id,
                job_id: job_id.clone(),
            },
        ))?;
        if !matches!(response, NodePrivateResponse::BenchmarkChanged(_)) {
            return Err(CoreUninstallError::BoundaryFailed(
                CoreUninstallBoundary::BenchmarkExit,
            ));
        }
        let deadline = Instant::now()
            .checked_add(plan.benchmark_stop_wait())
            .ok_or(CoreUninstallError::BoundaryFailed(
                CoreUninstallBoundary::BenchmarkExit,
            ))?;
        loop {
            let response = self.request(NodePrivateRequest::ReadBenchmark {
                job_id: job_id.clone(),
            })?;
            match response {
                NodePrivateResponse::BenchmarkRecord(Some(snapshot))
                    if snapshot.phase().is_terminal() =>
                {
                    break
                }
                NodePrivateResponse::BenchmarkRecord(Some(_)) if Instant::now() < deadline => {
                    std::thread::sleep(BENCHMARK_POLL_INTERVAL);
                }
                _ => {
                    return Err(CoreUninstallError::BoundaryFailed(
                        CoreUninstallBoundary::BenchmarkExit,
                    ))
                }
            }
        }
        CoreUninstallBoundaryReceipt::completed(plan, CoreUninstallBoundary::BenchmarkExit)
    }
}

impl<Exchange, Identity> CoreUninstallExposurePort for SystemCoreUninstallPorts<Exchange, Identity>
where
    Exchange: NodePrivateDocumentExchangePort + Send,
    Identity: NodeRequestIdentitySource + Send,
{
    // Disables only the public exposure proven by the preflight plan.
    fn disable(
        &self,
        plan: &CoreUninstallPlan,
    ) -> Result<CoreUninstallBoundaryReceipt, CoreUninstallError> {
        if plan.target_kind_count(CoreUninstallTargetKind::PublicExposure) != 0
            && !matches!(
                self.request(NodePrivateRequest::Uninstall(
                    NodeUninstallRequest::DisableExposure {
                        session_id: self.uninstall_session()?.session_id().clone(),
                    },
                ))?,
                NodePrivateResponse::Exposure(_)
            )
        {
            return Err(CoreUninstallError::BoundaryFailed(
                CoreUninstallBoundary::PublicExposure,
            ));
        }
        CoreUninstallBoundaryReceipt::completed(plan, CoreUninstallBoundary::PublicExposure)
    }
}

impl<Exchange, Identity> CoreUninstallWorkloadPort for SystemCoreUninstallPorts<Exchange, Identity>
where
    Exchange: NodePrivateDocumentExchangePort + Send,
    Identity: NodeRequestIdentitySource + Send,
{
    // Removes every exact model service, allowing ModelCoordinator to own placement shutdown.
    fn shutdown(
        &self,
        plan: &CoreUninstallPlan,
    ) -> Result<CoreUninstallBoundaryReceipt, CoreUninstallError> {
        for identity in target_identities(
            plan,
            CoreUninstallTargetKind::ModelService,
            "model_service:",
        )? {
            let service_id =
                ModelServiceId::parse(&identity).map_err(|_| CoreUninstallError::InvalidPlan)?;
            let request = uninstall_model_remove_request(plan, service_id)?;
            if !matches!(
                self.request(NodePrivateRequest::Uninstall(
                    NodeUninstallRequest::RemoveModel {
                        session_id: self.uninstall_session()?.session_id().clone(),
                        request,
                    }
                ))?,
                NodePrivateResponse::ModelChanged(_)
            ) {
                return Err(CoreUninstallError::BoundaryFailed(
                    CoreUninstallBoundary::Workloads,
                ));
            }
        }
        CoreUninstallBoundaryReceipt::completed(plan, CoreUninstallBoundary::Workloads)
    }
}

// Binds model-service removal to the preflight plan's exact runtime-retention policy.
fn uninstall_model_remove_request(
    plan: &CoreUninstallPlan,
    service_id: ModelServiceId,
) -> Result<NodeModelRemoveRequest, CoreUninstallError> {
    let command = model_remove_identity(&service_id)?;
    let runtime_retention = match plan.model_disposition() {
        CoreUninstallModelDisposition::KeepModels => NodeModelRemovalRetention::PreserveModels,
        CoreUninstallModelDisposition::RemoveModels => {
            NodeModelRemovalRetention::RemoveUnreferencedRuntimes
        }
    };
    Ok(NodeModelRemoveRequest::new(
        command,
        service_id,
        NodeModelRemovalSelection::All,
        runtime_retention,
    ))
}

impl<Exchange, Identity> CoreUninstallServicePort for SystemCoreUninstallPorts<Exchange, Identity>
where
    Exchange: NodePrivateDocumentExchangePort + Send,
    Identity: NodeRequestIdentitySource + Send,
{
    // Retires Gateway, Watchdog where present, and Node last through the existing supervisor.
    fn retire(
        &self,
        plan: &CoreUninstallPlan,
    ) -> Result<CoreUninstallBoundaryReceipt, CoreUninstallError> {
        self.reconcile_node_for_service_retirement(plan)?;
        for process in self.resident_processes() {
            let identity = planned_service_identity(plan, *process)?;
            self.services
                .retire(self.process_platform(), *process, &identity)
                .map_err(|_| {
                    CoreUninstallError::BoundaryFailed(CoreUninstallBoundary::PlatformServices)
                })?;
        }
        CoreUninstallBoundaryReceipt::completed(plan, CoreUninstallBoundary::PlatformServices)
    }
}

impl<Exchange, Identity> CoreUninstallRuntimePort for SystemCoreUninstallPorts<Exchange, Identity>
where
    Exchange: NodePrivateDocumentExchangePort + Send,
    Identity: NodeRequestIdentitySource + Send,
{
    // Removes targeted runtime closures, then exact managed containers and referenced images.
    fn clean(
        &self,
        plan: &CoreUninstallPlan,
    ) -> Result<CoreUninstallBoundaryReceipt, CoreUninstallError> {
        let session_id = self.uninstall_session()?.session_id().clone();
        remove_runtime_installations(plan, &session_id, |request| self.request(request))?;
        finalize_runtime_artifacts(plan, &session_id, |request| self.request_uninstall(request))?;
        clean_managed_docker_targets(plan, |arguments| self.docker_output(arguments))?;
        CoreUninstallBoundaryReceipt::completed(plan, CoreUninstallBoundary::RuntimeArtifacts)
    }
}

// Removes every removal-plan runtime through the local Node owner before service retirement.
fn remove_runtime_installations<Request>(
    plan: &CoreUninstallPlan,
    session_id: &Sha256Digest,
    mut request: Request,
) -> Result<(), CoreUninstallError>
where
    Request: FnMut(NodePrivateRequest) -> Result<NodePrivateResponse, CoreUninstallError>,
{
    for identity in target_identities(
        plan,
        CoreUninstallTargetKind::RuntimeInstallation,
        "runtime_installation:",
    )? {
        let installation_id = li_core_interface::RuntimeInstallationId::parse(&identity)
            .map_err(|_| CoreUninstallError::InvalidPlan)?;
        let model_retention = uninstall_runtime_model_retention(plan.model_disposition());
        if !matches!(
            request(NodePrivateRequest::Uninstall(
                NodeUninstallRequest::RemoveRuntimeInstallation {
                    session_id: session_id.clone(),
                    installation_id,
                    model_retention,
                },
            ))?,
            NodePrivateResponse::RuntimeInstallationRemoved(
                NodeRuntimeRemovalDisposition::Applied | NodeRuntimeRemovalDisposition::Replayed
            )
        ) {
            return Err(CoreUninstallError::BoundaryFailed(
                CoreUninstallBoundary::RuntimeArtifacts,
            ));
        }
    }
    Ok(())
}

// Closes the RuntimeManager root only after every snapshotted installation is terminal.
fn finalize_runtime_artifacts<Request>(
    plan: &CoreUninstallPlan,
    session_id: &Sha256Digest,
    mut request: Request,
) -> Result<(), CoreUninstallError>
where
    Request: FnMut(NodeUninstallRequest) -> Result<NodePrivateResponse, CoreUninstallError>,
{
    let model_retention = uninstall_runtime_model_retention(plan.model_disposition());
    if !matches!(
        request(NodeUninstallRequest::FinalizeRuntimeArtifacts {
            session_id: session_id.clone(),
            model_retention,
        })?,
        NodePrivateResponse::RuntimeArtifactsFinalized(receipt)
            if receipt.model_retention() == model_retention
    ) {
        return Err(CoreUninstallError::BoundaryFailed(
            CoreUninstallBoundary::RuntimeArtifacts,
        ));
    }
    Ok(())
}

// Removes only Docker targets whose complete cleanup-edge identity still matches preflight.
fn clean_managed_docker_targets<Docker>(
    plan: &CoreUninstallPlan,
    mut docker: Docker,
) -> Result<(), CoreUninstallError>
where
    Docker: FnMut(&[String]) -> Result<CoreNativeServiceCommandOutput, CoreUninstallError>,
{
    let (containers, images) = managed_docker_plan_targets(plan)?;
    let mut container_presence = Vec::with_capacity(containers.len());
    for container in &containers {
        container_presence.push(observe_managed_container(container, &mut docker)?);
    }
    let mut image_presence = Vec::with_capacity(images.len());
    for image in &images {
        image_presence.push(observe_managed_image(image, &mut docker)?);
    }
    for (container, presence) in containers.iter().zip(container_presence) {
        if presence == ManagedDockerTargetPresence::Present {
            let removal = docker(&[
                "container".to_string(),
                "rm".to_string(),
                "--force".to_string(),
                container.container_id.clone(),
            ])
            .map_err(|_| runtime_artifact_failure())?;
            if removal.status() != 0
                && observe_managed_container(container, &mut docker)?
                    != ManagedDockerTargetPresence::Absent
            {
                return Err(runtime_artifact_failure());
            }
        }
        if observe_managed_container(container, &mut docker)? != ManagedDockerTargetPresence::Absent
        {
            return Err(runtime_artifact_failure());
        }
    }
    for (image, presence) in images.iter().zip(image_presence) {
        if presence == ManagedDockerTargetPresence::Present {
            let removal = docker(&["image".to_string(), "rm".to_string(), image.clone()])
                .map_err(|_| runtime_artifact_failure())?;
            if removal.status() != 0
                && observe_managed_image(image, &mut docker)? != ManagedDockerTargetPresence::Absent
            {
                return Err(runtime_artifact_failure());
            }
        }
        if observe_managed_image(image, &mut docker)? != ManagedDockerTargetPresence::Absent {
            return Err(runtime_artifact_failure());
        }
    }
    Ok(())
}

// Parses the closed Docker subset and requires every container image to be explicitly targeted.
fn managed_docker_plan_targets(
    plan: &CoreUninstallPlan,
) -> Result<(Vec<ManagedDockerContainerTarget>, Vec<String>), CoreUninstallError> {
    let containers = plan
        .targets()
        .iter()
        .filter(|target| target.kind() == CoreUninstallTargetKind::ManagedContainer)
        .map(|target| ManagedDockerContainerTarget::from_identity(target.identity()))
        .collect::<Result<Vec<_>, _>>()?;
    let images = target_identities(plan, CoreUninstallTargetKind::ManagedImage, "image:")?
        .into_iter()
        .map(|image| canonical_image_id(Some(&image), CoreUninstallError::InvalidPlan))
        .collect::<Result<Vec<_>, _>>()?;
    if containers
        .iter()
        .any(|container| !images.contains(&container.image_id))
    {
        return Err(CoreUninstallError::InvalidPlan);
    }
    Ok((containers, images))
}

// Observes one canonical container and rejects identity, immutable-image, or label drift.
fn observe_managed_container<Docker>(
    expected: &ManagedDockerContainerTarget,
    docker: &mut Docker,
) -> Result<ManagedDockerTargetPresence, CoreUninstallError>
where
    Docker: FnMut(&[String]) -> Result<CoreNativeServiceCommandOutput, CoreUninstallError>,
{
    let inspection = docker(&[
        "container".to_string(),
        "inspect".to_string(),
        expected.container_id.clone(),
    ])
    .map_err(|_| runtime_artifact_failure())?;
    if inspection.status() == 0 {
        let observed = ManagedDockerContainerTarget::from_inspection(
            inspection.stdout(),
            runtime_artifact_failure(),
        )?;
        return if &observed == expected {
            Ok(ManagedDockerTargetPresence::Present)
        } else {
            Err(runtime_artifact_failure())
        };
    }
    let listing = docker(&[
        "container".to_string(),
        "ls".to_string(),
        "--all".to_string(),
        "--quiet".to_string(),
        "--no-trunc".to_string(),
        "--filter".to_string(),
        format!("id={}", expected.container_id),
    ])
    .map_err(|_| runtime_artifact_failure())?;
    if listing.status() != 0 {
        return Err(runtime_artifact_failure());
    }
    let identities = bounded_lines(listing.stdout()).map_err(|_| runtime_artifact_failure())?;
    if identities.is_empty() {
        Ok(ManagedDockerTargetPresence::Absent)
    } else {
        Err(runtime_artifact_failure())
    }
}

// Observes one immutable image ID and treats only proved exact absence as replay success.
fn observe_managed_image<Docker>(
    expected: &str,
    docker: &mut Docker,
) -> Result<ManagedDockerTargetPresence, CoreUninstallError>
where
    Docker: FnMut(&[String]) -> Result<CoreNativeServiceCommandOutput, CoreUninstallError>,
{
    let inspection = docker(&[
        "image".to_string(),
        "inspect".to_string(),
        expected.to_string(),
    ])
    .map_err(|_| runtime_artifact_failure())?;
    if inspection.status() == 0 {
        let observed = image_id_from_inspection(inspection.stdout(), runtime_artifact_failure())?;
        return if observed == expected {
            Ok(ManagedDockerTargetPresence::Present)
        } else {
            Err(runtime_artifact_failure())
        };
    }
    let listing = docker(&[
        "image".to_string(),
        "ls".to_string(),
        "--quiet".to_string(),
        "--no-trunc".to_string(),
        expected.to_string(),
    ])
    .map_err(|_| runtime_artifact_failure())?;
    if listing.status() != 0 {
        return Err(runtime_artifact_failure());
    }
    let identities = bounded_lines(listing.stdout()).map_err(|_| runtime_artifact_failure())?;
    if identities.is_empty() {
        Ok(ManagedDockerTargetPresence::Absent)
    } else {
        Err(runtime_artifact_failure())
    }
}

// Returns the stable runtime-artifact boundary failure used for every Docker uncertainty.
const fn runtime_artifact_failure() -> CoreUninstallError {
    CoreUninstallError::BoundaryFailed(CoreUninstallBoundary::RuntimeArtifacts)
}

// Maps one uninstall policy to the exact RuntimeManager cleanup policy bound by the Node lease.
const fn uninstall_runtime_model_retention(
    model_disposition: CoreUninstallModelDisposition,
) -> NodeRuntimeModelRetention {
    match model_disposition {
        CoreUninstallModelDisposition::KeepModels => NodeRuntimeModelRetention::Preserve,
        CoreUninstallModelDisposition::RemoveModels => NodeRuntimeModelRetention::Remove,
    }
}

// Maps one user policy to the application journal value persisted before Node admission.
const fn uninstall_session_retention(
    model_disposition: CoreUninstallModelDisposition,
) -> CoreUninstallSessionRetention {
    match model_disposition {
        CoreUninstallModelDisposition::KeepModels => CoreUninstallSessionRetention::KeepModels,
        CoreUninstallModelDisposition::RemoveModels => CoreUninstallSessionRetention::RemoveModels,
    }
}

impl<Exchange, Identity> CoreUninstallOwnerDataPort for SystemCoreUninstallPorts<Exchange, Identity>
where
    Exchange: NodePrivateDocumentExchangePort + Send,
    Identity: NodeRequestIdentitySource + Send,
{
    // Removes every preflight-bound owner path while leaving Core and requested model bytes intact.
    fn clean(
        &self,
        plan: &CoreUninstallPlan,
    ) -> Result<CoreUninstallBoundaryReceipt, CoreUninstallError> {
        remove_owner_data_targets(plan, self.owner_user_id, self.removal.as_ref())?;
        CoreUninstallBoundaryReceipt::completed(plan, CoreUninstallBoundary::OwnerData)
    }
}

// Removes only owner-data paths explicitly authorized by the model-aware preflight plan.
fn remove_owner_data_targets(
    plan: &CoreUninstallPlan,
    owner_user_id: u32,
    removal: &dyn CoreUninstallNativeRemovalPort,
) -> Result<(), CoreUninstallError> {
    for kind in [
        CoreUninstallTargetKind::OwnerRoot,
        CoreUninstallTargetKind::ModelRoot,
    ] {
        for path in target_identities(plan, kind, "path:")? {
            removal
                .remove_owner_tree(Path::new(&path), owner_user_id)
                .map_err(|_| {
                    CoreUninstallError::BoundaryFailed(CoreUninstallBoundary::OwnerData)
                })?;
        }
    }
    Ok(())
}

impl<Exchange, Identity> CoreUninstallImmutableCorePort
    for SystemCoreUninstallPorts<Exchange, Identity>
where
    Exchange: NodePrivateDocumentExchangePort + Send,
    Identity: NodeRequestIdentitySource + Send,
{
    // Removes the exact launcher first and immutable Core store last without daemon self-removal.
    fn retire(
        &self,
        plan: &CoreUninstallPlan,
    ) -> Result<CoreUninstallBoundaryReceipt, CoreUninstallError> {
        let core = self
            .configuration
            .core_update()
            .letsinfer_home()
            .join("core");
        let executable = self.core_source().join("bin/li_letsinfer");
        retire_immutable_core_targets(
            plan,
            &self.launcher_file,
            &core.join("current"),
            &core,
            &executable,
            self.privilege_command.as_deref(),
            self.owner_user_id,
            self.removal.as_ref(),
        )?;
        CoreUninstallBoundaryReceipt::completed(plan, CoreUninstallBoundary::ImmutableCore)
    }
}

// Retires the public launcher, active link, configuration, then self-hosting Core root in order.
#[allow(clippy::too_many_arguments)]
fn retire_immutable_core_targets(
    plan: &CoreUninstallPlan,
    launcher: &Path,
    current: &Path,
    core: &Path,
    executable: &Path,
    privilege_command: Option<&Path>,
    owner_user_id: u32,
    removal: &dyn CoreUninstallNativeRemovalPort,
) -> Result<(), CoreUninstallError> {
    let failed = || CoreUninstallError::BoundaryFailed(CoreUninstallBoundary::ImmutableCore);
    let configuration_paths =
        target_identities(plan, CoreUninstallTargetKind::CoreConfiguration, "path:")?;
    if path_exists(launcher).map_err(|_| failed())? {
        removal
            .validate_launcher(launcher, executable, privilege_command, owner_user_id)
            .map_err(|_| failed())?;
    }
    let current_exists = path_exists(current).map_err(|_| failed())?;
    let core_exists = path_exists(core).map_err(|_| failed())?;
    if current_exists
        && (!core_exists || fs::canonicalize(current).ok().as_deref() != Some(executable))
    {
        return Err(failed());
    }
    if core_exists {
        validate_core_store(core, current, owner_user_id).map_err(|_| failed())?;
    }
    for path in &configuration_paths {
        let path = Path::new(path);
        if path_exists(path).map_err(|_| failed())? {
            removal
                .validate_owner_tree(path, owner_user_id)
                .map_err(|_| failed())?;
        }
    }
    removal
        .remove_launcher(launcher, privilege_command, owner_user_id)
        .map_err(|_| failed())?;
    removal
        .remove_launcher(current, None, owner_user_id)
        .map_err(|_| failed())?;
    for path in configuration_paths {
        removal
            .remove_owner_tree(Path::new(&path), owner_user_id)
            .map_err(|_| failed())?;
    }
    removal
        .remove_owner_tree(core, owner_user_id)
        .map_err(|_| failed())
}

// Observes exact path absence without following a symbolic-link leaf.
fn path_exists(path: &Path) -> Result<bool, CoreUninstallError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(CoreUninstallError::PreflightRejected),
    }
}

// Composes every production uninstall port from already-validated setup authorities.
#[allow(clippy::too_many_arguments)]
pub fn compose_system_core_cli_uninstall<Exchange, Identity>(
    owner_user_id: u32,
    configuration: NodeConfiguration,
    installation: CoreInstallation,
    launcher_file: PathBuf,
    privilege_command: Option<PathBuf>,
    client: NodePrivateClient<Exchange, Identity>,
    removal: Arc<dyn CoreUninstallNativeRemovalPort>,
) -> Result<ApplicationCoreCliUninstall, CoreUninstallError>
where
    Exchange: NodePrivateDocumentExchangePort + Send + 'static,
    Identity: NodeRequestIdentitySource + Send + 'static,
{
    let platform = match configuration.core_update().release_platform() {
        CoreUpdateReleasePlatform::LinuxArm64 | CoreUpdateReleasePlatform::LinuxX86_64 => {
            CoreProcessPlatform::Linux
        }
        CoreUpdateReleasePlatform::MacosArm64 => CoreProcessPlatform::Macos,
    };
    let command_runner: Arc<dyn CoreNativeServiceCommandRunner> =
        Arc::new(SystemCoreNativeServiceCommandRunner);
    let services: Arc<dyn CoreNativeServiceSupervisor> = Arc::new(
        SystemCoreNativeServiceSupervisor::new(
            platform,
            configuration.core_update().home_directory().to_path_buf(),
            owner_user_id,
            configuration
                .core_update()
                .supervisor_command()
                .to_path_buf(),
            command_runner.clone(),
            Arc::new(SystemCoreNativeServiceIo),
        )
        .map_err(|_| CoreUninstallError::PreflightRejected)?,
    );
    let uninstall_session_owner = FilesystemCoreUninstallSessionOwner::new(
        configuration
            .core_update()
            .letsinfer_home()
            .join("core/.uninstall"),
        owner_user_id,
        Arc::new(SystemCoreUninstallSessionIdSource),
    )
    .map_err(uninstall_session_error)?;
    let ports = Arc::new(SystemCoreUninstallPorts {
        owner_user_id,
        configuration,
        installation,
        launcher_file,
        privilege_command,
        client: Mutex::new(client),
        uninstall_session_owner,
        uninstall_session: Mutex::new(None),
        services,
        command_runner,
        removal,
    });
    let coordinator = Arc::new(CoreUninstallCoordinator::new(
        ports.clone(),
        ports.clone(),
        ports.clone(),
        ports.clone(),
        ports.clone(),
        ports.clone(),
        ports.clone(),
        ports.clone(),
        ports,
    ));
    Ok(ApplicationCoreCliUninstall::new(coordinator))
}

// Returns one canonical target proof without trusting a mutable native diagnostic.
fn owned_target(
    kind: CoreUninstallTargetKind,
    identity: String,
) -> Result<CoreUninstallOwnedTarget, CoreUninstallError> {
    let proof = digest_text(&format!("li_core_uninstall_owned_v1:{kind:?}:{identity}"))?;
    CoreUninstallOwnedTarget::new(kind, identity, proof)
}

// Returns one SHA-256 identity from a bounded source-owned transcript.
fn digest_text(value: &str) -> Result<Sha256Digest, CoreUninstallError> {
    let digest = Sha256::digest(value.as_bytes());
    Sha256Digest::parse(&format!("{digest:x}")).map_err(|_| CoreUninstallError::InvalidPlan)
}

// Returns every exact plan identity of one kind after removing its closed prefix.
fn target_identities(
    plan: &CoreUninstallPlan,
    kind: CoreUninstallTargetKind,
    prefix: &str,
) -> Result<Vec<String>, CoreUninstallError> {
    plan.targets()
        .iter()
        .filter(|target| target.kind() == kind)
        .map(|target| {
            target
                .identity()
                .strip_prefix(prefix)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .ok_or(CoreUninstallError::InvalidPlan)
        })
        .collect()
}

// Returns zero or one exact target identity for a singleton boundary.
fn target_identity(
    plan: &CoreUninstallPlan,
    kind: CoreUninstallTargetKind,
    prefix: &str,
) -> Result<Option<String>, CoreUninstallError> {
    let identities = target_identities(plan, kind, prefix)?;
    if identities.len() > 1 {
        return Err(CoreUninstallError::InvalidPlan);
    }
    Ok(identities.into_iter().next())
}

// Binds one exact active resident definition digest into the immutable preflight plan.
fn platform_service_target(
    process: CoreResidentProcess,
    state: &CoreNativeServiceRetirementState,
) -> Result<CoreUninstallOwnedTarget, CoreUninstallError> {
    let identity = state
        .definition_identity()
        .cloned()
        .filter(|identity| state.is_active_identity(identity))
        .ok_or(CoreUninstallError::PreflightRejected)?;
    owned_target(
        CoreUninstallTargetKind::PlatformService,
        format!(
            "service:{}:{}",
            process.executable_name(),
            identity.as_str()
        ),
    )
}

// Returns the sole preflight-bound definition digest for one fixed resident service.
fn planned_service_identity(
    plan: &CoreUninstallPlan,
    process: CoreResidentProcess,
) -> Result<Sha256Digest, CoreUninstallError> {
    let prefix = format!("service:{}:", process.executable_name());
    let identities = target_identities(plan, CoreUninstallTargetKind::PlatformService, &prefix)?;
    if identities.len() != 1 {
        return Err(CoreUninstallError::InvalidPlan);
    }
    Sha256Digest::parse(&identities[0]).map_err(|_| CoreUninstallError::InvalidPlan)
}

// Decides whether an exact Node state still permits replay through its live private API.
fn node_reconciliation_requires_replay(
    state: &CoreNativeServiceRetirementState,
    expected: &Sha256Digest,
) -> Result<bool, CoreUninstallError> {
    if state.is_active_identity(expected) {
        return Ok(true);
    }
    if state.is_retirement_replay(expected) {
        return Ok(false);
    }
    Err(CoreUninstallError::BoundaryFailed(
        CoreUninstallBoundary::PlatformServices,
    ))
}

// Returns the sole object from one closed Docker inspection response.
fn docker_inspection_record(
    bytes: &[u8],
    failure: CoreUninstallError,
) -> Result<Value, CoreUninstallError> {
    let document: Value = serde_json::from_slice(bytes).map_err(|_| failure)?;
    let mut records = document.as_array().cloned().ok_or(failure)?;
    if records.len() != 1 {
        return Err(failure);
    }
    records.pop().ok_or(failure)
}

// Returns one canonical full Docker container ID without accepting a name or abbreviation.
fn canonical_container_id(
    value: Option<&str>,
    failure: CoreUninstallError,
) -> Result<String, CoreUninstallError> {
    canonical_sha256_text(value.ok_or(failure)?, failure)
}

// Returns one canonical immutable Docker image ID with its required algorithm prefix.
fn canonical_image_id(
    value: Option<&str>,
    failure: CoreUninstallError,
) -> Result<String, CoreUninstallError> {
    let value = value.ok_or(failure)?;
    let digest = value.strip_prefix("sha256:").ok_or(failure)?;
    Ok(format!(
        "sha256:{}",
        canonical_sha256_text(digest, failure)?
    ))
}

// Requires the lowercase 64-hex representation shared by Docker and Core SHA-256 identities.
fn canonical_sha256_text(
    value: &str,
    failure: CoreUninstallError,
) -> Result<String, CoreUninstallError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(failure);
    }
    Ok(value.to_string())
}

// Returns the immutable image identity from one Docker image inspection record.
fn image_id_from_inspection(
    bytes: &[u8],
    failure: CoreUninstallError,
) -> Result<String, CoreUninstallError> {
    let record = docker_inspection_record(bytes, failure)?;
    canonical_image_id(record.get("Id").and_then(Value::as_str), failure)
}

// Returns one immutable image only when its managed label remains present at preflight.
fn managed_image_id_from_inspection(
    bytes: &[u8],
    failure: CoreUninstallError,
) -> Result<String, CoreUninstallError> {
    let record = docker_inspection_record(bytes, failure)?;
    if record
        .pointer("/Config/Labels/ai.letsinfer.managed")
        .and_then(Value::as_str)
        != Some("true")
    {
        return Err(failure);
    }
    canonical_image_id(record.get("Id").and_then(Value::as_str), failure)
}

// Produces one deterministic ModelCoordinator replay identity for complete service removal.
fn model_remove_identity(
    service_id: &ModelServiceId,
) -> Result<NodeModelCommandIdentity, CoreUninstallError> {
    let digest = digest_text(&format!(
        "li_core_uninstall_model_remove_v1:{}",
        service_id.as_str()
    ))?;
    let operation =
        OperationId::parse(&digest.as_str()[..32]).map_err(|_| CoreUninstallError::InvalidPlan)?;
    let idempotency = TechnicalName::parse(&format!("uninstall_{}", &digest.as_str()[..32]))
        .map_err(|_| CoreUninstallError::InvalidPlan)?;
    Ok(NodeModelCommandIdentity::new(operation, idempotency))
}

// Parses bounded UTF-8 native output into nonempty whitespace-free identities.
fn bounded_lines(bytes: &[u8]) -> Result<Vec<String>, CoreUninstallError> {
    let text = std::str::from_utf8(bytes).map_err(|_| CoreUninstallError::PreflightRejected)?;
    text.lines()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            if value.len() > 1024 || value.chars().any(char::is_whitespace) {
                Err(CoreUninstallError::PreflightRejected)
            } else {
                Ok(value.to_string())
            }
        })
        .collect()
}

// Recursively validates one existing owner tree without following any symlink entry.
fn validate_owner_tree(path: &Path, owner_user_id: u32) -> Result<(), CoreUninstallError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| CoreUninstallError::PreflightRejected)?;
    if metadata.file_type().is_symlink() || metadata.uid() != owner_user_id {
        return Err(CoreUninstallError::PreflightRejected);
    }
    if metadata.is_dir() {
        for entry in fs::read_dir(path).map_err(|_| CoreUninstallError::PreflightRejected)? {
            validate_owner_tree(
                &entry
                    .map_err(|_| CoreUninstallError::PreflightRejected)?
                    .path(),
                owner_user_id,
            )?;
        }
    }
    Ok(())
}

// Validates one owner entry without traversing children or accepting a link.
fn validate_owner_entry(path: &Path, owner_user_id: u32) -> Result<(), CoreUninstallError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| CoreUninstallError::PreflightRejected)?;
    if metadata.file_type().is_symlink() || metadata.uid() != owner_user_id {
        Err(CoreUninstallError::PreflightRejected)
    } else {
        Ok(())
    }
}

// Validates the immutable Core store while allowing only its exact active-version link.
fn validate_core_store(
    store: &Path,
    current: &Path,
    owner_user_id: u32,
) -> Result<(), CoreUninstallError> {
    validate_owner_entry(store, owner_user_id)?;
    for entry in fs::read_dir(store).map_err(|_| CoreUninstallError::PreflightRejected)? {
        let path = entry
            .map_err(|_| CoreUninstallError::PreflightRejected)?
            .path();
        if path == current {
            let metadata =
                fs::symlink_metadata(&path).map_err(|_| CoreUninstallError::PreflightRejected)?;
            if !metadata.file_type().is_symlink() || metadata.uid() != owner_user_id {
                return Err(CoreUninstallError::PreflightRejected);
            }
        } else {
            validate_owner_tree(&path, owner_user_id)?;
        }
    }
    Ok(())
}

// Makes only previously validated owner entries removable without following links.
fn make_owner_tree_writable(path: &Path, owner_user_id: u32) -> Result<(), CoreUninstallError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| CoreUninstallError::PreflightRejected)?;
    if metadata.file_type().is_symlink() || metadata.uid() != owner_user_id {
        return Err(CoreUninstallError::PreflightRejected);
    }
    if metadata.is_dir() {
        fs::set_permissions(path, fs::Permissions::from_mode(metadata.mode() | 0o700))
            .map_err(|_| CoreUninstallError::PreflightRejected)?;
        for entry in fs::read_dir(path).map_err(|_| CoreUninstallError::PreflightRejected)? {
            make_owner_tree_writable(
                &entry
                    .map_err(|_| CoreUninstallError::PreflightRejected)?
                    .path(),
                owner_user_id,
            )?;
        }
    }
    Ok(())
}

// Requires the configured privilege boundary to be the exact non-writable sudo executable.
fn validate_privilege_command(path: &Path) -> Result<(), CoreUninstallError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| CoreUninstallError::PreflightRejected)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || path.file_name().and_then(|value| value.to_str()) != Some("sudo")
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
    {
        return Err(CoreUninstallError::PreflightRejected);
    }
    Ok(())
}

// Lazily composes the complete system graph only when the uninstall command is dispatched.
pub struct LazySystemCoreCliUninstall<Factory> {
    factory: Factory,
    composed: Mutex<Option<Arc<dyn NativeUninstallPort>>>,
}

impl<Factory> LazySystemCoreCliUninstall<Factory> {
    // Creates one deferred composition without opening database or native state for other commands.
    pub const fn new(factory: Factory) -> Self {
        Self {
            factory,
            composed: Mutex::new(None),
        }
    }
}

impl<Factory> NativeUninstallPort for LazySystemCoreCliUninstall<Factory>
where
    Factory: Fn() -> Result<Arc<dyn NativeUninstallPort>, CommandFailure> + Send + Sync,
{
    // Composes once on first dispatch and preserves the same replay owner for this process.
    fn uninstall(
        &self,
        disposition: NativeUninstallModelDisposition,
        progress: &mut dyn CommandProgressPort,
    ) -> Result<NativeUninstallReceipt, CommandFailure> {
        let uninstall = {
            let mut composed = self.composed.lock().map_err(|_| {
                CommandFailure::new(
                    li_core_cli::CommandFailureKind::Failed,
                    "uninstall.operation_conflict",
                    "Another uninstall request owns this process.",
                )
                .expect("static uninstall lock failure")
            })?;
            if composed.is_none() {
                *composed = Some((self.factory)()?);
            }
            Arc::clone(
                composed
                    .as_ref()
                    .expect("uninstall composition initialized"),
            )
        };
        uninstall.uninstall(disposition, progress)
    }
}

// Preserves only stable uninstall admission conflicts without copying transport diagnostics.
fn uninstall_barrier_client_error(error: NodePrivateClientError) -> CoreUninstallError {
    match error {
        NodePrivateClientError::RemoteRejected { code }
            if matches!(
                code.as_str(),
                "uninstall_busy"
                    | "uninstall_in_progress"
                    | "uninstall_session_conflict"
                    | "uninstall_barrier_unavailable"
            ) =>
        {
            CoreUninstallError::OperationConflict
        }
        _ => CoreUninstallError::PreflightRejected,
    }
}

// Preserves only concurrency as a caller-visible conflict and closes persistence diagnostics.
const fn uninstall_session_error(error: CoreUninstallSessionError) -> CoreUninstallError {
    match error {
        CoreUninstallSessionError::OperationConflict => CoreUninstallError::OperationConflict,
        CoreUninstallSessionError::IdentityUnavailable
        | CoreUninstallSessionError::InvalidStateRoot
        | CoreUninstallSessionError::InvalidJournal
        | CoreUninstallSessionError::PersistenceUnavailable => {
            CoreUninstallError::PreflightRejected
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;
    use std::sync::{Arc, Mutex};

    use crate::{CoreUninstallConfirmation, CoreUninstallRequest};

    use super::*;

    // Supplies one complete uninstall graph while retaining its Node and service boundary order.
    struct UninstallOrderPorts {
        plan: CoreUninstallPlan,
        events: Mutex<Vec<String>>,
        runtime_removal_fails: bool,
        runtime_finalization_fails: bool,
    }

    // Models only the exact Docker identities and mutations exercised by uninstall cleanup.
    struct DockerCleanupFixture {
        expected: ManagedDockerContainerTarget,
        observed: ManagedDockerContainerTarget,
        container_present: bool,
        image_present: bool,
        removals: Vec<Vec<String>>,
    }

    impl DockerCleanupFixture {
        // Executes one closed Docker command against deterministic in-memory target state.
        fn run(
            &mut self,
            arguments: &[String],
        ) -> Result<CoreNativeServiceCommandOutput, CoreUninstallError> {
            let arguments = arguments.iter().map(String::as_str).collect::<Vec<_>>();
            if arguments.len() == 3
                && arguments[0..2] == ["container", "inspect"]
                && arguments[2] == self.expected.container_id
            {
                return Ok(if self.container_present {
                    CoreNativeServiceCommandOutput::new(
                        0,
                        docker_container_inspection(
                            &self.observed,
                            "registry.example/runtime:mutable",
                        ),
                    )
                } else {
                    CoreNativeServiceCommandOutput::new(1, Vec::new())
                });
            }
            if arguments.len() == 7
                && arguments[0..6]
                    == [
                        "container",
                        "ls",
                        "--all",
                        "--quiet",
                        "--no-trunc",
                        "--filter",
                    ]
                && arguments[6] == format!("id={}", self.expected.container_id)
            {
                let output = if self.container_present {
                    format!("{}\n", self.observed.container_id).into_bytes()
                } else {
                    Vec::new()
                };
                return Ok(CoreNativeServiceCommandOutput::new(0, output));
            }
            if arguments.len() == 4
                && arguments[0..3] == ["container", "rm", "--force"]
                && arguments[3] == self.expected.container_id
            {
                self.removals
                    .push(arguments.iter().map(|value| (*value).to_string()).collect());
                self.container_present = false;
                return Ok(CoreNativeServiceCommandOutput::new(0, Vec::new()));
            }
            if arguments.len() == 3
                && arguments[0..2] == ["image", "inspect"]
                && arguments[2] == self.expected.image_id
            {
                return Ok(if self.image_present {
                    CoreNativeServiceCommandOutput::new(
                        0,
                        docker_image_inspection(&self.expected.image_id),
                    )
                } else {
                    CoreNativeServiceCommandOutput::new(1, Vec::new())
                });
            }
            if arguments.len() == 5
                && arguments[0..4] == ["image", "ls", "--quiet", "--no-trunc"]
                && arguments[4] == self.expected.image_id
            {
                let output = if self.image_present {
                    format!("{}\n", self.expected.image_id).into_bytes()
                } else {
                    Vec::new()
                };
                return Ok(CoreNativeServiceCommandOutput::new(0, output));
            }
            if arguments.len() == 3
                && arguments[0..2] == ["image", "rm"]
                && arguments[2] == self.expected.image_id
            {
                self.removals
                    .push(arguments.iter().map(|value| (*value).to_string()).collect());
                self.image_present = false;
                return Ok(CoreNativeServiceCommandOutput::new(0, Vec::new()));
            }
            panic!("unexpected Docker command: {arguments:?}");
        }
    }

    // Serializes one Docker container record with both immutable and deliberately mutable image fields.
    fn docker_container_inspection(
        target: &ManagedDockerContainerTarget,
        mutable_image: &str,
    ) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!([{
            "Id": target.container_id,
            "Image": target.image_id,
            "Config": {
                "Image": mutable_image,
                "Labels": {"ai.letsinfer.managed": "true"}
            }
        }]))
        .expect("container inspection")
    }

    // Serializes one Docker image record carrying the managed label used only by preflight.
    fn docker_image_inspection(image_id: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!([{
            "Id": image_id,
            "Config": {"Labels": {"ai.letsinfer.managed": "true"}}
        }]))
        .expect("image inspection")
    }

    // Creates one exact Docker-only uninstall plan from a verified inspection transcript.
    fn docker_cleanup_plan(target: &ManagedDockerContainerTarget) -> CoreUninstallPlan {
        CoreUninstallPlan::new(
            Sha256Digest::parse(&"f".repeat(64)).expect("ownership"),
            CoreUninstallModelDisposition::KeepModels,
            Duration::from_secs(30),
            vec![
                owned_target(CoreUninstallTargetKind::ManagedContainer, target.identity())
                    .expect("container target"),
                owned_target(
                    CoreUninstallTargetKind::ManagedImage,
                    format!("image:{}", target.image_id),
                )
                .expect("image target"),
            ],
        )
        .expect("Docker cleanup plan")
    }

    // Records exact immutable-boundary validation and removal calls without mutating fixture paths.
    #[derive(Default)]
    struct ImmutableCoreRemovalMock {
        removals: Mutex<Vec<PathBuf>>,
    }

    impl CoreUninstallNativeRemovalPort for ImmutableCoreRemovalMock {
        // Accepts one owner tree so the test remains focused on boundary ordering.
        fn validate_owner_tree(
            &self,
            _path: &Path,
            _owner_user_id: u32,
        ) -> Result<(), CoreUninstallError> {
            Ok(())
        }

        // Accepts one launcher so the test remains focused on boundary ordering.
        fn validate_launcher(
            &self,
            _launcher: &Path,
            _executable: &Path,
            _privilege_command: Option<&Path>,
            _owner_user_id: u32,
        ) -> Result<(), CoreUninstallError> {
            Ok(())
        }

        // Records one owner-tree removal at its exact requested path.
        fn remove_owner_tree(
            &self,
            path: &Path,
            _owner_user_id: u32,
        ) -> Result<(), CoreUninstallError> {
            self.removals
                .lock()
                .expect("immutable removals")
                .push(path.to_path_buf());
            Ok(())
        }

        // Records one launcher removal at its exact requested path.
        fn remove_launcher(
            &self,
            launcher: &Path,
            _privilege_command: Option<&Path>,
            _owner_user_id: u32,
        ) -> Result<(), CoreUninstallError> {
            self.removals
                .lock()
                .expect("immutable removals")
                .push(launcher.to_path_buf());
            Ok(())
        }
    }

    // Creates one minimal immutable-boundary plan for an exact configuration path.
    fn immutable_core_plan(configuration: &Path) -> CoreUninstallPlan {
        CoreUninstallPlan::new(
            Sha256Digest::parse(&"f".repeat(64)).expect("ownership"),
            CoreUninstallModelDisposition::KeepModels,
            Duration::from_secs(30),
            vec![owned_target(
                CoreUninstallTargetKind::CoreConfiguration,
                format!("path:{}", configuration.display()),
            )
            .expect("configuration target")],
        )
        .expect("uninstall plan")
    }

    // Creates one physical immutable Core closure and returns its mutation-boundary paths.
    fn immutable_core_fixture(
        root: &Path,
    ) -> (
        CoreUninstallPlan,
        PathBuf,
        PathBuf,
        PathBuf,
        PathBuf,
        PathBuf,
    ) {
        let core = root.join("core");
        let executable = core.join("versions/0.11.0/bin/li_letsinfer");
        let current = core.join("current");
        let configuration = root.join("configuration");
        let launcher = root.join("bin/letsinfer");
        fs::create_dir_all(executable.parent().expect("executable parent"))
            .expect("Core executable parent");
        fs::create_dir_all(core.join(".uninstall")).expect("uninstall journal root");
        fs::create_dir_all(&configuration).expect("configuration root");
        fs::create_dir_all(launcher.parent().expect("launcher parent")).expect("launcher parent");
        fs::write(&executable, b"immutable Core executable").expect("Core executable");
        let canonical_executable = fs::canonicalize(&executable).expect("canonical executable");
        fs::write(
            core.join(".uninstall/li_core_uninstall_session_v1.json"),
            b"durable recovery",
        )
        .expect("uninstall journal");
        fs::write(configuration.join("li_core_cli.json"), b"configuration").expect("configuration");
        symlink(&executable, &current).expect("current link");
        symlink(&executable, &launcher).expect("launcher link");
        (
            immutable_core_plan(&configuration),
            launcher,
            current,
            configuration,
            core,
            canonical_executable,
        )
    }

    impl UninstallOrderPorts {
        // Completes one ordinary boundary against the exact fixture plan.
        fn completed(
            &self,
            plan: &CoreUninstallPlan,
            boundary: CoreUninstallBoundary,
        ) -> Result<CoreUninstallBoundaryReceipt, CoreUninstallError> {
            CoreUninstallBoundaryReceipt::completed(plan, boundary)
        }
    }

    impl CoreUninstallPreflightPort for UninstallOrderPorts {
        // Returns the already-verified fixture plan without performing another inventory.
        fn preflight(
            &self,
            _model_disposition: CoreUninstallModelDisposition,
        ) -> Result<CoreUninstallPreflight, CoreUninstallError> {
            Ok(CoreUninstallPreflight::Ready(self.plan.clone()))
        }
    }

    impl CoreUninstallMutationBarrierPort for UninstallOrderPorts {
        // Supplies one deterministic Node exclusion identity for coordinator-order coverage.
        fn begin(
            &self,
            _model_disposition: CoreUninstallModelDisposition,
        ) -> Result<Sha256Digest, CoreUninstallError> {
            Sha256Digest::parse(&"e".repeat(64)).map_err(|_| CoreUninstallError::OperationConflict)
        }

        // Returns one deterministic fresh durable state for the production-order fixture.
        fn recovery_state(
            &self,
            session_id: &Sha256Digest,
        ) -> Result<CoreUninstallSessionRecoveryState, CoreUninstallError> {
            let retention = match self.plan.model_disposition() {
                CoreUninstallModelDisposition::KeepModels => {
                    CoreUninstallSessionRetention::KeepModels
                }
                CoreUninstallModelDisposition::RemoveModels => {
                    CoreUninstallSessionRetention::RemoveModels
                }
            };
            Ok(CoreUninstallSessionRecoveryState::admitting(
                session_id.clone(),
                retention,
            ))
        }

        // Accepts one fixture plan checkpoint without adding a second event vocabulary.
        fn persist_plan(
            &self,
            _session_id: &Sha256Digest,
            _plan: &CoreUninstallPlan,
        ) -> Result<(), CoreUninstallError> {
            Ok(())
        }

        // Accepts one fixture receipt checkpoint while boundary events remain authoritative.
        fn append_receipt(
            &self,
            _session_id: &Sha256Digest,
            _receipt: &CoreUninstallBoundaryReceipt,
        ) -> Result<(), CoreUninstallError> {
            Ok(())
        }

        // Accepts one fixture phase checkpoint while preserving production boundary order.
        fn advance_phase(
            &self,
            _session_id: &Sha256Digest,
            _phase: CoreUninstallSessionPhase,
        ) -> Result<(), CoreUninstallError> {
            Ok(())
        }

        // Releases the exact deterministic session before any failed service retirement.
        fn cancel(&self, session_id: &Sha256Digest) -> Result<(), CoreUninstallError> {
            if session_id.as_str() != "e".repeat(64) {
                return Err(CoreUninstallError::OperationConflict);
            }
            Ok(())
        }
    }

    impl CoreUninstallBenchmarkPort for UninstallOrderPorts {
        // Completes the empty benchmark boundary.
        fn stop_and_wait(
            &self,
            plan: &CoreUninstallPlan,
        ) -> Result<CoreUninstallBoundaryReceipt, CoreUninstallError> {
            self.completed(plan, CoreUninstallBoundary::BenchmarkExit)
        }
    }

    impl CoreUninstallExposurePort for UninstallOrderPorts {
        // Completes the empty exposure boundary.
        fn disable(
            &self,
            plan: &CoreUninstallPlan,
        ) -> Result<CoreUninstallBoundaryReceipt, CoreUninstallError> {
            self.completed(plan, CoreUninstallBoundary::PublicExposure)
        }
    }

    impl CoreUninstallWorkloadPort for UninstallOrderPorts {
        // Completes the empty workload boundary.
        fn shutdown(
            &self,
            plan: &CoreUninstallPlan,
        ) -> Result<CoreUninstallBoundaryReceipt, CoreUninstallError> {
            self.completed(plan, CoreUninstallBoundary::Workloads)
        }
    }

    impl CoreUninstallRuntimePort for UninstallOrderPorts {
        // Uses the production Node request adapter and records its exact request before completion.
        fn clean(
            &self,
            plan: &CoreUninstallPlan,
        ) -> Result<CoreUninstallBoundaryReceipt, CoreUninstallError> {
            let session_id = Sha256Digest::parse(&"e".repeat(64)).expect("session");
            remove_runtime_installations(plan, &session_id, |request| {
                let NodePrivateRequest::Uninstall(
                    NodeUninstallRequest::RemoveRuntimeInstallation {
                        session_id: request_session_id,
                        installation_id,
                        model_retention: _,
                    },
                ) = request
                else {
                    return Err(CoreUninstallError::BoundaryFailed(
                        CoreUninstallBoundary::RuntimeArtifacts,
                    ));
                };
                if request_session_id != session_id {
                    return Err(CoreUninstallError::BoundaryFailed(
                        CoreUninstallBoundary::RuntimeArtifacts,
                    ));
                }
                self.events
                    .lock()
                    .expect("uninstall order")
                    .push(format!("node_remove:{}", installation_id.as_str()));
                if self.runtime_removal_fails {
                    return Err(CoreUninstallError::BoundaryFailed(
                        CoreUninstallBoundary::RuntimeArtifacts,
                    ));
                }
                Ok(NodePrivateResponse::RuntimeInstallationRemoved(
                    NodeRuntimeRemovalDisposition::Applied,
                ))
            })?;
            finalize_runtime_artifacts(plan, &session_id, |request| {
                let NodeUninstallRequest::FinalizeRuntimeArtifacts {
                    session_id: request_session_id,
                    model_retention,
                } = request
                else {
                    return Err(CoreUninstallError::BoundaryFailed(
                        CoreUninstallBoundary::RuntimeArtifacts,
                    ));
                };
                if request_session_id != session_id {
                    return Err(CoreUninstallError::BoundaryFailed(
                        CoreUninstallBoundary::RuntimeArtifacts,
                    ));
                }
                self.events
                    .lock()
                    .expect("uninstall order")
                    .push("node_finalize:remove".to_string());
                if self.runtime_finalization_fails {
                    return Err(CoreUninstallError::BoundaryFailed(
                        CoreUninstallBoundary::RuntimeArtifacts,
                    ));
                }
                Ok(NodePrivateResponse::RuntimeArtifactsFinalized(
                    li_node_manager::NodeRuntimeArtifactsFinalizationReceipt::new(model_retention),
                ))
            })?;
            self.completed(plan, CoreUninstallBoundary::RuntimeArtifacts)
        }
    }

    impl CoreUninstallServicePort for UninstallOrderPorts {
        // Records service retirement so its order is bound to the production runtime request.
        fn retire(
            &self,
            plan: &CoreUninstallPlan,
        ) -> Result<CoreUninstallBoundaryReceipt, CoreUninstallError> {
            self.events
                .lock()
                .expect("uninstall order")
                .push("service_retire".to_string());
            self.completed(plan, CoreUninstallBoundary::PlatformServices)
        }
    }

    impl CoreUninstallOwnerDataPort for UninstallOrderPorts {
        // Completes the empty owner-data boundary.
        fn clean(
            &self,
            plan: &CoreUninstallPlan,
        ) -> Result<CoreUninstallBoundaryReceipt, CoreUninstallError> {
            self.completed(plan, CoreUninstallBoundary::OwnerData)
        }
    }

    impl CoreUninstallImmutableCorePort for UninstallOrderPorts {
        // Completes the empty immutable-Core boundary.
        fn retire(
            &self,
            plan: &CoreUninstallPlan,
        ) -> Result<CoreUninstallBoundaryReceipt, CoreUninstallError> {
            self.completed(plan, CoreUninstallBoundary::ImmutableCore)
        }
    }

    // Proves child uninstall never invokes or inventories main-only control-plane ownership.
    #[test]
    fn child_uninstall_inventory_skips_every_main_control_plane_request() {
        let inventory =
            NodeUninstallInventory::new(NodeRole::Child, None, None, Vec::new(), Vec::new())
                .expect("child inventory");
        let mut targets = Vec::new();

        inventory_main_control_plane_targets(&inventory, &mut targets).expect("child inventory");

        assert!(targets.is_empty());
    }

    // Proves main uninstall projects exact control-plane targets from one atomic Node inventory.
    #[test]
    fn main_uninstall_inventory_uses_only_the_barrier_snapshot() {
        let inventory = NodeUninstallInventory::new(
            NodeRole::Main,
            None,
            Some(Sha256Digest::parse(&"a".repeat(64)).expect("exposure identity")),
            Vec::new(),
            Vec::new(),
        )
        .expect("main inventory");
        let mut targets = Vec::new();

        inventory_main_control_plane_targets(&inventory, &mut targets).expect("main inventory");

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].kind(), CoreUninstallTargetKind::PublicExposure);
        assert_eq!(
            targets[0].identity(),
            format!("exposure:{}", "a".repeat(64))
        );
    }

    // Proves runtime targets come only from the barrier's exact RuntimeManager snapshot.
    #[test]
    fn runtime_inventory_uses_only_the_barrier_snapshot() {
        let installation_ids = vec![
            li_core_interface::RuntimeInstallationId::parse(&"1".repeat(32))
                .expect("first installation"),
            li_core_interface::RuntimeInstallationId::parse(&"2".repeat(32))
                .expect("second installation"),
        ];
        let inventory =
            NodeUninstallInventory::new(NodeRole::Child, None, None, Vec::new(), installation_ids)
                .expect("runtime inventory");
        let mut targets = Vec::new();
        inventory_runtime_installation_targets(&inventory, &mut targets)
            .expect("runtime inventory");
        assert_eq!(
            targets
                .iter()
                .map(CoreUninstallOwnedTarget::identity)
                .collect::<Vec<_>>(),
            [
                format!("runtime_installation:{}", "1".repeat(32)),
                format!("runtime_installation:{}", "2".repeat(32)),
            ]
        );
    }

    // Proves service plans bind exact digests and Node replay accepts only reachable projections.
    #[test]
    fn platform_service_identity_and_node_reconciliation_are_closed() {
        let expected = Sha256Digest::parse(&"a".repeat(64)).expect("expected definition");
        let foreign = Sha256Digest::parse(&"b".repeat(64)).expect("foreign definition");
        let active = CoreNativeServiceRetirementState::new(Some(expected.clone()), true, true)
            .expect("active state");
        let plan = CoreUninstallPlan::new(
            Sha256Digest::parse(&"f".repeat(64)).expect("ownership"),
            CoreUninstallModelDisposition::KeepModels,
            Duration::from_secs(30),
            vec![platform_service_target(CoreResidentProcess::Node, &active)
                .expect("service target")],
        )
        .expect("plan");
        assert_eq!(
            planned_service_identity(&plan, CoreResidentProcess::Node),
            Ok(expected.clone())
        );

        for (definition, loaded, active, replay_required) in [
            (Some(expected.clone()), true, true, true),
            (Some(expected.clone()), true, false, false),
            (Some(expected.clone()), false, false, false),
            (None, false, false, false),
        ] {
            let state = CoreNativeServiceRetirementState::new(definition, loaded, active)
                .expect("reachable state");
            assert_eq!(
                node_reconciliation_requires_replay(&state, &expected),
                Ok(replay_required)
            );
        }
        let replacement = CoreNativeServiceRetirementState::new(Some(foreign), true, true)
            .expect("replacement state");
        assert_eq!(
            node_reconciliation_requires_replay(&replacement, &expected),
            Err(CoreUninstallError::BoundaryFailed(
                CoreUninstallBoundary::PlatformServices
            ))
        );
        assert!(CoreNativeServiceRetirementState::new(None, true, false).is_err());
    }

    // Requires replay validation to match every compact Node-owned plan target exactly.
    #[test]
    fn compact_inventory_replay_requires_exact_plan_target_equality() {
        let benchmark_id = OperationId::parse(&"1".repeat(32)).expect("benchmark");
        let exposure_id = Sha256Digest::parse(&"2".repeat(64)).expect("exposure");
        let service_id = ModelServiceId::parse(&"3".repeat(32)).expect("service");
        let first_group =
            li_core_interface::PlacementGroupId::parse(&"4".repeat(32)).expect("first group");
        let second_group =
            li_core_interface::PlacementGroupId::parse(&"5".repeat(32)).expect("second group");
        let runtime_id =
            li_core_interface::RuntimeInstallationId::parse(&"6".repeat(32)).expect("runtime");
        let inventory = NodeUninstallInventory::new(
            NodeRole::Main,
            Some(benchmark_id.clone()),
            Some(exposure_id.clone()),
            vec![NodeUninstallModelTarget::new(
                service_id.clone(),
                vec![first_group.clone(), second_group.clone()],
            )],
            vec![runtime_id.clone()],
        )
        .expect("inventory");
        let plan = CoreUninstallPlan::new(
            Sha256Digest::parse(&"f".repeat(64)).expect("ownership"),
            CoreUninstallModelDisposition::KeepModels,
            Duration::from_secs(30),
            vec![
                owned_target(
                    CoreUninstallTargetKind::ActiveBenchmark,
                    format!("benchmark:{}", benchmark_id.as_str()),
                )
                .expect("benchmark target"),
                owned_target(
                    CoreUninstallTargetKind::PublicExposure,
                    format!("exposure:{}", exposure_id.as_str()),
                )
                .expect("exposure target"),
                owned_target(
                    CoreUninstallTargetKind::ModelService,
                    format!("model_service:{}", service_id.as_str()),
                )
                .expect("model target"),
                owned_target(
                    CoreUninstallTargetKind::PlacementGroup,
                    format!("placement_group:{}", first_group.as_str()),
                )
                .expect("first group target"),
                owned_target(
                    CoreUninstallTargetKind::PlacementGroup,
                    format!("placement_group:{}", second_group.as_str()),
                )
                .expect("second group target"),
                owned_target(
                    CoreUninstallTargetKind::RuntimeInstallation,
                    format!("runtime_installation:{}", runtime_id.as_str()),
                )
                .expect("runtime target"),
                owned_target(
                    CoreUninstallTargetKind::PlatformService,
                    "service:li_node".to_string(),
                )
                .expect("non-Node target"),
            ],
        )
        .expect("plan");
        validate_uninstall_inventory_plan(&inventory, &plan).expect("exact inventory");

        let drifted = NodeUninstallInventory::new(
            NodeRole::Main,
            Some(benchmark_id),
            Some(exposure_id),
            vec![NodeUninstallModelTarget::new(service_id, vec![first_group])],
            vec![runtime_id],
        )
        .expect("drifted inventory");
        assert_eq!(
            validate_uninstall_inventory_plan(&drifted, &plan),
            Err(CoreUninstallError::OperationConflict)
        );
    }

    // Proves workload removal carries the same keep-versus-remove decision into NodeManager.
    #[test]
    fn workload_request_binds_runtime_retention_to_the_uninstall_plan() {
        let service_id = ModelServiceId::parse(&"3".repeat(32)).expect("service");
        for (disposition, expected) in [
            (
                CoreUninstallModelDisposition::KeepModels,
                NodeModelRemovalRetention::PreserveModels,
            ),
            (
                CoreUninstallModelDisposition::RemoveModels,
                NodeModelRemovalRetention::RemoveUnreferencedRuntimes,
            ),
        ] {
            let plan = CoreUninstallPlan::new(
                Sha256Digest::parse(&"f".repeat(64)).expect("ownership"),
                disposition,
                Duration::from_secs(30),
                vec![owned_target(
                    CoreUninstallTargetKind::ModelService,
                    format!("model_service:{}", service_id.as_str()),
                )
                .expect("model target")],
            )
            .expect("uninstall plan");
            let request = uninstall_model_remove_request(&plan, service_id.clone())
                .expect("model removal request");
            assert_eq!(request.runtime_retention(), expected);
            assert_eq!(request.selection(), &NodeModelRemovalSelection::All);
        }
    }

    // Proves applied Docker cleanup replays exact absence without retaining a mutable image tag.
    #[test]
    fn docker_cleanup_replays_after_apply_before_checkpoint() {
        let expected = ManagedDockerContainerTarget {
            container_id: "1".repeat(64),
            image_id: format!("sha256:{}", "2".repeat(64)),
        };
        let inspection = docker_container_inspection(
            &expected,
            "registry.example/runtime:replacement-prone-tag",
        );
        let preflight = ManagedDockerContainerTarget::from_inspection(
            &inspection,
            CoreUninstallError::PreflightRejected,
        )
        .expect("preflight target");
        assert_eq!(preflight, expected);
        assert!(!preflight.identity().contains("replacement-prone-tag"));
        let plan = docker_cleanup_plan(&preflight);
        let mut docker = DockerCleanupFixture {
            expected: expected.clone(),
            observed: expected,
            container_present: true,
            image_present: true,
            removals: Vec::new(),
        };

        clean_managed_docker_targets(&plan, |arguments| docker.run(arguments))
            .expect("first cleanup");
        clean_managed_docker_targets(&plan, |arguments| docker.run(arguments))
            .expect("replayed cleanup");

        assert_eq!(
            docker.removals,
            [
                vec![
                    "container".to_string(),
                    "rm".to_string(),
                    "--force".to_string(),
                    "1".repeat(64),
                ],
                vec![
                    "image".to_string(),
                    "rm".to_string(),
                    format!("sha256:{}", "2".repeat(64)),
                ],
            ]
        );
        assert!(!docker.container_present);
        assert!(!docker.image_present);
    }

    // Proves a replacement or identity drift is rejected before any Docker target is removed.
    #[test]
    fn docker_cleanup_rejects_replacement_before_mutation() {
        let expected = ManagedDockerContainerTarget {
            container_id: "1".repeat(64),
            image_id: format!("sha256:{}", "2".repeat(64)),
        };
        let plan = docker_cleanup_plan(&expected);
        let mut docker = DockerCleanupFixture {
            expected,
            observed: ManagedDockerContainerTarget {
                container_id: "3".repeat(64),
                image_id: format!("sha256:{}", "4".repeat(64)),
            },
            container_present: true,
            image_present: true,
            removals: Vec::new(),
        };

        assert_eq!(
            clean_managed_docker_targets(&plan, |arguments| docker.run(arguments)),
            Err(CoreUninstallError::BoundaryFailed(
                CoreUninstallBoundary::RuntimeArtifacts
            ))
        );
        assert!(docker.removals.is_empty());
        assert!(docker.container_present);
        assert!(docker.image_present);
    }

    // Proves real owner cleanup preserves model bytes only for the keep-models plan.
    #[test]
    fn owner_cleanup_physically_preserves_or_removes_model_bytes_as_requested() {
        for (disposition, models_survive) in [
            (CoreUninstallModelDisposition::KeepModels, true),
            (CoreUninstallModelDisposition::RemoveModels, false),
        ] {
            let directory = tempfile::tempdir().expect("directory");
            let owner_root = directory.path().join("state");
            let model_root = directory.path().join("runtime_installations");
            let configuration_root = directory.path().join("configuration");
            let core_root = directory.path().join("core");
            let journal_file = core_root.join(".uninstall/li_core_uninstall_session_v1.json");
            let model_file = model_root.join("installation/models/weights.bin");
            fs::create_dir_all(&owner_root).expect("owner root");
            fs::create_dir_all(model_file.parent().expect("model parent")).expect("model root");
            fs::create_dir_all(&configuration_root).expect("configuration root");
            fs::create_dir_all(journal_file.parent().expect("journal parent")).expect("core root");
            fs::write(owner_root.join("database.sqlite3"), b"state").expect("owner bytes");
            fs::write(&model_file, b"downloaded-model-bytes").expect("model bytes");
            fs::write(
                configuration_root.join("li_core_cli.json"),
                b"configuration",
            )
            .expect("configuration bytes");
            fs::write(&journal_file, b"durable recovery").expect("journal bytes");
            let mut targets = vec![
                owned_target(
                    CoreUninstallTargetKind::OwnerRoot,
                    format!("path:{}", owner_root.display()),
                )
                .expect("owner target"),
                owned_target(
                    CoreUninstallTargetKind::CoreConfiguration,
                    format!("path:{}", configuration_root.display()),
                )
                .expect("configuration target"),
                owned_target(
                    CoreUninstallTargetKind::CoreInstallation,
                    format!("path:{}", core_root.display()),
                )
                .expect("Core target"),
            ];
            if disposition == CoreUninstallModelDisposition::RemoveModels {
                targets.push(
                    owned_target(
                        CoreUninstallTargetKind::ModelRoot,
                        format!("path:{}", model_root.display()),
                    )
                    .expect("model target"),
                );
            }
            let plan = CoreUninstallPlan::new(
                Sha256Digest::parse(&"f".repeat(64)).expect("ownership"),
                disposition,
                Duration::from_secs(30),
                targets,
            )
            .expect("uninstall plan");
            let owner_user_id = fs::metadata(directory.path()).expect("metadata").uid();

            remove_owner_data_targets(&plan, owner_user_id, &SystemCoreUninstallNativeRemoval)
                .expect("owner cleanup");

            assert!(!owner_root.exists());
            assert_eq!(
                fs::read(configuration_root.join("li_core_cli.json"))
                    .expect("retained configuration"),
                b"configuration"
            );
            assert_eq!(
                fs::read(&journal_file).expect("retained journal"),
                b"durable recovery"
            );
            assert_eq!(model_file.exists(), models_survive);
            if models_survive {
                assert_eq!(
                    fs::read(&model_file).expect("preserved model"),
                    b"downloaded-model-bytes"
                );
            }
        }
    }

    // Proves immutable retirement removes the launcher, active link, configuration, then Core.
    #[test]
    fn immutable_core_retirement_uses_the_exact_closed_order() {
        let directory = tempfile::tempdir().expect("directory");
        let (plan, launcher, current, configuration, core, executable) =
            immutable_core_fixture(directory.path());
        let removal = ImmutableCoreRemovalMock::default();
        let owner_user_id = fs::metadata(directory.path()).expect("metadata").uid();

        retire_immutable_core_targets(
            &plan,
            &launcher,
            &current,
            &core,
            &executable,
            None,
            owner_user_id,
            &removal,
        )
        .expect("immutable retirement");

        assert_eq!(
            *removal.removals.lock().expect("immutable removals"),
            [launcher, current, configuration, core]
        );
    }

    // Proves physical immutable retirement consumes its own journal last and absent replay succeeds.
    #[test]
    fn immutable_core_retirement_removes_the_complete_closure_and_replays_absence() {
        let directory = tempfile::tempdir().expect("directory");
        let (plan, launcher, current, configuration, core, executable) =
            immutable_core_fixture(directory.path());
        let owner_user_id = fs::metadata(directory.path()).expect("metadata").uid();

        for attempt in 0..2 {
            retire_immutable_core_targets(
                &plan,
                &launcher,
                &current,
                &core,
                &executable,
                None,
                owner_user_id,
                &SystemCoreUninstallNativeRemoval,
            )
            .unwrap_or_else(|_| panic!("immutable retirement attempt {attempt}"));
            for path in [&launcher, &current, &configuration, &core] {
                assert!(!path_exists(path).expect("path observation"));
            }
        }
    }

    // Proves a linked configuration or foreign owner fails before any immutable path is removed.
    #[test]
    fn immutable_core_retirement_rejects_unsafe_metadata_without_partial_mutation() {
        for unsafe_metadata in ["configuration_symlink", "foreign_owner"] {
            let directory = tempfile::tempdir().expect("directory");
            let (mut plan, launcher, current, configuration, core, executable) =
                immutable_core_fixture(directory.path());
            let owner_user_id = fs::metadata(directory.path()).expect("metadata").uid();
            let expected_owner_user_id = match unsafe_metadata {
                "configuration_symlink" => {
                    fs::remove_dir_all(&configuration).expect("remove configuration fixture");
                    let target = directory.path().join("foreign-configuration");
                    fs::create_dir(&target).expect("foreign configuration");
                    symlink(&target, &configuration).expect("configuration link");
                    plan = immutable_core_plan(&configuration);
                    owner_user_id
                }
                "foreign_owner" => owner_user_id.wrapping_add(1),
                _ => unreachable!(),
            };

            assert_eq!(
                retire_immutable_core_targets(
                    &plan,
                    &launcher,
                    &current,
                    &core,
                    &executable,
                    None,
                    expected_owner_user_id,
                    &SystemCoreUninstallNativeRemoval,
                ),
                Err(CoreUninstallError::BoundaryFailed(
                    CoreUninstallBoundary::ImmutableCore
                )),
                "unsafe_metadata={unsafe_metadata}"
            );
            assert!(fs::symlink_metadata(&launcher).is_ok());
            assert!(fs::symlink_metadata(&current).is_ok());
            assert!(fs::symlink_metadata(&configuration).is_ok());
            assert!(core.is_dir());
        }
    }

    // Proves composed uninstall requests Node-owned runtime removal before retiring residents.
    #[test]
    fn composed_uninstall_removes_runtime_through_node_before_service_retirement() {
        let installation_id = "4".repeat(32);
        let plan = CoreUninstallPlan::new(
            Sha256Digest::parse(&"f".repeat(64)).expect("ownership"),
            CoreUninstallModelDisposition::RemoveModels,
            Duration::from_secs(30),
            vec![
                owned_target(
                    CoreUninstallTargetKind::RuntimeInstallation,
                    format!("runtime_installation:{installation_id}"),
                )
                .expect("runtime target"),
                owned_target(
                    CoreUninstallTargetKind::PlatformService,
                    "service:li_node".to_string(),
                )
                .expect("service target"),
            ],
        )
        .expect("uninstall plan");
        let ports = Arc::new(UninstallOrderPorts {
            plan,
            events: Mutex::new(Vec::new()),
            runtime_removal_fails: false,
            runtime_finalization_fails: false,
        });
        let coordinator = CoreUninstallCoordinator::new(
            ports.clone(),
            ports.clone(),
            ports.clone(),
            ports.clone(),
            ports.clone(),
            ports.clone(),
            ports.clone(),
            ports.clone(),
            ports.clone(),
        );

        coordinator
            .uninstall(&CoreUninstallRequest::new(
                CoreUninstallConfirmation::Confirmed,
                CoreUninstallModelDisposition::RemoveModels,
            ))
            .expect("composed uninstall");

        assert_eq!(
            *ports.events.lock().expect("uninstall order"),
            [
                format!("node_remove:{installation_id}"),
                "node_finalize:remove".to_string(),
                "service_retire".to_string()
            ]
        );
    }

    // Proves a failed RuntimeManager removal stops before any resident service is retired.
    #[test]
    fn runtime_removal_failure_stops_before_service_retirement() {
        let installation_id = "5".repeat(32);
        let plan = CoreUninstallPlan::new(
            Sha256Digest::parse(&"f".repeat(64)).expect("ownership"),
            CoreUninstallModelDisposition::RemoveModels,
            Duration::from_secs(30),
            vec![
                owned_target(
                    CoreUninstallTargetKind::RuntimeInstallation,
                    format!("runtime_installation:{installation_id}"),
                )
                .expect("runtime target"),
                owned_target(
                    CoreUninstallTargetKind::PlatformService,
                    "service:li_node".to_string(),
                )
                .expect("service target"),
            ],
        )
        .expect("uninstall plan");
        let ports = Arc::new(UninstallOrderPorts {
            plan,
            events: Mutex::new(Vec::new()),
            runtime_removal_fails: true,
            runtime_finalization_fails: false,
        });
        let coordinator = CoreUninstallCoordinator::new(
            ports.clone(),
            ports.clone(),
            ports.clone(),
            ports.clone(),
            ports.clone(),
            ports.clone(),
            ports.clone(),
            ports.clone(),
            ports.clone(),
        );

        assert_eq!(
            coordinator.uninstall(&CoreUninstallRequest::new(
                CoreUninstallConfirmation::Confirmed,
                CoreUninstallModelDisposition::RemoveModels,
            )),
            Err(CoreUninstallError::BoundaryFailed(
                CoreUninstallBoundary::RuntimeArtifacts
            ))
        );
        assert_eq!(
            *ports.events.lock().expect("uninstall order"),
            [format!("node_remove:{installation_id}")]
        );
    }

    // Proves failed root finalization stops after removal and before resident retirement.
    #[test]
    fn runtime_finalization_failure_stops_before_service_retirement() {
        let installation_id = "6".repeat(32);
        let plan = CoreUninstallPlan::new(
            Sha256Digest::parse(&"f".repeat(64)).expect("ownership"),
            CoreUninstallModelDisposition::RemoveModels,
            Duration::from_secs(30),
            vec![
                owned_target(
                    CoreUninstallTargetKind::RuntimeInstallation,
                    format!("runtime_installation:{installation_id}"),
                )
                .expect("runtime target"),
                owned_target(
                    CoreUninstallTargetKind::PlatformService,
                    "service:li_node".to_string(),
                )
                .expect("service target"),
            ],
        )
        .expect("uninstall plan");
        let ports = Arc::new(UninstallOrderPorts {
            plan,
            events: Mutex::new(Vec::new()),
            runtime_removal_fails: false,
            runtime_finalization_fails: true,
        });
        let coordinator = CoreUninstallCoordinator::new(
            ports.clone(),
            ports.clone(),
            ports.clone(),
            ports.clone(),
            ports.clone(),
            ports.clone(),
            ports.clone(),
            ports.clone(),
            ports.clone(),
        );

        assert_eq!(
            coordinator.uninstall(&CoreUninstallRequest::new(
                CoreUninstallConfirmation::Confirmed,
                CoreUninstallModelDisposition::RemoveModels,
            )),
            Err(CoreUninstallError::BoundaryFailed(
                CoreUninstallBoundary::RuntimeArtifacts
            ))
        );
        assert_eq!(
            *ports.events.lock().expect("uninstall order"),
            [
                format!("node_remove:{installation_id}"),
                "node_finalize:remove".to_string()
            ]
        );
    }
}
