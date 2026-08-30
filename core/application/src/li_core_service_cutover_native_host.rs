// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use li_core_interface::Sha256Digest;
use li_core_update_manager::{CoreUpdateServiceContext, CoreUpdateServicePlatform};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    CoreNativeServiceCommandOutput, CoreNativeServiceCommandRunner, CoreNativeServiceWaiter,
    CoreServiceCutoverNativeHost, CoreServiceCutoverNativeSnapshot, CoreServiceSetupError,
    SystemCoreNativeServiceWaiter,
};

const MAXIMUM_SERVICE_DEFINITION_BYTES: u64 = 64 * 1024;
const MAXIMUM_NATIVE_COMMAND_OUTPUT_BYTES: usize = 64 * 1024;
const NATIVE_COMMAND_TIMEOUT_MILLISECONDS: u64 = 30_000;
const NATIVE_SNAPSHOT_SCHEMA_NAME: &str = "li_core_native_service_snapshot";
const NATIVE_SNAPSHOT_SCHEMA_VERSION: u32 = 1;
const LAUNCHD_BOOTSTRAP_ATTEMPTS: usize = 30;
const LAUNCHD_BOOTSTRAP_RETRY_MILLISECONDS: u64 = 250;

// Defines one fixed Rust-native service identity and definition filename.
#[derive(Clone, Copy)]
struct NativeServiceSpec {
    identity: &'static str,
    filename: &'static str,
}

const LINUX_SERVICE_SPECS: [NativeServiceSpec; 3] = [
    NativeServiceSpec {
        identity: "li_gateway.service",
        filename: "li_gateway.service",
    },
    NativeServiceSpec {
        identity: "li_node.service",
        filename: "li_node.service",
    },
    NativeServiceSpec {
        identity: "li_watchdog.service",
        filename: "li_watchdog.service",
    },
];

const MACOS_SERVICE_SPECS: [NativeServiceSpec; 2] = [
    NativeServiceSpec {
        identity: "ai.letsinfer.gateway",
        filename: "ai.letsinfer.gateway.plist",
    },
    NativeServiceSpec {
        identity: "ai.letsinfer.node",
        filename: "ai.letsinfer.node.plist",
    },
];

const LINUX_RESTORE_START_ORDER: [&str; 3] = [
    "li_node.service",
    "li_watchdog.service",
    "li_gateway.service",
];

// Carries one exact user-owned native definition and its original mode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreServiceCutoverFile {
    bytes: Vec<u8>,
    mode: u32,
}

impl CoreServiceCutoverFile {
    // Creates one bounded Rust-native service definition.
    pub fn new(bytes: Vec<u8>, mode: u32) -> Result<Self, CoreServiceSetupError> {
        if bytes.is_empty()
            || bytes.len() as u64 > MAXIMUM_SERVICE_DEFINITION_BYTES
            || !matches!(mode, 0o600 | 0o644)
        {
            return Err(native_host_error("native service definition is invalid"));
        }
        Ok(Self { bytes, mode })
    }

    // Returns the exact definition bytes captured before mutation.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    // Returns the exact original user-file mode.
    pub const fn mode(&self) -> u32 {
        self.mode
    }
}

// Isolates variable-mode native definition I/O from lifecycle policy.
pub trait CoreServiceCutoverFileIo: Send + Sync {
    // Validates one canonical owner-controlled service definition directory.
    fn validate_root(&self, root: &Path, owner_user_id: u32) -> Result<(), CoreServiceSetupError>;

    // Reads one optional owner-controlled definition without following its final path.
    fn read(
        &self,
        path: &Path,
        owner_user_id: u32,
    ) -> Result<Option<CoreServiceCutoverFile>, CoreServiceSetupError>;

    // Atomically restores one exact definition and persists its directory.
    fn replace(
        &self,
        path: &Path,
        file: &CoreServiceCutoverFile,
        owner_user_id: u32,
    ) -> Result<(), CoreServiceSetupError>;

    // Removes one optional exact owner-controlled definition and persists its directory.
    fn remove(&self, path: &Path, owner_user_id: u32) -> Result<bool, CoreServiceSetupError>;
}

// Implements no-follow owner-bound Rust-native service-definition I/O.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemCoreServiceCutoverFileIo;

impl CoreServiceCutoverFileIo for SystemCoreServiceCutoverFileIo {
    // Requires the exact service directory to be owner-controlled and non-writable by others.
    fn validate_root(&self, root: &Path, owner_user_id: u32) -> Result<(), CoreServiceSetupError> {
        validate_directory_chain(root)?;
        let metadata = fs::symlink_metadata(root)
            .map_err(|_| native_host_error("native service directory is unavailable"))?;
        if !metadata.file_type().is_dir()
            || metadata.uid() != owner_user_id
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(native_host_error("native service directory is unsafe"));
        }
        Ok(())
    }

    // Reads one bounded exact-mode regular definition through a no-follow descriptor.
    fn read(
        &self,
        path: &Path,
        owner_user_id: u32,
    ) -> Result<Option<CoreServiceCutoverFile>, CoreServiceSetupError> {
        validated_definition_parent(path, owner_user_id)?;
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => {
                return Err(native_host_error(
                    "native service definition is unavailable",
                ))
            }
        };
        let mode = validate_definition_file(&file, owner_user_id)?;
        let mut bytes = Vec::new();
        file.take(MAXIMUM_SERVICE_DEFINITION_BYTES.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| native_host_error("native service definition could not be read"))?;
        CoreServiceCutoverFile::new(bytes, mode).map(Some)
    }

    // Writes through one collision-resistant same-directory file before atomic rename.
    fn replace(
        &self,
        path: &Path,
        file: &CoreServiceCutoverFile,
        owner_user_id: u32,
    ) -> Result<(), CoreServiceSetupError> {
        CoreServiceCutoverFile::new(file.bytes.clone(), file.mode)?;
        let parent = validated_definition_parent(path, owner_user_id)?;
        if let Some(existing) = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .ok()
        {
            validate_definition_file(&existing, owner_user_id)?;
        } else if fs::symlink_metadata(path).is_ok() {
            return Err(native_host_error(
                "native service definition path is unsafe",
            ));
        }
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce)
            .map_err(|_| native_host_error("native service temporary identity is unavailable"))?;
        let temporary = parent.join(format!(
            ".li_core_service_{}.tmp",
            nonce
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ));
        let result = (|| {
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(file.mode)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&temporary)
                .map_err(|_| native_host_error("native service definition could not be staged"))?;
            output
                .set_permissions(fs::Permissions::from_mode(file.mode))
                .map_err(|_| {
                    native_host_error("native service definition mode could not be set")
                })?;
            output
                .write_all(&file.bytes)
                .and_then(|_| output.sync_all())
                .map_err(|_| {
                    native_host_error("native service definition could not be persisted")
                })?;
            validate_definition_file(&output, owner_user_id)?;
            drop(output);
            fs::rename(&temporary, path).map_err(|_| {
                native_host_error("native service definition could not be activated")
            })?;
            sync_directory(&parent)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    // Removes only a validated exact-mode definition.
    fn remove(&self, path: &Path, owner_user_id: u32) -> Result<bool, CoreServiceSetupError> {
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(_) => {
                return Err(native_host_error(
                    "native service definition is unavailable",
                ))
            }
        };
        validate_definition_file(&file, owner_user_id)?;
        let parent = validated_definition_parent(path, owner_user_id)?;
        drop(file);
        fs::remove_file(path)
            .map_err(|_| native_host_error("native service definition could not be removed"))?;
        sync_directory(&parent)?;
        Ok(true)
    }
}

// Carries the nested schema identity of one native snapshot.
#[derive(Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeSnapshotSchema {
    name: String,
    version: u32,
}

// Carries one optional exact native definition in snapshot JSON.
#[derive(Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeSnapshotFile {
    bytes_base64: String,
    mode: u32,
    sha256: String,
}

// Carries one exact fixed service state in snapshot JSON.
#[derive(Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeSnapshotService {
    identity: String,
    definition: Option<NativeSnapshotFile>,
    enablement: String,
    activity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    disabled: Option<bool>,
}

// Defines the complete closed platform-native snapshot JSON.
#[derive(Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeSnapshotDocument {
    schema: NativeSnapshotSchema,
    platform: String,
    services: Vec<NativeSnapshotService>,
}

// Observes and mutates every fixed Rust-native service identity.
pub struct SystemCoreServiceCutoverNativeHost {
    platform: CoreUpdateServicePlatform,
    service_root: PathBuf,
    owner_user_id: u32,
    supervisor_executable: PathBuf,
    runner: Arc<dyn CoreNativeServiceCommandRunner>,
    io: Arc<dyn CoreServiceCutoverFileIo>,
    waiter: Arc<dyn CoreNativeServiceWaiter>,
}

impl SystemCoreServiceCutoverNativeHost {
    // Creates one host from a canonical home and exact native supervisor executable.
    pub fn new(
        platform: CoreUpdateServicePlatform,
        home_directory: PathBuf,
        owner_user_id: u32,
        supervisor_executable: PathBuf,
        runner: Arc<dyn CoreNativeServiceCommandRunner>,
        io: Arc<dyn CoreServiceCutoverFileIo>,
    ) -> Result<Self, CoreServiceSetupError> {
        Self::new_with_waiter(
            platform,
            home_directory,
            owner_user_id,
            supervisor_executable,
            runner,
            io,
            Arc::new(SystemCoreNativeServiceWaiter),
        )
    }

    // Creates one host with an explicit bounded launchd retry waiter.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_waiter(
        platform: CoreUpdateServicePlatform,
        home_directory: PathBuf,
        owner_user_id: u32,
        supervisor_executable: PathBuf,
        runner: Arc<dyn CoreNativeServiceCommandRunner>,
        io: Arc<dyn CoreServiceCutoverFileIo>,
        waiter: Arc<dyn CoreNativeServiceWaiter>,
    ) -> Result<Self, CoreServiceSetupError> {
        if !is_safe_absolute_path(&home_directory) || home_directory == Path::new("/") {
            return Err(native_host_error("native service home is invalid"));
        }
        let expected_executable = match platform {
            CoreUpdateServicePlatform::Linux => Path::new("/usr/bin/systemctl"),
            CoreUpdateServicePlatform::Macos => Path::new("/bin/launchctl"),
        };
        if supervisor_executable != expected_executable {
            return Err(native_host_error("native service supervisor is invalid"));
        }
        let service_root = match platform {
            CoreUpdateServicePlatform::Linux => home_directory.join(".config/systemd/user"),
            CoreUpdateServicePlatform::Macos => home_directory.join("Library/LaunchAgents"),
        };
        io.validate_root(&service_root, owner_user_id)?;
        Ok(Self {
            platform,
            service_root,
            owner_user_id,
            supervisor_executable,
            runner,
            io,
            waiter,
        })
    }

    // Returns the fixed platform inventory in retirement order.
    fn specs(&self) -> &'static [NativeServiceSpec] {
        match self.platform {
            CoreUpdateServicePlatform::Linux => &LINUX_SERVICE_SPECS,
            CoreUpdateServicePlatform::Macos => &MACOS_SERVICE_SPECS,
        }
    }

    // Executes one bounded shell-free supervisor command.
    fn run(
        &self,
        arguments: Vec<String>,
    ) -> Result<CoreNativeServiceCommandOutput, CoreServiceSetupError> {
        self.runner
            .run(
                &self.supervisor_executable,
                &arguments,
                Duration::from_millis(NATIVE_COMMAND_TIMEOUT_MILLISECONDS),
                MAXIMUM_NATIVE_COMMAND_OUTPUT_BYTES,
            )
            .map_err(|_| native_host_error("native service command failed"))
    }

    // Requires one mutation command to return successful status.
    fn require_success(
        &self,
        arguments: Vec<String>,
        reason: &'static str,
    ) -> Result<(), CoreServiceSetupError> {
        if self.run(arguments)?.status() == 0 {
            Ok(())
        } else {
            Err(native_host_error(reason))
        }
    }

    // Retries only launchd's exact transient bootstrap failure within the fixed bound.
    fn bootstrap_launchd(&self, domain: String, path: String) -> Result<(), CoreServiceSetupError> {
        for attempt in 0..LAUNCHD_BOOTSTRAP_ATTEMPTS {
            let output = self.run(vec!["bootstrap".to_string(), domain.clone(), path.clone()])?;
            if output.status() == 0 {
                return Ok(());
            }
            if !is_transient_launchd_bootstrap_failure(&output)
                || attempt + 1 == LAUNCHD_BOOTSTRAP_ATTEMPTS
            {
                return Err(native_host_error("launchd service could not be loaded"));
            }
            self.waiter
                .wait(Duration::from_millis(LAUNCHD_BOOTSTRAP_RETRY_MILLISECONDS))
                .map_err(|_| native_host_error("launchd bootstrap retry failed"))?;
        }
        Err(native_host_error("launchd service could not be loaded"))
    }

    // Accepts launchd's exact successful or already-unloaded bootout result.
    fn bootout_launchd(&self, target: String) -> Result<(), CoreServiceSetupError> {
        let output = self.run(vec!["bootout".to_string(), target])?;
        if matches!(output.status(), 0 | 3 | 113) {
            Ok(())
        } else {
            Err(native_host_error("launchd service could not be unloaded"))
        }
    }

    // Observes one fixed systemd definition, enablement, and activity state.
    fn observe_systemd(
        &self,
        spec: NativeServiceSpec,
    ) -> Result<NativeSnapshotService, CoreServiceSetupError> {
        let definition = self
            .io
            .read(&self.service_root.join(spec.filename), self.owner_user_id)?;
        let enabled = self.run(vec![
            "--user".to_string(),
            "is-enabled".to_string(),
            spec.identity.to_string(),
        ])?;
        let active = self.run(vec![
            "--user".to_string(),
            "is-active".to_string(),
            spec.identity.to_string(),
        ])?;
        let enablement = systemd_enablement(&enabled)?;
        let activity = systemd_activity(&active)?;
        validate_systemd_state(definition.as_ref(), enablement, activity)?;
        Ok(NativeSnapshotService {
            identity: spec.identity.to_string(),
            definition: definition.map(encoded_file),
            enablement: enablement.to_string(),
            activity: activity.to_string(),
            disabled: None,
        })
    }

    // Observes one fixed launchd definition and GUI-domain load state.
    fn observe_launchd(
        &self,
        spec: NativeServiceSpec,
        disabled_output: &CoreNativeServiceCommandOutput,
    ) -> Result<NativeSnapshotService, CoreServiceSetupError> {
        let definition = self
            .io
            .read(&self.service_root.join(spec.filename), self.owner_user_id)?;
        let target = format!("gui/{}/{}", self.owner_user_id, spec.identity);
        let output = self.run(vec!["print".to_string(), target])?;
        let (manager_state, activity) = launchd_state(&output)?;
        let disabled = launchd_disabled(disabled_output, spec.identity)?;
        if manager_state == "loaded" && definition.is_none() {
            return Err(native_host_error("launchd service state is inconsistent"));
        }
        let enablement = match (manager_state, definition.is_some()) {
            ("loaded", true) => "loaded",
            ("unloaded", true) => "unloaded",
            ("unloaded", false) => "absent",
            _ => return Err(native_host_error("launchd service state is inconsistent")),
        };
        Ok(NativeSnapshotService {
            identity: spec.identity.to_string(),
            definition: definition.map(encoded_file),
            enablement: enablement.to_string(),
            activity: activity.to_string(),
            disabled: Some(disabled),
        })
    }

    // Observes the complete platform inventory without changing service state.
    fn observe_services(&self) -> Result<Vec<NativeSnapshotService>, CoreServiceSetupError> {
        match self.platform {
            CoreUpdateServicePlatform::Linux => self
                .specs()
                .iter()
                .copied()
                .map(|spec| self.observe_systemd(spec))
                .collect(),
            CoreUpdateServicePlatform::Macos => {
                let disabled = self.run(vec![
                    "print-disabled".to_string(),
                    format!("gui/{}", self.owner_user_id),
                ])?;
                self.specs()
                    .iter()
                    .copied()
                    .map(|spec| self.observe_launchd(spec, &disabled))
                    .collect()
            }
        }
    }

    // Retires the current systemd inventory idempotently and reloads once after removal.
    fn retire_systemd(&self) -> Result<(), CoreServiceSetupError> {
        let current = self.observe_services()?;
        self.retire_observed_systemd(current)
    }

    // Retires one already-validated systemd inventory without reopening the comparison window.
    fn retire_observed_systemd(
        &self,
        current: Vec<NativeSnapshotService>,
    ) -> Result<(), CoreServiceSetupError> {
        let mut removed = false;
        for service in current {
            match service.activity.as_str() {
                "active" => self.require_success(
                    vec![
                        "--user".to_string(),
                        "stop".to_string(),
                        service.identity.clone(),
                    ],
                    "systemd service could not be stopped",
                )?,
                "failed" => self.require_success(
                    vec![
                        "--user".to_string(),
                        "reset-failed".to_string(),
                        service.identity.clone(),
                    ],
                    "systemd service failure could not be reset",
                )?,
                "inactive" => {}
                _ => return Err(native_host_error("systemd activity state is invalid")),
            }
            if service.enablement == "enabled" {
                self.require_success(
                    vec![
                        "--user".to_string(),
                        "disable".to_string(),
                        service.identity.clone(),
                    ],
                    "systemd service could not be disabled",
                )?;
            }
            let spec = required_spec(self.specs(), &service.identity)?;
            removed |= self
                .io
                .remove(&self.service_root.join(spec.filename), self.owner_user_id)?;
        }
        if removed {
            self.require_success(
                vec!["--user".to_string(), "daemon-reload".to_string()],
                "systemd definitions could not be reloaded",
            )?;
        }
        Ok(())
    }

    // Retires the current launchd inventory idempotently before definition removal.
    fn retire_launchd(&self) -> Result<(), CoreServiceSetupError> {
        let current = self.observe_services()?;
        self.retire_observed_launchd(current)
    }

    // Retires one already-validated launchd inventory without reopening the comparison window.
    fn retire_observed_launchd(
        &self,
        current: Vec<NativeSnapshotService>,
    ) -> Result<(), CoreServiceSetupError> {
        for service in current {
            if service.enablement == "loaded" {
                self.bootout_launchd(format!("gui/{}/{}", self.owner_user_id, service.identity))?;
            }
            let spec = required_spec(self.specs(), &service.identity)?;
            self.io
                .remove(&self.service_root.join(spec.filename), self.owner_user_id)?;
        }
        Ok(())
    }

    // Restores exact systemd files and enablement before starting only prior active units.
    fn restore_systemd(
        &self,
        document: &NativeSnapshotDocument,
    ) -> Result<(), CoreServiceSetupError> {
        self.retire_systemd()?;
        for service in &document.services {
            if let Some(file) = service.definition.as_ref().map(decoded_file).transpose()? {
                let spec = required_spec(self.specs(), &service.identity)?;
                self.io.replace(
                    &self.service_root.join(spec.filename),
                    &file,
                    self.owner_user_id,
                )?;
            }
        }
        if document
            .services
            .iter()
            .any(|service| service.definition.is_some())
        {
            self.require_success(
                vec!["--user".to_string(), "daemon-reload".to_string()],
                "systemd definitions could not be reloaded",
            )?;
        }
        for service in &document.services {
            match service.enablement.as_str() {
                "enabled" => self.require_success(
                    vec![
                        "--user".to_string(),
                        "enable".to_string(),
                        service.identity.clone(),
                    ],
                    "systemd service enablement could not be restored",
                )?,
                "disabled" => self.require_success(
                    vec![
                        "--user".to_string(),
                        "disable".to_string(),
                        service.identity.clone(),
                    ],
                    "systemd service disablement could not be restored",
                )?,
                "static" | "absent" => {}
                _ => return Err(native_host_error("systemd snapshot enablement is invalid")),
            }
        }
        for identity in LINUX_RESTORE_START_ORDER {
            let service = document
                .services
                .iter()
                .find(|service| service.identity == identity)
                .ok_or_else(|| native_host_error("systemd snapshot identity is invalid"))?;
            if service.activity == "active" {
                self.require_success(
                    vec![
                        "--user".to_string(),
                        "start".to_string(),
                        service.identity.clone(),
                    ],
                    "systemd service activity could not be restored",
                )?;
            }
        }
        Ok(())
    }

    // Restores exact launchd files and prior loaded state through the GUI domain.
    fn restore_launchd(
        &self,
        document: &NativeSnapshotDocument,
    ) -> Result<(), CoreServiceSetupError> {
        self.retire_launchd()?;
        for service in document.services.iter().rev() {
            let spec = required_spec(self.specs(), &service.identity)?;
            let path = self.service_root.join(spec.filename);
            if let Some(file) = service.definition.as_ref().map(decoded_file).transpose()? {
                self.io.replace(&path, &file, self.owner_user_id)?;
            }
            let target = format!("gui/{}/{}", self.owner_user_id, service.identity);
            if service.enablement == "loaded" {
                self.require_success(
                    vec!["enable".to_string(), target.clone()],
                    "launchd service could not be enabled",
                )?;
                self.bootstrap_launchd(
                    format!("gui/{}", self.owner_user_id),
                    path.to_string_lossy().into_owned(),
                )?;
                if service.activity == "active" {
                    self.require_success(
                        vec!["kickstart".to_string(), "-k".to_string(), target.clone()],
                        "launchd service activity could not be restored",
                    )?;
                }
            } else if !matches!(service.enablement.as_str(), "unloaded" | "absent") {
                return Err(native_host_error("launchd snapshot enablement is invalid"));
            }
            let disabled = service
                .disabled
                .ok_or_else(|| native_host_error("launchd snapshot disabled state is invalid"))?;
            if disabled || service.enablement != "loaded" {
                self.require_success(
                    vec![
                        if disabled { "disable" } else { "enable" }.to_string(),
                        target.clone(),
                    ],
                    "launchd service disabled state could not be restored",
                )?;
            }
            let restored_output = self.run(vec!["print".to_string(), target.clone()])?;
            let restored = launchd_state(&restored_output)?;
            let expected = if service.enablement == "loaded" {
                ("loaded", service.activity.as_str())
            } else {
                ("unloaded", "inactive")
            };
            if restored != expected {
                return Err(native_host_error("launchd restored state is inconsistent"));
            }
        }
        let restored_disabled = self.run(vec![
            "print-disabled".to_string(),
            format!("gui/{}", self.owner_user_id),
        ])?;
        for service in &document.services {
            if launchd_disabled(&restored_disabled, &service.identity)?
                != service.disabled.ok_or_else(|| {
                    native_host_error("launchd snapshot disabled state is invalid")
                })?
            {
                return Err(native_host_error(
                    "launchd restored disabled state is inconsistent",
                ));
            }
        }
        Ok(())
    }
}

impl CoreServiceCutoverNativeHost for SystemCoreServiceCutoverNativeHost {
    // Captures exact native files and supervisor states before any retirement mutation.
    fn snapshot(
        &self,
        context: CoreUpdateServiceContext,
    ) -> Result<CoreServiceCutoverNativeSnapshot, CoreServiceSetupError> {
        if context.platform() != self.platform {
            return Err(native_host_error("native service platform changed"));
        }
        let services = self.observe_services()?;
        let document = NativeSnapshotDocument {
            schema: NativeSnapshotSchema {
                name: NATIVE_SNAPSHOT_SCHEMA_NAME.to_string(),
                version: NATIVE_SNAPSHOT_SCHEMA_VERSION,
            },
            platform: platform_text(self.platform).to_string(),
            services,
        };
        let mut bytes = serde_json::to_vec_pretty(&document)
            .map_err(|_| native_host_error("native service snapshot could not be encoded"))?;
        bytes.push(b'\n');
        CoreServiceCutoverNativeSnapshot::new(bytes)
    }

    // Validates one durable snapshot before idempotently retiring the current inventory.
    fn retire(
        &self,
        snapshot: &CoreServiceCutoverNativeSnapshot,
    ) -> Result<(), CoreServiceSetupError> {
        let document = decode_snapshot(snapshot, self.platform, self.specs())?;
        let current = self.observe_services()?;
        if current != document.services {
            return Err(CoreServiceSetupError::RolledBack {
                reason: "native service state changed before retirement",
            });
        }
        match self.platform {
            CoreUpdateServicePlatform::Linux => self.retire_observed_systemd(current),
            CoreUpdateServicePlatform::Macos => self.retire_observed_launchd(current),
        }
    }

    // Resumes only one exact monotonic prefix of the fixed native retirement sequence.
    fn resume_retirement(
        &self,
        snapshot: &CoreServiceCutoverNativeSnapshot,
    ) -> Result<(), CoreServiceSetupError> {
        let document = decode_snapshot(snapshot, self.platform, self.specs())?;
        let current = self.observe_services()?;
        if !retirement_is_reachable(&current, &document.services, self.platform)? {
            return Err(CoreServiceSetupError::RolledBack {
                reason: "native service state changed before retirement",
            });
        }
        match self.platform {
            CoreUpdateServicePlatform::Linux => self.retire_observed_systemd(current),
            CoreUpdateServicePlatform::Macos => self.retire_observed_launchd(current),
        }
    }

    // Restores exact definitions/enablement and prior active versus non-running intent.
    fn restore(
        &self,
        snapshot: &CoreServiceCutoverNativeSnapshot,
    ) -> Result<(), CoreServiceSetupError> {
        let document = decode_snapshot(snapshot, self.platform, self.specs())?;
        match self.platform {
            CoreUpdateServicePlatform::Linux => self.restore_systemd(&document),
            CoreUpdateServicePlatform::Macos => self.restore_launchd(&document),
        }
    }
}

// Accepts only exact native states reachable in fixed retirement order from one snapshot.
fn retirement_is_reachable(
    current: &[NativeSnapshotService],
    snapshot: &[NativeSnapshotService],
    platform: CoreUpdateServicePlatform,
) -> Result<bool, CoreServiceSetupError> {
    if current.len() != snapshot.len() {
        return Err(native_host_error("native service inventory is invalid"));
    }
    let mut previous_progress = u8::MAX;
    for (current, snapshot) in current.iter().zip(snapshot) {
        let Some(progress) = retirement_progress(current, snapshot, platform) else {
            return Ok(false);
        };
        if snapshot.enablement == "absent" {
            continue;
        }
        if progress > previous_progress {
            return Ok(false);
        }
        previous_progress = progress;
    }
    Ok(true)
}

// Returns one service's exact monotonic retirement progress or rejects native state drift.
fn retirement_progress(
    current: &NativeSnapshotService,
    snapshot: &NativeSnapshotService,
    platform: CoreUpdateServicePlatform,
) -> Option<u8> {
    if current.identity != snapshot.identity || current.disabled != snapshot.disabled {
        return None;
    }
    if current == snapshot {
        return Some(if snapshot.enablement == "absent" {
            3
        } else {
            0
        });
    }
    if current.definition.is_none()
        && current.enablement == "absent"
        && current.activity == "inactive"
    {
        return Some(3);
    }
    if current.definition != snapshot.definition || current.activity != "inactive" {
        return None;
    }
    match platform {
        CoreUpdateServicePlatform::Macos
            if snapshot.enablement == "loaded" && current.enablement == "unloaded" =>
        {
            Some(1)
        }
        CoreUpdateServicePlatform::Linux
            if matches!(snapshot.activity.as_str(), "active" | "failed")
                && current.enablement == snapshot.enablement =>
        {
            Some(1)
        }
        CoreUpdateServicePlatform::Linux
            if snapshot.enablement == "enabled" && current.enablement == "disabled" =>
        {
            Some(2)
        }
        _ => None,
    }
}

// Encodes one exact native file without changing its bytes or mode.
fn encoded_file(file: CoreServiceCutoverFile) -> NativeSnapshotFile {
    NativeSnapshotFile {
        bytes_base64: BASE64.encode(file.bytes()),
        mode: file.mode(),
        sha256: format!("{:x}", Sha256::digest(file.bytes())),
    }
}

// Decodes one canonical exact-mode native file.
fn decoded_file(
    file: &NativeSnapshotFile,
) -> Result<CoreServiceCutoverFile, CoreServiceSetupError> {
    let bytes = BASE64
        .decode(file.bytes_base64.as_bytes())
        .map_err(|_| native_host_error("native service snapshot encoding is invalid"))?;
    if BASE64.encode(&bytes) != file.bytes_base64 {
        return Err(native_host_error(
            "native service snapshot encoding is noncanonical",
        ));
    }
    let identity = Sha256Digest::parse(&file.sha256)
        .map_err(|_| native_host_error("native service snapshot identity is invalid"))?;
    let actual = Sha256Digest::parse(&format!("{:x}", Sha256::digest(&bytes)))
        .map_err(|_| native_host_error("native service snapshot identity is invalid"))?;
    if identity != actual {
        return Err(native_host_error(
            "native service snapshot definition was modified",
        ));
    }
    CoreServiceCutoverFile::new(bytes, file.mode)
}

// Decodes and validates one complete fixed-inventory native snapshot.
fn decode_snapshot(
    snapshot: &CoreServiceCutoverNativeSnapshot,
    platform: CoreUpdateServicePlatform,
    specs: &[NativeServiceSpec],
) -> Result<NativeSnapshotDocument, CoreServiceSetupError> {
    let actual_snapshot_identity =
        Sha256Digest::parse(&format!("{:x}", Sha256::digest(snapshot.bytes())))
            .map_err(|_| native_host_error("native service snapshot identity is invalid"))?;
    if snapshot.sha256() != &actual_snapshot_identity {
        return Err(native_host_error("native service snapshot was modified"));
    }
    let document: NativeSnapshotDocument = serde_json::from_slice(snapshot.bytes())
        .map_err(|_| native_host_error("native service snapshot is malformed"))?;
    if document.schema.name != NATIVE_SNAPSHOT_SCHEMA_NAME
        || document.schema.version != NATIVE_SNAPSHOT_SCHEMA_VERSION
        || document.platform != platform_text(platform)
        || document.services.len() != specs.len()
    {
        return Err(native_host_error(
            "native service snapshot contract is invalid",
        ));
    }
    for (service, spec) in document.services.iter().zip(specs) {
        if service.identity != spec.identity {
            return Err(native_host_error(
                "native service snapshot identity is invalid",
            ));
        }
        if let Some(file) = &service.definition {
            decoded_file(file)?;
        }
        match platform {
            CoreUpdateServicePlatform::Linux => validate_stored_systemd_service(service)?,
            CoreUpdateServicePlatform::Macos => validate_stored_launchd_service(service)?,
        }
    }
    Ok(document)
}

// Validates one stored Linux state independently of live native observation.
fn validate_stored_systemd_service(
    service: &NativeSnapshotService,
) -> Result<(), CoreServiceSetupError> {
    let definition = service.definition.is_some();
    let enablement = service.enablement.as_str();
    let activity = service.activity.as_str();
    if !matches!(enablement, "enabled" | "disabled" | "static" | "absent")
        || !matches!(activity, "active" | "inactive" | "failed")
        || service.disabled.is_some()
        || (enablement == "absent") != !definition
        || (activity == "active" && enablement == "absent")
    {
        return Err(native_host_error("systemd snapshot state is invalid"));
    }
    Ok(())
}

// Validates one stored macOS state independently of live native observation.
fn validate_stored_launchd_service(
    service: &NativeSnapshotService,
) -> Result<(), CoreServiceSetupError> {
    let definition = service.definition.is_some();
    if !matches!(
        service.enablement.as_str(),
        "loaded" | "unloaded" | "absent"
    ) || !matches!(service.activity.as_str(), "active" | "inactive")
        || service.disabled.is_none()
        || (service.enablement == "absent") != !definition
        || (service.activity == "active" && service.enablement != "loaded")
    {
        return Err(native_host_error("launchd snapshot state is invalid"));
    }
    Ok(())
}

// Parses one closed systemd enablement result.
fn systemd_enablement(
    output: &CoreNativeServiceCommandOutput,
) -> Result<&str, CoreServiceSetupError> {
    match (output.status(), output_text(output)?) {
        (0, "enabled") => Ok("enabled"),
        (1, "disabled") => Ok("disabled"),
        (0, "static") => Ok("static"),
        (4, "not-found") => Ok("absent"),
        _ => Err(native_host_error("systemd enablement state is invalid")),
    }
}

// Parses one closed systemd activity result.
fn systemd_activity(
    output: &CoreNativeServiceCommandOutput,
) -> Result<&str, CoreServiceSetupError> {
    match (output.status(), output_text(output)?) {
        (0, "active") => Ok("active"),
        (0 | 3, "activating" | "deactivating") => Ok("active"),
        (3, "inactive") | (4, "inactive" | "unknown") => Ok("inactive"),
        (3, "failed") => Ok("failed"),
        _ => Err(native_host_error("systemd activity state is invalid")),
    }
}

// Requires one live systemd file/state combination to be unambiguous.
fn validate_systemd_state(
    definition: Option<&CoreServiceCutoverFile>,
    enablement: &str,
    activity: &str,
) -> Result<(), CoreServiceSetupError> {
    if (enablement == "absent") != definition.is_none()
        || (activity == "active" && enablement == "absent")
    {
        return Err(native_host_error("systemd service state is inconsistent"));
    }
    Ok(())
}

// Parses one closed launchd loaded/activity result.
fn launchd_state(
    output: &CoreNativeServiceCommandOutput,
) -> Result<(&str, &str), CoreServiceSetupError> {
    if output.status() == 113 {
        return Ok(("unloaded", "inactive"));
    }
    if output.status() != 0 {
        return Err(native_host_error("launchd activity state is invalid"));
    }
    let text = output_text(output)?;
    let states = text
        .lines()
        .filter_map(launchd_direct_field)
        .filter_map(|line| line.strip_prefix("state = "))
        .collect::<Vec<_>>();
    if states.len() != 1 {
        return Err(native_host_error("launchd activity state is invalid"));
    }
    match states[0] {
        "running" => Ok(("loaded", "active")),
        "exited" | "waiting" => Ok(("loaded", "inactive")),
        _ => Err(native_host_error("launchd activity state is invalid")),
    }
}

// Returns one direct launchd job field without admitting nested coalition state.
fn launchd_direct_field(line: &str) -> Option<&str> {
    let field = line.strip_prefix('\t')?;
    (!field.starts_with('\t')).then_some(field)
}

// Parses one label's semantic disabled override from launchd's bounded GUI-domain projection.
fn launchd_disabled(
    output: &CoreNativeServiceCommandOutput,
    identity: &str,
) -> Result<bool, CoreServiceSetupError> {
    if output.status() != 0 {
        return Err(native_host_error("launchd disabled state is invalid"));
    }
    let text = output_text(output)?;
    let mut lines = text.lines().map(str::trim).filter(|line| !line.is_empty());
    if lines.next() != Some("disabled services = {") {
        return Err(native_host_error("launchd disabled state is invalid"));
    }
    let mut disabled = None;
    let mut closed = false;
    for line in lines {
        if closed {
            return Err(native_host_error("launchd disabled state is invalid"));
        }
        if line == "}" {
            closed = true;
            continue;
        }
        let (label, value) = line
            .split_once(" => ")
            .ok_or_else(|| native_host_error("launchd disabled state is invalid"))?;
        let label = label
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .ok_or_else(|| native_host_error("launchd disabled state is invalid"))?;
        if label != identity {
            continue;
        }
        let value = match value {
            "disabled" => true,
            "enabled" => false,
            _ => return Err(native_host_error("launchd disabled state is invalid")),
        };
        if disabled.replace(value).is_some() {
            return Err(native_host_error("launchd disabled state is invalid"));
        }
    }
    if !closed {
        return Err(native_host_error("launchd disabled state is invalid"));
    }
    Ok(disabled.unwrap_or(false))
}

// Selects launchd's diagnostic stream without combining unrelated output.
fn diagnostic_text(output: &CoreNativeServiceCommandOutput) -> Result<&str, CoreServiceSetupError> {
    let bytes = if output.stderr().is_empty() {
        output.stdout()
    } else {
        output.stderr()
    };
    std::str::from_utf8(bytes)
        .map(str::trim)
        .map_err(|_| native_host_error("launchd diagnostics are invalid"))
}

// Recognizes only launchd's documented transient bootstrap input/output failure.
fn is_transient_launchd_bootstrap_failure(output: &CoreNativeServiceCommandOutput) -> bool {
    output.status() == 5
        && diagnostic_text(output).is_ok_and(|text| {
            text.contains("Bootstrap failed: 5:") && text.contains("Input/output error")
        })
}

// Returns one strict trimmed UTF-8 native supervisor output.
fn output_text(output: &CoreNativeServiceCommandOutput) -> Result<&str, CoreServiceSetupError> {
    std::str::from_utf8(output.stdout())
        .map(str::trim)
        .map_err(|_| native_host_error("native service state is invalid"))
}

// Returns one fixed spec by exact identity.
fn required_spec<'a>(
    specs: &'a [NativeServiceSpec],
    identity: &str,
) -> Result<&'a NativeServiceSpec, CoreServiceSetupError> {
    specs
        .iter()
        .find(|spec| spec.identity == identity)
        .ok_or_else(|| native_host_error("native service identity is invalid"))
}

// Returns the closed snapshot platform value.
const fn platform_text(platform: CoreUpdateServicePlatform) -> &'static str {
    match platform {
        CoreUpdateServicePlatform::Linux => "linux",
        CoreUpdateServicePlatform::Macos => "macos",
    }
}

// Validates one no-traversal absolute home path.
fn is_safe_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

// Rejects every symlink or non-directory component in one absolute service-root chain.
fn validate_directory_chain(path: &Path) -> Result<(), CoreServiceSetupError> {
    if !is_safe_absolute_path(path) || path == Path::new("/") {
        return Err(native_host_error("native service directory is invalid"));
    }
    let mut current = PathBuf::from("/");
    for component in path.components().skip(1) {
        let Component::Normal(value) = component else {
            return Err(native_host_error("native service directory is invalid"));
        };
        current.push(value);
        let metadata = fs::symlink_metadata(&current)
            .map_err(|_| native_host_error("native service directory is unavailable"))?;
        if !metadata.file_type().is_dir() {
            return Err(native_host_error("native service directory is unsafe"));
        }
    }
    Ok(())
}

// Validates one open Rust-native definition and returns its exact mode.
fn validate_definition_file(file: &File, owner_user_id: u32) -> Result<u32, CoreServiceSetupError> {
    let metadata = file
        .metadata()
        .map_err(|_| native_host_error("native service definition metadata is unavailable"))?;
    let mode = metadata.permissions().mode() & 0o777;
    if !metadata.file_type().is_file()
        || metadata.uid() != owner_user_id
        || metadata.nlink() != 1
        || !matches!(mode, 0o600 | 0o644)
        || metadata.len() == 0
        || metadata.len() > MAXIMUM_SERVICE_DEFINITION_BYTES
    {
        return Err(native_host_error("native service definition is unsafe"));
    }
    Ok(mode)
}

// Validates the exact owner-controlled native service parent directory.
fn validated_definition_parent(
    path: &Path,
    owner_user_id: u32,
) -> Result<PathBuf, CoreServiceSetupError> {
    let parent = path
        .parent()
        .ok_or_else(|| native_host_error("native service path is invalid"))?
        .to_path_buf();
    SystemCoreServiceCutoverFileIo.validate_root(&parent, owner_user_id)?;
    Ok(parent)
}

// Persists one already-validated native service directory.
fn sync_directory(path: &Path) -> Result<(), CoreServiceSetupError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| native_host_error("native service directory could not be persisted"))
}

// Creates one stable redacted native-host failure.
fn native_host_error(reason: &'static str) -> CoreServiceSetupError {
    CoreServiceSetupError::provider("native service cutover", reason)
}
