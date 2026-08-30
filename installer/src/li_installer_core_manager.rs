// SPDX-License-Identifier: AGPL-3.0-only

use flate2::read::GzDecoder;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use tar::Archive;

use crate::li_installer_arguments::InstallerArguments;
use crate::li_installer_download_manager::DownloadManager;
use crate::li_installer_probe_manager::ProbeFacts;
use crate::li_installer_release_manager::ReleaseManager;
use crate::li_installer_service_manager::SetupRootPreparation;

const CORE_RELEASE_MANIFEST: &str = "li_core_release_manifest_v1.json";
const CORE_RELEASE_SCHEMA_NAME: &str = "li_core_release_manifest";
const CORE_RELEASE_SCHEMA_VERSION: u32 = 1;
const MAXIMUM_CORE_ARCHIVE_FILES: usize = 20_000;
const MAXIMUM_CORE_ARCHIVE_BYTES: u64 = 1024 * 1024 * 1024;

// Stores activated Core identity, public launcher state, and exact fresh-home rollback authority.
pub struct CoreInstallResult {
    pub command: PathBuf,
    pub installation_root: PathBuf,
    pub setup_command: PathBuf,
    pub source_identity: String,
    pub version: String,
    launcher_activation: LauncherActivationReceipt,
    previous_activation: Option<PathBuf>,
    pub(crate) setup_root_preparation: Option<SetupRootPreparation>,
}

// Captures the exact public launcher state required to reverse one failed activation.
#[derive(Clone, Debug, Eq, PartialEq)]
struct LauncherActivationReceipt {
    launcher: PathBuf,
    installed_target: PathBuf,
    previous: LauncherState,
    privilege_command: Option<PathBuf>,
}

// Represents the only two launcher states accepted before installer mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
enum LauncherState {
    Absent,
    Symlink(PathBuf),
}

// Retains whether a failed launcher transition completed its exact compensation.
#[derive(Debug)]
struct LauncherActivationError {
    message: String,
    rollback_completed: bool,
}

impl LauncherActivationError {
    // Creates one pre-mutation launcher failure that requires no compensation.
    fn unmutated(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            rollback_completed: true,
        }
    }
}

// Applies launcher filesystem mutations through the selected privilege boundary.
trait LauncherMutationProvider {
    // Creates or verifies the exact public launcher directory.
    fn prepare_directory(&self, root: &Path, privilege: Option<&Path>) -> Result<(), String>;

    // Atomically replaces one public launcher with the exact target.
    fn replace(
        &self,
        launcher: &Path,
        target: &Path,
        privilege: Option<&Path>,
    ) -> Result<(), String>;

    // Removes one already-validated installer-owned public launcher.
    fn remove(&self, launcher: &Path, privilege: Option<&Path>) -> Result<(), String>;
}

// Uses direct owner operations or one exact shell-free sudo command boundary.
struct SystemLauncherMutationProvider;

impl LauncherMutationProvider for SystemLauncherMutationProvider {
    // Creates one mode-0755 launcher directory directly or through sudo.
    fn prepare_directory(&self, root: &Path, privilege: Option<&Path>) -> Result<(), String> {
        match privilege {
            Some(sudo) => run_checked(
                Command::new(sudo)
                    .args(["install", "-d", "-m", "0755"])
                    .arg(root),
                "cannot create system launcher root",
            )
            .map(|_| ()),
            None => {
                fs::create_dir_all(root)
                    .map_err(|error| format!("cannot create launcher root: {error}"))?;
                set_mode(root, 0o755)
            }
        }
    }

    // Replaces one symlink atomically without introducing a shell command.
    fn replace(
        &self,
        launcher: &Path,
        target: &Path,
        privilege: Option<&Path>,
    ) -> Result<(), String> {
        let Some(sudo) = privilege else {
            return atomic_symlink(launcher, target);
        };
        let root = launcher
            .parent()
            .ok_or_else(|| "launcher parent is unavailable".to_string())?;
        let name = launcher
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| "launcher name is unavailable".to_string())?;
        let temporary = root.join(format!(".{}.li_installer_{}", name, std::process::id()));
        run_checked(
            Command::new(sudo).args(["rm", "-f", "--"]).arg(&temporary),
            "cannot prepare system launcher",
        )?;
        run_checked(
            Command::new(sudo)
                .arg("ln")
                .arg("-s")
                .arg(target)
                .arg(&temporary),
            "cannot stage system launcher",
        )?;
        #[cfg(target_os = "macos")]
        run_checked(
            Command::new(sudo)
                .args(["chmod", "-h", "0755"])
                .arg(&temporary),
            "cannot make system launcher public",
        )?;
        run_checked(
            Command::new(sudo)
                .args(["mv", "-f", "--"])
                .arg(&temporary)
                .arg(launcher),
            "cannot activate system launcher",
        )
        .map(|_| ())
    }

    // Removes one exact symlink directly or through the same sudo executable.
    fn remove(&self, launcher: &Path, privilege: Option<&Path>) -> Result<(), String> {
        match privilege {
            Some(sudo) => run_checked(
                Command::new(sudo).args(["rm", "-f", "--"]).arg(launcher),
                "cannot remove failed system launcher",
            )
            .map(|_| ()),
            None => {
                fs::remove_file(launcher)
                    .map_err(|error| format!("cannot remove failed launcher: {error}"))?;
                sync_directory(
                    launcher
                        .parent()
                        .ok_or_else(|| "launcher parent is unavailable".to_string())?,
                )
            }
        }
    }
}

// Stores one downloaded Core archive before source verification begins.
pub struct DownloadedCore {
    archive_path: PathBuf,
}

// Stores one fully verified Core source tree ready for immutable installation.
pub struct PreparedCore {
    release_root: PathBuf,
    verified: VerifiedCore,
    version: String,
}

// Owns Core download, verification, immutable installation, and launchers.
pub struct CoreManager<'a> {
    arguments: &'a InstallerArguments,
    download_manager: &'a DownloadManager,
    release_manager: &'a ReleaseManager,
}

impl<'a> CoreManager<'a> {
    // Creates one manager bound to the verified release and installation paths.
    pub fn new(
        arguments: &'a InstallerArguments,
        download_manager: &'a DownloadManager,
        release_manager: &'a ReleaseManager,
    ) -> Self {
        Self {
            arguments,
            download_manager,
            release_manager,
        }
    }

    // Downloads the selected Core archive without trusting its contents.
    pub fn download(&self) -> Result<DownloadedCore, String> {
        let archive_path = self
            .arguments
            .temporary_root
            .join(&self.arguments.core_archive_name);
        self.download_manager
            .download(&self.arguments.core_archive_name, &archive_path)?;
        Ok(DownloadedCore { archive_path })
    }

    // Verifies the signed checksum, native archive, manifest, and release identity.
    pub fn prepare(&self, downloaded: DownloadedCore) -> Result<PreparedCore, String> {
        self.release_manager
            .verify(&self.arguments.core_archive_name, &downloaded.archive_path)?;
        let unpacked = self
            .arguments
            .temporary_root
            .join("li_installer_core_unpacked");
        fs::create_dir(&unpacked)
            .map_err(|error| format!("cannot create Core extraction root: {}", error))?;
        extract_core_archive(&downloaded.archive_path, &unpacked)?;
        let release_root = unpacked.join("letsinfer");
        let verified = verify_core_release(
            &release_root,
            self.arguments.operating_system(),
            self.arguments.architecture(),
        )?;
        let version = verified.version.clone();
        if self.arguments.release_version != "auto" && version != self.arguments.release_version {
            return Err(format!(
                "Core archive version {} differs from requested {}",
                version, self.arguments.release_version
            ));
        }
        Ok(PreparedCore {
            release_root,
            verified,
            version,
        })
    }

    // Installs, activates, and exposes one previously verified Core source.
    pub(crate) fn install(
        &self,
        prepared: PreparedCore,
        facts: &ProbeFacts,
        setup_root_preparation: Option<SetupRootPreparation>,
    ) -> Result<CoreInstallResult, String> {
        self.install_with_launcher_provider(
            prepared,
            facts,
            setup_root_preparation,
            &SystemLauncherMutationProvider,
        )
    }

    // Installs Core through one injected launcher boundary for exact compensation verification.
    fn install_with_launcher_provider(
        &self,
        prepared: PreparedCore,
        facts: &ProbeFacts,
        mut setup_root_preparation: Option<SetupRootPreparation>,
        launcher_provider: &dyn LauncherMutationProvider,
    ) -> Result<CoreInstallResult, String> {
        // The effective installation UID is the sole lifecycle authority across adjacent lexical
        // Core mutations; fresh-home retirement remains separately descriptor-relative.
        validate_unactivated_setup_home(
            &mut setup_root_preparation,
            &self.arguments.letsinfer_home,
        )?;
        if let Err(error) = install_release_trust(
            &self.arguments.release_allowed_signers_file,
            &self.arguments.letsinfer_home,
        ) {
            return Err(cleanup_unactivated_home(&mut setup_root_preparation, error));
        }
        validate_unactivated_setup_home(
            &mut setup_root_preparation,
            &self.arguments.letsinfer_home,
        )?;
        let source_identity = prepared.verified.identity.clone();
        let destination = match install_core_release(
            &prepared.release_root,
            &self.arguments.letsinfer_home,
            &prepared.version,
            &prepared.verified,
        ) {
            Ok(destination) => destination,
            Err(error) => return Err(cleanup_unactivated_home(&mut setup_root_preparation, error)),
        };
        validate_unactivated_setup_home(
            &mut setup_root_preparation,
            &self.arguments.letsinfer_home,
        )?;
        let previous_activation = match current_activation(&self.arguments.letsinfer_home) {
            Ok(previous) => previous,
            Err(error) => return Err(cleanup_unactivated_home(&mut setup_root_preparation, error)),
        };
        validate_unactivated_setup_home(
            &mut setup_root_preparation,
            &self.arguments.letsinfer_home,
        )?;
        if let Err(error) = activate_core(&self.arguments.letsinfer_home, &destination) {
            validate_setup_home(
                setup_root_preparation.as_ref(),
                &self.arguments.letsinfer_home,
            )
            .map_err(|validation| {
                format!(
                    "{error}; Core activation state was preserved because home validation failed: {validation}"
                )
            })?;
            restore_core_activation(
                &self.arguments.letsinfer_home,
                &destination,
                previous_activation.as_ref(),
            )
            .map_err(|rollback| format!("{error}; Core activation rollback failed: {rollback}"))?;
            return Err(cleanup_unactivated_home(&mut setup_root_preparation, error));
        }
        if let Err(error) = validate_setup_home(
            setup_root_preparation.as_ref(),
            &self.arguments.letsinfer_home,
        ) {
            return Err(format!(
                "{error}; installed Core activation was preserved for exact recovery"
            ));
        }
        let launcher_activation = match self.install_launchers(facts, launcher_provider) {
            Ok(activation) => activation,
            Err(error) => {
                let message = error.message;
                validate_setup_home(
                    setup_root_preparation.as_ref(),
                    &self.arguments.letsinfer_home,
                )
                .map_err(|validation| {
                    format!(
                        "{message}; Core activation was preserved because home validation failed: {validation}"
                    )
                })?;
                if !error.rollback_completed {
                    return Err(format!(
                        "{message}; Core activation was preserved because launcher recovery is required"
                    ));
                }
                restore_core_activation(
                    &self.arguments.letsinfer_home,
                    &destination,
                    previous_activation.as_ref(),
                )
                .map_err(|rollback| {
                    format!("{message}; Core activation rollback failed: {rollback}")
                })?;
                validate_setup_home(
                    setup_root_preparation.as_ref(),
                    &self.arguments.letsinfer_home,
                )
                .map_err(|validation| {
                    format!(
                        "{message}; Core activation was restored but fresh-home cleanup was refused: {validation}"
                    )
                })?;
                return Err(cleanup_unactivated_home(
                    &mut setup_root_preparation,
                    message,
                ));
            }
        };
        if let Err(error) = validate_setup_home(
            setup_root_preparation.as_ref(),
            &self.arguments.letsinfer_home,
        ) {
            let launcher = rollback_launcher(launcher_provider, &launcher_activation);
            return match launcher {
                Ok(()) => Err(format!(
                    "{error}; public launcher was restored and Core activation was preserved for exact recovery"
                )),
                Err(rollback) => Err(format!(
                    "{error}; launcher rollback failed: {rollback}; Core activation was preserved for exact recovery"
                )),
            };
        }
        Ok(CoreInstallResult {
            command: launcher_activation.launcher.clone(),
            setup_command: destination.join("bin/li_core_setup"),
            installation_root: destination,
            source_identity,
            version: prepared.version,
            launcher_activation,
            previous_activation,
            setup_root_preparation,
        })
    }

    // Restores the exact prior launcher and Core activation after failed native setup.
    pub fn rollback_activation(&self, core: &CoreInstallResult) -> Result<(), String> {
        validate_setup_home(
            core.setup_root_preparation.as_ref(),
            &self.arguments.letsinfer_home,
        )?;
        let launcher =
            rollback_launcher(&SystemLauncherMutationProvider, &core.launcher_activation);
        if let Err(error) = validate_setup_home(
            core.setup_root_preparation.as_ref(),
            &self.arguments.letsinfer_home,
        ) {
            return match launcher {
                Ok(()) => Err(error),
                Err(launcher) => Err(format!(
                    "launcher rollback failed: {launcher}; Core home validation failed: {error}"
                )),
            };
        }
        let activation = restore_core_activation(
            &self.arguments.letsinfer_home,
            &core.installation_root,
            core.previous_activation.as_ref(),
        );
        let rollback = combine_rollback_results(launcher, activation);
        rollback?;
        validate_setup_home(
            core.setup_root_preparation.as_ref(),
            &self.arguments.letsinfer_home,
        )
    }

    // Retires only one receipt-owned fresh home after the caller restores public activation.
    pub fn cleanup_failed_setup_home(&self, core: &mut CoreInstallResult) -> Result<(), String> {
        core.setup_root_preparation
            .as_mut()
            .map(SetupRootPreparation::cleanup_created_home)
            .transpose()
            .map(|_| ())
    }

    // Installs user or system launchers through one exact privilege boundary.
    fn install_launchers(
        &self,
        facts: &ProbeFacts,
        provider: &dyn LauncherMutationProvider,
    ) -> Result<LauncherActivationReceipt, LauncherActivationError> {
        let privilege_command = if self.arguments.user_install {
            None
        } else {
            Some(facts.dependency_path("sudo").ok_or_else(|| {
                LauncherActivationError::unmutated("sudo is required for system launchers")
            })?)
        };
        activate_launcher(
            provider,
            &self.arguments.launcher_root,
            &self
                .arguments
                .letsinfer_home
                .join("core/current/bin/li_letsinfer"),
            privilege_command,
        )
    }
}

// Reopens the complete lexical installation home against the receipt before each mutation boundary.
fn validate_setup_home(
    preparation: Option<&SetupRootPreparation>,
    home: &Path,
) -> Result<(), String> {
    preparation
        .map(|value| value.validate_lexical_home(home))
        .transpose()
        .map(|_| ())
}

// Validates one pre-activation home and retires only its exact receipt-owned tree on failure.
fn validate_unactivated_setup_home(
    preparation: &mut Option<SetupRootPreparation>,
    home: &Path,
) -> Result<(), String> {
    match validate_setup_home(preparation.as_ref(), home) {
        Ok(()) => Ok(()),
        Err(error) => Err(cleanup_unactivated_home(preparation, error)),
    }
}

// Cleans one exact fresh home after a pre-activation failure without touching prior homes.
fn cleanup_unactivated_home(
    preparation: &mut Option<SetupRootPreparation>,
    error: String,
) -> String {
    match preparation
        .as_mut()
        .map(SetupRootPreparation::cleanup_created_home)
        .transpose()
    {
        Ok(_) => error,
        Err(cleanup) => format!("{error}; Core fresh-home rollback failed: {cleanup}"),
    }
}

// Installs one launcher and returns the complete exact rollback receipt.
fn activate_launcher(
    provider: &dyn LauncherMutationProvider,
    launcher_root: &Path,
    installed_target: &Path,
    privilege_command: Option<PathBuf>,
) -> Result<LauncherActivationReceipt, LauncherActivationError> {
    let launcher = launcher_root.join("letsinfer");
    let previous = launcher_state_with_privilege(&launcher, privilege_command.as_deref())
        .map_err(LauncherActivationError::unmutated)?;
    provider
        .prepare_directory(launcher_root, privilege_command.as_deref())
        .map_err(LauncherActivationError::unmutated)?;
    let receipt = LauncherActivationReceipt {
        launcher,
        installed_target: installed_target.to_path_buf(),
        previous,
        privilege_command,
    };
    if let Err(error) = provider.replace(
        &receipt.launcher,
        &receipt.installed_target,
        receipt.privilege_command.as_deref(),
    ) {
        return Err(launcher_activation_failure(provider, &receipt, error));
    }
    let observed = match launcher_state_with_privilege(
        &receipt.launcher,
        receipt.privilege_command.as_deref(),
    ) {
        Ok(observed) => observed,
        Err(error) => return Err(launcher_activation_failure(provider, &receipt, error)),
    };
    if observed != LauncherState::Symlink(receipt.installed_target.clone()) {
        return Err(launcher_activation_failure(
            provider,
            &receipt,
            "installed launcher identity differs after activation".to_string(),
        ));
    }
    Ok(receipt)
}

// Attempts one exact launcher compensation and retains whether cleanup authority remains safe.
fn launcher_activation_failure(
    provider: &dyn LauncherMutationProvider,
    receipt: &LauncherActivationReceipt,
    error: String,
) -> LauncherActivationError {
    match rollback_launcher(provider, receipt) {
        Ok(()) => LauncherActivationError {
            message: error,
            rollback_completed: true,
        },
        Err(rollback) => LauncherActivationError {
            message: format!("{error}; launcher activation rollback failed: {rollback}"),
            rollback_completed: false,
        },
    }
}

// Restores one prior launcher only while the installer-owned target remains authoritative.
fn rollback_launcher(
    provider: &dyn LauncherMutationProvider,
    receipt: &LauncherActivationReceipt,
) -> Result<(), String> {
    let observed =
        launcher_state_with_privilege(&receipt.launcher, receipt.privilege_command.as_deref())?;
    if observed == receipt.previous {
        return Ok(());
    }
    if observed != LauncherState::Symlink(receipt.installed_target.clone()) {
        return Err(
            "public launcher changed before installer rollback; recovery required".to_string(),
        );
    }
    match &receipt.previous {
        LauncherState::Absent => {
            provider.remove(&receipt.launcher, receipt.privilege_command.as_deref())?
        }
        LauncherState::Symlink(previous) => provider.replace(
            &receipt.launcher,
            previous,
            receipt.privilege_command.as_deref(),
        )?,
    }
    if launcher_state_with_privilege(&receipt.launcher, receipt.privilege_command.as_deref())?
        != receipt.previous
    {
        return Err("public launcher rollback identity differs; recovery required".to_string());
    }
    Ok(())
}

// Returns exact launcher absence or raw symlink target without following it.
fn launcher_state(launcher: &Path) -> Result<LauncherState, String> {
    launcher_state_with_privilege(launcher, None)
}

// Returns exact launcher state and uses the selected privilege only for an unreadable symlink.
fn launcher_state_with_privilege(
    launcher: &Path,
    privilege: Option<&Path>,
) -> Result<LauncherState, String> {
    match fs::symlink_metadata(launcher) {
        Ok(metadata) if metadata.file_type().is_symlink() => match fs::read_link(launcher) {
            Ok(target) => Ok(LauncherState::Symlink(target)),
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                let privilege =
                    privilege.ok_or_else(|| format!("cannot read public launcher: {error}"))?;
                privileged_launcher_target(privilege, launcher).map(LauncherState::Symlink)
            }
            Err(error) => Err(format!("cannot read public launcher: {error}")),
        },
        Ok(_) => Err(format!(
            "refusing to replace a non-symlink launcher: {}",
            launcher.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(LauncherState::Absent),
        Err(error) => Err(format!("cannot inspect public launcher: {error}")),
    }
}

// Reads one root-owned symlink target without following it or invoking a shell.
fn privileged_launcher_target(privilege: &Path, launcher: &Path) -> Result<PathBuf, String> {
    let output = run_checked(
        Command::new(privilege)
            .arg("/usr/bin/readlink")
            .arg(launcher),
        "cannot read public launcher",
    )?;
    decode_readlink_output(output)
}

// Decodes one newline-terminated native readlink result without target ambiguity.
fn decode_readlink_output(mut output: Vec<u8>) -> Result<PathBuf, String> {
    if output.last() == Some(&b'\n') {
        output.pop();
    }
    if output.is_empty()
        || output.contains(&b'\0')
        || output.contains(&b'\n')
        || output.contains(&b'\r')
    {
        return Err("cannot read public launcher: target is invalid".to_string());
    }
    #[cfg(unix)]
    {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        Ok(PathBuf::from(OsString::from_vec(output)))
    }
    #[cfg(not(unix))]
    {
        let _ = output;
        Err("native installer requires Unix symlink support".to_string())
    }
}

// Returns both rollback failures without hiding a successfully completed boundary.
fn combine_rollback_results(
    launcher: Result<(), String>,
    activation: Result<(), String>,
) -> Result<(), String> {
    match (launcher, activation) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(launcher), Err(activation)) => Err(format!(
            "launcher rollback failed: {launcher}; Core activation rollback failed: {activation}"
        )),
    }
}

// Installs or verifies the signed bootstrap's persistent owner-only release trust document.
fn install_release_trust(source: &Path, home: &Path) -> Result<PathBuf, String> {
    let details = fs::symlink_metadata(source)
        .map_err(|error| format!("cannot inspect release trust: {error}"))?;
    if details.file_type().is_symlink()
        || !details.is_file()
        || details.len() == 0
        || details.len() > 64 * 1024
    {
        return Err("release trust is invalid".to_string());
    }
    let expected = fs::read(source).map_err(|_| "release trust is unavailable".to_string())?;
    if expected.len() as u64 != details.len() {
        return Err("release trust changed while it was read".to_string());
    }
    ensure_private_directory(home)?;
    let trust = home.join("trust");
    ensure_private_directory(&trust)?;
    let destination = trust.join("release-allowed-signers");
    match fs::symlink_metadata(&destination) {
        Ok(_) => {
            verify_installed_release_trust(&destination, &expected)?;
            return Ok(destination);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("cannot inspect installed release trust: {error}")),
    }
    let temporary = trust.join(format!(
        ".release-allowed-signers.li_installer_{}.tmp",
        std::process::id()
    ));
    match fs::symlink_metadata(&temporary) {
        Ok(_) => return Err("release trust staging path already exists".to_string()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "cannot inspect release trust staging path: {error}"
            ))
        }
    }
    write_new_file(&temporary, &expected, 0o600)?;
    match fs::hard_link(&temporary, &destination) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            fs::remove_file(&temporary).map_err(|cleanup| {
                format!("cannot remove release trust staging file: {cleanup}")
            })?;
            verify_installed_release_trust(&destination, &expected)?;
            return Ok(destination);
        }
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            return Err(format!("cannot activate release trust: {error}"));
        }
    }
    if let Err(error) = fs::remove_file(&temporary) {
        let rollback = fs::remove_file(&destination);
        return match rollback {
            Ok(()) => Err(format!("cannot remove release trust staging file: {error}")),
            Err(rollback) => Err(format!(
                "cannot remove release trust staging file: {error}; cannot roll back release trust: {rollback}"
            )),
        };
    }
    sync_directory(&trust)?;
    Ok(destination)
}

// Verifies one immutable owner-only release trust document without following a forged path type.
fn verify_installed_release_trust(destination: &Path, expected: &[u8]) -> Result<(), String> {
    let details = fs::symlink_metadata(destination)
        .map_err(|_| "installed release trust is unavailable".to_string())?;
    if details.file_type().is_symlink()
        || !details.is_file()
        || details.len() != expected.len() as u64
        || file_mode(destination)? != 0o600
    {
        return Err("installed release trust differs from signed bootstrap trust".to_string());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if details.nlink() != 1 {
            return Err("installed release trust differs from signed bootstrap trust".to_string());
        }
    }
    let installed =
        fs::read(destination).map_err(|_| "installed release trust is unavailable".to_string())?;
    if installed != expected {
        return Err("installed release trust differs from signed bootstrap trust".to_string());
    }
    Ok(())
}

// Stores one verified native Core release and its immutable manifest identity.
struct VerifiedCore {
    identity: String,
    manifest_bytes: Vec<u8>,
    records: Vec<CoreFileRecord>,
    version: String,
}

// Stores one exact native file path, content identity, and authored mode.
struct CoreFileRecord {
    bytes: u64,
    mode: u32,
    path: PathBuf,
    sha256: String,
}

// Decodes the closed top-level native Core release manifest.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CoreReleaseDocument {
    schema: CoreReleaseSchemaDocument,
    release: CoreReleaseIdentityDocument,
    platform: CoreReleasePlatformDocument,
    files: Vec<CoreReleaseFileDocument>,
}

// Decodes the exact user-facing Core release version.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CoreReleaseIdentityDocument {
    version: String,
}

// Decodes the nested Core release schema identity.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CoreReleaseSchemaDocument {
    name: String,
    version: u32,
}

// Decodes the exact platform identity of one native Core archive.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CoreReleasePlatformDocument {
    os: String,
    architecture: String,
}

// Decodes one exact regular-file record from the native Core manifest.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CoreReleaseFileDocument {
    path: String,
    bytes: u64,
    mode: u32,
    sha256: String,
}

// Extracts one checksum-verified Core archive after rejecting unsafe entries.
fn extract_core_archive(archive_path: &Path, destination: &Path) -> Result<(), String> {
    let source =
        File::open(archive_path).map_err(|error| format!("cannot open Core archive: {}", error))?;
    let mut archive = Archive::new(GzDecoder::new(source));
    let mut count = 0_usize;
    let mut total = 0_u64;
    for entry in archive
        .entries()
        .map_err(|error| format!("cannot read Core archive: {}", error))?
    {
        let mut entry =
            entry.map_err(|error| format!("Core archive entry is invalid: {}", error))?;
        count += 1;
        total = total
            .checked_add(entry.size())
            .ok_or_else(|| "Core archive size overflowed".to_string())?;
        if count > MAXIMUM_CORE_ARCHIVE_FILES || total > MAXIMUM_CORE_ARCHIVE_BYTES {
            return Err("Core archive exceeds its extraction boundary".to_string());
        }
        let path = entry
            .path()
            .map_err(|error| format!("Core archive path is invalid: {}", error))?;
        validate_relative_path(&path)?;
        if !path.starts_with("letsinfer") {
            return Err("Core archive entry is outside its release root".to_string());
        }
        let kind = entry.header().entry_type();
        if !kind.is_file() && !kind.is_dir() {
            return Err(format!(
                "Core archive entry type is invalid: {}",
                path.display()
            ));
        }
        entry
            .unpack_in(destination)
            .map_err(|error| format!("cannot extract Core archive: {}", error))?;
    }
    if count == 0 {
        return Err("Core archive is empty".to_string());
    }
    Ok(())
}

// Verifies every native file against the closed platform release manifest.
fn verify_core_release(
    root: &Path,
    operating_system: &str,
    architecture: &str,
) -> Result<VerifiedCore, String> {
    let manifest_path = root.join(CORE_RELEASE_MANIFEST);
    let details = fs::symlink_metadata(&manifest_path)
        .map_err(|error| format!("cannot inspect source manifest: {}", error))?;
    if details.file_type().is_symlink() || !details.is_file() || details.len() > 16 * 1024 * 1024 {
        return Err("Core release manifest is invalid".to_string());
    }
    let manifest_bytes = fs::read(&manifest_path)
        .map_err(|error| format!("cannot read Core release manifest: {}", error))?;
    let manifest: CoreReleaseDocument = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("Core release manifest JSON is invalid: {}", error))?;
    if manifest.schema.name != CORE_RELEASE_SCHEMA_NAME
        || manifest.schema.version != CORE_RELEASE_SCHEMA_VERSION
        || manifest.platform.os != operating_system
        || manifest.platform.architecture != architecture
        || !valid_release_version(&manifest.release.version)
    {
        return Err("Core release manifest identity is invalid".to_string());
    }
    let files = manifest.files;
    let mut records = Vec::new();
    let mut expected_paths = BTreeSet::new();
    for value in files {
        let path = PathBuf::from(&value.path);
        validate_relative_path(&path)?;
        if !expected_paths.insert(path.clone()) {
            return Err(format!("Core release path is duplicated: {}", value.path));
        }
        if value.bytes == 0 || !matches!(value.mode, 0o644 | 0o755) || !valid_sha256(&value.sha256)
        {
            return Err("Core release file record is invalid".to_string());
        }
        let source = root.join(&path);
        verify_file(&source, value.bytes, &value.sha256)?;
        records.push(CoreFileRecord {
            bytes: value.bytes,
            mode: value.mode,
            path,
            sha256: value.sha256,
        });
    }
    require_native_binary_set(operating_system, &expected_paths)?;
    let actual_paths = source_file_paths(root)?;
    if actual_paths != expected_paths {
        return Err("Core release has unexpected or missing files".to_string());
    }
    let identity = format!("{:x}", Sha256::digest(&manifest_bytes));
    Ok(VerifiedCore {
        identity,
        manifest_bytes,
        records,
        version: manifest.release.version,
    })
}

// Requires the exact resident and public binary closure for one platform.
fn require_native_binary_set(
    operating_system: &str,
    paths: &BTreeSet<PathBuf>,
) -> Result<(), String> {
    let mut expected = BTreeSet::from([
        PathBuf::from("bin/li_benchmark_worker"),
        PathBuf::from("bin/li_letsinfer"),
        PathBuf::from("bin/li_core_setup"),
        PathBuf::from("bin/li_node"),
        PathBuf::from("bin/li_gateway"),
    ]);
    match operating_system {
        "linux" => {
            expected.insert(PathBuf::from("bin/li_watchdog"));
        }
        "macos" => {
            expected.insert(PathBuf::from("bin/li_hardware_macos_probe"));
        }
        _ => return Err("Core release platform is unsupported".to_string()),
    }
    if paths != &expected {
        return Err("Core release binary inventory is incomplete".to_string());
    }
    Ok(())
}

// Returns every regular source path except the source manifest itself.
fn source_file_paths(root: &Path) -> Result<BTreeSet<PathBuf>, String> {
    let mut pending = vec![root.to_path_buf()];
    let mut paths = BTreeSet::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)
            .map_err(|error| format!("cannot inspect source tree: {}", error))?
        {
            let entry =
                entry.map_err(|error| format!("source tree entry is invalid: {}", error))?;
            let path = entry.path();
            let details = fs::symlink_metadata(&path)
                .map_err(|error| format!("cannot inspect source path: {}", error))?;
            if details.file_type().is_symlink() {
                return Err(format!(
                    "source tree contains a symlink: {}",
                    path.display()
                ));
            }
            if details.is_dir() {
                pending.push(path);
            } else if details.is_file() {
                let relative = path
                    .strip_prefix(root)
                    .map_err(|_| "source path escaped its root".to_string())?
                    .to_path_buf();
                if relative != Path::new(CORE_RELEASE_MANIFEST) {
                    paths.insert(relative);
                }
            } else {
                return Err(format!(
                    "source tree path type is invalid: {}",
                    path.display()
                ));
            }
        }
    }
    Ok(paths)
}

// Installs one verified native Core release into its immutable content-addressed root.
fn install_core_release(
    source: &Path,
    home: &Path,
    version: &str,
    verified: &VerifiedCore,
) -> Result<PathBuf, String> {
    ensure_private_directory(home)?;
    let core = home.join("core");
    ensure_private_directory(&core)?;
    let versions_root = core.join("versions");
    ensure_version_directory(&versions_root)?;
    let versions = versions_root.join(version);
    ensure_version_directory(&versions)?;
    let destination = versions.join(&verified.identity);
    if destination.exists() {
        verify_installed_core(&destination, verified)?;
        return Ok(destination);
    }
    let staging = versions.join(format!(
        ".{}.li_installer_{}.tmp",
        verified.identity,
        std::process::id()
    ));
    if staging.exists() || staging.is_symlink() {
        return Err("Core installation staging path already exists".to_string());
    }
    fs::create_dir(&staging)
        .map_err(|error| format!("cannot create Core staging root: {}", error))?;
    let installation = (|| {
        for record in &verified.records {
            let destination_path = staging.join(&record.path);
            if let Some(parent) = destination_path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|error| format!("cannot create Core source directory: {}", error))?;
            }
            copy_file(
                &source.join(&record.path),
                &destination_path,
                installed_mode(record.mode),
            )?;
        }
        let manifest_path = staging.join(CORE_RELEASE_MANIFEST);
        write_new_file(&manifest_path, &verified.manifest_bytes, 0o444)?;
        set_child_directory_modes(&staging, 0o555)?;
        fs::rename(&staging, &destination)
            .map_err(|error| format!("cannot commit immutable Core: {}", error))?;
        set_mode(&destination, 0o555)
    })();
    if let Err(error) = installation {
        make_tree_writable(&staging);
        let _ = fs::remove_dir_all(&staging);
        return Err(error);
    }
    sync_directory(&versions)?;
    verify_installed_core(&destination, verified)?;
    Ok(destination)
}

// Verifies one previously installed immutable native Core identity.
fn verify_installed_core(root: &Path, verified: &VerifiedCore) -> Result<(), String> {
    let manifest = root.join(CORE_RELEASE_MANIFEST);
    let bytes = fs::read(&manifest)
        .map_err(|error| format!("cannot read installed source manifest: {}", error))?;
    if bytes != verified.manifest_bytes {
        return Err("installed Core manifest differs from release".to_string());
    }
    let actual = source_file_paths(root)?;
    let expected = verified
        .records
        .iter()
        .map(|record| record.path.clone())
        .collect::<BTreeSet<_>>();
    if actual != expected {
        return Err("installed Core has unexpected or missing files".to_string());
    }
    for record in &verified.records {
        let path = root.join(&record.path);
        verify_file(&path, record.bytes, &record.sha256)?;
        let mode = file_mode(&path)?;
        if mode != installed_mode(record.mode) {
            return Err(format!(
                "installed source mode is invalid: {}",
                record.path.display()
            ));
        }
    }
    Ok(())
}

// Activates one immutable native Core through a single atomic symlink replacement.
fn activate_core(home: &Path, destination: &Path) -> Result<(), String> {
    let core = home.join("core");
    atomic_symlink(&core.join("current"), destination)?;
    Ok(())
}

// Returns the exact prior atomic activation target or absence before installation.
fn current_activation(home: &Path) -> Result<Option<PathBuf>, String> {
    let current = home.join("core/current");
    match fs::symlink_metadata(&current) {
        Ok(metadata) if metadata.file_type().is_symlink() => fs::read_link(&current)
            .map(Some)
            .map_err(|error| format!("cannot read active Core link: {error}")),
        Ok(_) => Err("active Core path is not a managed symlink".to_string()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("cannot inspect active Core: {error}")),
    }
}

// Restores one exact prior activation only while the failed release still owns `current`.
fn restore_core_activation(
    home: &Path,
    failed: &Path,
    previous: Option<&PathBuf>,
) -> Result<(), String> {
    let current = home.join("core/current");
    let observed = current_activation(home)?;
    if observed.as_ref() == previous {
        return Ok(());
    }
    if observed.as_deref() != Some(failed) {
        return Err("active Core changed before installer rollback; recovery required".to_string());
    }
    match previous {
        Some(previous) => atomic_symlink(&current, previous),
        None => {
            fs::remove_file(&current)
                .map_err(|error| format!("cannot remove failed Core activation: {error}"))?;
            sync_directory(
                current
                    .parent()
                    .ok_or_else(|| "Core activation parent is unavailable".to_string())?,
            )
        }
    }
}

// Copies one verified source file through an exclusive durable destination.
fn copy_file(source: &Path, destination: &Path, mode: u32) -> Result<(), String> {
    let mut input = File::open(source)
        .map_err(|error| format!("cannot open source file {}: {}", source.display(), error))?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| {
            format!(
                "cannot create installed source {}: {}",
                destination.display(),
                error
            )
        })?;
    std::io::copy(&mut input, &mut output)
        .map_err(|error| format!("cannot copy installed source: {}", error))?;
    output
        .sync_all()
        .map_err(|error| format!("cannot persist installed source: {}", error))?;
    set_mode(destination, mode)
}

// Writes one exclusive durable file with its final immutable mode.
fn write_new_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("cannot create {}: {}", path.display(), error))?;
    output
        .write_all(bytes)
        .map_err(|error| format!("cannot write {}: {}", path.display(), error))?;
    output
        .sync_all()
        .map_err(|error| format!("cannot persist {}: {}", path.display(), error))?;
    set_mode(path, mode)
}

// Replaces one managed symlink through an atomic same-directory transition.
fn atomic_symlink(link: &Path, target: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        if link.exists() && !link.is_symlink() {
            return Err(format!(
                "refusing to replace a non-symlink: {}",
                link.display()
            ));
        }
        let parent = link
            .parent()
            .ok_or_else(|| "managed symlink has no parent".to_string())?;
        fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create symlink parent: {}", error))?;
        let temporary = parent.join(format!(
            ".{}.li_installer_{}.tmp",
            link.file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("link"),
            std::process::id()
        ));
        let _ = fs::remove_file(&temporary);
        symlink(target, &temporary)
            .map_err(|error| format!("cannot stage managed symlink: {}", error))?;
        fs::rename(&temporary, link)
            .map_err(|error| format!("cannot activate managed symlink: {}", error))?;
        sync_directory(parent)
    }
    #[cfg(not(unix))]
    {
        let _ = (link, target);
        Err("native installer requires Unix symlink support".to_string())
    }
}

// Returns whether one path is a safe nonempty relative archive path.
fn validate_relative_path(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!("relative path is unsafe: {}", path.display()));
    }
    Ok(())
}

// Verifies one regular source file's size and SHA-256 identity.
fn verify_file(path: &Path, expected_bytes: u64, expected_sha256: &str) -> Result<(), String> {
    let details = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect source file {}: {}", path.display(), error))?;
    if details.file_type().is_symlink() || !details.is_file() || details.len() != expected_bytes {
        return Err(format!(
            "source file metadata is invalid: {}",
            path.display()
        ));
    }
    let mut source = File::open(path)
        .map_err(|error| format!("cannot open source file {}: {}", path.display(), error))?;
    let mut digest = Sha256::new();
    let mut block = [0_u8; 1024 * 1024];
    loop {
        let count = source
            .read(&mut block)
            .map_err(|error| format!("cannot hash source file {}: {}", path.display(), error))?;
        if count == 0 {
            break;
        }
        digest.update(&block[..count]);
    }
    if format!("{:x}", digest.finalize()) != expected_sha256 {
        return Err(format!(
            "source file checksum is invalid: {}",
            path.display()
        ));
    }
    Ok(())
}

// Creates or verifies one private nonsymlink directory.
fn ensure_private_directory(path: &Path) -> Result<(), String> {
    if path.exists() {
        let details = fs::symlink_metadata(path)
            .map_err(|error| format!("cannot inspect private directory: {}", error))?;
        if details.file_type().is_symlink() || !details.is_dir() {
            return Err(format!(
                "private path is not a real directory: {}",
                path.display()
            ));
        }
    } else {
        fs::create_dir_all(path)
            .map_err(|error| format!("cannot create private directory: {}", error))?;
    }
    set_mode(path, 0o700)
}

// Creates or verifies one target-owner version directory through a stable no-follow descriptor.
fn ensure_version_directory(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(format!(
                "Core version path is not a real directory: {}",
                path.display()
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => fs::create_dir(path)
            .map_err(|error| format!("cannot create Core version directory: {error}"))?,
        Err(error) => {
            return Err(format!(
                "cannot inspect Core version directory {}: {error}",
                path.display()
            ));
        }
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| {
            format!(
                "cannot open Core version directory {}: {error}",
                path.display()
            )
        })?;
    let before = directory
        .metadata()
        .map_err(|error| format!("cannot inspect Core version directory: {error}"))?;
    if !before.is_dir()
        || before.uid() != unsafe { libc::geteuid() }
        || before.permissions().mode() & 0o7022 != 0
    {
        return Err("Core version directory ownership is unsafe".to_string());
    }
    directory
        .set_permissions(fs::Permissions::from_mode(0o755))
        .map_err(|error| format!("cannot set Core version directory mode: {error}"))?;
    directory
        .sync_all()
        .map_err(|error| format!("cannot persist Core version directory: {error}"))?;
    let after = directory
        .metadata()
        .map_err(|error| format!("cannot inspect Core version directory: {error}"))?;
    let observed = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot re-open Core version directory: {error}"))?;
    if !observed.is_dir()
        || observed.file_type().is_symlink()
        || after.dev() != before.dev()
        || after.ino() != before.ino()
        || observed.dev() != after.dev()
        || observed.ino() != after.ino()
        || after.uid() != before.uid()
        || observed.uid() != after.uid()
        || after.permissions().mode() & 0o7777 != 0o755
        || observed.permissions().mode() & 0o7777 != 0o755
    {
        return Err("Core version directory changed during preparation".to_string());
    }
    sync_directory(
        path.parent()
            .ok_or_else(|| "Core version directory parent is unavailable".to_string())?,
    )
}

// Applies one mode to every child directory under an immutable source root.
fn set_child_directory_modes(root: &Path, mode: u32) -> Result<(), String> {
    let mut directories = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    let mut index = 0;
    while index < pending.len() {
        let directory = pending[index].clone();
        for entry in fs::read_dir(&directory)
            .map_err(|error| format!("cannot inspect installed directories: {}", error))?
        {
            let path = entry
                .map_err(|error| format!("installed directory entry is invalid: {}", error))?
                .path();
            if path.is_dir() && !path.is_symlink() {
                pending.push(path.clone());
                directories.push(path);
            }
        }
        index += 1;
    }
    for directory in directories.into_iter().rev() {
        set_mode(&directory, mode)?;
    }
    Ok(())
}

// Restores writable modes so an incomplete private staging tree can be removed.
fn make_tree_writable(root: &Path) {
    let mut pending = vec![root.to_path_buf()];
    let mut index = 0;
    while index < pending.len() {
        let directory = pending[index].clone();
        let _ = set_mode(&directory, 0o755);
        if let Ok(entries) = fs::read_dir(&directory) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() && !path.is_symlink() {
                    pending.push(path);
                } else if path.is_file() {
                    let _ = set_mode(&path, 0o644);
                }
            }
        }
        index += 1;
    }
}

// Returns the immutable installed mode corresponding to one authored source mode.
fn installed_mode(source_mode: u32) -> u32 {
    if source_mode & 0o111 != 0 {
        0o555
    } else {
        0o444
    }
}

// Applies one exact Unix permission mode.
fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|error| format!("cannot set mode on {}: {}", path.display(), error))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Err("native installer requires Unix permission support".to_string())
    }
}

// Returns one exact Unix permission mode.
fn file_mode(path: &Path) -> Result<u32, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        Ok(fs::metadata(path)
            .map_err(|error| format!("cannot inspect mode for {}: {}", path.display(), error))?
            .permissions()
            .mode()
            & 0o777)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err("native installer requires Unix permission support".to_string())
    }
}

// Persists one directory after an atomic filesystem transition.
fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("cannot persist directory {}: {}", path.display(), error))
}

// Runs one exact command and returns its bounded output on success.
fn run_checked(command: &mut Command, context: &str) -> Result<Vec<u8>, String> {
    let output = command
        .output()
        .map_err(|error| format!("{}: {}", context, error))?;
    if output.stdout.len() > 4 * 1024 * 1024 || output.stderr.len() > 4 * 1024 * 1024 {
        return Err(format!("{}: diagnostics exceeded their boundary", context));
    }
    if !output.status.success() {
        let diagnostics = String::from_utf8_lossy(&output.stderr);
        let detail = diagnostics
            .lines()
            .find(|line| !line.trim().is_empty())
            .unwrap_or("command failed")
            .trim();
        return Err(format!("{}: {}", context, detail));
    }
    Ok(output.stdout)
}

// Returns whether one string is exactly a lowercase SHA-256 identity.
fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

// Returns whether one version is a release or numbered release candidate.
fn valid_release_version(value: &str) -> bool {
    let (release, candidate) = match value.split_once("-rc.") {
        Some((release, candidate)) => (release, Some(candidate)),
        None => (value, None),
    };
    let components = release.split('.').collect::<Vec<_>>();
    if components.len() != 3
        || components
            .iter()
            .any(|component| component.is_empty() || component.parse::<u64>().is_err())
    {
        return false;
    }
    match candidate {
        Some(candidate) => !candidate.is_empty() && candidate.parse::<u64>().is_ok(),
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Mutex;

    // Applies deterministic launcher mutations while recording the selected privilege boundary.
    #[derive(Default)]
    struct MockLauncherMutationProvider {
        calls: Mutex<Vec<String>>,
    }

    impl MockLauncherMutationProvider {
        // Returns an immutable snapshot of every mutation boundary reached by the test.
        fn calls(&self) -> Vec<String> {
            self.calls.lock().expect("launcher calls").clone()
        }

        // Records whether one mutation used the direct owner or system privilege boundary.
        fn record(&self, action: &str, privilege: Option<&Path>) {
            self.calls.lock().expect("launcher calls").push(format!(
                "{action}:{}",
                if privilege.is_some() {
                    "system"
                } else {
                    "user"
                }
            ));
        }
    }

    impl LauncherMutationProvider for MockLauncherMutationProvider {
        // Creates the real temporary fixture directory without executing a native command.
        fn prepare_directory(&self, root: &Path, privilege: Option<&Path>) -> Result<(), String> {
            self.record("prepare", privilege);
            fs::create_dir_all(root).map_err(|error| error.to_string())
        }

        // Replaces the real fixture symlink while recording the requested command boundary.
        fn replace(
            &self,
            launcher: &Path,
            target: &Path,
            privilege: Option<&Path>,
        ) -> Result<(), String> {
            self.record("replace", privilege);
            atomic_symlink(launcher, target)
        }

        // Removes the real fixture symlink while recording the requested command boundary.
        fn remove(&self, launcher: &Path, privilege: Option<&Path>) -> Result<(), String> {
            self.record("remove", privilege);
            fs::remove_file(launcher).map_err(|error| error.to_string())?;
            sync_directory(
                launcher
                    .parent()
                    .ok_or_else(|| "fixture launcher parent is unavailable".to_string())?,
            )
        }
    }

    // Selects one exact launcher failure or home-drift boundary for Core compensation tests.
    #[derive(Clone, Copy)]
    enum CoreInstallLauncherScenario {
        RejectBeforeMutation,
        FailRollbackAfterMutation,
        ReplaceHomeAfterActivation,
    }

    // Mutates one real fixture launcher while injecting only the selected lifecycle boundary.
    struct CoreInstallLauncherProvider {
        home: PathBuf,
        original_home: PathBuf,
        scenario: CoreInstallLauncherScenario,
    }

    impl LauncherMutationProvider for CoreInstallLauncherProvider {
        // Creates the real fixture launcher directory before the selected replacement boundary.
        fn prepare_directory(&self, root: &Path, _privilege: Option<&Path>) -> Result<(), String> {
            fs::create_dir_all(root).map_err(|error| error.to_string())
        }

        // Applies exactly enough real mutation to prove the selected compensation branch.
        fn replace(
            &self,
            launcher: &Path,
            target: &Path,
            _privilege: Option<&Path>,
        ) -> Result<(), String> {
            match self.scenario {
                CoreInstallLauncherScenario::RejectBeforeMutation => {
                    Err("injected launcher rejection".to_string())
                }
                CoreInstallLauncherScenario::FailRollbackAfterMutation => {
                    atomic_symlink(launcher, target)?;
                    Err("injected launcher publication uncertainty".to_string())
                }
                CoreInstallLauncherScenario::ReplaceHomeAfterActivation => {
                    atomic_symlink(launcher, target)?;
                    fs::rename(&self.home, &self.original_home)
                        .map_err(|error| error.to_string())?;
                    fs::create_dir(&self.home).map_err(|error| error.to_string())?;
                    fs::write(self.home.join("replacement-sentinel"), b"replacement")
                        .map_err(|error| error.to_string())
                }
            }
        }

        // Refuses only the ambiguous publication rollback and performs real safe compensation.
        fn remove(&self, launcher: &Path, _privilege: Option<&Path>) -> Result<(), String> {
            if matches!(
                self.scenario,
                CoreInstallLauncherScenario::FailRollbackAfterMutation
            ) {
                return Err("injected launcher rollback failure".to_string());
            }
            fs::remove_file(launcher).map_err(|error| error.to_string())
        }
    }

    // Returns one isolated launcher fixture root and removes an interrupted prior test tree.
    fn launcher_fixture(name: &str) -> PathBuf {
        let root = std::env::temp_dir()
            .canonicalize()
            .expect("canonical temporary root")
            .join(format!(
                "li_installer_launcher_{name}_test_{}",
                std::process::id()
            ));
        make_tree_writable(&root);
        let _ = fs::remove_dir_all(&root);
        root
    }

    // Accepts one native readlink line and rejects every empty or ambiguous target encoding.
    #[test]
    fn privileged_readlink_output_is_closed() {
        assert_eq!(
            decode_readlink_output(b"/Users/taimur/.local/bin/letsinfer\n".to_vec()),
            Ok(PathBuf::from("/Users/taimur/.local/bin/letsinfer"))
        );
        for output in [
            Vec::new(),
            b"\n".to_vec(),
            b"first\nsecond\n".to_vec(),
            b"first\rsecond\n".to_vec(),
            b"first\0second\n".to_vec(),
        ] {
            assert!(decode_readlink_output(output).is_err());
        }
    }

    // Removes a first-install launcher through both direct-user and mocked-system boundaries.
    #[test]
    fn launcher_rollback_removes_first_install_and_replays_on_both_boundaries() {
        for (name, privilege) in [
            ("user", None),
            ("system", Some(PathBuf::from("/usr/bin/sudo"))),
        ] {
            let root = launcher_fixture(name);
            let launcher_root = root.join("bin");
            let target = root.join("home/core/current/bin/li_letsinfer");
            let provider = MockLauncherMutationProvider::default();
            let receipt = activate_launcher(&provider, &launcher_root, &target, privilege.clone())
                .expect("launcher activation");
            assert_eq!(fs::read_link(&receipt.launcher).expect("launcher"), target);
            rollback_launcher(&provider, &receipt).expect("first rollback");
            assert_eq!(
                launcher_state(&receipt.launcher).expect("absence"),
                LauncherState::Absent
            );
            let before_replay = provider.calls();
            rollback_launcher(&provider, &receipt).expect("idempotent replay");
            assert_eq!(provider.calls(), before_replay);
            let boundary = if privilege.is_some() {
                "system"
            } else {
                "user"
            };
            assert_eq!(
                provider.calls(),
                [
                    format!("prepare:{boundary}"),
                    format!("replace:{boundary}"),
                    format!("remove:{boundary}"),
                ]
            );
            fs::remove_dir_all(&root).expect("fixture cleanup");
        }
    }

    // Restores exact relative and absolute prior targets without canonicalizing their bytes.
    #[test]
    fn launcher_rollback_restores_exact_relative_and_absolute_targets() {
        #[cfg(unix)]
        use std::os::unix::fs::symlink;

        for (name, previous) in [
            ("relative", PathBuf::from("../legacy/letsinfer")),
            (
                "absolute",
                PathBuf::from("/opt/legacy/letsinfer/bin/li_letsinfer"),
            ),
        ] {
            let root = launcher_fixture(name);
            let launcher_root = root.join("bin");
            fs::create_dir_all(&launcher_root).expect("launcher root");
            let launcher = launcher_root.join("letsinfer");
            symlink(&previous, &launcher).expect("prior launcher");
            let provider = MockLauncherMutationProvider::default();
            let receipt = activate_launcher(
                &provider,
                &launcher_root,
                &root.join("home/core/current/bin/li_letsinfer"),
                None,
            )
            .expect("launcher activation");
            rollback_launcher(&provider, &receipt).expect("launcher rollback");
            assert_eq!(fs::read_link(&launcher).expect("restored target"), previous);
            let before_replay = provider.calls();
            rollback_launcher(&provider, &receipt).expect("idempotent replay");
            assert_eq!(provider.calls(), before_replay);
            fs::remove_dir_all(&root).expect("fixture cleanup");
        }
    }

    // Preserves concurrent target drift and rejects unsafe regular-file launcher ownership.
    #[test]
    fn launcher_rollback_preserves_drift_and_refuses_non_symlink_state() {
        #[cfg(unix)]
        use std::os::unix::fs::symlink;

        let root = launcher_fixture("drift");
        let launcher_root = root.join("bin");
        let provider = MockLauncherMutationProvider::default();
        let receipt = activate_launcher(
            &provider,
            &launcher_root,
            &root.join("home/core/current/bin/li_letsinfer"),
            None,
        )
        .expect("launcher activation");
        fs::remove_file(&receipt.launcher).expect("remove installed launcher");
        let foreign = PathBuf::from("../concurrent/letsinfer");
        symlink(&foreign, &receipt.launcher).expect("concurrent launcher");
        let before_rollback = provider.calls();
        let error = rollback_launcher(&provider, &receipt).expect_err("drift must fail");
        assert!(error.contains("recovery required"));
        assert_eq!(
            fs::read_link(&receipt.launcher).expect("foreign target"),
            foreign
        );
        assert_eq!(provider.calls(), before_rollback);

        fs::remove_file(&receipt.launcher).expect("remove foreign launcher");
        fs::write(&receipt.launcher, b"foreign executable").expect("regular launcher");
        let original = fs::read(&receipt.launcher).expect("regular launcher bytes");
        assert!(activate_launcher(
            &provider,
            &launcher_root,
            &root.join("other/core/current/bin/li_letsinfer"),
            None,
        )
        .expect_err("non-symlink must fail")
        .message
        .contains("non-symlink"));
        assert_eq!(
            fs::read(&receipt.launcher).expect("preserved bytes"),
            original
        );
        make_tree_writable(&root);
        fs::remove_dir_all(&root).expect("fixture cleanup");
    }

    // Replays prior Core activation restoration and preserves concurrent current-link drift.
    #[test]
    fn core_activation_rollback_is_idempotent_and_drift_safe() {
        #[cfg(unix)]
        use std::os::unix::fs::symlink;

        let root = launcher_fixture("core_activation");
        let home = root.join("home");
        let core = home.join("core");
        fs::create_dir_all(&core).expect("Core root");
        let failed = root.join("versions/failed");
        let previous = PathBuf::from("versions/previous");
        symlink(&failed, core.join("current")).expect("failed activation");
        restore_core_activation(&home, &failed, Some(&previous)).expect("rollback");
        assert_eq!(
            fs::read_link(core.join("current")).expect("previous"),
            previous
        );
        restore_core_activation(&home, &failed, Some(&previous)).expect("replay");

        fs::remove_file(core.join("current")).expect("remove previous");
        let concurrent = PathBuf::from("versions/concurrent");
        symlink(&concurrent, core.join("current")).expect("concurrent activation");
        let error =
            restore_core_activation(&home, &failed, Some(&previous)).expect_err("drift must fail");
        assert!(error.contains("recovery required"));
        assert_eq!(
            fs::read_link(core.join("current")).expect("concurrent"),
            concurrent
        );
        fs::remove_dir_all(&root).expect("fixture cleanup");
    }

    // Persists bootstrap release trust once and accepts only an exact owner-only replay.
    #[test]
    fn installs_and_replays_exact_release_trust() {
        let root = std::env::temp_dir().join(format!(
            "li_installer_release_trust_replay_test_{}",
            std::process::id()
        ));
        make_tree_writable(&root);
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).expect("fixture root should be created");
        let source = root.join("allowed_signers");
        fs::write(
            &source,
            b"release namespaces=letsinfer-core ssh-ed25519 fixture\n",
        )
        .expect("release trust should be written");
        let home = root.join("home");

        let installed = install_release_trust(&source, &home).expect("trust should install");
        let replayed = install_release_trust(&source, &home).expect("trust should replay");

        assert_eq!(installed, replayed);
        assert_eq!(fs::read(&installed).unwrap(), fs::read(&source).unwrap());
        assert_eq!(file_mode(&installed).unwrap(), 0o600);
        make_tree_writable(&root);
        fs::remove_dir_all(&root).expect("fixture should be removed");
    }

    // Rejects divergent content and forged source or destination symlinks without replacement.
    #[test]
    fn rejects_divergent_or_forged_release_trust() {
        #[cfg(unix)]
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!(
            "li_installer_release_trust_rejection_test_{}",
            std::process::id()
        ));
        make_tree_writable(&root);
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).expect("fixture root should be created");
        let source = root.join("allowed_signers");
        fs::write(
            &source,
            b"release namespaces=letsinfer-core ssh-ed25519 first\n",
        )
        .expect("release trust should be written");
        let home = root.join("home");
        let installed = install_release_trust(&source, &home).expect("trust should install");
        let original = fs::read(&installed).expect("installed trust should be readable");

        fs::write(
            &source,
            b"release namespaces=letsinfer-core ssh-ed25519 second\n",
        )
        .expect("divergent trust should be written");
        assert!(install_release_trust(&source, &home).is_err());
        assert_eq!(fs::read(&installed).unwrap(), original);

        #[cfg(unix)]
        {
            let hard_link = root.join("release_trust_hard_link");
            fs::hard_link(&installed, &hard_link).expect("hard link should be created");
            fs::write(&source, &original).expect("original trust should be restored");
            assert!(install_release_trust(&source, &home).is_err());
            fs::remove_file(&hard_link).expect("hard link should be removed");

            let forged_source = root.join("forged_source");
            symlink(&source, &forged_source).expect("source symlink should be created");
            assert!(install_release_trust(&forged_source, &root.join("other_home")).is_err());

            fs::remove_file(&installed).expect("installed trust should be removed");
            symlink(&source, &installed).expect("destination symlink should be created");
            assert!(install_release_trust(&source, &home).is_err());
            assert!(installed.is_symlink());
        }
        make_tree_writable(&root);
        fs::remove_dir_all(&root).expect("fixture should be removed");
    }

    // Keeps every fresh Core layout mode compatible with update and prune under bootstrap umask.
    #[test]
    fn fresh_install_modes_match_update_and_prune_under_restrictive_umask() {
        const CHILD_ENVIRONMENT: &str = "LI_INSTALLER_CORE_LAYOUT_UMASK_CHILD";
        if std::env::var_os(CHILD_ENVIRONMENT).is_some() {
            use std::os::unix::fs::MetadataExt;

            let root = std::env::temp_dir().join(format!(
                "li_installer_core_layout_umask_test_{}",
                std::process::id()
            ));
            make_tree_writable(&root);
            let _ = fs::remove_dir_all(&root);
            let source = root.join("release");
            fs::create_dir_all(source.join("bin")).expect("source executable root");
            fs::create_dir_all(source.join("schemas")).expect("source data root");
            let executable = source.join("bin/li_node");
            let data = source.join("schemas/li_node.json");
            fs::write(&executable, b"native-node").expect("source executable");
            fs::write(&data, b"{}\n").expect("source data");
            let records = vec![
                CoreFileRecord {
                    bytes: fs::metadata(&executable)
                        .expect("executable metadata")
                        .len(),
                    mode: 0o755,
                    path: PathBuf::from("bin/li_node"),
                    sha256: format!(
                        "{:x}",
                        Sha256::digest(fs::read(&executable).expect("executable bytes"))
                    ),
                },
                CoreFileRecord {
                    bytes: fs::metadata(&data).expect("data metadata").len(),
                    mode: 0o644,
                    path: PathBuf::from("schemas/li_node.json"),
                    sha256: format!("{:x}", Sha256::digest(fs::read(&data).expect("data bytes"))),
                },
            ];
            let verified = VerifiedCore {
                identity: "a".repeat(64),
                manifest_bytes: b"exact manifest\n".to_vec(),
                records,
                version: "1.2.3".to_string(),
            };
            let home = root.join("home");
            let previous_umask = unsafe { libc::umask(0o077) };
            let installed = install_core_release(&source, &home, "1.2.3", &verified)
                .expect("fresh Core installation");
            unsafe { libc::umask(previous_umask) };

            let expected_modes = [
                (home.clone(), 0o700),
                (home.join("core"), 0o700),
                (home.join("core/versions"), 0o755),
                (home.join("core/versions/1.2.3"), 0o755),
                (installed.clone(), 0o555),
                (installed.join("bin"), 0o555),
                (installed.join("schemas"), 0o555),
                (installed.join("bin/li_node"), 0o555),
                (installed.join("schemas/li_node.json"), 0o444),
                (installed.join(CORE_RELEASE_MANIFEST), 0o444),
            ];
            let owner_user_id = unsafe { libc::geteuid() };
            for (path, mode) in expected_modes {
                let metadata = fs::symlink_metadata(&path).expect("installed path metadata");
                assert_eq!(metadata.uid(), owner_user_id, "owner: {}", path.display());
                assert_eq!(file_mode(&path).expect("installed path mode"), mode);
            }
            make_tree_writable(&root);
            fs::remove_dir_all(&root).expect("fixture cleanup");
            return;
        }
        let output = Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "li_installer_core_manager::tests::fresh_install_modes_match_update_and_prune_under_restrictive_umask",
                "--nocapture",
            ])
            .env(CHILD_ENVIRONMENT, "1")
            .output()
            .expect("restrictive-umask child");
        assert!(
            output.status.success(),
            "restrictive-umask child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Writes and verifies one complete native Core fixture for lifecycle tests.
    fn prepared_core_fixture(root: &Path) -> PreparedCore {
        let source = root.join("release");
        fs::create_dir_all(source.join("bin")).expect("source root should be created");
        let names = [
            "li_benchmark_worker",
            "li_letsinfer",
            "li_core_setup",
            "li_node",
            "li_gateway",
            "li_watchdog",
        ];
        let mut files = Vec::new();
        for name in names {
            let binary = source.join("bin").join(name);
            fs::write(&binary, b"native-core-binary").expect("binary should be written");
            set_mode(&binary, 0o755).expect("binary mode should be set");
            let content = fs::read(&binary).expect("binary should be readable");
            files.push(json!({
                "bytes": content.len(),
                "mode": 0o755,
                "path": format!("bin/{name}"),
                "sha256": format!("{:x}", Sha256::digest(&content))
            }));
        }
        let manifest = json!({
            "schema": {"name": CORE_RELEASE_SCHEMA_NAME, "version": CORE_RELEASE_SCHEMA_VERSION},
            "release": {"version": "1.2.3"},
            "platform": {"os": "linux", "architecture": "x86_64"},
            "files": files
        });
        let mut manifest_bytes = serde_json::to_vec(&manifest).expect("manifest should serialize");
        manifest_bytes.push(b'\n');
        fs::write(source.join(CORE_RELEASE_MANIFEST), manifest_bytes)
            .expect("manifest should be written");

        let verified =
            verify_core_release(&source, "linux", "x86_64").expect("release should verify");
        PreparedCore {
            release_root: source,
            version: verified.version.clone(),
            verified,
        }
    }

    // Installs and activates one verified immutable native Core fixture entirely in Rust.
    #[test]
    fn installs_immutable_native_core_release() {
        let root = std::env::temp_dir().join(format!(
            "li_installer_core_manager_test_{}",
            std::process::id()
        ));
        make_tree_writable(&root);
        let _ = fs::remove_dir_all(&root);
        let prepared = prepared_core_fixture(&root);
        let home = root.join("home");
        let installed =
            install_core_release(&prepared.release_root, &home, "1.2.3", &prepared.verified)
                .expect("release should install");
        activate_core(&home, &installed).expect("Core should activate");

        assert_eq!(
            home.join("core/current")
                .canonicalize()
                .expect("current should resolve"),
            installed
                .canonicalize()
                .expect("installed root should resolve")
        );
        assert_eq!(
            file_mode(&installed.join("bin/li_letsinfer")).unwrap(),
            0o555
        );
        make_tree_writable(&root);
        fs::remove_dir_all(&root).expect("fixture should be removed");
    }

    // Proves CoreManager consumes fresh-home authority on safe install failure and refuses drift.
    #[test]
    fn core_install_failure_cleanup_is_receipt_bound_and_drift_closed() {
        use std::os::unix::fs::DirBuilderExt;

        let root = std::env::temp_dir()
            .canonicalize()
            .expect("canonical temporary root")
            .join(format!(
                "li_installer_core_receipt_test_{}",
                std::process::id()
            ));
        make_tree_writable(&root);
        let _ = fs::remove_dir_all(&root);
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(&root).expect("receipt fixture root");
        let checksums = root.join("SHA256SUMS");
        fs::write(&checksums, format!("{}  fixture.tar.gz\n", "a".repeat(64)))
            .expect("fixture checksums");
        let release_manager = ReleaseManager::load(&checksums).expect("release manager");
        let download_manager = DownloadManager::new(
            PathBuf::from("/usr/bin/curl"),
            "file:///fixture".to_string(),
            true,
        );
        let prepared = || PreparedCore {
            release_root: root.join("release"),
            verified: VerifiedCore {
                identity: "b".repeat(64),
                manifest_bytes: b"fixture\n".to_vec(),
                records: Vec::new(),
                version: "1.2.3".to_string(),
            },
            version: "1.2.3".to_string(),
        };
        let arguments = |home: PathBuf| InstallerArguments {
            allow_insecure: true,
            checksums_file: checksums.clone(),
            control_address: crate::li_installer_arguments::ControlAddressSelection::Explicit(
                "127.0.0.1".to_string(),
            ),
            core_archive_name: "fixture.tar.gz".to_string(),
            curl_command: PathBuf::from("/usr/bin/curl"),
            id_command: PathBuf::from("/usr/bin/id"),
            letsinfer_home: home,
            launcher_root: root.join("launcher/bin"),
            progress_enabled: false,
            release_base: "file:///fixture".to_string(),
            release_allowed_signers_file: root.join("missing-allowed-signers"),
            release_version: "1.2.3".to_string(),
            repair_docker_access: false,
            run_setup: true,
            selected_platform: "linux-x86_64".to_string(),
            tar_command: PathBuf::from("/usr/bin/tar"),
            temporary_root: root.join("temporary"),
            user_install: true,
        };
        let facts = ProbeFacts::from_test_document(serde_json::json!({}));
        let owner_user_id = unsafe { libc::geteuid() };

        let fresh_home = root.join("fresh-home");
        let fresh_arguments = arguments(fresh_home.clone());
        let fresh_manager = CoreManager::new(&fresh_arguments, &download_manager, &release_manager);
        let fresh_receipt =
            SetupRootPreparation::claim(&fresh_home, owner_user_id).expect("fresh receipt");
        assert!(fresh_manager
            .install(prepared(), &facts, Some(fresh_receipt))
            .is_err());
        assert!(!fresh_home.exists());

        let drift_home = root.join("drift-home");
        let original_home = root.join("original-home");
        let drift_arguments = arguments(drift_home.clone());
        let drift_manager = CoreManager::new(&drift_arguments, &download_manager, &release_manager);
        let drift_receipt =
            SetupRootPreparation::claim(&drift_home, owner_user_id).expect("drift receipt");
        fs::rename(&drift_home, &original_home).expect("move claimed home");
        builder.create(&drift_home).expect("replacement home");
        fs::write(drift_home.join("sentinel"), b"replacement").expect("replacement sentinel");
        let error = match drift_manager.install(prepared(), &facts, Some(drift_receipt)) {
            Ok(_) => panic!("drifted install must fail"),
            Err(error) => error,
        };
        assert!(error.contains("changed before rollback"));
        assert_eq!(
            fs::read(drift_home.join("sentinel")).expect("replacement retained"),
            b"replacement"
        );
        assert!(original_home.is_dir());

        make_tree_writable(&root);
        fs::remove_dir_all(&root).expect("receipt fixture cleanup");
    }

    // Proves post-activation launcher failures compensate only when publication is unambiguous.
    #[test]
    fn core_install_launcher_compensation_preserves_only_recovery_required_state() {
        use std::os::unix::fs::DirBuilderExt;

        let root = launcher_fixture("core_install_compensation");
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(&root).expect("compensation fixture root");
        let checksums = root.join("SHA256SUMS");
        fs::write(&checksums, format!("{}  fixture.tar.gz\n", "a".repeat(64)))
            .expect("fixture checksums");
        let trust = root.join("release-allowed-signers");
        fs::write(
            &trust,
            b"release namespaces=letsinfer-core ssh-ed25519 fixture\n",
        )
        .expect("fixture release trust");
        let release_manager = ReleaseManager::load(&checksums).expect("release manager");
        let download_manager = DownloadManager::new(
            PathBuf::from("/usr/bin/curl"),
            "file:///fixture".to_string(),
            true,
        );
        let facts = ProbeFacts::from_test_document(serde_json::json!({}));
        let owner_user_id = unsafe { libc::geteuid() };

        for (name, scenario) in [
            (
                "safe-rejection",
                CoreInstallLauncherScenario::RejectBeforeMutation,
            ),
            (
                "ambiguous-publication",
                CoreInstallLauncherScenario::FailRollbackAfterMutation,
            ),
            (
                "home-drift",
                CoreInstallLauncherScenario::ReplaceHomeAfterActivation,
            ),
        ] {
            let scenario_root = root.join(name);
            builder
                .create(&scenario_root)
                .expect("scenario fixture root");
            let home = scenario_root.join("home");
            let original_home = scenario_root.join("original-home");
            let launcher_root = scenario_root.join("launcher/bin");
            let arguments = InstallerArguments {
                allow_insecure: true,
                checksums_file: checksums.clone(),
                control_address: crate::li_installer_arguments::ControlAddressSelection::Explicit(
                    "127.0.0.1".to_string(),
                ),
                core_archive_name: "fixture.tar.gz".to_string(),
                curl_command: PathBuf::from("/usr/bin/curl"),
                id_command: PathBuf::from("/usr/bin/id"),
                letsinfer_home: home.clone(),
                launcher_root: launcher_root.clone(),
                progress_enabled: false,
                release_base: "file:///fixture".to_string(),
                release_allowed_signers_file: trust.clone(),
                release_version: "1.2.3".to_string(),
                repair_docker_access: false,
                run_setup: true,
                selected_platform: "linux-x86_64".to_string(),
                tar_command: PathBuf::from("/usr/bin/tar"),
                temporary_root: scenario_root.join("temporary"),
                user_install: true,
            };
            let manager = CoreManager::new(&arguments, &download_manager, &release_manager);
            let preparation =
                SetupRootPreparation::claim(&home, owner_user_id).expect("fresh scenario receipt");
            let provider = CoreInstallLauncherProvider {
                home: home.clone(),
                original_home: original_home.clone(),
                scenario,
            };

            let error = match manager.install_with_launcher_provider(
                prepared_core_fixture(&scenario_root),
                &facts,
                Some(preparation),
                &provider,
            ) {
                Ok(_) => panic!("scenario must fail: {name}"),
                Err(error) => error,
            };
            let launcher = launcher_root.join("letsinfer");
            match scenario {
                CoreInstallLauncherScenario::RejectBeforeMutation => {
                    assert!(error.contains("injected launcher rejection"));
                    assert!(!home.exists());
                    assert_eq!(
                        launcher_state(&launcher).expect("launcher state"),
                        LauncherState::Absent
                    );
                }
                CoreInstallLauncherScenario::FailRollbackAfterMutation => {
                    assert!(error.contains("launcher recovery is required"));
                    assert!(home.join("core/current").is_symlink());
                    assert!(launcher.is_symlink());
                }
                CoreInstallLauncherScenario::ReplaceHomeAfterActivation => {
                    assert!(error.contains("preserved for exact recovery"));
                    assert_eq!(
                        fs::read(home.join("replacement-sentinel")).expect("replacement retained"),
                        b"replacement"
                    );
                    assert!(original_home.join("core/current").is_symlink());
                    assert_eq!(
                        launcher_state(&launcher).expect("launcher state"),
                        LauncherState::Absent
                    );
                }
            }
        }

        make_tree_writable(&root);
        fs::remove_dir_all(&root).expect("compensation fixture cleanup");
    }

    // Rejects absolute paths and parent traversal before archive extraction.
    #[test]
    fn rejects_unsafe_source_paths() {
        assert!(validate_relative_path(Path::new("../escape")).is_err());
        assert!(validate_relative_path(Path::new("/absolute")).is_err());
        assert!(validate_relative_path(Path::new("core/cli.py")).is_ok());
    }

    // Accepts each exact platform closure and rejects missing, extra, or cross-platform binaries.
    #[test]
    fn native_binary_inventory_mutation_table_is_closed() {
        let common = BTreeSet::from([
            PathBuf::from("bin/li_benchmark_worker"),
            PathBuf::from("bin/li_core_setup"),
            PathBuf::from("bin/li_gateway"),
            PathBuf::from("bin/li_letsinfer"),
            PathBuf::from("bin/li_node"),
        ]);
        for (operating_system, platform_binary) in [
            ("linux", "bin/li_watchdog"),
            ("macos", "bin/li_hardware_macos_probe"),
        ] {
            let mut valid = common.clone();
            valid.insert(PathBuf::from(platform_binary));
            let mut missing = valid.clone();
            missing.remove(Path::new("bin/li_benchmark_worker"));
            let mut extra = valid.clone();
            extra.insert(PathBuf::from("bin/li_foreign"));
            let mut cross_platform = common.clone();
            cross_platform.insert(PathBuf::from(if operating_system == "linux" {
                "bin/li_hardware_macos_probe"
            } else {
                "bin/li_watchdog"
            }));
            for (name, inventory, accepted) in [
                ("valid", valid, true),
                ("missing_worker", missing, false),
                ("extra", extra, false),
                ("cross_platform", cross_platform, false),
            ] {
                assert_eq!(
                    require_native_binary_set(operating_system, &inventory).is_ok(),
                    accepted,
                    "{operating_system}:{name}"
                );
            }
        }
    }
}
