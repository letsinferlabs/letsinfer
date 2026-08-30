// SPDX-License-Identifier: AGPL-3.0-only

pub mod li_installer_arguments;
pub mod li_installer_core_manager;
pub mod li_installer_dependency_manager;
pub mod li_installer_display_manager;
pub mod li_installer_download_manager;
pub mod li_installer_event;
pub mod li_installer_linux_provider;
pub mod li_installer_macos_provider;
pub mod li_installer_probe_manager;
pub mod li_installer_release_manager;
pub mod li_installer_service_manager;

pub const INSTALLATION_PROBE_SCHEMA_NAME: &str = "letsinfer.installer.installation-probe";
pub const INSTALLATION_PROBE_SCHEMA_VERSION: u64 = 1;

use std::fs;
use std::path::PathBuf;

use li_installer_arguments::InstallerArguments;
use li_installer_core_manager::CoreManager;
use li_installer_dependency_manager::{manage, DependencyManagerResult, ManagerMode};
use li_installer_display_manager::DisplayManager;
use li_installer_download_manager::DownloadManager;
use li_installer_event::InstallerEvent;
use li_installer_probe_manager::ProbeManager;
use li_installer_release_manager::ReleaseManager;
use li_installer_service_manager::{ServiceManager, ServiceSetupError};

// Runs the complete native installation lifecycle after the shell bootstrap.
pub fn run(arguments: &InstallerArguments, display: &mut DisplayManager) -> Result<(), String> {
    let _temporary_root = TemporaryRoot::new(arguments.temporary_root.clone());
    let release_manager = ReleaseManager::load(&arguments.checksums_file)?;
    let download_manager = DownloadManager::new(
        arguments.curl_command.clone(),
        arguments.release_base.clone(),
        arguments.allow_insecure,
    );
    let probe_manager = ProbeManager::new(arguments)?;

    display.present(InstallerEvent::InspectingSystem);
    let initial = probe_manager.observe("initial")?;
    let service_manager = ServiceManager::new(arguments);
    service_manager.preflight_privileges(&initial)?;
    let final_facts = if !arguments.run_setup {
        initial
    } else {
        display.present(InstallerEvent::InstallingDependencies);
        let dependency_result = manage(
            ManagerMode::Apply,
            initial.path(),
            probe_manager.id_command(),
        )?;
        if dependency_result == DependencyManagerResult::Installed {
            display.present(InstallerEvent::VerifyingDependencies);
            let observed = probe_manager.observe("verified")?;
            if manage(
                ManagerMode::Verify,
                observed.path(),
                probe_manager.id_command(),
            )? != DependencyManagerResult::Unchanged
            {
                return Err("dependency verification produced an invalid result".to_string());
            }
            observed
        } else {
            if manage(
                ManagerMode::Verify,
                initial.path(),
                probe_manager.id_command(),
            )? != DependencyManagerResult::Unchanged
            {
                return Err("dependency verification produced an invalid result".to_string());
            }
            initial
        }
    };
    if arguments.run_setup && final_facts.status() != Some("ready") {
        return Err(format!(
            "installation probe is not ready: {}",
            final_facts.status().unwrap_or("unknown")
        ));
    }

    let docker_group = service_manager.prepare(&final_facts, display)?;
    display.present(InstallerEvent::DownloadingCore);
    let core_manager = CoreManager::new(arguments, &download_manager, &release_manager);
    let downloaded_core = core_manager.download()?;
    display.present(InstallerEvent::VerifyingCore);
    let prepared_core = core_manager.prepare(downloaded_core)?;
    display.present(InstallerEvent::InstallingCore);
    let setup_root_preparation = service_manager.prepare_setup_root()?;
    let mut core = core_manager.install(prepared_core, &final_facts, setup_root_preparation)?;
    display.present(InstallerEvent::InitializingServices);
    let setup = match service_manager.setup(&final_facts, &mut core, docker_group.as_deref()) {
        Ok(setup) => setup,
        Err(error) => {
            return resolve_setup_failure(
                error,
                &mut core,
                |installed| core_manager.rollback_activation(installed),
                |installed| core_manager.cleanup_failed_setup_home(installed),
            );
        }
    };
    let details = setup
        .as_ref()
        .map(|value| value.details())
        .unwrap_or_default();
    display.completion(
        &core.version,
        &arguments.selected_platform,
        setup.is_some(),
        &details,
    );
    Ok(())
}

// Rolls back activation only when the typed setup result proves that reversal is safe.
fn resolve_setup_failure<T>(
    error: ServiceSetupError,
    state: &mut T,
    rollback_activation: impl FnOnce(&T) -> Result<(), String>,
    cleanup_created_home: impl FnOnce(&mut T) -> Result<(), String>,
) -> Result<(), String> {
    let may_rollback_activation = error.may_rollback_activation();
    let message = error.into_message();
    if !may_rollback_activation {
        return Err(format!(
            "{message}; installed Core activation was preserved for exact recovery"
        ));
    }
    rollback_activation(state)
        .map_err(|rollback| format!("{message}; Core activation rollback failed: {rollback}"))?;
    cleanup_created_home(state)
        .map_err(|rollback| format!("{message}; Core fresh-home rollback failed: {rollback}"))?;
    Err(message)
}

// Owns cleanup of the exact temporary root inherited from the shell bootstrap.
struct TemporaryRoot {
    path: PathBuf,
}

impl TemporaryRoot {
    // Creates a cleanup owner for one already-validated temporary root.
    fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl Drop for TemporaryRoot {
    // Removes only the exact temporary root after native installation ends.
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    // Proves only the explicit safe class invokes Core activation rollback.
    #[test]
    fn setup_failure_rolls_back_only_the_safe_machine_class() {
        let rollback_called = Cell::new(false);
        let order = RefCell::new(Vec::new());
        let mut authority = Some("fresh-home-authority");
        let safe = resolve_setup_failure(
            ServiceSetupError::SafeToRollback("safe setup rejection".to_string()),
            &mut authority,
            |_| {
                rollback_called.set(true);
                order.borrow_mut().push("activation");
                Ok(())
            },
            |state| {
                order.borrow_mut().push("fresh-home");
                *state = None;
                Ok(())
            },
        );
        assert_eq!(safe, Err("safe setup rejection".to_string()));
        assert!(rollback_called.get());
        assert_eq!(*order.borrow(), ["activation", "fresh-home"]);
        assert_eq!(authority, None);

        rollback_called.set(false);
        order.borrow_mut().clear();
        authority = Some("fresh-home-authority");
        let recovery = resolve_setup_failure(
            ServiceSetupError::RecoveryRequired("ambiguous setup outcome".to_string()),
            &mut authority,
            |_| {
                rollback_called.set(true);
                Ok(())
            },
            |state| {
                *state = None;
                Ok(())
            },
        );
        assert_eq!(
            recovery,
            Err(
                "ambiguous setup outcome; installed Core activation was preserved for exact recovery"
                    .to_string()
            )
        );
        assert!(!rollback_called.get());
        assert!(order.borrow().is_empty());
        assert_eq!(authority, Some("fresh-home-authority"));
    }

    // Preserves both the setup and activation diagnostics when a safe rollback itself fails.
    #[test]
    fn setup_failure_preserves_a_failed_activation_rollback() {
        assert_eq!(
            resolve_setup_failure(
                ServiceSetupError::SafeToRollback("safe setup rejection".to_string()),
                &mut (),
                |_| Err("injected rollback failure".to_string()),
                |_| panic!("fresh-home cleanup must follow successful activation rollback"),
            ),
            Err(
                "safe setup rejection; Core activation rollback failed: injected rollback failure"
                    .to_string()
            )
        );
    }
}
