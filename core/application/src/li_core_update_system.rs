// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;
use std::sync::Arc;

use li_core_update_manager::{
    CoreUpdateError, CoreUpdateReadinessPolicy, CoreUpdateReleasePlatform,
    CoreUpdateServiceContext, CurlCoreUpdateReleaseTransport, ProcessCoreUpdateCommandRunner,
    SshKeygenCoreUpdateSignatureVerifier,
};
use li_database::DatabaseManager;
use li_node_manager::{DatabaseCoreUpdateStore, NodeCoreUpdateCoordinator, NodeManager};

use crate::{
    compose_core_update_coordinator, ApplicationCoreUpdateAdmissionProvider,
    ApplicationCoreUpdateConfiguration, ApplicationCoreUpdatePorts,
    ApplicationCoreUpdatePruneReferenceProvider, ApplicationCoreUpdateServiceControl,
    CoreProcessPlatform, SystemCoreNativeServiceCommandRunner, SystemCoreNativeServiceIo,
    SystemCoreNativeServiceSupervisor, SystemCoreSetupExecutionLockProvider,
};

// Carries every exact filesystem, trust, command, platform, and timing input for Core updates.
pub struct ApplicationSystemCoreUpdateConfiguration {
    release_platform: CoreUpdateReleasePlatform,
    service_context: CoreUpdateServiceContext,
    letsinfer_home: PathBuf,
    home_directory: PathBuf,
    setup_state_directory: PathBuf,
    configuration_root: PathBuf,
    owner_user_id: u32,
    curl_command: PathBuf,
    ssh_keygen_command: PathBuf,
    allowed_signers_file: PathBuf,
    supervisor_command: PathBuf,
    readiness: CoreUpdateReadinessPolicy,
}

impl ApplicationSystemCoreUpdateConfiguration {
    // Creates one closed production contract without path discovery or platform defaults.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        release_platform: CoreUpdateReleasePlatform,
        service_context: CoreUpdateServiceContext,
        letsinfer_home: PathBuf,
        home_directory: PathBuf,
        setup_state_directory: PathBuf,
        configuration_root: PathBuf,
        owner_user_id: u32,
        curl_command: PathBuf,
        ssh_keygen_command: PathBuf,
        allowed_signers_file: PathBuf,
        supervisor_command: PathBuf,
        readiness: CoreUpdateReadinessPolicy,
    ) -> Result<Self, CoreUpdateError> {
        ApplicationCoreUpdateConfiguration::new(
            release_platform,
            service_context,
            letsinfer_home.clone(),
            owner_user_id,
            readiness,
        )?;
        Ok(Self {
            release_platform,
            service_context,
            letsinfer_home,
            home_directory,
            setup_state_directory,
            configuration_root,
            owner_user_id,
            curl_command,
            ssh_keygen_command,
            allowed_signers_file,
            supervisor_command,
            readiness,
        })
    }
}

// Composes every real Core-update authority into the resident Node API capability.
pub fn compose_system_core_update(
    configuration: ApplicationSystemCoreUpdateConfiguration,
    database: Arc<DatabaseManager>,
    node: Arc<NodeManager>,
) -> Result<NodeCoreUpdateCoordinator, CoreUpdateError> {
    let process_platform = process_platform(configuration.release_platform);
    let command_runner = Arc::new(ProcessCoreUpdateCommandRunner);
    let release_transport = Arc::new(CurlCoreUpdateReleaseTransport::new(
        configuration.curl_command,
        command_runner.clone(),
    )?);
    let signature_verifier = Arc::new(SshKeygenCoreUpdateSignatureVerifier::new(
        configuration.ssh_keygen_command,
        configuration.allowed_signers_file,
        command_runner,
    )?);
    let updates = Arc::new(DatabaseCoreUpdateStore::new(database.clone()));
    let admission = Arc::new(ApplicationCoreUpdateAdmissionProvider::new(
        Arc::new(
            SystemCoreSetupExecutionLockProvider::new(
                configuration.setup_state_directory,
                configuration.owner_user_id,
            )
            .map_err(|_| {
                CoreUpdateError::provider("admission", "global update lock is unavailable")
            })?,
        ),
        node,
        updates.clone(),
    ));
    let supervisor = Arc::new(SystemCoreNativeServiceSupervisor::new(
        process_platform,
        configuration.home_directory,
        configuration.owner_user_id,
        configuration.supervisor_command,
        Arc::new(SystemCoreNativeServiceCommandRunner),
        Arc::new(SystemCoreNativeServiceIo),
    )?);
    let service_handoff = Arc::new(ApplicationCoreUpdateServiceControl::new(
        configuration.service_context,
        configuration.letsinfer_home.clone(),
        configuration.configuration_root,
        supervisor,
    )?);
    let prune_references = Arc::new(ApplicationCoreUpdatePruneReferenceProvider::new(updates));
    compose_core_update_coordinator(
        ApplicationCoreUpdateConfiguration::new(
            configuration.release_platform,
            configuration.service_context,
            configuration.letsinfer_home,
            configuration.owner_user_id,
            configuration.readiness,
        )?,
        ApplicationCoreUpdatePorts::new(
            Some(database),
            Some(admission),
            Some(release_transport),
            Some(signature_verifier),
            Some(service_handoff),
            Some(prune_references),
        ),
    )
}

// Maps one closed release target to the native supervisor family compiled into Core.
const fn process_platform(platform: CoreUpdateReleasePlatform) -> CoreProcessPlatform {
    match platform {
        CoreUpdateReleasePlatform::LinuxArm64 | CoreUpdateReleasePlatform::LinuxX86_64 => {
            CoreProcessPlatform::Linux
        }
        CoreUpdateReleasePlatform::MacosArm64 => CoreProcessPlatform::Macos,
    }
}
