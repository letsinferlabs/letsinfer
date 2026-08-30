// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;
use std::sync::Arc;

use li_core_update_manager::{
    CoreUpdateAdmissionProvider, CoreUpdateArtifactProvider, CoreUpdateError,
    CoreUpdatePruneReferenceProvider, CoreUpdateReadinessPolicy, CoreUpdateReleasePlatform,
    CoreUpdateReleaseTransport, CoreUpdateServiceContext, CoreUpdateServiceControl,
    CoreUpdateServicePlatform, CoreUpdateSignatureVerifier, FilesystemCoreUpdateArtifactIo,
    FilesystemCoreUpdateArtifactProvider, FilesystemCoreUpdateCandidateFilesystem,
    FilesystemCoreUpdatePruneIo, GithubCoreUpdateCandidateInstaller,
    PlatformCoreUpdateServiceProvider, ReferenceAwareCoreUpdatePruneProvider,
    SystemCoreUpdateReadinessClock,
};
use li_database::DatabaseManager;
use li_node_manager::{
    ArtifactNodeCoreUpdateAvailabilityProvider, DatabaseCoreUpdateServiceSnapshotStore,
    DatabaseCoreUpdateStore, NodeCoreUpdateCoordinator,
};

// Supplies every authority that production update composition cannot infer or replace.
pub struct ApplicationCoreUpdatePorts {
    database: Option<Arc<DatabaseManager>>,
    admission: Option<Arc<dyn CoreUpdateAdmissionProvider>>,
    release_transport: Option<Arc<dyn CoreUpdateReleaseTransport>>,
    signature_verifier: Option<Arc<dyn CoreUpdateSignatureVerifier>>,
    service_handoff: Option<Arc<dyn CoreUpdateServiceControl>>,
    prune_references: Option<Arc<dyn CoreUpdatePruneReferenceProvider>>,
}

impl ApplicationCoreUpdatePorts {
    // Creates one explicit port set without silently manufacturing a missing authority.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        database: Option<Arc<DatabaseManager>>,
        admission: Option<Arc<dyn CoreUpdateAdmissionProvider>>,
        release_transport: Option<Arc<dyn CoreUpdateReleaseTransport>>,
        signature_verifier: Option<Arc<dyn CoreUpdateSignatureVerifier>>,
        service_handoff: Option<Arc<dyn CoreUpdateServiceControl>>,
        prune_references: Option<Arc<dyn CoreUpdatePruneReferenceProvider>>,
    ) -> Self {
        Self {
            database,
            admission,
            release_transport,
            signature_verifier,
            service_handoff,
            prune_references,
        }
    }
}

// Binds immutable filesystem, signed release, service, journal, and prune policy inputs.
pub struct ApplicationCoreUpdateConfiguration {
    release_platform: CoreUpdateReleasePlatform,
    service_context: CoreUpdateServiceContext,
    letsinfer_home: PathBuf,
    owner_user_id: u32,
    readiness: CoreUpdateReadinessPolicy,
}

impl ApplicationCoreUpdateConfiguration {
    // Creates one exact platform and owner-bound production update configuration.
    pub fn new(
        release_platform: CoreUpdateReleasePlatform,
        service_context: CoreUpdateServiceContext,
        letsinfer_home: PathBuf,
        owner_user_id: u32,
        readiness: CoreUpdateReadinessPolicy,
    ) -> Result<Self, CoreUpdateError> {
        if release_service_platform(release_platform) != service_context.platform() {
            return Err(composition_error(
                "release platform differs from the resident service platform",
            ));
        }
        Ok(Self {
            release_platform,
            service_context,
            letsinfer_home,
            owner_user_id,
            readiness,
        })
    }
}

// Composes the production CoreUpdateManager only from complete explicit authorities.
pub fn compose_core_update_manager(
    configuration: ApplicationCoreUpdateConfiguration,
    ports: ApplicationCoreUpdatePorts,
) -> Result<li_core_update_manager::CoreUpdateManager, CoreUpdateError> {
    compose_core_update_parts(configuration, ports).map(|(manager, _)| manager)
}

// Composes mutation and signed read-only availability over one shared artifact authority.
pub fn compose_core_update_coordinator(
    configuration: ApplicationCoreUpdateConfiguration,
    ports: ApplicationCoreUpdatePorts,
) -> Result<NodeCoreUpdateCoordinator, CoreUpdateError> {
    let (manager, artifacts) = compose_core_update_parts(configuration, ports)?;
    Ok(NodeCoreUpdateCoordinator::new(
        Arc::new(manager),
        Arc::new(ArtifactNodeCoreUpdateAvailabilityProvider::new(artifacts)),
    ))
}

// Builds the complete manager and returns the same signed artifact authority for availability.
fn compose_core_update_parts(
    configuration: ApplicationCoreUpdateConfiguration,
    ports: ApplicationCoreUpdatePorts,
) -> Result<
    (
        li_core_update_manager::CoreUpdateManager,
        Arc<dyn CoreUpdateArtifactProvider>,
    ),
    CoreUpdateError,
> {
    let database = require_port(ports.database, "database authority is unavailable")?;
    let admission = require_port(
        ports.admission,
        "global update lease authority is unavailable",
    )?;
    let release_transport = require_port(
        ports.release_transport,
        "signed release transport is unavailable",
    )?;
    let signature_verifier = require_port(
        ports.signature_verifier,
        "release signature trust is unavailable",
    )?;
    let service_handoff = require_port(
        ports.service_handoff,
        "active-service cutover authority is unavailable",
    )?;
    let prune_references = require_port(
        ports.prune_references,
        "update prune-reference authority is unavailable",
    )?;

    let artifact_io = Arc::new(FilesystemCoreUpdateArtifactIo::new(
        configuration.owner_user_id,
    ));
    let candidate_filesystem = Arc::new(FilesystemCoreUpdateCandidateFilesystem::new(
        configuration.owner_user_id,
    ));
    let candidate_installer = Arc::new(GithubCoreUpdateCandidateInstaller::new(
        configuration.release_platform,
        release_transport,
        signature_verifier,
        candidate_filesystem,
    ));
    let artifacts: Arc<dyn CoreUpdateArtifactProvider> =
        Arc::new(FilesystemCoreUpdateArtifactProvider::new(
            configuration.letsinfer_home.clone(),
            artifact_io.clone(),
            candidate_installer,
        )?);
    if service_handoff.context()? != configuration.service_context {
        return Err(composition_error(
            "active-service cutover context differs from update configuration",
        ));
    }
    let service_snapshots = Arc::new(DatabaseCoreUpdateServiceSnapshotStore::new(
        database.clone(),
    ));
    let services = Arc::new(PlatformCoreUpdateServiceProvider::new(
        service_snapshots,
        service_handoff,
    ));
    let pruner = Arc::new(ReferenceAwareCoreUpdatePruneProvider::new(
        configuration.letsinfer_home,
        artifact_io,
        Arc::new(FilesystemCoreUpdatePruneIo::new(
            configuration.owner_user_id,
        )),
        prune_references,
    )?);
    let manager = li_core_update_manager::CoreUpdateManager::new(
        Arc::new(DatabaseCoreUpdateStore::new(database)),
        admission,
        artifacts.clone(),
        services,
        pruner,
        Arc::new(SystemCoreUpdateReadinessClock::new()),
        configuration.readiness,
    );
    Ok((manager, artifacts))
}

// Requires one external authority without choosing an unsafe fallback implementation.
fn require_port<Value>(
    port: Option<Value>,
    reason: &'static str,
) -> Result<Value, CoreUpdateError> {
    port.ok_or_else(|| composition_error(reason))
}

// Maps one release archive family to its exact resident service platform.
const fn release_service_platform(
    platform: CoreUpdateReleasePlatform,
) -> CoreUpdateServicePlatform {
    match platform {
        CoreUpdateReleasePlatform::LinuxArm64 | CoreUpdateReleasePlatform::LinuxX86_64 => {
            CoreUpdateServicePlatform::Linux
        }
        CoreUpdateReleasePlatform::MacosArm64 => CoreUpdateServicePlatform::Macos,
    }
}

// Creates one stable redacted production-composition failure.
fn composition_error(reason: &'static str) -> CoreUpdateError {
    CoreUpdateError::provider("production composition", reason)
}
