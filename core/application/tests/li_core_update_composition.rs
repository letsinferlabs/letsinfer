// SPDX-License-Identifier: AGPL-3.0-only

use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use li_core_application::{
    compose_core_update_manager, compose_system_core_update, ApplicationCoreUpdateConfiguration,
    ApplicationCoreUpdatePorts, ApplicationSystemCoreUpdateConfiguration,
};
use li_core_interface::{
    DisplayName, EntityTimestamps, InstallationId, MachineId, Node, NodeAddress, NodeId,
    NodeIdentity, NodeRole, NodeState, Sha256Digest, UnixMilliseconds,
};
use li_core_update_manager::{
    CoreInstallation, CoreUpdateAdmissionLease, CoreUpdateAdmissionProvider, CoreUpdateError,
    CoreUpdateNodeRole, CoreUpdatePruneReferenceProvider, CoreUpdatePruneReferences,
    CoreUpdateReadinessPolicy, CoreUpdateReleasePlatform, CoreUpdateReleaseTransport,
    CoreUpdateResidentService, CoreUpdateServiceContext, CoreUpdateServiceControl,
    CoreUpdateServiceMode, CoreUpdateServicePlatform, CoreUpdateServiceState,
    CoreUpdateSignatureVerifier,
};
use li_database::{DatabaseConfiguration, DatabaseManager};
use li_node_manager::NodeManager;

// Holds one inert global update lease for composition-only tests.
struct AdmissionLeaseMock;

impl CoreUpdateAdmissionLease for AdmissionLeaseMock {}

// Supplies the explicit global admission authority without touching external state.
struct AdmissionMock;

impl CoreUpdateAdmissionProvider for AdmissionMock {
    // Acquires one inert lease because composition tests never execute an update.
    fn acquire(
        &self,
        _update_id: &Sha256Digest,
    ) -> Result<Box<dyn CoreUpdateAdmissionLease>, CoreUpdateError> {
        Ok(Box::new(AdmissionLeaseMock))
    }
}

// Keeps release transport explicit while refusing accidental network access in tests.
struct TransportMock;

impl CoreUpdateReleaseTransport for TransportMock {
    // Fails if construction unexpectedly attempts a release download.
    fn download(
        &self,
        _url: &str,
        _destination: &Path,
        _maximum_bytes: u64,
    ) -> Result<(), CoreUpdateError> {
        Err(CoreUpdateError::provider(
            "test transport",
            "unexpected release download",
        ))
    }
}

// Keeps release trust explicit while refusing accidental verification in tests.
struct SignatureMock;

impl CoreUpdateSignatureVerifier for SignatureMock {
    // Fails if construction unexpectedly attempts signature verification.
    fn verify(&self, _message: &[u8], _signature: &Path) -> Result<(), CoreUpdateError> {
        Err(CoreUpdateError::provider(
            "test signature",
            "unexpected signature verification",
        ))
    }
}

// Keeps active-service handoff explicit without allowing construction-time mutation.
struct ServiceHandoffMock {
    context: CoreUpdateServiceContext,
}

impl CoreUpdateServiceControl for ServiceHandoffMock {
    // Returns the exact immutable service context owned by this handoff authority.
    fn context(&self) -> Result<CoreUpdateServiceContext, CoreUpdateError> {
        Ok(self.context)
    }

    // Fails if construction unexpectedly observes a resident service.
    fn observe_service(
        &self,
        _service: CoreUpdateResidentService,
    ) -> Result<CoreUpdateServiceState, CoreUpdateError> {
        Err(CoreUpdateError::provider(
            "test service handoff",
            "unexpected service observation",
        ))
    }

    // Fails if construction unexpectedly rebinds a resident service.
    fn rebind_service(
        &self,
        _service: CoreUpdateResidentService,
        _mode: CoreUpdateServiceMode,
        _installation: &CoreInstallation,
        _active: bool,
    ) -> Result<(), CoreUpdateError> {
        Err(CoreUpdateError::provider(
            "test service handoff",
            "unexpected service rebind",
        ))
    }

    // Fails if construction unexpectedly checks resident readiness.
    fn service_is_ready(
        &self,
        _service: CoreUpdateResidentService,
        _mode: CoreUpdateServiceMode,
        _installation: Option<&CoreInstallation>,
        _active: bool,
    ) -> Result<bool, CoreUpdateError> {
        Err(CoreUpdateError::provider(
            "test service handoff",
            "unexpected readiness observation",
        ))
    }

    // Fails if construction unexpectedly restores a resident service.
    fn restore_service(
        &self,
        _state: &CoreUpdateServiceState,
        _installation: &CoreInstallation,
    ) -> Result<(), CoreUpdateError> {
        Err(CoreUpdateError::provider(
            "test service handoff",
            "unexpected service restoration",
        ))
    }
}

// Keeps prune-reference authority explicit without inventing an empty reference set.
struct ReferenceMock;

impl CoreUpdatePruneReferenceProvider for ReferenceMock {
    // Fails if construction unexpectedly reads mutable reference state.
    fn references(
        &self,
        _update_id: &Sha256Digest,
        _active: &CoreInstallation,
    ) -> Result<CoreUpdatePruneReferences, CoreUpdateError> {
        Err(CoreUpdateError::provider(
            "test references",
            "unexpected prune-reference read",
        ))
    }
}

// Opens one isolated real database authority for composition.
fn database(directory: &tempfile::TempDir) -> Arc<DatabaseManager> {
    Arc::new(
        DatabaseManager::open(DatabaseConfiguration::new(
            directory.path().join("core.sqlite3"),
        ))
        .expect("database"),
    )
}

// Initializes one exact active local Node required by the production operation authority.
fn node(database: Arc<DatabaseManager>) -> Arc<NodeManager> {
    Arc::new(
        NodeManager::open(
            database,
            Node::new(
                NodeIdentity::new(
                    NodeId::parse(&"1".repeat(32)).expect("node"),
                    MachineId::parse(&"2".repeat(32)).expect("machine"),
                    InstallationId::parse(&"3".repeat(64)).expect("installation"),
                ),
                DisplayName::parse("Test Node").expect("display name"),
                NodeRole::Main,
                NodeState::Active,
                NodeAddress::parse("test.local").expect("address"),
                None,
                EntityTimestamps::new(UnixMilliseconds::new(1), UnixMilliseconds::new(1))
                    .expect("timestamps"),
            ),
            "initialize-update-composition",
        )
        .expect("Node manager")
        .0,
    )
}

// Returns one complete explicit authority set with one optional missing position.
fn ports(
    database: Arc<DatabaseManager>,
    missing: Option<usize>,
    context: CoreUpdateServiceContext,
) -> ApplicationCoreUpdatePorts {
    ApplicationCoreUpdatePorts::new(
        (missing != Some(0)).then_some(database),
        (missing != Some(1)).then_some(Arc::new(AdmissionMock) as Arc<_>),
        (missing != Some(2)).then_some(Arc::new(TransportMock) as Arc<_>),
        (missing != Some(3)).then_some(Arc::new(SignatureMock) as Arc<_>),
        (missing != Some(4)).then_some(Arc::new(ServiceHandoffMock { context }) as Arc<_>),
        (missing != Some(5)).then_some(Arc::new(ReferenceMock) as Arc<_>),
    )
}

// Returns one bounded readiness policy without using native time during construction.
fn readiness() -> CoreUpdateReadinessPolicy {
    CoreUpdateReadinessPolicy::new(30_000, 100, 2).expect("readiness")
}

// Creates every existing private directory required before production composition begins.
fn system_roots(directory: &tempfile::TempDir) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let root = directory.path().canonicalize().expect("canonical root");
    let home = root.join("home");
    let letsinfer = root.join("letsinfer");
    let setup = letsinfer.join("setup");
    let configuration = letsinfer.join("configuration");
    for path in [&home, &letsinfer, &setup, &configuration] {
        std::fs::create_dir_all(path).expect("directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
                .expect("directory mode");
        }
    }
    (home, letsinfer, setup, configuration)
}

// Builds one exact system composition configuration with independently replaceable boundaries.
fn system_configuration(
    home: PathBuf,
    letsinfer: PathBuf,
    setup: PathBuf,
    configuration: PathBuf,
    curl: PathBuf,
    ssh_keygen: PathBuf,
    signers: PathBuf,
    supervisor: PathBuf,
) -> ApplicationSystemCoreUpdateConfiguration {
    ApplicationSystemCoreUpdateConfiguration::new(
        CoreUpdateReleasePlatform::LinuxArm64,
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Main),
        letsinfer,
        home,
        setup,
        configuration,
        unsafe { libc::geteuid() },
        curl,
        ssh_keygen,
        signers,
        supervisor,
        readiness(),
    )
    .expect("system configuration")
}

// Composes every concrete system authority without performing a download or service mutation.
#[test]
fn system_composition_binds_real_authorities_without_external_mutation() {
    let directory = tempfile::tempdir().expect("directory");
    let (home, letsinfer, setup, configuration) = system_roots(&directory);
    let database = database(&directory);
    let node = node(database.clone());
    let composed = compose_system_core_update(
        system_configuration(
            home,
            letsinfer.clone(),
            setup,
            configuration,
            PathBuf::from("/usr/bin/curl"),
            PathBuf::from("/usr/bin/ssh-keygen"),
            letsinfer.join("trust/release-allowed-signers"),
            PathBuf::from("/usr/bin/systemctl"),
        ),
        database,
        node,
    );
    if let Err(error) = composed {
        panic!("system composition: {error}");
    }
}

// Rejects each unsafe system command or missing global-lock root before exposing the capability.
#[test]
fn system_composition_fails_closed_at_native_authority_boundaries() {
    for failure in ["curl", "ssh", "signers", "lock", "supervisor"] {
        let directory = tempfile::tempdir().expect("directory");
        let (home, letsinfer, mut setup, configuration) = system_roots(&directory);
        let mut curl = PathBuf::from("/usr/bin/curl");
        let mut ssh = PathBuf::from("/usr/bin/ssh-keygen");
        let mut signers = letsinfer.join("trust/release-allowed-signers");
        let mut supervisor = PathBuf::from("/usr/bin/systemctl");
        match failure {
            "curl" => curl = PathBuf::from("relative/curl"),
            "ssh" => ssh = PathBuf::from("relative/ssh-keygen"),
            "signers" => signers = PathBuf::from("relative/signers"),
            "lock" => setup = directory.path().join("missing-setup"),
            "supervisor" => supervisor = PathBuf::from("/usr/bin/false"),
            _ => unreachable!(),
        }
        let database = database(&directory);
        let node = node(database.clone());
        let result = compose_system_core_update(
            system_configuration(
                home,
                letsinfer,
                setup,
                configuration,
                curl,
                ssh,
                signers,
                supervisor,
            ),
            database,
            node,
        );
        assert!(result.is_err(), "{failure}");
    }
}

// Composes every supported platform and role without invoking external authorities.
#[test]
fn production_composition_binds_exact_platform_and_role_contracts() {
    for (release, platform, role) in [
        (
            CoreUpdateReleasePlatform::LinuxArm64,
            CoreUpdateServicePlatform::Linux,
            CoreUpdateNodeRole::Main,
        ),
        (
            CoreUpdateReleasePlatform::LinuxX86_64,
            CoreUpdateServicePlatform::Linux,
            CoreUpdateNodeRole::Child,
        ),
        (
            CoreUpdateReleasePlatform::MacosArm64,
            CoreUpdateServicePlatform::Macos,
            CoreUpdateNodeRole::Main,
        ),
        (
            CoreUpdateReleasePlatform::MacosArm64,
            CoreUpdateServicePlatform::Macos,
            CoreUpdateNodeRole::Child,
        ),
    ] {
        let directory = tempfile::tempdir().expect("directory");
        let context = CoreUpdateServiceContext::new(platform, role);
        let configuration = ApplicationCoreUpdateConfiguration::new(
            release,
            context,
            directory.path().join("letsinfer"),
            unsafe { libc::geteuid() },
            readiness(),
        )
        .expect("configuration");
        compose_core_update_manager(configuration, ports(database(&directory), None, context))
            .expect("production composition");
    }
}

// Rejects each absent authority and a release/service platform mismatch before mutation.
#[test]
fn production_composition_rejects_missing_or_inconsistent_authority() {
    for (missing, reason) in [
        (0, "database authority is unavailable"),
        (1, "global update lease authority is unavailable"),
        (2, "signed release transport is unavailable"),
        (3, "release signature trust is unavailable"),
        (4, "active-service cutover authority is unavailable"),
        (5, "update prune-reference authority is unavailable"),
    ] {
        let directory = tempfile::tempdir().expect("directory");
        let context = CoreUpdateServiceContext::new(
            CoreUpdateServicePlatform::Linux,
            CoreUpdateNodeRole::Main,
        );
        let configuration = ApplicationCoreUpdateConfiguration::new(
            CoreUpdateReleasePlatform::LinuxArm64,
            context,
            directory.path().join("letsinfer"),
            unsafe { libc::geteuid() },
            readiness(),
        )
        .expect("configuration");
        let error = match compose_core_update_manager(
            configuration,
            ports(database(&directory), Some(missing), context),
        ) {
            Ok(_) => panic!("missing authority"),
            Err(error) => error,
        };
        assert_eq!(
            error.to_string(),
            format!("Core update production composition failed: {reason}")
        );
    }

    let directory = tempfile::tempdir().expect("directory");
    assert!(ApplicationCoreUpdateConfiguration::new(
        CoreUpdateReleasePlatform::MacosArm64,
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Main,),
        directory.path().join("letsinfer"),
        unsafe { libc::geteuid() },
        readiness(),
    )
    .is_err());

    let context =
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Main);
    let configuration = ApplicationCoreUpdateConfiguration::new(
        CoreUpdateReleasePlatform::LinuxArm64,
        context,
        directory.path().join("letsinfer"),
        unsafe { libc::geteuid() },
        readiness(),
    )
    .expect("configuration");
    let error = match compose_core_update_manager(
        configuration,
        ports(
            database(&directory),
            None,
            CoreUpdateServiceContext::new(
                CoreUpdateServicePlatform::Macos,
                CoreUpdateNodeRole::Main,
            ),
        ),
    ) {
        Ok(_) => panic!("inconsistent handoff"),
        Err(error) => error,
    };
    assert_eq!(
        error.to_string(),
        "Core update production composition failed: active-service cutover context differs from update configuration"
    );
}
